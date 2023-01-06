/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include <assert.h>
#include <nettle/blowfish.h>
#include <nettle/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// IMB 2023-01-01 Most of the code here is
// adapted from code by Nicolas Dade https://github.com/nsd20463/pwsafe

// Prevent memset from being optimized out
typedef void *(*fmemset)(void *, int, size_t);
static volatile fmemset memset_func = memset;

// Byte ordering
// inline uint32_t identity(uint32_t val) { return val; }
// inline uint32_t be_to_le(uint32_t val) { return __builtin_bswap32(val); }
// typedef uint32_t (*fboswap)(uint32_t);
// static fboswap host_to_le = identity;

// A magic number used to verify the handle in API calls
static const unsigned char DB_MAGIC[16] = {
    0x05, 0xf5, 0x4d, 0x91, 0xe8, 0xb6, 0x44, 0x4b, 0xb4, 0xed, 0xba, 0xd4, 0x2a, 0x5e, 0x03, 0x49};

const char * const PWSAFE_V2_NAME_MAGIC = 
    " !!!Version 2 File Format!!! Please upgrade to PasswordSafe 2.0 or later";

typedef uint8_t Block[8];
static const size_t BLOCK_SIZE = sizeof(Block);

typedef struct
{
    Block random;
    unsigned char hash[SHA1_DIGEST_SIZE]; // 20
    unsigned char salt[SHA1_DIGEST_SIZE]; // 20
    Block iv;
} Header;

typedef struct
{
    unsigned char magic[16];
    unsigned char ver; // Struct version
    FILE *db_file;
    Header db_header;
    PWS_DB_VERSION db_vers;
    struct blowfish_ctx bf_ctx;
    Block cbc;
} PwsDb;

typedef struct
{
    uint8_t type;
    char *value;
} PwsDbField;

typedef struct
{
    PwsDbField *fields;
} PwsDbRecord;

/** Swap block byte order le--be */
static void swap_byte_order(Block b)
{
    uint32_t *l = (uint32_t *)(b), *h = (uint32_t *)(b + 4);
    *l = __builtin_bswap32(*l);
    *h = __builtin_bswap32(*h);
}

static PwsDb *db_alloc()
{
    PwsDb *pdb = NULL;
    pdb = malloc(sizeof(PwsDb));
    memcpy(pdb->magic, DB_MAGIC, sizeof(DB_MAGIC));
    pdb->ver = 1;
    pdb->db_file = NULL;
    return pdb;
}

static void db_free(PwsDb *pdb)
{
    if (pdb->db_file)
    {
        fclose(pdb->db_file);
    }
    memset_func(pdb, 0, sizeof(*pdb));
    free(pdb);
}

static _Bool db_read_header(PwsDb *pdb)
{
    FILE *f = pdb->db_file;
    Header *hdr = &pdb->db_header;
    if (fread(hdr->random, 1, sizeof(hdr->random), f) != sizeof(hdr->random) ||
        fread(hdr->hash, 1, sizeof(hdr->hash), f) != sizeof(hdr->hash) ||
        fread(hdr->salt, 1, sizeof(hdr->salt), f) != sizeof(hdr->salt) ||
        fread(hdr->iv, 1, sizeof(hdr->iv), f) != sizeof(hdr->iv))
    {
        return false;
    }
    return true;
}

static _Bool db_read_block(PwsDb *pdb, Block block, PWS_RESULT_CODE *rc)
{
    *rc = PWS_SUCCESS;

    FILE *f = pdb->db_file;
    size_t len = fread(block, 1, BLOCK_SIZE, f);
    if (len != BLOCK_SIZE)
    {
        if (feof(f))
        {
            *rc = PWS_ERR_CORRUPT_DB;
        }
        else
        {
            *rc = PWS_ERR_READ;
        }
        return false;
    }

    Block save_block;
    memcpy(save_block, block, BLOCK_SIZE);

    // There is something very fishy about having to 
    // swap byte-order in order to match OpenSSL
    swap_byte_order(block);
    blowfish_decrypt(&pdb->bf_ctx, BLOCK_SIZE, (uint8_t *)block, (const uint8_t *)block);
    swap_byte_order(block);

    const uint8_t *cbc = pdb->cbc;
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
    {
        block[i] = block[i] ^ cbc[i];
    }
    memcpy(pdb->cbc, save_block, BLOCK_SIZE);

    memset_func(save_block, 0, BLOCK_SIZE);
    
    return true;
}

static _Bool db_read_next_field(PwsDb *pdb, uint8_t *type, char **str, PWS_RESULT_CODE *rc)
{
    *type = FT_END;
    *str = NULL;

    Block block;
    if (!db_read_block(pdb, block, rc))
        return false;

    *type = block[4];
    int32_t len = *(int32_t *)(block);
    if (len < 0 || len > 64 * 1024)
    {
        *rc = PWS_ERR_CORRUPT_DB;
        return false;
    }

    char *s = *str = malloc(len + 1);
    size_t nblocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (size_t i = 0; i < nblocks; ++i)
    {
        if (!db_read_block(pdb, block, rc))
        {
            free(*str);
            *str = NULL;
            return false;
        }
        memcpy(s + i * BLOCK_SIZE, block, BLOCK_SIZE);
    }
    s[len] = 0;

    return true;
}

static _Bool db_read_next_v1_record(PwsDb *pdb, PWS_RESULT_CODE *rc)
{
    uint8_t unused;
    char *value;

    _Bool status = db_read_next_field(pdb, &unused, &value, rc);
    status = status && db_read_next_field(pdb, &unused, &value, rc);
    status = status && db_read_next_field(pdb, &unused, &value, rc);

    return status;
}

static _Bool db_read_next_v2_record(PwsDb *pdb, PWS_RESULT_CODE *rc)
{
    _Bool status = true;
    FILE *f = pdb->db_file;

    int nfields = 1000;
    while (status && !feof(f) && nfields-- > 1)
    {
        uint8_t type;
        char *value;
        status = db_read_next_field(pdb, &type, &value, rc);
        switch(type) {
            case FT_END: goto done;
        }
    }
    if (nfields == 0)
    {
        *rc = PWS_ERR_CORRUPT_DB;
    }
done:
    return status;
}

static _Bool db_read_next_record(PwsDb *pdb, PWS_RESULT_CODE *rc)
{
    if (pdb->db_vers == PWSAFE_DB_V2)
    {
        return db_read_next_v2_record(pdb, rc);
    }
    else
    {
        return db_read_next_v1_record(pdb, rc);
    }
}

static void db_compute_key(PwsDb *pdb, const char *pw)
{
    Header *h = &pdb->db_header;
    memcpy(pdb->cbc, h->iv, sizeof(pdb->cbc));
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    size_t pw_len = strlen(pw);
    sha1_update(&ctx, pw_len, (const uint8_t *)pw);
    sha1_update(&ctx, sizeof(h->salt), h->salt);
    uint8_t key[SHA1_DIGEST_SIZE];
    sha1_digest(&ctx, sizeof(key), key);
    blowfish_set_key(&pdb->bf_ctx, sizeof(key), key);
}

/** Sanity checks */
static _Bool check_hdb(PWSHANDLE hdb, PWS_RESULT_CODE *rc)
{
    PwsDb *pdb = (PwsDb *)hdb;
    if (!pdb)
    {
        if (rc)
            *rc = PWS_ERR_INVALID_ARG;
        goto err;
    }
    if (memcmp(pdb->magic, DB_MAGIC, sizeof(DB_MAGIC)) != 0)
    {
        if (rc)
            *rc = PWS_ERR_INVALID_HANDLE;
        goto err;
    }

    return true;

err:
    return false;
}

// static _Bool init_done = false;

// PWSAFE_EXTERN void pws_init()
// {
//     if (!init_done)
//     {
//         _Bool is_le = (union{uint16_t n; char c[2];}){1}.c[0] ? true : false;
//         if (!is_le) host_to_le = be_to_le;
//         init_done = true;
//     }
// }

PWSAFE_EXTERN PWSHANDLE pws_db_open(const char *pathname, const char *password, PWS_RESULT_CODE *rc)
{
    if (rc)
        *rc = PWS_ERR_FAIL;

    FILE *dbfile = fopen(pathname, "rb");
    if (!dbfile)
    {
        if (rc)
            *rc = PWS_ERR_OPEN;
        return NULL;
    }

    PwsDb *pdb = db_alloc();
    pdb->db_file = dbfile;

    if (!db_read_header(pdb))
    {
        if (rc)
            *rc = PWS_ERR_OPEN;
        db_free(pdb);
        return NULL;
    }
    db_compute_key(pdb, password);

    if (rc)
        *rc = PWS_SUCCESS;
    return pdb;
}

PWSAFE_EXTERN void pws_db_close(PWSHANDLE hdb, PWS_RESULT_CODE *rc)
{
    if (!check_hdb(hdb, rc))
        return;
    // Trash memory in case client tries to reuse invalid pointer
    PwsDb *pdb = (PwsDb *)hdb;
    db_free(pdb);
}

PWSAFE_EXTERN _Bool pws_db_check_password(PWSHANDLE hdb, const char *pw)
{
    if (!check_hdb(hdb, NULL))
        return false;

    PwsDb *pdb = (PwsDb *)hdb;
    Header *h = &pdb->db_header;

    // generate test hash from random and passphrase
    // I am mystified as to why Bruce uses these extra 2 zero bytes in the hashes
    struct sha1_ctx sha_ctx;
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, sizeof(h->random), h->random);
    const static unsigned char zeros[2] = {0, 0};
    sha1_update(&sha_ctx, sizeof(zeros), zeros);
    size_t pw_len = strlen(pw);
    sha1_update(&sha_ctx, pw_len, (const uint8_t *)pw);
    unsigned char key[SHA1_DIGEST_SIZE];
    sha1_digest(&sha_ctx, sizeof(key), key);

    struct blowfish_ctx bf_ctx;
    blowfish_set_key(&bf_ctx, sizeof(key), key);

    Block block;
    memcpy(&block, h->random, BLOCK_SIZE);

    // For nettle to match OpenSSL we must swap byte order before and after encrypt
    // TODO: test this on a big-endian machine
    swap_byte_order(block);

    // to mimic passwordsafe I use BF_encrypt() directly, but that means I have to pretend that I am on a little-endian
    // machine b/c passwordsafe assumes a i386
    for (int i = 0; i < 1000; ++i)
        blowfish_encrypt(&bf_ctx, BLOCK_SIZE, (uint8_t *)&block, (const uint8_t *)&block);

    swap_byte_order(block);

    // Now comes a sad part: I have to hack to mimic the original passwordsafe which contains what I believe
    // is a bug. passwordsafe used its own blowfish and sha1 libraries, and its version of SHA1Final()
    // memset the sha context to 0's. However the passwordsafe code went ahead and performed a
    // SHA1Update on that zero'ed context. This of course did not crash anything, but it is not
    // a real sha hash b/c the initial state of a real sha1 is not all zeros. Also we end up only
    // hashing 8 bytes of stuff, so there are not 20 bytes of randomness in the result.
    // The good thing is we are hashing something which is already well hashed, so I doubt this
    // opened up any holes. But it does show that one should always step the program in a debugger
    // and watch what the variables are doing; sometimes it is eye opening!
    sha1_init(&sha_ctx);
    memset_func(sha_ctx.state, 0, sizeof(sha_ctx.state));
    sha1_update(&sha_ctx, BLOCK_SIZE, (const uint8_t *)block);
    sha1_update(&sha_ctx, sizeof(zeros), zeros);
    unsigned char test_hash[SHA1_DIGEST_SIZE];
    sha1_digest(&sha_ctx, sizeof(test_hash), test_hash);

    memset_func(key, 0, sizeof(key));
    memset_func(&bf_ctx, 0, sizeof(bf_ctx));

    _Bool equal = memcmp(test_hash, h->hash, sizeof(h->hash)) == 0 ? true : false;

    return equal;
}

PWSAFE_EXTERN _Bool pws_db_read_accounts(PWSHANDLE hdb, PWS_RESULT_CODE *rc)
{
    if (!check_hdb(hdb, NULL))
        return false;

    PwsDb *pdb = (PwsDb *)hdb;

    while (db_read_next_record(pdb, rc))
    {
//  PWSAFE_V2_NAME_MAGIC       
    }

    return false;
}