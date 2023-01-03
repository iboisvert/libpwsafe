/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include <assert.h>
#include <arpa/inet.h> // for byte order
#include <nettle/sha1.h>
#include <nettle/blowfish.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Prevent memset from being optimized out
typedef void *(*fmemset)(void *, int, size_t);
static volatile fmemset memset_func = memset;

// Byte ordering
// inline uint32_t identity(uint32_t val) { return val; }
// inline uint32_t be_to_le(uint32_t val) { return __builtin_bswap32(val); }
// typedef uint32_t (*fboswap)(uint32_t);
// static fboswap host_to_le = identity;

// A magic number used to verify the header
static const unsigned char DB_MAGIC[16] = {
    0x05, 0xf5, 0x4d, 0x91, 0xe8, 0xb6, 0x44, 0x4b, 0xb4, 0xed, 0xba, 0xd4, 0x2a, 0x5e, 0x03, 0x49};

typedef struct
{
    unsigned char random[8];
    unsigned char hash[SHA1_DIGEST_SIZE]; // 20
    unsigned char salt[SHA1_DIGEST_SIZE]; // 20
    unsigned char iv[8];
} Header;

typedef struct
{
    unsigned char magic[16];
    unsigned char ver; // Struct version
    FILE *dbfile;
    Header header;
    unsigned char key[SHA1_DIGEST_SIZE];
} PwsDb;

typedef uint32_t Block[2];

static PwsDb *db_alloc()
{
    PwsDb *pdb = NULL;
    pdb = malloc(sizeof(PwsDb));
    memcpy(pdb->magic, DB_MAGIC, sizeof(DB_MAGIC));
    pdb->ver = 1;
    pdb->dbfile = NULL;
    return pdb;
}

static void db_free(PwsDb *pdb)
{
    memset(pdb->magic, 0, sizeof(DB_MAGIC));
    if (pdb->dbfile)
    {
        fclose(pdb->dbfile);
        pdb->dbfile = NULL;
    }
    memset_func(pdb->key, 0, sizeof(pdb->key));
    free(pdb);
}

static _Bool db_read_header(PwsDb *pdb)
{
    // IMB 2023-01-01 Adapted from code by Nicolas Dade https://github.com/nsd20463/pwsafe
    FILE *f = pdb->dbfile;
    Header *hdr = &pdb->header;
    if (fread(hdr->random, 1, sizeof(hdr->random), f) != sizeof(hdr->random) ||
        fread(hdr->hash, 1, sizeof(hdr->hash), f) != sizeof(hdr->hash) ||
        fread(hdr->salt, 1, sizeof(hdr->salt), f) != sizeof(hdr->salt) ||
        fread(hdr->iv, 1, sizeof(hdr->iv), f) != sizeof(hdr->iv))
    {
        return false;
    }
    return true;
}

static void db_compute_key(PwsDb *pdb, const char *pw)
{
    Header *h = &pdb->header;

    // IMB 2023-01-01 Adapted from code by Nicolas Dade https://github.com/nsd20463/pwsafe
    // cbc.read(h.iv,sizeof(h.iv));
    // SHA_CTX sha;
    // SHA1_Init(&sha);
    // SHA1_Update(&sha, pw.data(), pw.length());
    // SHA1_Update(&sha, h.salt, sizeof(h.salt));
    // unsigned char key[SHA_DIGEST_LENGTH];
    // SHA1_Final(key, &sha);
    // BF_set_key(&bf, sizeof(key), key);
    // memset(&sha,0,sizeof(sha));
    // memset(&key,0,sizeof(key));
    struct sha1_ctx ctx;
    sha1_init(&ctx);
    size_t pw_len = strlen(pw);
    sha1_update(&ctx, pw_len, (const uint8_t *)pw);
    sha1_update(&ctx, sizeof(h->salt), h->salt);
    sha1_digest(&ctx, sizeof(pdb->key), pdb->key);
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
    pdb->dbfile = dbfile;

    if (!db_read_header(pdb))
    {
        if (rc)
            *rc = PWS_ERR_OPEN;
        db_free(pdb);
        return NULL;
    }
    db_compute_key(pdb, password);

    if (rc) *rc = PWS_SUCCESS;
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

    // IMB 2023-01-01 Adapted from code by Nicolas Dade https://github.com/nsd20463/pwsafe
    PwsDb *pdb = (PwsDb *)hdb;
    Header *h = &pdb->header;

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
    memcpy(&block, h->random, sizeof(block));

    // For nettle to match OpenSSL we must swap byte order before and after encrypt
    // TODO: test this on a big-endian machine
    block[0] = __builtin_bswap32(block[0]);
    block[1] = __builtin_bswap32(block[1]);

    // to mimic passwordsafe I use BF_encrypt() directly, but that means I have to pretend that I am on a little-endian
    // machine b/c passwordsafe assumes a i386
    for (int i = 0; i < 1000; ++i)
        blowfish_encrypt(&bf_ctx, sizeof(block), (uint8_t *)&block, (const uint8_t *)&block);

    block[0] = __builtin_bswap32(block[0]);
    block[1] = __builtin_bswap32(block[1]);

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
    sha1_update(&sha_ctx, sizeof(block), (const uint8_t *)block);
    sha1_update(&sha_ctx, sizeof(zeros), zeros);
    unsigned char test_hash[SHA1_DIGEST_SIZE];
    sha1_digest(&sha_ctx, sizeof(test_hash), test_hash);

    memset_func(key, 0, sizeof(key));

    _Bool equal = memcmp(test_hash, h->hash, sizeof(h->hash)) == 0 ? true : false;

    return equal;
}
