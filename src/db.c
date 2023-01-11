/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include <assert.h>
#include <nettle/blowfish.h>
#include <nettle/sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

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

typedef enum {
    PWSAFE_DB_V1,
    PWSAFE_DB_V2,
} PWS_DB_VERSION;

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

/** Swap block byte order le--be */
static inline void swap_byte_order(Block b)
{
    uint32_t *l = (uint32_t *)(b), *h = (uint32_t *)(b + 4);
    *l = __builtin_bswap32(*l);
    *h = __builtin_bswap32(*h);
}

const char *get_default_user()
{
    const char *dl = getenv("PWSAFE_DEFAULT_USER");
    if (!dl)
    {
        dl = getenv("USER");
        if (!dl)
        {
            dl = getenv("LOGNAME");
            if (!dl)
            {
                // fine, we'll go get LOGNAME from the pwdatabase
                const struct passwd *const pw = getpwuid(getuid());
                if (pw)
                {
                    dl = pw->pw_name;
                }
            }
        }
    }
    if (!dl)
    {
        // no USER, no LOGNAME, no /etc/passwd entry for this UID; they're on their own now
        dl = "";
    }
    return dl;
}

static inline _Bool is_ws(const char c)
{
    return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

/** 
 * Trim whitespace from right side of string 
 * \param pend Pointer to character after end-of-string (usually `'0'`).
 *             Length of string is `(pend-pbegin)`
 * \note
 * A null terminator will be assigned after the first non-whitespace character,
 * or at `pbegin` if the string consists entirely of whitespace
 */
const char *trim_right(const char *pbegin, char *pend)
{
    assert(pend);
    assert(pbegin);
    assert(pend > pbegin);
    while (pend-- > pbegin && is_ws(*pend)) ;
    *(pend+1) = 0;
    return pbegin;
}

static inline void set_rc(PWS_RESULT_CODE *prc, PWS_RESULT_CODE rc)
{
    if (prc) *prc = rc;
}

static PwsDb *db_alloc(PWS_RESULT_CODE *rc)
{
    PwsDb *pdb = NULL;
    pdb = malloc(sizeof(PwsDb));
    if (!pdb)
    {
        set_rc(rc, PWS_ERR_ALLOC);
    }
    else
    {
        memcpy(pdb->magic, DB_MAGIC, sizeof(DB_MAGIC));
        pdb->ver = 1;
        pdb->db_file = NULL;
    }
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

static PwsDbField *alloc_field(uint8_t type, char *value)
{
    PwsDbField *p = malloc(sizeof(PwsDbField));
    if (p)
    {
        p->type = type;
        p->value = value;
        p->next = NULL;
    }
    return p;
}

static void free_fields(PwsDbField *p)
{
    while (p != NULL)
    {
        PwsDbField *pnext = p->next;
        size_t len = strlen(p->value);
        memset_func(p->value, 0, len);
        free(p->value);
        memset_func(p, 0, sizeof(*p));
        free(p);
        p = pnext;
    }
}

static void free_record(PwsDbRecord *p)
{
    free_fields(p->fields);
    memset_func(p, 0, sizeof(*p));
    free(p);
}

static _Bool db_read_header(FILE *f, Header *h)
{
    if (fread(h->random, 1, sizeof(h->random), f) != sizeof(h->random) ||
        fread(h->hash, 1, sizeof(h->hash), f) != sizeof(h->hash) ||
        fread(h->salt, 1, sizeof(h->salt), f) != sizeof(h->salt) ||
        fread(h->iv, 1, sizeof(h->iv), f) != sizeof(h->iv))
    {
        return false;
    }
    return true;
}

static _Bool db_check_password(Header *h, const char *pw)
{
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

static const char *db_get_title(PwsDbRecord *record)
{
    assert(record);
    PwsDbField *field = record->fields;
    while (field != NULL && field->type != FT_TITLE)
    {
        field = field->next;
    }
    const char *retval = NULL;
    if (field)
    {
        retval = field->value;
    }
    return retval;
}

static _Bool db_read_block(PwsDb *pdb, Block block, PWS_RESULT_CODE *rc)
{
    assert(pdb);
    set_rc(rc, PWS_SUCCESS);

    FILE *f = pdb->db_file;
    size_t len = fread(block, 1, BLOCK_SIZE, f);
    if (len != BLOCK_SIZE)
    {
        if (feof(f))
        {
            set_rc(rc, PWS_ERR_CORRUPT_DB);
        }
        else
        {
            set_rc(rc, PWS_ERR_READ);
        }
        return false;
    }

    Block save_block;
    memcpy(save_block, block, BLOCK_SIZE);

    // I believe that the reason that byte-ordering is required
    // is because the blowfish implementation used in the original passwordsafe
    // operated on 32-bit ints and not arrays of bytes
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

static _Bool db_read_next_field(PwsDb *pdb, PwsDbField **field, PWS_RESULT_CODE *rc)
{
    assert(field);
    *field = NULL;

    Block block;
    if (!db_read_block(pdb, block, rc))
        return false;

    uint8_t type;
    char *str;

    type = block[4];
    int32_t len = *(int32_t *)(block);
    if (len < 0 || len > 64 * 1024)
    {
        set_rc(rc, PWS_ERR_CORRUPT_DB);
        return false;
    }

    size_t nblocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    str = malloc(nblocks*BLOCK_SIZE + 1);
    if (!str)
    {
        set_rc(rc, PWS_ERR_ALLOC);
        return false;
    }

    for (size_t i = 0; i < nblocks; ++i)
    {
        if (!db_read_block(pdb, block, rc))
        {
            free(str);
            return false;
        }
        memcpy(str + i * BLOCK_SIZE, block, BLOCK_SIZE);
    }
    str[len] = 0;

    *field = alloc_field(type, str);
    if (!*field)
    {
        set_rc(rc, PWS_ERR_ALLOC);
        free(str);
        return false;
    }

    return true;
}

const static char SPLIT_CHAR = '\xAD';
const static char DEFAULT_USER_CHAR = '\xA0';

static _Bool db_read_next_v1_record(PwsDb *pdb, PwsDbField** fields, PWS_RESULT_CODE *rc)
{
    assert(fields);
    PwsDbField *phead = NULL, *p = NULL;

    _Bool status = db_read_next_field(pdb, &p, rc);
    if (status)
    {
        p->type = FT_NAME;
        phead = p;

        const char *name = p->value;
        const char *pos = strchr(name, SPLIT_CHAR);
        if (!pos) 
        {
            pos = strchr(name, DEFAULT_USER_CHAR);
        }
        if (!pos)
        {
            // no magic split chars; assume this is a very old database that contains no login field
            pos = name + strlen(name);
        }

        p = alloc_field(FT_TITLE, NULL);
        if (!p)
        {
            set_rc(rc, PWS_ERR_ALLOC);
            status = false;
            goto done;
        }
        size_t len = pos - name;
        p->value = malloc(len+1);
        if (!p->value)
        {
            set_rc(rc, PWS_ERR_ALLOC);
            status = false;
            goto done;
        }
        strncpy(p->value, name, len);
        trim_right(p->value, p->value+len);
        p->next = phead;
        phead = p;

        /*
         * IMB 2023-01-10 From Rony Shapiro
         * https://github.com/pwsafe/pwsafe/blob/master/docs/formatV1.txt
         * Apparently as a hack to upgrade from previous versions, the Name field
         * is actually two fields, "Title" and "Username", separated by
         * SPLTCHR. Furthermore, if the Username is DEFUSERCHR, then it is
         * replaced by the user's "default user name", as specified in
         * options. It works, but is not a pretty sight.
        */
        if (*pos == SPLIT_CHAR || *pos == DEFAULT_USER_CHAR)
        {
            p = alloc_field(FT_USER, NULL);
            if (!p)
            {
                set_rc(rc, PWS_ERR_ALLOC);
                status = false;
                goto done;
            }
            if (*pos == SPLIT_CHAR)
            {
                // split name_login if it contains the magic split char
                size_t len = strlen(pos+1);
                p->value = malloc(len+1);
                if (!p->value)
                {
                    set_rc(rc, PWS_ERR_ALLOC);
                    status = false;
                    goto done;
                }
                strncpy(p->value, pos+1, len);
                trim_right(p->value, p->value+len);
            }
            else //if (*pos == DEFAULT_USER_CHAR)
            {
                // this entry uses the default login. this is not part of the database; 
                // instead it is part of the configuration, or in our case, $USER
                const char *default_user = get_default_user();
                size_t len = strlen(default_user);
                p->value = malloc(len+1);
                if (!p->value)
                {
                    set_rc(rc, PWS_ERR_ALLOC);
                    status = false;
                    goto done;
                }
                strncpy(p->value, default_user, len);
                trim_right(p->value, p->value+len);
            }
            p->next = phead;
            phead = p;
        }
    }
    status = status && db_read_next_field(pdb, &p, rc);
    if (status)
    {
        p->type = FT_PASSWORD;
        p->next = phead;
        phead = p;
    }
    status = status && db_read_next_field(pdb, &p, rc);
    if (status)
    {
        p->type = FT_NOTES;
        p->next = phead;
        phead = p;
    }

done:
    *fields = phead;
    return status;
}

static _Bool db_read_next_v2_record(PwsDb *pdb, PwsDbField** fields, PWS_RESULT_CODE *rc)
{
    assert(fields);
    set_rc(rc, PWS_SUCCESS);

    _Bool status = true;
    FILE *f = pdb->db_file;
    PwsDbField *phead = NULL;

    int nfields = 1000;
    while (status && (status = !feof(f) && nfields-- > 1))
    {
        PwsDbField *pfield = NULL;
        status = db_read_next_field(pdb, &pfield, rc);
        if (status)
        {
            pfield->next = phead;
            phead = pfield;
            if (pfield->type == FT_END) goto done;
        }
    }
    if (nfields == 0)
    {
        // We've read too many fields for a single record, 
        // something is not right
        set_rc(rc, PWS_ERR_CORRUPT_DB);
    }

done:
    *fields = phead;
    return status;
}

static _Bool db_read_next_record(PwsDb *pdb, PwsDbRecord** record, PWS_RESULT_CODE *rc)
{
    PwsDbField *fields = NULL;
    _Bool status = false;
    if (pdb->db_vers == PWSAFE_DB_V2)
    {
        status = db_read_next_v2_record(pdb, &fields, rc);
    }
    else
    {
        status = db_read_next_v1_record(pdb, &fields, rc);
    }
    if (status)
    {
        *record = malloc(sizeof(PwsDbRecord));
        if (!*record)
        {
            set_rc(rc, PWS_ERR_ALLOC);
            free_fields(fields);
            return false;
        }
        (*record)->fields = fields;
    }
    return status;
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
        set_rc(rc, PWS_ERR_INVALID_ARG);
        goto err;
    }
    if (memcmp(pdb->magic, DB_MAGIC, sizeof(DB_MAGIC)) != 0)
    {
        set_rc(rc, PWS_ERR_INVALID_HANDLE);
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

PWSAFE_EXTERN void pws_free_db_records(PwsDbRecord *p)
{
    while (p != NULL)
    {
        PwsDbRecord *pnext = p->next;
        free_record(p);
        p = pnext;
    }
}

PWSAFE_EXTERN PWSHANDLE pws_db_open(const char *pathname, const char *password, PWS_RESULT_CODE *rc)
{
    set_rc(rc, PWS_ERR_FAIL);

    FILE *dbfile = fopen(pathname, "rb");
    if (!dbfile)
    {
        set_rc(rc, PWS_ERR_OPEN);
        return NULL;
    }

    Header header;

    if (!db_read_header(dbfile, &header))
    {
        set_rc(rc, PWS_ERR_OPEN);
        return NULL;
    }

    if (!db_check_password(&header, password))
    {
        set_rc(rc, PWS_ERR_INCORRECT_PW);
        return NULL;
    }

    PwsDb *pdb = db_alloc(rc);
    if (pdb)
    {
        pdb->db_file = dbfile;
        memcpy(&pdb->db_header, &header, sizeof(pdb->db_header));

        db_compute_key(pdb, password);

        set_rc(rc, PWS_SUCCESS);
    }


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

PWSAFE_EXTERN _Bool pws_db_read_accounts(PWSHANDLE hdb, PwsDbRecord **records, PWS_RESULT_CODE *rc)
{
    *records = NULL;

    if (!check_hdb(hdb, rc))
        return false;

    PwsDb *pdb = (PwsDb *)hdb;
    PwsDbRecord *phead = NULL, *p = NULL;

    if (db_read_next_record(pdb, &p, rc))
    {
        const char *ptitle = db_get_title(p);
        if (ptitle == NULL)
        {
            // No title field == something is wrong
            set_rc(rc, PWS_ERR_CORRUPT_DB);
            free(p);
            return false;
        }
        if (strcmp(PWSAFE_V2_NAME_MAGIC, ptitle) == 0)
        {
            pdb->db_vers = PWSAFE_DB_V2;
            db_read_next_record(pdb, &p, rc);
        }
        else
        {
            pdb->db_vers = PWSAFE_DB_V1;
        }

        phead = p;
        while (db_read_next_record(pdb, &p, rc))
        {
            p->next = phead;
            phead = p;
        };
    }

    *records = phead;
    return true;
}