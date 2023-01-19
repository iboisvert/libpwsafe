/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include "pwsafe_priv.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

// IMB 2023-01-01 Most of the code here is
// adapted from code by Nicolas Dade https://github.com/nsd20463/pwsafe

// Prevent memset from being optimized out
volatile fmemset memset_func = memset;

// A magic number used to verify the handle in API calls
static const uint8_t DB_MAGIC[16] = {
    0x05, 0xf5, 0x4d, 0x91, 0xe8, 0xb6, 0x44, 0x4b, 0xb4, 0xed, 0xba, 0xd4, 0x2a, 0x5e, 0x03, 0x49};

static const char * const PWSAFE_V2_NAME_MAGIC = 
    " !!!Version 2 File Format!!! Please upgrade to PasswordSafe 2.0 or later";
static const char * const PWSAFE_V2_PASSWORD_MAGIC = "2.0";

static inline void set_rc(PWS_RESULT_CODE *prc, PWS_RESULT_CODE rc)
{
    if (prc) *prc = rc;
}

static void init_pdb(PwsDb *pdb)
{
    memcpy(pdb->magic, DB_MAGIC, sizeof(DB_MAGIC));
    pdb->ver = 1;
    pdb->db_vers = -1;
    pdb->db_file = NULL;
    memset_func(&pdb->db_header, 0, sizeof(Header));
}

static PwsDb *db_alloc(PWS_RESULT_CODE *rc)
{
    PwsDb *pdb = NULL;
    pdb = malloc(sizeof(PwsDb));
    if (!pdb)
    {
        set_rc(rc, PRC_ERR_ALLOC);
    }
    else
    {
        init_pdb(pdb);
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

static _Bool db_read_header(FILE *f, Header *h, PWS_RESULT_CODE *rc)
{
    assert(f);
    assert(h);
    set_rc(rc, PRC_ERR_READ);

    if (fread(h->random, 1, sizeof(h->random), f) != sizeof(h->random)
        || fread(h->hash, 1, sizeof(h->hash), f) != sizeof(h->hash)
        || fread(h->salt, 1, sizeof(h->salt), f) != sizeof(h->salt)
        || fread(h->iv, 1, sizeof(h->iv), f) != sizeof(h->iv))
    {
        return false;
    }
    set_rc(rc, PRC_SUCCESS);
    return true;
}

static _Bool db_write_header(PwsDb *pdb, PWS_RESULT_CODE *rc)
{
    assert(pdb);
    FILE *f = pdb->db_file;
    Header *h = &pdb->db_header;
    set_rc(rc, PRC_ERR_WRITE);

    if (fwrite(h->random, 1, sizeof(h->random), f) != sizeof(h->random)
        || fwrite(h->hash, 1, sizeof(h->hash), f) != sizeof(h->hash)
        || fwrite(h->salt, 1, sizeof(h->salt), f) != sizeof(h->salt)
        || fwrite(h->iv, 1, sizeof(h->iv), f) != sizeof(h->iv))
    {
        return false;
    }
    set_rc(rc, PRC_SUCCESS);
    return true;
}

/**
 * Hash function for random data block in db header
*/
static void generate_hash(Block input, uint8_t output[SHA1_DIGEST_SIZE], const char *pw)
{
    // generate test hash from random and passphrase
    // I am mystified as to why Bruce uses these extra 2 zero bytes in the hashes
    struct sha1_ctx sha_ctx;
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, BLOCK_SIZE, input);
    static const unsigned char zeros[2] = {0, 0};
    sha1_update(&sha_ctx, sizeof(zeros), zeros);
    size_t pw_len = strlen(pw);
    sha1_update(&sha_ctx, pw_len, (const uint8_t *)pw);
    unsigned char key[SHA1_DIGEST_SIZE];
    sha1_digest(&sha_ctx, sizeof(key), key);

    struct blowfish_ctx bf_ctx;
    blowfish_set_key(&bf_ctx, sizeof(key), key);

    Block block;
    memcpy(&block, input, BLOCK_SIZE);

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
    sha1_digest(&sha_ctx, SHA1_DIGEST_SIZE, output);

    memset_func(key, 0, sizeof(key));
    memset_func(&bf_ctx, 0, sizeof(bf_ctx));
}

static inline _Bool generate_random(uint8_t *buf, size_t len)
{
#ifdef HAVE_SYS_RANDOM_H
    return getrandom(buf, len, GRND_NONBLOCK) == (ssize_t)len;
#else
  #error Function generate_random undefined
#endif
}

/**
 * Initialize a new database header
*/
_Bool db_init_header(Header *h, const char *pw, PWS_RESULT_CODE *rc)
{
    assert(h);
    assert(pw);
    assert(strlen(pw) > 0);

    memset_func(h, 0, sizeof(*h));

    // Generate random data used to check password
    if (!generate_random(h->random, sizeof(h->random))
        || !generate_random(h->salt, sizeof(h->salt))
        || !generate_random(h->iv, sizeof(h->iv)))
    {
        set_rc(rc, PRC_ERR_INIT_RANDOM);
        return false;
    }

    generate_hash(h->random, h->hash, pw);
    return true;

}

_Bool db_check_password(Header *h, const char *pw)
{
    unsigned char test_hash[SHA1_DIGEST_SIZE];
    generate_hash(h->random, test_hash, pw);

    _Bool equal = memcmp(test_hash, h->hash, sizeof(h->hash)) == 0 ? true : false;

    memset_func(test_hash, 0, sizeof(test_hash));

    return equal;
}

const char *pws_rec_get_field(PwsDbRecord *record, PWS_FIELD_TYPE ft)
{
    assert(record);
    PwsDbField *field = record->fields;
    while (field != NULL && field->type != ft)
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
static inline const char *rec_get_title(PwsDbRecord *record)
{
    return pws_rec_get_field(record, FT_TITLE);
}
static inline const char *rec_get_uuid(PwsDbRecord *record)
{
    return pws_rec_get_field(record, FT_UUID);
}

void db_decode_block(PwsDb *pdb, Block block)
{
    Block cipher_block;
    memcpy(cipher_block, block, BLOCK_SIZE);

    // I believe that the reason that byte-ordering is required
    // is because the blowfish implementation used in the original passwordsafe
    // operated on assumed little-endian 32-bit ints and not arrays of bytes
    swap_byte_order(block);
    blowfish_decrypt(&pdb->bf_ctx, BLOCK_SIZE, (uint8_t *)block, (const uint8_t *)block);
    swap_byte_order(block);

    const uint8_t *cbc = pdb->cbc;
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
    {
        block[i] = block[i] ^ cbc[i];
    }
    memcpy(pdb->cbc, cipher_block, BLOCK_SIZE);

    zero_block(cipher_block);
}

void db_encode_block(PwsDb *pdb, Block block)
{
    const uint8_t *cbc = pdb->cbc;
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
    {
        block[i] = block[i] ^ cbc[i];
    }

    swap_byte_order(block);
    blowfish_encrypt(&pdb->bf_ctx, BLOCK_SIZE, (uint8_t *)block, (const uint8_t *)block);
    swap_byte_order(block);

    memcpy(pdb->cbc, block, BLOCK_SIZE);
}

static _Bool db_read_block(PwsDb *pdb, Block block, PWS_RESULT_CODE *rc)
{
    assert(pdb);

    FILE *f = pdb->db_file;
    size_t len = fread(block, 1, BLOCK_SIZE, f);
    if (len != BLOCK_SIZE)
    {
        if (feof(f))
        {
            set_rc(rc, PRC_ERR_EOF);
        }
        else
        {
            set_rc(rc, PRC_ERR_READ);
        }
        return false;
    }

    db_decode_block(pdb, block);

    return true;
}

static _Bool db_write_block(PwsDb *pdb, Block block, PWS_RESULT_CODE *rc)
{
    assert(pdb);
    assert(block);

    db_encode_block(pdb, block);

    FILE *f = pdb->db_file;
    size_t len = fwrite(block, 1, BLOCK_SIZE, f);
    if (len != BLOCK_SIZE)
    {
        set_rc(rc, PRC_ERR_WRITE);
        return false;
    }

    return true;
}

static _Bool db_read_next_field(PwsDb *pdb, PwsDbField **field, PWS_RESULT_CODE *rc)
{
    assert(field);
    *field = NULL;

    Block block;
    if (!db_read_block(pdb, block, rc))
    {
        return false;
    }
    block_le_to_sys(block);

    uint8_t type;
    char *str;

    type = block[4];
    int32_t len = *(int32_t *)(block);
    if (len < 0 || len > 64 * 1024)
    {
        set_rc(rc, PRC_ERR_CORRUPT_DB);
        return false;
    }

    size_t nblocks = (len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    // Always read at least one block
    if (nblocks < 1) nblocks = 1;
    str = malloc(nblocks*BLOCK_SIZE + 1);
    if (!str)
    {
        set_rc(rc, PRC_ERR_ALLOC);
        return false;
    }

    for (size_t i = 0; i < nblocks; ++i)
    {
        if (!db_read_block(pdb, block, rc))
        {
            free(str);
            if (*rc == PRC_ERR_EOF)
            {
                set_rc(rc, PRC_ERR_CORRUPT_DB);
            }
            return false;
        }
        memcpy(str + i * BLOCK_SIZE, block, BLOCK_SIZE);
    }
    str[len] = 0;

    *field = alloc_field(type, str);
    if (!*field)
    {
        set_rc(rc, PRC_ERR_ALLOC);
        free(str);
        return false;
    }

    return true;
}

static _Bool db_write_next_field_values(PwsDb *pdb, const PWS_FIELD_TYPE type, const char *value, PWS_RESULT_CODE *rc)
{
    assert(pdb);
    assert(value);

    if (!value) return true;

    const uint32_t len = (uint32_t)strlen(value);

    Block block;
    make_block_le(block, type, len);
    
    if (!db_write_block(pdb, block, rc))
        return false;

    const char *p = value, *pend = p + len;
    for ( ; p < pend-BLOCK_SIZE; p += BLOCK_SIZE)
    {
        memcpy(block, p, BLOCK_SIZE);
        if (!db_write_block(pdb, block, rc))
            return false;
    }
    // Pad string out to multiple of block length
    zero_block(block);
    if (pend > p)
    {
        memcpy(block, p, pend-p);
    }
    // Always write at least one block
    if (!db_write_block(pdb, block, rc))
        return false;

    return true;
}

static _Bool db_write_next_field(PwsDb *pdb, const PwsDbField *field, PWS_RESULT_CODE *rc)
{
    return db_write_next_field_values(pdb, field->type, field->value, rc);
}

static const char SPLIT_CHAR = '\xAD';
static const char DEFAULT_USER_CHAR = '\xA0';

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
            set_rc(rc, PRC_ERR_ALLOC);
            status = false;
            goto done;
        }
        size_t len = pos - name;
        p->value = malloc(len+1);
        if (!p->value)
        {
            set_rc(rc, PRC_ERR_ALLOC);
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
            p = alloc_field(FT_USER, /*value*/NULL);
            if (!p)
            {
                set_rc(rc, PRC_ERR_ALLOC);
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
                    set_rc(rc, PRC_ERR_ALLOC);
                    status = false;
                    goto done;
                }
                while (is_ws(*++pos) && *pos != 0) ;
                strncpy(p->value, pos, len);
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
                    set_rc(rc, PRC_ERR_ALLOC);
                    status = false;
                    goto done;
                }
                strncpy(p->value, default_user, len+1);
                trim_right(p->value, p->value+len);
            }
            p->next = phead;
            phead = p;
        }
    }
    if (status)
    {
        status = db_read_next_field(pdb, &p, rc);
        p->type = FT_PASSWORD;
        p->next = phead;
        phead = p;
    }
    if (status)
    {
        status = db_read_next_field(pdb, &p, rc);
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

    _Bool status = true;
    PwsDbField *phead = NULL;

    size_t count = 0;
    while (status && ++count < FT_END)
    {
        PwsDbField *pfield = NULL;
        status = db_read_next_field(pdb, &pfield, rc);
        if (status)
        {
            if (pfield->type == FT_END) 
            {
                free_fields(pfield);
                goto done;
            }
            pfield->next = phead;
            phead = pfield;
        }
        else if (count > 1 && *rc == PRC_ERR_EOF)
        {
            // Encountering EOF without reading FT_END field
            // should maybe be an error?
        }
    }
    if (count == FT_END)
    {
        // We've read too many fields for a single record, 
        // something is not right
        set_rc(rc, PRC_ERR_CORRUPT_DB);
    }

done:
    *fields = phead;
    return status;
}

static _Bool db_write_next_v1_record(PwsDb *pdb, const char *name, const char *password, const char *notes, PWS_RESULT_CODE *rc)
{
    assert(pdb);
    assert(name);
    assert(password);
    assert(notes);

    // It would seem that version 1x of Password Safe did not use the 
    // high 32 bits of the block--type is always zero
    _Bool status = db_write_next_field_values(pdb, /*type*/0, name, rc);
    if (status)
    {
        status = db_write_next_field_values(pdb, /*type*/0, password, rc);
    }
    if (status)
    {
        status = db_write_next_field_values(pdb, /*type*/0, notes, rc);
    }
    return status;
}

// Field record that terminates list of fields
static const PwsDbField DB_FIELD_END = {NULL, FT_END, ""};

/**
 * \param extras Field that will be written into the database record
 *               after the fields that are contained in the record
 * \note The `extras` parameter allows us to append missing data into the 
 * database record without modifying the object passed in by the user
*/
static _Bool db_write_next_v2_record(PwsDb *pdb, const PwsDbField* fields, const PwsDbField *extras, PWS_RESULT_CODE *rc)
{
    assert(pdb);
    assert(fields);

    const PwsDbField *field = fields;
    _Bool has_title = false;
    while (field && field->type != FT_END)
    {
        if (field->type == FT_TITLE && strlen(field->value) > 0)
        {
            has_title = true;
        }
        field = field->next;
    }
    if (!has_title)
    {
        set_rc(rc, PRC_ERR_INVALID_ARG);
        return false;
    }

    field = fields;
    while (field)
    {
        if (field->type == FT_END)
        {
            if (field->next != NULL)
            {
                set_rc(rc, PRC_ERR_INVALID_ARG);
                return false;
            }
            break;
        }
        db_write_next_field(pdb, field, rc);
        field = field->next;
    }
    field = extras;
    while (field)
    {
        db_write_next_field(pdb, field, rc);
        field = field->next;
    }
    db_write_next_field(pdb, &DB_FIELD_END, rc);

    set_rc(rc, PRC_SUCCESS);
    return true;
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
        PwsDbRecord *prec = *record;
        if (!prec)
        {
            set_rc(rc, PRC_ERR_ALLOC);
            free_fields(fields);
            return false;
        }
        prec->next = NULL;
        prec->fields = fields;
    }
    else if (*rc == PRC_ERR_EOF)
    {
        free_fields(fields);
        // EOF on first block is not an error
        set_rc(rc, PRC_SUCCESS);
    }
    return status;
}

static _Bool db_write_next_record(PwsDb *pdb, const PwsDbRecord* record, PwsDbField *extras, PWS_RESULT_CODE *rc)
{
    assert(pdb);
    assert(record);

    if (record->fields)
    {
        if (!db_write_next_v2_record(pdb, record->fields, extras, rc))
            return false;
    }

    return true;
}

static _Bool db_write_v2_ident_record(PwsDb *pdb, PWS_RESULT_CODE *rc)
{
    return db_write_next_v1_record(pdb, PWSAFE_V2_NAME_MAGIC, PWSAFE_V2_PASSWORD_MAGIC, "", rc);
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
static _Bool check_invalid_args(_Bool test, PWS_RESULT_CODE *rc)
{
    if (!test)
    {
        set_rc(rc, PRC_ERR_INVALID_ARG);
        return false;
    }
    return true;
}

static _Bool check_hdb(PWSHANDLE hdb, PWS_RESULT_CODE *rc)
{
    PwsDb *pdb = (PwsDb *)hdb;
    if (memcmp(pdb->magic, DB_MAGIC, sizeof(DB_MAGIC)) != 0)
    {
        set_rc(rc, PRC_ERR_INVALID_HANDLE);
        return false;
    }
    return true;
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
    if (!check_invalid_args(pathname && password, rc))
        return false;

    PWS_RESULT_CODE local_rc = PRC_SUCCESS;
    eval_sys_byte_order();

    FILE *f = fopen(pathname, "rb");
    if (!f)
    {
        set_rc(rc, PRC_ERR_OPEN);
        return NULL;
    }

    Header header;

    if (!db_read_header(f, &header, &local_rc))
    {
        return NULL;
    }

    if (!db_check_password(&header, password))
    {
        set_rc(rc, PRC_ERR_INCORRECT_PW);
        return NULL;
    }

    PwsDb *pdb = db_alloc(rc);
    if (pdb)
    {
        pdb->db_file = f;
        memcpy(&pdb->db_header, &header, sizeof(pdb->db_header));

        db_compute_key(pdb, password);
    }

    set_rc(rc, local_rc);
    return pdb;
}

PWSAFE_EXTERN void pws_db_close(PWSHANDLE hdb, PWS_RESULT_CODE *rc)
{
    if (!check_invalid_args(hdb, rc)
        || !check_hdb(hdb, rc))
        return;

    // Trash memory in case client tries to reuse invalid pointer
    PwsDb *pdb = (PwsDb *)hdb;
    db_free(pdb);
}

PWSAFE_EXTERN _Bool pws_db_read_accounts(PWSHANDLE hdb, PwsDbRecord **records, PWS_RESULT_CODE *rc)
{
    if (!check_invalid_args(hdb && records, rc)
        || !check_hdb(hdb, rc))
        return false;

    PWS_RESULT_CODE local_rc = PRC_SUCCESS;
    *records = NULL;

    PwsDb *pdb = (PwsDb *)hdb;
    PwsDbRecord *phead = NULL, *p = NULL;

    if (db_read_next_record(pdb, &p, &local_rc))
    {
        const char *ptitle = rec_get_title(p);
        if (ptitle == NULL)
        {
            // No title field == something is wrong
            set_rc(rc, PRC_ERR_CORRUPT_DB);
            free(p);
            return false;
        }
        if (strcmp(PWSAFE_V2_NAME_MAGIC, ptitle) == 0)
        {
            free_record(p);
            pdb->db_vers = PWSAFE_DB_V2;
            db_read_next_record(pdb, &p, &local_rc);
        }
        else
        {
            pdb->db_vers = PWSAFE_DB_V1;
        }

        phead = p;
        while (db_read_next_record(pdb, &p, &local_rc))
        {
            p->next = phead;
            phead = p;
        };
    }

    *records = phead;
    set_rc(rc, local_rc);
    return true;
}

static _Bool db_ensure_record_has_uuid(PwsDbRecord *rec, PwsDbRecord *records, uint8_t *uuid)
{
    if (rec_get_uuid(rec) == NULL)
    {
        _Bool is_unique = false;
        do
        { 
            if (!generate_random(uuid, 16))
            {
                // It is probably better to write the record
                // without an UUID than to fail.
                // set_rc(rc, PRC_ERR_INIT_RANDOM);
                // return false;
                break;
            }
            PwsDbRecord *r = records;
            while (r != NULL)
            {
                if (r != rec)
                {
                    const char *other_uuid;
                    if ((other_uuid = rec_get_uuid(r)) != NULL && memcmp(uuid, other_uuid, 16) == 0)
                    {
                        break;
                    }
                }
                r = r->next;
            }
            if (r == NULL)
            {
                is_unique = true;
            }
        } while (!is_unique);

        return true;
    }
    return false;
}

PWSAFE_EXTERN _Bool pws_db_write(const char *pathname,
    const char *password, PwsDbRecord *records, PWS_RESULT_CODE *rc)
{
    if (!check_invalid_args(pathname && password, rc))
        return false;

    PWS_RESULT_CODE local_rc = PRC_SUCCESS;
    eval_sys_byte_order();

    FILE * f = fopen(pathname, "wb");
    if (!f)
    {
        set_rc(rc, PRC_ERR_OPEN);
        return false;
    }

    _Bool status = false;
    PwsDb pdb;
    init_pdb(&pdb);
    pdb.db_vers = PWSAFE_DB_V2;
    pdb.db_file = f;

    if (!db_init_header(&pdb.db_header, password, &local_rc)
        || !db_write_header(&pdb, rc))
    {
        goto done;
    }

    db_compute_key(&pdb, password);

    // No need to write if database is empty
    if (records != NULL)
    {
        if (!db_write_v2_ident_record(&pdb, &local_rc))
        {
            goto done;
        }
    }

    PwsDbRecord *rec = records;
    while (rec != NULL)
    {
        PwsDbField *extras = NULL;
        uint8_t uuid[17];
        uuid[16] = 0;
        PwsDbField uuid_field = {
            NULL,
            FT_UUID,
            (char *)uuid
        };

        if (db_ensure_record_has_uuid(rec, records, uuid))
        {
            extras = &uuid_field;
        }

        if (!db_write_next_record(&pdb, rec, extras, &local_rc))
        {
            goto done;
        }
        rec = rec->next;
    }

    memset_func(&pdb, 0, sizeof(PwsDb));
    status = true;

done:
    fclose(f);
    set_rc(rc, local_rc);
    return status;
}