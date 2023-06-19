/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include "pwsafe_priv.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
#include <nettle/sha2.h>

// IMB 2023-01-01 Most of the code here is
// adapted from code by Nicolas Dade https://github.com/nsd20463/pwsafe

// Prevent memset from being optimized out
volatile fmemset memset_func = memset;

static const char * const PWSAFE_V2_NAME_MAGIC = 
    " !!!Version 2 File Format!!! Please upgrade to PasswordSafe 2.0 or later";
static const char * const PWSAFE_V2_PASSWORD_MAGIC = "2.0";

static const int MAX_RECORD_COUNT = 1000000;  // For sanity checks

// Forward decls
static PwsDbField *alloc_field(uint8_t type, char *value);
static void free_fields(PwsDbField *p);

const char *pws_get_version()
{
    return LIBPWSAFE_VERSION;
}

static inline void set_rc(int *prc, int rc)
{
    if (prc) *prc = rc;
}

static void init_pdb(PwsDb *pdb)
{
    pdb->db_vers = -1;
    pdb->db_file = NULL;
    memset_func(&pdb->db_header, 0, sizeof(Header));
}

PwsDbRecord *alloc_record()
{
    PwsDbRecord *p = malloc(sizeof(PwsDbRecord));
    if (p)
    {
        p->next = NULL;
        p->fields = NULL;
    }
    return p;
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
        if (p->value)
        {
            size_t len = strlen(p->value);
            memset_func(p->value, 0, len);
            free(p->value);
        }
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

static _Bool db_read_header(FILE *f, Header *h, int *rc)
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

static _Bool db_write_header(PwsDb *pdb, int *rc)
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
_Bool db_init_header(Header *h, const char *pw, int *rc)
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

_Bool db_check_password(Header *h, const char *pw, int *rc)
{
    unsigned char test_hash[SHA1_DIGEST_SIZE];
    generate_hash(h->random, test_hash, pw);

    _Bool equal = memcmp(test_hash, h->hash, sizeof(h->hash)) == 0 ? true : false;

    memset_func(test_hash, 0, sizeof(test_hash));

    if (!equal)
        set_rc(rc, PRC_ERR_INCORRECT_PW);

    return equal;
}

const char *pws_rec_get_field(const PwsDbRecord *record, PwsFieldType ft)
{
    assert(record);
    const PwsDbField *field = record->fields;
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
static inline const char *rec_get_title(const PwsDbRecord *record)
{
    return pws_rec_get_field(record, FT_TITLE);
}
static inline const char *rec_get_uuid(const PwsDbRecord *record)
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

static _Bool db_read_block(PwsDb *pdb, Block block, int *rc)
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

static _Bool db_write_block(PwsDb *pdb, Block block, int *rc)
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

static _Bool db_read_next_field(PwsDb *pdb, PwsDbField **field, int *rc)
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
            if (rc && *rc == PRC_ERR_EOF)
            {
                set_rc(rc, PRC_ERR_CORRUPT_DB);
            }
            return false;
        }
        memcpy(str + i * BLOCK_SIZE, block, BLOCK_SIZE);
    }
    str[len] = 0;

    // UUID is stored in the database in binary,
    // convert to text for convenience
    if (type == FT_UUID)
    {
        char *uuid = realloc(str, 33);
        if (!uuid)
        {
            free(str);
            set_rc(rc, PRC_ERR_ALLOC);
            return false;
        }
        uuid_bin_to_hex((unsigned char *)uuid, uuid);
        str = uuid;
        str[32] = 0;
    }

    *field = alloc_field(type, str);
    if (!*field)
    {
        set_rc(rc, PRC_ERR_ALLOC);
        free(str);
        return false;
    }

    return true;
}

static _Bool db_write_next_field_values(PwsDb *pdb, const PwsFieldType type, const char *value, int *rc)
{
    assert(pdb);
    assert(value);

    if (!value) return true;

    const uint32_t len = (type == FT_UUID) ? 16 : (uint32_t)strlen(value);

    Block block;
    make_block_le(block, type, len);
    
    if (!db_write_block(pdb, block, rc))
        return false;

    const char *p = NULL;

    // UUID is stored in the database in binary,
    // convert from text
    char uuid[16];
    if (type == FT_UUID)
    {
        uuid_hex_to_bin(value, (unsigned char *)uuid);
        p = uuid;
    }
    else
    {
        p = value;
    }

    const char *pend = p + len;
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

static _Bool db_write_next_field(PwsDb *pdb, const PwsDbField *field, int *rc)
{
    return db_write_next_field_values(pdb, field->type, field->value, rc);
}

static const char SPLIT_CHAR = '\xAD';
static const char DEFAULT_USER_CHAR = '\xA0';

static _Bool db_read_next_v1_record(PwsDb *pdb, PwsDbField** fields, int *rc)
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

static _Bool db_read_next_v2_record(PwsDb *pdb, PwsDbField** fields, int *rc)
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

static _Bool db_write_next_v1_record(PwsDb *pdb, const char *name, const char *password, const char *notes, int *rc)
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
static _Bool db_write_next_v2_record(PwsDb *pdb, const PwsDbField* fields, const PwsDbField *extras, int *rc)
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

static _Bool db_read_next_record(PwsDb *pdb, PwsDbRecord** record, int *rc)
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
        *record = alloc_record();
        PwsDbRecord *prec = *record;
        if (!prec)
        {
            set_rc(rc, PRC_ERR_ALLOC);
            free_fields(fields);
            return false;
        }
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

static _Bool db_write_next_record(PwsDb *pdb, const PwsDbRecord* record, PwsDbField *extras, int *rc)
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

static _Bool db_write_v2_ident_record(PwsDb *pdb, int *rc)
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
static _Bool check_invalid_args(_Bool test, int *rc)
{
    if (!test)
    {
        set_rc(rc, PRC_ERR_INVALID_ARG);
        return false;
    }
    return true;
}

static _Bool check_invalid_uuid(PwsDbRecord *prec, int *rc)
{
    while (prec != NULL)
    {
        const char *value = pws_rec_get_field(prec, FT_UUID);
        if (value)
        {
            size_t len = strlen(value);
            if (len != 32)
            {
                set_rc(rc, PRC_ERR_INVALID_ARG);
                return false;
            }
            for (size_t i = 0; i < len; ++i)
            {
                if (!isxdigit(value[i]))
                {
                    set_rc(rc, PRC_ERR_INVALID_ARG);
                    return false;
                }
            }
        }
        prec = prec->next;
    }
    return true;
}

PWSAFE_EXTERN int pws_db_record_count(PwsDbRecord * const records)
{
    int count = 0;
    PwsDbRecord *record = records;
    while (record && count < MAX_RECORD_COUNT)
    {
        ++count;
        record = record->next;
    }
    if (count == MAX_RECORD_COUNT) count = -1;
    return count;
}

PWSAFE_EXTERN void pws_free_db_records(PwsDbRecord *p)
{
    while (p != NULL)
    {
        PwsDbRecord *pnext = p->next;
        p->next = NULL;
        free_record(p);
        p = pnext;
    }
}

/**
 * Check if `password` unlocks the account database at `pathname`
 * \param [in] pathname The pathname of the account database
 * \param [in] password The database password
 * \param[out] rc Optional result code, set if operation fails.
 * \returns `true` if password is correct, `false` otherwise.
 */
PWSAFE_EXTERN int pws_db_check_password(const char *pathname, const char *password, int *rc)
{
    if (!check_invalid_args(pathname && password, rc))
        return false;

    int local_rc = PRC_SUCCESS;
    eval_sys_byte_order();

    FILE *f = fopen(pathname, "rb");
    if (!f)
    {
        set_rc(rc, PRC_ERR_OPEN);
        return false;
    }

    Header header;

    _Bool status = db_read_header(f, &header, &local_rc)
        && db_check_password(&header, password, &local_rc);

    fclose(f);

    set_rc(rc, local_rc);
    return status;
}

_Bool db_read_accounts(PwsDb *pdb, PwsDbRecord **records, int *rc)
{
    int local_rc = PRC_SUCCESS;
    *records = NULL;

    PwsDbRecord *phead = NULL, *p = NULL;

    // Read the first record to check for the V2 magic
    bool status = db_read_next_record(pdb, &p, &local_rc);
    if (status)
    {
        const char *ptitle = rec_get_title(p);
        if (ptitle != NULL)
        {
            if (strcmp(PWSAFE_V2_NAME_MAGIC, ptitle) == 0)
            {
                // V2 database, free the record and read the next
                free_record(p);
                pdb->db_vers = PWSAFE_DB_V2;
                status = db_read_next_record(pdb, &p, &local_rc);
            }
            else
            {
                pdb->db_vers = PWSAFE_DB_V1;
            }
        }
    }

    while (status)
    {
        const char *ptitle = rec_get_title(p);
        if (ptitle == NULL)
        {
            // No title field == something is wrong
            set_rc(rc, PRC_ERR_CORRUPT_DB);
            free(p);
            return false;
        }

        p->next = phead;
        phead = p;

        status = db_read_next_record(pdb, &p, &local_rc);
    }

    *records = phead;
    set_rc(rc, local_rc);
    return true;
}

static _Bool db_ensure_record_has_uuid(PwsDbRecord *rec, PwsDbRecord *records, char *uuid)
{
    if (rec_get_uuid(rec) == NULL)
    {
        _Bool is_unique = false;
        do
        {
            if (!generate_random((unsigned char *)uuid, 16))
            {
                // It is probably better to write the record
                // without an UUID than to fail.
                // set_rc(rc, PRC_ERR_INIT_RANDOM);
                // return false;
                break;
            }
            uuid_bin_to_hex((unsigned char *)uuid, uuid);
            uuid[32] = 0;
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

_Bool db_open(const char *pathname, const char *password, struct PwsDb *pdb, int *rc)
{
    int local_rc = PRC_SUCCESS;

    FILE *f = fopen(pathname, "rb");
    if (!f)
    {
        set_rc(rc, PRC_ERR_OPEN);
        return false;
    }

    Header header;
    
    _Bool status = db_read_header(f, &header, &local_rc)
        && db_check_password(&header, password, &local_rc);
    if (!status)
    {
        fclose(f);
        goto done;
    }

    init_pdb(pdb);
    pdb->db_file = f;
    memcpy(&pdb->db_header, &header, sizeof(pdb->db_header));

    db_compute_key(pdb, password);

done:
    set_rc(rc, local_rc);
    return status;
}

PWSAFE_EXTERN int pws_db_read(const char *pathname, const char *password, PwsDbRecord **records, int *rc)
{
    if (!check_invalid_args(pathname && password && records, rc))
        return false;

    eval_sys_byte_order();

    int local_rc = PRC_SUCCESS;
    _Bool status;

    PwsDb pdb;
    status = db_open(pathname, password, &pdb, &local_rc);
    if (status)
    {
    status = db_read_accounts(&pdb, records, &local_rc);

        fclose(pdb.db_file);
        pdb.db_file = NULL;
    }

    set_rc(rc, local_rc);
    return status;
}

PWSAFE_EXTERN int pws_db_write(const char *pathname,
    const char *password, PwsDbRecord *records, int *rc)
{
    if (!check_invalid_args(pathname && password, rc))
        return false;

    if (!check_invalid_uuid(records, rc))
        return false;

    int local_rc = PRC_SUCCESS;
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
        char uuid[33];
        uuid[32] = 0;
        PwsDbField uuid_field = {
            NULL,
            FT_UUID,
            uuid
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