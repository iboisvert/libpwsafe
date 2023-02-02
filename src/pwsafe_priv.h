/* Copyright 2023 Ian Boisvert */
#ifndef HAVE_PWSAFE_PRIV_H
#define HAVE_PWSAFE_PRIV_H

#include "config.h"
#include <nettle/sha1.h>
#include <nettle/blowfish.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

// Prevent memset from being optimized out
typedef void *(*fmemset)(void *, int, size_t);
extern volatile fmemset memset_func;

// Byte order of system on which we're running
// Evaluated at runtime
enum SYS_BYTE_ORDER {
    SBE_LITTLE_ENDIAN,  // Little-endian
    SBE_BIG_ENDIAN  // Big-endian
};
extern enum SYS_BYTE_ORDER sys_byte_order;

/**
 * Detect system byte order
 * Can only detect little- and big-endian
*/
void eval_sys_byte_order();

typedef uint8_t Block[8];
static const size_t BLOCK_SIZE = sizeof(Block);

typedef enum {
    PWSAFE_DB_V1,
    PWSAFE_DB_V2,
} PWSAFE_DB_VERSION;

typedef struct Header
{
    Block random;  // Always little-endian
    uint8_t hash[SHA1_DIGEST_SIZE]; // 20
    uint8_t salt[SHA1_DIGEST_SIZE]; // 20
    Block iv;  // Always little-endian
} Header;

typedef struct PwsDb
{
    FILE *db_file;
    Header db_header;
    PWSAFE_DB_VERSION db_vers;
    struct blowfish_ctx bf_ctx;
    Block cbc;  // Always little-endian
} PwsDb;

/** Swap block byte order le--be */
void swap_byte_order(Block b);
/** Make a block composed of two little-endian unsigned ints */
void make_block_le(Block b, uint32_t h, uint32_t l);
/** Convert a little-endian block to the system byte order */
void block_le_to_sys(Block b);
/** Write zeros to block */
void zero_block(Block block);

/**
 * Initialize a new database header
 */
extern _Bool db_init_header(struct Header *h, const char *pw, int *rc);
extern _Bool db_check_password(struct Header *h, const char *pw, int *rc);
extern void db_encode_block(struct PwsDb *pdb, Block block);
extern void db_decode_block(struct PwsDb *pdb, Block block);

extern const char *trim_right(const char *pbegin, char *pend);
extern _Bool is_ws(const char c);

extern const char *get_default_user();

#ifdef __cplusplus
}
#endif

#endif // #ifndef HAVE_PWSAFE_PRIV_H