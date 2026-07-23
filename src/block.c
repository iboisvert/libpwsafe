/* Copyright 2023 Ian Boisvert */
#include "pwsafe_priv.h"

// Byte ordering
// inline uint32_t identity(uint32_t val) { return val; }
// inline uint32_t be_to_le(uint32_t val) { return pws_bswap32(val); }
// typedef uint32_t (*fboswap)(uint32_t);
// static fboswap host_to_le = identity;

// Portable 32-bit byte swap
#if defined(_MSC_VER)
#  include <stdlib.h>
#  define pws_bswap32(x) _byteswap_ulong(x)
#elif defined(__GNUC__) || defined(__clang__)
#  define pws_bswap32(x) __builtin_bswap32(x)
#else
static inline uint32_t pws_bswap32(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8)
         | ((x & 0x00FF0000u) >> 8) | ((x & 0xFF000000u) >> 24);
}
#endif

/** Swap block byte order le<=>be */
void swap_byte_order(Block b)
{
    uint32_t *l = (uint32_t *)(b), *h = (uint32_t *)(b + 4);
    *l = pws_bswap32(*l);
    *h = pws_bswap32(*h);
}

/** Make a block composed of two little-endian unsigned ints */
void make_block_le(Block b, uint32_t h, uint32_t l)
{
    *(uint32_t *)(b) = l;
    *(uint32_t *)(b+4) = h;
    if (sys_byte_order == SBE_BIG_ENDIAN)
        swap_byte_order(b);
}

/** Convert a little-endian block to the system byte order */
void block_le_to_sys(Block b)
{
    if (sys_byte_order == SBE_BIG_ENDIAN)
        swap_byte_order(b);
}

void zero_block(Block block)
{
    memset_func(block, 0, BLOCK_SIZE);
}
