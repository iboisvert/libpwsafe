/* Copyright 2023 Ian Boisvert */
#include "pwsafe_priv.h"

// Byte ordering
// inline uint32_t identity(uint32_t val) { return val; }
// inline uint32_t be_to_le(uint32_t val) { return __builtin_bswap32(val); }
// typedef uint32_t (*fboswap)(uint32_t);
// static fboswap host_to_le = identity;

/** Swap block byte order le<=>be */
void swap_byte_order(Block b)
{
    uint32_t *l = (uint32_t *)(b), *h = (uint32_t *)(b + 4);
    *l = __builtin_bswap32(*l);
    *h = __builtin_bswap32(*h);
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
