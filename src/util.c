/* Copyright 2023 Ian Boisvert */
#include "pwsafe_priv.h"
#include <assert.h>
#include <stdlib.h>
#ifdef HAVE_PWUID
#include <sys/types.h>
#include <pwd.h>
#endif
#include <unistd.h>

enum SYS_BYTE_ORDER sys_byte_order;

/**
 * Detect system byte order
 * Can only detect little- and big-endian
*/
void eval_sys_byte_order()
{
    uint16_t word = 0x0001;
    if (*(uint8_t*)&word)
        sys_byte_order = SBE_LITTLE_ENDIAN;
    else
        sys_byte_order = SBE_BIG_ENDIAN;
}

_Bool is_ws(const char c)
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

const char *get_default_user()
{
    const char *dl = getenv("PWSAFE_DEFAULT_USER");
    if (!dl)
    {
        dl = getenv("USER");
        if (!dl)
        {
            dl = getenv("LOGNAME");
#ifdef HAVE_PWUID
            if (!dl)
            {
                // fine, we'll go get LOGNAME from the pwdatabase
                const struct passwd *const pw = getpwuid(getuid());
                if (pw)
                {
                    dl = pw->pw_name;
                }
            }
#endif
        }
    }
    if (!dl)
    {
        // no USER, no LOGNAME, no /etc/passwd entry for this UID; they're on their own now
        dl = "";
    }
    return dl;
}
