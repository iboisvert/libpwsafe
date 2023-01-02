/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include <stdlib.h>

PWSAFE_EXTERN PWSHANDLE pws_open_db(const char *pathname, const char *password, PWS_RESULT_CODE *rc)
{
    if (rc) *rc = FAILURE;
    PWSHANDLE retval = NULL;

    return retval;
}