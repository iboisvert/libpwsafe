/* Copyright 2023 Ian Boisvert */
#pragma once

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    V1,
    V2,
    V3,
    V4
} PWS_DB_VERSION;

typedef enum {
    SUCCESS = 0,
    FAILURE = 1
} PWS_RESULT_CODE;

#define PWSAFE_EXTERN

#define PWSHANDLE void *

/**
 * Open a Passwordsafe database
 * \param pathname The pathname of the account database
 * \param password The password to unlock the database
 * \param rc Result code, > 0 if operation failed.
 * \returns Database handle if successful, `NULL` otherwise.
*/
PWSAFE_EXTERN PWSHANDLE pws_open_db(const char *pathname, const char *password, PWS_RESULT_CODE *rc);

PWSAFE_EXTERN PWS_DB_VERSION pws_db_version(PWSHANDLE db_handle);

#ifdef  __cplusplus
}
#endif
