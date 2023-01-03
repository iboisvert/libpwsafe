/* Copyright 2023 Ian Boisvert */
#pragma once

#include <stdio.h>
#include <stdbool.h>

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
    PWS_SUCCESS = 0,
    PWS_ERR_FAIL,  // Generic failure
    PWS_ERR_OPEN,  // File open error, check `errno`
    PWS_ERR_INVALID_ARG,  // Invalid function argument
    PWS_ERR_INVALID_HANDLE,  // Invalid handle
} PWS_RESULT_CODE;

#define PWSAFE_EXTERN

#define PWSHANDLE void *

/**
 * Open a Passwordsafe database file and reads the database header.
 * \param [in] pathname The pathname of the account database
 * \param [in] password The database password
 * \param [out] rc Optional result code, > 0 if operation failed
 * \returns Database handle if successful, `NULL` otherwise.
 * \remarks
 * pws_db_close() must be called on the handle that is returned.
*/
PWSAFE_EXTERN PWSHANDLE pws_db_open(const char *pathname, const char *password, PWS_RESULT_CODE *rc);

/**
 * Close the database and release resources. 
 * Handle `hdb` is invalid after calling this function.
 * \param [in] hdb Handle allocated by pws_db_open().
 * \param [out] rc Optional result code, > 0 if operation failed.
*/
PWSAFE_EXTERN void pws_db_close(PWSHANDLE hdb, PWS_RESULT_CODE *rc);

PWSAFE_EXTERN _Bool pws_db_check_password(PWSHANDLE hdb, const char *password);

PWSAFE_EXTERN PWS_DB_VERSION pws_db_version(PWSHANDLE db_handle);

#ifdef  __cplusplus
}
#endif
