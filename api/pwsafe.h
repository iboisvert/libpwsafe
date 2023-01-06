/* Copyright 2023 Ian Boisvert */
#pragma once

#include <stdio.h>
#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    PWSAFE_DB_V1,
    PWSAFE_DB_V2,
} PWS_DB_VERSION;

typedef enum {
    PWS_SUCCESS = 0,
    PWS_ERR_FAIL,  // Generic failure
    PWS_ERR_OPEN,  // File open error, check `errno`
    PWS_ERR_INCORRECT_PW,  // Incorrect password supplied to open database
    PWS_ERR_INVALID_ARG,  // Invalid function argument
    PWS_ERR_INVALID_HANDLE,  // Invalid handle
    PWS_ERR_CORRUPT_DB,  // Database file is corrupt
    PWS_ERR_READ  // A read error occurred while reading the database, check `errno`
} PWS_RESULT_CODE;

// future fields: CTIME = 0x7, MTIME = 0x8, ATIME = 0x9, LTIME = 0xa, POLICY = 0xb,
typedef enum
{
    FT_NAME = 0,
    FT_UUID = 0x1,
    FT_GROUP = 0x2,
    FT_TITLE = 0x3,
    FT_USER = 0x4,
    FT_NOTES = 0x5,
    FT_PASSWORD = 0x6,
    FT_END = 0xff
} PWS_FIELD_TYPE;

#define PWSAFE_EXTERN

#define PWSHANDLE void *

/**
 * Open a Passwordsafe database file and reads the database header.
 * \param [in] pathname The pathname of the account database
 * \param [in] password The database password
 * \param [out] rc Optional result code, > 0 if operation failed
 * \returns Database handle if successful, `NULL` otherwise.
 * \note
 * pws_db_close() must be called on the handle that is returned.
 * \see pws_db_close()
 */
PWSAFE_EXTERN PWSHANDLE pws_db_open(const char *pathname, const char *password, PWS_RESULT_CODE *rc);

/**
 * Close the database and release resources. 
 * Handle `hdb` is invalid after calling this function.
 * \param [in] hdb Database handle
 * \param [out] rc Optional result code, > 0 if operation failed.
 * \see pws_db_open()
*/
PWSAFE_EXTERN void pws_db_close(PWSHANDLE hdb, PWS_RESULT_CODE *rc);

/**
 * Check if password is correct to unlock database.
 * \param[in] hdb Database handle
 * \param[in] password The database password
 * \returns `true` if password is correct, `false` otherwise.
 * \see pws_db_open()
*/
PWSAFE_EXTERN _Bool pws_db_check_password(PWSHANDLE hdb, const char *password);

/**
 * Read all accounts from the database
 * \param[in] hdb Database handle
 * \param[out] rc Optional result code, > 0 if operation failed.
 * \returns `true` if operation succeeded, `false` otherwise
 * \see pws_db_open()
*/
PWSAFE_EXTERN _Bool pws_db_read_accounts(PWSHANDLE hdb, PWS_RESULT_CODE *rc);

/**
 * Create a new PasswordSafe database
 * \param[in] version Version of the database format to create.
 *                    Recommended value is `PWSAFE_DB_V2`.
 *                    If `PWSAFE_DB_V1` is used data may be lost--see Note below
 * \param[in] pathname The pathname of the account database
 * \param[in] password The database password
 * \param[out] rc Optional result code, > 0 if operation failed
 * \returns `true` if operation succeeded, `false` otherwise
 * \note
 * If `version` is set to `PWSAFE_DB_V1` and input fields containing data
 * are ignored when writing the database, the operation will succeed,
 * but the result code will be set to `PWS_WARN_DATA_LOST`.
 * \note
 * pws_db_close() must be called on the handle that is returned.
 * \see pws_db_close()
 */
PWSAFE_EXTERN _Bool pws_db_create(PWS_DB_VERSION version, const char *pathname,
    const char *password, PWS_RESULT_CODE *rc);

#ifdef  __cplusplus
}
#endif
