/* Copyright 2023 Ian Boisvert */
#ifndef HAVE_PWSAFE_H
#define HAVE_PWSAFE_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum PwsResultCode {
    PRC_SUCCESS = 0,
    PRC_ERR_FAIL,  // Generic failure
    PRC_ERR_OPEN,  // File open error, check `errno`
    PRC_ERR_INCORRECT_PW,  // Incorrect password supplied to open database
    PRC_ERR_INVALID_ARG,  // Invalid function argument
    PRC_ERR_CORRUPT_DB,  // Database file is corrupt
    PRC_ERR_READ,  // An error occurred while reading the database, check `errno`
    PRC_ERR_WRITE,  // An error occurred while writing the database, check `errno`
    PRC_ERR_ALLOC,  // An error occurred allocating memory, check `errno`
    PRC_ERR_INIT_RANDOM,  // An error occurred generating random data to initialize the database header
    PRC_ERR_EOF,  // End-of-file encountered while reading
} PwsResultCode;

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
    FT_URL = 0x0d,
    FT_EMAIL = 0x14,
    FT_FILEPATH = 0x65,
    FT_END = 0xff
} PwsFieldType;

typedef struct PwsDbField
{
    struct PwsDbField *next;
    uint8_t type;
    char *value;
} PwsDbField;

typedef struct PwsDbRecord
{
    struct PwsDbRecord *next;
    PwsDbField *fields;
} PwsDbRecord;

#ifndef PWSAFE_EXTERN
#define PWSAFE_EXTERN extern
#endif

/** Get libpwsafe version */
PWSAFE_EXTERN const char *pws_get_version();

/**
 * Get a specific field from a database record
 * \returns The field value, `NULL` if the field does not exist in the record.
*/
PWSAFE_EXTERN const char *pws_rec_get_field(const PwsDbRecord *record, PwsFieldType ft);

/**
 * Free memory that has been allocated for a returned value
*/
PWSAFE_EXTERN void pws_free_db_records(PwsDbRecord *p);

/**
 * Check if `password` unlocks the account database at `pathname`
 * \param [in] pathname The pathname of the account database
 * \param [in] password The database password
 * \param[out] rc Optional result code, set if operation fails.
 * \returns `true` if password is correct, `false` otherwise.
 */
PWSAFE_EXTERN _Bool pws_db_check_password(const char *pathname, const char *password, int *rc);

/**
 * Open a Password Safe database file and read the database header.
 * \param [in] pathname The pathname of the account database
 * \param [in] password The database password
 * \param[out] records Linked list of records read from database
 * \param[out] rc Optional result code, set if operation fails.
 * \returns `true` if operation succeeded, `false` otherwise
 */
PWSAFE_EXTERN _Bool pws_db_read(const char *pathname, const char *password, PwsDbRecord **records, int *rc);

/**
 * Write a new Password Safe v2 database
 * \param[in] pathname The pathname of the account database
 * \param[in] password The database password
 * \param[in] records Optional account records to write to the database.
 *                    If `records` is `NULL` an empty database will be created.
 * \param[out] rc Optional result code, set if operation fails.
 * \returns `true` if operation succeeded, `false` otherwise
 * \note
 * If the file `pathname` already exists, it will be overwritten.
 * \note
 * All account fields, including those not recognized, will be written.
 * Fields for which `value` is `NULL` will be silently ignored.
 * \note
 * It is not necessary to terminate the fields of a record with
 * a field of type `FT_END`. If a field of type `FT_END` is present
 * and `next` is not `NULL`, the function will return `false`
 * and `rc` will be set to `PWS_ERR_INVALID_ARG`.
 * \note
 * The "default user character" from Password Safe 1.x 
 * is not respected in the FT_NAME field.
 * \note
 * If the `FT_TITLE` field is not present or is empty,
 * the function will return `false`
 * and `rc` will be set to `PWS_ERR_INVALID_ARG`.
 */
PWSAFE_EXTERN _Bool pws_db_write(const char *pathname,
    const char *password, PwsDbRecord *records, int *rc);

#ifdef  __cplusplus
}
#endif

#endif //#ifndef HAVE_PWSAFE_H