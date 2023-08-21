/** \file pwsafe.h
 *  Copyright 2023 Ian Boisvert 
 */
#ifndef HAVE_PWSAFE_H
#define HAVE_PWSAFE_H

#include <stdio.h>
#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

/** \brief Result codes returned from API functions. */
typedef enum PwsResultCode {
    PRC_SUCCESS = 0,  ///< Generic success
    PRC_ERR_FAIL,  ///< Generic failure
    PRC_ERR_OPEN,  ///< File open error, check `errno`
    PRC_ERR_INCORRECT_PW,  ///< Incorrect password supplied to open database
    PRC_ERR_INVALID_ARG,  ///< Invalid function argument
    PRC_ERR_CORRUPT_DB,  ///< Database file is corrupt
    PRC_ERR_READ,  ///< An error occurred while reading the database, check `errno`
    PRC_ERR_WRITE,  ///< An error occurred while writing the database, check `errno`
    PRC_ERR_ALLOC,  ///< An error occurred allocating memory, check `errno`
    PRC_ERR_INIT_RANDOM,  ///< An error occurred generating random data to initialize the database header
    PRC_ERR_EOF,  ///< End-of-file encountered while reading
} PwsResultCode;

// future fields: CTIME = 0x7, MTIME = 0x8, ATIME = 0x9, LTIME = 0xa, POLICY = 0xb,
/** \brief Password Safe database field types */
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

/** \brief Linked-list of record fields. */
typedef struct PwsDbField
{
    struct PwsDbField *next;  ///< Next field in list
    uint8_t type;  ///< Type of field, see PwsFieldType
    char *value;  ///< Field value, `NULL`-terminated string
} PwsDbField;

/** \brief Linked-list of database records. */
typedef struct PwsDbRecord
{
    struct PwsDbRecord *next;  ///< Next record in list
    PwsDbField *fields;  ///< List of fields owned by the record
} PwsDbRecord;

#ifndef PWSAFE_EXTERN
#define PWSAFE_EXTERN extern
#endif

/** 
 * \brief Get libpwsafe version 
 */
PWSAFE_EXTERN const char *pws_get_version();

/**
 * \brief Allocate a new empty account record.
 * 
 * This function behaves exactly the same as calling
 * `pws_add_record(NULL)`
 * \note
 * Caller must call `pws_free_db_records()` to release memory.
 */
PWSAFE_EXTERN PwsDbRecord *pws_new_record();

/**
 * Generate a UUID for an account record.
 * \param[out] uuid An array of at least 33 characters into which is copied 
 *   the UUID as a hex string of 32 character. The string is `NULL`-terminated. 
 * \returns `PRC_ERR_FAIL` if an error occurred generating UUID, otherwise `PRC_SUCCESS`.
*/
PWSAFE_EXTERN int pws_generate_uuid(char uuid[33]);

/**
 * \brief Allocate a new empty account record and
 *        insert it at the head of the linked list of account records
 * \param[in] head Pointer to the head of the linked list of account records. Optional.
 * \returns Pointer to the head of the linked list of account records
 * \note
 * Caller must call `pws_free_db_records()` to release memory.
 */
PWSAFE_EXTERN PwsDbRecord *pws_add_record(PwsDbRecord *records);

/**
 * \brief Allocate a new field and add it to the account record
 * \returns Pointer to the allocated field, 
 *          or `NULL` if `records` is NULL, `field_type` is invalid, or `value` is `NULL`.
 * \note
 * Caller must call `pws_free_db_records()` to release memory.
 */
PWSAFE_EXTERN PwsDbField *pws_add_field(PwsDbRecord *record, PwsFieldType field_type, const char *value);

/**
 * \brief Get a specific field from an account database record
 * \returns The field value, `NULL` if the field does not exist in the record.
*/
PWSAFE_EXTERN const char *pws_rec_get_field(const PwsDbRecord *record, PwsFieldType field_type);

/** 
 * \brief Free memory that has been allocated for a returned value
 * \param[in] records Pointer to the head of the linked list of account records
 */
PWSAFE_EXTERN void pws_free_db_records(PwsDbRecord *records);

/**
 * \brief Check if `password` unlocks the account database at `pathname`
 * \param [in] pathname The pathname of the account database
 * \param [in] password The database password
 * \param[out] rc Optional result code, set if operation fails.
 * \returns `true` if password is correct, `false` otherwise.
 */
PWSAFE_EXTERN int pws_db_check_password(const char *pathname, const char *password, int *rc);

/**
 * \brief Open a Password Safe database file and read the database header.
 * \param [in] pathname The pathname of the account database
 * \param [in] password The database password
 * \param[out] records Linked list of records read from database
 * \param[out] rc Optional result code, set if operation fails.
 * \returns `true` if operation succeeded, `false` otherwise
 * \note
 * Fields of type `FT_UUID` have form `0123456789ABCDEF0123456789ABCDEF`
 */
PWSAFE_EXTERN int pws_db_read(const char *pathname, const char *password, PwsDbRecord **records, int *rc);

/**
 * \brief Return number of records in linked list
 * \returns < 0 if error occurred (e.g. circular linked list)
 */
PWSAFE_EXTERN int pws_db_record_count(const PwsDbRecord *records);

/**
 * \brief Write a new Password Safe v2 database
 *
 * All account fields, including those not recognized, will be written.
 * Fields for which `value` is `NULL` will be silently ignored.
 *
 * A field of type `FT_UUID` with a unique value will be generated 
 * for any record that does not already contain this field.
 * \param[in] pathname The pathname of the account database
 * \param[in] password The database password
 * \param[in] records Optional account records to write to the database.
 *                    If `records` is `NULL` an empty database will be created.
 * \param[out] rc Optional result code, set if operation fails.
 * \returns `true` if operation succeeded, `false` otherwise
 * \note
 * If the file `pathname` already exists, it will be overwritten.
 * \note
 * It is not necessary to terminate the fields of a record with
 * a field of type `FT_END`. If a field of type `FT_END` is present
 * and `next` is not `NULL`, the function will return `false`
 * and `rc` will be set to `PWS_ERR_INVALID_ARG`.
 * \note
 * If the `FT_TITLE` field is not present or is empty,
 * the function will return `false`
 * and `rc` will be set to `PWS_ERR_INVALID_ARG`.
 * \note
 * If any record has a field of type `FT_UUID` with a value that is not of 
 * form `0123456789ABCDEF0123456789ABCDEF`, the function will return `false`
 * and `rc` will be set to `PWS_ERR_INVALID_ARG`.
 * \note
 * The "default user character" from Password Safe 1.x 
 * is not respected in the FT_NAME field.
 */
PWSAFE_EXTERN int pws_db_write(const char *pathname,
    const char *password, PwsDbRecord *records, int *rc);

#ifdef  __cplusplus
}
#endif

#endif //#ifndef HAVE_PWSAFE_H