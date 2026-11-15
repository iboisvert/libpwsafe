/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include "pwsafe_priv.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#ifdef _WIN32
// MSVC has no POSIX setenv/unsetenv; emulate with _putenv_s.
// Setting a variable to "" removes it from the environment on Windows.
static int setenv(const char *name, const char *value, int overwrite)
{
    if (!overwrite && getenv(name)) return 0;
    return _putenv_s(name, value);
}
static int unsetenv(const char *name)
{
    return _putenv_s(name, "");
}
#endif

TEST(Test, Version)
{
    ASSERT_STREQ(LIBPWSAFE_VERSION, pws_get_version());
}

TEST(Test, ByteOrderIsSupported)
{
    const uint32_t dw = 0x00000001;
    const char *pdw = (const char *)&dw;
    EXPECT_TRUE(pdw[0] || pdw[3]);
}

TEST(Test, UuidBinToHex)
{
    uint8_t uuid[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    char suuid[33] = "0";
    suuid[32] = 0;
    uuid_bin_to_hex(uuid, suuid, 16);
    EXPECT_STREQ("0123456789ABCDEF0123456789ABCDEF", suuid);
}

TEST(Test, UuidHexToBin)
{
    char suuid[] = "0123456789abcdef0123456789abcdef";
    uint8_t uuid[16] = {0};
    uuid_hex_to_bin(suuid, uuid, 16);
    EXPECT_EQ(0, memcmp("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef", uuid, 16));
}

TEST(Test, TrimRight)
{
    std::string s{"\n\r\t "};
    EXPECT_STREQ("", trim_right(s.data(), s.data() + s.length()));
    s = "abc";
    EXPECT_STREQ("abc", trim_right(s.data(), s.data() + s.length()));
}

TEST(Test, GetDefaultUserSucceeds)
{
    const char *save_PWSAFE_DEFAULT_USER = getenv("PWSAFE_DEFAULT_USER");
    const char *save_USER = getenv("USER");
    const char *save_LOGNAME = getenv("LOGNAME");
    setenv("PWSAFE_DEFAULT_USER", "user1", 1);
    setenv("USER", "user2", 1);
    setenv("LOGNAME", "user3", 1);
    EXPECT_STREQ("user1", get_default_user());
    unsetenv("PWSAFE_DEFAULT_USER");
    EXPECT_STREQ("user2", get_default_user());
    unsetenv("USER");
    EXPECT_STREQ("user3", get_default_user());
    unsetenv("LOGNAME");
    if (save_USER) 
    {
        // This should be true unless someone runs unit tests with sudo
        EXPECT_STREQ(save_USER, get_default_user());
    }
    if (save_PWSAFE_DEFAULT_USER) setenv("PWSAFE_DEFAULT_USER", save_PWSAFE_DEFAULT_USER, 0);
    if (save_USER) setenv("USER", save_USER, 0);
    if (save_LOGNAME) setenv("LOGNAME", save_LOGNAME, 0);
}

TEST(Test, BlockEncodeDecodeSucceeds)
{
    uint8_t block[8] = {'d', 'a', 't', 'a', 'd', 'a', 't', 'a'};
    PwsDb pdb;
    memset(&pdb, 0, sizeof(PwsDb));
    uint8_t key[SHA1_DIGEST_SIZE] = {
        'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 
        'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 
        'p', 'a', 's', 's'};
    uint8_t cbc[8] = {'1','2','3','4','5','6','7','8'};

    memset(&pdb.bf_ctx, 0, sizeof(pdb.bf_ctx));
    BF_set_key(&pdb.bf_ctx, sizeof(key), key);
    memcpy(pdb.cbc, cbc, 8);
    db_encode_block(&pdb, block);

    memset(&pdb.bf_ctx, 0, sizeof(pdb.bf_ctx));
    BF_set_key(&pdb.bf_ctx, sizeof(key), key);
    memcpy(pdb.cbc, cbc, 8);
    db_decode_block(&pdb, block);

    ASSERT_EQ(0l, memcmp("datadata", block, 8));
}

TEST(Test, CheckPassword)
{
    int rc = -1;
    bool result = pws_db_check_password("data/test-v2-empty.dat", "improbable", &rc);
    ASSERT_FALSE(result);
    EXPECT_EQ(PRC_ERR_INCORRECT_PW, rc);

    rc = (int)-1;
    result = pws_db_check_password("data/test-v2-empty.dat", "password", &rc);
    ASSERT_TRUE(result);
    EXPECT_EQ(PRC_SUCCESS, rc);
}

TEST(Test, OpenFailsNoFileFails)
{
    int rc = -1;
    PwsDbRecord *records;
    bool status = pws_db_read("/nonexistent", "password", &records, &rc);
    ASSERT_FALSE(status);
    EXPECT_EQ(PRC_ERR_OPEN, rc);
}

TEST(Test, OpenEmptyDbV1Succeeds)
{
    int rc = -1;
    PwsDbRecord *records;
    bool status = pws_db_read("data/test-v1-empty.dat", "password", &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_EQ(PRC_SUCCESS, rc);

    pws_free_db_records(records);
}

TEST(Test, OpenEmptyDbV2Succeeds)
{
    int rc = -1;
    PwsDbRecord *records;
    bool status = pws_db_read("data/test-v2-empty.dat", "password", &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_EQ(PRC_SUCCESS, rc);
    EXPECT_EQ(nullptr, records);
}

TEST(Test, OpenEmptyDbV2WithIncorrectPasswordFails)
{
    int rc = -1;
    PwsDbRecord *records;
    bool status = pws_db_read("data/test-v2-empty.dat", "foobar", &records, &rc);
    ASSERT_FALSE(status);
    EXPECT_EQ(PRC_ERR_INCORRECT_PW, rc);
}

TEST(Test, OpenDbV1Succeeds)
{
    int rc = 0;

    PwsDb pdb;
    ASSERT_EQ(true, db_open("data/test-v1.dat", "password", &pdb, &rc));
    PwsDbRecord *records = NULL;
    ASSERT_EQ(true, db_read_accounts(&pdb, &records, &rc));

    fclose(pdb.db_file);
    pws_free_db_records(records);

    ASSERT_EQ(PWSAFE_DB_V1, pdb.db_vers);
}

TEST(Test, ReadDbV1Succeeds)
{
    int rc = -1;
    PwsDbRecord *records;
    bool status = pws_db_read("data/test-v1.dat", "password", &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_EQ(PRC_SUCCESS, rc);

    PwsDbRecord *rec = records;
    EXPECT_NE(nullptr, rec->next);
    EXPECT_NE(nullptr, rec->fields);
    // \xAD is the V1 field split character
    EXPECT_STREQ("title  \xAD  name", pws_rec_get_field(rec, FT_NAME));
    EXPECT_EQ(nullptr, pws_rec_get_field(rec, FT_GROUP));
    EXPECT_STREQ("title", pws_rec_get_field(rec, FT_TITLE));
    EXPECT_STREQ("name", pws_rec_get_field(rec, FT_USER));
    EXPECT_STREQ("password", pws_rec_get_field(rec, FT_PASSWORD));
    EXPECT_STREQ("notes", pws_rec_get_field(rec, FT_NOTES));

    rec = rec->next;
    EXPECT_EQ(nullptr, rec->next);
    EXPECT_NE(nullptr, rec->fields);
    // \xA0 is the default user character
    EXPECT_STREQ("group.title\xA0", pws_rec_get_field(rec, FT_NAME));
    // IMB 2023-01-18 Nicolas Dade's pwsafe presents v2 records as 
    // "group.title" but does not split v1 records
    // into separate fields. I wonder if we should do this.
    EXPECT_EQ(nullptr, pws_rec_get_field(rec, FT_GROUP));
    EXPECT_STREQ("group.title", pws_rec_get_field(rec, FT_TITLE));
    EXPECT_EQ(0, strcmp(pws_rec_get_field(rec, FT_USER), get_default_user()));
    EXPECT_LT(0, strlen(pws_rec_get_field(rec, FT_PASSWORD)));
    EXPECT_STREQ("", pws_rec_get_field(rec, FT_NOTES));

    pws_free_db_records(records);
}

TEST(Test, OpenDbV2Succeeds)
{
    int rc = 0;

    PwsDb pdb;
    ASSERT_EQ(true, db_open("data/test-v2.dat", "password", &pdb, &rc));
    PwsDbRecord *records = NULL;
    ASSERT_EQ(true, db_read_accounts(&pdb, &records, &rc));

    fclose(pdb.db_file);
    pws_free_db_records(records);

    ASSERT_EQ(PWSAFE_DB_V2, pdb.db_vers);
}

TEST(Test, ReadDbV2Succeeds)
{
    int rc = -1;
    PwsDbRecord *records;
    bool status = pws_db_read("data/test-v2.dat", "password", &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_EQ(PRC_SUCCESS, rc);
    EXPECT_EQ(nullptr, records->next);
    EXPECT_NE(nullptr, records->fields);
    EXPECT_STREQ("group", pws_rec_get_field(records, FT_GROUP));
    EXPECT_STREQ("account", pws_rec_get_field(records, FT_TITLE));
    EXPECT_STREQ("password", pws_rec_get_field(records, FT_PASSWORD));
    EXPECT_STREQ("notes", pws_rec_get_field(records, FT_NOTES));

    pws_free_db_records(records);
}

TEST(Test, InitHeaderSucceeds)
{
    int rc = -1;
    const char *pw = "password";
    Header h;
    ASSERT_TRUE(db_init_header(&h, pw, &rc));
    ASSERT_TRUE(db_check_password(&h, pw, &rc));
}

TEST(Test, WriteEmptyDatabaseSucceeds)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    const char *pw = "password";
    ASSERT_TRUE(pws_db_write(pathname, pw, nullptr, &rc));
    EXPECT_EQ(PRC_SUCCESS, rc);

    rc = (int)-1;
    PwsDbRecord *records;
    bool status = pws_db_read(pathname, "password", &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_EQ(nullptr, records);
    EXPECT_EQ(PRC_SUCCESS, rc);
    pws_free_db_records(records);

    struct stat st;
    status = stat(pathname, &st);
    EXPECT_EQ(0, status);
    if (status == 0)
    {
        EXPECT_EQ(/*sizeof(Header)*/ 56, st.st_size);
    }
}

TEST(Test, WriteRecordWithNoUuidSucceeds)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char password[] = "password", title[] = "title";
    PwsDbField title_rec = {NULL, FT_TITLE, title};
    PwsDbRecord rec = {NULL, &title_rec};

    ASSERT_TRUE(pws_db_write(pathname, password, &rec, &rc));
    EXPECT_EQ(PRC_SUCCESS, rc);

    rc = (int)-1;

    PwsDbRecord *records;
    bool status = pws_db_read(pathname, password, &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_NE(nullptr, records);
    EXPECT_EQ(PRC_SUCCESS, rc);
    if (records)
    {
        EXPECT_STREQ(title, pws_rec_get_field(records, FT_TITLE));
        EXPECT_NE(nullptr, pws_rec_get_field(records, FT_UUID));
        EXPECT_EQ(32, strlen(pws_rec_get_field(records, FT_UUID)));
    }

    pws_free_db_records(records);
}


TEST(Test, WriteRecordWithUuidSucceeds)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char password[] = "password", title[] = "title", uuid[] = "0123456789ABCDEF0123456789ABCDEF";
    PwsDbField title_rec = {NULL, FT_TITLE, title}, uuid_rec = {&title_rec, FT_UUID, uuid};
    PwsDbRecord rec = {NULL, &uuid_rec};

    ASSERT_TRUE(pws_db_write(pathname, password, &rec, &rc));
    EXPECT_EQ(PRC_SUCCESS, rc);

    rc = (int)-1;

    PwsDbRecord *records;
    bool status = pws_db_read(pathname, password, &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_NE(nullptr, records);
    EXPECT_EQ(PRC_SUCCESS, rc);
    if (records)
    {
        EXPECT_STREQ(uuid, pws_rec_get_field(records, FT_UUID));
    }

    pws_free_db_records(records);
}

TEST(Test, TestCountRecordsSucceeds)
{
    PwsDbRecord *head = alloc_record();
    head->next = alloc_record();
    head->next->next = alloc_record();
    ASSERT_EQ(3, pws_db_record_count(head));
    pws_free_db_records(head);
}

TEST(Test, TestCountRecordsFails)
{
    PwsDbRecord *head = alloc_record();
    head->next = alloc_record();
    head->next->next = alloc_record();
    head->next->next->next = head;
    ASSERT_EQ(-1, pws_db_record_count(head));
    head->next->next->next = NULL;
    pws_free_db_records(head);
}

TEST(Test, TestAllocateRecordSucceeds)
{
    PwsDbRecord *prec1 = pws_new_record();
    ASSERT_EQ(nullptr, prec1->next);
    ASSERT_EQ(nullptr, prec1->fields);
    pws_free_db_records(prec1);
    prec1 = nullptr;

    PwsDbRecord *prec2 = pws_add_record(nullptr);
    ASSERT_EQ(nullptr, prec2->next);
    ASSERT_EQ(nullptr, prec2->fields);

    PwsDbRecord *prec3 = pws_add_record(prec2);
    ASSERT_EQ(nullptr, prec2->next);
    ASSERT_NE(nullptr, prec3->next);

    pws_free_db_records(prec3);
}

TEST(Test, TestAllocateFieldFails)
{
    PwsDbField *pfield;

    pfield = pws_add_field(nullptr, FT_GROUP, "value");
    ASSERT_EQ(nullptr, pfield);

    PwsDbRecord *prec = pws_new_record();

    pfield = pws_add_field(prec, (PwsFieldType)FT_END, "value");
    ASSERT_EQ(nullptr, pfield);

    pfield = pws_add_field(prec, (PwsFieldType)(FT_END+1), "value");
    ASSERT_EQ(nullptr, pfield);

    pfield = pws_add_field(prec, FT_GROUP, nullptr);
    ASSERT_EQ(nullptr, pfield);

    pws_free_db_records(prec);
}

TEST(Test, TestAllocateFieldSucceeds)
{
    PwsDbRecord *prec = pws_new_record();
    PwsDbField *pfield;

    pfield = pws_add_field(prec, FT_GROUP, "value");
    ASSERT_NE(nullptr, pfield);

    pws_free_db_records(prec);
}

// --- Regression tests for review-stability fixes ---

#include <fstream>
#include <iterator>
#include <vector>

static std::vector<char> read_file(const char *pathname)
{
    std::ifstream in(pathname, std::ios::binary);
    return std::vector<char>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

static void write_file(const char *pathname, const char *data, size_t len)
{
    std::ofstream out(pathname, std::ios::binary | std::ios::trunc);
    out.write(data, (std::streamsize)len);
}

TEST(Test, TrimRightEmptyString)
{
    char s[1] = {0};
    EXPECT_STREQ("", trim_right(s, s));
}

TEST(Test, TrimRightTrailingWhitespaceOnly)
{
    std::string s{"ab \t"};
    EXPECT_STREQ("ab", trim_right(s.data(), s.data() + s.length()));
}

TEST(Test, GetFieldOfNullRecordReturnsNull)
{
    EXPECT_EQ(nullptr, pws_rec_get_field(nullptr, FT_TITLE));
}

TEST(Test, ReadTruncatedDbV1Fails)
{
    std::vector<char> data = read_file("data/test-v1.dat");
    ASSERT_EQ(200u, data.size());
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);

    // Header (56) + name field (8 + 16), then EOF before the password field
    write_file(pathname, data.data(), 80);
    int rc = -1;
    PwsDbRecord *records = (PwsDbRecord *)0x1;
    EXPECT_FALSE(pws_db_read(pathname, "password", &records, &rc));
    EXPECT_EQ(PRC_ERR_CORRUPT_DB, rc);
    EXPECT_EQ(nullptr, records);
    remove(pathname);
}

// Reading any truncation of a valid database must not crash, and must
// never return records together with a failure
static void read_every_truncation(const char *source)
{
    std::vector<char> data = read_file(source);
    ASSERT_FALSE(data.empty());
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    for (size_t len = 0; len < data.size(); ++len)
    {
        write_file(pathname, data.data(), len);
        int rc = -1;
        PwsDbRecord *records = nullptr;
        bool status = pws_db_read(pathname, "password", &records, &rc);
        if (status)
        {
            EXPECT_EQ(PRC_SUCCESS, rc) << "len=" << len;
            pws_free_db_records(records);
        }
        else
        {
            EXPECT_NE(PRC_SUCCESS, rc) << "len=" << len;
            EXPECT_EQ(nullptr, records) << "len=" << len;
        }
    }
    remove(pathname);
}

TEST(Test, ReadEveryTruncationOfDbV1DoesNotCrash)
{
    read_every_truncation("data/test-v1.dat");
}

TEST(Test, ReadEveryTruncationOfDbV2DoesNotCrash)
{
    read_every_truncation("data/test-v2.dat");
}

TEST(Test, WriteRecordWithNullTitleValueFails)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    PwsDbField title_rec = {NULL, FT_TITLE, NULL};
    PwsDbRecord rec = {NULL, &title_rec};

    EXPECT_FALSE(pws_db_write(pathname, "password", &rec, &rc));
    EXPECT_EQ(PRC_ERR_INVALID_ARG, rc);
    remove(pathname);
}

TEST(Test, WriteRecordWithNullFieldValueIgnoresField)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char title[] = "title";
    PwsDbField title_rec = {NULL, FT_TITLE, title}, notes_rec = {&title_rec, FT_NOTES, NULL};
    PwsDbRecord rec = {NULL, &notes_rec};

    ASSERT_TRUE(pws_db_write(pathname, "password", &rec, &rc));
    EXPECT_EQ(PRC_SUCCESS, rc);

    PwsDbRecord *records = nullptr;
    ASSERT_TRUE(pws_db_read(pathname, "password", &records, &rc));
    ASSERT_NE(nullptr, records);
    EXPECT_STREQ(title, pws_rec_get_field(records, FT_TITLE));
    EXPECT_EQ(nullptr, pws_rec_get_field(records, FT_NOTES));
    pws_free_db_records(records);
    remove(pathname);
}

TEST(Test, WriteRecordWithInvalidSecondUuidFails)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char title[] = "title", uuid[] = "0123456789ABCDEF0123456789ABCDEF", bad_uuid[] = "abc";
    PwsDbField title_rec = {NULL, FT_TITLE, title},
        bad_uuid_rec = {&title_rec, FT_UUID, bad_uuid},
        uuid_rec = {&bad_uuid_rec, FT_UUID, uuid};
    PwsDbRecord rec = {NULL, &uuid_rec};

    EXPECT_FALSE(pws_db_write(pathname, "password", &rec, &rc));
    EXPECT_EQ(PRC_ERR_INVALID_ARG, rc);
    remove(pathname);
}

TEST(Test, WriteRecordWithNonAsciiUuidFails)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char title[] = "title", uuid[] = "\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD"
                                     "\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD\xAD";
    PwsDbField title_rec = {NULL, FT_TITLE, title}, uuid_rec = {&title_rec, FT_UUID, uuid};
    PwsDbRecord rec = {NULL, &uuid_rec};

    EXPECT_FALSE(pws_db_write(pathname, "password", &rec, &rc));
    EXPECT_EQ(PRC_ERR_INVALID_ARG, rc);
    remove(pathname);
}

TEST(Test, ReadDbV2TruncatedBeforeEndFieldFails)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char title1[] = "title1", title2[] = "title2";
    PwsDbField title1_rec = {NULL, FT_TITLE, title1}, title2_rec = {NULL, FT_TITLE, title2};
    PwsDbRecord rec2 = {NULL, &title2_rec}, rec1 = {&rec2, &title1_rec};
    ASSERT_TRUE(pws_db_write(pathname, "password", &rec1, &rc));

    // Drop the last record's FT_END field (one length block, one data block)
    std::vector<char> data = read_file(pathname);
    ASSERT_GT(data.size(), 16u);
    write_file(pathname, data.data(), data.size() - 16);

    PwsDbRecord *records = (PwsDbRecord *)0x1;
    EXPECT_FALSE(pws_db_read(pathname, "password", &records, &rc));
    EXPECT_EQ(PRC_ERR_CORRUPT_DB, rc);
    EXPECT_EQ(nullptr, records);
    remove(pathname);
}

TEST(Test, FailedWriteLeavesExistingDbUnchanged)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char title[] = "title";
    PwsDbField title_rec = {NULL, FT_TITLE, title};
    PwsDbRecord good = {NULL, &title_rec};
    ASSERT_TRUE(pws_db_write(pathname, "password", &good, &rc));
    std::vector<char> before = read_file(pathname);

    // Second record has no title, so the write fails after the first record
    char notes[] = "notes";
    PwsDbField notes_rec = {NULL, FT_NOTES, notes};
    PwsDbRecord bad = {NULL, &notes_rec}, first = {&bad, &title_rec};
    EXPECT_FALSE(pws_db_write(pathname, "password", &first, &rc));
    EXPECT_EQ(PRC_ERR_INVALID_ARG, rc);

    EXPECT_EQ(before, read_file(pathname));
    PwsDbRecord *records = nullptr;
    ASSERT_TRUE(pws_db_read(pathname, "password", &records, &rc));
    ASSERT_NE(nullptr, records);
    EXPECT_STREQ(title, pws_rec_get_field(records, FT_TITLE));
    pws_free_db_records(records);
    remove(pathname);
}

TEST(Test, WriteFieldAtMaxLengthRoundTrips)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char title[] = "title";
    std::string notes(64 * 1024, 'n');
    PwsDbField title_rec = {NULL, FT_TITLE, title}, notes_rec = {&title_rec, FT_NOTES, notes.data()};
    PwsDbRecord rec = {NULL, &notes_rec};
    ASSERT_TRUE(pws_db_write(pathname, "password", &rec, &rc));

    PwsDbRecord *records = nullptr;
    ASSERT_TRUE(pws_db_read(pathname, "password", &records, &rc));
    ASSERT_NE(nullptr, records);
    EXPECT_STREQ(notes.c_str(), pws_rec_get_field(records, FT_NOTES));
    pws_free_db_records(records);
    remove(pathname);
}

TEST(Test, WriteFieldOverMaxLengthFails)
{
    int rc = -1;
    char pathname[L_tmpnam + 1];
    (void)!tmpnam(pathname);
    char title[] = "title";
    std::string notes(64 * 1024 + 1, 'n');
    PwsDbField title_rec = {NULL, FT_TITLE, title}, notes_rec = {&title_rec, FT_NOTES, notes.data()};
    PwsDbRecord rec = {NULL, &notes_rec};
    EXPECT_FALSE(pws_db_write(pathname, "password", &rec, &rc));
    EXPECT_EQ(PRC_ERR_INVALID_ARG, rc);
    // A failed write of a new database must not leave a file behind
    EXPECT_TRUE(read_file(pathname).empty());
    remove(pathname);
}
