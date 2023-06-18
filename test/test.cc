/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include "pwsafe_priv.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

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
    uuid_bin_to_hex(uuid, suuid);
    EXPECT_STREQ("0123456789ABCDEF0123456789ABCDEF", suuid);
}

TEST(Test, UuidHexToBin)
{
    char suuid[] = "0123456789abcdef0123456789abcdef";
    uint8_t uuid[16] = {0};
    uuid_hex_to_bin(suuid, uuid);
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
    blowfish_set_key(&pdb.bf_ctx, sizeof(key), (uint8_t *)key);
    memcpy(pdb.cbc, cbc, 8);
    db_encode_block(&pdb, block);

    memset(&pdb.bf_ctx, 0, sizeof(pdb.bf_ctx));
    blowfish_set_key(&pdb.bf_ctx, sizeof(key), (uint8_t *)key);
    memcpy(pdb.cbc, cbc, 8);
    db_decode_block(&pdb, block);

    ASSERT_EQ(0l, memcmp("datadata", block, 8));
}

TEST(Test, CheckPassword)
{
    int rc = -1;
    _Bool result = pws_db_check_password("data/test-v2-empty.dat", "improbable", &rc);
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
    _Bool status = pws_db_read("/nonexistent", "password", &records, &rc);
    ASSERT_FALSE(status);
    EXPECT_EQ(PRC_ERR_OPEN, rc);
}

TEST(Test, OpenEmptyDbV1Succeeds)
{
    int rc = -1;
    PwsDbRecord *records;
    _Bool status = pws_db_read("data/test-v1-empty.dat", "password", &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_EQ(PRC_SUCCESS, rc);

    pws_free_db_records(records);
}

TEST(Test, OpenEmptyDbV2Succeeds)
{
    int rc = -1;
    PwsDbRecord *records;
    _Bool status = pws_db_read("data/test-v2-empty.dat", "password", &records, &rc);
    ASSERT_TRUE(status);
    EXPECT_EQ(PRC_SUCCESS, rc);
    EXPECT_EQ(nullptr, records);
}

TEST(Test, OpenEmptyDbV2WithIncorrectPasswordFails)
{
    int rc = -1;
    PwsDbRecord *records;
    _Bool status = pws_db_read("data/test-v2-empty.dat", "foobar", &records, &rc);
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
    _Bool status = pws_db_read("data/test-v1.dat", "password", &records, &rc);
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
    _Bool status = pws_db_read("data/test-v2.dat", "password", &records, &rc);
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
    _Bool status = pws_db_read(pathname, "password", &records, &rc);
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
    _Bool status = pws_db_read(pathname, password, &records, &rc);
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
    _Bool status = pws_db_read(pathname, password, &records, &rc);
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
