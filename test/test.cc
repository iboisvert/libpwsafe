/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include "pwsafe_priv.h"
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

TEST(Test, ByteOrderIsSupported)
{
    const uint32_t dw = 0x00000001;
    const char *pdw = (const char *)&dw;
    EXPECT_TRUE(pdw[0] || pdw[3]);
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
    // This should be true unless someone runs unit tests with sudo
    EXPECT_STREQ(save_USER, get_default_user());
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

TEST(Test, OpenFailsNoFileFails)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    PWSHANDLE hdb = pws_db_open("(nonexistent", "password", &rc);
    ASSERT_EQ(nullptr, hdb);
    EXPECT_EQ(PRC_ERR_OPEN, rc);
}

TEST(Test, OpenEmptyDbV1Succeeds)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    PWSHANDLE hdb = pws_db_open("data/test-v1-empty.dat", "password", &rc);
    ASSERT_NE(nullptr, hdb);
    EXPECT_EQ(PRC_SUCCESS, rc);

    pws_db_close(hdb, &rc);
}

TEST(Test, OpenEmptyDbV2Succeeds)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    PWSHANDLE hdb = pws_db_open("data/test-v2-empty.dat", "password", &rc);
    ASSERT_NE(nullptr, hdb);
    EXPECT_EQ(PRC_SUCCESS, rc);

    pws_db_close(hdb, &rc);
}

TEST(Test, OpenEmptyDbV2WithIncorrectPasswordFails)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    PWSHANDLE hdb = pws_db_open("data/test-v2-empty.dat", "foobar", &rc);
    ASSERT_EQ(nullptr, hdb);
    EXPECT_EQ(PRC_ERR_INCORRECT_PW, rc);
}

TEST(Test, ReadDbV1Succeeds)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    PWSHANDLE hdb = pws_db_open("data/test-v1.dat", "password", &rc);
    ASSERT_NE(nullptr, hdb);
    EXPECT_EQ(PRC_SUCCESS, rc);

    PwsDbRecord *records;
    rc = (PWS_RESULT_CODE)-1;
    EXPECT_TRUE(pws_db_read_accounts(hdb, &records, &rc));
    EXPECT_EQ(nullptr, records->next);
    EXPECT_NE(nullptr, records->fields);
    EXPECT_EQ(PRC_SUCCESS, rc);
    pws_free_db_records(records);

    pws_db_close(hdb, &rc);
}

TEST(Test, ReadDbV2Succeeds)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    PWSHANDLE hdb = pws_db_open("data/test-v2.dat", "password", &rc);
    ASSERT_NE(nullptr, hdb);
    EXPECT_EQ(PRC_SUCCESS, rc);

    PwsDbRecord *records;
    rc = (PWS_RESULT_CODE)-1;
    EXPECT_TRUE(pws_db_read_accounts(hdb, &records, &rc));
    EXPECT_EQ(nullptr, records->next);
    EXPECT_NE(nullptr, records->fields);
    EXPECT_EQ(PRC_SUCCESS, rc);
    EXPECT_STREQ("group", pws_rec_get_field(records, FT_GROUP));
    EXPECT_STREQ("account", pws_rec_get_field(records, FT_TITLE));
    EXPECT_STREQ("password", pws_rec_get_field(records, FT_PASSWORD));
    EXPECT_STREQ("notes", pws_rec_get_field(records, FT_NOTES));

    pws_free_db_records(records);
    pws_db_close(hdb, &rc);
}

TEST(Test, InitHeaderSucceeds)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    const char *pw = "password";
    Header h;
    ASSERT_TRUE(db_init_header(&h, pw, &rc));
    ASSERT_TRUE(db_check_password(&h, pw));
}

TEST(Test, WriteEmptyDatabaseSucceeds)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    char pathname[L_tmpnam + 1];
    tmpnam(pathname);
    const char *pw = "password";
    ASSERT_TRUE(pws_db_write(pathname, pw, nullptr, &rc));
    EXPECT_EQ(PRC_SUCCESS, rc);

    rc = (PWS_RESULT_CODE)-1;
    PwsDbRecord *records = nullptr;
    PWSHANDLE hdb = pws_db_open(pathname, "password", &rc);
    ASSERT_NE(nullptr, hdb);
    EXPECT_TRUE(pws_db_read_accounts(hdb, &records, &rc));
    EXPECT_EQ(nullptr, records);
    EXPECT_EQ(PRC_SUCCESS, rc);
    pws_db_close(hdb, &rc);

    struct stat st;
    int status = stat(pathname, &st);
    EXPECT_EQ(0, status);
    if (status == 0)
    {
        EXPECT_EQ(/*sizeof(Header)*/ 56, st.st_size);
    }
}

TEST(Test, WriteFieldWithNoUUIDSucceeds)
{
    PWS_RESULT_CODE rc = (PWS_RESULT_CODE)-1;
    char pathname[L_tmpnam + 1];
    tmpnam(pathname);
    const char *pw = "password";
    char str[] = "title";
    PwsDbField title = {NULL, FT_TITLE, str};
    PwsDbRecord rec = {NULL, &title};

    ASSERT_TRUE(pws_db_write(pathname, pw, &rec, &rc));
    EXPECT_EQ(PRC_SUCCESS, rc);

    rc = (PWS_RESULT_CODE)-1;

    PWSHANDLE hdb = pws_db_open(pathname, "password", &rc);
    ASSERT_NE(nullptr, hdb);

    PwsDbRecord *records = nullptr;
    EXPECT_TRUE(pws_db_read_accounts(hdb, &records, &rc));
    EXPECT_NE(nullptr, records);
    EXPECT_EQ(PRC_SUCCESS, rc);
    if (records)
    {
        EXPECT_STREQ("title", pws_rec_get_field(records, FT_TITLE));
    }

    pws_free_db_records(records);
    pws_db_close(hdb, &rc);
}