/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include <gtest/gtest.h>
#include <stdlib.h>
#include <string>

extern "C"
{
    extern const char *trim_right(const char *pbegin, char *pend);
    extern const char *get_default_user();
}

TEST(Test, TrimRight)
{
    std::string s{"\n\r\t "};
    EXPECT_STREQ("", trim_right(s.data(), s.data() + s.length()));
    s = "abc";
    EXPECT_STREQ("abc", trim_right(s.data(), s.data() + s.length()));
}

TEST(Test, GetDefaultUser)
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

TEST(Test, OpenEmptyDbV1)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v1-empty.dat", "password", &rc);
    ASSERT_NE((void *)NULL, hdb);
    ASSERT_EQ(PWS_SUCCESS, rc);

    pws_db_close(hdb, &rc);
}

TEST(Test, OpenEmptyDbV2)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v2-empty.dat", "password", &rc);
    ASSERT_NE((void *)NULL, hdb);
    ASSERT_EQ(0, rc);

    pws_db_close(hdb, &rc);
}

TEST(Test, OpenEmptyDbV2WithIncorrectPassword)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v2-empty.dat", "foobar", &rc);
    ASSERT_EQ((void *)NULL, hdb);
    ASSERT_EQ(PWS_ERR_INCORRECT_PW, rc);
}

TEST(Test, ReadDbV2)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v2.dat", "password", &rc);
    ASSERT_NE((void *)NULL, hdb);
    ASSERT_EQ(0, rc);

    PwsDbRecord *records;
    ASSERT_TRUE(pws_db_read_accounts(hdb, &records, &rc));
    EXPECT_EQ(nullptr, records->next);
    EXPECT_NE(nullptr, records->fields);
    pws_free_db_records(records);

    pws_db_close(hdb, &rc);
}