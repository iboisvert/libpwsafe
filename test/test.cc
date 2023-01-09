/* Copyright 2023 Ian Boisvert */
#include "pwsafe.h"
#include <gtest/gtest.h>
#include <stdlib.h>
#include <string>

extern "C"
{
    extern const char *trim_right(const char *pbegin, char *pend);
}

TEST(Test, TrimRight)
{
    std::string s{"\n\r\t "};
    EXPECT_STREQ("", trim_right(s.data(), s.data() + s.length()));
    s = "abc";
    EXPECT_STREQ("abc", trim_right(s.data(), s.data() + s.length()));
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