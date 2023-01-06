/* Copyright 2023 Ian Boisvert */
#include <gtest/gtest.h>
#include <stdlib.h>
#include "pwsafe.h"

TEST(Test, OpenEmptyDbV1)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v1-empty.dat", "password", &rc);
    ASSERT_NE((void*)NULL, hdb);
    ASSERT_EQ(0, rc);

    ASSERT_TRUE(pws_db_check_password(hdb, "password"));

    pws_db_close(hdb, &rc);
}

TEST(Test, OpenEmptyDbV2)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v2-empty.dat", "password", &rc);
    ASSERT_NE((void*)NULL, hdb);
    ASSERT_EQ(0, rc);

    ASSERT_TRUE(pws_db_check_password(hdb, "password"));

    pws_db_close(hdb, &rc);
}

TEST(Test, ReadDbV2)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v2.dat", "password", &rc);
    ASSERT_NE((void*)NULL, hdb);
    ASSERT_EQ(0, rc);

    ASSERT_TRUE(pws_db_read_accounts(hdb, &rc));

    pws_db_close(hdb, &rc);
}