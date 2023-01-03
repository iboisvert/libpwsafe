/* Copyright 2023 Ian Boisvert */
#include <gtest/gtest.h>
#include <stdlib.h>
#include "pwsafe.h"

TEST(Test, OpenDbV1)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v1-empty.dat", "password", &rc);
    ASSERT_NE((void*)NULL, hdb);
    ASSERT_EQ(0, rc);

    ASSERT_TRUE(pws_db_check_password(hdb, "password"));

    pws_db_close(hdb, &rc);
}

TEST(Test, OpenDbV2)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE hdb = pws_db_open("data/test-v2-empty.dat", "password", &rc);
    ASSERT_NE((void*)NULL, hdb);
    ASSERT_EQ(0, rc);

    ASSERT_TRUE(pws_db_check_password(hdb, "password"));

    pws_db_close(hdb, &rc);
}
