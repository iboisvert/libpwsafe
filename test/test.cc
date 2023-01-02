#include <gtest/gtest.h>
#include <stdlib.h>
#include "pwsafe.h"

TEST(Test, OpenDb)
{
    PWS_RESULT_CODE rc;
    PWSHANDLE db = pws_open_db("tmp", "foo", &rc);
    ASSERT_NE((void*)NULL, db);
}