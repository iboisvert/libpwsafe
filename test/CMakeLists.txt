add_executable(libpwsafe-test 
    test.cc
)
target_link_libraries(
    libpwsafe-test
    pwsafeStatic
    GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(libpwsafe-test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/../test")

# add_test("unit tests" COMMAND libpwsafe-test)