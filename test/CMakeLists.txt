include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        58d77fa8070e8cec2dc1ed015d66b454c8d78850 # release-1.12.1
)
FetchContent_MakeAvailable(googletest)

add_executable(libpwsafe-test 
    test.cc
)
target_link_libraries(
    libpwsafe-test
    pwsafe
    GTest::gtest_main
)
add_dependencies(libpwsafe-test pwsafe)

include(GoogleTest)
gtest_discover_tests(libpwsafe-test)

# add_test("unit tests" COMMAND libpwsafe-test)