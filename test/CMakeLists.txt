add_executable(libpwsafe-test 
    test.cc
)
target_link_libraries(
    libpwsafe-test
    pwsafeStatic
    GTest::gtest_main
)
target_link_directories(libpwsafe-test PRIVATE ${NETTLE_LIBRARY_DIRS})
# TODO IMB 2024-07-29 Copy test resources after build
#add_custom_target(
#    TARGET libpwsafe-test POST_BUILD
#    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/test/data ${RUNTIME_OUTPUT_DIRECTORY}
#)

include(GoogleTest)
gtest_discover_tests(libpwsafe-test WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/../test")

# add_test("unit tests" COMMAND libpwsafe-test)