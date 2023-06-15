cmake_minimum_required(VERSION 3.22)
project(libpwsafe 
    VERSION 0.1.0 
    DESCRIPTION "Library for reading and writing Password Safe account database files" 
    HOMEPAGE_URL "https://github.com/iboisvert/libpwsafe"
)
set (LIBPWSAFE_VERSION "${CMAKE_PROJECT_VERSION}")

option(LIBPWSAFE_BUILD_DOCS "Build documentation (needs Doxygen)" ON)
option(LIBPWSAFE_BUILD_TESTS "Build test executables" ON)
option(LIBPWSAFE_BUILD_SHARED "Build shared library" ON)
option(LIBPWSAFE_BUILD_STATIC "Build static library" ON)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CPackDescription.txt")
set(CPACK_PACKAGE_VENDOR "Ian Boisvert")

include(CheckIncludeFiles)
include(CheckFunctionExists)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(LIBPWSAFE_BUILD_DOCS)
    find_package(Doxygen)
endif()
if(LIBPWSAFE_BUILD_TESTS)
    find_package(GTest REQUIRED)
endif()
find_package(Nettle REQUIRED)
CHECK_INCLUDE_FILES("sys/random.h" HAVE_SYS_RANDOM_H)
CHECK_FUNCTION_EXISTS("getpwuid" HAVE_PWUID)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")

if(LIBPWSAFE_BUILD_TESTS)
    enable_testing()
endif()

add_compile_definitions(
    "$<$<CONFIG:RELEASE>:NDEBUG>"
)
add_compile_options(
    -fPIC -Wall -Wextra
    "$<$<CONFIG:DEBUG>:-ggdb;-O0;-fsanitize=address,undefined;-fno-omit-frame-pointer>"
)
add_link_options(
    "$<$<CONFIG:DEBUG>:-fsanitize=address,undefined>"
)

include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories(api)
include_directories(src)

add_subdirectory(api)
add_subdirectory(src)
if(LIBPWSAFE_BUILD_TESTS)
    add_subdirectory(test)
endif()

set(CPACK_VERBATIM_VARIABLES YES)
set(CPACK_COMPONENTS_ALL "dev;runtime")
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES
  \\.git/
  \\.vscode/
  build/
  ".*~$"
)

include(CPack)
