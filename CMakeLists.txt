cmake_minimum_required(VERSION 3.22)
project(libpwsafe 
    VERSION 0.1.0 
    DESCRIPTION "Library for reading and writing Password Safe account database files" 
    HOMEPAGE_URL "https://github.com/iboisvert/libpwsafe"
)
set (LIBPWSAFE_VERSION "${CMAKE_PROJECT_VERSION}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules")

INCLUDE(CheckIncludeFiles)
CHECK_INCLUDE_FILES("sys/random.h" HAVE_SYS_RANDOM_H)
INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS("getpwuid" HAVE_PWUID)
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")

enable_testing()

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

add_compile_options(
    -fPIC -Wall -Wextra
    "$<$<CONFIG:DEBUG>:-ggdb;-O0;-fsanitize=address,undefined;-fno-omit-frame-pointer>"
)
add_compile_definitions(
    "$<$<CONFIG:RELEASE>:NDEBUG>"
)
add_link_options(
    "$<$<CONFIG:DEBUG>:-fsanitize=address,undefined>"
)

include_directories("${CMAKE_CURRENT_BINARY_DIR}")
include_directories(api)
include_directories(src)

add_subdirectory(test)
add_subdirectory(src)
add_subdirectory(api)

set(CPACK_COMPONENTS_ALL "dev;runtime")
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
include(CPack)