cmake_minimum_required(VERSION 3.21)

project(libpwsafe
    VERSION 0.1
    DESCRIPTION "Library for reading and writing Password Safe account database files"
    HOMEPAGE_URL "https://github.com/iboisvert/libpwsafe"
)
set (LIBPWSAFE_VERSION "${CMAKE_PROJECT_VERSION}")

# Doxygen is rarely installed on Windows; default docs off there
if(WIN32)
    set(LIBPWSAFE_BUILD_DOCS_DEFAULT OFF)
else()
    set(LIBPWSAFE_BUILD_DOCS_DEFAULT ON)
endif()

option(LIBPWSAFE_BUILD_DOCS "Build documentation (needs Doxygen)" ${LIBPWSAFE_BUILD_DOCS_DEFAULT})
option(LIBPWSAFE_BUILD_TESTS "Build test executables" ON)
option(LIBPWSAFE_BUILD_SHARED "Build shared library" ON)
option(LIBPWSAFE_BUILD_STATIC "Build static library" ON)
option(LIBPWSAFE_DEBUG_SANITIZE "Enable AddressSantizer and UBSan, requires full recompile" OFF)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)
# Position-independent code so object files can go into the shared library
# (no-op / implicit on Windows)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(CheckIncludeFiles)
include(CheckFunctionExists)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(LIBPWSAFE_BUILD_DOCS)
    find_package(Doxygen REQUIRED)
endif()
if(LIBPWSAFE_BUILD_TESTS)
    find_package(GTest REQUIRED)
endif()
find_package(OpenSSL REQUIRED)

CHECK_FUNCTION_EXISTS("getpwuid" HAVE_PWUID)
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h")

if(LIBPWSAFE_BUILD_TESTS)
    enable_testing()
endif()

add_compile_definitions(
    "$<$<CONFIG:RELEASE>:NDEBUG>"
)

if(MSVC)
    add_compile_definitions(
        # Silence warnings for POSIX/C-runtime names (strdup, fopen, ...)
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS
    )
    add_compile_options(
        /W3
        "$<$<CONFIG:DEBUG>:/Od;/Zi>"
    )
else()
    add_compile_options(
        -Wall -Wextra
        "$<$<CONFIG:DEBUG>:-ggdb;-O0;-fno-omit-frame-pointer>"
        "$<$<AND:$<CONFIG:DEBUG>,$<BOOL:${LIBPWSAFE_DEBUG_SANITIZE}>>:-fsanitize=address,undefined>"
    )
    add_link_options(
        "$<$<AND:$<CONFIG:DEBUG>,$<BOOL:${LIBPWSAFE_DEBUG_SANITIZE}>>:-fsanitize=address,undefined>"
    )
endif()

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
