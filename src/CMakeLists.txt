list(APPEND SRC
    block.c
    db.c
    util.c
)
add_library(objlib OBJECT ${SRC})
target_include_directories(objlib PUBLIC ${OPENSSL_INCLUDE_DIR})

if(LIBPWSAFE_BUILD_STATIC)
    add_library(pwsafeStatic STATIC)
    target_link_libraries(pwsafeStatic PUBLIC pwsafe_api objlib INTERFACE OpenSSL::Crypto)

    # On Windows, static lib is libpwsafe.lib, DLL is pwsafe.dll/.lib
    # On Linux, static lib is libpwsafe.a, SO is libpwsafe.so
    set_target_properties(pwsafeStatic 
        PROPERTIES 
        VERSION ${LIBPWSAFE_VERSION}
        OUTPUT_NAME $<IF:$<BOOL:${WIN32}>,libpwsafe,pwsafe>
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

    if(CMAKE_PROJECT_NAME STREQUAL "libpwsafe")
        install(TARGETS pwsafeStatic ARCHIVE COMPONENT dev)
    endif()
endif()

if(LIBPWSAFE_BUILD_SHARED)
    add_library(pwsafe SHARED)
    target_link_libraries(pwsafe PRIVATE objlib PUBLIC pwsafe_api OpenSSL::Crypto)

    set_target_properties(pwsafe 
        PROPERTIES 
        VERSION ${LIBPWSAFE_VERSION}
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
    
    if(CMAKE_PROJECT_NAME STREQUAL "libpwsafe")
        install(TARGETS pwsafe LIBRARY COMPONENT dev)
        install(TARGETS pwsafe LIBRARY COMPONENT runtime)
    endif()
endif()

if(CMAKE_PROJECT_NAME STREQUAL "libpwsafe")
    set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CPackDescription.txt")
    set(CPACK_PACKAGE_VENDOR "Ian Boisvert")

    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ian Boisvert" PARENT_SCOPE)

    set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-only" PARENT_SCOPE)
endif()

set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.35-0ubuntu3.1), libssl3 (>= 3.0.0)" PARENT_SCOPE)
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.36, openssl-libs >= 3.0.0" PARENT_SCOPE)
