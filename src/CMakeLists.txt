include_directories(${NETTLE_INCLUDE_DIR})

list(APPEND SRC
    block.c
    db.c
    util.c
)
add_library(objlib OBJECT ${SRC})

if(LIBPWSAFE_BUILD_STATIC)
    add_library(pwsafeStatic STATIC $<TARGET_OBJECTS:objlib>)
    target_link_libraries(pwsafeStatic PUBLIC pwsafe_api INTERFACE nettle)

    # On Windows, static lib is libpwsafe.lib, DLL is pwsafe.dll/.lib
    # On Linux, static lib is libpwsafe.a, SO is libpwsafe.so
    set_target_properties(pwsafeStatic 
        PROPERTIES 
        VERSION ${LIBPWSAFE_VERSION}
        OUTPUT_NAME $<IF:$<BOOL:${WIN32}>,libpwsafe,pwsafe>
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

    install(TARGETS pwsafeStatic ARCHIVE COMPONENT dev)
endif()

if(LIBPWSAFE_BUILD_SHARED)
    add_library(pwsafe SHARED $<TARGET_OBJECTS:objlib>)
    target_link_libraries(pwsafe PUBLIC pwsafe_api nettle)

    set_target_properties(pwsafe 
        PROPERTIES 
        VERSION ${LIBPWSAFE_VERSION}
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
    
    install(TARGETS pwsafe LIBRARY COMPONENT dev)
    install(TARGETS pwsafe LIBRARY COMPONENT runtime)
endif()

set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.35-0ubuntu3.1), libnettle8 (>= 3.7.3-1build2)" PARENT_SCOPE)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ian Boisvert" PARENT_SCOPE)

set(CPACK_RPM_PACKAGE_LICENSE "GPL-3.0-only" PARENT_SCOPE)
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.36, nettle >= 3.8" PARENT_SCOPE)