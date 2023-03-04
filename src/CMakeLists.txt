find_package(Nettle REQUIRED)
include_directories(${NETTLE_INCLUDE_DIR})

list(APPEND SRC
    block.c
    db.c
    util.c
)
add_library(objlib OBJECT ${SRC})

if(PWSAFE_BUILD_STATIC)
    add_library(pwsafeStatic $<TARGET_OBJECTS:objlib>)
    target_include_directories(pwsafeStatic INTERFACE ..)
    # On Windows, static lib is libpwsafe.lib, DLL is pwsafe.dll/.lib
    # On Linux, static lib is libpwsafe.a, SO is libpwsafe.so
    set_target_properties(pwsafeStatic PROPERTIES OUTPUT_NAME $<IF:$<BOOL:${WIN32}>,libpwsafe,pwsafe>)

    install(TARGETS pwsafeStatic ARCHIVE COMPONENT dev)
endif()

if(PWSAFE_BUILD_SHARED)
    add_library(pwsafe SHARED $<TARGET_OBJECTS:objlib>)
    target_include_directories(pwsafe INTERFACE ..)
    target_link_libraries (pwsafe nettle)

    install(TARGETS pwsafe LIBRARY COMPONENT dev)
    install(TARGETS pwsafe LIBRARY COMPONENT runtime)
endif()

set(CPACK_DEB_COMPONENT_INSTALL ON PARENT_SCOPE)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.35-0ubuntu3.1), libnettle8 (>= 3.7.3-1build2)" PARENT_SCOPE)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Ian Boisvert" PARENT_SCOPE)
