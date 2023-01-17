find_package(Nettle REQUIRED)
include_directories(${NETTLE_INCLUDE_DIR})

list(APPEND SRC
    block.c
    db.c
    util.c
)
add_library(pwsafe ${SRC})
target_link_libraries (pwsafe nettle)

#set (CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.11.1-0ubuntu7.2), ${LIBCURL}, libmagic1 (>= 1:5.25), libuuid1 (>= 2.17.2-0ubuntu1), libwxgtk3.0-gtk3-0v5 (>= 3.0.0-2), libxtst6 (>= 2:1.1.0-2), libxerces-c${XercesC_VER} (>= 3.1.0-1), libykpers-1-1 (>= 1.7.0-1), ${LIBQRENCODE}")
install(TARGETS pwsafe LIBRARY)