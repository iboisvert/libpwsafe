add_library(pwsafe_api INTERFACE)
target_include_directories(pwsafe_api INTERFACE ${CMAKE_CURRENT_LIST_DIR})

# IMB 2023-05-14 Replace install(FILES) with install(PUBLIC_HEADER)
if(CMAKE_PROJECT_NAME STREQUAL "libpwsafe")
    install(FILES pwsafe.h DESTINATION include/libpwsafe COMPONENT dev)
endif()

if(LIBPWSAFE_BUILD_DOCS)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C "YES")
    set(DOXYGEN_HTML_EXTRA_STYLESHEET "${CMAKE_SOURCE_DIR}/docs/docs.css")
    set(DOXYGEN_SORT_BRIEF_DOCS "YES")
    set(DOXYGEN_SEARCHENGINE "NO")

    doxygen_add_docs(docs pwsafe.h ALL)

    if(CMAKE_PROJECT_NAME STREQUAL "libpwsafe")
        install(DIRECTORY ${CMAKE_BINARY_DIR}/api/html/ DESTINATION usr/share/doc/libpwsafe COMPONENT dev)
    endif()
endif()