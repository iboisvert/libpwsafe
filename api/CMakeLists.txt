install(FILES pwsafe.h DESTINATION include/libpwsafe COMPONENT dev)

if(DOXYGEN_FOUND)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C "YES")
    set(DOXYGEN_HTML_EXTRA_STYLESHEET "${CMAKE_SOURCE_DIR}/docs/docs.css")
    set(DOXYGEN_SORT_BRIEF_DOCS "YES")
    set(DOXYGEN_SEARCHENGINE "NO")

    doxygen_add_docs(docs pwsafe.h ALL)

    install(DIRECTORY ${CMAKE_BINARY_DIR}/api/html/ DESTINATION usr/share/doc/libpwsafe COMPONENT dev)
endif()