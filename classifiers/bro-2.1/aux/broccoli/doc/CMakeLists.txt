configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in
               ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
               @ONLY)

add_custom_target(broccolidoc
                  COMMAND doxygen ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
                  COMMENT "[Doxygen] Generating HTML Broccoli API docs")

add_custom_target(broccolidocclean
                  COMMAND rm -rf ${CMAKE_CURRENT_BINARY_DIR}/html)

if (NOT TARGET doc)
    add_custom_target(doc)
endif ()
add_dependencies(doc broccolidoc)

if (NOT TARGET docclean)
    add_custom_target(docclean)
endif ()
add_dependencies(docclean broccolidocclean)
