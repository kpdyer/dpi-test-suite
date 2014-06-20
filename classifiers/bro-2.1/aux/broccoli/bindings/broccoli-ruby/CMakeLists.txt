project(broccoli-ruby)
cmake_minimum_required(VERSION 2.6.3 FATAL_ERROR)
include(cmake/CommonCMakeConfig.cmake)

########################################################################
## Dependency Configuration

include(FindRequiredPackage)

FindRequiredPackage(Broccoli)
FindRequiredPackage(SWIG)

find_package(Ruby 1.8)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/example.i "%module example %{%}")
execute_process(COMMAND ${SWIG_EXECUTABLE} -ruby
    ${CMAKE_CURRENT_BINARY_DIR}/example.i
    ERROR_VARIABLE SWIG_RUBY_ERR)

if (MISSING_PREREQS OR NOT RUBY_FOUND OR SWIG_RUBY_ERR)
    if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
        set(msg_type SEND_ERROR)
    else ()
        set(msg_type STATUS)
    endif ()

    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(${msg_type} ${prereq})
    endforeach ()

    if (NOT RUBY_FOUND)
        message(${msg_type} "No ruby installation found")
    endif ()

    if (SWIG_RUBY_ERR)
        message(${msg_type} "Swig installation doesn't support Ruby wrapper generation: ${SWIG_RUBY_ERR}")
    endif ()

    if (NOT "${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
        message(STATUS "Warning: Ruby bindings will not be built")
        return()
    endif ()

    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

if (RUBY_INCLUDE_PATH)
    # CMake 2.6 compatibility -- FindRuby used to set RUBY_INCLUDE_PATH
    include_directories(BEFORE ${RUBY_INCLUDE_PATH})
else ()
    include_directories(BEFORE ${RUBY_INCLUDE_DIRS})
endif ()

include_directories(BEFORE ${Broccoli_INCLUDE_DIR})

########################################################################
## Build Ruby Extension

include(UseSWIG)

set(CMAKE_SWIG_OUTDIR ${CMAKE_CURRENT_BINARY_DIR}/ext/broccoli_ext)
swig_add_module(broccoli_ext ruby ext/broccoli_ext/broccoli_intern.i)
if (APPLE)
    # Mac OS X needs ruby extensions to end with ".bundle"
    # and it needs the -flat_namespace argument for SWIG.
    set_target_properties(broccoli_ext 
        PROPERTIES SUFFIX ".bundle"
        LINK_FLAGS "-flat_namespace" )
endif ()
set_target_properties(broccoli_ext PROPERTIES 
    OUTPUT_NAME "broccoli_ext" 
    PREFIX "")
swig_link_libraries(broccoli_ext ${Broccoli_LIBRARY} ${RUBY_LIBRARY})
set_source_files_properties(${swig_generated_file_fullname} PROPERTIES
                            COMPILE_FLAGS -fno-strict-aliasing)

########################################################################
## Install Files

if (NOT RB_INSTALL_DIR)
    # the configure wrapper was not used, default to "home" style installation
    set(RB_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/lib/ruby)
    set(RB_ARCH_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/lib/ruby)
endif ()

install(FILES lib/broccoli.rb DESTINATION ${RB_INSTALL_DIR})
install(FILES lib/Broccoli/connection.rb DESTINATION ${RB_INSTALL_DIR}/Broccoli)
install(FILES lib/Broccoli/event.rb DESTINATION ${RB_INSTALL_DIR}/Broccoli)
install(FILES lib/Broccoli/record.rb DESTINATION ${RB_INSTALL_DIR}/Broccoli)

install(TARGETS broccoli_ext DESTINATION ${RB_ARCH_INSTALL_DIR})

########################################################################
## Build Summary

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n==============|  Broccoli-Ruby Build Summary  |================="
    "\n"
    "\nLib install dir:   ${RB_INSTALL_DIR}"
    "\nExt install dir:   ${RB_ARCH_INSTALL_DIR}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
