project(Broccoli C)
cmake_minimum_required(VERSION 2.6.3 FATAL_ERROR)
include(cmake/CommonCMakeConfig.cmake)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

set(SOVersion 5) # this must be incremented when broccoli interface changes
set(SOVersionMinor 1)
set(SOVersionRelease 0)

set(BRO_SYSCONF_DIR ${BRO_ETC_INSTALL_DIR})

if (NOT BRO_SYSCONF_FILE)
    # BRO_SYSCONF_FILE not already defined from the --with-configfile option
    set(BRO_SYSCONF_FILE ${BRO_SYSCONF_DIR}/broccoli.conf)
endif ()

site_name(hostname)
if (UNIX)
    execute_process(COMMAND date OUTPUT_VARIABLE builddate
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
else ()
    set(builddate "build date not available")
endif ()
set(BUILDINFO "${hostname}, ${builddate}, Debugging support: ${ENABLE_DEBUG}")

# if no static/shared library preference is given, default to building both
if (NOT DEFINED ENABLE_SHARED)
    set(ENABLE_SHARED true)
endif ()

if (NOT DEFINED ENABLE_STATIC)
    set(ENABLE_STATIC true)
endif ()

########################################################################
## Dependency Configuration

include(FindRequiredPackage)

FindRequiredPackage(OpenSSL)
FindRequiredPackage(FLEX)
FindRequiredPackage(BISON)
find_package(PCAP)

set(BRO_PCAP_SUPPORT true)
if (NOT PCAP_INCLUDE_DIR)
    set(BRO_PCAP_SUPPORT false)
endif ()

if (MISSING_PREREQS)
    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(SEND_ERROR ${prereq})
    endforeach ()
    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

########################################################################
## System Introspection

if (${CMAKE_SYSTEM_NAME} MATCHES "BSD")
    set(BSD_HOST true)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX_HOST true)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Solaris")
    set(BRO_LIBADD socket nsl)
elseif (MINGW)
    set(BRO_LIBADD wsock32)
endif ()

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

include(CheckFunctionExists)
check_function_exists(geteuid HAVE_GETEUID)
check_function_exists(getpwuid HAVE_GETPWUID)

include(CheckTypeSize)

set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h)
check_type_size(uint UINT)
if (NOT UINT)
    set (TYPEDEF_UINT "typedef unsigned int uint")
endif ()
set(CMAKE_EXTRA_INCLUDE_FILES)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/broccoli-config.in
               ${CMAKE_CURRENT_BINARY_DIR}/broccoli-config
               @ONLY)

include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})
add_definitions(-DHAVE_CONFIG_H)

########################################################################
## Install Files

include(InstallPackageConfigFile)

InstallPackageConfigFile(
    ${CMAKE_CURRENT_SOURCE_DIR}/broccoli.conf
    ${BRO_SYSCONF_DIR}
    broccoli.conf)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/broccoli-config DESTINATION bin)

########################################################################
## Recurse on sub-directories

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(doc)

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bindings/broccoli-python/CMakeLists.txt
    AND NOT DISABLE_PYTHON_BINDINGS)
    add_subdirectory(bindings/broccoli-python)
else ()
    message(STATUS "Not building broccoli-python bindings")
endif ()

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bindings/broccoli-ruby/CMakeLists.txt
    AND NOT DISABLE_RUBY_BINDINGS)
    add_subdirectory(bindings/broccoli-ruby)
else ()
    message(STATUS "Not building broccoli-ruby bindings")
endif ()

########################################################################
## Packaging Setup

# If this CMake project is a sub-project of another, we will not
# configure the generic packaging because CPack will fail in the case
# that the parent project has already configured packaging
if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()

########################################################################
## Build Summary

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n=================|  Broccoli Build Summary  |==================="
    "\n"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\nShared libs:       ${ENABLE_SHARED}"
    "\nStatic libs:       ${ENABLE_STATIC}"
    "\n"
    "\nConfig file:       ${BRO_SYSCONF_FILE}"
    "\nPacket support:    ${BRO_PCAP_SUPPORT}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_C_COMPILER}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
