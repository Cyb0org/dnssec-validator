#/**********************************************************\ 
# Auto-generated Mac project definition file for the
# TLSAValidatorPlugin project
#\**********************************************************/

# Mac template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in Mac/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    Mac/[^.]*.cpp
    Mac/[^.]*.h
    Mac/[^.]*.cmake
    )

SOURCE_GROUP(Mac FILES ${PLATFORM})

# use this to add preprocessor definitions
add_definitions(
  -DTGT_SYSTEM=TGT_OSX
  -DCA_STORE=OSX_CA_STORE
)

set (SOURCES
    ${SOURCES}
    ../common/log_osx.m
    ca_store_osx.m
    ${PLATFORM}
    )

set(PLIST "Mac/bundle_template/Info.plist")
set(STRINGS "Mac/bundle_template/InfoPlist.strings")
set(LOCALIZED "Mac/bundle_template/Localized.r")

add_mac_plugin(${PROJECT_NAME} ${PLIST} ${STRINGS} ${LOCALIZED} SOURCES)

SET(CMAKE_LIBRARY_PATH_FLAG ${CMAKE_LIBRARY_PATH_FLAG} ${LIBRARY_LOC})
SET(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} ${LIBRARY_LOC})

IF(STATIC_LINKING STREQUAL "yes")
  # set header file directories
  include_directories(AFTER
                      ${CMAKE_CURRENT_SOURCE_DIR}/../../../${LIBS_BUILT_DIR}/openssl/include
                      ${CMAKE_CURRENT_SOURCE_DIR}/../../../${LIBS_BUILT_DIR}/ldns/include
                      ${CMAKE_CURRENT_SOURCE_DIR}/../../../${LIBS_BUILT_DIR}/unbound/include
                      ${INCLUDE_LOC}
                      ${CMAKE_CURRENT_SOURCE_DIR}/../../../plugin-source/common)

  # set static library paths
  add_library(unbound STATIC IMPORTED)
  set_property(TARGET unbound PROPERTY IMPORTED_LOCATION
               ${CMAKE_CURRENT_SOURCE_DIR}/../../../${LIBS_BUILT_DIR}/unbound/lib/libunbound.a)

  add_library(ldns STATIC IMPORTED)
  set_property(TARGET ldns PROPERTY IMPORTED_LOCATION
               ${CMAKE_CURRENT_SOURCE_DIR}/../../../${LIBS_BUILT_DIR}/ldns/lib/libldns.a)

  add_library(ssl STATIC IMPORTED)
  set_property(TARGET ssl PROPERTY IMPORTED_LOCATION
               ${CMAKE_CURRENT_SOURCE_DIR}/../../../${LIBS_BUILT_DIR}/openssl/lib/libssl.a)

  add_library(crypto STATIC IMPORTED)
  set_property(TARGET crypto PROPERTY IMPORTED_LOCATION
               ${CMAKE_CURRENT_SOURCE_DIR}/../../../${LIBS_BUILT_DIR}/openssl/lib/libcrypto.a)

  SET(UNBOUND unbound)
  SET(LDNS ldns)
  SET(SSL ssl)
  SET(CRYPTO crypto)
ELSE()
  include_directories(AFTER
                      ${INCLUDE_LOC}
                      ${CMAKE_CURRENT_SOURCE_DIR}/../../../plugin-source/common)

  FIND_LIBRARY(UNBOUND unbound)
  FIND_LIBRARY(LDNS ldns)
  FIND_LIBRARY(SSL ssl)
  FIND_LIBRARY(CRYPTO crypto)
ENDIF()

FIND_LIBRARY(COCOA_FRAMEWORK Cocoa)
FIND_LIBRARY(SECURITY_FRAMEWORK Security)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    ${UNBOUND}
    ${LDNS}
    ${SSL}
    ${CRYPTO}
    ${COCOA_FRAMEWORK}
    ${SECURITY_FRAMEWORK}
    )

#To create a DMG, include the following file
#include(Mac/installer.cmake)
