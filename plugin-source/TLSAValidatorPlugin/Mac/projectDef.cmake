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

# use this to add preprocessor definitions
add_definitions(
  -DTGT_SYSTEM=TGT_OSX
  -DCA_STORE=OSX_CA_STORE
)


SOURCE_GROUP(Mac FILES ${PLATFORM})

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

# set header file directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/openssl/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/ldns/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/unbound/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../../plugin-source/common)

# set static library paths
add_library(unbound STATIC IMPORTED)
set_property(TARGET unbound PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/unbound/lib/libunbound.a)

add_library(ldns STATIC IMPORTED)
set_property(TARGET ldns PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/ldns/lib/libldns.a)

add_library(ssl STATIC IMPORTED)
set_property(TARGET ssl PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/openssl/lib/libssl.a)

add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs/openssl/lib/libcrypto.a)

FIND_LIBRARY(COCOA_FRAMEWORK Cocoa)
FIND_LIBRARY(SECURITY_FRAMEWORK Security)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    unbound
    ldns
    ssl
    crypto
    ${COCOA_FRAMEWORK}
    ${SECURITY_FRAMEWORK}
    )

#To create a DMG, include the following file
#include(Mac/installer.cmake)
