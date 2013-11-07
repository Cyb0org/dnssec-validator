#/**********************************************************\ 
# 
# Auto-generated CMakeLists.txt for the DNSSECValidatorPlugin project
#
#\**********************************************************/

# Written to work with cmake 2.6
cmake_minimum_required (VERSION 2.6)
set (CMAKE_BACKWARDS_COMPATIBILITY 2.6)

if (NOT WIN32)
Project(${PLUGIN_NAME})
endif ()

if (WIN32)
include(${CMAKE_DIR}/common.cmake)
set (PROJNAME ${PLUGIN_NAME})
browserplugin_project(${PROJNAME})
endif ()

# add validating library to build on UNIX
if (NOT WIN32)
    set(DSLIB dnssec-plug.c)
endif ()

file (GLOB GENERAL RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    [^.]*.cpp
    [^.]*.h
    [^.]*.cmake
    ${DSLIB}
    )

if (NOT WIN32)
    include_directories(${PLUGIN_INCLUDE_DIRS})
endif ()

# Generated files are stored in ${GENERATED} by the project configuration
SET_SOURCE_FILES_PROPERTIES(
    ${GENERATED}
    PROPERTIES
        GENERATED 1
    )

SOURCE_GROUP(Generated FILES
    ${GENERATED}
    )

SET( SOURCES
    ${GENERAL}
    ${GENERATED}
    )

# This will include Win/projectDef.cmake, X11/projectDef.cmake, Mac/projectDef 
# depending on the platform
include_platform()

#this will build a Chrome package
#add_chrome_package(${PLUGIN_NAME}
#	${FB_BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/ 
#	"${FB_BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/${FBSTRING_PluginFileName}.dll"
#	"${CMAKE_CURRENT_SOURCE_DIR}/sign/package_key.pem"
#	${PROJECT_NAME})

#this will build a XPI package using XPISigner (see http://code.google.com/p/xpisigner/ )
# add_signed_xpi_installer(${PLUGIN_NAME}
# 	${FB_BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/ 
#   "${FB_BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/${FBSTRING_PluginFileName}.dll"
# 	$ENV{XPI_PATH} 
# 	"${CMAKE_CURRENT_SOURCE_DIR}/sign/certificate.pfx" 
# 	"${CMAKE_CURRENT_SOURCE_DIR}/sign/passphrase.txt"
# 	${PROJECT_NAME})

