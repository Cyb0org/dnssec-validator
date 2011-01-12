#/**********************************************************\ 
# Auto-generated Windows project definition file for the
# DNSSEC Validator project
#\**********************************************************/

# Windows template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in Win/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    Win/[^.]*.cpp
    Win/[^.]*.h
    Win/[^.]*.cmake
    )

# use this to add preprocessor definitions
add_definitions(
    /D "_ATL_STATIC_REGISTRY"
)

SOURCE_GROUP(Win FILES ${PLATFORM})

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_windows_plugin(${PROJNAME} SOURCES)

# generate .lib from the validating library compiled by mingw
add_custom_command(TARGET ${PROJNAME} PRE_LINK
                   COMMAND lib.exe /machine:x86 /def:ds_windows-x86.def
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../../tmp_build
    )

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../tmp_build/ds_windows-x86.lib
    )

set(WIX_HEAT_FLAGS
    -gg                 # Generate GUIDs
    -srd                # Suppress Root Dir
    -cg PluginDLLGroup  # Set the Component group name
    -dr INSTALLDIR      # Set the directory ID to put the files in
    )

add_wix_installer( ${PLUGIN_NAME}
    ${CMAKE_CURRENT_SOURCE_DIR}/Win/WiX/DNSSECValidatorInstaller.wxs
    PluginDLLGroup
    ${BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/
    ${BIN_DIR}/${PLUGIN_NAME}/${CMAKE_CFG_INTDIR}/np${PLUGIN_NAME}.dll
    ${PROJNAME}
    )
