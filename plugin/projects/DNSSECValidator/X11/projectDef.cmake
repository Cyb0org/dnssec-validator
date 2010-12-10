#/**********************************************************\ 
# Auto-generated X11 project definition file for the
# DNSSEC Validator project
#\**********************************************************/

# X11 template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in ${PLATFORM_NAME}/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    ${PLATFORM_NAME}/[^.]*.cpp
    ${PLATFORM_NAME}/[^.]*.h
    ${PLATFORM_NAME}/[^.]*.cmake
    )

SOURCE_GROUP(${PLATFORM_NAME} FILES ${PLATFORM})

# use this to add preprocessor definitions
add_definitions(
)

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

add_x11_plugin(${PROJNAME} SOURCES)

# detect 32/64 bit system
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(UNIX_64_BIT 1)
else ()
  set(UNIX_64_BIT 0)
endif ()

# set appropriate arch for linking
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  if (CMAKE_CXX_FLAGS MATCHES "-m64" OR
      NOT CMAKE_CXX_FLAGS MATCHES "-m" AND UNIX_64_BIT)
    message("Configuring for 64bit build...")
    set(BUILD_ARCH "x64")
  elseif (CMAKE_CXX_FLAGS MATCHES "-m32" OR
          NOT CMAKE_CXX_FLAGS MATCHES "-m")
    message("Configuring for 32bit build...")
    set(BUILD_ARCH "x86")
  else ()
    message(FATAL_ERROR "Unknown plugin build architecture")
  endif ()
endif ()

# set header file directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../lib/ldns
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/openssl
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/linux/${BUILD_ARCH})

# set static library paths
add_library(ldns STATIC IMPORTED)
set_property(TARGET ldns PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/linux/${BUILD_ARCH}/libldns.a)
add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/linux/${BUILD_ARCH}/libcrypto.a)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    ldns
    crypto
    )
