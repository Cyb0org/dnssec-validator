#/**********************************************************\ 
# Auto-generated X11 project definition file for the
# DNSSECValidatorPlugin project
#\**********************************************************/

# X11 template platform definition CMake file
# Included from ../CMakeLists.txt

# remember that the current source dir is the project root; this file is in X11/
file (GLOB PLATFORM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    X11/[^.]*.cpp
    X11/[^.]*.h
    X11/[^.]*.cmake
    )

SOURCE_GROUP(X11 FILES ${PLATFORM})

# use this to add preprocessor definitions
add_definitions(
  -DTGT_SYSTEM=TGT_DFLT
)

set (SOURCES
    ${SOURCES}
    ../common/log_dflt.c
    ${PLATFORM}
    )

add_x11_plugin(${PROJECT_NAME} SOURCES)

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


# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJECT_NAME}
    ${PLUGIN_INTERNAL_DEPS}
    unbound
    ldns
    ssl    	
    crypto
    )
