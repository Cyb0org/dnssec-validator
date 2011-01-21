# ***** BEGIN LICENSE BLOCK *****
# Copyright 2010, 2011 CZ.NIC, z.s.p.o.
#
# This file is part of DNSSEC Validator Add-on.
#
# DNSSEC Validator Add-on is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# DNSSEC Validator Add-on is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
# ***** END LICENSE BLOCK *****

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
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../lib/linux/${BUILD_ARCH}
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/ldns
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/openssl/include)

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
