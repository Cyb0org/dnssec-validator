# ***** BEGIN LICENSE BLOCK *****
# Copyright 2012 CZ.NIC, z.s.p.o.
#
# Authors: Martin Straka <martin.straka@nic.cz>
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

)


SOURCE_GROUP(Mac FILES ${PLATFORM})

set (SOURCES
    ${SOURCES}
    ${PLATFORM}
    )

set(PLIST "Mac/bundle_template/Info.plist")
set(STRINGS "Mac/bundle_template/InfoPlist.strings")
set(LOCALIZED "Mac/bundle_template/Localized.r")

add_mac_plugin(${PROJNAME} ${PLIST} ${STRINGS} ${LOCALIZED} SOURCES)

# set header file directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../libs/openssl/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/ldns/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/unbound/include)

# set static library paths
add_library(unbound STATIC IMPORTED)
set_property(TARGET unbound PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/unbound/lib/libunbound.a)

add_library(ldns STATIC IMPORTED)
set_property(TARGET ldns PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/ldns/lib/libldns.a)

add_library(ssl STATIC IMPORTED)
set_property(TARGET ssl PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/openssl/lib/libssl.a)

add_library(crypto STATIC IMPORTED)
set_property(TARGET crypto PROPERTY IMPORTED_LOCATION
             ${CMAKE_CURRENT_SOURCE_DIR}/../../libs/openssl/lib/libcrypto.a)

# add library dependencies here; leave ${PLUGIN_INTERNAL_DEPS} there unless you know what you're doing!
target_link_libraries(${PROJNAME}
    ${PLUGIN_INTERNAL_DEPS}
    ldns
    crypto
    unbound
    )
