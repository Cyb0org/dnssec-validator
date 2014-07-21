# ***** BEGIN LICENSE BLOCK *****
# Copyright 2011, 2012 CZ.NIC, z.s.p.o.
#
# Authors: Karel Slany <karel.slany@nic.cz>
#
# This file is part of DNSSEC Validator 2.0 Add-on.
#
# DNSSEC Validator 2.0 Add-on is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# DNSSEC Validator 2.0 Add-on is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# DNSSEC Validator 2.0 Add-on.  If not, see <http://www.gnu.org/licenses/>.
# ***** END LICENSE BLOCK *****


.PHONY: all clean

include ../Makefile.layout


OSNAME ?= UNIX
# Lower case.
OSNAME_LC ?= unix
MAKE_CMD ?= make
SHELL_CMD ?= bash
SHLIB_SUFF ?= so


BASEDIR = ..
JSCTYPES_CORE_DIR = core_js-ctypes
OPENSSL_LIB = $(BASEDIR)/$(LIBS_BUILT_DIR)/openssl
LDNS_LIB = $(BASEDIR)/$(LIBS_BUILT_DIR)/ldns
UNBOUND_LIB = $(BASEDIR)/$(LIBS_BUILT_DIR)/unbound


# Determine OS type
KERNEL = $(shell uname -s | tr '[:upper:]' '[:lower:]')


# OS dependent stuff.
STATIC_LINKING ?= yes
ifeq ($(STATIC_LINKING),yes)
  OPENSSL_CFLAGS = -I$(OPENSSL_LIB)/include
  OPENSSL_LDFLAGS = -L$(OPENSSL_LIB)/lib
  OPENSSL_STATIC = $(OPENSSL_LIB)/lib/libssl.a $(OPENSSL_LIB)/lib/libcrypto.a
  LDNS_CFLAGS = -I$(LDNS_LIB)/include
  LDNS_LDFLAGS = -L$(LDNS_LIB)/lib
  LDNS_STATIC = $(LDNS_LIB)/lib/libldns.a
  UNBOUND_CFLAGS = -I$(UNBOUND_LIB)/include
  UNBOUND_LDFLAGS = -L$(UNBOUND_LIB)/lib
  UNBOUND_STATIC = $(UNBOUND_LIB)/lib/libunbound.a

  STATIC_LIBS = $(OPENSSL_STATIC) $(LDNS_STATIC) $(UNBOUND_STATIC)

  ifneq ($(KERNEL),darwin)
    # On OS X the following flags should be omitted when linking statically.
    LDFLAGS += -lssl -lcrypto -lldns -lunbound
  endif
else
  #UNBOUND_CFLAGS =
  UNBOUND_LDFLAGS = -lunbound
  #LDNS_CFLAGS =
  LDNS_LDFLAGS = -lldns
  OPENSSL_CFLAGS = $(shell pkg-config --cflags openssl)
  OPENSSL_LDFLAGS = $(shell pkg-config --libs openssl)
endif


OPTFLAGS = -g -O0
#OPTFLAGS = -g -O3
PICFLAGS = -fPIC -g
CFLAGS += $(OPTFLAGS) $(PICFLAGS) -Wall -Wextra -pedantic
CFLAGS += $(OPENSSL_CFLAGS) $(LDNS_CFLAGS) $(UNBOUND_CFLAGS)
CFLAGS += -I../plugin-source/common
CFLAGS_STD = -std=c99

LDFLAGS_DNSSEC_VISIBILITY = -Wl,-version-script -Wl,$(BASEDIR)/$(JSCTYPES_CORE_DIR)/libDNSSECcore.ver
LDFLAGS_DANE_VISIBILITY = -Wl,-version-script -Wl,$(BASEDIR)/$(JSCTYPES_CORE_DIR)/libDANEcore.ver
LDFLAGS += $(UNBOUND_LDFLAGS) $(LDNS_LDFLAGS) $(OPENSSL_LDFLAGS)
LDFLAGS += -lpthread
LDFLAGS += $(LDFLAGS_VISIBILITY)

# Which system is it compiled on.
ifeq ($(KERNEL),darwin)
  CPPFLAGS += -DTGT_SYSTEM=TGT_OSX
  LOG_OBJ = log_osx.o
  SHLIB_SUFF = dylib
  LDFLAGS_DNSSEC_VISIBILITY =
  LDFLAGS_DANE_VISIBILITY =
else
  # Default settings.
  LOG_OBJ = log_dflt.o
endif


# Which CA store to use.
CA_STORE ?= AUTO
ifeq ($(CA_STORE),AUTO)
  ifeq ($(KERNEL),linux)
    CPPFLAGS += -DCA_STORE=DIR_CA_STORE
    CA_STORE_OBJ = ca_store_directory.o
  else
    ifeq ($(KERNEL),freebsd)
      CPPFLAGS += -DCA_STORE=DIR_CA_STORE
      CA_STORE_OBJ = ca_store_directory.o
    else
      ifeq ($(KERNEL),darwin)
        CPPFLAGS += -DCA_STORE=OSX_CA_STORE
        CA_STORE_OBJ = ca_store_osx.o
        LDFLAGS += -framework Cocoa -framework Security
      else
        #CPPFLAGS += -DCA_STORE=NONE_CA_STORE
        #CA_STORE_OBJ =
      endif
    endif
  endif
else
  ifeq ($(CA_STORE),NONE)
    #CPPFLAGS += -DCA_STORE=NONE_CA_STORE
    #CA_STORE_OBJ = 
  else
    ifeq ($(CA_STORE),DIR)
      CPPFLAGS += -DCA_STORE=DIR_CA_STORE
      CA_STORE_OBJ = ca_store_directory.o
    else
      ifeq ($(CA_STORE),NSS)
        CPPFLAGS += -DCA_STORE=NSS_CA_STORE
        CA_STORE_OBJ = ca_store_nss.o
        CFLAGS += $(shell pkg-config --cflags nss)
        LDFLAGS += $(shell pkg-config --libs nss)
      else
        ifeq ($(CA_STORE),OSX)
          CPPFLAGS += -DCA_STORE=OSX_CA_STORE
          CA_STORE_OBJ = ca_store_osx.o
          LDFLAGS += -framework Cocoa -framework Security
        else
          #CPPFLAGS += -DCA_STORE=NONE_CA_STORE
          #CA_STORE_OBJ =
        endif
      endif
    endif
  endif
endif


TARGETS = libDNSSECcore-$(OSNAME_LC)-$(HWARCH).$(SHLIB_SUFF) libDANEcore-$(OSNAME_LC)-$(HWARCH).$(SHLIB_SUFF)

all: $(TARGETS)

clean:
	rm -f *.o $(TARGETS)

## Separate test builds

common.o: ../plugin-source/common/common.c ../plugin-source/common/common.h
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

libDNSSECcore-$(OSNAME_LC)-$(HWARCH).$(SHLIB_SUFF): dnssec-plug.o common.o $(LOG_OBJ) $(STATIC_LIBS)
	$(CC) $^ -o $@ $(LDFLAGS) -shared $(LDFLAGS_DNSSEC_VISIBILITY) $(CFLAGS)

dnssec-plug.o: ../plugin-source/DNSSECValidatorPlugin/dnssec-plug.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

libDANEcore-$(OSNAME_LC)-$(HWARCH).$(SHLIB_SUFF): dane-plug.o common.o $(CA_STORE_OBJ) $(LOG_OBJ) $(STATIC_LIBS)
	$(CC) $^ -o $@ $(LDFLAGS) -shared $(LDFLAGS_DANE_VISIBILITY) $(CFLAGS)

dane-plug.o: ../plugin-source/TLSAValidatorPlugin/dane-plug.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

ca_store_directory.o: ../plugin-source/TLSAValidatorPlugin/ca_store_directory.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

ca_store_nss.o: ../plugin-source/TLSAValidatorPlugin/ca_store_nss.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

ca_store_osx.o: ../plugin-source/TLSAValidatorPlugin/ca_store_osx.m
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS)

log_dflt.o: ../plugin-source/common/log_dflt.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

log_osx.o: ../plugin-source/common/log_osx.m
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS)
