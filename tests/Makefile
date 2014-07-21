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


.PHONY: all clean run

OSNAME_LC = linux
# Determine architecture.
HWARCH = $(shell uname -m | tr '[:upper:]' '[:lower:]' | sed -e 's/amd64/x86_64/g')


include ../core_js-ctypes/Makefile


ifneq ($(STATIC_LINKING),yes)
  THIRD_PARTY_LOCATION := $(shell echo ${HOME})/third_party/built
  ifeq ($(strip $(UNBOUND_CFLAGS)),)
    UNBOUND_CFLAGS = -I$(THIRD_PARTY_LOCATION)/include
    UNBOUND_LDFLAGS := -L$(THIRD_PARTY_LOCATION)/lib -Wl,-rpath,$(THIRD_PARTY_LOCATION)/lib $(UNBOUND_LDFLAGS)
  endif
  ifeq ($(strip $(UNBOUND_CFLAGS)),)
    LDNS_CFLAGS = -I$(THIRD_PARTY_LOCATION)/include
    LDNS_LDFLAGS := -L$(THIRD_PARTY_LOCATION)/lib -Wl,-rpath,$(THIRD_PARTY_LOCATION)/lib $(LDNS_LDFLAGS)
  endif
endif


CPPFLAGS += -DCMNDLINE_TEST

ifneq ($(KERNEL),freebsd)
  LDFLAGS += -ldl
endif

TARGETS += dane-plug dnssec-plug checkDNSSEClib checkDANElib

all: $(TARGETS)

run: all
	./dane-plug gitlab.labs.nic.cz
	./dnssec-plug

checkDNSSEClib.o: checkDNSSEClib.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD) -I../plugin-source/DNSSECValidatorPlugin

checkDNSSEClib: checkDNSSEClib.o libDNSSECcore-$(OSNAME_LC)-$(HWARCH).$(SHLIB_SUFF)
	$(CC) $^ -o $@ -L. -Wl,-rpath,. -lDNSSECcore-$(OSNAME_LC)-$(HWARCH)

dnssec-plug: dnssec-plug.o common.o $(LOG_OBJ) $(STATIC_LIBS)
	$(CC) $^ -o $@ $(LDFLAGS)

checkDANElib.o: checkDANElib.c
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD) -I../plugin-source/TLSAValidatorPlugin

checkDANElib: checkDANElib.o libDANEcore-$(OSNAME_LC)-$(HWARCH).$(SHLIB_SUFF)
	$(CC) $^ -o $@ -L. -Wl,-rpath,. -lDANEcore-$(OSNAME_LC)-$(HWARCH)

dane-plug: dane-plug.o common.o $(CA_STORE_OBJ) $(LOG_OBJ) $(STATIC_LIBS)
	$(CC) $^ -o $@ $(LDFLAGS)


#PUGIN_INCLUDES := -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include
#PLUGIN_LIBS := -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -lunbound -lldns -lssl -lcrypto -lpthread -ldl

#LOC_LOCATION := $(shell echo ${HOME})/third_party/built
#LOC_INCLUDES := -I$(LOC_LOCATION)/include
#LOC_LIBS := -L$(LOC_LOCATION)/lib -Wl,-rpath,$(LOC_LOCATION)/lib -lunbound -lldns

#dane-plug-loclibs: ../plugin-source/TLSAValidatorPlugin/dane-plug.c
#	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LOC_INCLUDES) $(LOC_LIBS)

#unbound-test-dnssec: unbound-test-dnssec.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
#	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(PLUGIN_INCLUDES) $(PLUGIN_LIBS)

#ssl-test: ssl-test.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
#	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS_NOSTD) $(LDFLAGS) $(PLUGIN_INCLUDES) $(PLUGIN_LIBS)
##	gcc -Wall -pedantic -g -lssl -lcrypto -o ssl-test ssl-test.c

#dnssec-plug.o: ../plugin-source/DNSSECValidatorPlugin/dnssec-plug.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
#	$(CC) -c $^ -o $@ $(CPPFLAGS) $(CFLAGS) $(PLUGIN_INCLUDES)

#dnssec-plug-loclibs: ../plugin-source/DNSSECValidatorPlugin/dnssec-plug.c
#	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LOC_INCLUDES) $(LOC_LIBS)
