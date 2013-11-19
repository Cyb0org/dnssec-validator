.PHONY: all clean loc run


OPENSSL_LIB := ../libs/openssl
LDNS_LIB := ../libs/ldns
UNBOUND_LIB := ../libs/unbound
#NPAPI_LIB := ../FireBreath/build/bin/TLSAfetcher
#NPAPI_LINK := -Wl,-\( $(NPAPI_LIB)/npTLSAfetcher.so -Wl,-\)
#DANE_CORE_LIB := ../FireBreath/build/projects/TLSAfetcher/libDANECore.a

FB_DIR := ../FireBreath
FB_INCLUDE := -I$(FB_DIR)/src/ScriptingCore -I$(FB_DIR)/src/config
BOOST_FLAGS := -I$(FB_DIR)/src/3rdParty/boost -DBOOST_ALL_NO_LIB=1

PLUGIN_INCLUDES := -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include $(FB_INCLUDE)
PLUGIN_LIBS := -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -lunbound -lldns -lssl -lcrypto -lpthread -ldl

LOC_LOCATION := $(shell echo ${HOME})/third_party/built
LOC_INCLUDES := -I$(LOC_LOCATION)/include
LOC_LIBS := -L$(LOC_LOCATION)/lib -Wl,-rpath,$(LOC_LOCATION)/lib -lunbound -lldns

OPTFLAGS = -g -O0
#OPTFLAGS = -g -O3
CPPFLAGS += -DCMNDLINE_TEST
CFLAGS_NOSTD += $(INCLUDES) -Wall -Wextra -pedantic $(OPTFLAGS)
CFLAGS += $(CFLAGS_NOSTD) -std=c99
CXXFLAGS += $(INCLUDES) -Wall -Westra -pedantic $(OPTFLAGS)
LDFLAGS += $(LIBS)

TARGETS := dane-plug unbound-test-dnssec ssl-test dnssec-plug
TARGETS_LOCLIBS := dane-plug-loclibs dnssec-plug-loclibs

## Generic targets

all: $(TARGETS)

loc: $(TARGETS_LOCLIBS)

run: all
	./dane-plug gitlab.labs.nic.cz
	./unbound-test-dnssec
	./ssl-test
	./dnssec-plug

clean:
	rm -f $(TARGETS) $(TARGETS_LOCLIBS)

## Separate test builds

dane-plug: ../plugin-source/TLSAValidatorPlugin/dane-plug.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(PLUGIN_INCLUDES) $(PLUGIN_LIBS)

dane-plug-loclibs: ../plugin-source/TLSAValidatorPlugin/dane-plug.c
	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LOC_INCLUDES) $(LOC_LIBS)

unbound-test-dnssec: unbound-test-dnssec.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(PLUGIN_INCLUDES) $(PLUGIN_LIBS)

ssl-test: ssl-test.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS_NOSTD) $(LDFLAGS) $(PLUGIN_INCLUDES) $(PLUGIN_LIBS)
#	gcc -Wall -pedantic -g -lssl -lcrypto -o ssl-test ssl-test.c  

dnssec-plug: ../plugin-source/DNSSECValidatorPlugin/dnssec-plug.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(PLUGIN_INCLUDES) $(PLUGIN_LIBS)

dnssec-plug-loclibs: ../plugin-source/DNSSECValidatorPlugin/dnssec-plug.c
	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(LOC_INCLUDES) $(LOC_LIBS)
