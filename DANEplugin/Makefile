.PHONY: build-tests run-tests clean-tests

all: build-tests

OPENSSL_LIB := ../libs/openssl
LDNS_LIB := ../libs/ldns
UNBOUND_LIB := ../libs/unbound
#NPAPI_LIB := ../FireBreath/build/bin/TLSAfetcher
#NPAPI_LINK := -Wl,-\( $(NPAPI_LIB)/npTLSAfetcher.so -Wl,-\)
#DANE_CORE_LIB := ../FireBreath/build/projects/TLSAfetcher/libDANECore.a

PLUGIN_SOURCE_DIR := ./
FB_DIR := ../FireBreath
FB_INCLUDE := -I$(FB_DIR)/src/ScriptingCore -I$(FB_DIR)/src/config
BOOST_FLAGS := -I$(FB_DIR)/src/3rdParty/boost -DBOOST_ALL_NO_LIB=1

INCLUDES := -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include -I$(PLUGIN_SOURCE_DIR) $(FB_INCLUDE)
LIBS := -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -lunbound -lldns -lssl -lcrypto -lpthread -ldl
CFLAGS += $(INCLUDES) $(BOOST_FLAGS) -Wall -pedantic -g -std=c99
CFLAGS2 += $(INCLUDES) $(BOOST_FLAGS) -Wall -pedantic -g
CXXFLAGS += $(INCLUDES) $(BOOST_FLAGS) -Wall -g
LDFLAGS += $(DANE_CORE_LIB) $(LIBS)

TARGETS := dane-plug unbound-test-dnssec ssl-test iptest

## Generic targets

build-tests: $(TARGETS)

run-tests: build-tests
	./dane-plug
	./unbound-test-dnssec
	./ssl-test
	./iptest

clean-tests:
	rm -f $(TARGETS)

## Separate test builds

dane-plug: dane-plug.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

unbound-test-dnssec: unbound-test-dnssec.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

iptest: iptest.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CFLAGS) $(LDFLAGS)

ssl-test: ssl-test.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) $< -o $@ $(CFLAGS2) $(LDFLAGS) 
#	gcc -Wall -pedantic -g -lssl -lcrypto -o ssl-test ssl-test.c  


