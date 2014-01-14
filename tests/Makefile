.PHONY: all clean loc run


OPENSSL_LIB := ../libs/openssl
LDNS_LIB := ../libs/ldns
UNBOUND_LIB := ../libs/unbound
#NPAPI_LIB := ../FireBreath/build/bin/TLSAfetcher
#NPAPI_LINK := -Wl,-\( $(NPAPI_LIB)/npTLSAfetcher.so -Wl,-\)
#DANE_CORE_LIB := ../FireBreath/build/projects/TLSAfetcher/libDANECore.a

FB_DIR := ../FireBreath
COMMON_INCLUDE := -I../plugin-source/common
FB_INCLUDE := -I$(FB_DIR)/src/ScriptingCore -I$(FB_DIR)/src/config
BOOST_FLAGS := -I$(FB_DIR)/src/3rdParty/boost -DBOOST_ALL_NO_LIB=1

PLUGIN_INCLUDES := -I$(OPENSSL_LIB)/include -I$(LDNS_LIB)/include -I$(UNBOUND_LIB)/include $(FB_INCLUDE) $(COMMON_INCLUDE)
PLUGIN_LIBS := -L$(UNBOUND_LIB)/lib -L$(OPENSSL_LIB)/lib -L$(LDNS_LIB)/lib -lunbound -lldns -lssl -lcrypto -lpthread -ldl

LOC_LOCATION := $(shell echo ${HOME})/third_party/built
LOC_INCLUDES := -I$(LOC_LOCATION)/include
LOC_LIBS := -L$(LOC_LOCATION)/lib -Wl,-rpath,$(LOC_LOCATION)/lib -lunbound -lldns

OPTFLAGS = -g -O0
#OPTFLAGS = -g -O3
CPPFLAGS += -DCMNDLINE_TEST
CPPFLAGS += -DRES_OSX
#CPPFLAGS += -DCA_STORE=OSX_CA_STORE
CFLAGS_NOSTD += $(INCLUDES) -Wall -Wextra -pedantic $(OPTFLAGS)
CFLAGS_NOSTD += $(shell pkg-config --cflags nss)
CFLAGS += $(CFLAGS_NOSTD) -std=c99
CXXFLAGS += $(INCLUDES) -Wall -Westra -pedantic $(OPTFLAGS)
LDFLAGS += $(LIBS)
LDFLAGS += $(shell pkg-config --libs nss)
#LDFLAGS += -framework Cocoa -framework Security

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
	rm -f *.o $(TARGETS) $(TARGETS_LOCLIBS)

## Separate test builds

#dane-plug: ../plugin-source/TLSAValidatorPlugin/dane-plug.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
#	$(CC) $< -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(PLUGIN_INCLUDES) $(PLUGIN_LIBS)

#dane-plug: dane-plug.o ca_store_osx.o
#	$(CC) $^ -o $@ $(LDFLAGS) $(PLUGIN_LIBS)

dane-plug: dane-plug.o
	$(CC) $^ -o $@ $(LDFLAGS) $(PLUGIN_LIBS)

dane-plug.o: ../plugin-source/TLSAValidatorPlugin/dane-plug.c $(UNBOUND_LIB) $(DANE_CORE_LIB)
	$(CC) -c $^ -o $@ $(CPPFLAGS) $(CFLAGS) $(PLUGIN_INCLUDES)

ca_store_osx.o: ../plugin-source/TLSAValidatorPlugin/ca_store_osx.m
	$(CC) -c $^ -o $@ $(CPPFLAGS) $(CFLAGS_NOSTD) $(PLUGIN_INCLUDES)

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
