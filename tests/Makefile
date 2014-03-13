
.PHONY: all clean loc run

# Passed parameter.
USE_STATIC ?= yes

# Determine OS type
KERNEL = $(shell uname -s | tr '[:upper:]' '[:lower:]')
# Determine achitexture.
ARCH = $(shell uname -m | tr '[:upper:]' '[:lower:]' | sed -e 's/amd64/x86_64/g')

# OS dependent stuff.
ifeq ($(USE_STATIC), yes)
  UNBOUND_CFLAGS = -I../libs/unbound/include
  UNBOUND_LDFLAGS = -L../libs/unbound/lib -lunbound
  UNBOUND_STATIC = ../libs/unbound/lib/libunbound.a
  LDNS_CFLAGS = -I../libs/ldns/include
  LDNS_LDFLAGS = -L../libs/ldns/lib -lldns
  LDNS_STATIC = ../libs/ldns/lib/libldns.a
  OPENSSL_CFLAGS = -I../libs/openssl/include
  OPENSSL_LDFLAGS = -L../libs/openssl/lib -lssl -lcrypto
  OPENSSL_STATIC = ../libs/openssl/lib/libssl.a ../libs/openssl/lib/libcrypto.a

  STATIC_LIBS = $(UNBOUND_STATIC) $(LDNS_STATIC) $(OPENSSL_STATIC)
else
  THIRD_PARTY_LOCATION := $(shell echo ${HOME})/third_party/built
  #UNBOUND_CFLAGS =
  UNBOUND_LDFLAGS = -lunbound
  ifeq ($(strip $(UNBOUND_CFLAGS)),)
    UNBOUND_CFLAGS = -I$(THIRD_PARTY_LOCATION)/include
    UNBOUND_LDFLAGS = -L$(THIRD_PARTY_LOCATION)/lib -Wl,-rpath,$(THIRD_PARTY_LOCATION)/lib $(UNBOUND_LDFLAGS)
  endif
  #LDNS_CFLAGS =
  LDNS_LDFLAGS = -lldns
  ifeq ($(strip $(UNBOUND_CFLAGS)),)
    LDNS_CFLAGS = -I$(THIRD_PARTY_LOCATION)/include
    LDNS_LDFLAGS = -L$(THIRD_PARTY_LOCATION)/lib -Wl,-rpath,$(THIRD_PARTY_LOCATION)/lib $(LDNS_LDFLAGS)
  endif
  OPENSSL_CFLAGS = $(shell pkg-config --cflags openssl)
  OPENSSL_LDFLAGS = $(shell pkg-config --libs openssl)
endif


CPPFLAGS += -DCMNDLINE_TEST

OPTFLAGS = -g -O0
#OPTFLAGS = -g -O3
CFLAGS += $(OPTFLAGS) -Wall -Wextra -pedantic
CFLAGS += $(OPENSSL_CFLAGS) $(LDNS_CFLAGS) $(UNBOUND_CFLAGS)
CFLAGS += -I../plugin-source/common
CFLAGS_STD = -std=c99

LDFLAGS += $(UNBOUND_LDFLAGS) $(LDNS_LDFLAGS) $(OPENSSL_LDFLAGS)
LDFLAGS += -lpthread
ifneq ($(KERNEL),freebsd)
  LDFLAGS += -ldl
endif


# Which system is it compiled on.
ifeq ($(KERNEL),darwin)
  CPPFLAGS += -DTGT_SYSTEM=TGT_OSX
  LOG_OBJ = log_osx.o
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



TARGETS := dane-plug dnssec-plug

## Generic targets

all: $(TARGETS)

run: all
	./dane-plug gitlab.labs.nic.cz
	./dnssec-plug

clean:
	rm -f *.o $(TARGETS)

## Separate test builds

common.o: ../plugin-source/common/common.c ../plugin-source/common/common.h
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

dnssec-plug: dnssec-plug.o common.o $(LOG_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

dnssec-plug.o: ../plugin-source/DNSSECValidatorPlugin/dnssec-plug.c $(STATIC_LIBS)
	$(CC) -c $< -o $@ $(CPPFLAGS) $(CFLAGS) $(CFLAGS_STD)

dane-plug: dane-plug.o common.o $(CA_STORE_OBJ) $(LOG_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

dane-plug.o: ../plugin-source/TLSAValidatorPlugin/dane-plug.c $(STATIC_LIBS)
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
