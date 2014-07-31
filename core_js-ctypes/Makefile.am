
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

# FIXME: Different suffixes on differemt systems.
all: libDNSSECcore.so libDANEcore.so


AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h


EXTRA_LTLIBRARIES = \
	libDNSSECcore.la \
	libDANEcore.la


CLEANFILES = \
	libDNSSECcore.so \
	libDANEcore.so


libDNSSECcore_la_SOURCES = \
	$(top_srcdir)/plugin-source/common/common.c \
	$(top_srcdir)/plugin-source/common/common.h \
	$(top_srcdir)/plugin-source/common/log.h \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/dnssec-plug.c

if LOG_DFLT
libDNSSECcore_la_SOURCES += \
	$(top_srcdir)/plugin-source/common/log_dflt.c
endif
if LOG_OSX
libDNSSECcore_la_SOURCES += \
	$(top_srcdir)/plugin-source/common/log_osx.c
endif

libDNSSECcore_la_CPPFLAGS = \
	@CORE_CPPFLAGS@
libDNSSECcore_la_CFLAGS = \
	-I$(top_srcdir)/plugin-source/common/ @CORE_CFLAGS@

libDNSSECcore_la_LDFLAGS = \
	-avoid-version \
	-export-symbols-regex "^(dnssec)_" \
	-shared \
	-rpath "/usr/lib"


libDANEcore_la_SOURCES = \
	$(top_srcdir)/plugin-source/common/common.c \
	$(top_srcdir)/plugin-source/common/common.h \
	$(top_srcdir)/plugin-source/common/log.h \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/dane-plug.c


if CA_STORE_DIR
libDANEcore_la_SOURCES += \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/ca_store_directory.c
endif
if CA_STORE_NSS
libDANEcore_la_SOURCES += \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/ca_store_nss.c
endif
if CA_STORE_OSX
libDANEcore_la_SOURCES += \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/ca_store_osx.c
endif

if LOG_DFLT
libDANEcore_la_SOURCES += \
	$(top_srcdir)/plugin-source/common/log_dflt.c
endif
if LOG_OSX
libDANEcore_la_SOURCES += \
	$(top_srcdir)/plugin-source/common/log_osx.c
endif

libDANEcore_la_CFLAGS = \
	-I$(top_srcdir)/plugin-source/common/

libDANEcore_la_LDFLAGS = \
	-avoid-version \
	-export-symbols-regex "^(dane)_" \
	-shared \
	-rpath "/usr/lib"


libDNSSECcore.so: libDNSSECcore.la
	$(INSTALL) -s -m 644 .libs/libDNSSECcore.so $@ # FIXME: Ugly

libDANEcore.so: libDANEcore.la
	$(INSTALL) -s -m 644 .libs/libDANEcore.so $@ # FIXME: Ugly
