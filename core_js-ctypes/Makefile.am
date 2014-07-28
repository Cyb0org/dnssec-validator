
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

all: libDNSSECcore.so

AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h

EXTRA_LTLIBRARIES = \
	libDNSSECcore.la \
	libDANEcore.la

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

libDNSSECcore_la_CFLAGS = \
	-I$(top_srcdir)/plugin-source/common/

libDNSSECcore_la_LDFLAGS = \
	-avoid-version \
	-export-symbols-regex "^(dnssec)_" \
	-shared \
	-rpath "/usr/lib"

libDNSSECcore.so: libDNSSECcore.la
	$(INSTALL) -s -m 644 .libs/libDNSSECcore.so $@ # FIXME: Ugly
