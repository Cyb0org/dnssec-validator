
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

all: libDNSSECcore$(SO_SUFF) libDANEcore$(SO_SUFF)


AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h


EXTRA_LTLIBRARIES = \
	libDNSSECcore.la \
	libDANEcore.la


CLEANFILES = \
	libDNSSECcore.la \
	libDNSSECcore$(SO_SUFF) \
	libDANEcore.la \
	libDANEcore$(SO_SUFF)


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
	-rpath "/usr/lib" \
	@CORE_LDFLAGS@

libDNSSECcore_la_LIBADD = \
	@CORE_LIBS@

if STATIC_CORE
#libDNSSECcore_la_LDFLAGS += \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libcrypto.a,--no-whole-archive \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libssl.a,--no-whole-archive \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/ldns/lib/libldns.a,--no-whole-archive \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/unbound/lib/libunbound.a,--no-whole-archive
# The order of libraries does matter.
libDNSSECcore_la_LDFLAGS += \
	$(abs_top_builddir)/static-libs/libs-built/unbound/lib/libunbound.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libssl.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libcrypto.a
endif


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
	-rpath "/usr/lib" \
	@CORE_LDFLAGS@

libDANEcore_la_LIBADD = \
	@CORE_LIBS@

if STATIC_CORE
#libDANEcore_la_LDFLAGS += \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libcrypto.a,--no-whole-archive \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libssl.a,--no-whole-archive \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/ldns/lib/libldns.a,--no-whole-archive \
#	-Wl,--whole-archive,$(abs_top_builddir)/static-libs/libs-built/unbound/lib/libunbound.a,--no-whole-archive
# The order of libraries does matter.
libDANEcore_la_LDFLAGS += \
	$(abs_top_builddir)/static-libs/libs-built/ldns/lib/libldns.a \
	$(abs_top_builddir)/static-libs/libs-built/unbound/lib/libunbound.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libssl.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libcrypto.a
endif


libDNSSECcore$(SO_SUFF): libDNSSECcore.la
	$(INSTALL) -s -m 644 .libs/libDNSSECcore$(SO_SUFF) $@ # FIXME: Ugly

libDANEcore$(SO_SUFF): libDANEcore.la
	$(INSTALL) -s -m 644 .libs/libDANEcore$(SO_SUFF) $@ # FIXME: Ugly
