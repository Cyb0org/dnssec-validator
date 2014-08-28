
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

include Makefile.core

all: libDNSSECcore$(SO_SUFF) libDANEcore$(SO_SUFF)


AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h \
	@CORE_CPPFLAGS@ \
	-I$(top_srcdir)/plugin-source/common/

AM_CFLAGS = \
	@CORE_CFLAGS@


EXTRA_LTLIBRARIES = \
	libDNSSECcore.la \
	libDANEcore.la


CLEANFILES = \
	libDNSSECcore.la \
	libDNSSECcore$(SO_SUFF) \
	libDANEcore.la \
	libDANEcore$(SO_SUFF)


libDNSSECcore_la_SOURCES = \
	$(DNSSEC_CORE_SRCS)

libDNSSECcore_la_LDFLAGS = \
	-avoid-version \
	-export-symbols-regex "^(dnssec)_" \
	-rpath "/usr/lib" \
	-shared \
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
	$(DANE_CORE_SRCS)

libDANEcore_la_LDFLAGS = \
	-avoid-version \
	-export-symbols-regex "^(dane)_" \
	-rpath "/usr/lib" \
	-shared \
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
	$(INSTALL) -m 644 .libs/libDNSSECcore$(SO_SUFF) $@ # FIXME: Ugly
	$(STRIP) $@

libDANEcore$(SO_SUFF): libDANEcore.la
	$(INSTALL) -m 644 .libs/libDANEcore$(SO_SUFF) $@ # FIXME: Ugly
	$(STRIP) $@
