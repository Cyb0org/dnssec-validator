
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4


AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h \
	@CORE_CPPFLAGS@ \
	-I$(top_srcdir)/plugin-source/common/


noinst_PROGRAMS = \
	dnssec-plug \
	dane-plug


dnssec_plug_SOURCES = \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/dnssec-main.c

dnssec_plug_LDADD = \
	$(top_srcdir)/core_js-ctypes/.libs/libDNSSECcore.a

dnssec_plug_LDADD += \
	@CORE_LIBS@

if STATIC_CORE
# The order of libraries does matter.
dnssec_plug_LDADD += \
	$(abs_top_builddir)/static-libs/libs-built/unbound/lib/libunbound.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libssl.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libcrypto.a
endif


dane_plug_SOURCES = \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/dane-main.c

dane_plug_LDADD = \
	$(top_srcdir)/core_js-ctypes/.libs/libDANEcore.a

dane_plug_LDADD += \
	@CORE_LIBS@

if STATIC_CORE
# The order of libraries does matter.
dane_plug_LDADD += \
	$(abs_top_builddir)/static-libs/libs-built/ldns/lib/libldns.a \
	$(abs_top_builddir)/static-libs/libs-built/unbound/lib/libunbound.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libssl.a \
	$(abs_top_builddir)/static-libs/libs-built/openssl/lib/libcrypto.a
endif
