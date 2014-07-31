
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4


AM_CPPFLAGS = \
	-include $(top_srcdir)/plugin-source/config.h


noinst_PROGRAMS = \
	dnssec-plug \
	dane-plug


dnssec_plug_SOURCES = \
	$(top_srcdir)/plugin-source/DNSSECValidatorPlugin/dnssec-main.c

dnssec_plug_CFLAGS = \
	-I$(top_srcdir)/plugin-source/common/

dnssec_plug_LDADD = \
	$(top_srcdir)/core_js-ctypes/.libs/libDNSSECcore.a


dane_plug_SOURCES = \
	$(top_srcdir)/plugin-source/TLSAValidatorPlugin/dane-main.c

dane_plug_CFLAGS = \
	-I$(top_srcdir)/plugin-source/common/

dane_plug_LDADD = \
	$(top_srcdir)/core_js-ctypes/.libs/libDANEcore.a
