ACLOCAL_AMFLAGS = -I m4

all: dnssec.xpi

AM_CPPFLAGS = \
        -include $(top_builddir)/plugin-source/config.h

EXTRA_LTLIBRARIES = libDNSSECcore.la libDANEcore.la

libDNSSECcore_la_CFLAGS =					\
	-I$(top_srcdir)/plugin-source/common/

libDNSSECcore_la_SOURCES =					\
	plugin-source/common/common.c				\
	plugin-source/common/common.h				\
	plugin-source/common/log.h				\
	plugin-source/DNSSECValidatorPlugin/dnssec-plug.c

if LOG_DFLT
libDNSSECcore_la_SOURCES += plugin-source/common/log_dflt.c
endif
if LOG_OSX
libDNSSECcore_la_SOURCES += plugin-source/common/log_osx.c
endif

libDNSSECcore_la_LDFLAGS =					\
	-export-symbols-regex '^(dnssec)_'			\
	-rpath /usr/lib						\
	-avoid-version

libDANEcore_la_CFLAGS =						\
	-Iplugin-source/common/

libDANEcore_la_SOURCES =					\
	plugin-source/common/common.c				\
	plugin-source/common/common.h				\
	plugin-source/common/log.h				\
	plugin-source/TLSAValidatorPlugin/dane-plug.c


if CA_STORE_DIR
libDANEcore_la_SOURCES += plugin-source/TLSAValidatorPlugin/ca_store_directory.c
endif
if CA_STORE_NSS
libDANEcore_la_SOURCES += plugin-source/TLSAValidatorPlugin/ca_store_nss.c
endif
if CA_STORE_OSX
libDANEcore_la_SOURCES += plugin-source/TLSAValidatorPlugin/ca_store_osx.c
endif

if LOG_DFLT
libDANEcore_la_SOURCES += plugin-source/common/log_dflt.c
endif
if LOG_OSX
libDANEcore_la_SOURCES += plugin-source/common/log_osx.c
endif

libDANEcore_la_LDFLAGS =					\
	-export-symbols-regex '^(dane)_'			\
	-rpath /usr/lib						\
	-avoid-version

de_DE_LOCALE = \
	add-on/firefox/common/locale/de-DE/prefwindow.dtd	\
	add-on/firefox/common/locale/de-DE/dnssec.preferences	\
	add-on/firefox/common/locale/de-DE/dnssec.properties	\
	add-on/firefox/common/locale/de-DE/dnssec.dtd		\
	add-on/firefox/common/locale/de-DE/aboutwindow.dtd

en_US_LOCALE = \
	add-on/firefox/common/locale/en-US/prefwindow.dtd	\
	add-on/firefox/common/locale/en-US/dnssec.preferences	\
	add-on/firefox/common/locale/en-US/dnssec.properties	\
	add-on/firefox/common/locale/en-US/dnssec.dtd		\
	add-on/firefox/common/locale/en-US/aboutwindow.dtd

cs_CZ_LOCALE = \
	add-on/firefox/common/locale/cs-CZ/prefwindow.dtd	\
	add-on/firefox/common/locale/cs-CZ/dnssec.preferences	\
	add-on/firefox/common/locale/cs-CZ/dnssec.properties	\
	add-on/firefox/common/locale/cs-CZ/dnssec.dtd		\
	add-on/firefox/common/locale/cs-CZ/aboutwindow.dtd

dnssec_validator_LOCALES = $(de_DE_LOCALE) $(en_US_LOCALE) $(cs_CZ_LOCALE)

dnssec_validator_CONTENT = \
	add-on/firefox/js-ctypes/content/tlsa.js		\
	add-on/firefox/js-ctypes/content/firefoxOverlay.xul	\
	add-on/firefox/js-ctypes/content/preferences.xul	\
	add-on/firefox/js-ctypes/content/npapi_const.js		\
	add-on/firefox/js-ctypes/content/preferences.js		\
	add-on/firefox/js-ctypes/content/overlay.js		\
	add-on/firefox/js-ctypes/content/about.js		\
	add-on/firefox/js-ctypes/content/tlsalib.js		\
	add-on/firefox/js-ctypes/content/dnsseclib.js

do_subst = sed -e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	       -e 's,[@]libDNSSECcore[@],plugins/libDNSSECcore-$(OS_TARGET).so,g' \
	       -e 's,[@]libDANEcore[@],plugins/libDANEcore-$(OS_TARGET).so,g'

add-on/firefox/js-ctypes/content/tlsalib.js: $(srcdir)/add-on/firefox/js-ctypes/content/tlsalib.js.in Makefile
	$(do_subst) < $(srcdir)/add-on/firefox/js-ctypes/content/tlsalib.js.in > $@

add-on/firefox/js-ctypes/content/dnsseclib.js: $(srcdir)/add-on/firefox/js-ctypes/content/dnsseclib.js.in Makefile
	$(do_subst) < $(srcdir)/add-on/firefox/js-ctypes/content/dnsseclib.js.in > $@

dnssec_validator_SKIN = \
	add-on/firefox/common/skin/dnssec_ip.png	\
	add-on/firefox/common/skin/tlsa_init.png	\
	add-on/firefox/common/skin/tlsa_orange.png	\
	add-on/firefox/common/skin/dnssec_error.png	\
	add-on/firefox/common/skin/tlsa_nodnssec.png	\
	add-on/firefox/common/skin/dnssec_bogus.png	\
	add-on/firefox/common/skin/tlsa_no.png		\
	add-on/firefox/common/skin/tlsa_nohttps.png	\
	add-on/firefox/common/skin/dnssec_no.png	\
	add-on/firefox/common/skin/overlay-tlsa.css	\
	add-on/firefox/common/skin/dnssec_orange.png	\
	add-on/firefox/common/skin/overlay.css		\
	add-on/firefox/common/skin/tlsa_invalid.png	\
	add-on/firefox/common/skin/dnssec_valid.png	\
	add-on/firefox/common/skin/overlay-dnssec.css	\
	add-on/firefox/common/skin/tlsa_action.png	\
	add-on/firefox/common/skin/tlsa_off.png		\
	add-on/firefox/common/skin/dnssec_off.png	\
	add-on/firefox/common/skin/dnssec_action.png	\
	add-on/firefox/common/skin/tlsa_error.png	\
	add-on/firefox/common/skin/overlay-win-ff4.css	\
	add-on/firefox/common/skin/dnssec_init.png	\
	add-on/firefox/common/skin/icon.png		\
	add-on/firefox/common/skin/tlsa_valid.png

dnssec-validator-content-stamp: $(dnssec_validator_CONTENT)
	-rm -rf content
	mkdir content
	for f in $(dnssec_validator_CONTENT); do \
		$(INSTALL) -m 644 $(top_srcdir)/$$f content/; \
	done
	touch dnssec-validator-chrome-stamp

dnssec-validator-skin-stamp: $(dnssec_validator_SKIN)
	-rm -rf skin
	mkdir -p skin
	for f in $(dnssec_validator_SKIN); do \
		$(INSTALL) -m 644 $(top_srcdir)/$$f skin/; \
	done
	touch dnssec-validator-skin-stamp

dnssec-validator-locale-stamp: $(dnssec_validator_LOCALES)
	-rm -rf locale
	for f in $(dnssec_validator_LOCALES); do \
		mkdir -p locale/$$(basename $$(dirname $$f))/; \
		$(INSTALL) -m 644 $(top_srcdir)/$$f locale/$$(basename $$(dirname $$f))/; \
	done
	touch dnssec-validator-locale-stamp

defaults/preferences/dnssec.js: add-on/firefox/common/defaults/preferences/dnssec.js
	$(INSTALL) -d 755 defaults/preferences/
	$(INSTALL) -m 644 $< $@

chrome/dnssec.jar: dnssec-validator-content-stamp dnssec-validator-locale-stamp dnssec-validator-skin-stamp
	-rm -rf chrome
	$(INSTALL) -d chrome
	zip -0 -r $@ content locale skin

plugins/libDNSSECcore-$(OS_TARGET).so: libDNSSECcore.la
	rm -f $@
	$(INSTALL) -d -m 755 plugins
	$(INSTALL) -s -m 644 .libs/libDNSSECcore.so plugins/libDNSSECcore-$(OS_TARGET).so # FIXME: Ugly

plugins/libDANEcore-$(OS_TARGET).so: libDANEcore.la
	rm -f $@
	$(INSTALL) -d -m 755 plugins
	$(INSTALL) -s -m 644 .libs/libDANEcore.so plugins/libDANEcore-$(OS_TARGET).so # FIXME: Ugly

dnssec.xpi: plugins/libDNSSECcore-$(OS_TARGET).so plugins/libDANEcore-$(OS_TARGET).so defaults/preferences/dnssec.js chrome/dnssec.jar
	rm -f $@
	zip -r $@ COPYING README icon.png Version CHANGELOG plugins defaults chrome install.rdf chrome.manifest

