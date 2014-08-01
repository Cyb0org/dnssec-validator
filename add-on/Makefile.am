
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4


all: MF-dnssec-validator-@VERSION@-js-ctypes.xpi


# FIXME: All architectures do not use the .so suffix.
do_subst = sed \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]OS_TARGET[@],$(OS_TARGET),g' \
	-e 's,[@]VERSION[@],$(VERSION),g'\
	-e 's,[@]libDNSSECcore[@],libDNSSECcore-$(OS_TARGET).so,g' \
	-e 's,[@]libDANEcore[@],libDANEcore-$(OS_TARGET).so,g'


cs_CZ_LOCALE = \
	$(top_srcdir)/add-on/firefox/common/locale/cs-CZ/aboutwindow.dtd \
	$(top_srcdir)/add-on/firefox/common/locale/cs-CZ/dnssec.dtd \
	$(top_srcdir)/add-on/firefox/common/locale/cs-CZ/dnssec.preferences \
	$(top_srcdir)/add-on/firefox/common/locale/cs-CZ/dnssec.properties \
	$(top_srcdir)/add-on/firefox/common/locale/cs-CZ/prefwindow.dtd

de_DE_LOCALE = \
	$(top_srcdir)/add-on/firefox/common/locale/de-DE/aboutwindow.dtd \
	$(top_srcdir)/add-on/firefox/common/locale/de-DE/dnssec.dtd \
	$(top_srcdir)/add-on/firefox/common/locale/de-DE/dnssec.preferences \
	$(top_srcdir)/add-on/firefox/common/locale/de-DE/dnssec.properties \
	$(top_srcdir)/add-on/firefox/common/locale/de-DE/prefwindow.dtd

en_US_LOCALE = \
	$(top_srcdir)/add-on/firefox/common/locale/en-US/aboutwindow.dtd \
	$(top_srcdir)/add-on/firefox/common/locale/en-US/dnssec.dtd \
	$(top_srcdir)/add-on/firefox/common/locale/en-US/dnssec.preferences \
	$(top_srcdir)/add-on/firefox/common/locale/en-US/dnssec.properties \
	$(top_srcdir)/add-on/firefox/common/locale/en-US/prefwindow.dtd

dnssec_tlsa_validator_LOCALES = \
	$(cs_CZ_LOCALE) \
	$(de_DE_LOCALE) \
	$(en_US_LOCALE)

dnssec_tlsa_validator_CONTENT = \
	$(top_srcdir)/add-on/firefox/common/about.xul

dnssec_tlsa_validator_BALLAST = \
	$(top_srcdir)/add-on/firefox/common/COPYING \
	$(top_srcdir)/add-on/firefox/common/README \
	$(top_srcdir)/add-on/firefox/common/chrome.manifest \
	$(top_srcdir)/add-on/firefox/common/install.rdf \
	$(top_srcdir)/add-on/firefox/common/skin/icon.png \
	$(top_srcdir)/Version \
	$(top_srcdir)/CHANGELOG

BUILT_SOURCES = \
	$(top_srcdir)/add-on/firefox/common/about.xul \
	$(top_srcdir)/add-on/firefox/common/install.rdf

CLEANFILES = \
	$(top_srcdir)/add-on/firefox/common/about.xul \
	$(top_srcdir)/add-on/firefox/common/install.rdf

$(top_srcdir)/add-on/firefox/common/about.xul: $(top_srcdir)/add-on/firefox/common/about.xul.in
	$(do_subst) < $< > $@

$(top_srcdir)/add-on/firefox/common/install.rdf: $(top_srcdir)/add-on/firefox/common/install.rdf.in
	$(do_subst) < $< > $@

if EXTPKG_MOZZ_JC

BUILT_SOURCES += \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/dnsseclib.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/tlsalib.js

CLEANFILES += \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/dnsseclib.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/tlsalib.js

$(top_srcdir)/add-on/firefox/js-ctypes/content/tlsalib.js: $(top_srcdir)/add-on/firefox/js-ctypes/content/tlsalib.js.in Makefile
	$(do_subst) < $< > $@

$(top_srcdir)/add-on/firefox/js-ctypes/content/dnsseclib.js: $(top_srcdir)/add-on/firefox/js-ctypes/content/dnsseclib.js.in Makefile
	$(do_subst) < $< > $@

dnssec_tlsa_validator_CONTENT_MOZZ_JC = \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/about.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/dnsseclib.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/firefoxOverlay.xul \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/npapi_const.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/overlay.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/preferences.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/preferences.xul \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/tlsa.js \
	$(top_srcdir)/add-on/firefox/js-ctypes/content/tlsalib.js

dnssec_tlsa_validator_SKIN_MOZZ_JC = \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_action.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_bogus.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_error.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_init.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_ip.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_no.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_off.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_orange.png \
	$(top_srcdir)/add-on/firefox/common/skin/dnssec_valid.png \
	$(top_srcdir)/add-on/firefox/common/skin/icon.png \
	$(top_srcdir)/add-on/firefox/common/skin/overlay.css \
	$(top_srcdir)/add-on/firefox/common/skin/overlay-dnssec.css \
	$(top_srcdir)/add-on/firefox/common/skin/overlay-tlsa.css \
	$(top_srcdir)/add-on/firefox/common/skin/overlay-win-ff4.css \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_action.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_error.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_init.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_invalid.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_nodnssec.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_nohttps.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_no.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_off.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_orange.png \
	$(top_srcdir)/add-on/firefox/common/skin/tlsa_valid.png

dtvmjc-locales-stamp: $(dnssec_tlsa_validator_LOCALES)
	-rm -rf _dtvmjc_workdir/locale
	$(INSTALL) -d _dtvmjc_workdir/locale
	for f in $^; do \
		mkdir -p _dtvmjc_workdir/locale/$$(basename $$(dirname $$f))/; \
		$(INSTALL) -m 644 $$f _dtvmjc_workdir/locale/$$(basename $$(dirname $$f))/; \
	done
	touch $@

dtvmjc-content-stamp: $(dnssec_tlsa_validator_CONTENT) $(dnssec_tlsa_validator_CONTENT_MOZZ_JC)
	-rm -rf _dtvmjc_workdir/content
	$(INSTALL) -d _dtvmjc_workdir/content
	for f in $^; do \
		$(INSTALL) -m 644 $$f _dtvmjc_workdir/content/; \
	done
	touch $@

dtvmjc-skin-stamp: $(dnssec_tlsa_validator_SKIN_MOZZ_JC)
	-rm -rf _dtvmjc_workdir/skin
	$(INSTALL) -d _dtvmjc_workdir/skin
	for f in $^; do \
		$(INSTALL) -m 644 $$f _dtvmjc_workdir/skin/; \
	done
	touch $@

dtvmjc-jar-stamp: dtvmjc-locales-stamp dtvmjc-content-stamp dtvmjc-skin-stamp
	-rm -rf _dtvmjc_workdir/chrome
	$(INSTALL) -d _dtvmjc_workdir/chrome
	cd _dtvmjc_workdir; zip -0 -r chrome/dnssec.jar content locale skin; cd ..
	touch $@

dtvmjc-prefs-stamp: $(top_srcdir)/add-on/firefox/common/defaults/preferences/dnssec.js
	-rm -rf _dtvmjc_workdir/defaults/preferences
	$(INSTALL) -d -m 755 _dtvmjc_workdir/defaults/preferences
	$(INSTALL) -m 644 $< _dtvmjc_workdir/defaults/preferences/
	touch $@

dtvmjc-ballast-stamp: $(dnssec_tlsa_validator_BALLAST)
	for f in $^; do \
		$(INSTALL) -m 644 $$f _dtvmjc_workdir/; \
	done
	touch $@

_dtvmjc_workdir/plugins/libDNSSECcore-$(OS_TARGET).so: $(top_srcdir)/core_js-ctypes/libDNSSECcore.la
	-rm -f $@
	$(INSTALL) -d -m 755 _dtvmjc_workdir/plugins
	$(INSTALL) -s -m 644 $(top_srcdir)/core_js-ctypes/.libs/libDNSSECcore.so $@ # FIXME: Ugly

_dtvmjc_workdir/plugins/libDANEcore-$(OS_TARGET).so: $(top_srcdir)/core_js-ctypes/libDANEcore.la
	-rm -f $@
	$(INSTALL) -d -m 755 _dtvmjc_workdir/plugins
	$(INSTALL) -s -m 644 $(top_srcdir)/core_js-ctypes/.libs/libDANEcore.so $@ # FIXME: Ugly

MF-dnssec-validator-@VERSION@-js-ctypes.xpi: dtvmjc-jar-stamp dtvmjc-prefs-stamp dtvmjc-ballast-stamp _dtvmjc_workdir/plugins/libDNSSECcore-$(OS_TARGET).so _dtvmjc_workdir/plugins/libDANEcore-$(OS_TARGET).so
	-rm -f $@
	cd _dtvmjc_workdir; \
	zip -r $@ COPYING README icon.png Version CHANGELOG plugins defaults chrome install.rdf chrome.manifest; \
	$(INSTALL) -m 644 $@ ../; \
	cd ..

endif
