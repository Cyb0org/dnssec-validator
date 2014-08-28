
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

NPAPI_PLUGIN_NAME_DNSSEC = DNSSECValidatorPlugin
NPAPI_PLUGIN_NAME_TLSA = TLSAValidatorPlugin

SHELL_CMD ?= bash

WORKDIRS = $(EMPTY)

# FIXME: Different suffixes on differemt systems.
if NPAPI_CORE
NPAPI_TARGETS = \
	fb-dnssec-stamp \
	fb-tlsa-stamp
endif

if STATIC_CORE
STATIC_LINKING = yes
else
STATIC_LINKING = no
endif

all: $(NPAPI_TARGETS)

fb-git-stamp:
	-rm -rf FireBreath
	git clone https://github.com/firebreath/FireBreath.git FireBreath
	cd FireBreath; git reset --hard 66af0df36be98e9fcf7ee196fe5c275e54752ae8; cd .. # 2014-06-24 17:48:14
	touch $@

fb-workdir-stamp: fb-git-stamp FireBreath
	cp -r FireBreath WDFireBreath
	touch $@

fb-projects-stamp: fb-workdir-stamp WDFireBreath
	-rm -rf WDFireBreath/projects
	$(INSTALL) -d WDFireBreath/projects
	cp -r $(top_srcdir)/plugin-source/* WDFireBreath/projects
	touch $@

# TODO -- Add crosscompile options:
# -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32

INCLUDE_LOC = "$(abs_top_builddir)/core_npapi/WDFireBreath/projects/common"

fb-compile-stamp: fb-projects-stamp WDFireBreath/projects
	$(SHELL_CMD) ./WDFireBreath/prepmake.sh \
	    WDFireBreath/projects WDFireBreath/build \
	    -DSTATIC_LINKING="$(STATIC_LINKING)" \
	    -DLIBS_BUILT_DIR="$(abs_top_builddir)/static-libs/libs-built/" \
	    -DINCLUDE_LOC="$(INCLUDE_LOC)" -DLIBRARY_LOC="$(LIBRARY_LOC)" \
	    -DCMAKE_VERBOSE_MAKEFILE=1 \
	    -DCMAKE_BUILD_TYPE=MinSizeRel
	$(MAKE) -C WDFireBreath/build
	touch $@

fb-dnssec-stamp: fb-compile-stamp
np$(NPAPI_PLUGIN_NAME_DNSSEC)_$(XPCOM_ABI)$(SO_SUFF): fb-compile-stamp
	if [ -d WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin ]; then \
		cp -R WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin; \
		$(STRIP) np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin/Contents/MacOS/np$(NPAPI_PLUGIN_NAME_DNSSEC); \
	elif [ -f WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC)$(SO_SUFF) ]; then \
		$(INSTALL) -m 644 -s WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_DNSSEC)/np$(NPAPI_PLUGIN_NAME_DNSSEC)$(SO_SUFF) np$(NPAPI_PLUGIN_NAME_DNSSEC)_$(XPCOM_ABI)$(SO_SUFF); \
	else \
		false; \
	fi

fb-tlsa-stamp: fb-compile-stamp
np$(NPAPI_PLUGIN_NAME_TLSA)_$(XPCOM_ABI)$(SO_SUFF): fb-compile-stamp
	if [ -d WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA).plugin ]; then \
		cp -R WDFireBreath/build/projects/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA).plugin np$(NPAPI_PLUGIN_NAME_TLSA).plugin; \
		$(STRIP) np$(NPAPI_PLUGIN_NAME_TLSA).plugin/Contents/MacOS/np$(NPAPI_PLUGIN_NAME_TLSA); \
	elif [ -f WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA)$(SO_SUFF) ]; then \
		$(INSTALL) -m 644 -s WDFireBreath/build/bin/$(NPAPI_PLUGIN_NAME_TLSA)/np$(NPAPI_PLUGIN_NAME_TLSA)$(SO_SUFF) np$(NPAPI_PLUGIN_NAME_TLSA)_$(XPCOM_ABI)$(SO_SUFF); \
	else \
		false; \
	fi

CLEANFILES = \
	fb-workdir-stamp \
	fb-projects-stamp \
	fb-compile-stamp \
	$(NPAPI_TARGETS)

WORKDIRS += \
	WDFireBreath/projects \
	WDFireBreath \
	np$(NPAPI_PLUGIN_NAME_DNSSEC)_$(XPCOM_ABI)$(SO_SUFF) \
	np$(NPAPI_PLUGIN_NAME_DNSSEC).plugin \
	np$(NPAPI_PLUGIN_NAME_TLSA)_$(XPCOM_ABI)$(SO_SUFF) \
	np$(NPAPI_PLUGIN_NAME_TLSA).plugin

clean-local:
	for d in $(WORKDIRS); do \
		rm -rf $$d; \
	done

distclean-local:
	-rm -rf FireBreath
	-rm -rf fb-git-stamp
