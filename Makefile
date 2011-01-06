# ***** BEGIN LICENSE BLOCK *****
# Copyright 2010 CZ.NIC, z.s.p.o.
#
# This file is part of DNSSEC Validator Add-on.
#
# DNSSEC Validator Add-on is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# DNSSEC Validator Add-on is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
# ***** END LICENSE BLOCK *****

EXTENSION_VERSION = $(shell cat install.rdf.template | sed -n 's/.*<em:version>\(.*\)<\/em:version>.*/\1/p')
PLUGIN_ROOT = plugin
PLUGIN_NAME = DNSSECValidator

#all: sys_linux sys_macosx sys_windows

sys_linux:
	@echo '### Creating package for Linux... ###'
	rm -rf platform $(PLUGIN_ROOT)/build
	./$(PLUGIN_ROOT)/FireBreath/prepmake.sh $(PLUGIN_ROOT)/projects $(PLUGIN_ROOT)/build -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_C_FLAGS=-m64 -DCMAKE_CXX_FLAGS=-m64 -DFB_GUI_DISABLED=1
	make -C $(PLUGIN_ROOT)/build
	mkdir -p platform/Linux_x86_64-gcc3/plugins && mv $(PLUGIN_ROOT)/build/bin/$(PLUGIN_NAME)/np$(PLUGIN_NAME).so platform/Linux_x86_64-gcc3/plugins/np$(PLUGIN_NAME)_x64.so
	rm -rf $(PLUGIN_ROOT)/build
	./$(PLUGIN_ROOT)/FireBreath/prepmake.sh $(PLUGIN_ROOT)/projects $(PLUGIN_ROOT)/build -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 -DFB_GUI_DISABLED=1
	make -C $(PLUGIN_ROOT)/build
	mkdir -p platform/Linux_x86-gcc3/plugins && mv $(PLUGIN_ROOT)/build/bin/$(PLUGIN_NAME)/np$(PLUGIN_NAME).so platform/Linux_x86-gcc3/plugins/np$(PLUGIN_NAME)_x86.so
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Linux_x86_64-gcc3<\/em:targetPlatform><em:targetPlatform>Linux_x86-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-linux.xpi && ln -sf dnssec_validator-$(EXTENSION_VERSION)-linux.xpi dnssec_validator-linux.xpi

sys_macosx:
	@echo '### Creating package for Mac OS X... ###'
	rm -rf platform $(PLUGIN_ROOT)/build
	./$(PLUGIN_ROOT)/FireBreath/prepmac.sh $(PLUGIN_ROOT)/projects $(PLUGIN_ROOT)/build -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_OSX_ARCHITECTURES="i386;ppc"
	cd $(PLUGIN_ROOT)/build && xcodebuild && cd ../..
	mkdir -p platform/Darwin/plugins && mv $(PLUGIN_ROOT)/build/projects/$(PLUGIN_NAME)/Debug/$(PLUGIN_NAME).plugin platform/Darwin/plugins/
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Darwin_x86-gcc3<\/em:targetPlatform><em:targetPlatform>Darwin_ppc-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-macosx.xpi && ln -sf dnssec_validator-$(EXTENSION_VERSION)-macosx.xpi dnssec_validator-macosx.xpi

sys_windows:
	@echo '### Creating package for Windows... ###'
	rm -rf platform
	mkdir -p platform/WINNT_x86-msvc/components && ln -s ../../../xpcom/windows/dnssecWinStubLoader/Release/dnssecWinStubLoader.dll platform/WINNT_x86-msvc/components/dnssecWinStubLoader.dll
	mkdir -p platform/WINNT_x86-msvc/libraries && ln -s ../../../xpcom/windows/dnssecValidator/Release/dnssecValidator.dll platform/WINNT_x86-msvc/libraries/dnssecValidator.dll && ln -s ../../../xpcom/ds_windows-x86.dll platform/WINNT_x86-msvc/libraries/ds_windows-x86.dll
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>WINNT_x86-msvc<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-windows.xpi && ln -sf dnssec_validator-$(EXTENSION_VERSION)-windows.xpi dnssec_validator-windows.xpi

clean:
	rm -rf platform
	rm -f install.rdf

clean_pkg:
	rm -f dnssec_validator-$(EXTENSION_VERSION)-*.xpi
