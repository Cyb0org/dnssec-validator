# ***** BEGIN LICENSE BLOCK *****
# Copyright 2010, 2011 CZ.NIC, z.s.p.o.
#
# Authors: Zbynek Michl <zbynek.michl@nic.cz>
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
PLUGIN_ROOT = ../ub_plugin
PLUGIN_TMP = ../ub_tmp_build
PLUGIN_NAME = DNSSECValidatorPlugin
PLUGIN_NAME_DLL = components

X86_MINGW_CC = i586-mingw32msvc-gcc
X86_MINGW_STRIP = i586-mingw32msvc-strip

#all: sys_linux sys_macosx sys_windows

sys_linux:
	@echo '### Creating package for Linux... ###'
	rm -rf plugins
	mkdir plugins
	cp ../plugins/npDNSSECValidatorPlugin_x64.so plugins
	cp ../plugins/npDNSSECValidatorPlugin_x86.so plugins
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Linux_x86_64-gcc3<\/em:targetPlatform><em:targetPlatform>Linux_x86-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-linux.xpi
	@echo '### Creating package for Windows... ###'
	rm -rf plugins
	mkdir plugins
	cp ../plugins/ub_ds_windows-x86.dll plugins
	cp ../plugins/npDNSSECValidatorPlugin.dll plugins
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>WINNT_x86-msvc<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-windows.xpi
	@echo '### Creating package for MAC OS X... ###'
	rm -rf plugins
	mkdir plugins
	cp -r ../plugins/DNSSECValidatorPlug-in.plugin plugins
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Darwin_x86-gcc3<\/em:targetPlatform><em:targetPlatform>Darwin_x86_64-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-macosx.xpi
	rm -rf plugins
	@echo '### Creating packages ... Done ###'

clean:
	rm -rf plugins
	rm -f install.rdf

clean_pkg:
	rm -f ub_dnssec_validator-$(EXTENSION_VERSION)-*.xpi
