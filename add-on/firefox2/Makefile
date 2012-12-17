#/* ***** BEGIN LICENSE BLOCK *****
#Copyright 2012 CZ.NIC, z.s.p.o.
#
#Authors: Martin Straka <martin.straka@nic.cz>
#
#This file is part of DNSSEC Validator 2.0 Add-on.
#
#DNSSEC Validator 2.0 Add-on is free software: you can redistribute it and/or
#modify it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or (at your
#option) any later version.
#
#DNSSEC Validator 2.0 Add-on is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
#or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
#more details.
#
#You should have received a copy of the GNU General Public License along with
#DNSSEC Validator 2.0 Add-on.  If not, see <http://www.gnu.org/licenses/>.
#***** END LICENSE BLOCK ***** */

EXTENSION_VERSION = $(shell cat install.rdf.template | sed -n 's/.*<em:version>\(.*\)<\/em:version>.*/\1/p')

#all: xpi

xpi:
	@echo '### Creating package for Linux... ###'
	rm -rf plugins
	rm -rf xpi
	mkdir plugins
	mkdir xpi
	cp ../plugins/npDNSSECValidatorPlugin_x64.so plugins
	cp ../plugins/npDNSSECValidatorPlugin_x86.so plugins
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Linux_x86_64-gcc3<\/em:targetPlatform><em:targetPlatform>Linux_x86-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi xpi/FF-dnssec_validator-$(EXTENSION_VERSION)-linux.xpi
	@echo '### Creating package for Windows... ###'
	rm -rf plugins
	mkdir plugins
	cp ../plugins/ub_ds_windows-x86.dll plugins
	cp ../plugins/npDNSSECValidatorPlugin.dll plugins
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>WINNT_x86-msvc<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi xpi/FF-dnssec_validator-$(EXTENSION_VERSION)-windows.xpi
	@echo '### Creating package for MAC OS X... ###'
	rm -rf plugins
	mkdir plugins
	cp -r ../plugins/DNSSECValidatorPlugin.plugin plugins
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Darwin_x86-gcc3<\/em:targetPlatform><em:targetPlatform>Darwin_x86_64-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi xpi/FF-dnssec_validator-$(EXTENSION_VERSION)-macosx.xpi
	rm -rf plugins
	@echo '### Creating packages ... Done ###'

clean:
	rm -rf plugins
	rm -f install.rdf
	rm -rf xpi

clean_pkg:
	rm -f ub_dnssec_validator-$(EXTENSION_VERSION)-*.xpi
