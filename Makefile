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

EXTENSION_VERSION = `cat install.rdf.template | sed -n 's/.*<em:version>\(.*\)<\/em:version>.*/\1/p'`

all: sys_linux sys_macosx sys_windows

sys_linux:
	@echo '### Creating package for Linux... ###'
	rm -rf platform
	mkdir -p platform/Linux_x86_64-gcc3/components && ln -s ../../../xpcom/dnssecValidator_linux-x64.so platform/Linux_x86_64-gcc3/components/dnssecValidator.so
	mkdir -p platform/Linux_x86-gcc3/components && ln -s ../../../xpcom/dnssecValidator_linux-x86.so platform/Linux_x86-gcc3/components/dnssecValidator.so
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Linux_x86_64-gcc3<\/em:targetPlatform><em:targetPlatform>Linux_x86-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-linux.xpi

sys_macosx:
	@echo '### Creating package for Mac OS X... ###'
	rm -rf platform
	mkdir -p platform/Darwin_x86-gcc3/components && ln -s ../../../xpcom/dnssecValidator_macosx-x86.dylib platform/Darwin_x86-gcc3/components/dnssecValidator.so
	mkdir -p platform/Darwin_ppc-gcc3/components && ln -s ../../../xpcom/dnssecValidator_macosx-ppc.dylib platform/Darwin_ppc-gcc3/components/dnssecValidator.so
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>Darwin_x86-gcc3<\/em:targetPlatform><em:targetPlatform>Darwin_ppc-gcc3<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-macosx.xpi

sys_windows:
	@echo '### Creating package for Windows... ###'
	rm -rf platform
	mkdir -p platform/WINNT_x86-msvc/components && ln -s ../../../xpcom/windows/dnssecWinStubLoader/Release/dnssecWinStubLoader.dll platform/WINNT_x86-msvc/components/dnssecWinStubLoader.dll
	mkdir -p platform/WINNT_x86-msvc/libraries && ln -s ../../../xpcom/windows/dnssecValidator/Release/dnssecValidator.dll platform/WINNT_x86-msvc/libraries/dnssecValidator.dll && ln -s ../../../xpcom/ds_windows-x86.dll platform/WINNT_x86-msvc/libraries/ds_windows-x86.dll
	sed 's/<em:targetPlatform><\/em:targetPlatform>/<em:targetPlatform>WINNT_x86-msvc<\/em:targetPlatform>/g' install.rdf.template > install.rdf
	./build.sh && mv dnssec.xpi dnssec_validator-$(EXTENSION_VERSION)-windows.xpi

clean:
	rm -rf platform
	rm -f install.rdf

clean_pkg:
	rm -f dnssec_validator-$(EXTENSION_VERSION)-*.xpi
