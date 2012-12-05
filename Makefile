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

PLUGIN_ROOT = ub_plugin
PLUGIN_TMP = ub_tmp_build
PLUGIN_NAME = DNSSECValidatorPlugin
PLUGIN_NAME_DLL = components
X86_MINGW_CC = i586-mingw32msvc-gcc
X86_MINGW_STRIP = i586-mingw32msvc-strip

#all: sys_linux sys_macosx sys_windows

sys_linux:
	@echo '### Creating package for Linux... ###'
	rm -rf plugins $(PLUGIN_ROOT)/build $(PLUGIN_TMP)
	./$(PLUGIN_ROOT)/FireBreath/prepmake.sh $(PLUGIN_ROOT)/projects $(PLUGIN_ROOT)/build -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_C_FLAGS=-m64 -DCMAKE_CXX_FLAGS=-m64 -DCMAKE_BUILD_TYPE=MinSizeRel
	make -C $(PLUGIN_ROOT)/build
	mkdir plugins && cp $(PLUGIN_ROOT)/build/bin/$(PLUGIN_NAME)/np$(PLUGIN_NAME).so plugins/np$(PLUGIN_NAME)_x64.so
	rm -rf $(PLUGIN_ROOT)/build
	./$(PLUGIN_ROOT)/FireBreath/prepmake.sh $(PLUGIN_ROOT)/projects $(PLUGIN_ROOT)/build -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 -DCMAKE_BUILD_TYPE=MinSizeRel
	make -C $(PLUGIN_ROOT)/build
	cp $(PLUGIN_ROOT)/build/bin/$(PLUGIN_NAME)/np$(PLUGIN_NAME).so plugins/np$(PLUGIN_NAME)_x86.so
	strip plugins/np$(PLUGIN_NAME)_x64.so plugins/np$(PLUGIN_NAME)_x86.so

sys_windows:
	@echo '### Compiling validation library for Windows... ###'
	rm -rf $(PLUGIN_NAME_DLL) $(PLUGIN_ROOT)/build $(PLUGIN_TMP)
	mkdir $(PLUGIN_NAME_DLL) && mkdir $(PLUGIN_TMP)
	$(X86_MINGW_CC) -Wall -shared -o $(PLUGIN_TMP)/ub_ds_windows-x86.dll $(PLUGIN_ROOT)/projects/$(PLUGIN_NAME)/ub_ds.c $(PLUGIN_ROOT)/lib/windows/x86/libunbound.a $(PLUGIN_ROOT)/lib/windows/x86/libldns.a $(PLUGIN_ROOT)/lib/windows/x86/libssl.a $(PLUGIN_ROOT)/lib/windows/x86/libcrypto.a -DRES_WIN -D__USE_MINGW_ANSI_STDIO=1 -I$(PLUGIN_ROOT)/lib/windows/x86 -I$(PLUGIN_ROOT)/lib/ldns -I$(PLUGIN_ROOT)/lib/unbound -I$(PLUGIN_ROOT)/lib/openssl/include -Wl,--output-def,$(PLUGIN_TMP)/ub_ds_windows-x86.def,-Bstatic,-Bsymbolic,-lws2_32,-liphlpapi,-lgdi32
	cp $(PLUGIN_TMP)/ub_ds_windows-x86.dll $(PLUGIN_NAME_DLL)
	cp $(PLUGIN_TMP)/ub_ds_windows-x86.def $(PLUGIN_NAME_DLL)
	$(X86_MINGW_STRIP) -x -S $(PLUGIN_NAME_DLL)/ub_ds_windows-x86.dll
	@echo '### Now you can build the plugin on Windows... ###'
  
  


clean:
	rm -rf plugins $(PLUGIN_ROOT)/build $(PLUGIN_TMP)
	rm -f install.rdf

clean_pkg:
	rm -f ub_dnssec_validator-$(EXTENSION_VERSION)-*.xpi
