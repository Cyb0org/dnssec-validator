# ***** BEGIN LICENSE BLOCK *****
# Copyright 2011, 2012 CZ.NIC, z.s.p.o.
#
# Authors: Martin Straka <martin.straka@nic.cz>
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

PLUGIN_ROOT = ../plugin
PLUGIN_TMP = ../tmp_build
PLUGIN_NAME = DNSSECValidatorPlugin
PLUGIN_NAME_DLL = dll

X86_MINGW_CC = i586-mingw32msvc-gcc
X86_MINGW_STRIP = i586-mingw32msvc-strip

#all: sys_windows_pre

sys_windows_pre:
	@echo '### Compiling validation library for Windows... ###'
	rm -rf $(PLUGIN_NAME_DLL) $(PLUGIN_ROOT)/build $(PLUGIN_TMP)
	mkdir $(PLUGIN_NAME_DLL) && mkdir $(PLUGIN_TMP)
	$(X86_MINGW_CC) -Wall -shared -o $(PLUGIN_TMP)/ds_windows-x86.dll $(PLUGIN_ROOT)/projects/$(PLUGIN_NAME)/cache/ds.c -DRES_WIN -D__USE_MINGW_ANSI_STDIO=1 -I$(PLUGIN_ROOT)/lib/windows/x86 -I$(PLUGIN_ROOT)/lib/ldns -I$(PLUGIN_ROOT)/lib/openssl/include -Wl,--output-def,$(PLUGIN_TMP)/ds_windows-x86.def,-L$(PLUGIN_ROOT)/lib/windows/x86,-Bstatic,-lldns,-Bsymbolic,-lcrypto,-Bdynamic,-lws2_32,-liphlpapi,-lgdi32
	cp $(PLUGIN_TMP)/ds_windows-x86.dll $(PLUGIN_NAME_DLL)
	cp $(PLUGIN_TMP)/ds_windows-x86.def $(PLUGIN_NAME_DLL)
	$(X86_MINGW_STRIP) -x -S $(PLUGIN_NAME_DLL)/ds_windows-x86.dll
	@echo '### Now you can build the plugin on Windows... ###'
