/* ***** BEGIN LICENSE BLOCK *****
Copyright 2010, 2011 CZ.NIC, z.s.p.o.

Authors: Zbynek Michl <zbynek.michl@nic.cz>

This file is part of DNSSEC Validator Add-on.

DNSSEC Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */

#ifndef XP_WIN
  #include <stdint.h>
#else
  #if (_MSC_VER < 1300)
    typedef unsigned short    uint16_t;
    typedef unsigned int      uint32_t;
  #else
    typedef unsigned __int16  uint16_t;
    typedef unsigned __int32  uint32_t;
  #endif
#endif

/* main validating function */
short dnssec_validate(const char *domain, const uint16_t options,
                  const char *optdnssrv, char **resaddrs);