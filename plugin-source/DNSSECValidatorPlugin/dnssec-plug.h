/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator 2.0 Add-on.

DNSSEC Validator 2.0 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator 2.0 Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.0 Add-on.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */

#ifndef _DNSSEC_PLUG_H_
#define _DNSSEC_PLUG_H_


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

#ifdef __cplusplus
extern "C" {
#endif


/* Forward structure declaration. */
struct dnssec_options_st;


//*****************************************************************************
// read input options into a structure
// ----------------------------------------------------------------------------
void dnssec_set_validation_options(struct dnssec_options_st *opts,
    uint16_t options);


//*****************************************************************************
// Create validation context.
// ----------------------------------------------------------------------------
int dnssec_validation_init(void);


//*****************************************************************************
/* main validating function */
// return status DNSSEC security
// Input: *domain - domain name
//        options - options of validator, IPv4, IPv6, usefwd, etc..
//        *optdnssrv - IP address of resolver/forvarder
//        *ipbrowser - is IP address of remote which browser uses to
//                     connect to the server
// Out:   **ipvalidator - is IP address(es) of validator
// ----------------------------------------------------------------------------
int dnssec_validate(const char *domain, uint16_t options,
    const char *optdnssrv, const char *ipbrowser, char **ipvalidator);


//*****************************************************************************
// Destroy validation context.
// ----------------------------------------------------------------------------
int dnssec_validation_deinit(void);


#ifdef __cplusplus
}
#endif

#endif /* _DNSSEC_PLUG_H_ */
