/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.
File: DANE/TLSA library
Authors: Martin Straka <martin.straka@nic.cz>
         Karel Slany <karel.slany@nic.cz>

This file is part of TLSA Validator 2 Add-on.

TLSA Validator 2 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

TLSA Validator 2.Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
TLSA Validator 2 Add-on.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */


#ifndef _COMMON_H_
#define _COMMON_H_


#include "config_related.h"


#include <stdbool.h>

#include "log.h"


#ifdef __cplusplus
extern "C" {
#endif


/* Debugging related prefixes. */
#define DEBUG_PREFIX_CERT "CERT: "
#define DEBUG_PREFIX_DANE "DANE: "
#define DEBUG_PREFIX_DNSSEC "DNSSEC: "
#define DEBUG_PREFIX_TLSA "TLSA: "


/* Global flag, used for generating debugging information. */
extern int global_debug;


/* DS record of root zone. */
#define TA \
	". IN DS 19036 8 2 " \
	"49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"


/* DNSKEY of DLV register. */
#define DLV \
	"dlv.isc.org. IN DNSKEY 257 3 5 " \
	"BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 " \
	"brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ " \
	"1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 " \
	"ymX4BI/oQ+ " \
	"cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk " \
	"Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM " \
	"QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt " \
	"TDN0YUuWrBNh"


/*!
 * @brief Prints debugging information.
 *
 * @param[in] pref Mesage prefix.
 * @param[in] fmt  Format of the message.
 */
#define printf_debug(pref, fmt, ...) \
	do { \
		if (global_debug && (fmt != NULL)) { \
			_debug_log(pref, fmt, __VA_ARGS__); \
		} \
	} while (0)


/* Error codes. */
#define ERROR_RESOLVER -2 /* Resolver error. */
#define ERROR_GENERIC -1 /*
                          * Any error except of those which have their own
                          * codes.
                          */


/*!
 * @brief Initialise unbound resolver context.
 *
 * @param[in]  optdnssrv    Space-separated list of resolver IP addresses.
 * @param[out] err_code_ptr Location to which to write the error code.
 * @param[in]  usefwd       Use exrernal resolvers.
 * @param[in]  userootds    Use root key with DS record of root zone.
 * @return Pointer to newly created unbound context or NULL on failure.
 */
struct ub_ctx * unbound_resolver_init(const char *optdnssrv,
    int *err_code_ptr, int usefwd, int userootds, const char *debug_prefix);


#ifdef __cplusplus
} /* extern "C" */
#endif


#endif /* !_COMMON_H_ */
