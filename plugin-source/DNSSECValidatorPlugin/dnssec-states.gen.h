/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

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

/*
 * Also don't forget to edit dnssec-states.gen .
 */

extern const short DNSSEC_UNBOUND_NO_DATA;
extern const short DNSSEC_RESOLVER_NO_DNSSEC;
extern const short DNSSEC_ERROR_RESOLVER;
extern const short DNSSEC_ERROR_GENERIC;
extern const short DNSSEC_OFF;

extern const short DNSSEC_DOMAIN_UNSECURED;
extern const short DNSSEC_COT_DOMAIN_SECURED;
extern const short DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
extern const short DNSSEC_COT_DOMAIN_BOGUS;
extern const short DNSSEC_NXDOMAIN_UNSECURED;
extern const short DNSSEC_NXDOMAIN_SIGNATURE_VALID;
extern const short DNSSEC_NXDOMAIN_SIGNATURE_INVALID;
extern const short DNSSEC_NXDOMAIN_SIGNATURE_VALID_BAD_IP;

extern const unsigned short DNSSEC_FLAG_DEBUG;
extern const unsigned short DNSSEC_FLAG_USEFWD;
extern const unsigned short DNSSEC_FLAG_RESOLVIPV4;
extern const unsigned short DNSSEC_FLAG_RESOLVIPV6;
