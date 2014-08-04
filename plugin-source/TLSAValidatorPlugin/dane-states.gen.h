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
 * Also don't forget to edit dane-states.gen .
 */

extern const short DANE_RESOLVER_NO_DNSSEC;
extern const short DANE_ERROR_RESOLVER;
extern const short DANE_ERROR_GENERIC;
extern const short DANE_OFF;

extern const short DANE_NO_HTTPS;
extern const short DANE_DNSSEC_UNSECURED;
extern const short DANE_NO_TLSA;
extern const short DANE_DNSSEC_SECURED;
extern const short DANE_VALID_TYPE0;
extern const short DANE_VALID_TYPE1;
extern const short DANE_VALID_TYPE2;
extern const short DANE_VALID_TYPE3;

extern const short DANE_DNSSEC_BOGUS;
extern const short DANE_CERT_ERROR;
extern const short DANE_NO_CERT_CHAIN;
extern const short DANE_TLSA_PARAM_ERR;
extern const short DANE_INVALID_TYPE0;
extern const short DANE_INVALID_TYPE1;
extern const short DANE_INVALID_TYPE2;
extern const short DANE_INVALID_TYPE3;

extern const unsigned short DANE_FLAG_DEBUG;
extern const unsigned short DANE_FLAG_USEFWD;
