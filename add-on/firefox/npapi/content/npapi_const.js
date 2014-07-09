/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator 2 Add-on.

DNSSEC/TLSA Validator 2 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator 2 Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC/TLSA Validator 2 Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

// DNSSEC NPAPI constant returned by binary plugin
	
cz.nic.extension.dnssecExtNPAPIConst = {

	DNSSEC_UNBOUND_NO_DATA		: -4, /* valdiator does not recived data */
	DNSSEC_RESOLVER_NO_DNSSEC	: -3, /* resolver does not support DNSSEC */
	DNSSEC_ERROR_RESOLVER		: -2, /* bad resolver or wrong IP address of DNS*/
	DNSSEC_ERROR_GENERIC		: -1, /* any except those listed above */
	DNSSEC_OFF			: 0, /* domain name validation disabled */

	DNSSEC_DOMAIN_UNSECURED		: 1, /* domain is not secured */
	DNSSEC_COT_DOMAIN_SECURED	: 2, /* both domain and connection are secured and IPs is valid */
	DNSSEC_COT_DOMAIN_SECURED_BAD_IP: 3, /* both domain and connection are secured and IPs are differ */  
	DNSSEC_COT_DOMAIN_BOGUS		: 4, /* domain signature is not valid or COT is not established */
	DNSSEC_NXDOMAIN_UNSECURED	: 5, /* non-existent domain is not secured */
	DNSSEC_NXDOMAIN_SIGNATURE_VALID	: 6, /* domain name does not exist and connection are secured */
	DNSSEC_NXDOMAIN_SIGNATURE_INVALID: 7, /* domain name does not exist and NSEC/NSEC3 is not valid */
	DNSSEC_NXDOMAIN_SIGNATURE_VALID_BAD_IP: 8, /* domain name does not exist but browser got address */


	DNSSEC_FLAG_DEBUG		: 1, /* debug output */
	DNSSEC_FLAG_USEFWD		: 2, /* use forwarder/resolver */
	DNSSEC_FLAG_RESOLVIPV4		: 4, /* use IPv4, A for validation */
	DNSSEC_FLAG_RESOLVIPV6		: 8, /* use IPv6, AAAA for validation */
};

// DANE NPAPI constant returned by binary plugin
cz.nic.extension.tlsaExtNPAPIConst = {

	DANE_RESOLVER_NO_DNSSEC		: -10, /* resolver does not support DNSSEC */
	DANE_ERROR_RESOLVER		: -2, /* bad resolver or wrong IP address of DNS*/
	DANE_ERROR_GENERIC		: -1, /* any except those listed above */
	DANE_OFF			: 0,  /* domain name validation disabled */

	DANE_NO_HTTPS			: 1,  /* no https connection on the remote server */
	DANE_DNSSEC_UNSECURED		: 2,  /* domain name or TLSA is not secured by DNSSEC */
	DANE_NO_TLSA			: 3,  /* domain name have not TLSA */
	DANE_DNSSEC_SECURED		: 9,  /* domain name or TLSA is secured by DNSSEC */
	DANE_VALID_TYPE0		: 10, /* Certificate corresponds to TLSA (type 0) */
	DANE_VALID_TYPE1		: 11, /* Certificate corresponds to TLSA (type 1) */
	DANE_VALID_TYPE2		: 12, /* Certificate corresponds to TLSA (type 2) */
	DANE_VALID_TYPE3		: 13, /* Certificate corresponds to TLSA (type 3) */

	DANE_DNSSEC_BOGUS		: 16, /* DNSSEC of domain name or TLSA is bogus */
	DANE_CERT_ERROR			: 17, /* Server certificate missing */
	DANE_NO_CERT_CHAIN		: 18, /* Server certificate chain missing */
	DANE_TLSA_PARAM_ERR		: 19, /* Wrong TLSA parameter(s) */
	DANE_INVALID_TYPE0		: 20, /* Certificate does not corresponds to TLSA (type 0) */
	DANE_INVALID_TYPE1		: 21, /* Certificate does not corresponds to TLSA (type 1) */
	DANE_INVALID_TYPE2		: 22, /* Certificate does not corresponds to TLSA (type 2) */
	DANE_INVALID_TYPE3		: 23, /* Certificate does not corresponds to TLSA (type 3) */

	DANE_FLAG_DEBUG			: 1, /* debug output */
	DANE_FLAG_USEFWD		: 2, /* use forwarder/resolver */
};
