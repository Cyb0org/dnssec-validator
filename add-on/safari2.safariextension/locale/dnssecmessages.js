/* ***** BEGIN LICENSE BLOCK *****
Copyright 2014 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator Add-on.

DNSSEC/TLSA Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC/TLSA Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

var txt_tooltip_dnssecfail  =  "DNSSEC status unknown";
var txt_tooltip_dnssecok = "Secured by DNSSEC";
var txt_tooltip_dnssecaction = "Retrieving DNSSEC status";
var txt_tooltip_dnssecbogus = "Bogus DNSSEC signature";
var txt_tooltip_dnssecnone = "Not secured by DNSSEC";
var txt_tooltip_validatoroff = "Not verified by DNSSEC";
var txt_tooltip_dnssecwrongres = "Resolver doesn't support DNSSEC";

var txt_pre_domain = "Domain name ";
var txt_preno_domain = "Nonexistence of the domain name ";

// DNSSEC_DOMAIN_UNSECURED		: 1, /* domain is not secured */
var txt_post_1unsecuredDomain = " is not secured by DNSSEC.";
var txt_detail_1unsecuredDomainInfo = "This domain name is not secured by DNSSEC, so it is not possible to verify validity of obtained data and you are not secured against domain name spoofing.";

// DNSSEC_COT_DOMAIN_SECURED		: 2, /* both domain and connection are secured and IPs is valid */
var txt_post_2securedConnectionDomain = " is correctly secured by DNSSEC.";
var txt_detail_2securedConnectionDomainInfo = "Information about the IP address of this domain name was validated using DNSSEC. Because this domain name is secured by DNSSEC, you are protected against domain name spoofing.";

// DNSSEC_COT_DOMAIN_SECURED_BAD_IP	: 3, /* both domain and connection are secured and IPs are differ */  
var txt_post_3securedConnectionDomainInvIPaddr = " is secured by DNSSEC but browser's IP address is invalid.";
var txt_detail_3securedConnectionDomainInvIPaddrInfo = "This domain name is secured by DNSSEC but the IP address which the browser is using differs from the address obtained by the DNSSEC add-on. This may have a legitimate reason but can also point at a DNS spoofing attempt!" ;

// DNSSEC_COT_DOMAIN_BOGUS		: 4, /* domain signature is not valid or COT is not established */
var txt_post_4invalidDomainSignature = " is secured by DNSSEC but invalid domain name signature has been detected!";
var txt_detail_4invalidDomainSignatureInfo = "This domain name is secured by DNSSEC but invalid domain name signature has been detected. It could indicate spoofed domain name!";

// DNSSEC_NXDOMAIN_UNSECURED		: 5, /* non-existent domain is not secured */
var txt_post_5unsecuredNoDomain = " can not be verified with DNSSEC.";
var txt_detail_5unsecuredNoDomainInfo = "The parent domain is not secured by DNSSEC, thus it was not possible to verify nonexistence of this domain name.";

// DNSSEC_NXDOMAIN_SIGNATURE_VALID	: 6, /* domain name does not exist and connection are secured */
var txt_post_6securedConnectionNoDomain = " was validated by DNSSEC.";
var txt_detail_6securedConnectionNoDomainInfo = "The parent domain is secured by DNSSEC, thus it was possible to successfully verify nonexistence of this domain name.";

// DNSSEC_NXDOMAIN_SIGNATURE_INVALID	: 7, /* domain name does not exist and NSEC/NSEC3 is not valid */
var txt_post_7invalidNoDomainSignature = " was not correctly validated by DNSSEC because invalid signature has been detected!";
var txt_detail_7invalidNoDomainSignatureInfo = "The parent domain is secured by DNSSEC but the received domain name nonexistence response does not contain a valid signature. This may signalise a domain name spoofing attempt in order to deny the access to the domain.";

// DNSSEC_UNBOUND_NO_DATA		: -4, /* valdiator does not recived data */
var txt_post_unboundnodata = " can not be verified by DNSSEC.";
var txt_detail_unboundnodataInfo = "An error occurred while getting the DNSSEC status of this domain name. This may be caused by using a proxy server in your network. The validator is in such cases unable to prove the server's IP-address records.";

// DNSSEC_RESOLVER_NO_DNSSEC		: -3, /* resolver does not support DNSSEC */
var txt_post_dnssecWrongResolver = " can not be verified by DNSSEC.";
var txt_detail_dnssecWrongResolverInfo = "Current DNS server or resolver does not support DNSSEC technology. Please, change the validator settings (choice \"Without resolver\").";

// DNSSEC_ERROR_RESOLVER		: -2, /* bad resolver or wrong IP address of DNS*/
var txt_post_0dnssecError = " can not be verified by DNSSEC.";
var txt_detail_0dnssecErrorInfo = "An error occurred while getting the DNSSEC status of this domain name. This may be caused by loss of connection to the DNS server or the user-chosen validating resolver IP address is not an address of a validating resolver.";

// DNSSEC_ERROR_GENERIC			: -1, /* any except those listed above */
var txt_post_dnssecgenericError = " can not be verified by DNSSEC because an error occurred in DNSSEC validator core.";
var txt_detail_dnssecgenericErrorInfo = "Please, restart your web-browser...";

// DNSSEC_OFF				: 0, /* domain name validation disabled */
var txt_post_dnsseOff = " was not verified by DNSSEC.";
var txt_detail_dnsseOffInfo = "DNSSEC validation was not performed because this domain or its parent domain is mentioned in the list of excluded domains.";
