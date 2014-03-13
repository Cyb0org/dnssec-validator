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

var dmvsTooltipwrongres = "Resolver doesn't support DNSSEC";
var dmvsTooltip = "Certificate corresponds to TLSA";
var dmvfTooltip = "TLSA validation failed";
var dmaTooltip = "TLSA validation in progress";
var dmfsTooltip = "TLSA status unknown";
var dmwpTooltip = "Wrong TLSA parameters";
var dmntrTooltip = "Non-existent TLSA record";
var dmnccTooltip = "Unable to get certificate";
var dmoffTooltip = "TLSA validation disabled";
var dmnohttpsTooltip = "No HTTPS connection";
var dmdnssecbogusTooltip = "Bogus DNSSEC signature";
var dmdnssecunsecTooltip = "Not secured by DNSSEC";
var dmerrorgenericTooltip = "Validator fails";

var dnssecWrongResolver = "The authenticity of TLS/SSL remote server certificate for the domain name could not be verified by DANE protocol.";
var dnssecWrongResolverInfo = "Current DNS server or resolver does not support DNSSEC technology. Please, change the validator settings (choice \"Without resolver\").";

var dm_errgen = "The remote server certificate for this domain name could not be verified by DANE protocol because an error occurred in TLSA validator core.";
var dm_errgenInfo = "Please, restart your web-browser...";

var dm_rfesolverfailed = "The remote server certificate for this domain name could not be verified by DANE protocol because an error occurred while retrieving the TLSA record for this domain name.";
var dm_rfesolverfailedInfo = "An error occurred while retrieving the TLSA record for this domain name. This may be caused by loss of connection to the DNS server or the user-chosen validating resolver IP address is not an address of a validating resolver.";

var dm_nohttps = "No HTTPS secured connection to the remote server was established. Therefore, you can not perform TLSA record validation.";
var dm_nohttpsInfo = "The authenticity of TLS/SSL remote server certificate for the domain name could not be verified by DANE protocol because the connection to the remote server is not realized via HTTPS protocol.";

var dm_notlsarecord = "The remote server certificate for this domain name could not be verified by DANE protocol because there is no TLSA record for this domain name.";
var dm_notlsarecordInfo = "The authenticity of TLS/SSL remote server certificate for this domain name could not be verified by DANE protocol because there is no TLSA record for this domain name.";

var dm_dnssecunsecured = "This domain name is not secured by DNSSEC, therefore it is not possible to verify the validity of remote server certifcate by DANE protocol.";
var dm_dnssecunsecuredInfo = "The authenticity of TLS/SSL remote server certificate for this domain name could not be verified by DANE protocol because this domain name is not secured by DNSSEC.";

var dm_dnssecbogus = "This domain name is secured by DNSSEC but an invalid domain name signature has been detected. Therefore, the validation of the server certificate can not be verified by DANE protocol.";
var dm_dnssecbogusInfo = "The authenticity of TLS/SSL remote server certificate for this domain name can not be verified by DANE protocol because an invalid domain name signature has been detected by DNSSEC.";

var dm_certchain = "The remote server certificate for this domain name can not be verified by DANE protocol because the certificate chain could not be obtained.";
var dm_certchainInfo = "The authenticity of TLS/SSL remote server certificate for the domain name can not be verified by DANE protocol because the certificate chain could not be obtained.";

var dm_certerr = "The remote server certificate for this domain name could not be verified by DANE protocol because the server certificate could not be obtained.";
var dm_certerrInfo = "The authenticity of TLS/SSL remote server certificate for the domain name can not be verified by DANE protocol because the server certificate could not be obtained.";

var dm_tlsapramwrong = "The remote server certificate for this domain name was not verified by DANE protocol because the TLSA record contains wrong parameter values.";
var dm_tlsapramwrongInfo = "The authenticity of TLS/SSL remote server certificate for this domain name could not be verified by DANE protocol because the TLSA record has wrong parameter values. It could indicate spoofing of TLSA information.";

var dm_vf = "The DANE protocol verification of remote server's certificate for this domain name failed. The certificate does not correspond to the TLSA record which is secured by DNSSEC technology.";
var dm_vfInfo = "The authenticity of TLS/SSL remote server certificate for this domain name was not verified by DANE protocol. The certificate does not correspond to the TLSA record which is secured by DNSSEC technology.";

var dm_vf0 = "The DANE protocol verification of remote server's certificate for this domain name failed. The certificate does not correspond to the TLSA record which is secured by DNSSEC technology.";
var dm_vf0Info = "The authenticity of TLS/SSL remote server certificate for this domain name couldn't be verified by DANE protocol. The certificate does not correspond with the CA certificate in the TLSA record (type 0). TLSA record is secured by DNSSEC technology.";

var dm_vf1 = "The DANE protocol verification of remote server's certificate for this domain name failed. The certificate does not correspond to the TLSA record which is secured by DNSSEC technology.";
var dm_vf1Info = "The authenticity of TLS/SSL remote server certificate for this domain name couldn't be verified by DANE protocol. The certificate does not correspond with the EE certificate in the TLSA record (type 1). TLSA record is secured by DNSSEC technology.";

var dm_vf2 = "The DANE protocol verification of remote server's certificate for this domain name failed. The certificate does not correspond to the TLSA record which is secured by DNSSEC technology.";
var dm_vf2Info = "The authenticity of TLS/SSL remote server certificate for this domain name couldn't be verified by DANE protocol. The certificate does not correspond with the CA certificate in the TLSA record (type 2). TLSA record is secured by DNSSEC technology.";

var dm_vf3 = "The DANE protocol verification of remote server's certificate for this domain name failed. The certificate does not correspond to the TLSA record which is secured by DNSSEC technology.";
var dm_vf3Info = "The authenticity of TLS/SSL remote server certificate for this domain name couldn't be verified by DANE protocol. The certificate does not correspond with the EE certificate in the TLSA record (type 3). TLSA record is secured by DNSSEC technology.";

var dm_vs0 = "The remote server certificate for this domain name was verified by DANE protocol. The certificate corresponds to TLSA record which is secured by DNSSEC technology.";
var dm_vs0Info = "The authenticity of TLS/SSL remote server certificate for this domain name was verified by DANE protocol. Certificate passed the PKIX validation and corresponds with the CA certificate in the TLSA record (type 0). TLSA record is secured by DNSSEC technology.";

var dm_vs1 = "The remote server certificate for this domain name was verified by DANE protocol. The certificate corresponds to TLSA record which is secured by DNSSEC technology.";
var dm_vs1Info = "The authenticity of TLS/SSL remote server certificate for this domain name was verified by DANE protocol. Certificate passed the PKIX validation and corresponds with the EE certificate in the TLSA record (type 1). TLSA record is secured by DNSSEC technology.";

var dm_vs2 = "The remote server certificate for this domain name was verified by DANE protocol. The certificate corresponds to TLSA record which is secured by DNSSEC technology.";
var dm_vs2Info = "The authenticity of TLS/SSL remote server certificate for this domain name was verified by DANE protocol. Certificate passed the PKIX validation and corresponds with the CA certificate in the TLSA record (type 2). TLSA record is secured by DNSSEC technology.";

var dm_vs3 = "The remote server certificate for this domain name was verified by DANE protocol. The certificate corresponds to TLSA record which is secured by DNSSEC technology.";
var dm_vs3Info = "The authenticity of TLS/SSL remote server certificate for this domain name was verified by DANE protocol. Certificate is corresponding with the EE certificate in the TLSA record (type 3). TLSA record is secured by DNSSEC technology.";

var dm_validationoff = "The remote server certificate for this domain name was not verified by DANE protocol. The TLSA validation has not been performed because this domain is mentioned in the list of excluded domains.";
var dm_validationoffInfo = "The validity of TLS/SSL remote server certificate for the domain name was not verified by DANE protocol. The TLSA validation has not been performed because this domain is mentioned in the list of excluded domains.";

var warningpre = "TLSA validator warning!\n\nThe remote server certificate for https://";
var warningpost = "\ndoes not correspond to the TLSA record. This can be caused by:\n- trying to connect to untrusted remote server\n- invalid or untrusted server certificate\n\nDo you want close the connection to this server?";
