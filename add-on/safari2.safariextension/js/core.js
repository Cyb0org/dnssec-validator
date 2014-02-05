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

var debugout = true;

//****************************************************************
// Initialize DNSSEC binary plugin after start of Safari
//****************************************************************
function InitDnssecPlugin(objectid) {

        var DNSSECPlugin = document.getElementById(objectid);
	if (DNSSECPlugin) {
		if (debugout) {
			console.log("DNSSECplugin init ... DONE");
		}
		return DNSSECPlugin;
	} else {
		if (debugout) {
			console.log("DNSSECplugin init ... FAIL!");
		}
		return null;
	}
};

//****************************************************************
// Initialize TLSA binary plugin after start of Safari
//****************************************************************
function InitTlsaPlugin(objectid) {

        var TLSAPlugin = document.getElementById(objectid);
	if (TLSAPlugin) {
		if (debugout) {
			console.log("TLSAplugin init ... DONE");
		}
		return TLSAPlugin;
	} else {
		if (debugout) {
			console.log("TLSAplugin init ... FAIL!");
		}
		return null;
	}
};

//****************************************************************
// Call DNSSEC binary plugin when any validation request was fired 
//****************************************************************
function DnssecValidate(domain, options, resolver, ip) {

	if (dnssecobj != null) {
		var result = dnssecobj.Validate(domain, options, resolver, ip);
		if (debugout) {
	       		console.log("DNSSECplugin return: " + result[0]);
		}
		return result[0];		
	}
	else return null;
};

//****************************************************************
// Call TLSA binary plugin when any validation request was fired
//****************************************************************
function TlsaValidate(cert, len, options, resolver, domain, port, protocol, policy) {

	if (tlsaobj != null) {
		var result = tlsaobj.TLSAValidate(cert, len, options, resolver, domain, port, protocol, policy);
		if (debugout) {
		       	console.log("TLSAplugin return: " + result[0]);
		}
		return result[0];
	}
	else return null; 	
};
