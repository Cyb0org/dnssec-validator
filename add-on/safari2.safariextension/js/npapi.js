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

// DNSSEC NPAPI constant returned by binary plugin	
var dnssecExtNPAPIConst = {

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

	DNSSEC_FLAG_DEBUG		: 1, /* debug output */
	DNSSEC_FLAG_USEFWD		: 2, /* use forwarder/resolver */
	DNSSEC_FLAG_RESOLVIPV4		: 4, /* use IPv4, A for validation */
	DNSSEC_FLAG_RESOLVIPV6		: 8, /* use IPv6, AAAA for validation */
};

var tlsaExtNPAPIConst = {

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

var dnssecModes = {
	DNSSEC_MODE_UNBOUND_NO_DATA			: "unboundnodata",
	DNSSEC_MODE_UNBOUND_NO_DATA_INFO		: "unboundnodataInfo",
	// DNSSEC Validation OFF
	DNSSEC_MODE_OFF					: "dnsseOff",
	DNSSEC_MODE_OFF_INFO               		: "dnsseOffInfo",
	// Wrong resovler for DNSSEC
	DNSSEC_MODE_WRONG_RES				: "dnssecWrongResolver",
	DNSSEC_MODE_WRONG_RES_INFO			: "dnssecWrongResolverInfo",
	// No DNSSEC signature
	DNSSEC_MODE_DOMAIN_UNSECURED                    : "1unsecuredDomain",
	DNSSEC_MODE_DOMAIN_UNSECURED_INFO               : "1unsecuredDomainInfo",
	// Domain and also connection are secured
	DNSSEC_MODE_CONNECTION_DOMAIN_SECURED           : "2securedConnectionDomain",
	DNSSEC_MODE_CONNECTION_DOMAIN_SECURED_INFO      : "2securedConnectionDomainInfo",
	// Domain and also connection are secured but browser's IP address is invalid
	DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED : "3securedConnectionDomainInvIPaddr",
	DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED_INFO : "3securedConnectionDomainInvIPaddrInfo",         
	// Domain is secured, but it has an invalid signature
	DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID            : "4invalidDomainSignature",
	DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID_INFO       : "4invalidDomainSignatureInfo",
	// No NSEC/NSEC3 for non-existent domain name
	DNSSEC_MODE_NODOMAIN_UNSECURED                  : "5unsecuredNoDomain",          
	DNSSEC_MODE_NODOMAIN_UNSECURED_INFO             : "5unsecuredNoDomainInfo", 
	// Connection is secured, but domain name does not exist
	DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED         : "6securedConnectionNoDomain",
	DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED_INFO    : "6securedConnectionNoDomainInfo",
	// Non-existent domain is secured, but it has an invalid signature
	DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID          : "7invalidNoDomainSignature",
	DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID_INFO     : "7invalidNoDomainSignatureInfo",
	// Getting security status
	DNSSEC_MODE_ACTION     			  	: "actionDnssec",
	// Inaction status
	DNSSEC_MODE_INACTION   			  	: "inactionDnssec",
	// Error or unknown state occured
	DNSSEC_MODE_ERROR 	 			: "0dnssecError",
	DNSSEC_MODE_ERROR_INFO 			  	: "0dnssecErrorInfo",
	// Error or unknown state occured
	DNSSEC_MODE_GENERIC_ERROR			: "dnssecgenericError",
	DNSSEC_MODE_GENERIC_ERROR_INFO 			: "dnssecgenericErrorInfo",

	// Tooltips states
	DNSSEC_TOOLTIP_SECURED	: "dnssecok",
	DNSSEC_TOOLTIP_UNSECURED: "dnssecnone",
	DNSSEC_TOOLTIP_ACTION   : "dnssecaction",
	DNSSEC_TOOLTIP_ERROR    : "dnssecfail",
	DNSSEC_TOOLTIP_BOGUS    : "dnssecbogus",
	DNSSEC_TOOLTIP_WRONG_RES: "dnssecwrongres",
	DNSSEC_TOOLTIP_DNSSEC_OFF: "validatoroff", 
};


/*
//****************************************************************
// Called when the DNSSEC status is retriving
//****************************************************************
function dnssecvalidate(domain, tabId, tab) {                  	
     
	// set custom resolver
	var resolver = this.getResolver();
	var currentURL = tab.url;
	var c = this.dnssecExtNPAPIConst;
      	 
	var resolvipv4 = false; // No IPv4 resolving as default
	var resolvipv6 = false; // No IPv6 resolving as default

	if (debuglogout) {
		console.log(DNSSEC + "URL: " + currentURL);
	}

	var addr = "0.0.0.0"; // set default IP address

	addr = currentIPList[currentURL];

	if (debuglogout) {
		console.log(DNSSEC + "Browser url IP: " + addr);
	}

	if (addr == undefined) {
		addr = currentIPListDomain[domain];
		if (debuglogout) {
			console.log(DNSSEC + "Browser Domain IP: " + addr);
		}
	} 

	if (addr == undefined) {

		addr = "0.0.0.0";
		resolvipv6 = true;
		resolvipv4 = true;
	}
	else {
		// Check IP version
		if (addr.indexOf(":") != -1) {
			// ipv6
			resolvipv6 = true;
		} else if (addr.indexOf(".") != -1) {
			// ipv4
			resolvipv4 = true;
		}//if
	}
   
	var options = 0;
	if (debuglogout) options |= c.DNSSEC_FLAG_DEBUG;
	if (resolver != "nofwd") options |= c.DNSSEC_FLAG_USEFWD;
	if (resolvipv4) options |= c.DNSSEC_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= c.DNSSEC_FLAG_RESOLVIPV6;
	    
	//chrome.pageAction.setIcon({path: "dnssec_action.png", tabId: tabId});
 	//chrome.pageAction.show(tabId);

	if (resolver != "") {
		if (debuglogout) {
			console.log(DNSSEC + "DNSSEC plugin inputs: " + domain 
			+ "; options: " + options  + "; resolver: " + resolver 
			+ "; IP-br: " + addr);
		}
	}
	else {
		if (debuglogout) {
			console.log(DNSSEC + "DNSSEC plugin inputs: " + domain 
			+ "; options: " + options  + "; resolver: system; IP-br: " + addr);
		}
	}
	// Call of DNSSEC Validation plugin
	try {
		var plugin = document.getElementById("dnssec-plugin");	 	
		var result = plugin.Validate(domain, options, resolver, addr);
		if (debuglogout) {
			console.log(DNSSEC + "DNSSEC plugin result: " + result[0] + "; " + result[1]);
		}
		if (result[0] == c.DNSSEC_COT_DOMAIN_BOGUS) {
			if (debuglogout) {
				console.log(DNSSEC + "Plugin returns DNSSEC bogus state: Testing why?");
			}
			plugin.DNSSECCacheFree();
			plugin.DNSSECCacheInit();
			options = 0;
			if (debuglogout) options |= c.DNSSEC_FLAG_DEBUG;
			if (resolvipv4) options |= c.DNSSEC_FLAG_RESOLVIPV4;
			if (resolvipv6) options |= c.DNSSEC_FLAG_RESOLVIPV6;
			
			if (debuglogout) {
				console.log(DNSSEC + "   DNSSEC plugin inputs: " + domain 
				+ "; options: " + options  + "; resolver: nofwd; IP-br: " + addr);
			}

			var resultnofwd = plugin.Validate(domain, options, "nofwd", addr);

			if (debuglogout) {
				console.log(DNSSEC + "   DNSSEC plugin result: " + resultnofwd[0] 
				+ "; " + resultnofwd[1]);
			}

			if (resultnofwd[0] == c.DNSSEC_COT_DOMAIN_BOGUS) {
				if (debuglogout) {
					console.log(DNSSEC + "   Yes, DNSSEC of domain is really bogus");
				}
				result[0] = resultnofwd[0];
				plugin.DNSSECCacheFree();
				plugin.DNSSECCacheInit();
			}
			else {
				if (debuglogout) {
					console.log(DNSSEC + "   Current resolver does not support DNSSEC!");
				}
				result[0] = c.DNSSEC_RESOLVER_NO_DNSSEC;
				plugin.DNSSECCacheFree();
				plugin.DNSSECCacheInit();
			}	
		}
	} catch (ex) {
		if (debuglogout) {
			console.log(DNSSEC + "DNSSEC plugin call failed!");
		}
	     	return [c.DNSSEC_ERROR_GENERIC, "n/a", addr];		
	}
	
	if (addr == "0.0.0.0") {
		addr = "n/a"; 
	}
	var ipval = result[1];
	if (ipval == "") {
		ipval = "n/a";
	}

	return [result[0], ipval, addr];
};
  

//*****************************************************
// Return true/false if domain name is in exclude domain list
//*****************************************************
function ExcludeDomainList(domain) {

	var result = true;
 
	if (StringToBool(localStorage["domainfilteron"])) {
		var DomainSeparator = /[.]+/;
		var DomainArray = domain.split(DomainSeparator);
		var DomainList = localStorage["domainlist"];
		if (DomainList == undefined) {
			return result;
		}
		var DomainListSeparators = /[ ,;]+/;
		var DomainListArray = DomainList.split(DomainListSeparators);

		var i = 0;
		var j = 0;
		var domaintmp = DomainArray[DomainArray.length-1];
		for (i = DomainArray.length-1; i >= 0; i--) {
			for (j = 0; j < DomainListArray.length; j++) {
				if (domaintmp == DomainListArray[j]) {
					return false;
				}
			}
			domaintmp = DomainArray[i-1] + "." + domaintmp;
		}
	}
	return result;
};

      
//****************************************************************
// Called when the url of a tab changes.
//****************************************************************
function onUrlChange(tabId, changeInfo, tab) {                  	

	debuglogout = StringToBool(localStorage["DebugOutput"]);

	if (changeInfo.status == "undefined") {
		//chrome.pageAction.hide(tabId);
		return;		
	}

	if (changeInfo.status != "loading") {
		if (changeInfo.status != "complete") {
			//chrome.pageAction.hide(tabId);
			return;
		}
	}

	// reset any old popup
	chrome.pageAction.setPopup({tabId: tabId, popup: ""});

        // hide icon for chrome:// and chrome-extension:// urls
        if (tab.url.match(/^chrome(?:-extension)?:\/\//)) {
              chrome.pageAction.hide(tabId);
              return;
        }//if

	// deactive other tabs
        if (tab.url.match(/^chrome(?:-devtools)?:\/\//)) {
                chrome.pageAction.hide(tabId);
                return;
         }//if


	// deactive other tabs
        if (tab.url.match(/^(?:-devtools)?:\/\//)) {
                chrome.pageAction.hide(tabId);
                return;
         }//if

	// deactive other tabs
        if (tab.url.match(/^(?:-devtools)?:\/\//)) {
                chrome.pageAction.hide(tabId);
                return;
         }//if

	if (tab.url.indexOf("local-ntp") != -1) {
                chrome.pageAction.hide(tabId);
                return;
	}

	// get domain name from URL
	var domain = tab.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.\[\]\:-]+)\]?(?::)*(?::\d+)?/)[1];
        //console.log("Browser: URL: " + domain);
	//ipv6
	if (domain.indexOf("]") != -1) {
	      //console.log("Browser: URL: " + domain);
              chrome.pageAction.hide(tabId);
              return;
        }//if

	var domain = tab.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];
	// ipv4
        if (domain.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)) {
	      //console.log("Browser: URL: " + domain);
              chrome.pageAction.hide(tabId);
              return;
        }//if

        if (debuglogout) {
		console.log("Browser: onUrlChange(TabID: " + tabId 
		+ ", Action: " + changeInfo.status + ", Info: " + changeInfo.url + ");");
	}
	
	if (debuglogout) {
		console.log(DNSSEC + "--------- Start of DNSSEC Validation ("+ domain +") ---------");
	}

	if (ExcludeDomainList(domain)) {
		if (debuglogout) {
			console.log(DNSSEC + 'Validate this domain: YES');
		}
		var data = dnssecvalidate(domain, tabId, tab);
		statusdnssec = data[0];
		var ipval = data[1];
		var addrs = data[2];
		setDNSSECSecurityState(tabId, domain, statusdnssec, addrs, ipval);
	}
	else {
		if (debuglogout) {
			console.log(DNSSEC + 'Validate this domain: NO');
		}
		var c = this.dnssecExtNPAPIConst;
		var statusdnssec = c.DNSSEC_OFF;
		setDNSSECSecurityState(tabId, domain, statusdnssec, "n/a", "n/a");
	}

	if (debuglogout) {
		console.log(DNSSEC + "--------- End of DNSSEC Validation ("+ domain +") ---------\n");
	}
}; // onUrlChange
*/
