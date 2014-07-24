/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator 2.x Add-on.

DNSSEC Validator 2.x Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator 2.x Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.x Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

document.write("<!DOCTYPE html>");
document.write("<html>");
document.write("<head>");
document.write("</head>");
document.write("<body>");
document.write("<object id=\"tlsa-plugin\" type=\"application/x-tlsavalidatorplugin\" width=\"0\" height=\"0\"></object>");
document.write("<script>");

// expirate time of one item in the cache [seconds]
var CACHE_ITEM_EXPIR = 600; 
// debug pretext
var DANE = "DANE: ";
var debuglogout = false;
var init = true;
var wrongresolver = false;
var checkall = false;

/* TLSA Validator's internal cache - shared with all window tabs */
var tlsaExtCache = {

	data: null,

	init: function() {
		// Create new array for caching
		this.data = new Array();
		init = false;
	},


	record: function(tlsaresult, block, expir) {
		this.state = tlsaresult;  // tlsa result
		this.block = block;    // blocked ?
		this.expir = expir;    // expir time
	},

	addRecord: function(domain, tlsaresult, block) {	
		// Get current time
			const cur_t = new Date().getTime();
			var expir = cur_t + CACHE_ITEM_EXPIR * 1000;
			delete this.data[domain];
			this.data[domain] = new this.record(tlsaresult, block, expir);
	},

	getRecord: function(n) {
		const c = this.data;

		if (typeof c[n] != 'undefined') {
			return [c[n].state, c[n].block, c[n].expir];
		}
		return ['', '', ''];
	},

	printContent: function() {
	
		var i = 0;
		var n;
		const c = this.data;

		if (debuglogout) { 
			console.log(DANE + 'Cache content:');
		}
	          
		for (n in c) {
			if (debuglogout) { 
				console.log(DANE +'      r' + i + ': \"' + n 
				+ '\": \"' + c[n].state + '\"; ' + c[n].block 
				+ '\"; ' + c[n].expir);
			}
      			i++;
		}

		if (debuglogout) {
			console.log(DANE + 'Total records count: ' + i);
		}
	},

	delAllRecords: function() {

		if (debuglogout) { 
			console.log(DANE + 'Flushing all cache records...');
		}
		delete this.data;
		this.data = new Array();
	},
};

// DANE NPAPI constant returned by binary plugin
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

var tlsaModes = {
  // DANE/TLSA MODE
	DANE_MODE_INACTION 			: "dm_inaction",
	DANE_MODE_VALIDATION_OFF   		: "dm_validationoff",
	DANE_MODE_ACTION   			: "dm_action",
	DANE_MODE_ERROR 			: "dm_error",
	DANE_MODE_RESOLVER_FAILED     		: "dm_rfesolverfailed",
	DANE_MODE_DNSSEC_BOGUS			: "dm_dnssecbogus",
	DANE_MODE_DNSSEC_UNSECURED		: "dm_dnssecunsecured",
	DANE_MODE_NO_TLSA_RECORD		: "dm_notlsarecord",		
	DANE_MODE_NO_CERT_CHAIN			: "dm_certchain",
	DANE_MODE_TLSA_PARAM_WRONG		: "dm_tlsapramwrong",
	DANE_MODE_NO_HTTPS			: "dm_nohttps",
	DANE_MODE_DNSSEC_SECURED      		: "dm_dnssecsec", 
	DANE_MODE_CERT_ERROR          		: "dm_certerr",
	DANE_MODE_VALIDATION_FALSE		: "dm_vf",
	DANE_MODE_VALIDATION_FALSE_TYPE0	: "dm_vf0",
	DANE_MODE_VALIDATION_FALSE_TYPE1	: "dm_vf1",
	DANE_MODE_VALIDATION_FALSE_TYPE2	: "dm_vf2",
	DANE_MODE_VALIDATION_FALSE_TYPE3	: "dm_vf3",
	DANE_MODE_VALIDATION_SUCCESS_TYPE0	: "dm_vs0",
	DANE_MODE_VALIDATION_SUCCESS_TYPE1	: "dm_vs1",
	DANE_MODE_VALIDATION_SUCCESS_TYPE2	: "dm_vs2",
	DANE_MODE_VALIDATION_SUCCESS_TYPE3	: "dm_vs3",
	DANE_MODE_ERROR_GENERIC			: "dm_errgen",
	DANE_MODE_WRONG_RES			: "dnssecWrongResolver",

  //DANE/TLSA tooltip	
	DANE_TOOLTIP_VALIDATION_SUCCESS 	: "dmvsTooltip",
	DANE_TOOLTIP_VALIDATION_FALSE 		: "dmvfTooltip",
	DANE_TOOLTIP_ACTION          		: "dmaTooltip",
	DANE_TOOLTIP_FAILED_RESOLVER  		: "dmfsTooltip",
	DANE_TOOLTIP_PARAM_WRONG		: "dmwpTooltip",
	DANE_TOOLTIP_NO_TLSA_RECORD   		: "dmntrTooltip",
	DANE_TOOLTIP_NO_CERT_CHAIN    		: "dmnccTooltip",
	DANE_TOOLTIP_OFF	        	: "dmoffTooltip",
	DANE_TOOLTIP_NO_HTTPS	        	: "dmnohttpsTooltip",
	DANE_TOOLTIP_DNSSEC_BOGUS     		: "dmdnssecbogusTooltip",
	DANE_TOOLTIP_DNSSEC_UNSECURED 		: "dmdnssecunsecTooltip",
	DANE_TOOLTIP_ERROR_GENERIC 		: "dmerrorgenericTooltip",
	DANE_TOOLTIP_WRONG_RES			: "dnssecwrongres",
};


//****************************************************************
// text bool value from LocalStorage to bool
//****************************************************************
function StringToBool(value) {
	if (value == undefined) return false;
	else if (value == "false") return false;
	else if (value == "true") return true;
	else return false;
}

//****************************************************************
// this function sets TLSA mode. status ICON and popup text
//****************************************************************
function setModeTLSA(newMode, tabId, domain, status, scheme) {
	var icon;
	var title;
	var domainpre;
	var tooltiptitle;

	if (debuglogout) {	    
		console.log(DANE + "Set mode: " + newMode + "; TabId: " + tabId 
		+ "; Domain: " + domain + "; Status: " + status + "; Scheme: " 
		+ scheme);
	}
            
	switch (newMode) {
            /* green icon */
            // Both domain and connection are secured
            case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE0:
	    case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1:
            case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE2:
	    case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE3:
              	icon = "tlsa_valid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_VALIDATION_SUCCESS;
	      	domainpre = scheme;
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_VALIDATION_SUCCESS);
              break;
            case this.tlsaModes.DANE_MODE_VALIDATION_FALSE:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE1:
            case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE2:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE3:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE0:
              	icon = "tlsa_invalid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_VALIDATION_FALSE;
	      	domainpre = scheme;
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_VALIDATION_FALSE);
              break;
	    case this.tlsaModes.DANE_MODE_CERT_ERROR:
	    case this.tlsaModes.DANE_MODE_NO_CERT_CHAIN:
              	icon = "tlsa_orange.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_CERT_CHAIN;
	      	domainpre = scheme;
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_CERT_CHAIN);
              break;
	    case this.tlsaModes.DANE_MODE_TLSA_PARAM_WRONG:
              	icon = "tlsa_invalid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_PARAM_WRONG;
	      	domainpre = scheme;
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_PARAM_WRONG);
              break;
	    case this.tlsaModes.DANE_MODE_NO_TLSA_RECORD:
              	icon = "tlsa_no.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_TLSA_RECORD;
	      	domainpre = scheme;
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_TLSA_RECORD);
              break;
	    case this.tlsaModes.DANE_MODE_NO_HTTPS:
              	icon = "tlsa_nohttps.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_HTTPS;
	      	domainpre = scheme;
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_HTTPS);
              break;
	    case this.tlsaModes.DANE_MODE_DNSSEC_UNSECURED:
              	icon = "tlsa_nodnssec.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_DNSSEC_UNSECURED;
	      	domainpre = scheme;	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_DNSSEC_UNSECURED);
              break;
	    case this.tlsaModes.DANE_MODE_VALIDATION_OFF:
              	icon = "tlsa_off.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_OFF;
	      	domainpre = scheme;	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_OFF);
              break;
	    case this.tlsaModes.DANE_MODE_DNSSEC_BOGUS:
              	icon = "tlsa_invalid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_DNSSEC_BOGUS;
	      	domainpre = scheme;	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_DNSSEC_BOGUS);
              break;
	    case this.tlsaModes.DANE_MODE_ACTION:
              	icon = "tlsa_action.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_ACTION;
	      	domainpre = scheme;	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_ACTION);
              break;
	    case this.tlsaModes.DANE_MODE_RESOLVER_FAILED:
		icon = "tlsa_error.png";
		title = this.tlsaModes.DANE_TOOLTIP_FAILED_RESOLVER;
		domainpre = scheme;	
		tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_FAILED_RESOLVER);
              break;
	    case this.tlsaModes.DANE_MODE_WRONG_RES:
		icon = "tlsa_error.png";
		title = this.tlsaModes.DANE_TOOLTIP_WRONG_RES;
		domainpre = scheme;	
		tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_WRONG_RES);
              break;
            default:
		icon = "tlsa_error.png";
		title = this.tlsaModes.DANE_TOOLTIP_ERROR_GENERIC;
		domainpre = scheme;	
		tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_ERROR_GENERIC);
     	} // switch

        chrome.pageAction.setTitle({tabId: tabId, title: tooltiptitle}); 

        //console.log("icon: " + icon);
        chrome.pageAction.setIcon({path: icon, tabId: tabId});

        chrome.pageAction.show(tabId);
        //chrome.pageAction.setTitle({tabId: tabId, 
        //                            title: "DNSSEC status for " + domain + ": " + newMode});
            
        // This is extremely fucking annoying, but chrome.extension.getViews() won't work
        // unless popup is opened, so we set the validation result like GET parameters.
        chrome.pageAction.setPopup({tabId: tabId, popup: "popuptlsa.html?" + domain + "," 
		+ newMode + "," + icon + "," + title + "," + domainpre});
	    	   
     }; // setMode

//****************************************************************
// get information about custom resolver
//****************************************************************
function getResolver() {
            var resolver = "nofwd";
            var dnssecResolver = localStorage["dnssecResolver"];
            if (dnssecResolver != undefined) {
                resolver = dnssecResolver;

                if (resolver == "custom") {
                    var dnssecCustomResolver = localStorage["dnssecCustomResolver"];
                    if (dnssecCustomResolver != undefined) {
                        resolver = dnssecCustomResolver;
                    } else {
                        // We shouldn't get here unless someone deletes part of
                        // localStorage with the custom resolver setting.
                        // Empty string causes LDNS to use system settings.
                        resolver = "";
                    }
                }
            }

      return resolver;
}; // getResolver


//****************************************************************
// SET TLSA state
//****************************************************************
function setTLSASecurityState(tabId, domain, status, scheme) {

	var c = this.tlsaExtNPAPIConst;	

     	switch (status) {
	    case c.DANE_VALID_TYPE0: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE0,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_VALID_TYPE1: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_VALID_TYPE2: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_VALID_TYPE3: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE3,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_DNSSEC_SECURED: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_SECURED,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_OFF: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_OFF,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_ERROR_RESOLVER: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_RESOLVER_FAILED,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_NO_HTTPS: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_HTTPS,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_NO_TLSA: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_TLSA_RECORD,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_DNSSEC_UNSECURED: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_UNSECURED,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_DNSSEC_BOGUS: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_BOGUS,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_NO_CERT_CHAIN: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_CERT_CHAIN,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_CERT_ERROR: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_CERT_ERROR,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_TLSA_PARAM_ERR: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_TLSA_PARAM_WRONG,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_INVALID_TYPE0: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE0,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_INVALID_TYPE1: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE1,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_INVALID_TYPE2: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE2,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_INVALID_TYPE3: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE3,
			tabId, domain, status, scheme);
    		break;
	    case c.DANE_RESOLVER_NO_DNSSEC: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_WRONG_RES,
			tabId, domain, status, scheme);
    		break;
	    default:
	        this.setModeTLSA(this.tlsaModes.DANE_MODE_ERROR_GENERIC,
			tabId, domain, status, scheme);
                break;
	    }
};

//****************************************************************
// Get URL scheme (http/https/ftp/ftps)
//****************************************************************
function httpscheme(taburl){

	if (taburl.indexOf("https") != -1) return "https";
	else if (taburl.indexOf("http") != -1) return "http";
	else if (taburl.indexOf("ftps") != -1) return "ftps";
	else if (taburl.indexOf("ftp") != -1) return "ftp";
	else return "undefined";	
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
// Main TLSA validation function, call NPAPI plugin, returns TLSA state
//****************************************************************
function TLSAvalidate(scheme, domain, port){	  	

	if (debuglogout) {
		console.log(DANE + "--------- Start of TLSA Validation ("+ scheme +":"+ domain +":"+ port +") ---------");	
	}       	   

    	var c = this.tlsaExtNPAPIConst;
	var result = c.DANE_OFF;

	if (ExcludeDomainList(domain)) {		

		if (scheme == "https" || scheme == "ftps") { 
		        var resolver = this.getResolver();
			var options = 0;
			if (debuglogout) options |= c.DANE_FLAG_DEBUG;
			if (resolver != "nofwd") options |= c.DANE_FLAG_USEFWD;
			var certchain = new Array();
		        certchain.push("00FF");
			var len = 0;
			var protocol = "tcp";
			var policy = 1;
			if (debuglogout) {
				console.log(DANE + "DANE plugin inputs: {certchain}, " + 
					len +", "+ options +", "+ resolver 
					+", "+ domain +", "+ port +", "+ protocol 
					+", "+ policy); 
			}

			// Call NPAPI validation
			try {
				var tlsa = document.getElementById("tlsa-plugin");
				var daneMatch = tlsa.TLSAValidate(certchain, len, options, 
						resolver, domain, port, protocol, policy);
				result = daneMatch[0];

				if (wrongresolver) {
					if (result != c.DANE_DNSSEC_BOGUS) {
						tlsaExtCache.delAllRecords();
						wrongresolver = false;
					}
					else {
						result = c.DANE_RESOLVER_NO_DNSSEC;
					}
				}

				
				if (result == c.DANE_DNSSEC_BOGUS && !wrongresolver) {
					if (debuglogout) {
						console.log(DANE + "Plugin returns DNSSEC bogus state: Testing why?");
					}

					tlsa.TLSACacheFree();
					tlsa.TLSACacheInit();
					options = 0;
					if (debuglogout) options |= c.DANE_FLAG_DEBUG;

					if (debuglogout) {
						console.log(DANE + "   DANE plugin inputs: {certchain}, " + 
						len +", "+ options +", "+ "nofwd" 
						+", "+ domain +", "+ port +", "+ protocol 
						+", "+ policy); 
					}

					var resultnofwd = tlsa.TLSAValidate(certchain, len, options, 
						"nofwd", domain, port, protocol, policy);

					if (debuglogout) {
						console.log(DANE + "   DANE plugin result: " + resultnofwd[0]);
					}
	
					if (resultnofwd[0] == c.DANE_DNSSEC_BOGUS) {
						if (debuglogout) {
							console.log(DANE + "   Yes, DNSSEC of domain is really bogus");
						}
						result = resultnofwd[0];
						tlsa.TLSACacheFree();
						tlsa.TLSACacheInit();
					}
					else {
						if (debuglogout) {
							console.log(DANE + "   Current resolver does not support DNSSEC!");
						}
						result = c.DANE_RESOLVER_NO_DNSSEC;
						wrongresolver = true;
						tlsa.TLSACacheFree();
						tlsa.TLSACacheInit();
					}	
				}
			} catch (ex) {
				if (debuglogout) {
					console.log(DANE + 'Error: DANE plugin call failed!');
					result = c.DANE_ERROR_GENERIC;
				}
			}
		}
		else  result = c.DANE_NO_HTTPS;
        }	
	if (debuglogout) {
		console.log(DANE + "DANE plugin result: " + result);
		console.log(DANE + "--------- End of TLSA Validation ("+ scheme 
				+":"+ domain +":"+ port +") ---------");
	}
	return result;
};

//****************************************************************
// Detection of valid url. 
//****************************************************************
function IsValidUrl(tabId, url) {

	// hide icon for chrome:// and chrome-extension:// urls
	if (url.match(/^chrome(?:-extension)?:\/\//)) {
		if (tabId >= 0) {
			chrome.pageAction.hide(tabId);
		}
		return 1;
	}//if

	// deactive other tabs
	if (url.match(/^chrome(?:-devtools)?:\/\//)) {
		if (tabId >= 0) {
			chrome.pageAction.hide(tabId);
		}
		return 1;
	}//if

	// deactive other tabs
	if (url.match(/^about:/)) {
		if (tabId >= 0) {
			chrome.pageAction.hide(tabId);
		}
		return 1;
	}//if
	
	if (url.indexOf("local-ntp") != -1) {
                chrome.pageAction.hide(tabId);
                return;
	}

	// get domain name from URL
	var domain = url.match(/^(?:[\w-]+:\/+)?\[?([\w\.\[\]\:-]+)\]?(?::)*(?::\d+)?/)[1];
        //console.log("Browser: URL: " + domain);
	//ipv6
	if (domain.indexOf("]") != -1) {
	      //console.log("Browser: URL: " + domain);
              chrome.pageAction.hide(tabId);
              return;
        }//if

	// get domain name from URL
	var domain = url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];

	if (domain.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/)) {
		//console.log("Browser: URL: " + domain);
		if (tabId >= 0) {
			//chrome.pageAction.hide(tabId);
		}
		return 1;
	}//if


	return 0;
};


//****************************************************************
// return domain name and port number of url
//****************************************************************
function getDomainAndPort(url) {
	var tmp = url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(:[0-9]+)*(:)?/);
	return [tmp[1], tmp[2]];
};


//****************************************************************
// Called when TLSA is invalid, return value for web request blocking
//****************************************************************
function checkDaneResult(ret, domain) {
	
	var block = "no";

	if (ret >= tlsaExtNPAPIConst.DANE_TLSA_PARAM_ERR) {

		if (StringToBool(localStorage["blockhttps"])) {				
			var alerttext = chrome.i18n.getMessage("warningpre") 
			+ " " + domain + " " + chrome.i18n.getMessage("warningpost");
			var choice = confirm(alerttext);
			if (choice) {				
				if (debuglogout) {
					console.log(DANE + "Connection to this server was canceled by user...");
				}
				block = "yes";					
			}
			else {
				if (debuglogout) {
					console.log(DANE + "Connection to this server was permitted by user....");
				}
				block = "no";
			}
		}
	}
	return block; 
};

//****************************************************************
// Called when the url of a tab were changed.
//****************************************************************
function onUrlChange(tabId, changeInfo, tab) {                  	

	debuglogout = StringToBool(localStorage["DebugOutput"]);
   	
	if (changeInfo.status != "loading") {
		if (changeInfo.status != "complete") {
			//chrome.pageAction.hide(tabId);
			return;
		}
	}
 
	if (IsValidUrl(tabId, tab.url)) {
		return;
	}

	var portplugin = "80";
	var portpopup = "";
	var domain = "";
	var ret = tlsaExtNPAPIConst.DANE_NO_HTTPS; 
	
	if (changeInfo.status == "loading") {
		if (debuglogout) {
			console.log("\nBrowser: onUrlChange(TabID: " + tabId + ", URL: " + tab.url +");");
		}

		if (StringToBool(localStorage["cachefree"])) {
			tlsaExtCache.delAllRecords();
			localStorage["cachefree"] = false;
			wrongresolver = false;
		}

		chrome.pageAction.setPopup({tabId: tabId, popup: ""});

		var scheme = httpscheme(tab.url);
		var domainandport = getDomainAndPort(tab.url);
		domain = domainandport[0];

		if (scheme == "https" || scheme == "http") {
			portplugin = (domainandport[1] == undefined) ? "443" : domainandport[1].substring(1);	
			portpopup = (domainandport[1] == undefined) ? "" : domainandport[1];
		}
		if (scheme == "ftps" || scheme == "ftp") {
			portplugin = (domainandport[1] == undefined) ? "990" : domainandport[1].substring(1);
			portpopup = (domainandport[1] == undefined) ? "" : domainandport[1];

		}		

		if (scheme == "https" || scheme == "ftps") {
			var domainport = domain + portpopup;
			var cacheitem = tlsaExtCache.getRecord(domainport);
			if (cacheitem[0] == '' && cacheitem[1] == '') {

				ret = TLSAvalidate(scheme, domain, portplugin);
				block = "no";
			
				if (portpopup == "") {
					tlsaExtCache.addRecord(domain, ret, block);			
				}
				else {
					domain = domain + portpopup;
					tlsaExtCache.addRecord(domain, ret, block);
				}
				tlsaExtCache.printContent();
			}
			else {
				var current_time = new Date().getTime();
				if (cacheitem[2] < current_time) {
					ret = TLSAvalidate(scheme, domain, portplugin);
					block = "no";
					if (portpopup == "") {
						tlsaExtCache.addRecord(domain, ret, block);			
					}
					else {
						domain = domain + portpopup;
						tlsaExtCache.addRecord(domain, ret, block);
					}
					tlsaExtCache.printContent();
				}
				else {
					ret = cacheitem[0];
				}				
			}
		}
		setTLSASecurityState(tabId, domain+portpopup, ret, scheme);
	}
}; // onUrlChange

//****************************************************************
// Fires when the (http) request was made
//****************************************************************
function onBeforeRequest(tabId, url) {                  	

	var block = "no";	
	var portplugin = "80";
	var portcache = "80";
	var domain = "";
	var ret = tlsaExtNPAPIConst.DANE_OFF;
       
	if (IsValidUrl(tabId, url)) {
		return block;
	}

	var scheme = httpscheme(url);

	if (scheme == "https" || scheme == "ftps") {

		var domainandport = getDomainAndPort(url);
		domain = domainandport[0];

		if (scheme == "https") {
			portplugin = (domainandport[1] == undefined) ? "443" : domainandport[1].substring(1);
			portcache = (domainandport[1] == undefined) ? "" : domainandport[1];
		}
		if (scheme == "ftps") {
			portplugin = (domainandport[1] == undefined) ? "990" : domainandport[1].substring(1);
			portcache = (domainandport[1] == undefined) ? "" : domainandport[1];
		}

		var domainport = domain + portcache;
		var cacheitem = tlsaExtCache.getRecord(domainport);
		if (cacheitem[0] == '' && cacheitem[1] == '') {

			if (debuglogout) {
				console.log("\nBrowser: onBeforeRequest(TabID: " + 
				tabId + ", URL: " + url + ");");
			}

			ret = TLSAvalidate(scheme, domain, portplugin);
			block = checkDaneResult(ret, domain);
			
			if (portcache == "") {
				tlsaExtCache.addRecord(domain, ret, block);			
			}
			else {
				domain = domain + portcache;
				tlsaExtCache.addRecord(domain, ret, block);
			}
			tlsaExtCache.printContent();
		}
		else {
			var current_time = new Date().getTime();
			if (cacheitem[2] < current_time) {
				ret = TLSAvalidate(scheme, domain, portplugin);
				block = checkDaneResult(ret, domain);
				if (portcache == "") {
					tlsaExtCache.addRecord(domain, ret, block);			
				}
				else {
					domain = domain + portcache;
					tlsaExtCache.addRecord(domain, ret, block);
				}
				tlsaExtCache.printContent();
			}
			else {
				if (cacheitem[0] >= tlsaExtNPAPIConst.DANE_TLSA_PARAM_ERR) {
					if (cacheitem[1] == "yes") {
						ret = TLSAvalidate(scheme, domain, portplugin);
						block = checkDaneResult(ret, domain);
						if (portcache == "") {
							tlsaExtCache.addRecord(domain, ret, block);			
						}
						else {
							domain = domain + portcache;
							tlsaExtCache.addRecord(domain, ret, block);
						}
						tlsaExtCache.printContent();
					}
					else {
						ret = cacheitem[0];
					}				
				}
			}
		}
	}
	return block;
}; 

//****************************************************************
// Listen for any changes to the URL of any tab or tab was switched
//****************************************************************
chrome.tabs.onUpdated.addListener(onUrlChange);

//****************************************************************
// Listen for any onCompleted event of any tab
//****************************************************************
/*
chrome.webNavigation.onCompleted.addListener(function(details) {		


	if (processId == details.processId) {
		if (urlnavigate == details.url)  {
			if (frameId == details.frameId) {
				isfirst = true;
				if (debuglogout) {
					console.log("\nBrowser: onCompleted(TabID: " + 
					details.tabId + ", url: " + details.url + ", processId: " + 
					details.processId + ", frameId  : " + 	details.frameId  +");");
				}
			}
		}
	}
});
*/

//****************************************************************
// Listen for any onBeforeNavigate event of any tab
//****************************************************************
/*
chrome.webNavigation.onBeforeNavigate.addListener(function(details) {
	if (isfirst) {
		urlnavigate = details.url;
		processId = details.processId;
		frameId = details.frameId;
		isfirst = false;

		if (debuglogout) {
			console.log("\nBrowser: onBeforeNavigate(TabID: " + details.tabId 
			+ ", url: " + details.url + ", processId: " + details.processId 
			+ " Parent: " + details.parentFrameId  + ", frameId  : " + details.frameId  +");");
		}
	}
});
*/

//****************************************************************
// Listen for any webRequest of any tab
//****************************************************************
chrome.webRequest.onBeforeRequest.addListener(function(details) {

	debuglogout = StringToBool(localStorage["DebugOutput"]);	
	checkall = StringToBool(localStorage["AllHttps"]);

	if (checkall) {

		if (details.tabId >= 0) {

			if (StringToBool(localStorage["cachefree"])) {
				tlsaExtCache.delAllRecords();
				localStorage["cachefree"] = false;
				wrongresolver = false;
			}

			var domain = details.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];
		
			var block = onBeforeRequest(details.tabId, details.url);
			if (block == "yes") {
				return {cancel: details.url.indexOf(domain) != -1};		
			}
		}
	}
}, {urls: ["<all_urls>"]}, ["blocking"]);


//****************************************************************
// Do something clever here once data has been removed.
//****************************************************************
var callback = function () {
};

//****************************************************************
// Interenal initialization of plugin when browser starts
//****************************************************************
if (init) {

	var plugin = document.getElementById("tlsa-plugin");
	plugin.TLSACacheInit();

	tlsaExtCache.init();

	if (StringToBool(localStorage["clearcache"])) {
		// new API since Chrome Dev 19.0.1055.1
		if( chrome['browsingData'] && chrome['browsingData']['removeCache'] ){
			chrome.browsingData.removeCache( {'since': 0}, callback);
			if (StringToBool(localStorage["DebugOutput"])) {
				console.log(DANE + "Clear browser cache....");
			}
		}	
	}
}

//****************************************************************
// TLS/SSL features for DANE/TLSA validation
//****************************************************************
//chrome.experimental.ssl;
//chrome.experimental.ssl.onCertificateVerify.addListener(function(channel) { 
//console.log("experimental.ssl: " + channel.hostname  + " -- " + channel.constructedChain[1]  + ";");
//}, { urls: []},  []);
                
document.write("</script>");
document.write("</body>");
document.write("</html>");
