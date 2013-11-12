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

// debug pretext
var DANE = "DANE: ";
var olddomain = "null";
var currenturl = "null";
var laststate = 0;
var initcache = true;

/* TLSA Validator's internal cache - shared with all window tabs */
var tlsaExtCache = {

	data: null,

	init: function() {
		// Create new array for caching
		this.data = new Array();
		initcache = false;
	},


	record: function(tlsaresult, block) {
		this.state = tlsaresult;  // tlsa result
		this.block = block;    // blocked ?
	},

	addRecord: function(domain, tlsaresult, block) {	
		delete this.data[domain];
		this.data[domain] = new this.record(tlsaresult, block);
	},

	getRecord: function(n) {
		const c = this.data;

		if (typeof c[n] != 'undefined') {
			return [c[n].state, c[n].block];
		}
		return ['', ''];
	},

	printContent: function() {
	
		var i = 0;
		var n;
		const c = this.data;

		if (true) { 
			console.log(DANE + 'Cache content:');
		}
	          
		for (n in c) {
			if (true) { 
				console.log(DANE +'      r' + i + ': \"' + n + '\": \"' + c[n].state + '\"; ' + c[n].block);
			}
      			i++;
		}

		if (true) { 
			console.log(DANE + 'Total records count: ' + i);
		}
	},

	delAllRecords: function() {

		if (true) { 
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
};

//****************************************************************
// this function show comfirm window when resolver does not support DNSSEC
// not used since version 2.2.0
//****************************************************************
function showresolverinfo(tabId) {
	var choice = confirm(chrome.i18n.getMessage("fwdinfo"));
	if (choice) chrome.tabs.create({url: "options.html?4,0,8.8.8.8"});
};//showresolverinfo


//****************************************************************
// this function sets TLSA mode. status ICON and popup text
//****************************************************************
function setModeTLSA(newMode, tabId, domain, status, changeInfo) {
        var icon;
	var title;
	var domainpre;
      	var tooltiptitle;
	    
	console.log(DANE + "Set mode: " + newMode + "; TabId: " + tabId + "; Domain: " + domain + "; Status: " + status);
            
	switch (newMode) {
            /* green icon */
            // Both domain and connection are secured
            case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE0:
	    case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1:
            case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE2:
	    case this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE3:
              	icon = "tlsa_valid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_VALIDATION_SUCCESS;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_VALIDATION_SUCCESS);
              break;
            case this.tlsaModes.DANE_MODE_VALIDATION_FALSE:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE1:
            case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE2:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE3:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE0:
              	icon = "tlsa_invalid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_VALIDATION_FALSE;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_VALIDATION_FALSE);
              break;
	    case this.tlsaModes.DANE_MODE_CERT_ERROR:
	    case this.tlsaModes.DANE_MODE_NO_CERT_CHAIN:
              	icon = "tlsa_orange.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_CERT_CHAIN;
	      	domainpre = "https://";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_CERT_CHAIN);
              break;
	    case this.tlsaModes.DANE_MODE_TLSA_PARAM_WRONG:
              	icon = "tlsa_invalid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_PARAM_WRONG;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_PARAM_WRONG);
              break;
	    case this.tlsaModes.DANE_MODE_NO_TLSA_RECORD:
              	icon = "tlsa_no.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_TLSA_RECORD;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_TLSA_RECORD);
              break;
	    case this.tlsaModes.DANE_MODE_NO_HTTPS:
              	icon = "tlsa_nohttps.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_HTTPS;
	      	domainpre = "http";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_HTTPS);
              break;
	    case this.tlsaModes.DANE_MODE_DNSSEC_UNSECURED:
              	icon = "tlsa_nodnssec.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_DNSSEC_UNSECURED;
	      	domainpre = "https";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_DNSSEC_UNSECURED);
              break;
	    case this.tlsaModes.DANE_MODE_VALIDATION_OFF:
              	icon = "tlsa_off.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_OFF;
	      	domainpre = "http://";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_OFF);
              break;
	    case this.tlsaModes.DANE_MODE_DNSSEC_BOGUS:
              	icon = "tlsa_invalid.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_DNSSEC_BOGUS;
	      	domainpre = "https";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_DNSSEC_BOGUS);
              break;
	    case this.tlsaModes.DANE_MODE_ACTION:
              	icon = "tlsa_action.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_ACTION;
	      	domainpre = "https";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_ACTION);
              break;
            default:
               icon = "tlsa_error.png";
	       title = this.tlsaModes.DANE_MODE_RESOLVER_FAILED ;
	       domainpre = "https";	
               tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_MODE_RESOLVER_FAILED );
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
// SET TLSA status
//****************************************************************
function setTLSASecurityState(tabId, domain, status, changeInfo ) {

	var c = this.tlsaExtNPAPIConst;	

     	switch (status) {
	    case c.DANE_VALID_TYPE0: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE0,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_VALID_TYPE1: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_VALID_TYPE2: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_VALID_TYPE3: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE3,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_DNSSEC_SECURED: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_SECURED,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_OFF: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_OFF,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_ERROR_RESOLVER: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_RESOLVER_FAILED,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_NO_HTTPS: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_HTTPS,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_NO_TLSA: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_TLSA_RECORD,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_DNSSEC_UNSECURED: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_UNSECURED,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_DNSSEC_BOGUS: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_BOGUS,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_NO_CERT_CHAIN: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_CERT_CHAIN,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_CERT_ERROR: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_CERT_ERROR,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_TLSA_PARAM_ERR: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_TLSA_PARAM_WRONG,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_INVALID_TYPE0: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE0,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_INVALID_TYPE1: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE1,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_INVALID_TYPE2: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE2,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_INVALID_TYPE3: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE3,
			tabId, domain, status, changeInfo);
    		break;
	    default:
	        this.setModeTLSA(this.tlsaModes.DANE_MODE_RESOLVER_FAILED,
			tabId, domain, status, changeInfo);
                break;
	    }
};


//****************************************************************
// Get URL scheme (http/https/ftp)
//****************************************************************
function httpscheme(taburl){

	if (taburl.indexOf("https") != -1) return "https";
	else if (taburl.indexOf("http") != -1) return "http";
	else if (taburl.indexOf("ftp") != -1) return "ftp";
	else return "undefined";	
};


function TLSAvalidate(scheme, domain, port){	  	
	console.log(DANE + "--------- Start of TLSA Validation ("+ scheme +":"+ domain +":"+ port +") ---------");	

	var debug = localStorage["dnssecDebugOutput"];
	     debug = (debug == "false") ? false : true;        	   

        var resolver = this.getResolver();
	// get domain filter status
	var filteron = localStorage["domainfilteron"];
	// validate thi domain?
	var validate = true;
    	if (filteron == "true") {
		console.log(DANE + 'Domain filter: ON');
		var urldomainsepar=/[.]+/;
		var urldomainarray=domain.split(urldomainsepar);	
		var domainlist = localStorage["domainlist"];
		var domainlistsepar=/[ ,;]+/;
		var domainarraylist=domainlist.split(domainlistsepar);

		// first TLD
	        for (j=0;j<domainarraylist.length;j++) { 
	            if (urldomainarray[urldomainarray.length-1] == domainarraylist[j]) {
			validate=false; break;
		    }//if

        	} // for
		// domain in format xxx.yy
 		if (validate) {
 		   for (j=0;j<domainarraylist.length;j++) {
		   	if (domainarraylist[j].indexOf(urldomainarray[urldomainarray.length-2]) !=-1) {
				validate=false;
				break;
		   	}//if
       	            }//for
		}//if        
    	}//filteron
	else console.log(DANE + 'Domain filter: OFF');
	console.log(DANE + 'Validate this domain: ' + validate );
    	var c = this.tlsaExtNPAPIConst;
	var result = c.DANE_OFF;

     	if (validate) { 
		if (scheme == "https") { 
		        var tlsa = document.getElementById("tlsa-plugin");
			var options = 0;
			var c = this.tlsaExtNPAPIConst;
			if (debug) options |= c.DNSSEC_FLAG_DEBUG;
			if (resolver != "nofwd") options |= c.DNSSEC_FLAG_USEFWD;
			var certchain = new Array();
		        certchain.push("xxx");
			var len = certchain.length;
			len = 0;
			var daneMatch = tlsa.TLSAValidate(certchain, len, options, resolver, domain, port, "tcp", 1);
			result = daneMatch[0];
		}
		else  result = c.DANE_NO_HTTPS;
        }	
	console.log(DANE + "TLSA Validator result: " + result);
	console.log(DANE + "--------- End of TLSA Validation ("+ scheme +":"+ domain +":"+ port +") ---------");
	return result;
};

//****************************************************************
// Called when the url of a tab changes.
//****************************************************************
function onUrlChange(tabId, changeInfo, tab) {                  	
   	
	if (changeInfo.status==undefined) return;
 
	// hide icon for chrome:// and chrome-extension:// urls
	if (tab.url.match(/^chrome(?:-extension)?:\/\//)) {
		if (tabId >= 0) {
			chrome.pageAction.hide(tabId);
		}
		return;
	}//if

	// deactive other tabs
	if (tab.url.match(/^chrome(?:-devtools)?:\/\//)) {
		if (tabId >= 0) {
			chrome.pageAction.hide(tabId);
		}
		return;
	}//if

	// deactive other tabs
	if (tab.url.match(/^about:/)) {
		chrome.pageAction.hide(tabId);
		return;
	}//if


	
	if (changeInfo.status=="loading") {
		console.log("\nBrowser: onUrlChange(TabID: " + tabId + ", URL: " + tab.url +");");


		chrome.pageAction.setPopup({tabId: tabId, popup: ""});
		var scheme = httpscheme(tab.url);

		var tmp = tab.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(:[0-9]+)*(:)?/);
		var domain = tmp[1];
		var port = (tmp[2] == undefined) ? 443 : tmp[2].substring(1);	
		var port2 = (tmp[2] == undefined) ? "" : tmp[2];

	        var ret = TLSAvalidate(scheme, domain, port);
		setTLSASecurityState(tabId, domain+port2, ret, "xxx");
	}

	if (changeInfo.status=="complete") {		
		currenturl = "null";

	}


}; // onUrlChange



//****************************************************************
// Called when the url of a tab changes.
//****************************************************************
function onBeforeRequest(tabId, url) {                  	
       
	// hide icon for chrome:// and chrome-extension:// urls
	if (url.match(/^chrome(?:-extension)?:\/\//)) {
		if (tabId >= 0) {
			chrome.pageAction.hide(tabId);
		}
		return;
	}//if

	// deactive other tabs
	if (url.match(/^chrome(?:-devtools)?:\/\//)) {
		if (tabId >= 0) {
			chrome.pageAction.hide(tabId);
		}
		return;
	}//if

	// deactive other tabs
	if (url.match(/^about:/)) {
		chrome.pageAction.hide(tabId);
		return;
	}//if

	// get scheme from URL
	var scheme = httpscheme(url);

	var tmp = url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(:[0-9]+)*(:)?/);
	var domain = tmp[1];
	var port = (tmp[2] == undefined) ? 443 : tmp[2].substring(1);

	var ret = TLSAvalidate(scheme,domain,port);
//	olddomain = domain;
	return ret;
}; // onUrlChange

//****************************************************************
// Listen for any changes to the URL of any tab or tab was switched
//****************************************************************
chrome.tabs.onUpdated.addListener(onUrlChange);


//****************************************************************
// Listen for any webRequest of any tab
//****************************************************************
chrome.webRequest.onBeforeRequest.addListener(
  function(details) {
	if (details.tabId >= 0) {
		var domain = details.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];		
		if (domain == olddomain) {						
			var cacheitem = tlsaExtCache.getRecord(domain);
			if (cacheitem[1] == 'no') {
				return;
			}
			else if (cacheitem[0] == '' && cacheitem[1] == '') {
				 return;
			} else if (currenturl != "null") {
					return;		
			}
		}
		else {
			olddomain = domain;
			var cacheitem = tlsaExtCache.getRecord(domain);
			if (cacheitem[1] == 'no') {
				return;
			}
		}
		console.log("\nBrowser: onBeforeRequest(TabID: " + details.tabId + ", URL: " + details.url +");");	

   		var c = this.tlsaExtNPAPIConst;
		var result = onBeforeRequest(details.tabId, details.url);
		if (result >= c.DANE_DNSSEC_BOGUS) {
			var block = "no";				
			var blockhttps = localStorage["blockhttps"];
	   		blockhttps = (blockhttps == undefined || blockhttps == "false") ? false : true;	
		
			if (blockhttps) {				
				var alerttext = chrome.i18n.getMessage("warningpre") + " " + domain + " " + chrome.i18n.getMessage("warningpost");
				var choice = confirm(alerttext);
				if (choice) {				
					console.log(DANE + "Connection to this server was canceled by user...");
					block = "yes";
					tlsaExtCache.addRecord(domain, result , block);
					tlsaExtCache.printContent();
					return {cancel: details.url.indexOf(domain) != -1};							
				}
				else {
					block = "no";
					tlsaExtCache.addRecord(domain, result , block);
					tlsaExtCache.printContent();
					console.log(DANE + "Connection to this server was permitted by user....");
				}
			}
		}
	}	
}, {urls: ["<all_urls>"]}, ["blocking"]);


var callback = function () {
  // Do something clever here once data has been removed.
};


if (initcache) {
	tlsaExtCache.init();
	var clearcache = localStorage["clearcache"];
	clearcache = (clearcache == undefined || clearcache == "true") ? true : false;
	if (clearcache) {
		// new API since Chrome Dev 19.0.1055.1
		if( chrome['browsingData'] && chrome['browsingData']['removeCache'] ){
			chrome.browsingData.removeCache( {'since': 0}, callback);
			console.log(DANE + "Clear browser cache....");
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
