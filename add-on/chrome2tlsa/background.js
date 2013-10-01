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
var valid = true;
var laststate = 0;

// States of TLSA validator
var tlsaExtNPAPIConst = {
	DANE_EXIT_VALIDATION_SUCCESS_TYPE0	 : 10,
	DANE_EXIT_VALIDATION_SUCCESS_TYPE1	 : 11,
	DANE_EXIT_VALIDATION_SUCCESS_TYPE2	 : 12,
	DANE_EXIT_VALIDATION_SUCCESS_TYPE3	 : 13,
	DANE_EXIT_DNSSEC_SECURED		 : 1,
	DANE_EXIT_VALIDATION_OFF 		 : 0,
	DANE_EXIT_RESOLVER_FAILED      		 : -1,             
	DANE_EXIT_NO_HTTPS			 : -2,
	DANE_EXIT_NO_TLSA_RECORD		 : -3,
	DANE_EXIT_DNSSEC_UNSECURED		 : -4,
	DANE_EXIT_DNSSEC_BOGUS			 : -5, 
	DANE_EXIT_NO_CERT_CHAIN			 : -6,
	DANE_EXIT_CERT_ERROR			 : -7,
	DANE_EXIT_TLSA_PARAM_ERR		 : -8,
	DANE_EXIT_VALIDATION_FALSE		 : -9,
	DANE_EXIT_VALIDATION_FALSE_TYPE0	 : -10,
	DANE_EXIT_VALIDATION_FALSE_TYPE1	 : -11,
	DANE_EXIT_VALIDATION_FALSE_TYPE2	 : -12,
	DANE_EXIT_VALIDATION_FALSE_TYPE3	 : -13,
	DANE_INPUT_FLAG_DEBUGOUTPUT              : 1,
	DANE_INPUT_FLAG_USEFWD                   : 2, 
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
              	icon = "tlsagreen.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_VALIDATION_SUCCESS;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_VALIDATION_SUCCESS);
              break;
            case this.tlsaModes.DANE_MODE_VALIDATION_FALSE:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE1:
            case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE2:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE3:
	    case this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE0:
              	icon = "tlsared.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_VALIDATION_FALSE;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_VALIDATION_FALSE);
              break;
	    case this.tlsaModes.DANE_MODE_CERT_ERROR:
	    case this.tlsaModes.DANE_MODE_NO_CERT_CHAIN:
              	icon = "tlsaerr.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_CERT_CHAIN;
	      	domainpre = "https://";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_CERT_CHAIN);
              break;
	    case this.tlsaModes.DANE_MODE_TLSA_PARAM_WRONG:
              	icon = "tlsared.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_PARAM_WRONG;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_PARAM_WRONG);
              break;
	    case this.tlsaModes.DANE_MODE_NO_TLSA_RECORD:
              	icon = "tlsagrey.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_TLSA_RECORD;
	      	domainpre = "https";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_TLSA_RECORD);
              break;
	    case this.tlsaModes.DANE_MODE_NO_HTTPS:
              	icon = "tlsaoff.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_NO_HTTPS;
	      	domainpre = "http";
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_NO_HTTPS);
              break;
	    case this.tlsaModes.DANE_MODE_DNSSEC_UNSECURED:
              	icon = "tlsaoff.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_DNSSEC_UNSECURED;
	      	domainpre = "https";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_DNSSEC_UNSECURED);
              break;
	    case this.tlsaModes.DANE_MODE_VALIDATION_OFF:
              	icon = "tlsaoff.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_OFF;
	      	domainpre = "http://";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_OFF);
              break;
	    case this.tlsaModes.DANE_MODE_DNSSEC_BOGUS:
              	icon = "tlsaorange.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_DNSSEC_BOGUS;
	      	domainpre = "https";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_DNSSEC_BOGUS);
              break;
	    case this.tlsaModes.DANE_MODE_ACTION:
              	icon = "tlsaactive.png";
	      	title = this.tlsaModes.DANE_TOOLTIP_ACTION;
	      	domainpre = "https";	
        	tooltiptitle = chrome.i18n.getMessage(this.tlsaModes.DANE_TOOLTIP_ACTION);
              break;
            default:
               icon = "tlsaerr.png";
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
	    case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE0: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE0,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE1: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE2: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE1,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE3: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_SUCCESS_TYPE3,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_DNSSEC_SECURED: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_SECURED,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_OFF: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_OFF,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_RESOLVER_FAILED: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_RESOLVER_FAILED,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_NO_HTTPS: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_HTTPS,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_NO_TLSA_RECORD: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_TLSA_RECORD,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_DNSSEC_UNSECURED: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_UNSECURED,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_DNSSEC_BOGUS: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_DNSSEC_BOGUS,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_NO_CERT_CHAIN: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_NO_CERT_CHAIN,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_CERT_ERROR: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_CERT_ERROR,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_TLSA_PARAM_ERR: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_TLSA_PARAM_WRONG,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_FALSE_TYPE0: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE0,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_FALSE_TYPE1: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE1,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_FALSE_TYPE2: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE2,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_FALSE_TYPE3: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE_TYPE3,
			tabId, domain, status, changeInfo);
    		break;
	    case c.DANE_EXIT_VALIDATION_FALSE: 
		this.setModeTLSA(this.tlsaModes.DANE_MODE_VALIDATION_FALSE,
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


function TLSAvalidate(scheme,domain){	  	
	console.log(DANE + "--------- Start of TLSA Validation ("+ scheme +":"+ domain +") ---------");	

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
	var result = c.DANE_EXIT_VALIDATION_OFF;

     	if (validate) { 
		if (scheme == "https") { 
		        var tlsa = document.getElementById("tlsa-plugin");
			var options = 0;
			var c = this.tlsaExtNPAPIConst;
			options |= c.DANE_INPUT_FLAG_DEBUGOUTPUT;
			var certchain = new Array();
		        certchain.push("xxx");
			var len = certchain.length;
			len = 0;
			var daneMatch = tlsa.TLSAValidate(certchain, len, options, resolver, domain, "443", "tcp", 1);
			result = daneMatch[0];
		}
		else  result = c.DANE_EXIT_NO_HTTPS;
        }	
	console.log("DANE: TLSA Validator result: " + result);
	console.log(DANE + "--------- End of TLSA Validation ("+ scheme +":"+ domain +") ---------");
	return result;
};

//****************************************************************
// Called when the url of a tab changes.
//****************************************************************
function onUrlChange(tabId, changeInfo, tab) {                  	
   	
	if (changeInfo.status==undefined) return;
 
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
        if (tab.url.match(/^about:/)) {
                chrome.pageAction.hide(tabId);
                return;
         }//if
	
	 console.log("\nBrowser: onUrlChange(TabID: " + tabId + ", Action: " + changeInfo.status 
		+ ", Info: " + changeInfo.url + ");");

	if (changeInfo.status=="loading") {
		chrome.pageAction.setPopup({tabId: tabId, popup: ""});
		var scheme = httpscheme(tab.url);
	        var domain = tab.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];
	        var ret = TLSAvalidate(scheme,domain);
		setTLSASecurityState(tabId, domain, ret, "xxx");
	}
	 
	//if (changeInfo.status=="loading") { setTLSASecurityState(tabId, domain, laststate, "xxx");}
	if (changeInfo.status=="complete") {valid = true;}



}; // onUrlChange



//****************************************************************
// Called when the url of a tab changes.
//****************************************************************
function onBeforeRequest(tabId, url) {                  	
       
        // hide icon for chrome:// and chrome-extension:// urls
        if (url.match(/^chrome(?:-extension)?:\/\//)) {
              if (tabId >= 0) chrome.pageAction.hide(tabId);
              return;
        }//if

	// deactive other tabs
        if (url.match(/^chrome(?:-devtools)?:\/\//)) {
                if (tabId >= 0) chrome.pageAction.hide(tabId);
                return;
         }//if

    	// deactive other tabs
        if (url.match(/^about:/)) {
                chrome.pageAction.hide(tabId);
                return;
         }//if

	// get scheme from URL
	var scheme = httpscheme(url);
	// get domain name from URL
        var domain = url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];
        var ret = TLSAvalidate(scheme,domain);
        olddomain = domain;
	valid = false;
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
		if (valid)  {	
			
		console.log("\nBrowser: onBeforeRequest(TabID: " + details.tabId + ", URL: " + details.url +", valid: " + valid +");");	
			if (domain != olddomain) {						
		   		var c = this.tlsaExtNPAPIConst;
				var result = onBeforeRequest(details.tabId, details.url);
				if (result <= c.DANE_EXIT_DNSSEC_BOGUS) {
				
					var blockhttps = localStorage["blockhttps"];
			   		blockhttps = (blockhttps == undefined || blockhttps == "false") ? false : true;				
					if (blockhttps) {				
						var alerttext = chrome.i18n.getMessage("warningpre") + " " + domain + " " + chrome.i18n.getMessage("warningpost");
						var choice = confirm(alerttext);
						if (choice) {				
							console.log("DANE: Connection was aborted...");
							return {cancel: details.url.indexOf(domain) != -1};
						}
					}
				}
			}
		}	
	}
  },
  {urls: ["<all_urls>"]},
  ["blocking"]);


/*
chrome.webNavigation.onCompleted.addListener(function(details) {
        // hide icon for chrome:// and chrome-extension:// urls
        if (details.url.match(/^chrome(?:-extension)?:\/\//)) {
              chrome.pageAction.hide(details.tabId);
              return;
        }//if

	// deactive other tabs
        if (details.url.match(/^chrome(?:-devtools)?:\/\//)) {
                chrome.pageAction.hide(details.tabId);
                return;
         }//if

	// deactive other tabs
        if (details.url.match(/^about:/)) {
                chrome.pageAction.hide(details.tabId);
                return;
         }//if
console.log("Browser: onCompleted(TabID: " + details.tabId + ", URL: " + details.url +");\n");
  },
{ urls: [], types: [] },  []);
*/
/*
chrome.webNavigation.onBeforeNavigate.addListener(function(details) {	
console.log("Browser: onBeforeNavigate(TabID: " + details.tabId + ", URL: " + details.url +");\n");
  },
{ urls: [], types: [] },  []);
*/

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
