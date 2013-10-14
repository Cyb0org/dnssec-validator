/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator 2.0 Add-on.

DNSSEC Validator 2.0 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator 2.0 Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.0 Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

document.write("<!DOCTYPE html>");
document.write("<html>");
document.write("<head>");
document.write("</head>");
document.write("<body>");
document.write("<object id=\"dnssec-plugin\" type=\"application/x-dnssecvalidator\" width=\"0\" height=\"0\"></object>");
document.write("<script>");

	// debug pretext
	var DNSSEC = "DNSSEC: ";
	
	// some variables for chrome IP API
	var currentIPList= new Array();
	var currentIPListDomain= new Array();
        // Save all IP addresses by URLs in a temporary object
	var addr = "0.0.0.0";        // set default IP address
	var addrbackup = "0.0.0.0";  // set default IP address for backup

	// States of DNSSEC validator
	var dnssecExtNPAPIConst = {
		DNSSEC_EXIT_WRONG_RES                      : -2,
		DNSSEC_EXIT_DNSSEC_OFF                     : -1,
  		DNSSEC_EXIT_FAILED                         : 0, /* state is unknown or fail*/
		DNSSEC_EXIT_DOMAIN_UNSECURED 		   : 1, /* domain is not secured */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP   : 2, /* domain name is secured by DNSSEC and the IP address of browser is valid */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP : 3, /* domain name is secured by DNSSEC but the IP address of browser is invalid */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS        : 4, /* domain signature is not valid or chain of trust is not established */
  		DNSSEC_EXIT_NODOMAIN_UNSECURED             : 5, /* non-existent domain is not secured */
  		DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID       : 6, /* non-existent domain is secured by DNSSEC */
  		DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID     : 7, /* non-existent domain is not valid or chain of trust is not established */
  		DNSSEC_INPUT_FLAG_DEBUGOUTPUT              : 1, /* debug output */
  		DNSSEC_INPUT_FLAG_USEFWD                   : 2, /* use TCP instead of default UDP */
  		DNSSEC_INPUT_FLAG_RESOLVIPV4               : 4, /* resolve IPv4 address (A record) */
  		DNSSEC_INPUT_FLAG_RESOLVIPV6               : 8, /* resolve IPv6 address (AAAA record) */
	};

        var dnssecModes = {
          // DNSSEC Validation OFF
          DNSSEC_MODE_OFF                    		  : "dnsseOff",
	  DNSSEC_MODE_OFF_INFO               		  : "dnsseOffInfo",
	  // Wrong resovler for DNSSEC
	  DNSSEC_MODE_WRONG_RES				  : "dnssecWrongResolver",
 	  DNSSEC_MODE_WRONG_RES_INFO			  : "dnssecWrongResolverInfo",
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
          DNSSEC_MODE_ACTION     			  : "actionDnssec",
          // Inaction status
          DNSSEC_MODE_INACTION   			  : "inactionDnssec",
          // Error or unknown state occured
          DNSSEC_MODE_ERROR 	 			  : "0dnssecError",
	  DNSSEC_MODE_ERROR_INFO 			  : "0dnssecErrorInfo",

          // Tooltips states
          DNSSEC_TOOLTIP_SECURED   : "dnssecok",
          DNSSEC_TOOLTIP_UNSECURED : "dnssecnone",
          DNSSEC_TOOLTIP_ACTION    : "dnssecaction",
          DNSSEC_TOOLTIP_ERROR     : "dnssecfail",
          DNSSEC_TOOLTIP_BOGUS     : "dnssecbogus",
          DNSSEC_TOOLTIP_WRONG_RES : "dnssecwrongres",
	  DNSSEC_TOOLTIP_DNSSEC_OFF : "validatoroff",  
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
// this function sets DNSSEC mode. status ICON and popup text
//****************************************************************
function setModeDNSSEC(newMode, tabId, domain, status,  addr, ipval, changeInfo) {
        var icon;
	var title;
	var domainpre;
      	var tooltiptitle;
	    
	console.log(DNSSEC + "Set mode: " + newMode + "; TabId: " + tabId + "; Doamin: " + domain + "; Status: " + status);
            
	switch (newMode) {
            /* green icon */
            // Both domain and connection are secured
            case this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED:
              	icon = "dnssec_valid.png";
	      	title = this.dnssecModes.DNSSEC_TOOLTIP_SECURED;
	      	domainpre = "domain";
        	tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_SECURED);
              break;
            // Both non-existent domain and connection are secured
            case this.dnssecModes.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED:
              	icon = "dnssec_valid.png";
	      	title = this.dnssecModes.DNSSEC_TOOLTIP_SECURED;
	      	domainpre = "nodomain";
	        tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_SECURED);
              break;
            // Domain and also connection are secured but browser's IP address is invalid
            case this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED:
	        icon = "dnssec_ip.png";
 	 	title = this.dnssecModes.DNSSEC_TOOLTIP_SECURED;
		domainpre = "domain";
	        tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_SECURED);
              break;
            /* grey icon */
            // No DNSSEC signature
            case this.dnssecModes.DNSSEC_MODE_DOMAIN_UNSECURED:
	        icon = "dnssec_no.png";
		title = this.dnssecModes.DNSSEC_TOOLTIP_UNSECURED;
	        domainpre = "domain";
	        tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_UNSECURED);
              break; 
            case this.dnssecModes.DNSSEC_MODE_NODOMAIN_UNSECURED:
                icon = "dnssec_no.png";
	        title = this.dnssecModes.DNSSEC_TOOLTIP_UNSECURED;
	        domainpre = "nodomain";
	        tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_UNSECURED);
              break;
            /* red icon */
            // Domain signature is invalid
            case this.dnssecModes.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID:
                 icon = "dnssec_bogus.png";
	        title = this.dnssecModes.DNSSEC_TOOLTIP_BOGUS;
	        domainpre = "domain";
	        tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_BOGUS);
              break;
            // Non-existent domain signature is invalid
            case this.dnssecModes.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID:
                icon = "dnssec_bogus.png";
	        title = this.dnssecModes.DNSSEC_TOOLTIP_BOGUS;
	        domainpre = "nodomain";
	        tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_BOGUS);
              break;
            // Getting security status
            case this.dnssecModes.DNSSEC_MODE_ACTION:
                icon = "dnssec_action.png";
	        title = this.dnssecModes.DNSSEC_TOOLTIP_ACTION;
	        tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_ACTION);
              break;
            case this.dnssecModes.DNSSEC_MODE_OFF:
                icon = "dnssec_off.png";
		domainpre = "domain";
  	        title = this.dnssecModes.DNSSEC_TOOLTIP_DNSSEC_OFF;
                tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_DNSSEC_OFF);
              break;
            case this.dnssecModes.DNSSEC_MODE_WRONG_RES:
                icon = "dnssec_error.png";
		domainpre = "domain";
  	        title = this.dnssecModes.DNSSEC_TOOLTIP_WRONG_RES;
                tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_WRONG_RES);
              break;
            // An error occured
            case this.dnssecModes.DNSSEC_MODE_ERROR:
            // Unknown
            default:
               icon = "dnssec_error.png";
	       title = this.dnssecModes.DNSSEC_TOOLTIP_ERROR;
	       domainpre = "domain";	
               tooltiptitle = chrome.i18n.getMessage(this.dnssecModes.DNSSEC_TOOLTIP_ERROR);
     	} // switch

        chrome.pageAction.setTitle({tabId: tabId, title: tooltiptitle}); 

        //console.log("icon: " + icon);
        chrome.pageAction.setIcon({path: icon, tabId: tabId});

        chrome.pageAction.show(tabId);
        //chrome.pageAction.setTitle({tabId: tabId, 
        //                            title: "DNSSEC status for " + domain + ": " + newMode});
            
        // This is extremely fucking annoying, but chrome.extension.getViews() won't work
        // unless popup is opened, so we set the validation result like GET parameters.
        chrome.pageAction.setPopup({tabId: tabId, popup: "popup.html?" + domain + "," 
		+ newMode + "," + icon + "," + title + "," + domainpre + "," + addr + "," + ipval});
	    
	//if (fwdinfo) if (changeInfo == "complete") showresolverinfo(tabId);	   
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
// SET DNSSEC status
//****************************************************************
function setDNSSECSecurityState(tabId, domain, status, addr, ipval, changeInfo ) {

	var c = this.dnssecExtNPAPIConst;	
	
     	switch (status) {
	    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP: 
		this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED,
			tabId, domain, status, addr, ipval, changeInfo);
    		break;
	    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP: 
		this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED,
			tabId, domain, status, addr,  ipval, changeInfo);
	        break;
	    case c.DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID: 
		this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED,
			tabId, domain, status, addr,  ipval, changeInfo);
	        break;
	    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS:
	        this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID,
			tabId, domain, status, addr,  ipval, changeInfo);
	        break;
	    case c.DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID:
	        this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID,
			tabId, domain, status, addr,  ipval, changeInfo);
	        break;
	    case c.DNSSEC_EXIT_DOMAIN_UNSECURED:
	        this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_DOMAIN_UNSECURED,
			tabId, domain, status,  addr, ipval, changeInfo);
                break;
	    case c.DNSSEC_EXIT_NODOMAIN_UNSECURED:
	        this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_NODOMAIN_UNSECURED,
			tabId, domain, status,  addr, ipval, changeInfo);
	        break;
	    case c.DNSSEC_EXIT_DNSSEC_OFF:
	        this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_OFF,
			tabId, domain, status, addr, ipval, changeInfo);
	        break;
	    case c.DNSSEC_EXIT_WRONG_RES:
	        this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_WRONG_RES,
			tabId, domain, status, addr, ipval, changeInfo);
	        break;
	    case c.DNSSEC_EXIT_FAILED:
	    default:
	        this.setModeDNSSEC(this.dnssecModes.DNSSEC_MODE_ERROR,
			tabId, domain, status, addr,  ipval, changeInfo);
                break;
	    }
};

//****************************************************************
// Called when the DNSSEC status is retriving
//****************************************************************
function dnssecvalidate(domain, tabId, changeInfo, tab) {                  	
     
	// set custom resolver
        var resolver = this.getResolver();
        var currentURL = tab.url;
	var c = this.dnssecExtNPAPIConst;
	var debug = localStorage["dnssecDebugOutput"];
	     debug = (debug == "false") ? false : true;        	   

	var resolvipv4 = false; // No IPv4 resolving as default
	var resolvipv6 = false; // No IPv6 resolving as default

        console.log(DNSSEC + "URL: " + currentURL);	  	     
	addr = currentIPList[currentURL];
	console.log(DNSSEC + "Browser URL IP: " + addr);
	
	if (addr == undefined) {
		addr = currentIPListDomain[domain];
	        console.log(DNSSEC + "Browser Domain IP: " + addr);
	}//if
	    
	if (addr == undefined) {
		addr = addrbackup;
	        console.log(DNSSEC + "NO IP: " + addr);
	}//if

	    
	// Check IP version
	if (addr.indexOf(":") != -1) {
		// ipv6
	        resolvipv6 = true;
	} else if (addr.indexOf(".") != -1) {
	        // ipv4
	        resolvipv4 = true;
	}//if
   
	var options = 0;
	if (debug) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
	if (resolver != "nofwd") options |= c.DNSSEC_INPUT_FLAG_USEFWD;
	if (resolvipv4) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV6;
	    
	var icon = "dnssec_action.png";
	chrome.pageAction.setIcon({path: icon, tabId: tabId});
 	chrome.pageAction.show(tabId);

	if (resolver!="") console.log(DNSSEC + "Validator input: " + domain + "; options: " + options  + "; resolver: " + resolver  + "; IP-br: " + addr);	    
	else console.log(DNSSEC + "Validator input: " + domain + "; options: " + options  + "; resolver: system; IP-br: " + addr);
	// Call of Validation function
      	var plugin = document.getElementById("dnssec-plugin");	 	
	var result = plugin.Validate(domain, options, resolver, addr);
        console.log(DNSSEC + "Validator result: " + result[0] + "; " + result[1]);

	if (result[0]==c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS) {
		console.log(DNSSEC + "Unbound return bogus state: Testing why?");
		plugin.CacheFree();
		options = 0;
	    	if (debug) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
   	    	if (resolvipv4) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV4;
	    	if (resolvipv6) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV6;
	    	console.log(DNSSEC + "NOFWD input: " + domain + "; options: " + options  + "; resolver: nofwd; IP-br: " + addr);
	    	var resultnofwd = plugin.Validate(domain, options, "nofwd", addr);
	    	console.log(DNSSEC + "NOFWD result: " + resultnofwd[0] + "; " + resultnofwd[1]);
		if (resultnofwd[0]==c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS) {
			result[0]=resultnofwd[0];
			console.log(DNSSEC + "Yes, domain name has bogus");
			plugin.CacheFree();
			//fwdinfo=false;
		} 
		else
		{		   
			console.log(DNSSEC + "Current resolver does not support DNSSEC!");
			console.log(DNSSEC + "Results: FWD: " + result[0] + "; NOFWD: " + resultnofwd[0]);
			result[0]=c.DNSSEC_EXIT_WRONG_RES;
			plugin.CacheFree();
			//fwdinfo=true;
		}//if		
	    } //if

	    if (addr == "0.0.0.0") addr = "n/a"; 
  	    icon = ""; 
     	    var ipval = result[1];
            if (ipval == "")  ipval = "n/a";
  
     	return [result[0], ipval];
}; // dnssecvalidate
        
//****************************************************************
// Called when the url of a tab changes.
//****************************************************************
function onUrlChange(tabId, changeInfo, tab) {                  	

	// reset any old popup
	chrome.pageAction.setPopup({tabId: tabId, popup: ""});
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
 
        if (changeInfo.status==undefined) return;

        console.log("Browser: onUrlChange(TabID: " + tabId + ", Action: " + changeInfo.status 
		+ ", Info: " + changeInfo.url + ");");

	 // get domain name from URL
         var domain = tab.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];
  	  	
	console.log(DNSSEC + "--------- Start of DNSSEC Validation ("+ domain +") ---------");  	

	// get domain filter status
	var filteron = localStorage["domainfilteron"];
	// validate thi domain?
	var validate = true;
    	if (filteron == "true") {
		console.log(DNSSEC + 'Domain filter: ON');
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
	else console.log(DNSSEC + 'Domain filter: OFF');
	
	console.log(DNSSEC + 'Validate this domain: ' + validate );
        var c = this.dnssecExtNPAPIConst;
        var statusdnssec = c.DNSSEC_EXIT_DNSSEC_OFF;

     	if (validate) {  
	    var data = dnssecvalidate(domain, tabId, changeInfo, tab);
	    statusdnssec = data[0];
	    var ipval = data[1];
	    setDNSSECSecurityState(tabId, domain, statusdnssec, addr, ipval, changeInfo.status);
        }
	else setDNSSECSecurityState(tabId, domain, statusdnssec, addr, "n/a", changeInfo.status);

        console.log(DNSSEC + "--------- End of DNSSEC Validation ("+ domain +") ---------\n");
}; // onUrlChange

//****************************************************************  
// get IP address of URL      
//****************************************************************
chrome.webRequest.onResponseStarted.addListener(function(info) {
	currentIPList[ info.url ] = info.ip;
	var urldomain = info.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1];
	currentIPListDomain[ urldomain ] = info.ip;
    	//console.log("currentIPList: " + info.url + " -- " + info.ip + ";");
      	//console.log("currentIPListDomain: " + urldomain + " -- " + info.ip + ";");
	return;},
	{ urls: [], types: [] },  []
	);

//****************************************************************
// Listen for any changes to the URL of any tab.
//****************************************************************
chrome.tabs.onUpdated.addListener(onUrlChange);
                
document.write("</script>");
document.write("</body>");
document.write("</html>");
