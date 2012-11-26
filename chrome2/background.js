document.write("<!DOCTYPE html>");
document.write("<html>");
document.write("<head>");
document.write("</head>");
document.write("<body>");
document.write("<object id=\"dnssec-plugin\" type=\"application/x-dnssecvalidator\" width=\"0\" height=\"0\"></object>");
document.write("<script>");

	// Save all IP addresses by URLs in a temporary object
	var currentIPList= new Array();
	var addr = "0.0.0.0";  // set default IP address
	var init = true;

	var dnssecExtNPAPIConst = {
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


/* connection is secured, but domain has invalid signature */

        var dnssecModes = {
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

/*
          // Non-existent domain and also connection are secured but browser's IP address is invalid
          DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED : "securedConnectionNoDomainInvIPaddr",
          // Connection is secured, but domain name signature is invalid
          DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED     : "securedConnectionInvSigDomain",
          // Connection is secured, but domain name signature and browser's IP address are invalid
          DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED : "securedConnectionInvSigDomainInvIPaddr",
          // Domain is secured and has a valid signature, but no chain of trust
          DNSSEC_MODE_DOMAIN_SIGNATURE_VALID              : "validDomainSignature",
          // Authoritative domain is secured and has a valid signature, but no chain of trust
          DNSSEC_MODE_AUTH_DOMAIN_SIGNATURE_VALID         : "validAuthDomainSignature",
          // Domain is secured and has a valid signature, but browser's IP address is invalid
          DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID    : "validDomainSignatureInvIPaddr",
          // Domain is secured, but it has an invalid signature
          DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID            : "invalidDomainSignature",
          // Domain is secured, but signature and browser's IP address are invalid
          DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID  : "invalidDomainSignatureInvIPaddr",
          // Non-existent domain is secured and has a valid signature, but no chain of trust
          DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID            : "validNoDomainSignature",
          // Authoritative non-existent domain is secured and has a valid signature, but no chain of trust
          DNSSEC_MODE_AUTH_NODOMAIN_SIGNATURE_VALID       : "validAuthNoDomainSignature",
          // Non-existent domain is secured and has a valid signature, but browser's IP address is invalid
          DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_VALID  : "validNoDomainSignatureInvIPaddr",

          // Non-existent domain is secured, but signature and browser's IP address are invalid
          DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_INVALID : "invalidNoDomainSignatureInvIPaddr",
*/
          // Getting security status
          DNSSEC_MODE_ACTION : "actionDnssec",
          // Inaction status
          DNSSEC_MODE_INACTION : "inactionDnssec",
          // Error or unknown state occured
          DNSSEC_MODE_ERROR : "0dnssecError",
	  DNSSEC_MODE_ERROR_INFO : "0dnssecErrorInfo",

          // Tooltips
          DNSSEC_TOOLTIP_SECURED   : "securedTooltip",
          DNSSEC_TOOLTIP_UNSECURED : "unsecuredTooltip",
          DNSSEC_TOOLTIP_ACTION    : "actionTooltip",
          DNSSEC_TOOLTIP_ERROR     : "errorTooltip",
            
        };

        function setMode(newMode, tabId, domain, status) {
            var icon;
	    var title;
	    var domainpre;
		console.log("SET MODE: " + newMode + "; TabId: " + tabId + "; Doamin: " + domain + "; Status: " + status);
            
	switch (newMode) {
            /* green icon */
            // Both domain and connection are secured
            case this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED:
              icon = "icon_green.png";
	      title = "dnssecok";
	      domainpre = "domain";
              break;
            // Both non-existent domain and connection are secured
            case this.dnssecModes.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED:
              icon = "icon_green.png";
	      title = "dnssecok";
	      domainpre = "nodomain";
              break;
            // Domain and also connection are secured but browser's IP address is invalid
            case this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED:
              icon = "icon_green_ip.png";
     	      title = "dnssecok";
	      domainpre = "domain";
              break;
            /* grey icon */

            // No DNSSEC signature
            case this.dnssecModes.DNSSEC_MODE_DOMAIN_UNSECURED:
              icon = "icon_grey2.png";
	      title = "dnssecnone";
	      domainpre = "domain";
              break; 
            case this.dnssecModes.DNSSEC_MODE_NODOMAIN_UNSECURED:
              icon = "icon_grey2.png";
	      title = "dnssecnone";
	      domainpre = "nodomain";
              break;

            /* red icon */
            // Domain signature is invalid
            case this.dnssecModes.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID:
              icon = "icon_red.png";
	      title = "dnssecbogus";
	      domainpre = "domain";
              break;
            // Non-existent domain signature is invalid
            case this.dnssecModes.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID:
              icon = "icon_red.png";
	      title = "dnssecbogus";
	      domainpre = "nodomain";
              break;
            // Getting security status
            case this.dnssecModes.DNSSEC_MODE_ACTION:
              icon = "icon_action.gif";
	      title = "dnssecaction";
              break;
            // An error occured
            case this.dnssecModes.DNSSEC_MODE_ERROR:
            // Unknown
            default:
              icon = "icon_unknown.png";
	      title = "dnssecfail";
	      domainpre = "domain";	
            }

            //console.log("icon: " + icon);
            chrome.pageAction.setIcon({path: icon,
                                           tabId: tabId});
            chrome.pageAction.show(tabId);
            //chrome.pageAction.setTitle({tabId: tabId, 
            //                            title: "DNSSEC status for " + domain + ": " + newMode});
            
            // This is extremely fucking annoying, but chrome.extension.getViews() won't work
            // unless popup is opened, so we set the validation result like GET parameters.
            chrome.pageAction.setPopup({tabId: tabId, popup: "popup.html?" + domain + "," + newMode + "," + icon + "," + title + "," + domainpre});
        };

        function getResolver() {
            var resolver = "";
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
        };
        
	// Called when the url of a tab changes.
        function onUrlChange(tabId, changeInfo, tab) {
	    console.log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");         
            // reset any old popup
            chrome.pageAction.setPopup({tabId: tabId, popup: ""});

            // hide icon for chrome:// and chrome-extension:// urls
            if (tab.url.match(/^chrome(?:-extension)?:\/\//)) {
                chrome.pageAction.hide(tabId);
                return;
            }

            if (tab.url.match(/^chrome(?:-devtools)?:\/\//)) {
                chrome.pageAction.hide(tabId);
                return;
            }
	             
	   var resolver = this.getResolver();
            //Old regular expresion with port number 
            //var domain = tab.url.match(/^[\w-]+:\/*\[?([\w\.:-]+)\]?(?::\d+)?/)[1]; /**/
            var domain = tab.url.match(/^(?:[\w-]+:\/+)?\[?([\w\.-]+)\]?(?::)*(?::\d+)?/)[1]; /**/
       
       
       
    
                	   
    	    var currentURL = tab.url;
	        console.log("URL: " + currentURL + ";");	  
	    /*
      chrome.webRequest.onResponseStarted.addListener(
		  function(info) {
			currentIPList[ info.url ] = info.ip;
      console.log("IPs: " + currentURL + " -- " + info.ip + ";");                       		  
		  return;},{ urls: [], types: [] },  []
	    );
	   
     for (var i = 0, l = currentIPList.length; i < l; ++i) {
        console.log(currentIPList[i] + " ");
     }
    console.log(currentIPList.length);
        */
	    addr = currentIPList[ currentURL ]; 		
	    console.log("IP Browser: " + addr + ";");
	    var resolvipv4 = false; // No IPv4 resolving as default
	    var resolvipv6 = false; // No IPv6 resolving as default
	    if (addr == undefined) addr = "0.0.0.0";
	     // Check IP version
	      if (addr.indexOf(":") != -1) {
	        // ipv6
	        resolvipv6 = true;
	      } else if (addr.indexOf(".") != -1) {
	        // ipv4
	        resolvipv4 = true;
	      }
   
	    var options = 0;
	    var c = this.dnssecExtNPAPIConst;
            console.log("resolver: " + resolver);
	    if (true) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
	    if (resolver != "nofwd") options |= c.DNSSEC_INPUT_FLAG_USEFWD;
	    if (resolvipv4) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV4;
	    if (resolvipv6) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV6;

	   var icon = "";
	   icon = "icon_action.gif";
	   chrome.pageAction.setIcon({path: icon, tabId: tabId});
 	   chrome.pageAction.show(tabId);

	    console.log("INPUT: " + domain + "; Options; " + options  + "; Res: " + resolver  + "; IP: " + addr);
	    // Call of Validation function
      var plugin = document.getElementById("dnssec-plugin");	 	
	    var result = plugin.Validate(domain, options, resolver, addr);
            console.log("RESULT: " + domain + "; " + result[0]);
	
  	   icon = ""; 
	   var status = result[0]; 
     //status = 7;
       
     	switch (status) {
	    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP: 
		this.setMode(this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED, tabId, domain, status);
    		break;
	    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP: 
		this.setMode(this.dnssecModes.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED, tabId, domain, status);
	        break;
	    case c.DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID: 
		this.setMode(this.dnssecModes.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED, tabId, domain, status);
	        break;
	    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS:
	        this.setMode(this.dnssecModes.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID, tabId, domain, status);
	        break;
	    case c.DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID:
	        this.setMode(this.dnssecModes.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID, tabId, domain, status);
	        break;
	    case c.DNSSEC_EXIT_DOMAIN_UNSECURED:
	        this.setMode(this.dnssecModes.DNSSEC_MODE_DOMAIN_UNSECURED, tabId, domain, status);
                break;
	    case c.DNSSEC_EXIT_NODOMAIN_UNSECURED:
	        this.setMode(this.dnssecModes.DNSSEC_MODE_NODOMAIN_UNSECURED, tabId, domain, status);
	        break;
	    case c.DNSSEC_EXIT_FAILED:
	    default:
	        this.setMode(this.dnssecModes.DNSSEC_MODE_ERROR, tabId, domain, status);
                break;
	    }
        };

  function testdnssec() {
      var nameserver = this.getResolver();
      var c = this.dnssecExtNPAPIConst;
      var options = 0;
      var testnic = 0;
      var dn = "www.nic.cz";
      var addr = "217.31.205.50";
      options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
      if (nameserver != "nofwd") options |= c.DNSSEC_INPUT_FLAG_USEFWD;
      options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV4;
      var plugin = document.getElementById("dnssec-plugin");
      //dump('INIT parameters: \"'+ dn + '; ' + options + '; ' + nameserver + '; ' + addr + '\"\n');
      testnic = plugin.Validate(dn, options, nameserver, addr);
      if ((testnic==c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS) || (testnic==c.DNSSEC_EXIT_FAILED)) {
        //dnssecExtHandler.showDnssecFwdInfo();	 		
    }
  };


	if (init) {
		testdnssec();
		init = false;
    } 
        // Listen for any changes to the URL of any tab.
  chrome.tabs.onUpdated.addListener(onUrlChange);
        
  chrome.webRequest.onResponseStarted.addListener(function(info) {
			currentIPList[ info.url ] = info.ip;
      console.log("IPs: " + info.url + " -- " + info.ip + ";");                       		  
		  return;},{ urls: [], types: [] },  []
	    );
	                          
document.write("</script>");
document.write("</body>");
document.write("</html>");
