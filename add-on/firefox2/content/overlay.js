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


//Components.utils.import("resource://gre/modules/ctypes.jsm");
//Components.utils.import("resource://gre/modules/AddonManager.jsm"); 

window.addEventListener("load", function() { dnssecExtension.init(); }, false);
window.addEventListener("unload", function() { dnssecExtension.uninit(); }, false);


var dnssecExtUrlBarListener = {

  onLocationChange: function(aWebProgress, aRequest, aLocationURI)
  {
    //dump('Browser: onLocationChange()\n');
    var host = dnssecExtension.processNewURL(aLocationURI);
    //var tlsares = tlsaValidator.processNewURL(aRequest, aLocationURI);     	
  },

  onSecurityChange: function(aWebProgress, aRequest, aState)
  {
    //dump('Browser: onSecurityChange(): ' +aState + '\n');
    //var uri = null;
    //uri = window.gBrowser.currentURI;
    //var tlsares = tlsaValidator.processNewURL(aRequest, uri);
  },

  onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus)
  {
    //dump('Browser: onStateChange\n');
  },

  onProgressChange: function(aWebProgress, aRequest,
                             aCurSelfProgress, aMaxSelfProgress,
                             aCurTotalProgress, aMaxTotalProgress)
  {
    //dump('Browser: onProgressChange()\n');
  },
  onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage)
  {
    //dump('Browser: onStatusChange()\n');
  }
};

/* Observe preference changes */
var dnssecExtPrefObserver = {

  _branch: null,

  register: function() {
    var prefService = Components.classes["@mozilla.org/preferences-service;1"]
                      .getService(Components.interfaces.nsIPrefService);

    // Add the observer
    this._branch = prefService.getBranch(dnssecExtPrefs.prefBranch);
    this._branch.QueryInterface(Components.interfaces.nsIPrefBranch2);
    this._branch.addObserver("", this, false);
  },

  unregister: function() {
    if (!this._branch) return;
    this._branch.removeObserver("", this);
  },

  observe: function(aSubject, aTopic, aData) {    
    if (aTopic != "nsPref:changed") return;

    // aSubject is the nsIPrefBranch we're observing (after appropriate QI)
    // aData is the name of the pref that's been changed (relative to aSubject)
    switch (aData) {
    case "debugoutput":     // Change debugging to stdout
      dnssecExtension.getDebugOutputFlag();
      break;
    case "asyncresolve":    // Change sync/async resolving
      dnssecExtension.getAsyncResolveFlag();
      break;
    case "popupfgcolor":   // Change popup-window fore/background color
    case "popupbgcolor":
      dnssecExtension.getPopupColors();
      break;
    }
  }
};

// **************************************************************
// --------------------------------------------------------------
/* dnssecExtension */
// --------------------------------------------------------------
// **************************************************************
var dnssecExtension = {
  dnssecExtID: "dnssec@nic.cz",
  debugOutput: false,
  debugPrefix: "dnssec: ",
  debugStartNotice: "----- DNSSEC resolving start -----\n",
  debugEndNotice: "----- DNSSEC resolving end -----\n",
  asyncResolve: false,
  timer: null,
  oldAsciiHost: null,
  //oldAsciiHost2: null,

  init: function() {

    // Enable debugging information on stdout if desired
    this.getDebugOutputFlag();

    if (this.debugOutput)
      dump(this.debugPrefix + 'Start of add-on init\n');

    // Enable asynchronous resolving if desired
    this.getAsyncResolveFlag();

    // Set inaction mode (no icon)
    dnssecExtHandler.setMode(dnssecExtHandler.DNSSEC_MODE_INACTION);

    // Change popup-window fore/background color if desired
    this.getPopupColors();

    // Register preferences observer
    dnssecExtPrefObserver.register();
    //httpRequestObserver.register();
    //this.inittest();
     
    //this.registerObserver("http-on-examine-response");
   //this.registerObserver("http-on-modify-request");
   //this.registerObserver("http-on-examine-cached-response");
    // Create the timer
    this.timer = Components.classes["@mozilla.org/timer;1"]
                 .createInstance(Components.interfaces.nsITimer);

    // Get DNSSEC Validator extension object
    if (Application.extensions) {   // Firefox < 3.7, sync
      var dnssecExt = Application.extensions.get(this.dnssecExtID);
      this.showHomepage(dnssecExt);
    } else {   // Firefox >= 3.7, async
      Application.getExtensions(function(extensions) {
        var dnssecExt = extensions.get(dnssecExtension.dnssecExtID);
        dnssecExtension.showHomepage(dnssecExt);
      });
    }

    // Listen for webpage events
    gBrowser.addProgressListener(dnssecExtUrlBarListener);
    //gBrowser.addTabsProgressListener(dnssecExtUrlBarListener2);
    //gBrowser.addEventListener("load", examplePageLoad, true);

    if (this.debugOutput)
      dump(this.debugPrefix + 'End of add-on init\n');
  },

  showHomepage: function(dnssecExt) {
    // Get saved extension version
    var dnssecExtOldVersion = dnssecExtPrefs.getChar("version");

    // Display initialisation page if appropriate
    if (dnssecExt.version != dnssecExtOldVersion) {
      dnssecExtPrefs.setChar("version", dnssecExt.version);  // Save new version
      dnssecExtPrefs.setChar("dnsserveraddr", "nofwd");  // Save default settings of resolver
      dnssecExtPrefs.setBool("usefwd", true);  // Save default settings of resolver
      dnssecExtPrefs.setInt("dnsserverchoose", 3);  // Save default settings of resolver
      // Define timer callback
      this.timer.initWithCallback(
        function() {
          if (gBrowser) {
            gBrowser.selectedTab = gBrowser.addTab('http://www.dnssec-validator.cz');
          }
        },
        100,
        Components.interfaces.nsITimer.TYPE_ONE_SHOT);
    }
  },

  getDebugOutputFlag: function() {
    this.debugOutput = dnssecExtPrefs.getBool("debugoutput");
  },

  getAsyncResolveFlag: function() {
    this.asyncResolve = dnssecExtPrefs.getBool("asyncresolve");
  },

  getPopupColors: function() {
    var dpw = document.getElementById("dnssec-popup-container");
    dpw.style.color = dnssecExtPrefs.getChar("popupfgcolor");
    dpw.style.backgroundColor = dnssecExtPrefs.getChar("popupbgcolor");
  },

  uninit: function() {

    if (this.debugOutput)
      dump(this.debugPrefix + 'Start of add-on uninit\n');

    gBrowser.removeProgressListener(dnssecExtUrlBarListener);
    //gBrowser.removeTabsProgressListener(dnssecExtUrlBarListener2);
//gBrowser.removeEventListener("load", examplePageLoad, true);


    // Unregister preferences observer
    dnssecExtPrefObserver.unregister();

    //this.unregisterObserver("http-on-modify-request");
 //this.unregisterObserver("http-on-examine-response");
 //this.unregisterObserver("http-on-examine-cached-response");
    //httpRequestObserver.unregister();
    // Reset resolving flag
    dnssecExtPrefs.setBool("resolvingactive", false);

    //validator.shutdown();
    var dsp = document.getElementById("dnssec-plugin");
    dsp.CacheFree();
    if (this.debugOutput) 
	dump('...Clear Cache...\n');

    if (this.debugOutput)
      dump(this.debugPrefix + 'End of add-on uninit\n');
  },

    registerObserver: function(topic) {
	var observerService = Components.classes["@mozilla.org/observer-service;1"]
	  .getService(Components.interfaces.nsIObserverService);
	observerService.addObserver(this, topic, false);
    },

    unregisterObserver: function(topic) {
	var observerService = Components.classes["@mozilla.org/observer-service;1"]
	  .getService(Components.interfaces.nsIObserverService);
	observerService.removeObserver(this, topic);
    },
/*
    observe: function(channel, topic, data) {



     if (topic == "http-on-examine-response") {
	
	var Cc = Components.classes, Ci = Components.interfaces;
	channel.QueryInterface(Ci.nsIHttpChannel);
	var host = channel.URI.hostPort;
	var url = channel.URI.spec;
	var currentURL = gBrowser.currentURI.hostPort;
	dump('---observe: function('+url+', '+topic+', '+host+', '+data+')\n');
	

	var si = channel.securityInfo;
	if (!si) return;
	
	var nc = channel.notificationCallbacks;
	if (!nc && channel.loadGroup)
	  nc = channel.loadGroup.notificationCallbacks;
	if (!nc) return;

	try {
	    var win = nc.getInterface(Ci.nsIDOMWindow);
	} catch (e) {
	    return; // no window for e.g. favicons
	}
	if (!win.document) return;

	var browser;
	// thunderbird has no gBrowser
	if (typeof gBrowser != "undefined") {
	    browser = gBrowser.getBrowserForDocument(win.top.document);
	    // We get notifications for a request in all of the open windows
	    // but browser is set only in the window the request is originated from,
	    // browser is null for favicons too.
	    if (!browser) return;
	}

	dump('---'+this.oldAsciiHost2+'-----'+host+'-----\n');
 	if (this.oldAsciiHost2 != host) {
		this.oldAsciiHost2 = host;
	   	si.QueryInterface(Ci.nsISSLStatusProvider);
		var st = si.SSLStatus;
		if (!st) return;
		dump('---'+currentURL+'-----'+host+'-----\n');
		//if (host == currentURL) {
			st.QueryInterface(Ci.nsISSLStatus);
			var cert = st.serverCert;
			if (!cert) return;
		var tlsares = tlsaValidator.check_tlsa2(channel, cert, browser, host, "443");
		////this.certCheck(browser, cert, channel);
		//}
	}
	dump('---observe: end\n');
      }
    },

*/





  processNewURL: function(aLocationURI) {
    var scheme = null;
    var asciiHost = null;
    var utf8Host = null;
    
    try {
      scheme = aLocationURI.scheme;             // Get URI scheme
      asciiHost = aLocationURI.asciiHost;       // Get punycoded hostname
      utf8Host = aLocationURI.host;             // Get UTF-8 encoded hostname
    } catch(ex) {
//      dump(ex + '\n');
    }

    if (this.debugOutput)
      dump(this.debugPrefix + 'Scheme: "' + scheme + '"; ' +
           'ASCII domain name: "' + asciiHost + '"');

    if (scheme == 'chrome' ||                   // Eliminate chrome scheme
        asciiHost == null ||
        asciiHost == '' ||                      // Empty string
        asciiHost.indexOf("\\") != -1 ||        // Eliminate addr containing '\'
        asciiHost.indexOf(":") != -1 ||         // Eliminate IPv6 addr notation
        asciiHost.search(/[A-Za-z]/) == -1) {   // Eliminate IPv4 addr notation

      if (this.debugOutput) dump(' ...invalid\n');
      this.oldAsciiHost = null;
      // Set inaction mode (no icon)
      dnssecExtHandler.setMode(dnssecExtHandler.DNSSEC_MODE_INACTION);
      //tlsaExtHandler.setMode(tlsaExtHandler.DANE_MODE_INACTION);
      return;

    // Eliminate duplicated queries
    } else if (asciiHost == this.oldAsciiHost) {
      if (this.debugOutput) dump(' ...duplicated\n');
      return;
    }

  
    if (this.debugOutput) dump(' ...valid\n');

    // Check DNS security
    dnssecExtHandler.checkSecurity(asciiHost, utf8Host);
    return asciiHost;
  },
};//class

// **************************************************************
// --------------------------------------------------------------
/* Get security status through NPAPI plugin call */
// --------------------------------------------------------------
// **************************************************************
var dnssecExtResolver = {

  //******************************************
  // Called when request is not cached already
  //*******************************************
  doNPAPIvalidation: function(dn, resolvipv4, resolvipv6, aRecord) {

    // Plugin callback
    function NPAPIcallback(plug, resArr) {
      dnssecExtResolver.setValidatedData(dn, resArr, aRecord, addr);
    }

    // Get DNS resolver address(es)
    var nameserver = dnssecExtPrefs.getChar("dnsserveraddr");

    // Create variable to pass options
    var c = dnssecExtNPAPIConst;
    var options = 0;
    if (dnssecExtension.debugOutput) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
    if (dnssecExtPrefs.getInt("dnsserverchoose") != 3) options |= c.DNSSEC_INPUT_FLAG_USEFWD;
    if (resolvipv4) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV4;
    if (resolvipv6) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV6;

        // Check browser's IP address(es)
    var addr = null;
    var invipaddr = false; // Browser's IP addresses are presumed as valid
    if (aRecord) {
      aRecord.rewind();
      if (aRecord.hasMore()) {   // Address list has another item
        addr = aRecord.getNextAddrAsString();
        if (dnssecExtension.debugOutput) dump(dnssecExtension.debugPrefix + 'Checking browser IP: '
               + addr + ';\n');
      }

    }
    if (addr == null) addr = "0.0.0.0";
    
    /*ipbrowser = addr;*/
    if (dnssecExtension.debugOutput)
      dump(dnssecExtension.debugPrefix + 'Validation parameters: \"'
           + dn + '; ' + options + '; ' + nameserver + '; ' + addr + '\"\n');
	
    // Call NPAPI validation
    try {
      // Get the binary plugin
      var dsp = document.getElementById("dnssec-plugin");

      if (!dnssecExtension.asyncResolve) {   // Synchronous NPAPI validation
        NPAPIcallback(null, dsp.Validate(dn, options, nameserver, addr));
      } else {   // Asynchronous NPAPI validation
        dsp.ValidateAsync(dn, options, nameserver, addr, NPAPIcallback);
      }
    } catch (ex) {
      dump(dnssecExtension.debugPrefix + 'Error: Plugin call failed!\n');

      // Set error mode
      dnssecExtHandler.setMode(dnssecExtHandler.DNSSEC_MODE_ERROR);

      // Reset resolving flag
      dnssecExtPrefs.setBool("resolvingactive", false);

      return;
    }
  },

  //*****************************************************
  // Called when unbound return bogus, validation without resolver
  //*****************************************************
  revalidate: function(dn, addr, res) {

    // Plugin callback
    function NPAPIcallback(plug, resArr) {

      dnssecExtResolver.ValidatedDataNoFwd(dn, resArr, res, addr);

    }
	var c = dnssecExtNPAPIConst;
	var resolvipv4 = true;
        var resolvipv6 = false;
	var dsp = document.getElementById("dnssec-plugin");
	dsp.CacheFree();
	options = 0;
	if (false) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
   	if (resolvipv4) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV6;
	 if (dnssecExtension.debugOutput)
          dump(dnssecExtension.debugPrefix + "NOFWD input: " + dn + "; options: " + options  + "; resolver: nofwd; IP-br: " + addr + ';\n');

   // Call NPAPI validation
    try {
      if (!dnssecExtension.asyncResolve) {   // Synchronous NPAPI validation
        NPAPIcallback(null, dsp.Validate(dn, options, "nofwd", addr));
      } else {   // Asynchronous NPAPI validation
        dsp.ValidateAsync(dn, options, "nofwd", addr, NPAPIcallback);
      }
    } catch (ex) {
      dump(dnssecExtension.debugPrefix + 'Error: Plugin call failed!\n');

      // Set error mode
      dnssecExtHandler.setMode(dnssecExtHandler.DNSSEC_MODE_ERROR);

      // Reset resolving flag
      dnssecExtPrefs.setBool("resolvingactive", false);

      return;
    }
  },


  //*****************************************************
  // Set appropriate security state for without resolver
  //*****************************************************
  ValidatedDataNoFwd: function(dn, resArr, res, addr) {

     var ext = dnssecExtension;
     var c = dnssecExtNPAPIConst;
     var d = tlsaExtNPAPIConst;
    if (ext.debugOutput) {
       dump(ext.debugPrefix + 'NOFWD result: ' + resArr[0] + '; ' + resArr[1] +' ;\n');
    }	    	
    
    var restmp = resArr[0];
    var ipvalidator = resArr[1];
    
    var tlsa = d.DANE_EXIT_VALIDATION_OFF;	

    if (restmp==c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS) {
	if (ext.debugOutput) dump(ext.debugPrefix + 'Yes, domain name has bogus\n');
	res=restmp;
	tlsa = d.DANE_EXIT_DNSSEC_BOGUS
    } 
    else
    {
	if (ext.debugOutput) dump(ext.debugPrefix + "Current resolver does not support DNSSEC!\n");
	if (ext.debugOutput) dump(ext.debugPrefix + "Results: FWD: " + res + "; NOFWD: " + restmp +"\n");
	var dsp = document.getElementById("dnssec-plugin");
	dsp.CacheFree();
	//dnssecExtHandler.showDnssecFwdInfo();
    // tlsa	
 /*   if (restmp==c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP || restmp==c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP) {
	var uri = gBrowser.currentURI;
	var port = "443";
	//dump(ext.debugPrefix + uri.asciiHost + '\n');
        if (uri.schemeIs("https")) { 
		if (ext.debugOutput) dump(ext.debugPrefix + 'Connection is https...\n');
		//tlsa = tlsaValidator.check_tlsa(uri,port);
	}
	else { if (ext.debugOutput) dump(ext.debugPrefix + 'Connection is NOT https...\n');
	     tlsa = d.DANE_EXIT_NO_HTTPS;
        }
	dump("DANE: Return >>> " + tlsa + '\n');
    }	

*/
	res=restmp;	
    }//if
		
    // Set appropriate state if host name does not changed
    // during resolving process (tab has not been switched)
    if (dn == gBrowser.currentURI.asciiHost)
	//tlsaExtHandler.setSecurityState(tlsa); 
      dnssecExtHandler.setSecurityState(res,addr,ipvalidator);

    if (ext.debugOutput)
      dump(ext.debugPrefix + ext.debugEndNotice);

    // Resolving has finished
    if (ext.debugOutput) {
      dump(ext.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');
      dump(ext.debugPrefix + 'Unlocking section...\n');
    }
    dnssecExtPrefs.setBool("resolvingactive", false);
    if (ext.debugOutput)
      dump(ext.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');
  },

  //*****************************************************
  // Set appropriate security state
  //*****************************************************
  setValidatedData: function(dn, resArr, aRecord, addr) {

    var ext = dnssecExtension;

    if (ext.debugOutput) {
      dump(ext.debugPrefix + 'Queried domain name: ' + dn + '\n');
      dump(ext.debugPrefix + 'Getting return values: ' + resArr[0] + ';\n');
    }

    // Get validated data from cache or by NPAPI call
    var res = -1;
   
    res = resArr[0];
    var ipvalidator = resArr[1];

    var c = dnssecExtNPAPIConst;
    var d = tlsaExtNPAPIConst;
    if (res==c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS) {
      	if (ext.debugOutput) dump(ext.debugPrefix + "Unbound return bogus state: Testing why?\n");
	this.revalidate(dn,addr,res);
	return;
    }// if
/*
    var tlsa = d.DANE_EXIT_VALIDATION_OFF;	
    // tlsa	
    if (res==c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP || res==c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP) {
	var uri = gBrowser.currentURI;
	var port = "443";
	//dump(ext.debugPrefix + uri.asciiHost + '\n');
        if (uri.schemeIs("https")) { 
		if (ext.debugOutput) dump(ext.debugPrefix + 'Connection is https...\n');
		//tlsa = tlsaValidator.check_tlsa(uri,port);
	}
	else { if (ext.debugOutput) dump(ext.debugPrefix + 'Connection is NOT https...\n');
	     tlsa = d.DANE_EXIT_NO_HTTPS;
        }
	dump("DANE: Return >>> " + tlsa + '\n');   
    }

*/

    // Set appropriate state if host name does not changed
    // during resolving process (tab has not been switched)
    if (dn == gBrowser.currentURI.asciiHost){
 	 //tlsaExtHandler.setSecurityState(tlsa);    
	 dnssecExtHandler.setSecurityState(res, addr, ipvalidator);
    }

    if (ext.debugOutput)
      dump(ext.debugPrefix + ext.debugEndNotice);

    // Resolving has finished
    if (ext.debugOutput) {
      dump(ext.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');
      dump(ext.debugPrefix + 'Unlocking section...\n');
    }
    dnssecExtPrefs.setBool("resolvingactive", false);
    if (ext.debugOutput)
      dump(ext.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');
  },

  //*****************************************************
  // Called when browser async host lookup completes
  //*****************************************************
  onBrowserLookupComplete: function(dn, aRecord) {

    var filteron = dnssecExtPrefs.getBool("domainfilteron");
    var validate = true;
    if (filteron) {
	var urldomainsepar=/[.]+/;
	var urldomainarray=dn.split(urldomainsepar);
	var domainlist = dnssecExtPrefs.getChar("domainlist");
	var domainlistsepar=/[ ,;]+/;
	var domainarraylist=domainlist.split(domainlistsepar);

	// TLD
        for (j=0;j<domainarraylist.length;j++) { 
            if (urldomainarray[urldomainarray.length-1] == domainarraylist[j]) {validate=false; break;}

        }
	// xxx.yy
 	if (validate) for (j=0;j<domainarraylist.length;j++) {
	   if (domainarraylist[j].indexOf(urldomainarray[urldomainarray.length-2]) !=-1) {validate=false; break}
            }
        if (dnssecExtension.debugOutput) dump(dnssecExtension.debugPrefix + 'Validate this domain? ' + validate + ';\n');
    }//if

    if (validate) {

    	var resolvipv4 = false; // No IPv4 resolving as default
    	var resolvipv6 = false; // No IPv6 resolving as default
    	var addr = null;

    	if (dnssecExtension.debugOutput)
    	  dump(dnssecExtension.debugPrefix + dnssecExtension.debugStartNotice);

    	if (aRecord && aRecord.hasMore()) {   // Address list is not empty
	      addr = aRecord.getNextAddrAsString();
	      // Check IP version
	      if (addr.indexOf(":") != -1) {
	        // ipv6
        	resolvipv6 = true;
	      } else if (addr.indexOf(".") != -1) {
	        // ipv4
	        resolvipv4 = true;
	      }
	      // No need to check more addresses
	      //if (resolvipv4 && resolvipv6) break;
	 }

	 if (dnssecExtension.debugOutput)
	      dump(dnssecExtension.debugPrefix + 'Browser uses IPv4/IPv6 resolving: \"'
        	   + resolvipv4 + '/' + resolvipv6 + '\"\n');

         // Resolve IPv4 if no version is desired
         if (!resolvipv4 && !resolvipv6) resolvipv4 = true;
	 // Call NPAPI plugin core
	 this.doNPAPIvalidation(dn, resolvipv4, resolvipv6, aRecord);
     }
     else {
     // no DNSSEC validation resolve
        dnssecExtHandler.setSecurityState(-1);
        // Reset resolving flag
        if (dnssecExtension.debugOutput) {
          dump(dnssecExtension.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');
          dump(dnssecExtension.debugPrefix + 'Unlocking section...\n');
        }
        dnssecExtPrefs.setBool("resolvingactive", false);
        if (dnssecExtension.debugOutput)
            dump(dnssecExtension.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');
     }//if
  },//function
};//class


//*****************************************************************************
//*****************************************************************************
/* Utility class to handle manipulations of the dnssec indicators in the UI */
//*****************************************************************************
//*****************************************************************************
var dnssecExtHandler = {

  // Mode strings used to control CSS display

  // 1. No DNSSEC signature
  DNSSEC_MODE_DOMAIN_UNSECURED                    : "unsecuredDomain",
  // 2. Domain and also connection are secured
  DNSSEC_MODE_CONNECTION_DOMAIN_SECURED           : "securedConnectionDomain",
  // 3. Domain and also connection are secured but browser's IP address is invalid
  DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED : "securedConnectionDomainInvIPaddr",
  // 4. Domain is secured, but it has an invalid signature
  DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID            : "invalidDomainSignature",
  // 5. No NSEC/NSEC3 for non-existent domain name
  DNSSEC_MODE_NODOMAIN_UNSECURED                  : "unsecuredNoDomain",
  // 6. Connection is secured, but domain name does not exist
  DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID         : "securedConnectionNoDomain",
  // 7. Non-existent domain is secured, but it has an invalid signature
  DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID          : "invalidNoDomainSignature",
  // Getting security status
  DNSSEC_MODE_ACTION : "actionDnssec",
  // Inaction status
  DNSSEC_MODE_INACTION : "inactionDnssec",
  // Error or unknown state occured
  DNSSEC_MODE_ERROR : "errorDnssec",
  DNSSEC_MODE_OFF   : "dnssecOff",
  // Tooltips
  DNSSEC_TOOLTIP_SECURED   : "securedTooltip",
  DNSSEC_TOOLTIP_UNSECURED : "unsecuredTooltip",
  DNSSEC_TOOLTIP_ACTION    : "actionTooltip",
  DNSSEC_TOOLTIP_ERROR     : "errorTooltip",
  DNSSEC_TOOLTIP_BOGUS     : "bogusTooltip",
  DNSSEC_TOOLTIP_OFF       : "offTooltip",
  // Cache the most recent hostname seen in checkSecurity
  _asciiHostName : null,
  _utf8HostName : null,

  ipvalidator : "",
  ipbrowser : "",
  valstate : 0,




  get _domainPreText () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._domainPreText;
    this._domainPreText = {};

	// 0. DNSSEC error
    this._domainPreText[this.DNSSEC_MODE_ERROR] =
      this._stringBundle.getString("domain");
	// 1. No DNSSEC signature    
    this._domainPreText[this.DNSSEC_MODE_DOMAIN_UNSECURED] =
      this._stringBundle.getString("domain");
	// 2. Domain and also connection are secured
    this._domainPreText[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] =
      this._stringBundle.getString("domain");
  	// 3. Domain and also connection are secured but browser's IP address is invalid
    this._domainPreText[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] =
      this._stringBundle.getString("domain");
	// 4. Domain is secured, but it has an invalid signature
    this._domainPreText[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("domain");
  	// 5. No NSEC/NSEC3 for non-existent domain name
    this._domainPreText[this.DNSSEC_MODE_NODOMAIN_UNSECURED] =
      this._stringBundle.getString("nodomain");
  	// 6. Connection is secured, but domain name does not exist
    this._domainPreText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("nodomain");
  	// 7. Non-existent domain is secured, but it has an invalid signature
    this._domainPreText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("nodomain");
  	// -1. Validator OFF
    this._domainPreText[this.DNSSEC_MODE_OFF] =
      this._stringBundle.getString("domain");

    return this._domainPreText;
  },

  // Smart getters
  get _securityText () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._securityText;
    this._securityText = {};

	// 0. DNSSEC error
    this._securityText[this.DNSSEC_MODE_ERROR] =
      this._stringBundle.getString("0dnssecError");
	// 1. No DNSSEC signature    
    this._securityText[this.DNSSEC_MODE_DOMAIN_UNSECURED] =
      this._stringBundle.getString("1unsecuredDomain");
	// 2. Domain and also connection are secured
    this._securityText[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] =
      this._stringBundle.getString("2securedConnectionDomain");
  	// 3. Domain and also connection are secured but browser's IP address is invalid
    this._securityText[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] =
      this._stringBundle.getString("3securedConnectionDomainInvIPaddr");
	// 4. Domain is secured, but it has an invalid signature
    this._securityText[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("4invalidDomainSignature");
  	// 5. No NSEC/NSEC3 for non-existent domain name
    this._securityText[this.DNSSEC_MODE_NODOMAIN_UNSECURED] =
      this._stringBundle.getString("5unsecuredNoDomain");
  	// 6. Connection is secured, but domain name does not exist
    this._securityText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("6securedConnectionNoDomain");
  	// 7. Non-existent domain is secured, but it has an invalid signature
    this._securityText[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("7invalidNoDomainSignature");
  	// -1. Validator OFF
    this._securityText[this.DNSSEC_MODE_OFF] =
      this._stringBundle.getString("dnsseOff");

    return this._securityText;
  },

  get _securityDetail () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._securityDetail;
    this._securityDetail = {};

	// 0. DNSSEC error
    this._securityDetail[this.DNSSEC_MODE_ERROR] =
      this._stringBundle.getString("0dnssecErrorInfo");
	// 1. No DNSSEC signature    
    this._securityDetail[this.DNSSEC_MODE_DOMAIN_UNSECURED] =
      this._stringBundle.getString("1unsecuredDomainInfo");
	// 2. Domain and also connection are secured
    this._securityDetail[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] =
      this._stringBundle.getString("2securedConnectionDomainInfo");
  	// 3. Domain and also connection are secured but browser's IP address is invalid
    this._securityDetail[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] =
      this._stringBundle.getString("3securedConnectionDomainInvIPaddrInfo");
	// 4. Domain is secured, but it has an invalid signature
    this._securityDetail[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("4invalidDomainSignatureInfo");
  	// 5. No NSEC/NSEC3 for non-existent domain name
    this._securityDetail[this.DNSSEC_MODE_NODOMAIN_UNSECURED] =
      this._stringBundle.getString("5unsecuredNoDomainInfo");
  	// 6. Connection is secured, but domain name does not exist
    this._securityDetail[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("6securedConnectionNoDomainInfo");
  	// 7. Non-existent domain is secured, but it has an invalid signature
    this._securityDetail[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("7invalidNoDomainSignatureInfo");
  	// -1. Validator OFF
    this._securityDetail[this.DNSSEC_MODE_OFF] =
      this._stringBundle.getString("dnsseOffInfo");
    return this._securityDetail;
  },

  get _tooltipLabel () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._tooltipLabel;
    this._tooltipLabel = {};

    this._tooltipLabel[this.DNSSEC_TOOLTIP_SECURED] =
      this._stringBundle.getString("dnssec.tooltip.secured");
    this._tooltipLabel[this.DNSSEC_TOOLTIP_UNSECURED] =
      this._stringBundle.getString("dnssec.tooltip.unsecured");
    this._tooltipLabel[this.DNSSEC_TOOLTIP_ACTION] =
      this._stringBundle.getString("dnssec.tooltip.action");
    this._tooltipLabel[this.DNSSEC_TOOLTIP_ERROR] =
      this._stringBundle.getString("dnssec.tooltip.error");
    this._tooltipLabel[this.DNSSEC_TOOLTIP_BOGUS] =
      this._stringBundle.getString("dnssec.tooltip.bogus");
    this._tooltipLabel[this.DNSSEC_TOOLTIP_OFF] =
      this._stringBundle.getString("dnssec.tooltip.off");
    return this._tooltipLabel;
  },
  get _dnssecPopup () {
    delete this._dnssecPopup;
    return this._dnssecPopup = document.getElementById("dnssec-popup");
  },
  get _dnssecPopupfwd () {
    delete this._dnssecPopupfwd;
    return this._dnssecPopupfwd = document.getElementById("dnssec-popup-fwd");
  },
  get _dnssecBox () {
    delete this._dnssecBox;
    return this._dnssecBox = document.getElementById("dnssec-box");
  },
 // get _tlsaBox () {
  //  delete this._tlsaBox;
  //  return this._tlsaBox = document.getElementById("tlsa-box");
  //},
  get _dnssecPopupContentBox () {
    delete this._dnssecPopupContentBox;
    return this._dnssecPopupContentBox =
      document.getElementById("dnssec-popup-content-box");
  },
  get _dnssecPopupContentBox2 () {
    delete this._dnssecPopupContentBox2;
    return this._dnssecPopupContentBox2 =
      document.getElementById("dnssec-popup-content-box2");
  },
  get _dnssecPopupContentBox3 () {
    delete this._dnssecPopupContentBox3;
    return this._dnssecPopupContentBox3 =
      document.getElementById("dnssec-popup-content-box3");
  },
  get _dnssecPopupContentBox4 () {
    delete this._dnssecPopupContentBox4;
    return this._dnssecPopupContentBox4 =
      document.getElementById("dnssec-popup-content-box4");
  },
  get _dnssecPopupContentHost () {
    delete this._dnssecPopupContentHost;
    return this._dnssecPopupContentHost =
      document.getElementById("dnssec-popup-content-host");
  },
  get _dnssecPopupSecLabel () {
    delete this._dnssecPopupSecLabel;
    return this._dnssecPopupSecLabel =
      document.getElementById("dnssec-popup-security-text");
  },
  get _dnssecPopupSecDetail () {
    delete this._dnssecPopupSecDetail;
    return this._dnssecPopupSecDetail =
      document.getElementById("dnssec-popup-security-detail");
  },
  get _dnssecPopupfwdDetail () {
    delete this._dnssecPopupfwdDetail;
    return this._dnssecPopupfwdDetail =
      document.getElementById("dnssec-popup-fwd-text");
  },
  get _dnssecPopupIpBrowser () {
    delete this._dnssecPopupIpBrowser;
    return this._dnssecPopupIpBrowser =
      document.getElementById("dnssec-popup-ipbrowser-ip");
  },
  get _dnssecPopupIpValidator () {
    delete this._dnssecPopupIpValidator;
    return this._dnssecPopupIpValidator =
      document.getElementById("dnssec-popup-ipvalidator-ip");
  },
  // Build out a cache of the elements that we need frequently
  _cacheElements : function() {
    delete this._dnssecBox;
    this._dnssecBox = document.getElementById("dnssec-box");
    //delete this._tlsaBox;
    //this._tlsaBox = document.getElementById("tlsa-box");
  },

  // Set appropriate security state
  setSecurityState : function(state,addr,ipvalidator) {
     this.ipvalidator = ipvalidator;
     this.ipbrowser = addr;
     this.valstate = state;

    var c = dnssecExtNPAPIConst;
    
     if (dnssecExtension.debugOutput)
      dump(dnssecExtension.debugPrefix + 'State: \"'
           + state + '\"\n');

    switch (state) {
	// 1
    case c.DNSSEC_EXIT_DOMAIN_UNSECURED:
      this.setMode(this.DNSSEC_MODE_DOMAIN_UNSECURED);
      break;
	// 2
    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP: 
	this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED);
    	break;
	// 3
    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP: 
	this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED);
        break;
	// 4
    case c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS:
        this.setMode(this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID);
      break;
	// 5
    case c.DNSSEC_EXIT_NODOMAIN_UNSECURED:
      this.setMode(this.DNSSEC_MODE_NODOMAIN_UNSECURED);
      break;
	// 6	
    case c.DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID: 
	this.setMode(this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID);
      break;
	// 7
    case c.DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID:
      this.setMode(this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID);
      break;
	// -1
    case -1:
      this.setMode(this.DNSSEC_MODE_OFF);
      break;
	// 0
    case c.DNSSEC_EXIT_FAILED:
    default:
      this.setMode(this.DNSSEC_MODE_ERROR);
      break;
    }
  },

  // Determine the security of the domain and connection and, if necessary,
  // update the UI to reflect this. Intended to be called by onLocationChange.
  checkSecurity : function(asciiHost, utf8Host) {

    // Set action state
    this.setMode(this.DNSSEC_MODE_ACTION);
    //tlsaExtHandler.setMode(tlsaExtHandler.DANE_MODE_ACTION);
    // Detect if any resolving is already running...
    if (dnssecExtPrefs.getBool("resolvingactive")) {

      // Set inaction mode (no icon)
//      dnssecExtHandler.setMode(dnssecExtHandler.DNSSEC_MODE_INACTION);

      if (dnssecExtension.debugOutput)
        dump(dnssecExtension.debugPrefix + 'Activating resolving timer\n');

      // Cancel running timer if any
      dnssecExtension.timer.cancel();

      // Define timer callback
      dnssecExtension.timer.initWithCallback(
        function() {
          if (dnssecExtension.debugOutput)
            dump(dnssecExtension.debugPrefix + 'Starting timer action\n');
          dnssecExtension.processNewURL(gBrowser.currentURI);
        },
        500,
        Components.interfaces.nsITimer.TYPE_ONE_SHOT);

      // Do not continue to the critical section
      return;
    }

    // ...and lock the critical section - this should be atomic in FF
    if (dnssecExtension.debugOutput) {
      dump(dnssecExtension.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');
      dump(dnssecExtension.debugPrefix + 'Locking section...\n');
    }
    dnssecExtPrefs.setBool("resolvingactive", true);
    if (dnssecExtension.debugOutput)
      dump(dnssecExtension.debugPrefix + 'Lock is: ' + dnssecExtPrefs.getBool("resolvingactive") + '\n');

    // Set action state
//    this.setMode(this.DNSSEC_MODE_ACTION);

    // Remember last host name to eliminate duplicated queries
    dnssecExtension.oldAsciiHost = asciiHost;

    this._asciiHostName = asciiHost;
    this._utf8HostName = utf8Host;

    var dnsService = Components.classes["@mozilla.org/network/dns-service;1"]
                     .getService(Components.interfaces.nsIDNSService);


    var dnsListener = {

      // Called when async host lookup completes
      onLookupComplete: function(aRequest, aRecord, aStatus) {

        // Check hostname security state
        dnssecExtResolver.onBrowserLookupComplete(dnssecExtHandler._asciiHostName, aRecord);

      }
    };

    // Thread on which onLookupComplete should be called after lookup
    var th = Components.classes["@mozilla.org/thread-manager;1"]
             .getService(Components.interfaces.nsIThreadManager)
             .mainThread;

    // Get browser's IP address(es) that uses to connect to the remote site.
    // Uses browser's internal resolver cache
    try {
      dnsService.asyncResolve(asciiHost, 0, dnsListener, th); // Ci.nsIDNSService.RESOLVE_BYPASS_CACHE
    } catch(ex) {
      dump(dnssecExtension.debugPrefix + 'Error: Browser\'s async DNS lookup failed!\n');

      // Set error mode
      dnssecExtHandler.setMode(dnssecExtHandler.DNSSEC_MODE_ERROR);

      // Reset resolving flag
      dnssecExtPrefs.setBool("resolvingactive", false);

      return;
    }

  },

  /**
   * Update the UI to reflect the specified mode, which should be one of the
   * DNSSEC_MODE_* constants.
   */
  setMode : function(newMode) {
    if (!this._dnssecBox) {
      // No DNSSEC box means the DNSSEC box is not visible, in which
      // case there's nothing to do.
      return;
    } 
    else if (newMode == this.DNSSEC_MODE_ACTION) {  // Close window for these states
      this.hideDnssecPopup();
    }

    this._dnssecBox.className = newMode;
    this.setSecurityMessages(newMode);

    // Update the popup too, if it's open
    if (this._dnssecPopup.state == "open")
      this.setPopupMessages(newMode);
  },

  /**
   * Set up the messages for the primary security UI based on the specified mode,
   *
   * @param newMode The newly set security mode. Should be one of the DNSSEC_MODE_* constants.
   */
  setSecurityMessages : function(newMode) {

    var tooltip;

    switch (newMode) {
    // Both domain and connection are secured
    case this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED:
    // Domain and also connection are secured but browser's IP address is invalid
    case this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED:
    // Both non-existent domain and connection are secured
    case this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_SECURED];
      break;
    // Domain signature is valid
    case this.DNSSEC_MODE_DOMAIN_UNSECURED:
    case this.DNSSEC_MODE_NODOMAIN_UNSECURED:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_UNSECURED];
      break;
    case this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID:
    case this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_BOGUS];
      break;
    // Getting security status
    case this.DNSSEC_MODE_ACTION:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_ACTION];
      break;
    // An error occured
    case this.DNSSEC_MODE_ERROR:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_ERROR];
      break;
    case this.DNSSEC_MODE_OFF:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_OFF];
      break;
    // Unknown
    default:
      tooltip = "";
    }

    // Push the appropriate strings out to the UI
    this._dnssecBox.tooltipText = tooltip;
  },

  showAddInfoIP : function() {
		document.getElementById("dnssec-popup-ipbrowser-title").style.display = 'block';
		document.getElementById("dnssec-popup-ipbrowser-ip").style.display = 'block';
		document.getElementById("dnssec-popup-ipvalidator-title").style.display = 'block';
		document.getElementById("dnssec-popup-ipvalidator-ip").style.display = 'block';
  },

  hideAddInfoIP : function() {
		document.getElementById("dnssec-popup-ipbrowser-title").style.display = 'none';
		document.getElementById("dnssec-popup-ipbrowser-ip").style.display = 'none';
		document.getElementById("dnssec-popup-ipvalidator-title").style.display = 'none';
		document.getElementById("dnssec-popup-ipvalidator-ip").style.display = 'none';
  },

  showAddInfo : function(id) {
		document.getElementById(id).style.display = 'block';
		document.getElementById("link").style.display = 'none';
		document.getElementById("dnssec-popup-homepage").style.display = 'block';
		if (this.valstate==3) {this.showAddInfoIP();}
  },

  hideAddInfo : function() {
		document.getElementById("dnssec-popup-security-detail").style.display = 'none';
		document.getElementById("link").style.display = 'block';
		document.getElementById("dnssec-popup-homepage").style.display = 'none';
		if (this.valstate==3) {this.hideAddInfoIP();}
  },

  /**
   * Set up the title and content messages for the security message popup,
   * based on the specified mode
   *
   * @param newMode The newly set security mode. Should be one of the DNSSEC_MODE_* constants.
   */
  setPopupMessages : function(newMode) {

    this._dnssecPopup.className = newMode;
    this._dnssecPopupContentBox.className = newMode;
    this._dnssecPopupContentBox2.className = newMode;
    this._dnssecPopupContentBox3.className = newMode;
    this._dnssecPopupContentBox4.className = newMode;
    // Set the static strings up front
    this._dnssecPopupSecLabel.textContent = this._domainPreText[newMode] + " " + this._utf8HostName + " " + this._securityText[newMode];
    this._dnssecPopupSecDetail.textContent = this._securityDetail[newMode];
    


    if (this.valstate==3) {
    this._dnssecPopupIpBrowser.textContent = this.ipbrowser;
    if (this.ipvalidator=="") this.ipvalidator="n/a";	
    this._dnssecPopupIpValidator.textContent = this.ipvalidator;
     }

    //dump(this._dnssecPopupSecDetail.textContent);
    // Push the appropriate strings out to the UI
    this._dnssecPopupContentHost.textContent = this._utf8HostName;

    var idnService = Components.classes["@mozilla.org/network/idn-service;1"]
                     .getService(Components.interfaces.nsIIDNService);

    var tooltipName;

    if (idnService.isACE(this._utf8HostName)) {
      // Encode to UTF-8 if IDN domain name is not in browser's whitelist
      // See "network.IDN.whitelist.*"
      tooltipName = idnService.convertACEtoUTF8(this._utf8HostName);
    } else if (idnService.isACE(this._asciiHostName)) {
      // Use punycoded name
      tooltipName = this._asciiHostName;
    } else {
      tooltipName = "";
    }

    this._dnssecPopupContentHost.tooltipText = tooltipName;
  },

  hideDnssecPopup : function() {
    // hide add info message
    this.hideAddInfo();
    this._dnssecPopup.hidePopup();
  },

  hideDnssecPopupfwd : function() {
    // hide add info message
    this._dnssecPopupfwd.hidePopup();
  },

  showDnssecFwdInfo : function() {
    // Make sure that the display:none style we set in xul is removed now that
    // the popup is actually needed
    this._dnssecPopupfwd.hidden = false;

    // Tell the popup to consume dismiss clicks, to avoid bug 395314
    //this._dnssecPopupfwd.popupBoxObject
    //    .setConsumeRollupEvent(Ci.nsIPopupBoxObject.ROLLUP_CONSUME);
     //dump('Open popup FWD...\n');

     delete this._stringBundle;
     this._stringBundle = document.getElementById("dnssec-strings");
     this._dnssecPopupfwdDetail.textContent = this._stringBundle.getString("dnssecfwdLabel");
    // Now open the popup, anchored off the primary chrome element
    this._dnssecPopupfwd.openPopup(this._dnssecBox, 'after_end', -10, 0);
  },

    hideDnssecFwdInfo: function() {
    this._dnssecPopupfwd.hidden = true;
  },

  /**
   * Click handler for the dnssec-box element in primary chrome.
   */
  handleDnssecButtonEvent : function(event) {

    event.stopPropagation();

    if ((event.type == "click" && event.button != 0) ||
        (event.type == "keypress" && event.charCode != KeyEvent.DOM_VK_SPACE &&
         event.keyCode != KeyEvent.DOM_VK_RETURN))
      return; // Left click, space or enter only

    // No popup window while...
    if (this._dnssecBox && (this._dnssecBox.className == this.DNSSEC_MODE_ACTION )) // getting security status
      return;
    // Revert the contents of the location bar, see bug 406779
//    handleURLBarRevert(); // firefox 3.5 fixed
    
    // hide add info message	
    this.hideAddInfo();	
    // Make sure that the display:none style we set in xul is removed now that
    // the popup is actually needed
    this._dnssecPopup.hidden = false;

    // Tell the popup to consume dismiss clicks, to avoid bug 395314
    this._dnssecPopup.popupBoxObject
        .setConsumeRollupEvent(Ci.nsIPopupBoxObject.ROLLUP_CONSUME);

    // Update the popup strings
    this.setPopupMessages(this._dnssecBox.className);
 	//dump('Open popopu...\n');
    // Now open the popup, anchored off the primary chrome element
    this._dnssecPopup.openPopup(this._dnssecBox, 'after_end', -10, 0);
  }
}



