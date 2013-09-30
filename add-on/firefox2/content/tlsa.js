/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator 2.0 Add-on.

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

window.addEventListener("load", function() { daneExtension.init(); }, false);
window.addEventListener("unload", function() { daneExtension.uninit(); }, false);

// **********************************************************************
/* onPageLoad: observe that page is completed in any tabs or window    */
// **********************************************************************
function onPageLoad(event) {

	if (daneExtension.debugOutput)
		dump(tlsaValidator.DANE_DEBUG_PRE + "+++++++PAGE WAS LOADED++++++++++++" + tlsaValidator.DANE_DEBUG_POST); 
	
	daneExtension.oldAsciiHost2 = null;
	if (event.originalTarget instanceof HTMLDocument) {
		var win = event.originalTarget.defaultView;
	    if (win.frameElement) {
			win = win.top;
	    }
	}
};

// **********************************************************************
/* daneExtUrlBarListener: observe the browser events a securtiy changes*/
// **********************************************************************
var daneExtUrlBarListener = {

	onLocationChange: function(aWebProgress, aRequest, aLocationURI) {
	    //dump('Browser: onLocationChange()\n');  	
	},

	onSecurityChange: function(aWebProgress, aRequest, aState) {
	    //dump('Browser: onSecurityChange(' +aState + ')\n');
	    var uri = null;
	    uri = window.gBrowser.currentURI;
	    var tlsares = tlsaValidator.processNewURL(aRequest, uri);
	},

	onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
	    //dump('Browser: onStateChange\n');
	},

	onProgressChange: function(aWebProgress, aRequest,
                             aCurSelfProgress, aMaxSelfProgress,
                             aCurTotalProgress, aMaxTotalProgress) {
	    //dump('Browser: onProgressChange()\n');
	},
	
	onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {
	    //dump('Browser: onStatusChange()\n');
	}
};


// **************************************************************
// --------------------------------------------------------------
/* daneExtension */
// --------------------------------------------------------------
// **************************************************************
var daneExtension = {
	dnssecExtID: "dnssec@nic.cz",
	debugOutput: false,
	debugPrefix: "dane: ",
	debugStartNotice: "----- DANE resolving start -----\n",
	debugEndNotice: "----- DANE resolving end -----\n",
	asyncResolve: false,
	timer: null,
	oldAsciiHost: null,
	oldAsciiHost2: null,

init: function() {

    // Enable debugging information on stdout if desired
    this.getDebugOutputFlag();

   // if (this.debugOutput)
   //   dump(this.debugPrefix + 'Start of add-on init\n');

    // Enable asynchronous resolving if desired
    this.getAsyncResolveFlag();

    // Set inaction mode (no icon)
    tlsaExtHandler.setMode(tlsaExtHandler.DANE_MODE_INACTION);

    // Change popup-window fore/background color if desired
    this.getPopupColors();

    this.registerObserver("http-on-examine-response");
    this.registerObserver("http-on-examine-cached-response");

    // Create the timer
    this.timer = Components.classes["@mozilla.org/timer;1"]
                 .createInstance(Components.interfaces.nsITimer);

    // Listen for webpage events
    gBrowser.addProgressListener(daneExtUrlBarListener);
    gBrowser.addEventListener("load", onPageLoad, true);

    if (this.debugOutput)
      dump(this.debugPrefix + 'add-on init...\n');
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

    gBrowser.removeProgressListener(daneExtUrlBarListener);

    gBrowser.removeEventListener("load", onPageLoad, true);

   this.unregisterObserver("http-on-examine-response");
   this.unregisterObserver("http-on-examine-cached-response");


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

// catch http/https request	
observe: function(channel, topic, data) {

	if (topic == "http-on-examine-response") {
		var tlsaonoff = dnssecExtPrefs.getBool("tlsa");
		if (tlsaonoff) {    

			var Cc = Components.classes, Ci = Components.interfaces;
			channel.QueryInterface(Ci.nsIHttpChannel);
			var host = channel.URI.hostPort;
			var url = channel.URI.spec;
	
			if (this.debugOutput)
 			    dump(tlsaValidator.DANE_DEBUG_PRE + this.oldAsciiHost2 + " == " + host);      
	    	// Eliminate duplicated queries
	    	if (host == this.oldAsciiHost2) {
			if (this.debugOutput) dump(" ... TRUE" + tlsaValidator.DANE_DEBUG_POST);    
	     	 return;
    		}
			if (this.debugOutput) dump(" ... FALSE" + tlsaValidator.DANE_DEBUG_POST);

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
	
		   	si.QueryInterface(Ci.nsISSLStatusProvider);
			var st = si.SSLStatus;
			if (!st) return;
		
			st.QueryInterface(Ci.nsISSLStatus);
			var cert = st.serverCert;
			if (!cert) return;
			var ccancel = tlsaValidator.check_tlsa_https(channel, cert, browser, host, "443");
			if (ccancel) this.oldAsciiHost2 = null;
			else this.oldAsciiHost2 = host;		
    	}//tlsaoff
     } //if
     
     
     if (topic == "http-on-examine-cached-response") {
		//if (this.debugOutput) dump(tlsaValidator.DANE_DEBUG_PRE + "http-on-examine-cached-response" + tlsaValidator.DANE_DEBUG_POST);	 
      }
},

};//class


// **************************************************************
/* tlsaValidator class					       */
// **************************************************************
var tlsaValidator = {

 overrideService: Components.classes["@mozilla.org/security/certoverride;1"]
					.getService(Components.interfaces.nsICertOverrideService),
          
  state : {
      STATE_IS_BROKEN : 
	      Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN,
      STATE_IS_INSECURE :
	      Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE,
      STATE_IS_SECURE :
	      Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE
  },

    ALLOW_TYPE_01: 1,
    ALLOW_TYPE_23: 2,
    DANE_DEBUG_PRE: "dane: ",
    DANE_DEBUG_POST: "\n",

// it is call when url was changed 
processNewURL: function(aRequest, aLocationURI) {

    var scheme = null;
    var asciiHost = null;
    var c = tlsaExtNPAPIConst;

    scheme = aLocationURI.scheme;             // Get URI scheme
    asciiHost = aLocationURI.asciiHost;       // Get punycoded hostname

    if (daneExtension.debugOutput)
	dump(this.DANE_DEBUG_PRE + 'Scheme: "' + scheme + '"; ' + 'ASCII domain name: "' + asciiHost + '"'); 

    if (scheme == 'chrome' ||                   // Eliminate chrome scheme
        asciiHost == null ||
	asciiHost == 'about' ||
        asciiHost == '' ||                      // Empty string
        asciiHost.indexOf("\\") != -1 ||        // Eliminate addr containing '\'
        asciiHost.indexOf(":") != -1 ||         // Eliminate IPv6 addr notation
        asciiHost.search(/[A-Za-z]/) == -1) {   // Eliminate IPv4 addr notation

       if (daneExtension.debugOutput) dump(' ...invalid\n');
      this.oldAsciiHost = null;
      // Set inaction mode (no icon)
      tlsaExtHandler.setMode(tlsaExtHandler.DANE_MODE_INACTION);
      return;

    // Eliminate duplicated queries
    } else if (asciiHost == this.oldAsciiHost) {
      if (daneExtension.debugOutput) dump(' ...duplicated\n');
      return;
    }

    dump(' ...valid\n');

   var tlsaonoff = dnssecExtPrefs.getBool("tlsa");
   if (tlsaonoff) {               
	if (!aLocationURI || scheme.toLowerCase() != "https") {
		if (daneExtension.debugOutput) 
		  dump(this.DANE_DEBUG_PRE + "Connection is NOT secured (http)" + this.DANE_DEBUG_POST);
		tlsaExtHandler.setSecurityState(c.DANE_EXIT_NO_HTTPS);
		this.oldAsciiHost = asciiHost;
		return c.DANE_EXIT_NO_HTTPS;
	 } 
	 else {
		var tlsa = c.DANE_EXIT_VALIDATION_OFF;
		if (daneExtension.debugOutput)
	           dump(this.DANE_DEBUG_PRE + "Connection is secured (https)" + this.DANE_DEBUG_POST);
		tlsa = this.check_tlsa_tab_change(aRequest, asciiHost, "443");
		this.oldAsciiHost = asciiHost;
		return tlsa;
	}		
  }
  else {
	tlsaExtHandler.setSecurityState(c.DANE_EXIT_VALIDATION_OFF);
  	return c.DANE_EXIT_VALIDATION_OFF; 
  }
},
  
//gets valid or invalid certificate used by the browser
getCertificate: function(browser) {
    var uri = browser.currentURI;
    var ui = browser.securityUI;
    var cert = this.get_valid_cert(ui);
    if(!cert){
      cert = this.get_invalid_cert_SSLStatus(uri);
    }

    if(!cert) {
      return null;
    }
    return cert;
},


// gets current certificate, if it PASSED the browser check 
get_valid_cert: function(ui) {
    try { 
      ui.QueryInterface(Components.interfaces.nsISSLStatusProvider); 
      if(!ui.SSLStatus) 
	      return null; 
      return ui.SSLStatus.serverCert; 
    }
    catch (e) {
      return null;
    }
},
  
// gets current certificate, if it FAILED the security check
get_invalid_cert_SSLStatus: function(uri){
     var recentCertsSvc = null;

      // firefox <= 19 and seamonkey
      if (typeof Components.classes["@mozilla.org/security/recentbadcerts;1"] !== "undefined") {

            recentCertsSvc = Components.classes["@mozilla.org/security/recentbadcerts;1"]
                               .getService(Components.interfaces.nsIRecentBadCertsService);
      }
      // firefox > v20
      else if (typeof Components.classes["@mozilla.org/security/x509certdb;1"] !== "undefined") {

         var certDB = Components.classes["@mozilla.org/security/x509certdb;1"]
                      .getService(Components.interfaces.nsIX509CertDB);
         if (!certDB) return null;

         var privateMode = false;
          if (typeof Components.classes['@mozilla.org/privatebrowsing;1'] !== 'undefined')
             
              privateMode = Components.classes["@mozilla.org/privatebrowsing;1"]
                           .getService(Components.interfaces.nsIPrivateBrowsingService);
              recentCertsSvc = certDB.getRecentBadCerts(privateMode);
          }
          else {
             if (daneExtension.debugOutput)
                dump("No way to get invalid cert status!");
                return null;
          }

      if (!recentCertsSvc) return null;

      var port = (uri.port == -1) ? 443 : uri.port;

      var hostWithPort = uri.host + ":" + port;
      var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
      if (!gSSLStatus) return null;
   return gSSLStatus;
},

// check TLSA when tab is change
check_tlsa_tab_change: function (channel, uri, port){

	if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "--- TLSA validation start ---" + this.DANE_DEBUG_POST); 

    var c = tlsaExtNPAPIConst;
	var cert = this.getCertificate(window.gBrowser);

    if(!cert) {
	  if (daneExtension.debugOutput)
	      dump(this.DANE_DEBUG_PRE + "No certificate!" + this.DANE_DEBUG_POST);
	  tlsaExtHandler.setSecurityState(c.DANE_EXIT_NO_CERT_CHAIN);
	  this.oldAsciiHost = null;
  	  if (daneExtension.debugOutput)
	      dump(this.DANE_DEBUG_PRE + "--- TLSA validation end ---" + this.DANE_DEBUG_POST); 
	  return c.DANE_EXIT_NO_CERTCHAIN;
    }
          
	var state = window.gBrowser.securityUI.state;
	var derCerts = new Array();
	var chain = cert.getChain();
        var len = chain.length;
        for (var i = 0; i < chain.length; i++) {
                var cert = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
                var derData = cert.getRawDER({});
                var derHex = derData.map(function(x) {return ("0"+x.toString(16)).substr(-2);}).join("");
                derCerts.push(derHex);
        } //for
	var tlsa = document.getElementById("dane-tlsa-plugin");
	var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;
    var protocol = "tcp";
       
    var options = 0;
    if (dnssecExtension.debugOutput) options |= c.DANE_INPUT_FLAG_DEBUGOUTPUT;
    if (dnssecExtPrefs.getInt("dnsserverchoose") != 3) options |= c.DANE_INPUT_FLAG_USEFWD;

    var nameserver = "";
    if (dnssecExtPrefs.getChar("dnsserveraddr") != "") nameserver = dnssecExtPrefs.getChar("dnsserveraddr");

    if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "https://" + uri + "; certchain lenght: " + len + this.DANE_DEBUG_POST); 

    var daneMatch = tlsa.TLSAValidate(derCerts, len, options, nameserver, uri, port, protocol, policy);

	if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "For https://" + uri + " DANE return: " + daneMatch[0] + this.DANE_DEBUG_POST); 

   	if (daneMatch[0] <= c.DANE_EXIT_NO_CERT_CHAIN) { 	   	
	   if (channel) {
	      if (this.oldAsciiHost == uri) {  
	        if (daneExtension.debugOutput)
	    		dump(this.DANE_DEBUG_PRE + this.oldAsciiHost + " == " + uri + this.DANE_DEBUG_POST); 
	      }	
	      else { 
				if (daneExtension.debugOutput)	    
		    	    dump(this.DANE_DEBUG_PRE + this.oldAsciiHost + " <> " + uri + this.DANE_DEBUG_POST); 
				var tlsablock = dnssecExtPrefs.getBool("tlsablocking"); 
		 		if (tlsablock) {      
         			var stringbundle = document.getElementById("dnssec-strings");
   	     			var pre = stringbundle.getString("warning.dialog.pre");
    	 	    	var post = stringbundle.getString("warning.dialog.post");	
					if (confirm(pre + uri + " "+post)) {
					   channel.cancel(Components.results.NS_BINDING_ABORTED);
					   dump(this.DANE_DEBUG_PRE + "https request for (" +uri+ ") was canceled!" + this.DANE_DEBUG_POST);
					   this.oldAsciiHost = null;  
					}
				}
	      	}
	   	}
    }

	tlsaExtHandler.setSecurityState(daneMatch[0]);
	if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "--- TLSA validation end ---" + this.DANE_DEBUG_POST);
	this.oldAsciiHost = null;
	return daneMatch[0];
},

// check TLSA when new https request is create
check_tlsa_https: function (channel, cert, browser, uri, port){

	if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "--- TLSA VALIDATION START ---" + this.DANE_DEBUG_POST); 
    var c = tlsaExtNPAPIConst;
    if(!cert) {
		 if (daneExtension.debugOutput)
		    dump(this.DANE_DEBUG_PRE + "No certificate!" + this.DANE_DEBUG_POST);
		  tlsaExtHandler.setSecurityState(c.DANE_EXIT_NO_CERT_CHAIN);
		  //this.oldAsciiHost2 = null;
  		  if (daneExtension.debugOutput)
		    dump(this.DANE_DEBUG_PRE + "--- TLSA VALIDATION END ---" + this.DANE_DEBUG_POST); 
	 	 return true;
    }
                
	var state = window.gBrowser.securityUI.state;
	var derCerts = new Array();
	var chain = cert.getChain();
        var len = chain.length;
        for (var i = 0; i < chain.length; i++) {  
                var cert = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);	
                var derData = cert.getRawDER({});
                var derHex = derData.map(function(x) {return ("0"+x.toString(16)).substr(-2);}).join("");
                derCerts.push(derHex);
        } //for
        
	var tlsa = document.getElementById("dane-tlsa-plugin");
	var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;
    var protocol = "tcp";
       
    var options = 0;
    if (dnssecExtension.debugOutput) options |= c.DANE_INPUT_FLAG_DEBUGOUTPUT;
    if (dnssecExtPrefs.getInt("dnsserverchoose") != 3) options |= c.DANE_INPUT_FLAG_USEFWD;

    var nameserver = "";
    if (dnssecExtPrefs.getChar("dnsserveraddr") != "") nameserver = dnssecExtPrefs.getChar("dnsserveraddr");

    if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "https://" + uri + "; certchain lenght: " + len + this.DANE_DEBUG_POST); 

    var daneMatch = tlsa.TLSAValidate(derCerts, len, options, nameserver, uri, port, protocol, policy);

	if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "For https://" + uri + " DANE return: " + daneMatch[0] + this.DANE_DEBUG_POST); 
	var ccancel = false;
   	if (daneMatch[0] <= c.DANE_EXIT_NO_CERT_CHAIN) { 	   	
		if (channel) {
				ccancel = false;
				var tlsablock = dnssecExtPrefs.getBool("tlsablocking"); 
				if (tlsablock) {      
					var stringbundle = document.getElementById("dnssec-strings");
		   	        var pre = stringbundle.getString("warning.dialog.pre");
	    	        var post = stringbundle.getString("warning.dialog.post");	
					if (confirm(pre + uri + " "+post)) {					
					   channel.cancel(Components.results.NS_BINDING_ABORTED);
					   if (daneExtension.debugOutput)
	    					dump(this.DANE_DEBUG_PRE + "https request for (" +uri+ ") was canceled!" + this.DANE_DEBUG_POST); 
					   ccancel = true;
					}
	      		}
		   }
    }
	
	//tlsaExtHandler.setSecurityState(daneMatch[0]);
	if (daneExtension.debugOutput)
	    dump(this.DANE_DEBUG_PRE + "--- TLSA TLSA VALIDATION END ---" + this.DANE_DEBUG_POST);
	return ccancel;
  }
};

//*****************************************************************************
//*****************************************************************************
/* Utility class to handle manipulations of the TLSA indicators in the UI */
//*****************************************************************************
//*****************************************************************************
var tlsaExtHandler = {
  // DANE/TLSA MODE
  DANE_MODE_INACTION 		: "dm_inaction",
  DANE_MODE_VALIDATION_OFF   	: "dm_validationoff",
  DANE_MODE_ACTION   		: "dm_action",
  DANE_MODE_ERROR 		: "dm_error",
  DANE_MODE_RESOLVER_FAILED     : "dm_rfesolverfailed",
  DANE_MODE_DNSSEC_BOGUS	: "dm_dnssecbogus",
  DANE_MODE_DNSSEC_UNSECURED	: "dm_dnssecunsecured",
  DANE_MODE_NO_TLSA_RECORD	: "dm_notlsarecord",		
  DANE_MODE_NO_CERT_CHAIN	: "dm_certchain",
  DANE_MODE_TLSA_PARAM_WRONG	: "dm_tlsapramwrong",
  DANE_MODE_NO_HTTPS		: "dm_nohttps",
  DANE_MODE_DNSSEC_SECURED      : "dm_dnssecsec", 
  DANE_MODE_CERT_ERROR          : "dm_certerr",

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
  DANE_TOOLTIP_VALIDATION_SUCCESS : "dmvsTooltip",
  DANE_TOOLTIP_VALIDATION_FALSE : "dmvfTooltip",
  DANE_TOOLTIP_ACTION          	: "dmaTooltip",
  DANE_TOOLTIP_FAILED_RESOLVER  : "dmfsTooltip",
  DANE_TOOLTIP_PARAM_WRONG	: "dmwpTooltip",
  DANE_TOOLTIP_NO_TLSA_RECORD   : "dmntrTooltip",
  DANE_TOOLTIP_NO_CERT_CHAIN    : "dmnccTooltip",
  DANE_TOOLTIP_OFF	        : "dmoffTooltip",
  DANE_TOOLTIP_NO_HTTPS	        : "dmnohttpsTooltip",
  DANE_TOOLTIP_DNSSEC_BOGUS     : "dmdnssecbogusTooltip",
  DANE_TOOLTIP_DNSSEC_UNSECURED : "dmdnssecunsecTooltip",

  // Cache the most recent hostname seen in checkSecurity
  _asciiHostName : null,
  _utf8HostName : null,

  valstate : -1,

  get _tooltipLabel () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._tooltipLabel;
    this._tooltipLabel = {};
    this._tooltipLabel[this.DANE_TOOLTIP_NO_HTTPS] =
      this._stringBundle.getString("dane.tooltip.nohttps");
    this._tooltipLabel[this.DANE_TOOLTIP_VALIDATION_SUCCESS] =
      this._stringBundle.getString("dane.tooltip.success");
    this._tooltipLabel[this.DANE_TOOLTIP_VALIDATION_FALSE] =
      this._stringBundle.getString("dane.tooltip.false");
    this._tooltipLabel[this.DANE_TOOLTIP_ACTION] =
      this._stringBundle.getString("dane.tooltip.action");
    this._tooltipLabel[this.DANE_TOOLTIP_PARAM_WRONG] =
      this._stringBundle.getString("dane.tooltip.param.wrong");
    this._tooltipLabel[this.DANE_TOOLTIP_FAILED_RESOLVER] =
      this._stringBundle.getString("dane.tooltip.error");
    this._tooltipLabel[this.DANE_TOOLTIP_NO_TLSA_RECORD] =
      this._stringBundle.getString("dane.tooltip.notlsa");
    this._tooltipLabel[this.DANE_TOOLTIP_NO_CERT_CHAIN ] =
      this._stringBundle.getString("dane.tooltip.chain");
    this._tooltipLabel[this.DANE_TOOLTIP_OFF] =
      this._stringBundle.getString("dane.tooltip.off");
    this._tooltipLabel[this.DANE_TOOLTIP_DNSSEC_BOGUS] =
      this._stringBundle.getString("dane.tooltip.dnssec.bogus");
    this._tooltipLabel[this.DANE_TOOLTIP_DNSSEC_UNSECURED] =
      this._stringBundle.getString("dane.tooltip.dnssec.unsecured");
    return this._tooltipLabel;
  },

  //set DANE security text
  get _securityText () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._securityText;
    this._securityText = {};

    this._securityText[this.DANE_MODE_ERROR] =
      this._stringBundle.getString("dane.mode.error");
    this._securityText[this.DANE_MODE_RESOLVER_FAILED] =
      this._stringBundle.getString("dane.mode.resolver.failed");
    this._securityText[this.DANE_MODE_DNSSEC_BOGUS] =
      this._stringBundle.getString("dane.mode.dnssec.bogus");
    this._securityText[this.DANE_MODE_DNSSEC_UNSECURED] =
      this._stringBundle.getString("dane.mode.dnssec.unsecured");
    this._securityText[this.DANE_MODE_NO_TLSA_RECORD] =
      this._stringBundle.getString("dane.mode.no.tlsa.record");
    this._securityText[this.DANE_MODE_NO_CERT_CHAIN] =
      this._stringBundle.getString("dane.mode.no.cert.chain");
    this._securityDetail[this.DANE_MODE_CERT_ERROR] =
      this._stringBundle.getString("dane.mode.no.cert");
    this._securityText[this.DANE_MODE_TLSA_PARAM_WRONG] =
      this._stringBundle.getString("dane.mode.tlsa.param.wrong");
    this._securityText[this.DANE_MODE_NO_HTTPS] =
      this._stringBundle.getString("dane.mode.no.https");
    this._securityText[this.DANE_MODE_VALIDATION_FALSE] =
      this._stringBundle.getString("dane.mode.validation.false");
    this._securityText[this.DANE_MODE_VALIDATION_FALSE_TYPE0] =
      this._stringBundle.getString("dane.mode.validation.false.type0");
    this._securityText[this.DANE_MODE_VALIDATION_FALSE_TYPE1] =
      this._stringBundle.getString("dane.mode.validation.false.type1");
    this._securityText[this.DANE_MODE_VALIDATION_FALSE_TYPE2] =
      this._stringBundle.getString("dane.mode.validation.false.type2");
    this._securityText[this.DANE_MODE_VALIDATION_FALSE_TYPE3] =
      this._stringBundle.getString("dane.mode.validation.false.type3");
    this._securityText[this.DANE_MODE_VALIDATION_SUCCESS_TYPE0] =
      this._stringBundle.getString("dane.mode.validation.success.type0");
    this._securityText[this.DANE_MODE_VALIDATION_SUCCESS_TYPE1] =
      this._stringBundle.getString("dane.mode.validation.success.type1");
    this._securityText[this.DANE_MODE_VALIDATION_SUCCESS_TYPE2] =
      this._stringBundle.getString("dane.mode.validation.success.type2");
    this._securityText[this.DANE_MODE_VALIDATION_SUCCESS_TYPE3] =
      this._stringBundle.getString("dane.mode.validation.success.type3");
    this._securityText[this.DANE_MODE_VALIDATION_OFF] =
      this._stringBundle.getString("dane.mode.validation.off");
    return this._securityText;
  },

  //set DANE security message detail
  get _securityDetail () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._securityDetail;
    this._securityDetail = {};

    this._securityDetail[this.DANE_MODE_ERROR] =
      this._stringBundle.getString("dane.mode.error.detail");
    this._securityDetail[this.DANE_MODE_RESOLVER_FAILED] =
      this._stringBundle.getString("dane.mode.resolver.failed.detail");
    this._securityDetail[this.DANE_MODE_DNSSEC_BOGUS] =
      this._stringBundle.getString("dane.mode.dnssec.bogus.detail");
    this._securityDetail[this.DANE_MODE_DNSSEC_UNSECURED] =
      this._stringBundle.getString("dane.mode.dnssec.unsecured.detail");
    this._securityDetail[this.DANE_MODE_NO_TLSA_RECORD] =
      this._stringBundle.getString("dane.mode.no.tlsa.record.detail");
    this._securityDetail[this.DANE_MODE_NO_CERT_CHAIN] =
      this._stringBundle.getString("dane.mode.no.cert.chain.detail");
    this._securityDetail[this.DANE_MODE_CERT_ERROR] =
      this._stringBundle.getString("dane.mode.no.cert.detail");
    this._securityDetail[this.DANE_MODE_TLSA_PARAM_WRONG] =
      this._stringBundle.getString("dane.mode.tlsa.param.wrong.detail");
    this._securityDetail[this.DANE_MODE_NO_HTTPS] =
      this._stringBundle.getString("dane.mode.no.https.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_FALSE] =
      this._stringBundle.getString("dane.mode.validation.false.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_FALSE_TYPE0] =
      this._stringBundle.getString("dane.mode.validation.false.type0.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_FALSE_TYPE1] =
      this._stringBundle.getString("dane.mode.validation.false.type1.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_FALSE_TYPE2] =
      this._stringBundle.getString("dane.mode.validation.false.type2.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_FALSE_TYPE3] =
      this._stringBundle.getString("dane.mode.validation.false.type3.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_SUCCESS_TYPE0] =
      this._stringBundle.getString("dane.mode.validation.success.type0.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_SUCCESS_TYPE1] =
      this._stringBundle.getString("dane.mode.validation.success.type1.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_SUCCESS_TYPE2] =
      this._stringBundle.getString("dane.mode.validation.success.type2.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_SUCCESS_TYPE3] =
      this._stringBundle.getString("dane.mode.validation.success.type3.detail");
    this._securityDetail[this.DANE_MODE_VALIDATION_OFF] =
      this._stringBundle.getString("dane.mode.validation.off.detail");
    return this._securityDetail;
  },

  get _tlsaPopup () {
    delete this._tlsaPopup;
    return this._tlsaPopup = document.getElementById("tlsa-popup");
  },
  get _tlsaPopupfwd () {
    delete this._tlsaPopupfwd;
    return this._tlsaPopupfwd = document.getElementById("tlsa-popup-fwd");
  },
  get _tlsaBox () {
    delete this._tlsaBox;
    return this._tlsaBox = document.getElementById("tlsa-box");
  },
  get _tlsaPopupContentBox () {
    delete this._tlsaPopupContentBox;
    return this._tlsaPopupContentBox =
      document.getElementById("tlsa-popup-content-box");
  },
  get _tlsaPopupContentBox2 () {
    delete this._tlsaPopupContentBox2;
    return this._tlsaPopupContentBox2 =
      document.getElementById("tlsa-popup-content-box2");
  },
  get _tlsaPopupContentBox3 () {
    delete this._tlsaPopupContentBox3;
    return this._tlsaPopupContentBox3 =
      document.getElementById("tlsa-popup-content-box3");
  },
  get _tlsaPopupContentBox4 () {
    delete this._tlsaPopupContentBox4;
    return this._tlsaPopupContentBox4 =
      document.getElementById("tlsa-popup-content-box4");
  },
  get _tlsaPopupContentHost () {
    delete this._tlsaPopupContentHost;
    return this._tlsaPopupContentHost =
      document.getElementById("tlsa-popup-content-host");
  },
  get _tlsaPopupSecLabel () {
    delete this._tlsaPopupSecLabel;
    return this._tlsaPopupSecLabel =
      document.getElementById("tlsa-popup-security-text");
  },
  get _tlsaPopupSecLabel2 () {
    delete this._tlsaPopupSecLabel2;
    return this._tlsaPopupSecLabel2 =
      document.getElementById("tlsa-popup-security-label");
  },
  get _tlsaPopupSecDetail () {
    delete this._tlsaPopupSecDetail;
    return this._tlsaPopupSecDetail =
      document.getElementById("tlsa-popup-security-detail");
  },
  get _tlsaPopupfwdDetail () {
    delete this._tlsaPopupfwdDetail;
    return this._tlsaPopupfwdDetail =
      document.getElementById("tlsa-popup-fwd-text");
  },
  get _tlsaPopupIpBrowser () {
    delete this._tlsaPopupIpBrowser;
    return this._tlsaPopupIpBrowser =
      document.getElementById("tlsa-popup-ipbrowser-ip");
  },
  get _tlsaPopupIpValidator () {
    delete this._tlsaPopupIpValidator;
    return this._tlsaPopupIpValidator =
      document.getElementById("tlsa-popup-ipvalidator-ip");
  },
  // Build out a cache of the elements that we need frequently
  _cacheElements : function() {
    delete this._tlsaBox;
    this._tlsaBox = document.getElementById("tlsa-box");
  },

  // Set appropriate DANE security state
  setSecurityState : function(state) {
    var c = tlsaExtNPAPIConst;

    switch (state) {
	case c.DANE_EXIT_VALIDATION_OFF:
		this.setMode(this.DANE_MODE_VALIDATION_OFF);
		break;
 	case c.DANE_EXIT_NO_TLSA_RECORD:
		this.setMode(this.DANE_MODE_NO_TLSA_RECORD);
		break;
	case c.DANE_EXIT_RESOLVER_FAILED:
		this.setMode(this.DANE_MODE_RESOLVER_FAILED);
		break;
	case c.DANE_EXIT_DNSSEC_BOGUS:
		this.setMode(this.DANE_MODE_DNSSEC_BOGUS);
		break;
	case c.DANE_EXIT_DNSSEC_UNSECURED:
		this.setMode(this.DANE_MODE_DNSSEC_UNSECURED);
		break;
	case c.DANE_EXIT_NO_HTTPS:
		this.setMode(this.DANE_MODE_NO_HTTPS);
		break;
	case c.DANE_EXIT_TLSA_PARAM_ERR:
		this.setMode(this.DANE_MODE_TLSA_PARAM_WRONG);
		break;
	case c.DANE_EXIT_DNSSEC_SECURED:
		this.setMode(this.DANE_MODE_DNSSEC_SECURED);
		break;
	case c.DANE_EXIT_CERT_ERROR:
		this.setMode(this.DANE_MODE_CERT_ERROR);
		break;
	case c.DANE_EXIT_NO_CERT_CHAIN:
		this.setMode(this.DANE_MODE_NO_CERT_CHAIN);
		break;
	case c.DANE_EXIT_VALIDATION_FALSE:
		this.setMode(this.DANE_MODE_VALIDATION_FALSE);
		break;
	case c.DANE_EXIT_VALIDATION_FALSE_TYPE0:
		this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE0);
		break;
	case c.DANE_EXIT_VALIDATION_FALSE_TYPE1:
		this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE1);
		break;
	case c.DANE_EXIT_VALIDATION_FALSE_TYPE2:
		this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE2);
		break;
	case c.DANE_EXIT_VALIDATION_FALSE_TYPE3:
		this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE3);
		break;
	case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE0:
		this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE0);
		break;
	case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE1:
		this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE1);
		break;
	case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE2:
		this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE2);
		break;
	case c.DANE_EXIT_VALIDATION_SUCCESS_TYPE3:
		this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE3);
		break;
      default: this.setMode(this.DANE_MODE_ERROR);
      		break;
    }
  },

  /**
   * Update the UI to reflect the specified mode, which should be one of the
   * TLSA_MODE_* constants.
   */
  setMode : function(newMode) {
    if (!this._tlsaBox) {
      // No TLSA box means the TLSA box is not visible, in which
      // case there's nothing to do.
      return;
    } 
    else if (newMode == this.DANE_MODE_ACTION) {  // Close window for these states
      this.hideTlsaPopup();
    }

    this._tlsaBox.className = newMode;
    this.setSecurityMessages(newMode);

    // Update the popup too, if it's open
    if (this._tlsaPopup.state == "open")
      this.setPopupMessages(newMode);
  },

  /**
   * Set up the messages for the primary security UI based on the specified mode,
   *
   * @param newMode The newly set security mode. Should be one of the TLSA_MODE_* constants.
   */
  setSecurityMessages : function(newMode) {

   var tooltip;

   switch (newMode) {
	case this.DANE_MODE_NO_HTTPS:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_NO_HTTPS];
	      break;
	case this.DANE_MODE_ACTION:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_ACTION];
	      break;
	case this.DANE_MODE_VALIDATION_SUCCESS_TYPE0:
	case this.DANE_MODE_VALIDATION_SUCCESS_TYPE1:
	case this.DANE_MODE_VALIDATION_SUCCESS_TYPE2:
	case this.DANE_MODE_VALIDATION_SUCCESS_TYPE3:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_VALIDATION_SUCCESS];
	      break;
	case this.DANE_MODE_VALIDATION_FALSE:
	case this.DANE_MODE_VALIDATION_FALSE_TYPE0:
	case this.DANE_MODE_VALIDATION_FALSE_TYPE1:
	case this.DANE_MODE_VALIDATION_FALSE_TYPE2:
	case this.DANE_MODE_VALIDATION_FALSE_TYPE3:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_VALIDATION_FALSE];
	      break;
	case this.DANE_MODE_TLSA_PARAM_WRONG:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_PARAM_WRONG];
	      break;
	case this.DANE_MODE_NO_TLSA_RECORD:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_NO_TLSA_RECORD];
	      break;
	case this.DANE_MODE_ERROR:
	case this.DANE_MODE_RESOLVER_FAILED:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_FAILED_RESOLVER];
	      break;
	case this.DANE_MODE_NO_CERT_CHAIN:
	case this.DANE_MODE_CERT_ERROR:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_NO_CERT_CHAIN];
	      break;
	case this.DANE_MODE_VALIDATION_OFF:
	     tooltip = this._tooltipLabel[this.DANE_TOOLTIP_OFF];
	     break;
	case this.DANE_MODE_DNSSEC_UNSECURED:
	     tooltip = this._tooltipLabel[this.DANE_TOOLTIP_DNSSEC_UNSECURED];
	     break;
	case this.DANE_MODE_DNSSEC_BOGUS:
	     tooltip = this._tooltipLabel[this.DANE_TOOLTIP_DNSSEC_BOGUS];
	     break;
    // Unknown
       default: tooltip = "";
    }
    // Push the appropriate strings out to the UI
    this._tlsaBox.tooltipText = tooltip;
    return tooltip;
  },

  /**
   * Set up the title and content messages for the security message popup,
   * based on the specified mode
   *
   * @param newMode The newly set security mode. Should be one of the tlsa_MODE_* constants.
   */
  setPopupMessages : function(newMode) {

    this._tlsaPopup.className = newMode;
    this._tlsaPopupContentBox.className = newMode;
    this._tlsaPopupContentBox2.className = newMode;
    this._tlsaPopupContentBox3.className = newMode;
    this._tlsaPopupContentBox4.className = newMode;
    // Set the static strings up front
    this._tlsaPopupSecLabel.textContent = " " + this._securityText[newMode];
    this._tlsaPopupSecDetail.textContent = this._securityDetail[newMode];
    this._tlsaPopupSecLabel2.textContent =  this.setSecurityMessages(newMode);
 

    //dump(this._tlsaPopupSecDetail.textContent);
     //Push the appropriate strings out to the UI
     if (newMode == this.DANE_MODE_NO_HTTPS) {
    	this._tlsaPopupContentHost.textContent = gBrowser.currentURI.asciiHost;
    }
    else this._tlsaPopupContentHost.textContent = "https://" + gBrowser.currentURI.asciiHost;

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
    this._tlsaPopupContentHost.tooltipText = tooltipName;
  },

  hideTlsaPopup : function() {
    this.hideAddInfo();
    this._tlsaPopup.hidePopup();
  },

  showAddInfoIP : function() {
		document.getElementById("tlsa-popup-ipbrowser-title").style.display = 'block';
		document.getElementById("tlsa-popup-ipbrowser-ip").style.display = 'block';
		document.getElementById("tlsa-popup-ipvalidator-title").style.display = 'block';
		document.getElementById("tlsa-popup-ipvalidator-ip").style.display = 'block';
  },

  hideAddInfoIP : function() {
		document.getElementById("tlsa-popup-ipbrowser-title").style.display = 'none';
		document.getElementById("tlsa-popup-ipbrowser-ip").style.display = 'none';
		document.getElementById("tlsa-popup-ipvalidator-title").style.display = 'none';
		document.getElementById("tlsa-popup-ipvalidator-ip").style.display = 'none';
  },

  showAddInfo : function(id) {
		document.getElementById(id).style.display = 'block';
		document.getElementById("linkt").style.display = 'none';
		document.getElementById("tlsa-popup-homepage").style.display = 'block';
  },

  hideAddInfo : function() {
		document.getElementById("tlsa-popup-security-detail").style.display = 'none';
		document.getElementById("linkt").style.display = 'block';
		document.getElementById("tlsa-popup-homepage").style.display = 'none';
  },


  /**
   * Click handler for the tlsa-box element in primary chrome.
   */
  handleTlsaButtonEvent : function(event) {

    event.stopPropagation();

    if ((event.type == "click" && event.button != 0) ||
        (event.type == "keypress" && event.charCode != KeyEvent.DOM_VK_SPACE &&
         event.keyCode != KeyEvent.DOM_VK_RETURN))
      return; // Left click, space or enter only

    // No popup window while...
    if (this._tlsaBox && (this._tlsaBox.className == this.DANE_MODE_ACTION )) // getting security status
      return;

    this.hideAddInfo();	
    // Make sure that the display:none style we set in xul is removed now that
    // the popup is actually needed
    this._tlsaPopup.hidden = false;

    // Tell the popup to consume dismiss clicks, to avoid bug 395314
    this._tlsaPopup.popupBoxObject
        .setConsumeRollupEvent(Ci.nsIPopupBoxObject.ROLLUP_CONSUME);

    // Update the popup strings
    this.setPopupMessages(this._tlsaBox.className);
 	//dump('Open popopu...\n');
    // Now open the popup, anchored off the primary chrome element
    this._tlsaPopup.openPopup(this._tlsaBox, 'after_end', -10, 0);
  }
}
