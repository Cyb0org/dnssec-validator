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


observe : function(aSubject, aTopic, aData) {
dump("ccccccccccccccccccc");  

    aSubject.QueryInterface(Components.interfaces.nsIHttpChannel);
      aSubject.cancel(Components.results.NS_BINDING_ABORTED);
},





  
  //gets valid or invalid certificate used by the browser
  getCertificate: function(browser) {

    var uri = browser.currentURI;
    var ui = browser.securityUI;
    var cert = this.get_valid_cert(ui);
    if(!cert){
      cert = this.get_invalid_cert(uri);
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
 	dump("dffffffffffffff" + ui.SSLStatus + "\n");

      if(!ui.SSLStatus) 
	      return null; 
	dump("dffffffffffffff" + ui.SSLStatus.serverCert + "\n");
      return ui.SSLStatus.serverCert; 
    }
    catch (e) {
      return null;
    }
  },
  
  // gets current certificate, if it FAILED the security check
  get_invalid_cert: function(uri) {
    var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
		if(!gSSLStatus){
			return null;
		}
		return gSSLStatus.QueryInterface(Components.interfaces.nsISSLStatus)
				.serverCert;
  },
  
  get_invalid_cert_SSLStatus: function(uri) {
    var recentCertsSvc = 
		Components.classes["@mozilla.org/security/recentbadcerts;1"]
			.getService(Components.interfaces.nsIRecentBadCertsService);
		if (!recentCertsSvc)
			return null;

		var port = (uri.port == -1) ? 443 : uri.port;  

		var hostWithPort = uri.host + ":" + port;
		var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
		if (!gSSLStatus)
			return null;
		return gSSLStatus;
  },
  
  //Override the certificate as trusted
  do_override: function(browser, cert) { 
    var uri = browser.currentURI;
        
    //Get SSL status (untrusted flags)
    var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
    if(gSSLStatus == null) { 
	    return false; 
    } 
    var flags = 0;
    if(gSSLStatus.isUntrusted)
	    flags |= this.overrideService.ERROR_UNTRUSTED;
    if(gSSLStatus.isDomainMismatch)
	    flags |= this.overrideService.ERROR_MISMATCH;
    if(gSSLStatus.isNotValidAtThisTime)
	    flags |= this.overrideService.ERROR_TIME;
    //override the certificate trust
    this.overrideService.clearValidityOverride(uri.asciiHost, uri.port);
    this.overrideService.rememberValidityOverride(uri.asciiHost, uri.port, cert, flags, true);

    setTimeout(function (){ browser.loadURIWithFlags(uri.spec, flags);}, 25);
  },

     // check if URI had an untrusted cert and return the status
getInvalidCertStatus: function (uri){
            var recentCertsSvc = 
            Components.classes["@mozilla.org/security/recentbadcerts;1"]
                .getService(Components.interfaces.nsIRecentBadCertsService);
            if (!recentCertsSvc)
                return null;

            var port = (uri.port == -1) ? 443 : uri.port;  

            var hostWithPort = uri.host + ":" + port;
            var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
            if (!gSSLStatus)
                return null;
            return gSSLStatus;
},


check_tlsa: function (uri,port){
	dump("DANE: --- TLSA validation start ---\n");	
	var cert = this.getCertificate(window.gBrowser);
    	if(!cert) {
	  dump("DANE: No certificate!!!\n");
      	  return;
        }
	var state = window.gBrowser.securityUI.state;
	var derCerts = new Array();
	var chain = cert.getChain();
	//dump("DANE: chain is\n" + chain +"\n");
        var len = chain.length;
        for (var i = 0; i < chain.length; i++) {
		//dump(i + "\n");   
                var cert = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
		//dump("DANE: Cert is\n" + cert +"\n");
                var derData = cert.getRawDER({});
		//dump("DANE: derData is\n" + derData +"\n");
                // derData is Blob, can't pass it as Blob, can't pass it as
                // string because of Unicode.
                // Fairly sure the next line tops ugliness of visualbasic
                var derHex = derData.map(function(x) {return ("0"+x.toString(16)).substr(-2);}).join("");
                derCerts.push(derHex);
		//dump("derHex:\n" + derHex + "\n");
        } //for
	var tlsa = document.getElementById("dane-tlsa-plugin");
	var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;
        var protocol = "tcp";
    	// Create variable to pass options
	    var c = dnssecExtNPAPIConst;
	    var options = 0;
	    if (dnssecExtension.debugOutput) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
        var daneMatch = tlsa.TLSAValidate(derCerts, len, options, "",  uri.asciiHost, port, protocol, policy);
        dump("DANE: https://" + uri.asciiHost + " : " + daneMatch[0] +"\n"); 
	tlsaExtHandler.setSecurityState(daneMatch[0]);

	//tlsa.TLSACacheFree();
        //dump("dercer " + daneMatch.derCert + ", pemCert " + daneMatch.pemCert + "\n");
        //dump("tlsa " + daneMatch.tlsa + "\n");
	dump("DANE: --- TLSA validation end ---\n");
	return daneMatch[0];
  },

check_tlsa2: function (aRequest,uri,port){
	dump("DANE: --- TLSA validation start ---\n");
	var state = window.gBrowser.securityUI.state;
		
	dump("DANE: STATE is ::" + state +"\n");
	
	var len;
	var derCerts = new Array();
	var cert = this.getCertificate(window.gBrowser);
    	if(!cert) {
	  dump("DANE: No certificate!!!\n");
	  len = 0;
          derCerts.push("XXX");
 	
        }
	else {
	var state = window.gBrowser.securityUI.state;
	var chain = cert.getChain();
	//dump("DANE: chain is\n" + chain +"\n");
        len = chain.length;
        for (var i = 0; i < chain.length; i++) {
		//dump(i + "\n");   
                var cert = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
		//dump("DANE: Cert is\n" + cert +"\n");
                var derData = cert.getRawDER({});
		//dump("DANE: derData is\n" + derData +"\n");
                // derData is Blob, can't pass it as Blob, can't pass it as
                // string because of Unicode.
                // Fairly sure the next line tops ugliness of visualbasic
                var derHex = derData.map(function(x) {return ("0"+x.toString(16)).substr(-2);}).join("");
                derCerts.push(derHex);
		//dump("derHex:\n" + derHex + "\n");
        } //for
	}

	var tlsa = document.getElementById("dane-tlsa-plugin");
	var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;
        var protocol = "tcp";
    	// Create variable to pass options
	    var c = dnssecExtNPAPIConst;
	    var options = 0;
	    if (dnssecExtension.debugOutput) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
	dump("DANE: https://" + uri + " : " + len +"\n"); 
        var daneMatch = tlsa.TLSAValidate(derCerts, len, options, "",  uri, port, protocol, policy);
        dump("DANE: https://" + uri + " : " + daneMatch[0] +"\n"); 
	tlsaExtHandler.setSecurityState(daneMatch[0]);

	//tlsa.TLSACacheFree();
        //dump("dercer " + daneMatch.derCert + ", pemCert " + daneMatch.pemCert + "\n");
        //dump("tlsa " + daneMatch.tlsa + "\n");
	dump("DANE: --- TLSA validation end ---\n");
	return daneMatch[0];
    
  }
};




var httpRequestObserver =
{
  observe: function(subject, topic, data)
  {


    if (topic == "http-on-examine-response") {
      //subject.QueryInterface(Components.interfaces.nsIHttpChannel);
      //var url = subject.aLocation.spec;
      //dnssecExtension.processNewURL(url);
      //var httpChannel = subject.QueryInterface(Ci.nsIHttpChannel);
      //httpChannel.setRequestHeader("X-Hello", "World", false);
   //var tlsa = tlsaValidator.check_tlsa("www.nic.cz","443");
   //dump(tlsa + "++++++++++++++\n");
   dump("++ " + subject + " ++ " + topic + " ++ " + data + " ++\n");
   //subject.cancel(Components.results.NS_BINDING_ABORTED);
  //alert("x"); 

    }
  },

  get observerService() {
    return Cc["@mozilla.org/observer-service;1"]
                     .getService(Ci.nsIObserverService);
  },

  register: function()
  {
    this.observerService.addObserver(this, "http-on-examine-response", false);
  },

  unregister: function()
  {
    this.observerService.removeObserver(this, "http-on-examine-response");
  }
};


var dnssecExtUrlBarListener = {
  onLocationChange: function(aWebProgress, aRequest, aLocationURI)
  {

    var host = dnssecExtension.processNewURL(aLocationURI);

    var scheme = aLocationURI.scheme;             // Get URI scheme
    var  asciiHost = aLocationURI.asciiHost;       // Get punycoded hostname
    //var  utf8Host = aLocationURI.host;             // Get UTF-8 encoded hostname


    dump("+++ " + host + " +++\n");
    var tlsa = -4;
    if (host != undefined) {  
	if (scheme=="https") { 
		dump('Connection is https...\n');
		tlsa = tlsaValidator.check_tlsa2(aRequest,host,"443");
	}
	else { 
	    dump('Connection is NOT https...\n');
	     tlsa = -5;
        }
	dump("DANE: Return >>> " + tlsa + '\n');
    tlsaExtHandler.setSecurityState(tlsa);
	
    dump(" ----------------------------- "+ tlsa +"\n");
    if (tlsa <= -8 || tlsa == -6 ) if (aRequest) aRequest.cancel(Components.results.NS_BINDING_ABORTED);
   }

    //aRequest.cancel(NS_BINDING_ABORTED);
  },
  onSecurityChange: function(aWebProgress, aRequest, aState)
  {
    dump('Event: onSecurityChange\n');
    dump(aState + '\n');
	

  },
  onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus)
  {
    dump('Event: onStateChange\n');
  },
  onProgressChange: function(aWebProgress, aRequest,
                             aCurSelfProgress, aMaxSelfProgress,
                             aCurTotalProgress, aMaxTotalProgress)
  {
    dump('Event: onProgressChange\n');
  },
  onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage)
  {
    dump('Event: onStatusChange\n');
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

/*
  inittest: function() {
      var nameserver = dnssecExtPrefs.getChar("dnsserveraddr");
      var c = dnssecExtNPAPIConst;
      var options = 0;
      var testnic = 0;
      var dn = "www.nic.cz";
      var addr = "217.31.205.50";
      if (dnssecExtension.debugOutput) options |= c.DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
      if (dnssecExtPrefs.getInt("dnsserverchoose") != 3) options |= c.DNSSEC_INPUT_FLAG_USEFWD;
      options |= c.DNSSEC_INPUT_FLAG_RESOLVIPV4;
      var dsp = document.getElementById("dnssec-plugin");
      //dump('INIT parameters: \"'+ dn + '; ' + options + '; ' + nameserver + '; ' + addr + '\"\n');
      testnic = dsp.Validate(dn, options, nameserver, addr);
      testnic = testnic[0];
      if ((testnic==c.DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS) || (testnic==c.DNSSEC_EXIT_FAILED)) {
        dnssecExtHandler.showDnssecFwdInfo();	 		
    }
  },
*/

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
    httpRequestObserver.register();
    //this.inittest();
     
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

    // Unregister preferences observer
    dnssecExtPrefObserver.unregister();
httpRequestObserver.unregister();
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

      // Set inaction mode (no icon)
      dnssecExtHandler.setMode(dnssecExtHandler.DNSSEC_MODE_INACTION);
      tlsaExtHandler.setMode(tlsaExtHandler.DANE_MODE_INACTION);
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
    if (restmp==c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP || restmp==c.DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP) {
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
    tlsaExtHandler.setMode(tlsaExtHandler.DANE_MODE_ACTION);
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
//    dnssecExtension.oldAsciiHost = asciiHost;

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
  DANE_TOOLTIP_NO_TLSA_RECORD   : "dmntrTooltip",
  DANE_TOOLTIP_NO_CERT_CHAIN    : "dmnccTooltip",
  DANE_TOOLTIP_OFF	        : "dmoffTooltip",
  DANE_TOOLTIP_NO_HTTPS	        : "dmnohttpsTooltip",
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
    this._tooltipLabel[this.DANE_TOOLTIP_FAILED_RESOLVER] =
      this._stringBundle.getString("dane.tooltip.error");
    this._tooltipLabel[this.DANE_TOOLTIP_NO_TLSA_RECORD] =
      this._stringBundle.getString("dane.tooltip.notlsa");
    this._tooltipLabel[this.DANE_TOOLTIP_NO_CERT_CHAIN ] =
      this._stringBundle.getString("dane.tooltip.chain");
    this._tooltipLabel[this.DANE_TOOLTIP_OFF] =
      this._stringBundle.getString("dane.tooltip.off");
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
	case this.DANE_MODE_DNSSEC_BOGUS:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_FAILED_RESOLVER];
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
	case this.DANE_MODE_TLSA_PARAM_WRONG:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_VALIDATION_FALSE];
	      break;
	case this.DANE_MODE_NO_TLSA_RECORD:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_NO_TLSA_RECORD];
	      break;
	case this.DANE_MODE_ERROR:
	case this.DANE_MODE_RESOLVER_FAILED:
	case this.DANE_MODE_NO_CERT_CHAIN:
	      tooltip = this._tooltipLabel[this.DANE_TOOLTIP_FAILED_RESOLVER];
	      break;
	case this.DANE_MODE_VALIDATION_OFF:
	case this.DANE_MODE_DNSSEC_UNSECURED:
	     tooltip = this._tooltipLabel[this.DANE_TOOLTIP_OFF];
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
    this._tlsaPopupContentHost.textContent = gBrowser.currentURI.asciiHost;

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
	
    // Make sure that the display:none style we set in xul is removed now that
    // the popup is actually needed
    this._tlsaPopup.hidden = false;

    this.hideAddInfo();
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

