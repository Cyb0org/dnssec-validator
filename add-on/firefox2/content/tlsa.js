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
      if(!ui.SSLStatus) 
	      return null; 
      return ui.SSLStatus.serverCert; 
    }
    catch (e) {
      org.os3sec.Extval.Extension.logMsg('get_valid_cert: ' + e);
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
    
    org.os3sec.Extval.Extension.logMsg('Overriding certificate trust ');
    
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
	dump("DANE: State is\n" + state +"\n");
	var derCerts = new Array();
	var chain = cert.getChain();
	dump("DANE: chain is\n" + chain +"\n");
        var len = chain.length;
        for (var i = 0; i < chain.length; i++) {
		dump(i + "\n");   
                var cert = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
		dump("DANE: Cert is\n" + cert +"\n");
                var derData = cert.getRawDER({});
		dump("DANE: derData is\n" + derData +"\n");
                // derData is Blob, can't pass it as Blob, can't pass it as
                // string because of Unicode.
                // Fairly sure the next line tops ugliness of visualbasic
                var derHex = derData.map(function(x) {return ("0"+x.toString(16)).substr(-2);}).join("");
                derCerts.push(derHex);
		dump("derHex:\n" + derHex + "\n");
        } //for
	var tlsa = document.getElementById("dane-tlsa-plugin");
	var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;
        var protocol = "tcp";
        var daneMatch = tlsa.TLSAValidate(derCerts, len, 5, "",  uri.asciiHost, port, protocol, policy);
        dump("DANE: host " + uri.asciiHost + " : " + daneMatch[0] +"\n");
	//tlsa.TLSACacheFree();
        //dump("dercer " + daneMatch.derCert + ", pemCert " + daneMatch.pemCert + "\n");
        //dump("tlsa " + daneMatch.tlsa + "\n");
	dump("DANE: --- TLSA validation end ---\n");

}
}


//*****************************************************************************
//*****************************************************************************
/* Utility class to handle manipulations of the dnssec indicators in the UI */
//*****************************************************************************
//*****************************************************************************
var daneExtHandler = {

  // -1
  DANE_MODE_FAILED_RESOLVER     : "dmfs",
  // -2
  DANE_MODE_NO_TLSA_RECORD	: "dmntr",		
  // -3	 
  DANE_MODE_NO_CERT_CHAIN	: "dmncc",
  // -4
  DANE_MODE_TLSA_PARAM_ERR	: "dmtpe",
  // 0
  DANE_MODE_VALIDATION_FALSE	: "dmvf",
  // 1
  DANE_MODE_VALIDATION_SUCCESS	: "dmvs",
  DANE_MODE_ERROR : "dme",
  DANE_MODE_OFF   : "dmo",

  DANE_TOOLTIP_VALIDATION_SUCCESS : "dmvsTooltip",
  DANE_TOOLTIP_VALIDATION_FALSE : "dmvfTooltip",
  DANE_TOOLTIP_ACTION          	: "dmaTooltip",
  DANE_TOOLTIP_FAILED_RESOLVER  : "dmfsTooltip",
  DANE_TOOLTIP_NO_TLSA_RECORD   : "dmntrTooltip",
  DANE_TOOLTIP_NO_CERT_CHAIN    : "dmnccTooltip",

  // Cache the most recent hostname seen in checkSecurity
  _asciiHostName : null,
  _utf8HostName : null,

  ipvalidator : "",
  ipbrowser : "",
  valstate : 0,

  get _tooltipLabel () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("tlsa-strings");

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
  get _tlsaBox () {
    delete this._tlsaBox;
    return this._tlsaBox = document.getElementById("tlsa-box");
  },
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
    delete this._tlsaBox;
    this._tlsaBox = document.getElementById("tlsa-box");
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
    this._tlsaBox.tooltipText = tooltip;
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

  hideTlsaPopup : function() {
    this._tlsaPopup.hidePopup();
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
    // Revert the contents of the location bar, see bug 406779
//    handleURLBarRevert(); // firefox 3.5 fixed
    	
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

