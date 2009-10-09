/*
https://developer.mozilla.org/en/Code_snippets/Progress_Listeners
https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsIURI
*/

// Temp function
function sleep(delay)
{
  var start = new Date().getTime();
  while (new Date().getTime() < start + delay);
}


var dnssecExt_urlBarListener = {

  onLocationChange: function(aWebProgress, aRequest, aLocationURI)
  {
//    dump('onLocationChange1\n');
    dnssecExtension.processNewURL(aLocationURI);
  },
  onSecurityChange: function(aWebProgress, aRequest, aState)
  {
//    dump('onSecurityChange\n');
  },
  onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus)
  {
//    dump('onStateChange\n');
  },
  onProgressChange: function(aWebProgress, aRequest,
                             aCurSelfProgress, aMaxSelfProgress,
                             aCurTotalProgress, aMaxTotalProgress)
  {
//    dump('onProgressChange\n');
  },
  onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage)
  {
//    dump('onStatusChange\n');
  }
};

var dnssecExtension = {
  oldHost: null,
  
  init: function() {

    // Set unknown security state
    getDnssecHandler().setSecurityState(Ci.dnssecIValidator.XPCOM_EXIT_UNSECURED);

    // Listen for webpage loads
    gBrowser.addProgressListener(dnssecExt_urlBarListener,
        Components.interfaces.nsIWebProgress.NOTIFY_LOCATION);
  },
  
  uninit: function() {
    gBrowser.removeProgressListener(dnssecExt_urlBarListener);
  },

  processNewURL: function(aLocationURI) {
//    dump('onLocationChange2\n');

    var host = null;
    // try to prevent strange NS_ERRORS from StringBundle...
    try {
      host = aLocationURI.host;
    } catch(ex) {
//      dump(ex);
    }


    if ((host == null) || (host.search(/^[A-Za-z0-9]+([-_\.]?[A-Za-z0-9])*\.[A-Za-z]{2,4}$/) == -1)) {   // test for valid hostname
      // Set unknown security state
      getDnssecHandler().setSecurityState(Ci.dnssecIValidator.XPCOM_EXIT_UNSECURED);
      this.oldHost = host;
      return;
    } else if (host == this.oldHost) {   // test for hostname change
      return;
    }

    // check DNS security
    getDnssecHandler().checkSecurity(host);

    // remember last hostname
    this.oldHost = host;
  },

/*
  onToolbarButtonCommand: function() {


  },
*/

};

window.addEventListener("load", function() {dnssecExtension.init()}, false);
window.addEventListener("unload", function() {dnssecExtension.uninit()}, false);




/**
 * Utility class to handle manipulations of the dnssec indicators in the UI
 */

function DnssecHandler() {
  this._stringBundle = document.getElementById("dnssec-strings");
  this._staticStrings = {};
  this._staticStrings[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.secured")
  };
  this._staticStrings[this.DNSSEC_MODE_DOMAIN_SIGNATURE_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.unsecured")
  };
  this._staticStrings[this.DNSSEC_MODE_DOMAIN_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.unsecured")
  };
  this._staticStrings[this.DNSSEC_MODE_UNSECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.unsecured")
  };

  this._cacheElements();
}

DnssecHandler.prototype = {

  // Mode strings used to control CSS display
  DNSSEC_MODE_CONNECTION_DOMAIN_SECURED : "securedConnectionDomain", // Domain and also connection are secured
  DNSSEC_MODE_DOMAIN_SIGNATURE_SECURED  : "securedDomainSignature",  // Domain is secured and has a valid signature, but no chain of trust
  DNSSEC_MODE_DOMAIN_SECURED            : "securedDomain",           // Only domain is secured
  DNSSEC_MODE_UNSECURED                 : "unsecuredDnssec",         // No trusted security information

  // Cache the most recent hostname seen in checkSecurity
  _hostName : null,

  // Build out a cache of the elements that we need frequently
  _cacheElements : function() {
    this._dnssecPopup = document.getElementById("dnssec-popup");
    this._dnssecBox = document.getElementById("dnssec-box");
    this._dnssecPopupContentBox = document.getElementById("dnssec-popup-content-box");
    this._dnssecPopupContentHost = document.getElementById("dnssec-popup-content-host");
    this._dnssecPopupSecLabel = document.getElementById("dnssec-popup-security-detail-label");
  },

  /* Set appropriate security state */
  setSecurityState : function(state) {

    switch (state) {
    case Ci.dnssecIValidator.XPCOM_EXIT_DOMAIN_CONNECTION_SECURED:
      this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED);
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_DOMAIN_SIGNATURE_SECURED:
      this.setMode(this.DNSSEC_MODE_DOMAIN_SIGNATURE_SECURED);
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_DOMAIN_SECURED:
      this.setMode(this.DNSSEC_MODE_DOMAIN_SECURED);
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_UNSECURED:
    default:
      this.setMode(this.DNSSEC_MODE_UNSECURED);
      this._dnssecBox.hidden = true;
      break;
    }

  },

  // Determine the security of the domain and connection and, if necessary,
  // update the UI to reflect this. Intended to be called by onLocationChange.
  checkSecurity : function(host) {

    // Set unknown security state
//    this.setSecurityState(Ci.dnssecIValidator.XPCOM_EXIT_UNSECURED);

    this._hostName = host;
    var cls = Components.classes['@mozilla.org/network/dns-service;1'];
    var iface = Components.interfaces.nsIDNSService;
    var dns = cls.getService(iface);

    var dnslistener = {
      // Called when async host lookup completes
      onLookupComplete: function(aRequest, aRecord, aStatus) {

        var ipver = 4; // Default address if resolving fails

        if (aRecord && aRecord.hasMore()) {   // Address list is not empty

          var addr = aRecord.getNextAddrAsString();
          dump('Browser address: ' + addr + '\n');

          // Check IP version
          if (addr.indexOf(":") != -1) {
            // ipv6
            ipver = 6;
          } else if (addr.indexOf(".") != -1) {
            // ipv4
            ipver = 4;
          }

        }

        dump('Browser IP ver: ' + ipver + '\n');

        /* XPCOM validation call */
        try {
          netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
          const cid = "@nic.cz/dnssecValidator;1";
          var obj = Components.classes[cid].createInstance();
          obj = obj.QueryInterface(Components.interfaces.dnssecIValidator);
        } catch (err) {
          dump(err + '\n');
          return;
        }

        var res = obj.Validate(getDnssecHandler()._hostName, ipver);
        dump('XPCOM retval: ' + res + '\n');

        // Set appropriate state
        getDnssecHandler().setSecurityState(res);

      }
    };

    // Thread on which onLookupComplete should be called
    var th;
    if (Components.classes["@mozilla.org/event-queue-service;1"]) {
      const EQS = Components.classes["@mozilla.org/event-queue-service;1"].getService(Components.interfaces.nsIEventQueueService);
      th = EQS.getSpecialEventQueue(EQS.CURRENT_THREAD_EVENT_QUEUE);
    } else {
      th = Components.classes["@mozilla.org/thread-manager;1"].getService().mainThread;
    }

    // Get browser's IP address(es) that uses to connect to the remote site.
    // Uses browser's internal resolver cache
//    dump('HOST: ' +  host + '\n');
    dns.asyncResolve(host, 0, dnslistener, th); // Ci.nsIDNSService.RESOLVE_BYPASS_CACHE

  },
  
  /**
   * Return the eTLD+1 version of the current hostname
   */
  getEffectiveHost : function() {
    // Cache the eTLDService if this is our first time through
    if (!this._eTLDService)
      this._eTLDService = Cc["@mozilla.org/network/effective-tld-service;1"]
                         .getService(Ci.nsIEffectiveTLDService);
    try {
      return this._eTLDService.getBaseDomainFromHost(this._hostName);
    } catch (e) {
      // If something goes wrong (e.g. hostname is an IP address) just fail back
      // to the full domain.
      return this._hostName;
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
    if (newMode == this.DNSSEC_MODE_DOMAIN_SECURED) {
      // Cache the override service the first time we need to check it
      if (!this._overrideService)
        this._overrideService = Components.classes["@mozilla.org/security/certoverride;1"]
                                          .getService(Components.interfaces.nsICertOverrideService);

      // Domain is secured, but connection not
      var tooltip = this._stringBundle.getString("dnssec.tooltip.unsecured");
      
    }
    else if (newMode == this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED) {
      // Both domain and connection are secured
      tooltip = this._stringBundle.getString("dnssec.tooltip.secured");
    }
    else {
      // Unknown
      tooltip = this._stringBundle.getString("dnssec.tooltip.unsecured");
    }
    
    // Push the appropriate strings out to the UI
    this._dnssecBox.tooltipText = tooltip;
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
    
    // Set the static strings up front
    this._dnssecPopupSecLabel.textContent = this._staticStrings[newMode].security_label;
    
    if (newMode == this.DNSSEC_MODE_DOMAIN_SECURED) {
//      var host = this.getEffectiveHost();
      var host = this._hostName;
    }
    else if (newMode == this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED) {
//      host = this.getEffectiveHost();
      host = this._hostName;
    }
    else {
      // This string will be hidden in CSS anyhow
      host = "";
    }
    
    // Push the appropriate strings out to the UI
    this._dnssecPopupContentHost.textContent = host;
  },

  hideDnssecPopup : function() {
    this._dnssecPopup.hidePopup();
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

    // Revert the contents of the location bar, see bug 406779
//    handleURLBarRevert(); // firefox 3.5 fixed

    // Make sure that the display:none style we set in xul is removed now that
    // the popup is actually needed
    this._dnssecPopup.hidden = false;
    
    // Tell the popup to consume dismiss clicks, to avoid bug 395314
    this._dnssecPopup.popupBoxObject
        .setConsumeRollupEvent(Ci.nsIPopupBoxObject.ROLLUP_CONSUME);

    // Update the popup strings
    this.setPopupMessages(this._dnssecBox.className);

    // Now open the popup, anchored off the primary chrome element
    this._dnssecPopup.openPopup(this._dnssecBox, 'after_start');
  }
};

var gDnssecHandler;

/**
 * Returns the singleton instance of the dnssec handler class. Should always be
 * used instead of referencing the global variable directly or creating new instances
 */
function getDnssecHandler() {
  if (!gDnssecHandler)
    gDnssecHandler = new DnssecHandler();
  return gDnssecHandler;
}
