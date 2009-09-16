/*
https://developer.mozilla.org/en/Code_snippets/Progress_Listeners
https://developer.mozilla.org/en/XPCOM_Interface_Reference/nsIURI
*/

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

    getDnssecHandler()._dnssecBox.hidden = true;

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

    // test for hostname change
    if (host == this.oldHost) {
      return;
    }

    // check DNS security
    getDnssecHandler().checkSecurity(host);

    // remember last hostname
    this.oldHost = host;
  }
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


  // Determine the security of the domain and connection and, if necessary,
  // update the UI to reflect this. Intended to be called by onSecurityChange.
  checkSecurity : function(host) {

    this._hostName = host;

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

    var res = obj.Validate(this._hostName, 4);
    dump('retval: ' + res + '\n');

    /* set appropriate state */
    switch (res) {
    case 0:
      this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED);
      this._dnssecBox.hidden = false;
      break;
    case 1:
      this.setMode(this.DNSSEC_MODE_DOMAIN_SECURED);
      this._dnssecBox.hidden = false;
      break;
    case 2:
    default:
      this.setMode(this.DNSSEC_MODE_UNSECURED);
      this._dnssecBox.hidden = true;
      break;
    }

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
      var host = this.getEffectiveHost();
    }
    else if (newMode == this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED) {
      host = this.getEffectiveHost();
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
