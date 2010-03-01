/* ***** BEGIN LICENSE BLOCK *****
Copyright 2010 CZ.NIC, z.s.p.o.

This file is part of DNSSEC Validator Add-on.

DNSSEC Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

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
  dnssecExtID: "dnssec@nic.cz",
  debugOutput: false,
  debugPrefix: "dnssec: ",
  debugStartNotice: "----- DNSSEC debug start -----\n",
  debugEndNotice: "----- DNSSEC debug end -----\n",
  oldHost: null,

  init: function() {

    // Enable debugging information on stdout if desired
    if (dnssecExtPrefs.getBool("debugoutput")) this.debugOutput = true;

    // Set unknown security state
    getDnssecHandler().setSecurityState(Ci.dnssecIValidator.XPCOM_EXIT_UNSECURED, -1);

    // Listen for webpage loads
    gBrowser.addProgressListener(dnssecExt_urlBarListener,
        Components.interfaces.nsIWebProgress.NOTIFY_LOCATION);

    // Get current extension version
    var dnssecExtVersion = Components.classes["@mozilla.org/extensions/manager;1"]
                           .getService(Components.interfaces.nsIExtensionManager)
                           .getItemForID(this.dnssecExtID)
                           .version.toString();

    // Get saved extension version
    var dnssecExtOldVersion = dnssecExtPrefs.getChar("version");

    // Display initialisation page if appropriate
    if (dnssecExtVersion != dnssecExtOldVersion) {
      dnssecExtPrefs.setChar("version", dnssecExtVersion);  // Save new version
      try {
        setTimeout(function() {
          if (gBrowser) {
            gBrowser.selectedTab = gBrowser.addTab('http://labs.nic.cz/dnssec-validator/');
          }
        }, 100);
      } catch(ex) {
//        dump(ex);
      }
    }
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
      getDnssecHandler().setSecurityState(Ci.dnssecIValidator.XPCOM_EXIT_UNSECURED, -1);
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
    security_label: this._stringBundle.getString("dnssec.connection.domain.secured")
  };
  this._staticStrings[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.domain.invipaddr.secured")
  };
  this._staticStrings[this.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.nodomain.secured")
  };
  this._staticStrings[this.DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.nodomain.invipaddr.secured")
  };
  this._staticStrings[this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.invsigdomain.secured")
  };
  this._staticStrings[this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED] = {
    security_label: this._stringBundle.getString("dnssec.connection.invsigdomain.invipaddr.secured")
  };
  this._staticStrings[this.DNSSEC_MODE_DOMAIN_SIGNATURE_VALID] = {
    security_label: this._stringBundle.getString("dnssec.domain.signature.valid")
  };
  this._staticStrings[this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID] = {
    security_label: this._stringBundle.getString("dnssec.invipaddr.domain.signature.valid")
  };
  this._staticStrings[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] = {
    security_label: this._stringBundle.getString("dnssec.domain.signature.invalid")
  };
  this._staticStrings[this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID] = {
    security_label: this._stringBundle.getString("dnssec.invipaddr.domain.signature.invalid")
  };

  this._cacheElements();
}

DnssecHandler.prototype = {

  // Mode strings used to control CSS display

  // Domain and also connection are secured
  DNSSEC_MODE_CONNECTION_DOMAIN_SECURED           : "securedConnectionDomain",
  // Domain and also connection are secured but browser's IP address is invalid
  DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED : "securedConnectionDomainInvIPaddr",
  // Connection is secured, but domain name does not exist
  DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED         : "securedConnectionNoDomain",
  // Non-existent domain and also connection are secured but browser's IP address is invalid
  DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED : "securedConnectionNoDomainInvIPaddr",
  // Connection is secured, but domain name signature is invalid
  DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED     : "securedConnectionInvSigDomain",
  // Connection is secured, but domain name signature and browser's IP address are invalid
  DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED : "securedConnectionInvSigDomainInvIPaddr",
  // Domain is secured and has a valid signature, but no chain of trust
  DNSSEC_MODE_DOMAIN_SIGNATURE_VALID              : "validDomainSignature",
  // Domain is secured and has a valid signature, but browser's IP address is invalid
  DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID    : "validDomainSignatureInvIPaddr",
  // Domain is secured, but it has an invalid signature
  DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID            : "invalidDomainSignature",
  // Domain is secured, but signature and browser's IP address are invalid
  DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID  : "invalidDomainSignatureInvIPaddr",
  // No trusted security information
  DNSSEC_MODE_UNSECURED                           : "unsecuredDnssec",

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
  setSecurityState : function(state, invipaddr) {

    switch (state) {
    case Ci.dnssecIValidator.XPCOM_EXIT_CONNECTION_DOMAIN_SECURED:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED);
      } else {
        this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED);
      }
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_CONNECTION_NODOMAIN_SECURED:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED);
      } else {
        this.setMode(this.DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED);
      }
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_CONNECTION_INVSIGDOMAIN_SECURED:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED);
      } else {
        this.setMode(this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED);
      }
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_DOMAIN_SIGNATURE_VALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_DOMAIN_SIGNATURE_VALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID);
      }
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_DOMAIN_SIGNATURE_INVALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID);
      }
      this._dnssecBox.hidden = false;
      break;
    case Ci.dnssecIValidator.XPCOM_EXIT_UNSECURED:
    case Ci.dnssecIValidator.XPCOM_EXIT_UNKNOWN:
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

        var resolvipv4 = false; // No IPv4 resolving as default
        var resolvipv6 = false; // No IPv6 resolving as default
        var addr = null;

        if (dnssecExtension.debugOutput) dump (dnssecExtension.debugStartNotice);

        while (aRecord && aRecord.hasMore()) {   // Address list is not empty

          addr = aRecord.getNextAddrAsString();
//          if (dnssecExtension.debugOutput)
//            dump(dnssecExtension.debugPrefix + 'Browser address: ' + addr + '\n');

          // Check IP version
          if (addr.indexOf(":") != -1) {
            // ipv6
            resolvipv6 = true;
          } else if (addr.indexOf(".") != -1) {
            // ipv4
            resolvipv4 = true;
          }

          // No need to check more addresses
          if (resolvipv4 && resolvipv6) break;
        }

        if (dnssecExtension.debugOutput)
          dump(dnssecExtension.debugPrefix + 'Browser uses IPv4/IPv6 resolving: \"'
               + resolvipv4 + '/' + resolvipv6 + '\"\n');

        /* Use validator's XPCOM interface */
        try {
          netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
          const cid = "@nic.cz/dnssecValidator;1";
          var obj = Components.classes[cid].createInstance();
          obj = obj.QueryInterface(Components.interfaces.dnssecIValidator);
        } catch (ex) {
          dump(ex + '\n');
          return;
        }

        // Get DNS resolver address(es)
        var nameserver = dnssecExtPrefs.getChar("dnsserveraddr");

        // Create variable to pass options
        var options = 0;
        if (dnssecExtension.debugOutput) options |= Ci.dnssecIValidator.XPCOM_INPUT_FLAG_DEBUGOUTPUT;
        if (dnssecExtPrefs.getBool("usetcp")) options |= Ci.dnssecIValidator.XPCOM_INPUT_FLAG_USETCP;
        if (resolvipv4) options |= Ci.dnssecIValidator.XPCOM_INPUT_FLAG_RESOLVIPV4;
        if (resolvipv6) options |= Ci.dnssecIValidator.XPCOM_INPUT_FLAG_RESOLVIPV6;

        if (dnssecExtension.debugOutput)
          dump(dnssecExtension.debugPrefix + 'Validation parameters: \"'
               + getDnssecHandler()._hostName + '; ' + options + '; ' + nameserver + '\"\n');

        // Call XPCOM validation
        var resaddrs = {};
        var res = obj.Validate(getDnssecHandler()._hostName, options, nameserver, resaddrs);

        if (dnssecExtension.debugOutput)
          dump(dnssecExtension.debugPrefix + 'Getting return values: \"' + res + '; '
               + resaddrs.value + '\"\n');


        // Temporarily checking only first address
        var invipaddr = false; // Browser's IP addresses are presumed as valid
        if (aRecord) {
          aRecord.rewind();
          while (aRecord.hasMore()) {   // Address list has another item

            addr = aRecord.getNextAddrAsString();

            // Check if each browser's address is present in DNSSEC address resolved list
            if (resaddrs.value.indexOf(addr) == -1) invipaddr = true;

            if (dnssecExtension.debugOutput)
              dump(dnssecExtension.debugPrefix + 'Checking browser IP: '
                   + addr + '; address is invalid: ' + invipaddr + '\n');

            // No need to check more addresses
            if (invipaddr) break;
          }
        }

        // Set appropriate state
        getDnssecHandler().setSecurityState(res, invipaddr);

        if (dnssecExtension.debugOutput) dump (dnssecExtension.debugEndNotice);

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

    var tooltip;

    switch (newMode) {
    // Both domain and connection are secured
    case this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED:
    // Domain and also connection are secured but browser's IP address is invalid
    case this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED:
    // Both non-existent domain and connection are secured
    case this.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED:
    // Non-existent domain and also connection are secured but browser's IP address is invalid
    case this.DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED:
    // Connection is secured, but domain signature is invalid
    case this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED:
    // Connection is secured, but domain signature and browser's IP address are invalid
    case this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED:
      tooltip = this._stringBundle.getString("dnssec.tooltip.secured");
      break;
    // Domain signature is valid
    case this.DNSSEC_MODE_DOMAIN_SIGNATURE_VALID:
    case this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID:
    // Domain signature is invalid
    case this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID:
    case this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID:
      tooltip = this._stringBundle.getString("dnssec.tooltip.unsecured");
      break;
    // Unknown
    default:
      tooltip = "";
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

    // Push the appropriate strings out to the UI
    this._dnssecPopupContentHost.textContent = this._hostName;
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
