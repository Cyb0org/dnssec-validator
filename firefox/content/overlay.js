/* ***** BEGIN LICENSE BLOCK *****
Copyright 2010, 2011 CZ.NIC, z.s.p.o.

Authors: Zbynek Michl <zbynek.michl@nic.cz>

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

var Cc = Components.classes;
var Ci = Components.interfaces;

window.addEventListener("load", function() { dnssecExtension.init(); }, false);
window.addEventListener("unload", function() { dnssecExtension.uninit(); }, false);

// Temp function
/*
function sleep(delay) {
  var start = new Date().getTime();
  while (new Date().getTime() < start + delay);
}
*/

/* DNSSEC Validator's internal cache - shared with all window tabs */
var dnssecExtCache = {

  flushTimer: null,
  flushInterval: 0,     // in seconds (0 is for cache disable)
  data: null,

  init: function() {

    // Create new array for caching
    this.data = new Array();

    // Get cache flush interval
    this.getFlushInterval();

// Timer cache flushing is currently disabled
/*
    // Create the timer for cache flushing
    if (dnssecExtension.debugOutput) {
      dump(dnssecExtension.debugPrefix + 'Initializing flush timer with interval: '
           + this.flushInterval + ' s\n');
    }

    this.flushTimer = Components.classes["@mozilla.org/timer;1"]
                                .createInstance(Components.interfaces.nsITimer);

    // Define cache flush timer callback
    this.flushTimer.initWithCallback(
      function() {
        dnssecExtCache.delExpiredRecords();
      },
      this.flushInterval * 1000,
      Components.interfaces.nsITimer.TYPE_REPEATING_SLACK); // repeat periodically
*/
  },

  getFlushInterval: function() {
    this.flushInterval = dnssecExtPrefs.getInt("cacheflushinterval");
  },

  record: function(a, e4, e6, s) {
    this.addrs = a;        // resolved IPv4 and IPv6 address list
    this.expir = new function() {
      this.ipv4 = e4;      // time of IPv4 address expiration
      this.ipv6 = e6;      // time of IPv6 address expiration
    };
    this.state = s;        // result state
  },

  addRecord: function(name, addrs, expir4, expir6, state) {

    // Get current time
    const cur_t = new Date().getTime();

    // Record expiration time
    var exp4_t = cur_t + expir4 * 1000;   // expire4 is in seconds
    var exp6_t = cur_t + expir6 * 1000;   // expire6 is in seconds

    delete this.data[name];
    this.data[name] = new this.record(addrs, exp4_t, exp6_t, state);
  },

  getRecord: function(n) {
    const c = this.data;

    if (typeof c[n] != 'undefined') {
      return [c[n].addrs, c[n].expir.ipv4, c[n].expir.ipv6, c[n].state];
    }
    return ['', '', '', ''];
  },

  printContent: function() {
    var i = 0;
    var n;
    const c = this.data;
    const cur_t = new Date().getTime();
    var ttl4;
    var ttl6;

    dump(dnssecExtension.debugPrefix + 'Cache content:\n');

    for (n in c) {

      // compute TTL in seconds
      ttl4 = Math.round((c[n].expir.ipv4 - cur_t) / 1000);
      ttl6 = Math.round((c[n].expir.ipv6 - cur_t) / 1000);

      dump('r' + i + ': \"' + n + '\": \"' + c[n].addrs + '\"; '
           + c[n].expir.ipv4 + ' (' + ttl4 + '); ' + c[n].expir.ipv6 + ' ('
           + ttl6 + '); ' + c[n].state + '\n');
      i++;
    }
    dump('Total records count: ' + i + '\n');
  },

  delExpiredRecords: function() {
    const c = this.data;

    // Get current time
    const cur_t = new Date().getTime();

    if (dnssecExtension.debugOutput) {
      dump(dnssecExtension.debugPrefix + 'Flushing expired cache records...\n');
    }

    for (n in c) {
      if (cur_t > c[n].expir.ipv4 && cur_t > c[n].expir.ipv6) {
        if (dnssecExtension.debugOutput) dump(dnssecExtension.debugPrefix +
                                              'Deleting cache r: \"' + n + '\"\n');
        delete c[n];
      }
    }
  },

  delAllRecords: function() {

    if (dnssecExtension.debugOutput) {
      dump(dnssecExtension.debugPrefix + 'Flushing all cache records...\n');
    }

    delete this.data;
    this.data = new Array();
  },

  existsUnexpiredRecord: function(n, v4, v6) {
    const c = this.data;
    const cur_t = new Date().getTime();

    if (typeof c[n] != 'undefined') {
      return (( v4 &&  v6 && cur_t <= c[n].expir.ipv4 && cur_t <= c[n].expir.ipv6) ||
              ( v4 && !v6 && cur_t <= c[n].expir.ipv4) ||
              (!v4 &&  v6 && cur_t <= c[n].expir.ipv6)
              ? true : false);
    }
    return false;
  },

};


var dnssecExtUrlBarListener = {

  onLocationChange: function(aWebProgress, aRequest, aLocationURI)
  {
//    dump('Event: onLocationChange\n');
    dnssecExtension.processNewURL(aLocationURI);
  },
  onSecurityChange: function(aWebProgress, aRequest, aState)
  {
//    dump('Event: onSecurityChange\n');
  },
  onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus)
  {
//    dump('Event: onStateChange\n');
  },
  onProgressChange: function(aWebProgress, aRequest,
                             aCurSelfProgress, aMaxSelfProgress,
                             aCurTotalProgress, aMaxTotalProgress)
  {
//    dump('Event: onProgressChange\n');
  },
  onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage)
  {
//    dump('Event: onStatusChange\n');
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
    case "dnsserveraddr":   // Flush all cache records
      dnssecExtCache.delAllRecords();
      break;
    case "cacheflushinterval":
      dnssecExtCache.getFlushInterval();
      if (!dnssecExtCache.flushInterval) dnssecExtCache.delAllRecords();
      break;
    case "popupfgcolor":   // Change popup-window fore/background color
    case "popupbgcolor":
      dnssecExtension.getPopupColors();
      break;
    }
  }
};


var dnssecExtension = {
  dnssecExtID: "dnssec@nic.cz",
  debugOutput: false,
  debugPrefix: "dnssec: ",
  debugStartNotice: "----- DNSSEC resolving start -----\n",
  debugEndNotice: "----- DNSSEC resolving end -----\n",
  asyncResolve: false,
  timer: null,
  oldAsciiHost: null,

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

// Shared cache is temporarily disabled (only works for tabs)
/*
    // Shared cache - only one instance for all browser's windows
    if (!dnssecExt.storage.has("dnssecExtCache")) {

      // Create new instance
      dnssecExt.storage.set("dnssecExtCache", dnssecExtCache);
*/
      // Initialize cache and timer
      dnssecExtCache.init();
/*
    } else {

      // Use existing shared cache instance (overwrite default global instance)
      delete dnssecExtCache;
      dnssecExtCache = dnssecExt.storage.get("dnssecExtCache", null);
    }
*/

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

    // Reset resolving flag
    dnssecExtPrefs.setBool("resolvingactive", false);

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

      // Remember last hostname
//      this.oldAsciiHost = asciiHost;

      return;

    // Eliminate duplicated queries
    } else if (asciiHost == this.oldAsciiHost) {
      if (this.debugOutput) dump(' ...duplicated\n');
      return;
    }

    if (this.debugOutput) dump(' ...valid\n');

    // Check DNS security
    dnssecExtHandler.checkSecurity(asciiHost, utf8Host);

  },
/*
  onToolbarButtonCommand: function() {

  },
*/
};


/* Get security status through NPAPI plugin call or from cache */
var dnssecExtResolver = {

  // Called when request is not cached already
  doNPAPIvalidation: function(dn, resolvipv4, resolvipv6, aRecord) {

    // Plugin callback
    function NPAPIcallback(plug, resArr) {

      if (dnssecExtCache.flushInterval) { // do not cache if 0
        dnssecExtCache.addRecord(dn, resArr[0], resArr[1], resArr[2], resArr[3]);
      }
      dnssecExtResolver.setValidatedData(dn, resArr, aRecord);

    }

    // Get DNS resolver address(es)
    var nameserver = dnssecExtPrefs.getChar("dnsserveraddr");

    // Create variable to pass options
    var c = dnssecExtNPAPIConst;
    var options = 0;
    if (dnssecExtension.debugOutput) options |= c.NPAPI_INPUT_FLAG_DEBUGOUTPUT;
    if (dnssecExtPrefs.getBool("usetcp")) options |= c.NPAPI_INPUT_FLAG_USETCP;
    if (resolvipv4) options |= c.NPAPI_INPUT_FLAG_RESOLVIPV4;
    if (resolvipv6) options |= c.NPAPI_INPUT_FLAG_RESOLVIPV6;

    if (dnssecExtension.debugOutput)
      dump(dnssecExtension.debugPrefix + 'Validation parameters: \"'
           + dn + '; ' + options + '; ' + nameserver + '\"\n');

    // Call NPAPI validation
    try {
      // Get the binary plugin
      var dsp = document.getElementById("dnssec-plugin");

      if (!dnssecExtension.asyncResolve) {   // Synchronous NPAPI validation
        NPAPIcallback(null, dsp.Validate(dn, options, nameserver));
      } else {   // Asynchronous NPAPI validation
        dsp.ValidateAsync(dn, options, nameserver, NPAPIcallback);
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


  // Set appropriate security state
  setValidatedData: function(dn, resArr, aRecord) {

    var ext = dnssecExtension;

    if (ext.debugOutput) {
      dump(ext.debugPrefix + 'Queried domain name: ' + dn + '\n');
      dump(ext.debugPrefix + 'Getting return values: ' + resArr[3] + '; \"'
           + resArr[0] + '\"; ' + resArr[1] + '; ' + resArr[2] + '\n');
    }

    // Get validated data from cache or by NPAPI call
    var resaddrs = '';
    var res = -1;
    resaddrs = resArr[0];
    res = resArr[3];

    // Temporary deleting of expired cache records until
    // cache flush timer will be working
    if (dnssecExtCache.flushInterval) {
      dnssecExtCache.delExpiredRecords();
    }

    if (ext.debugOutput) {
      dnssecExtCache.printContent();
    }

    // Check browser's IP address(es)
    var addr = null;
    var invipaddr = false; // Browser's IP addresses are presumed as valid
    if (aRecord) {
      aRecord.rewind();
      while (aRecord.hasMore()) {   // Address list has another item

        addr = aRecord.getNextAddrAsString();

        // Check if each browser's address is present in DNSSEC address resolved list
        if (resaddrs.indexOf(' ' + addr + ' ') == -1) invipaddr = true;

        if (ext.debugOutput)
          dump(ext.debugPrefix + 'Checking browser IP: '
               + addr + '; address is invalid: ' + invipaddr + '\n');

        // No need to check more addresses
        if (invipaddr) break;
      }
    }

    // Set appropriate state if host name does not changed
    // during resolving process (tab has not been switched)
    if (dn == gBrowser.currentURI.asciiHost)
      dnssecExtHandler.setSecurityState(res, invipaddr);

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


  // Get validated data from cache or by NPAPI call
  getValidatedData: function(dn, v4, v6, aRecord) {

    var ext = dnssecExtension;
    var cache = dnssecExtCache;
    var resArr;

    if (cache.existsUnexpiredRecord(dn, v4, v6)) {
      if (ext.debugOutput)
        dump(ext.debugPrefix + 'Reading IPv4/IPv6 record "' + dn + '" from cache ('
             + v4 + '/' + v6 + ')...\n');
        this.setValidatedData(dn, cache.getRecord(dn), aRecord);
    } else {
      if (ext.debugOutput)
        dump(ext.debugPrefix + 'Using NPAPI to get IPv4/IPv6 record "' + dn
             + '" (' + v4 + '/' + v6 + ')...\n');
      this.doNPAPIvalidation(dn, v4, v6, aRecord);
    }
  },


  // Called when browser async host lookup completes
  onBrowserLookupComplete: function(dn, aRecord) {

    var resolvipv4 = false; // No IPv4 resolving as default
    var resolvipv6 = false; // No IPv6 resolving as default
    var addr = null;

    if (dnssecExtension.debugOutput)
      dump(dnssecExtension.debugPrefix + dnssecExtension.debugStartNotice);

    while (aRecord && aRecord.hasMore()) {   // Address list is not empty

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
      if (resolvipv4 && resolvipv6) break;
    }

    if (dnssecExtension.debugOutput)
      dump(dnssecExtension.debugPrefix + 'Browser uses IPv4/IPv6 resolving: \"'
           + resolvipv4 + '/' + resolvipv6 + '\"\n');

    // Resolve IPv4 if no version is desired
    if (!resolvipv4 && !resolvipv6) resolvipv4 = true;

    this.getValidatedData(dn, resolvipv4, resolvipv6, aRecord);

  },
};


/* Utility class to handle manipulations of the dnssec indicators in the UI */
var dnssecExtHandler = {

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
  // Authoritative domain is secured and has a valid signature, but no chain of trust
  DNSSEC_MODE_AUTH_DOMAIN_SIGNATURE_VALID         : "validAuthDomainSignature",
  // Domain is secured and has a valid signature, but browser's IP address is invalid
  DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID    : "validDomainSignatureInvIPaddr",
  // Domain is secured, but it has an invalid signature
  DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID            : "invalidDomainSignature",
  // Domain is secured, but signature and browser's IP address are invalid
  DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID  : "invalidDomainSignatureInvIPaddr",
  // No DNSSEC signature
  DNSSEC_MODE_DOMAIN_UNSECURED                    : "unsecuredDomain",
  // No NSEC/NSEC3 for non-existent domain name
  DNSSEC_MODE_NODOMAIN_UNSECURED                  : "unsecuredNoDomain",
  // Non-existent domain is secured and has a valid signature, but no chain of trust
  DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID            : "validNoDomainSignature",
  // Authoritative non-existent domain is secured and has a valid signature, but no chain of trust
  DNSSEC_MODE_AUTH_NODOMAIN_SIGNATURE_VALID       : "validAuthNoDomainSignature",
  // Non-existent domain is secured and has a valid signature, but browser's IP address is invalid
  DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_VALID  : "validNoDomainSignatureInvIPaddr",
  // Non-existent domain is secured, but it has an invalid signature
  DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID          : "invalidNoDomainSignature",
  // Non-existent domain is secured, but signature and browser's IP address are invalid
  DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_INVALID : "invalidNoDomainSignatureInvIPaddr",
  // Getting security status
  DNSSEC_MODE_ACTION : "actionDnssec",
  // Inaction status
  DNSSEC_MODE_INACTION : "inactionDnssec",
  // Error or unknown state occured
  DNSSEC_MODE_ERROR : "errorDnssec",

  // Tooltips
  DNSSEC_TOOLTIP_SECURED   : "securedTooltip",
  DNSSEC_TOOLTIP_UNSECURED : "unsecuredTooltip",
  DNSSEC_TOOLTIP_ACTION    : "actionTooltip",
  DNSSEC_TOOLTIP_ERROR     : "errorTooltip",

  // Cache the most recent hostname seen in checkSecurity
  _asciiHostName : null,
  _utf8HostName : null,

  // Smart getters
  get _securityLabel () {
    delete this._stringBundle;
    this._stringBundle = document.getElementById("dnssec-strings");

    delete this._securityLabel;
    this._securityLabel = {};

    this._securityLabel[this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED] =
      this._stringBundle.getString("dnssec.connection.domain.secured");
    this._securityLabel[this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED] =
      this._stringBundle.getString("dnssec.connection.domain.invipaddr.secured");
    this._securityLabel[this.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED] =
      this._stringBundle.getString("dnssec.connection.nodomain.secured");
    this._securityLabel[this.DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED] =
      this._stringBundle.getString("dnssec.connection.nodomain.invipaddr.secured");
    this._securityLabel[this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED] =
      this._stringBundle.getString("dnssec.connection.invsigdomain.secured");
    this._securityLabel[this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED] =
      this._stringBundle.getString("dnssec.connection.invsigdomain.invipaddr.secured");
    this._securityLabel[this.DNSSEC_MODE_DOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("dnssec.domain.signature.valid");
    this._securityLabel[this.DNSSEC_MODE_AUTH_DOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("dnssec.auth.domain.signature.valid");
    this._securityLabel[this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("dnssec.invipaddr.domain.signature.valid");
    this._securityLabel[this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("dnssec.domain.signature.invalid");
    this._securityLabel[this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("dnssec.invipaddr.domain.signature.invalid");
    this._securityLabel[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("dnssec.nodomain.signature.valid");
    this._securityLabel[this.DNSSEC_MODE_AUTH_NODOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("dnssec.auth.nodomain.signature.valid");
    this._securityLabel[this.DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_VALID] =
      this._stringBundle.getString("dnssec.invipaddr.nodomain.signature.valid");
    this._securityLabel[this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("dnssec.nodomain.signature.invalid");
    this._securityLabel[this.DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_INVALID] =
      this._stringBundle.getString("dnssec.invipaddr.nodomain.signature.invalid");
    this._securityLabel[this.DNSSEC_MODE_DOMAIN_UNSECURED] =
      this._stringBundle.getString("dnssec.domain.unsecured");
    this._securityLabel[this.DNSSEC_MODE_NODOMAIN_UNSECURED] =
      this._stringBundle.getString("dnssec.nodomain.unsecured");

    return this._securityLabel;
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

    return this._tooltipLabel;
  },
  get _dnssecPopup () {
    delete this._dnssecPopup;
    return this._dnssecPopup = document.getElementById("dnssec-popup");
  },
  get _dnssecBox () {
    delete this._dnssecBox;
    return this._dnssecBox = document.getElementById("dnssec-box");
  },
  get _dnssecPopupContentBox () {
    delete this._dnssecPopupContentBox;
    return this._dnssecPopupContentBox =
      document.getElementById("dnssec-popup-content-box");
  },
  get _dnssecPopupContentHost () {
    delete this._dnssecPopupContentHost;
    return this._dnssecPopupContentHost =
      document.getElementById("dnssec-popup-content-host");
  },
  get _dnssecPopupSecLabel () {
    delete this._dnssecPopupSecLabel;
    return this._dnssecPopupSecLabel =
      document.getElementById("dnssec-popup-security-detail-label");
  },

  // Build out a cache of the elements that we need frequently
  _cacheElements : function() {
    delete this._dnssecBox;
    this._dnssecBox = document.getElementById("dnssec-box");
  },

  // Set appropriate security state
  setSecurityState : function(state, invipaddr) {

    var c = dnssecExtNPAPIConst;

    switch (state) {
    case c.NPAPI_EXIT_CONNECTION_DOMAIN_SECURED:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_SECURED);
      } else {
        this.setMode(this.DNSSEC_MODE_CONNECTION_DOMAIN_INVIPADDR_SECURED);
      }
      break;
    case c.NPAPI_EXIT_CONNECTION_NODOMAIN_SECURED:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED);
      } else {
        this.setMode(this.DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED);
      }
      break;
    case c.NPAPI_EXIT_CONNECTION_INVSIGDOMAIN_SECURED:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED);
      } else {
        this.setMode(this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED);
      }
      break;
    case c.NPAPI_EXIT_DOMAIN_SIGNATURE_VALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_DOMAIN_SIGNATURE_VALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID);
      }
      break;
    case c.NPAPI_EXIT_AUTH_DOMAIN_SIGNATURE_VALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_AUTH_DOMAIN_SIGNATURE_VALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID);
      }
      break;
    case c.NPAPI_EXIT_DOMAIN_SIGNATURE_INVALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID);
      }
      break;
    case c.NPAPI_EXIT_NODOMAIN_SIGNATURE_VALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_VALID);
      }
      break;
    case c.NPAPI_EXIT_AUTH_NODOMAIN_SIGNATURE_VALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_AUTH_NODOMAIN_SIGNATURE_VALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_VALID);
      }
      break;
    case c.NPAPI_EXIT_NODOMAIN_SIGNATURE_INVALID:
      if (!invipaddr) {
        this.setMode(this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID);
      } else {
        this.setMode(this.DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_INVALID);
      }
      break;
    case c.NPAPI_EXIT_DOMAIN_UNSECURED:
      this.setMode(this.DNSSEC_MODE_DOMAIN_UNSECURED);
      break;
    case c.NPAPI_EXIT_NODOMAIN_UNSECURED:
      this.setMode(this.DNSSEC_MODE_NODOMAIN_UNSECURED);
      break;
    case c.NPAPI_EXIT_UNKNOWN:
    case c.NPAPI_EXIT_FAILED:
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
   * DNSSEC_MODE_* constants.
   */
  setMode : function(newMode) {
    if (!this._dnssecBox) {
      // No DNSSEC box means the DNSSEC box is not visible, in which
      // case there's nothing to do.
      return;
    } else if (newMode == this.DNSSEC_MODE_ACTION || // Close window for these states
               newMode == this.DNSSEC_MODE_ERROR) {
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
    case this.DNSSEC_MODE_CONNECTION_NODOMAIN_SECURED:
    // Non-existent domain and also connection are secured but browser's IP address is invalid
    case this.DNSSEC_MODE_CONNECTION_NODOMAIN_INVIPADDR_SECURED:
    // Connection is secured, but domain signature is invalid
    case this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_SECURED:
    // Connection is secured, but domain signature and browser's IP address are invalid
    case this.DNSSEC_MODE_CONNECTION_INVSIGDOMAIN_INVIPADDR_SECURED:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_SECURED];
      break;
    // Domain signature is valid
    case this.DNSSEC_MODE_DOMAIN_SIGNATURE_VALID:
    case this.DNSSEC_MODE_AUTH_DOMAIN_SIGNATURE_VALID:
    case this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_VALID:
    // Domain signature is invalid
    case this.DNSSEC_MODE_DOMAIN_SIGNATURE_INVALID:
    case this.DNSSEC_MODE_INVIPADDR_DOMAIN_SIGNATURE_INVALID:
    // Non-existent domain signature is valid
    case this.DNSSEC_MODE_NODOMAIN_SIGNATURE_VALID:
    case this.DNSSEC_MODE_AUTH_NODOMAIN_SIGNATURE_VALID:
    case this.DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_VALID:
    // Non-existent domain signature is invalid
    case this.DNSSEC_MODE_NODOMAIN_SIGNATURE_INVALID:
    case this.DNSSEC_MODE_INVIPADDR_NODOMAIN_SIGNATURE_INVALID:
    // No DNSSEC signature
    case this.DNSSEC_MODE_DOMAIN_UNSECURED:
    case this.DNSSEC_MODE_NODOMAIN_UNSECURED:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_UNSECURED];
      break;
    // Getting security status
    case this.DNSSEC_MODE_ACTION:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_ACTION];
      break;
    // An error occured
    case this.DNSSEC_MODE_ERROR:
      tooltip = this._tooltipLabel[this.DNSSEC_TOOLTIP_ERROR];
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
    this._dnssecPopupSecLabel.textContent = this._securityLabel[newMode];

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

    // No popup window while...
    if (this._dnssecBox &&
       (this._dnssecBox.className == this.DNSSEC_MODE_ACTION || // getting security status
        this._dnssecBox.className == this.DNSSEC_MODE_ERROR))   // get an error
      return;

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