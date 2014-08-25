/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator 2 Add-on.

DNSSEC/TLSA Validator 2 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator 2 Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC/TLSA Validator 2 Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

window.addEventListener("load", function() { cz.nic.extension.daneExtension.init();}, false);
window.addEventListener("unload", function() {cz.nic.extension.daneExtension.uninit();}, false);

// **********************************************
/* Observe preference changes */
// **********************************************
cz.nic.extension.daneExtPrefObserver = {

_branch:
	null,

register:
	function() {
		var prefService = Components.classes["@mozilla.org/preferences-service;1"]
		.getService(Components.interfaces.nsIPrefService);

		// Add the observer
		this._branch = prefService.getBranch(cz.nic.extension.dnssecExtPrefs.prefBranch);
		this._branch.QueryInterface(Components.interfaces.nsIPrefBranch);
		this._branch.addObserver("", this, false);
	},

unregister:
	function() {
		if (!this._branch) return;
		this._branch.removeObserver("", this);
	},

observe:
	function(aSubject, aTopic, aData) {
		if (aTopic != "nsPref:changed") return;
	
		// aSubject is the nsIPrefBranch we're observing (after appropriate QI)
		// aData is the name of the pref that's been changed (relative to aSubject)
		switch (aData) {
		case "danedebug":     // Change debugging to stdout
			cz.nic.extension.daneExtension.getDebugOutputFlag();
			break;
		case "popupfgcolor":   // Change popup-window fore/background color
		case "popupbgcolor":
			cz.nic.extension.daneExtension.getPopupColors();
			break;
		}
	}
};

// **********************************************************************
/* TLSA Validator's internal cache - shared with all window tabs */
// **********************************************************************
// expirate time of one item in the cache [seconds]

cz.nic.extension.tlsaExtCache = {

CACHE_ITEM_EXPIR : 600,
data: null,

init:
	function() {
		// Create new array for caching
		this.data = new Array();
		CACHE_ITEM_EXPIR = cz.nic.extension.dnssecExtPrefs.getInt("cacheexpir");
	},


record:
	function(tlsaresult, block, expir) {
		this.state = tlsaresult;  // tlsa result
		this.block = block;    // blocked ?
		this.expir = expir;    // expir time
	},

addRecord:
	function(domain, tlsaresult, block) {
		// Get current time
		const cur_t = new Date().getTime();
		CACHE_ITEM_EXPIR = cz.nic.extension.dnssecExtPrefs.getInt("cacheexpir");
		var expir = cur_t + CACHE_ITEM_EXPIR * 1000;
		delete this.data[domain];
		this.data[domain] = new this.record(tlsaresult, block, expir);
	},

getRecord:
	function(n) {
		const c = this.data;

		if (typeof c[n] != 'undefined') {
			return [c[n].state, c[n].block, c[n].expir];
		}
		return ['', '', ''];
	},

printContent:
	function() {

		var i = 0;
		var n;
		const c = this.data;

		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(cz.nic.extension.tlsaValidator.DANE_DEBUG_PRE + 'Cache content:\n');
		}

		for (n in c) {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.tlsaValidator.DANE_DEBUG_PRE +'      r' +
				     i + ': \"' + n + '\": \"' + c[n].state + '\"; ' +
				     c[n].block + '\": \"' + c[n].expir + '\"\n');
			}
			i++;
		}

		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(cz.nic.extension.tlsaValidator.DANE_DEBUG_PRE + 'Total records count: ' + i + '\n');
		}
	},

delAllRecords:
	function() {

		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(cz.nic.extension.tlsaValidator.DANE_DEBUG_PRE + 'Flushing all cache records...\n');
		}
		delete this.data;
		this.data = new Array();
	},
};

// **********************************************************************
/* daneExtUrlBarListener: observe the browser events a securtiy changes*/
// **********************************************************************
cz.nic.extension.daneExtUrlBarListener = {

onLocationChange:
	function(aWebProgress, aRequest, aLocationURI) {
		//dump('BrowserTLSA: onLocationChange()\n');
		var uri = null;
		uri = window.gBrowser.currentURI;
		cz.nic.extension.tlsaValidator.processNewURL(aRequest, uri);
	},

onSecurityChange:
	function(aWebProgress, aRequest, aState) {
		//dump('BrowserTLSA: onSecurityChange(' +aState + ')\n');
		var uri = null;
		uri = window.gBrowser.currentURI;
		cz.nic.extension.tlsaValidator.processNewURL(aRequest, uri);
	},

onStateChange:
	function(aWebProgress, aRequest, aStateFlags, aStatus) {
		//dump('Browser: onStateChange\n');
	},

onProgressChange:
	function(aWebProgress, aRequest,
	aCurSelfProgress, aMaxSelfProgress,
	aCurTotalProgress, aMaxTotalProgress) {
		//dump('Browser: onProgressChange()\n');
	},

onStatusChange:
	function(aWebProgress, aRequest, aStatus, aMessage) {
		//dump('Browser: onStatusChange()\n');
	}
};


// **************************************************************
// --------------------------------------------------------------
/* cz.nic.extension.daneExtension */
// --------------------------------------------------------------
// **************************************************************
cz.nic.extension.daneExtension = {

debugOutput: false,
debugPrefix: "  dane: ",
DANE_DEBUG_PRE: "  dane: ",
DANE_DEBUG_POST: "\n",
oldAsciiHost: null,

//---------------------------------------------------------
// initialization of TLSA plugin
//---------------------------------------------------------
init:
	function() {

		// Enable debugging information on stdout if desired
		this.getDebugOutputFlag();

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Start of add-on\n');
		}

		try {
			var dsp = document.getElementById("dane-tlsa-plugin");
			dsp.TLSACacheInit();
			cz.nic.extension.tlsaExtHandler.setMode(cz.nic.extension.tlsaExtHandler.DANE_MODE_INACTION);
		} catch(e) {
			cz.nic.extension.tlsaExtHandler.setMode(cz.nic.extension.tlsaExtHandler.DANE_MODE_ERROR_GENERIC);
		}

		// Register preferences observer
		cz.nic.extension.daneExtPrefObserver.register();
		// Change popup-window fore/background color if desired
		this.getPopupColors();

		this.registerObserver("http-on-examine-response");
		//this.registerObserver("http-on-examine-cached-response");

		// Listen for webpage events
		gBrowser.addProgressListener(cz.nic.extension.daneExtUrlBarListener);

		cz.nic.extension.tlsaExtCache.init();

		var clearcache = cz.nic.extension.dnssecExtPrefs.getBool("clearcache");
		if (clearcache) {
			this.clearMFcache('all');
		}

	},

getService:
	function(service_type) {
		return Components.classes["@mozilla.org/network/cache-service;1"]
		       .getService(Components.interfaces.nsICacheService);
	},

clearMFcache :
	function(cache) {
		if (cache == 'all') {
			this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_ON_DISK);
			this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_IN_MEMORY);
			//this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_OFFLINE);
		} else {
			if (cache == 'disk') {
				this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_ON_DISK);
			}
			if (cache == 'memory') {
				this.getService('cache').evictEntries(Components.interfaces.nsICache.STORE_IN_MEMORY);
			}
		}

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Clear main MF cache\n');
		}
	},

getDebugOutputFlag:
	function() {
		this.debugOutput = cz.nic.extension.dnssecExtPrefs.getBool("danedebug");
	},

getPopupColors:
	function() {
		var dpw = document.getElementById("dnssec-popup-container");
		dpw.style.color = cz.nic.extension.dnssecExtPrefs.getChar("popupfgcolor");
		dpw.style.backgroundColor = cz.nic.extension.dnssecExtPrefs.getChar("popupbgcolor");
	},

//---------------------------------------------------------
// uninitialization of TLSA plugin
//---------------------------------------------------------
uninit:
	function() {

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Stop of add-on\n');
		}

		gBrowser.removeProgressListener(cz.nic.extension.daneExtUrlBarListener);

		// Unregister preferences observer
		cz.nic.extension.daneExtPrefObserver.unregister();

		this.unregisterObserver("http-on-examine-response");
		//this.unregisterObserver("http-on-examine-cached-response");

		var dsp = document.getElementById("dane-tlsa-plugin");
		dsp.TLSACacheFree();

		cz.nic.extension.tlsaExtCache.delAllRecords();

		if (this.debugOutput) {
			dump(this.debugPrefix + 'Clear Cache...\n');
		}
	},

//---------------------------------------------------------
// Register observe service for http/https request catching
//---------------------------------------------------------
registerObserver:
	function(topic) {
		var observerService = Components.classes["@mozilla.org/observer-service;1"]
		                      .getService(Components.interfaces.nsIObserverService);
		observerService.addObserver(this, topic, false);
	},

//---------------------------------------------------------
// Unregister observe service
//---------------------------------------------------------
unregisterObserver:
	function(topic) {
		var observerService = Components.classes["@mozilla.org/observer-service;1"]
		                      .getService(Components.interfaces.nsIObserverService);
		observerService.removeObserver(this, topic);
	},

//---------------------------------------------------------
// Observe http/https cannel, for TLSA validation
// is call when http/https request was generated
//---------------------------------------------------------
observe:
	function(channel, topic, data) {

		var freecache = cz.nic.extension.dnssecExtPrefs.getBool("cachefree");
		if (freecache) {
			cz.nic.extension.tlsaExtCache.delAllRecords();
			cz.nic.extension.dnssecExtPrefs.setBool("cachefree", false);
		}

		var checkall = cz.nic.extension.dnssecExtPrefs.getBool("checkhttpsrequestsonpages");
		if (checkall) {

			if (topic == "http-on-examine-response") {

				var tlsaonoff = cz.nic.extension.dnssecExtPrefs.getBool("tlsaenable");
				if (tlsaonoff) {

					var Cc = Components.classes, Ci = Components.interfaces;
					channel.QueryInterface(Ci.nsIHttpChannel);
					var url = channel.URI.spec;
					var host = channel.URI.host;
					var hostport = channel.URI.hostPort;
					var si = channel.securityInfo;
					if (!si) return;

					if (cz.nic.extension.tlsaValidator.is_in_domain_list(host)) {

						var current_time = new Date().getTime();
						var cacheitem = cz.nic.extension.tlsaExtCache.getRecord(hostport);
						if (cacheitem[0] != '') {
							if (cacheitem[1] == "no") {
								if (cacheitem[2] > current_time) {
									return;
								}
							}
						}

						if (cz.nic.extension.daneExtension.debugOutput) {
							dump(cz.nic.extension.tlsaValidator.DANE_DEBUG_PRE + "http-on-examine-response -> "
							     + hostport + cz.nic.extension.tlsaValidator.DANE_DEBUG_POST);
						}

						if (cz.nic.extension.daneExtension.debugOutput) {
							dump(this.DANE_DEBUG_PRE + 'Validate this domain: yes'+ this.DANE_DEBUG_POST);
						}

						if (cz.nic.extension.daneExtension.debugOutput) {
							dump(this.DANE_DEBUG_PRE
							     + 'Scheme: https; ASCII domain name: "' + hostport + '"'+ this.DANE_DEBUG_POST);
						}


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

						var port = (channel.URI.port == -1) ? 443 : channel.URI.port;
						cz.nic.extension.tlsaValidator.check_tlsa_https(channel, cert, browser, host, port, "tcp", url, hostport);

					}
					else if (cz.nic.extension.daneExtension.debugOutput)
						dump(this.DANE_DEBUG_PRE + 'Validate this domain: no'+ this.DANE_DEBUG_POST);
				}//tlsaoff
				else {
					if (cz.nic.extension.daneExtension.debugOutput) {
						dump(this.DANE_DEBUG_PRE + 'TLSA Validation is disable'+ this.DANE_DEBUG_POST);
					}
				}
				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(cz.nic.extension.tlsaValidator.DANE_DEBUG_POST);
				}
			} //if
		}//if
	},
};//class


// **************************************************************
// cz.nic.extension.tlsaValidator class
// **************************************************************
cz.nic.extension.tlsaValidator = {

ALLOW_TYPE_01: 1,
ALLOW_TYPE_23: 2,
DANE_DEBUG_PRE: "  dane: ",
DANE_DEBUG_POST: "\n",

overrideService:
	Components.classes["@mozilla.org/security/certoverride;1"]
	.getService(Components.interfaces.nsICertOverrideService),

//---------------------------------------------------------
// return true if domain name or TLD is in the list of
// exluded domains else false
//---------------------------------------------------------
is_in_domain_list:
	function(domain) {

		var result = true;
		var DoaminFilter = cz.nic.extension.dnssecExtPrefs.getBool("domainfilter");
		if (DoaminFilter) {
			var DomainSeparator = /[.]+/;
			var DomainArray = domain.split(DomainSeparator);
			//if (dnssecExtension.debugOutput) {
			//	dump(dnssecExtension.debugPrefix + 'DomainArray: ' + DomainArray + ' #: '+DomainArray.length +'\n');
			//}
			var DomainList = cz.nic.extension.dnssecExtPrefs.getChar("domainlist");
			var DomainListSeparators = /[ ,;]+/;
			var DomainListArray = DomainList.split(DomainListSeparators);
			//if (dnssecExtension.debugOutput) {
			//	dump(dnssecExtension.debugPrefix + 'domainarraylist: ' + DomainListArray + '\n');
			//}
			var i = 0;
			var j = 0;
			var domaintmp = DomainArray[DomainArray.length-1];
			for (i = DomainArray.length-1; i >= 0; i--) {
				for (j = 0; j < DomainListArray.length; j++) {
					//if (dnssecExtension.debugOutput) {
					//	dump(dnssecExtension.debugPrefix + 'domaintmp: ' +
					//	 domaintmp + ' == DomainListArray[j]: ' + DomainListArray[j] +'\n');
					//}
					if (domaintmp == DomainListArray[j]) {
						return false;
					}
				}
				domaintmp = DomainArray[i-1] + "." + domaintmp;
			}
		}
		return result;
	},

//---------------------------------------------------------
// it is call when url was changed
// for TLSA status (icon) refresh in the url bar
//---------------------------------------------------------
processNewURL:
	function(aRequest, aLocationURI) {

		var scheme = null;
		var asciiHost = null;
		var c = cz.nic.extension.tlsaExtNPAPIConst;

		scheme = aLocationURI.scheme;             // Get URI scheme
		asciiHost = aLocationURI.asciiHost;       // Get punycoded hostname


		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_PRE + 'Scheme: "' + scheme
			     + '"; ' + 'ASCII domain name: "' + asciiHost + '"');
		}

		if (scheme == 'chrome' || asciiHost == null || asciiHost == 'about' ||
		                asciiHost == '' || asciiHost.indexOf("\\") != -1 ||
		                asciiHost.indexOf(":") != -1 ||
		                asciiHost.search(/[A-Za-z]/) == -1) {

			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(' ...invalid\n');
			}
			// Set inaction mode (no icon)
			cz.nic.extension.tlsaExtHandler.setMode(cz.nic.extension.tlsaExtHandler.DANE_MODE_INACTION);
			return;
		}
		else {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(' ...valid\n');
			}
		}

		var freecache = cz.nic.extension.dnssecExtPrefs.getBool("cachefree");
		if (freecache) {
			cz.nic.extension.tlsaExtCache.delAllRecords();
			cz.nic.extension.dnssecExtPrefs.setBool("cachefree", false);
		}

		var tlsaon = cz.nic.extension.dnssecExtPrefs.getBool("tlsaenable");
		if (tlsaon) {

			if (this.is_in_domain_list(asciiHost)) {
				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(this.DANE_DEBUG_PRE + 'Validate this domain: yes'+ this.DANE_DEBUG_POST);
				}

				if (!aLocationURI || scheme.toLowerCase() != "https") {
					cz.nic.extension.tlsaExtHandler.setSecurityState(c.DANE_NO_HTTPS);
				}
				else {
					var tlsa = c.DANE_OFF;
					var port = (aLocationURI.port == -1) ? 443 : aLocationURI.port;
					var portcache = (aLocationURI.port == -1) ? '' : ":"+aLocationURI.port;
					var current_time = new Date().getTime();
					var hostport = asciiHost + portcache;
					var cacheitem = cz.nic.extension.tlsaExtCache.getRecord(hostport);
					if (cacheitem[0] != '') {
						if (cacheitem[2] < current_time) {
							tlsa = this.check_tlsa_tab_change(aRequest, asciiHost, port, "tcp", hostport);
						}
						else {
							cz.nic.extension.tlsaExtHandler.setSecurityState(cacheitem[0]);
							if (cz.nic.extension.daneExtension.debugOutput) {
								dump(this.DANE_DEBUG_PRE + "TLSA result from cache was used: " + cacheitem[0] + this.DANE_DEBUG_POST);
							}
						}
					}
					else {
						tlsa = this.check_tlsa_tab_change(aRequest, asciiHost, port, "tcp", hostport);
					}
				}
			}
			else {
				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(this.DANE_DEBUG_PRE + 'Validate this domain: no'+ this.DANE_DEBUG_POST);
				}
				cz.nic.extension.tlsaExtHandler.setSecurityState(c.DANE_OFF);
			}
		}
		else {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(this.DANE_DEBUG_PRE + 'TLSA Validation is disable'+ this.DANE_DEBUG_POST);
			}
			cz.nic.extension.tlsaExtHandler.setSecurityState(c.DANE_OFF);
		}
		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_POST);
		}
	},

//---------------------------------------------------------
//gets valid or invalid certificate used by the browser
//---------------------------------------------------------
getCertificate:
	function(browser) {

		var uri = browser.currentURI;

		// This construction uses some strange behaviour of the constructs.
		// The browser may return any certificate chain when port is -1.
		//if (uri.port == -1) {
		//	uri.port = 443;
		//}

		var ui = browser.securityUI;

		var cert = this.get_valid_cert(ui);

		if (!cert) {
			//if (uri.port == -1) {
			//	// Ask for 443 if not specified.
			//	uri.port == 443;
			//	cert = this.get_invalid_cert_SSLStatus(uri);
			//	uri.port == -1;
			//} else {
			//	cert = this.get_invalid_cert_SSLStatus(uri);
			//}
			cert = this.get_invalid_cert_SSLStatus(uri);
		}

		if (!cert) {
			return null;
		}

		return cert;
	},

//---------------------------------------------------------
// gets current certificate, if it PASSED the browser check
//---------------------------------------------------------
get_valid_cert:
	function(ui) {

		try {
			ui.QueryInterface(Components.interfaces.nsISSLStatusProvider);
			if (!ui.SSLStatus) {
				return null;
			}
			return ui.SSLStatus.serverCert;
		}
		catch (e) {
			return null;
		}
	},

//----------------------------------------------------------
// gets current certificate, if it FAILED the security check
//----------------------------------------------------------
get_invalid_cert_SSLStatus:
	function(uri) {

		var recentCertsSvc = null;

		// firefox <= 19 and seamonkey
		if (typeof Components.classes["@mozilla.org/security/recentbadcerts;1"] !== "undefined") {
			recentCertsSvc = Components.classes["@mozilla.org/security/recentbadcerts;1"]
			                 .getService(Components.interfaces.nsIRecentBadCertsService);
		}
		// firefox > v20
		else if (typeof Components.classes["@mozilla.org/security/x509certdb;1"] !== "undefined") {
			var certDB = Components.classes["@mozilla.org/security/x509certdb;1"]
			             .getService(Components.interfaces.nsIX509CertDB2);
			if (!certDB) {
				return null;
			}

			var privateMode = false;
			if (typeof Components.classes['@mozilla.org/privatebrowsing;1'] !== 'undefined') {
				privateMode = Components.classes["@mozilla.org/privatebrowsing;1"]
				              .getService(Components.interfaces.nsIPrivateBrowsingService);
				recentCertsSvc = certDB.getRecentBadCerts(privateMode);
			}
		}
		else {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(this.DANE_DEBUG_PRE + "No way to get invalid cert status!\n");
			}
			return null;
		}

		if (!recentCertsSvc) {
			return null;
		}

		var port = (uri.port == -1) ? 443 : uri.port;
		var hostWithPort = uri.host + ":" + port;
		var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
		if (!gSSLStatus) {
			return null;
		}

		return gSSLStatus;
	},

//---------------------------------------------------------
// check TLSA records when tab or url is changed
//---------------------------------------------------------
check_tlsa_tab_change:
	function (channel, domain, port, protocol, hostport) {

		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_PRE + "------------ TLSA validation start ----------------" + this.DANE_DEBUG_POST);
		}
		cz.nic.extension.tlsaExtHandler.setMode(cz.nic.extension.tlsaExtHandler.DANE_MODE_ACTION);
		var c = cz.nic.extension.tlsaExtNPAPIConst;

		var derCerts = new Array();
		var len = 0;

		if (cz.nic.extension.dnssecExtPrefs.getBool("usebrowsercertchain")) {

			var cert = this.getCertificate(window.gBrowser);
			if (!cert) {
				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(this.DANE_DEBUG_PRE + "No certificate!" + this.DANE_DEBUG_POST);
				}
				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(this.DANE_DEBUG_PRE + "------------- TLSA validation end ------------------" + this.DANE_DEBUG_POST);
				}
				cz.nic.extension.tlsaExtHandler.setMode(cz.nic.extension.tlsaExtHandler.DANE_MODE_INIT);

				return null;
			}

			var chain = cert.getChain();
			len = chain.length;
			for (var i = 0; i < chain.length; i++) {
				var certx = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
				var derData = certx.getRawDER({});
				var derHex = derData.map(function(x) {
					return ("0"+x.toString(16)).substr(-2);
				}).join("");
				derCerts.push(derHex);
			} //for
		} else {
			derCerts.push("00FF00FF");
		}

		var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;

		var options = 0;
		if (cz.nic.extension.daneExtension.debugOutput) {
			options |= c.DANE_FLAG_DEBUG;
		}
		if (cz.nic.extension.dnssecExtPrefs.getInt("dnsserverchoose") != 3) {
			options |= c.DANE_FLAG_USEFWD;
		}

		var nameserver = "";
		if (cz.nic.extension.dnssecExtPrefs.getChar("dnsserveraddr") != "") {
			nameserver = cz.nic.extension.dnssecExtPrefs.getChar("dnsserveraddr");
		}

		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_PRE +"HTTPS request: https://" + domain
			     + "; certchain length: " + len + ";"+ this.DANE_DEBUG_POST);

			dump(this.DANE_DEBUG_PRE +"DANE core request: {certchain}, "
			     + len +", "+ options +", "+ nameserver +", "+ domain +", "+
			     port +", "+ protocol +", "+ policy+ this.DANE_DEBUG_POST);
		}

		// Call NPAPI validation
		try {
			var tlsa = document.getElementById("dane-tlsa-plugin");
			var daneMatch = tlsa.TLSAValidate(derCerts, len, options,
			                                  nameserver, domain, port, protocol, policy);
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(this.DANE_DEBUG_PRE + "Return: " + daneMatch[0]
				     + " for https://" + domain + ";" + this.DANE_DEBUG_POST);
			}
		} catch (ex) {

			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(this.DANE_DEBUG_PRE + 'Error: TLSA plugin call failed!' + this.DANE_DEBUG_POST);
				dump(this.DANE_DEBUG_PRE + "----------- TLSA validation end --------------" + this.DANE_DEBUG_POST);
			}
			cz.nic.extension.tlsaExtHandler.setMode(cz.nic.extension.tlsaExtHandler.DANE_MODE_ERROR_GENERIC);
			return null;

		}

		if (daneMatch[0] == c.DANE_DNSSEC_BOGUS) {

			options = 0;
			tlsa.TLSACacheFree();
			tlsa.TLSACacheInit();
			var daneMatchnofwd = tlsa.TLSAValidate(derCerts, len, options, "nofwd", domain, port, protocol, policy);

			if (daneMatchnofwd[0] != daneMatch[0]) {
				daneMatch[0] = c.DANE_RESOLVER_NO_DNSSEC;
				tlsa.TLSACacheFree();
				tlsa.TLSACacheInit();
			}
		}

		var block = "no";
/*		if (daneMatch[0] >= c.DANE_DNSSEC_BOGUS) {

			var cacheitem = cz.nic.extension.tlsaExtCache.getRecord(domain);
			if (cacheitem[1] == "no" || cacheitem[1] == "yes") {
				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(this.DANE_DEBUG_PRE + "Cache: "+ domain + "; " + cacheitem[0] + "; " + cacheitem[1] + ";" + this.DANE_DEBUG_POST);
				}
			}
			else {

				if (channel) {
					var tlsablock = cz.nic.extension.dnssecExtPrefs.getBool("tlsablocking");
					if (tlsablock) {
						var stringbundle = document.getElementById("dnssec-strings");
						var pre = stringbundle.getString("warning.dialog.pre");
						var post = stringbundle.getString("warning.dialog.post");

						if (confirm(pre + domain + " "+post)) {
							channel.cancel(Components.results.NS_BINDING_ABORTED);
							block = "yes";
							if (cz.nic.extension.daneExtension.debugOutput) {
								dump(this.DANE_DEBUG_PRE + "https request for (" +
								     domain+ ") was CANCELED!" +
								     this.DANE_DEBUG_POST);
							}
						}
						else {
							block = "no";
							if (cz.nic.extension.daneExtension.debugOutput) {
								dump(this.DANE_DEBUG_PRE + "https request for (" +
								     domain+ ") was CONFIRMED" + this.DANE_DEBUG_POST);
							}
						}
						//cz.nic.extension.tlsaExtCache.addRecord(domain, daneMatch[0] , block);
						//cz.nic.extension.tlsaExtCache.printContent();
					}
				}
			}
		}
*/
		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_PRE + "------------ TLSA validation end ------------------" + this.DANE_DEBUG_POST);
		}
		cz.nic.extension.tlsaExtCache.addRecord(hostport, daneMatch[0] , block);
		cz.nic.extension.tlsaExtCache.printContent();
		cz.nic.extension.tlsaExtHandler.setSecurityState(daneMatch[0]);
		return null;
	},

//--------------------------------------------------------------
// check TLSA records when new https request is create
//--------------------------------------------------------------
check_tlsa_https:
	function (channel, cert, browser, domain, port, protocol, url, hostport) {

		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_PRE + "---------- TLSA VALIDATION START -------------" + this.DANE_DEBUG_POST);
		}

		var c = cz.nic.extension.tlsaExtNPAPIConst;
		var len = 0;
		var derCerts = new Array();

		if (cz.nic.extension.dnssecExtPrefs.getBool("usebrowsercertchain")) {

			if(!cert) {

				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(this.DANE_DEBUG_PRE + "Certificate chain missing!" + this.DANE_DEBUG_POST);
				}

				cz.nic.extension.tlsaExtHandler.setSecurityState(c.DANE_NO_CERT_CHAIN);

				if (cz.nic.extension.daneExtension.debugOutput) {
					dump(this.DANE_DEBUG_PRE + "----------- TLSA VALIDATION END -------------" + this.DANE_DEBUG_POST);
				}
				return;
			} // if not cert

			var chain = cert.getChain();
			len = chain.length;
			for (var i = 0; i < chain.length; i++) {
				var certx = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
				var derData = certx.getRawDER({});
				var derHex = derData.map(function(x) {
					return ("0"+x.toString(16)).substr(-2);
				}).join("");
				derCerts.push(derHex);
			} //for
		} else {
			derCerts.push("00FF00FF");
		}
		
		var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;

		var options = 0;
		if (cz.nic.extension.daneExtension.debugOutput) {
			options |= c.DANE_FLAG_DEBUG;
		}
		if (cz.nic.extension.dnssecExtPrefs.getInt("dnsserverchoose") != 3) {
			options |= c.DANE_FLAG_USEFWD;
		}

		var nameserver = "";
		if (cz.nic.extension.dnssecExtPrefs.getChar("dnsserveraddr") != "") {
			nameserver = cz.nic.extension.dnssecExtPrefs.getChar("dnsserveraddr");
		}

		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_PRE + "HTTPS request: https://" +
			     domain + "; certchain length: " + len + ";"+ this.DANE_DEBUG_POST);

			dump(this.DANE_DEBUG_PRE +"TLSA core request: {certchain}, "
			     + len +", "+ options +", "+ nameserver +", "+ domain +", "+
			     port +", "+ protocol +", "+ policy+ this.DANE_DEBUG_POST);
		}

		// Call NPAPI validation
		try {
			var tlsa = document.getElementById("dane-tlsa-plugin");
			var daneMatch = tlsa.TLSAValidate(derCerts, len, options,
			                                  nameserver, domain, port, protocol, policy);
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(this.DANE_DEBUG_PRE + "Return: " + daneMatch[0]
				     + " for https://" + domain + ";" + this.DANE_DEBUG_POST);
			}
		} catch (ex) {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(this.DANE_DEBUG_PRE + 'Error: TLSA plugin call failed!' + this.DANE_DEBUG_POST);
				dump(this.DANE_DEBUG_PRE + "----------- TLSA VALIDATION END --------------" + this.DANE_DEBUG_POST);
			}
			// Set error mode
			cz.nic.extension.tlsaExtHandler.setMode(cz.nic.extension.tlsaExtHandler.DANE_MODE_ERROR_GENERIC);
			return;
		}

		var block = "no";
		if (daneMatch[0] >= c.DANE_TLSA_PARAM_ERR) {
			if (channel) {
				var tlsablock = cz.nic.extension.dnssecExtPrefs.getBool("tlsablocking");
				if (tlsablock) {
					var stringbundle = document.getElementById("dnssec-strings");
					var pre = stringbundle.getString("warning.dialog.pre");
					var post = stringbundle.getString("warning.dialog.post");

					if (confirm(pre + domain + " "+post)) {
						channel.cancel(Components.results.NS_BINDING_ABORTED);
						block = "yes";

						var uritop = window.content.location.href;

						if (url == uritop) {
							cz.nic.extension.tlsaExtHandler.setSecurityState(daneMatch[0]);
						}
						if (cz.nic.extension.daneExtension.debugOutput) {
							dump(this.DANE_DEBUG_PRE + "https request for (" +
							     domain + ") was CANCELED!" + this.DANE_DEBUG_POST);
						}
					}
					else {
						block = "no";
						if (cz.nic.extension.daneExtension.debugOutput) {
							dump(this.DANE_DEBUG_PRE + "https request for (" +
							     domain + ") was CONFIRMED" + this.DANE_DEBUG_POST);
						}
					}
				}
			}
		}
		cz.nic.extension.tlsaExtCache.addRecord(hostport, daneMatch[0] , block);
		cz.nic.extension.tlsaExtCache.printContent();


		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(this.DANE_DEBUG_PRE + "----------- TLSA VALIDATION END --------------" + this.DANE_DEBUG_POST);
		}

	}
};

//*****************************************************************************
//*****************************************************************************
/* Utility class to handle manipulations of the TLSA indicators in the UI */
//*****************************************************************************
//*****************************************************************************
cz.nic.extension.tlsaExtHandler = {

// DANE/TLSA MODE
DANE_MODE_INACTION 				: "dm_inaction",
DANE_MODE_VALIDATION_OFF   			: "dm_validationoff",
DANE_MODE_ACTION   				: "dm_action",
DANE_MODE_ERROR 				: "dm_error",
DANE_MODE_ERROR_GENERIC				: "dm_errorgeneric",
DANE_MODE_RESOLVER_FAILED     			: "dm_rfesolverfailed",
DANE_MODE_DNSSEC_BOGUS				: "dm_dnssecbogus",
DANE_MODE_DNSSEC_UNSECURED			: "dm_dnssecunsecured",
DANE_MODE_NO_TLSA_RECORD			: "dm_notlsarecord",
DANE_MODE_NO_CERT_CHAIN				: "dm_certchain",
DANE_MODE_TLSA_PARAM_WRONG			: "dm_tlsapramwrong",
DANE_MODE_NO_HTTPS				: "dm_nohttps",
DANE_MODE_DNSSEC_SECURED      			: "dm_dnssecsec",
DANE_MODE_CERT_ERROR          			: "dm_certerr",
DANE_MODE_WRONG_RESOLVER			: "dm_wrongres",
DANE_MODE_VALIDATION_FALSE			: "dm_vf",
DANE_MODE_VALIDATION_FALSE_TYPE0		: "dm_vf0",
DANE_MODE_VALIDATION_FALSE_TYPE1		: "dm_vf1",
DANE_MODE_VALIDATION_FALSE_TYPE2		: "dm_vf2",
DANE_MODE_VALIDATION_FALSE_TYPE3		: "dm_vf3",
DANE_MODE_VALIDATION_SUCCESS_TYPE0		: "dm_vs0",
DANE_MODE_VALIDATION_SUCCESS_TYPE1		: "dm_vs1",
DANE_MODE_VALIDATION_SUCCESS_TYPE2		: "dm_vs2",
DANE_MODE_VALIDATION_SUCCESS_TYPE3		: "dm_vs3",
DANE_MODE_INIT					: "dm_nxdomain",
//DANE/TLSA tooltip
DANE_TOOLTIP_VALIDATION_SUCCESS 		: "dmvsTooltip",
DANE_TOOLTIP_VALIDATION_FALSE 			: "dmvfTooltip",
DANE_TOOLTIP_ACTION          			: "dmaTooltip",
DANE_TOOLTIP_FAILED_RESOLVER  			: "dmfsTooltip",
DANE_TOOLTIP_PARAM_WRONG			: "dmwpTooltip",
DANE_TOOLTIP_NO_TLSA_RECORD   			: "dmntrTooltip",
DANE_TOOLTIP_NO_CERT_CHAIN    			: "dmnccTooltip",
DANE_TOOLTIP_OFF	        		: "dmoffTooltip",
DANE_TOOLTIP_NO_HTTPS	        		: "dmnohttpsTooltip",
DANE_TOOLTIP_DNSSEC_BOGUS     			: "dmdnssecbogusTooltip",
DANE_TOOLTIP_DNSSEC_UNSECURED 			: "dmdnssecunsecTooltip",
DANE_TOOLTIP_WRONG_RESOLVER 			: "dmwrongresTooltip",

// Cache the most recent hostname seen in checkSecurity
_asciiHostName : null,
_utf8HostName : null,

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
		this._tooltipLabel[this.DANE_TOOLTIP_WRONG_RESOLVER] =
		        this._stringBundle.getString("dane.tooltip.wrong.resolver");
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
		this._securityText[this.DANE_MODE_WRONG_RESOLVER] =
		        this._stringBundle.getString("dane.mode.wrong.resolver");
		this._securityText[this.DANE_MODE_ERROR_GENERIC] =
		        this._stringBundle.getString("dane.mode.error.generic");
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
		this._securityDetail[this.DANE_MODE_ERROR_GENERIC] =
		        this._stringBundle.getString("dane.mode.error.generic.detail");
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
		this._securityDetail[this.DANE_MODE_WRONG_RESOLVER] =
		        this._stringBundle.getString("dane.mode.wrong.resolver.detail");
		return this._securityDetail;
	},

	get _tlsaPopup () {
		delete this._tlsaPopup;
		return this._tlsaPopup = document.getElementById("dnssec-tlsa-popup");
	},
	get _tlsaPopupfwd () {
		delete this._tlsaPopupfwd;
		return this._tlsaPopupfwd = document.getElementById("dnssec-tlsa-popup-fwd");
	},
	get _tlsaBox () {
		delete this._tlsaBox;
		return this._tlsaBox = document.getElementById("dnssec-tlsa-box");
	},
	get _tlsaPopupContentBox () {
		delete this._tlsaPopupContentBox;
		return this._tlsaPopupContentBox =
		               document.getElementById("dnssec-tlsa-popup-content-box");
	},
	get _tlsaPopupContentBox2 () {
		delete this._tlsaPopupContentBox2;
		return this._tlsaPopupContentBox2 =
		               document.getElementById("dnssec-tlsa-popup-content-box2");
	},
	get _tlsaPopupContentBox3 () {
		delete this._tlsaPopupContentBox3;
		return this._tlsaPopupContentBox3 =
		               document.getElementById("dnssec-tlsa-popup-content-box3");
	},
	get _tlsaPopupContentBox4 () {
		delete this._tlsaPopupContentBox4;
		return this._tlsaPopupContentBox4 =
		               document.getElementById("dnssec-tlsa-popup-content-box4");
	},
	get _tlsaPopupContentHost () {
		delete this._tlsaPopupContentHost;
		return this._tlsaPopupContentHost =
		               document.getElementById("dnssec-tlsa-popup-content-host");
	},
	get _tlsaPopupSecLabel () {
		delete this._tlsaPopupSecLabel;
		return this._tlsaPopupSecLabel =
		               document.getElementById("dnssec-tlsa-popup-security-text");
	},
	get _tlsaPopupSecLabel2 () {
		delete this._tlsaPopupSecLabel2;
		return this._tlsaPopupSecLabel2 =
		               document.getElementById("dnssec-tlsa-popup-security-label");
	},
	get _tlsaPopupSecDetail () {
		delete this._tlsaPopupSecDetail;
		return this._tlsaPopupSecDetail =
		               document.getElementById("dnssec-tlsa-popup-security-detail");
	},
	get _tlsaPopupfwdDetail () {
		delete this._tlsaPopupfwdDetail;
		return this._tlsaPopupfwdDetail =
		               document.getElementById("dnssec-tlsa-popup-fwd-text");
	},
	get _tlsaPopupIpBrowser () {
		delete this._tlsaPopupIpBrowser;
		return this._tlsaPopupIpBrowser =
		               document.getElementById("dnssec-tlsa-popup-ipbrowser-ip");
	},
	get _tlsaPopupIpValidator () {
		delete this._tlsaPopupIpValidator;
		return this._tlsaPopupIpValidator =
		               document.getElementById("dnssec-tlsa-popup-ipvalidator-ip");
	},
	// Build out a cache of the elements that we need frequently
_cacheElements :
	function() {
		delete this._tlsaBox;
		this._tlsaBox = document.getElementById("dnssec-tlsa-box");
	},

	// Set appropriate DANE security state
setSecurityState :
	function(state) {
		var c = cz.nic.extension.tlsaExtNPAPIConst;

		switch (state) {
		case c.DANE_OFF:
			this.setMode(this.DANE_MODE_VALIDATION_OFF);
			break;
		case c.DANE_NO_TLSA:
			this.setMode(this.DANE_MODE_NO_TLSA_RECORD);
			break;
		case c.DANE_ERROR_RESOLVER:
			this.setMode(this.DANE_MODE_RESOLVER_FAILED);
			break;
		case c.DANE_DNSSEC_BOGUS:
			this.setMode(this.DANE_MODE_DNSSEC_BOGUS);
			break;
		case c.DANE_DNSSEC_UNSECURED:
			this.setMode(this.DANE_MODE_DNSSEC_UNSECURED);
			break;
		case c.DANE_NO_HTTPS:
			this.setMode(this.DANE_MODE_NO_HTTPS);
			break;
		case c.DANE_TLSA_PARAM_ERR:
			this.setMode(this.DANE_MODE_TLSA_PARAM_WRONG);
			break;
		case c.DANE_DNSSEC_SECURED:
			this.setMode(this.DANE_MODE_DNSSEC_SECURED);
			break;
		case c.DANE_CERT_ERROR:
			this.setMode(this.DANE_MODE_CERT_ERROR);
			break;
		case c.DANE_NO_CERT_CHAIN:
			this.setMode(this.DANE_MODE_NO_CERT_CHAIN);
			break;
		case c.DANE_INVALID_TYPE0:
			this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE0);
			break;
		case c.DANE_INVALID_TYPE1:
			this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE1);
			break;
		case c.DANE_INVALID_TYPE2:
			this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE2);
			break;
		case c.DANE_INVALID_TYPE3:
			this.setMode(this.DANE_MODE_VALIDATION_FALSE_TYPE3);
			break;
		case c.DANE_VALID_TYPE0:
			this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE0);
			break;
		case c.DANE_VALID_TYPE1:
			this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE1);
			break;
		case c.DANE_VALID_TYPE2:
			this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE2);
			break;
		case c.DANE_VALID_TYPE3:
			this.setMode(this.DANE_MODE_VALIDATION_SUCCESS_TYPE3);
			break;
		case c.DANE_RESOLVER_NO_DNSSEC:
			this.setMode(this.DANE_MODE_WRONG_RESOLVER);
			break;
		default:
			this.setMode(this.DANE_MODE_ERROR_GENERIC);
			break;
		}
	},

	/**
	 * Update the UI to reflect the specified mode, which should be one of the
	 * TLSA_MODE_* constants.
	 */
setMode :
	function(newMode) {
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
setSecurityMessages :
	function(newMode) {

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
		case this.DANE_MODE_ERROR_GENERIC:
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
		case this.DANE_MODE_WRONG_RESOLVER:
			tooltip = this._tooltipLabel[this.DANE_TOOLTIP_WRONG_RESOLVER];
			break;
		case this.DANE_MODE_DNSSEC_BOGUS:
			tooltip = this._tooltipLabel[this.DANE_TOOLTIP_DNSSEC_BOGUS];
			break;
		case this.DANE_MODE_INIT:
			tooltip = "";
			break;
			// Unknown
		default:
			tooltip = "";
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
setPopupMessages :
	function(newMode) {

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
		var port = gBrowser.currentURI.port;
		if (port == -1) {
			port = "";
		} else {
			port = ":" + port;
		}

		if (newMode == this.DANE_MODE_NO_HTTPS) {
			this._tlsaPopupContentHost.textContent = gBrowser.currentURI.asciiHost + port;
		}
		else this._tlsaPopupContentHost.textContent = "https://" + gBrowser.currentURI.asciiHost + port;

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

hideTlsaPopup :
	function() {
		this.hideAddInfo();
		this._tlsaPopup.hidePopup();
	},

showAddInfoIP :
	function() {
		document.getElementById("dnssec-tlsa-popup-ipbrowser-title").style.display = 'block';
		document.getElementById("dnssec-tlsa-popup-ipbrowser-ip").style.display = 'block';
		document.getElementById("dnssec-tlsa-popup-ipvalidator-title").style.display = 'block';
		document.getElementById("dnssec-tlsa-popup-ipvalidator-ip").style.display = 'block';
	},

hideAddInfoIP :
	function() {
		document.getElementById("dnssec-tlsa-popup-ipbrowser-title").style.display = 'none';
		document.getElementById("dnssec-tlsa-popup-ipbrowser-ip").style.display = 'none';
		document.getElementById("dnssec-tlsa-popup-ipvalidator-title").style.display = 'none';
		document.getElementById("dnssec-tlsa-popup-ipvalidator-ip").style.display = 'none';
	},

showAddInfo :
	function(id) {
		document.getElementById(id).style.display = 'block';
		document.getElementById("dnssec-linkt").style.display = 'none';
		document.getElementById("dnssec-tlsa-popup-homepage").style.display = 'block';
	},

hideAddInfo :
	function() {
		document.getElementById("dnssec-tlsa-popup-security-detail").style.display = 'none';
		document.getElementById("dnssec-linkt").style.display = 'block';
		document.getElementById("dnssec-tlsa-popup-homepage").style.display = 'none';
	},


	/**
	 * Click handler for the dnssec-tlsa-box element in primary chrome.
	 */
handleTlsaButtonEvent :
	function(event) {

		event.stopPropagation();

		if ((event.type == "click" && event.button != 0) ||
		                (event.type == "keypress" && event.charCode != KeyEvent.DOM_VK_SPACE &&
		                 event.keyCode != KeyEvent.DOM_VK_RETURN))
			return; // Left click, space or enter only

		// No popup window while...
		if (this._tlsaBox && ((this._tlsaBox.className == this.DANE_MODE_ACTION) || (this._tlsaBox.className == this.DANE_MODE_INIT) )) // getting security status
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

