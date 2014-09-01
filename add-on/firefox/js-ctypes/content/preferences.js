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

// Define our name space.
if(!cz) var cz={};
if(!cz.nic) cz.nic={};
if(!cz.nic.extension) cz.nic.extension={};

Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/AddonManager.jsm");

// DNSSEC preferences functions
cz.nic.extension.dnssecExtPrefs = {

instantApply : true, // default value that changes on pref window load
// Some parts of following code are used from UrlbarExt project
prefObj : Components.classes["@mozilla.org/preferences-service;1"]
    .getService(Components.interfaces.nsIPrefBranch),
prefBranch : "extensions.dnssec.",
pluginlib : null,
coreFileName : null,

/* Synchronous core initialisation. */
sync_dnssec_init: function() {
	/*
	 * Note: The DNSSEC may be initialised for the second time here. This
	 * is because we cannot access the extension which may have been
	 * already initialised in the main XUL module.
	 */

	/* Initialise add-on. */
	var addonObj = null;
	AddonManager.getAddonByID("dnssec@nic.cz", function(addon) {
		addonObj = addon;
	});
	var Cc = Components.classes;
	var thread = Cc["@mozilla.org/thread-manager;1"]
	    .getService().currentThread;
	/* Wait till add-on initialisation finishes. */
	while (null == addonObj) {
		/* Don't block other events. */
		thread.processNextEvent(true);
	}

	var abi = Components.classes["@mozilla.org/xre/app-info;1"]
	    .getService(Components.interfaces.nsIXULRuntime).XPCOMABI;
	var os = Components.classes["@mozilla.org/xre/app-info;1"]
	    .getService(Components.interfaces.nsIXULRuntime).OS;

	var dnssecLibName = "unspecified";
	var coreStr = "libDNSSECcore";

	/* Set library name/suffix according to system. */
	var osTgtStr = "unspecified";
	var libSuffStr = "unspecified";
	if (os.match("Darwin")) {
		osTgtStr = "Darwin";
		libSuffStr = "dylib";
	} else if (os.match("FreeBSD")) {
		osTgtStr = "FreeBSD";
		libSuffStr = "so";
	} else if (os.match("Linux")) {
		osTgtStr = "Linux";
		libSuffStr = "so";
	} else if (os.match("WINNT")) {
		osTgtStr = "WINNT";
		libSuffStr = "dll";
	}

	/* Test for unsupported OS. */
	if (("unspecified" == osTgtStr) ||
	    ("unspecified" == libSuffStr)) {
		if (this.getBool("dnssecdebug")) {
			dump("Error: Unsupported OS '" + os + "'!\n");
		}
		return false;
	}

	/* Try system location (core.lib). */
	dnssecLibName = coreStr + "." + libSuffStr;
	try {
		cz.nic.extension.dnssecExtPrefs._initDnssecLib(dnssecLibName);
		if (this.getBool("dnssecdebug")) {
			dump("Loaded DNSSEC library:\n        '" +
			    dnssecLibName + "'\n");
		}
		return true;
	} catch(e) {
		/*
		 * Failed loading OS library. Fall back to library
		 * distributed with the plug-in.
		 */
		if (this.getBool("dnssecdebug")) {
			dump("Warning: Cannot find DNSSEC system " +
			    "library '" + dnssecLibName + "'.\n");
		}
	}

	/* Try system location (core-os.lib). */
	dnssecLibName = coreStr + "-" + osTgtStr + "." + libSuffStr;
	try {
		cz.nic.extension.dnssecExtPrefs._initDnssecLib(dnssecLibName);
		if (this.getBool("dnssecdebug")) {
			dump("Loaded DNSSEC library:\n        '" +
			    dnssecLibName + "'\n");
		}
		return true;
	} catch(e) {
		/*
		 * Failed loading OS library. Fall back to library
		 * distributed with the plug-in.
		 */
		if (this.getBool("dnssecdebug")) {
			dump("Warning: Cannot find DNSSEC system " +
			    "library '" + dnssecLibName + "'. Library " +
			    "distributed with plugin will be used.\n");
		}
	}

	var abiStr = "unspecified";
	if (abi.match("x86_64")) {
		abiStr = "x86_64";
	} else if (abi.match("x86")) {
		abiStr = "x86";
	}

	/* Test for unsupported ABI. */
	if ("unspecified" == abiStr) {
		if (this.getBool("dnssecdebug")) {
			dump("Error: Unsupported OS architecture!\n");
		}
		return false;
	}

	/* Only 32-bit Windows at the moment. */
	if ("WINNT" == osTgtStr) {
		abiStr = "x86";
	}

	/* Packaged library (platform/core-os-arch.lib). */
	dnssecLibName = "platform/" + coreStr + "-" + osTgtStr +
	    "-" + abiStr + "." + libSuffStr;
	dnssecLibName = addonObj.getResourceURI(dnssecLibName)
	    .QueryInterface(Components.interfaces.nsIFileURL).file
	    .path;
	try {
		cz.nic.extension.dnssecExtPrefs._initDnssecLib(dnssecLibName);
		if (this.getBool("dnssecdebug")) {
			dump("Loaded DNSSEC library:\n        '" +
			    dnssecLibName + "'\n");
		}
		return true;
	} catch(e) {
		/*
		 * Failed loading plug-in distributed library.
		 */
		if (this.getBool("dnssecdebug")) {
			dump("Warning: Cannot load plug-in core " +
			    "library '" + dnssecLibName + "'.\n");
		}
	}

	/* Last option, packaged library (platform/core-os.lib). */
	dnssecLibName = "platform/" + coreStr + "-" + osTgtStr +
	    "." + libSuffStr;
	dnssecLibName = addonObj.getResourceURI(dnssecLibName)
	    .QueryInterface(Components.interfaces.nsIFileURL).file
	    .path;
	try {
		cz.nic.extension.dnssecExtPrefs._initDnssecLib(dnssecLibName);
		if (this.getBool("dnssecdebug")) {
			dump("Loaded DNSSEC library:\n        '" +
			    dnssecLibName + "'\n");
		}
		return true;
	} catch(e) {
		if (this.getBool("dnssecdebug")) {
			dump("Error: Cannot load plug-in core " +
			    "library '" + dnssecLibName + "'.\n");
		}
	}

	return false;

},

_initDnssecLib: function(dnssecLibName) {

	++this.initAttempt;

	/* Open library. */
	this.pluginlib = ctypes.open(dnssecLibName);

	/* Declare dnssec API functions. */

	this.pluginlib.dnssec_validation_init =
	    this.pluginlib.declare("dnssec_validation_init",
	    ctypes.default_abi,
	    ctypes.int);

	this.pluginlib.dnssec_validation_deinit =
	    this.pluginlib.declare("dnssec_validation_deinit",
	    ctypes.default_abi,
	    ctypes.int);

	this.pluginlib.dnssec_validate =
	    this.pluginlib.declare("dnssec_validate",
	    ctypes.default_abi,
	    ctypes.int,		//return state
	    ctypes.char.ptr,	//doamin
	    ctypes.uint16_t,	//options
	    ctypes.char.ptr,	//optdnssrv
	    ctypes.char.ptr,	//ipbrowser
	    ctypes.char.ptr.ptr //ipvalidator out
	    );

	this.coreFileName = dnssecLibName;
},

getInt : function(prefName) {
	try {
		return this.prefObj.getIntPref(this.prefBranch + prefName);
	} catch (ex) {
		return null;
	}
},

getBool : function(prefName) {
	try {
		return this.prefObj.getBoolPref(this.prefBranch + prefName);
	} catch (ex) {
		return null;
	}
},

getChar : function(prefName) {
	try {
		return this.prefObj.getCharPref(this.prefBranch + prefName);
	} catch (ex) {
		return null;
	}
},

setChar : function(prefName, prefValue) {
	try {
		return this.prefObj.setCharPref(this.prefBranch + prefName,
		    prefValue);
	} catch (ex) {
		return null;
	}
},

setBool : function(prefName, prefValue) {
	try {
		return this.prefObj.setBoolPref(this.prefBranch + prefName,
		    prefValue);
	} catch (ex) {
		return null;
	}
},

setInt : function(prefName, prefValue) {
	try {
		return this.prefObj.setIntPref(this.prefBranch + prefName,
		    prefValue);
	} catch (ex) {
		return null;
	}
},

resetUserPref : function(prefName) {
	try {
		this.prefObj.clearUserPref(this.prefBranch + prefName);
	} catch (ex) {
	}
},

hasUserValue : function(prefName) {
	try {
		return this.prefObj.prefHasUserValue(this.prefBranch + prefName);
	} catch (ex) {
		return null;
	}
},

checkOptdnsserveraddr : function() {
	var str = document.getElementById("dnssec-pref-optdnsserveraddr").value;
	var n = str.split(" ");
	var c = 0;
	for(c = 0; c < n.length; c++) {
		if (!this.test_ip(n[c])) {
			return false;
		}
	}
	return true;
},


checkdomainlist : function() {
	var str=document.getElementById("dnssec-pref-domains").value;
	var match = str.match(/^[a-z0-9.-]+(, [a-z0-9.-]+)*$/);
	return match != null;
},

savePrefs : function() {
	switch (document.getElementById("dnssec-pref-dnsserverchoose").value) {
	case '2': // Custom resolver
		if (this.checkOptdnsserveraddr()) {
			this.setChar("dnsserveraddr",
			    document.getElementById(
			        "dnssec-pref-optdnsserveraddr").value);
			document.getElementById("dnssec-pref-optdnsserveraddr")
			    .setAttribute("style", "color: black");
		} else {
			document.getElementById("dnssec-pref-optdnsserveraddr")
			    .setAttribute("style", "color: red");
		}
		break;
	case '3': // System
		/* Empty string for using system resolver conf. */
		this.setChar("dnsserveraddr", "nofwd");
		break;
	case '0': // System
	default:
		/* Empty string for using system resolver conf. */
		this.setChar("dnsserveraddr", "");
		break;
	}
	if (!document.getElementById("dnssec-pref-domains").disabled)
	{
		if (this.checkdomainlist()) {
			this.setChar("domainlist",
			    document.getElementById("dnssec-pref-domains")
			        .value);
			document.getElementById("dnssec-pref-domains")
			    .setAttribute("style", "color: black");
		} else {
			document.getElementById("dnssec-pref-domains")
			    .setAttribute("style", "color: red");
		}
	}
},

setElementsattributes : function() {
	var tmpCheck;
	document.getElementById("dnssecok").style.display = 'none';
	document.getElementById("dnssecbogus").style.display = 'none';
	document.getElementById("dnssecerror").style.display = 'none';
	document.getElementById("wrongip").style.display = 'none';
	document.getElementById("space").style.display = 'block';


	/*
	 * Enable optional DNS address text box only if appropriate radio
	 * button is selected.
	 */
	tmpCheck = document.getElementById("dnssec-pref-useoptdnsserver")
	    .selected;
	document.getElementById("dnssec-pref-optdnsserveraddr").disabled =
	    !tmpCheck;

	tmpCheck = document.getElementById("dnssec-pref-usefilter").checked;
	document.getElementById("dnssec-pref-domains").disabled = !tmpCheck;

	tmpCheck = document.getElementById("dnssec-pref-tlsaonoff").checked;
	document.getElementById("dnssec-pref-tlsablock").disabled = !tmpCheck;
	//document.getElementById("dnssec-pref-clearcache").disabled = !tmpCheck;
	document.getElementById("dnssec-pref-checkallhttps").disabled =
	    !tmpCheck;
	document.getElementById("dnssec-pref-usebrowsercertchain").disabled =
	    !tmpCheck;
//	document.getElementById("dnssec-pref-tlsablock").disabled = !tmpCheck;
//	document.getElementById("dnssec-pref-clearcache").disabled = !tmpCheck;
	if (tmpCheck) {
		var tmp = document.getElementById("dnssec-pref-checkallhttps")
		    .checked;
		document.getElementById("dnssec-pref-tlsablock").disabled =
		    !tmp;
		//document.getElementById("dnssec-pref-clearcache").disabled =
		//    !tmp;
	}

},

get _dnssecok() {
	delete this._dnssecok;
	return this._dnssecok = document.getElementById("dnssecok");
},

get _dnssecbogus() {
	delete this._dnssecbogus;
	return this._dnssecbogus = document.getElementById("dnssecbogus");
},

get _dnssecerror() {
	delete this._dnssecerror;
	return this._dnssecerror = document.getElementById("dnssecerror");
},

get _wrongip() {
	delete this._wrongip;
	return this._wrongip = document.getElementById("wrongip");
},

pane1Load : function() {
	delete this._stringBundle;
	this._stringBundle = document.getElementById("dnssec-strings-pref");
	this._dnssecok.textContent = this._stringBundle.getString("dnssecok");
	this._dnssecbogus.textContent =
	    this._stringBundle.getString("dnssecbogus");
	this._dnssecerror.textContent =
	    this._stringBundle.getString("dnssecerror");
	this._wrongip.textContent = this._stringBundle.getString("wrongip");
	this.setElementsattributes();
},

dnsserverchooseCommand : function() {
	this.setElementsattributes();
	if (this.instantApply) {
		this.windowDialogaccept();
	}
},

dnsserverpresetchooseCommand : function() {
	this.dnsserverchooseCommand();
},

optdnsserveraddrInput : function() {
	this.setElementsattributes();
	if (this.instantApply) {
		this.windowDialogaccept();
	}
},

testdnssec : function() {

	var dnsseclib = null;

	var options = 6;
	var ip = false;
	var testnic = 0;
	var dn = "www.nic.cz";
	var addr = "217.31.205.50";
	var nameserver = "";
	switch (document.getElementById("dnssec-pref-dnsserverchoose").value) {
	case '0': // System setting
		nameserver = "";
		break;
	case '2': // Custom
		nameserver = document.getElementById(
		    "dnssec-pref-optdnsserveraddr").value;
		if (!this.checkOptdnsserveraddr()) {
			ip = true;
		}
		break;
	case '3': // Self-validation
		nameserver = "nofwd";
		options = 4;
		break;
	default:
		nameserver = "";
		break;
	} //switch

	if (!ip) {
		try {
			if (window.arguments == undefined) {

				/* Set plug-in path and open lib. */
				if (!this.sync_dnssec_init()) {
					/*
					 * TODO -- Print error message because
					 * extension library could not be
					 * initialised.
					 */
					if (this.getBool("dnssecdebug")) {
						dump("Error: Cannot initialise extension.\n");
					}
				}
				this.pluginlib.dnssec_validation_deinit();
				this.pluginlib.dnssec_validation_init();
				var outputParam = new ctypes.char.ptr();
				testnic = this.pluginlib.dnssec_validate(dn,
				    options, nameserver, addr,
				    outputParam.address());
				this.pluginlib.close();
			} else {
				window.arguments[0]
				    .dnssec_validation_deinit_core();
				testnic = window.arguments[0]
				    .dnssec_validate_core(dn, options,
				        nameserver, addr);
				testnic = testnic[0];
			}

			if (testnic == -2) {
				document.getElementById("dnssecok").style
				    .display = 'none';
				document.getElementById("dnssecbogus").style
				    .display = 'none';
				document.getElementById("dnssecerror").style
				    .display = 'block';
				document.getElementById("wrongip").style
				    .display = 'none';
				document.getElementById("space").style
				    .display = 'none';
			}
			else if (testnic == 4) {
				document.getElementById("dnssecok").style
				    .display = 'none';
				document.getElementById("dnssecbogus").style
				    .display = 'block';
				document.getElementById("dnssecerror").style
				    .display = 'none';
				document.getElementById("wrongip").style
				    .display = 'none';
				document.getElementById("space").style
				    .display = 'none';
			}
			else {
				document.getElementById("dnssecok").style
				    .display = 'block';
				document.getElementById("dnssecbogus").style
				    .display = 'none';
				document.getElementById("dnssecerror").style
				    .display = 'none';
				document.getElementById("wrongip").style
				    .display = 'none';
				document.getElementById("space").style
				    .display = 'none';
				this.savePrefs();
			}

		} catch (ex) {
			if (this.getBool("dnssecdebug")) {
				dump('Error: Plugin call failed!\n');
			}
		}
	} else {
		document.getElementById("wrongip").style.display = 'block';
		document.getElementById("space").style.display = 'none';
	}
},

windowDialogaccept : function() {
	this.savePrefs();
},

onUnload : function(prefwindow) {
	this.setBool("dnsseccachefree", true);
	this.setBool("tlsacachefree", true);
	//if (window.arguments != undefined) {
	//	window.arguments[0].dnssec_validation_deinit_core();
	//	window.arguments[1].dane_validation_deinit_core();
	//}
	return true;
},


setLoading : function(state) {
	document.getElementById("identifier").style.display =
	    (state) ? 'block' : 'none';
	document.getElementById('identifier').mode =
	    (state) ? 'undetermined' : 'determined';
},

showPrefWindow : function(dnssecLibCore, daneLibCore) {
	var optionsURL = "chrome://dnssec/content/preferences.xul";
	// Check if the pref window is not already opened
	var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
	         .getService(Components.interfaces.nsIWindowMediator);
	var enumerator = wm.getEnumerator(null);
	while(enumerator.hasMoreElements()) {
		var win = enumerator.getNext();
		if (win.document.documentURI == optionsURL) {
			win.focus();
			return;
		}
	}
	// Open the pref window
	var features = "chrome,titlebar,toolbar,centerscreen,dialog=yes";
	window.openDialog(optionsURL, "", features, dnssecLibCore, daneLibCore);
},

// Functions for IP address with port notation validation
test_ip : function(ip) {
	var expression = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(@\d{1,5})?\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?(@\d{1,5})?\s*$))/;

	var match = ip.match(expression);
	return match != null;
},

};
