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

//Define our namespace
if(!cz) var cz={};
if(!cz.nic) cz.nic={};
if(!cz.nic.extension) cz.nic.extension={};

// DNSSEC preferences functions
cz.nic.extension.dnssecExtPrefs = {

instantApply :
	true, // default value that changes on pref window load
	// Some parts of next code are used from UrlbarExt project


prefObj :
	Components.classes["@mozilla.org/preferences-service;1"]
	.getService(Components.interfaces.nsIPrefBranch),
prefBranch : "extensions.dnssec."
	,

getInt :
	function(prefName) {
		try {
			return this.prefObj.getIntPref(this.prefBranch + prefName);
		} catch (ex) {
			return null;
		}
	},

getBool :
	function(prefName) {
		try {
			return this.prefObj.getBoolPref(this.prefBranch + prefName);
		} catch (ex) {
			return null;
		}
	},

getChar :
	function(prefName) {
		try {
			return this.prefObj.getCharPref(this.prefBranch + prefName);
		} catch (ex) {
			return null;
		}
	},

setChar :
	function(prefName, prefValue) {
		try {
			return this.prefObj.setCharPref(this.prefBranch + prefName,
			                                prefValue);
		} catch (ex) {
			return null;
		}
	},

setBool :
	function(prefName, prefValue) {
		try {
			return this.prefObj.setBoolPref(this.prefBranch + prefName,
			                                prefValue);
		} catch (ex) {
			return null;
		}
	},

setInt :
	function(prefName, prefValue) {
		try {
			return this.prefObj.setIntPref(this.prefBranch + prefName,
			                               prefValue);
		} catch (ex) {
			return null;
		}
	},

resetUserPref :
	function(prefName) {
		try {
			this.prefObj.clearUserPref(this.prefBranch + prefName);
		} catch (ex) {
		}
	},

hasUserValue :
	function(prefName) {
		try {
			return this.prefObj.prefHasUserValue(this.prefBranch + prefName);
		} catch (ex) {
			return null;
		}
	},

checkOptdnsserveraddr :
	function() {
		var str = document.getElementById("dnssec-pref-optdnsserveraddr").value;
		var n = str.split(" ");
		var c = 0;
		for(c = 0; c < n.length; c++) {
			if (!this.test_ip(n[c])) {
				return false;
			} //if
		} //for
		return true;
	},


checkdomainlist :
	function() {
		var str=document.getElementById("dnssec-pref-domains").value;
		var match = str.match(/^[a-z0-9.-]+(, [a-z0-9.-]+)*$/);
		return match != null;
	},

savePrefs :
	function() {
		switch (document.getElementById("dnssec-pref-dnsserverchoose").value) {
		case '2': // Custom resolver
			if (this.checkOptdnsserveraddr()) {
				this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-optdnsserveraddr").value);
				document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: black");
			} else {
				document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: red");
			}
			break;
		case '3': // System
			this.setChar("dnsserveraddr", "nofwd"); // empty string for using system resolver conf
			break;
		case '0': // System
		default:
			this.setChar("dnsserveraddr", ""); // empty string for using system resolver conf
			break;
		}
		if (!document.getElementById("dnssec-pref-domains").disabled)
		{
			if (this.checkdomainlist()) {
				this.setChar("domainlist", document.getElementById("dnssec-pref-domains").value);
				document.getElementById("dnssec-pref-domains").setAttribute("style", "color: black");
			} else {
				document.getElementById("dnssec-pref-domains").setAttribute("style", "color: red");
			}
		}
	},

setElementsattributes :
	function() {
		var tmpCheck;
		document.getElementById("dnssecok").style.display = 'none';
		document.getElementById("dnssecbogus").style.display = 'none';
		document.getElementById("dnssecerror").style.display = 'none';
		document.getElementById("wrongip").style.display = 'none';
		document.getElementById("space").style.display = 'block';


		// enable optional DNS address textbox only if appropriate radio button is selected
		tmpCheck = document.getElementById("dnssec-pref-useoptdnsserver").selected;
		document.getElementById("dnssec-pref-optdnsserveraddr").disabled = !tmpCheck;

		tmpCheck = document.getElementById("dnssec-pref-usefilter").checked;
		document.getElementById("dnssec-pref-domains").disabled = !tmpCheck;

		tmpCheck = document.getElementById("dnssec-pref-tlsaonoff").checked;
		document.getElementById("dnssec-pref-tlsablock").disabled = !tmpCheck;
		document.getElementById("dnssec-pref-clearcache").disabled = !tmpCheck;
		document.getElementById("dnssec-pref-checkallhttps").disabled = !tmpCheck;
		document.getElementById("dnssec-pref-usebrowsercertchain").disabled = !tmpCheck;
//		document.getElementById("dnssec-pref-tlsablock").disabled = !tmpCheck;
//		document.getElementById("dnssec-pref-clearcache").disabled = !tmpCheck;
		if (tmpCheck) {
			var tmp = document.getElementById("dnssec-pref-checkallhttps").checked;
			document.getElementById("dnssec-pref-tlsablock").disabled = !tmp;
			document.getElementById("dnssec-pref-clearcache").disabled = !tmp;
		}

	},

	get _dnssecok () {
		delete this._dnssecok;
		return this._dnssecok =
		               document.getElementById("dnssecok");
	},

	get _dnssecbogus () {
		delete this._dnssecbogus;
		return this._dnssecbogus =
		               document.getElementById("dnssecbogus");
	},

	get _dnssecerror() {
		delete this._dnssecerror;
		return this._dnssecerror =
		               document.getElementById("dnssecerror");
	},

	get _wrongip() {
		delete this._wrongip;
		return this._wrongip =
		               document.getElementById("wrongip");
	},


pane1Load :
	function() {
		delete this._stringBundle;
		this._stringBundle = document.getElementById("dnssec-strings-pref");
		this._dnssecok.textContent = this._stringBundle.getString("dnssecok");
		this._dnssecbogus.textContent = this._stringBundle.getString("dnssecbogus");
		this._dnssecerror.textContent = this._stringBundle.getString("dnssecerror");
		this._wrongip.textContent = this._stringBundle.getString("wrongip");
		this.setElementsattributes();
	},

dnsserverchooseCommand :
	function() {
		this.setElementsattributes();

		if (this.instantApply) {
			this.windowDialogaccept();
		}
	},

dnsserverpresetchooseCommand :
	function() {
		this.dnsserverchooseCommand();
	},

optdnsserveraddrInput :
	function() {
		this.setElementsattributes();
		if (this.instantApply) {
			this.windowDialogaccept();
		}
	},

testdnssec :
	function() {
		//this.setLoading(true);
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
			nameserver = document.getElementById("dnssec-pref-optdnsserveraddr").value;
			if (!this.checkOptdnsserveraddr()) {
				ip=true;
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
		if (ip) {
			document.getElementById("wrongip").style.display = 'block';
			document.getElementById("space").style.display = 'none';
		}
		else {
			try {
				window.arguments[0].dnssec_validation_deinit_core();	
				testnic = window.arguments[0].dnssec_validate_core(dn, options, nameserver, addr);
				testnic = testnic[0];

				if (testnic==-2) {
					document.getElementById("dnssecok").style.display = 'none';
					document.getElementById("dnssecbogus").style.display = 'none';
					document.getElementById("dnssecerror").style.display = 'block';
					document.getElementById("wrongip").style.display = 'none';
					document.getElementById("space").style.display = 'none';

				}
				else if (testnic==4) {
					document.getElementById("dnssecok").style.display = 'none';
					document.getElementById("dnssecbogus").style.display = 'block';
					document.getElementById("dnssecerror").style.display = 'none';
					document.getElementById("wrongip").style.display = 'none';
					document.getElementById("space").style.display = 'none';

				}
				else {
					document.getElementById("dnssecok").style.display = 'block';
					document.getElementById("dnssecbogus").style.display = 'none';
					document.getElementById("dnssecerror").style.display = 'none';
					document.getElementById("wrongip").style.display = 'none';
					document.getElementById("space").style.display = 'none';

					this.savePrefs();
				}
			} catch (ex) {
				if (this.getBool("dnssecdebug")) {
					dump('Error: Plugin call failed!\n');
				}
			}
		}//if ip
	},

windowDialogaccept :
	function() {
		this.savePrefs();
	},

onUnload :
	function(prefwindow) {
		this.setBool("cachefree", true);
		window.arguments[0].dnssec_validation_deinit_core();
		window.arguments[1].dane_validation_deinit_core();
		return true;
	},


setLoading :
	function(state) {
		document.getElementById("identifier").style.display = (state) ? 'block' : 'none';
		document.getElementById('identifier').mode =
		        (state) ? 'undetermined' : 'determined';
	},

showPrefWindow :
	function(dnssecLibCore, daneLibCore) {
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
test_ip :
	function(ip) {
		var expression = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(@\d{1,5})?\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?(@\d{1,5})?\s*$))/;

		var match = ip.match(expression);
		return match != null;
	},

};
