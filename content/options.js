/* Some parts of this code are used from UrlbarExt project */

var dnssecExtPrefs = {
	prefObj : Components.classes["@mozilla.org/preferences-service;1"]
			.getService(Components.interfaces.nsIPrefBranch),
	prefBranch : "extensions.dnssec.",

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


	useoptdnsserverClick : function() {
		var mycheck = document.getElementById("dnssec-pref-useoptdnsserver").checked;
		document.getElementById("dnssec-pref-optdnsservername").disabled = !mycheck;
	}

};
