
// DNSSEC preferences functions
var dnssecExtPrefs = {

    // Some parts of next code are used from UrlbarExt project

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


    pane1Load : function() {
      // enable optional DNS address textbox only if appropriate radio button is selected
      var mycheck = document.getElementById("dnssec-pref-useoptdnsserver").selected;
      document.getElementById("dnssec-pref-optdnsserveraddr").disabled = !mycheck;

    },

    dnsserverchooseCommand : function() {
      this.pane1Load();

      switch (document.getElementById("dnssec-pref-dnsserverchoose").value) {
      case '1': // CZ.NIC's ODVR
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-cznicdnsserveraddr").value);
        break;
      case '2': // OARC's ODVR
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-oarcdnsserveraddr").value);
        break;
      case '3': // User's own
        this.optdnsserveraddrInput();
        break;
      case '0': // System
      default:
        this.setChar("dnsserveraddr", ""); // empty string for using system resolver conf
        break;
      }

    },

    optdnsserveraddrInput : function() {
      if (checkIPaddr.test_ipv4(document.getElementById("dnssec-pref-optdnsserveraddr").value)
          || checkIPaddr.test_ipv6(document.getElementById("dnssec-pref-optdnsserveraddr").value)) {
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-optdnsserveraddr").value);
//        document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: black");
      } else {
//        document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: red");

      }

    },

};


// Functions for IP address notation validation
var checkIPaddr = {

  // Used from http://ipv6blog.net/ipv6-validation-javascript/

  // Support function
  substr_count : function(haystack, needle, offset, length) {

    var pos = 0, cnt = 0;

    haystack += '';
    needle += '';
    if (isNaN(offset)) {offset = 0;}
    if (isNaN(length)) {length = 0;}
    offset--;

    while ((offset = haystack.indexOf(needle, offset+1)) != -1) {
      if (length > 0 && (offset+needle.length) > length){
        return false;
      } else {
        cnt++;
      }
    }

    return cnt;
  },

  // Test for a valid dotted IPv4 address
  test_ipv4 : function(ip) {

    var match = ip.match(/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);
    return match != null;

  },

  // Test if the input is a valid IPv6 address
  test_ipv6 : function(ip) {

    // Test for empty address
    if (ip.length<3)
    {
      return ip == "::";
    }

    // Check if part is in IPv4 format
    if (ip.indexOf('.')>0)
    {
      var lastcolon = ip.lastIndexOf(':');

      if (!(lastcolon && this.test_ipv4(ip.substr(lastcolon + 1))))
        return false;

      // replace IPv4 part with dummy
      ip = ip.substr(0, lastcolon) + ':0:0';
    } 

    // Check uncompressed
    if (ip.indexOf('::')<0)
    {
      var match = ip.match(/^(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}$/i);
      return match != null;
    }

    // Check colon-count for compressed format
    if (this.substr_count(ip, ':') < 8)
    {
      var match = ip.match(/^(?::|(?:[a-f0-9]{1,4}:)+):(?:(?:[a-f0-9]{1,4}:)*[a-f0-9]{1,4})?$/i);
      return match != null;
    } 

    // Not a valid IPv6 address
    return false;

  },

}
