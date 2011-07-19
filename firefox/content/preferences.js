/* ***** BEGIN LICENSE BLOCK *****
Copyright 2010 CZ.NIC, z.s.p.o.

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

// DNSSEC preferences functions
var dnssecExtPrefs = {

  instantApply : true, // default value that changes on pref window load

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


  isInstantApply : function() {
    try {
      return Components.classes["@mozilla.org/preferences-service;1"]
             .getService(Components.interfaces.nsIPrefBranch)
             .getBoolPref("browser.preferences.instantApply");
    } catch (ex) {
      return null;
    }
  },

  checkOptdnsserveraddr : function() {
    if (dnssecExtCheckIPaddr.test_ipv4(document.getElementById("dnssec-pref-optdnsserveraddr").value)
        || dnssecExtCheckIPaddr.test_ipv6(document.getElementById("dnssec-pref-optdnsserveraddr").value)) {
      return true;
    } else {
      return false;
    }
  },

  savePrefs : function() {
    switch (document.getElementById("dnssec-pref-dnsserverchoose").value) {
    case '1': // Preset resolvers
      switch (document.getElementById("dnssec-pref-dnsserverpresetchoose").value) {
      case '1': // OARC's ODVR
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-oarcdnsserveraddr").value);
        break;
      case '0': // CZ.NIC's ODVR
      default:
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-cznicdnsserveraddr").value);
        break;
      }
      break;
    case '2': // Custom resolver
      if (this.checkOptdnsserveraddr()) {
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-optdnsserveraddr").value);
//        document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: black");
      } else {
//        document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: red");
      }
      break;
    case '0': // System
    default:
      this.setChar("dnsserveraddr", ""); // empty string for using system resolver conf
      break;
    }
  },

  setElementsattributes : function() {

    var tmpCheck;

    // enable preset DNS resolvers menulist only if appropriate radio button is selected
    tmpCheck = document.getElementById("dnssec-pref-usepresetdnsserver").selected;
    document.getElementById("dnssec-pref-dnsserverpresetchoose").disabled = !tmpCheck;

    // enable optional DNS address textbox only if appropriate radio button is selected
    tmpCheck = document.getElementById("dnssec-pref-useoptdnsserver").selected;
    document.getElementById("dnssec-pref-optdnsserveraddr").disabled = !tmpCheck;
  },

  pane1Load : function() {
    this.instantApply = this.isInstantApply();
    this.setElementsattributes();
  },

  dnsserverchooseCommand : function() {
    this.setElementsattributes();

    if (this.instantApply) {
      this.savePrefs();
    }
  },

  dnsserverpresetchooseCommand : function() {
    this.dnsserverchooseCommand();
  },

  optdnsserveraddrInput : function() {
    if (this.instantApply) {
      this.savePrefs();
    }
  },

  windowDialogaccept : function() {
    this.savePrefs();
  },

  showPrefWindow : function() {
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
    var features = "chrome,titlebar,toolbar,centerscreen";
    try {
      features += this.isInstantApply() ? ",dialog=no" : ",modal";
    } catch (e) {
      features += ",modal";
    }
    window.openDialog(optionsURL, "", features);
  },

};


// Functions for IP address notation validation
var dnssecExtCheckIPaddr = {

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
    if (this.substr_count(ip, ':')<8)
    {
      var match = ip.match(/^(?::|(?:[a-f0-9]{1,4}:)+):(?:(?:[a-f0-9]{1,4}:)*[a-f0-9]{1,4})?$/i);
      return match != null;
    } 

    // Not a valid IPv6 address
    return false;

  },

}
