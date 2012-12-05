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


// DNSSEC preferences functions
var dnssecExtAbout = {

  prefObj : Components.classes["@mozilla.org/preferences-service;1"]
            .getService(Components.interfaces.nsIPrefBranch),
  prefBranch : "extensions.dnssec.",

  isInstantApply : function() {
    try {
      return Components.classes["@mozilla.org/preferences-service;1"]
             .getService(Components.interfaces.nsIPrefBranch)
             .getBoolPref("browser.preferences.instantApply", false);
    } catch (ex) {
      return null;
    }
  },


  showAboutWindow : function() {
    var optionsURL = "chrome://dnssec/content/about.xul";

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
      features += this.isInstantApply() ? ",dialog=yes" : ",modal";
    } catch (e) {
      features += ",modal";
    }
    window.openDialog(optionsURL, "", features);
  },

};
