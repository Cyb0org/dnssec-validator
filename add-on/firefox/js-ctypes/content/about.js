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

cz.nic.extension.dnssecExtAbout = {

prefObj :
	Components.classes["@mozilla.org/preferences-service;1"]
	.getService(Components.interfaces.nsIPrefBranch),
prefBranch : "extensions.dnssec."
	,

showAboutWindow :
	function() {
		var about = "chrome://dnssec/content/about.xul";

		// Check if the window is not already opened
		var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
		         .getService(Components.interfaces.nsIWindowMediator);
		var enumerator = wm.getEnumerator(null);
		while(enumerator.hasMoreElements()) {
			var win = enumerator.getNext();
			if (win.document.documentURI == about) {
				win.focus();
				return;
			}
		}

		// Open the window
		var features = "chrome,titlebar,toolbar,centerscreen,dialog=yes";
		window.openDialog(about, "", features);
	},

};
