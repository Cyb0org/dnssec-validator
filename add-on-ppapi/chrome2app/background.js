/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator 2 Add-on.

DNSSEC Validator 2 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator 2 Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2 Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

function moduleDidLoad() {
	// Once we load, hide the plugin. In this example, we don't display
	// anything in the plugin, so it is fine to hide it.
	common.hideModule();

	// After the NaCl module has loaded, common.naclModule is a reference
	// to the NaCl module's <embed> element.
	//
	// postMessage sends a message to it.
	common.naclModule.postMessage({command: "initialise"});
}


function handleMessage(message) {
	message.data;
}

/*
function createNaClModule() {
	var moduleEl = document.createElement('embed');
	moduleEl.setAttribute('name', 'dnssec_nacl_module');
	moduleEl.setAttribute('id', 'dnssec_validator');
	moduleEl.setAttribute('width', 0);
	moduleEl.setAttribute('height', 0);
	moduleEl.setAttribute('type', 'application/x-nacl');
	moduleEl.setAttribute('src', 'dnssec_validator.nmf');
}
*/



chrome.app.runtime.onLaunched.addListener(function() {
 chrome.app.window.create('window.html', {
   'bounds': {
     'width': 0,
     'height': 0
   }
 });
/*
	var moduleEl = document.createElement('embed');
	moduleEl.setAttribute('name', 'dnssec_nacl_module');
	moduleEl.setAttribute('id', 'dnssec_validator');
	moduleEl.setAttribute('width', 0);
	moduleEl.setAttribute('height', 0);
	moduleEl.setAttribute('type', 'application/x-nacl');
	moduleEl.setAttribute('src', 'dnssec_validator.nmf');
*/
 //createNaClModule();
});
