/* ***** BEGIN LICENSE BLOCK *****
Copyright 2014 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator Add-on.

DNSSEC/TLSA Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC/TLSA Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

const myGlobal = safari.extension.globalPage.contentWindow;

var domain = myGlobal.tlsa_domain;
var icon = myGlobal.tlsa_icon;
var text = myGlobal.tlsa_text;
var tooltip = myGlobal.tlsa_tooltip;
var detail = myGlobal.tlsa_detail;

// set text of html elements
function addText(id, str) {
	if (document.createTextNode){
		var tn = document.createTextNode(str);
		document.getElementById(id).appendChild(tn);
	}
};

// set icon into popup
function TLSAicon(icon){
	var pic = document.getElementById("popup-tlsa-icon"); 
	if (pic == typeof('undefined')) return;
	pic.src = icon;
};


function showTlsaDetailInfo(){
	document.getElementById("divright").style.display = 'none';
	document.getElementById("detail-text").style.display = 'block';
	document.getElementById("homepage").style.display = 'block';
};

TLSAicon(icon);
addText("domain-name-title", domain);
addText("tlsa-tooltip", tooltip);
addText("pre-domain-text", text);
addText("detail-text", detail);


safari.application.addEventListener('popover', function(event) {
	event.target.contentWindow.location.reload();
	document.getElementById("divright").style.display = 'block';
	document.getElementById("detail-text").style.display = 'none';
	document.getElementById("homepage").style.display = 'none';
}, true);
