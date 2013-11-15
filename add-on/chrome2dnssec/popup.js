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

// set text of html elements
function addText(id, str) {
	if (document.createTextNode){
		var tn = document.createTextNode(str);
		document.getElementById(id).appendChild(tn);
	} // if
} 

// set icon into popup
function DNSSECicon(icon){
	var pic = document.getElementById("dnssec-icon"); 
	if (pic == typeof('undefined')) return;
	pic.src = icon;
}

// send parameters into detail popup
function NextLevel(overall){
	var pic = document.getElementById("moreinfo"); 
	if (pic == typeof('undefined')) return;
	pic.href = "detail-info.html?"+overall;
}

	resultRegexp = /\?([^?,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)$/;
	matches = resultRegexp.exec(document.location.href);
	domain = matches[1];
	statusString = matches[2];
	icon = matches[3];
	status = matches[4];
	statuspre = matches[5];
	ipbrowser = matches[6];
	ipvalidator = matches[7];
	overall = domain + "," + statusString + "," + icon + "," + status + "," + statuspre + "," + statusString + "Info" + "," + ipbrowser + "," + ipvalidator;      
	addText("domain-name-title", domain);
	addText("domain-name-text", domain);
	addText("long-text", chrome.i18n.getMessage(statusString));
	addText("long-text-domain", chrome.i18n.getMessage(statuspre));
	addText("dnssec-title", chrome.i18n.getMessage(status));
	addText("moreinfo", chrome.i18n.getMessage("moreinfo"));
	DNSSECicon(icon);	
	NextLevel(overall);

