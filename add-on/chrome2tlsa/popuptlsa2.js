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

// set text on the html element on the popup window
function addText(id, str){
      if (document.createTextNode){
         var tn = document.createTextNode(str);
         document.getElementById(id).appendChild(tn);
       } // if
}

// set icon in popup window
function TLSAicon2(icon){
       var pic = document.getElementById("tlsa-icon2"); 
       if (pic == typeof('undefined')) return;
       pic.src = icon;
}

	// this code set text into popup window
        resultRegexp = /\?([^?,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)$/;
        matches = resultRegexp.exec(document.location.href);
	domain = matches[1];
        statusString = matches[2];
        icon = matches[3];
	status = matches[4];
	domainpre = matches[5];
	info = matches[6];
	var domaintmp = domain;
	domaintmp=domainpre+"://"+domain;   
	addText("domain-name-title-tlsa", domaintmp);
	addText("long-text-tlsa", chrome.i18n.getMessage(statusString));
	addText("tlsa-title", chrome.i18n.getMessage(status));
	addText("tlsa-info", chrome.i18n.getMessage(info));
	addText("homepage", chrome.i18n.getMessage("homepage"));	
	TLSAicon2(icon);
