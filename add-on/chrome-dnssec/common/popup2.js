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
function DNSSECicon2(icon){
       var pic = document.getElementById("dnssec-icon2"); 
       if (pic == typeof('undefined')) return;
       pic.src = icon;
}

	// this code set text into popup window
        resultRegexp = /\?([^?,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)$/;
        matches = resultRegexp.exec(document.location.href);
	domain = matches[1];
        statusString = matches[2];
        icon = matches[3];
	status = matches[4];
	statuspre = matches[5];
	info = matches[6];
	ipbrowser = matches[7];
	ipvalidator = matches[8];    
	addText("domain-name-title", domain);
	addText("domain-name-text", domain);
	addText("long-text", chrome.i18n.getMessage(statusString));
	addText("long-text-domain", chrome.i18n.getMessage(statuspre));
	addText("dnssec-title", chrome.i18n.getMessage(status));
	addText("dnssec-info", chrome.i18n.getMessage(info));
	
	if (statusString == "3securedConnectionDomainInvIPaddr" ||
	    statusString == "8securedConnectionNoDomainIPaddr")  {
		document.getElementById("ip-info-b").style.display = 'block';
		document.getElementById("ip-info-v").style.display = 'block';
	  	document.getElementById("ip-info-bh").style.display = 'block';
		document.getElementById("ip-info-vh").style.display = 'block'; 
	    	addText("ip-info-b", decodeURIComponent(ipbrowser));
		addText("ip-info-v", decodeURIComponent(ipvalidator));
		addText("ip-info-bh", chrome.i18n.getMessage("ipbrowsertext"));
		addText("ip-info-vh", chrome.i18n.getMessage("ipvalidatortext"));
  	}
	else {
		document.getElementById("ip-info-b").style.display = 'none';
		document.getElementById("ip-info-v").style.display = 'none';
		document.getElementById("ip-info-bh").style.display = 'none';
		document.getElementById("ip-info-vh").style.display = 'none';
	}   
	addText("homepage", chrome.i18n.getMessage("homepage"));	
	DNSSECicon2(icon);
