/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator 2.x Add-on.

DNSSEC Validator 2.x Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator 2.x Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.x Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

document.write("<object id=\"tlsa-plugin\" type=\"application/x-tlsavalidatorplugin\" width=\"0\" height=\"0\"></object>");
var defaultResolver = "nofwd"; // LDNS will use system resolver if empty string is passed
var defaultCustomResolver = "217.31.204.130";

//--------------------------------------------------------
// Set string in the web element
//--------------------------------------------------------
function addText(id, str){
	if (document.createTextNode){
		var tn = document.createTextNode(str);
		document.getElementById(id).appendChild(tn);
	}
}

//--------------------------------------------------------
// check correct format of IP addresses in the textarea
//--------------------------------------------------------
function test_ip(ip) {
	var expression = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(@\d{1,5})?\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?(@\d{1,5})?\s*$))/;

	var match = ip.match(expression);
	return match != null;
}

//--------------------------------------------------------
// check correct format of IP addresses in the textarea
//--------------------------------------------------------
function checkOptdnsserveraddr(str) {
	
	var n = str.split(" ");
	var c = 0;
	for(c = 0; c < n.length; c++) {
		if (!test_ip(n[c])) {
			return false;
		} //if
	} //for
	return true;
}

//--------------------------------------------------------
// check correct format of domain and TLD in the textarea
//--------------------------------------------------------
function checkdomainlist() {
	var str = document.getElementById("domainlist").value;
	var match = str.match(/^[a-z0-9.-]+(, [a-z0-9.-]+)*$/);
	return match != null;
}

//--------------------------------------------------------
// Cancel settings without saving on the localstorage
//--------------------------------------------------------
function cancelOptions() {
	window.close();
}

//--------------------------------------------------------
// Save settings on the localstorage
//--------------------------------------------------------
function saveOptions() {
	var radiogroup = document.tlsaSettings.resolver;
	var resolver;
	for (var i = 0; i < radiogroup.length; i++) {
		var child = radiogroup[i];
			if (child.checked == true) {
                            resolver = child.value;
			    break;
		}
	}
	localStorage["dnssecResolver"] = resolver;
	localStorage["dnssecCustomResolver"] = document.tlsaSettings.customResolver.value;
	localStorage["DebugOutput"] = document.tlsaSettings.DebugOutput.checked;
	localStorage["domainfilteron"] = document.tlsaSettings.domainfilteron.checked;
	localStorage["blockhttps"] = document.tlsaSettings.blockhttps.checked;
	localStorage["clearcache"] = document.tlsaSettings.clearcache.checked;
	localStorage["AllHttps"] = document.tlsaSettings.AllHttps.checked;
	localStorage["domainlist"] = document.tlsaSettings.domainlist.value;
	var plugin = document.getElementById("tlsa-plugin");
	plugin.TLSACacheFree();
	plugin.TLSACacheInit();
	document.write("<div>Settings were saved...</div>");
	document.write("<div>Please, close this window...Thanks</div>");
	localStorage["cachefree"] = true;
	window.close();
}

//--------------------------------------------------------
// test on DNSSEC support
//--------------------------------------------------------
function testdnssec() {

	var nameserver = "217.31.204.130";
	var options = 0;
	var testnic = 0;
	var ip = false;
	var dn = "www.nic.cz";
	var addr = "217.31.205.50";
	var chioce = 0;
	var tmp = document.tlsaSettings.customResolver.value;
	var radiogroup = document.tlsaSettings.resolver;
      
	for (var i = 0; i < radiogroup.length; i++) {
		var child = radiogroup[i];
		if (child.checked == true) {
			switch (i) {
				case 0: // System setting
					nameserver = "";
					chioce=0;
					break;
				case 1: // Custom
					chioce=1;
					//tmp = document.tlsaSettings.customResolver.value;
					if (!checkOptdnsserveraddr(tmp)) { 
						ip=true;
					}
					else {
						nameserver = tmp;
					}
					break;
				case 2: // NOFWD
					chioce=2;
					nameserver = "nofwd";
					options = 5;
					break;
			} //switch
		} // if
	} // for

	if (ip) {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none'
		document.getElementById("messageip").style.display = 'block';
	}
	else {
		try {
			var plugin = document.getElementById("tlsa-plugin");
			plugin.TLSACacheFree();
			plugin.TLSACacheInit();
			var derCerts = new Array();
			derCerts.push("XXX");
			testnic = plugin.TLSAValidate(derCerts, 0, options, nameserver, dn, "443", "tcp", 1);     
			if (testnic==13) {
				document.getElementById("messageok").style.display = 'block';
				document.getElementById("messagebogus").style.display = 'none';
				document.getElementById("messageerror").style.display = 'none';
				document.getElementById("messageip").style.display = 'none';
			}
			else if (testnic==16) {
				document.getElementById("messageok").style.display = 'none';
				document.getElementById("messagebogus").style.display = 'block';
				document.getElementById("messageerror").style.display = 'none';
				document.getElementById("messageip").style.display = 'none';
			}
			else { 
				document.getElementById("messageok").style.display = 'none';
				document.getElementById("messagebogus").style.display = 'none';
				document.getElementById("messageerror").style.display = 'block';
				document.getElementById("messageip").style.display = 'none';
			} 
		} catch (ex) {
				console.log('Error: Plugin call failed!\n');
			       	document.getElementById("messageok").style.display = 'none';
				document.getElementById("messagebogus").style.display = 'none';
				document.getElementById("messageerror").style.display = 'none';
				document.getElementById("messageip").style.display = 'none';
		} //try
	}//if ip
}

//--------------------------------------------------------
// help function for clear TLSA localestorage
//--------------------------------------------------------
function eraseOptions() {
	localStorage.removeItem("dnssecResolver");
	localStorage.removeItem("dnssecCustomResolver");
	localStorage.removeItem("DebugOutput");
	location.reload();
}


function AllHttpscheckbox() {

	var ischecked = document.getElementById("AllHttps").checked;
	document.getElementById("blockhttps").disabled = !ischecked;
	document.getElementById("clearcache").disabled = !ischecked;
	if (ischecked) {
		document.getElementById("blockhttpstext").style.color = 'black';
		document.getElementById("clearcachetext").style.color = 'black';
	} else {
		document.getElementById("blockhttpstext").style.color = 'grey';
		document.getElementById("clearcachetext").style.color = 'grey';
	}
	//location.reload();
}

function RefreshExclude() {

	var ischecked = document.getElementById("domainfilteron").checked;
	document.getElementById("domainlist").disabled = !ischecked;
	if (ischecked) {
		document.getElementById("domainlist").style.color = 'black';
		document.getElementById("filtertext").style.color = 'black';
	} else {
		document.getElementById("domainlist").style.color = 'grey';
		document.getElementById("filtertext").style.color = 'grey';
	}
	//location.reload();
}


//--------------------------------------------------------
// Replaces onclick for the option buttons
//--------------------------------------------------------
window.onload = function(){
	document.querySelector('input[id="savebutton"]').onclick = saveOptions;
	document.querySelector('input[id="testbutton"]').onclick = testdnssec;
	document.querySelector('input[id="cancelbutton"]').onclick = cancelOptions;
	var AllHttps = document.querySelectorAll('input[type=checkbox][id=AllHttps]');
	AllHttps[0].onchange = AllHttpscheckbox;
	var domainfilteron = document.querySelectorAll('input[type=checkbox][id=domainfilteron]');
	domainfilteron[0].onchange = RefreshExclude; 
}


//--------------------------------------------------------
// show DNSSEC text about resover settings 
//--------------------------------------------------------
function testinfodisplay(state){

   if (state==0) {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none'
		document.getElementById("messageip").style.display = 'block';
   	}
    else if (state==1) {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'block';
	    document.getElementById("messageip").style.display = 'none';
        }
    else if (state==2) {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'block';
		document.getElementById("messageerror").style.display = 'none';
		document.getElementById("messageip").style.display = 'none';
        }
    else if (state==3) { 
		document.getElementById("messageok").style.display = 'block';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none';
	    document.getElementById("messageip").style.display = 'none';
        }
    else {
		document.getElementById("messageok").style.display = 'none';
		document.getElementById("messagebogus").style.display = 'none';
		document.getElementById("messageerror").style.display = 'none';
	    document.getElementById("messageip").style.display = 'none';
	}
} 

//--------------------------------------------------------
// Settings window initialization
//--------------------------------------------------------
window.addEventListener('load',function() {

	resultRegexp = /\?([^?,]+),([^,]+),([^,]+)$/;
	matches = resultRegexp.exec(document.location.href);
	state = matches[1];
	choice = matches[2];
	resolver = matches[3];
    	unescape(resolver);
	testinfodisplay(state);

	addText("preftitle", chrome.i18n.getMessage("preftitle"));
	addText("prefresolver", chrome.i18n.getMessage("prefresolver"));
	addText("legend", chrome.i18n.getMessage("legend"));
	addText("resolver0", chrome.i18n.getMessage("resolver0"));
	addText("resolver3", chrome.i18n.getMessage("resolver3"));
	addText("resolver4", chrome.i18n.getMessage("resolver4"));
	addText("messageok", chrome.i18n.getMessage("messageok"));
	addText("messagebogus", chrome.i18n.getMessage("messagebogus"));
	addText("messageerror", chrome.i18n.getMessage("messageerror"));
	addText("messageip", chrome.i18n.getMessage("messageip"));
	addText("groupboxfilter", chrome.i18n.getMessage("groupboxfilter"));
	addText("usefilter", chrome.i18n.getMessage("usefilter"));
	addText("filtertext", chrome.i18n.getMessage("filtertext"));
	addText("blockhttpstext", chrome.i18n.getMessage("blockhttpstext"));
	addText("clearcachetext", chrome.i18n.getMessage("clearcachetext"));
	addText("debugoutputtext", chrome.i18n.getMessage("debugoutputtext"));
	addText("AllHttpstext", chrome.i18n.getMessage("AllHttpstext"));
	document.getElementById("testbutton").value=chrome.i18n.getMessage("testbutton");
	document.getElementById("savebutton").value=chrome.i18n.getMessage("savebutton");
	document.getElementById("cancelbutton").value=chrome.i18n.getMessage("cancelbutton");

	if (state==4) {
		var dnssecResolver = localStorage["dnssecResolver"];
	        // IP address of custom resolver
	        var dnssecCustomResolver = localStorage["dnssecCustomResolver"];
	        // debug output of resolving to stderr
	        var DebugOutput = localStorage["DebugOutput"];
		var domainfilteron = localStorage["domainfilteron"];
		var blockhttps = localStorage["blockhttps"];
		var clearcache = localStorage["clearcache"];
		var AllHttps = localStorage["AllHttps"];
		var domainlist = localStorage["domainlist"];
		if (domainlist == undefined) {
			domainlist = "";
		}
		if (dnssecResolver == undefined) {
			dnssecResolver = defaultResolver;
		}
		if (dnssecCustomResolver == undefined) {
			dnssecCustomResolver = defaultCustomResolver;
		}
	        // OMG localstorage has everything as text
	        DebugOutput = (DebugOutput == undefined || DebugOutput == "false") ? false : true;
	        document.tlsaSettings.customResolver.value = dnssecCustomResolver;
	        document.tlsaSettings.DebugOutput.checked = DebugOutput;
	        document.tlsaSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
		blockhttps = (blockhttps == undefined || blockhttps == "false") ? false : true;
		clearcache = (clearcache == undefined || clearcache == "false") ? false : true;
		AllHttps = (AllHttps == undefined || AllHttps == "false") ? false : true;
	        document.tlsaSettings.domainfilteron.checked = domainfilteron;

		document.getElementById("domainlist").disabled = !domainfilteron;
		if (domainfilteron) {
			document.getElementById("domainlist").style.color = 'black';
			document.getElementById("filtertext").style.color = 'black';
		} else {
			document.getElementById("domainlist").style.color = 'grey';
			document.getElementById("filtertext").style.color = 'grey';
		}


		document.tlsaSettings.blockhttps.checked = blockhttps;
		document.tlsaSettings.clearcache.checked = clearcache;
		document.tlsaSettings.AllHttps.checked = AllHttps;
		document.getElementById("blockhttps").disabled = !AllHttps;
		document.getElementById("clearcache").disabled = !AllHttps;
		if (AllHttps) {
			document.getElementById("blockhttpstext").style.color = 'black';
			document.getElementById("clearcachetext").style.color = 'black';
		} else {
			document.getElementById("blockhttpstext").style.color = 'grey';
			document.getElementById("clearcachetext").style.color = 'grey';
		}

		var radiogroup = document.tlsaSettings.resolver;
		for (var i = 0; i < radiogroup.length; i++) {
			var child = radiogroup[i];
				if (child.value == dnssecResolver) {
				    child.checked = "true";
				    break;
			}
		}
	}
	else {
		document.tlsaSettings.customResolver.value = unescape(resolver);
		var radiogroup = document.tlsaSettings.resolver;
		var child = radiogroup[choice];
		child.checked = "true";
		var domainfilteron = localStorage["domainfilteron"];
		var domainlist = localStorage["domainlist"];
		if (domainlist == undefined) {
			domainlist = "";
		}
		var blockhttps = localStorage["blockhttps"];
		var clearcache = localStorage["clearcache"];
		var DebugOutput = localStorage["DebugOutput"];
		document.tlsaSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
		document.tlsaSettings.domainfilteron.checked = domainfilteron;

		document.getElementById("domainlist").disabled = !domainfilteron;
		if (domainfilteron) {
			document.getElementById("domainlist").style.color = 'black';
			document.getElementById("filtertext").style.color = 'black';
		} else {
			document.getElementById("domainlist").style.color = 'grey';
			document.getElementById("filtertext").style.color = 'grey';
		}


		AllHttps = (AllHttps == undefined || AllHttps == "false") ? false : true;
		document.tlsaSettings.AllHttps.checked = AllHttps;
		blockhttps = (blockhttps == undefined || blockhttps == "false") ? false : true;
		document.tlsaSettings.blockhttps.checked = blockhttps;	
		clearcache = (clearcache == undefined || clearcache == "false") ? false : true;
		document.tlsaSettings.clearcache.checked = clearcache;
		document.getElementById("blockhttps").disabled = !AllHttps;
		document.getElementById("clearcache").disabled = !AllHttps;
		if (AllHttps) {
			document.getElementById("blockhttpstext").style.color = 'black';
			document.getElementById("clearcachetext").style.color = 'black';
		} else {
			document.getElementById("blockhttpstext").style.color = 'grey';
			document.getElementById("clearcachetext").style.color = 'grey';
		}
		DebugOutput = (DebugOutput == undefined || DebugOutput == "false") ? false : true;
		document.tlsaSettings.DebugOutput.checked = DebugOutput;		
	}  //state
});


