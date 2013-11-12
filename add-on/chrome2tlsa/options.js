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
var defaultCustomResolver = "8.8.8.8";

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
// Helper function from stackeoverflow
//--------------------------------------------------------
function substr_count(haystack, needle, offset, length) {

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
}


//--------------------------------------------------------
// Test if the input is a valid IPv4 address
//--------------------------------------------------------
function  test_ipv4(ip) {
    var match = ip.match(/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);
    return match != null;

}

//--------------------------------------------------------
// Test if the input is a valid IPv6 address
//--------------------------------------------------------
function test_ipv6(ip) {

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
    if (substr_count(ip, ':')<8)
    {
      var match = ip.match(/^(?::|(?:[a-f0-9]{1,4}:)+):(?:(?:[a-f0-9]{1,4}:)*[a-f0-9]{1,4})?$/i);
      return match != null;
    } 

    // Not a valid IPv6 address
    return false;
}

//--------------------------------------------------------
// check correct format of IP addresses in the textarea
//--------------------------------------------------------
function checkOptdnsserveraddr(str) {
    var n=str.split(" ");
    var result=0;
    for(c= 0;c<n.length; c++){
      if (test_ipv4(n[c]) || test_ipv6(n[c])) {
     	 //result=0;
      } else {
     	 result=1;
      } //if
    } //for
    if (result==1) return false;
    else return true;
}

//--------------------------------------------------------
// check correct format of domain and TLD in the textarea
//--------------------------------------------------------
function checkdomainlist() {
    var str=document.getElementById("domainlist").value;
    var match = str.match(/^[a-z0-9.-]+(, [a-z0-9.-]+)*$/);
    return match != null;
}

//--------------------------------------------------------
// Cancel settings without saving on the localstorage
//--------------------------------------------------------
function cancelOptions() {
        console.log("CLOSE:");
		window.close();
}

//--------------------------------------------------------
// Save settings on the localstorage
//--------------------------------------------------------
function saveOptions() {
    console.log("SAVE:");
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
    localStorage["dnssecDebugOutput"] = document.tlsaSettings.debugOutput.checked;
	localStorage["domainfilteron"] = document.tlsaSettings.domainfilteron.checked;
	localStorage["blockhttps"] = document.tlsaSettings.blockhttps.checked;
	localStorage["clearcache"] = document.tlsaSettings.clearcache.checked;
	localStorage["domainlist"] = document.tlsaSettings.domainlist.value;
    var plugin = document.getElementById("tlsa-plugin");
	plugin.TLSACacheFree();
	document.write("<div>Settings were saved...</div>");
	document.write("<div>Please, close this window...Thanks</div>");
	window.close();
}

//--------------------------------------------------------
// test on DNSSEC support
//--------------------------------------------------------
function testdnssec() {

      //console.log("TEST:");
      var nameserver = "8.8.8.8";
      var options = 7;
      var testnic = 0;
      var ip = false;
      var dn = "www.nic.cz";
      var addr = "217.31.205.50";
      var chioce = 0;
      var tmp = document.tlsaSettings.customResolver.value;
      var radiogroup = document.tlsaSettings.resolver;
      
		for (var i = 0; i < radiogroup.length; i++) {
			var child = radiogroup[i];
			console.log('CHOICE: \"'+ i + '; ' + child.checked + '\"\n');
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
									options = 5; ;
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
			      console.log('INIT parameters: \"'+ dn + '; ' + options + '; ' + nameserver + '; ' + addr + '\"\n');
			      var plugin = document.getElementById("tlsa-plugin");
				  plugin.TLSACacheFree();
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
	console.log("ERASE:");
	localStorage.removeItem("dnssecResolver");
	localStorage.removeItem("dnssecCustomResolver");
	localStorage.removeItem("dnssecDebugOutput");
	location.reload();
}


//--------------------------------------------------------
// Replaces onclick for the option buttons
//--------------------------------------------------------
window.onload = function(){
    document.querySelector('input[id="savebutton"]').onclick=saveOptions;
    document.querySelector('input[id="testbutton"]').onclick=testdnssec;
    document.querySelector('input[id="cancelbutton"]').onclick=cancelOptions;
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
	document.getElementById("testbutton").value=chrome.i18n.getMessage("testbutton");
	document.getElementById("savebutton").value=chrome.i18n.getMessage("savebutton");
	document.getElementById("cancelbutton").value=chrome.i18n.getMessage("cancelbutton");

	if (state==4) {
		var dnssecResolver = localStorage["dnssecResolver"];
	        // IP address of custom resolver
	        var dnssecCustomResolver = localStorage["dnssecCustomResolver"];
	        // debug output of resolving to stderr
	        var debugOutput = localStorage["dnssecDebugOutput"];
		var domainfilteron = localStorage["domainfilteron"];
		var blockhttps = localStorage["blockhttps"];
		var clearcache = localStorage["clearcache"];
		var domainlist = localStorage["domainlist"];

		if (dnssecResolver == undefined) {
			dnssecResolver = defaultResolver;
		}
		if (dnssecCustomResolver == undefined) {
			dnssecCustomResolver = defaultCustomResolver;
		}
	        // OMG localstorage has everything as text
	        debugOutput = (debugOutput == undefined || debugOutput == "false") ? false : true;
	        document.tlsaSettings.customResolver.value = dnssecCustomResolver;
	        document.tlsaSettings.debugOutput.checked = debugOutput;
	        document.tlsaSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
		blockhttps = (blockhttps == undefined || blockhttps == "true") ? true : false;
		clearcache = (clearcache == undefined || clearcache == "true") ? true : false;
	        document.tlsaSettings.domainfilteron.checked = domainfilteron;
		document.tlsaSettings.blockhttps.checked = blockhttps;
		document.tlsaSettings.clearcache.checked = clearcache;
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
		var blockhttps = localStorage["blockhttps"];
		var clearcache = clearcache["clearcache"];
		document.tlsaSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
		document.tlsaSettings.domainfilteron.checked = domainfilteron;
   		blockhttps = (blockhttps == undefined || blockhttps == "true") ? true : false;
		document.tlsaSettings.blockhttps.checked = blockhttps;	
		clearcache = (clearcache == undefined || clearcache == "true") ? true : false;
		document.tlsaSettings.clearcache.checked = clearcache;		
	}  //state
});


