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


var defaultResolver = "nofwd"; // LDNS will use system resolver if empty string is passed
var defaultCustomResolver = "8.8.8.8";

function addText(id, str){
   if (document.createTextNode){
     var tn = document.createTextNode(str);
     document.getElementById(id).appendChild(tn);
  }
}



  // Support function
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

  // Test for a valid dotted IPv4 address
function  test_ipv4(ip) {
    var match = ip.match(/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);
    return match != null;

}

  // Test if the input is a valid IPv6 address
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

function checkdomainlist() {
    var str=document.getElementById("domainlist").value;
    var match = str.match(/^[a-z0-9.-]+(, [a-z0-9.-]+)*$/);
    return match != null;
}

function cancelOptions() {
        console.log("CLOSE:");
	window.close();
}


function saveOptions() {
        console.log("SAVE:");
	var radiogroup = document.dnssecSettings.resolver;
        var resolver;
	for (var i = 0; i < radiogroup.length; i++) {
		var child = radiogroup[i];
			if (child.checked == true) {
                            resolver = child.value;
			    break;
		}
	}
	localStorage["dnssecResolver"] = resolver;
	localStorage["dnssecCustomResolver"] = document.dnssecSettings.customResolver.value;
        localStorage["dnssecDebugOutput"] = document.dnssecSettings.debugOutput.checked;
	localStorage["domainfilteron"] = document.dnssecSettings.domainfilteron.checked;
	localStorage["domainlist"] = document.dnssecSettings.domainlist.value;
	document.write("<object id=\"dnssec-plugin\" type=\"application/x-dnssecvalidator\" width=\"0\" height=\"0\"></object>");
        var plugin = document.getElementById("dnssec-plugin");
	plugin.CacheFree();
	document.write("<div>Settings were saved...</div>");
	document.write("<div>Please, close this window...Thanks</div>");
	window.close();
}

function testdnssec() {
      console.log("TEST:");
      var nameserver = "8.8.8.8";
      var c = this.dnssecExtNPAPIConst;
      var options = 7;
      var testnic = 0;
      var ip = false;
      var dn = "www.nic.cz";
      var addr = "217.31.205.50";
      var chioce = 0;
      var tmp = document.dnssecSettings.customResolver.value;
      var vvvv = unescape(tmp);
      console.log(vvvv);
      var radiogroup = document.dnssecSettings.resolver;
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
         		//tmp = document.dnssecSettings.customResolver.value;
			if (!checkOptdnsserveraddr(tmp)) { 
			   ip=true;
 		        }
			else
			{
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
        window.open('options.html?0,'+chioce+','+unescape(tmp), "_top");
   }
   else {
     try {
      console.log('INIT parameters: \"'+ dn + '; ' + options + '; ' + nameserver + '; ' + addr + '\"\n');
      document.write("<object id=\"dnssec-plugin\" type=\"application/x-dnssecvalidator\" width=\"0\" height=\"0\"></object>");
      var plugin = document.getElementById("dnssec-plugin");
      plugin.CacheFree();
      testnic = plugin.Validate(dn, options, nameserver, addr);
      testnic = testnic[0];
      if (testnic==-2) {
        window.open('options.html?1,'+chioce+','+unescape(tmp), "_top");
      }
      else if (testnic==4) {
        window.open('options.html?2,'+chioce+','+unescape(tmp), "_top");
      }
      else { 
        window.open('options.html?3,'+chioce+','+unescape(tmp), "_top");
      }       
    } catch (ex) {
       console.log('Error: Plugin call failed!\n');
	window.open('options.html', "_top");
    }
   }//if ip
}

function eraseOptions() {
	console.log("ERASE:");
	localStorage.removeItem("dnssecResolver");
	localStorage.removeItem("dnssecCustomResolver");
	localStorage.removeItem("dnssecDebugOutput");
	location.reload();
}

// Replaces onclick for the Save button
window.onload = function(){
    document.querySelector('input[id="savebutton"]').onclick=saveOptions;
    document.querySelector('input[id="testbutton"]').onclick=testdnssec;
    document.querySelector('input[id="cancelbutton"]').onclick=cancelOptions;
}


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


window.addEventListener('load',function(){

        resultRegexp = /\?([^?,]+),([^,]+),([^,]+)$/;
        matches = resultRegexp.exec(document.location.href);
	state = matches[1];
        choice = matches[2];
        resolver = matches[3];
	unescape(resolver);
	console.log(state);
	console.log(choice);
	console.log(resolver);
	console.log("LOAD:");
	//var urllength = document.location.href.length;
	//var state = document.location.href[urllength-1];
	testinfodisplay(state);

      	addText("preftitle", chrome.i18n.getMessage("preftitle"));
      	addText("prefresolver", chrome.i18n.getMessage("prefresolver"));
	addText("legend", chrome.i18n.getMessage("legend"));
      	addText("resolver0", chrome.i18n.getMessage("resolver0"));
	//addText("resolver1", chrome.i18n.getMessage("resolver1"));
	//addText("resolver2", chrome.i18n.getMessage("resolver2"));
	addText("resolver3", chrome.i18n.getMessage("resolver3"));
	addText("resolver4", chrome.i18n.getMessage("resolver4"));
	addText("messageok", chrome.i18n.getMessage("messageok"));
	addText("messagebogus", chrome.i18n.getMessage("messagebogus"));
	addText("messageerror", chrome.i18n.getMessage("messageerror"));
	addText("messageip", chrome.i18n.getMessage("messageip"));
	addText("groupboxfilter", chrome.i18n.getMessage("groupboxfilter"));
	addText("usefilter", chrome.i18n.getMessage("usefilter"));
	addText("filtertext", chrome.i18n.getMessage("filtertext"));
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
		var domainlist = localStorage["domainlist"];

		if (dnssecResolver == undefined) {
			dnssecResolver = defaultResolver;
		}
		if (dnssecCustomResolver == undefined) {
			dnssecCustomResolver = defaultCustomResolver;
		}
	        // OMG localstorage has everything as text
	        debugOutput = (debugOutput == undefined || debugOutput == "false") ? false : true;

	        document.dnssecSettings.customResolver.value = dnssecCustomResolver;
	        document.dnssecSettings.debugOutput.checked = debugOutput;
	        document.dnssecSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
	        document.dnssecSettings.domainfilteron.checked = domainfilteron;

		var radiogroup = document.dnssecSettings.resolver;
		for (var i = 0; i < radiogroup.length; i++) {
			var child = radiogroup[i];
				if (child.value == dnssecResolver) {
				    child.checked = "true";
				    break;
			}
		}
	  }
	else
	 {
	        document.dnssecSettings.customResolver.value = unescape(resolver);
		var radiogroup = document.dnssecSettings.resolver;
		var child = radiogroup[choice];
		child.checked = "true";
		var domainfilteron = localStorage["domainfilteron"];
		var domainlist = localStorage["domainlist"];
	        document.dnssecSettings.domainlist.value = domainlist;
		domainfilteron = (domainfilteron == undefined || domainfilteron == "false") ? false : true;
	        document.dnssecSettings.domainfilteron.checked = domainfilteron;
			
	}  //state
});


