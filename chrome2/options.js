var defaultResolver = ""; // LDNS will use system resolver if empty string is passed
var defaultCustomResolver = "8.8.8.8";

var dnssecExtNPAPIConst = {
  		DNSSEC_EXIT_FAILED                         : 0, /* state is unknown or fail*/
		DNSSEC_EXIT_DOMAIN_UNSECURED 		   : 1, /* domain is not secured */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP   : 2, /* domain name is secured by DNSSEC and the IP address of browser is valid */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP : 3, /* domain name is secured by DNSSEC but the IP address of browser is invalid */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS        : 4, /* domain signature is not valid or chain of trust is not established */
  		DNSSEC_EXIT_NODOMAIN_UNSECURED             : 5, /* non-existent domain is not secured */
  		DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID       : 6, /* non-existent domain is secured by DNSSEC */
  		DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID     : 7, /* non-existent domain is not valid or chain of trust is not established */
  		DNSSEC_INPUT_FLAG_DEBUGOUTPUT              : 1, /* debug output */
  		DNSSEC_INPUT_FLAG_USEFWD                   : 2, /* use TCP instead of default UDP */
  		DNSSEC_INPUT_FLAG_RESOLVIPV4               : 4, /* resolve IPv4 address (A record) */
  		DNSSEC_INPUT_FLAG_RESOLVIPV6               : 8, /* resolve IPv6 address (AAAA record) */
};

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
		    case 1: // Preset
         		nameserver = child.value;
			chioce=1;
            	        break;
		    case 2: // Preset
         		nameserver = child.value;
			chioce=2;
            	        break;
		    case 3: // Custom
			chioce=3;
         		tmp = document.dnssecSettings.customResolver.value;
			if (!checkOptdnsserveraddr(tmp)) { 
			   ip=true;
 		        }
			else
			{
			nameserver = tmp;
			}
            	        break;
		    case 4: // NOFWD
			chioce=4;
         		nameserver = "nofwd";
			options = 5; ;
            	    	break;
		    } //switch
	         } // if
	} // for
   if (ip) {
        window.open('options.html?0,'+chioce+','+tmp, "_top");
   }
   else {
     try {
      console.log('INIT parameters: \"'+ dn + '; ' + options + '; ' + nameserver + '; ' + addr + '\"\n');
      document.write("<object id=\"dnssec-plugin\" type=\"application/x-dnssecvalidator\" width=\"0\" height=\"0\"></object>");
      var plugin = document.getElementById("dnssec-plugin");
      plugin.CacheFree();
      testnic = plugin.Validate(dn, options, nameserver, addr);
      console.log('REsult: \"'+ testnic + '\"\n');
      if (testnic==0) {
        window.open('options.html?1,'+chioce+','+tmp, "_top");
      }
      else if (testnic==4) {
        window.open('options.html?2,'+chioce+','+tmp, "_top");
      }
      else { 
        window.open('options.html?3,'+chioce+','+tmp, "_top");
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
	addText("resolver1", chrome.i18n.getMessage("resolver1"));
	addText("resolver2", chrome.i18n.getMessage("resolver2"));
	addText("resolver3", chrome.i18n.getMessage("resolver3"));
	addText("resolver4", chrome.i18n.getMessage("resolver4"));
	addText("messageok", chrome.i18n.getMessage("messageok"));
	addText("messagebogus", chrome.i18n.getMessage("messagebogus"));
	addText("messageerror", chrome.i18n.getMessage("messageerror"));
	addText("messageip", chrome.i18n.getMessage("messageip"));
	document.getElementById("testbutton").value=chrome.i18n.getMessage("testbutton");
	document.getElementById("savebutton").value=chrome.i18n.getMessage("savebutton");
	document.getElementById("cancelbutton").value=chrome.i18n.getMessage("cancelbutton");

	if (state==4) {
		var dnssecResolver = localStorage["dnssecResolver"];
        	// IP address of custom resolver
        	var dnssecCustomResolver = localStorage["dnssecCustomResolver"];
        	// debug output of resolving to stderr
        	var debugOutput = localStorage["dnssecDebugOutput"];

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
	        document.dnssecSettings.customResolver.value = resolver;
		var radiogroup = document.dnssecSettings.resolver;
		var child = radiogroup[choice];
		child.checked = "true";
			
	}  //state
});


