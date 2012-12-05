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


// DNSSEC preferences functions
var dnssecExtPrefs = {

  instantApply : true, // default value that changes on pref window load 
  // Some parts of next code are used from UrlbarExt project


  prefObj : Components.classes["@mozilla.org/preferences-service;1"]
            .getService(Components.interfaces.nsIPrefBranch),
  prefBranch : "extensions.dnssec.",

  getInt : function(prefName) {
    try {
      return this.prefObj.getIntPref(this.prefBranch + prefName);
    } catch (ex) {
      return null;
    }
  },

  getBool : function(prefName) {
    try {
      return this.prefObj.getBoolPref(this.prefBranch + prefName);
    } catch (ex) {
      return null;
    }
  },

  getChar : function(prefName) {
    try {
      return this.prefObj.getCharPref(this.prefBranch + prefName);
    } catch (ex) {
      return null;
    }
  },

  setChar : function(prefName, prefValue) {
    try {
      return this.prefObj.setCharPref(this.prefBranch + prefName,
          prefValue);
    } catch (ex) {
      return null;
    }
  },

  setBool : function(prefName, prefValue) {
    try {
      return this.prefObj.setBoolPref(this.prefBranch + prefName,
          prefValue);
    } catch (ex) {
      return null;
    }
  },

  setInt : function(prefName, prefValue) {
    try {
      return this.prefObj.setIntPref(this.prefBranch + prefName,
          prefValue);
    } catch (ex) {
      return null;
    }
  },

  resetUserPref : function(prefName) {
    try {
      this.prefObj.clearUserPref(this.prefBranch + prefName);
    } catch (ex) {
    }
  },

  hasUserValue : function(prefName) {
    try {
      return this.prefObj.prefHasUserValue(this.prefBranch + prefName);
    } catch (ex) {
      return null;
    }
  },


  isInstantApply : function() {
    try {
      return Components.classes["@mozilla.org/preferences-service;1"]
             .getService(Components.interfaces.nsIPrefBranch)
             .getBoolPref("browser.preferences.instantApply", false);
    } catch (ex) {
      return null;
    }
  },

  checkOptdnsserveraddr : function() {
    var str=document.getElementById("dnssec-pref-optdnsserveraddr").value;
    var n=str.split(" ");
    var result=0;
    for(c= 0;c<n.length; c++){
      if (dnssecExtCheckIPaddr.test_ipv4(n[c]) || dnssecExtCheckIPaddr.test_ipv6(n[c])) {
     	 //result=0;
      } else {
     	 result=1;
      } //if
    } //for
    if (result==1) return false;
    else return true;
  },

  savePrefs : function() {  
  switch (document.getElementById("dnssec-pref-dnsserverchoose").value) {
    case '1': // Preset resolvers
      switch (document.getElementById("dnssec-pref-dnsserverpresetchoose").value) {
      case '1': // OARC's ODVR
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-oarcdnsserveraddr").value);
        break;
      case '0': // CZ.NIC's ODVR
      default:
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-cznicdnsserveraddr").value);
        break;
      }
      break;
    case '2': // Custom resolver
      if (this.checkOptdnsserveraddr()) {
        this.setChar("dnsserveraddr", document.getElementById("dnssec-pref-optdnsserveraddr").value);
        document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: black");
      } else {
        document.getElementById("dnssec-pref-optdnsserveraddr").setAttribute("style", "color: red");
      }
      break;
    case '3': // System
      this.setChar("dnsserveraddr", "nofwd"); // empty string for using system resolver conf
      break;
    case '0': // System
    default:
      this.setChar("dnsserveraddr", ""); // empty string for using system resolver conf
      break;
    }
  },

  setElementsattributes : function() {


    var tmpCheck;
	document.getElementById("dnssecok").style.display = 'none';
	document.getElementById("dnssecbogus").style.display = 'none';
        document.getElementById("dnssecerror").style.display = 'none';
	document.getElementById("wrongip").style.display = 'none';
/*     tmpCheck = document.getElementById("dnssec-pref-usesysdnsserver").selected;
    tmpCheck2 = document.getElementById("dnssec-pref-useoptdnsserver").selected;
   if (tmpCheck) {
	document.getElementById("dnssec-pref-testbutton").disabled = !tmpCheck;
        document.documentElement.getButton("accept").disabled = tmpCheck;
	}
    else if (tmpCheck2) {
	document.getElementById("dnssec-pref-testbutton").disabled = !tmpCheck2;
	document.documentElement.getButton("accept").disabled = tmpCheck2;
	}
*/
    // enable preset DNS resolvers menulist only if appropriate radio button is selected
    tmpCheck = document.getElementById("dnssec-pref-usepresetdnsserver").selected;
    document.getElementById("dnssec-pref-dnsserverpresetchoose").disabled = !tmpCheck;
    
    // enable optional DNS address textbox only if appropriate radio button is selected
    tmpCheck = document.getElementById("dnssec-pref-useoptdnsserver").selected;
    document.getElementById("dnssec-pref-optdnsserveraddr").disabled = !tmpCheck;
  },

  get _dnssecok () {
    delete this._dnssecok;
    return this._dnssecok =
      document.getElementById("dnssecok");
  },

  get _dnssecbogus () {
    delete this._dnssecbogus;
    return this._dnssecbogus =
      document.getElementById("dnssecbogus");
  },

  get _dnssecerror() {
    delete this._dnssecerror;
    return this._dnssecerror =
      document.getElementById("dnssecerror");
  },

  get _wrongip() {
    delete this._wrongip;
    return this._wrongip =
      document.getElementById("wrongip");
  },


  pane1Load : function() {
     delete this._stringBundle;
     this._stringBundle = document.getElementById("dnssec-strings-pref");
     this._dnssecok.textContent = this._stringBundle.getString("dnssecok");
     this._dnssecbogus.textContent = this._stringBundle.getString("dnssecbogus");
     this._dnssecerror.textContent = this._stringBundle.getString("dnssecerror");
     this._wrongip.textContent = this._stringBundle.getString("wrongip");
    this.instantApply = this.isInstantApply();
    this.setElementsattributes();
  },

  dnsserverchooseCommand : function() {
    this.setElementsattributes();

    if (this.instantApply) {
      this.windowDialogaccept();
    }
  },

  dnsserverpresetchooseCommand : function() {
    this.dnsserverchooseCommand();
  },

  optdnsserveraddrInput : function() {
    this.setElementsattributes();
    if (this.instantApply) {
      this.windowDialogaccept();
    }
  },

   testdnssec : function() {
     //this.setLoading(true); 
      var options = 7;
      var ip = false; 
      var testnic = 0;
      var dn = "www.nic.cz";
      var addr = "217.31.205.50";
	switch (document.getElementById("dnssec-pref-dnsserverchoose").value) {
	    case '0': // System setting
         	nameserver = "";
            	break;
	    case '1': // Preset
	      switch (document.getElementById("dnssec-pref-dnsserverpresetchoose").value) {
	        case '1': // OARC's ODVR
        	nameserver = document.getElementById("dnssec-pref-oarcdnsserveraddr").value;
	        break;
	      case '0': // CZ.NIC's ODVR
	      default:
	        nameserver =  document.getElementById("dnssec-pref-cznicdnsserveraddr").value;
	        break;
	        }
              break;
	    case '2': // Custom
         	nameserver = document.getElementById("dnssec-pref-optdnsserveraddr").value;
		if (!this.checkOptdnsserveraddr()) { 
		   ip=true;
 		}
            	break;
	    case '3': // Self-validation
         	nameserver = "nofwd";
		options = 5; 
            	break;
	    default:
         	nameserver = "";
            	break;
 	} //switch
   if (ip) {
	document.getElementById("wrongip").style.display = 'block';
   }
   else {
     try {
      // Get the binary plugin
      var dsp = document.getElementById("dnssec-plugin");
      dsp.CacheFree(); 
      //dump('TEST parameters: \"'+ dn + '; ' + options + '; ' + nameserver + '; ' + addr + '\"\n');
      testnic = dsp.Validate(dn, options, nameserver, addr);
      //dump('TEST Return: ' + testnic + '\n');
      //this.setLoading(false);
      if (testnic==0) {
	document.getElementById("dnssecok").style.display = 'none';
	document.getElementById("dnssecbogus").style.display = 'none';
	document.getElementById("dnssecerror").style.display = 'block';
        document.getElementById("wrongip").style.display = 'none';
      }
      else if (testnic==4) {
	document.getElementById("dnssecok").style.display = 'none';
	document.getElementById("dnssecbogus").style.display = 'block';
	document.getElementById("dnssecerror").style.display = 'none';
	document.getElementById("wrongip").style.display = 'none';
      }
      else { 
	document.getElementById("dnssecok").style.display = 'block';
	document.getElementById("dnssecbogus").style.display = 'none';
	document.getElementById("dnssecerror").style.display = 'none';
        document.getElementById("wrongip").style.display = 'none';
	this.savePrefs();
      }
    } catch (ex) {
       dump('Error: Plugin call failed!\n');
    }
   }//if ip
  },

  windowDialogaccept : function() {
        this.savePrefs();
  },

  onUnload : function(prefwindow) {      
      var dsp = document.getElementById("dnssec-plugin");
      dsp.CacheFree();
      return true;
  },


  setLoading : function(state){
  document.getElementById("identifier").style.display = (state) ? 'block' : 'none';
  document.getElementById('identifier').mode =
           (state) ? 'undetermined' : 'determined';
 },

  showPrefWindow : function() {
    var optionsURL = "chrome://dnssec/content/preferences.xul";

    // Check if the pref window is not already opened
    var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"]
                       .getService(Components.interfaces.nsIWindowMediator);
    var enumerator = wm.getEnumerator(null);
    while(enumerator.hasMoreElements()) {
      var win = enumerator.getNext();
      if (win.document.documentURI == optionsURL) {
        win.focus();
        return;
      }
    }

    // Open the pref window
    var features = "chrome,titlebar,toolbar,centerscreen";
    try {
      features += this.isInstantApply() ? ",dialog=no" : ",modal";
    } catch (e) {
      features += ",modal";
    }
    window.openDialog(optionsURL, "", features);
  },
};


// Functions for IP address notation validation
var dnssecExtCheckIPaddr = {

  // Used from http://ipv6blog.net/ipv6-validation-javascript/

  // Support function
  substr_count : function(haystack, needle, offset, length) {

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
  },

  // Test for a valid dotted IPv4 address
  test_ipv4 : function(ip) {

    var match = ip.match(/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);
    return match != null;

  },

  // Test if the input is a valid IPv6 address
  test_ipv6 : function(ip) {

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
    if (this.substr_count(ip, ':')<8)
    {
      var match = ip.match(/^(?::|(?:[a-f0-9]{1,4}:)+):(?:(?:[a-f0-9]{1,4}:)*[a-f0-9]{1,4})?$/i);
      return match != null;
    } 

    // Not a valid IPv6 address
    return false;

  },

}
