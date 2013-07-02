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

var tlsaValidator = {

 overrideService: Components.classes["@mozilla.org/security/certoverride;1"]
					.getService(Components.interfaces.nsICertOverrideService),
          
  state : {
      STATE_IS_BROKEN : 
	      Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN,
      STATE_IS_INSECURE :
	      Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE,
      STATE_IS_SECURE :
	      Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE
  },


    ALLOW_TYPE_01: 1,
    ALLOW_TYPE_23: 2,

  
  //gets valid or invalid certificate used by the browser
  getCertificate: function(browser) {
    var uri = browser.currentURI;
    var ui = browser.securityUI;
    var cert = this.get_valid_cert(ui);
    if(!cert){
      cert = this.get_invalid_cert(uri);
    }

    if(!cert) {
      return null;
    }
    return cert;
  },


  // gets current certificate, if it PASSED the browser check 
  get_valid_cert: function(ui) {
    try { 
      ui.QueryInterface(Components.interfaces.nsISSLStatusProvider); 
      if(!ui.SSLStatus) 
	      return null; 
      return ui.SSLStatus.serverCert; 
    }
    catch (e) {
      org.os3sec.Extval.Extension.logMsg('get_valid_cert: ' + e);
      return null;
    }
  },
  
  // gets current certificate, if it FAILED the security check
  get_invalid_cert: function(uri) {
    var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
		if(!gSSLStatus){
			return null;
		}
		return gSSLStatus.QueryInterface(Components.interfaces.nsISSLStatus)
				.serverCert;
  },
  
  get_invalid_cert_SSLStatus: function(uri) {
    var recentCertsSvc = 
		Components.classes["@mozilla.org/security/recentbadcerts;1"]
			.getService(Components.interfaces.nsIRecentBadCertsService);
		if (!recentCertsSvc)
			return null;

		var port = (uri.port == -1) ? 443 : uri.port;  

		var hostWithPort = uri.host + ":" + port;
		var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
		if (!gSSLStatus)
			return null;
		return gSSLStatus;
  },
  
  //Override the certificate as trusted
  do_override: function(browser, cert) { 
    var uri = browser.currentURI;
    
    org.os3sec.Extval.Extension.logMsg('Overriding certificate trust ');
    
    //Get SSL status (untrusted flags)
    var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
    if(gSSLStatus == null) { 
	    return false; 
    } 
    var flags = 0;
    if(gSSLStatus.isUntrusted)
	    flags |= this.overrideService.ERROR_UNTRUSTED;
    if(gSSLStatus.isDomainMismatch)
	    flags |= this.overrideService.ERROR_MISMATCH;
    if(gSSLStatus.isNotValidAtThisTime)
	    flags |= this.overrideService.ERROR_TIME;
    //override the certificate trust
    this.overrideService.clearValidityOverride(uri.asciiHost, uri.port);
    this.overrideService.rememberValidityOverride(uri.asciiHost, uri.port, cert, flags, true);

    setTimeout(function (){ browser.loadURIWithFlags(uri.spec, flags);}, 25);
  },

     // check if URI had an untrusted cert and return the status
getInvalidCertStatus: function (uri){
            var recentCertsSvc = 
            Components.classes["@mozilla.org/security/recentbadcerts;1"]
                .getService(Components.interfaces.nsIRecentBadCertsService);
            if (!recentCertsSvc)
                return null;

            var port = (uri.port == -1) ? 443 : uri.port;  

            var hostWithPort = uri.host + ":" + port;
            var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
            if (!gSSLStatus)
                return null;
            return gSSLStatus;
},



check_tlsa: function (uri,port){
	dump("DANE: --- TLSA validation start ---\n");
	var cert = this.getCertificate(window.gBrowser);
    	if(!cert) {
	  dump("DANE: No certificate!!!\n");
      	  return;
        }
	var state = window.gBrowser.securityUI.state;
	dump("DANE: State is\n" + state +"\n");
	var derCerts = new Array();
	var chain = cert.getChain();
	//dump("DANE: chain is\n" + chain +"\n");
        var len = chain.length;
        for (var i = 0; i < chain.length; i++) {
		//dump(i + "\n");   
                var cert = chain.queryElementAt(i, Components.interfaces.nsIX509Cert);
		//dump("DANE: Cert is\n" + cert +"\n");
                var derData = cert.getRawDER({});
		//dump("DANE: derData is\n" + derData +"\n");
                // derData is Blob, can't pass it as Blob, can't pass it as
                // string because of Unicode.
                // Fairly sure the next line tops ugliness of visualbasic
                var derHex = derData.map(function(x) {return ("0"+x.toString(16)).substr(-2);}).join("");
                derCerts.push(derHex);
		//dump("derHex:\n" + derHex + "\n");
        } //for
	var tlsa = document.getElementById("dane-tlsa-plugin");
	var policy = this.ALLOW_TYPE_01 | this.ALLOW_TYPE_23;
        var protocol = "tcp";
        var daneMatch = tlsa.TLSAValidate(derCerts, len, 5, "",  uri.asciiHost, port, protocol, policy);
        dump("DANE: host " + uri.asciiHost + " : " + daneMatch[0] +"\n");
//        if (uri.asciiHost == gBrowser.currentURI.asciiHost) 
	tlsaExtHandler.setSecurityState(daneMatch[0]);
	//tlsa.TLSACacheFree();
        //dump("dercer " + daneMatch.derCert + ", pemCert " + daneMatch.pemCert + "\n");
        //dump("tlsa " + daneMatch.tlsa + "\n");
	dump("DANE: --- TLSA validation end ---\n");
	return daneMatch[0];
}
}

