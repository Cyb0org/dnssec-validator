/* ***** BEGIN LICENSE BLOCK *****
Copyright 2014 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator 2.x Add-on.

DNSSEC Validator 2.x Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator 2.x Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.x Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

Components.utils.import("resource://gre/modules/ctypes.jsm");
Components.utils.import("resource://gre/modules/AddonManager.jsm"); 

// libCore object
cz.nic.extension.libCore = {

dnsseclib: null,
tlsalib: null,  
  
dnssec_init: function() {
	AddonManager.getAddonByID("dnssec@nic.cz", function(addon) {
  		
		var abi = Components.classes["@mozilla.org/xre/app-info;1"]
		   .getService(Components.interfaces.nsIXULRuntime).XPCOMABI;
		var os = Components.classes["@mozilla.org/xre/app-info;1"]
		    .getService(Components.interfaces.nsIXULRuntime).OS;

		let dnssecLibName = "unpecified";

		// Loading from OS DNSSEC lib.         
		try {
			if(os.match("Darwin")) {
				dnssecLibName = "libDNSSECcore-macosx.dylib";
			} else if(os.match("WINNT")) {
				dnssecLibName = "libDNSSECcore-windows.dll";
			} else if(os.match("Linux")) {
				dnssecLibName = "libDNSSECcore-linux.so";
			} else if(os.match("FreeBSD")) {
				dnssecLibName = "libDNSSECcore-freebsd.so";
			}

			cz.nic.extension.libCore._initDnssecLib(dnssecLibName);
			return true;

		} catch(e) {
			// Failed loading from OS lib. Fall back to library distributed with plugin. 
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix + 
				    "Warning: Cannot find DNSSEC system library! Library distributed with plugin will be used.\n");	
			}

			if(os.match("Darwin")) {
				dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-macosx.dylib")
				    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
			} else if(os.match("Linux")) {
				if (abi.match("x86_64")) {
					dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-linux-x64.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else if (abi.match("x86")) {
					dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-linux-x86.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else {
					if (cz.nic.extension.dnssecExtension.debugOutput) {
						dump(cz.nic.extension.dnssecExtension.debugPrefix + 
						    "Error: Unknown architecture of Linux!\n");
					}
					return false;
				}

			} else if (os.match("FreeBSD")) {
				if (abi.match("x86_64")) {
					dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-freebsd-x64.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else if (abi.match("x86")) {
					dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-freebsd-x86.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else {
					if (cz.nic.extension.dnssecExtension.debugOutput) {
						dump(cz.nic.extension.dnssecExtension.debugPrefix + 
						    "Error: Unknown architecture of FreeBSD!\n");
					}
					return false;
				}

			} else if(os.match("WINNT")) {
				dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-windows-x86.dll")
				    .QueryInterface(Components.interfaces.nsIFileURL).file.path;

			} else {
				if (cz.nic.extension.dnssecExtension.debugOutput) {
					dump(cz.nic.extension.dnssecExtension.debugPrefix + 
					    "Error: Unsupported OS!\n");
				}
				return false;
			}
			cz.nic.extension.libCore._initDnssecLib(dnssecLibName);
			return true;
		}

	});
},


dane_init: function() {
	AddonManager.getAddonByID("dnssec@nic.cz", function(addon) {
  		
		var abi = Components.classes["@mozilla.org/xre/app-info;1"]
		   .getService(Components.interfaces.nsIXULRuntime).XPCOMABI;
		var os = Components.classes["@mozilla.org/xre/app-info;1"]
		    .getService(Components.interfaces.nsIXULRuntime).OS;

		let tlsaLibName = "unpecified";

		// Loading from OS DANE libs.         
		try {
			if(os.match("Darwin")) {
				tlsaLibName = "libDANEcore-macosx.dylib";
			} else if(os.match("WINNT")) {
				tlsaLibName = "libDANEcore-windows.dll";
			} else if(os.match("Linux")) {
				tlsaLibName = "libDANEcore-linux.so";
			} else if(os.match("FreeBSD")) {
				tlsaLibName = "libDANEcore-freebsd.so";
			}

			cz.nic.extension.libCore._initTlsaLib(tlsaLibName);
			return true;

		} catch(e) {
			// Failed loading from OS libs. Fall back to libraries distributed with plugin. 
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix + 
				    "Warning: Cannot find DANE system library! Library distributed with plugin will be used.\n");
			}

			if(os.match("Darwin")) {
				tlsaLibName = addon.getResourceURI("plugins/libDANEcore-macosx.dylib")
				    .QueryInterface(Components.interfaces.nsIFileURL).file.path;

			} else if(os.match("Linux")) {
				if (abi.match("x86_64")) {
					tlsaLibName = addon.getResourceURI("plugins/libDANEcore-linux-x64.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else if (abi.match("x86")) {
					tlsaLibName = addon.getResourceURI("plugins/libDANEcore-linux-x86.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else {
					if (cz.nic.extension.dnssecExtension.debugOutput) {
						dump(cz.nic.extension.dnssecExtension.debugPrefix + 
						    "Error: Unknown architecture of Linux!\n");				
					}
					return false;
				}

			} else if (os.match("FreeBSD")) {
				if (abi.match("x86_64")) {
					tlsaLibName = addon.getResourceURI("plugins/libDANEcore-freebsd-x64.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else if (abi.match("x86")) {
					tlsaLibName = addon.getResourceURI("plugins/libDANEcore-freebsd-x86.so")
					    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else {
					if (cz.nic.extension.dnssecExtension.debugOutput) {
						dump(cz.nic.extension.dnssecExtension.debugPrefix + 
						    "Error: Unknown architecture of FreeBSD!\n");
					}
					return false;
				}

			} else if(os.match("WINNT")) {
				tlsaLibName = addon.getResourceURI("plugins/libDANEcore-windows-x86.dll")
				    .QueryInterface(Components.interfaces.nsIFileURL).file.path;
			} else {
				if (cz.nic.extension.dnssecExtension.debugOutput) {
					dump(cz.nic.extension.dnssecExtension.debugPrefix + 
					    "Error: Unsupported OS!\n");
				}
				return false;
			}
			cz.nic.extension.libCore._initTlsaLib(tlsaLibName);
			return true;
		}

	});
},


_initDnssecLib: function(dnssecLibName) {

	//open library
	this.dnsseclib = ctypes.open(dnssecLibName);

	if (cz.nic.extension.dnssecExtension.debugOutput) {
		dump(cz.nic.extension.dnssecExtension.debugPrefix + 
	            "Loading DNSSEC library:\n        " + dnssecLibName + "\n");
	}

	//declare dnssec API functions
	this.dnssec_validation_init = 
	    this.dnsseclib.declare("dnssec_validation_init",
	    ctypes.default_abi,
	    ctypes.int);

	this.dnssec_validation_deinit = 
	    this.dnsseclib.declare("dnssec_validation_deinit",
	    ctypes.default_abi,
	    ctypes.int);

	this.dnssec_validate = 
	    this.dnsseclib.declare("dnssec_validate",
	    ctypes.default_abi,
	    ctypes.int,		//return state
	    ctypes.char.ptr,	//doamin
	    ctypes.uint16_t,	//options
	    ctypes.char.ptr,	//optdnssrv
	    ctypes.char.ptr,	//ipbrowser
	    ctypes.char.ptr.ptr //ipvalidator out
	    );
},


_initTlsaLib: function(tlsaLibName) {

	//open library
	this.tlsalib = ctypes.open(tlsaLibName);

	if (cz.nic.extension.daneExtension.debugOutput) {
		dump(cz.nic.extension.daneExtension.debugPrefix + 
	            "Loading DANE library:\n        " + tlsaLibName + "\n");
	}

	//declare tlsa API functions    
	this.dane_validation_init = 
	    this.tlsalib.declare("dane_validation_init",
	    ctypes.default_abi,
	    ctypes.int);


	this.dane_validation_deinit = 
	    this.tlsalib.declare("dane_validation_deinit",
	    ctypes.default_abi,
	    ctypes.int);

	this.dane_validate = 
	    this.tlsalib.declare("dane_validate",
	    ctypes.default_abi,
	    ctypes.int,		//return state
	    ctypes.char.ptr.array(),//certchain[]
	    ctypes.int,		//certcount
	    ctypes.uint16_t,	//options
	    ctypes.char.ptr,	//optdnssrv
	    ctypes.char.ptr,	//domain
	    ctypes.char.ptr, 	//port
	    ctypes.char.ptr, 	//protocol
	    ctypes.int		//policy
	    );
},


// wrapper to dnssec init
dnssec_validation_init_core: function() {
	var res = this.dnssec_validation_init();
	return res;
},

// wrapper to dnssec deinit
dnssec_validation_deinit_core: function() {
	var res = this.dnssec_validation_deinit();
	return res;
},


// wrapper to dnssec validation query
dnssec_validate_core: function(dn, options, nameserver, addr, outputParam) {

	let outputParam = new ctypes.char.ptr();
	var retval = this.dnssec_validate(dn, options, nameserver, addr, 
	    outputParam.address());
	return [retval, outputParam.readString()];
},



// wrapper to tlsa init
dane_validation_init_core: function() {
	var res = this.dane_validation_init();
	return res;
},

// wrapper to tlsa deinit
dane_validation_deinit_core: function() {
	var res = this.dane_validation_deinit();
	return res;
},

// wrapper to dnssec validation query
dane_validate_core: function(certchain, certlen, options, nameserver, dname,
    port, protocol, policy) {

	let ptrArrayType = ctypes.char.ptr.array(certlen);
	let certCArray = ptrArrayType();

	for (let i = 0; i < certlen; ++i) {
		/* Convert JS array of strings to array of char *. */
		certCArray[i] = ctypes.char.array()(certchain[i]);
	}

	var retval = this.dane_validate(certCArray, certlen, options,
	    nameserver, dname, port.toString(), protocol, policy);
	return retval;
},

dnssec_close: function() {
	this.dnsseclib.close();
},

dane_close: function() {
	this.tlsalib.close();
}

}
