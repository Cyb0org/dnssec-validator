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

//Define our namespace
if(!cz) var cz={};
if(!cz.nic) cz.nic={};
if(!cz.nic.extension) cz.nic.extension={};

// libCore object
cz.nic.extension.libCore = {

dnsseclib: null,
tlsalib: null,  
  
init: function() {
	AddonManager.getAddonByID("dnssec@nic.cz", function(addon) {
  		
		var abi = Components.classes["@mozilla.org/xre/app-info;1"]
		   .getService(Components.interfaces.nsIXULRuntime).XPCOMABI;
		var os = Components.classes["@mozilla.org/xre/app-info;1"]
		    .getService(Components.interfaces.nsIXULRuntime).OS;

		// Loading from OS libs.         
		try {
			if(os.match("Darwin")) {
				var dnssecLibName = "libDNSSECcore.dylib";
				var tlsaLibName = "libDANEcore.dylib";
			} else if(os.match("WINNT")) {
				var dnssecLibName = "libDNSSECcore.dll";
				var tlsaLibName = "libDANEcore.dll";
			} else if(os.match("Linux")) {
				var dnssecLibName = "libDNSSECcore.so";
				var tlsaLibName = "libDANEcore.so";
			} else if(os.match("FreeBSD")) {
				var dnssecLibName = "libDNSSECcore.so";
				var tlsaLibName = "libDANEcore.so";
			}

			cz.nic.extension.libCore.initlibs(dnssecLibName, 
			    tlsaLibName);

		} catch(e) {
			// Failed loading from OS libs. Fall back to libraries distributed with plugin. 
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix + 
				"Warning: Cannot find system libraries! Libraries distributed with plugin will be used.\n");				
			}

			if(os.match("Darwin")) {
				var dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-osx.dylib")
					.QueryInterface(Components.interfaces.nsIFileURL).file.path;
				var tlsaLibName = addon.getResourceURI("plugins/libDANEcore-osx.dylib")
					.QueryInterface(Components.interfaces.nsIFileURL).file.path;

			} else if(os.match("Linux")) {
				if (abi.match("x86_64")) {
					var dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-linux-x64.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
					var tlsaLibName = addon.getResourceURI("plugins/libDANEcore-linux-x64.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else if (abi.match("x86")) {
					var dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-linux-x86.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
					var tlsaLibName = addon.getResourceURI("plugins/libDANEcore-linux-x86.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else {
					if (cz.nic.extension.dnssecExtension.debugOutput) {
						dump(cz.nic.extension.dnssecExtension.debugPrefix + 
						"Error: Unknown architecture of Linux!\n");				
					}
					return;
				}

			} else if (os.match("FreeBSD")) {
				if (abi.match("x86_64")) {
					var dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-freebsd-x64.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
					var tlsaLibName = addon.getResourceURI("plugins/libDANEcore-freebsd-x64.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else if (abi.match("x86")) {
					var dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-freebsd-x86.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
					var tlsaLibName = addon.getResourceURI("plugins/libDANEcore-freebsd-x86.so")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
				} else {
					if (cz.nic.extension.dnssecExtension.debugOutput) {
						dump(cz.nic.extension.dnssecExtension.debugPrefix + 
						"Error: Unknown architecture of FreeBSD!\n");
					}
					return;
				}

			} else if(os.match("WINNT")) {
				var dnssecLibName = addon.getResourceURI("plugins/libDNSSECcore-win-x86.dll")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;

				var tlsaLibName = addon.getResourceURI("plugins/libDANEcore-win-x86.dll")
						.QueryInterface(Components.interfaces.nsIFileURL).file.path;
			} else {
				if (cz.nic.extension.dnssecExtension.debugOutput) {
					dump(cz.nic.extension.dnssecExtension.debugPrefix + 
					"Error: Unsupported OS!\n");
				}
				return;
			}
			cz.nic.extension.libCore.initlibs(dnssecLibName,
			    tlsaLibName);
		}

	});
},


initlibs: function(dnssecLibName, tlsaLibName) {

	//open libraries
	this.dnsseclib = ctypes.open(dnssecLibName);
	this.tlsalib = ctypes.open(tlsaLibName);

	if (cz.nic.extension.dnssecExtension.debugOutput) {
		dump(cz.nic.extension.dnssecExtension.debugPrefix + 
	            "Loading libraries:\n        " + dnssecLibName + 
		    "\n        " + tlsaLibName + "\n");				
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
	    ctypes.uint16_t,//options
	    ctypes.char.ptr,	//optdnssrv
	    ctypes.char.ptr,	//ipbrowser
	    ctypes.char.ptr.ptr //ipvalidator out	
	    );

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
	    this.dnsseclib.declare("dane_validate",
	    ctypes.default_abi,
	    ctypes.int,		//return state
	    ctypes.ArrayType(ctypes.char.ptr),//certchain[]
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


close: function() {
	this.dnsseclib.close();
	this.tlsalib.close();
}

}
