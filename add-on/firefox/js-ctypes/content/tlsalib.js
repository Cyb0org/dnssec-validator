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

//Define our namespace
if(!cz) var cz={};
if(!cz.nic) cz.nic={};
if(!cz.nic.extension) cz.nic.extension={};

// libCore object
cz.nic.extension.daneLibCore = {

tlsalib: null,  
  
dane_init: function() {
	AddonManager.getAddonByID("dnssec@nic.cz", function(addon) {

		var abi = Components.classes["@mozilla.org/xre/app-info;1"]
		   .getService(Components.interfaces.nsIXULRuntime).XPCOMABI;
		var os = Components.classes["@mozilla.org/xre/app-info;1"]
		    .getService(Components.interfaces.nsIXULRuntime).OS;

		var tlsaLibName = "unpecified";

		if(os.match("Darwin")) {
			tlsaLibName = "libDANEcore-macosx.dylib";
		} else if(os.match("FreeBSD")) {
			tlsaLibName = "libDANEcore-freebsd.so";
		} else if(os.match("Linux")) {
			tlsaLibName = "libDANEcore-linux.so";
		} else if(os.match("WINNT")) {
			tlsaLibName = "libDANEcore-windows.dll";
		} else {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.daneExtension.debugPrefix + 
				    "Error: Unsupported OS!\n");
			}
			return false;
		}

		try {
			cz.nic.extension.libCore._initTlsaLib(tlsaLibName);
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.daneExtension.debugPrefix + 
			            "Loaded DANE library:\n        " + tlsaLibName + "\n");
			}
			return true;
		} catch(e) {
			/*
			 * Failed loading OS library. Fall back to library
			 * distributed with the plug-in.
			 */
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.daneExtension.debugPrefix + 
				    "Warning: Cannot find DANE system library! Library distributed with plugin will be used.\n");
			}
		}

		tlsaLibName = "unspecified";

		var abiStr = "unspecified";
		if (abi.match("x86_64")) {
			abiStr = "x64";
		} else if (abi.match("x86")) {
			abiStr = "x86";
		} else {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.daneExtension.debugPrefix + 
				    "Error: Unsupported OS architecture!\n");
			}
			return false;
		}

		if(os.match("Darwin")) {
			tlsaLibName =
			    "plugins/libDANEcore-macosx-" + abiStr + ".dylib";
		} else if (os.match("FreeBSD")) {
			tlsaLibName =
			    "plugins/libDANEcore-freebsd-" + abiStr + ".so";
		} else if(os.match("Linux")) {
			tlsaLibName =
			    "plugins/libDANEcore-linux-" + abiStr + ".so";
		} else if(os.match("WINNT")) {
			tlsaLibName =
			    "plugins/libDANEcore-windows-x86.dll";
		}
		tlsaLibName = addon.getResourceURI(tlsaLibName)
		    .QueryInterface(Components.interfaces.nsIFileURL).file
		    .path;

		try {
			cz.nic.extension.libCore._initTlsaLib(tlsaLibName);
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.daneExtension.debugPrefix + 
			            "Loaded DANE library:\n        " + tlsaLibName + "\n");
			}
			return true;
		} catch(e) {
			/* Failed loading plug-in distributed library.
			 */
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.daneExtension.debugPrefix + 
				    "Warning: Cannot load plug-in core library.\n");
			}
		}

		/* Last choice. Only for some OS.*/
		tlsaLibName = "unspecified";

		if(os.match("Darwin")) {
			/* Fat binary. */
			tlsaLibName = "plugins/libDANEcore-macosx-.dylib";
		} else {
			if (cz.nic.extension.daneExtension.debugOutput) {
				dump(cz.nic.extension.daneExtension.debugPrefix + 
				    "Error: Sorry, no core found!\n");
			}
			return false;
		}
		tlsaLibName = addon.getResourceURI(tlsaLibName)
		    .QueryInterface(Components.interfaces.nsIFileURL).file
		    .path;

		cz.nic.extension.libCore._initTlsaLib(tlsaLibName);
		if (cz.nic.extension.daneExtension.debugOutput) {
			dump(cz.nic.extension.daneExtension.debugPrefix + 
		            "Loaded DANE library:\n        " + tlsaLibName + "\n");
		}

		return true;

	});
},

_initTlsaLib: function(tlsaLibName) {

	//open library
	this.tlsalib = ctypes.open(tlsaLibName);

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

	var ptrArrayType = ctypes.char.ptr.array(certlen);
	var certCArray = ptrArrayType();

	for (var i = 0; i < certlen; ++i) {
		/* Convert JS array of strings to array of char *. */
		certCArray[i] = ctypes.char.array()(certchain[i]);
	}

	var retval = this.dane_validate(certCArray, certlen, options,
	    nameserver, dname, port.toString(), protocol, policy);
	return retval;
},

dane_close: function() {
	this.tlsalib.close();
}

};



onmessage = function(event) {

	var queryParams = event.data.split("§");
	var dn = queryParams[0];	
	var options = queryParams[1];
	var nameserver = queryParams[2];
	var addr = queryParams[3];
	options = parseInt(options, 10);

	var retval = 0;

	//open library
	let tlsaLibName = "plugins/libDANEcore-linux-x64.so";
	var tlsalib = ctypes.open(tlsaLibName);

	var dane_validate = tlsalib.declare("dane_validate",
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


	var ptrArrayType = ctypes.char.ptr.array(certlen);
	var certCArray = ptrArrayType();

	for (var i = 0; i < certlen; ++i) {
		/* Convert JS array of strings to array of char *. */
		certCArray[i] = ctypes.char.array()(certchain[i]);
	}

	retval = dane_validate(certCArray, certlen, options,
	    nameserver, dname, port.toString(), protocol, policy);
	return retval;

	var retval = dnssec_validate(dn, options, nameserver, addr, outputParam.address());
	retval = dn + "§" + retval + "§" + outputParam.readString() + "§" + addr;
	postMessage(retval);
	return;
};

