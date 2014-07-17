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
cz.nic.extension.dnssecLibCore = {

dnsseclib: null,
coreFileName: null,

/* Counts initialisation attempt. */
initAttempt:  0,
ATTEMPT_LIMIT: 5,

dnssec_init: function() {
	AddonManager.getAddonByID("dnssec@nic.cz", function(addon) {

		var abi = Components.classes["@mozilla.org/xre/app-info;1"]
		   .getService(Components.interfaces.nsIXULRuntime).XPCOMABI;
		var os = Components.classes["@mozilla.org/xre/app-info;1"]
		    .getService(Components.interfaces.nsIXULRuntime).OS;

		var dnssecLibName = "unspecified";

		/* Try system location. */
		if(os.match("Darwin")) {
			dnssecLibName = "libDNSSECcore-macosx.dylib";
		} else if(os.match("FreeBSD")) {
			dnssecLibName = "libDNSSECcore-freebsd.so";
		} else if(os.match("Linux")) {
			dnssecLibName = "libDNSSECcore-linux.so";
		} else if(os.match("WINNT")) {
			dnssecLibName = "libDNSSECcore-windows.dll";
		} else {
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Error: Unsupported OS!\n");
			}
			return false;
		}

		try {
			cz.nic.extension.dnssecLibCore._initDnssecLib(dnssecLibName);
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Loaded DNSSEC library:\n        " +
				    dnssecLibName + "\n");
			}
			return true;
		} catch(e) {
			/*
			 * Failed loading OS library. Fall back to library
			 * distributed with the plug-in.
			 */
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Warning: Cannot find DNSSEC system " +
				    "library '" + dnssecLibName + "'! Library " +
				    "distributed with plugin will be used.\n");
			}
		}

		dnssecLibName = "unspecified";

		var abiStr = "unspecified";
		if (abi.match("x86_64")) {
			abiStr = "x64";
		} else if (abi.match("x86")) {
			abiStr = "x86";
		} else {
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Error: Unsupported OS architecture!\n");
			}
			return false;
		}

		if(os.match("Darwin")) {
			dnssecLibName =
			    "plugins/libDNSSECcore-macosx-" + abiStr + ".dylib";
		} else if (os.match("FreeBSD")) {
			dnssecLibName =
			    "plugins/libDNSSECcore-freebsd-" + abiStr + ".so";
		} else if(os.match("Linux")) {
			dnssecLibName =
			    "plugins/libDNSSECcore-linux-" + abiStr + ".so";
		} else if(os.match("WINNT")) {
			dnssecLibName =
			    "plugins/libDNSSECcore-windows-x86.dll";
		}
		dnssecLibName = addon.getResourceURI(dnssecLibName)
		    .QueryInterface(Components.interfaces.nsIFileURL).file
		    .path;

		try {
			cz.nic.extension.dnssecLibCore._initDnssecLib(dnssecLibName);
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Loaded DNSSEC library:\n        " +
				    dnssecLibName + "\n");
			}
			return true;
		} catch(e) {
			/*
			 * Failed loading plug-in distributed library.
			 */
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Warning: Cannot load plug-in core " +
				    "library '" + dnssecLibName + "'.\n");
			}
		}

		/* Last choice. Only for some OS. */
		dnssecLibName = "unspecified";

		if(os.match("Darwin")) {
			/* Fat binary. */
			dnssecLibName = "plugins/libDNSSECcore-macosx.dylib";
		} else {
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Error: Sorry, no core found!\n");
			}
			return false;
		}
		dnssecLibName = addon.getResourceURI(dnssecLibName)
		    .QueryInterface(Components.interfaces.nsIFileURL).file
		    .path;

		try {
			cz.nic.extension.dnssecLibCore._initDnssecLib(dnssecLibName);
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Loaded DNSSEC library:\n        " +
				    dnssecLibName + "\n");
			}
			return true;
		} catch(e) {
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Error: Cannot load plug-in core " +
				    "library '" + dnssecLibName + "'.\n");
			}
		}

		return false;

	});
},

_initDnssecLib: function(dnssecLibName) {

	++this.initAttempt;

	//open library
	this.dnsseclib = ctypes.open(dnssecLibName);

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

	this.coreFileName = dnssecLibName;
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
	var outputParam = new ctypes.char.ptr();
	var retval = this.dnssec_validate(dn, options, nameserver, addr,
	    outputParam.address());
	return [retval, outputParam.readString()];
},

// shoutdown lib
dnssec_close: function() {
	this.dnsseclib.close();
},

};


/*
 * Supported commands/returns are:
 *
 * initialise/initialiseRet
 * validate/validateRet
 *
 */
onmessage = function(event) {

	var queryParams = event.data.split("§");
	let cmd = queryParams[0];
	let retval = null;

	if (cz.nic.extension.dnssecLibCore.initAttempt >
	    cz.nic.extension.dnssecLibCore.ATTEMPT_LIMIT) {
		retval = "initialiseRet§fail";
		postMessage(retval);
		return;
	}

	switch (cmd) {
	case "initialise":
		try {
			cz.nic.extension.dnssecLibCore._initDnssecLib(
			    queryParams[1]);
			retval = "initialiseRet§ok";
		} catch(e) {
			retval = "initialiseRet§tryAgain";
		}
		postMessage(retval);
		break;
	case "validate":
		if (null == cz.nic.extension.dnssecLibCore.coreFileName) {
/*
			if (cz.nic.extension.dnssecExtension.debugOutput) {
				dump(cz.nic.extension.dnssecExtension.debugPrefix +
				    "Calling uninitialised worker.\n");
			}
*/
			setTimeout(function() {
/*
				if (cz.nic.extension.dnssecExtension.debugOutput) {
					dump(cz.nic.extension.dnssecExtension.debugPrefix +
					    "Trying to call again.\n");
				}
*/
				this.onmessage(event);
			}, 1000);
			return;
		}
		let dn = queryParams[1];
		let options = queryParams[2];
		let nameserver = queryParams[3];
		let addr = queryParams[4];
		options = parseInt(options, 10);

		let outputParam = new ctypes.char.ptr();
		retval = cz.nic.extension.dnssecLibCore.dnssec_validate_core(
		    dn, options, nameserver, addr, outputParam);
		retval = "validateRet§" + dn + "§" + retval[0] +
		    "§" + retval[1] + "§" + addr;
		postMessage(retval);
		break;
	default:
		break;
	}
};
