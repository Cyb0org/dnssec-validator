/* ***** BEGIN LICENSE BLOCK *****
Copyright 2014 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC/TLSA Validator Add-on.

DNSSEC/TLSA Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC/TLSA Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC/TLSA Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

var debugout = true;
var wrongresolver = false;

//****************************************************************
// TLSA Validator's internal cache - shared with all window tabs
//****************************************************************
// expirate time of one item in the cache [seconds]
var CACHE_ITEM_EXPIR = 600; 

var tlsaExtCache = {

	data: null,

	init: function() {
		// Create new array for caching
		this.data = new Array();
		init = false;
	},


	record: function(tlsaresult, block, expir) {
		this.state = tlsaresult;  // tlsa result
		this.block = block;    // blocked ?
		this.expir = expir;    // expir time
	},

	addRecord: function(domain, tlsaresult, block) {	
		// Get current time
			const cur_t = new Date().getTime();
			var expir = cur_t + CACHE_ITEM_EXPIR * 1000;
			delete this.data[domain];
			this.data[domain] = new this.record(tlsaresult, block, expir);
	},

	getRecord: function(n) {
		const c = this.data;

		if (typeof c[n] != 'undefined') {
			return [c[n].state, c[n].block, c[n].expir];
		}
		return ['', '', ''];
	},

	printContent: function() {
	
		var i = 0;
		var n;
		const c = this.data;

		if (debugout) { 
			console.log('Cache content:');
		}
	          
		for (n in c) {
			if (debugout) { 
				console.log('      r' + i + ': \"' + n 
				+ '\": ' + c[n].state + '; ' + c[n].block 
				+ '; ' + c[n].expir);
			}
      			i++;
		}

		if (debugout) {
			console.log('Total records count: ' + i);
		}
	},

	delAllRecords: function() {

		if (debugout) { 
			console.log('Flushing all cache records...');
		}
		delete this.data;
		this.data = new Array();
	},
};

//****************************************************************
// Initialize DNSSEC binary plugin after start of Safari
//****************************************************************
function InitDnssecPlugin(objectid) {

        var DNSSECPlugin = document.getElementById(objectid);
	if (DNSSECPlugin) {
		DNSSECPlugin.DNSSECCacheInit();
		if (debugout) {
			console.log("DNSSECplugin init ... DONE");
		}
		return DNSSECPlugin;
	} else {
		if (debugout) {
			console.log("DNSSECplugin init ... FAIL!");
		}
		return null;
	}
};

//****************************************************************
// Initialize TLSA binary plugin after start of Safari
//****************************************************************
function InitTlsaPlugin(objectid) {

        var TLSAPlugin = document.getElementById(objectid);
	if (TLSAPlugin) {
		TLSAPlugin.TLSACacheInit();
		tlsaExtCache.init();
		if (debugout) {
			console.log("TLSAplugin init ... DONE");
		}
		return TLSAPlugin;
	} else {
		if (debugout) {
			console.log("TLSAplugin init ... FAIL!");
		}
		return null;
	}
};

//****************************************************************
// Call DNSSEC binary plugin when any validation request was fired 
//****************************************************************
function DnssecValidate(domain, options, resolver, ip) {

	if (dnssecobj != null) {
		var result = dnssecobj.Validate(domain, options, resolver, ip);
		if (debugout) {
	       		console.log("DNSSECplugin return: " + result[0]);
		}
		return result[0];		
	}
	else return null;
};

//****************************************************************
// Call TLSA binary plugin when any validation request was fired
//****************************************************************
function TlsaValidate(cert, len, options, resolver, domain, port, protocol, policy) {

	if (tlsaobj != null) {
		var result = tlsaobj.TLSAValidate(cert, len, options, resolver, domain, port, protocol, policy);
		if (debugout) {
		       	console.log("TLSAplugin return: " + result[0]);
		}
		return result[0];
	}
	else return null; 	
};

//****************************************************************
// Calls when any item of settings was changed
//****************************************************************
function ClearDnssecPluginContetx() {

	if (dnssecobj != null) {
		dnssecobj.DNSSECCacheFree();
		dnssecobj.DNSSECCacheInit();
		if (debugout) {
	       		console.log("DNSSECplugin context was deleted...");
		}
	}
};

//****************************************************************
// Calls when any item of settings was changed
//****************************************************************
function ClearTlsaPluginContetx() {

	if (tlsaobj != null) {
		tlsaobj.TLSACacheFree();
		tlsaobj.TLSACacheInit();
		tlsaExtCache.delAllRecords();
		if (debugout) {
	       		console.log("TLSAplugin context was deleted...");
		}
	}
};
