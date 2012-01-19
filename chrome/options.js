var defaultResolver = ""; // LDNS will use system resolver if empty string is passed
var defaultCustomResolver = "127.0.0.1";

function loadOptions() {
        // choice of resolver
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

function saveOptions() {
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
}

function eraseOptions() {
	localStorage.removeItem("dnssecResolver");
	localStorage.removeItem("dnssecCustomResolver");
	localStorage.removeItem("dnssecDebugOutput");
	location.reload();
}
