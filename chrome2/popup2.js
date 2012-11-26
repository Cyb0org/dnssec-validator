        function addText(id, str){
            if (document.createTextNode){
                var tn = document.createTextNode(str);
                document.getElementById(id).appendChild(tn);
            }
        }

	function DNSSECicon2(icon){
	    var pic = document.getElementById("dnssec-icon2"); 
	    if (pic == typeof('undefined')) return;
	    pic.src = icon;
	}

        resultRegexp = /\?([^?,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)$/;
        matches = resultRegexp.exec(document.location.href);
	domain = matches[1];
        statusString = matches[2];
        icon = matches[3];
	status = matches[4];
	statuspre = matches[5];
	info = matches[6];    
        addText("domain-name-title", domain);
	addText("domain-name-text", domain);
        addText("long-text", chrome.i18n.getMessage(statusString));
	addText("long-text-domain", chrome.i18n.getMessage(statuspre));
	addText("dnssec-title", chrome.i18n.getMessage(status));
	addText("dnssec-info", chrome.i18n.getMessage(info));
	addText("homepage", chrome.i18n.getMessage("homepage"));	
	DNSSECicon2(icon);
