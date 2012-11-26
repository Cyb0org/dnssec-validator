        function addText(id, str){
            if (document.createTextNode){
                var tn = document.createTextNode(str);
                document.getElementById(id).appendChild(tn);
            }
        }

	function DNSSECicon(icon){
	    var pic = document.getElementById("dnssec-icon"); 
	    if (pic == typeof('undefined')) return;
	    pic.src = icon;
	}

	function NextLevel(overal){
	    var pic = document.getElementById("moreinfo"); 
	    if (pic == typeof('undefined')) return;
	    pic.href = "detail-info.html?"+overal;
	}

        resultRegexp = /\?([^?,]+),([^,]+),([^,]+),([^,]+),([^,]+)$/;
        matches = resultRegexp.exec(document.location.href);
	domain = matches[1];
        statusString = matches[2];
        icon = matches[3];
	status = matches[4];
	statuspre = matches[5];
	overal = domain + "," + statusString + "," + icon + "," + status + "," + statuspre + "," + statusString + "Info";      
        addText("domain-name-title", domain);
	addText("domain-name-text", domain);
        addText("long-text", chrome.i18n.getMessage(statusString));
	addText("long-text-domain", chrome.i18n.getMessage(statuspre));
	addText("dnssec-title", chrome.i18n.getMessage(status));
	addText("moreinfo", chrome.i18n.getMessage("moreinfo"));
	DNSSECicon(icon);	
	NextLevel(overal);
