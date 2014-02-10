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

function openNewTab(popoverId){

	var toolbarItemId = "infos";
	var toolbarItem = safari.extension.toolbarItems.filter(function (tbi) {
	return tbi.identifier == toolbarItemId && tbi.browserWindow == safari.application.activeBrowserWindow;})[0];
	var popover = safari.extension.popovers.filter(function (po) { return po.identifier == popoverId;})[0];
	toolbarItem.popover = popover;
	toolbarItem.popover.hide();
	toolbarItem.image = safari.extension.baseURI + "icons/default.png";
	toolbarItem.toolTip = "DNSSEC/TLSA Validator"; 
	safari.application.activeBrowserWindow.openTab().url = "http://www.dnssec-validator.cz/";
};
