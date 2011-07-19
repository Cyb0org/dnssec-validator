# ***** BEGIN LICENSE BLOCK *****
# Copyright 2010, 2011 CZ.NIC, z.s.p.o.
#
# Authors: Zbynek Michl <zbynek.michl@nic.cz>
#
# This file is part of DNSSEC Validator Add-on.
#
# DNSSEC Validator Add-on is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# DNSSEC Validator Add-on is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
# ***** END LICENSE BLOCK *****

set(PLUGIN_NAME "DNSSECValidatorPlugin")
set(PLUGIN_PREFIX "DSV")
set(COMPANY_NAME "CZNICLabs")

# ActiveX constants:
set(FBTYPELIB_NAME DNSSECValidatorPluginLib)
set(FBTYPELIB_DESC "DNSSECValidatorPlugin 1.0 Type Library")
set(IFBControl_DESC "DNSSECValidatorPlugin Control Interface")
set(FBControl_DESC "DNSSECValidatorPlugin Control Class")
set(IFBComJavascriptObject_DESC "DNSSECValidatorPlugin IComJavascriptObject Interface")
set(FBComJavascriptObject_DESC "DNSSECValidatorPlugin ComJavascriptObject Class")
set(IFBComEventSource_DESC "DNSSECValidatorPlugin IFBComEventSource Interface")
set(AXVERSION_NUM "1")

# NOTE: THESE GUIDS *MUST* BE UNIQUE TO YOUR PLUGIN/ACTIVEX CONTROL!  YES, ALL OF THEM!
set(FBTYPELIB_GUID 9cb03b6f-0b13-5b32-94c3-0b07838f2b19)
set(IFBControl_GUID 3267df51-0c9f-5be5-9212-36588a8b0160)
set(FBControl_GUID 681bf0ac-2513-5423-a383-9f0086f3a40a)
set(IFBComJavascriptObject_GUID 9d18c09e-54d7-5909-920e-10e77e3cf3c4)
set(FBComJavascriptObject_GUID f4d53565-80c3-55d6-930c-c71248cc7c6b)
set(IFBComEventSource_GUID 5244e87f-f56a-5c71-9e23-5944da961431)

# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "CZNICLabs.DNSSECValidatorPlugin")
set(MOZILLA_PLUGINID "nic.cz/DNSSECValidatorPlugin")

# strings
set(FBSTRING_CompanyName "CZ.NIC Labs")
set(FBSTRING_FileDescription "Plug-in used by DNSSEC Validator extension")
set(FBSTRING_PLUGIN_VERSION "1.0.2")
set(FBSTRING_LegalCopyright "Copyright 2010, 2011 CZ.NIC Labs")
set(FBSTRING_PluginFileName "np${PLUGIN_NAME}.dll")
set(FBSTRING_ProductName "DNSSEC Validator Plug-in")
set(FBSTRING_FileExtents "")
set(FBSTRING_PluginName "DNSSEC Validator Plug-in")
set(FBSTRING_MIMEType "application/x-dnssecvalidator")

# Mac plugin settings
set(FBMAC_USE_QUICKDRAW 0)
set(FBMAC_USE_CARBON 0)
set(FBMAC_USE_COCOA 0)
set(FBMAC_USE_COREGRAPHICS 0)
set(FBMAC_USE_COREANIMATION 0)

# If you want to register per-machine on Windows, uncomment this line
#set (FB_ATLREG_MACHINEWIDE 1)

# disable plugin drawing support
set(FB_GUI_DISABLED 1)
