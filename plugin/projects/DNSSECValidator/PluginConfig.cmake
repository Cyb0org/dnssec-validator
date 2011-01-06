#/**********************************************************\ 
#
# Auto-Generated Plugin Configuration file
# for DNSSEC Validator
#
#\**********************************************************/

set(PLUGIN_NAME "DNSSECValidator")
set(PLUGIN_PREFIX "DSV")
set(COMPANY_NAME "CZNICLabs")

# ActiveX constants:
set(FBTYPELIB_NAME DNSSECValidatorLib)
set(FBTYPELIB_DESC "DNSSECValidator 1.0 Type Library")
set(IFBControl_DESC "DNSSECValidator Control Interface")
set(FBControl_DESC "DNSSECValidator Control Class")
set(IFBComJavascriptObject_DESC "DNSSECValidator IComJavascriptObject Interface")
set(FBComJavascriptObject_DESC "DNSSECValidator ComJavascriptObject Class")
set(IFBComEventSource_DESC "DNSSECValidator IFBComEventSource Interface")
set(AXVERSION_NUM "1")

# NOTE: THESE GUIDS *MUST* BE UNIQUE TO YOUR PLUGIN/ACTIVEX CONTROL!  YES, ALL OF THEM!
set(FBTYPELIB_GUID 9cb03b6f-0b13-5b32-94c3-0b07838f2b19)
set(IFBControl_GUID 3267df51-0c9f-5be5-9212-36588a8b0160)
set(FBControl_GUID 681bf0ac-2513-5423-a383-9f0086f3a40a)
set(IFBComJavascriptObject_GUID 9d18c09e-54d7-5909-920e-10e77e3cf3c4)
set(FBComJavascriptObject_GUID f4d53565-80c3-55d6-930c-c71248cc7c6b)
set(IFBComEventSource_GUID 5244e87f-f56a-5c71-9e23-5944da961431)

# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "CZNICLabs.DNSSECValidator")
set(MOZILLA_PLUGINID "nic.cz/DNSSECValidator")

# strings
set(FBSTRING_CompanyName "CZ.NIC Labs")
set(FBSTRING_FileDescription "DNSSEC Validator Plug-in")
set(FBSTRING_PLUGIN_VERSION "0.0.1")
set(FBSTRING_LegalCopyright "Copyright 2010 CZ.NIC Labs")
set(FBSTRING_PluginFileName "np${PLUGIN_NAME}.dll")
set(FBSTRING_ProductName "DNSSEC Validator")
set(FBSTRING_FileExtents "")
set(FBSTRING_PluginName "DNSSEC Validator")
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
