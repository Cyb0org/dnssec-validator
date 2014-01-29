#/**********************************************************\ 
#
# Auto-Generated Plugin Configuration file
# for TLSAValidatorPlugin
#
#\**********************************************************/

set(PLUGIN_NAME "TLSAValidatorPlugin")
set(PLUGIN_PREFIX "TVP")
set(COMPANY_NAME "CZNIC")

# ActiveX constants:
set(FBTYPELIB_NAME TLSAValidatorPluginLib)
set(FBTYPELIB_DESC "TLSAValidatorPlugin 1.0 Type Library")
set(IFBControl_DESC "TLSAValidatorPlugin Control Interface")
set(FBControl_DESC "TLSAValidatorPlugin Control Class")
set(IFBComJavascriptObject_DESC "TLSAValidatorPlugin IComJavascriptObject Interface")
set(FBComJavascriptObject_DESC "TLSAValidatorPlugin ComJavascriptObject Class")
set(IFBComEventSource_DESC "TLSAValidatorPlugin IFBComEventSource Interface")
set(AXVERSION_NUM "1")

# NOTE: THESE GUIDS *MUST* BE UNIQUE TO YOUR PLUGIN/ACTIVEX CONTROL!  YES, ALL OF THEM!
set(FBTYPELIB_GUID b5a91630-22c7-5365-9a52-f153a21102d7)
set(IFBControl_GUID 178f9c21-d016-5e07-b3cf-1cb14739670b)
set(FBControl_GUID f1c12c74-e434-50a9-ad0a-5b3fb21f2c88)
set(IFBComJavascriptObject_GUID b0bb6faf-0aa1-5dd1-bb6c-783de3d52489)
set(FBComJavascriptObject_GUID 52aefc46-86fd-5ee4-9182-9dfa2ad6bbb5)
set(IFBComEventSource_GUID eb7ebc96-4088-5d70-9038-b36be0705440)
if ( FB_PLATFORM_ARCH_32 )
    set(FBControl_WixUpgradeCode_GUID 3813b197-410e-5f61-9037-6aa1be2ef122)
else ( FB_PLATFORM_ARCH_32 )
    set(FBControl_WixUpgradeCode_GUID 531cde4d-e22f-5907-95b3-d1698dfc62c0)
endif ( FB_PLATFORM_ARCH_32 )

# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "CZNIC.TLSAValidatorPlugin")
if ( FB_PLATFORM_ARCH_32 )
    set(MOZILLA_PLUGINID "nic.cz/TLSAValidatorPlugin")  # No 32bit postfix to maintain backward compatability.
else ( FB_PLATFORM_ARCH_32 )
    set(MOZILLA_PLUGINID "nic.cz/TLSAValidatorPlugin_${FB_PLATFORM_ARCH_NAME}")
endif ( FB_PLATFORM_ARCH_32 )

# strings
set(FBSTRING_CompanyName "CZ.NIC")
set(FBSTRING_PluginDescription "Plug-in used by TLSA Validator extension")
set(FBSTRING_PLUGIN_VERSION "2.1.0")
set(FBSTRING_LegalCopyright "Copyright 2014 CZ.NIC")
set(FBSTRING_PluginFileName "np${PLUGIN_NAME}")
set(FBSTRING_ProductName "TLSAValidatorPlugin")
set(FBSTRING_FileExtents "")
if ( FB_PLATFORM_ARCH_32 )
    set(FBSTRING_PluginName "TLSAValidatorPlugin")  # No 32bit postfix to maintain backward compatability.
else ( FB_PLATFORM_ARCH_32 )
    set(FBSTRING_PluginName "TLSAValidatorPlugin_${FB_PLATFORM_ARCH_NAME}")
endif ( FB_PLATFORM_ARCH_32 )
set(FBSTRING_MIMEType "application/x-tlsavalidatorplugin")

# Uncomment this next line if you're not planning on your plugin doing
# any drawing:

set (FB_GUI_DISABLED 1)

# Mac plugin settings. If your plugin does not draw, set these all to 0
set(FBMAC_USE_QUICKDRAW 0)
set(FBMAC_USE_CARBON 1)
set(FBMAC_USE_COCOA 1)
set(FBMAC_USE_COREGRAPHICS 1)
set(FBMAC_USE_COREANIMATION 0)
set(FBMAC_USE_INVALIDATINGCOREANIMATION 0)

# If you want to register per-machine on Windows, uncomment this line
#set (FB_ATLREG_MACHINEWIDE 1)
