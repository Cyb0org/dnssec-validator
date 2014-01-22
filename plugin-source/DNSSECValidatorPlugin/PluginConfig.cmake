#/**********************************************************\ 
#
# Auto-Generated Plugin Configuration file
# for DNSSECValidatorPlugin
#
#\**********************************************************/

set(PLUGIN_NAME "DNSSECValidatorPlugin")
set(PLUGIN_PREFIX "DVP")
set(COMPANY_NAME "CZNIC")

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
set(FBTYPELIB_GUID 8deb704d-ddba-5259-a6fe-3143a288267c)
set(IFBControl_GUID 84a69484-d3ec-5c3e-9216-9e39d7b3a0b3)
set(FBControl_GUID 6add0c13-57f5-562e-894a-9e9b5d48618a)
set(IFBComJavascriptObject_GUID 15d8633c-41f7-5dfd-b11f-9fba618e98ef)
set(FBComJavascriptObject_GUID 418e82d3-a6ed-5432-a5a1-1dd2f92391ae)
set(IFBComEventSource_GUID 18f2db8e-c47c-58ea-b776-51a388577635)
if ( FB_PLATFORM_ARCH_32 )
    set(FBControl_WixUpgradeCode_GUID 646a7437-b5df-5871-a295-3928c19fb90a)
else ( FB_PLATFORM_ARCH_32 )
    set(FBControl_WixUpgradeCode_GUID 5f5c05c7-95ed-593b-b71c-073e02f67564)
endif ( FB_PLATFORM_ARCH_32 )


# these are the pieces that are relevant to using it from Javascript
set(ACTIVEX_PROGID "CZNIC.DNSSECValidatorPlugin")
if ( FB_PLATFORM_ARCH_32 )
    set(MOZILLA_PLUGINID "nic.cz/DNSSECValidatorPlugin")  # No 32bit postfix to maintain backward compatability.
else ( FB_PLATFORM_ARCH_32 )
    set(MOZILLA_PLUGINID "nic.cz/DNSSECValidatorPlugin_${FB_PLATFORM_ARCH_NAME}")
endif ( FB_PLATFORM_ARCH_32 )

# strings
set(FBSTRING_CompanyName "CZ.NIC")
set(FBSTRING_PluginDescription "Plug-in used by DNSSEC Validator extension")
set(FBSTRING_PLUGIN_VERSION "2.1.0")
set(FBSTRING_LegalCopyright "Copyright 2014 CZ.NIC")
set(FBSTRING_PluginFileName "np${PLUGIN_NAME}")
set(FBSTRING_ProductName "DNSSECValidatorPlugin")
set(FBSTRING_FileExtents "")
if ( FB_PLATFORM_ARCH_32 )
    set(FBSTRING_PluginName "DNSSECValidatorPlugin")  # No 32bit postfix to maintain backward compatability.
else ( FB_PLATFORM_ARCH_32 )
    set(FBSTRING_PluginName "DNSSECValidatorPlugin_${FB_PLATFORM_ARCH_NAME}")
endif ( FB_PLATFORM_ARCH_32 )
set(FBSTRING_MIMEType "application/x-dnssecvalidatorplugin")

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
