/**********************************************************\

  Auto-generated DNSSECValidatorPluginAPI.cpp

\**********************************************************/

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "global/config.h"

#include "DNSSECValidatorPluginAPI.h"

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant DNSSECValidatorPluginAPI::echo(const FB::variant& msg)
///
/// @brief  Echos whatever is passed from Javascript.
///         Go ahead and change it. See what happens!
///////////////////////////////////////////////////////////////////////////////
FB::variant DNSSECValidatorPluginAPI::echo(const FB::variant& msg)
{
    static int n(0);
    fire_echo("So far, you clicked this many times: ", n++);

    // return "foobar";
    return msg;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn DNSSECValidatorPluginPtr DNSSECValidatorPluginAPI::getPlugin()
///
/// @brief  Gets a reference to the plugin that was passed in when the object
///         was created.  If the plugin has already been released then this
///         will throw a FB::script_error that will be translated into a
///         javascript exception in the page.
///////////////////////////////////////////////////////////////////////////////
DNSSECValidatorPluginPtr DNSSECValidatorPluginAPI::getPlugin()
{
    DNSSECValidatorPluginPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}

// Read/Write property testString
std::string DNSSECValidatorPluginAPI::get_testString()
{
    return m_testString;
}

void DNSSECValidatorPluginAPI::set_testString(const std::string& val)
{
    m_testString = val;
}

// Read-only property version
std::string DNSSECValidatorPluginAPI::get_version()
{
    return FBSTRING_PLUGIN_VERSION;
}

void DNSSECValidatorPluginAPI::testEvent()
{
    fire_test();
}

FB::VariantList DNSSECValidatorPluginAPI::Validate(const std::string& domain, const uint16_t options,
                                             const std::string& optdnssrv, const std::string& ipbrowser)
{    
    FB::VariantList reslist;
    short rv;
    char *ipvalidator = NULL;
    rv = dnssec_validate(domain.c_str(), options, optdnssrv.c_str(), ipbrowser.c_str(), &ipvalidator);    
    reslist.push_back(rv);
    reslist.push_back(ipvalidator ? (std::string)ipvalidator : "");    

    return reslist;
}


void DNSSECValidatorPluginAPI::DNSSECCacheFree()
{
    dnssec_validation_deinit();    
}

void DNSSECValidatorPluginAPI::DNSSECCacheInit()
{
    dnssec_validation_init();    
}


bool DNSSECValidatorPluginAPI::ValidateAsync(const std::string& domain, const uint16_t options,
                                       const std::string& optdnssrv, const std::string& ipbrowser, const FB::JSObjectPtr &callback)
{
    boost::thread t(boost::bind(&DNSSECValidatorPluginAPI::ValidateAsync_thread,
         FB::ptr_cast<DNSSECValidatorPluginAPI>(shared_from_this()), domain, options, optdnssrv, ipbrowser, callback));
    return true; // the thread is started
}

void DNSSECValidatorPluginAPI::ValidateAsync_thread(const std::string& domain, const uint16_t options,
                                              const std::string& optdnssrv, const std::string& ipbrowser, const FB::JSObjectPtr &callback)
{
    callback->InvokeAsync("", FB::variant_list_of(shared_from_this())(Validate(domain, options, optdnssrv, ipbrowser)));
}
