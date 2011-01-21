/**********************************************************\

  Auto-generated DNSSECValidatorAPI.cpp

\**********************************************************/

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"

#include "DNSSECValidatorAPI.h"

///////////////////////////////////////////////////////////////////////////////
/// @fn DNSSECValidatorAPI::DNSSECValidatorAPI(DNSSECValidatorPtr plugin, FB::BrowserHostPtr host)
///
/// @brief  Constructor for your JSAPI object.  You should register your methods, properties, and events
///         that should be accessible to Javascript from here.
///
/// @see FB::JSAPIAuto::registerMethod
/// @see FB::JSAPIAuto::registerProperty
/// @see FB::JSAPIAuto::registerEvent
///////////////////////////////////////////////////////////////////////////////
DNSSECValidatorAPI::DNSSECValidatorAPI(DNSSECValidatorPtr plugin, FB::BrowserHostPtr host) : m_plugin(plugin), m_host(host)
{
    registerMethod("Validate", make_method(this, &DNSSECValidatorAPI::Validate));
    registerMethod("ValidateAsync", make_method(this, &DNSSECValidatorAPI::ValidateAsync));
    registerMethod("ValidateAsync_thread", make_method(this, &DNSSECValidatorAPI::ValidateAsync_thread));
}

///////////////////////////////////////////////////////////////////////////////
/// @fn DNSSECValidatorAPI::~DNSSECValidatorAPI()
///
/// @brief  Destructor.  Remember that this object will not be released until
///         the browser is done with it; this will almost definitely be after
///         the plugin is released.
///////////////////////////////////////////////////////////////////////////////
DNSSECValidatorAPI::~DNSSECValidatorAPI()
{
}

///////////////////////////////////////////////////////////////////////////////
/// @fn DNSSECValidatorPtr DNSSECValidatorAPI::getPlugin()
///
/// @brief  Gets a reference to the plugin that was passed in when the object
///         was created.  If the plugin has already been released then this
///         will throw a FB::script_error that will be translated into a
///         javascript exception in the page.
///////////////////////////////////////////////////////////////////////////////
DNSSECValidatorPtr DNSSECValidatorAPI::getPlugin()
{
    DNSSECValidatorPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}


FB::VariantList DNSSECValidatorAPI::Validate(const std::string& domain, const uint16_t options,
                                             const std::string& optdnssrv)
{
    FB::VariantList reslist;
    short rv;
    char *tmpptr = NULL;
    uint32_t ttl4, ttl6;

    rv = ds_validate(domain.c_str(), options, optdnssrv.c_str(), &tmpptr, &ttl4, &ttl6);

    reslist.push_back((std::string)tmpptr);
    reslist.push_back(ttl4);
    reslist.push_back(ttl6);
    reslist.push_back(rv);

    ds_free_resaddrsbuf();

    return reslist;
}

bool DNSSECValidatorAPI::ValidateAsync(const std::string& domain, const uint16_t options,
                                       const std::string& optdnssrv, const FB::JSObjectPtr &callback)
{
    boost::thread t(boost::bind(&DNSSECValidatorAPI::ValidateAsync_thread,
         FB::ptr_cast<DNSSECValidatorAPI>(shared_ptr()), domain, options, optdnssrv, callback));
    return true; // the thread is started
}

void DNSSECValidatorAPI::ValidateAsync_thread(const std::string& domain, const uint16_t options,
                                              const std::string& optdnssrv, const FB::JSObjectPtr &callback)
{
    callback->InvokeAsync("", FB::variant_list_of(shared_ptr())(Validate(domain, options, optdnssrv)));
}
