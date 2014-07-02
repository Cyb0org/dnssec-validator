/**********************************************************\

  Auto-generated DNSSECValidatorPluginAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "DNSSECValidatorPlugin.h"

extern "C" {   /* use C language linkage */
  #include "dnssec-plug.h"
}

#ifndef H_DNSSECValidatorPluginAPI
#define H_DNSSECValidatorPluginAPI

class DNSSECValidatorPluginAPI : public FB::JSAPIAuto
{
public:
    ///////////////////////////////////////////////////////////////////////////
    /// @fn DNSSECValidatorPluginAPI::DNSSECValidatorPluginAPI(
    ///const DNSSECValidatorPluginPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    ///////////////////////////////////////////////////////////////////////////
    DNSSECValidatorPluginAPI(const DNSSECValidatorPluginPtr& plugin,
	const FB::BrowserHostPtr& host) : m_plugin(plugin), m_host(host)
    {
	registerMethod("DNSSECCacheFree", make_method(this, 
	    &DNSSECValidatorPluginAPI::DNSSECCacheFree));
	registerMethod("DNSSECCacheInit", make_method(this,
	    &DNSSECValidatorPluginAPI::DNSSECCacheInit));
	registerMethod("Validate", make_method(this,
	    &DNSSECValidatorPluginAPI::Validate));
	registerMethod("ValidateAsync", make_method(this,
	    &DNSSECValidatorPluginAPI::ValidateAsync));
	registerMethod("ValidateAsync_thread", make_method(this,
	    &DNSSECValidatorPluginAPI::ValidateAsync_thread));
    }

    ///////////////////////////////////////////////////////////////////////////
    /// @fn DNSSECValidatorPluginAPI::~DNSSECValidatorPluginAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////
    virtual ~DNSSECValidatorPluginAPI() {};

    DNSSECValidatorPluginPtr getPlugin();

    // Synchronous validation method
    // INPUTS:
    // domain - domain name to validate
    // options - XPCOM input options (each bit represents one option)
    // optdnssrv - IPv4 or IPv6 address(es) of the optional DNS server
    // OUTPUTS - array of:
    // [0] - security state
    FB::VariantList Validate(const std::string& domain, const uint16_t options,
	const std::string& optdnssrv, const std::string& ipbrowser);

    // Asynchronous validation method
    bool ValidateAsync(const std::string& domain, const uint16_t options,
	const std::string& optdnssrv, const std::string& ipbrowser, 
	const FB::JSObjectPtr &callback);

   void DNSSECCacheFree();
   void DNSSECCacheInit();

private:
    DNSSECValidatorPluginWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

    void ValidateAsync_thread(const std::string& domain, const uint16_t options,
	const std::string& optdnssrv, const std::string& ipbrowser,
	const FB::JSObjectPtr &callback);
};

#endif // H_DNSSECValidatorPluginAPI

