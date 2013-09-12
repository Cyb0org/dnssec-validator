/**********************************************************\

  Auto-generated TLSAValidatorPluginAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "TLSAValidatorPlugin.h"

extern "C" {   /* use C language linkage */
  #include "dane-plug.h"
}


#ifndef H_TLSAValidatorPluginAPI
#define H_TLSAValidatorPluginAPI

class TLSAValidatorPluginAPI : public FB::JSAPIAuto
{
public:
    ////////////////////////////////////////////////////////////////////////////
    /// @fn TLSAValidatorPluginAPI::TLSAValidatorPluginAPI(const TLSAValidatorPluginPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    ////////////////////////////////////////////////////////////////////////////
    TLSAValidatorPluginAPI(const TLSAValidatorPluginPtr& plugin, const FB::BrowserHostPtr& host) :
        m_plugin(plugin), m_host(host)
    {
        registerMethod("echo",      make_method(this, &TLSAValidatorPluginAPI::echo));
        registerMethod("testEvent", make_method(this, &TLSAValidatorPluginAPI::testEvent));
	registerMethod("TLSAValidate", make_method(this, &TLSAValidatorPluginAPI::TLSAValidate));
        registerMethod("TLSACacheFree", make_method(this, &TLSAValidatorPluginAPI::TLSACacheFree));
   //     registerMethod("TLSAValidateAsync", make_method(this, &TLSAValidatorPluginAPI::TLSAValidateAsync));
   //     registerMethod("TLSAValidateAsync_thread", make_method(this, &TLSAValidatorPluginAPI::TLSAValidateAsync_thread));


        // Read-write property
        registerProperty("testString",
                         make_property(this,
                                       &TLSAValidatorPluginAPI::get_testString,
                                       &TLSAValidatorPluginAPI::set_testString));
        
        // Read-only property
        registerProperty("version",
                         make_property(this,
                                       &TLSAValidatorPluginAPI::get_version));
    }

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn TLSAValidatorPluginAPI::~TLSAValidatorPluginAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////////
    virtual ~TLSAValidatorPluginAPI() {};

    TLSAValidatorPluginPtr getPlugin();

    // Read/Write property ${PROPERTY.ident}
    std::string get_testString();
    void set_testString(const std::string& val);

    // Read-only property ${PROPERTY.ident}
    std::string get_version();

    // Method echo
    FB::variant echo(const FB::variant& msg);
    
    // Event helpers
    //FB_JSAPI_EVENT(test, 0, ());
    //FB_JSAPI_EVENT(echo, 2, (const FB::variant&, const int));

    // Method test-event
    void testEvent();



    // Synchronous validation method
    // INPUTS:
    // domain - domain name to validate
    // options - XPCOM input options (each bit represents one option)
    // optdnssrv - IPv4 or IPv6 address(es) of the optional DNS server
    // OUTPUTS - array of:
    // [0] - security state
    FB::VariantList TLSAValidate(const std::vector<std::string>& certchain, const int certcount, const uint16_t options, const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy);
/*
    // Asynchronous validation method
    bool TLSAValidateAsync(const std::vector<std::string> &certchain, const int certcount, const uint16_t options,
                              const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy, const FB::JSObjectPtr &callback);


*/
    void TLSACacheFree();


private:
    TLSAValidatorPluginWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
/*
    void TLSAValidateAsync_thread(const std::vector<std::string> &certchain, const int certcount, const uint16_t options, const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy, const FB::JSObjectPtr &callback);
*/
    std::string m_testString;
};

#endif // H_TLSAValidatorPluginAPI

