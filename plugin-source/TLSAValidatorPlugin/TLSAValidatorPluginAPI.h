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
    /////////////////////////////////////////////////////////////////////////
    /// @fn TLSAValidatorPluginAPI::TLSAValidatorPluginAPI
    ///(const TLSAValidatorPluginPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    /////////////////////////////////////////////////////////////////////////
    TLSAValidatorPluginAPI(const TLSAValidatorPluginPtr& plugin, 
	const FB::BrowserHostPtr& host) : m_plugin(plugin), m_host(host)
    {
	registerMethod("TLSAValidate", make_method(this,
	    &TLSAValidatorPluginAPI::TLSAValidate));
        registerMethod("TLSACacheFree", make_method(this,
	    &TLSAValidatorPluginAPI::TLSACacheFree));
        registerMethod("TLSACacheInit", make_method(this,
	    &TLSAValidatorPluginAPI::TLSACacheInit));        
    }

    ///////////////////////////////////////////////////////////////////////////
    /// @fn TLSAValidatorPluginAPI::~TLSAValidatorPluginAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////
    virtual ~TLSAValidatorPluginAPI() {};

    TLSAValidatorPluginPtr getPlugin();

    FB::VariantList TLSAValidate(const std::vector<std::string>& certchain,
	const int certcount, const uint16_t options, const std::string& optdnssrv, 
	const std::string& domain, const std::string& port,
	const std::string& protocol, const int policy);

	void TLSACacheFree();
	void TLSACacheInit();

private:
    TLSAValidatorPluginWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
};

#endif // H_TLSAValidatorPluginAPI

