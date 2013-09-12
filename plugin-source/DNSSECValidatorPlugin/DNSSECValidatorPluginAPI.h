/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator Add-on.

DNSSEC Validator Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator Add-on.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "DNSSECValidatorPlugin.h"

extern "C" {   /* use C language linkage */
  #include "ub_ds.h"
}


#ifndef H_DNSSECValidatorPluginAPI
#define H_DNSSECValidatorPluginAPI

class DNSSECValidatorPluginAPI : public FB::JSAPIAuto
{
public:
    ////////////////////////////////////////////////////////////////////////////
    /// @fn DNSSECValidatorPluginAPI::DNSSECValidatorPluginAPI(const DNSSECValidatorPluginPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    ////////////////////////////////////////////////////////////////////////////
    DNSSECValidatorPluginAPI(const DNSSECValidatorPluginPtr& plugin, const FB::BrowserHostPtr& host) :
        m_plugin(plugin), m_host(host)
    {
        registerMethod("echo",      make_method(this, &DNSSECValidatorPluginAPI::echo));
        registerMethod("testEvent", make_method(this, &DNSSECValidatorPluginAPI::testEvent));
    registerMethod("CacheFree", make_method(this, &DNSSECValidatorPluginAPI::CacheFree));
    registerMethod("Validate", make_method(this, &DNSSECValidatorPluginAPI::Validate));
    registerMethod("ValidateAsync", make_method(this, &DNSSECValidatorPluginAPI::ValidateAsync));
    registerMethod("ValidateAsync_thread", make_method(this, &DNSSECValidatorPluginAPI::ValidateAsync_thread));

   //     registerMethod("DNSSECValidateAsync", make_method(this, &DNSSECValidatorPluginAPI::DNSSECValidateAsync));
   //     registerMethod("DNSSECValidateAsync_thread", make_method(this, &DNSSECValidatorPluginAPI::DNSSECValidateAsync_thread));


        // Read-write property
        registerProperty("testString",
                         make_property(this,
                                       &DNSSECValidatorPluginAPI::get_testString,
                                       &DNSSECValidatorPluginAPI::set_testString));
        
        // Read-only property
        registerProperty("version",
                         make_property(this,
                                       &DNSSECValidatorPluginAPI::get_version));
    }

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn DNSSECValidatorPluginAPI::~DNSSECValidatorPluginAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////////
    virtual ~DNSSECValidatorPluginAPI() {};

    DNSSECValidatorPluginPtr getPlugin();

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
    FB::VariantList Validate(const std::string& domain, const uint16_t options,
                             const std::string& optdnssrv, const std::string& ipbrowser);

/*
    // Asynchronous validation method
    bool DNSSECValidateAsync(const std::vector<std::string> &certchain, const int certcount, const uint16_t options,
                              const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy, const FB::JSObjectPtr &callback);


*/
    // Asynchronous validation method
    bool ValidateAsync(const std::string& domain, const uint16_t options,
                       const std::string& optdnssrv, const std::string& ipbrowser, const FB::JSObjectPtr &callback);

    void CacheFree();



private:
    DNSSECValidatorPluginWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;
/*
    void DNSSECValidateAsync_thread(const std::vector<std::string> &certchain, const int certcount, const uint16_t options, const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy, const FB::JSObjectPtr &callback);
*/
    std::string m_testString;
    void ValidateAsync_thread(const std::string& domain, const uint16_t options,
                              const std::string& optdnssrv, const std::string& ipbrowser, const FB::JSObjectPtr &callback);


};

#endif // H_DNSSECValidatorPluginAPI

