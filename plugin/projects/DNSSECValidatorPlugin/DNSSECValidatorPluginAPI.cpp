/* ***** BEGIN LICENSE BLOCK *****
Copyright 2010, 2011 CZ.NIC, z.s.p.o.

Authors: Zbynek Michl <zbynek.michl@nic.cz>

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

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "DOM/Window.h"

#include "DNSSECValidatorPluginAPI.h"

///////////////////////////////////////////////////////////////////////////////
/// @fn DNSSECValidatorPluginAPI::DNSSECValidatorPluginAPI(DNSSECValidatorPluginPtr plugin, FB::BrowserHostPtr host)
///
/// @brief  Constructor for your JSAPI object.  You should register your methods, properties, and events
///         that should be accessible to Javascript from here.
///
/// @see FB::JSAPIAuto::registerMethod
/// @see FB::JSAPIAuto::registerProperty
/// @see FB::JSAPIAuto::registerEvent
///////////////////////////////////////////////////////////////////////////////
DNSSECValidatorPluginAPI::DNSSECValidatorPluginAPI(DNSSECValidatorPluginPtr plugin, FB::BrowserHostPtr host) : m_plugin(plugin), m_host(host)
{
    // Allow privileged access only
    if (m_host->getDOMWindow()->getLocation() != "chrome://browser/content/browser.xul")
        return;

    registerMethod("Validate", make_method(this, &DNSSECValidatorPluginAPI::Validate));
    registerMethod("ValidateAsync", make_method(this, &DNSSECValidatorPluginAPI::ValidateAsync));
    registerMethod("ValidateAsync_thread", make_method(this, &DNSSECValidatorPluginAPI::ValidateAsync_thread));
}

///////////////////////////////////////////////////////////////////////////////
/// @fn DNSSECValidatorPluginAPI::~DNSSECValidatorPluginAPI()
///
/// @brief  Destructor.  Remember that this object will not be released until
///         the browser is done with it; this will almost definitely be after
///         the plugin is released.
///////////////////////////////////////////////////////////////////////////////
DNSSECValidatorPluginAPI::~DNSSECValidatorPluginAPI()
{
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


FB::VariantList DNSSECValidatorPluginAPI::Validate(const std::string& domain, const uint16_t options,
                                             const std::string& optdnssrv)
{
    FB::VariantList reslist;
    short rv;
    char *tmpptr = NULL;
    uint32_t ttl4, ttl6;

    rv = ds_validate(domain.c_str(), options, optdnssrv.c_str(), &tmpptr, &ttl4, &ttl6);

    reslist.push_back(tmpptr ? (std::string)tmpptr : "");
    reslist.push_back(ttl4);
    reslist.push_back(ttl6);
    reslist.push_back(rv);

    ds_free_resaddrsbuf();

    return reslist;
}

bool DNSSECValidatorPluginAPI::ValidateAsync(const std::string& domain, const uint16_t options,
                                       const std::string& optdnssrv, const FB::JSObjectPtr &callback)
{
    boost::thread t(boost::bind(&DNSSECValidatorPluginAPI::ValidateAsync_thread,
         FB::ptr_cast<DNSSECValidatorPluginAPI>(shared_ptr()), domain, options, optdnssrv, callback));
    return true; // the thread is started
}

void DNSSECValidatorPluginAPI::ValidateAsync_thread(const std::string& domain, const uint16_t options,
                                              const std::string& optdnssrv, const FB::JSObjectPtr &callback)
{
    callback->InvokeAsync("", FB::variant_list_of(shared_ptr())(Validate(domain, options, optdnssrv)));
}