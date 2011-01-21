/* ***** BEGIN LICENSE BLOCK *****
Copyright 2010, 2011 CZ.NIC, z.s.p.o.

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
#include "DNSSECValidator.h"

extern "C" {   /* use C language linkage */
  #include "ds.h"
}

#ifndef H_DNSSECValidatorAPI
#define H_DNSSECValidatorAPI

class DNSSECValidatorAPI : public FB::JSAPIAuto
{
public:
    DNSSECValidatorAPI(DNSSECValidatorPtr plugin, FB::BrowserHostPtr host);
    virtual ~DNSSECValidatorAPI();

    DNSSECValidatorPtr getPlugin();

    // Synchronous validation method
    // INPUTS:
    // domain - domain name to validate
    // options - XPCOM input options (each bit represents one option)
    // optdnssrv - IPv4 or IPv6 address(es) of the optional DNS server
    // OUTPUTS - array of:
    // [0] - list of resolved IPv4 and IPv6 address(es)
    // [1] - time to live of IPv4 address
    // [2] - time to live of IPv6 address
    // [3] - security state
    FB::VariantList Validate(const std::string& domain, const uint16_t options,
                             const std::string& optdnssrv);

    // Asynchronous validation method
    bool ValidateAsync(const std::string& domain, const uint16_t options,
                       const std::string& optdnssrv, const FB::JSObjectPtr &callback);

private:
    DNSSECValidatorWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

    void ValidateAsync_thread(const std::string& domain, const uint16_t options,
                              const std::string& optdnssrv, const FB::JSObjectPtr &callback);
};

#endif // H_DNSSECValidatorAPI
