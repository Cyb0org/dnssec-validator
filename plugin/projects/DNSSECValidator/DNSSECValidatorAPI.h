/**********************************************************\

  Auto-generated DNSSECValidatorAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "DNSSECValidator.h"

#ifndef H_DNSSECValidatorAPI
#define H_DNSSECValidatorAPI

class DNSSECValidatorAPI : public FB::JSAPIAuto
{
public:
    DNSSECValidatorAPI(DNSSECValidatorPtr plugin, FB::BrowserHostPtr host);
    virtual ~DNSSECValidatorAPI();

    DNSSECValidatorPtr getPlugin();

    // Read/Write property ${PROPERTY.ident}
    std::string get_testString();
    void set_testString(const std::string& val);

    // Read-only property ${PROPERTY.ident}
    std::string get_version();

    // Method echo
    FB::variant echo(const FB::variant& msg);

    // Method test-event
    void testEvent(const FB::variant& s);


    FB::VariantList Validate(const std::string& domain, const uint16_t options,
                             const std::string& optdnssrv);

    bool ValidateAsync(const std::string& domain, const uint16_t options,
                       const std::string& optdnssrv, const FB::JSObjectPtr &callback);


private:
    DNSSECValidatorWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

    std::string m_testString;

    void ValidateAsync_thread(const std::string& domain, const uint16_t options,
                              const std::string& optdnssrv, const FB::JSObjectPtr &callback);
};

#endif // H_DNSSECValidatorAPI

