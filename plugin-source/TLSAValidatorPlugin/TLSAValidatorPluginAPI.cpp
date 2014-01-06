/**********************************************************\

  Auto-generated TLSAValidatorPluginAPI.cpp

\**********************************************************/

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "global/config.h"
//#include "DOM/Window.h"

#include "TLSAValidatorPluginAPI.h"

///////////////////////////////////////////////////////////////////////////////
/// @fn FB::variant TLSAValidatorPluginAPI::echo(const FB::variant& msg)
///
/// @brief  Echos whatever is passed from Javascript.
///         Go ahead and change it. See what happens!
///////////////////////////////////////////////////////////////////////////////
FB::variant TLSAValidatorPluginAPI::echo(const FB::variant& msg)
{
    //static int n(0);
    //fire_echo("So far, you clicked this many times: ", n++);

    // return "foobar";
    return msg;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn TLSAValidatorPluginPtr TLSAValidatorPluginAPI::getPlugin()
///
/// @brief  Gets a reference to the plugin that was passed in when the object
///         was created.  If the plugin has already been released then this
///         will throw a FB::script_error that will be translated into a
///         javascript exception in the page.
///////////////////////////////////////////////////////////////////////////////
TLSAValidatorPluginPtr TLSAValidatorPluginAPI::getPlugin()
{
    TLSAValidatorPluginPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}

// Read/Write property testString
std::string TLSAValidatorPluginAPI::get_testString()
{
    return m_testString;
}

void TLSAValidatorPluginAPI::set_testString(const std::string& val)
{
    m_testString = val;
}

// Read-only property version
std::string TLSAValidatorPluginAPI::get_version()
{
    return FBSTRING_PLUGIN_VERSION;
}

void TLSAValidatorPluginAPI::testEvent()
{
    //fire_test();
}

char *convert(const std::string & s)
{
   char *pc = new char[s.size()+1];
   std::strcpy(pc, s.c_str());
   return pc; 
}


FB::VariantList TLSAValidatorPluginAPI::TLSAValidate(const std::vector<std::string> &certchain, const int certcount, const uint16_t options, const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy)
{    
//    std::vector<char*>  vc;
    //const char *vc[certcount];
//    std::transform(certchain.begin(), certchain.end(), std::back_inserter(vc), convert);  
    const char **vc = (const char **) malloc(sizeof(char *) * certcount);
    for (int i = 0; i < certcount; ++i) {
      vc[i] = certchain[i].c_str();
    }




    FB::VariantList reslist;
    short rv;
    rv = CheckDane(vc, certcount, options, optdnssrv.c_str(), domain.c_str(), port.c_str(), protocol.c_str(), policy);    
    reslist.push_back(rv);
    free(vc);
    return reslist;
}


void TLSAValidatorPluginAPI::TLSACacheFree()
{
    dane_validation_deinit();    
}

void TLSAValidatorPluginAPI::TLSACacheInit()
{
    dane_validation_init();    
}



/*
bool TLSAValidatorPluginAPI::TLSAValidateAsync(const std::vector<std::string> &certchain, const int certcount, const uint16_t options, const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy, const FB::JSObjectPtr &callback)
{
    boost::thread t(boost::bind(&TLSAValidatorPluginAPI::TLSAValidateAsync_thread, FB::ptr_cast<TLSAValidatorPluginAPI>(shared_from_this()), &certchain, certcount, options, optdnssrv, domain, port, protocol, policy, callback));
    return true; // the thread is started
}

void TLSAValidatorPluginAPI::TLSAValidateAsync_thread(const std::vector<std::string> &certchain, const int certcount, const uint16_t options, const std::string& optdnssrv, const std::string& domain, const std::string& port,
			      const std::string& protocol, const int policy, const FB::JSObjectPtr &callback)
{
    callback->InvokeAsync("", FB::variant_list_of(shared_from_this())(TLSAValidate(certchain, certcount, options, optdnssrv, domain, port, protocol, policy)));
}
*/






