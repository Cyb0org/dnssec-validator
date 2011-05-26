// dllmain.h : Declaration of module class.

class CDNSSECValidatorModule : public CAtlDllModuleT< CDNSSECValidatorModule >
{
public :
	DECLARE_LIBID(LIBID_DNSSECValidatorLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_DNSSECVALIDATOR, "{0E5C99B7-484A-4D37-B08C-2D14A5C17BDB}")
};

extern class CDNSSECValidatorModule _AtlModule;

