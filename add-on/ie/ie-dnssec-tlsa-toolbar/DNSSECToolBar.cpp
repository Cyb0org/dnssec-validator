// DNSSECToolBar.cpp : Implementation of DLL Exports.


// Note: Proxy/Stub Information
//      To build a separate proxy/stub DLL, 
//      run nmake -f DNSSECToolBarps.mk in the project directory.

#include "stdafx.h"
#include "resource.h"
#include <initguid.h>
#include "DNSSECToolBar.h"
//extern "C" {					// use C language linkage
//  #include "ds.h"
//}
#include "DNSSECToolBar_i.c"
#include "DNSSECToolBarBand.h"


CComModule _Module;
HINSTANCE GHins;
BEGIN_OBJECT_MAP(ObjectMap)
OBJECT_ENTRY(CLSID_DNSSECToolBarBand, CDNSSECToolBarBand)
END_OBJECT_MAP()

TCHAR g_strRegToolbars[] = _T("SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar");

class CDNSSECToolBarApp : public CWinApp
{
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDNSSECToolBarApp)
	public:
    virtual BOOL InitInstance();
    virtual int ExitInstance();
	//}}AFX_VIRTUAL

	//{{AFX_MSG(CDNSSECToolBarApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

BEGIN_MESSAGE_MAP(CDNSSECToolBarApp, CWinApp)
	//{{AFX_MSG_MAP(CDNSSECToolBarApp)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

CDNSSECToolBarApp theApp;

BOOL CDNSSECToolBarApp::InitInstance()
{
    _Module.Init(ObjectMap, m_hInstance, &LIBID_DNSSECToolBarLib);
	GHins=m_hInstance;
    return CWinApp::InitInstance();
}


int CDNSSECToolBarApp::ExitInstance()
{
    _Module.Term();
    return CWinApp::ExitInstance();
}

/////////////////////////////////////////////////////////////////////////////
// Used to determine whether the DLL can be unloaded by OLE

STDAPI DllCanUnloadNow(void)
{
    AFX_MANAGE_STATE(AfxGetStaticModuleState());
    return (AfxDllCanUnloadNow()==S_OK && _Module.GetLockCount()==0) ? S_OK : S_FALSE;
}

/////////////////////////////////////////////////////////////////////////////
// Returns a class factory to create an object of the requested type

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    return _Module.GetClassObject(rclsid, riid, ppv);
}

/////////////////////////////////////////////////////////////////////////////
// DllRegisterServer - Adds entries to the system registry

STDAPI DllRegisterServer(void)
{
    // registers object, typelib and all interfaces in typelib
    return _Module.RegisterServer(TRUE);
}

/////////////////////////////////////////////////////////////////////////////
// DllUnregisterServer - Removes entries from the system registry

STDAPI DllUnregisterServer(void)
{
USES_CONVERSION;

	// Remove toolbar from list (registry script doesn't do this)
	HKEY hKeyToolbar;
	LPOLESTR pstrCLSID;
	LONG res = RegOpenKey(HKEY_LOCAL_MACHINE, g_strRegToolbars, &hKeyToolbar);
	StringFromCLSID(CLSID_DNSSECToolBarBand, &pstrCLSID);
	res = RegDeleteValue(hKeyToolbar, OLE2T(pstrCLSID));
	CoTaskMemFree(pstrCLSID);
    return _Module.UnregisterServer(TRUE);
}


