/* ***** BEGIN LICENSE BLOCK *****
Copyright 2014 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator Add-on 2.x.

DNSSEC Validator Add-on 2.x is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator Add-on 2.x is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator Add-on 2.x.  If not, see <http://www.gnu.org/licenses/>.
***** END LICENSE BLOCK ***** */

#include "stdafx.h"
#include <initguid.h>
#include "DNSSECToolBar.h"
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


