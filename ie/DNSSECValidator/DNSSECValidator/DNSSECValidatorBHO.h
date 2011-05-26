/* ***** BEGIN LICENSE BLOCK *****
Copyright 2011 CZ.NIC, z.s.p.o.

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


This extension is based on the DNSSECVerify4IENav project
<http://cs.mty.itesm.mx/dnssecmx>, which is distributed under the Code Project
Open License (CPOL), see <http://www.codeproject.com/info/cpol10.aspx>.
***** END LICENSE BLOCK ***** */

// DNSSECValidatorBHO.h : Declaration of the CDNSSECValidatorBHO
#pragma once
#include "resource.h"       // main symbols
#include "DNSSECValidator_i.h"

#include <shlguid.h>     // IID_IWebBrowser2, DIID_DWebBrowserEvents2, etc
#include <exdispid.h> // DISPID_DOCUMENTCOMPLETE, etc.

//to load graphics
#include <atlapp.h>
#include <atlmisc.h>

extern "C" {					// use C language linkage
  #include "ds.h"
}

#include "dnssecStates.gen"		// DNSSEC state constants


////////////////////////////////////////////////


#define MAX_STR_LEN		1024

typedef struct {                // structure to save preferences
	char szDnsserveraddr[MAX_STR_LEN];
	DWORD dwDebugoutput;
	DWORD dwUsetcp;
} dsv_preferences;


#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
#endif

// CDNSSECValidatorBHO
class ATL_NO_VTABLE CDNSSECValidatorBHO :
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CDNSSECValidatorBHO, &CLSID_DNSSECValidatorBHO>,
	public IObjectWithSiteImpl<CDNSSECValidatorBHO>,
	public IDispatchImpl<IDNSSECValidatorBHO, &IID_IDNSSECValidatorBHO, &LIBID_DNSSECValidatorLib, /*wMajor =*/ 1, /*wMinor =*/ 0> 
{
//class constructor
public:
	CDNSSECValidatorBHO(){ //initializing elements
		//result=0;
		hTabWnd=NULL; //main Handle Tab Window reference
		hWndNewPane=NULL; // main Handle Tab Status Bar Pane
		domain=NULL; //current domain for each tab
		predomain=NULL;

		// default preference settings
		prefs.szDnsserveraddr[0] = '\0';
		prefs.dwDebugoutput = 0;
		prefs.dwUsetcp = 0;
	}
DECLARE_REGISTRY_RESOURCEID(IDR_DNSSECVALIDATORBHO)
DECLARE_PROTECT_FINAL_CONSTRUCT()
BEGIN_COM_MAP(CDNSSECValidatorBHO)
	COM_INTERFACE_ENTRY(IDNSSECValidatorBHO)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY(IObjectWithSite)
END_COM_MAP()
	HRESULT FinalConstruct() {
		return S_OK;
	}
	void FinalRelease() {
	}
	//class destructor
	//~CDNSSECValidatorBHO() {
	//}
public:
	//main access function
	STDMETHOD(SetSite)(IUnknown *pUnkSite); 
	//to extract the generated events on IE
	STDMETHOD(Invoke)(DISPID dispidMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pvarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
private:
	//connection to IE event functions
	HRESULT Connect(void);
	//it extracts a domain element from an URL element
	char *URL2domain(char*);
	//it extracts the hTabWnd element
	void InitDraw(void);
	//it creates the IE object interface
	CComQIPtr<IWebBrowser2, &IID_IWebBrowser2> m_spWebBrowser2;
	//it creates the IE object event links
	CComQIPtr<IConnectionPointContainer,&IID_IConnectionPointContainer> m_spCPC;
	//event handlers container
	DWORD m_dwCookie;
	short result; //the DNSSEC validation result
	HWND hTabWnd; // handle tab window element
	HWND hWndNewPane; //status bar pane element

	WORD ldicon; //ldicon element
	static WORD statldicon; // to copy ldicon result
	static int position; //main position of the icon

	static WNDPROC WProcStatus; //WNDPROC thread
	static bool WarnBlockAid; // navigate or not on non-authenticated domains

	//from last ver <<9.91>>
	//check DNS status as separated element of the main source code
	void checkdomainstatus(void);
	//adding BSTR URL elemento to the private section of the class
	CComBSTR bstrUrlName;

	char *domain;// current domain for each tab
	char *predomain;
	//validation function
	void displaydnssecstatus(void);
	// to draw the current Status Bar Pane
	static LRESULT CALLBACK NSProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
	// to draw the icon
	static LRESULT CALLBACK PWProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
	// sets the security status icon
	void SetSecurityState(void);
	// loads preference settings from the Windows registry
	void LoadOptions(void);
	// preferences variable
	dsv_preferences prefs;
};


OBJECT_ENTRY_AUTO(__uuidof(DNSSECValidatorBHO), CDNSSECValidatorBHO)
