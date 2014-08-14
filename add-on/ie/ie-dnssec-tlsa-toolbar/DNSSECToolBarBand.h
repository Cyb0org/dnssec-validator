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

Some parts of these codes are based on the DNSSECVerify4IENav project
<http://cs.mty.itesm.mx/dnssecmx>, which is distributed under the Code Project
Open License (CPOL), see <http://www.codeproject.com/info/cpol10.aspx>.
***** END LICENSE BLOCK ***** */

// DNSSECToolBarBand.h : Declaration of the CDNSSECToolBarBand
#ifndef __DNSSECToolBarBAND_H_
#define __DNSSECToolBarBAND_H_
#include "Winuser.h"
#include "Wincrypt.h"
#include "resource.h"
#include "hyperlink.h"
#include "KBToolBarCtrl.h"
#include <shlguid.h>	// IID_IWebBrowser2, DIID_DWebBrowserEvents2, etc
#include <exdispid.h>	// DISPID_DOCUMENTCOMPLETE, etc.
#include <shlobj.h>
#include <ctime>
#include <list>
#include <shlwapi.h>

// DNSSEC/TLSA core headrs
#include "dnssec-states.gen"	// DNSSEC state constants
#include "dane-states.gen"		// TLSA state constants
extern "C" {					// use C language linkage
  #include "dnssec-plug.h"		// dnssec core interface
  #include "dane-plug.h"		// dane core interface
}

// MSVS needs these pragma
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
using namespace std;

/* share cache memory name for Windows */
#define SM_NAME_LOCAL "Local\\SharedCacheTLSADNSSEC"
/* default content of dnssec.ini */
#define DEFAULT_INI_DATA "[DNSSEC]\ntlsaenable=1\nkeytext=0\nchoice=3\nchoicedns=0\nuserip=8.8.8.8\nfilteron=0\nlisttld="
/* define validator registry path */
#define HKU_REG_KEY TEXT(".DEFAULT\\Software\\CZ.NIC\\DNSSEC-TLSA Validator")
#define HKCU_REG_KEY TEXT("Software\\CZ.NIC\\DNSSEC-TLSA Validator")
#define INI_FILE_PATH _T("\\CZ.NIC\\DNSSEC-TLSA Validator\\dnssec.ini")
//---- CACHE MEMORY SETTINGS -------------------------------------------
#define CACHE_ITEMS_MAX 64          // max items in cache
#define DOMAIN_NAME_LENGTH_MAX 270   // max lenght of domain name include port number
#define PORT_LENGTH_MAX 6            // max lenght of port record
#define NO_ITEM_IN_CACHE -99         // the item is not in cache           
// seconds = 5 min is expir time of item in DANE cache
#define CACHE_EXPIR_TIME 300 
//---------------------------------------------------------------------
// size of buffer for URL parts save
#define STR_BUF_SIZE 512
// max length of IP
#define IPADDR_MLEN 256
// max length of IP list
#define TLD_LIST_MLEN 2048
// ToolBar dimension setting - no change
#define TB_MIN_SIZE_X   100
#define TB_MIN_SIZE_Y   22
#define TB_MAX_SIZE_Y   40

extern HINSTANCE GHins;

// settings
extern bool debug;
extern short textkey;
extern short choice;
extern short choice2;
extern short tlsaenable;
extern char dnssecseradr[IPADDR_MLEN];
extern short debugoutput;
extern short debugoutput_enable;
extern char ipvalidator4[256];
extern char* ipbrowser4;
extern char* ipvalidator6;
extern char* ipbrowser6;

// TLSA panel text
extern WORD paneltitletlsa;
extern WORD paneltextmain;
extern WORD paneltextadd;
extern WORD keylogo2;
extern WORD tlsaiconres;
extern short tlsaresult;

// DNSSEC panel text
extern WORD paneltitle;
extern WORD panelpredonain;
extern char* paneldomainname;
extern char tlsapaneldomainname[280];
extern WORD panelpostdomain;
extern WORD paneltext;
extern WORD keylogo;
extern short res;
extern short filteron;
extern char listtld[TLD_LIST_MLEN];
extern bool wrong;

class CHyperLink;
extern CHyperLink m_link;


/////////////////////////////////////////////////////////////////////////////
// CDNSSECToolBarBand class
/////////////////////////////////////////////////////////////////////////////
class ATL_NO_VTABLE CDNSSECToolBarBand : 
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CDNSSECToolBarBand, &CLSID_DNSSECToolBarBand>,
	public IObjectWithSiteImpl<CDNSSECToolBarBand>,
	public IDispEventImpl<0, CDNSSECToolBarBand,&__uuidof(DWebBrowserEvents2), &LIBID_SHDocVw, 1, 0>,
	public IDispatchImpl<IDNSSECToolBarBand, &IID_IDNSSECToolBarBand, &LIBID_DNSSECToolBarLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
	public IInputObject,
	public IDeskBand

		
{
   typedef IDispEventImpl<0, CDNSSECToolBarBand, &__uuidof(DWebBrowserEvents2), &LIBID_SHDocVw, 1, 0> tDispEvent;
public:
	CDNSSECToolBarBand()
	{
		if (!csInitialized) {
			InitializeCriticalSectionAndSpinCount(&cs, 0x00000400);
			csInitialized = true;
		}

	}

DECLARE_REGISTRY_RESOURCEID(IDR_DNSSECToolBarBAND)
DECLARE_PROTECT_FINAL_CONSTRUCT()

BEGIN_COM_MAP(CDNSSECToolBarBand)
	COM_INTERFACE_ENTRY(IObjectWithSite)
	COM_INTERFACE_ENTRY(IInputObject)
	COM_INTERFACE_ENTRY(IDeskBand)
	COM_INTERFACE_ENTRY(IDNSSECToolBarBand)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY2(IOleWindow, IDeskBand)
	COM_INTERFACE_ENTRY2(IDockingWindow, IDeskBand)
END_COM_MAP()

	BEGIN_SINK_MAP(CDNSSECToolBarBand)
	END_SINK_MAP()

	HRESULT FinalConstruct() {
		return S_OK;
	}
	void FinalRelease() {
	}


// Interfaces
public:
	//IOleWindow methods
	STDMETHOD (GetWindow) (HWND*);
	STDMETHOD (ContextSensitiveHelp) (BOOL);

	//IDockingWindow methods
	STDMETHOD (ShowDW) (BOOL fShow);
	STDMETHOD (CloseDW) (DWORD dwReserved);
	STDMETHOD (ResizeBorderDW) (LPCRECT prcBorder, IUnknown* punkToolbarSite, BOOL fReserved);

	//IDeskBand methods
	STDMETHOD (GetBandInfo) (DWORD, DWORD, DESKBANDINFO*);

	//IInputObject methods
	STDMETHOD (UIActivateIO) (BOOL, LPMSG);
	STDMETHOD (HasFocusIO) (void);
	STDMETHOD (TranslateAcceleratorIO) (LPMSG);

	//IObjectWithSite methods
	STDMETHOD (SetSite) (IUnknown*);
	STDMETHOD (GetSite) (REFIID, LPVOID*);

	STDMETHOD(Invoke)(DISPID dispidMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pvarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
	//IDeskBand methods

// Implementation:
public:

// functions
	bool CreateToolWindow(void);
	// refresh icon
	void RefreshIcons(void);
	//check DNS status as separated element of the main source code
	void CheckDomainStatus(char * url);
	// sets the security status icon
	void SetSecurityDNSSECStatus(void);
	void SetSecurityTLSAStatus(void);
	void cache_delete_all(void);
	void cache_delete_all2(void);
	// Index of Bitmap Button	
	int GetIconIndex(int icon);
	// loads preference settings from the Windows registry or file
	void LoadOptionsFromFile(void);
	// CALLBACK function
	static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam);
	bool FileExists(const TCHAR *fileName);
	void CreateIniFile(void);
	short TestResolver(char *domain, char *ipbrowser, char IPv);
	bool ExcludeDomainList(char *domain, short ExcludeOn, char domainlist[TLD_LIST_MLEN]);

// global variables
	HWND m_hWndParent;
	DWORD m_dwBandID;
	DWORD m_dwViewMode;
	char domain[2048];// current domain for each tab
	static CRITICAL_SECTION cs;
	short dnssecresult; //the DNSSEC validation result
	int dnssecicon;
	CKBToolBarCtrl m_wndToolBar;
	IInputObjectSite* inputObjectSite;
	IServiceProviderPtr m_pIOSite;
	CWnd m_wndReflectionWnd;
	CRect rcClientParent2;	
	static bool csInitialized;
	CComPtr< IWebBrowser2 > webBrowser2;
};

OBJECT_ENTRY_AUTO(__uuidof(DNSSECToolBarBand), CDNSSECToolBarBand)
#endif //__DNSSECToolBarBAND_H_
