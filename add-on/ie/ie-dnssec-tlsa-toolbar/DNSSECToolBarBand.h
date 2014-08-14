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
 // key icon dimension
#define ICON_KEY_WIDTH 16
#define ICON_KEY_HEIGHT 16
#define SBAR_POSITION_LEFT 47
#define SBAR_POSITION_TOP 10
#define SBAR_POSITION_LENGTH 620
#define SBAR_POSITION_HEIGHT 14

extern HINSTANCE GHins;
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
		// initialisation and set default values
		statdnssecicon = IDI_DNSSEC_ICON_INIT;
		debug = true;
		temp = "";
		textkey = 0;
		choice = 0;
		choice2 = 0;
		tlsaenable = 1;
		nic = "217.31.204.130";
		oarc = "149.20.64.20";
		usedfwd = 0;
		debugoutput = 1;
		debugoutput_enable = 1;
		wrong = false;
		paneltitletlsa  = 0;
		paneltextmain  = 0;
		paneltextadd  = 0;
		paneltitle  = 0;
		panelpredonain  = 0;
		paneldomainname  = 0;
		tlsapaneldomainname[280]; 
		panelpostdomain  = 0;
		paneltext  = 0;
		keylogo  = 0;
		keylogo2  = 0;
		tlsaiconres = 0;
		tlsaicon = 0;
		err = 0;
		state = 0;

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

// variables
	HWND m_hWndParent;
	DWORD m_dwBandID;
	DWORD m_dwViewMode;
	char domain[2048];
	static CRITICAL_SECTION cs;
	CKBToolBarCtrl m_wndToolBar;
	IInputObjectSite* inputObjectSite;
	IServiceProviderPtr m_pIOSite;
	CWnd m_wndReflectionWnd;
	CRect rcClientParent2;	
	static bool csInitialized;
	CComPtr< IWebBrowser2 > webBrowser2;
	// settings
	bool debug;
	char * temp;
	short textkey;
	short choice;
	short choice2;
	short tlsaenable;
	char dnssecseradr[IPADDR_MLEN];
	char* nic;
	char* oarc;
	short usedfwd;
	short debugoutput;
	short debugoutput_enable;
	// browser
	char ipvalidator4[256];
	char* ipbrowser4;
	char* ipvalidator6;
	char* ipbrowser6;
	int err;
	int state;
	// TLSA panel text
	WORD paneltitletlsa;
	WORD paneltextmain;
	WORD paneltextadd;
	char tlsapaneldomainname[280];
	WORD keylogo2;
	WORD tlsaiconres;
	short tlsaresult;
	int tlsaicon;
	// DNSSEC panel text
	short dnssecresult;
	int dnssecicon;	
	WORD statdnssecicon;	
	WORD dnsseciconBar;
	WORD paneltitle;
	WORD panelpredonain;
	char* paneldomainname;
	WORD panelpostdomain;
	WORD paneltext;
	WORD keylogo;
	short res;
	short filteron;
	char listtld[TLD_LIST_MLEN];
	bool wrong;
};

OBJECT_ENTRY_AUTO(__uuidof(DNSSECToolBarBand), CDNSSECToolBarBand)
#endif //__DNSSECToolBarBAND_H_
