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

// KBBarBand.h : Declaration of the CKBBarBand
#ifndef __KBBarBAND_H_
#define __KBBarBAND_H_
#include "Winuser.h"
#include "Wincrypt.h"
#include "resource.h"       // main symbols
#include "hyperlink.h"
#include "dnssec-states.gen"		// DNSSEC state constants
#include "dane-states.gen"		// TLSA state constants
extern "C" {					// use C language linkage
  #include "dnssec-plug.h"
  #include "dane-plug.h"
}
#include "KBToolBarCtrl.h"
#include <shlguid.h>     // IID_IWebBrowser2, DIID_DWebBrowserEvents2, etc
#include <exdispid.h> // DISPID_DOCUMENTCOMPLETE, etc.
#include <shlobj.h>
#include <ctime>
#include <list>
#include <shlwapi.h>
#pragma comment(lib,"shlwapi.lib")
#pragma comment(lib, "crypt32.lib")
using namespace std;
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define CACHE_EXPIR_TIME 300 // seconds = 5 min is expir time of item in DANE cache

#define TB_MIN_SIZE_X   100
#define TB_MIN_SIZE_Y   22
#define TB_MAX_SIZE_Y   40
#define MAX_STR_LEN		1024
#define IPADDR_MLEN 256
#define TLD_LIST_MLEN 2048
#define KEYTEXT				0
#define RESOLVER			0
#define RESOLVER2			0
#define TLSAENABLE			1
#define IPUSER		TEXT("8.8.8.8")
#define IPNIC		TEXT("217.31.204.130")
#define IPOARC		TEXT("149.20.64.20")
#define TCPUDP				0
#define DEBUGVAL			1
#define DEBUGVAL_ENABLE		1
#define CACHE				1
#define IPv4				1
#define IPv6				0
#define HKU_REG_KEY TEXT(".DEFAULT\\Software\\CZ.NIC\\DNSSEC-TLSA Validator")
#define HKCU_REG_KEY TEXT("Software\\CZ.NIC\\DNSSEC-TLSA Validator")
#define INI_FILE_PATH _T("\\CZ.NIC\\DNSSEC-TLSA Validator\\dnssec.ini")



const int BUTTON_INDEX = 0;
const short DANE_EXIT_WRONG_RESOLVER = -99;
extern HINSTANCE GHins;
extern bool debug;
// settings
extern short textkey;
extern short choice;
extern short choice2;
extern short tlsaenable;
extern char dnssecseradr[IPADDR_MLEN];
extern char* nic;
extern char* oarc;
extern short usedfwd;
extern short debugoutput;
extern short debugoutput_enable;
extern short cache_enable;
extern short ipv4;
extern short ipv6;
extern short ipv46;
extern char ipvalidator4[256];
extern char* ipbrowser4;
extern char* ipvalidator6;
extern char* ipbrowser6;
// TLSA panel text
extern WORD paneltitletlsa;
extern WORD paneltextmain;
extern WORD paneltextadd;
// DNSSEC panel text
extern WORD paneltitle;
extern WORD panelpredonain;
extern char* paneldomainname;
extern char tlsapaneldomainname[280];
extern WORD panelpostdomain;
extern WORD paneltext;
extern short paneltextip;
extern WORD keylogo;
extern WORD keylogo2;
extern WORD tlsaiconres;
extern int err;
extern short res;
extern short tlsaicon;
extern short tlsaresult;
extern short filteron;
extern char listtld[TLD_LIST_MLEN];
extern bool wrong;

// variable for IE version check
extern int iRes,iMajor,iMinor;
//#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
//#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
//#endif
//class CIPAddressCtrl;
class CHyperLink;
extern CHyperLink m_link;
//extern CIPAddressCtrl m_ip; 
/////////////////////////////////////////////////////////////////////////////
// CKBBarBand
class ATL_NO_VTABLE CKBBarBand : 
	public CComObjectRootEx<CComSingleThreadModel>,
	public CComCoClass<CKBBarBand, &CLSID_KBBarBand>,
	public IObjectWithSiteImpl<CKBBarBand>,
	public IDispEventImpl<0, CKBBarBand,&__uuidof(DWebBrowserEvents2), &LIBID_SHDocVw, 1, 0>,
	public IDispatchImpl<IKBBarBand, &IID_IKBBarBand, &LIBID_KBBarLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
	public IInputObject,
	public IDeskBand

		
{
   typedef IDispEventImpl<0, CKBBarBand, &__uuidof(DWebBrowserEvents2), &LIBID_SHDocVw, 1, 0> tDispEvent;
public:
	CKBBarBand()
	{
		//hTabWnd=NULL; //main Handle Tab Window reference
		hWndNewPane=NULL; // main Handle Tab Status Bar Pane
		hTabWnd=NULL;
		//domain=NULL; //current domain for each tab
		predomain=NULL;
		predomaintest=NULL;
		dnssecicon=0; //default key is grey
		// tooltip init
		tiInitialized = false;
		tiInitialized1 = false;
		if (!csInitialized) {
			InitializeCriticalSectionAndSpinCount(&cs, 0x00000400);
			csInitialized = true;
		}

	}

DECLARE_REGISTRY_RESOURCEID(IDR_KBBARBAND)
DECLARE_PROTECT_FINAL_CONSTRUCT()

BEGIN_COM_MAP(CKBBarBand)
	COM_INTERFACE_ENTRY(IObjectWithSite)
	COM_INTERFACE_ENTRY(IInputObject)
	COM_INTERFACE_ENTRY(IDeskBand)
	COM_INTERFACE_ENTRY(IKBBarBand)
	COM_INTERFACE_ENTRY(IDispatch)
	COM_INTERFACE_ENTRY2(IOleWindow, IDeskBand)
	COM_INTERFACE_ENTRY2(IDockingWindow, IDeskBand)
END_COM_MAP()

	BEGIN_SINK_MAP(CKBBarBand)
	END_SINK_MAP()

	HRESULT FinalConstruct() {
		return S_OK;
	}
	void FinalRelease() {
		//CKBBarBand::cache_delete_all2();
		//ATLTRACE("XXXXXXXXXXXXXXXXXXXXXXXx\n");
	}
// Interfaces
public:
	IWebBrowser2Ptr m_pIE;

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
	void cache_delete_all2(void);
	void FocusChange(bool bFocus);
	bool CreateToolWindow(void);
	// refresh icon
	void RefreshIcons(void);
	//check DNS status as separated element of the main source code
	void CheckDomainStatus(char * url);
	// create Status Bar
	bool CreateStatusBarKey(void);
		// create Status Bar
	bool CreateStatusBarText(void);
	// sets the security status icon
	void SetSecurityDNSSECStatus(void);
	void SetSecurityTLSAStatus();
	void cache_delete_all(void);
	// Index of Bitmap Button	
	int GetIconIndex(int icon);
	// version of IE broswer
	int GetMSIEversion(int *iMajor, int *iMinor);
	// loads preference settings from the Windows registry or file
	void LoadOptionsFromRegistry(void);
	void LoadOptionsFromFile(void);
	// creates a tooltip for showing information texts
	void CreateIconTooltip(HWND hwndParent);
	void CreateToolTipForRect(HWND hwndParent);
	// read DWORD and string from registry
	HRESULT RegGetDWord(HKEY hKey, LPCTSTR szValueName, DWORD * lpdwResult);
	HRESULT RegGetString(HKEY hKey, LPCTSTR szValueName, LPTSTR * lpszResult);
	// CALLBACK function
	static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam);
	bool FileExists(const TCHAR *fileName);
	void CreateIniFile();
	short TestResolver(char *domain, char *ipbrowser, char IPv);
	void ShowFwdTooltip(void);
	bool ExcludeDomainList(char *domain, short ExcludeOn, char domainlist[TLD_LIST_MLEN]);
	bool LoadCaCertFromStore(void);


	static int position; //main position of the icon
	bool m_bFocus;			
	HWND hWndNewPane; //status bar pane element
	HWND hWndNewPane2; //status bar pane element
	HWND m_hWndParent;
	HWND hTabWnd; // handle tab window element
	HWND m_hWnd;
	DWORD m_dwBandID;
	DWORD m_dwViewMode;

	char domain[2048];// current domain for each tab
	char *predomain;
	char *predomaintest;
	static CRITICAL_SECTION cs;
	short dnssecresult; //the DNSSEC validation result
	int dnssecicon,dnssecicon2,text; //dnssecicon element

	CWnd m_wndReflectionWnd;
	CRect rcClientParent2;	
	HWND hwndTT;
	TOOLINFO ti;
	bool tiInitialized,tiInitialized1;
	static bool csInitialized;
	DWORD m_dwCookie;
	CComQIPtr<IConnectionPointContainer,&IID_IConnectionPointContainer> m_spCPC;
	CComQIPtr<IWebBrowser2, &IID_IWebBrowser2> m_spWebBrowser2;	
	CComBSTR bstrUrlName,bstrUrlName2,bstrUrlName3;
	CKBToolBarCtrl m_wndToolBar;
	IInputObjectSite* inputObjectSite;
	IServiceProviderPtr m_pIOSite;
	CComPtr< IWebBrowser2 > webBrowser2;
};

OBJECT_ENTRY_AUTO(__uuidof(KBBarBand), CKBBarBand)
#endif //__KBBarBAND_H_
