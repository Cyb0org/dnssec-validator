// KBBarBand.h : Declaration of the CKBBarBand

#ifndef __KBBarBAND_H_
#define __KBBarBAND_H_
#include "Winuser.h"
#include "resource.h"       // main symbols
#include "dnssecStates.gen"		// DNSSEC state constants
#include "KBToolBarCtrl.h"
#include <shlguid.h>     // IID_IWebBrowser2, DIID_DWebBrowserEvents2, etc
#include <exdispid.h> // DISPID_DOCUMENTCOMPLETE, etc.
#define TB_MIN_SIZE_X   20
#define TB_MIN_SIZE_Y   26
const int BUTTON_INDEX = 0;
#define TB_MAX_SIZE_Y   40
#define MAX_STR_LEN		1024

typedef struct {                // structure to save preferences
	char szDnsserveraddr[MAX_STR_LEN];
	DWORD dwDebugoutput;
	DWORD dwUsetcp;
} dsv_preferences;

#if defined(_WIN32_WCE) && !defined(_CE_DCOM) && !defined(_CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA)
#error "Single-threaded COM objects are not properly supported on Windows CE platform, such as the Windows Mobile platforms that do not include full DCOM support. Define _CE_ALLOW_SINGLE_THREADED_OBJECTS_IN_MTA to force ATL to support creating single-thread COM object's and allow use of it's single-threaded COM object implementations. The threading model in your rgs file was set to 'Free' as that is the only threading model supported in non DCOM Windows CE platforms."
#endif


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
		prefs.szDnsserveraddr[0] = '\0';
		prefs.dwDebugoutput = 0;
		prefs.dwUsetcp = 0;
		//hTabWnd=NULL; //main Handle Tab Window reference
		hWndNewPane=NULL; // main Handle Tab Status Bar Pane
		hTabWnd=NULL;
		domain=NULL; //current domain for each tab
		predomain=NULL;

		// tooltip init
		tiInitialized = false;
		

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
/*		SINK_ENTRY_EX(0,
			(__uuidof(DWebBrowserEvents2)),
			0x000000fa, BeforeNavigate2)
		SINK_ENTRY_EX(0,
			(__uuidof(DWebBrowserEvents2)),
			0x000000fa, WindowStateChanged)
			*/
	END_SINK_MAP()


	HRESULT FinalConstruct() {
		return S_OK;
	}
	void FinalRelease() {
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
	
	//IContextMenu methods
	//STDMETHOD (QueryContextMenu)(HMENU, UINT, UINT, UINT, UINT);
	//STDMETHOD (InvokeCommand)(LPCMINVOKECOMMANDINFO);
	STDMETHOD(Invoke)(DISPID dispidMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pvarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
		//IDeskBand methods

	//CComQIPtr<IServiceProvider, &IID_IServiceProvider> m_pIOSite;
// Implementation:
public:
	void FocusChange(bool bFocus);
	bool CreateToolWindow(void);
	// refresh icon
	void RefreshIcon2(void);
	// create Status Bar
	bool CreateStatusBarKey(void);
		// create Status Bar
	bool CreateStatusBarText(void);
	// sets the security status icon
	void SetSecurityStatus(void);
	// Index of Bitmap Button
	int GetBitmapIndex(int Bitmap);


	static LRESULT CALLBACK WndProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam);
	static LRESULT CALLBACK NSProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
	static WNDPROC WProcStatus; //WNDPROC thread
	static int position; //main position of the icon


	//HRESULT Connect(void);
	// to draw the icon
	bool m_bFocus;			
	HWND hWndNewPane; //status bar pane element
	HWND hWndNewPane2; //status bar pane element
	HWND m_hWndParent;
	HWND hTabWnd; // handle tab window element
	HWND m_hWnd;
	DWORD m_dwBandID;
	DWORD m_dwViewMode;
	IServiceProviderPtr m_pIOSite;
	CWnd m_wndReflectionWnd;
		static bool WarnBlockAid; // navigate or not on non-authenticated domains
	CRect rcClientParent2;
			// creates a tooltip for showing information texts
	void CreateIconTooltip(HWND hwndParent);
	void CreateToolTipForRect(HWND hwndParent);
	HWND hwndTT;
	TOOLINFO ti;
	bool tiInitialized;
	DWORD m_dwCookie;
	CComQIPtr<IConnectionPointContainer,&IID_IConnectionPointContainer> m_spCPC;
		//it extracts a domain element from an URL element
	char *URL2domain(char*);
	CComQIPtr<IWebBrowser2, &IID_IWebBrowser2> m_spWebBrowser2;
	// loads preference settings from the Windows registry
	void LoadOptions(void);
	// preferences variable
	dsv_preferences prefs;
		//check DNS status as separated element of the main source code
	void checkdomainstatus(void);
		char *domain;// current domain for each tab
	char *predomain;
	
	short result; //the DNSSEC validation result
	int ldicon,ldicon2; //ldicon element
				//validation function
	void displaydnssecstatus(void);
	CComBSTR bstrUrlName;
	CKBToolBarCtrl m_wndToolBar;
	void CKBBarBand::InitDraw(void);
	IInputObjectSite* inputObjectSite;
	CComPtr< IWebBrowser2 > webBrowser2;
	CString LoadTextResource(UINT nID);
	/*
	void __stdcall BeforeNavigate2(LPDISPATCH pDisp, VARIANT* URL, VARIANT* Flags, VARIANT* TargetFrameName, VARIANT* PostData, VARIANT* Headers, BOOL* Cancel);	
	void __stdcall WindowStateChanged(DWORD dwFlags, DWORD dwValidFlagsMask);
	*/
};

OBJECT_ENTRY_AUTO(__uuidof(KBBarBand), CKBBarBand)
#endif //__KBBarBAND_H_
