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

#include "stdafx.h"
#include "KBBar.h"
#include "KBBarBand.h"
#include <string.h>
//String2BSTR conversion
#include <comutil.h>
#include <CommCtrl.h>
#include "resource.h"

WORD icon =IDI_ICON_KEY_ACTION1;
WORD statldicon=IDI_ICON_KEY_GREY;
WORD ldiconBar;
// default icon status 
int CKBBarBand::position=0; //default position
WNDPROC CKBBarBand::WProcStatus=NULL; //WNDPROC status
bool csInitialized = false;
int ICON_KEY_WIDTH = 39;
int ICON_KEY_HEIGHT = 19;
extern HINSTANCE GHins;
#define STR_BUF_SIZE	512
char* DNSSECtext= TEXT("DNSSEC Status:");
char* DNSSECtext2= TEXT("Undefined");
char* StatusBarText[BITMAP_NUMBER] = {TEXT("undefined") /*0*/, TEXT("secured") /*1*/,
	TEXT("non-secured")  /*2*/, TEXT("non-secured")  /*3*/,  TEXT("unknown")  /*4*/, 
	TEXT("unknown")  /*5*/, TEXT("unknown")  /*6*/};
//at the begining, all domain elements can be navigated
bool CKBBarBand::WarnBlockAid=true; 
/**************************************************************************/
// IObjectWithSite implementations
/**************************************************************************/
STDMETHODIMP CKBBarBand::SetSite(IUnknown* pUnkSite)
{
		ATLTRACE( "SetSite() call\n");
		if (m_pIOSite)
		{
			m_pIOSite->Release();
			m_pIOSite = NULL;
		}
		if (pUnkSite)
		{
			IOleWindow  *pOleWindow = NULL;
			this->m_hWndParent = NULL;
			if (SUCCEEDED(pUnkSite->QueryInterface(
				IID_IOleWindow, (LPVOID*)&pOleWindow)))
			{
				pOleWindow->GetWindow(&this->m_hWndParent);
				pOleWindow->Release();
			}
			if (!::IsWindow(m_hWndParent))
					return E_FAIL;
			if(!CreateToolWindow()) return E_FAIL;
			HRESULT hRes = pUnkSite->QueryInterface(
				IID_IInputObjectSite,
				(void**)&inputObjectSite);
			if (hRes != S_OK)
				return E_FAIL;
			if (!webBrowser2)
			{
				CComQIPtr<IServiceProvider> spSP(inputObjectSite);
				if ( spSP )
				{
					hRes = spSP->QueryService(
						__uuidof(IWebBrowserApp),
						__uuidof(IWebBrowser2),
						(void**)&webBrowser2);
					if ( hRes != S_OK )
						::MessageBox(NULL,"Chyba získání IE", NULL, NULL);
					tDispEvent::DispEventAdvise(webBrowser2);
				}
				else
					return E_FAIL;
			}
			return S_OK;
		}
		else
		{
			if (webBrowser2)
				tDispEvent::DispEventUnadvise(webBrowser2);	
		}
		return S_OK;
	}
STDMETHODIMP CKBBarBand::GetSite(REFIID riid, LPVOID *ppvReturn)
{
	ATLTRACE("GetSite():\n");
	*ppvReturn = NULL;

	if(m_pIOSite)
	   return m_pIOSite->QueryInterface(riid, ppvReturn);

	return E_FAIL;
}
/**************************************************************************/
// IOleWindow Implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::GetWindow(HWND *phWnd)
{
		ATLTRACE("GetWindow():\n");
	*phWnd = m_wndToolBar.GetSafeHwnd();

	return S_OK;
}
STDMETHODIMP CKBBarBand::ResizeBorderDW(LPCRECT prcBorder, IUnknown* punkSite, BOOL fReserved)
{
	ATLTRACE("ResizeBorderDW():\n");
	ATLTRACENOTIMPL("IDockingWindow::ResizeBorderDW");
}
STDMETHODIMP CKBBarBand::ContextSensitiveHelp(BOOL fEnterMode)
{
	ATLTRACE("ContextSensitiveHelp():\n");
	ATLTRACENOTIMPL("IOleWindow::ContextSensitiveHelp");
}
/**************************************************************************/
// IDockingWindow Implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::ShowDW(BOOL fShow)
{
	ATLTRACE("ShowDW():\n");
	if(m_wndToolBar.GetSafeHwnd())
	{
		if(fShow)
		{
			//show our window
			m_wndToolBar.ShowWindow(SW_SHOW);		
		}
		else
		{
			//hide our window
			m_wndToolBar.ShowWindow(SW_HIDE);
		}
	}
	return S_OK;
}
STDMETHODIMP CKBBarBand::CloseDW(DWORD dwReserved)
{
	ATLTRACE("CloseDW():\n");
	ShowDW(FALSE);
	return S_OK;
}
/**************************************************************************/
// IInputObject Implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::UIActivateIO(BOOL fActivate, LPMSG pMsg)
{
	ATLTRACE("UIActivateIO():\n");
	if(fActivate)
	{
		SetFocus(m_wndToolBar);
	}
	return S_OK;
}
STDMETHODIMP CKBBarBand::HasFocusIO(void)
{ 
	ATLTRACE("HasFocusIO():\n");
	HWND hwndFocus = ::GetFocus();
	return S_OK;
}
STDMETHODIMP CKBBarBand::TranslateAcceleratorIO(LPMSG pMsg)
{
	ATLTRACE("TranslateAcceleratorIO():\n");
	return m_wndToolBar.TranslateAcceleratorIO(pMsg);
}
/**************************************************************************/
// IDeskBand implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::GetBandInfo(DWORD dwBandID, DWORD dwViewMode, DESKBANDINFO* pdbi)
{
ATLTRACE("GetBandInfo():\n");
USES_CONVERSION;

	if(pdbi)
	{
		m_dwBandID = dwBandID;
		m_dwViewMode = dwViewMode;

		if(pdbi->dwMask & DBIM_MINSIZE)
		{
			pdbi->ptMinSize.x = TB_MIN_SIZE_X;
			pdbi->ptMinSize.y = TB_MIN_SIZE_Y;
		}

		if(pdbi->dwMask & DBIM_MAXSIZE)
		{
			pdbi->ptMaxSize.x = -1;
			pdbi->ptMaxSize.y = TB_MAX_SIZE_Y;
		}

		if(pdbi->dwMask & DBIM_INTEGRAL)
		{
			pdbi->ptIntegral.x = 1;
			pdbi->ptIntegral.y = 1;
		}

		if(pdbi->dwMask & DBIM_ACTUAL)
		{
			pdbi->ptActual.x = 0;
			pdbi->ptActual.y = 0;
		}

		if(pdbi->dwMask & DBIM_TITLE)
		{
			AFX_MANAGE_STATE(AfxGetStaticModuleState()); // Needed for any MFC usage in DLL
			CString strTitle((LPCSTR)IDS_TOOLBARNAME);
			lstrcpyW(pdbi->wszTitle, T2W((LPTSTR)(LPCTSTR)strTitle));
		}

		if(pdbi->dwMask & DBIM_MODEFLAGS)
		{
			pdbi->dwModeFlags = DBIMF_NORMAL;

			pdbi->dwModeFlags |= DBIMF_VARIABLEHEIGHT;
		}

		if(pdbi->dwMask & DBIM_BKCOLOR)
		{
			//Use the default background color by removing this flag.
			pdbi->dwMask &= ~DBIM_BKCOLOR;
		}

		return S_OK;
	}
	else // !pdbi
		return E_INVALIDARG;
}
/**************************************************************************/
//Invoke: This method allows to obtain MSIE events
/**************************************************************************/
STDMETHODIMP CKBBarBand::Invoke(DISPID dispidMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pvarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
   ATLTRACE("Invoke() call\n");
	USES_CONVERSION;//avoiding warnings with respect to ATL DATA_TYPE element
	HWND hwnd=NULL;
	//ATLTRACE(DEBUG_PREFIX "dispidMember: %d\n");
	//loading MSIE elements
	HRESULT hr = webBrowser2->get_HWND((LONG_PTR*)&hwnd);
	//succeed?
	if (SUCCEEDED(hr)) {
		switch(dispidMember) {	
			case DISPID_WINDOWSTATECHANGED : {
				ATLTRACE("Invoke(): DISPID_WINDOWSTATECHANGED\n");
				//statldicon = ldicon; // current status
				ldicon2 = ldicon;
				m_wndToolBar.RepaintButton(BUTTON_INDEX,ldicon2);
				statldicon = ldiconBar;
				RefreshIcon2();
			} break;

			case DISPID_BEFORENAVIGATE2 : {	
				ATLTRACE("Invoke(): DISPID_BEFORENAVIGATE2\n");
				//this element helps the plugin to extract the URL
				//allocated in memory of MSIE
				ATLASSERT((*pDispParams).rgvarg[5].vt = VT_BYREF | VT_BSTR);
				bstrUrlName = ((*pDispParams).rgvarg)[5].pvarVal->bstrVal;
				//DNSSEC display
				displaydnssecstatus();
				ldicon = 2;
				m_wndToolBar.RepaintButton(BUTTON_INDEX,ldicon);
			} break;
			//default status
			default : {
			} break;
		}
	}
	return S_FALSE;
}
/**************************************************************************/
// refresh icon in the status bar (WM_PAINT invocation)
/**************************************************************************/
void CKBBarBand::RefreshIcon2(void) {
	ATLTRACE( "RefreshIcon() call\n");
	RedrawWindow(hWndNewPane, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    MoveWindow(hWndNewPane, 50, 3, 235, ICON_KEY_HEIGHT, TRUE);
	//RedrawWindow(hWndNewPane2, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
    //MoveWindow(hWndNewPane2, 100, 3, 300, ICON_KEY_HEIGHT, TRUE);
	//SendMessage((HWND) hWndNewPane2, (UINT) SB_SETBKCOLOR, 0, 0x00FF0000);
	//SendMessage((HWND) hWndNewPane2, (UINT) SB_SETTEXT, (WPARAM)(INT) 0 | 0, (LPARAM) (LPSTR) TEXT("DNSSEC Validator"));
}
/**************************************************************************/
// CallBack function for StatusPanel repainting
/**************************************************************************/
LRESULT CKBBarBand::WndProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam)
{
	switch (uMessage) 
	{
		case WM_PAINT: 
		{	
			ATLTRACE("PWProc: WM_PAINT\n");
			PAINTSTRUCT ps;
			//beginning paint event
			HDC hDC = BeginPaint(hWnd, &ps);
		    // Get the coordinates of the parent window's client area.
			CRect rcClient;
			GetClientRect(hWnd, &rcClient);
			//loading current status icon
			HICON icon2 = (HICON)LoadImage(GHins, MAKEINTRESOURCE(statldicon), IMAGE_ICON, ICON_KEY_WIDTH, ICON_KEY_HEIGHT, LR_DEFAULTSIZE);
			//drawing icon
			ATLTRACE("PWProc: rcClient w: %d; h: %d\n", rcClient.Width(), rcClient.Height());
			DrawIconEx(hDC,110,0,icon2, 0, 0, NULL, NULL, DI_NORMAL);
			//DrawTextEx(
			SetBkMode(hDC,TRANSPARENT);
			DrawText(hDC,DNSSECtext,strlen(DNSSECtext),rcClient, DT_BOTTOM | DT_SINGLELINE | DT_LEFT);
			DrawText(hDC,DNSSECtext2,strlen(DNSSECtext2),rcClient, DT_BOTTOM | DT_SINGLELINE | DT_RIGHT);
			EndPaint(hWnd, &ps);
			break;
			
		}

		case WM_RBUTTONUP : {
			ATLTRACE("PWProc: WM_RBUTTONUP\n");
		    // Get the coordinates of the parent window's client area.
			CRect rcNewPane;
			POINT ptClick;
			//obtaining the current menu
			HMENU hMenuStatusBar = GetSubMenu(LoadMenu(GHins,MAKEINTRESOURCE(IDR_MENU_POPUP)), 0);
			//if available
			if(hMenuStatusBar) {
				//checking whether an option has changed
				if(WarnBlockAid)
					CheckMenuItem(hMenuStatusBar, ID_ENABLED, MF_CHECKED);
				//pre-drawing parameters under the ICON frame
				ptClick.x = rcNewPane.right;
				ptClick.y = rcNewPane.top;
				//to the parent window
				ClientToScreen(hWnd, &ptClick);
				//obtaining the element that has been chosen 
				int cmd = TrackPopupMenu(hMenuStatusBar, TPM_NONOTIFY|TPM_RETURNCMD|TPM_LEFTBUTTON|TPM_RIGHTALIGN, ptClick.x, ptClick.y, 0, hWnd, 0);
				switch (cmd) {
					case ID_ENABLED : {
						// the status changes
						// allow or not the navigation on non-signed domains
						WarnBlockAid=!WarnBlockAid;
						break;
					}
					case ID_ABOUT : { 
						//result = NPAPI_EXIT_NODOMAIN_SIGNATURE_INVALID;
						break;
					}
				}
			}
			break;
 		}
		default: {
			break;
		}
	}
   return DefWindowProc(hWnd, uMessage, wParam, lParam);
}
/**************************************************************************/
// CKBBarBand toolbar creator with one key button
/**************************************************************************/
bool CKBBarBand::CreateToolWindow()
{
	AFX_MANAGE_STATE(AfxGetStaticModuleState()); // Needed for any MFC usage in DLL
	ATLTRACE("CreateToolWindow():\n");
	CRect rcClientParent;
	rcClientParent2=rcClientParent;
	CWnd* pWndParent = CWnd::FromHandle(m_hWndParent);
	pWndParent->GetClientRect(&rcClientParent);

	// We need to create a reflection window in between our toolbar control
	// and the rebar in order to get WM_COMMAND messages sent from the toolbar to its
	// parent. 
	if (!m_wndReflectionWnd.CreateEx(NULL, TOOLBARCLASSNAME,"DNSSEC BAR Module",WS_CHILD | WS_CLIPSIBLINGS | WS_BORDER,rcClientParent.left,rcClientParent.top,rcClientParent.right-rcClientParent.left,rcClientParent.bottom-rcClientParent.top,*pWndParent,NULL,0))
		return false;

	if (!m_wndToolBar.Create(rcClientParent, &m_wndReflectionWnd, this, icon))
		return false;

	if (!SendMessage(m_wndToolBar, TB_SETBITMAPSIZE, 0, MAKELPARAM(39, 19)))
	return false;
	
	CreateStatusBarKey();
	//CreateStatusBarText();
	CreateIconTooltip(m_wndToolBar);

	//ti.lpszText = TEXT("DNSSEC Validator\nURL: www.sezanmc.cz\n\nStatus: DNSSEC OK");
	//SendMessage(hwndTT, TTM_SETTITLE, TTI_INFO, (LPARAM)"DNSSEC status:");
	//SendMessage(hwndTT, TTM_UPDATETIPTEXT, 0, (LPARAM) (LPTOOLINFO) &ti);

	//CreateStatusBar();
	return true;
}
/**************************************************************************/
// Status bar KEY creator
/**************************************************************************/
bool CKBBarBand::CreateStatusBarKey()
{
ATLTRACE("CreateStatusBar():\n");
HWND hWndNewPane = CreateWindowEx(
	0,					// no extended styles
	STATUSCLASSNAME,	// name of status bar class
	(LPCTSTR) "DNSSEC Key",		// no text when first created
	WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
	0, 0, 0, 0,			// ignores size and position
	m_wndToolBar,			// handle to parent window
	NULL,				// child window identifier
	GHins,				// handle to application instance
	NULL);	

	::SetWindowLongPtr(hWndNewPane, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(&WndProc));
	RedrawWindow(hWndNewPane, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
	MoveWindow(hWndNewPane, 50, 3, 235, ICON_KEY_HEIGHT, TRUE);

return true;
}
/**************************************************************************/
// Status bar TEXT creator
/**************************************************************************/
bool CKBBarBand::CreateStatusBarText()
{
ATLTRACE("CreateStatusBar():\n");
HWND hWndNewPane2 = CreateWindowEx(
	0,					// no extended styles
	STATUSCLASSNAME,	// name of status bar class
	(LPCTSTR) "DNSSEC Text",		// no text when first created
	WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
	0, 0, 0, 0,			// ignores size and position
	m_wndToolBar,			// handle to parent window
	NULL,				// child window identifier
	GHins,				// handle to application instance
	NULL);	

	::SetWindowLongPtr(hWndNewPane2, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(&WndProc));
	RedrawWindow(hWndNewPane2, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
	MoveWindow(hWndNewPane2, 100, 3, 300, ICON_KEY_HEIGHT, TRUE);
	SendMessage((HWND) hWndNewPane2, (UINT) SB_SETBKCOLOR, 0, 0x00FF0000);
	SendMessage((HWND) hWndNewPane2, (UINT) SB_SETTEXT, (WPARAM)(INT) 0 | 0, (LPARAM) (LPSTR) TEXT("DNSSEC Validator"));	 

return true;
}
/**************************************************************************/
// Tooltip bubble creator
/**************************************************************************/
void CKBBarBand::CreateIconTooltip(HWND hwndParent)
{
    ATLTRACE("CreateIconTooltip() call\n");	
	// Create a tooltip.
    hwndTT = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, 
                                 WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP | TTS_BALLOON,
                                 CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
                                 hwndParent, NULL, GHins, NULL);

    SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0, 
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    // Set up "tool" information. In this case, the "tool" is the entire parent window.
    //TOOLINFO ti = { 0 };
	ti.cbSize   = TTTOOLINFOA_V2_SIZE;
    ti.uFlags   = TTF_SUBCLASS;
    ti.hwnd     = hwndParent;
    ti.hinst    = NULL;
    ti.lpszText = MAKEINTRESOURCE(IDS_ADDON_INIT);
    
    GetClientRect(hwndParent, &ti.rect);

    SendMessage(hwndTT, TTM_SETMAXTIPWIDTH, 0, 300);
	
	// Associate the tooltip with the tool window.
    SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM) (LPTOOLINFO) &ti);
} 
/**************************************************************************/
// Bitmap index convert
/**************************************************************************/
int CKBBarBand::GetBitmapIndex(int Bitmap)
{	
	ATLTRACE("GetBitmapIndex():\n");
	for (int i=0; i<BITMAP_NUMBER; i++) {
	  if (Bitmap==StatusBitmap[i]) return i;
	}//for
	return -1;
}//
/**************************************************************************/
// Set security status (key bitmap and tooltip text)
/**************************************************************************/
void CKBBarBand::SetSecurityStatus()
{
	ATLTRACE("SetSecurityStatus():\n");
	// DNSSEC status tooltipinfo
	WORD tiicon = TTI_NONE;		// icon in tooltipinfo
	WORD tiicontitle = IDS_NONE;// main title of tooltipinfo
	WORD tipref = IDS_NONE;		// prefix
	WORD tistatus = IDS_NONE;	// DNSSEC status
	WORD titext = IDS_NONE;     // DNSSEC status text
	
	// switch of DNSSEC status - bitmap, tooltip info
	switch (result) {
	case NPAPI_EXIT_CONNECTION_DOMAIN_SECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREEN1);
		ldiconBar = IDI_ICON_KEY_GREEN;
		tiicon = TTI_INFO;
		tiicontitle = IDS_DNSSEC_SECURED_LABEL;
		tipref = IDS_DNSSEC_THISDOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_CONNECTION_DOMAIN_SECURED;
 		break;

	case NPAPI_EXIT_CONNECTION_NODOMAIN_SECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREEN1);
		ldiconBar = IDI_ICON_KEY_GREEN;
		tiicon = TTI_INFO;
		tiicontitle = IDS_DNSSEC_SECURED_LABEL;
		tipref = IDS_DNSSEC_THISDOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_CONNECTION_NODOMAIN_SECURED;
 		break;

	case NPAPI_EXIT_CONNECTION_INVSIGDOMAIN_SECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_DNSSEC_SECURED_LABEL;
		tipref = IDS_DNSSEC_THISDOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_CONNECTION_INVSIGDOMAIN_SECURED;
 		break;

	case NPAPI_EXIT_DOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISDOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_DOMAIN_SIGNATURE_VALID;
 		break;

	case NPAPI_EXIT_AUTH_DOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISNODOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_AUTH_DOMAIN_SIGNATURE_VALID;
 		break;

	case NPAPI_EXIT_DOMAIN_SIGNATURE_INVALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISNODOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_DOMAIN_SIGNATURE_INVALID;
 		break;

	case NPAPI_EXIT_NODOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISNODOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_NODOMAIN_SIGNATURE_VALID;
 		break;

	case NPAPI_EXIT_AUTH_NODOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISNODOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_AUTH_NODOMAIN_SIGNATURE_VALID;
 		break;

	case NPAPI_EXIT_NODOMAIN_SIGNATURE_INVALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISNODOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_NODOMAIN_SIGNATURE_INVALID;
 		break;

	case NPAPI_EXIT_DOMAIN_UNSECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_RC1);
		ldiconBar = IDI_ICON_KEY_GREY_RC;
		tiicon = TTI_INFO;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISDOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISUNSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_DOMAIN_UNSECURED;
 		break;

	case NPAPI_EXIT_NODOMAIN_UNSECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_RC1);
		ldiconBar = IDI_ICON_KEY_GREY_RC;
		tiicon = TTI_INFO;
		tiicontitle = IDS_DNSSEC_UNSECURED_LABEL;
		tipref = IDS_DNSSEC_THISNODOMAIN_LABEL;
		tistatus = IDS_DNSSEC_THISUNSECUREDDOMAIN_LABEL;
		titext = IDS_DNSSEC_NODOMAIN_UNSECURED;
 		break;

	case NPAPI_EXIT_UNKNOWN:
    case NPAPI_EXIT_FAILED:
    default:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_YT1);
		ldiconBar = IDI_ICON_KEY_GREY_YT;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_DNSSEC_ERROR_LABEL;
		tipref = IDS_DNSSEC_TOOLTIP_ERROR;
		break;
	}// switch


	DNSSECtext2 = StatusBarText[ldicon];
	char tmpbuf[STR_BUF_SIZE];
	char tibuf[STR_BUF_SIZE*4] = TEXT(""); // buffer to store tooltip string
	
	LoadStringA(GHins, tipref, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT(" "), 1);

	strncat_s(tibuf, domain, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT(" "), 1);

	LoadStringA(GHins, tistatus, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT("\n\n"), 2);

	
	//DNSSECtext = tibuf;
	
	LoadStringA(GHins, titext, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
    LoadStringA(GHins, tiicontitle, tmpbuf, STR_BUF_SIZE);
	
	ti.lpszText = tibuf;

	ldicon2 = ldicon; // action icon
	m_wndToolBar.RepaintButton(BUTTON_INDEX,ldicon2);

	statldicon = ldiconBar;
	RefreshIcon2();

	SendMessage(hwndTT, TTM_SETTITLE, tiicon, (LPARAM) tmpbuf);
	SendMessage(hwndTT, TTM_UPDATETIPTEXT, 0, (LPARAM) (LPTOOLINFO) &ti);
}//
/**************************************************************************/
// It displays DNSSEC status function
/**************************************************************************/
void CKBBarBand::displaydnssecstatus(void)
{
	ATLTRACE("displaydnssecstatus() call\n");

	//the next lines allow to the plugin to cast the URL name to
	//a "standard readable" string char*
	//but now in the case of the domain name
	domain = (char*)malloc(2048*sizeof(char));
	predomain= (char*)malloc(2048*sizeof(char));
	predomain=_com_util::ConvertBSTRToString(bstrUrlName);
	ATLTRACE(predomain);
	ATLTRACE("\n");
	//error URL
	static char pattern[]="res://ieframe.dll/dnserrordiagoff.htm#";
	char *errordomain=NULL;
	errordomain=(char*)malloc(2048*sizeof(char));
	strcpy_s(errordomain,2048,predomain);

	//this element will allocate the list of DNS primary servers
	char **prevDNSlist;
	prevDNSlist=(char**)malloc(200*sizeof(char));

	//output status has changed , special cases
	if (strcmp(predomain,"about:Tabs")==0 || strcmp(predomain,"about:Blank")==0 || strcmp(predomain,"about:blank")==0) {
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY1);
		ldiconBar = IDI_ICON_KEY_GREY;
	}else{
		//default FAIL URL 
		if (strcmp(predomain,"res://ieframe.dll/dnserrordiagoff.htm")!=0) { //current navigation
			char *isstring=NULL;
			isstring=(char*)malloc(2048*sizeof(char));
			isstring=strstr(errordomain,pattern);
			// here the current domain is verified
			if (isstring==NULL){
			checkdomainstatus();
			}
		}
	}
}
/**************************************************************************/
// It checks whether a domain is a DNSSEC domain
/**************************************************************************/
void CKBBarBand::checkdomainstatus(void) 
{
	ATLTRACE("checkdomainstatus() call\n");
	//temporal element that helps to fragment the given URL in a domain
	char* tmpdomain = NULL;
	tmpdomain= (char*)malloc(2048*sizeof(char));
	tmpdomain=URL2domain(predomain);
	strcpy_s(domain,2048,tmpdomain);	
	
	ldicon2 = IDI_ICON_KEY_ACTION1; 
	m_wndToolBar.RepaintButton(BUTTON_INDEX,ldicon2);
	
	statldicon = IDI_ICON_KEY_ACTION; // action icon
	RefreshIcon2();
	//LoadOptions();

	// temporary hardcoded requested IP version
	//bool resolvipv4 = true;
	//bool resolvipv6 = false;
	/*
	uint16_t options = 0;
	if (prefs.dwDebugoutput) options |= NPAPI_INPUT_FLAG_DEBUGOUTPUT;
	if (prefs.dwUsetcp) options |= NPAPI_INPUT_FLAG_USETCP;
	if (resolvipv4) options |= NPAPI_INPUT_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= NPAPI_INPUT_FLAG_RESOLVIPV6;
	*/
	// Request ownership of the critical section
	//EnterCriticalSection(&cs);
	//ATLTRACE(DEBUG_PREFIX "Critical section begin\n");

	//char *tmpptr = NULL;
	//uint32_t ttl4, ttl6;
	result = NPAPI_EXIT_DOMAIN_SIGNATURE_VALID;
	//ds_free_resaddrsbuf();
	
	
	// Release ownership of the critical section
	//ATLTRACE(DEBUG_PREFIX "Critical section end\n");
	//LeaveCriticalSection(&cs);
	SetSecurityStatus();
}
/**************************************************************************/
//to convert URL string on domain name, removed http:\\ 
/**************************************************************************/
char* CKBBarBand::URL2domain(char *url) 
{
	ATLTRACE("URL2domain() call\n");
	//static char instead of char
	static char separator[]   = "://";
	char *namedomain=NULL;
	char *next_token=NULL;
	//to store current domain name
	namedomain=(char*)malloc(2048*sizeof(char));
	next_token=(char*)malloc(2048*sizeof(char));
	//checking whether there is an available URL element
	if (strcmp(url,"")==0){
		return "Blank";
	}
	else {
		namedomain = strtok_s(url, separator, &next_token);
		namedomain = strtok_s(NULL,separator, &next_token);
		return namedomain;
	}
}
/**************************************************************************/
// not use for this time
/**************************************************************************/
void CKBBarBand::InitDraw(void) {
	ATLTRACE("InitDraw() call\n");

	//obtaining the HWND element of internet explorer
	HWND hMainWndIE = NULL;
	HRESULT hr = m_spWebBrowser2->get_HWND((LONG_PTR*)&hMainWndIE);
	if (SUCCEEDED(hr)) {
		// obtaning the HWND element for the current Tab element by using
		// IShellBrowser objects
		// this solution was chosen because of the main HWND element
		// remains STATIC under each HWND TAB reference
		IServiceProvider* pServiceProvider = NULL;
		if (SUCCEEDED(m_spWebBrowser2->QueryInterface(IID_IServiceProvider,(void**)&pServiceProvider))) {
			IOleWindow* pWindow = NULL;
			if (SUCCEEDED(pServiceProvider->QueryService(SID_SShellBrowser,IID_IOleWindow,(void**)&pWindow))) {
				TCHAR szClassName[MAX_PATH];
				//extracting HWND for the current Tab element
				if(SUCCEEDED(pWindow->GetWindow(&hTabWnd))) {
					//exxtracting each child window
					for (unsigned int i=0;i<2;i++) {
						if (i)
							//hTabWnd = GetWindow(hTabWnd, GW_CHILD);
						GetClassName(hTabWnd, szClassName, MAX_PATH);
						//detecting whether the current child window be TabWindowClass or StatusBarPaneClass
						while(hTabWnd && _tcscmp(szClassName, (!i) ? _T("TabWindowClass") : _T("msctls_statusbar32"))) {
							//hTabWnd = GetWindow(hTabWnd, GW_HWNDNEXT);
							GetClassName(hTabWnd, szClassName, MAX_PATH);
						}
					}
				}
				pWindow->Release();
			}
			pServiceProvider->Release();
		}
	}
}