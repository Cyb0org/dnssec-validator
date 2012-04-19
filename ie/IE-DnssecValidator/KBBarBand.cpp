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
#include "resource.h"
#include "shlobj.h"
#include <string>
//#include <CommCtrl.h>
// size of buffer for URL parts save
#define STR_BUF_SIZE	512
// default icon status 
WORD statldicon=IDI_ICON_KEY_GREY;
// for ICON KEY status - not used
WORD ldiconBar;
short textkey = KEYTEXT;
short choice = RESOLVER;
short choice2 = RESOLVER2;
char dnssecseradr[IPADDR_MLEN] = "000.000.000.000 0000:0000:0000:0000:0000:0000:0000:0000";
char* nic = IPNIC;
char* oarc = IPOARC;
short tcpudp = TCPUDP;
short debugoutput = DEBUGVAL;
short debugoutput_enable = DEBUGVAL_ENABLE;
// key state memory
int state;
// url address memory
char * urladdr = " ";
// variable for IE version check
int iRes,iMajor=0,iMinor=0;
 // key icon dimension
int ICON_KEY_WIDTH = 39;
int ICON_KEY_HEIGHT = 19;
int SBAR_POSITION_LEFT = 47;
int SBAR_POSITION_TOP = 10;
int SBAR_POSITION_LENGTH = 620;
int SBAR_POSITION_HEIGHT = 14;
// ctritical section for resolver
CRITICAL_SECTION CKBBarBand::cs;
// for tooltip creation
bool CKBBarBand::csInitialized = false;
bool csInitialized = false;
char DefaultIniData[] = "[DNSSEC]\nkeytext=0\nchoice=0\nchoicedns=0\nuserip=127.0.0.1\ntcpudp=0\ndebugoutput=0";
//CIPAddressCtrl m_ip; 
/**************************************************************************/
// IObjectWithSite implementations
/**************************************************************************/
STDMETHODIMP CKBBarBand::SetSite(IUnknown* pUnkSite)
{
		//ATLTRACE( "SetSite() call\n");
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
	//ATLTRACE("GetSite():\n");
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
		//ATLTRACE("GetWindow():\n");
	*phWnd = m_wndToolBar.GetSafeHwnd();

	return S_OK;
}
STDMETHODIMP CKBBarBand::ResizeBorderDW(LPCRECT prcBorder, IUnknown* punkSite, BOOL fReserved)
{
	//ATLTRACE("ResizeBorderDW():\n");
	ATLTRACENOTIMPL("IDockingWindow::ResizeBorderDW");
}
STDMETHODIMP CKBBarBand::ContextSensitiveHelp(BOOL fEnterMode)
{
	//ATLTRACE("ContextSensitiveHelp():\n");
	ATLTRACENOTIMPL("IOleWindow::ContextSensitiveHelp");
}
/**************************************************************************/
// IDockingWindow Implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::ShowDW(BOOL fShow)
{
	//ATLTRACE("ShowDW():\n");
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
	//ATLTRACE("CloseDW():\n");
	ShowDW(FALSE);
	return S_OK;
}
/**************************************************************************/
// IInputObject Implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::UIActivateIO(BOOL fActivate, LPMSG pMsg)
{
	//ATLTRACE("UIActivateIO():\n");
	if(fActivate)
	{
		SetFocus(m_wndToolBar);
	}
	return S_OK;
}
STDMETHODIMP CKBBarBand::HasFocusIO(void)
{ 
	//ATLTRACE("HasFocusIO():\n");
	HWND hwndFocus = ::GetFocus();
	return S_OK;
}
STDMETHODIMP CKBBarBand::TranslateAcceleratorIO(LPMSG pMsg)
{
	//ATLTRACE("TranslateAcceleratorIO():\n");
	return m_wndToolBar.TranslateAcceleratorIO(pMsg);
}
/**************************************************************************/
// IDeskBand implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::GetBandInfo(DWORD dwBandID, DWORD dwViewMode, DESKBANDINFO* pdbi)
{
//ATLTRACE("GetBandInfo():\n");
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
   //ATLTRACE("Invoke() call\n");
	USES_CONVERSION;//avoiding warnings with respect to ATL DATA_TYPE element
	HWND hwnd=NULL;
	//ATLTRACE(DEBUG_PREFIX "dispidMember: %d\n");
	//loading MSIE elements
	HRESULT hr = webBrowser2->get_HWND((LONG_PTR*)&hwnd);
	//succeed?
	if (SUCCEEDED(hr)) {
		switch(dispidMember) {	
			case DISPID_WINDOWSTATECHANGED : {
				//ATLTRACE("Invoke(): DISPID_WINDOWSTATECHANGED\n");
				if (pDispParams) {
					 DWORD dwMask  = pDispParams->rgvarg[0].lVal;
					 DWORD dwFlags = pDispParams->rgvarg[1].lVal;
				    // We only care about WINDOWSTATE_USERVISIBLE.
					if (dwMask & OLECMDIDF_WINDOWSTATE_USERVISIBLE)
					{
					bool visible = !!(dwFlags & OLECMDIDF_WINDOWSTATE_USERVISIBLE);
					//LoadOptionsFromRegistry();
					LoadOptionsFromFile();
					RefreshIcon2();					
					}
				}
			} break;

			case DISPID_BEFORENAVIGATE2 : {				
				//ATLTRACE("Invoke(): DISPID_BEFORENAVIGATE2\n");
				//ATLASSERT((*pDispParams).rgvarg[5].vt = VT_BYREF | VT_BSTR);
				BSTR BURL = L"";
				HRESULT hrs = webBrowser2->get_LocationURL(&BURL);
				bstrUrlName2 = ((*pDispParams).rgvarg)[5].pvarVal->bstrVal;
				char * predomain2 =_com_util::ConvertBSTRToString(BURL);
				char * temp2= (char*)malloc(2083*sizeof(char));
				//ATLTRACE(predomain2);
				if (strcmp(predomain2,"about:Tabs")==0 || strcmp(predomain2,"about:Blank")==0 || strcmp(predomain2,"about:blank")==0 || strcmp(predomain2,"javascript:false;")==0) 
				{
				ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY1);						
				RefreshIcon2();
				}
				else
				{
				temp2 = UrlToDomain(predomain2);
				//ATLTRACE("\n2");
				//ATLTRACE(temp2);
				//ATLTRACE(urladdr);
				//ATLTRACE("\n2");
					if (strcmp(temp2,urladdr)==0)
					{
						ldicon = state;
						RefreshIcon2();
					}
					else
					{
				    ldicon = GetBitmapIndex(IDI_ICON_KEY_ACTION1);				
					RefreshIcon2();
					}
				}	
			} break;

			case DISPID_NAVIGATECOMPLETE2 : {	
				//ATLTRACE("Invoke(): DISPID_NAVIGATECOMPLETE2\n");				
				BSTR BURL2 = L"";
				HRESULT hrs = webBrowser2->get_LocationURL(&BURL2);
				char * predomain4 =_com_util::ConvertBSTRToString(BURL2);
				char * temp= (char*)malloc(2083*sizeof(char));
				if (strcmp(predomain4,"about:Tabs")==0 || strcmp(predomain4,"about:Blank")==0 || strcmp(predomain4,"about:blank")==0 || strcmp(predomain4,"javascript:false;")==0) 
				{
				ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY1);						
				RefreshIcon2();
				}
				else
				{
				temp = UrlToDomain(predomain4);
					if (strcmp(temp,urladdr)==0)
					{
						ldicon = state;
						RefreshIcon2();
					}
					else
					{
				    bstrUrlName = BURL2; 
					DnssecStatus();
					urladdr = temp;
					state = ldicon;
					}
				}
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
	//ATLTRACE( "RefreshIcon() call\n");
	//MoveWindow(hWndNewPane, 0, 3, StatusBarLenght, ICON_KEY_HEIGHT, TRUE);
	//RedrawWindow(hWndNewPane, NULL, NULL, RDW_UPDATENOW);	
	m_wndToolBar.RepaintButton(BUTTON_INDEX,ldicon);
	//ATLTRACE("RepaintButton():\n");
}

/**************************************************************************/
// CallBack function for ToolBar action - recenty not use
/**************************************************************************/
LRESULT CKBBarBand::WndProc(HWND hWnd, UINT uMessage, WPARAM wParam, LPARAM lParam)
{
	switch (uMessage) 
	{
				case WM_PAINT: {
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
	//ATLTRACE("CreateToolWindow():\n");
	CRect rcClientParent;
	rcClientParent2=rcClientParent;
	CWnd* pWndParent = CWnd::FromHandle(m_hWndParent);
	pWndParent->GetClientRect(&rcClientParent);
	
	// Create ini file if not exists
	CreateIniFile();

	// Load preferences from registry
	//LoadOptionsFromRegistry();

	// Load preferences from ini file
	LoadOptionsFromFile();

	// We need to create a reflection window in between our toolbar control
	if (!m_wndReflectionWnd.CreateEx(NULL, TOOLBARCLASSNAME,"DNSSEC BAR Module",WS_CHILD | WS_CLIPSIBLINGS | WS_BORDER,rcClientParent.left,rcClientParent.top,rcClientParent.right-rcClientParent.left,rcClientParent.bottom-rcClientParent.top,*pWndParent,NULL,0))
	return false;
	// and the rebar in order to get WM_COMMAND messages sent from the toolbar to its
	// parent. 
	if (!m_wndToolBar.Create(rcClientParent, &m_wndReflectionWnd, this, GHins))
	return false;
	// Set toolbar button bitmap size
	if (!SendMessage(m_wndToolBar, TB_SETBITMAPSIZE, 0, MAKELPARAM(ICON_KEY_WIDTH, ICON_KEY_HEIGHT)))
	return false;

	//CreateStatusBarKey();
	
	// Get cuurent version of IE
	iRes = GetMSIEversion(&iMajor,&iMinor);		

	// if IE is 9.xx
	if (iMajor==9) {
		CreateIconTooltip(m_wndToolBar);
		return true;
	}
	// if IE is 7.xx
	if (iMajor==7) {
		CreateIconTooltip(m_wndToolBar);
		return true;
	}
	return true;
}

/**************************************************************************/
// Get IE version
/**************************************************************************/
int CKBBarBand::GetMSIEversion(int *iMajor, int *iMinor)
{
	LONG lResult;
	int iPos,iPos2;
    HKEY hKey;
	DWORD dwSize=100,dwType;
	char szVAL[100],szTemp[5];
	char *pDec,*pDec2;

    // Open the key for query access
	lResult = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    LPCTSTR("SOFTWARE\\Microsoft\\Internet Explorer"),
					0,KEY_QUERY_VALUE,&hKey);

	if(lResult != ERROR_SUCCESS)   // Unable to open Key
	{
		return 644;
	}

    // OK, read the value
	lResult=::RegQueryValueEx(hKey,LPTSTR("Version"),NULL,
			&dwType, LPBYTE(szVAL),&dwSize);

	if(lResult != ERROR_SUCCESS)    // Unable to get value
	{
	  // Close the key before quitting
		lResult=::RegCloseKey(hKey);
	  return 645;
	}

	// Close the key
    lResult=::RegCloseKey(hKey);

	// Extract major version by looking for the first decimal
	pDec=strstr(szVAL,".");
	if(pDec==NULL)
		return 650;         // Unable to decipher version number
	iPos=pDec-szVAL+1;
	ZeroMemory(szTemp,5);
	strncpy_s(szTemp,szVAL,iPos-1);
	*iMajor=atoi(szTemp);

	// Find the Minor version number, look for second decimal
	pDec++;
	pDec2=strstr(pDec,".");
	if(pDec2==NULL)
	{
		*iMinor=0;          // Minor version not found
		return 0;
	}
	iPos2=pDec2-szVAL+1;
	ZeroMemory(szTemp,5);
	strncpy_s(szTemp,pDec,iPos2-iPos-1);
	*iMinor=atoi(szTemp);

	return 0;
}

/**************************************************************************/
// Status bar KEY creator
/**************************************************************************/
bool CKBBarBand::CreateStatusBarKey()
{
//ATLTRACE("CreateStatusBar():\n");
HWND hWndNewPane = CreateWindowEx(
	0,					// no extended styles
	STATUSCLASSNAME,	// name of status bar class
	(LPCTSTR) " ",		// no text when first created
	WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP | SBARS_TOOLTIPS,
	0, 0, 0, 0,			// ignores size and position
	m_wndToolBar,			// handle to parent window
	NULL,				// child window identifier
	GHins,				// handle to application instance
	NULL);	

	//::SetWindowLongPtr(hWndNewPane, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(&WndProc));
	RedrawWindow(hWndNewPane, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
	MoveWindow(hWndNewPane, SBAR_POSITION_LEFT, SBAR_POSITION_TOP, SBAR_POSITION_LENGTH, SBAR_POSITION_HEIGHT, TRUE);

return true;
}

/**************************************************************************/
// Status bar TEXT creator
/**************************************************************************/
bool CKBBarBand::CreateStatusBarText()
{
//ATLTRACE("CreateStatusBar():\n");
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

	//::SetWindowLongPtr(hWndNewPane2, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(&WndProc));
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
   // ATLTRACE("CreateIconTooltip() call\n");	
	// Create a tooltip.
    hwndTT = CreateWindowEx(NULL, TOOLTIPS_CLASS, NULL, 
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
	//ATLTRACE("GetBitmapIndex():\n");
	for (int i=0; i<BITMAP_NUMBER; i++) {
	  if (Bitmap==StatusBitmap[i]) return i;
	}//for
	return 0;
}//

/**************************************************************************/
// Set security status (key bitmap and tooltip text)
/**************************************************************************/
void CKBBarBand::SetSecurityStatus()
{
	//ATLTRACE("SetSecurityStatus():\n");
	// DNSSEC status tooltipinfo
	WORD tiicon = TTI_NONE;		// icon in tooltipinfo
	WORD tiicontitle = IDS_NONE;// main title of tooltipinfo
	WORD tipref = IDS_NONE;		// prefix
	WORD tistatus = IDS_NONE;	// DNSSEC status
	WORD titext = IDS_NONE;     // DNSSEC status text
	
	// switch of DNSSEC status - bitmap, tooltip info
	switch (result) {
	// state 0
	case NPAPI_EXIT_CONNECTION_DOMAIN_SECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREEN1);
		ldiconBar = IDI_ICON_KEY_GREEN;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE0_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE0_TEXT_DOMAIN;
		titext = IDS_STATE0_TEXT_MAIN;
 		break;

   // state 1
	case NPAPI_EXIT_CONNECTION_NODOMAIN_SECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREEN1);
		ldiconBar = IDI_ICON_KEY_GREEN;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE1_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_FAIL;
		tistatus = IDS_STATE1_TEXT_DOMAIN;
		titext = IDS_STATE1_TEXT_MAIN;
 		break;

    // state 2
	case NPAPI_EXIT_CONNECTION_INVSIGDOMAIN_SECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE2_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE2_TEXT_DOMAIN;
		titext = IDS_STATE2_TEXT_MAIN;
 		break;

    // state 3
	case NPAPI_EXIT_DOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_STATE3_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE3_TEXT_DOMAIN;
		titext = IDS_STATE3_TEXT_MAIN;
 		break;

    // state 4
	case NPAPI_EXIT_AUTH_DOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_STATE4_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE4_TEXT_DOMAIN;
		titext = IDS_STATE4_TEXT_MAIN;
 		break;

    // state 5
	case NPAPI_EXIT_DOMAIN_SIGNATURE_INVALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE5_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE5_TEXT_DOMAIN;
		titext = IDS_STATE5_TEXT_MAIN;
 		break;

    // state 6
	case NPAPI_EXIT_NODOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_STATE6_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE6_TEXT_DOMAIN;
		titext = IDS_STATE6_TEXT_MAIN;
 		break;
    
	// state 7
	case NPAPI_EXIT_AUTH_NODOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_ORANGE1);
		ldiconBar = IDI_ICON_KEY_ORANGE;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_STATE7_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE7_TEXT_DOMAIN;
		titext = IDS_STATE7_TEXT_MAIN;
 		break;

    // state 8
	case NPAPI_EXIT_NODOMAIN_SIGNATURE_INVALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE8_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE8_TEXT_DOMAIN;
		titext = IDS_STATE8_TEXT_MAIN;
 		break;

	// state 9
	case NPAPI_EXIT_DOMAIN_UNSECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_RC1);
		ldiconBar = IDI_ICON_KEY_GREY_RC;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE9_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_STATE9_TEXT_DOMAIN;
		titext = IDS_STATE9_TEXT_MAIN;
 		break;
    
	// state 9
	case NPAPI_EXIT_NODOMAIN_UNSECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_RC1);
		ldiconBar = IDI_ICON_KEY_GREY_RC;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_STATE9_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_FAIL;
		tistatus = IDS_STATE9_TEXT_DOMAIN;
		titext = IDS_STATE9_TEXT_MAIN;
 		break;
    
	// other states
	case NPAPI_EXIT_UNKNOWN:
    case NPAPI_EXIT_FAILED:
    default:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_YT1);
		ldiconBar = IDI_ICON_KEY_GREY_YT;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_DNSSEC_ERROR_LABEL;
		tipref = IDS_PRE_TEXT_OK;
		tistatus = IDS_DNSSEC_ERROR_LABEL;
		titext = IDS_DNSSEC_ERROR_FAIL;
		break;
	}// switch
	
	char tmpbuf[STR_BUF_SIZE];
	char tibuf[STR_BUF_SIZE*4] = TEXT(""); // buffer to store tooltip string

	LoadStringA(GHins, tipref, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT("\n"), 1);
	
	/*char *Pre;
	Pre = tmpbuf;
	char * PreText;
	PreText = (char *)malloc(strlen(Pre));
	strcpy(PreText,Pre);
	*/
	strncat_s(tibuf, domain, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT("\n"), 1);
	LoadStringA(GHins, tistatus, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT("\n\n"), 2);

	/*
	char *Post;
	Post = tmpbuf;
	char * PostText;
	PostText = (char *)malloc(strlen(Post));
	strcpy(PostText,Post);
	char *Final;
	Final = (char *)malloc(strlen(PreText) + strlen(" ") + strlen(domain) + strlen(" ") + strlen(PostText));
	strcpy(Final,PreText);
	strcat(Final," ");
	strcat(Final,domain);
	strcat(Final," ");
	strcat(Final,PostText);
	int len = strlen(Final)+1;
	wchar_t *wText = new wchar_t[len];
	memset(wText,0,len);
	::MultiByteToWideChar(  CP_ACP, NULL, Final, -1, wText,len );
	DNSSECtext2 = wText;
	*/


	//ATLTRACE(DNSSECtext2);
	//ATLTRACE("\n");
	LoadStringA(GHins, titext, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
    LoadStringA(GHins, tiicontitle, tmpbuf, STR_BUF_SIZE);
	
	ti.lpszText = tibuf;
	RefreshIcon2();

	SendMessage(hwndTT, TTM_SETTITLE, tiicon, (LPARAM) tmpbuf);
	SendMessage(hwndTT, TTM_UPDATETIPTEXT, 0, (LPARAM) (LPTOOLINFO) &ti);
}//

/**************************************************************************/
// It displays DNSSEC status function
/**************************************************************************/
void CKBBarBand::DnssecStatus(void)
{
	//ATLTRACE("displaydnssecstatus() call\n");

	//the next lines allow to the plugin to cast the URL name to
	//a "standard readable" string char*
	//but now in the case of the domain name
	domain = (char*)malloc(2083*sizeof(char));
	predomain= (char*)malloc(2083*sizeof(char));
	predomain=_com_util::ConvertBSTRToString(bstrUrlName);
	//ATLTRACE(predomain);
	//ATLTRACE("\n");
	//error URL
	static char pattern[]="res://ieframe.dll/dnserrordiagoff.htm#";
	char *errordomain=NULL;
	errordomain=(char*)malloc(2083*sizeof(char));
	strcpy_s(errordomain,2083,predomain);

	//this element will allocate the list of DNS primary servers
	char **prevDNSlist;
	prevDNSlist=(char**)malloc(200*sizeof(char));

	//output status has changed , special cases
	if (strcmp(predomain,"about:Tabs")==0 || strcmp(predomain,"about:Blank")==0 || strcmp(predomain,"about:blank")==0) {
	ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY1);						
	RefreshIcon2();
	}else{
		//default FAIL URL 
		if (strcmp(predomain,"res://ieframe.dll/dnserrordiagoff.htm")!=0) { //current navigation
			char *isstring=NULL;
			isstring=(char*)malloc(2083*sizeof(char));
			isstring=strstr(errordomain,pattern);
			// here the current domain is verified
			if (isstring==NULL){
			CheckDomainStatus();
			}
		}
	}
}

/**************************************************************************/
// It checks whether a domain is a DNSSEC domain
/**************************************************************************/
void CKBBarBand::CheckDomainStatus(void) 
{   
	//ATLTRACE("checkdomainstatus() call\n");
    
	// if IE is version 8.xx, create tooltip	
	if (iMajor==8) {
		if (!tiInitialized1) {
			CreateIconTooltip(m_wndToolBar);
			tiInitialized1 = true;
		}
	}
	// if IE is version 6.xx, create tooltip	
	if (iMajor==6) {
		if (!tiInitialized1) {
			CreateIconTooltip(m_wndToolBar);
			tiInitialized1 = true;
		}
	}
	
	//temporal element that helps to fragment the given URL in a domain
	char* tmpdomain = NULL;
	tmpdomain= (char*)malloc(2083*sizeof(char));
	tmpdomain=UrlToDomain(predomain);
	strcpy_s(domain,2048,tmpdomain);	
	
	char* dnsip; 
	LoadOptionsFromFile();
	if (choice==2) dnsip = dnssecseradr;
	else if (choice==1) if (choice2==0) dnsip = nic; else dnsip = oarc;
	else dnsip = NULL;
	
	bool resolvipv4 = true;
	bool resolvipv6 = false;

	uint16_t options = 0;
	if (debugoutput) options |= NPAPI_INPUT_FLAG_DEBUGOUTPUT;
	if (tcpudp) options |= NPAPI_INPUT_FLAG_USETCP;
	if (resolvipv4) options |= NPAPI_INPUT_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= NPAPI_INPUT_FLAG_RESOLVIPV6;

	// Request ownership of the critical section
	EnterCriticalSection(&cs);
	//char str[100] = "\0";
	char *tmpptr = NULL;
	uint32_t ttl4, ttl6 = 0;
	//ATLTRACE("Critical section begin\n");
	result = ds_validate(domain, options, dnsip, &tmpptr, &ttl4, &ttl6);
	/*char c1[100];
	char c2[100];
	char* strttl4;
	char* strttl6;
	_itoa_s(ttl4,c1,10);
	strttl4 = c1;
	_itoa_s(ttl6,c2,10);
	strttl6 = c2;
	ATLTRACE("\n");
	ATLTRACE(tmpptr);
	ATLTRACE(" ");
	ATLTRACE(strttl4);
	ATLTRACE(" ");
	ATLTRACE(strttl6);
	ATLTRACE("\n");

	*/
	
	ds_free_resaddrsbuf();
	LeaveCriticalSection(&cs);


	//ATLTRACE("Critical section begin\n");
	//ATLTRACE("Critical section begin\n");

	SetSecurityStatus();
}

/**************************************************************************/
//to convert URL string on domain name, removed http:\\ 
/**************************************************************************/
char* CKBBarBand::UrlToDomain(char *url) 
{
	//ATLTRACE("UrlToDomain() call\n");
	//static char instead of char
	static char separator[]   = "://";
	char *domainname=NULL;
	char *next_token=NULL;
	//to store current domain name
	domainname=(char*)malloc(2083*sizeof(char));
	next_token=(char*)malloc(2083*sizeof(char));
	//checking whether there is an available URL element
	if (strcmp(url,"")==0){
		return "about:blank";
	}
	else {
		domainname = strtok_s(url, separator, &next_token);
		domainname = strtok_s(NULL,separator, &next_token);
		return domainname;
	}
}

/**************************************************************************/
// Load settings from the Windows registry
/**************************************************************************/
void CKBBarBand::LoadOptionsFromRegistry(void) {
	
	//ATLTRACE("LoadOptionsFromRegistry() call\n");	

	DWORD dwRet;
	HKEY hKey;
	LPTSTR szVal;
	DWORD dwVal;
	HRESULT hr;
	// open DNSSEC Validator registry key if exists
	dwRet = RegOpenKeyEx(HKEY_USERS, HKU_REG_KEY, 0, KEY_QUERY_VALUE, &hKey);
	if (dwRet == ERROR_SUCCESS) {

		//ATLTRACE("LoadOptionsFromRegistry() - ERROR_SUCCESS\n");

		// Get the registry values...
		hr = RegGetString(hKey,"userip", &szVal);
		if (FAILED(hr)) return;
		//else dnssecseradr=szVal;

		// Get the registry values...
		hr = RegGetString(hKey,"nicip", &szVal);
		if (FAILED(hr)) return;
		else nic=(char*)szVal;

		// Get the registry values...
		hr = RegGetString(hKey,"oarcip", &szVal);
		if (FAILED(hr)) return;
		else oarc=(char*)szVal;

		// Get the registry values...
		hr = RegGetDWord(hKey,"choice", &dwVal);
		if (FAILED(hr)) return;
		else if (dwVal==0x00000000) choice = 0;
		else if (dwVal==0x00000001) choice = 1;
		else choice = 2;

		// Get the registry values...
		hr = RegGetDWord(hKey,"keytext", &dwVal);
		if (FAILED(hr)) return;
		else if (dwVal==0x00000001) textkey = 1;
		else textkey = 0;

		// Get the registry values...
		hr = RegGetDWord(hKey,"tcpudp", &dwVal);
		if (FAILED(hr)) return;
		else if (dwVal==0x00000001) tcpudp = 1;
		else tcpudp = 0;

		// Get the registry values...
		hr = RegGetDWord(hKey,"choicedns", &dwVal);
		if (FAILED(hr)) return;
		else if (dwVal==0x00000001) choice2 = 1;
		else choice2 = 0;

		// Get the registry values...
		hr = RegGetDWord(hKey,"debugoutput", &dwVal);
		if (FAILED(hr)) return;
		else if (dwVal==0x00000001) debugoutput = 1;
		else debugoutput = 0;

		RegCloseKey(hKey);

	} else {
		//ATLTRACE("Cannot open DNSSEC Validator's registry key\n");
	}
}

/**************************************************************************/
// Get string from Windows registry
/**************************************************************************/
HRESULT CKBBarBand::RegGetString(HKEY hKey, LPCTSTR szValueName, LPTSTR * lpszResult) {
 
    // Given a HKEY and value name returns a string from the registry.
    // Upon successful return the string should be freed using free()
    // eg. RegGetString(hKey, TEXT("my value"), &szString);
 
    DWORD dwType=1, dwDataSize=0, dwBufSize=0;
    LONG lResult;
 
    // Incase we fail set the return string to null...
    if (lpszResult != NULL) *lpszResult = NULL;	
    // Check input parameters...
    if (hKey == NULL || lpszResult == NULL) return E_INVALIDARG;
    // Get the length of the string in bytes (placed in dwDataSize)...
    lResult = RegQueryValueEx(hKey, szValueName, 0, &dwType, NULL, &dwDataSize );
    // Check result and make sure the registry value is a string(REG_SZ)...
    if (lResult != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lResult);
    else if (dwType != REG_SZ)    return DISP_E_TYPEMISMATCH;
    // Allocate memory for string - We add space for a null terminating character...
    dwBufSize = dwDataSize + (1 * sizeof(TCHAR));
    *lpszResult = (CHAR *)malloc(dwBufSize);
    if (*lpszResult == NULL) return E_OUTOFMEMORY;
    // Now get the actual string from the registry...
    lResult = RegQueryValueEx(hKey, szValueName, 0, &dwType, (LPBYTE) *lpszResult, &dwDataSize );
    // Check result and type again.
    // If we fail here we must free the memory we allocated...
    if (lResult != ERROR_SUCCESS) { free(*lpszResult); return HRESULT_FROM_WIN32(lResult); }
    else if (dwType != REG_SZ)    { free(*lpszResult); return DISP_E_TYPEMISMATCH; }
    // We are not guaranteed a null terminated string from RegQueryValueEx.
    // Explicitly null terminate the returned string...
    (*lpszResult)[(dwBufSize / sizeof(TCHAR)) - 1] = TEXT('\0');
 
    return NOERROR;
}
 
/**************************************************************************/
// Get DWORD value from Windows registry
/**************************************************************************/
HRESULT CKBBarBand::RegGetDWord(HKEY hKey, LPCTSTR szValueName, DWORD * lpdwResult) {
    // Given a value name and an hKey returns a DWORD from the registry.
    // eg. RegGetDWord(hKey, TEXT("my dword"), &dwMyValue);
    LONG lResult;
    DWORD dwDataSize = sizeof(DWORD);
    DWORD dwType = 0;
 
    // Check input parameters...
    if (hKey == NULL || lpdwResult == NULL) return E_INVALIDARG;
 
    // Get dword value from the registry...
    lResult = RegQueryValueEx(hKey, szValueName, 0, &dwType, (LPBYTE) lpdwResult, &dwDataSize );
 
    // Check result and make sure the registry value is a DWORD(REG_DWORD)...
    if (lResult != ERROR_SUCCESS) return HRESULT_FROM_WIN32(lResult);
    else if (dwType != REG_DWORD) return DISP_E_TYPEMISMATCH;
 
    return NOERROR;
}

/**************************************************************************/
// loads preference settings from the ini file
/**************************************************************************/
void CKBBarBand::LoadOptionsFromFile(void) {

	//ATLTRACE("\nLoadOptionsFromFile\n");
	TCHAR szPath[MAX_PATH];
	char dbserver[IPADDR_MLEN];
	dbserver[0]='\0';
	if (SUCCEEDED( SHGetFolderPath( NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath ))){
		PathAppend( szPath, INI_FILE_PATH);
		GetPrivateProfileString("DNSSEC", "userip", "127.0.0.1", dbserver, IPADDR_MLEN, szPath);
		memcpy(dnssecseradr, dbserver, IPADDR_MLEN);

		textkey = GetPrivateProfileInt("DNSSEC", "keytext", 0 , szPath);
		//if (textkey) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");

		choice = GetPrivateProfileInt("DNSSEC", "choice", 0 , szPath);
		//if (choice) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");

		choice2 = GetPrivateProfileInt("DNSSEC", "choicedns", 0 , szPath);
		//if (choice2) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");

		tcpudp = GetPrivateProfileInt("DNSSEC", "tcpudp", 0 , szPath);
		//if (tcpudp) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");
	
		debugoutput = GetPrivateProfileInt("DNSSEC", "debugoutput", 0 , szPath);
		//if (debugoutput) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");
	}// if SHGetFolderPath
}

/**************************************************************************/
// Create INI file if not exists 
/**************************************************************************/
void CKBBarBand::CreateIniFile()
{
   TCHAR szPath[MAX_PATH];
   // Get path for each computer, non-user specific and non-roaming data.
   if ( SUCCEEDED( SHGetFolderPath( NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath )))
   {
   
	   PathAppend( szPath, INI_FILE_PATH);
	   
	   if (!FileExists(szPath)) 
			{
			SHGetFolderPath( NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath );
			// Append product-specific path - this path needs to already exist
			// for GetTempFileName to succeed.
			PathAppend( szPath, _T("\\CZ.NIC") );
			CreateDirectory(szPath,NULL);
			PathAppend( szPath, _T("\\DNSSEC Validator") );
			CreateDirectory(szPath,NULL);
			PathAppend( szPath, _T("\\1.0") );
			CreateDirectory(szPath,NULL);
			// Generate a temporary file name within this folder.
	  	  	PathAppend( szPath, _T("\\dnssec.ini") );
			
			HANDLE hFile = NULL;
			  
			DWORD dwBytesToWrite = (DWORD)strlen(DefaultIniData);
			DWORD dwBytesWritten = 0;
			BOOL bErrorFlag = FALSE;
			// Open the file.
			if (( hFile = CreateFile( szPath, GENERIC_READ|GENERIC_WRITE, 0,NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL )) != INVALID_HANDLE_VALUE )
			{
            // Write temporary data (code omitted).
			   bErrorFlag = WriteFile( 
                    hFile,           // open file handle
                    DefaultIniData,      // start of data to write
                    dwBytesToWrite,  // number of bytes to write
                    &dwBytesWritten, // number of bytes that were written
                    NULL);            // no overlapped structure
			 CloseHandle( hFile );
			}//if
		}//if
	}//if
}

/**************************************************************************/
// Return TRUE if file 'fileName' exists
/**************************************************************************/
bool CKBBarBand::FileExists(const TCHAR *fileName)
{
    DWORD  fileAttr;
    fileAttr = GetFileAttributes(fileName);
    if (0xFFFFFFFF == fileAttr)
        return false;
    return true;
}