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

#include <windows.h>  /* for shared memory */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h> /* for IP Helper API */
#include <winreg.h>

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
short usedfwd = TCPUDP;
short debugoutput = DEBUGVAL;
short debugoutput_enable = DEBUGVAL_ENABLE;
short cache_enable = CACHE;
short ipv4 = IPv4;
short ipv6 = IPv6;
short ipv46 = IPv4;
short ipresult = 0;
short res;
char*  ipbrowser4;
char*  ipbrowser6;
char ipvalidator4[256];
char*  ipvalidator6;
// global state info
WORD paneltitle  = 0;
WORD panelpredonain  = 0;
char* paneldomainname  = 0;
WORD panelpostdomain  = 0;
WORD paneltext  = 0;
short paneltextip  = 1;
WORD keylogo  = 0;
WORD keylogo2  = 0;
int err = 0;
// key state memory
int state;
// url address memory
char * urladdr = " ";
// variable for IE version check
int iRes,iMajor=0,iMinor=0;
 // key icon dimension
int ICON_KEY_WIDTH = 16;
int ICON_KEY_HEIGHT = 16;
int SBAR_POSITION_LEFT = 47;
int SBAR_POSITION_TOP = 10;
int SBAR_POSITION_LENGTH = 620;
int SBAR_POSITION_HEIGHT = 14;
short ipcmpresults = -1;
// ctritical section for resolver
CRITICAL_SECTION CKBBarBand::cs;
// for tooltip creation
bool CKBBarBand::csInitialized = false;
bool csInitialized = false;
char DefaultIniData[] = "[DNSSEC]\nkeytext=0\nchoice=0\nchoicedns=0\nuserip=8.8.8.8"; 
char str[INET6_ADDRSTRLEN];

typedef struct {   /* structure to save IPv4/IPv6 address from stub resolver */
  char* ipv4;
  char* ipv6;
} ip64struct;
ip64struct ip64buf;


/**************************************************************************/
// inet_ntop function for win32
/**************************************************************************/
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
        if (af == AF_INET)
        {
                struct sockaddr_in in;
                memset(&in, 0, sizeof(in));
                in.sin_family = AF_INET;
                memcpy(&in.sin_addr, src, sizeof(struct in_addr));
                getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in), dst, cnt, NULL, 0, NI_NUMERICHOST);
                return dst;
        }
        else if (af == AF_INET6)
        {
                struct sockaddr_in6 in;
                memset(&in, 0, sizeof(in));
                in.sin6_family = AF_INET6;
                memcpy(&in.sin6_addr, src, sizeof(struct in_addr6));
                getnameinfo((struct sockaddr *)&in, sizeof(struct sockaddr_in6), dst, cnt, NULL, 0, NI_NUMERICHOST);
                return dst;
        }
        return NULL;
}


/**************************************************************************/
// get IPv4/IPv6 address from stub resolver for windows
/**************************************************************************/
ip64struct stub_resolve(const char *domain)
{
    DWORD dwRetval;   
    char retval4[1024];
    char retval6[1024];
    char* IPv4x = " ";
	WSADATA wsaData;

    ip64buf.ipv4 = retval4;
    ip64buf.ipv6 = retval6;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
    return ip64buf;
    }                          


    struct addrinfo *result = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints;
    struct sockaddr_in  *sockaddr_ipv4;
    struct sockaddr_in6 *sockaddr_ipv6;
    const char *  IPv6x;
     
    // Setup the hints address info structure
    // which is passed to the getaddrinfo() function
    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_INET6;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_socktype = SOCK_DGRAM;

    // Call getaddrinfo(). If the call succeeds,
    // the result variable will hold a linked list
    // of addrinfo structures containing response
    // information
    dwRetval = getaddrinfo(domain, NULL, &hints, &result);
       
    // Retrieve each address and print out the hex bytes
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {
        switch (ptr->ai_family) {
            case AF_INET:
                sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
                IPv4x = inet_ntoa(sockaddr_ipv4->sin_addr);
                //retval4 = strcat_s(retval4,1024,IPv4x);
                //retval4 = strcat_s(retval4,"|");                                
                break;
            case AF_INET6:
        		sockaddr_ipv6 = (struct sockaddr_in6 *) ptr->ai_addr;
				IPv6x = inet_ntop(AF_INET6, &sockaddr_ipv6->sin6_addr,str, INET6_ADDRSTRLEN);                              
                //retval6 = strcat_s (retval6,str);
                //retval6 = strcat_s (retval6,"|");
                break;
            default: break;
        }
    }

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_socktype = SOCK_DGRAM;

    // Call getaddrinfo(). If the call succeeds,
    // the result variable will hold a linked list
    // of addrinfo structures containing response
    // information
    dwRetval = getaddrinfo(domain, NULL, &hints, &result);
       
    // Retrieve each address and print out the hex bytes
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {
        switch (ptr->ai_family) {
            case AF_INET:
                sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
                IPv4x = inet_ntoa(sockaddr_ipv4->sin_addr);
                //retval4 = strcat_s(retval4,1024,IPv4x);
                //retval4 = strcat_s(retval4,"|");                                
                break;
            case AF_INET6:
        		sockaddr_ipv6 = (struct sockaddr_in6 *) ptr->ai_addr;
				IPv6x = inet_ntop(AF_INET6, &sockaddr_ipv6->sin6_addr,str, INET6_ADDRSTRLEN);                              
                //retval6 = strcat_s (retval6,str);
                //retval6 = strcat_s (retval6,"|");
                break;
            default: break;
        }
    }

    ip64buf.ipv4 = IPv4x;
    ip64buf.ipv6 = str;
    freeaddrinfo(result);
    WSACleanup();
    return ip64buf;
}


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
		case DISPID_WINDOWCLOSING : { ATLTRACE("Invoke(): DISPID_WINDOWCLOSING\n");} break;

			case DISPID_WINDOWSTATECHANGED : {
				ATLTRACE("Invoke(): DISPID_WINDOWSTATECHANGED\n");
				if (pDispParams) {
					 DWORD dwMask  = pDispParams->rgvarg[0].lVal;
					 DWORD dwFlags = pDispParams->rgvarg[1].lVal;
				    // We only care about WINDOWSTATE_USERVISIBLE.
					if (dwMask & OLECMDIDF_WINDOWSTATE_USERVISIBLE)
					{
					bool visible = !!(dwFlags & OLECMDIDF_WINDOWSTATE_USERVISIBLE);
					//LoadOptionsFromRegistry();
					LoadOptionsFromFile();
				BSTR BURL2 = L"";
				HRESULT hrs = webBrowser2->get_LocationURL(&BURL2);
				char * predomain4 =_com_util::ConvertBSTRToString(BURL2);
				char * temp= (char*)malloc(2083*sizeof(char));
				if (strcmp(predomain4,"about:Tabs")==0 || strcmp(predomain4,"about:Blank")==0 || strcmp(predomain4,"about:blank")==0 || strcmp(predomain4,"javascript:false;")==0) 
				{
				ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY1);						
				keylogo=ldicon;
				RefreshIcon2();
				
				}
				else
				{
	
				    bstrUrlName = BURL2; 
					DnssecStatus(1);					
					state = ldicon;
					keylogo=ldicon;
				}
	
					}
				}
			} break;

			case DISPID_BEFORENAVIGATE2 : {				
				ATLTRACE("Invoke(): DISPID_BEFORENAVIGATE2\n");
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
				keylogo=ldicon;
				}
				else
				{
				/*temp2 = UrlToDomain(predomain2);
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
					{*/
				    ldicon = state;
					keylogo=ldicon;
					//ldicon = GetBitmapIndex(IDI_ICON_KEY_ACTION1);				
					RefreshIcon2();
					/*}*/
				}	
			} break;

			case DISPID_NAVIGATECOMPLETE2 : {	
				ATLTRACE("Invoke(): DISPID_NAVIGATECOMPLETE2\n");				
				BSTR BURL2 = L"";
				HRESULT hrs = webBrowser2->get_LocationURL(&BURL2);
				char * predomain4 =_com_util::ConvertBSTRToString(BURL2);
				char * temp= (char*)malloc(2083*sizeof(char));
				if (strcmp(predomain4,"about:Tabs")==0 || strcmp(predomain4,"about:Blank")==0 || strcmp(predomain4,"about:blank")==0 || strcmp(predomain4,"javascript:false;")==0) 
				{
				ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY1);						
				keylogo=ldicon;
				RefreshIcon2();
				
				}
				else
				{
				/*temp = UrlToDomain(predomain4);
					if (strcmp(temp,urladdr)==0)
					{
						ldicon = state;
						RefreshIcon2();
					}
					else
					{
					*/
				    bstrUrlName = BURL2; 
					DnssecStatus(1);
					//urladdr = temp;
					state = ldicon;
					keylogo=ldicon;
					/*}*/
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
	m_wndToolBar.RepaintButton(BUTTON_INDEX,ldicon);
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
	//if (!SendMessage(m_wndToolBar, TB_SETBITMAPSIZE, 0, MAKELPARAM(ICON_KEY_WIDTH, ICON_KEY_HEIGHT)))
	//return false;

	//CreateStatusBarKey();
	
	// Get cuurent version of IE
	iRes = GetMSIEversion(&iMajor,&iMinor);		
	/*
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
	*/
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

	// state 1
	case DNSSEC_EXIT_DOMAIN_UNSECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_RC1);
		ldiconBar = IDI_ICON_KEY_GREY_RC;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE1_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE1_TEXT_DOMAIN;
		titext = IDS_STATE1_TEXT_MAIN;
 		break;
		
	// state 2
	case DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREEN1);
		ldiconBar = IDI_ICON_KEY_GREEN;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE2_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE2_TEXT_DOMAIN;
		titext = IDS_STATE2_TEXT_MAIN;
 		break;

	// state 3
	case DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED_IP1);
		ldiconBar = IDI_ICON_KEY_REDIP;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE3_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE3_TEXT_DOMAIN;
		titext = IDS_STATE3_TEXT_MAIN;
 		break;

	// state 4
	case DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE4_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE4_TEXT_DOMAIN;
		titext = IDS_STATE4_TEXT_MAIN;
 		break;

	// state 5
	case DNSSEC_EXIT_NODOMAIN_UNSECURED:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_RC1);
		ldiconBar = IDI_ICON_KEY_GREY_RC;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_STATE5_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_NODOMAIN;
		tistatus = IDS_STATE5_TEXT_DOMAIN;
		titext = IDS_STATE5_TEXT_MAIN;
 		break;

   // state 6
	case DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREEN1);
		ldiconBar = IDI_ICON_KEY_GREEN;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE6_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_NODOMAIN;
		tistatus = IDS_STATE6_TEXT_DOMAIN;
		titext = IDS_STATE6_TEXT_MAIN;
 		break;

    // state 7
	case DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_RED1);
		ldiconBar = IDI_ICON_KEY_RED;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE7_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_NODOMAIN;
		tistatus = IDS_STATE7_TEXT_DOMAIN;
		titext = IDS_STATE7_TEXT_MAIN;
 		break;
   
	// other states
    case DNSSEC_EXIT_FAILED:
    default:
		ldicon = GetBitmapIndex(IDI_ICON_KEY_GREY_YT1);
		ldiconBar = IDI_ICON_KEY_GREY_YT;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE0_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_ERROR;
		tistatus = IDS_STATE0_TEXT_DOMAIN;
		titext = IDS_STATE0_TEXT_MAIN;
		break;
	}// switch
	err = ldicon;
	keylogo2 = ldiconBar;
	paneltitle  = tiicontitle;
	panelpredonain  = tipref;
	paneldomainname = domain;
	panelpostdomain  = tistatus;
	paneltext  = titext;
	paneltextip = ipresult;
	RefreshIcon2();
	res=result;
	/*
	char tmpbuf[STR_BUF_SIZE] = TEXT("");
	char tibuf[STR_BUF_SIZE*4] = TEXT(""); // buffer to store tooltip string

	LoadStringA(GHins, tipref, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT("\n"), 1);
	strncat_s(tibuf, domain, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT("\n"), 1);
	LoadStringA(GHins, tistatus, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, TEXT("\n\n"), 2);
	LoadStringA(GHins, titext, tmpbuf, STR_BUF_SIZE);
	strncat_s(tibuf, tmpbuf, STR_BUF_SIZE);
    LoadStringA(GHins, tiicontitle, tmpbuf, STR_BUF_SIZE);

	ti.lpszText = tibuf;
	RefreshIcon2();

	SendMessage(hwndTT, TTM_SETTITLE, tiicon, (LPARAM) tmpbuf);
	SendMessage(hwndTT, TTM_UPDATETIPTEXT, 0, (LPARAM) (LPTOOLINFO) &ti);
	*/
}//

/**************************************************************************/
// It displays DNSSEC status function
/**************************************************************************/
void CKBBarBand::DnssecStatus(short change)
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
			CheckDomainStatus(change);
			}
		}
	}
}

/**************************************************************************/
// It checks whether a domain is a DNSSEC domain
/**************************************************************************/
void CKBBarBand::CheckDomainStatus(short change) 
{   
	//ATLTRACE("checkdomainstatus() call\n");
    
	// if IE is version 8.xx, create tooltip	
	/*
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
	*/
	//temporal element that helps to fragment the given URL in a domain
	char* tmpdomain = NULL;
	bool resolvipv4 = true;
	bool resolvipv6 = true;
	bool cache_en = true;
	bool cache_flush = false;
	uint16_t options = 0;
	debugoutput = true; 
	short resultipv4 = 0; //the DNSSEC validation result
	short resultipv6 = 0; //the DNSSEC validation result	
	tmpdomain= (char*)malloc(2083*sizeof(char));
	tmpdomain=UrlToDomain(predomain);
	strcpy_s(domain,2048,tmpdomain);	
	//if (change==1) {
		if (strcmp(domain,"about:blank")==0) {
		//ATLTRACE("xxxxxxxxxxxxxxxxxxxxxxxxxxxx\n");
	}
	else {

	char* dnsip; 
	LoadOptionsFromFile();
	usedfwd = true;
	if (choice==2) dnsip = dnssecseradr;
	else if (choice==1) if (choice2==0) dnsip = nic; else dnsip = oarc;
	else if (choice==3) {dnsip = "nofwd"; usedfwd = false;}
	else dnsip = "";

	ip64struct ipv64;
	ipv64=stub_resolve(domain);

	ipbrowser4=ipv64.ipv4;
	resolvipv4 = true; 
	resolvipv6 = false; 
	if (debugoutput) options |= DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
	if (usedfwd) options |= DNSSEC_INPUT_FLAG_USEFWD;
	if (resolvipv4) options |= DNSSEC_INPUT_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= DNSSEC_INPUT_FLAG_RESOLVIPV6;
	if (change==1) {
	char* ipvalidator4tmp;
	EnterCriticalSection(&cs);
	//ATLTRACE("Critical section begin\n");
	ATLTRACE("\nIPv4: %s : %d : %s : %s\n", domain, options, dnsip, ipbrowser4);
	resultipv4 = ds_validate(domain, options, dnsip, ipbrowser4, &ipvalidator4tmp);
	ATLTRACE("IPv4: %s : %d : %s\n", domain, resultipv4, ipvalidator4); 
	LeaveCriticalSection(&cs);
	strcpy_s(ipvalidator4, ipvalidator4tmp);
	}

	ipbrowser6=ipv64.ipv6;
	resolvipv4 = false; 
	resolvipv6 = true;
	options = 0;
	if (debugoutput) options |= DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
	if (usedfwd) options |= DNSSEC_INPUT_FLAG_USEFWD;
	if (resolvipv4) options |= DNSSEC_INPUT_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= DNSSEC_INPUT_FLAG_RESOLVIPV6;
	// Request ownership of the critical section
	if (change==1) {
	EnterCriticalSection(&cs);
	//ATLTRACE("Critical section begin\n");
	ATLTRACE("\nIPv6: %s : %d : %s : %s\n", domain, options, dnsip, ipbrowser6);
	resultipv6 = ds_validate(domain, options, dnsip, ipbrowser6, &ipvalidator6);
	ATLTRACE("IPv6: %s : %d : %s\n", domain, resultipv6, ipvalidator6); 
	LeaveCriticalSection(&cs);
	}		
	(resultipv4 <= resultipv6 ?  result = resultipv6 : result = resultipv4);	
	SetSecurityStatus();
	}
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
		else if (dwVal==0x00000002) choice = 2;
		else choice = 3;

		// Get the registry values...
		hr = RegGetDWord(hKey,"keytext", &dwVal);
		if (FAILED(hr)) return;
		else if (dwVal==0x00000001) textkey = 1;
		else textkey = 0;

		// Get the registry values...
		hr = RegGetDWord(hKey,"tcpudp", &dwVal);
		if (FAILED(hr)) return;
		else if (dwVal==0x00000001) usedfwd = 1;
		else usedfwd = 0;

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
		GetPrivateProfileString("DNSSEC", "userip", "8.8.8.8", dbserver, IPADDR_MLEN, szPath);
		memcpy(dnssecseradr, dbserver, IPADDR_MLEN);

		textkey = GetPrivateProfileInt("DNSSEC", "keytext", 0 , szPath);
		//if (textkey) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");

		choice = GetPrivateProfileInt("DNSSEC", "choice", 0 , szPath);
		//if (choice) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");

		choice2 = GetPrivateProfileInt("DNSSEC", "choicedns", 0 , szPath);
		//if (choice2) ATLTRACE("\n1\n"); else ATLTRACE("\n0\n");
	
		debugoutput = GetPrivateProfileInt("DNSSEC", "debugoutput", 0 , szPath);
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
			PathAppend( szPath, _T("\\DNSSEC Validator 2.0") );
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