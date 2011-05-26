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

// DNSSECValidatorBHO.cpp : Implementation of CDNSSECValidatorBHO
#include "stdafx.h"
#include "DNSSECValidatorBHO.h"

// standard libraries
#include <string.h>

//String2BSTR conversion
#include <comutil.h>

//loading the global HINSTANCE from dllmain.cpp, it is important because it allows to load things such as MENU or 
//state-icons
extern HINSTANCE GHins;

WNDPROC CDNSSECValidatorBHO::WProcStatus=NULL; //WNDPROC status
bool CDNSSECValidatorBHO::WarnBlockAid=true; //at the begining, all domain elements can be navigated
WORD CDNSSECValidatorBHO::statldicon=IDI_ICON_KEY_GREY;// default icon status color, GRAY
int CDNSSECValidatorBHO::position=0; //default position

#define DEBUG_PREFIX "dnssec: "
#define DSV_REG_KEY L"SOFTWARE\\CZ.NIC\\DNSSEC Validator"

// key icon dimensions
#define ICON_KEY_WIDTH  39
#define ICON_KEY_HEIGHT 19

//SetSite: this function initializes the BHO object to extract and connect with the MSIE architecture
STDMETHODIMP CDNSSECValidatorBHO::SetSite(IUnknown *pUnkSite) {
  ATLTRACE(DEBUG_PREFIX "SetSite() call\n");
  
  // Retrieve and store the IWebBrowser2 pointer 
  m_spWebBrowser2 = pUnkSite; 
  if (m_spWebBrowser2 == NULL) //invalid if no IWebBrowser2 is loaded
   return E_INVALIDARG;
  // Retrieve and store the IConnectionPointerContainer pointer 
  m_spCPC = m_spWebBrowser2;
  if (m_spCPC == NULL) //invalid if no IConnectionPointerContainer is loaded
   return E_POINTER;
  //Extracting hTabWnd element, it allows to manage different TABS on navigators with such characteristic
  InitDraw();
  //Creating the Status Bar Pane draw procedure
  WProcStatus = (WNDPROC)::SetWindowLongPtr(hTabWnd, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(&NSProc));
  //creating the Status bar Pane element
  hWndNewPane = CreateWindowEx(
	0,					// no extended styles
	STATUSCLASSNAME,	// name of status bar class
	(LPCTSTR) NULL,		// no text when first created
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,			// ignores size and position
	hTabWnd,			// handle to parent window
	NULL,				// child window identifier
	GHins,				// handle to application instance
	NULL);

  //Drawing the Status bar Pane element
  ::SetWindowLongPtr(hWndNewPane, GWL_WNDPROC, reinterpret_cast<LONG_PTR>(&PWProc));
  
  // Connect to the container for receiving event notifications
  return Connect();
}

//Connect: If all tasks were succesfull on SetSite, BHO can establish a connection with MSIE properties
HRESULT CDNSSECValidatorBHO::Connect() {
  ATLTRACE(DEBUG_PREFIX "Connect() call\n");
  
  HRESULT hr;
  CComPtr<IConnectionPoint> spCP;
  // Receives the connection point for WebBrowser events
  hr = m_spCPC->FindConnectionPoint(DIID_DWebBrowserEvents2, &spCP);
  if (FAILED(hr))
   return hr;
  // Pass our event handlers to the container. Each time an event occurs
  // the container will invoke the functions of the IDispatch interface 
  // we implemented.
  hr = spCP->Advise( reinterpret_cast<IDispatch*>(this), &m_dwCookie);
  return hr;
}

//Invoke: This method allows to obtain MSIE events
STDMETHODIMP CDNSSECValidatorBHO::Invoke(DISPID dispidMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pvarResult, EXCEPINFO *pExcepInfo, UINT *puArgErr) {
    ATLTRACE(DEBUG_PREFIX "Invoke() call\n");
	
	USES_CONVERSION;//avoiding warnings with respect to ATL DATA_TYPE element
	HWND hwnd=NULL;

	//loading MSIE elements
	HRESULT hr = m_spWebBrowser2->get_HWND((LONG_PTR*)&hwnd);
	//succeed?
	if (SUCCEEDED(hr)) {
		switch(dispidMember) {	
			case DISPID_WINDOWSTATECHANGED : {
				statldicon=ldicon; //current status
				//redrawing the Status bar pane with the current status icon
				RedrawWindow(hWndNewPane,NULL,NULL,RDW_INVALIDATE|RDW_UPDATENOW);
				//setting again the status icon regards the Shape/Size of the Window 
				MoveWindow(hWndNewPane, position, 1, ICON_KEY_WIDTH, ICON_KEY_HEIGHT, TRUE);
			} break;

			case DISPID_BEFORENAVIGATE2 : {	
				//this element helps the plugin to extract the URL
				//allocated in memory of MSIE
				ATLASSERT((*pDispParams).rgvarg[5].vt = VT_BYREF | VT_BSTR);
				bstrUrlName = ((*pDispParams).rgvarg)[5].pvarVal->bstrVal;
				//DNSSEC display
				displaydnssecstatus();
			} break;
			//default status
			default : {
			} break;
		}
	}
	return S_FALSE;
}


//displaydnssecstatus: It displays DNSSEC status function
void CDNSSECValidatorBHO::displaydnssecstatus(void) {
	ATLTRACE(DEBUG_PREFIX "displaydnssecstatus() call\n");
	
	//the next lines allow to the plugin to cast the URL name to
	//a "standard readable" string char*
	//but now in the case of the domain name
	domain = (char*)malloc(2048*sizeof(char));
	predomain= (char*)malloc(2048*sizeof(char));
	predomain=_com_util::ConvertBSTRToString(bstrUrlName);

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
			ldicon=IDI_ICON_KEY_GREY;
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

// loads preference settings from the Windows registry
void CDNSSECValidatorBHO::LoadOptions(void) {
	ATLTRACE(DEBUG_PREFIX "LoadOptions() call\n");
	
	DWORD dwRet, dwSize;
	HKEY hKey;

	// open DNSSEC Validator registry key if exists
	dwRet = RegOpenKeyEx(HKEY_CURRENT_USER, DSV_REG_KEY, 0, KEY_READ, &hKey);
	if (dwRet == ERROR_SUCCESS) {
		// set maximum available buffer size
		dwSize = MAX_STR_LEN;
		// read preferences
		dwRet = RegQueryValueExA(hKey, "dnsserveraddr", NULL, NULL, (BYTE*)prefs.szDnsserveraddr, &dwSize);
		dwRet = RegQueryValueExA(hKey, "debugoutput", NULL, NULL, (BYTE*)&prefs.dwDebugoutput, &dwSize);
		dwRet = RegQueryValueExA(hKey, "usetcp", NULL, NULL, (BYTE*)&prefs.dwUsetcp, &dwSize);
		RegCloseKey(hKey);
	} else {
		ATLTRACE(DEBUG_PREFIX "Cannot open DNSSEC Validator's registry key\n");
	}
}

//checkdomainstatus: It checks whether a domain is a DNSSEC domain
void CDNSSECValidatorBHO::checkdomainstatus(void) {
	ATLTRACE(DEBUG_PREFIX "checkdomainstatus() call\n");
	
	//temporal element that helps to fragment the given URL in a domain
	char* tmpdomain = NULL;
	tmpdomain= (char*)malloc(2048*sizeof(char));
	tmpdomain=URL2domain(predomain);
	strcpy_s(domain,2048,tmpdomain);

	LoadOptions();

	// temporary hardcoded requested IP version
	bool resolvipv4 = true;
	bool resolvipv6 = false;

	uint16_t options = 0;
	if (prefs.dwDebugoutput) options |= NPAPI_INPUT_FLAG_DEBUGOUTPUT;
	if (prefs.dwUsetcp) options |= NPAPI_INPUT_FLAG_USETCP;
	if (resolvipv4) options |= NPAPI_INPUT_FLAG_RESOLVIPV4;
	if (resolvipv6) options |= NPAPI_INPUT_FLAG_RESOLVIPV6;

	char *tmpptr = NULL;
	uint32_t ttl4, ttl6;
	result = ds_validate(domain, options, prefs.szDnsserveraddr, &tmpptr, &ttl4, &ttl6);
	ds_free_resaddrsbuf();

	SetSecurityState();
}

// sets the appropriate security state
void CDNSSECValidatorBHO::SetSecurityState(void) {
	ATLTRACE(DEBUG_PREFIX "SetSecurityState() call\n");

	switch (result) {
	case NPAPI_EXIT_CONNECTION_DOMAIN_SECURED:
		ldicon = IDI_ICON_KEY_GREEN;
		break;
	case NPAPI_EXIT_CONNECTION_NODOMAIN_SECURED:
		ldicon = IDI_ICON_KEY_GREEN;
		break;
    case NPAPI_EXIT_CONNECTION_INVSIGDOMAIN_SECURED:
		ldicon = IDI_ICON_KEY_RED;
		break;
    case NPAPI_EXIT_DOMAIN_SIGNATURE_VALID:
		ldicon = IDI_ICON_KEY_ORANGE;
		break;
    case NPAPI_EXIT_AUTH_DOMAIN_SIGNATURE_VALID:
    	ldicon = IDI_ICON_KEY_ORANGE;
		break;
    case NPAPI_EXIT_DOMAIN_SIGNATURE_INVALID:
       	ldicon = IDI_ICON_KEY_RED;
		break;
    case NPAPI_EXIT_NODOMAIN_SIGNATURE_VALID:
       	ldicon = IDI_ICON_KEY_ORANGE;
		break;
    case NPAPI_EXIT_AUTH_NODOMAIN_SIGNATURE_VALID:
       	ldicon = IDI_ICON_KEY_ORANGE;
		break;
    case NPAPI_EXIT_NODOMAIN_SIGNATURE_INVALID:
		ldicon = IDI_ICON_KEY_RED;
		break;
    case NPAPI_EXIT_DOMAIN_UNSECURED:
		ldicon = IDI_ICON_KEY_GREY_RC;
		break;
	case NPAPI_EXIT_NODOMAIN_UNSECURED:
		ldicon = IDI_ICON_KEY_GREY_RC;
		break;
	case NPAPI_EXIT_UNKNOWN:
    case NPAPI_EXIT_FAILED:
    default:
		ldicon = IDI_ICON_KEY_GREY_YT;
		break;
    }
}

//to convert BSTR data to char data
char* CDNSSECValidatorBHO::URL2domain(char *url) {
	ATLTRACE(DEBUG_PREFIX "URL2domain() call\n");

	//static char instead of char
	static char seps[]   = "://";
	char *statdomain=NULL;
	char *next_token=NULL;

	//to store current domain name
	statdomain=(char*)malloc(2048*sizeof(char));
	next_token=(char*)malloc(2048*sizeof(char));

	//checking whether there is an available URL element
	if (strcmp(url,"")==0)
		return "";
	else {
		//extracting the domain
		statdomain = strtok_s(url, seps, &next_token);
		statdomain = strtok_s(NULL,seps, &next_token);
		return statdomain;
	}
}

//NSProc: drawing status bar pane
LRESULT CALLBACK CDNSSECValidatorBHO::NSProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	ATLTRACE(DEBUG_PREFIX "NSProc() call\n");

	switch (message) {
		case SB_SETPARTS: {
			if(lParam && wParam) {			
				//// Allocate an array for holding the right edge coordinates.
				HLOCAL hloc = LocalAlloc(LHND, (wParam)*sizeof(int));
				//obtainig the number of parts of the Status Bar
				LPINT lpPS=(LPINT)LocalLock(hloc);
				memcpy_s(lpPS,(lParam)*sizeof(int),(void*)lParam,(wParam)*sizeof(int));
				//current position of the second part of the Status Bar
				memcpy_s(&position,sizeof(int),&lpPS[1], sizeof(int));
			}
			break;
		}
	}
	//IMPORTANT : CallWindowProc returns the event to the current element
	// if this line is not performed, the event WON'T reach the main window
	// and the Status Bar WON'T BE DISPLAYED
	return ::CallWindowProc(WProcStatus, hWnd, message, wParam, lParam );
}

//PWProc: drawing icon
LRESULT CALLBACK CDNSSECValidatorBHO::PWProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	ATLTRACE(DEBUG_PREFIX "PWProc() call\n");

	switch (message) {
		case WM_PAINT: {
			ATLTRACE("PWProc: WM_PAINT\n");
			PAINTSTRUCT ps;
			//beginning paint event
			HDC hDC = BeginPaint(hWnd, &ps);
		    // Get the coordinates of the parent window's client area.
			CRect rcClient;
			GetClientRect(hWnd, &rcClient);
			//loading current status icon
			HICON icon = (HICON)LoadImage(GHins, MAKEINTRESOURCE(statldicon), IMAGE_ICON, ICON_KEY_WIDTH, ICON_KEY_HEIGHT, LR_DEFAULTSIZE);
			//drawing icon
			ATLTRACE("PWProc: rcClient w: %d; h: %d\n", rcClient.Width(), rcClient.Height());
			DrawIconEx(hDC,/*(rcClient.Width() - 16)/2*/ 0, /*(rcClient.Height() - 16)/2*/ 0 , icon, 0, 0, NULL, NULL, DI_NORMAL);
			//finishing ...
			EndPaint(hWnd, &ps);
			break;
		}
	    //clicking on the icon, RIGTH||LEFT click button on the mouse device
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
						//to check
						break;
					}
				}
			}
			break;
 		}
		case WM_LBUTTONUP : {
			ATLTRACE("PWProc: WM_LBUTTONUP\n");
			break;
		}
		default: {
			break;
		}
	}
	// instead of CallWindowProc && 0
	// DefWindowProc is used to send messages to the CURRENT hWwnd element
	// if this line is not implemented, the messages WON'T REACH the current 
	// window and the changes WON'T be performed
	return ::DefWindowProc(hWnd, message, wParam, lParam );
}


void CDNSSECValidatorBHO::InitDraw(void) {
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
							hTabWnd = GetWindow(hTabWnd, GW_CHILD);
						GetClassName(hTabWnd, szClassName, MAX_PATH);
						//detecting whether the current child window be TabWindowClass or StatusBarPaneClass
						while(hTabWnd && _tcscmp(szClassName, (!i) ? _T("TabWindowClass") : _T("msctls_statusbar32"))) {
							hTabWnd = GetWindow(hTabWnd, GW_HWNDNEXT);
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
