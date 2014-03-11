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
#define SM_NAME_LOCAL "Local\\SharedCacheTLSADNSSEC" /* share memory name for Windows*/
// default icon status 
WORD statdnssecicon=IDI_DNSSEC_ICON_INIT;
// for ICON KEY status - not used
WORD dnsseciconBar;
bool debug = true;
char * temp = "";
short textkey = KEYTEXT;
short choice = RESOLVER;
short choice2 = RESOLVER2;
short tlsaenable = TLSAENABLE;
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
short tlsaicon = 9;
short tlsaresult;
char*  ipbrowser4;
char*  ipbrowser6;
char ipvalidator4[256];
char*  ipvalidator6;
bool wrong = false;
// global state info
WORD paneltitletlsa  = 0;
WORD paneltextmain  = 0;
WORD paneltextadd  = 0;
WORD paneltitle  = 0;
WORD panelpredonain  = 0;
char* paneldomainname  = 0;
char tlsapaneldomainname[280]; 
WORD panelpostdomain  = 0;
WORD paneltext  = 0;
short paneltextip  = 1;
WORD keylogo  = 0;
WORD keylogo2  = 0;
WORD tlsaiconres = 0;
int err = 0;
short filteron;
char listtld[TLD_LIST_MLEN] = "";
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
char DefaultIniData[] = "[DNSSEC]\ntlsaenable=1\nkeytext=0\nchoice=3\nchoicedns=0\nuserip=8.8.8.8\nfilteron=0\nlisttld="; 
char str[INET6_ADDRSTRLEN];

//----BEGIN of CACHE MEMORY ---------------------------------------------------
#define CACHE_ITEMS_MAX 64          // max items in cache
#define DOMAIN_NAME_LENGTH_MAX 270   // max lenght of domain name include port number
#define PORT_LENGTH_MAX 6            // max lenght of port record
#define NO_ITEM_IN_CACHE -99         // the item is not in cache           


//----------------------------------------------------------------------------
static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static int byteMapLen = sizeof(byteMap);


//*****************************************************************************
// Utility function to convert nibbles (4 bit values) into a hex character
// representation.
// ----------------------------------------------------------------------------
static
char nibbleToChar(uint8_t nibble)
{
	if (nibble < byteMapLen) return byteMap[nibble];
	return '*';
}

//*****************************************************************************
// Helper function (binary data to hex string conversion)
// ----------------------------------------------------------------------------
static
char * bintohex(const uint8_t *bytes, size_t buflen)
{
	char *retval = NULL;
	unsigned i;

	retval =(char*)malloc(buflen * 2 + 1);

	if (retval == NULL) {
		return NULL;
	}

	for (i = 0; i < buflen; ++i) {
		retval[i * 2] = nibbleToChar(bytes[i] >> 4);
		retval[i * 2 + 1] = nibbleToChar(bytes[i] & 0x0f);
	}
	retval[i * 2] = '\0';
	return retval;
}

// cache item structure
typedef struct Record {
	char key[DOMAIN_NAME_LENGTH_MAX];
	char port[PORT_LENGTH_MAX];
	short tlsaresult;
	bool block;
	time_t expir;
} CacheItemStruct;

// shared cache array structure with controls
// idex
struct DaneCacheStruct {
	short itemindex;
	bool lock;
	CacheItemStruct cacheitem[CACHE_ITEMS_MAX];
}; 

// share cache structure in all instances of IE (windows and tabs)
HANDLE hFileMapping = CreateFileMapping (INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(struct DaneCacheStruct), SM_NAME_LOCAL);  
DaneCacheStruct *DaneCache = (struct DaneCacheStruct *) MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

bool cache_get_block(struct DaneCacheStruct* DaneCache, int item)
{
	return DaneCache->cacheitem[item].block;
}

short cache_get_tlsaresult(struct DaneCacheStruct* DaneCache, int item)
{
	return DaneCache->cacheitem[item].tlsaresult;
}

time_t cache_get_expir(struct DaneCacheStruct* DaneCache, int item)
{
	return DaneCache->cacheitem[item].expir;
}

char* cache_get_port(struct DaneCacheStruct* DaneCache, int item)
{
	return DaneCache->cacheitem[item].port;
}

// update item in cache
void cache_update_item(struct DaneCacheStruct* DaneCache, char* key, char *port, short tlsaresult, bool block, time_t expir, int item)
{
	strcpy_s(DaneCache->cacheitem[item].key, key);
	strcpy_s(DaneCache->cacheitem[item].port, port);
	DaneCache->cacheitem[item].tlsaresult = tlsaresult;
	DaneCache->cacheitem[item].block = block;
	DaneCache->cacheitem[item].expir = expir;
}

// write all items from cache to debug output
void cache_view_all(struct DaneCacheStruct* DaneCache)
{
   int i = 0;
   int cnt = 0;
    ATLTRACE("Cache content: \n");
   while  (i < CACHE_ITEMS_MAX) { 
	   if (strcmp(DaneCache->cacheitem[i].key,"")!=0) {
	     ATLTRACE("   r%i: ",i);
	     ATLTRACE("%s, ",DaneCache->cacheitem[i].key);
	     ATLTRACE("%s, ",DaneCache->cacheitem[i].port);
	     ATLTRACE("%i, ",DaneCache->cacheitem[i].tlsaresult);
	     //printf("%i, ",DaneCache->cacheitem[i].block);
	     ATLTRACE("%i\n",DaneCache->cacheitem[i].expir);
		 cnt++;
	   } // if
	   i++;
   } // while
  ATLTRACE("Cache items: %i\n",cnt);
}

// add item into cache
void cache_add_item(struct DaneCacheStruct* DaneCache, char* key, char *port, short tlsaresult, bool block, time_t expir)
{

	if (DaneCache->itemindex < CACHE_ITEMS_MAX-1) {
		DaneCache->itemindex++;
	}
	else {
		DaneCache->itemindex = 0;
	}
	strcpy_s(DaneCache->cacheitem[DaneCache->itemindex].key, key);
	if (port == NULL) {
		strcpy_s(DaneCache->cacheitem[DaneCache->itemindex].port, "");
	}
	else {
		strcpy_s(DaneCache->cacheitem[DaneCache->itemindex].port, port);
	}
	DaneCache->cacheitem[DaneCache->itemindex].tlsaresult = tlsaresult;
	DaneCache->cacheitem[DaneCache->itemindex].block = block;
	DaneCache->cacheitem[DaneCache->itemindex].expir = expir;
}

// find item in cache
int cache_find_item(struct DaneCacheStruct* DaneCache, char* key)
{ 
   int up = 0;
   int i;
   int down = CACHE_ITEMS_MAX - 1;
   char tmp[DOMAIN_NAME_LENGTH_MAX];
   strcpy_s(tmp, key);   
  
   if (DaneCache->itemindex < (CACHE_ITEMS_MAX/2))
   {     
     for (i=up; i <CACHE_ITEMS_MAX; i++) if (strcmp(DaneCache->cacheitem[i].key,tmp)==0) return i;
   }
   else
   {     
     for (i=down; i >=0; i--) if (strcmp(DaneCache->cacheitem[i].key,tmp)==0) return i;
   }
   return NO_ITEM_IN_CACHE;
}

// delete one item from cache (not use here)
void cache_delete_item(struct DaneCacheStruct* DaneCache, int item)
{
	strcpy_s(DaneCache->cacheitem[item].key, "");
	strcpy_s(DaneCache->cacheitem[item].port, "");
	DaneCache->cacheitem[item].tlsaresult = 0;
	DaneCache->cacheitem[item].block = false;
	DaneCache->cacheitem[item].expir = 0;
}

// delete all items from cache (internal call)
void CKBBarBand::cache_delete_all(void)
{
   //struct DaneCacheStruct* DaneCache;
	int i = 0;
   while ((strcmp(DaneCache->cacheitem[i].key,"")!=0) && (i < CACHE_ITEMS_MAX))
	{
   	strcpy_s(DaneCache->cacheitem[i].key, "");
  	strcpy_s(DaneCache->cacheitem[i].port, "");
  	DaneCache->cacheitem[i].tlsaresult = 0;
	  DaneCache->cacheitem[i].block = false;
	  DaneCache->cacheitem[i].expir = 0;
	  i++;	
	}
	DaneCache->itemindex = -1;
	if (debug) ATLTRACE("Setting was changed: Cache clear...\n");
}

// delete all items from cache (external call)
void CKBBarBand::cache_delete_all2(void)
{
    struct DaneCacheStruct* DaneCache;
    
    HANDLE hFileMapping = CreateFileMapping (INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(struct DaneCacheStruct), SM_NAME_LOCAL);
    DaneCache = (struct DaneCacheStruct *) MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
   
   int i = 0;
   while ((strcmp(DaneCache->cacheitem[i].key,"")!=0) && (i < CACHE_ITEMS_MAX))
	{
   	strcpy_s(DaneCache->cacheitem[i].key, "");
  	strcpy_s(DaneCache->cacheitem[i].port, "");
  	DaneCache->cacheitem[i].tlsaresult = 0;
	  DaneCache->cacheitem[i].block = false;
	  DaneCache->cacheitem[i].expir = 0;
	  i++;	
	}
  DaneCache->itemindex = -1;
}
//-- END of CACHE -------------------------------------------------------------

// structure to save IPv4/IPv6 address from stub resolver
typedef struct {   
  char* ipv4;
  char* ipv6;
} ipv64struct;
ipv64struct ip64buf;

// structure to save protocol, domain name and port from url
typedef struct {
  char *protocol;
  char *domainport;
  char *domain;
  char *port;
} urlstruct;

/**************************************************************************/
//to convert URL string on protocol, domain name and port 
/**************************************************************************/
urlstruct UrlToProtocolDomainPort(char *url) 
{
	//if (debug) ATLTRACE("UrlToProtocolDomainPort(%s);\n",url);

	static char separator1[]   = ":/";
	static char separator2[]   = "/";
	static char separator3[]   = ":";
	urlstruct Urlstructure;
	char *next_token=NULL;
	char *domainport=NULL;
	
	Urlstructure.protocol = strtok_s(url, separator1, &next_token);
	//if (debug) ATLTRACE("protocol(%s);\n",Urlstructure.protocol);
	domainport = strtok_s(NULL,separator2, &next_token);
	//if (debug) ATLTRACE("domainport(%s);\n",domainport);
	int size = strlen(domainport) + 1;
	Urlstructure.domainport =(char*)malloc(size);
	memcpy(Urlstructure.domainport, domainport, size);
	Urlstructure.domain = strtok_s(domainport, separator3, &next_token);
	//if (debug) ATLTRACE("domain(%s);\n",Urlstructure.domain);
	Urlstructure.port = strtok_s(NULL,separator1, &next_token);	
	//if (debug) ATLTRACE("port(%s);\n",Urlstructure.port);
	
	return Urlstructure;
}

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
ipv64struct stub_resolve(const char *domain)
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
		//if (debug) ATLTRACE( "SetSite() call\n");
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
	//if (debug) ATLTRACE("GetSite():\n");
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
		//if (debug) ATLTRACE("GetWindow():\n");
	*phWnd = m_wndToolBar.GetSafeHwnd();

	return S_OK;
}
STDMETHODIMP CKBBarBand::ResizeBorderDW(LPCRECT prcBorder, IUnknown* punkSite, BOOL fReserved)
{
	//if (debug) ATLTRACE("ResizeBorderDW():\n");
	ATLTRACENOTIMPL("IDockingWindow::ResizeBorderDW");
}
STDMETHODIMP CKBBarBand::ContextSensitiveHelp(BOOL fEnterMode)
{
	//if (debug) ATLTRACE("ContextSensitiveHelp():\n");
	ATLTRACENOTIMPL("IOleWindow::ContextSensitiveHelp");
}
/**************************************************************************/
// IDockingWindow Implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::ShowDW(BOOL fShow)
{
	//if (debug) ATLTRACE("ShowDW():\n");
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
	//if (debug) ATLTRACE("CloseDW():\n");
	ShowDW(FALSE);
	return S_OK;
}
/**************************************************************************/
// IInputObject Implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::UIActivateIO(BOOL fActivate, LPMSG pMsg)
{
	//if (debug) ATLTRACE("UIActivateIO():\n");
	if(fActivate)
	{
		SetFocus(m_wndToolBar);
	}
	return S_OK;
}
STDMETHODIMP CKBBarBand::HasFocusIO(void)
{ 
	//if (debug) ATLTRACE("HasFocusIO():\n");
	HWND hwndFocus = ::GetFocus();
	return S_OK;
}
STDMETHODIMP CKBBarBand::TranslateAcceleratorIO(LPMSG pMsg)
{
	//if (debug) ATLTRACE("TranslateAcceleratorIO():\n");
	return m_wndToolBar.TranslateAcceleratorIO(pMsg);
}
/**************************************************************************/
// IDeskBand implementation
/**************************************************************************/
STDMETHODIMP CKBBarBand::GetBandInfo(DWORD dwBandID, DWORD dwViewMode, DESKBANDINFO* pdbi)
{
//if (debug) ATLTRACE("GetBandInfo():\n");
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
   //if (debug) ATLTRACE("Invoke() call\n");
	USES_CONVERSION;//avoiding warnings with respect to ATL DATA_TYPE element
	HWND hwnd=NULL;
	//if (debug) ATLTRACE(DEBUG_PREFIX "dispidMember: %d\n");
	//loading MSIE elements
	HRESULT hr = webBrowser2->get_HWND((LONG_PTR*)&hwnd);
	BSTR BURL = L"";
	char * tmpurl = "";
	//succeed?
	if (SUCCEEDED(hr)) {
		switch(dispidMember) {

			// Fires if window or tab was changed 
			case DISPID_WINDOWSTATECHANGED : {
				if (debug) ATLTRACE("Invoke(): DISPID_WINDOWSTATECHANGED\n");

				if (pDispParams) {
					 DWORD dwMask  = pDispParams->rgvarg[0].lVal;
					 DWORD dwFlags = pDispParams->rgvarg[1].lVal;
				    // We only care about WINDOWSTATE_USERVISIBLE.
					if (dwMask & OLECMDIDF_WINDOWSTATE_USERVISIBLE)
					{
						bool visible = !!(dwFlags & OLECMDIDF_WINDOWSTATE_USERVISIBLE);
						LoadOptionsFromFile();					
						HRESULT hrs = webBrowser2->get_LocationURL(&BURL);
						tmpurl =_com_util::ConvertBSTRToString(BURL);
						if (debug) ATLTRACE("URL: %s", tmpurl);
						if (strcmp(tmpurl,"")==0 || strcmp(tmpurl,"about:Tabs")==0 || strcmp(tmpurl,"about:Blank")==0 || strcmp(tmpurl,"about:blank")==0 || strcmp(tmpurl,"javascript:false;")==0 || strcmp(tmpurl,"res://ieframe.dll/dnserrordiagoff.htm")==0) {
							if (debug) ATLTRACE("null\n");
							dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_INIT);
							tlsaicon = GetIconIndex(IDI_TLSA_ICON_INIT);						
							keylogo=dnssecicon;
							RefreshIcons();
						} else {
							if (debug) ATLTRACE("\n");					
							CheckDomainStatus(tmpurl);
						}
					}
				}
				free(tmpurl);
			} break;

			case DISPID_BEFORENAVIGATE2 : {				
				if (debug) ATLTRACE("Invoke(): DISPID_BEFORENAVIGATE2\n");	
				HRESULT hrs = webBrowser2->get_LocationURL(&BURL);
				tmpurl =_com_util::ConvertBSTRToString(BURL);
				if (debug) ATLTRACE("URL: %s", tmpurl);
				if (strcmp(tmpurl,"")==0 || strcmp(tmpurl,"about:Tabs")==0 || strcmp(tmpurl,"about:Blank")==0 || strcmp(tmpurl,"about:blank")==0 || strcmp(tmpurl,"javascript:false;")==0 || strcmp(tmpurl,"res://ieframe.dll/dnserrordiagoff.htm")==0) {
					if (debug) ATLTRACE("null\n");
					dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_INIT);
					tlsaicon = GetIconIndex(IDI_TLSA_ICON_INIT);					
					RefreshIcons();
					keylogo=dnssecicon;
				} else {					
					if (debug) ATLTRACE("\n");
					CheckDomainStatus(tmpurl);
					state = dnssecicon;
					keylogo=dnssecicon;							
				}	
			free(tmpurl);			
			} break;
/*
			case DISPID_NAVIGATECOMPLETE2 : {	
				if (debug) ATLTRACE("Invoke(): DISPID_NAVIGATECOMPLETE2: ");				
				HRESULT hrs = webBrowser2->get_LocationURL(&BURL);
				tmpurl =_com_util::ConvertBSTRToString(BURL);
				if (debug) ATLTRACE("%s", tmpurl);
				if (strcmp(tmpurl,"")==0 || strcmp(tmpurl,"about:Tabs")==0 || strcmp(tmpurl,"about:Blank")==0 || strcmp(tmpurl,"about:blank")==0 || strcmp(tmpurl,"javascript:false;")==0 || strcmp(tmpurl,"res://ieframe.dll/dnserrordiagoff.htm")==0) {
					if (debug) ATLTRACE("null\n");
					dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_INIT);
					tlsaicon = GetIconIndex(IDI_TLSA_ICON_INIT);						
					keylogo=dnssecicon;
					RefreshIcons();
				} else {
					if (debug) ATLTRACE("\n");
					dnssecicon = state;
					keylogo=dnssecicon;
					RefreshIcons();			
				}
			} break;
*/
			//default status
			default : {
			} break;
		}
	}
	return S_FALSE;
}

/**************************************************************************/
// refresh icons in the toolbar bar
/**************************************************************************/
void CKBBarBand::RefreshIcons(void) {
	m_wndToolBar.RepaintButtonDNSSEC(0,dnssecicon);
	m_wndToolBar.RepaintButtonTLSA(1,tlsaicon);
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
	if (debug) ATLTRACE("CreateToolWindow():\n");
	CRect rcClientParent;
	rcClientParent2=rcClientParent;
	CWnd* pWndParent = CWnd::FromHandle(m_hWndParent);
	pWndParent->GetClientRect(&rcClientParent);
	
	int ret;
	ret = dnssec_validation_init(); 
	if (debug) ATLTRACE("dnssec_validation_init(%d):\n",ret);

	ret =  dane_validation_init();
	if (debug) ATLTRACE("dane_validation_init(%d):\n",ret);
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
	/*
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
//if (debug) ATLTRACE("CreateStatusBar():\n");
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
//if (debug) ATLTRACE("CreateStatusBar():\n");
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
   // if (debug) ATLTRACE("CreateIconTooltip() call\n");	
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
int CKBBarBand::GetIconIndex(int icon)
{	
	//if (debug) ATLTRACE("GetIconIndex(%d):\n", icon);	
	int iconindex = 0;
	switch (icon) {
	case IDI_DNSSEC_ICON_INIT: 
			iconindex = 0; 
			break;
	case IDI_DNSSEC_ICON_OFF: 
			iconindex = 1; 
			break;
	case IDI_DNSSEC_ICON_ERROR:
			iconindex = 2; 
			break;
	case IDI_DNSSEC_ICON_ACTION: 
			iconindex = 3; 
			break;
	case IDI_DNSSEC_ICON_NO:
			iconindex = 4;
			break;
	case IDI_DNSSEC_ICON_VALID:
			iconindex = 5; 
			break;
	case IDI_DNSSEC_ICON_BOGUS:
			iconindex = 6;
			break;
	case IDI_DNSSEC_ICON_IP:
			iconindex = 7;
			break;
	case IDI_DNSSEC_ICON_ORANGE:
			iconindex = 8;
			break;
	case IDI_TLSA_ICON_INIT: 
			iconindex = 9;
			break;
	case IDI_TLSA_ICON_OFF:
			iconindex = 10;
			break;
	case IDI_TLSA_ICON_ERROR: 
			iconindex = 11;
			break;
	case IDI_TLSA_ICON_ACTION:
			iconindex = 12;
			break;
	case IDI_TLSA_ICON_NODNSSEC: 
			iconindex = 13; 
			break;
	case IDI_TLSA_ICON_VALID: 
			iconindex = 14; 
			break;
	case IDI_TLSA_ICON_INVALID: 
			iconindex = 15;
			break;
	case IDI_TLSA_ICON_NOHTTPS:
			iconindex = 16; 
			break;
	case IDI_TLSA_ICON_NO: 
			iconindex = 17; 
			break;
	case IDI_TLSA_ICON_ORANGE: 
			iconindex = 18;
			break;
	default: 
			iconindex = 0; 
			break;
	}
		//if (debug) ATLTRACE("GetIconIndexRETURN(%d):\n", iconindex);	
		return iconindex;
}//

/**************************************************************************/
// Set TLSA security status (key icon and popup text)
/**************************************************************************/
void CKBBarBand::SetSecurityTLSAStatus()
{
	if (debug) ATLTRACE("SetSecurityTLSAStatus(%d):\n", tlsaresult);	
	int daneicon = 0;
	WORD panel_label = IDS_NONE; // main label of popup
	WORD panel_text1 = IDS_NONE; // TLSA main text
	WORD panel_text2 = IDS_NONE; // TLSA additional text
	WORD tlsaiconresr = IDS_NONE;
	// switch of TLSA status - icon, popup info
	
  switch (tlsaresult) {

	// state 10
	case DANE_VALID_TYPE0:
		daneicon = GetIconIndex(IDI_TLSA_ICON_VALID);
		tlsaiconresr = IDI_TLSA_ICON_VALID;
		panel_label = IDS_DANE_STATE10_LABEL;
		panel_text1 = IDS_DANE_STATE10_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATE10_TEXT_ADD;
 		break;
    // state 11
	case DANE_VALID_TYPE1:
		daneicon = GetIconIndex(IDI_TLSA_ICON_VALID);
		tlsaiconresr = IDI_TLSA_ICON_VALID;
		panel_label = IDS_DANE_STATE11_LABEL;
		panel_text1 = IDS_DANE_STATE11_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATE11_TEXT_ADD;
 		break;
    // state 12
	case DANE_VALID_TYPE2:
		daneicon = GetIconIndex(IDI_TLSA_ICON_VALID);
		tlsaiconresr = IDI_TLSA_ICON_VALID;
		panel_label = IDS_DANE_STATE12_LABEL;
		panel_text1 = IDS_DANE_STATE12_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATE12_TEXT_ADD;
 		break;
    // state 13
	case DANE_VALID_TYPE3:
		daneicon = GetIconIndex(IDI_TLSA_ICON_VALID);
		tlsaiconresr = IDI_TLSA_ICON_VALID;
		panel_label = IDS_DANE_STATE13_LABEL;
		panel_text1 = IDS_DANE_STATE13_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATE13_TEXT_ADD;
 		break;
    // state 20
	case DANE_INVALID_TYPE0:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INVALID);
		tlsaiconresr = IDI_TLSA_ICON_INVALID;
		panel_label = IDS_DANE_STATEx10_LABEL;
		panel_text1 = IDS_DANE_STATEx10_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx10_TEXT_ADD;
 		break;
    // state 21
	case DANE_INVALID_TYPE1:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INVALID);
		tlsaiconresr = IDI_TLSA_ICON_INVALID;
		panel_label = IDS_DANE_STATEx11_LABEL;
		panel_text1 = IDS_DANE_STATEx11_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx11_TEXT_ADD;
 		break;
    // state 22
	case DANE_INVALID_TYPE2:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INVALID);
		tlsaiconresr = IDI_TLSA_ICON_INVALID;
		panel_label = IDS_DANE_STATEx12_LABEL;
		panel_text1 = IDS_DANE_STATEx12_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx12_TEXT_ADD;
 		break;
    // state 23
	case DANE_INVALID_TYPE3:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INVALID);
		tlsaiconresr = IDI_TLSA_ICON_INVALID;
		panel_label = IDS_DANE_STATEx13_LABEL;
		panel_text1 = IDS_DANE_STATEx13_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx13_TEXT_ADD;
 		break;
    // state 9
	case DANE_DNSSEC_SECURED:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INIT);
		tlsaiconresr = IDI_TLSA_ICON_INIT;
		panel_label = IDS_DANE_STATE1_LABEL;
		panel_text1 = IDS_DANE_STATE1_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATE1_TEXT_ADD;
 		break;
    // state 0
	case DANE_OFF:
		daneicon = GetIconIndex(IDI_TLSA_ICON_OFF);
		tlsaiconresr = IDI_TLSA_ICON_OFF;
		panel_label = IDS_DANE_STATE0_LABEL;
		panel_text1 = IDS_DANE_STATE0_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATE0_TEXT_ADD;
 		break;
	// state 1
	case DANE_NO_HTTPS:
		daneicon = GetIconIndex(IDI_TLSA_ICON_NOHTTPS);
		tlsaiconresr = IDI_TLSA_ICON_NOHTTPS;
		panel_label = IDS_DANE_STATEx2_LABEL;
		panel_text1 = IDS_DANE_STATEx2_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx2_TEXT_ADD;
 		break;
	// state 2
	case DANE_NO_TLSA:
		daneicon = GetIconIndex(IDI_TLSA_ICON_NO);
		tlsaiconresr = IDI_TLSA_ICON_NO;
		panel_label = IDS_DANE_STATEx3_LABEL;
		panel_text1 = IDS_DANE_STATEx3_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx3_TEXT_ADD;
 		break; 
	// state 3
	case DANE_DNSSEC_UNSECURED:
		daneicon = GetIconIndex(IDI_TLSA_ICON_NODNSSEC);
		tlsaiconresr = IDI_TLSA_ICON_NODNSSEC;
		panel_label = IDS_DANE_STATEx4_LABEL;
		panel_text1 = IDS_DANE_STATEx4_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx4_TEXT_ADD;
 		break;
	// state 16
	case DANE_DNSSEC_BOGUS:
		daneicon = GetIconIndex(IDI_TLSA_ICON_ORANGE);
		tlsaiconresr = IDI_TLSA_ICON_ORANGE;
		panel_label = IDS_DANE_STATEx5_LABEL;
		panel_text1 = IDS_DANE_STATEx5_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx5_TEXT_ADD;
 		break;
	// state 17
	case DANE_NO_CERT_CHAIN:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INVALID);
		tlsaiconresr = IDI_TLSA_ICON_INVALID;
		panel_label = IDS_DANE_STATEx6_LABEL;
		panel_text1 = IDS_DANE_STATEx6_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx6_TEXT_ADD;
 		break;
	// state 18
	case DANE_CERT_ERROR:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INVALID);
		tlsaiconresr = IDI_TLSA_ICON_INVALID;
		panel_label = IDS_DANE_STATEx7_LABEL;
		panel_text1 = IDS_DANE_STATEx7_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx7_TEXT_ADD;
 		break;
	// state 19
	case DANE_TLSA_PARAM_ERR:
		daneicon = GetIconIndex(IDI_TLSA_ICON_INVALID);
		tlsaiconresr = IDI_TLSA_ICON_INVALID;
		panel_label = IDS_DANE_STATEx8_LABEL;
		panel_text1 = IDS_DANE_STATEx8_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx8_TEXT_ADD;
 		break;
	// state -3
	case DANE_RESOLVER_NO_DNSSEC:
		daneicon = GetIconIndex(IDI_TLSA_ICON_ERROR);
		tlsaiconresr = IDI_TLSA_ICON_ERROR;
		panel_label = IDS_DANE_STATEx99_LABEL;
		panel_text1 = IDS_DANE_STATEx99_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx99_TEXT_ADD;
 		break;
	// state -2
    case DANE_ERROR_RESOLVER:
		daneicon = GetIconIndex(IDI_TLSA_ICON_ERROR);
		tlsaiconresr = IDI_TLSA_ICON_ERROR;
		panel_label = IDS_DANE_STATEx1_LABEL;
		panel_text1 = IDS_DANE_STATEx1_TEXT_MAIN;
		panel_text2 = IDS_DANE_STATEx1_TEXT_ADD;
		break;
	// generic error -1
    default:
		daneicon = GetIconIndex(IDI_TLSA_ICON_ERROR);
		tlsaiconresr = IDI_TLSA_ICON_ERROR;
		panel_label = IDS_DANE_ERROR_GEN_LABEL;
		panel_text1 = IDS_DANE_ERROR_GEN_TEXT_MAIN;
		panel_text2 = IDS_DANE_ERROR_GEN_TEXT_ADD;
		break;
	}// switch

	tlsaicon = daneicon;
	tlsaiconres = tlsaiconresr; 
	paneltitletlsa  = panel_label;
	paneltextmain  = panel_text1;
	paneltextadd  = panel_text2;
}//

/**************************************************************************/
// Set DNSSEC security status (key icon and popup text)
/**************************************************************************/
void CKBBarBand::SetSecurityDNSSECStatus()
{
	if (debug) ATLTRACE("SetSecurityDNSSECStatus(%d):\n", dnssecresult);
	// DNSSEC status tooltipinfo
	WORD tiicon = TTI_NONE;		// icon in tooltipinfo
	WORD tiicontitle = IDS_NONE;// main title of tooltipinfo
	WORD tipref = IDS_NONE;		// prefix
	WORD tistatus = IDS_NONE;	// DNSSEC status
	WORD titext = IDS_NONE;     // DNSSEC status text
	
	// switch of DNSSEC status - icon, popup info
	switch (dnssecresult) {

	// state 1
	case DNSSEC_DOMAIN_UNSECURED:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_NO);
		dnsseciconBar = IDI_DNSSEC_ICON_NO;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE1_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE1_TEXT_DOMAIN;
		titext = IDS_STATE1_TEXT_MAIN;
 		break;		
	// state 2
	case DNSSEC_COT_DOMAIN_SECURED:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_VALID);
		dnsseciconBar = IDI_DNSSEC_ICON_VALID;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE2_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE2_TEXT_DOMAIN;
		titext = IDS_STATE2_TEXT_MAIN;
 		break;
	// state 3
	case DNSSEC_COT_DOMAIN_SECURED_BAD_IP:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_IP);
		dnsseciconBar = IDI_DNSSEC_ICON_IP;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE3_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE3_TEXT_DOMAIN;
		titext = IDS_STATE3_TEXT_MAIN;
 		break;
	// state 4
	case DNSSEC_COT_DOMAIN_BOGUS:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_BOGUS);
		dnsseciconBar = IDI_DNSSEC_ICON_BOGUS;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE4_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE4_TEXT_DOMAIN;
		titext = IDS_STATE4_TEXT_MAIN;
 		break;
	// state 5
	case DNSSEC_NXDOMAIN_UNSECURED:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_NO);
		dnsseciconBar = IDI_DNSSEC_ICON_NO;
		tiicon = TTI_WARNING;
		tiicontitle = IDS_STATE5_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_NODOMAIN;
		tistatus = IDS_STATE5_TEXT_DOMAIN;
		titext = IDS_STATE5_TEXT_MAIN;
 		break;
   // state 6
	case DNSSEC_NXDOMAIN_SIGNATURE_VALID:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_VALID);
		dnsseciconBar = IDI_DNSSEC_ICON_VALID;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE6_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_NODOMAIN;
		tistatus = IDS_STATE6_TEXT_DOMAIN;
		titext = IDS_STATE6_TEXT_MAIN;
 		break;
    // state 7
	case DNSSEC_NXDOMAIN_SIGNATURE_INVALID:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_BOGUS);
		dnsseciconBar = IDI_DNSSEC_ICON_BOGUS;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE7_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_NODOMAIN;
		tistatus = IDS_STATE7_TEXT_DOMAIN;
		titext = IDS_STATE7_TEXT_MAIN;
 		break;  
    // state 0
	case DNSSEC_OFF:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_OFF);
		dnsseciconBar = IDI_DNSSEC_ICON_OFF;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE01_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE01_TEXT_DOMAIN;
		titext = IDS_STATE01_TEXT_MAIN;
 		break;
	//-3
	case DNSSEC_RESOLVER_NO_DNSSEC:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_ERROR);
		dnsseciconBar = IDI_DNSSEC_ICON_ERROR;
		tiicon = TTI_INFO;
		tiicontitle = IDS_STATE02_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_DOMAIN;
		tistatus = IDS_STATE02_TEXT_DOMAIN;
		titext = IDS_STATE02_TEXT_MAIN;
 		break;
	// state -2
    case DNSSEC_ERROR_RESOLVER:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_ERROR);
		dnsseciconBar = IDI_DNSSEC_ICON_ERROR;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE0_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_ERROR;
		tistatus = IDS_STATE0_TEXT_DOMAIN;
		titext = IDS_STATE0_TEXT_MAIN;
		break;
	// state -4
    case DNSSEC_UNBOUND_NO_DATA:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_ERROR);
		dnsseciconBar = IDI_DNSSEC_ICON_ERROR;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_STATE0_TEXT_TOOLTIP;
		tipref = IDS_PRE_TEXT_ERROR;
		tistatus = IDS_STATE0_TEXT_DOMAIN;
		titext = IDS_STATEx4_TEXT_MAIN;
		break;
	// generic error
	default:
		dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_ERROR);
		dnsseciconBar = IDI_DNSSEC_ICON_ERROR;
		tiicon = TTI_ERROR;
		tiicontitle = IDS_DNSSEC_ERROR_GEN_TOOLTIP;
		tipref = IDS_PRE_TEXT_ERROR;
		tistatus = IDS_DNSSEC_ERROR_GEN_DOMAIN;
		titext = IDS_DNSSEC_ERROR_GEN_MAIN;
		break;
		
	}// switch
	err = dnssecicon;
	keylogo2 = dnsseciconBar;
	paneltitle  = tiicontitle;
	panelpredonain  = tipref;
	paneldomainname = (char *)domain;
	panelpostdomain  = tistatus;
	paneltext  = titext;
	paneltextip = ipresult;
	res=dnssecresult;
}//

/**************************************************************************/
// Check domain name if is contain in the list of Exclude domain
// return true if domain havent in the list else false
// input: domain name from url, enable filter from ini, Excluded Doamin list
/**************************************************************************/
bool CKBBarBand::ExcludeDomainList(char *domain, short ExcludeOn, char domainlist[TLD_LIST_MLEN]){

	const int DOMAINLEVEL = 10;
	const int DOMAINLEN = 256;

	if (domain == NULL) return false;
	if (domainlist == NULL) return false;
	int len = strlen(domain);
	if (len > DOMAINLEN) return false;

	bool validate = true;
	char str2[TLD_LIST_MLEN] = "";
	char str1[TLD_LIST_MLEN] = "";
	char* pch1 = NULL; 
	char* pch2 = NULL;
	char* context = NULL;
	char **text;
	int i = 0;

	if (ExcludeOn) {

		if (debug) {	
			ATLTRACE("DomainList: %s\n", domainlist);
			ATLTRACE("DomainUrl: %s [%i]\n", domain, len);
		}
		
		text = (char **)malloc(DOMAINLEVEL*sizeof(char*));
		for (i = 0; i < DOMAINLEVEL; i++) {
			text[i]=(char *) malloc(DOMAINLEN*sizeof(char));
			strcpy_s(text[i], DOMAINLEN, "");
		}
		strncpy_s(str2, sizeof(str2), domainlist, sizeof(str2));
		strncpy_s(str1, sizeof(str1), domain, sizeof(str1));

		strcpy_s(text[0], DOMAINLEN, domain);
		pch1 = strtok_s(str1,". ", &context);
		int i = 1;
		while (pch1 != NULL && i < 10) {
			strcpy_s(text[i], DOMAINLEN, context);
			pch1 = strtok_s (NULL, ". ", &context);
			i++;
		} //while	

		int count = 0;
		for (i = 0; i < DOMAINLEVEL; i++) {
			if (strcmp (text[i],"") != 0) count = i;
		}

		for (i = count; i >= 0; i--) {
			strncpy_s (str2, sizeof(str2), domainlist, sizeof(str2));
			//if (debug) ATLTRACE("[%i]: %s\n",i, text[i]);
			pch2 = strtok_s (str2," ,", &context);
			while (pch2 != NULL) {
				//if (debug) ATLTRACE("%s == %s\n",text[i],pch2);
				if (strcmp (pch2,text[i]) == 0) {
					validate = false;
					goto cleanup;
					break;
				}
				pch2 = strtok_s (NULL, " ,", &context);
			} // while		
		}
		goto cleanup;

cleanup: 
		for (i=0; i<DOMAINLEVEL; i++) {
			free(text[i]);
		}
		free(text);
		goto exit;
	}

exit: return validate;
}

/**************************************************************************/
// It checks whether a domain is a DNSSEC domain
/**************************************************************************/
void CKBBarBand::CheckDomainStatus(char * url) 
{   
	//if (debug) ATLTRACE("CheckDomainStatus(%s);\n", url);
	dnssecicon = GetIconIndex(IDI_DNSSEC_ICON_ACTION);
	tlsaicon = GetIconIndex(IDI_TLSA_ICON_ACTION);
	RefreshIcons();

	bool resolvipv4 = true;
	bool resolvipv6 = true;
	uint16_t options = 0;
	debugoutput = false; 
	short resultipv4 = 0; //the DNSSEC validation result
	short resultipv6 = 0; //the DNSSEC validation result	
	urlstruct UrlStructData = UrlToProtocolDomainPort(url);
	char * domaintmp = (char*)malloc(DOMAIN_NAME_LENGTH_MAX*sizeof(char));
	strcpy_s(domaintmp, DOMAIN_NAME_LENGTH_MAX, UrlStructData.domain);

	char* dnsip; 
	LoadOptionsFromFile();
	bool validated = true;

	validated = ExcludeDomainList(domaintmp, filteron, listtld);

	if (validated) {
		if (debug) ATLTRACE("\n*************** DNSSEC validation Start ***************\n");
		usedfwd = true;
		if (choice==2) dnsip = dnssecseradr;
			else if (choice==1) if (choice2==0) dnsip = nic; else dnsip = oarc;
			else if (choice==3) {dnsip = "nofwd"; usedfwd = false;}
			else dnsip = "";
		ipv64struct ipv64;
		ipv64=stub_resolve(domaintmp);
		
		// validation IPv4
		ipbrowser4=ipv64.ipv4;
		if (strcmp (ipbrowser4,"") != 0) {
			resolvipv4 = true; 
			resolvipv6 = false; 
			if (debugoutput) options |= DNSSEC_FLAG_DEBUG;
			if (usedfwd) options |= DNSSEC_FLAG_USEFWD;
			if (resolvipv4) options |= DNSSEC_FLAG_RESOLVIPV4;
			if (resolvipv6) options |= DNSSEC_FLAG_RESOLVIPV6;

				char* ipvalidator4tmp;
				wrong = false;
				EnterCriticalSection(&cs);
				if (debug) ATLTRACE("DNSSEC: IPv4 request: %s, %d, %s, %s\n", domaintmp, options, dnsip, ipbrowser4);
				resultipv4 = dnssec_validate(domaintmp, options, dnsip, ipbrowser4, &ipvalidator4tmp);	
				if (debug) ATLTRACE("DNSSEC: IPv4 result: %s, %d, %s\n", domaintmp, resultipv4, ipvalidator4tmp); 				
				LeaveCriticalSection(&cs);
				if (resultipv4==DNSSEC_COT_DOMAIN_BOGUS) {
				  if (debug) ATLTRACE("DNSSEC: Unbound return bogus state: Testing why?\n");
				  dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();
				  short res = 0 ;
				  res = TestResolver(domaintmp, ipbrowser4, '4');
				  if (res==DNSSEC_COT_DOMAIN_BOGUS) {
					  resultipv4 = 	res;
					  if (debug) ATLTRACE("DNSSEC: Yes, domain name has bogus\n");
					  dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();
				  }
				  else 
				  {					
					if (debug) ATLTRACE("DNSSEC: Current resolver does not support DNSSEC!\n");
					wrong = true;
					resultipv4 = DNSSEC_RESOLVER_NO_DNSSEC;
					dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();
				  } // if bogus				
				} // if bogus
		if (debug) ATLTRACE("-------------------------------------------------------\n");			
		}
		// validation IPv6
		ipbrowser6=ipv64.ipv6;
		if (strcmp (ipbrowser6,"") != 0) {
			resolvipv4 = false; 
			resolvipv6 = true;
			options = 0;
			if (debugoutput) options |= DNSSEC_FLAG_DEBUG;
			if (usedfwd) options |= DNSSEC_FLAG_USEFWD;
			if (resolvipv4) options |= DNSSEC_FLAG_RESOLVIPV4;
			if (resolvipv6) options |= DNSSEC_FLAG_RESOLVIPV6;

				wrong = false;
				EnterCriticalSection(&cs);
				if (debug) ATLTRACE("DNSSEC: IPv6 request: %s, %d, %s, %s\n", domaintmp, options, dnsip, ipbrowser6);
				resultipv6 = dnssec_validate(domaintmp, options, dnsip, ipbrowser6, &ipvalidator6);
				if (debug) ATLTRACE("DNSSEC: IPv6 result: %s, %d, %s\n", domaintmp, resultipv6, ipvalidator6); 
				LeaveCriticalSection(&cs);
				if (resultipv6==DNSSEC_COT_DOMAIN_BOGUS) {
				  if (debug) ATLTRACE("DNSSEC: Unbound return bogus state: Testing why?\n");
				  dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();
				  short res = 0 ;
				  res = TestResolver(domaintmp, ipbrowser6, '6');
				  if (res==DNSSEC_COT_DOMAIN_BOGUS) {
					  resultipv6 = 	res;
					  if (debug) ATLTRACE("DNSSEC: Yes, domain name has bogus\n");
					  dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();
				  }
				  else 
				  {					
					if (debug) ATLTRACE("DNSSEC: Current resolver does not support DNSSEC!\n");
					wrong = true;					
					resultipv6 = DNSSEC_RESOLVER_NO_DNSSEC;
					dnssec_validation_deinit(); dnssec_validation_init(); dane_validation_deinit(); dane_validation_init();
				  } // if bogus
				
				} // if bogus
		if (debug) ATLTRACE("-------------------------------------------------------\n");	
		}
		if (resultipv4 < 0 && resultipv6 >= 0) {
			dnssecresult = resultipv6;
		} else if (resultipv6 < 0 && resultipv4 >= 0) {
			dnssecresult = resultipv4;
		} else {
			if (resultipv4 <= resultipv6) {
				dnssecresult = resultipv6;
			}
			else {
				dnssecresult = resultipv4;
			}
		}

		if (debug) ATLTRACE("DNSSEC: IPv4/IPv6/Overall: %d/%d/%d\n", resultipv4, resultipv6, dnssecresult);
		if (debug) ATLTRACE("*************** DNSSEC validation End *****************\n");
		
		char * port = NULL;
		if (UrlStructData.port==NULL) {
			port="443";
		} else {
			port=UrlStructData.port;
		}

		// tlsa validation
		if (debug) ATLTRACE("\n+++++++++++++++ TLSA validation Start +++++++++++++++\n");

		if (tlsaenable == 1) {
			if (!wrong) {							
				if (strcmp (UrlStructData.protocol,"https") == 0) {
					if (debug) ATLTRACE("DANE: Connection is secured (https/ftps)\n");
					time_t now = time(0);
					int item = cache_find_item(DaneCache, UrlStructData.domainport);
					if (item != NO_ITEM_IN_CACHE) {
						time_t expir = cache_get_expir(DaneCache, item);
						if (now < expir) {	
							tlsaresult = cache_get_tlsaresult(DaneCache, item);
							if (debug) ATLTRACE("DANE: TLSA result used from cache: %s, %i\n",domaintmp, tlsaresult);
							cache_view_all(DaneCache);
						}
						else {
							EnterCriticalSection(&cs);
							const char* certhex[] = {"FF"};
							if (debug) ATLTRACE("DANE: Plugin inputs: %s, %d, %d, %s, %s, %s, %s, %d\n", certhex[0], 0, options, dnsip, domaintmp, port, "tcp", 1);
							tlsaresult = dane_validate(certhex, 0, options, dnsip, domaintmp, port, "tcp", 1);
							if (debug) ATLTRACE("DANE: Plugin result: %s: %d\n", domaintmp, tlsaresult);
							LeaveCriticalSection(&cs);
							cache_update_item(DaneCache, UrlStructData.domainport, port, tlsaresult, false, now + CACHE_EXPIR_TIME, item);
							if (debug) ATLTRACE("DANE: Record in cache was updated...\n");
							cache_view_all(DaneCache);
						}
					}
					else {
						EnterCriticalSection(&cs);
						const char* certhex[] = {"FF"};
						if (debug) ATLTRACE("DANE: plugin inputs: %s, %d, %d, %s, %s, %s, %s, %d\n", certhex[0], 0, options, dnsip, domaintmp, port, "tcp", 1);
						tlsaresult = dane_validate(certhex, 0, options, dnsip, domaintmp, port, "tcp", 1);
						if (debug) ATLTRACE("DANE: plugin result: %s: %d\n", domaintmp, tlsaresult);
						LeaveCriticalSection(&cs);
						cache_add_item(DaneCache, UrlStructData.domainport, port, tlsaresult, false, now + CACHE_EXPIR_TIME);
						if (debug) ATLTRACE("DANE: Result was added into cache...\n");
						cache_view_all(DaneCache);
					}
				} //if
				else {
					tlsaresult = DANE_NO_HTTPS;
					if (debug) {
						ATLTRACE("DANE: Connection is not secured...\n");
						ATLTRACE("DANE: TLSA validation has not been performed...\n");
					}
				}
			} 
			else {
				tlsaresult = DANE_RESOLVER_NO_DNSSEC;
				if (debug) ATLTRACE("DANE: Current resolver does not support DNSSEC...\n");
			}
		} else {
			if (debug) ATLTRACE("DANE: TLSA validation is disable...\n");		
		}
	if (debug) ATLTRACE("+++++++++++++++ TLSA validation End +++++++++++++++++\n\n");
	}
	else {
		dnssecresult = DNSSEC_OFF;
		tlsaresult = DANE_OFF;
	}
	

	//set DNSSEC security status
	strcpy_s(domain, domaintmp);
	SetSecurityDNSSECStatus();
	if (tlsaenable == 1) {
		strcpy_s(tlsapaneldomainname, UrlStructData.protocol);
		strcat_s(tlsapaneldomainname, "://");
		strcat_s(tlsapaneldomainname, UrlStructData.domain);
		if (UrlStructData.port != NULL) {
			strcat_s(tlsapaneldomainname, ":");
			strcat_s(tlsapaneldomainname, UrlStructData.port);
		}
		SetSecurityTLSAStatus();
	}
	RefreshIcons();
	free(UrlStructData.domainport);
	free(domaintmp);	
}

/**************************************************************************/
//to convert URL string on domain name, removed http:\\ 
/**************************************************************************/
short CKBBarBand::TestResolver(char *domain, char *ipbrowser, char IPv) 
{
	short res = 0;
	uint16_t options = 0;
	char* ipvalidator;
	if (debugoutput) options |= DNSSEC_FLAG_DEBUG;
	if (IPv == '4') options |= DNSSEC_FLAG_RESOLVIPV4;
	if (IPv == '6') options |= DNSSEC_FLAG_RESOLVIPV6;
	
	EnterCriticalSection(&cs);
	//if (debug) ATLTRACE("Critical section begin\n");
	if (debug) ATLTRACE("TEST DNSSEC: %s : %d : %s : %s\n", domain, options, "nowfd", ipbrowser);
	res = dnssec_validate(domain, options, "nowfd", ipbrowser, &ipvalidator);
	if (debug) ATLTRACE("TEST DNSSEC result: %d : %s\n", res, ipvalidator); 
	LeaveCriticalSection(&cs);
	return res;
}

void CKBBarBand::ShowFwdTooltip() 
{
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
	

	char tibuf[STR_BUF_SIZE] = TEXT("DNSSEC Upozornìní"); // buffer to store tooltip string
	char tibuf2[STR_BUF_SIZE] = TEXT("Aktuálnì nastavený resolver nepodporuje DNSSEC technologii. Prosím, zmìòte nastavení validátoru."); // buffer to store tooltip string
	ti.lpszText = tibuf2;
	SendMessage(hwndTT, TTM_SETTITLE, TTI_WARNING, (LPARAM) tibuf);
	SendMessage(hwndTT, TTM_UPDATETIPTEXT, 0, (LPARAM) (LPTOOLINFO) &ti);
}

/**************************************************************************/
// Load CA certificate from windows cet store - not used since 2.1.0
/**************************************************************************/
bool CKBBarBand::LoadCaCertFromStore() {

	if (debug) ATLTRACE("\n----------------------------------------------------\n");	
	if (debug) ATLTRACE("LoadCaCertFromStore() call\n");	

	HCERTSTORE hSysStore = NULL;
	if (hSysStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,          // The store provider type
		0,                               // The encoding type is not needed
		NULL,                            // Use the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a registry location
		L"Root"                            // The store name as a Unicode string
   ))
	{
		ATLTRACE("The system store was created successfully.\n");
	}
	else {
		ATLTRACE("An error occurred during creation of the system store!\n");
		return false;
	}

	int i = 0;
	PCCERT_CONTEXT  pCertContext = NULL; 
	//CRYPT_BIT_BLOB  SubjectUniqueId;
	while(pCertContext= CertEnumCertificatesInStore(
      hSysStore,
      pCertContext)) // on the first call to the function,
                     // this parameter is NULL 
                     // on all subsequent calls, 
                     // this parameter is the last pointer 
                     // returned by the function
{
    //----------------------------------------------------------------
    // Do whatever is needed for a current certificate.
	char * cerhex = bintohex(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
	i++;
	LPTSTR outtext = new TCHAR[256];
	CertNameToStr(X509_ASN_ENCODING,&pCertContext->pCertInfo->Subject,CERT_SIMPLE_NAME_STR,outtext,256); 
	ATLTRACE("%i) %s |%lu|\n%s",i, outtext, pCertContext->cbCertEncoded, cerhex);
	ATLTRACE("'\n\n");
} // End of while.

	if(CertCloseStore(
        hSysStore, 
        CERT_CLOSE_STORE_CHECK_FLAG))
{
     ATLTRACE("The file store was closed successfully.\n");
}
else
{
     ATLTRACE("An error occurred during closing of the file store.\n");
}

if (pCertContext)
    CertFreeCertificateContext(pCertContext);

if (debug) ATLTRACE("----------------------------------------------------\n\n");
return true;
}

/**************************************************************************/
// Load settings from the Windows registry
/**************************************************************************/
void CKBBarBand::LoadOptionsFromRegistry(void) {
	
	//if (debug) ATLTRACE("LoadOptionsFromRegistry() call\n");	

	DWORD dwRet;
	HKEY hKey;
	LPTSTR szVal;
	DWORD dwVal;
	HRESULT hr;
	// open DNSSEC Validator registry key if exists
	dwRet = RegOpenKeyEx(HKEY_USERS, HKU_REG_KEY, 0, KEY_QUERY_VALUE, &hKey);
	if (dwRet == ERROR_SUCCESS) {

		//if (debug) ATLTRACE("LoadOptionsFromRegistry() - ERROR_SUCCESS\n");

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
		//if (debug) ATLTRACE("Cannot open DNSSEC Validator's registry key\n");
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
    if (lResult != ERROR_SUCCESS) { 
			free(*lpszResult); 
			return HRESULT_FROM_WIN32(lResult); 
	}
    else if (dwType != REG_SZ)    { 
			free(*lpszResult); return DISP_E_TYPEMISMATCH; 
	}
    // We are not guaranteed a null terminated string from RegQueryValueEx.
    // Explicitly null terminate the returned string...
    (*lpszResult)[(dwBufSize / sizeof(TCHAR)) - 1] = TEXT('\0');
	free(*lpszResult);

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

	//if (debug) ATLTRACE("\nLoadOptionsFromFile\n");
	TCHAR szPath[MAX_PATH];
	char dbserver[IPADDR_MLEN];
	char list[TLD_LIST_MLEN];
	dbserver[0]='\0';
	if (SUCCEEDED( SHGetFolderPath( NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath ))){
		PathAppend( szPath, INI_FILE_PATH);
		GetPrivateProfileString("DNSSEC", "userip", "8.8.8.8", dbserver, IPADDR_MLEN, szPath);
		memcpy(dnssecseradr, dbserver, IPADDR_MLEN);
		tlsaenable = GetPrivateProfileInt("DNSSEC", "tlsaenable", 1 , szPath);
		textkey = GetPrivateProfileInt("DNSSEC", "keytext", 0 , szPath);		
		choice = GetPrivateProfileInt("DNSSEC", "choice", 3 , szPath);
		choice2 = GetPrivateProfileInt("DNSSEC", "choicedns", 0 , szPath);			
		debugoutput = GetPrivateProfileInt("DNSSEC", "debugoutput", 0 , szPath);
		filteron = GetPrivateProfileInt("DNSSEC", "filteron", 0 , szPath);
		GetPrivateProfileString("DNSSEC", "listtld", "", list, TLD_LIST_MLEN, szPath);
		memcpy(listtld, list, TLD_LIST_MLEN);
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
			PathAppend( szPath, _T("\\DNSSEC-TLSA Validator") );
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