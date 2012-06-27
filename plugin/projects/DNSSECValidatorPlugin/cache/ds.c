/* ***** BEGIN LICENSE BLOCK *****
Copyright 2010 CZ.NIC, z.s.p.o.

Authors: Zbynek Michl <zbynek.michl@nic.cz>, Martin Straka <martin.straka@nic.cz> 

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

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */

#include "ldns/config.h"
#include "ldns/ldns.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include "dnssecStates.gen"

/* Windows */
#ifdef RES_WIN
  #include <windows.h>  /* for shared memory */
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h> /* for IP Helper API */
  #include <winreg.h>
  #define DWORD_MAX 0xFFFFFFFF
  #define SM_NAME_LOCAL "Local\\SharedCacheDNSSEC" /* share memory name for Windows*/
#else
  /* /Linux, MAC */  
  #include <sys/ipc.h>
  #include <sys/shm.h>
  #include <sys/sem.h>
  #define SM_KEY  3546      /* share memory name for Linux*/
#endif

#define CACHE_ITEMS_MAX 128                 /* max items in cache */
#define DOMAIN_NAME_LENGTH_MAX 256          /* max lenght of domain name*/
#define IP_ADDRESS_LENGTH_MAX 512           /* max lenght of IPv4/IPv6 buffer*/
#define NO_ITEM_IN_CACHE -99                    
#define DEBUG_PREFIX "dnssec: npapi: "
#define ERROR_PREFIX "dnssec: npapi: error: "
#define MAX_IPADDRLEN 39             /* max len of IPv4 and IPv6 addr notation */
#define MAX_SRCHLSTLEN 6*256         /* max len of searchlist */

ldns_buffer *addrsbuf;               /* resolved IP address(es) buffer
                                        note: each address must be delimited
                                              (before and after) by a space */
char str[INET6_ADDRSTRLEN];

//-----------------------------------------------------------------------------
typedef struct {                     /* structure to save input options */
  bool debug;
  bool usetcp;
  bool resolvipv4;
  bool resolvipv6;
  bool cache_en;
  bool cache_flush; 
  bool ipbrowser;
} ds_options;
ds_options opts;                     /* options variable */

typedef struct {   /* structure to save IPv4/IPv6 address from stub resolver */
  char* ipv4;
  char* ipv6;
} ip64struct;
ip64struct ip64buf;


//----BEGIN of CACHE MEMORY ---------------------------------------------------
// cache data structure
typedef struct CacheEntry {
    char key[DOMAIN_NAME_LENGTH_MAX];
    char ip[IP_ADDRESS_LENGTH_MAX];
    uint32_t ttl4;
    uint32_t ttl6;
    short ipv4;
    short ipv6;
    short overall;
} cache;

// cache controls and array of items 
struct caches{
   short addindex;
   bool lock;  
   cache cachex[CACHE_ITEMS_MAX];
}; 

// get overall DNSSEC status for domain name
short cache_get_overall(struct caches* cache2, int item)
{
	return cache2->cachex[item].overall;
}

// get IPv4 DNSSEC status for domain name
short cache_get_ipv4(struct caches* cache2, int item)
{
	return cache2->cachex[item].ipv4;
}

// get IPv6 DNSSEC status for domain name
short cache_get_ipv6(struct caches* cache2, int item)
{
	return cache2->cachex[item].ipv6;
}

// get TTL4 for A
uint32_t cache_get_ttl4(struct caches* cache2, int item)
{
	return cache2->cachex[item].ttl4;
}

// get TTL6 for AAAA
uint32_t cache_get_ttl6(struct caches* cache2, int item)
{
	return cache2->cachex[item].ttl6;
}

// get IP address
char* cache_get_ip(struct caches* cache2, int item)
{
	return cache2->cachex[item].ip;
}

// update item in cache
void cache_update_item(struct caches* cache2, char* domain, char *ip,uint32_t ttl4, uint32_t ttl6, short ipv4, short ipv6, short overall, int item)
{
   	strcpy(cache2->cachex[item].key, domain);
	  strcpy(cache2->cachex[item].ip, ip);
	  cache2->cachex[item].ttl4 = ttl4;
	  cache2->cachex[item].ttl6 = ttl6;
    cache2->cachex[item].ipv4 = ipv4;
	  cache2->cachex[item].ipv6 = ipv6;
	  cache2->cachex[item].overall = overall;
}

// write all items from cache to debug output
void cache_view_all(struct caches* cache2)
{
   int i = 0;
   while  (i < CACHE_ITEMS_MAX) { 
	   if (strcmp(cache2->cachex[i].key,"")!=0) {
	     printf(" %i: ",i);
	     printf(" %s ",cache2->cachex[i].key);
	     printf(" %s ",cache2->cachex[i].ip);
	     printf(" %i ",cache2->cachex[i].ttl4);
	     printf(" %i ",cache2->cachex[i].ttl6);
	     printf(" %i ",cache2->cachex[i].ipv4);
	     printf(" %i ",cache2->cachex[i].ipv6);
	     printf(" %i\n",cache2->cachex[i].overall);	
	     } // if
	   i++;
   } // while
}

// add item into cache
void cache_add_item(struct caches* cache2, char* domain, char *ip,uint32_t ttl4, uint32_t ttl6, short ipv4, short ipv6, short overall)
{
      if (cache2->addindex < CACHE_ITEMS_MAX-1) cache2->addindex++; 
	    else cache2->addindex = 0;
      strcpy(cache2->cachex[cache2->addindex].key, domain);
      strcpy(cache2->cachex[cache2->addindex].ip, ip);
      cache2->cachex[cache2->addindex].ttl4 = ttl4;
	    cache2->cachex[cache2->addindex].ttl6 = ttl6;
      cache2->cachex[cache2->addindex].ipv4 = ipv4;
	    cache2->cachex[cache2->addindex].ipv6 = ipv6;
	    cache2->cachex[cache2->addindex].overall = overall;
}

// find item in cache
int cache_find_item(struct caches* cache2, char* domain)
{ 
   int up = 0;
   int i;
   int down = CACHE_ITEMS_MAX - 1;
   char tmp[DOMAIN_NAME_LENGTH_MAX];
   strcpy(tmp, domain);   
  
   if (cache2->addindex < (CACHE_ITEMS_MAX/2))
   {     
     for (i=up; i <CACHE_ITEMS_MAX; i++) if (strcmp(cache2->cachex[i].key,tmp)==0) return i;
   }
   else
   {     
     for (i=down; i >=0; i--) if (strcmp(cache2->cachex[i].key,tmp)==0) return i;
   }
   return NO_ITEM_IN_CACHE;
}

// delete one item from cache (not use here)
void cache_delete_item(struct caches* cache2, int item)
{
	strcpy(cache2->cachex[item].key, "");
	strcpy(cache2->cachex[item].ip, "");
  cache2->cachex[item].ttl4 = 0;
	cache2->cachex[item].ttl6 = 0;
  cache2->cachex[item].ipv4 = 0;
	cache2->cachex[item].ipv6 = 0;
	cache2->cachex[item].overall = 0;
}

// delete all items from cache (internal call)
void cache_delete_all(struct caches* cache2)
{
   int i = 0;
   while ((strcmp(cache2->cachex[i].key,"")!=0) && (i < CACHE_ITEMS_MAX))
	{
   	strcpy(cache2->cachex[i].key, "");
  	strcpy(cache2->cachex[i].ip, "");
  	cache2->cachex[i].ttl4 = 0;
    cache2->cachex[i].ttl6 = 0;
    cache2->cachex[i].ipv4 = 0;
	  cache2->cachex[i].ipv6 = 0;
	  cache2->cachex[i].overall = 0;
	  i++;	
	}
 cache2->addindex = -1; 
}

// delete all items from cache (external call)
void cache_delete_all2()
{
    struct caches* cache2;
    
    HANDLE hFileMapping = CreateFileMapping (INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(struct caches), SM_NAME_LOCAL);
    cache2 = (struct caches *) MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
   
   int i = 0;
   while ((strcmp(cache2->cachex[i].key,"")!=0) && (i < CACHE_ITEMS_MAX))
	{
   	strcpy(cache2->cachex[i].key, "");
	  strcpy(cache2->cachex[i].ip, "");
	  cache2->cachex[i].ttl4 = 0;
	  cache2->cachex[i].ttl6 = 0;
    cache2->cachex[i].ipv4 = 0;
	  cache2->cachex[i].ipv6 = 0;
	  cache2->cachex[i].overall = 0;
	  i++;	
	}
  cache2->addindex = -1;
}
//-- END of CACHE ------------------------------------------------------------- 

      
// match IPs from stub resolver and validator
//  0 : IPs is not equal 
//  1 : IPs is equal
// -1 : IP is not set or error
short is_ip_in_resaddrs(char *resaddrs, char *ipstub)
{
    const char delimiters[] = "|";
    char *token;
    char*  is = NULL;

    if ((strcmp ((const char*)resaddrs," ") != 0) &&  (strcmp ((const char*)ipstub,"") != 0))
      {
        token = strtok (ipstub, delimiters);
        if (token==NULL) return 0;
        is = strstr(resaddrs,(const char*)token);
        if (is!=NULL) return 1;
        while (token != NULL) {                    
            token = strtok (NULL, delimiters);
            if (token==NULL) return 0;
            is = strstr(resaddrs,(const char*)token);                       
            if (is!=NULL) return 1;                  
        }
        return 0;        
     }
   return -1;
}


// safety strings concatenate funciton
char *strconcat(char *s1, char *s2)
{
    size_t old_size;
    char *t;
    old_size = strlen(s1);
    t = malloc(old_size + strlen(s2) + 1);
    strcpy(t, s1);
    strcpy(t + old_size, s2);
    return t;
}


// get IPv4/IPv6 address from stub resolver for windows
ip64struct stub_resolve(const char *domain)
{
    DWORD dwRetval;   
    char* retval4 = "";
    char* retval6 = "";
    char* IPv4 = " ";
    #ifdef RES_WIN
    WSADATA wsaData;
    #endif


    ip64buf.ipv4 = retval4;
    ip64buf.ipv6 = retval6;

    #ifdef RES_WIN
    /* initialize WinSock */
    if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
    fprintf(stderr, ERROR_PREFIX "Win: cannot initilize WinSock\n");
    return ip64buf;
    }                          
    #endif

    struct addrinfo *result = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints;
    struct sockaddr_in  *sockaddr_ipv4;
    struct sockaddr_in6 *sockaddr_ipv6;
    const char *  IPv6;
     
    if (opts.debug) printf(DEBUG_PREFIX "Get address from stub resolver (localhost)...\n");

    // Setup the hints address info structure
    // which is passed to the getaddrinfo() function
    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    if (opts.usetcp) {
      hints.ai_protocol = IPPROTO_TCP;
      hints.ai_socktype = SOCK_STREAM;
      }
    else {
      hints.ai_protocol = IPPROTO_UDP;
      hints.ai_socktype = SOCK_DGRAM;
      }

    // Call getaddrinfo(). If the call succeeds,
    // the result variable will hold a linked list
    // of addrinfo structures containing response
    // information
    dwRetval = getaddrinfo(domain, NULL, &hints, &result);
    
    if (opts.debug) {
        if ( dwRetval != 0 ) printf(DEBUG_PREFIX "Getaddrinfo failed with error: %d\n", dwRetval);
        else printf(DEBUG_PREFIX "Getaddrinfo returned success\n");
    }
    
    // Retrieve each address and print out the hex bytes
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {
        switch (ptr->ai_family) {
            case AF_INET:
                sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
                IPv4 = inet_ntoa(sockaddr_ipv4->sin_addr);
                retval4 = strconcat (retval4,IPv4);
                retval4 = strconcat (retval4,"|");                                
                break;
            case AF_INET6:
        				sockaddr_ipv6 = (struct sockaddr_in6 *) ptr->ai_addr;
				        IPv6 = inet_ntop(AF_INET6, &sockaddr_ipv6->sin6_addr,str, INET6_ADDRSTRLEN);                              
                retval6 = strconcat(retval6,str);
                retval6 = strconcat(retval6,"|");
                break;
            default: break;
        }
    }
    ip64buf.ipv4 = retval4;
    ip64buf.ipv6 = retval6;
    
    freeaddrinfo(result);
    
    #ifdef RES_WIN
    WSACleanup();
    #endif
    return ip64buf;
}

/* print buffer content */
void ds_print_buf_info(const ldns_buffer *buf) {

  int i;

  /* print buffer metadata */
  printf("  position: %d; limit: %d; capacity: %d; fixed: %d; status: %d\n",
         (int)buf->_position, (int)buf->_limit, (int)buf->_capacity,
         buf->_fixed, buf->_status);

  /* print buffer data */
  printf("  data: \"");
  for (i = 0; buf->_data[i] != '\0' && i < buf->_limit; i++) {
    putchar(buf->_data[i]);
  }
  printf("\"\n");

}


/* parse and read resolver list and search list from buffers */
short ds_parse_resolver(ldns_resolver **res, ldns_buffer *resbuf,
                        ldns_buffer *srchbuf) {

  ldns_status s;
  ldns_rdf *tmprdf;
  char *token;

  s = LDNS_STATUS_OK;
  tmprdf = NULL;
  token = NULL;

  if (!*res || !resbuf) { /* check input */
    fprintf(stderr, ERROR_PREFIX "ds_parse_resolver() input failed!\n");
    return -1;
  }

  if (opts.debug) {
    printf(DEBUG_PREFIX "Resolver address input parse buffer:\n");
    ds_print_buf_info(resbuf);
  }

  token = malloc(MAX_IPADDRLEN+1);
  if (!token) {
    return -1;
  }

  /* read each IP addr and add it to resolver config */
  while (ldns_bget_token(resbuf, token, " ,;|", MAX_IPADDRLEN+3) > 0) {

    if (opts.debug) printf(DEBUG_PREFIX "DNS addr token: \"%s\"; length: %d\n",
                           token, (int)strlen(token));

    tmprdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, token); /* try IPv6 */
    if (!tmprdf) {
      tmprdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, token);  /* try IPv4 */
    }
    if (!tmprdf) {
      free(token);
      return -1;
    }

    /* use IPv4/IPv6 resolver addresses */
    s = ldns_resolver_push_nameserver(*res, tmprdf);
    if (s != LDNS_STATUS_OK) {
      fprintf(stderr, ERROR_PREFIX "%s\n", ldns_get_errorstr_by_id(s));
      free(token);
      ldns_rdf_deep_free(tmprdf);
      return -1;
    }

    ldns_rdf_deep_free(tmprdf);
  }

  free(token); token = NULL;

  /* parse and read only if searchlist buffer exists */
  if (srchbuf) {

    if (opts.debug) {
      printf(DEBUG_PREFIX "Searchlist input parse buffer:\n");
      ds_print_buf_info(srchbuf);
    }

    token = malloc(LDNS_MAX_DOMAINLEN+1);
    if (!token) {
      return -1;
    }

    /* read each domain name suffix and add it to resolver config */
    while (ldns_bget_token(srchbuf, token, " ,;|", LDNS_MAX_DOMAINLEN+3) > 0) {

      if (opts.debug) printf(DEBUG_PREFIX "Searchlist token: \"%s\"; length: %d\n",
                             token, (int)strlen(token));

      ldns_resolver_push_searchlist(*res, ldns_dname_new_frm_str(token));
    }

    free(token);
  }

  /* finally, add the root domain to the search list */
  /* - this is necessary for querying domain names already in FQDN format */
  ldns_resolver_push_searchlist(*res, ldns_dname_new_frm_str("."));

  return 0;
}

#ifdef RES_WIN
/* Windows: read resolvers and searchlist into buffer from a system */
short ds_read_resolver_win(ldns_buffer *resbuf, ldns_buffer *srchbuf) {

  PIP_ADAPTER_ADDRESSES pAdapterAddresses, pAA;
  ULONG ulFlags;
  DWORD dwRet, dwSize;

  DWORD ipv4index;
  DWORD ipv6index;
  int i;
  PIP_ADAPTER_DNS_SERVER_ADDRESS pDnsServerAddress;
  char szAddress[NI_MAXHOST];
  HKEY hKey;
  char szSearchList[MAX_SRCHLSTLEN];

  ulFlags = GAA_FLAG_SKIP_ANYCAST |
            GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_UNICAST;

  ipv4index = DWORD_MAX;
  ipv6index = DWORD_MAX;

  /* dwSize, which requests the buffer size necessary to store the return
     value, obtains that value */
  dwRet = GetAdaptersAddresses(AF_UNSPEC, ulFlags, NULL, NULL, &dwSize);
  if (dwRet != ERROR_BUFFER_OVERFLOW) {
    fprintf(stderr, ERROR_PREFIX "Win: no enough buffer\n");
    return -1;
  }

  /* allocate a buffer of size dwSize in pAdapterAddresses */
  pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(dwSize);
  if (pAdapterAddresses == NULL) {
    fprintf(stderr, ERROR_PREFIX "Win: no enough buffer\n");
    return -1;
  }

  /* call the GetAdaptersAddresses() function again and obtain the adapter
     information in pAdapterAddresses */
  dwRet = GetAdaptersAddresses(AF_UNSPEC, ulFlags,
                               NULL, pAdapterAddresses, &dwSize);
  if (dwRet != ERROR_SUCCESS) {
    fprintf(stderr, ERROR_PREFIX "Win: GetAdaptersAddresses() failed\n");
    free(pAdapterAddresses);
    return -1;
  }

  /* for each adapter, the variable pAA, which shows adapter information, is
     set to point to an IP_ADAPTER_ADDRESSES instance */
  for (pAA = pAdapterAddresses; pAA; pAA = pAA->Next) {
 
    /* operation status is "up", interface is not "loopback" and interface
       has some resolver address */
    if (pAA->OperStatus == 1 && pAA->IfType != 24 &&
        pAA->FirstDnsServerAddress) {

      /* choose the lowest interface index (preferred adapter)
         0 - IPv4/IPv6 for appropriate adapter is disabled */
      if (pAA->IfIndex < ipv4index && pAA->IfIndex > 0) {
        ipv4index = pAA->IfIndex;
      }
      if (pAA->Ipv6IfIndex < ipv6index && pAA->Ipv6IfIndex > 0) {
        ipv6index = pAA->Ipv6IfIndex;
      }
    }
  }

  if (opts.debug) printf(DEBUG_PREFIX "Win: ipv4index: %u; ipv6index: %u\n",
                         (unsigned int)ipv4index, (unsigned int)ipv6index);

  /* for each adapter, the variable pAA, which shows adapter information, is
     set to point to an IP_ADAPTER_ADDRESSES instance */
  for (pAA = pAdapterAddresses; pAA; pAA = pAA->Next) {

    if (pAA->IfIndex == ipv4index || pAA->Ipv6IfIndex == ipv6index) {

      /* read DNS server addresses using the FirstDnsServerAddress member */
      for (pDnsServerAddress = pAA->FirstDnsServerAddress; pDnsServerAddress;
           pDnsServerAddress = pDnsServerAddress->Next) {
 
          /* convert the address stored in network format (binary)
             into a human-readable character string (presentation format) */
          if (getnameinfo(pDnsServerAddress->Address.lpSockaddr,
                          pDnsServerAddress->Address.iSockaddrLength,
                          szAddress, sizeof(szAddress), NULL, 0,
                          NI_NUMERICHOST)) {
              fprintf(stderr, ERROR_PREFIX
                      "Win: Can't convert network format to presentation format\n");
              free(pAdapterAddresses);
              return -1;
          }

          /* remove zone info from IPv6 address if any */
          for (i = 0; szAddress[i] != '\0'; i++) {
            if (szAddress[i] == '%') {
              szAddress[i] = '\0';
              break;
            }
          }

          /* print DNS server address character string */
          if (opts.debug) printf(DEBUG_PREFIX "Win: DNS server address: %s\n",
                                 szAddress);

          ldns_buffer_printf(resbuf, szAddress);
          ldns_buffer_printf(resbuf, " ");
      }
    }
  }

  /* free the space that was used to store the adapter information */
  free(pAdapterAddresses);

  /* open registry key with network settings that we need */
  dwRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                       "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                       0, KEY_READ, &hKey);
  if (dwRet == ERROR_SUCCESS) {
    /* set maximum available buffer size */
    dwSize = MAX_SRCHLSTLEN;
    /* read custom searchlist value */
    dwRet = RegQueryValueEx(hKey, "SearchList", NULL, NULL, (BYTE*)szSearchList, &dwSize);
    if (dwRet == ERROR_SUCCESS && dwSize > 1) { /* custom searchlist exists and is not empty */
      ldns_buffer_printf(srchbuf, szSearchList); /* save searchlist into the buffer */
    } else {   /* read searchlist obtained by DHCP */
      dwSize = MAX_SRCHLSTLEN; /* set maximum available buffer size */
      dwRet = RegQueryValueEx(hKey, "DhcpDomain", NULL, NULL, (BYTE*)szSearchList, &dwSize);
      if (dwRet == ERROR_SUCCESS && dwSize > 1) { /* DHCP searchlist exists and is not empty */
        ldns_buffer_printf(srchbuf, szSearchList); /* save searchlist into the buffer */
      } else {
        if (opts.debug) printf(DEBUG_PREFIX "Win: Cannot get SearchList nor DhcpDomain value data\n");
      }
    }
    RegCloseKey(hKey);
  } else {
    fprintf(stderr, ERROR_PREFIX "Win: RegOpenKeyEx() failed\n");
    return -1;
  }

  return 0;
}
#endif


/* add resolver address(es) */
short ds_read_resolver(ldns_resolver **res, const char *str) {

  ldns_status s;
  ldns_buffer *resbuf, *srchbuf;

  s = LDNS_STATUS_OK;
  resbuf = NULL;
  srchbuf = NULL;

  if (!res) return -1; /* check input */

  if (!str || str[0] == '\0') { /* str is NULL or empty -> */
                                /* read resolvers from a system */

#ifndef RES_WIN   /* Linux or MACOSX */
    /* create a new resolver from /etc/resolv.conf */
    s = ldns_resolver_new_frm_file(res, NULL);

    if (s != LDNS_STATUS_OK) {
      fprintf(stderr, ERROR_PREFIX "%s\n", ldns_get_errorstr_by_id(s));
      return -1;
    }
#else             /* Windows */

    *res = ldns_resolver_new();
    if (!*res) return -1;

    /* create new address and searchlist buffers */
    resbuf = ldns_buffer_new(LDNS_MIN_BUFLEN);
    srchbuf = ldns_buffer_new(LDNS_MIN_BUFLEN);
    if (!resbuf || !srchbuf) return -1;

    /* put '\0' in them */
    ldns_buffer_printf(resbuf, "");
    ldns_buffer_printf(srchbuf, "");

    /* read resolvers and searchlist into buffers */
    if (ds_read_resolver_win(resbuf, srchbuf) != 0) {
      ldns_buffer_free(resbuf);
      ldns_buffer_free(srchbuf);
      return -1;
    }

    /* make the buffers ready for reading */
    ldns_buffer_flip(resbuf);
    ldns_buffer_flip(srchbuf);

    if (opts.debug) {
      printf(DEBUG_PREFIX "Windows resolver addrs buffer:\n");
      ds_print_buf_info(resbuf);
      printf(DEBUG_PREFIX "Windows searchlist buffer:\n");
      ds_print_buf_info(srchbuf);
    }

    /* parse and read resolvers and searchlist from buffers */
    if (ds_parse_resolver(res, resbuf, srchbuf) != 0) {
      ldns_buffer_free(resbuf);
      ldns_buffer_free(srchbuf);
      return -1;
    }

    ldns_buffer_free(resbuf);
    ldns_buffer_free(srchbuf);
    
#endif

  } else {   /* read user's preferred resolver */

    *res = ldns_resolver_new();
    resbuf = LDNS_MALLOC(ldns_buffer);
    if (!*res || !resbuf) return -1;

    /* read resolvers' string into a buffer */
    ldns_buffer_new_frm_data(resbuf, (char*)str, strlen(str)+1);

    if (opts.debug) {
      printf(DEBUG_PREFIX "Custom resolver addrs buffer:\n");
      ds_print_buf_info(resbuf);
    }

    /* parse and read resolvers from a buffer */
    if (ds_parse_resolver(res, resbuf, NULL) != 0) {
      ldns_buffer_free(resbuf);
      return -1;
    }

    ldns_buffer_free(resbuf);
  }

  return 0;
}


/* read input options into a structure */
void ds_init_opts(const uint16_t options) {
  opts.debug = options & NPAPI_INPUT_FLAG_DEBUGOUTPUT;
  opts.usetcp = options & NPAPI_INPUT_FLAG_USETCP;
  opts.resolvipv4 = options & NPAPI_INPUT_FLAG_RESOLVIPV4;
  opts.resolvipv6 = options & NPAPI_INPUT_FLAG_RESOLVIPV6;
  opts.cache_en = options & NPAPI_INPUT_FLAG_CACHE_ENABLE;
  opts.cache_flush = options & NPAPI_INPUT_FLAG_CACHE_FLUSH;
  opts.ipbrowser = options & NPAPI_INPUT_FLAG_IP_BROWSER_CHECK;
}


/* get RRSIG(s) for given RR from existing packet or extra packet */
short ds_get_rrsiglist(ldns_rr_list **rrs, const ldns_pkt *p, ldns_rdf *n,
                       ldns_rr_type t, const ldns_resolver *r) {

//  ldns_rr_list *rrsigs = NULL;
  ldns_pkt *tmp_p = NULL;

  if ((!rrs || !p || !t || !r) &&          /* check input */
      (!n && (t == LDNS_RR_TYPE_A || t == LDNS_RR_TYPE_AAAA ||
              t == LDNS_RR_TYPE_CNAME))) {
    fprintf(stderr, ERROR_PREFIX "ds_get_rrsiglist() input failed!\n");
    return -1;
  }

//  rrsigs = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_RRSIG,
//                                    LDNS_SECTION_ANSWER);
  *rrs = (n ? ldns_dnssec_pkt_get_rrsigs_for_name_and_type(p, n, t) :
              ldns_dnssec_pkt_get_rrsigs_for_type(p, t));

  if (!*rrs) { /* RRSIG record is not already present in packet, so
                 try to get it explicitly */

    /* send query packet to get RRSIG */
    tmp_p = ldns_resolver_query(r, n, LDNS_RR_TYPE_RRSIG,
                                LDNS_RR_CLASS_IN, LDNS_RD);

    if (tmp_p) {   /* answer packet exists */

      /* get RRSIG record(s) from answer */
//      rrsigs = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_RRSIG,
//                                       LDNS_SECTION_ANSWER);
      *rrs = (n ? ldns_dnssec_pkt_get_rrsigs_for_name_and_type(tmp_p, n, t) :
                  ldns_dnssec_pkt_get_rrsigs_for_type(p, t));

      /* free packet */
      ldns_pkt_free(tmp_p);

    } else {   /* answer packet does not exist */
      fprintf(stderr, ERROR_PREFIX "RRSIG packet failed!\n");
      return -1;
    }
  }

  return 0;
}


/* check RRSIG timestamps */
ldns_status ds_rrsig_check_timestamps(const ldns_rr* rrsig,
                                      const int32_t now) {

  int32_t inception, expiration;

  /* check the signature time stamps */
  inception = (int32_t)ldns_rdf2native_time_t(ldns_rr_rrsig_inception(rrsig));
  expiration = (int32_t)ldns_rdf2native_time_t(ldns_rr_rrsig_expiration(rrsig));

  if (expiration - inception < 0) {
    /* bad sig, expiration before inception?? Tsssg */
    return LDNS_STATUS_CRYPTO_EXPIRATION_BEFORE_INCEPTION;
  }
  if (now - inception < 0) {
    /* bad sig, inception date has not yet come to pass */
    return LDNS_STATUS_CRYPTO_SIG_NOT_INCEPTED;
  }
  if (expiration - now < 0) {
    /* bad sig, expiration date has passed */
    return LDNS_STATUS_CRYPTO_SIG_EXPIRED;
  }

  return LDNS_STATUS_OK;
}


/* get signer's name from RRSIG */
ldns_rdf* ds_get_rrsig_signame(const ldns_rr_list *rrsigs) {

  size_t i;
  ldns_rr *rrsig;

  if (!rrsigs) { /* check input */
    fprintf(stderr, ERROR_PREFIX "ds_get_rrsig_signame() input failed!\n");
    return NULL;
  }

  for (i = 0; i < ldns_rr_list_rr_count(rrsigs); i++) { /* get each RR */

    rrsig = ldns_rr_list_rr(rrsigs, i);

    /* get signer's name from RRSIG with valid timestamp */
    /* or get the name from the last RRSIG - validity will be check later */
    if (ds_rrsig_check_timestamps(rrsig, (int32_t)time(NULL)) == LDNS_STATUS_OK
        || i == ldns_rr_list_rr_count(rrsigs) - 1) {
      return ldns_rr_rrsig_signame(rrsig);
    }
  }
  return NULL;
}


/* get DNSKEY(s) for given RRSIG(s) record from extra packet */
ldns_rr_list* ds_get_keylist(const ldns_rr_list *rrsigs,
                             const ldns_resolver *r) {

  ldns_rr_list *rrs = NULL;
  ldns_pkt *tmp_p = NULL;
  ldns_rdf *sn = NULL;

  if (!rrsigs || !r) { /* check input */
    fprintf(stderr, ERROR_PREFIX "ds_get_keylist() input failed!\n");
    return NULL;
  }

  /* get RRSIG signer's name */
  sn = ds_get_rrsig_signame(rrsigs);
  if (!sn) {
    fprintf(stderr, ERROR_PREFIX "ds_get_rrsig_signame() has no signer's name\n");
    return NULL;
  }

  /* send query packet to get DNSKEY */
  tmp_p = ldns_resolver_query(r, sn, LDNS_RR_TYPE_DNSKEY,
                              LDNS_RR_CLASS_IN, LDNS_RD);

  if (tmp_p) {   /* answer packet exists */

    /* get DNSKEY record(s) from answer */
    rrs = ldns_pkt_rr_list_by_type(tmp_p, LDNS_RR_TYPE_DNSKEY,
                                   LDNS_SECTION_ANSWER);

    /* free packet */
    ldns_pkt_free(tmp_p);

  } else {   /* answer packet does not exist */
    fprintf(stderr, ERROR_PREFIX "DNSKEY packet failed!\n");
    return NULL;
  }

  return rrs;
}


/* get domain name from RRSET */
ldns_rdf* ds_rr_get_rdata2rdf(const ldns_rr_list *rrs) {
  return ldns_rr_rdf(ldns_rr_list_rr(rrs, 0), 0);
}


/* verify RRSIG(s) of RRSET using DNSKEY(s) */
ldns_status ds_rr_verify(ldns_rr_list *rrlist, ldns_rr_list *rrsiglist,
                         const ldns_rr_list *keylist) {

  ldns_status s;
  ldns_rr_list *goodkeylist = NULL;

  if (opts.debug) {
    printf(DEBUG_PREFIX "ldns_verify() input data:\n");
    ldns_rr_list_print(stdout, rrlist);
    ldns_rr_list_print(stdout, rrsiglist);
    ldns_rr_list_print(stdout, keylist);
  }

  /* create new list for good keys */
  goodkeylist = ldns_rr_list_new();

  /* verify RRSIG(s) using DNSKEY(s) */
  s = ldns_verify(rrlist, rrsiglist, keylist, goodkeylist);

  if (opts.debug) {
    printf(DEBUG_PREFIX "ldns_verify() result: %s\n", ldns_get_errorstr_by_id(s));
    printf(DEBUG_PREFIX "goodkeylist:\n");
    ldns_rr_list_print(stdout, goodkeylist);
  }

  /* free list for good keys */
  ldns_rr_list_free(goodkeylist);

  return s;
}


/* check the denial of existence for RR using NSEC and its RRSIG(s) */
ldns_status ds_rr_verify_nsec(ldns_rr *rr, ldns_rr_list *nseclist,
                              ldns_rr_list *rrsiglist) {

  ldns_status s;

  if (opts.debug) {
    printf(DEBUG_PREFIX "ldns_dnssec_verify_denial() input data:\n");
    ldns_rr_print(stdout, rr);
    ldns_rr_list_print(stdout, nseclist);
    ldns_rr_list_print(stdout, rrsiglist);
  }

  /* verify RR */
  s = ldns_dnssec_verify_denial(rr, nseclist, rrsiglist);

  if (opts.debug) {
    printf(DEBUG_PREFIX "ldns_dnssec_verify_denial() result: %s\n",
           ldns_get_errorstr_by_id(s));
  }

  return s;
}


/* check the denial of existence for RR using NSEC3 and its RRSIG(s) */
ldns_status ds_rr_verify_nsec3(ldns_rr *rr, ldns_rr_list *nsec3list,
                               ldns_rr_list *rrsiglist, ldns_pkt_rcode rc,
                               ldns_rr_type qt, bool nodata) {

  ldns_status s;

  if (opts.debug) {
    printf(DEBUG_PREFIX "ldns_dnssec_verify_denial_nsec3() input data:\n");
    ldns_rr_print(stdout, rr);
    ldns_rr_list_print(stdout, nsec3list);
    ldns_rr_list_print(stdout, rrsiglist);
    printf("rc: %s; qt: %s; nodata: %d\n", ldns_pkt_rcode2str(rc),
           ldns_rr_type2str(qt), nodata);
  }

  /* verify RR */
  s = ldns_dnssec_verify_denial_nsec3(rr, nsec3list, rrsiglist, rc, qt, nodata);

  if (opts.debug) {
    printf(DEBUG_PREFIX "ldns_dnssec_verify_denial_nsec3() result: %s\n",
           ldns_get_errorstr_by_id(s));
  }

  return s;
}


/* get worse value of return code */
short ds_get_worse_case(const short a, const short b) {
  return (a <= b ? a : b);
}


/* send query to a resolver and receive reply */
ldns_pkt* ds_resolver_search_query(const ldns_resolver *r, const ldns_rdf *n,
                                   ldns_rr_type t, ldns_rr_class c,
                                   uint16_t f) {
  if (opts.debug) {
    printf(DEBUG_PREFIX "Trying to query domain name: \"%s\"; labels: %d\n",
           ldns_rdf2str(n), ldns_dname_label_count(n));
  }
  return ldns_resolver_query(r, n, t, c, f);
}


/* use search-list for queried domain name */
ldns_pkt* ds_resolver_search(const ldns_resolver *r, const ldns_rdf *name,
                             ldns_rr_type t, ldns_rr_class c, uint16_t flags) {

  ldns_rdf *new_name;
  ldns_rdf **search_list;
  size_t i;
  ldns_pkt *orig_p, *new_p;

  orig_p = NULL;
  new_p = NULL;

  if (ldns_dname_label_count(name) > 1 ||
      (t != LDNS_RR_TYPE_A && t != LDNS_RR_TYPE_AAAA)) { /* query as is */
    orig_p = ds_resolver_search_query(r, name, t, c, flags);
    if (orig_p && ldns_pkt_get_rcode(orig_p) == LDNS_RCODE_NOERROR) {
      return orig_p;
    }
  }

  if (ldns_resolver_dnsrch(r)) { /* query using search-list */
    search_list = ldns_resolver_searchlist(r);
    for (i = 0; i < ldns_resolver_searchlist_count(r); i++) {
      new_name = ldns_dname_cat_clone(name, search_list[i]);
      new_p = ds_resolver_search_query(r, new_name, t, c, flags);
      ldns_rdf_free(new_name);
      if (new_p) {
        if (ldns_pkt_get_rcode(new_p) == LDNS_RCODE_NOERROR) {
          ldns_pkt_free(orig_p);
          return new_p;
        } else {
          ldns_pkt_free(new_p);
        }
      }
    }
  }

  return orig_p;
}


/* validate CNAME and A/AAAA rrsets */
short ds_validate_rrsets(ldns_resolver *res, ldns_rdf *dn,
                         const ldns_rr_type qt, uint32_t *ttl) {

  short retval;                      /* exit status */
  ldns_status s;
  ldns_pkt *ap;                      /* answer packet */
  ldns_rr_list *rrlist;              /* RRset */
  ldns_rr_list *rrsiglist;           /* RRSET of RRSIGs */
  ldns_rr_list *alist;               /* RRSET of As or AAAAs */
  ldns_rr_list *keylist;             /* RRSET of DNSKEYs */
  ldns_rr_list *nseclist;            /* list of NSECs */
  ldns_rr_list *nsec3list;           /* list of NSEC3s */
  ldns_rr *soa;                      /* SOA RR */
  ldns_rr *a;                        /* A/AAAA RR */
  ldns_rdf *tmp_dn;                  /* temp domain name */
  ldns_rdf *new_dn;                  /* domain name got using search-list */
  ldns_rr_type tmp_qt;               /* temp query type */
  short tmp_rv;                      /* temp exit status */
  size_t i;

  /* initialize variables */
  retval = NPAPI_EXIT_FAILED;        /* default exit status */
  s = LDNS_STATUS_OK;
  ap = NULL;
  rrlist = NULL;
  rrsiglist = NULL;
  alist = NULL;
  keylist = NULL;
  nseclist = NULL;
  nsec3list = NULL;
  soa = NULL;
  a = NULL;
  tmp_dn = NULL;
  new_dn = NULL;


//  ldns_resolver_set_debug(res, true);
  if (opts.usetcp) ldns_resolver_set_usevc(res, true); /* use TCP instead of UDP */

  /* set DO flag in EDNS */
  ldns_resolver_set_dnssec(res, true);

  /* send query packet */
  ap = ds_resolver_search(res, dn, qt, LDNS_RR_CLASS_IN, LDNS_RD); // | LDNS_AD

  /* unset DO flag in EDNS */
  ldns_resolver_set_dnssec(res, false);

  if (!ap) {   /* answer packet does not exist */
    fprintf(stderr, ERROR_PREFIX "A/AAAA packet failed!\n");
    goto closure;
  }

  if (opts.debug) {
    printf(DEBUG_PREFIX "--- ap ---\n");
    ldns_pkt_print(stdout, ap);
    printf(DEBUG_PREFIX "--- ap ---\n");
  }

  /* replace old domain name if search-list was used */
  new_dn = ldns_rdf_clone(ldns_rr_owner(ldns_rr_list_rr(ldns_pkt_question(ap), 0)));
  if (new_dn && ldns_dname_label_count(dn) < ldns_dname_label_count(new_dn)) {
    dn = new_dn;
  }

  if (ldns_pkt_get_rcode(ap) != LDNS_RCODE_SERVFAIL) { /* response code is not SERVFAIL */

    if (ldns_pkt_get_rcode(ap) == LDNS_RCODE_NOERROR) { /* response code is NOERROR */

      /* get A (AAAA) record(s) from answer */
      alist = ldns_pkt_rr_list_by_type(ap, qt, LDNS_SECTION_ANSWER);
      if (!alist) {
        fprintf(stderr, ERROR_PREFIX "alist failed (answer)!\n");
        goto closure;
      }

      /* buffer check */
      if (!addrsbuf) {
        fprintf(stderr, ERROR_PREFIX "addrsbuf failed!\n");
        goto closure;
      }

      /* get IP address list and TTL from A (AAAA) record(s) */
      /* RRSIG in answer ensures complete A (AAAA) record(s) list */
      for (i = 0; i < ldns_rr_list_rr_count(alist); i++) { /* get each RR */
        if (i == 0) *ttl = ldns_rr_ttl(ldns_rr_list_rr(alist, i)); /* get TTL of the RRSET */
        ldns_rdf2buffer_str(addrsbuf, ldns_rr_rdf(ldns_rr_list_rr(alist, i), 0)); /* get RDF data */
        ldns_buffer_printf(addrsbuf, " "); /* put delimiter between addresses */
      }

      if (ldns_pkt_ad(ap)) {   /* AD bit is set in answer */
        retval = NPAPI_EXIT_CONNECTION_DOMAIN_SECURED;
      } else {

        tmp_dn = ldns_rdf_clone(dn);
        tmp_qt = qt;
        tmp_rv = NPAPI_EXIT_DOMAIN_SIGNATURE_VALID; /* assume this security state */

        if (opts.debug) {
          printf(DEBUG_PREFIX "Start of RRSET(s) validation...\n");
        }

        /* go through all CNAME and A/AAAA RRSETs and verify their RRSIGs (if any) using DNSKEYs */
        while (((rrlist = ldns_pkt_rr_list_by_name_and_type(ap, tmp_dn, LDNS_RR_TYPE_CNAME, LDNS_SECTION_ANSWER))
                 && (tmp_qt = LDNS_RR_TYPE_CNAME)) ||
               ((rrlist = ldns_pkt_rr_list_by_name_and_type(ap, tmp_dn, qt, LDNS_SECTION_ANSWER))
                 && (tmp_qt = qt))) {

          if (opts.debug) {
            printf(DEBUG_PREFIX "RRSET:\n");
            ldns_rr_list_print(stdout, rrlist);
          }

          /* get RRSIG record(s) from answer */
          if (ds_get_rrsiglist(&rrsiglist, ap, tmp_dn, tmp_qt, res) != 0) {
            fprintf(stderr, ERROR_PREFIX "CNAME/A/AAAA rrsiglist getting failed!\n");
            retval = NPAPI_EXIT_FAILED;
            goto closure;
          }

          if (!rrsiglist) { /* RRSIG does not exist */
            tmp_rv = ds_get_worse_case(tmp_rv, NPAPI_EXIT_DOMAIN_UNSECURED);
          } else {

            /* get DNSKEY record(s) */
            keylist = ds_get_keylist(rrsiglist, res);
            if (!keylist) {
              fprintf(stderr, ERROR_PREFIX "keylist failed!\n");
              retval = NPAPI_EXIT_FAILED;
              goto closure;
            }

            s = ds_rr_verify(rrlist, rrsiglist, keylist);

            if (s == LDNS_STATUS_OK) {
              tmp_rv = ds_get_worse_case(tmp_rv, NPAPI_EXIT_DOMAIN_SIGNATURE_VALID);
            } else {
              tmp_rv = ds_get_worse_case(tmp_rv, NPAPI_EXIT_DOMAIN_SIGNATURE_INVALID);
            }
          }

          /* free used resources */
          ldns_rdf_deep_free(tmp_dn);
          tmp_dn = NULL;
          tmp_dn = ldns_rdf_clone(ds_rr_get_rdata2rdf(rrlist)); /* get next domain name */
          ldns_rr_list_deep_free(rrlist);
          ldns_rr_list_deep_free(rrsiglist);
          ldns_rr_list_deep_free(keylist);
          rrsiglist = keylist = rrlist = NULL;

          /* assign temp return value */
          retval = tmp_rv;

        }

        /* test for AA bit in answer */
        if (ldns_pkt_aa(ap) && retval == NPAPI_EXIT_DOMAIN_SIGNATURE_VALID) {
          retval = NPAPI_EXIT_AUTH_DOMAIN_SIGNATURE_VALID;
        }

        if (opts.debug) {
          printf(DEBUG_PREFIX "...end of RRSET(s) validation\n");
        }

      }

    } else { /* response code is not NOERROR */

      if (ldns_pkt_get_rcode(ap) != LDNS_RCODE_NXDOMAIN) { /* unknown state */
        retval = NPAPI_EXIT_UNKNOWN;
      } else { /* domain name does not exist */

        /* get SOA RR from answer packet */
        soa = ldns_rr_list_rr(ldns_pkt_rr_list_by_type(ap, LDNS_RR_TYPE_SOA,
                                                       LDNS_SECTION_AUTHORITY), 0);

        /* get negative cache TTL from SOA (minimum) */
        if (soa) {
          *ttl = ldns_rdf2native_int32(ldns_rr_rdf(soa, 6));
        }

        if (ldns_pkt_ad(ap)) {
          retval = NPAPI_EXIT_CONNECTION_NODOMAIN_SECURED; /* AD bit is set in answer */
        } else { /* AD bit is not set in answer */

          /* try to get NSEC/NSEC3 from answer */
          nseclist = ldns_pkt_rr_list_by_type(ap, LDNS_RR_TYPE_NSEC,
                                              LDNS_SECTION_AUTHORITY);

          nsec3list = ldns_pkt_rr_list_by_type(ap, LDNS_RR_TYPE_NSEC3,
                                               LDNS_SECTION_AUTHORITY);

          if (nseclist || nsec3list) {
            /* get A (AAAA) record from query section */
            alist = ldns_pkt_rr_list_by_type(ap, qt, LDNS_SECTION_QUESTION);
            if (!alist || !(a = ldns_rr_list_rr(alist, 0))) {
              fprintf(stderr, ERROR_PREFIX "alist failed (question)!\n");
              goto closure;
            }

            if (nseclist) {   /* NSEC */
              /* get RRSIG record(s) from answer */
              if (ds_get_rrsiglist(&rrsiglist, ap, NULL, LDNS_RR_TYPE_NSEC, res) != 0) {
                fprintf(stderr, ERROR_PREFIX "NSEC rrsiglist getting failed!\n");
                goto closure;
              }
              s = ds_rr_verify_nsec(a, nseclist, rrsiglist);
            } else {   /* NSEC3 */
              /* get RRSIG record(s) from answer */
              if (ds_get_rrsiglist(&rrsiglist, ap, NULL, LDNS_RR_TYPE_NSEC3, res) != 0) {
                fprintf(stderr, ERROR_PREFIX "NSEC3 rrsiglist getting failed!\n");
                goto closure;
              }
              s = ds_rr_verify_nsec3(a, nsec3list, rrsiglist, ldns_pkt_get_rcode(ap),
                                     qt, !(bool)ldns_pkt_ancount(ap));
            }

            if (s == LDNS_STATUS_OK) {
              retval = ldns_pkt_aa(ap) ? NPAPI_EXIT_AUTH_NODOMAIN_SIGNATURE_VALID
                                       : NPAPI_EXIT_NODOMAIN_SIGNATURE_VALID;
            } else {
              retval = NPAPI_EXIT_NODOMAIN_SIGNATURE_INVALID;
            }

            /* free used resources */
            ldns_rr_list_deep_free(rrsiglist);

          } else {   /* no NSEC/NSEC3 */
            retval = NPAPI_EXIT_NODOMAIN_UNSECURED;
          }
        }
      }
    }

  } else { /* response code is SERVFAIL */

    /* free old packet */
    ldns_pkt_free(ap);

    /* send query packet with CD flag */
    ap = ldns_resolver_query(res, dn, qt, LDNS_RR_CLASS_IN, LDNS_RD | LDNS_CD);

    if (!ap) {   /* answer packet does not exist */
      fprintf(stderr, ERROR_PREFIX "A/AAAA packet failed (CD)!\n");
      goto closure;
    }

    if (ldns_pkt_get_rcode(ap) != LDNS_RCODE_SERVFAIL) { /* response code is not SERVFAIL */
//        && ldns_pkt_get_rcode(ap) == LDNS_RCODE_NOERROR) { /* response code is NOERROR */

      /* get A (AAAA) record(s) from answer */
      alist = ldns_pkt_rr_list_by_type(ap, qt, LDNS_SECTION_ANSWER);
      if (!alist) {
        fprintf(stderr, ERROR_PREFIX "alist failed!\n");
        goto closure;
      }

      /* read TTL */
      *ttl = ldns_rr_ttl(ldns_rr_list_rr(alist, 0));

      retval = NPAPI_EXIT_CONNECTION_INVSIGDOMAIN_SECURED;
    } else {
      retval = NPAPI_EXIT_UNKNOWN;
    }

  }


closure:

  /* deallocate used resources */
  ldns_pkt_free(ap);
  ldns_rr_list_deep_free(alist);
//  ldns_rr_list_deep_free(rrlist);
//  ldns_rr_list_deep_free(rrsiglist);
//  ldns_rr_list_deep_free(keylist);
  ldns_rr_list_deep_free(nseclist);
  ldns_rr_list_deep_free(nsec3list);
  ldns_rdf_deep_free(new_dn);

  if (opts.debug) printf(DEBUG_PREFIX "All used resources freed\n");

  return retval;

}


/* init resolved address buffer */
short ds_init_resaddrsbuf(void) {

  /* buffer init */
  addrsbuf = ldns_buffer_new(LDNS_MIN_BUFLEN);
  if (!addrsbuf) return -1;

  /* put a space in it */
  ldns_buffer_printf(addrsbuf, " ");

  return 0;
}


/* free resolved address buffer */
void ds_free_resaddrsbuf(void) {
  ldns_buffer_free(addrsbuf);
  addrsbuf = NULL;
}


/* init resolver */
short ds_init_resolver(ldns_resolver **res, const char *optdnssrv) {

  /* read DNS resolver address(es) */
  if (ds_read_resolver(res, optdnssrv) != 0)
    return -1;

  /* set resolver defaults */
//  ldns_resolver_set_dnsrch(*res, false);   /* disable applying search list */
  ldns_resolver_set_random(*res, false);   /* disable random res selection */
  ldns_resolver_set_retrans(*res, 1);      /* time between trying each res */
  (*res)->_timeout.tv_sec = 2;             /* socket timeout */
  ldns_resolver_set_retry(*res,            /* number of trying each res */
                          ldns_resolver_nameserver_count(*res) > 1 ? 1 : 2);
//  ldns_resolver_set_ip6(*res, 0);   /* no IP version preference */

  if (opts.debug) {
    printf(DEBUG_PREFIX "Resolver info:\n");
    ldns_resolver_print(stdout, *res);
  }

  return 0;
}


/* second validating function */
short ds_validate(const char *domain, const uint16_t options,
                  const char *optdnssrv, short isipbrowser, char **resaddrs, uint32_t *ttl4,
                  uint32_t *ttl6, short *ipv4_state, short *ipv6_state) {

  short retval;
  short retval_ipv4;
  short retval_ipv6;
  ldns_rdf *dn;                      /* domain name */
  ldns_resolver *res;                /* resolver address(es) */
#ifdef RES_WIN
  WSADATA wsaData;
#endif

  //stubIP = "";
  retval = NPAPI_EXIT_FAILED;
  retval_ipv4 = NPAPI_EXIT_FAILED;
  retval_ipv6 = NPAPI_EXIT_FAILED;
  dn = NULL;
  res = NULL;
  //*stubIP = NULL;
  *ttl4 = *ttl6 = 0;                 /* IPv4 and IPv6 addresses TTL */
  *ipv4_state = *ipv6_state = 0;

  /* disable stdout buffering if debug info desired */
  if (opts.debug) {
    setbuf(stdout, NULL);
  }
  setbuf(stderr, NULL);

  if (opts.debug) printf(DEBUG_PREFIX "Input parameters: \"%s; %u; %s\"\n",
                               domain, options, optdnssrv);

#ifdef RES_WIN
  /* initialize WinSock */
  if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
    fprintf(stderr, ERROR_PREFIX "Win: cannot initilize WinSock\n");
    return retval;
  }
#endif

  /* create a rdf from the domain input arg */
  dn = ldns_dname_new_frm_str(domain);
  if (!dn) goto closure;

  /* init resolver */
  if (ds_init_resolver(&res, optdnssrv) != 0) goto closure;

  /* resolved address(es) buffer init */
  if (ds_init_resaddrsbuf() != 0) {
    goto closure;
  }


  if (opts.debug) {
    printf(DEBUG_PREFIX "Going to resolve IPv4/IPv6 addrs: \"%d/%d\"\n",
           opts.resolvipv4, opts.resolvipv6);
  }


  if (isipbrowser) {               
      /* resolve desired IPv4 and/or IPv6 RRSET */
      if (!opts.resolvipv4 && opts.resolvipv6) {             /* 0 1 */

          retval_ipv6 = ds_validate_rrsets(res, dn, LDNS_RR_TYPE_AAAA, ttl6);
          retval = retval_ipv6;

      } else if (opts.resolvipv4 && !opts.resolvipv6) {      /* 1 0 */

          retval_ipv4 = ds_validate_rrsets(res, dn, LDNS_RR_TYPE_A, ttl4);
          retval = retval_ipv4;

      } else {                                               /* 0 0 or 1 1 */

          retval_ipv4 = ds_validate_rrsets(res, dn, LDNS_RR_TYPE_A, ttl4);
          retval_ipv6 = ds_validate_rrsets(res, dn, LDNS_RR_TYPE_AAAA, ttl6);
          /* set worse security state according to security priority */
          /* see dnssecIValidator.idl */
          retval = ds_get_worse_case(retval_ipv4, retval_ipv6);
      }
     /* export resolved addrs buf as static */
     if (resaddrs) *resaddrs = ldns_buffer_export(addrsbuf);
  }
  
  else // IP of browser was not set 
  {   
      retval_ipv4 = ds_validate_rrsets(res, dn, LDNS_RR_TYPE_A, ttl4);
      retval_ipv6 = ds_validate_rrsets(res, dn, LDNS_RR_TYPE_AAAA, ttl6);

      *ipv4_state = retval_ipv4;
      *ipv6_state = retval_ipv6;
    
      /* export resolved addrs buf as static */  
      if (resaddrs) *resaddrs = ldns_buffer_export(addrsbuf);
 
      if (retval_ipv4==NPAPI_EXIT_FAILED) {
          // IPv4 return error
          if (retval_ipv6==NPAPI_EXIT_FAILED) retval = NPAPI_EXIT_FAILED;
          else retval = retval_ipv6;
      }
      else if ((retval_ipv6==NPAPI_EXIT_FAILED)) { 
            retval = retval_ipv4; 
      }
      //both IPv4 and IPv6 have any value, return worse case  
      else {
          retval = ds_get_worse_case(retval_ipv4, retval_ipv6);                   
        }   
    }

  if (opts.debug) {
    printf(DEBUG_PREFIX "Resolved IP address buffer: \"%s\"\n", *resaddrs);
    printf(DEBUG_PREFIX "Returned value (overall/ipv4/ipv6): \"%d/%d/%d\"\n",
           retval, retval_ipv4, retval_ipv6);
  }


closure:

  ldns_rdf_deep_free(dn);
  ldns_resolver_deep_free(res);

#ifdef RES_WIN
  /* clean up WinSock */
  WSACleanup();
#endif

  return retval;

}

/* main validating function with cache */
short dnssec_validate(char *domain, const uint16_t options,
                  char *optdnssrv, char *resolvaddrs, char *ipbrowser, short *ipcmpresults) {
	  
    short ipv4_state, ipv6_state, ipv4tmp, ipv6tmp, result = NPAPI_EXIT_FAILED;
    uint32_t ttl4tmp, ttl4, ttl6, ttl6tmp, ttlnowout = 0;
    char * resaddrstmp = "";
    char * ipv4 = "";
    char * ipv6 = "";
    char * resaddrs = "";
    short ipmatch6 = -1;
    short ipmatch4 = -1;
    short isipbrowser = 0;
    int item;
    ip64struct ipv64;
    short ipmatch = -1;
    bool first = false;	

#ifdef RES_WIN // Windows

  struct caches* cache2;
  HANDLE hFileMapping = CreateFileMapping (INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(struct caches), SM_NAME_LOCAL);  
  if(GetLastError()!=ERROR_ALREADY_EXISTS) first=true;
  cache2 = (struct caches *) MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);    
#else // Linux

 struct caches* cache2;
 int shmid;
 if ((shmid = shmget (SM_KEY, sizeof(struct caches), 0666 | IPC_CREATE ) == -1) {
    if (errno != EEXIST) first=true; 
 }
 cache2 = (struct caches *) shmat (shmid, (void*)0, 0);   

#endif
     // first running of modul, init of cache structure
     if (first) {
        cache2->addindex = -1;
        cache2->lock = false; 
    }
    
    /* check input args */
    if (!domain) return result;
                 
    /* options init */
    ds_init_opts(options);

    char tmp[MAX_IPADDRLEN];
    strcpy(tmp, ipbrowser);
    if (strcmp(tmp,"")!=0) isipbrowser = 1;
  
  
    if (opts.cache_en) {

        time_t seconds;
		    seconds = time (NULL);
		    unsigned int ttlnow   =  (unsigned int)(seconds);
		    ttlnowout = ttlnow;
		    if (opts.debug) printf("TIME: %i\n", ttlnowout);	
		    
        // Is item in cache?
		    item = cache_find_item(cache2,domain);
	
        if (item!=NO_ITEM_IN_CACHE) {
           
          ttl4tmp = cache_get_ttl4(cache2,item);
 		      ttl6tmp = cache_get_ttl6(cache2,item);
          ipv4tmp = cache_get_ipv4(cache2,item);
	 	      ipv6tmp = cache_get_ipv6(cache2,item);
          resaddrstmp = cache_get_ip(cache2,item);
          result = cache_get_overall(cache2,item);
          
          if  (ttl6tmp!=0) {
            if (ttl6tmp<seconds)
       			 {
				      // Check and save new dnssec status into cache
				      result = ds_validate(domain, options, optdnssrv, isipbrowser, &resaddrs, &ttl4, &ttl6, &ipv4_state, &ipv6_state);				
              if (ttl4!=0) ttl4 = ttl4 + ttlnow;
				      if (ttl6!=0) ttl6 = ttl6 + ttlnow;
              if (isipbrowser) {
                  ipmatch = is_ip_in_resaddrs(resaddrs,ipbrowser);
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrs;
              }
              else
              {
                  ipv64 = stub_resolve(domain);
      	          ipmatch = is_ip_in_resaddrs(resaddrs,ipv64.ipv6); 
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrs;      
              } 				
				      if (opts.debug) printf("Action: UPD6 | Domain: %s | TTL4: %i | TTL6: %i | IPv4: %i | IPv6: %i | Overall: %i\n", domain, ttl4, ttl6, ipv4_state, ipv6_state, result);			
				      if (opts.debug) printf("Action: UPD6 | Domain: %s | VAL: %s | STUB4: %s | STUB6: %s | COMP64: %d\n", domain, resaddrs, ipv4, ipv6, ipmatch);
              cache_update_item(cache2,domain, resaddrs, ttl4, ttl6, ipv4_state, ipv6_state, result, item);   
				      ds_free_resaddrsbuf();
              //return result; 
			        }
			       else
			       {	
              if (opts.debug) printf("Action: RCA6 | Domain: %s | TTL4: %i | TTL6: %i | IPv4: %i | IPv6: %i | Overall: %i\n", domain, ttl4tmp, ttl6tmp, ipv4tmp, ipv6tmp, result);
              if (isipbrowser) {
                  ipmatch = is_ip_in_resaddrs(resaddrstmp,ipbrowser);
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrstmp;
              }
              else
              {
                  ipv64 = stub_resolve(domain);
      	          ipmatch = is_ip_in_resaddrs(resaddrstmp,ipv64.ipv6);   
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrstmp;      
              }               
              if (opts.debug) printf("Action: RCA6 | Domain: %s | VAL: %s | STUB4: %s | STUB6: %s | COMP64: %d\n", domain, resaddrstmp, ipv64.ipv4, ipv64.ipv6, ipmatch6);              
			       }   
           } 
          if (ipmatch!=-1) return result;  
    
          if  (ttl4tmp!=0) {
            if (ttl4tmp<seconds)
       			 {
				      // Check and save new dnssec status into cache
				      result = ds_validate(domain, options, optdnssrv, isipbrowser, &resaddrs, &ttl4, &ttl6, &ipv4_state, &ipv6_state);								      
              if (ttl4!=0) ttl4 = ttl4 + ttlnow;
				      if (ttl6!=0) ttl6 = ttl6 + ttlnow;
              if (isipbrowser) {
                  ipmatch = is_ip_in_resaddrs(resaddrs,ipbrowser);
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrs;
              }
              else
              {
                  ipv64 = stub_resolve(domain);  
			            ipmatch = is_ip_in_resaddrs(resaddrs,ipv64.ipv4);
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrs;      
              } 		
				      if (opts.debug) printf("Action: UPD4 | Domain: %s | TTL4: %i | TTL6: %i | IPv4: %i | IPv6: %i | Overall: %i\n", domain, ttl4, ttl6, ipv4_state, ipv6_state, result);			
				      if (opts.debug) printf("Action: UPD4 | Domain: %s | VAL: %s | STUB4: %s | STUB6: %s | COMP64: %d\n", domain, resaddrs, ipv4, ipv6, ipmatch);
              cache_update_item(cache2,domain, resaddrs, ttl4, ttl6, ipv4_state, ipv6_state, result, item);    
				      ds_free_resaddrsbuf();
              return result; 
			        }
			       else
			       {	
              if (opts.debug) printf("Action: RCA4 | Domain: %s | TTL4: %i | TTL6: %i | IPv4: %i | IPv6: %i | Overall: %i\n", domain, ttl4tmp, ttl6tmp, ipv4tmp, ipv6tmp, result);
              if (isipbrowser) {
                  ipmatch = is_ip_in_resaddrs(resaddrstmp,ipbrowser);
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrstmp;
              }
              else
              {
                  ipv64 = stub_resolve(domain);
			            ipmatch = is_ip_in_resaddrs(resaddrstmp,ipv64.ipv4);
                  *ipcmpresults = ipmatch;
                  resolvaddrs = resaddrstmp;      
              } 	              
              if (opts.debug) printf("Action: RCA4 | Domain: %s | VAL: %s | STUB4: %s | STUB6: %s | COMP64: %d\n", domain, resaddrstmp, ipv64.ipv4, ipv64.ipv6, ipmatch4);              
              return result; 
			       }// if TTL4 or TTL6 is invalidate
            }
            return result; 
           /*} */ // IPv4 IPv6		
		} // item is in cache
		else
		{
			// ADD item into cache
			result = ds_validate(domain, options, optdnssrv, isipbrowser, &resaddrs, &ttl4, &ttl6, &ipv4_state, &ipv6_state);			
			if (ttl4!=0) ttl4 = ttl4 + ttlnow;
			if (ttl6!=0) ttl6 = ttl6 + ttlnow;			
      if (isipbrowser) {
         ipmatch = is_ip_in_resaddrs(resaddrs,ipbrowser);
         *ipcmpresults = ipmatch;
         resolvaddrs = resaddrs;
      }
      else
      {
         ipv64 = stub_resolve(domain);
      	 ipmatch6 = is_ip_in_resaddrs(resaddrs,ipv64.ipv6);  
			   ipmatch4 = is_ip_in_resaddrs(resaddrs,ipv64.ipv4);
         if (ipmatch4<=ipmatch6) ipmatch = ipmatch6;
         else ipmatch = ipmatch4;	 
         *ipcmpresults = ipmatch;
         resolvaddrs = resaddrs;      
      }  
      
      if (opts.debug) printf("Action: ADD | Domain: %s | TTL4: %i | TTL6: %i | IPv4: %i | IPv6: %i | Overall: %i\n", domain, ttl4, ttl6, ipv4_state, ipv6_state, result);	
      if (opts.debug) printf("Action: ADD | Domain: %s | VAL: %s | STUB4: %s | STUB6: %s | COMP64: %d\n", domain, resaddrs, ipv4, ipv6, ipmatch);     
      cache_add_item(cache2, domain, resaddrs, ttl4, ttl6, ipv4_state, ipv6_state, result);
			ds_free_resaddrsbuf();
      return result; 
		} //item is not in cache;                  
    
   }//cache enable
   
   
   
   else //cache disable
   {   
      result = ds_validate(domain, options, optdnssrv, isipbrowser, &resaddrs, &ttl4, &ttl6, &ipv4_state, &ipv6_state);
      if (isipbrowser) {
         ipmatch = is_ip_in_resaddrs(resaddrs,ipbrowser);
         *ipcmpresults = ipmatch;
         resolvaddrs = resaddrs;
      }
      else
      {
         ipv64 = stub_resolve(domain);
      	 ipmatch6 = is_ip_in_resaddrs(resaddrs,ipv64.ipv6);  
			   ipmatch4 = is_ip_in_resaddrs(resaddrs,ipv64.ipv4);
         if (ipmatch4<=ipmatch6) ipmatch = ipmatch6;
         else ipmatch = ipmatch4;	 
         *ipcmpresults = ipmatch;
         resolvaddrs = resaddrs;      
      }      
      if (opts.debug) printf("Action: N/A | Domain: %s | TTL4: %i | TTL6: %i | IPv4: %i | IPv6: %i | Overall: %i\n", domain, ttl4, ttl6, ipv4_state, ipv6_state, result);	
      if (opts.debug) printf("Action: N/A | Domain: %s | VAL: %s | STUB4: %s | STUB6: %s | COMP64: %d\n", domain, resaddrs, ipv4, ipv6, ipmatch);
      ds_free_resaddrsbuf();
      return result;                  
   } //cache disable              
}
