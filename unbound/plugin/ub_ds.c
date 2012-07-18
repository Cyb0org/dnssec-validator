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

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */

//#include "ldns/config.h"
#include "ldns/ldns.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unbound.h>
#include <errno.h>
#include <arpa/inet.h>

/* Windows */
#ifdef RES_WIN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h> /* for IP Helper API */
  #include <winreg.h>
  #define DWORD_MAX 0xFFFFFFFF
#endif
/* /Windows */

#include "ub_dnssec_states.gen"
//#include "ds.h"

#define DEBUG_PREFIX "DNSSEC: "
#define ERROR_PREFIX "DNSSEC error: "
#define MAX_IPADDRLEN 39             /* max len of IPv4 and IPv6 addr notation */
#define MAX_SRCHLSTLEN 6*256         /* max len of searchlist */

ldns_buffer *addrsbuf;               /* resolved IP address(es) buffer
                                        note: each address must be delimited
                                              (before and after) by a space */

typedef struct {                     /* structure to save input options */
  bool debug;
  bool usetcp;
  bool resolvipv4;
  bool resolvipv6;
} ds_options;

ds_options opts;                     /* options variable */

int context, host, resolv, key = 0;  

struct ub_ctx* ctx;

/* read input options into a structure */
void ds_init_opts(const uint16_t options) {
  opts.debug = options & DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
  opts.usetcp = options & DNSSEC_INPUT_FLAG_USETCP;
  opts.resolvipv4 = options & DNSSEC_INPUT_FLAG_RESOLVIPV4;
  opts.resolvipv6 = options & DNSSEC_INPUT_FLAG_RESOLVIPV6;
}

/* get worse value of return code */
short ds_get_worse_case(const short a, const short b) {
  return (a <= b ? a : b);
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

// match IPs from stub resolver and validator
//  0 : IPs is not equal 
//  1 : IPs is equal
// -1 : IP is not set or error
short ipmatches(char *ipbrowser, char *ipvalidator)
{
    const char delimiters[] = " ";
    char *token;
    char* is = NULL;
    //printf("-%s- -%s-\n",ipbrowser, ipvalidator);
    
    if ((ipbrowser != NULL) &&  (ipvalidator != NULL))
      {
        token = strtok (ipvalidator, delimiters);
        if (token==NULL) return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;
        is = strstr(ipbrowser,(const char*)token);
        if (is!=NULL) return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP;
        while (token != NULL) {                    
            token = strtok (NULL, delimiters);
            if (token==NULL) return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;
            is = strstr(ipbrowser,(const char*)token);                       
            if (is!=NULL) return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP;                  
        }
        return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;        
     }
   return DNSSEC_EXIT_FAILED;
}

short examine_result(char* domain, struct ub_result *result,
                     short qt, char* ipbrowser){

	
  if (opts.debug) printf(DEBUG_PREFIX "Examine result: %s %i %s \n",domain, qt, ipbrowser); 
  
  int i;
  //struct sockaddr_in6 sa;
	char ipv6[INET6_ADDRSTRLEN];
  short retval;  
  char *ipv4;
  char *ipvalidator;
  retval =  DNSSEC_EXIT_FAILED;
  ipvalidator = "";
 
    if (opts.debug) {       	
        printf(DEBUG_PREFIX "qname: %s\n", result->qname);
	      printf(DEBUG_PREFIX "qtype: %d\n", result->qtype);
	      printf(DEBUG_PREFIX "qclass: %d\n", result->qclass);
        printf(DEBUG_PREFIX "DNS rcode: %d\n", result->rcode);
    }

  if (result->rcode != LDNS_RCODE_SERVFAIL ) {
  /* response code is not SERVFAIL */
  
      if  (result->rcode == LDNS_RCODE_NOERROR ) {
         /* response code is NOERROR */             
            
            if  (result->havedata) {                  	
               
                   if (opts.debug) printf(DEBUG_PREFIX "Has data\n");  
                               
                   if (qt == LDNS_RR_TYPE_A) {	
                          for (i=0; result->data[i]; i++) {	
		                          ipv4 = inet_ntoa(*(struct in_addr*)result->data[i]);                          
                              ipvalidator = strconcat(ipvalidator,ipv4);
                              ipvalidator = strconcat(ipvalidator," ");
                          } // for                          
                          if (opts.debug) printf(DEBUG_PREFIX "IPv4 address: %s\n", ipvalidator);                                                                                                        
		                  }
                      else { 
                          for (i=0; result->data[i]; i++) {	
                              inet_ntop(AF_INET6, ((struct in_addr*)result->data[i]), ipv6, INET6_ADDRSTRLEN);
                              ipvalidator = strconcat(ipvalidator,ipv6);
                              ipvalidator = strconcat(ipvalidator," ");                                                   
                          } // for                      
                          if (opts.debug) printf(DEBUG_PREFIX "IPv6 address: %s\n", ipvalidator);
	                    } // if qt 
                    
                      if ((!result->secure) && (!result->bogus)) {            
                              retval = DNSSEC_EXIT_DOMAIN_UNSECURED;          
                      } 
                      else if ((result->secure) && (!result->bogus)) {
                              retval = ipmatches(ipbrowser,ipvalidator);      
                      }
                      else retval = DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS;                                                                                                        
            } //result->havedata      
            else retval = DNSSEC_EXIT_FAILED; // no data                             
      } // LDNS_RCODE_NOERROR
      else
      {
      
          if  (result->rcode != LDNS_RCODE_NXDOMAIN) {
                /* response code is UNKNOWN */
                retval = DNSSEC_EXIT_FAILED;
          }
          else  
          {  /* response code is NXDOMAIN */
              if ((!result->secure) && (!result->bogus)) {            
                    retval = DNSSEC_EXIT_NODOMAIN_UNSECURED;          
              } 
              else if ((result->secure) && (!result->bogus)) {
                      retval = DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID;      
              }
              else retval = DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID;                                       
          } // nxdomain
                          
      } // not LDNS_RCODE_NOERROR      
  
   if (opts.debug) printf(DEBUG_PREFIX "ub-secure: %i\n", result->secure);
   if (opts.debug) printf(DEBUG_PREFIX "ub-bogus: %i\n", result->bogus);  
  
  } // not LDNS_RCODE_SERVFAIL
  else {
    /* response code is SERVFAIL */
    retval = DNSSEC_EXIT_FAILED;
  } // LDNS_RCODE_SERVFAIL
    
  return retval;
}


/* main validating function */
short ds_validate(char *domain, const uint16_t options,
                  char *optdnssrv, char *ipbrowser, uint32_t *ttl4,
                  uint32_t *ttl6) {


  struct ub_result* result;
  int ub_retval;
  short retval;
  short retval_ipv4;
  short retval_ipv6;
  

  retval = DNSSEC_EXIT_FAILED;
  retval_ipv4 = DNSSEC_EXIT_FAILED;
  retval_ipv6 = DNSSEC_EXIT_FAILED;
  ub_retval = 0;
  char ipval[100];

  printf("\n");
  if (!domain) {
    return retval;
  }

  printf(DEBUG_PREFIX "Input parameters: \"%s; %u; %s; %s;\"\n",
                               domain, options, optdnssrv, ipbrowser);
 

  /* options init */
  ds_init_opts(options);


  /* read /etc/resolv.conf for DNS proxy settings (from DHCP) */
//  if( (ub_retval=ub_ctx_resolvconf(ctx, "/etc/resolv.conf")) != 0) {
//	   if (opts.debug) {
//         printf(DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n", 
//			           ub_strerror(ub_retval), strerror(errno));
//    }
//		return retval;
//	}

    /* read /etc/hosts for locally supplied host addresses */
	
  if (!context) {
      ctx = ub_ctx_create();
      context = 1;
  } 
  
  
  if ((ub_retval=ub_ctx_hosts(ctx, "/etc/hosts")) != 0) {
		 if (opts.debug) {
       printf(DEBUG_PREFIX "Error reading hosts: %s. errno says: %s\n", 
			                   ub_strerror(ub_retval), strerror(errno));
      }
  }


    /* read public keys of root zone for DNSSEC verification */
	 if ((ub_retval=ub_ctx_add_ta_file(ctx, "root.key")) != 0) {
      if (opts.debug) { 	
          printf(DEBUG_PREFIX "Error adding keys: %s\n", 
                                ub_strerror(ub_retval));
      }
   }
  
 

    if (optdnssrv) {
        strcpy(ipval, optdnssrv); 
   /* set users resolver IP address */
        if ((ub_retval=ub_ctx_set_fwd(ctx, ipval)) != 0) {
            if (opts.debug) { 	
                printf(DEBUG_PREFIX "Error adding resolver IP address: %s\n",
                               ub_strerror(ub_retval));
            }
		        //return retval;
        }
    }
    else ub_retval = ub_ctx_resolvconf(ctx, "/etc/resolv.conf");
     

	   /* query for webserver */
   ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, &result);
	 
   if(ub_retval != 0) {
		  if (opts.debug) { 
        printf(DEBUG_PREFIX "Resolve error: %s\n", ub_strerror(ub_retval));
      }
		return retval;
	 }
   
   retval_ipv6 = examine_result(domain, result, LDNS_RR_TYPE_AAAA, ipbrowser);
   
  	   /* query for webserver */
   ub_retval = ub_resolve(ctx,
                          domain, 
                          LDNS_RR_TYPE_A /* TYPE A (IPv4 address) */, 
		                      LDNS_RR_CLASS_IN /* CLASS IN (internet) */, 
                          &result);
	 if(ub_retval != 0) {
		  if (opts.debug) { 
        printf(DEBUG_PREFIX "Resolve error: %s\n", ub_strerror(ub_retval));
      }
		return retval;
	 }

   retval_ipv4 = examine_result(domain, result, LDNS_RR_TYPE_A, ipbrowser);

   retval = ds_get_worse_case(retval_ipv4, retval_ipv6);

  if (opts.debug) {
    printf(DEBUG_PREFIX "Returned value (overall/ipv4/ipv6): \"%d/%d/%d\"\n",
           retval, retval_ipv4, retval_ipv6);
  }

  ub_resolve_free(result);
  
  return retval;

}


void main(int argc, char **argv){

  
  short res;
  uint32_t ttl4, ttl6 = 0;
  res = 12;
  int i;
  uint16_t options = 0;

    
  #define URL 12
	char* domain[URL] = {"www.kninice.web4u.cz","unbound.net","www.kninice.cz","unbound.net","www.nic.cz","www.seznam.cz","www.rhybar.cz","www.napul.cz","ipv6.oskarcz.net","www.seznam.cz","www.napul.cz","www.google.cz"};
  char* ip[URL] = {"81.91.86.10","8.8.8.8","8.8.8.8","8.8.8.8","2001:1488:0:3::2","8.8.8.8","8.8.8.8","8.8.8.8","8.8.8.8","8.8.8.8","8.8.8.8","8.8.8.8"};
  
  options |= DNSSEC_INPUT_FLAG_DEBUGOUTPUT;

  // 149.20.64.20    217.31.204.130

    
  for (i=0;i<URL;i++){
    res = ds_validate(domain[i], options, "217.31.204.130" , ip[i] , &ttl4, &ttl6);
    printf(DEBUG_PREFIX "Returned DNSSEC value for %s : %d\n" , domain[i], res);
  }
 
    printf("\n");
}
