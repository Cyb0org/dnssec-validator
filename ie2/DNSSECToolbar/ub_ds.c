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

//----------------------------------------------------------------------------
#include "ldns/config.h"
#include "ldns/ldns.h"
#include "libunbound/unbound.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include "ub_dnssec_states.gen"

/* Windows */
#ifdef RES_WIN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h> /* for IP Helper API */
  #include <winreg.h>
  #define DWORD_MAX 0xFFFFFFFF
#else
/* Linux */
 #include <arpa/inet.h>
#endif

//----------------------------------------------------------------------------
#define TA ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"
#define DEBUG_PREFIX "DNSSEC: "
#define ERROR_PREFIX "DNSSEC error: "
#define MAX_IPADDRLEN 40             /* max len of IPv4 and IPv6 addr notation */
#define MAX_SRCHLSTLEN 6*256         /* max len of searchlist */
#define FNAME "dnssecval.log"	     /* mane of output log file */
            
//----------------------------------------------------------------------------
typedef struct {                     /* structure to save input options */
  bool debug;
  bool usefwd;
  bool resolvipv4;
  bool resolvipv6;
} ds_options;

ds_options opts;
//----------------------------------------------------------------------------
bool ws = false;		     /* write debug info into output file */
bool ds = false;   		     /* load root DS key from file */
bool context = false;		     /* for ub_ctx initialization */
FILE *dfout;			     /* FILE */
struct ub_ctx* ctx;

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
/* read input options into a structure */
void ds_init_opts(const uint16_t options) {
  opts.debug = options & DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
  opts.usefwd = options & DNSSEC_INPUT_FLAG_USEFWD;
  opts.resolvipv4 = options & DNSSEC_INPUT_FLAG_RESOLVIPV4;
  opts.resolvipv6 = options & DNSSEC_INPUT_FLAG_RESOLVIPV6;
}

/* get worse value of return code */
short ds_get_worse_case(const short a, const short b) {
  return (a <= b ? b : a);
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

    if (opts.debug) printf(DEBUG_PREFIX "IPmatches: -%s- -%s-\n", ipbrowser, ipvalidator);
    if (ws) fprintf(dfout, DEBUG_PREFIX "IPmatches: -%s- -%s-\n", ipbrowser, ipvalidator);
    
    if ((ipbrowser != NULL) &&  (ipvalidator != NULL))
      {
        token = strtok (ipvalidator, delimiters);
        if (token==NULL) {			
		return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;
		}
        is = strstr(ipbrowser,(const char*)token);
        if (is!=NULL) {
 		return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP;
		}
        while (token != NULL) {                    
            token = strtok (NULL, delimiters);
            if (token==NULL) {
       	        return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;
		}
            is = strstr(ipbrowser,(const char*)token);                       
            if (is!=NULL) {
		return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP;
		}                  
        }
        return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;        
     }
   return DNSSEC_EXIT_FAILED;
}


// set DNSSEC state from response on query
short examine_result(struct ub_result *result, char* ipbrowser) {
	  
  int i;
  //struct sockaddr_in6 sa;
  char ipv6[INET6_ADDRSTRLEN];
  short retval;  
  char *ipv4;
  char *ipvalidator;
  retval =  DNSSEC_EXIT_FAILED;
  ipvalidator = "";
 
  if (opts.debug) printf(DEBUG_PREFIX "Examine result: %s %i %i %i %s \n", result->qname, result->qtype, result->qclass, result->rcode, ipbrowser); 
  if (ws) fprintf(dfout, DEBUG_PREFIX "Examine result: %s %i %i %i %s \n", result->qname, result->qtype, result->qclass, result->rcode, ipbrowser);

  if (result->rcode != LDNS_RCODE_SERVFAIL ) {
  /* response code is not SERVFAIL */
  
      if  (result->rcode == LDNS_RCODE_NOERROR ) {
         /* response code is NOERROR */             
            
            if  (result->havedata) {                  	
               
                   if (opts.debug) printf(DEBUG_PREFIX "Has data\n");  
                   if (ws) fprintf(dfout, DEBUG_PREFIX "Has data\n");
                                                   
                      if ((!result->secure) && (!result->bogus)) {            
                              retval = DNSSEC_EXIT_DOMAIN_UNSECURED;          
                      } 
                      else if ((result->secure) && (!result->bogus)) {

	                   if (result->qtype == LDNS_RR_TYPE_A) {	
                             for (i=0; result->data[i]; i++) {	
	                        ipv4 = inet_ntoa(*(struct in_addr*)result->data[i]);                          
                                ipvalidator = strconcat(ipvalidator,ipv4);
                                ipvalidator = strconcat(ipvalidator," ");
                              } // for                          
                              if (opts.debug) printf(DEBUG_PREFIX "IPv4 address of validator: %s\n", ipvalidator);
                              if (ws) fprintf(dfout, DEBUG_PREFIX "IPv4 address of validator: %s\n", ipvalidator);
		            }
                      	    else { 
                              for (i=0; result->data[i]; i++) {	
                                inet_ntop(AF_INET6, ((struct in_addr*)result->data[i]), ipv6, INET6_ADDRSTRLEN);
                                ipvalidator = strconcat(ipvalidator,ipv6);
                                ipvalidator = strconcat(ipvalidator," ");                                                   
                          	} // for                      
                          	if (opts.debug) printf(DEBUG_PREFIX "IPv6 address of validator: %s\n", ipvalidator);
                                if (ws) fprintf(dfout, DEBUG_PREFIX "IPv6 address of validator: %s\n", ipvalidator);
	                     } // result->qtype

                            retval = ipmatches(ipbrowser,ipvalidator);
			    free(ipvalidator);      
                      }
                      else { 
                        if (opts.debug) printf(DEBUG_PREFIX "Why bogus?: %s\n", result->why_bogus);
                        if (ws) fprintf(dfout, DEBUG_PREFIX "Why bogus?: %s\n", result->why_bogus);

			retval = DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS; 
		      }
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
   if (ws) fprintf(dfout, DEBUG_PREFIX "ub-secure: %i\n", result->secure);
   if (opts.debug) printf(DEBUG_PREFIX "ub-bogus: %i\n", result->bogus);
   if (ws) fprintf(dfout, DEBUG_PREFIX "ub-bogus: %i\n", result->bogus);  
  
  } // not LDNS_RCODE_SERVFAIL
  else {
    /* response code is SERVFAIL */
    retval = DNSSEC_EXIT_FAILED;
  } // LDNS_RCODE_SERVFAIL

  return retval;
}

// free ub context (erase cache data)
void ub_context_free(){
    if (context==true) { 
      ub_ctx_delete(ctx);
      context = false;
      if (ws) fclose(dfout);
    }
} //ub_context_free

/* main validating function */
short ds_validate(char *domain, const uint16_t options, char *optdnssrv, char *ipbrowser) {

  struct ub_result* result;
  int ub_retval;
  short retval;
  short retval_ipv4;
  short retval_ipv6;
  char *fwd_addr;
  char delims[] = " ";

  retval = DNSSEC_EXIT_FAILED;
  retval_ipv4 = DNSSEC_EXIT_FAILED;
  retval_ipv6 = DNSSEC_EXIT_FAILED;
  ub_retval = 0;  

  /* options init */
  ds_init_opts(options);

  if (ws) dfout = fopen(FNAME, "w+");

  if (opts.debug) printf(DEBUG_PREFIX "Input parameters: \"%s; %u; %s; %s;\"\n", domain, options, optdnssrv, ipbrowser);
  if (ws) fprintf(dfout, "Input parameters: \"%s; %u; %s; %s;\"\n", domain, options, optdnssrv, ipbrowser);

  if (!domain) {
    if (opts.debug) printf(DEBUG_PREFIX "Error: no domain...\n");
    if (ws) fprintf(dfout, DEBUG_PREFIX "Error: no domain...\n");
    return retval;
  }
  
 // if (!context) ub_context_init(ds, optdnssrv);

  if (!context) {


    ctx = ub_ctx_create();
	  if(!ctx) {
		    if (opts.debug) printf(DEBUG_PREFIX "Error: could not create unbound context\n");
		    if (ws) fprintf(dfout, DEBUG_PREFIX "Error: could not create unbound context\n");
	  }
    context = true;
  
   if (opts.usefwd) {
      if (strcmp (optdnssrv,"") != 0) {
	   fwd_addr = strtok(optdnssrv, delims);
	   while (fwd_addr != NULL) {
		if ((ub_retval=ub_ctx_set_fwd(ctx, optdnssrv)) != 0) {
		   if (opts.debug) printf(DEBUG_PREFIX "Error adding resolver IP address: %s\n", ub_strerror(ub_retval));
  		   if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding resolver IP address: %s\n", ub_strerror(ub_retval));
		} //if            	  
	    	fwd_addr = strtok(NULL, delims);
	   } //while
  	}  
    	else {
       	    if ((ub_retval = ub_ctx_resolvconf(ctx, NULL)) != 0) {
        	if (opts.debug)	printf(DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n", ub_strerror(ub_retval), strerror(errno));
	        if (ws)	fprintf(dfout, DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n", ub_strerror(ub_retval), strerror(errno));
            }   
      	}
    } // if (opts.usefwd)
  
        /* read public keys of root zone for DNSSEC verification */
    if (ds) {
	// !!! problem s nacitami souboru s klicem !!!!     
	if ((ub_retval=ub_ctx_add_ta_file(ctx, "root.key")) != 0) {
        if (opts.debug)	printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
        if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
      }
   }
   else {
     	if ((ub_retval=ub_ctx_add_ta(ctx, TA)) != 0) {
        if (opts.debug)	printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
        if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
      }
    }   
   
 }

	if (opts.resolvipv6 && !opts.resolvipv4) {
        /* query for AAAA only*/    
        ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, &result);
        if(ub_retval != 0) {
		        if (opts.debug) printf(DEBUG_PREFIX "Resolve error AAAA: %s\n", ub_strerror(ub_retval));
		        if (ws) fprintf(dfout, DEBUG_PREFIX "Resolve error AAAA: %s\n", ub_strerror(ub_retval));
	      return retval;
	      }
        retval_ipv6 = examine_result(result, ipbrowser);
        retval = retval_ipv6;
   }
   else if (!opts.resolvipv6 && opts.resolvipv4) {
       /* query for A only */
       ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, &result);
	     if(ub_retval != 0) {
		      if (opts.debug) printf(DEBUG_PREFIX "Resolve error A: %s\n", ub_strerror(ub_retval));
		      if (ws) fprintf(dfout, DEBUG_PREFIX "Resolve error A: %s\n", ub_strerror(ub_retval));
	        return retval;
       }
       retval_ipv4 = examine_result(result, ipbrowser);
       retval = retval_ipv4; 
   }
   else {
       ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, &result);
       if(ub_retval != 0) {
		        if (opts.debug) printf(DEBUG_PREFIX "Resolve error AAAA: %s\n", ub_strerror(ub_retval));
		        if (ws) fprintf(dfout, DEBUG_PREFIX "Resolve error AAAA: %s\n", ub_strerror(ub_retval));
	          return retval;
	      }
        retval_ipv6 = examine_result(result, ipbrowser);
       
        ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, &result);
	      if(ub_retval != 0) {
		      if (opts.debug) printf(DEBUG_PREFIX "Resolve error A: %s\n", ub_strerror(ub_retval));
		      if (ws) fprintf(dfout, DEBUG_PREFIX "Resolve error A: %s\n", ub_strerror(ub_retval));
	        return retval;
        }
        retval_ipv4 = examine_result(result, ipbrowser);
       
        retval = ds_get_worse_case(retval_ipv4, retval_ipv6);
    }
  
  if (opts.debug) printf(DEBUG_PREFIX "Returned value (overall/ipv4/ipv6): \"%d/%d/%d\"\n", retval, retval_ipv4, retval_ipv6);
  if (ws) fprintf(dfout, DEBUG_PREFIX "Returned value (overall/ipv4/ipv6): \"%d/%d/%d\"\n", retval, retval_ipv4, retval_ipv6);

  ub_resolve_free(result);
  return retval;
}
