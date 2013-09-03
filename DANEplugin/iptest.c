#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ub_dnssec_states.gen"

#include "unbound.h"
#include "ldns/ldns.h"
#include "ldns/packet.h"
#include "ldns/wire2host.h"
#include "openssl/x509.h"
#include "openssl/evp.h"

  #include <netinet/in.h>
  #include <netdb.h>
  #include <sys/types.h>
  #include <sys/socket.h>


//----------------------------------------------------------------------------
#define TA ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"    // DS record of root domain
#define DLV "dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+ cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh" //DNSKEY DLV register
#define DEBUG_PREFIX "DNSSEC: "
#define ERROR_PREFIX "DNSSEC error: "
#define MAX_IPADDRLEN 40              /* max len of IPv4 and IPv6 addr notation */
#define MAX_SRCHLSTLEN 6*256          /* max len of searchlist */
#define FNAME "dnssecval.log"	        /* mane of output log file */
            
//----------------------------------------------------------------------------
typedef struct {                     /* structure to save input options */
  bool debug;                        // debug output enable
  bool usefwd;                       // use of resolver
  bool resolvipv4;                   // IPv4 - validation of A record
  bool resolvipv6;                   // IPv6 - valiadtion of AAAA record
} ds_options;
ds_options opts;

//----------------------------------------------------------------------------
bool ws = false;		       /* write debug info into output file */
bool ds = false;   		     /* load root DS key from file */
bool context = false;		   /* for ub_ctx initialization */
FILE *dfout;			         /* FILE - for debug information*/
struct ub_ctx* ctx;        	// ub context structure
char ip_validator[256];		// return IP address(es) of validator

//*****************************************************************************
/* comparison of IPv6 addresses as structure */
// ----------------------------------------------------------------------------
int ipv6str_equal(const char *lhs, const char *rhs)
{
	int ret;

	struct in6_addr la, ra; /* Left and gight address. */

	ret = inet_pton(AF_INET6, lhs, &la);
	assert(ret == 1);

	ret = inet_pton(AF_INET6, rhs, &ra);
	assert(ret == 1);

	return memcmp(&la, &ra, sizeof(struct in6_addr)) == 0;
}

//*****************************************************************************
/* comparison of IPv6 addresses as string */
// ----------------------------------------------------------------------------
int ipv6str_equal_str(const char *lhs, const char *rhs)
{
	struct sockaddr_in6 la, ra;
	char str[INET6_ADDRSTRLEN];
	char str2[INET6_ADDRSTRLEN];
	// store this IP address in sa:
	inet_pton(AF_INET6, lhs, &(la.sin6_addr));
	inet_pton(AF_INET6, rhs, &(ra.sin6_addr));
	inet_ntop(AF_INET6, &(la.sin6_addr), str, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(ra.sin6_addr), str2, INET6_ADDRSTRLEN);

	return strncmp(str, str2, INET6_ADDRSTRLEN) == 0;
}

//*****************************************************************************
/* read input options into a structure */
// ----------------------------------------------------------------------------
void ds_init_opts(const uint16_t options) {
  opts.debug = options & DNSSEC_INPUT_FLAG_DEBUGOUTPUT;
  opts.usefwd = options & DNSSEC_INPUT_FLAG_USEFWD;
  opts.resolvipv4 = options & DNSSEC_INPUT_FLAG_RESOLVIPV4;
  opts.resolvipv6 = options & DNSSEC_INPUT_FLAG_RESOLVIPV6;
}

//*****************************************************************************
/* get worse value of return code */
// ----------------------------------------------------------------------------
short ds_get_worse_case(const short a, const short b) {
  return (a <= b ? b : a);
}

//*****************************************************************************
// safety strings concatenate funciton
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// match IPs from stub resolver and validator
//  0 : IPs is not equal 
//  1 : IPs is equal
// -1 : IP is not set or any error was detected 
// ----------------------------------------------------------------------------
short ipv6matches(char *ipbrowser, char *ipvalidator)
{
    const char delimiters[] = " ";
    char *token;
    int isequal = 0;

    if (opts.debug) printf(DEBUG_PREFIX "IPmatches: %s %s\n", ipbrowser, ipvalidator);
    if (ws) fprintf(dfout, DEBUG_PREFIX "IPmatches: %s %s\n", ipbrowser, ipvalidator);
    strcpy( ip_validator, ipvalidator );

    if ((ipbrowser != NULL) &&  (ipvalidator != NULL))
      {
        token = strtok (ipvalidator, delimiters);
        if (token==NULL) {			
		return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;
	}
        isequal = ipv6str_equal((const char*)ipbrowser,(const char*)token);
        if (isequal != 0) {
 		return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP;
	}
        while (token != NULL) {                    
            token = strtok (NULL, delimiters);
            if (token==NULL) {
       	        return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;
	    }
            isequal = ipv6str_equal((const char*)ipbrowser,(const char*)token);                       
            if (isequal != 0) {
		return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP;
	    }                  
        }
        return DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP;        
     }
   return DNSSEC_EXIT_FAILED;
}


//*****************************************************************************
// match IPs from stub resolver and validator
//  0 : IPs is not equal 
//  1 : IPs is equal
// -1 : IP is not set or any error was detected 
// ----------------------------------------------------------------------------
short ipv4matches(char *ipbrowser, char *ipvalidator)
{
    const char delimiters[] = " ";
    char *token;
    char* is = NULL;

    if (opts.debug) printf(DEBUG_PREFIX "IPmatches: -%s- -%s-\n", ipbrowser, ipvalidator);
    if (ws) fprintf(dfout, DEBUG_PREFIX "IPmatches: -%s- -%s-\n", ipbrowser, ipvalidator);
    strcpy( ip_validator, ipvalidator );

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

//*****************************************************************************
// return DNSSEC state from response A/AAAA
// ----------------------------------------------------------------------------
short examine_result(struct ub_result *result, char* ipbrowser) {
	  
  int i;
  //struct sockaddr_in6 sa;
  char ipv6[INET6_ADDRSTRLEN];
  short retval;  
  char *ipv4;
  char *ipvalidator;
  retval =  DNSSEC_EXIT_FAILED;
  ipvalidator = "";
 
  // debug
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
                    /* result is secured and bogus not was detected */ 
                   if (result->qtype == LDNS_RR_TYPE_A) {
                       /* A examine result */	
                       for (i=0; result->data[i]; i++) {	
                          ipv4 = inet_ntoa(*(struct in_addr*)result->data[i]);                          
                          ipvalidator = strconcat(ipvalidator,ipv4);
                          ipvalidator = strconcat(ipvalidator," ");
                       } // for                          
                       if (opts.debug) printf(DEBUG_PREFIX "IPv4 address of validator: %s\n", ipvalidator);
                       if (ws) fprintf(dfout, DEBUG_PREFIX "IPv4 address of validator: %s\n", ipvalidator);
		       retval = ipv4matches(ipbrowser,ipvalidator);
                    }
               	    else {
                      /* AAAA examine result */	 
                      for (i=0; result->data[i]; i++) {	
                         inet_ntop(AF_INET6, ((struct in_addr*)result->data[i]), ipv6, INET6_ADDRSTRLEN);
                         ipvalidator = strconcat(ipvalidator,ipv6);
                          ipvalidator = strconcat(ipvalidator," ");                                                   
                     	} // for                      
                     	if (opts.debug) printf(DEBUG_PREFIX "IPv6 address of validator: %s\n", ipvalidator);
                        if (ws) fprintf(dfout, DEBUG_PREFIX "IPv6 address of validator: %s\n", ipvalidator);
			retval = ipv6matches(ipbrowser,ipvalidator);
                    } // result->qtype		    
		    free(ipvalidator);
 	                  // free malloc ipvalidator
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
  
   // for debug
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

//*****************************************************************************
// free ub context (erase cache data from ub context)
// ----------------------------------------------------------------------------
void ub_context_free(){
    if (context==true) { 
      ub_ctx_delete(ctx);
      context = false;
      if (ws) fclose(dfout);
    }
} //ub_context_free


//*****************************************************************************
/* main validating function */
// return status DNSSEC security
// Input: *domain - domain name 
//        options - options of validator, IPv4, IPv6, usefwd, etc..
//        *optdnssrv - IP address of resolver/forvarder
//        *ipbrowser - is IP address of browser which browser used to connection on the server
// Out:	  **ipvalidator - is IP address(es) of validator
// ----------------------------------------------------------------------------
short ds_validate(char *domain, const uint16_t options, char *optdnssrv, char *ipbrowser, char **ipvalidator) {

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

  char* x = "";
  strcpy( ip_validator, x );  

  /* options init - get integer values send from browser */
  ds_init_opts(options);

  // file for debug
  if (ws) dfout = fopen(FNAME, "w+");

  if (opts.debug) printf(DEBUG_PREFIX "Input parameters: \"%s; %u; %s; %s;\"\n", domain, options, optdnssrv, ipbrowser);
  if (ws) fprintf(dfout, "Input parameters: \"%s; %u; %s; %s;\"\n", domain, options, optdnssrv, ipbrowser);

  if (!domain) {
    if (opts.debug) printf(DEBUG_PREFIX "Error: no domain...\n");
    if (ws) fprintf(dfout, DEBUG_PREFIX "Error: no domain...\n");
    return retval;
  }
  
  // if context is not created 
  if (!context) {
    ctx = ub_ctx_create();
	  if(!ctx) {
		    if (opts.debug) printf(DEBUG_PREFIX "Error: could not create unbound context\n");
		    if (ws) fprintf(dfout, DEBUG_PREFIX "Error: could not create unbound context\n");
	  }
    context = true;
  
   // set resolver/forawarder if it was set in options
   if (opts.usefwd) {
     //
     if (strcmp (optdnssrv,"") != 0) {
	     fwd_addr = strtok(optdnssrv, delims);
	     // set ip addresses of resolvers into ub context
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
    // ds true = zone key will be set from file root.key
    //    false = zone key will be set from TA constant
    if (ds) {
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
        if ((ub_retval=ub_ctx_set_option(ctx, "dlv-anchor:", DLV))) {
    		if (opts.debug)	printf(DEBUG_PREFIX "Error adding DLV keys: %s\n", ub_strerror(ub_retval));
        if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding DLV keys: %s\n", ub_strerror(ub_retval));
      }
    } // if (ds)   
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
     /* query for A and AAAA */
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

  /* export resolved addrs buf as static */
  if (ipvalidator) {
    *ipvalidator = ip_validator;
  } else {
    *ipvalidator = "n/a";
  }

  // free resolve context
  ub_resolve_free(result);
  return retval;
} // ds_validate



// for commadline testing
int main(int argc, char **argv)
{
	short i;
	char *tmp = NULL;	
	i = ds_validate(argv[1], 13, "nofwd", "2001:610:188:301:145::2:10", &tmp);
	printf(DEBUG_PREFIX "Returned value: \"%d\" %s\n", i, tmp);				
	return 1;
}

