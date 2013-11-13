/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors: Martin Straka <martin.straka@nic.cz>

This file is part of DNSSEC Validator 2.0 Add-on.

DNSSEC Validator 2.0 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator 2.0 Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.0 Add-on.  If not, see <http://www.gnu.org/licenses/>.

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
//----------------------------------------------------------------------------
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include "dnssec-states.gen"


#ifdef RES_WIN
/* Windows */
#include "ldns/config.h"
#include "ldns/ldns.h"
#include "libunbound/unbound.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <winreg.h>
#else
/* Linux */
#include "unbound.h"
#include "ldns/ldns.h"
#include "ldns/packet.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif

//----------------------------------------------------------------------------
#define TA ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"    // DS record of root domain
#define DLV "dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+ cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh" //DNSKEY DLV register
#define DEBUG_PREFIX "DNSSEC: "
#define ERROR_PREFIX "DNSSEC error: "
#define MAX_IPADDRLEN 40          /* max len of IPv4 and IPv6 addr notation */
#define MAX_SRCHLSTLEN (6 * 256)  /* max len of searchlist */

//----------------------------------------------------------------------------
typedef struct {                     /* structure to save input options */
	bool debug;                        // debug output enable
	bool usefwd;                       // use of resolver
	bool resolvipv4;                   // IPv4 - validation of A record
	bool resolvipv6;                   // IPv6 - valiadtion of AAAA record
	bool ds;  
} ds_options;
ds_options opts;

//----------------------------------------------------------------------------

static struct ub_ctx* ctx = NULL;     // ub context structure
char ip_validator[256]; // return IP address(es) of validator

static
int printf_debug(const char *fmt, ...)
  __attribute__((format(printf, 1, 2)));

//*****************************************************************************
/* debug output function */
// ----------------------------------------------------------------------------
static
int printf_debug(const char *fmt, ...)
{
	va_list argp;
	int ret = 0;

	if (opts.debug && (fmt != NULL)) {
		va_start(argp, fmt);

		fputs(DEBUG_PREFIX, stderr);
		ret = vfprintf(stderr, fmt, argp);

		va_end(argp);
	}

	return ret;
}

//*****************************************************************************
/* comparison of IPv6 addresses as structure */
// ----------------------------------------------------------------------------
static
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

#if 0
//*****************************************************************************
/* comparison of IPv6 addresses as string */
// ----------------------------------------------------------------------------
static
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
#endif

//*****************************************************************************
/* read input options into a structure */
// ----------------------------------------------------------------------------
static
void ds_init_opts(const uint16_t options)
{
	opts.debug = options & DNSSEC_FLAG_DEBUG;
	opts.usefwd = options & DNSSEC_FLAG_USEFWD;
	opts.resolvipv4 = options & DNSSEC_FLAG_RESOLVIPV4;
	opts.resolvipv6 = options & DNSSEC_FLAG_RESOLVIPV6;
	opts.ds = false;
}

//*****************************************************************************
/* get worse value of return code */
// ----------------------------------------------------------------------------
static
short ds_get_worse_case(const short a, const short b)
{
	return (a <= b ? b : a);
}

//*****************************************************************************
// safe string concatenation funciton
// ----------------------------------------------------------------------------
static
char * strconcat(const char *s1, const char *s2)
{
	size_t s1_size = 0,
	       s2_size = 0;
	char *t = NULL;

	if (s1 != NULL) {
		s1_size = strlen(s1);
	}
	if (s2 != NULL) {
		s2_size = strlen(s2);
	}
	if ((s1_size + s2_size) > 0) {
		t = malloc(s1_size + s2_size + 1);
		if (t == NULL) {
			return NULL; /* Allocation error. */
		}
		if (s1 != NULL) {
			strcpy(t, s1);
		}
		if (s2 != NULL) {
			strcpy(t + s1_size, s2);
		}
	}
	return t;
}

//*****************************************************************************
// match IPs from stub resolver and validator
//  0 : IPs is not equal
//  1 : IPs is equal
// -1 : IP is not set or any error was detected
// ----------------------------------------------------------------------------
static
short ipv6matches(const char *ipbrowser, const char *ipvalidator)
{
	const char delimiters[] = " ";
	char *token;
	int isequal = 0;

	printf_debug("IP matches: %s %s\n", ipbrowser, ipvalidator);
	strcpy(ip_validator, ipvalidator);

	if ((ipbrowser != NULL) && (ipbrowser[0] != '\0') &&
	    (ipvalidator != NULL) && (ipvalidator[0] != '\0')) {
		size_t size = strlen(ipvalidator) + 1;
		char *str_cpy = malloc(size);
		if (str_cpy == NULL) {
			return DNSSEC_ERROR_GENERIC;
		}
		memcpy(str_cpy, ipvalidator, size);
		token = strtok(str_cpy, delimiters);
		if (token == NULL) {
			free(str_cpy);
			return DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
		}
		isequal = ipv6str_equal(ipbrowser, token);
		if (isequal != 0) {
			free(str_cpy);
			return DNSSEC_COT_DOMAIN_SECURED;
		}
		while (token != NULL) {
			token = strtok(NULL, delimiters);
			if (token == NULL) {
				free(str_cpy);
				return DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
			}
			isequal = ipv6str_equal(ipbrowser, token);
			if (isequal != 0) {
				free(str_cpy);
				return DNSSEC_COT_DOMAIN_SECURED;
			}
		}
		free(str_cpy);
		return DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
	}
	return DNSSEC_ERROR_GENERIC;
}


//*****************************************************************************
// match IPs from stub resolver and validator
//  0 : IPs is not equal
//  1 : IPs is equal
// -1 : IP is not set or any error was detected
// ----------------------------------------------------------------------------
static
short ipv4matches(const char *ipbrowser, const char *ipvalidator)
{
	const char delimiters[] = " ";
	char *token;
	char* is = NULL;

	printf_debug("IP matches: %s %s\n", ipbrowser, ipvalidator);
	strcpy(ip_validator, ipvalidator);

	if ((ipbrowser != NULL) && (ipbrowser[0] != '\0') &&
	    (ipvalidator != NULL) && (ipvalidator[0] != '\0')) {
		size_t size = strlen(ipvalidator) + 1;
		char *str_cpy = malloc(size);
		if (str_cpy == NULL) {
			return DNSSEC_ERROR_GENERIC;
		}
		memcpy(str_cpy, ipvalidator, size);
		token = strtok(str_cpy, delimiters);
		if (token == NULL) {
			free(str_cpy);
			return DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
		}
		is = strstr(ipbrowser, token);
		if (is != NULL) {
			free(str_cpy);
			return DNSSEC_COT_DOMAIN_SECURED;
		}
		while (token != NULL) {
			token = strtok(NULL, delimiters);
			if (token == NULL) {
				free(str_cpy);
				return DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
			}
			is = strstr(ipbrowser, token);
			if (is != NULL) {
				free(str_cpy);
				return DNSSEC_COT_DOMAIN_SECURED;
			}
		}
		free(str_cpy);
		return DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
	}
	return DNSSEC_ERROR_GENERIC;
}

//*****************************************************************************
// return DNSSEC state from response A/AAAA
// ----------------------------------------------------------------------------
static
short examine_result(const struct ub_result *ub_res, const char *ipbrowser)
{
	int i;
	//struct sockaddr_in6 sa;
	char ipv6[INET6_ADDRSTRLEN];
	short retval;
	char *ipv4;
	char *ipvalidator = NULL,
	     *ipvalidator_old = NULL;
	retval = DNSSEC_ERROR_GENERIC;

	printf_debug("Examine result: %s %i %i %i %s \n",
	    ub_res->qname, ub_res->qtype, ub_res->qclass,
	    ub_res->rcode, ipbrowser);

	if (ub_res->rcode == LDNS_RCODE_SERVFAIL) {
		/* response code is SERVFAIL */
		return DNSSEC_ERROR_RESOLVER;
	}

	/* response code is not SERVFAIL */
	if (ub_res->rcode == LDNS_RCODE_NOERROR ) {
		/* response code is NOERROR */

		if (ub_res->havedata) {

			printf_debug("Has data\n");

			if ((!ub_res->secure) && (!ub_res->bogus)) {
				retval = DNSSEC_DOMAIN_UNSECURED;
			} else if ((ub_res->secure) &&
			           (!ub_res->bogus)) {
				/* Result is secured and bogus wasn't
				 * detected. */
				if (ub_res->qtype == LDNS_RR_TYPE_A) {
					/* A examine result */
					for (i=0; ub_res->data[i]; i++) {
						ipv4 = inet_ntoa(*(const struct in_addr *) ub_res->data[i]);
						ipvalidator_old = ipvalidator;
						ipvalidator = strconcat(ipvalidator_old,ipv4);
						free(ipvalidator_old);
						ipvalidator_old = ipvalidator;
						ipvalidator = strconcat(ipvalidator_old," ");
						free(ipvalidator_old);
					}
					printf_debug("IPv4 address of validator: %s\n",
					    ipvalidator);
					retval = ipv4matches(ipbrowser, ipvalidator);
				} else {
					/* AAAA examine result */
					for (i=0; ub_res->data[i]; i++) {
						inet_ntop(AF_INET6, ((const struct in_addr *) ub_res->data[i]), ipv6, INET6_ADDRSTRLEN);
						ipvalidator_old = ipvalidator;
						ipvalidator = strconcat(ipvalidator_old,ipv6);
						free(ipvalidator_old);
						ipvalidator_old = ipvalidator;
						ipvalidator = strconcat(ipvalidator_old," ");
						free(ipvalidator_old);
					}
					printf_debug("IPv6 address of validator: %s\n",
					    ipvalidator);
					retval = ipv6matches(ipbrowser, ipvalidator);
				} // ub_res->qtype
				free(ipvalidator);
				// free malloc ipvalidator
			} else {
				printf_debug("Why bogus?: %s\n",
				    ub_res->why_bogus);
				retval = DNSSEC_COT_DOMAIN_BOGUS;
			}

			//ub_res->havedata
		} else {
			retval = DNSSEC_ERROR_RESOLVER; // no data
		}

		// LDNS_RCODE_NOERROR
	} else {
		if (ub_res->rcode != LDNS_RCODE_NXDOMAIN) {
			/* response code is UNKNOWN */
			retval = DNSSEC_ERROR_RESOLVER;
		} else { /* response code is NXDOMAIN */
			if ((!ub_res->secure) && (!ub_res->bogus)) {
				retval = DNSSEC_NXDOMAIN_UNSECURED;
			} else if ((ub_res->secure) &&
			           (!ub_res->bogus)) {
				retval = DNSSEC_NXDOMAIN_SIGNATURE_VALID;
			} else {
				retval = DNSSEC_NXDOMAIN_SIGNATURE_INVALID;
			}
		} // nxdomain
	} // not LDNS_RCODE_NOERROR

	printf_debug("ub-secure: %i\n", ub_res->secure);
	printf_debug("ub-bogus: %i\n", ub_res->bogus);

	return retval;
}

//*****************************************************************************
// free ub context (erase cache data from ub context)
// ----------------------------------------------------------------------------
void ub_context_free(void)
{
	if (ctx != NULL) {
		ub_ctx_delete(ctx);
		ctx = NULL;
	}
}


//*****************************************************************************
/* main validating function */
// return status DNSSEC security
// Input: *domain - domain name
//        options - options of validator, IPv4, IPv6, usefwd, etc..
//        *optdnssrv - IP address of resolver/forvarder
//        *ipbrowser - is IP address of browser which browser used to connection on the server
// Out:   **ipvalidator - is IP address(es) of validator
// ----------------------------------------------------------------------------
short ds_validate(const char *domain, const uint16_t options,
    const char *optdnssrv, const char *ipbrowser, char **ipvalidator)
{
	struct ub_result *ub_res;
	int ub_retval;
	short retval;
	short retval_ipv4;
	short retval_ipv6;
	char *fwd_addr;
	char delims[] = " ";

	retval = DNSSEC_ERROR_GENERIC;
	retval_ipv4 = DNSSEC_OFF;
	retval_ipv6 = DNSSEC_OFF;
	ub_retval = 0;

	char *x = "";
	strcpy(ip_validator, x);

	/* options init - get integer values send from browser */
	ds_init_opts(options);

	printf_debug("Input parameters: \"%s; %u; %s; %s;\"\n",
	    domain, options, optdnssrv, ipbrowser);

	if ((domain == NULL) || (domain[0] == '\0')) {
		printf_debug("Error: no domain...\n");
		return retval;
	}

	// if context is not created
	if (ctx == NULL) {
		ctx = ub_ctx_create();
		if (ctx == NULL) {
			printf_debug("Error: could not create unbound context\n");
			return retval; /* DNSSEC_ERROR_GENERIC */
		}

		// set resolver/forawarder if it was set in options
		if (opts.usefwd) {

			if (strcmp(optdnssrv, "") != 0) {
				size_t size = strlen(optdnssrv) + 1;
				char *str_cpy = malloc(size);
				if (str_cpy == NULL) {
					return DNSSEC_ERROR_GENERIC;
				}
				memcpy(str_cpy, optdnssrv, size);
				fwd_addr = strtok(str_cpy, delims);
				// set ip addresses of resolvers into ub context
				while (fwd_addr != NULL) {
					printf_debug("Adding resolver IP address '%s'\n",
					    fwd_addr);
					ub_retval = ub_ctx_set_fwd(ctx,
					    fwd_addr);
					if (ub_retval != 0) {
						printf_debug("Error adding resolver IP address '%s': %s\n",
						    fwd_addr,
						    ub_strerror(ub_retval));
						free(str_cpy);
						return retval; /* DNSSEC_ERROR_GENERIC */
					}
					fwd_addr = strtok(NULL, delims);
				} //while
				free(str_cpy);
			} else {
				printf_debug("Using system resolver.\n");
				ub_retval = ub_ctx_resolvconf(ctx, NULL);
				if (ub_retval != 0) {
					printf_debug("Error reading resolv.conf: %s. errno says: %s\n",
					    ub_strerror(ub_retval),
					    strerror(errno));
					return retval; /* DNSSEC_ERROR_GENERIC */
				}
			}
		} // if (opts.usefwd)

		/* read public keys of root zone for DNSSEC verification */
		// ds true = zone key will be set from file root.key
		//    false = zone key will be set from TA constant
		if (opts.ds) {
			ub_retval = ub_ctx_add_ta_file(ctx, "root.key");
			if (ub_retval != 0) {
				printf_debug("Error adding keys: %s\n",
				    ub_strerror(ub_retval));
				return retval; /* DNSSEC_ERROR_GENERIC */
			}
		} else {
			ub_retval = ub_ctx_add_ta(ctx, TA);
			if (ub_retval != 0) {
				printf_debug("Error adding keys: %s\n",
				    ub_strerror(ub_retval));
				return retval; /* DNSSEC_ERROR_GENERIC */
			}
			ub_retval = ub_ctx_set_option(ctx, "dlv-anchor:", DLV);
			if (ub_retval != 0) {
				printf_debug("Error adding DLV keys: %s\n",
				    ub_strerror(ub_retval));
				return retval; /* DNSSEC_ERROR_GENERIC */
			}
		}
	}

	if (opts.resolvipv6 && !opts.resolvipv4) {
		/* query for AAAA only*/
		ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_AAAA,
		    LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug("Resolve error AAAA: %s\n",
			    ub_strerror(ub_retval));
			return retval; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv6 = examine_result(ub_res, ipbrowser);
		retval = retval_ipv6;
		ub_resolve_free(ub_res);
	} else if (!opts.resolvipv6 && opts.resolvipv4) {
		/* query for A only */
		ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_A,
		    LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug("Resolve error A: %s\n",
			    ub_strerror(ub_retval));
			return retval; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv4 = examine_result(ub_res, ipbrowser);
		retval = retval_ipv4;
		ub_resolve_free(ub_res);
	} else {
		/* query for A and AAAA */
		ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_AAAA,
		    LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug("Resolve error AAAA: %s\n",
			    ub_strerror(ub_retval));
			return retval; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv6 = examine_result(ub_res, ipbrowser);
		ub_resolve_free(ub_res);

		ub_retval = ub_resolve(ctx, domain, LDNS_RR_TYPE_A,
		    LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug("Resolve error A: %s\n",
			    ub_strerror(ub_retval));
			return retval; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv4 = examine_result(ub_res, ipbrowser);
		retval = ds_get_worse_case(retval_ipv4, retval_ipv6);
		ub_resolve_free(ub_res);
	}

	printf_debug("Returned value (overall/ipv4/ipv6): \"%d/%d/%d\"\n",
	    retval, retval_ipv4, retval_ipv6);

	/* export resolved addrs buf as static */
	if (ipvalidator != NULL) {
		*ipvalidator = ip_validator;
	}

	return retval;
}


#ifdef CMNDLINE_TEST

// for commadline testing
int main(int argc, char **argv)
{
	char *dname = NULL;
	short i;
	char *tmp = NULL;
	uint16_t options;

	char resolver_addresses[256];
	// Must be taken through writeable buffer.
	// TODO -- Modify it so it can take constant string literals.
	strcpy(resolver_addresses,
	    ""
	    " 8.8.8.8"
	    " 217.31.204.130"
//	    " 193.29.206.206"
	    );

	if (argc != 2) {
		fprintf(stderr, "Usage\n\t%s dname\n", argv[0]);
		return 1;
	}

	dname = argv[1];

	options =
	    DNSSEC_FLAG_DEBUG |
	    DNSSEC_FLAG_USEFWD |
	    DNSSEC_FLAG_RESOLVIPV4 |
	    DNSSEC_FLAG_RESOLVIPV6;

	i = ds_validate(dname, options, resolver_addresses,
	    "2001:610:188:301:145::2:10", &tmp);
	printf(DEBUG_PREFIX "Returned value: \"%d\" %s\n", i, tmp);
	ub_context_free();
	return 0;
}

#endif /* CMNDLINE_TEST */
