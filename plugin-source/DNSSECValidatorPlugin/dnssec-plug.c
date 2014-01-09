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

#include "dnssec-plug.h"
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
#define DEBUG_OUTPUT stderr
#define DEBUG_PREFIX "DNSSEC: "
#define ERROR_PREFIX "DNSSEC error: "
#define MAX_IPADDRLEN 40          /* max len of IPv4 and IPv6 addr notation */
#define MAX_SRCHLSTLEN (6 * 256)  /* max len of search list */

//----------------------------------------------------------------------------
struct ds_options_st { /* structure to save input options */
	bool debug;                        // debug output enable
	bool usefwd;                       // use of resolver
	bool resolvipv4;                   // IPv4 - validation of A record
	bool resolvipv6;                   // IPv6 - validation of AAAA record
	bool ds;  
};

//----------------------------------------------------------------------------

/* TODO -- Fixed size buffer. Writes don't check the buffer size. In some
 * cases buffer overflow may occur. */
char ip_validated[256]; // holds resolved and validated IP address(es)

/* DANE validation context. */
struct dnssec_validation_ctx {
	struct ds_options_st opts; /* Options. */
	struct ub_ctx *ub; /*
	                    * Unbound context.
	                    * Initialised outside the context initialisation
	                    * procedure.
	                    */
};
static
struct dnssec_validation_ctx glob_val_ctx = {
	{false, false, false, false, false}, NULL
};

static
int printf_debug(const char *pref, const char *fmt, ...)
  __attribute__((format(printf, 2, 3)));

//*****************************************************************************
/* debug output function */
// ----------------------------------------------------------------------------
static
int printf_debug(const char *pref, const char *fmt, ...)
{
	va_list argp;
	int ret = 0;

	if (glob_val_ctx.opts.debug && (fmt != NULL)) {
		va_start(argp, fmt);

		if (pref != NULL) {
			fputs(pref, DEBUG_OUTPUT);
		} else {
			fputs(DEBUG_PREFIX, DEBUG_OUTPUT);
		}
		ret = vfprintf(DEBUG_OUTPUT, fmt, argp);

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
	struct in6_addr la, ra; /* Left and right address. */

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
void ds_init_opts(struct ds_options_st *opts, const uint16_t options)
{
	opts->debug = options & DNSSEC_FLAG_DEBUG;
	opts->usefwd = options & DNSSEC_FLAG_USEFWD;
	opts->resolvipv4 = options & DNSSEC_FLAG_RESOLVIPV4;
	opts->resolvipv6 = options & DNSSEC_FLAG_RESOLVIPV6;
	opts->ds = false;
}

//*****************************************************************************
/* get worse value of return code */
// ----------------------------------------------------------------------------
static
short ds_get_worse_case(const short a, const short b)
{
	return (a <= b ? b : a);
}

#if 0
//*****************************************************************************
// safe string concatenation function
// Returns NULL on error or when both input parameters are NULL.
// Returns newly allocated string containing concatenated input data.
// ----------------------------------------------------------------------------
static
char * strcat_clone(const char *s1, const char *s2)
{
	size_t s1_size = 0,
	       s2_size = 0;
	char *cat = NULL;

	if (s1 != NULL) {
		s1_size = strlen(s1);
	}

	if (s2 != NULL) {
		s2_size = strlen(s2);
	}

	if ((s1 != NULL) || (s2 != NULL)) {
		cat = malloc(s1_size + s2_size + 1);
		if (cat == NULL) {
			return NULL; /* Allocation error. */
		}

		if (s1_size > 0) {
			memcpy(cat, s1, s1_size);
		}

		if (s2_size > 0) {
			memcpy(cat + s1_size, s2, s2_size);
		}

		cat[s1_size + s2_size] = '\0';
	}

	return cat;
}
#endif

//*****************************************************************************
// safe string concatenation function
// Returns NULL on error or when both input parameters are NULL.
// Returns newly allocated string containing concatenated input data.
// If both strings are non-empty then a joiner character will be inserted
// between them.
// ----------------------------------------------------------------------------
static
char * strcat_join_clone(const char *s1, char joiner, const char *s2)
{
	size_t s1_size = 0,
	       s2_size = 0;
	char *cat = NULL;

	assert(joiner != '\0');

	if (s1 != NULL) {
		s1_size = strlen(s1);
	}

	if (s2 != NULL) {
		s2_size = strlen(s2);
	}

	if ((s1_size > 0) && (s2_size > 0)) {
		/* Both strings. */
		cat = malloc(s1_size + s2_size + 2);
		if (cat == NULL) {
			return NULL; /* Allocation error. */
		}

		memcpy(cat, s1, s1_size);
		cat[s1_size] = joiner;
		memcpy(cat + s1_size + 1, s2, s2_size);
		cat[s1_size + s2_size + 1] = '\0';
	} else if ((s1 != NULL) || (s2 != NULL)) {
		/* Only one string. */
		cat = malloc(s1_size + s2_size + 1);
		if (cat == NULL) {
			return NULL; /* Allocation error. */
		}

		if (s1_size > 0) {
			memcpy(cat, s1, s1_size);
		}

		if (s2_size > 0) {
			memcpy(cat + s1_size, s2, s2_size);
		}

		cat[s1_size + s2_size] = '\0';
	}

	return cat;
}

//*****************************************************************************
// match IPs from stub resolver and validator
//  0 : IPs is not equal
//  1 : IPs is equal
// -1 : IP is not set or any error was detected
// ----------------------------------------------------------------------------
static
short ipv6matches(const char *ipbrowser, const char *ipvalidator,
    const char *delimiters)
{
	char *token;
	int isequal = 0;

	printf_debug(NULL, "IP matches: %s %s\n", ipbrowser, ipvalidator);
	strcpy(ip_validated, ipvalidator);

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
short ipv4matches(const char *ipbrowser, const char *ipvalidator,
    const char *delimiters)
{
	char *token;
	char *is = NULL;

	printf_debug(NULL, "IP matches: %s %s\n", ipbrowser, ipvalidator);
	strcpy(ip_validated, ipvalidator);

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
	     *aux_str = NULL;
	retval = DNSSEC_ERROR_GENERIC;

	printf_debug(NULL, "Examine result: %s %i %i %i %s \n",
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

			printf_debug(NULL, "Has data\n");

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
						aux_str = ipvalidator;
						ipvalidator =
						    strcat_join_clone(aux_str, ' ', ipv4);
						free(aux_str);
					}
					printf_debug(NULL, "IPv4 address of validator: %s\n",
					    ipvalidator);
					retval = ipv4matches(ipbrowser, ipvalidator, " ");
				} else {
					/* AAAA examine result */
					for (i=0; ub_res->data[i]; i++) {
						inet_ntop(AF_INET6, ((const struct in_addr *) ub_res->data[i]), ipv6, INET6_ADDRSTRLEN);
						aux_str = ipvalidator;
						ipvalidator =
						    strcat_join_clone(aux_str, ' ', ipv6);
						free(aux_str);
					}
					printf_debug(NULL, "IPv6 address of validator: %s\n",
					    ipvalidator);
					retval = ipv6matches(ipbrowser, ipvalidator, " ");
				} // ub_res->qtype
				free(ipvalidator);
				// free malloc ipvalidator
			} else {
				printf_debug(NULL, "Why bogus?: %s\n",
				    ub_res->why_bogus);
				retval = DNSSEC_COT_DOMAIN_BOGUS;
			}

			//ub_res->havedata
		} else {
			retval = DNSSEC_UNBOUND_NO_DATA; // no data
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

	printf_debug(NULL, "ub-secure: %i\n", ub_res->secure);
	printf_debug(NULL, "ub-bogus: %i\n", ub_res->bogus);

	return retval;
}


//*****************************************************************************
// Initialises Unbound resolver
//
// opts         - options
// optdnssrv    - list of IP resolver addresses separated by space
// err_code_ptr - error code
//
// Returns pointer to new resolver context, NULL if fails.
// If NULL returned then err_code is set if given
// ----------------------------------------------------------------------------
static
struct ub_ctx * unbound_resolver_init(const struct ds_options_st *opts,
    const char *optdnssrv, int *err_code_ptr)
{
	struct ub_ctx *ub = NULL;
	int err_code = DNSSEC_ERROR_RESOLVER;
	int ub_retval;

	ub = ub_ctx_create();
	if(ub == NULL) {
		printf_debug(DEBUG_PREFIX,
		    "Error: could not create unbound context\n");
		goto fail;
	}

	/* Set resolver/forwarder if it was set in options. */
	if (opts->usefwd) {
		if ((optdnssrv != NULL) && (optdnssrv[0] != '\0')) {
			size_t size = strlen(optdnssrv) + 1;
			char *str_cpy = malloc(size);
			const char *fwd_addr;
			const char *delims = " ";
			if (str_cpy == NULL) {
				err_code = DNSSEC_ERROR_GENERIC;
				goto fail;
			}
			memcpy(str_cpy, optdnssrv, size);
			fwd_addr = strtok(str_cpy, delims);
			/* Set IP addresses of resolvers into ub context. */
			while (fwd_addr != NULL) {
				printf_debug(DEBUG_PREFIX,
				    "Adding resolver IP address '%s'\n",
				    fwd_addr);
				ub_retval = ub_ctx_set_fwd(ub, fwd_addr);
				if (ub_retval != 0) {
					printf_debug(DEBUG_PREFIX,
					    "Error adding resolver IP address '%s': %s\n",
					    fwd_addr, ub_strerror(ub_retval));
					free(str_cpy);
					goto fail;
				}
				fwd_addr = strtok(NULL, delims);
			}
			free(str_cpy);
		} else {
			printf_debug(DEBUG_PREFIX,
			    "Using system resolver.\n");
			ub_retval = ub_ctx_resolvconf(ub, NULL);
			if (ub_retval != 0) {
				printf_debug(DEBUG_PREFIX,
				    "Error reading resolv.conf: %s. errno says: %s\n",
				    ub_strerror(ub_retval),
				    strerror(errno));
				goto fail;
			}
		}
	}

	/*
	// set debugging verbosity
	ub_ctx_debugout(ub, DEBUG_OUTPUT);
	if (ub_retval != 0) {
		printf_debug(DEBUG_PREFIX,
		    "Error setting debugging output.\n");
		goto fail;
	}
	ub_retval = ub_ctx_debuglevel(ub, 5);
	if (ub_retval != 0) {
		printf_debug(DEBUG_PREFIX,
		    "Error setting verbosity level.\n");
		goto fail;
	}
	*/

	/*
	 * Read public keys of root zone for DNSSEC verification.
	 * ds true = zone key will be set from file root.key
	 *    false = zone key will be set from TA constant
	 */
	if (opts->ds) {
		ub_retval = ub_ctx_add_ta_file(ub, "root.key");
		if (ub_retval != 0) {
			printf_debug(DEBUG_PREFIX, "Error adding keys: %s\n",
			    ub_strerror(ub_retval));
			goto fail;
		}
	} else {
		ub_retval = ub_ctx_add_ta(ub, TA);
		if (ub_retval != 0) {
			printf_debug(DEBUG_PREFIX, "Error adding keys: %s\n",
			    ub_strerror(ub_retval));
			goto fail;
		}
		/* Set dlv-anchor.
		 * (TODO -- This location differs from DANE validation.
		 * Why?) */
		ub_retval = ub_ctx_set_option(ub, "dlv-anchor:", DLV);
		if (ub_retval != 0) {
			printf_debug(DEBUG_PREFIX,
			    "Error adding DLV keys: %s\n",
			    ub_strerror(ub_retval));
			goto fail;
		}
	}

	return ub;

fail:
	if (ub != NULL) {
		ub_ctx_delete(ub);
	}
	if (err_code_ptr != NULL) {
		*err_code_ptr = err_code;
	}
	return NULL;
}


//*****************************************************************************
// Initialises global validation structures.
// ----------------------------------------------------------------------------
int dnssec_validation_init(void)
{
	glob_val_ctx.ub = NULL; /* Has separate initialisation procedure. */

	printf_debug(NULL, "Initialising DNSSEC.\n");

	return 0;
}


//*****************************************************************************
/* main validating function */
// return status DNSSEC security
// Input: *domain - domain name
//        options - options of validator, IPv4, IPv6, usefwd, etc..
//        *optdnssrv - IP address of resolver/forwarder
//        *ipbrowser - is IP address of browser which browser used to
//                     connection on the server
// Out:   **ipvalidator - is IP address(es) of validator
// ----------------------------------------------------------------------------
short ds_validate(const char *domain, const uint16_t options,
    const char *optdnssrv, const char *ipbrowser, char **ipvalidator)
{
	struct ub_result *ub_res;
	int ub_retval;
	short retval_ipv4;
	short retval_ipv6;
	int exitcode = DNSSEC_ERROR_RESOLVER;

	retval_ipv4 = DNSSEC_OFF;
	retval_ipv6 = DNSSEC_OFF;
	ub_retval = 0;

	ip_validated[0] = '\0';

	/* options init - get integer values send from browser */
	ds_init_opts(&glob_val_ctx.opts, options);

	printf_debug(NULL, "Input parameters: domain='%s'; options=%u; "
	    "resolver_address='%s'; remote_address='%s';\n",
	    (domain != NULL) ? domain : "(null)",
	    options,
	    (optdnssrv != NULL) ? optdnssrv : "(null)",
	    (ipbrowser != NULL) ? ipbrowser : "(null)");

	if ((domain == NULL) || (domain[0] == '\0')) {
		printf_debug(NULL, "Error: no domain...\n");
		return exitcode;
	}

	// if context is not created
	if (glob_val_ctx.ub == NULL) {
		glob_val_ctx.ub = unbound_resolver_init(&glob_val_ctx.opts,
		    optdnssrv, &exitcode);
		if(glob_val_ctx.ub == NULL) {
			printf_debug(DEBUG_PREFIX,
			    "Error: could not create unbound context\n");
			return exitcode;
		}
	}

	if (glob_val_ctx.opts.resolvipv6 && !glob_val_ctx.opts.resolvipv4) {
		/* query for AAAA only*/
		ub_retval = ub_resolve(glob_val_ctx.ub, domain,
		    LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug(NULL, "Resolve error AAAA: %s\n",
			    ub_strerror(ub_retval));
			return exitcode; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv6 = examine_result(ub_res, ipbrowser);
		exitcode = retval_ipv6;
		ub_resolve_free(ub_res);
	} else if (!glob_val_ctx.opts.resolvipv6 &&
	           glob_val_ctx.opts.resolvipv4) {
		/* query for A only */
		ub_retval = ub_resolve(glob_val_ctx.ub, domain, LDNS_RR_TYPE_A,
		    LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug(NULL, "Resolve error A: %s\n",
			    ub_strerror(ub_retval));
			return exitcode; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv4 = examine_result(ub_res, ipbrowser);
		exitcode = retval_ipv4;
		ub_resolve_free(ub_res);
	} else {
		/* query for A and AAAA */
		ub_retval = ub_resolve(glob_val_ctx.ub, domain,
		    LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug(NULL, "Resolve error AAAA: %s\n",
			    ub_strerror(ub_retval));
			return exitcode; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv6 = examine_result(ub_res, ipbrowser);
		ub_resolve_free(ub_res);

		ub_retval = ub_resolve(glob_val_ctx.ub, domain, LDNS_RR_TYPE_A,
		    LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug(NULL, "Resolve error A: %s\n",
			    ub_strerror(ub_retval));
			return exitcode; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv4 = examine_result(ub_res, ipbrowser);
		exitcode = ds_get_worse_case(retval_ipv4, retval_ipv6);
		ub_resolve_free(ub_res);
	}

	printf_debug(NULL,
	    "Returned value (overall/ipv4/ipv6): \"%d/%d/%d\"\n",
	    exitcode, retval_ipv4, retval_ipv6);

	/* export resolved addrs buf as static */
	if (ipvalidator != NULL) {
		*ipvalidator = ip_validated;
	}

	return exitcode;
}


//*****************************************************************************
// Initialises global validation structures.
// ----------------------------------------------------------------------------
int dnssec_validation_deinit(void)
{
	printf_debug(NULL, "Deinitialising DNSSEC.\n");

	if (glob_val_ctx.ub != NULL) {
		ub_ctx_delete(glob_val_ctx.ub);
		glob_val_ctx.ub = NULL;
	}

	return 0;
}


#ifdef CMNDLINE_TEST

// for command-line testing
int main(int argc, char **argv)
{
	const char *dname = NULL;
	const char *resolver_addresses = NULL;
	short i;
	char *tmp = NULL;
	uint16_t options;

	if ((argc < 2) || (argc > 3)) {
		fprintf(stderr, "Usage\n\t%s dname [resolver_list]\n",
		    argv[0]);
		return 1;
	}

	dname = argv[1];
	if (argc > 2) {
		resolver_addresses = argv[2];
	} else {
/*
		resolver_addresses =
//		    "::1"
		    " 8.8.8.8"
		    " 217.31.204.130"
//		    " 193.29.206.206"
		    ;
*/
	}

	options =
	    DNSSEC_FLAG_DEBUG |
	    DNSSEC_FLAG_USEFWD |
	    DNSSEC_FLAG_RESOLVIPV4 |
	    DNSSEC_FLAG_RESOLVIPV6;

	/* Apply options. */
	ds_init_opts(&glob_val_ctx.opts, options);

	if (dnssec_validation_init() != 0) {
		printf(DEBUG_PREFIX "Error initialising context.\n");
		return 1;
	}

	i = ds_validate(dname, options, resolver_addresses,
	    "2001:610:188:301:145::2:10", &tmp);
	printf(DEBUG_PREFIX "Returned value: \"%d\" %s\n", i, tmp);

	if (dnssec_validation_deinit() != 0) {
		printf(DEBUG_PREFIX "Error de-initialising context.\n");
	}

	return 0;
}

#endif /* CMNDLINE_TEST */
