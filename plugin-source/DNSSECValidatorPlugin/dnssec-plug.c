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
#include "config_related.h"


#include <assert.h>
#include <errno.h>
#ifdef CMNDLINE_TEST
  #include <getopt.h>
#endif /* CMNDLINE_TEST */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "dnssec-plug.h"
#include "dnssec-states.gen"


#if TGT_SYSTEM == TGT_WIN
/* Windows */
#include "ldns/config.h"
#include "ldns/ldns.h"
//#include "libunbound/unbound.h"
#include "unbound.h"
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
#define MAX_IPADDRLEN 40          /* max len of IPv4 and IPv6 addr notation */
#define MAX_SRCHLSTLEN (6 * 256)  /* max len of search list */

//----------------------------------------------------------------------------
struct dnssec_options_st { /* structure to save input options */
	bool usefwd; // use of resolver
	bool ds; // use root.key with DS record of root zone
	bool resolvipv4; // IPv4 - validation of A record
	bool resolvipv6; // IPv6 - validation of AAAA record
};

//----------------------------------------------------------------------------

/* TODO -- Fixed size buffer. Writes don't check the buffer size. In some
 * cases buffer overflow may occur. */
char ip_validated[256]; // holds resolved and validated IP address(es)

/* DANE validation context. */
struct dnssec_validation_ctx {
	struct dnssec_options_st opts; /* Options. */
	struct ub_ctx *ub; /*
	                    * Unbound context.
	                    * Initialised outside the context initialisation
	                    * procedure.
	                    */
};
static
struct dnssec_validation_ctx glob_val_ctx = {
	{false, false, false, false}, NULL
};


//*****************************************************************************
/*
 * comparison of IPv4 addresses as structure
 *
 * Returns:
 *       1 when IPv6 addresses match,
 *       0 when they do not match
 *      -1 on error.
 */
// ----------------------------------------------------------------------------
static
int ipv4str_equal(const char *lhs, const char *rhs)
{
	int ret;
	struct in_addr la, ra; /* Left and right address. */

	ret = inet_pton(AF_INET, lhs, &la);
	if (ret != 1) {
		return -1;
	}

	ret = inet_pton(AF_INET, rhs, &ra);
	if (ret != 1) {
		return -1;
	}

	return (memcmp(&la, &ra, sizeof(struct in_addr)) == 0) ? 1 : 0;
}


//*****************************************************************************
/*
 * comparison of IPv6 addresses as structure
 *
 * Returns:
 *       1 when IPv6 addresses match,
 *       0 when they do not match
 *      -1 on error.
 */
// ----------------------------------------------------------------------------
static
int ipv6str_equal(const char *lhs, const char *rhs)
{
	int ret;
	struct in6_addr la, ra; /* Left and right address. */

	ret = inet_pton(AF_INET6, lhs, &la);
	if (ret != 1) {
		return -1;
	}

	ret = inet_pton(AF_INET6, rhs, &ra);
	if (ret != 1) {
		return -1;
	}

	return (memcmp(&la, &ra, sizeof(struct in6_addr)) == 0) ? 1 : 0;
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
void dnssec_set_validation_options(struct dnssec_options_st *opts,
    uint16_t options)
{
	assert(opts != NULL);

	/* TODO -- Not really a structure member. */
	global_debug = options & DNSSEC_FLAG_DEBUG;

	opts->usefwd = options & DNSSEC_FLAG_USEFWD;
	opts->ds = false;
	opts->resolvipv4 = options & DNSSEC_FLAG_RESOLVIPV4;
	opts->resolvipv6 = options & DNSSEC_FLAG_RESOLVIPV6;
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

	printf_debug(DEBUG_PREFIX_DNSSEC, "Comparing IP addresses: %s %s\n",
	    ipbrowser, ipvalidator);
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
		if (isequal > 0) {
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
			if (isequal > 0) {
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
	int isequal = 0;

	printf_debug(DEBUG_PREFIX_DNSSEC, "IP matches: %s %s\n",
	    ipbrowser, ipvalidator);
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
		isequal = ipv4str_equal(ipbrowser, token);
		if (isequal > 0) {
			free(str_cpy);
			return DNSSEC_COT_DOMAIN_SECURED;
		}
		while (token != NULL) {
			token = strtok(NULL, delimiters);
			if (token == NULL) {
				free(str_cpy);
				return DNSSEC_COT_DOMAIN_SECURED_BAD_IP;
			}
			isequal = ipv4str_equal(ipbrowser, token);
			if (isequal > 0) {
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

	printf_debug(DEBUG_PREFIX_DNSSEC, "Examine result: %s %i %i %i %s \n",
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

			printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n", "Has data.");

			if ((!ub_res->secure) && (!ub_res->bogus)) {
				retval = DNSSEC_DOMAIN_UNSECURED;
			} else if ((ub_res->secure) && (!ub_res->bogus)) {
				/* Result is secured and bogus wasn't
				 * detected. */
				if ((ipbrowser == NULL) ||
				    (ipbrowser[0] == '\0')) {
					/*
					 * The browser had not provided a list
					 * of IP addresses.
					 *
					 * Let's pretend everything is OK.
					 */
					printf_debug(DEBUG_PREFIX_DNSSEC,
					    "%s\n", "Browser did not provide "
					    "remote IP addresses.");
					retval = DNSSEC_COT_DOMAIN_SECURED;
				} else if (ub_res->qtype == LDNS_RR_TYPE_A) {
					/* A examine result */
					for (i=0; ub_res->data[i]; i++) {
						ipv4 = inet_ntoa(*(const struct in_addr *) ub_res->data[i]);
						aux_str = ipvalidator;
						ipvalidator =
						    strcat_join_clone(aux_str, ' ', ipv4);
						free(aux_str);
					}
					printf_debug(DEBUG_PREFIX_DNSSEC,
					    "IPv4 address of validator: %s\n",
					    ipvalidator);
					retval = ipv4matches(ipbrowser,
					    ipvalidator, " ");
				} else if (ub_res->qtype ==
				           LDNS_RR_TYPE_AAAA) {
					/* AAAA examine result */
					for (i=0; ub_res->data[i]; i++) {
						inet_ntop(AF_INET6, ((const struct in_addr *) ub_res->data[i]), ipv6, INET6_ADDRSTRLEN);
						aux_str = ipvalidator;
						ipvalidator =
						    strcat_join_clone(aux_str, ' ', ipv6);
						free(aux_str);
					}
					printf_debug(DEBUG_PREFIX_DNSSEC,
					    "IPv6 address of validator: %s\n",
					    ipvalidator);
					retval = ipv6matches(ipbrowser,
					    ipvalidator, " ");
				} else {
					printf_debug(DEBUG_PREFIX_DNSSEC,
					    "%s\n", "Unsupported query type.");
					retval = DNSSEC_ERROR_GENERIC;
				}
				free(ipvalidator);
			} else {
				printf_debug(DEBUG_PREFIX_DNSSEC,
				    "Why bogus?: %s\n", ub_res->why_bogus);
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
			} else if ((ub_res->secure) && (!ub_res->bogus)) {
				/*
				 * TODO -- Use IP address structure rather than
				 * string containing address.
				 */
				if ((NULL != ipbrowser) &&
				    ('\0' != ipbrowser[0])) {
					/* Browser got address. */
					retval =
					    DNSSEC_NXDOMAIN_SIGNATURE_VALID_BAD_IP;
				} else {
					retval =
					    DNSSEC_NXDOMAIN_SIGNATURE_VALID;
				}
			} else {
				retval = DNSSEC_NXDOMAIN_SIGNATURE_INVALID;
			}
		} // nxdomain
	} // not LDNS_RCODE_NOERROR

	printf_debug(DEBUG_PREFIX_DNSSEC, "ub-secure: %i\n", ub_res->secure);
	printf_debug(DEBUG_PREFIX_DNSSEC, "ub-bogus: %i\n", ub_res->bogus);

	return retval;
}


//*****************************************************************************
// Initialises global validation structures.
// ----------------------------------------------------------------------------
int dnssec_validation_init(void)
{
	glob_val_ctx.ub = NULL; /* Has separate initialisation procedure. */

	printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n", "Initialising DNSSEC.");

	return 0;
}


//*****************************************************************************
/* main validating function */
// return status DNSSEC security
// Input: *domain - domain name
//        options - options of validator, IPv4, IPv6, usefwd, etc..
//        *optdnssrv - IP address of resolver/forwarder
//        *ipbrowser - IP address of remote which browser uses to
//                     connect to the server
// Out:   **ipvalidator - is IP address(es) of validator
// ----------------------------------------------------------------------------
int dnssec_validate(const char *domain, uint16_t options,
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

	/* Empty string and "n/a" behaves as no address supplied. */
	if ((NULL != ipbrowser) &&
	    (('\0' == ipbrowser[0]) || (strcmp(ipbrowser, "n/a") == 0))) {
		ipbrowser = NULL;
	}

	/* options init - get integer values send from browser */
	dnssec_set_validation_options(&glob_val_ctx.opts, options);

	printf_debug(DEBUG_PREFIX_DNSSEC,
	    "Input parameters: domain='%s'; options=%u; "
	    "resolver_address='%s'; remote_address='%s';\n",
	    (domain != NULL) ? domain : "(null)",
	    options,
	    (optdnssrv != NULL) ? optdnssrv : "(null)",
	    (ipbrowser != NULL) ? ipbrowser : "(null)");

	/* TODO -- Check whether IP browser is really an IP address. */

	if ((domain == NULL) || (domain[0] == '\0')) {
		printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n",
		    "Error: no domain...");
		return exitcode;
	}

	// if context is not created
	if (glob_val_ctx.ub == NULL) {
		glob_val_ctx.ub = unbound_resolver_init(optdnssrv, &exitcode,
		    glob_val_ctx.opts.usefwd, glob_val_ctx.opts.ds,
		    DEBUG_PREFIX_DNSSEC);
		if(glob_val_ctx.ub == NULL) {
			printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n",
			    "Error: could not create unbound context.");
			switch (exitcode) {
			case ERROR_RESOLVER:
				return DNSSEC_ERROR_RESOLVER;
			case ERROR_GENERIC:
				return DNSSEC_ERROR_GENERIC;
			default:
				return exitcode;
			}
		}
	}

	if (glob_val_ctx.opts.resolvipv6 && !glob_val_ctx.opts.resolvipv4) {
		/* query for AAAA only*/
		ub_retval = ub_resolve(glob_val_ctx.ub, domain,
		    LDNS_RR_TYPE_AAAA, LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug(DEBUG_PREFIX_DNSSEC,
			    "Resolver error AAAA: %s\n",
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
			printf_debug(DEBUG_PREFIX_DNSSEC,
			    "Resolver error A: %s\n",
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
			printf_debug(DEBUG_PREFIX_DNSSEC,
			    "Resolver error AAAA: %s\n",
			    ub_strerror(ub_retval));
			return exitcode; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv6 = examine_result(ub_res, ipbrowser);
		ub_resolve_free(ub_res);

		ub_retval = ub_resolve(glob_val_ctx.ub, domain, LDNS_RR_TYPE_A,
		    LDNS_RR_CLASS_IN, &ub_res);
		if(ub_retval != 0) {
			printf_debug(DEBUG_PREFIX_DNSSEC,
			    "Resolver error A: %s\n",
			    ub_strerror(ub_retval));
			return exitcode; /* DNSSEC_ERROR_GENERIC */
		}
		retval_ipv4 = examine_result(ub_res, ipbrowser);
		exitcode = ds_get_worse_case(retval_ipv4, retval_ipv6);
		ub_resolve_free(ub_res);
	}

	printf_debug(DEBUG_PREFIX_DNSSEC,
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
	printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n", "Deinitialising DNSSEC.");

	if (glob_val_ctx.ub != NULL) {
		ub_ctx_delete(glob_val_ctx.ub);
		glob_val_ctx.ub = NULL;
	}

	return 0;
}

#if 0
__attribute__ ((constructor))
static
void _construct(void)
{
	int global_debug_bak = global_debug;

	global_debug = 1;
	
	printf_debug(DEBUG_PREFIX_DNSSEC, "Running inside PID %d.\n", getpid());

	global_debug = global_debug_bak;
}
#endif

#ifdef CMNDLINE_TEST


/*!
 * @brief Structure help to option structure.
 */
struct option_help {
	int val; /*!< Option value as specified in option structure. */
	const char *metavar; /*!< Metavar string displayed after option. */
	const char *help; /*!< Option description. */
};


/*!
 * @brief Option description string.
 */
static
const char *optstr =
	"a:hr:";


/*!
 * @brief Command-line options.
 */
static
struct option long_opts[] = {
	{"address", required_argument, NULL, 'a'},
	{"help", no_argument, NULL, 'h'},
	{"resolvers", required_argument, NULL, 'r'},
	{NULL, no_argument, NULL, 0}
};


/*!
 * @brief Help to command-line options.
 */
static
struct option_help opts_help[] = {
	{'a', "ADDRESS", "Compate resolved address wint given ADDRESS."},
	{'h', NULL, "Prints this message and exits."},
	{'r', "RESOLVERS", "List of resolvera addresses to be used."},
	{0, NULL, NULL}
};


#define BASIC_USAGE "dnssec-plug [OPTIONS] dname"


/* ========================================================================= */
/*
 * Prints a description of the command-line arguments.
 */
static
void print_usage(FILE *fout, const char *basic_usage,
    const struct option *opts, const struct option_help *usage)
/* ========================================================================= */
{
	assert(fout != NULL);
	assert(opts != NULL);
	assert(usage != NULL);

	if ((NULL != basic_usage) && ('\0' != basic_usage[0])) {
		fprintf(fout, "%s\n", basic_usage);
	}

	while ((opts->name != NULL) && (usage->help != NULL)) {
		assert(opts->val == usage->val);

		fprintf(fout, "-%c / --%s", opts->val, opts->name);
		if (usage->metavar != NULL) {
			fprintf(fout, "=%s", usage->metavar);
		}
		fprintf(fout, "\n\t%s\n", usage->help);

		++opts;
		++usage;
	};

	assert((opts->name == NULL) && (usage->help == NULL));
}


/* ========================================================================= */
/* ========================================================================= */
/*
 * Main funcion. Intended for testing purposes.
 */
int main(int argc, char **argv)
/* ========================================================================= */
/* ========================================================================= */
{
	int ch;
	const char *dname = NULL;
	const char *supplied_address = NULL;
	const char *resolver_addresses = NULL;
	short i;
	char *tmp = NULL;
	uint16_t options;

	while ((ch = getopt_long(argc, argv, optstr, long_opts, NULL)) != -1) {
		switch (ch) {
		case 'a':
			if (NULL != supplied_address) {
				fprintf(stderr, "Browser address has already "
				    "been set to '%s'.\n", supplied_address);
				exit(EXIT_FAILURE);
			}
			supplied_address = optarg;
			break;
		case 'h':
			print_usage(stdout, BASIC_USAGE, long_opts, opts_help);
			exit(EXIT_SUCCESS);
			break;
		case 'r':
			if (NULL != resolver_addresses) {
				fprintf(stderr, "Resolvers have already been "
				    "set to '%s'.\n", resolver_addresses);
				exit(EXIT_FAILURE);
			}
			resolver_addresses = optarg;
			break;
		default:
			print_usage(stderr, BASIC_USAGE, long_opts, opts_help);
			exit(EXIT_FAILURE);
			break;
		}
	}

	/* Last argument is the domain name. */
	dname = argv[argc - 1];

	options =
	    DNSSEC_FLAG_DEBUG |
	    DNSSEC_FLAG_USEFWD |
	    DNSSEC_FLAG_RESOLVIPV4 |
	    DNSSEC_FLAG_RESOLVIPV6;

	/* Apply options. */
	dnssec_set_validation_options(&glob_val_ctx.opts, options);

	if (dnssec_validation_init() != 0) {
		printf(DEBUG_PREFIX_DNSSEC "Error initialising context.\n");
		return EXIT_FAILURE;
	}

//#define REMOTE_IPS "217.31.205.50"
//#define REMOTE_IPS "2001:610:188:301:145::2:10"
//#define REMOTE_IPS NULL
//#define REMOTE_IPS ""

	i = dnssec_validate(dname, options, resolver_addresses,
	    supplied_address, &tmp);
	printf(DEBUG_PREFIX_DNSSEC "Returned value: \"%d\" %s\n", i, tmp);

	if (dnssec_validation_deinit() != 0) {
		printf(DEBUG_PREFIX_DNSSEC "Error de-initialising context.\n");
	}

	return EXIT_SUCCESS;
}

#endif /* CMNDLINE_TEST */
