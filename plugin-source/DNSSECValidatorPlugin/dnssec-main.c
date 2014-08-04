/* ***** BEGIN LICENSE BLOCK *****
Copyright 2012 CZ.NIC, z.s.p.o.

Authors:
  Karel Slany <karel.slany@nic.cz>
  Martin Straka <martin.straka@nic.cz>

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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "dnssec-plug.h"
#include "dnssec-states.gen.h"


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
	{'a', "ADDRESS", "Compare resolved address with given ADDRESS."},
	{'h', NULL, "Prints this message and exits."},
	{'r', "RESOLVERS", "List of resolver addresses to be used."},
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
/*!
 * @brief Waits for a native message string and sends a native response.
 *
 * Commands: finish, validate, validateBogus, reinitialise
 *
 * @return -1 on error,
 *          0 on success
 *          1 if end of program desired.
 */
static
int wait_for_and_process_native_message(void)
/* ========================================================================= */
{
#define MAX_BUF_LEN 1024
#define DELIMS "~"
	char inbuf[MAX_BUF_LEN], outbuf[MAX_BUF_LEN];
	unsigned int inlen, outlen;
	char *cmd, *dn, *options_str, *nameserver, *addr, *tab_id, *saveptr;
	int options_num;
	int val_ret;
	char *tmp;

	printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n", "Waiting for native input.");

	inbuf[0] = '\0';
	inlen = 0;
	if (fread(&inlen, 4, 1, stdin) != 1) {
		printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n",
		    "Cannot read input length.");
		return -1;
	}
	if (fread(inbuf, 1, inlen, stdin) != inlen) {
		printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n",
		    "Cannot read message.");
		return -1;
	}
	inbuf[inlen] = '\0';
	printf_debug(DEBUG_PREFIX_DNSSEC, "IN %d %s\n", inlen, inbuf);

	/* First and last character is '"' .*/
	--inlen;
	inbuf[inlen] = '\0';
	cmd = strsplit(inbuf + 1, DELIMS, &saveptr);
	/*
	 * TODO -- strtok_r()?
	 * Use a tokeniser which can handle empty strings.
	 */
	if (strcmp(cmd, "finish") == 0) {
		/* Just tell that exit is desired. */
		return 1;
	} else if (strcmp(cmd, "initialise") == 0) {
		printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n", "Initialising.");

		dnssec_validation_init();

		/* Generate output. */
		if (snprintf(outbuf, MAX_BUF_LEN, "\"%sRet~ok\"",
		        cmd) >= MAX_BUF_LEN) {
			/* Error. */
			printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n",
			    "Error while creating response string.");
			return -1;
		}

		outlen = strlen(outbuf);

		printf_debug(DEBUG_PREFIX_DNSSEC, "OUT %d %s\n", outlen,
		    outbuf);
		/* Write and flush. */
		fwrite(&outlen, 4, 1, stdout);
		fputs(outbuf, stdout);
		fflush(stdout);
	} else if (strcmp(cmd, "reinitialise") == 0) {
		printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n", "Reinitialising.");

		dnssec_validation_deinit();
		dnssec_validation_init();

		/* Generate no output. */
	} else if ((strcmp(cmd, "validate") == 0) ||
	           (strcmp(cmd, "validateBogus") == 0)) {
		/* Tokenise input. */
		dn = strsplit(NULL, DELIMS, &saveptr);
		options_str = strsplit(NULL, DELIMS, &saveptr);
		nameserver = strsplit(NULL, DELIMS, &saveptr);
		addr = strsplit(NULL, DELIMS, &saveptr);
		tab_id = strsplit(NULL, DELIMS, &saveptr);

		if (('\0' == nameserver[0]) ||
		    (strcmp("sysresolver", nameserver) == 0)) {
			nameserver = NULL;
		}

		options_num = strtol(options_str, NULL, 10);

		val_ret = dnssec_validate(dn, options_num, nameserver, addr,
		    &tmp);

		/* Generate output. */
		if (snprintf(outbuf, MAX_BUF_LEN, "\"%sRet~%s~%d~%s~%s~%s\"",
		        cmd, dn, val_ret, tmp, addr, tab_id) >= MAX_BUF_LEN) {
			/* Error. */
			printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n",
			    "Error while creating response string.");
			return -1;
		}

		outlen = strlen(outbuf);

		printf_debug(DEBUG_PREFIX_DNSSEC, "OUT %d %s\n", outlen,
		    outbuf);
		/* Write and flush. */
		fwrite(&outlen, 4, 1, stdout);
		fputs(outbuf, stdout);
		fflush(stdout);
	} else {
		/* No action. */
		printf_debug(DEBUG_PREFIX_DNSSEC, "Undefined command '%s'.\n",
		    cmd);
	}

	return 0;
#undef MAX_BUF_LEN
#undef DELIMS
}


/* ========================================================================= */
/* ========================================================================= */
/*
 * Main function. Intended for testing purposes or for native messaging.
 */
int main(int argc, char **argv)
/* ========================================================================= */
/* ========================================================================= */
{
	int ch;
	const char *dname = NULL;
	const char *supplied_address = NULL;
	const char *resolver_addresses = NULL;
	char *tmp = NULL;
	uint16_t options;
	int i;
	int ret;

#define CHREXT_CALL "chrome-extension://"

//	global_debug = 1;

	/*
	 * On Windows the argument --parent-window= is passed before
	 * chrome-extension://. Therefore, test all command-line arguments.
	 */

	ret = 0;
	i = 1;
	while ((0 == ret) && (i < argc)) {
		ret =
		    (strncmp(argv[i], CHREXT_CALL, strlen(CHREXT_CALL)) == 0);
		++i;
	}

	if (0 != ret) {
		/* Native messaging call. */
		printf_debug(DEBUG_PREFIX_DNSSEC, "%s\n",
		    "Calling via native messaging.");

		do {
			ret = wait_for_and_process_native_message();
		} while (0 == ret);

		return (1 == ret) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

#undef CHREXT_CALL

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
		//printf(DEBUG_PREFIX_DNSSEC "Error initialising context.\n");
		return EXIT_FAILURE;
	}

//#define REMOTE_IPS "217.31.205.50"
//#define REMOTE_IPS "2001:610:188:301:145::2:10"
//#define REMOTE_IPS NULL
//#define REMOTE_IPS ""

	i = dnssec_validate(dname, options, resolver_addresses,
	    supplied_address, &tmp);
	//printf(DEBUG_PREFIX_DNSSEC "Returned value: \"%d\" %s\n", i, tmp);

	if (dnssec_validation_deinit() != 0) {
		//printf(DEBUG_PREFIX_DNSSEC "Error de-initialising context.\n");
	}

	return EXIT_SUCCESS;
}
