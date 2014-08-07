/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.
File: DANE/TLSA library
Authors:
  Karel Slany <karel.slany@nic.cz>
  Martin Straka <martin.straka@nic.cz>

This file is part of TLSA Validator 2 Add-on.

TLSA Validator 2 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

TLSA Validator 2.Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
TLSA Validator 2 Add-on.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */


#include "config_related.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "dane-plug.h"
#include "dane-states.gen.h"


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
	char *cmd, *options_str, *resolver, *dn, *port, *proto, *policy_str,
	    *tab_id, *schema, *saveptr;
	int options_num, policy_num;
	int val_ret;

	printf_debug(DEBUG_PREFIX_DANE, "%s\n", "Waiting for native input.");

	inbuf[0] = '\0';
	inlen = 0;
	if (fread(&inlen, 4, 1, stdin) != 1) {
		printf_debug(DEBUG_PREFIX_DANE, "%s\n",
		    "Cannot read input length.");
		return -1;
	}
	if (fread(inbuf, 1, inlen, stdin) != inlen) {
		printf_debug(DEBUG_PREFIX_DANE, "%s\n",
		    "Cannot read message.");
		return -1;
	}
	inbuf[inlen] = '\0';
	printf_debug(DEBUG_PREFIX_DANE, "IN %d %s\n", inlen, inbuf);

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
		printf_debug(DEBUG_PREFIX_DANE, "%s\n", "Initialising.");

		dane_validation_init();

		/* Generate output. */
		if (snprintf(outbuf, MAX_BUF_LEN, "\"%sRet~ok\"",
		        cmd) >= MAX_BUF_LEN) {
			/* Error. */
			printf_debug(DEBUG_PREFIX_DANE, "%s\n",
			    "Error while creating response string.");
			return -1;
		}

		outlen = strlen(outbuf);

		printf_debug(DEBUG_PREFIX_DANE, "OUT %d %s\n", outlen,
		    outbuf);
		/* Write and flush. */
		fwrite(&outlen, 4, 1, stdout);
		fputs(outbuf, stdout);
		fflush(stdout);
	} else if (strcmp(cmd, "reinitialise") == 0) {
		printf_debug(DEBUG_PREFIX_DANE, "%s\n", "Reinitialising.");

		dane_validation_deinit();
		dane_validation_init();

		/* Generate no output. */
	} else if ((strcmp(cmd, "validate") == 0) ||
	           (strcmp(cmd, "validateBlock") == 0) ||
	           (strcmp(cmd, "validateBogus") == 0)) {
		options_str = strsplit(NULL, DELIMS, &saveptr);
		resolver = strsplit(NULL, DELIMS, &saveptr);
		dn = strsplit(NULL, DELIMS, &saveptr);
		port = strsplit(NULL, DELIMS, &saveptr);
		proto = strsplit(NULL, DELIMS, &saveptr);
		policy_str = strsplit(NULL, DELIMS, &saveptr);
		tab_id = strsplit(NULL, DELIMS, &saveptr);
		schema = strsplit(NULL, DELIMS, &saveptr);

		if (('\0' == resolver[0]) ||
		    (strcmp("sysresolver", resolver) == 0)) {
			resolver = NULL;
		}

		options_num = strtol(options_str, NULL, 10);
		policy_num = strtol(policy_str, NULL, 10);

		val_ret = dane_validate(NULL, 0, options_num, resolver, dn,
		    port, proto, policy_num);

		/* Generate output. */
		if (snprintf(outbuf, MAX_BUF_LEN,
		        "\"%sRet~%s~%s~%s~%d~%s~%s~%s\"", cmd, dn, port, proto,
		        val_ret, tab_id, schema, VERSION) >= MAX_BUF_LEN) {
			/* Error. */
			printf_debug(DEBUG_PREFIX_DANE, "%s\n",
			    "Error while creating response string.");
			return -1;
		}

		outlen = strlen(outbuf);

		printf_debug(DEBUG_PREFIX_DANE, "OUT %d %s\n", outlen,
		    outbuf);
		/* Write and flush. */
		fwrite(&outlen, 4, 1, stdout);
		fputs(outbuf, stdout);
		fflush(stdout);
	} else {
		/* No action. */
		printf_debug(DEBUG_PREFIX_DANE, "Undefined command '%s'.\n",
		    cmd);
	}

	return 0;
#undef MAX_BUF_LEN
#undef DELIMS
}

static
const char *certhex[] = {"12345678"};

/* ========================================================================= */
/* ========================================================================= */
/*
 * Main funcion. Intended for testing purposes.
 */
int main(int argc, char **argv)
/* ========================================================================= */
/* ========================================================================= */
{
	const char *dname = NULL, *port = NULL;
	const char *resolver_addresses = NULL;
	int res = DANE_ERROR_GENERIC;

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
		printf_debug(DEBUG_PREFIX_DANE, "%s\n",
		    "Calling via native messaging.");

		do {
			ret = wait_for_and_process_native_message();
		} while (0 == ret);

		return (1 == ret) ? EXIT_SUCCESS : EXIT_FAILURE;
	}

#undef CHREXT_CALL

	if ((argc < 2) || (argc > 4)) {
		fprintf(stderr, "Usage:\n\t%s dname port [resolver_list]\n",
		    argv[0]);
		return 1;
	}

	dname = argv[1];
	if (argc > 2) {
		/* Default is 443. */
		port = argv[2];
	}
	if (argc > 3) {
		resolver_addresses = argv[3];
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
	    DANE_FLAG_DEBUG |
	    DANE_FLAG_USEFWD;

	/* Apply options. */
	dane_set_validation_options(&glob_val_ctx.opts, options);

	if (dane_validation_init() != 0) {
		printf(DEBUG_PREFIX_DANE "Error initialising context.\n");
		return 1;
	}

	res = dane_validate(NULL, 0, options, resolver_addresses, dname,
	    port, "tcp", 1);
	printf(DEBUG_PREFIX_DANE "Main result: %i\n", res);

	if (dane_validation_deinit() != 0) {
		printf(DEBUG_PREFIX_DANE "Error de-initialising context.\n");
	}

	return 0;
}
