/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.
File: DANE/TLSA library
Authors: Martin Straka <martin.straka@nic.cz>
         Karel Slany <karel.slany@nic.cz>

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


#include <errno.h>
#include <stdlib.h>
#include <string.h>

//#if TGT_SYSTEM == TGT_WIN
//   #include "libunbound/unbound.h"
//#else
   #include "unbound.h"
//#endif

#include "common.h"


/*
 * Global flag, used for generating debugging information.
 * Default is off.
 */
int global_debug = 0;


/*
 * Initialise unbound resolver context.
 */
struct ub_ctx * unbound_resolver_init(const char *optdnssrv,
    int *err_code_ptr, int usefwd, int userootds, const char *debug_prefix)
{
	struct ub_ctx *ub = NULL;
	int err_code = ERROR_RESOLVER;
	int ub_retval;

	ub = ub_ctx_create();
	if(ub == NULL) {
		printf_debug(debug_prefix, "%s\n",
		    "Error: could not create unbound context.");
		goto fail;
	}

	/* Set resolver/forwarder if it was set in options. */
	if (usefwd) {
		if ((optdnssrv != NULL) && (optdnssrv[0] != '\0')) {
			size_t size = strlen(optdnssrv) + 1;
			char *str_cpy = malloc(size);
			const char *fwd_addr;
			const char *delims = " ";
			if (str_cpy == NULL) {
				err_code = ERROR_GENERIC;
				goto fail;
			}
			memcpy(str_cpy, optdnssrv, size);
			fwd_addr = strtok(str_cpy, delims);
			/* Set IP addresses of resolvers into ub context. */
			while (fwd_addr != NULL) {
				printf_debug(debug_prefix,
				    "Adding resolver IP address '%s'\n",
				    fwd_addr);
				ub_retval = ub_ctx_set_fwd(ub, fwd_addr);
				if (ub_retval != 0) {
					printf_debug(debug_prefix,
					    "Error adding resolver IP "
					    "address '%s': %s\n",
					    fwd_addr, ub_strerror(ub_retval));
					free(str_cpy);
					goto fail;
				}
				fwd_addr = strtok(NULL, delims);
			}
			free(str_cpy);
		} else {
			printf_debug(debug_prefix, "%s\n",
			    "Using system resolver.");
			ub_retval = ub_ctx_resolvconf(ub, NULL);
			if (ub_retval != 0) {
				printf_debug(debug_prefix,
				    "Error reading resolv.conf: %s. "
				    "errno says: %s\n",
				    ub_strerror(ub_retval),
				    strerror(errno));
				goto fail;
			}
		}
	}

	/*
	 * Read public keys of root zone for DNSSEC verification.
	 * ds true = zone key will be set from file root.key
	 *    false = zone key will be set from TA constant
	 */
	if (userootds) {
		ub_retval = ub_ctx_add_ta_file(ub, "root.key");
		if (ub_retval != 0) {
			printf_debug(debug_prefix, "Error adding keys: %s\n",
			    ub_strerror(ub_retval));
			goto fail;
		}
	} else {
		ub_retval = ub_ctx_add_ta(ub, TA);
		if (ub_retval != 0) {
			printf_debug(debug_prefix, "Error adding keys: %s\n",
			    ub_strerror(ub_retval));
			goto fail;
		}
		/*
		 * TODO -- DLV anchor can be set also here.
		 * Determine which location is better.
		 */
	}

	/* Set dlv-anchor. */
	ub_retval = ub_ctx_set_option(ub, "dlv-anchor:", DLV);
	if (ub_retval != 0) {
		printf_debug(debug_prefix, "Error adding DLV keys: %s\n",
		    ub_strerror(ub_retval));
		goto fail;
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
