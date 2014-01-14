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


#define _BSD_SOURCE /* S_IFREG */


#include <sys/stat.h> /* stat(2) */

#include <assert.h>
#include <dirent.h> /* opendir(3) */
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string.h>
#include <unistd.h> /* stat(2) */

#include "ca_stores.h"
#include "common.h"


/* TODO -- These location should be given at configuration time. */
#define MOZILLA_CA_DIR "/usr/share/ca-certificates/mozilla"

/* CA certificate directories. */
const char *ca_dirs[] = {MOZILLA_CA_DIR, NULL};


/*!
 * @brief Store CA file into store.
 *
 * @param[in,out] store X509 store.
 * @param[in]     fname Certificate file.
 * @return 0 on success, -1 else.
 */
static
int X509_store_add_cert_file(X509_STORE *store, const char *fname);


/*
 * Access directories containing CA certificates and store them.
 */
int X509_store_add_certs_from_dirs(X509_STORE *store, const char **dirname_p)
{
	DIR *dir = NULL;
	struct dirent *ent;
	struct stat s;
#define MAX_PATH_LEN 256
	char aux_path[MAX_PATH_LEN];
	size_t prefix_len;
	int certcnt = 0;

	assert(dirname_p != NULL);
	if (dirname_p == NULL) {
		goto fail;
	}

	while (*dirname_p != NULL) {
		/*
		 * Assume that path is a directory.
		 * TODO -- Check for it.
		 */

		certcnt = 0;

		dir = opendir(*dirname_p);
		if (dir == NULL) {
			goto fail;
		}

		prefix_len = strlen(*dirname_p);
		if ((prefix_len + 1) > (MAX_PATH_LEN - 1)) {
			goto fail;
		}
		memcpy(aux_path, *dirname_p, MAX_PATH_LEN);
		aux_path[prefix_len++] = '/';
		aux_path[prefix_len] = '\0';

		while ((ent = readdir(dir)) != NULL) {
			if ((strlen(ent->d_name) + prefix_len) >
			    (MAX_PATH_LEN - 1)) {
				continue; /* Next entry. */
			}

			strncpy(aux_path + prefix_len, ent->d_name,
			    MAX_PATH_LEN - prefix_len);
			aux_path[MAX_PATH_LEN - 1] = '\0';

			if((stat(aux_path, &s) == 0) &&
			   (s.st_mode & S_IFREG)) {
				/* Is file. */

				X509_store_add_cert_file(store, aux_path);
				++certcnt;
			}
		}

		printf_debug(DEBUG_PREFIX_CERT,
		    "Added %d certificates from directory '%s'.\n",
		    certcnt, *dirname_p);

		closedir(dir); dir = NULL;
		++dirname_p;
	}

	return 0;

fail:
	if (dir != NULL) {
		closedir(dir);
	}
	return -1;
#undef MAX_PATH_LEN
}


/*
 * Store CA file into store.
 */
static
int X509_store_add_cert_file(X509_STORE *store, const char *fname)
{
	FILE *fin = NULL;
	X509 *x509 = NULL;

	assert(store != NULL);
	assert(fname != NULL);

	fin = fopen(fname, "r");
	if (fin == NULL) {
		printf_debug(DEBUG_PREFIX_CERT,
		    "Cannot open certificate '%s'.\n", fname);
		goto fail;
	}

	x509 = PEM_read_X509(fin, NULL, NULL, NULL);
	if (x509 == NULL) {
		printf_debug(DEBUG_PREFIX_CERT,
		    "Cannot parse certificate '%s'.\n", fname);
		goto fail;
	}

	if (X509_STORE_add_cert(store, x509) == 0) {
		printf_debug(DEBUG_PREFIX_CERT,
		    "Cannot store certificate '%s'.\n", fname);
		goto fail;
	}

	X509_free(x509); x509 = NULL;
	fclose(fin); fin = NULL;

	return 0;

fail:
	if (fin != NULL) {
		fclose(fin);
	}
	if (x509 != NULL) {
		X509_free(x509);
	}
	return -1;
}
