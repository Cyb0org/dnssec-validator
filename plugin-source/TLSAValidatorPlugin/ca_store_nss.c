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


#include "config_related.h"


#include <sys/stat.h> /* stat(2) */

#include <assert.h>
#include <base64.h> /* NSS BTOA_DataToAscii() */
#include <cert.h> /* NSS CERT_DestroyCertList() */
#include <dirent.h> /* opendir(3) */
#include <nss.h> /* NSS */
#include <openssl/err.h>
#include <openssl/x509.h>
#include <pk11func.h> /* NSS ListCertsInSlot() */
#include <prlink.h> /* NSPR PR_GetLibraryName() */
#include <secmod.h> /* NSS slots, SECMOD_LoadUserModule() */
#include <unistd.h> /* stat(2) */

#include "ca_stores.h"
#include "common.h"


/* Directories containing cert8.db. */
/* TODO -- These directories should be detected automatically (somehow). */
const char * cert8_ca_dirs[] = {NULL};


//*****************************************************************************
// Load all available certificates from NSS built-in certificates.
// ----------------------------------------------------------------------------
int X509_store_add_certs_from_nssckbi(X509_STORE *store)
{
	NSSInitParameters initparams;
	NSSInitContext *nss_ctx = NULL;
	SECMODModule *secmod = NULL;
	CERTCertList *cert_list = NULL;
	CERTCertListNode *cert_node;
	X509 *x509 = NULL;
	const unsigned char *der;
	int certcnt = 0;
	unsigned long err;

	memset(&initparams, 0, sizeof(initparams));
	initparams.length = sizeof(initparams);
	nss_ctx = NSS_InitContext("", "", "", "", &initparams,
	    NSS_INIT_READONLY | NSS_INIT_NOCERTDB);
	if (nss_ctx == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Unable to create a NSS context structure.");
		goto fail;
	}

	secmod = SECMOD_LoadUserModule(
	    "name=\"Root Certs\" library=\"libnssckbi.so\"",
	    NULL, PR_FALSE);
	if ((secmod == NULL) || (!secmod->loaded)) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Cannot access NSS builtin CA store.\n");
		goto fail;
	}

	for (int i = 0; i < secmod->slotCount; ++i) {
		cert_list = PK11_ListCertsInSlot(secmod->slots[i]);
		for(cert_node = CERT_LIST_HEAD(cert_list);
		    !CERT_LIST_END(cert_node, cert_list);
		    cert_node = CERT_LIST_NEXT(cert_node)) {
			der = cert_node->cert->derCert.data;

			x509 = d2i_X509(NULL, &der,
			    cert_node->cert->derCert.len);
			if (x509 == NULL) {
				printf_debug(DEBUG_PREFIX_CERT, "%s\n",
				    "Cannot create X509 from DER.\n");
				continue;
			}

			if (X509_STORE_add_cert(store, x509) == 0) {
				err = ERR_get_error();
				printf_debug(DEBUG_PREFIX_CERT,
				    "Cannot store certificate. "
				    "Error: %s.\n",
				    ERR_error_string(err, NULL));
			} else {
				++certcnt;
			}

			X509_free(x509); x509 = NULL;
		}
		CERT_DestroyCertList(cert_list); cert_list = NULL;
	}

	if (SECMOD_UnloadUserModule(secmod) != SECSuccess) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error unloading NSS module.\n");
	}
	SECMOD_DestroyModule(secmod); secmod = NULL;

	NSS_ShutdownContext(nss_ctx); nss_ctx = NULL;

	printf_debug(DEBUG_PREFIX_CERT,
	    "Added %d built-in NSS certificates.\n",
	    certcnt);

	return 0;

fail:
	if (secmod != NULL) {
		SECMOD_UnloadUserModule(secmod);
		SECMOD_DestroyModule(secmod);
	}
	if (cert_list != NULL) {
		CERT_DestroyCertList(cert_list);
	}
	if (x509 != NULL) {
		X509_free(x509);
	}
	if (nss_ctx != NULL) {
		NSS_ShutdownContext(nss_ctx);
	}
	return -1;
}


//*****************************************************************************
// Load all available certificates from directories containing cert8.db files.
// ----------------------------------------------------------------------------
int X509_store_add_certs_from_cert8_dirs(X509_STORE *store,
    const char **dirname_p)
{
	NSSInitParameters initparams;
	NSSInitContext *nss_ctx = NULL;
	struct stat s;
#define MAX_MODSPEC_LEN 512
	char aux_modspec[MAX_MODSPEC_LEN];
	PK11SlotInfo *slot = NULL;
	CERTCertList *cert_list = NULL;
	CERTCertListNode *cert_node;
	X509 *x509 = NULL;
	const unsigned char *der;
	int certcnt = 0;
	unsigned long err;

	assert(dirname_p != NULL);
	if (dirname_p == NULL) {
		goto fail;
	}

	memset(&initparams, 0, sizeof(initparams));
	initparams.length = sizeof(initparams);
	nss_ctx = NSS_InitContext("", "", "", "", &initparams,
	    NSS_INIT_READONLY | NSS_INIT_NOCERTDB);
	if (nss_ctx == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Unable to create a NSS context structure.");
		goto fail;
	}

	while (*dirname_p != NULL) {
		/*
		 * Assume that path is a directory.
		 * TODO -- Check for it.
		 */

		certcnt = 0;

		if ((stat(*dirname_p, &s) != 0) || !(s.st_mode & S_IFDIR)) {
			printf_debug(DEBUG_PREFIX_CERT,
			    "Cannot access directory '%s'.\n", *dirname_p);
			continue;
		}
		/* Is directory. */

		if (snprintf(aux_modspec, MAX_MODSPEC_LEN,
		        " name=\"Directory Certs\" " \
		        " configdir='%s' " \
		        " certPrefix='' " \
		        " keyPrefix='' " \
		        " flags=readOnly,noKeyDB ", *dirname_p) >=
		    MAX_MODSPEC_LEN) {
			/* Output truncated. */
			printf_debug(DEBUG_PREFIX_CERT,
			    "Cannot work with directory '%s'.\n", *dirname_p);
			continue;
		}

		slot = SECMOD_OpenUserDB(aux_modspec);
		if (slot == NULL) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Error loading user database.\n");
			continue;
		}

		cert_list = PK11_ListCertsInSlot(slot);
		if (cert_list != NULL) {
			for(cert_node = CERT_LIST_HEAD(cert_list);
			    !CERT_LIST_END(cert_node, cert_list);
			    cert_node = CERT_LIST_NEXT(cert_node)) {
				der = cert_node->cert->derCert.data;

				x509 = d2i_X509(NULL, &der,
				    cert_node->cert->derCert.len);
				if (x509 == NULL) {
					printf_debug(DEBUG_PREFIX_CERT, "%s\n",
					    "Cannot create X509 from DER.\n");
					continue;
				}

				if (X509_STORE_add_cert(store, x509) == 0) {
					err = ERR_get_error();
					printf_debug(DEBUG_PREFIX_CERT,
					    "Cannot store certificate. "
					    "Error: %s.\n",
					    ERR_error_string(err, NULL));
				} else {
					++certcnt;
				}

				X509_free(x509); x509 = NULL;
			}
			CERT_DestroyCertList(cert_list); cert_list = NULL;
		}

		printf_debug(DEBUG_PREFIX_CERT,
		    "Added %d NSS certificates from directory '%s'.\n",
		    certcnt, *dirname_p);

		SECMOD_CloseUserDB(slot);
		PK11_FreeSlot(slot); slot = NULL;

		++dirname_p;
	}

	NSS_ShutdownContext(nss_ctx); nss_ctx = NULL;

	return 0;

fail:
	if (slot != NULL) {
		SECMOD_CloseUserDB(slot);
		PK11_FreeSlot(slot);
	}
	if (cert_list != NULL) {
		CERT_DestroyCertList(cert_list);
	}
	if (x509 != NULL) {
		X509_free(x509);
	}
	if (nss_ctx != NULL) {
		NSS_ShutdownContext(nss_ctx);
	}
	return -1;
#undef MAX_MODSPEC_LEN
}
