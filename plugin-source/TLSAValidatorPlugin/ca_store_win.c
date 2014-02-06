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


#include "ca_stores.h"
#include "common.h"

#include "openssl/err.h"
#include "openssl/x509.h"
#include "openssl/evp.h"

#include "ldns/config.h"
//#include "ldns/ldns.h"
//#include "libunbound/unbound.h"

#include <wincrypt.h>

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#ifndef CERT_SYSTEM_STORE_CURRENT_USER
	#define CERT_SYSTEM_STORE_CURRENT_USER 0x00010000
#endif

#ifndef CERT_STORE_READONLY_FLAG
	#define CERT_STORE_READONLY_FLAG 0x00008000
#endif

#ifndef CCERT_CLOSE_STORE_CHECK_FLAG
	#define CERT_CLOSE_STORE_CHECK_FLAG 0x00000002
#endif


/*
 * Access Windows CA store and store the certificates.
 */
int X509_store_add_certs_from_win_store(X509_STORE *store)
{
	/*
	 * Load settings from the Windows registry
	 * cert context in DER format is in pCertContext->pbCertEncoded
	 * cert context lenght is in pCertContext->cbCertEncoded
	 */

#define CERT_NAME_LEN 256
	HCERTSTORE hSysStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	const unsigned char *der;
	int certcnt = 0;
	X509 *x509 = NULL;
	unsigned long err;

	printf_debug(DEBUG_PREFIX_CERT,
	    "\n>>------------%s----------------------\n", __func__);

	hSysStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
		L"Root"
		);
	if (hSysStore == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error while accessing Windows CA store.\n");
		goto fail;
	}
	printf_debug(DEBUG_PREFIX_CERT, "%s\n",
	    "The system store accessed successfully.\n");

	while ((pCertContext = CertEnumCertificatesInStore(hSysStore,
	                           pCertContext)) != NULL) {
#if 0
		char * cerhex = bintohex(pCertContext->pbCertEncoded,
		    pCertContext->cbCertEncoded);
		LPTSTR outtext = (LPTSTR)
		    malloc(CERT_NAME_LEN * sizeof(TCHAR)+1);
		CertNameToStr(X509_ASN_ENCODING,
		    &pCertContext->pCertInfo->Subject, CERT_SIMPLE_NAME_STR,
		    outtext, CERT_NAME_LEN);
		printf_debug("","%i) %s |%lu|\n%s",
		    certcnt, outtext, pCertContext->cbCertEncoded, cerhex);
		printf_debug("", "\n\n");
		free(cerhex);
		free(outtext);
#endif
		der = pCertContext->pbCertEncoded;

		x509 = d2i_X509(NULL, &der, pCertContext->cbCertEncoded);
		if (x509 == NULL) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot create X509 from DER.\n");
			continue;
		}

		if (X509_STORE_add_cert(store, x509) == 0) {
			err = ERR_get_error();
			printf_debug(DEBUG_PREFIX_CERT,
			    "Cannot store certificate. Error: %s.\n",
			    ERR_error_string(err, NULL));
		} else {
			++certcnt;
		}

		X509_free(x509); x509 = NULL;
	}

	if (pCertContext) {
		CertFreeCertificateContext(pCertContext);
	}

	if (CertCloseStore(hSysStore, CERT_CLOSE_STORE_CHECK_FLAG)) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Win CA store was closed successfully.\n");
	} else {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error during closing Win CA store.\n");
	}

	printf_debug(DEBUG_PREFIX_CERT,
	    "<<------------%s----------------------\n", __func__);

	return 0;

fail:
	if (hSysStore != NULL) {
		CertCloseStore(hSysStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
	if (pCertContext != NULL) {
		CertFreeCertificateContext(pCertContext);
	}
	if (x509 != NULL) {
		X509_free(x509);
	}
	return -1;
#undef CERT_NAME_LEN
}
