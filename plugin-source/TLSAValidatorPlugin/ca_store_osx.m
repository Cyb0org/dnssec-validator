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


#include <openssl/x509.h>

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include "ca_stores.h"
#include "common.h"


#define VRCFRelease(object) \
	do { \
		if(object) CFRelease(object); \
	} while(0)


#ifdef RES_OSX
int X509_store_add_certs_from_osx_store(X509_STORE *store)
{
	OSStatus status;
	SecKeychainSearchRef search = NULL;

	SecKeychainRef keychain = NULL;

	printf_debug();

	status = SecKeychainOpen(
	    "/System/Library/Keychains/SystemRootCertificates.keychain",
	    &keychain);
	if(status) {
		VRCFRelease(keychain);
		return -1;
	}

	CFArrayRef searchList = CFArrayCreate(kCFAllocatorDefault,
	    (const void **) &keychain, 1, &kCFTypeArrayCallBacks);

#ifndef __OBJC_GC__
	VRCFRelease(keychain);
#endif

	/*
	 * The first argument (searchList) being NULL indicates the user's
	 * current keychain list.
	 */
	status = SecKeychainSearchCreateFromAttributes(searchList,
	    kSecCertificateItemClass, NULL, &search);
	if (status != errSecSuccess) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error retrieving keychain.");
		return -1;
	}

	SecKeychainItemRef searchItem = NULL;

	while (SecKeychainSearchCopyNext(search, &searchItem) !=
	       errSecItemNotFound) {
		SecKeychainAttributeList attrList;
		CSSM_DATA certData;

		attrList.count = 0;
		attrList.attr = NULL;

		status = SecKeychainItemCopyContent(searchItem, NULL,
		    &attrList, (UInt32 *) (&certData.Length),
		    (void **) (&certData.Data));

		if (status != errSecSuccess) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Error accessing keychain.");
			CFRelease(searchItem);
			continue;
		}

		const unsigned char *der;
		X509 *x509 = NULL;
		der = certData.Data;
		x509 = d2i_X509(NULL, &der, certData.Length);
		if (x509 == NULL) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot create DER.\n");
		}
		if (X509_STORE_add_cert(store, x509) == 0) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot store x509.\n");
		}
		X509_free(x509); x509 = NULL;

#if 0
		/*
		 * At this point you should have a valid CSSM_DATA structure
		 * representing the certificate.
		 */

		SecCertificateRef certificate;
		status = SecCertificateCreateFromData(&certData,
		    CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_BER, &certificate);
		if (status != errSecSuccess) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Error accessing certificate.");
			SecKeychainItemFreeContent(&attrList, certData.Data);
			CFRelease(searchItem);
			continue;
		}

		/*
		 * Do whatever you want to do with the certificate.
		 * For instance, print its common name (if there's one).
		 */

		CFStringRef commonName = NULL;
		SecCertificateCopyCommonName(certificate, &commonName);
		NSLog(@"common name = %@", (NSString *) commonName);
		if (commonName) {
			CFRelease(commonName);
		}
#endif

		SecKeychainItemFreeContent(&attrList, certData.Data);
		CFRelease(searchItem);
	}

	CFRelease(search);

	return 0;
}
#endif /* RES_OSX */
