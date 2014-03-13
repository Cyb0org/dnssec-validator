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


#include <openssl/err.h>
#include <openssl/x509.h>

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include "ca_stores.h"
#include "common.h"


#define VRCFRelease(object) \
	do { \
		if (object) CFRelease(object); \
	} while(0)


#define OLD 0 /* Uses deprecated constructions. */
#define NEW 1

#define IMPLEMENTATION OLD
//#define IMPLEMENTATION NEW

#ifndef IMPLEMENTATION
  #define IMPLEMEMENTATION OLD
#endif /* !IMPLEMENTATION */


#define CA_KEYCHAIN_PATH \
	"/System/Library/Keychains/SystemRootCertificates.keychain"


#if IMPLEMENTATION == OLD
int X509_store_add_certs_from_osx_store(X509_STORE *store)
{
	SecKeychainRef keychain = NULL;
	CFArrayRef searchList = NULL;

	SecKeychainSearchRef search = NULL;
	OSStatus status;
	int certcnt = 0;

	printf_debug(DEBUG_PREFIX_CERT, "%s\n",
	    "Accesssing CA store via SecKeychainSearchCreateFromAttributes().");

	status = SecKeychainOpen(CA_KEYCHAIN_PATH, &keychain);
	if (status != errSecSuccess) {
		VRCFRelease(keychain); keychain = NULL;
		CFStringRef str_ref = SecCopyErrorMessageString(status, NULL);
		printf_debug(DEBUG_PREFIX_CERT, "Error: %s\n",
		    CFStringGetCStringPtr(str_ref, kCFStringEncodingMacRoman));
		CFRelease(str_ref);
		goto fail;
	}

	searchList = CFArrayCreate(kCFAllocatorDefault,
	    (const void **) &keychain, 1, &kCFTypeArrayCallBacks);
	if (searchList == NULL) {
		goto fail;
	}

#ifndef __OBJC_GC__
	VRCFRelease(keychain); keychain = NULL;
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
		goto fail;
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
		CFRelease(searchItem); searchItem = NULL;

		const unsigned char *der;
		X509 *x509 = NULL;
		unsigned long err;

		der = certData.Data;
		x509 = d2i_X509(NULL, &der, certData.Length);
		if (x509 == NULL) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot create DER.\n");
			SecKeychainItemFreeContent(&attrList, certData.Data);
			continue;
		}
		SecKeychainItemFreeContent(&attrList, certData.Data);

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

	CFRelease(searchList); searchList = NULL;
	CFRelease(search); search = NULL;

	printf_debug(DEBUG_PREFIX_CERT,
	    "Loaded %d certificates from CA store.\n", certcnt);

	return 0;

fail:
	if (keychain != NULL) {
		CFRelease(keychain);
	}
	if (searchList != NULL) {
		CFRelease(searchList);
	}
	if (search != NULL) {
		CFRelease(search);
	}
	return -1;
}
#endif /* OLD */


#if IMPLEMENTATION == NEW
int X509_store_add_certs_from_osx_store(X509_STORE *store)
{
	SecKeychainRef keychain = NULL;
	CFArrayRef search_list = NULL;

	CFMutableDictionaryRef cfquery = NULL;
	CFArrayRef cfcerts = NULL;
	OSStatus status;
	int certcnt = 0;

	printf_debug(DEBUG_PREFIX_CERT, "%s\n",
	    "Accesssing CA store via SecItemCopyMatching().");

	status = SecKeychainOpen(CA_KEYCHAIN_PATH, &keychain);
	if (status != errSecSuccess) {
		VRCFRelease(keychain); keychain = NULL;
		CFStringRef str_ref = SecCopyErrorMessageString(status, NULL);
		printf_debug(DEBUG_PREFIX_CERT, "Error: %s\n",
		    CFStringGetCStringPtr(str_ref, kCFStringEncodingMacRoman));
		CFRelease(str_ref);
		goto fail;
	}

	search_list = CFArrayCreate(kCFAllocatorDefault,
	    (const void **) &keychain, 1, &kCFTypeArrayCallBacks);
	if (search_list == NULL) {
		goto fail;
	}

	SecKeychainSetSearchList(search_list);
	/* SecKeychainSetDefault(keychain); */

#ifndef __OBJC_GC__
	VRCFRelease(keychain); keychain = NULL;
#endif

	cfquery = CFDictionaryCreateMutable(NULL, 0,
	        &kCFTypeDictionaryKeyCallBacks,
	        &kCFTypeDictionaryValueCallBacks);
	if (cfquery == NULL) {
		/* Failure. */
		goto fail;
	}
	CFDictionarySetValue(cfquery, kSecClass, kSecClassCertificate);
	CFDictionarySetValue(cfquery, kSecReturnRef, kCFBooleanTrue);
	CFDictionarySetValue(cfquery, kSecMatchLimit, kSecMatchLimitAll);
	CFDictionarySetValue(cfquery, kSecMatchTrustedOnly, kCFBooleanTrue);
	CFDictionarySetValue(cfquery, kSecMatchValidOnDate, kCFNull);


	status = SecItemCopyMatching((CFDictionaryRef) cfquery,
	     (CFTypeRef *) &cfcerts);
	CFRelease(cfquery); cfquery = NULL;
	if (status != errSecSuccess) {
		CFStringRef str_ref = SecCopyErrorMessageString(status, NULL);
		printf_debug(DEBUG_PREFIX_CERT, "Error: %s\n",
		    CFStringGetCStringPtr(str_ref, kCFStringEncodingMacRoman));
		CFRelease(str_ref);
		goto fail;
	}

	printf_debug(DEBUG_PREFIX_CERT, "%ld certificates in keyring\n",
	    CFArrayGetCount(cfcerts));

	NSArray *certificates = CFBridgingRelease(cfcerts);
	for (id value in certificates) {
//		SecCertificateRef cfcertificate =
//		    (SecCertificateRef) CFBridgingRetain(value);

		CFDataRef cert_data = NULL;
		const unsigned char *der;
		unsigned long length;
		X509 *x509 = NULL;
		unsigned long err;

		cert_data = SecCertificateCopyData(
		    (SecCertificateRef) CFBridgingRetain(value));
		der = CFDataGetBytePtr(cert_data);
		length = CFDataGetLength(cert_data);
		x509 = d2i_X509(NULL, &der, length);
		if (x509 == NULL) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot create DER.\n");
			CFRelease(cert_data); cert_data = NULL;
			continue;
		}
		CFRelease(cert_data); cert_data = NULL;

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

	CFRelease(search_list); search_list = NULL;
	CFRelease(cfcerts); cfcerts = NULL;

	printf_debug(DEBUG_PREFIX_CERT,
	    "Loaded %d certificates from CA store.\n", certcnt);

	return 0;

fail:
	if (keychain != NULL) {
		CFRelease(keychain);
	}
	if (search_list) {
		CFRelease(search_list);
	}
	if (cfquery != NULL) {
		CFRelease(cfquery);
	}
	if (cfcerts != NULL) {
		CFRelease(cfcerts);
	}
	return -1;
}
#endif /* NEW */
