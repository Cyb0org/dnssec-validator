

#include <openssl/x509.h>
#include <stdio.h>

#import <Foundation/Foundation.h>
#import <Security/Security.h>

/* TODO -- Isolate code into modules. */

#define VRCFRelease(object) if(object) CFRelease(object)

#ifdef RES_OSX
int X509_store_add_certs_from_osx_store(X509_STORE *store)
{
	OSStatus status;
        SecKeychainSearchRef search = NULL;

        SecKeychainRef keychain = NULL;

        status = SecKeychainOpen(
            "/System/Library/Keychains/SystemRootCertificates.keychain",
            &keychain);
        if(status) {
                VRCFRelease(keychain);
                return -1;
        }

        CFArrayRef searchList = CFArrayCreate(kCFAllocatorDefault,
            (const void**) &keychain, 1, &kCFTypeArrayCallBacks);

#ifndef __OBJC_GC__
        VRCFRelease(keychain);
#endif

        /*
         * The first argument being NULL indicates the user's current keychain
         * list.
         */
        status = SecKeychainSearchCreateFromAttributes(searchList,
                kSecCertificateItemClass, NULL, &search);

        if (status != errSecSuccess) {
                fprintf(stderr, "SecKeychainSearchCreateFromAttributes().\n");
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
                    &attrList, (UInt32 *)(&certData.Length),
                    (void **) (&certData.Data));

                if (status != errSecSuccess) {
                        fprintf(stderr, "SecKeychainItemCopyContent().\n");
                        CFRelease(searchItem);
                        continue;
                }

		const unsigned char *der;
		X509 *x509 = NULL;
		der = certData.Data;
		x509 = d2i_X509(NULL, &der, certData.Length);
		if (x509 == NULL) {
			fprintf(stderr, "Cannot create DER.\n");
		}
		if (X509_STORE_add_cert(store, x509) == 0) {
			fprintf(stderr, "Cannot store x509.\n");
		}
		X509_free(x509); x509 = NULL;

                /*
                 * At this point you should have a valid CSSM_DATA structure
                 * representing the certificate.
                 */

                SecCertificateRef certificate;
                status = SecCertificateCreateFromData(&certData,
                    CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_BER, &certificate);

                if (status != errSecSuccess) {
                        fprintf(stderr, "SecCertificateCreateFromData().\n");
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

                SecKeychainItemFreeContent(&attrList, certData.Data);
                CFRelease(searchItem);
        }

        CFRelease(search);

	return 0;
}
#endif /* RES_OSX */
