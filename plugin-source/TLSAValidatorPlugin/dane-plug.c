/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.
File: DANE/TLSA library
Authors: Martin Straka <martin.straka@nic.cz>

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

#define _POSIX_SOURCE


#include "config_related.h"


#define NONE_CA_STORE 0 /* No external CA store is loaded. */
#define DIR_CA_STORE 1 /* CA certificates stored in directories. */
#define NSS_CA_STORE 2 /* NSS built-in CA certificates. */
#define NSS_CERT8_CA_STORE 3 /* NSS built-in CA certificates + directories
                                with cert8.db, key3.db, secmod.db */
#define OSX_CA_STORE 4 /* Mac OS X CA store. */
#define WIN_CA_STORE 5 /* Windows CA store. */

/* Select which CA store to use. */
#ifndef CA_STORE
   #define CA_STORE NONE_CA_STORE
   #warning "No CA store is being used."
#endif /* !CA_STORE */


#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ldns/wire2host.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/x509.h"

#include "ca_stores.h"
#include "common.h"
#include "dane-plug.h"
#include "dane-states.gen"

#if TGT_SYSTEM == TGT_WIN
/* Windows */
  #include "ldns/config.h"
  #include "ldns/ldns.h"
//  #include "libunbound/unbound.h"
  #include "unbound.h"

  #include <wincrypt.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #include <winreg.h>

  #define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

  #ifndef CERT_SYSTEM_STORE_CURRENT_USER
    #define CERT_SYSTEM_STORE_CURRENT_USER 0x00010000
  #endif

  #ifndef CCERT_CLOSE_STORE_CHECK_FLAG
    #define CERT_CLOSE_STORE_CHECK_FLAG 0x00000002
  #endif

#else
/* Linux */
  #include <sys/stat.h> /* stat(2) */
  #include <sys/types.h>
  #include <sys/socket.h>

  #include <arpa/inet.h>
  #include <dirent.h> /* opendir(3) */
  #include <netdb.h>
  #include <netinet/in.h>
  #include <unistd.h> /* stat(3) */

  #include "ldns/ldns.h"
  #include "ldns/packet.h"
  #include "unbound.h"
#endif

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
// define policy of browser
#define ALLOW_TYPE_01 1
#define ALLOW_TYPE_23 2
// define DANE constants
#define CA_CERT_PIN 0
#define EE_CERT_PIN 1
#define CA_TA_ADDED 2
#define EE_TA_ADDED 3
#define EXACT 0
#define SHA256 1
#define SHA512 2
#define FULL 0
#define SPKI 1


//----------------------------------------------------------------------------

/* structure to save input options of validator */
struct dane_options_st {
	bool usefwd; // use of resolver
	bool ds; // use root.key with DS record of root zone
};

/* DNSSEC status */
enum dnssec_stat {
	DNSSEC_STAT_INSECURE = 0,
	DNSSEC_STAT_SECURE,
	DNSSEC_STAT_BOGUS
};

//----------------------------------------------------------------------------
static const char byteMap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8',
     '9', 'A', 'B', 'C', 'D', 'E', 'F'};
static int byteMapLen = sizeof(byteMap);
//----------------------------------------------------------------------------
/* structure to save TLSA records */
struct tlsa_store_item {
	char *domain;
	enum dnssec_stat dnssec_status;
	uint8_t cert_usage;
	uint8_t selector;
	uint8_t matching_type;
	uint8_t *association;
	size_t association_size;
	unsigned char *assochex;
	struct tlsa_store_item *next;
};

#define tlsa_store_item_init(ptr) \
	do { \
		(ptr)->domain = NULL; \
		(ptr)->dnssec_status = DNSSEC_STAT_INSECURE; \
		(ptr)->cert_usage = 0; \
		(ptr)->selector = 0; \
		(ptr)->matching_type = 0; \
		(ptr)->association = NULL; \
		(ptr)->association_size = 0; \
		(ptr)->assochex = NULL; \
		(ptr)->next = NULL; \
	} while(0)

/* pointer structure to save TLSA records */
struct tlsa_store_head {
	struct tlsa_store_item *first;
};

/* structure to save certificate records */
struct cert_store_item {
	char *cert_der;
	int cert_len;
	char *cert_der_hex;
	char *spki_der;
	int spki_len;
	char *spki_der_hex;
	struct cert_store_item *next;
};

#define cert_store_item_init(ptr) \
	do { \
		(ptr)->cert_der = NULL; \
		(ptr)->cert_len = 0; \
		(ptr)->cert_der_hex = NULL; \
		(ptr)->spki_der = NULL; \
		(ptr)->spki_len = 0; \
		(ptr)->spki_der_hex = NULL; \
		(ptr)->next = NULL; \
	} while(0)

/* pointer structure to save certificate records */
struct cert_store_head {
	struct cert_store_item *first;
};

/* Structure to save certificate records */
struct cert_tmp_ctx {
	char *spki_der;
	int spki_len;
	char *spki_der_hex;
};


/* DANE validation context. */
struct dane_validation_ctx {
	struct dane_options_st opts; /* Options. */
	struct ub_ctx *ub; /*
	                    * Unbound context.
	                    * Initialised outside the context initialisation
	                    * procedure.
	                    */
	SSL_CTX *ssl_ctx; /* SSL context. */
};
static
struct dane_validation_ctx glob_val_ctx = {
	{false, false}, NULL, NULL
};
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------


//*****************************************************************************
// read input options into a structure
// ----------------------------------------------------------------------------
void dane_set_validation_options(struct dane_options_st *opts,
    uint16_t options)
{
	assert(opts != NULL);

	/* TODO -- Not really a structure member. */
	global_debug = options & DANE_FLAG_DEBUG;

	opts->usefwd = options & DANE_FLAG_USEFWD;
	opts->ds = false;
}


//*****************************************************************************
// Function checks whether supplied string contains a port number
// Returns -1 if not a number in range <0-65535>
// ----------------------------------------------------------------------------
static
int str_is_port_number(const char *port_str)
{
	unsigned i, length;
	unsigned long port_num;

	assert(port_str != NULL);

	length = strlen(port_str);
	if ((length == 0) || (length > 5)) {
		return -1;
	}
	for (i = 0; i < length; ++i) {
		if (!isdigit(port_str[0])) {
			return -1;
		}
	}
	port_num = strtoul(port_str, NULL, 10);
	if (port_num > 65535) {
		return -1;
	}

	return port_num;
}


//*****************************************************************************
// Helper function (SSL connection)
// create_socket() creates the socket & TCP-connect to server
// domain contains only domain name, port_str contains port number
// ----------------------------------------------------------------------------
static
int create_socket(const char *domain, const char *port_str)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, getaddrres;

#ifdef WIN32
	WSADATA wsaData;
	WORD version;
	int error;

	version = MAKEWORD( 2, 0 );
	error = WSAStartup( version, &wsaData );

	/* check for error */
	if (error != 0) {
		return -1;
	}

	/* check for correct version */
	if ((LOBYTE(wsaData.wVersion) != 2) ||
	    (HIBYTE(wsaData.wVersion) != 0)) {
		WSACleanup();
		return -1;
	}
#endif /* WIN32 */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;          /* Any protocol */

	getaddrres = getaddrinfo(domain, port_str, &hints, &result);
	if (getaddrres != 0) {
		printf_debug(DEBUG_PREFIX_CERT, "Error: getaddrinfo: %s\n",
		    gai_strerror(getaddrres));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,rp->ai_protocol);
		if (sfd == -1) {
			continue;
		}

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
			break; //Success
		}

		close(sfd);
	}

	if (rp == NULL) {               /* No address succeeded */
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Could not connect to remote server!");
		return -1;
	}

	freeaddrinfo(result);           /* No longer needed */

	return sfd;
}

//*****************************************************************************
// Helper function (return DNSSEC status)
// ----------------------------------------------------------------------------
static
const char * get_dnssec_status(enum dnssec_stat dnssec_status)
{
	switch (dnssec_status) {
	case DNSSEC_STAT_INSECURE: return "INSECURE";
	case DNSSEC_STAT_SECURE: return "SECURE";
	case DNSSEC_STAT_BOGUS: return "BOGUS";
	default: assert(0); return "ERROR";
	}
}


//*****************************************************************************
// Utility function to convert nibbles (4 bit values) into a hex character
// representation.
// ----------------------------------------------------------------------------
static
char nibbleToChar(uint8_t nibble)
{
	if (nibble < byteMapLen) return byteMap[nibble];
	return '*';
}


//*****************************************************************************
// Helper function (binary data to hex string conversion)
// ----------------------------------------------------------------------------
static
char * bintohex(const uint8_t *bytes, size_t buflen)
{
	char *retval = NULL;
	unsigned i;

	retval = malloc(buflen * 2 + 1);

	if (retval == NULL) {
		return NULL;
	}

	for (i = 0; i < buflen; ++i) {
		retval[i * 2] = nibbleToChar(bytes[i] >> 4);
		retval[i * 2 + 1] = nibbleToChar(bytes[i] & 0x0f);
	}
	retval[i * 2] = '\0';
	return retval;
}


//*****************************************************************************
// Helper function (hex to int)
// ----------------------------------------------------------------------------
static
int hex_to_int(char c)
{
	if(c >=97) c=c-32;
	int first = c / 16 - 3;
	int second = c % 16;
	int result = first*10 + second;
	if (result > 9) result--;
	return result;
}


//*****************************************************************************
// Helper function (hex to char)
// ----------------------------------------------------------------------------
static
int hex_to_ascii(char c, char d)
{
	int high = hex_to_int(c) * 16;
	int low = hex_to_int(d);
	return high+low;
}


//*****************************************************************************
// HEX string to Binary data converter
//
// Return NULL on failure.
// ----------------------------------------------------------------------------
static
char * hextobin(const char *data)
{
	size_t length = strlen(data);
	unsigned i;
	char *buf;

	/* Two hex digits encode one byte. */
	assert((length % 2) == 0);
	buf = malloc(length >> 1);
	if (buf == NULL) {
		return NULL;
	}

	for(i = 0; i < length; i += 2){
		buf[i >> 1] = hex_to_ascii(data[i], data[i + 1]);
	}
	return buf;
}


//*****************************************************************************
// Helper function (add new record in the TLSA list - last)
//
// Return 0 on success, -1 else.
//
// Note: Association related data are not copied, only pointer values are
// copied.
// ----------------------------------------------------------------------------
static
int add_tlsarecord_bottom(struct tlsa_store_head *tlsa_list,
	const char *domain, enum dnssec_stat dnssec_status, uint8_t cert_usage,
	uint8_t selector, uint8_t matching_type,
	const uint8_t *association, size_t association_size)
{
	struct tlsa_store_item *tlsa_entry = NULL;
	size_t size;

	assert(domain != NULL);
	assert(association != NULL);
	assert(association_size > 0);

	tlsa_entry = malloc(sizeof(struct tlsa_store_item));
	if (tlsa_entry == NULL) {
		goto fail;
	}

	tlsa_store_item_init(tlsa_entry);

	size = strlen(domain) + 1;
	tlsa_entry->domain = malloc(size);
	if (tlsa_entry->domain == NULL) {
		goto fail;
	}
	memcpy(tlsa_entry->domain, domain, size);

	tlsa_entry->dnssec_status = dnssec_status;
	tlsa_entry->cert_usage = cert_usage;
	tlsa_entry->selector = selector;
	tlsa_entry->matching_type = matching_type;

	tlsa_entry->association = malloc(association_size);
	if (tlsa_entry->association == NULL) {
		goto fail;
	}
	memcpy(tlsa_entry->association, association, association_size);
	tlsa_entry->association_size = association_size;
	tlsa_entry->assochex = (unsigned char *) bintohex(association,
	    association_size);
	if (tlsa_entry->assochex == NULL) {
		goto fail;
	}

	tlsa_entry->next = NULL;

	if (tlsa_list->first != NULL) {
		struct tlsa_store_item *tmp = tlsa_list->first;
		while (tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = tlsa_entry;
	} else {
		tlsa_list->first = tlsa_entry;
	}

	return 0;

fail:
	if (tlsa_entry != NULL) {
		if (tlsa_entry->domain != NULL) {
			free(tlsa_entry->domain);
		}
		if (tlsa_entry->association != NULL) {
			free(tlsa_entry->association);
		}
		if (tlsa_entry->assochex != NULL) {
			free(tlsa_entry->assochex);
		}
		free(tlsa_entry);
	}
	return -1;
}

//*****************************************************************************
// Helper function (print TLSA list)
// ----------------------------------------------------------------------------
static
void print_tlsalist_debug(const struct tlsa_store_head *tlsa_list)
{
	struct tlsa_store_item *tmp;
	int num;

	if (!global_debug) {
		/* Function prints only debugging information. */
		return;
	}

	num = 1;
	tmp = tlsa_list->first;
	while (tmp != NULL) {
		printf_debug(DEBUG_PREFIX_TLSA,
		    ">> %04d ---------------------------------------\n", num);
		printf_debug(DEBUG_PREFIX_TLSA,
		    "%s: dnssec: %s (%d), cert usage: %d, selector: %d, "
		    "matching type: %d, assoc.hex: %s, assoc.size: %zu \n",
		    tmp->domain, get_dnssec_status(tmp->dnssec_status),
		    tmp->dnssec_status, tmp->cert_usage, tmp->selector,
		    tmp->matching_type, tmp->assochex,
		    tmp->association_size);
		printf_debug(DEBUG_PREFIX_TLSA,
		    "<< %04d ---------------------------------------\n", num);
		++num;
		tmp = tmp->next;
	}
}

//*****************************************************************************
// Helper function (print certificate list)
// ----------------------------------------------------------------------------
static
void print_certlist_debug(const struct cert_store_head *cert_list)
{
	struct cert_store_item *tmp;
	unsigned num;
	X509 *cert_x509 = NULL;
	const unsigned char *cert_der;
	BIO *mem_bio;
	char *bio_data;

	if (!global_debug) {
		/* Function prints only debugging information. */
		return;
	}

	num = 1;
	tmp = cert_list->first;
	while (tmp != NULL) {
		printf_debug(DEBUG_PREFIX_CERT,
		    ">> %04d ---------------------------------------\n", num);
		/* TODO -- Get rid of the explicit conversion. */
		cert_der = (unsigned char *) tmp->cert_der;
		cert_x509 = d2i_X509(NULL, &cert_der, tmp->cert_len);
		if (cert_x509 != NULL) {
			mem_bio = BIO_new(BIO_s_mem());
			if (mem_bio != NULL) {
				printf_debug(DEBUG_PREFIX_CERT, "%s\n",
				    "Certificate in text format:");
				X509_print_ex(mem_bio, cert_x509,
				    XN_FLAG_COMPAT, X509_FLAG_COMPAT);
				X509_free(cert_x509); cert_x509 = NULL;

				BIO_get_mem_data(mem_bio, &bio_data);
				/*
				 * Make sure the buffer content is
				 * null-terminated.
				 */
				BIO_write(mem_bio, "", 1);

				/* Already contains new line at the end. */
				printf_debug(DEBUG_PREFIX_CERT, "%s",
				    bio_data);

				BIO_free(mem_bio);
			} else {
				printf_debug(DEBUG_PREFIX_CERT, "%s\n",
				    "Cannot create memory BIO.\n");
			}
		} else {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot convert certificate into text format.");
		}
		printf_debug(DEBUG_PREFIX_CERT, "certlen: %i\n%s\n",
		    tmp->cert_len, tmp->cert_der_hex);
		printf_debug(DEBUG_PREFIX_CERT, "spkilen: %i\n%s\n",
		     tmp->spki_len, tmp->spki_der_hex);
		printf_debug(DEBUG_PREFIX_CERT,
		    "<< %04d ---------------------------------------\n", num);
		++num;
		tmp = tmp->next;
	}
}


//*****************************************************************************
// Helper function
// ----------------------------------------------------------------------------
static
void free_tlsalist_item(struct tlsa_store_item *tlsa_item)
{
	assert(tlsa_item != NULL);

	free(tlsa_item->domain);
	free(tlsa_item->association);
	free(tlsa_item->assochex);
	free(tlsa_item);
}

//*****************************************************************************
// Helper function (free TLSA list)
// ----------------------------------------------------------------------------
static
void free_tlsalist(struct tlsa_store_head *tlsa_list)
{
	struct tlsa_store_item *aux;

	while (tlsa_list->first != NULL) {
		aux = tlsa_list->first->next;

		free_tlsalist_item(tlsa_list->first);

		tlsa_list->first = aux;
	}
}

//*****************************************************************************
// Helper function (free certificate list)
// ----------------------------------------------------------------------------
static
void free_certlist(struct cert_store_head *cert_list)
{
	struct cert_store_item *aux;

	while (cert_list->first != NULL) {
		aux = cert_list->first->next;

		free(cert_list->first->cert_der);
		free(cert_list->first->spki_der);
		free(cert_list->first->cert_der_hex);
		free(cert_list->first->spki_der_hex);
		free(cert_list->first);

		cert_list->first = aux;
	}
}

//*****************************************************************************
// DANE algorithm (spkicert)
// Get SPKI from binary data of certificate
// return struct (binary SPKI, SPKI length, SPKI in HEX format and its length
// ----------------------------------------------------------------------------
static
struct cert_tmp_ctx spkicert(const char *certder, int len)
{
	struct cert_tmp_ctx tmp;
	EVP_PKEY *pkey = NULL;
	X509 *cert;
	cert = d2i_X509(NULL, (const unsigned char **) &certder, len);
	if (cert == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error obtaining X509 from hex.");
	}

	if ((pkey = X509_get_pubkey(cert)) == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error getting public key from certificate");
	}

	int len2;
	unsigned char *buf2;
	char *hex2;
	buf2 = NULL;
	len2 = i2d_PUBKEY(pkey, &buf2);
	hex2 = bintohex((uint8_t*)buf2, len2);
	tmp.spki_der = (char*) buf2;
	tmp.spki_len =len2;
	tmp.spki_der_hex = hex2;
	X509_free(cert);
	EVP_PKEY_free(pkey);
	//free(buf2);
	return tmp;
}

//*****************************************************************************
// Helper function (add new record in the certificate list - last)
//
// Return 0 on success -1 on failure.
// ----------------------------------------------------------------------------
static
int add_certrecord_bottom_from_der_hex(struct cert_store_head *cert_list,
    const char *der_hex)
{
	struct cert_store_item *cert_entry = NULL;
	size_t hex_len;

	assert(cert_list != NULL);
	assert(der_hex != NULL);

	cert_entry = malloc(sizeof(struct cert_store_item));
	if (cert_entry == NULL) {
		goto fail;
	}

	cert_store_item_init(cert_entry);

	hex_len = strlen(der_hex);
	assert(!(hex_len & 0x01)); /* Must be even number. */

	cert_entry->cert_der = hextobin(der_hex);
	if (cert_entry->cert_der == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error converting hex DER to bin.");
		goto fail;
	}

	cert_entry->cert_len = hex_len >> 1;

	cert_entry->cert_der_hex = malloc(hex_len + 1);
	if (cert_entry->cert_der_hex == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n", "Errror copying hex.");
		goto fail;
	}
	memcpy(cert_entry->cert_der_hex, der_hex, hex_len + 1);

	struct cert_tmp_ctx spki = spkicert(cert_entry->cert_der,
	    cert_entry->cert_len);

	cert_entry->spki_der = spki.spki_der;
	if (cert_entry->spki_der == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error obtaining SPKI DER.");
		goto fail;
	}

	cert_entry->spki_len = spki.spki_len;

	cert_entry->spki_der_hex = spki.spki_der_hex;
	if (cert_entry->spki_der == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error obtaining SPKI DER hex.");
		goto fail;
	}

	/* Append to list. */
	if (cert_list->first != NULL) {
		struct cert_store_item *tmp = cert_list->first;
		while (tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = cert_entry;
	} else {
		cert_list->first = cert_entry;
	}

	return 0;

fail:
	if (cert_entry != NULL) {
		if (cert_entry->cert_der != NULL) {
			free(cert_entry->cert_der);
		}
		if (cert_entry->cert_der_hex != NULL) {
			free(cert_entry->cert_der_hex);
		}
		if (cert_entry->spki_der != NULL) {
			free(cert_entry->spki_der);
		}
		if (cert_entry->spki_der_hex != NULL) {
			free(cert_entry->spki_der_hex);
		}
		free(cert_entry);
	}
	return -1;
}

//*****************************************************************************
// Helper function (add new record in the certificate list - last)
//
// Return 0 on success -1 on failure.
// ----------------------------------------------------------------------------
static
int add_certrecord_bottom_from_x509(struct cert_store_head *cert_list,
    X509 *x509)
{
	struct cert_store_item *cert_entry = NULL;
	EVP_PKEY *pkey = NULL;

	assert(cert_list != NULL);
	assert(x509 != NULL);

	cert_entry = malloc(sizeof(struct cert_store_item));
	if (cert_entry == NULL) {
		goto fail;
	}

	cert_store_item_init(cert_entry);

	cert_entry->cert_der = NULL;
	cert_entry->cert_len = i2d_X509(x509,
	    (unsigned char **) &cert_entry->cert_der);
	if (cert_entry->cert_len < 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error encoding into DER.");
		goto fail;
	}
	cert_entry->cert_der_hex =
	    bintohex((uint8_t *) cert_entry->cert_der,
	        cert_entry->cert_len);
	if (cert_entry->cert_der_hex == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error converting DER to hex.");
		goto fail;
	}

	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error getting public key from certificate");
		goto fail;
	}

	cert_entry->spki_der = NULL;
	cert_entry->spki_len = i2d_PUBKEY(pkey,
	    (unsigned char **) &cert_entry->spki_der);

	EVP_PKEY_free(pkey); pkey = NULL;

	if (cert_entry->spki_len < 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error encoding into DER.");
		goto fail;
	}
	cert_entry->spki_der_hex =
	    bintohex((uint8_t *) cert_entry->spki_der,
	        cert_entry->spki_len);
	if (cert_entry->spki_der_hex == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error converting DER to hex.");
		goto fail;
	}

	/* Append to list. */
	if (cert_list->first != NULL) {
		struct cert_store_item *tmp = cert_list->first;
		while (tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = cert_entry;
	} else {
		cert_list->first = cert_entry;
	}

	return 0;

fail:
	if (cert_entry != NULL) {
		if (cert_entry->cert_der != NULL) {
			free(cert_entry->cert_der);
		}
		if (cert_entry->cert_der_hex != NULL) {
			free(cert_entry->cert_der_hex);
		}
		if (cert_entry->spki_der != NULL) {
			free(cert_entry->spki_der);
		}
		if (cert_entry->spki_der_hex != NULL) {
			free(cert_entry->spki_der_hex);
		}
		free(cert_entry);
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	return -1;
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
// Get certificates from SSL handshake
// Add certificate into structure
// Helper function
// return 0 success or -1 on error
// TODO -- Is there a feasible way how to get certificate chain from the server
// without using SSL_connect(3) ?
// ----------------------------------------------------------------------------
static
int get_cert_list(SSL_CTX *ssl_ctx, const char *dest_url,
    const char *domain, const char *port,
    struct cert_store_head *cert_list)
{
	int i;
	SSL *ssl = NULL;
	int server_fd = -1;
#if CA_STORE != NONE_CA_STORE
	X509 *cert = NULL;
	X509_STORE_CTX *store_ctx = NULL;
	STACK_OF(X509) *verified_chain = NULL;
#endif /* !NONE_CA_STORE */
	STACK_OF(X509) *chain;
	X509 *cert2;
	EVP_PKEY *pkey = NULL;
	int ret;

	assert(ssl_ctx != NULL);

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Cannot create SSL structure.");
		goto fail;
	}

	server_fd = create_socket(domain, port);
	if(server_fd == -1) {
		printf_debug(DEBUG_PREFIX_CERT,
		    "Error establishing TCP connection to: %s.\n", dest_url);
		goto fail;
	}

	if (SSL_set_fd(ssl, server_fd) != 1) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Error: Cannot set server socket.");
		goto fail;
	}

	if (domain != NULL) {
		if (!SSL_set_tlsext_host_name(ssl, domain)) {
			printf_debug(DEBUG_PREFIX_CERT,
			    "Error: Unable to set TLS server-name-indication "
			    "extension: %s.\n", domain);
			goto fail;
		}
	}

	ret = SSL_connect(ssl);
	if (ret < 0) {
		printf_debug(DEBUG_PREFIX_CERT,
		    "Error: Could not build a SSL session to: %s.\n",
		    dest_url);
		goto fail;
	} else if (0 == ret) {
		printf_debug(DEBUG_PREFIX_CERT,
		    "Error: SSL handshake with %s shut down by controller.\n",
		    dest_url);
	}

	assert(ret >= 0);

	chain = SSL_get_peer_cert_chain(ssl);
	if (chain == NULL) {
		printf_debug(DEBUG_PREFIX_CERT,
		    "Error: Could not get a certificate chain: %s.\n",
		    dest_url);
		goto fail;
	}

	printf_debug(DEBUG_PREFIX_CERT,
	    "There are %d certificates in the peer chain.\n",
	    sk_X509_num(chain));

#if CA_STORE != NONE_CA_STORE
	{
//		printf_debug()

		cert = SSL_get_peer_certificate(ssl);
		if (cert == NULL) {
			printf_debug(DEBUG_PREFIX_CERT,
			    "Error: Could not get a certificate from: %s.\n",
			    dest_url);
			goto fail;
		}

		/*
		 * Initialize a store context with store (for root CA certs),
		 * the peer's cert and the peer's chain with intermediate CA
		 * certs.
		 */

		store_ctx = X509_STORE_CTX_new();
		if (store_ctx == NULL) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot create store context.");
			goto fail;
		}

		if (X509_STORE_CTX_init(store_ctx,
		         SSL_CTX_get_cert_store(ssl_ctx), cert, chain) == 0) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Cannot initialise store context.");
			goto fail;
		}

		/*
		 * Validate peer cert using its intermediate CA certs and the
		 * context's root CA certs.
		 */
		if (X509_verify_cert(store_ctx) <= 0) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Error verifying certificates using current "
			    "CA store.");
			/* verified_chain is NULL, use chain */
		} else {
			/* Get chain from store context */
			verified_chain = X509_STORE_CTX_get1_chain(store_ctx);
			printf_debug(DEBUG_PREFIX_CERT,
			    "There are %d certificates in the verified "
			    "certificate chain.\n",
			    sk_X509_num(verified_chain));
			chain = verified_chain;
			/* Use verified_chain. */
		}
		X509_STORE_CTX_free(store_ctx); store_ctx = NULL;
		X509_free(cert); cert = NULL;
	}
#endif /* !NONE_CA_STORE */

	for (i = 0; i < sk_X509_num(chain); ++i) {
		cert2 = sk_X509_value(chain, i);

		if (add_certrecord_bottom_from_x509(cert_list, cert2) != 0) {
			printf_debug(DEBUG_PREFIX_CERT, "%s\n",
			    "Error adding certificate into list.\n");
			goto fail;
		}
	}

#if CA_STORE != NONE_CA_STORE
	if (verified_chain != NULL) {
		/*
		 * Verified chain has to be freed explicitly if successfully
		 * verified in the CA store.
		 */
		sk_X509_pop_free(verified_chain, X509_free);
		    verified_chain = NULL;
	}
#endif /* !NONE_CA_STORE */

#ifdef WIN32
	closesocket(server_fd);
	WSACleanup();
#else
	close(server_fd);
#endif

	SSL_shutdown(ssl);
	SSL_free(ssl);

	printf_debug(DEBUG_PREFIX_CERT,
	    "Finished SSL/TLS connection with server: %s.\n",
	    dest_url);

	return 0;

fail:
	if (ssl != NULL) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	if (server_fd != -1) {
#ifdef WIN32
		closesocket(server_fd);
		WSACleanup();
#else
		close(server_fd);
#endif
	}
#if CA_STORE != NONE_CA_STORE
	if (cert != NULL) {
		X509_free(cert);
	}
	if (store_ctx != NULL) {
		X509_STORE_CTX_free(store_ctx);
	}
	if (verified_chain != NULL) {
		sk_X509_pop_free(verified_chain, X509_free);
	}
#endif /* !NONE_CA_STORE */
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	return -1;
}

//*****************************************************************************
// DANE algorithm (opensslDigest)
// return binary data of certificate or SPKI encode by sha256, sha512 as HEX string
// ----------------------------------------------------------------------------
static
char * opensslDigest(const EVP_MD *md, const char *data, int len)
{
	EVP_MD_CTX mdctx;
	unsigned int md_len;
	unsigned char md_value[64];
	char *hex;

	assert(md);
	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, data, len);
	EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);
	hex = bintohex((uint8_t*)md_value, md_len);

	return hex;
}

//*****************************************************************************
// DANE algorithm
// return binary data of certificate or SPKI encode by sha256
// ----------------------------------------------------------------------------
static
char * sha256(const char *data, int len)
{
	printf_debug(DEBUG_PREFIX_DANE, "%s\n", "crypto: SHA-256");

	return opensslDigest(EVP_sha256(), data, len);
}

//*****************************************************************************
// DANE algorithm
// return binary data of certificate or SPKI encode by sha512
// ----------------------------------------------------------------------------
static
char * sha512(const char *data, int len)
{
	printf_debug(DEBUG_PREFIX_DANE, "%s\n", "crypto: SHA-512");

	return opensslDigest(EVP_sha512(), data, len);
}

//*****************************************************************************
// DANE algorithm  (selector)
// return binary data of certificate or SPKI
// ----------------------------------------------------------------------------
static
const char * selectorData(uint8_t selector,
    const struct cert_store_item *cert_item)
{
	printf_debug(DEBUG_PREFIX_DANE, "selector: %i \n",
	    selector);
	switch (selector) {
	case FULL:
		return cert_item->cert_der;
	case SPKI:
		return cert_item->spki_der;
	default:
		printf_debug(DEBUG_PREFIX_DANE,
		    "Wrong value of selector parameter: %i \n", selector);
		return NULL;
	}
}

//*****************************************************************************
// DANE algorithm (matching_type)
// return copy of binary data of certificate or SPKI encode in SHA256, SHA512
// Caller must ensure proper deallocation of memory.
// ----------------------------------------------------------------------------
static
char * matchingData(uint8_t matching_type, uint8_t selector,
    const struct cert_store_item *cert_item)
{
	printf_debug(DEBUG_PREFIX_DANE, "matching_type: %i \n", matching_type);

	const char *data = selectorData(selector, cert_item);
	char *der_copy;
	unsigned i;

	if (data == NULL) {
		return NULL;
	}
	switch (matching_type) {
	case EXACT:
		der_copy = malloc(strlen(cert_item->cert_der_hex) + 1);
		if (der_copy == NULL) {
			return NULL;
		}
		/* Convert hex string to upper case. */
		for (i = 0; i < (strlen(cert_item->cert_der_hex) + 1); ++i) {
			der_copy[i] = toupper(cert_item->cert_der_hex[i]);
		}
		return der_copy;
	case SHA256:
		if (selector==SPKI) {
			return sha256(data, cert_item->spki_len);
		} else {
			return sha256(data, cert_item->cert_len);
		}
	case SHA512:
		if (selector==SPKI) {
			return sha512(data, cert_item->spki_len);
		} else {
			return sha512(data, cert_item->cert_len);
		}
	default:
		printf_debug(DEBUG_PREFIX_DANE,
		    "Wrong value of matching_type parameter: %i \n",
		    matching_type);
		return NULL;
	}
}

//*****************************************************************************
// TLSA validation of EE certificate (type 1)
// Binary data codes EE certificate
// Servers certificate must correspond EE certificate in TLSA
// TODO -- Server certificate must pass PKIX validation to trust anchor.
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int eeCertMatch1(const struct tlsa_store_item *tlsa_item,
    const struct cert_store_head *cert_list)
{
	//printf_debug(DEBUG_PREFIX_DANE, "eeCertMatch1\n");

	int ret_val = DANE_INVALID_TYPE1;
	char *data = matchingData(tlsa_item->matching_type,
	    tlsa_item->selector, cert_list->first);

	if (data == NULL) {
		return DANE_TLSA_PARAM_ERR;
	}

	if (strcmp(data, (const char *) tlsa_item->assochex) == 0) {
		ret_val = DANE_VALID_TYPE1;
	}

	printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
	printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n", tlsa_item->assochex);

	free(data);
	return ret_val;
}


//*****************************************************************************
// TLSA validation of EE certificate (type 3)
// Binary data codes EE certificate
// Servers certificate must correspond EE certificate in TLSA
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int eeCertMatch3(const struct tlsa_store_item *tlsa_item,
    const struct cert_store_head *cert_list)
{
	//printf_debug(DEBUG_PREFIX_DANE, "eeCertMatch3\n");

	int ret_val = DANE_INVALID_TYPE3;
	char *data = matchingData(tlsa_item->matching_type,
	    tlsa_item->selector, cert_list->first);

	if (data == NULL) {
		return DANE_TLSA_PARAM_ERR;
	}

	if (strcmp(data, (const char *) tlsa_item->assochex) == 0) {
		ret_val = DANE_VALID_TYPE3;
	}

	printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
	printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n", tlsa_item->assochex);

	free(data);
	return ret_val;
}

//*****************************************************************************
// TLSA validation CA certificate (type 0)
// Binary data codes CA certificate
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int caCertMatch(const struct tlsa_store_item *tlsa_item,
    const struct cert_store_head *cert_list)
{
	const struct cert_store_item *aux_cert;

	//printf_debug(DEBUG_PREFIX_DANE, "caCertMatch0\n");

	int ret_val = DANE_INVALID_TYPE0;

	if ((cert_list->first == NULL) || (cert_list->first->next == NULL)) {
		return DANE_NO_CERT_CHAIN;
	}

	aux_cert = cert_list->first->next;
	while (aux_cert != NULL) {
		char *data = matchingData(tlsa_item->matching_type,
		    tlsa_item->selector, aux_cert);
		if (data == NULL) {
			return DANE_TLSA_PARAM_ERR;
		}

		printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
		printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n",
		    tlsa_item->assochex);

		if (strcmp((const char *) data,
		        (const char *) tlsa_item->assochex) == 0) {
			free(data);
			return DANE_VALID_TYPE0;
		}

		free(data);
		aux_cert = aux_cert->next;
	}
	return ret_val;
}

//*****************************************************************************
// TLSA validation new trust anchor (type 2)
// Binary data codes CA certificate
// This certificate is use as new trust anchor
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int chainCertMatch(const struct tlsa_store_item *tlsa_item,
    const struct cert_store_head *cert_list)
{
	const struct cert_store_item *aux_cert;

	//printf_debug(DEBUG_PREFIX_DANE, "chainCertMatch2\n");

	if (cert_list->first == NULL) {
		return DANE_NO_CERT_CHAIN;
	}

	int ret_val = DANE_INVALID_TYPE2;

	aux_cert = cert_list->first;
	while (aux_cert != NULL) {
		char *data = matchingData(tlsa_item->matching_type,
		    tlsa_item->selector, aux_cert);
		if (data == NULL) {
			return DANE_TLSA_PARAM_ERR;
		}

		printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
		printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n",
		    tlsa_item->assochex);

		if (strcmp((const char *) data,
		        (const char *) tlsa_item->assochex) == 0) {
			free(data);
			return DANE_VALID_TYPE2;
		}

		free(data);
		aux_cert = aux_cert->next;
	}
	return ret_val;
}

//*****************************************************************************
// Main TLSA validation function
// Validates and compares TLSA records with certificate or SPKI
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int tlsa_validate(const struct tlsa_store_head *tlsa_list,
    const struct cert_store_head *cert_list)
{
	int val_ret;
	const struct tlsa_store_item *aux_tlsa;

	val_ret = DANE_NO_TLSA;
	aux_tlsa = tlsa_list->first;
	while (aux_tlsa != NULL) {
		val_ret = DANE_NO_TLSA;

		switch (aux_tlsa->dnssec_status) {
		case DNSSEC_STAT_INSECURE:
			return DANE_DNSSEC_UNSECURED;
		case DNSSEC_STAT_BOGUS:
			return DANE_DNSSEC_BOGUS;
		case DNSSEC_STAT_SECURE:
			printf_debug(DEBUG_PREFIX_DANE,
			    "cert_usage: %i \n",
			    aux_tlsa->cert_usage);
			switch (aux_tlsa->cert_usage) {
			case CA_CERT_PIN: //0
				val_ret = caCertMatch(aux_tlsa, cert_list);
				break;
			case CA_TA_ADDED: //2
				val_ret = chainCertMatch(aux_tlsa, cert_list);
				break;
			case EE_CERT_PIN: //1
				val_ret = eeCertMatch1(aux_tlsa, cert_list);
				break;
			case EE_TA_ADDED: //3
				val_ret = eeCertMatch3(aux_tlsa, cert_list);
				break; // continue checking
			default:
				printf_debug(DEBUG_PREFIX_DANE,
				    "Wrong value of cert_usage parameter: %i\n",
				    aux_tlsa->cert_usage);
				/* Unknown cert usage. */
				val_ret = DANE_TLSA_PARAM_ERR;
			}
			break; // continue checking
		}

		aux_tlsa = aux_tlsa->next;
		if ((val_ret >= DANE_VALID_TYPE0) &&
		    (val_ret <= DANE_VALID_TYPE3)) {
			return val_ret;
		}
	}

	return val_ret;
}

//*****************************************************************************
// Parse TLSA records from DNS response for particular domain name
// Store TSLA data into TLSA structure and add structure in the list
// return 1 if success or 0 when TLSA record is wrong or missing
// ----------------------------------------------------------------------------
static
int parse_tlsa_record(struct tlsa_store_head *tlsa_list,
    const struct ub_result *ub_res, const char *domain)
{
	ldns_pkt *packet = NULL;
	ldns_rr_list *rrs = NULL;
	unsigned i = 0;
	int exitcode = DANE_ERROR_RESOLVER;

	assert(tlsa_list != NULL);
	assert(ub_res != NULL);
	assert(domain != NULL);

	/* show security status */
	if (ub_res->rcode == LDNS_RCODE_SERVFAIL) {
		return DANE_ERROR_RESOLVER;
	}

	if (ub_res->secure) {
		/* show tlsa_first result */
		if (ub_res->havedata) {

			printf_debug(DEBUG_PREFIX_TLSA, "%s\n",
			    "Domain is secured by DNSSEC ... "
			    "found TLSA record(s).");

			ldns_status parse_status = ldns_wire2pkt(&packet,
			    (uint8_t *)(ub_res->answer_packet),
			    ub_res->answer_len);

			if (parse_status != LDNS_STATUS_OK) {
				printf_debug(DEBUG_PREFIX_TLSA, "%s\n",
				     "Failed to parse response packet.");
				exitcode = DANE_ERROR_RESOLVER;
				goto fail;
			}

			rrs = ldns_pkt_rr_list_by_type(packet,
			    LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);
			if (rrs == NULL) {
				printf_debug(DEBUG_PREFIX_TLSA, "%s\n",
				    "Packet has no resource recors.");
				exitcode = DANE_ERROR_RESOLVER;
				goto fail;
			}
			ldns_pkt_free(packet); packet = NULL;

			for (i = 0; i < ldns_rr_list_rr_count(rrs); ++i) {
				/*
				 * Extract first rdf, which is the whole TLSA
				 * record.
				 */
				ldns_rr *rr = ldns_rr_list_rr(rrs, i);
				assert(rr != NULL);
				/*
				 * Since ldns 1.6.14, RR for TLSA is parsed
				 * into 4 RDFs instead of 1 RDF in ldns 1.6.13.
				 */
				if (ldns_rr_rd_count(rr) < 4) {
					printf_debug(DEBUG_PREFIX_TLSA,
					    "RR %d hasn't enough fields\n", i);
					exitcode = DANE_TLSA_PARAM_ERR;
					goto fail;
				}
				ldns_rdf *rdf_cert_usage = ldns_rr_rdf(rr, 0),
				    *rdf_selector      = ldns_rr_rdf(rr, 1),
				    *rdf_matching_type = ldns_rr_rdf(rr, 2),
				    *rdf_association   = ldns_rr_rdf(rr, 3);

				if ((ldns_rdf_size(rdf_cert_usage) != 1) ||
				    (ldns_rdf_size(rdf_selector) != 1) ||
				    (ldns_rdf_size(rdf_matching_type) != 1)) {
					printf_debug(DEBUG_PREFIX_TLSA,
					    "Improperly formatted TLSA RR %d\n", i);
					exitcode = DANE_TLSA_PARAM_ERR;
					goto fail;
				}

				uint8_t cert_usage, selector, matching_type;
				uint8_t *association;
				size_t association_size;
				cert_usage = ldns_rdf_data(rdf_cert_usage)[0];
				selector = ldns_rdf_data(rdf_selector)[0];
				matching_type = ldns_rdf_data(rdf_matching_type)[0];
				association = ldns_rdf_data(rdf_association);
				association_size = ldns_rdf_size(rdf_association);
				if (add_tlsarecord_bottom(tlsa_list, domain, 1,
				    cert_usage, selector, matching_type,
				    association, association_size) != 0) {
					exitcode = DANE_ERROR_GENERIC;
					goto fail;
				}
			}

			exitcode = DANE_DNSSEC_SECURED;
			ldns_rr_list_deep_free(rrs); rrs = NULL;

		} else {
			printf_debug(DEBUG_PREFIX_TLSA,
			    "Unbound hasn't received any TLSA data for %s.\n",
			    domain);
			exitcode = DANE_NO_TLSA;
		}
	} else if (ub_res->bogus) {
		exitcode = DANE_DNSSEC_BOGUS;
		printf_debug(DEBUG_PREFIX_TLSA, "Domain is bogus: %s \n",
		    ub_res->why_bogus);
	} else {
		exitcode = DANE_DNSSEC_UNSECURED;
		printf_debug(DEBUG_PREFIX_TLSA, "%s\n",
		    "Domain is insecure...");
	}

	return exitcode;

fail:
	if (packet != NULL) {
		ldns_pkt_free(packet);
	}
	if (rrs != NULL) {
		ldns_rr_list_free(rrs);
	}
	return exitcode;
}


//*****************************************************************************
// Function char * create_tlsa_qname
// returns newly allocated string containing _port._protocol.domain
// e.g: _443._tcp.www.nic.cz
// ----------------------------------------------------------------------------
static
char * create_tlsa_qname(const char *domain, const char *port,
    const char *protocol)
{
	char *tlsa_query;
	unsigned dom_len, port_len, proto_len;
	unsigned offs;

	assert(domain != NULL);
	if (domain == NULL) return NULL;
	assert(port != NULL);
	if (port == NULL) return NULL;
	assert(protocol != NULL);
	if(protocol == NULL) return NULL;

	dom_len = strlen(domain);
	port_len = strlen(port);
	proto_len = strlen(protocol);

	/* '_' + '.' + '_' + '.' + '\0' */
	tlsa_query = malloc(dom_len + port_len + proto_len + 5);
	if (tlsa_query == NULL) {
		return NULL;
	}

	offs = 0;
	tlsa_query[offs++] = '_';

	memcpy(tlsa_query + offs, port, port_len);
	offs += port_len;

	tlsa_query[offs++] = '.';
	tlsa_query[offs++] = '_';

	memcpy(tlsa_query + offs, protocol, proto_len);
	offs += proto_len;

	tlsa_query[offs++] = '.';

	memcpy(tlsa_query + offs, domain, dom_len);
	offs += dom_len;

	tlsa_query[offs] = '\0';

	return tlsa_query;
}


//*****************************************************************************
// Initialises SSL context
// ----------------------------------------------------------------------------
static
SSL_CTX * ssl_context_init(void)
{
	const SSL_METHOD *method;
	SSL_CTX *ssl_ctx = NULL;

	printf_debug(DEBUG_PREFIX_CERT, "%s\n", "Initialising SSL context.");

	/* Initialise SSL. */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	/* Always returns 1. */
	SSL_library_init();

	method = SSLv23_client_method();
	ssl_ctx = SSL_CTX_new(method);
	if (ssl_ctx == NULL) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Unable to create a SSL context structure.");
		goto fail;
	}

	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);

#if CA_STORE == DIR_CA_STORE
	/* Load certificates. */
	if (X509_store_add_certs_from_files_and_dirs(ssl_ctx,
	        ca_files, ca_dirs) != 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Failed loading browser CA certificates.");
		//goto fail; /* Failure is not desired, ignore return value. */
	}
#endif /* DIR_CA_STORE */

#if (CA_STORE == NSS_CA_STORE) || (CA_STORE == NSS_CERT8_CA_STORE)
	if (X509_store_add_certs_from_nssckbi(
	        SSL_CTX_get_cert_store(ssl_ctx)) != 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Failed loading NSS built-in CA certificates.");
		//goto fail; /* Failure is not desired, ignore return value. */
	}
#endif /* NSS_CA_STORE || NSS_CERT8_CA_STORE */

#if CA_STORE == NSS_CERT8_CA_STORE
	if (X509_store_add_certs_from_cert8_dirs(
	    SSL_CTX_get_cert_store(ssl_ctx), cert8_ca_dirs) != 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Failed loading NSS CA certificates from cert8.db.");
		//goto fail; /* Failure is not desired, ignore return value. */
	}
#endif /* NSS_CERT8_CA_STORE */

#if CA_STORE == OSX_CA_STORE
	if (X509_store_add_certs_from_osx_store(
	    SSL_CTX_get_cert_store(ssl_ctx)) != 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Failed loading OS X CA certificates.");
		//goto fail; /* Failure is not desired, ignore return value. */
	}
#endif /* OSX_CA_STORE */

#if defined WIN32 && (CA_STORE == WIN_CA_STORE)
	if (X509_store_add_certs_from_win_store(
	    SSL_CTX_get_cert_store(ssl_ctx)) != 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Failed loading Windows CA certificates.");
		//goto fail; /* Failure is not desired, ignore return value. */
	}
#endif /* WIN32 && WIN_CA_STORE */

	printf_debug(DEBUG_PREFIX_CERT, "%s\n",
	    "Initialisation of SSL context succeeded.");

	return ssl_ctx;

fail:
	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
	}
	printf_debug(DEBUG_PREFIX_CERT, "%s\n",
	    "Initialisation of SSL context failed.");
	return NULL;
}


//*****************************************************************************
// Initialises global validation structures.
// ----------------------------------------------------------------------------
int dane_validation_init(void)
{
	printf_debug(DEBUG_PREFIX_DANE, "%s\n", "Initialising DANE.");

	glob_val_ctx.ub = NULL; /* Has separate initialisation procedure. */
	glob_val_ctx.ssl_ctx = ssl_context_init();

	return (glob_val_ctx.ssl_ctx != NULL) ? 0 : -1;
}

//*****************************************************************************
// Main DANE/TLSA validation function, external API
// Input parmateers:
//        char* certchain[] - array of derCert in HEX (certificate chain)
//        int certcount - number of cert in array - count(array)
//        const uint16_t options - TLSA validator option (debug,IPv4,IPv6)
//        char *optdnssrv - list of IP resolver addresses separated by space
//        char* domain - domain name (e.g.: wwww.nic.cz, torproject.org, ...)
//        char* port_str - number of port for SSL (443, 25)
//        char* protocol - "tcp" only
//        int policy - certificate policy from browser
// Return: DANE/TLSA validation status (x<0 = error, <0-13> = success, x>16 = fail)
//         return values: dane-state.gen file
// ----------------------------------------------------------------------------
int dane_validate(const char *certchain[], int certcount, uint16_t options,
    const char *optdnssrv, const char *domain,  const char *port_str,
    const char *protocol, int policy)
{
	struct ub_result *ub_res = NULL;
	struct tlsa_store_head tlsa_list;
	struct cert_store_head cert_list;
	tlsa_list.first = NULL;
	cert_list.first = NULL;
	int retval;
#define DEFAULT_PORT "443"
#define HTTPS_PREF "https://"
#define HTTPS_PREF_LEN 8
#define MAX_URI_LEN (256 + 64) /*
                                * RFC 1034, RFC 1035 -- Maximal domain name
                                * length is 255 octets. Adding 64 bytes for
                                * prefixes and other stuff should be
                                * sufficient.
                                */
	char uri[MAX_URI_LEN];
	int exitcode = DANE_ERROR_RESOLVER;
	char *dn = NULL;

	dane_set_validation_options(&glob_val_ctx.opts, options);

	printf_debug(DEBUG_PREFIX_TLSA, "Input parameters: domain='%s'; port='%s'; "
	    "protocol='%s'; options=%u; resolver_address='%s';\n",
	    (domain != NULL) ? domain : "(null)",
	    (port_str != NULL) ? port_str : "(null)",
	    (protocol != NULL) ? protocol : "(null)",
	    options,
	    (optdnssrv != NULL) ? optdnssrv : "(null)");

	if ((domain == NULL) || (domain[0] == '\0')) {
		printf_debug(DEBUG_PREFIX_TLSA, "%s\n", "Error: no domain...");
		return DANE_ERROR_GENERIC;
	}

	if ((port_str != NULL) && (port_str[0] != '\0')) {
		/*
		 * Check whether port really contains an uint16_t in
		 * decimal notation without any additional characters.
		 */
		if (str_is_port_number(port_str) < 0) {
			printf_debug(DEBUG_PREFIX_TLSA,
			    "Error: Supplied an invalid port number '%s'.\n",
			    port_str);
			return exitcode;
		}
	} else {
		port_str = DEFAULT_PORT;
	}

	/*
	 * TODO -- Make sure that domain and port are separated
	 * (i.e., domain name does not contain port number such as
	 * test.com:444).
	 */

	/* ----------------------------------------------- */
	/* Unbound resolver initialization, set forwarder. */
	if (glob_val_ctx.ub == NULL) {
		glob_val_ctx.ub = unbound_resolver_init(optdnssrv, &exitcode,
		    glob_val_ctx.opts.usefwd, glob_val_ctx.opts.ds,
		    DEBUG_PREFIX_TLSA);
		if(glob_val_ctx.ub == NULL) {
			printf_debug(DEBUG_PREFIX_TLSA, "%s\n",
			    "Error: could not create unbound context.");
			switch (exitcode) {
			case ERROR_RESOLVER:
				return DANE_ERROR_RESOLVER;
			case ERROR_GENERIC:
				return DANE_ERROR_GENERIC;
			default:
				return exitcode;
			}
		}
	}
	/* ----------------------------------------------- */

	/* Initialise SSL context if not initialised. */
	if (NULL == glob_val_ctx.ssl_ctx) {
		glob_val_ctx.ssl_ctx = ssl_context_init();
	}

	/* Create TLSA query. */
	dn = create_tlsa_qname(domain, port_str, protocol);
	retval = ub_resolve(glob_val_ctx.ub, dn, LDNS_RR_TYPE_TLSA,
	    LDNS_RR_CLASS_IN, &ub_res);
	free(dn); dn = NULL;

	if (retval != 0) {
		printf_debug(DEBUG_PREFIX_TLSA, "resolver error: %s\n",
		    ub_strerror(retval));
		return exitcode;
	}

	/* Parse TLSA records from response. */
	retval = parse_tlsa_record(&tlsa_list, ub_res, domain);
	ub_resolve_free(ub_res); ub_res = NULL;

	if (retval == DANE_DNSSEC_UNSECURED) {
		free_tlsalist(&tlsa_list);
		return DANE_DNSSEC_UNSECURED;
	} else if (retval == DANE_DNSSEC_BOGUS) {
		free_tlsalist(&tlsa_list);
		return DANE_DNSSEC_BOGUS;
	} else if (retval == DANE_TLSA_PARAM_ERR) {
		free_tlsalist(&tlsa_list);
		return DANE_TLSA_PARAM_ERR;
	} else if (retval == DANE_NO_TLSA) {
		free_tlsalist(&tlsa_list);
		return DANE_NO_TLSA;
	} else if (retval == DANE_ERROR_RESOLVER) {
		free_tlsalist(&tlsa_list);
		return DANE_ERROR_RESOLVER;
	}

	print_tlsalist_debug(&tlsa_list);

	if (certcount > 0) {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "Browser's certificate chain is used.");

		int i;
		for (i = 0; i < certcount; i++) {
			if (add_certrecord_bottom_from_der_hex(&cert_list,
			        certchain[i]) != 0) {
				printf_debug(DEBUG_PREFIX_CERT, "%s\n",
				    "Error adding certificate into list.");
				return DANE_ERROR_GENERIC;
			}
		}
	} else {
		printf_debug(DEBUG_PREFIX_CERT, "%s\n",
		    "External certificate chain is used.");

		memcpy(uri, "https://", HTTPS_PREF_LEN + 1);
		strncat(uri, domain, MAX_URI_LEN - HTTPS_PREF_LEN - 1);
		retval = get_cert_list(glob_val_ctx.ssl_ctx,
		    uri, domain, port_str, &cert_list);
		if (retval != 0) {
			free_tlsalist(&tlsa_list);
			free_certlist(&cert_list);
			return DANE_NO_CERT_CHAIN;
		}
	}

	print_certlist_debug(&cert_list);

	retval = tlsa_validate(&tlsa_list, &cert_list);

	printf_debug(DEBUG_PREFIX_DANE, "result: %i\n", retval);

	free_tlsalist(&tlsa_list);
	free_certlist(&cert_list);

	return retval;

#undef HTTPS_PREF
#undef HTTPS_PREF_LEN
#undef MAX_URI_LEN
}


//*****************************************************************************
// Initialises global validation structures.
// ----------------------------------------------------------------------------
int dane_validation_deinit(void)
{
	printf_debug(DEBUG_PREFIX_DANE, "%s\n", "Deinitialising DANE.");

	if (glob_val_ctx.ub != NULL) {
		ub_ctx_delete(glob_val_ctx.ub);
		glob_val_ctx.ub = NULL;
	}

	if (glob_val_ctx.ssl_ctx != NULL) {
		SSL_CTX_free(glob_val_ctx.ssl_ctx);
		glob_val_ctx.ssl_ctx = NULL;
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
	
	printf_debug(DEBUG_PREFIX_DANE, "Running inside PID %d.\n", getpid());

	global_debug = global_debug_bak;
}
#endif

#ifdef CMNDLINE_TEST

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

	res = dane_validate(certhex, 0, options, resolver_addresses, dname,
	    port, "tcp", 1);
	printf(DEBUG_PREFIX_DANE "Main result: %i\n", res);

	if (dane_validation_deinit() != 0) {
		printf(DEBUG_PREFIX_DANE "Error de-initialising context.\n");
	}

	return 0;
}

#endif /* CMNDLINE_TEST */
