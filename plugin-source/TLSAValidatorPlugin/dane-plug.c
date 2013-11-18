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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "ldns/wire2host.h"
#include "openssl/x509.h"
#include "openssl/evp.h"

#include "dane-plug.h"
#include "dane-states.gen"

#ifdef RES_WIN
/* Windows */
  #include "ldns/config.h"
  #include "ldns/ldns.h"
  #include "libunbound/unbound.h"
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h>
  #include <winreg.h>
#else
/* Linux */
  #include "unbound.h"
  #include "ldns/ldns.h"
  #include "ldns/packet.h"
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <sys/types.h>
  #include <sys/socket.h>
#endif

//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
//DS record of root zone
#define TA ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5"
//DNSKEY of DLV register
#define DLV "dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+ cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh"
//debug prefixs
#define DEBUG_PREFIX "TLSA: "        
#define DEBUG_PREFIX_CER "CERT: "
#define DEBUG_PREFIX_DANE "DANE: "
// define policy of browser
#define ALLOW_TYPE_01 1
#define ALLOW_TYPE_23 2
// define DANE konstatnt
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
typedef struct {     
	bool debug; // debug output enable
	bool usefwd; // use of resolver
	bool ds; // use root.key with DS record of root zone 
} ds_options;
ds_options opts;

//----------------------------------------------------------------------------
static struct ub_ctx* ctx = NULL;
static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static int byteMapLen = sizeof(byteMap);
//----------------------------------------------------------------------------
/* structure to save TLSA records */
typedef struct tlsa_store_ctx_st {   
	char *domain;
	uint8_t dnssec_status;
	uint8_t cert_usage;
	uint8_t selector;
	uint8_t matching_type;
	uint8_t *association;
	size_t association_size;
	unsigned char *assochex;
	struct tlsa_store_ctx_st *next;
} tlsa_store_ctx;

/* pointer structure to save TLSA records */
struct tlsa_store_head {
	struct tlsa_store_ctx_st *first;
};

/* structure to save certificate records */
typedef struct cert_store_ctx_st {
	char *cert_der;
	int cert_len;
	char *cert_der_hex;
	char *spki_der;
	int spki_len;
	char *spki_der_hex;
	struct cert_store_ctx_st *next;
} cert_store_ctx;

/* pointer structure to save certificate records */
struct cert_store_head {
	struct cert_store_ctx_st *first;
};

/* structure to save certificate records */
typedef struct cert_tmp_st {
	char *spki_der;
	int spki_len;
	char *spki_der_hex;
} cert_tmp_ctx;
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------

static
int printf_debug(const char *pref, const char *fmt, ...)
  __attribute__((format(printf, 2, 3)));

//*****************************************************************************
/* debug output function */
// ----------------------------------------------------------------------------
static
int printf_debug(const char *pref, const char *fmt, ...)
{
	va_list argp;
	int ret = 0;

	if (opts.debug && (fmt != NULL)) {
		va_start(argp, fmt);

		if (pref != NULL) {
			fputs(pref, stderr);
		} else {
			fputs(DEBUG_PREFIX, stderr);
		}
		ret = vfprintf(stderr, fmt, argp);

		va_end(argp);
	}

	return ret;
}


//*****************************************************************************
// read input options into a structure
// ----------------------------------------------------------------------------
static
void ds_init_opts(const uint16_t options) 
{
	opts.debug = options & DANE_FLAG_DEBUG;
	opts.usefwd = options & DANE_FLAG_USEFWD;
	opts.ds = false;
}


//*****************************************************************************
// Helper function (SSL conection)
// create_socket() creates the socket & TCP-connect to server
// url_str contains only domain name (+ optional port number)
// ----------------------------------------------------------------------------
static
int create_socket(char *url_str, const char *port_str)
{
	int sockfd;
	char hostname[256] = "";
	char    portnum[6] = "443";
	char      proto[6] = "";
	char      *tmp_ptr = NULL;
	int           port;

	struct hostent *host;
	struct sockaddr_in dest_addr;

	/*
	 * TODO -- Add input sanity check.
	 * Copy port number.
	 */
	if ((port_str != NULL) && (port_str[0] != '\0')) {
		strncpy(portnum, port_str, 5);
		portnum[5] = '\0';
	}

#ifdef WIN32
	WSADATA wsaData;
	WORD version;
	int error;

	version = MAKEWORD( 2, 0 );
	error = WSAStartup( version, &wsaData );

	/* check for error */
	if ( error != 0 ) return -1;

	/* check for correct version */
	if ( LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0) {
		WSACleanup();
		return -1;
	}
#endif

	//Remove the final / from url_str, if there is one
	if (url_str[strlen(url_str)] == '/') {
		url_str[strlen(url_str)] = '\0';
	}

	//the first : ends the protocol string, i.e. http
	strncpy(proto, url_str, (strchr(url_str, ':')-url_str));

	//the hostname starts after the "://" part
	strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

	//if the hostname contains a colon :, we got a port number
	if(strchr(hostname, ':')) {
		tmp_ptr = strchr(hostname, ':');
		/* the last : starts the port number, if avail, i.e. 8443 */
		strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
		*tmp_ptr = '\0';
	}

	port = atoi(portnum);
	if ( (host = gethostbyname(hostname)) == NULL ) {
		printf_debug(DEBUG_PREFIX_CER,
		    "Error: Cannot resolve hostname %s.\n", hostname);
		abort();
	}

	//create the basic TCP socket                                
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf_debug(DEBUG_PREFIX_CER, "error opening socket\n");
		return -1;
	}

	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = 0;
	dest_addr.sin_addr.s_addr = * (unsigned long*) host->h_addr_list[0];

	//Zeroing the rest of the struct       
	memset(&(dest_addr.sin_zero), '\0', 8);
	tmp_ptr = inet_ntoa(dest_addr.sin_addr);

	//Try to make the host connect here
	if (connect(sockfd, (struct sockaddr *) &dest_addr,
	        sizeof(struct sockaddr_in)) == -1) {
		printf_debug(DEBUG_PREFIX_CER,
		    "Error: Cannot connect to host %s [%s] on port %d.\n",
		    hostname, tmp_ptr, port);
	}

	return sockfd;
}

//*****************************************************************************
// Helper function (return DNSSEC status)
// ----------------------------------------------------------------------------
static
const char * get_dnssec_status(uint8_t dnssec_status)
{
	switch (dnssec_status) {
	case 0: return "INSECURE";
	case 1: return "SECURE";
	case 2: return "BOGUS";
	default: return "ERROR";
	}
}

#if 0
//*****************************************************************************
// Helper function (add new record in the TLSA list - first)
// ----------------------------------------------------------------------------
static
void add_tlsarecord(struct tlsa_store_head *tlsa_list, const char *domain, 
	uint8_t dnssec_status, uint8_t cert_usage, uint8_t selector, 
	uint8_t matching_type, uint8_t *association, size_t association_size, 
	const char *assochex)
{
	tlsa_store_ctx *field_tlsa;
	size_t size;

	field_tlsa = tlsa_list->first;
	field_tlsa = malloc(sizeof(tlsa_store_ctx));
	size = strlen(domain) + 1;
	field_tlsa->domain = malloc(size);
	memcpy(field_tlsa->domain, domain, size);
	field_tlsa->dnssec_status = dnssec_status;
	field_tlsa->cert_usage = cert_usage;
	field_tlsa->selector = selector;
	field_tlsa->matching_type = matching_type;
	field_tlsa->association = association;
	field_tlsa->association_size = association_size;
	size = strlen(assochex) + 1;
	field_tlsa->assochex = malloc(size);
	memcpy(field_tlsa->assochex, assochex, size);
	field_tlsa->next = tlsa_list->first;
	tlsa_list->first = field_tlsa;
}
#endif

//*****************************************************************************
// Helper function (add new record in the TLSA list - last)
// ----------------------------------------------------------------------------
static
void add_tlsarecord_bottom(struct tlsa_store_head *tlsa_list,
	const char *domain, 
	uint8_t dnssec_status, uint8_t cert_usage, uint8_t selector, 
	uint8_t matching_type, uint8_t *association, size_t association_size, 
	const char *assochex)
{
	tlsa_store_ctx *field_tlsa;
	size_t size;

	field_tlsa = malloc(sizeof(tlsa_store_ctx));
	size = strlen(domain) + 1;
	field_tlsa->domain = malloc(size);
	memcpy(field_tlsa->domain, domain, size);
	field_tlsa->dnssec_status = dnssec_status;
	field_tlsa->cert_usage = cert_usage;
	field_tlsa->selector = selector;
	field_tlsa->matching_type = matching_type;
	field_tlsa->association = association;
	field_tlsa->association_size = association_size;
	size = strlen(assochex) + 1;
	field_tlsa->assochex = malloc(size);
	memcpy(field_tlsa->assochex, assochex, size);
	field_tlsa->next = NULL;

	if (tlsa_list->first != NULL) {
		tlsa_store_ctx *tmp = tlsa_list->first;
		while (tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = field_tlsa; 
	} else {
		tlsa_list->first = field_tlsa;
	}
}

#if 0
//*****************************************************************************
// Helper function (sorte TLSA list base on Policy)
// ----------------------------------------------------------------------------
static
struct tlsa_store_head policyFilter(struct tlsa_store_head *tlsa_list, int policy)
{
	struct tlsa_store_head tlsa_list_new;
	tlsa_list_new.first = NULL;
    
	struct tlsa_store_ctx_st *tmp;
	tmp=tlsa_list->first;
	
	while (tmp != NULL) {
		switch (tmp->cert_usage) {
		case CA_CERT_PIN:
		case EE_CERT_PIN:
			if (policy & ALLOW_TYPE_01) {
				add_tlsarecord_bottom(&tlsa_list_new, 
				tmp->domain, tmp->dnssec_status, tmp->cert_usage,
				tmp->selector, tmp->matching_type, tmp->association, 
				tmp->association_size, (char*)tmp->assochex); 
			}
			break;
		case CA_TA_ADDED:
		case EE_TA_ADDED:
			if (policy & ALLOW_TYPE_23) {
				add_tlsarecord_bottom(&tlsa_list_new, 
				tmp->domain, tmp->dnssec_status, tmp->cert_usage,
				tmp->selector, tmp->matching_type, tmp->association,
				tmp->association_size, (char*)tmp->assochex); 
			}
			break;
		default:
			break;
		} //switch
	} //while

	return tlsa_list_new;
}
#endif

//*****************************************************************************
// Helper function (print TLSA list)
// ----------------------------------------------------------------------------
static
void print_tlsalist_debug(const struct tlsa_store_head *tlsa_list)
{
	struct tlsa_store_ctx_st *tmp;

	if (!opts.debug) {
		/* Function prints only debugging information. */
		return;
	}

	tmp = tlsa_list->first;
	while (tmp != NULL) {
		printf_debug(DEBUG_PREFIX,
		    "---------------------------------------------\n");
		printf_debug(DEBUG_PREFIX,
		    "%s: dnssec: %s (%d), cert usage: %d, selector: %d, "
		    "matching type: %d, assoc.hex: %s, assoc.size: %zu \n",
		    tmp->domain, get_dnssec_status(tmp->dnssec_status),
		    tmp->dnssec_status, tmp->cert_usage, tmp->selector,
		    tmp->matching_type, tmp->assochex,
		    tmp->association_size);
		tmp = tmp->next;
	}

	printf_debug(DEBUG_PREFIX,
	    "---------------------------------------------\n");
} 

//*****************************************************************************
// Helper function (print certificate list)
// ----------------------------------------------------------------------------
static
void print_certlist_debug(const struct cert_store_head *cert_list)
{
	struct cert_store_ctx_st *tmp;

	if (!opts.debug) {
		/* Function prints only debugging information. */
		return;
	}

	tmp = cert_list->first;
	while (tmp != NULL) {
		printf_debug(DEBUG_PREFIX_CER,
		    "---------------------------------------------\n");
		printf_debug(DEBUG_PREFIX_CER, "certlen: %i\n%s\n",
		    tmp->cert_len, tmp->cert_der_hex);
		printf_debug(DEBUG_PREFIX_CER, "spkilen: %i\n%s\n",
		     tmp->spki_len, tmp->spki_der_hex);
		tmp = tmp->next;
	}

	printf_debug(DEBUG_PREFIX_CER,
	    "---------------------------------------------\n");
}

//*****************************************************************************
// Helper function (free TLSA list)
// ----------------------------------------------------------------------------
static
void free_tlsalist(struct tlsa_store_head *tlsa_list)
{
	tlsa_store_ctx *aux;

	while (tlsa_list->first != NULL) {
		aux = tlsa_list->first->next;

		free(tlsa_list->first->domain);
		free(tlsa_list->first->assochex);
		free(tlsa_list->first);

		tlsa_list->first = aux;
	}
}

//*****************************************************************************
// Helper function (free certificate list)
// ----------------------------------------------------------------------------
static
void free_certlist(struct cert_store_head *cert_list)
{
	cert_store_ctx *aux;

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

#if 0
//*****************************************************************************
// Helper function (add new record in the certificate list - first)
// ----------------------------------------------------------------------------
static
void add_certrecord(struct cert_store_head *cert_list, char* cert_der, 
    int cert_len, char* cert_der_hex,  char* spki_der, int spki_len,
    char* spki_der_hex)
{
	cert_store_ctx *field_cert;
	field_cert = cert_list->first;
	field_cert = malloc(sizeof(cert_store_ctx));
	field_cert->cert_der = malloc(cert_len + 1);
	memcpy(field_cert->cert_der, cert_der, cert_len);
	field_cert->cert_len = cert_len;
	field_cert->cert_der_hex = malloc(strlen(cert_der_hex) + 1);
	strcpy(field_cert->cert_der_hex, cert_der_hex);
	field_cert->spki_der = malloc(spki_len + 1);
	memcpy(field_cert->spki_der, spki_der, spki_len);
	field_cert->spki_len = spki_len;
	field_cert->spki_der_hex = malloc(strlen(spki_der_hex) + 1);
	strcpy(field_cert->spki_der_hex, spki_der_hex);
	field_cert->next = cert_list->first;
	cert_list->first = field_cert;
}
#endif

//*****************************************************************************
// Helper function (add new record in the certificate list - last)
// ----------------------------------------------------------------------------
static
void add_certrecord_bottom(struct cert_store_head *cert_list,
    const char *cert_der, int cert_len, const char *cert_der_hex,
    const char *spki_der, int spki_len, const char *spki_der_hex)
{
	cert_store_ctx *field_cert;

	field_cert = malloc(sizeof(cert_store_ctx));

	field_cert->cert_der = malloc(cert_len + 1);
	memcpy(field_cert->cert_der, cert_der, cert_len);
	field_cert->cert_len = cert_len;
	field_cert->cert_der_hex = malloc(strlen(cert_der_hex) + 1);
	strcpy(field_cert->cert_der_hex, cert_der_hex);
	field_cert->spki_der = malloc(spki_len + 1);
	memcpy(field_cert->spki_der, spki_der, spki_len);
	field_cert->spki_len = spki_len;
	field_cert->spki_der_hex = malloc(strlen(spki_der_hex) + 1);
	strcpy(field_cert->spki_der_hex, spki_der_hex);
	field_cert->next = NULL;

	if (cert_list->first != NULL) {
		cert_store_ctx *tmp = cert_list->first;
		while (tmp->next) {
			tmp = tmp->next;
		}
		tmp->next = field_cert; 
	} else {
		cert_list->first = field_cert;
	}
}

//*****************************************************************************
// Utility function to convert nibbles (4 bit values) into a hex character representation
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
// HEX string to Binary data converter
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
// Get certificates from SSL handshake
// Add certificate into structure
// Helper function 
// return success or error
// ----------------------------------------------------------------------------
static
int getcert(char *dest_url, const char *domain, const char *port,
    struct cert_store_head *cert_list)
{
	int i;
	const SSL_METHOD *method;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	int server_fd = -1;
	X509 *cert = NULL;
	STACK_OF(X509) *chain;
	X509 *cert2;
	EVP_PKEY *pkey = NULL;
	unsigned char *buf = NULL, *buf2 = NULL;
	char *hex = NULL, *hex2 = NULL;
	int len, len2;

	//These function calls initialize openssl for correct work.
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	/* Always returns 1. */
	SSL_library_init();

	method = SSLv23_client_method();
	ssl_ctx = SSL_CTX_new(method);
	if (ssl_ctx == NULL) {
		printf_debug(DEBUG_PREFIX_CER,
		    "Unable to create a new SSL context structure.\n");
		goto fail;
	}

	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		printf_debug(DEBUG_PREFIX_CER, "Cannot create SSL structure.\n");
		goto fail;
	}

	server_fd = create_socket(dest_url, port);
	if(server_fd == -1) {
		printf_debug(DEBUG_PREFIX_CER, "Error TCP connection to: %s.\n", dest_url);
		goto fail;
	}

	if (SSL_set_fd(ssl, server_fd) != 1) {
		printf_debug(DEBUG_PREFIX_CER, "Error: Cannot set server socket.\n");
		goto fail;
	}


	if (domain != NULL) {
		if (!SSL_set_tlsext_host_name(ssl, domain)) {
			printf_debug(DEBUG_PREFIX_CER,
			    "Error: Unable to set TLS server-name extension: %s.\n",
			    domain);
			goto fail;
		}
	}

	if (SSL_connect(ssl) != 1) {
		printf_debug(DEBUG_PREFIX_CER,
		    "Error: Could not build a SSL session to: %s.\n",
		    dest_url);
		goto fail;
	}

	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		printf_debug(DEBUG_PREFIX_CER,
		    "Error: Could not get a certificate from: %s.\n",
		    dest_url);
		goto fail;
	}

	chain = SSL_get_peer_cert_chain(ssl);
	if (chain == NULL) {
		printf_debug(DEBUG_PREFIX_CER,
		    "Error: Could not get a certificate chain: %s.\n",
		    dest_url);
		goto fail;
	}

	printf_debug(DEBUG_PREFIX_CER, "Number of certificates in chain: %i\n",
	    sk_X509_num(chain));

	for (i = 0; i < sk_X509_num(chain); ++i) {
		//if (opts.debug) PEM_write_bio_X509(outbio, sk_X509_value(chain, i));
		cert2 = sk_X509_value(chain, i);
		pkey = X509_get_pubkey(cert2);
		if (pkey == NULL) {
			printf_debug(DEBUG_PREFIX_CER,
			    "Error getting public key from certificate\n");
			goto fail;
		}

		buf = NULL;
		len = i2d_X509(cert2, &buf);
		if (len < 0) {
			printf_debug(DEBUG_PREFIX_CER, "Error encoding into DER.\n");
			goto fail;
		}
		hex = bintohex((uint8_t *) buf, len);
		if (hex == NULL) {
			printf_debug(DEBUG_PREFIX_CER, "Error converting DER to hex.\n");
			goto fail;
		}

		buf2 = NULL;
		len2 = i2d_PUBKEY(pkey, &buf2);
		EVP_PKEY_free(pkey); pkey = NULL;
		if (len2 < 0) {
			printf_debug(DEBUG_PREFIX_CER, "Error encoding into DER.\n");
			goto fail;
		}
		hex2 = bintohex((uint8_t *) buf2, len2);
		if (hex2 == NULL) {
			printf_debug(DEBUG_PREFIX_CER, "Error converting DER to hex.\n");
			goto fail;
		}

		add_certrecord_bottom(cert_list, (char*) buf, len, hex,
		    (char *) buf2, len2, hex2);
		free(buf); buf = NULL;
		free(buf2); buf2 = NULL;
		free(hex); hex = NULL;
		free(hex2); hex2 = NULL;
	}

	/* Chain does not have to be freed explicitly. */
	/*
	sk_X509_pop_free(chain, X509_free);
	*/

	X509_free(cert);

#ifdef WIN32
	closesocket(server_fd);
	WSACleanup();
#else
	close(server_fd);
#endif

	SSL_shutdown(ssl);
	SSL_free(ssl);

	SSL_CTX_free(ssl_ctx);

	printf_debug(DEBUG_PREFIX_CER, "Finished SSL/TLS connection with server: %s.\n",
	    dest_url);

	return 1;

fail:
	if (ssl_ctx != NULL) {
		SSL_CTX_free(ssl_ctx);
	}
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
	if (cert != NULL) {
		X509_free(cert);
	}
	if (pkey != NULL) {
		EVP_PKEY_free(pkey);
	}
	if (buf != NULL) {
		free(buf);
	}
	if (buf2 != NULL) {
		free(buf2);
	}
	if (hex != NULL) {
		free(hex);
	}
	if (hex2 != NULL) {
		free(hex2);
	}
	return 0;
}

//*****************************************************************************
// DANE algorithm (spkicert)
// Get SPKI from binary data of certificate
// return struct (binary SPKI, SPKI length, SPKI in HEX format and its length 
// ----------------------------------------------------------------------------
static
cert_tmp_ctx spkicert(const unsigned char *certder, int len)
{
	cert_tmp_ctx tmp;
	EVP_PKEY *pkey = NULL;
	X509* cert;
	cert = d2i_X509(NULL, &certder, len);
	
	if ((pkey = X509_get_pubkey(cert)) == NULL) {
		printf_debug(DEBUG_PREFIX_DANE,
		    "Error getting public key from certificate\n");
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
	printf_debug(DEBUG_PREFIX_DANE, "crypto: SHA-256\n");

	return opensslDigest(EVP_sha256(), data, len);
}

//*****************************************************************************
// DANE algorithm
// return binary data of certificate or SPKI encode by sha512
// ----------------------------------------------------------------------------
static
char * sha512(const char *data, int len)
{
	printf_debug(DEBUG_PREFIX_DANE, "crypto: SHA-512\n");

	return opensslDigest(EVP_sha512(), data, len);
}

//*****************************************************************************
// DANE algorithm  (selector)
// return binary data of certificate or SPKI
// ----------------------------------------------------------------------------
static
const char * selectorData(uint8_t selector,
    const struct cert_store_ctx_st *cert_ctx)
{
	printf_debug(DEBUG_PREFIX_DANE, "selector: %i \n",
	    selector);
	switch (selector) {
	case FULL:
		return cert_ctx->cert_der;
	case SPKI:
		return cert_ctx->spki_der;
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
    const struct cert_store_ctx_st *cert_ctx)
{
	printf_debug(DEBUG_PREFIX_DANE, "matching_type: %i \n", matching_type);

	const char *data = selectorData(selector, cert_ctx);
	char *der_copy;
	unsigned i;

	if (data == NULL) {
		return NULL;
	}
	switch (matching_type) {
	case EXACT:
		der_copy = malloc(strlen(cert_ctx->cert_der_hex) + 1);
		if (der_copy == NULL) {
			return NULL;
		}
		/* Convert hex string to upper case. */
		for (i = 0; i < (strlen(cert_ctx->cert_der_hex) + 1); ++i) {
			der_copy[i] = toupper(cert_ctx->cert_der_hex[i]);
		}
		return der_copy;
	case SHA256:
		if (selector==SPKI) {
			return sha256(data, cert_ctx->spki_len);
		} else {
			return sha256(data, cert_ctx->cert_len);
		}
	case SHA512:
		if (selector==SPKI) {
			return sha512(data, cert_ctx->spki_len);
		} else {
			return sha512(data, cert_ctx->cert_len);
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
// Servers certificate must coresponde EE certificate in TLSA
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int eeCertMatch1(const struct tlsa_store_ctx_st *tlsa_ctx,
    const struct cert_store_head *cert_list)
{
	//printf_debug(DEBUG_PREFIX_DANE, "eeCertMatch1\n");

	int ret_val = DANE_INVALID_TYPE1;
	char *data = matchingData(tlsa_ctx->matching_type,
	    tlsa_ctx->selector, cert_list->first);

	if (data == NULL) {
		return DANE_TLSA_PARAM_ERR;
	}

	if (strcmp((const char *) data,
	        (const char *) tlsa_ctx->assochex) == 0) {
		ret_val = DANE_VALID_TYPE1; 
	}

	printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
	printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n", tlsa_ctx->assochex);

	free(data);
	return ret_val;
}


//*****************************************************************************
// TLSA validation of EE certificate (type 3)
// Binary data codes EE certificate
// Servers certificate must corresponds EE certificate in TLSA
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int eeCertMatch3(const struct tlsa_store_ctx_st *tlsa_ctx,
    const struct cert_store_head *cert_list)
{
	//printf_debug(DEBUG_PREFIX_DANE, "eeCertMatch3\n");

	int ret_val = DANE_INVALID_TYPE3;
	char *data = matchingData(tlsa_ctx->matching_type,
	    tlsa_ctx->selector, cert_list->first);

	if (data == NULL) {
		return DANE_TLSA_PARAM_ERR;
	}

	if (strcmp((const char *) data,
	        (const char *) tlsa_ctx->assochex) == 0) {
		ret_val = DANE_VALID_TYPE3; 
	}

	printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
	printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n", tlsa_ctx->assochex);

	free(data);
	return ret_val;
}

//*****************************************************************************
// TLSA validation CA certificate (type 0)
// Binary data codes CA certificate
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int caCertMatch(const struct tlsa_store_ctx_st *tlsa_ctx,
    const struct cert_store_head *cert_list) 
{
	const cert_store_ctx *aux_cert;

	//printf_debug(DEBUG_PREFIX_DANE, "caCertMatch0\n");

	int ret_val = DANE_INVALID_TYPE0;

	if ((cert_list->first == NULL) || (cert_list->first->next == NULL)) {
		return DANE_NO_CERT_CHAIN;
	}

	aux_cert = cert_list->first->next;
	while (aux_cert != NULL) {
		char *data = matchingData(tlsa_ctx->matching_type,
		    tlsa_ctx->selector, aux_cert);
		if (data == NULL) {
			return DANE_TLSA_PARAM_ERR;
		}
		if (strcmp((const char *) data,
		        (const char *) tlsa_ctx->assochex) == 0) {
			free(data);
			return DANE_VALID_TYPE0;
		}

		printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
		printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n",
		    tlsa_ctx->assochex);

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
int chainCertMatch(const struct tlsa_store_ctx_st *tlsa_ctx,
    const struct cert_store_head *cert_list)
{
	const cert_store_ctx *aux_cert;

	//printf_debug(DEBUG_PREFIX_DANE, "chainCertMatch2\n");

	if (cert_list->first == NULL) {
		return DANE_NO_CERT_CHAIN;
	}

	int ret_val = DANE_INVALID_TYPE2;

	aux_cert = cert_list->first;
	while (aux_cert != NULL) {
		char *data = matchingData(tlsa_ctx->matching_type,
		    tlsa_ctx->selector, aux_cert);
		if (data == NULL) {
			return DANE_TLSA_PARAM_ERR;
		}
		if (strcmp((const char *) data,
		        (const char *) tlsa_ctx->assochex) == 0) {
			free(data);
			return DANE_VALID_TYPE2;
		}

		printf_debug(DEBUG_PREFIX_DANE, "cert: %s\n", data);
		printf_debug(DEBUG_PREFIX_DANE, "tlsa: %s\n",
		    tlsa_ctx->assochex);

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
	int idx;
	const tlsa_store_ctx *aux_tlsa;

	aux_tlsa = tlsa_list->first;
	while (aux_tlsa != NULL) {
		idx = DANE_NO_TLSA;

		switch (aux_tlsa->dnssec_status) {
		case 0:
			return DANE_DNSSEC_UNSECURED;
		case 2:
			return DANE_DNSSEC_BOGUS;
		case 1:
			printf_debug(DEBUG_PREFIX_DANE,
			    "cert_usage: %i \n",
			    aux_tlsa->cert_usage);
			switch (aux_tlsa->cert_usage) {
			case CA_CERT_PIN: //0
				idx = caCertMatch(aux_tlsa, cert_list);
				break;
			case CA_TA_ADDED: //2
				idx = chainCertMatch(aux_tlsa, cert_list);
				break;
			case EE_CERT_PIN: //1
				idx = eeCertMatch1(aux_tlsa, cert_list);
				break;
			case EE_TA_ADDED: //3
				idx = eeCertMatch3(aux_tlsa, cert_list);
				break; // continue checking
			default:
				printf_debug(DEBUG_PREFIX_DANE,
				    "Wrong value of cert_usage parameter: %i \n",
				    aux_tlsa->cert_usage);
				idx = DANE_TLSA_PARAM_ERR; // unknown cert usage, skip
			} // switch
			break; // continue checking
		} // switch

		aux_tlsa = aux_tlsa->next;
		if ((idx >= DANE_VALID_TYPE0) && (idx <= DANE_VALID_TYPE3)) {
			return idx;
		}
	} // while

	return idx;
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

			printf_debug(DEBUG_PREFIX,
			    "Domain is secured by DNSSEC ... found TLSA record(s).\n");

			ldns_pkt *packet;
			ldns_status parse_status = ldns_wire2pkt(&packet,
			    (uint8_t *)(ub_res->answer_packet),
			    ub_res->answer_len);
        
			if (parse_status != LDNS_STATUS_OK) {
				printf_debug(DEBUG_PREFIX,
				     "Failed to parse response packet\n");
				return DANE_ERROR_RESOLVER;
			} //if
        
			ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(packet,
			    LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);

			for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
				/* extract first rdf, which is the whole TLSA record */
				ldns_rr *rr = ldns_rr_list_rr(rrs, i);
				// Since ldns 1.6.14, RR for TLSA is parsed into 4 RDFs 
				// instead of 1 RDF in ldns 1.6.13.
				if (ldns_rr_rd_count(rr) < 4) {
					printf_debug(DEBUG_PREFIX,
					    "RR %d hasn't enough fields\n", i);
					return DANE_TLSA_PARAM_ERR;
				}
				ldns_rdf *rdf_cert_usage = ldns_rr_rdf(rr, 0),
				*rdf_selector      = ldns_rr_rdf(rr, 1),
				*rdf_matching_type = ldns_rr_rdf(rr, 2),
				*rdf_association   = ldns_rr_rdf(rr, 3);

				if ((ldns_rdf_size(rdf_cert_usage) != 1) ||
				    (ldns_rdf_size(rdf_selector) != 1) ||
				    (ldns_rdf_size(rdf_matching_type) != 1) ||
				    (ldns_rdf_size(rdf_association) < 0)) {

					printf_debug(DEBUG_PREFIX,
					    "Improperly formatted TLSA RR %d\n", i);
					return DANE_TLSA_PARAM_ERR;
				}//if

				uint8_t cert_usage, selector, matching_type;
				uint8_t *association;
				size_t association_size;
				cert_usage = ldns_rdf_data(rdf_cert_usage)[0];
				selector = ldns_rdf_data(rdf_selector)[0];
				matching_type = ldns_rdf_data(rdf_matching_type)[0];
				association = ldns_rdf_data(rdf_association);
				association_size = ldns_rdf_size(rdf_association);
				char *asshex; 
				asshex = bintohex(association,association_size);
				add_tlsarecord_bottom(tlsa_list, domain, 1,
				    cert_usage, selector, matching_type,
				    association, association_size, asshex);
				free(asshex);
				ldns_rr_free(rr);
			} //for

			exitcode = DANE_DNSSEC_SECURED;                
			if (packet) {
				ldns_pkt_free(packet);
			}
			if (rrs) {
				ldns_rr_list_free(rrs);
			}

		} else {
			printf_debug(DEBUG_PREFIX,
			    "Unbound haven't received any TLSA data for %s.\n",
			    domain);
			exitcode = DANE_NO_TLSA;
		} //if
	} else if (ub_res->bogus) {
		exitcode = DANE_DNSSEC_BOGUS;
		printf_debug(DEBUG_PREFIX, "Domain is bogus: %s \n",
		    ub_res->why_bogus);
	} else {
		exitcode = DANE_DNSSEC_UNSECURED;
		printf_debug(DEBUG_PREFIX, "Domain is insecure...\n");
	}

	return exitcode;
}


//*****************************************************************************
// free unbound context (erase cache data from ub context), ctx = NULL
// external API
// ----------------------------------------------------------------------------
void ub_context_free(void)
{
	if (ctx != NULL) { 
		ub_ctx_delete(ctx);
		ctx = NULL;
	}
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
short CheckDane(const char *certchain[], int certcount, const uint16_t options,
    const char *optdnssrv, const char *domain,  const char *port_str,
    const char *protocol, int policy)
{
	struct ub_result *ub_res;
	struct tlsa_store_head tlsa_list;
	struct cert_store_head cert_list;
	tlsa_list.first = NULL;
	cert_list.first = NULL;
	int tlsa_res = -1;
	int tlsa_ret = 0;
	int retval = 0;
#define HTTPS_PREF "https://"
#define HTTPS_PREF_LEN 8
#define MAX_URI_LEN (256 + 64) /*
                                * RFC 1034, RFC 1035 -- Maximal domain name
                                * length is 255 octets. Adding 64 bytes for
                                * prefixes and other stuff should be
                                * sufficient.
                                */
	char uri[MAX_URI_LEN];
	int ub_retval = 0;
	char *fwd_addr = NULL;
	char delims[] = " ";
	short exitcode = DANE_ERROR_RESOLVER;
	char *dn = NULL;

	ds_init_opts(options);

	char port[6] = "443";
	if ((port_str != NULL) && (port_str[0] != '\0')) {
		/*
		 * TODO -- Check whether port really contains an uint16_t in
		 * decimal notation.
		 */
		strncpy(port, port_str, 5);
		port[5] = '\0';
	}

	/*
	 * TODO -- Make sure that domain and port are separated
	 * (i.e., domain name does not contain port number such as
	 * test.com:444).
	 */

	//-----------------------------------------------
	// Unbound resolver initialization, set forwarder 
	if (ctx == NULL) {
		ctx = ub_ctx_create();

		if(ctx == NULL) {
			printf_debug(DEBUG_PREFIX,
			    "Error: could not create unbound context\n");
			return exitcode;
		}


		// set resolver/forwarder if it was set in options
		if (opts.usefwd) {
			if ((optdnssrv != NULL) && (optdnssrv[0] != '\0')) {
				size_t size = strlen(optdnssrv) + 1;
				char *str_cpy = malloc(size);
				if (str_cpy == NULL) {
					return DANE_ERROR_GENERIC;
				}
				memcpy(str_cpy, optdnssrv, size);
				fwd_addr = strtok(str_cpy, delims);
				// set ip addresses of resolvers into ub context
				while (fwd_addr != NULL) {
					printf_debug(DEBUG_PREFIX,
					    "Adding resolver IP address '%s'\n",
					    fwd_addr);
					ub_retval = ub_ctx_set_fwd(ctx,
					    fwd_addr);
					if (ub_retval != 0) {
						printf_debug(DEBUG_PREFIX,
						    "Error adding resolver IP address '%s': %s\n",
						    fwd_addr,
						    ub_strerror(ub_retval));
						free(str_cpy);
						return exitcode;
					} //if
					fwd_addr = strtok(NULL, delims);
				} //while
				free(str_cpy);
			} else {
				printf_debug(DEBUG_PREFIX,
				    "Using system resolver.\n");
				ub_retval = ub_ctx_resolvconf(ctx, NULL);
				if (ub_retval != 0) {
					printf_debug(DEBUG_PREFIX,
					    "Error reading resolv.conf: %s. errno says: %s\n",
					    ub_strerror(ub_retval),
					    strerror(errno));
					return exitcode;
				} //if  
			} //if
		} // if(usefwd)

		/* read public keys of root zone for DNSSEC verification */
		// ds true = zone key will be set from file root.key
		//    false = zone key will be set from TA constant
		if (opts.ds) {
			ub_retval = ub_ctx_add_ta_file(ctx, "root.key");
			if (ub_retval != 0) {
				printf_debug(DEBUG_PREFIX,
				    "Error adding keys: %s\n",
				    ub_strerror(ub_retval));
				return exitcode;
			} //if
		} else {
			ub_retval = ub_ctx_add_ta(ctx, TA);
			if (ub_retval != 0) {
				printf_debug(DEBUG_PREFIX,
				    "Error adding keys: %s\n",
				    ub_strerror(ub_retval));
				return exitcode;
			}
		}// if (ds)   

		// set dlv-anchor
		ub_retval=ub_ctx_set_option(ctx, "dlv-anchor:", DLV);
		if (ub_retval != 0) {
			printf_debug(DEBUG_PREFIX,
			    "Error adding DLV keys: %s\n",
			    ub_strerror(ub_retval));
			return exitcode;      
		}
	} // end of init resolver
	//------------------------------------------------------------

	// create TLSA query 
	dn = create_tlsa_qname(domain, port, protocol);
	retval = ub_resolve(ctx, dn, LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN,
	    &ub_res);
	free(dn);

	if (retval != 0) {
		printf_debug(DEBUG_PREFIX, "resolver error: %s\n",
		    ub_strerror(retval));
		return exitcode;
	}

	// parse TLSA records from response
	tlsa_ret = parse_tlsa_record(&tlsa_list, ub_res, domain);
	ub_resolve_free(ub_res);

	if (tlsa_ret == DANE_DNSSEC_UNSECURED) {
		free_tlsalist(&tlsa_list);
		return DANE_DNSSEC_UNSECURED;
	} else if (tlsa_ret == DANE_DNSSEC_BOGUS) {
		free_tlsalist(&tlsa_list);
		return DANE_DNSSEC_BOGUS;
	} else if (tlsa_ret == DANE_TLSA_PARAM_ERR) {
		free_tlsalist(&tlsa_list);
		return DANE_TLSA_PARAM_ERR;
	} else if (tlsa_ret == DANE_NO_TLSA) {
		free_tlsalist(&tlsa_list);
		return DANE_NO_TLSA;
	} else if (tlsa_ret == DANE_ERROR_RESOLVER) {
		free_tlsalist(&tlsa_list);
		return DANE_ERROR_RESOLVER;
	}

	print_tlsalist_debug(&tlsa_list);

	int i;
	if (certcount > 0) {

		printf_debug(DEBUG_PREFIX_CER,
		    "Browser's certificate chain is used\n");

		for (i = 0; i < certcount; i++) {
			int certlen = strlen(certchain[i]) / 2;
			unsigned char *certbin = (unsigned char *) hextobin(certchain[i]);
			char *certbin2 = hextobin(certchain[i]);   
			cert_tmp_ctx skpi = spkicert(certbin, certlen);

			add_certrecord_bottom(&cert_list, certbin2, certlen,
			    certchain[i], skpi.spki_der, skpi.spki_len,
			    skpi.spki_der_hex);

			free(certbin);
			free(certbin2);
			free(skpi.spki_der_hex); /* Messy clean-up. Create a better one. */
			free(skpi.spki_der);
		}
	} else {
		printf_debug(DEBUG_PREFIX_CER,
		    "External certificate chain is used\n");
		memcpy(uri, "https://", HTTPS_PREF_LEN + 1);
		strncat(uri, domain, MAX_URI_LEN - HTTPS_PREF_LEN - 1);
		tlsa_ret = getcert(uri, domain, port, &cert_list);
		if (tlsa_ret == 0) {
			free_tlsalist(&tlsa_list);
			free_certlist(&cert_list);
			return DANE_NO_CERT_CHAIN;
		}
	}

	print_certlist_debug(&cert_list);

	tlsa_res = tlsa_validate(&tlsa_list, &cert_list);

	printf_debug(DEBUG_PREFIX_DANE, "result: %i\n", tlsa_res);

	free_tlsalist(&tlsa_list);
	free_certlist(&cert_list);
  
	return tlsa_res;

#undef HTTPS_PREF
#undef HTTPS_PREF_LEN
#undef MAX_URI_LEN
}


#ifdef CMNDLINE_TEST

const char *certhex[] = {"12345678"};

//*****************************************************************************
// Main function for testing of lib, input: domain name
// ----------------------------------------------------------------------------
int main(int argc, char **argv) 
{
	const char *dname = NULL, *port = NULL;
	const char *resolver_addresses = NULL;
	int res = DANE_ERROR_GENERIC;

	uint16_t options;

	if ((argc < 2) || (argc > 4)) {
		fprintf(stderr, "Usage:\n\t%s dname port [resolver_list]\n", argv[0]);
		return 1;
	}

	dname = argv[1];
	if (argc > 2) {
		/* Default if 443. */
		port = argv[2];
	}
	if (argc > 3) {
		resolver_addresses = argv[3];
	} else {
		resolver_addresses =
//		    "::1"
		    " 8.8.8.8"
		    " 217.31.204.130"
//		    " 193.29.206.206"
		    ;
	}

	options =
	    DANE_FLAG_DEBUG |
	    DANE_FLAG_USEFWD;

	res = CheckDane(certhex, 0, options, resolver_addresses, dname, port, "tcp", 1);
	printf(DEBUG_PREFIX_DANE "Main result: %i\n", res);

	ub_context_free();

	return 0;
}

#endif /* CMNDLINE_TEST */
