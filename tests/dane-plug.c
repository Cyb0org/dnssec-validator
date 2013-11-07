/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.
File: DANE/TLSA library
Authors: Martin Straka <martin.straka@nic.cz> 

This file is part of DNSSEC Validator 2.0 Add-on.

DNSSEC Validator 2.0 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DNSSEC Validator 2.0 Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
DNSSEC Validator 2.0 Add-on.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "ldns/wire2host.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
#include "dane-states.gen"


/* Windows */
  #ifdef RES_WIN
  #include "ldns/config.h"
  #include "ldns/ldns.h"
  #include "libunbound/unbound.h"
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h> /* for IP Helper API */
  #include <winreg.h>
  //#define DWORD_MAX 0xFFFFFFFF
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
#define TA ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5" //DS record of root domain
#define DLV "dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+ cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh" //DNSKEY DLV register
#define FNAME "tlsa.log"	        /* mane of output log file */
#define DEBUG_PREFIX "TLSA: "		//debug prefix
#define DEBUG_PREFIX_CER "CERT: "
#define DEBUG_PREFIX_DANE "DANE: "
// define policy, cert-usage
#define ALLOW_TYPE_01 1
#define ALLOW_TYPE_23 2
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
//----------------------------------------------------------------------------
typedef struct {                     /* structure to save input options */
	bool debug;                        // debug output enable
	bool usefwd;                       // use of resolver
} ds_options;
ds_options opts;
//----------------------------------------------------------------------------
struct ub_ctx* ctx;
bool ds = false;   		/* load root DS key from file */
bool debug = true;
bool context = false;
static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static int byteMapLen = sizeof(byteMap);
//----------------------------------------------------------------------------
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
	unsigned char* assochex; 
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


//*****************************************************************************
// read input options into a structure
// ----------------------------------------------------------------------------
static
void ds_init_opts(const uint16_t options) 
{
	opts.debug = options & DANE_INPUT_FLAG_DEBUGOUTPUT;
	opts.usefwd = options & DANE_INPUT_FLAG_USEFWD;
}


//*****************************************************************************
// Helper function (SSL conection)
// create_socket() creates the socket & TCP-connect to server
// url_str contains only domain name (+ optional port number)
// ----------------------------------------------------------------------------
static
int create_socket(char *url_str, char *port_str)
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
	} //if
#endif

	//Remove the final / from url_str, if there is one
	if (url_str[strlen(url_str)] == '/') {
		url_str[strlen(url_str)] = '\0';
	} //if

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
	} //if

	port = atoi(portnum);
	if ( (host = gethostbyname(hostname)) == NULL ) {
		if (debug) {
			printf(DEBUG_PREFIX "Error: Cannot resolve hostname %s.\n",  hostname);
		}
		abort();
	} //if

	//create the basic TCP socket                                
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd == -1) {
		if (debug) {
			printf(DEBUG_PREFIX "error opening socket\n");
		}
		return -1;
	} //if

	dest_addr.sin_family=AF_INET;
	dest_addr.sin_port=htons(port);
	dest_addr.sin_addr.s_addr = 0;
	dest_addr.sin_addr.s_addr = *(unsigned long*)host->h_addr_list[0];

	//Zeroing the rest of the struct       
	memset(&(dest_addr.sin_zero), '\0', 8);
	tmp_ptr = inet_ntoa(dest_addr.sin_addr);

	//Try to make the host connect here
	if (connect(sockfd, (struct sockaddr *) &dest_addr,
	        sizeof(struct sockaddr_in)) == -1) {
		if (debug) {
			printf(DEBUG_PREFIX "Error: Cannot connect to host %s [%s] on port %d.\n",
			    hostname, tmp_ptr, port);
		}
	} //if


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
void add_tlsarecord(struct tlsa_store_head *tlsa_list, char *domain, 
	uint8_t dnssec_status, uint8_t cert_usage, uint8_t selector, 
	uint8_t matching_type, uint8_t *association, size_t association_size, 
	char* assochex) 
{
	tlsa_store_ctx *field_tlsa;
	field_tlsa = tlsa_list->first;
	field_tlsa = malloc(sizeof(tlsa_store_ctx));
	field_tlsa->domain = malloc(strlen(domain) + 1);
	strcpy(field_tlsa->domain, domain);
	field_tlsa->dnssec_status = dnssec_status;
	field_tlsa->cert_usage = cert_usage;
	field_tlsa->selector = selector;
	field_tlsa->matching_type = matching_type;
	field_tlsa->association = association;
	field_tlsa->association_size = association_size;
	field_tlsa->assochex = malloc(strlen((char*)assochex) + 1);
	strcpy((char*)field_tlsa->assochex, (char*)assochex);
	field_tlsa->next = tlsa_list->first;
	tlsa_list->first = field_tlsa;
}
#endif

//*****************************************************************************
// Helper function (add new record in the TLSA list - last)
// ----------------------------------------------------------------------------
static
void add_tlsarecord_bottom(struct tlsa_store_head *tlsa_list, char *domain, 
	uint8_t dnssec_status, uint8_t cert_usage, uint8_t selector, 
	uint8_t matching_type, uint8_t *association, size_t association_size, 
	char* assochex) 
{
	tlsa_store_ctx *field_tlsa;

	field_tlsa = malloc(sizeof(tlsa_store_ctx));

	field_tlsa->domain = malloc(strlen(domain) + 1);
	strcpy(field_tlsa->domain, domain);
	field_tlsa->dnssec_status = dnssec_status;
	field_tlsa->cert_usage = cert_usage;
	field_tlsa->selector = selector;
	field_tlsa->matching_type = matching_type;
	field_tlsa->association = association;
	field_tlsa->association_size = association_size;
	field_tlsa->assochex = malloc(strlen((char*)assochex) + 1);
	strcpy((char*)field_tlsa->assochex, (char*)assochex);
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
void print_tlsalist(const struct tlsa_store_head *tlsa_list) 
{
	struct tlsa_store_ctx_st *tmp;
	tmp=tlsa_list->first;

	while (tmp != NULL) {

		if (debug) {
			printf(DEBUG_PREFIX "---------------------------------------------\n");
			printf(DEBUG_PREFIX "%s: dnssec: %s (%d), cert usage: %d, selector: %d,	matching type: %d, assoc.hex: %s, assoc.size: %zu \n", 
			    tmp->domain, get_dnssec_status(tmp->dnssec_status),
			    tmp->dnssec_status, tmp->cert_usage, tmp->selector,
			    tmp->matching_type, tmp->assochex, tmp->association_size);
		}
		tmp = tmp->next;
	} // while

	if (debug) {
		printf(DEBUG_PREFIX "---------------------------------------------\n");
	}
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
void add_certrecord_bottom(struct cert_store_head *cert_list, char *cert_der,
    int cert_len, char *cert_der_hex, char *spki_der, int spki_len,
    char *spki_der_hex)
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
// Helper function (print certificate list)
// ----------------------------------------------------------------------------
static
void print_certlist(struct cert_store_head *cert_list)
{
	struct cert_store_ctx_st *tmp;
	tmp=cert_list->first;

	while (tmp != NULL) {
		if (debug) {
			printf(DEBUG_PREFIX_CER "---------------------------------------------\n");
			printf(DEBUG_PREFIX_CER "certlen: %i\n%s\nspkilen: %i\n%s\n", 
				tmp->cert_len, tmp->cert_der_hex, tmp->spki_len, 
				tmp->spki_der_hex);
		}
		tmp = tmp->next;
	} // while

	if (debug) {
		printf(DEBUG_PREFIX_CER "---------------------------------------------\n");
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
	int i;

	retval = malloc(buflen * 2 + 1);

	if (retval == NULL) {
		return NULL;
	}

	for (i = 0; i < buflen; ++i) {
		retval[i * 2] = nibbleToChar(bytes[i] >> 4);
		retval[i * 2 + 1] = nibbleToChar(bytes[i] & 0x0f);
	}
	retval[i*2] = '\0';
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
// safety strings concatenate funciton
// ----------------------------------------------------------------------------
static
char * mystrcat(const char *s1, const char *s2)
{
	size_t s1_size = 0,
	s2_size = 0;
	char *t = NULL;

	if (s1 != NULL) {
		s1_size = strlen(s1);
	}

	if (s2 != NULL) {
		s2_size = strlen(s2);
	}

	if ((s1_size + s2_size) > 0) {
		t = malloc(s1_size + s2_size + 1);
		if (t == NULL) {
			return NULL; /* Allocation error. */
		}

		if (s1 != NULL) {
			strcpy(t, s1);
		}

		if (s2 != NULL) {
			strcpy(t + s1_size, s2);
		}
	}

	return t;
}

//*****************************************************************************
// HEX string to Binary data convertor
// ----------------------------------------------------------------------------
static
char * hextobin(char *data)
{
	int length = strlen(data);
	int i, j;
	char buffer[2048] = "";
	char *ret;
	assert((length % 2) == 0);
	for(i = 0, j = 0; i < length; i += 2, ++j){
		buffer[j] = hex_to_ascii(data[i], data[i+1]);
	}
	ret = malloc(length + 1);
	memcpy(ret, buffer, length);
	return ret;
}

//*****************************************************************************
// Get certificates from SSL handshake
// Add certificate into structure
// Helper function 
// return success or error
// ----------------------------------------------------------------------------
static
int getcert(char *dest_url, char *domain, char *port, struct cert_store_head *cert_list) 
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
		if (debug) {
			printf("Unable to create a new SSL context structure.\n");
		}
		goto fail;
	}

	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		if (debug) {
			printf("Cannot create SSL structure.\n");
		}
		goto fail;
	}

	server_fd = create_socket(dest_url, port);
	if(server_fd == -1) {
		if (debug) {
			printf("Error TCP connection to: %s.\n", dest_url);
		}
		goto fail;
	}

	if (SSL_set_fd(ssl, server_fd) != 1) {
		if (debug) {
			printf("Error: Cannot set server socket.\n");
		}
		goto fail;
	}


	if (domain != NULL) {
		if (!SSL_set_tlsext_host_name(ssl,domain)) {
			if (debug) {
				printf("Error: Unable to set TLS servername extension: %s.\n",
				    domain);
			}
			goto fail;
		}
	}

	if (SSL_connect(ssl) != 1) {
		if (debug) {
			printf("Error: Could not build a SSL session to: %s.\n",
			    dest_url);
		}
		goto fail;
	}

	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL) {
		if (debug) {
			printf("Error: Could not get a certificate from: %s.\n",
			    dest_url);
		}
	}

	chain = SSL_get_peer_cert_chain(ssl);
	if (chain == NULL) {
		if (debug) {
			printf("Error: Could not get a certificate chain: %s.\n",
			    dest_url);
		}
		goto fail;
	}

	if (debug) {
		int value = sk_X509_num(chain);
		printf("Number of certificates in chain: %i\n", value);
	}

	for (i = 0; i < sk_X509_num(chain); ++i) {
		//if (debug) PEM_write_bio_X509(outbio, sk_X509_value(chain, i));
		cert2 = sk_X509_value(chain, i);
		pkey = X509_get_pubkey(cert2);
		if (pkey == NULL) {
			if (debug) {
				printf("Error getting public key from certificate\n");
			}
			goto fail;
		}

		buf = NULL;
		len = i2d_X509(cert2, &buf);
		if (len < 0) {
			if (debug) {
				printf("Error encoding into DER.\n");
			}
			goto fail;
		}
		hex = bintohex((uint8_t *) buf, len);
		if (hex == NULL) {
			if (debug) {
				printf("Error converting DER to hex.\n");
			}
			goto fail;
		}

		buf2 = NULL;
		len2 = i2d_PUBKEY(pkey, &buf2);
		EVP_PKEY_free(pkey); pkey = NULL;
		if (len2 < 0) {
			if (debug) {
				printf("Error encoding into DER.\n");
			}
			goto fail;
		}
		hex2 = bintohex((uint8_t *) buf2, len2);
		if (hex2 == NULL) {
			if (debug) {
				printf("Error converting DER to hex.\n");
			}
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

	if (debug) {
		printf("Finished SSL/TLS connection with server: %s.\n",
		    dest_url);
	}

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
		if (debug) {
			printf(DEBUG_PREFIX_DANE "Error getting public key from certificate\n");
		}
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
char * sha256(char *data, int len)
{

	if (debug) {
		printf(DEBUG_PREFIX_DANE "sha256\n");
	}

	return opensslDigest(EVP_sha256(), data, len);
}

//*****************************************************************************
// DANE algorithm
// return binary data of certificate or SPKI encode by sha512
// ----------------------------------------------------------------------------
static
char * sha512(char *data, int len)
{
	if (debug) {
		printf(DEBUG_PREFIX_DANE "sha512\n");
	}

	return opensslDigest(EVP_sha512(), data, len);
}

//*****************************************************************************
// DANE algorithm  (selector)
// return binary data of certificate or SPKI
// ----------------------------------------------------------------------------
static
char * selectorData(uint8_t selector, struct cert_store_ctx_st *cert_ctx)
{
	if (debug) {
		printf(DEBUG_PREFIX_DANE "selectorData->selector: %i \n",
		    selector);
	}
	switch (selector) {
	case FULL:
		return cert_ctx->cert_der;
	case SPKI:
		return cert_ctx->spki_der;
	default:
		if (debug) {
			printf(DEBUG_PREFIX_DANE "Wrong value of selector parameter: %i \n",
			    selector);
		}
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
    struct cert_store_ctx_st *cert_ctx)
{
	if (debug) {
		printf(DEBUG_PREFIX_DANE "matching_type: %i \n",
		    matching_type);
	}

	char* data = selectorData(selector, cert_ctx);
	char *der_copy;
	unsigned i;

	if (data == NULL) {
		return data;
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
		if (debug) {
			printf(DEBUG_PREFIX_DANE "Wrong value of matching_type parameter: %i \n",
			    matching_type);
		}
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
int eeCertMatch1(struct tlsa_store_ctx_st *tlsa_ctx,
    struct cert_store_head *cert_list)
{
	if (debug) {
		printf(DEBUG_PREFIX_DANE "eeCertMatch1\n");
	}

	int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE1;
	char *data = matchingData(tlsa_ctx->matching_type,
	    tlsa_ctx->selector, cert_list->first);

	if (data == NULL) {
		free(data);
		return DANE_EXIT_TLSA_PARAM_ERR;
	}

	if (strcmp((const char *) data,
	        (const char *) tlsa_ctx->assochex) == 0) {
		ret_val = DANE_EXIT_VALIDATION_SUCCESS_TYPE1; 
	}
	if (debug) {
		printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
		printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_ctx->assochex);
	}

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
int eeCertMatch3(struct tlsa_store_ctx_st *tlsa_ctx,
    struct cert_store_head *cert_list)
{
	if (debug) {
		printf(DEBUG_PREFIX_DANE "eeCertMatch3\n");
	}

	int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE3;
	char *data = matchingData(tlsa_ctx->matching_type,
	    tlsa_ctx->selector, cert_list->first);

	if (data == NULL) {
		free(data);
		return DANE_EXIT_TLSA_PARAM_ERR;
	}

	if (strcmp((const char *) data,
	        (const char *) tlsa_ctx->assochex) == 0) {
		ret_val = DANE_EXIT_VALIDATION_SUCCESS_TYPE3; 
	}
	if (debug) {
		printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
		printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_ctx->assochex);
	}

	free(data);
	return ret_val;
}

//*****************************************************************************
// TLSA validation CA certificate (type 0)
// Binary data codes CA certificate
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
static
int caCertMatch(struct tlsa_store_ctx_st *tlsa_ctx,
    struct cert_store_head *cert_list) 
{
	cert_store_ctx *aux_cert;

	if (debug) {
		printf(DEBUG_PREFIX_DANE "caCertMatch0\n");
	}

	int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE0;

	if ((cert_list->first == NULL) || (cert_list->first->next == NULL)) {
		return DANE_EXIT_NO_CERT_CHAIN;
	}

	aux_cert = cert_list->first->next;
	while (aux_cert != NULL) {
		char *data = matchingData(tlsa_ctx->matching_type,
		    tlsa_ctx->selector, aux_cert);
		if (data == NULL) {
			free(data);
			return DANE_EXIT_TLSA_PARAM_ERR;
		}
		if (strcmp((const char *) data,
		        (const char *) tlsa_ctx->assochex) == 0) {
			free(data);
			return DANE_EXIT_VALIDATION_SUCCESS_TYPE0;
		}
		if (debug) {
			printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
			printf(DEBUG_PREFIX_DANE "TLSA: %s\n",
			    tlsa_ctx->assochex);
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
int chainCertMatch(struct tlsa_store_ctx_st *tlsa_ctx,
    struct cert_store_head *cert_list)
{
	cert_store_ctx *aux_cert;

	if (debug) {
		printf(DEBUG_PREFIX_DANE "chainCertMatch2\n");
	}

	if (cert_list->first == NULL) {
		return DANE_EXIT_NO_CERT_CHAIN;
	}

	int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE2;

	aux_cert = cert_list->first;
	while (aux_cert != NULL) {
		char *data = matchingData(tlsa_ctx->matching_type,
		    tlsa_ctx->selector, aux_cert);
		if (data == NULL) {
			free(data);
			return DANE_EXIT_TLSA_PARAM_ERR;
		}
		if (strcmp((const char *) data,
		        (const char *) tlsa_ctx->assochex) == 0) {
			free(data);
			return DANE_EXIT_VALIDATION_SUCCESS_TYPE2;
		}
		if (debug) {
			printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
			printf(DEBUG_PREFIX_DANE "TLSA: %s\n",
			    tlsa_ctx->assochex);
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
int TLSAValidate(struct tlsa_store_head *tlsa_list,
    struct cert_store_head *cert_list)
{
	int idx;
	tlsa_store_ctx *aux_tlsa;

	aux_tlsa = tlsa_list->first;
	while (aux_tlsa != NULL) {
		idx = DANE_EXIT_VALIDATION_FALSE;

		switch (aux_tlsa->dnssec_status) {
		case 0:
			return DANE_EXIT_DNSSEC_UNSECURED;
		case 2:
			return DANE_EXIT_DNSSEC_BOGUS;
		case 1:
			if (debug) {
				printf(DEBUG_PREFIX_DANE "TLSAValidate->cert_usage: %i \n",
				    aux_tlsa->cert_usage);
			}
			switch (aux_tlsa->cert_usage) {
			case CA_CERT_PIN: //0
				idx = caCertMatch(aux_tlsa, cert_list);
				break;
			case CA_TA_ADDED: //2
				idx = chainCertMatch(aux_tlsa, cert_list);
				break;
			case EE_CERT_PIN: //1
				idx = eeCertMatch1(aux_tlsa, cert_list);
				break; // continue checking
			case EE_TA_ADDED: //3
				idx = eeCertMatch3(aux_tlsa, cert_list);
				break; // continue checking
			default:
				if (debug) {
					printf(DEBUG_PREFIX_DANE "Wrong value of cert_usage parameter: %i \n",
					    aux_tlsa->cert_usage);
				}
				idx = DANE_EXIT_TLSA_PARAM_ERR; // unknown cert usage, skip
			} // switch
			break; // continue checking
		} // switch

		if (debug) {
			printf(DEBUG_PREFIX_DANE "Return: %i > %i\n", idx,
			    DANE_EXIT_NO_CERT_CHAIN);
		}

		aux_tlsa = aux_tlsa->next;
		if (idx > DANE_EXIT_NO_CERT_CHAIN) {
			return idx;
		}
	} // while

	return idx;
}

//*****************************************************************************
// Get TLSA records from DNS response for particulary domain name
// Store the TLSA record into TLSA structure and add structure in the list
// return 1 if success or 0 when TLSA record is wrong or missing
// ----------------------------------------------------------------------------
static
int get_tlsa_record(struct tlsa_store_head *tlsa_list,
    struct ub_result *result, char *domain)
{	
	int i = 0;
	int exitcode = DANE_EXIT_RESOLVER_FAILED;

	/* show security status */
	if (result->secure) {
		/* show tlsa_first result */
		if (result->havedata) {

			if (debug) {
				printf(DEBUG_PREFIX "Domain is secured by DNSSEC ... found TLSA record(s).\n");
			}

			ldns_pkt *packet;
			ldns_status parse_status = ldns_wire2pkt(&packet,
			    (uint8_t*)(result->answer_packet),
			    result->answer_len);
                
			if (parse_status != LDNS_STATUS_OK) {
				if (debug) {
					printf(DEBUG_PREFIX "Failed to parse response packet\n");
				}
				ub_resolve_free(result);
				return DANE_EXIT_RESOLVER_FAILED;
			} //if
                
			ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(packet,
			    LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);

			for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
				/* extract first rdf, which is the whole TLSA record */
				ldns_rr *rr = ldns_rr_list_rr(rrs, i);
				// Since ldns 1.6.14, RR for TLSA is parsed into 4 RDFs 
				// instead of 1 RDF in ldns 1.6.13.
				if (ldns_rr_rd_count(rr) < 4) {
					if (debug) {
						printf(DEBUG_PREFIX "RR %d hasn't enough fields\n", i);
					}
					ub_resolve_free(result);
					return DANE_EXIT_TLSA_PARAM_ERR;
				}	
				ldns_rdf *rdf_cert_usage = ldns_rr_rdf(rr, 0),
				*rdf_selector      = ldns_rr_rdf(rr, 1),
				*rdf_matching_type = ldns_rr_rdf(rr, 2),
				*rdf_association   = ldns_rr_rdf(rr, 3);
                        
				if ((ldns_rdf_size(rdf_cert_usage) != 1) ||
				    (ldns_rdf_size(rdf_selector) != 1) ||
				    (ldns_rdf_size(rdf_matching_type) != 1) ||
				    (ldns_rdf_size(rdf_association) < 0)) {

					if (debug) {
						printf(DEBUG_PREFIX "Improperly formatted TLSA RR %d\n", i);
					}
					ub_resolve_free(result);
					return DANE_EXIT_TLSA_PARAM_ERR;
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

			exitcode = DANE_EXIT_DNSSEC_SECURED;                
			if (packet) {
				ldns_pkt_free(packet);
			}
			if (rrs) {
				ldns_rr_list_free(rrs);
			}

		} else {
			if (debug) {
				printf(DEBUG_PREFIX "Unbound haven't received any data for %s.\n", domain);
			}
			exitcode = DANE_EXIT_NO_TLSA_RECORD;
		} //if
	} else if (result->bogus) {
		exitcode = DANE_EXIT_DNSSEC_BOGUS;
		if (debug) {
			printf(DEBUG_PREFIX "Domain is bogus: %s \n", result->why_bogus);
		}
	} else {
		exitcode = DANE_EXIT_DNSSEC_UNSECURED;
		if (debug) {
			printf(DEBUG_PREFIX "Domain is insecure...\n");
		}
	}

	ub_resolve_free(result);
	return exitcode;
}


//*****************************************************************************
// free unbound context (erase cache data from ub context), ctx = NULL
// external API
// ----------------------------------------------------------------------------
void ub_context_free()
{
	if (context == true) { 
		ub_ctx_delete(ctx);
		context = false;
	}
} //ub_context_free


//*****************************************************************************
// Function char* get_tlsa_query
// return _port._protocol.domain e.g: _443._tcp.www.nic.cz
// ----------------------------------------------------------------------------
static
char * get_tlsa_query(char *domain, char *port, char *protocol) 
{
	char *tlsa_query = NULL,
	*tlsa_query_old = NULL;

	tlsa_query_old = tlsa_query;
	tlsa_query  = mystrcat("_", port);
	free(tlsa_query_old);
	tlsa_query_old = tlsa_query;
	tlsa_query = mystrcat(tlsa_query, "._");
	free(tlsa_query_old);
	tlsa_query_old = tlsa_query;
	tlsa_query = mystrcat(tlsa_query, protocol);
	free(tlsa_query_old);
	tlsa_query_old = tlsa_query;
	tlsa_query = mystrcat(tlsa_query, ".");
	free(tlsa_query_old);
	tlsa_query_old = tlsa_query;
	tlsa_query = mystrcat(tlsa_query, domain);
	free(tlsa_query_old);
   
	return tlsa_query;
}

//*****************************************************************************
// Main DANE/TLSA validation function, external API
// Input parmateers:
// 	char* certchain[] - array of derCert in HEX (certificate chain)
//	int certcount - number of cert in array - count(array)
//	const uint16_t options - TLSA validator option (debug,IPv4,IPv6) 
//	char *optdnssrv - list of IP resolver addresses separated by space
//	char* domain - domain name (e.g.: wwww.nic.cz, torproject.org, ...)
//	char* port - number of port for SSL (443, 25)
//	char* protocol - "tcp" only 
//	int policy - certificate policy from browser
// Return: DANE/TLSA validation status (x<0=valfail or error, x>0 = success)
//	   return values: dane-state.gen file
// ----------------------------------------------------------------------------
short CheckDane(char *certchain[], int certcount, const uint16_t options, char *optdnssrv, char *domain,  char *port, char *protocol, int policy) 
{
	struct ub_result* result;
	struct tlsa_store_head tlsa_list;
	struct cert_store_head cert_list;
	tlsa_list.first = NULL;
	cert_list.first = NULL;
	int tlsa_res = -1;
	int tlsa_ret = 0;
	int retval = 0;
	char uri[256];
	int ub_retval = 0;
	char *fwd_addr = NULL;
	char delims[] = " ";
	bool usefwd = false;
	short exitcode = DANE_EXIT_RESOLVER_FAILED;
	char* dn = NULL;
	ds_init_opts(options);
	debug = opts.debug;
	usefwd = opts.usefwd;

	//-----------------------------------------------
	// Unbound resolver initialization, set forwarder 
	if (!context) {
		ctx = ub_ctx_create();

		if(!ctx) {
			if (debug) printf(DEBUG_PREFIX "Error: could not create unbound context\n");
			return exitcode;
		}
		context = true;

		// set resolver/forwarder if it was set in options
		if (usefwd) {
			if (strcmp (optdnssrv,"") != 0) {
				fwd_addr = strtok(optdnssrv, delims);
				// set ip addresses of resolvers into ub context
				while (fwd_addr != NULL) {
					if ((ub_retval=ub_ctx_set_fwd(ctx, optdnssrv)) != 0) {
						if (debug) {
							printf(DEBUG_PREFIX "Error adding resolver IP address: %s\n",
							    ub_strerror(ub_retval));
						}
						return exitcode;
					} //if            	  
					fwd_addr = strtok(NULL, delims);
				} //while
			} else {
				if ((ub_retval = ub_ctx_resolvconf(ctx, NULL)) != 0) {
					if (debug) {
						printf(DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n",
						    ub_strerror(ub_retval), strerror(errno));
					}
					return exitcode;
				} //if  
			} //if
		} // if(usefwd)

		/* read public keys of root zone for DNSSEC verification */
		// ds true = zone key will be set from file root.key
		//    false = zone key will be set from TA constant
		if (ds) {
			if ((ub_retval=ub_ctx_add_ta_file(ctx, "root.key")) != 0) {
				if (debug) {
					printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
				}
				return exitcode;
			} //if
		} else {
			if ((ub_retval=ub_ctx_add_ta(ctx, TA)) != 0) {
				if (debug) {
					printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
				}
				return exitcode;
			}
		}// if (ds)   

		// set dlv-anchor
		if ((ub_retval=ub_ctx_set_option(ctx, "dlv-anchor:", DLV))) {
			if (debug) {
				printf(DEBUG_PREFIX "Error adding DLV keys: %s\n", ub_strerror(ub_retval));
			}
			return exitcode;      
		}
	} // end of init resolver
	//------------------------------------------------------------

	// create TLSA query 
	dn = get_tlsa_query(domain, port, protocol);

	retval = ub_resolve(ctx, dn, LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN , &result);

	if (retval != 0) {
		if (debug) {
			printf(DEBUG_PREFIX "resolve error: %s\n", ub_strerror(retval));
		}
		return exitcode;
	} //if

	// get TLSA records from response
	tlsa_ret = get_tlsa_record(&tlsa_list, result, domain);

	free(dn);

	if (tlsa_ret == DANE_EXIT_DNSSEC_UNSECURED) {
		free_tlsalist(&tlsa_list);
		return DANE_EXIT_DNSSEC_UNSECURED;
	} else if (tlsa_ret == DANE_EXIT_DNSSEC_BOGUS) {
		free_tlsalist(&tlsa_list);
		return DANE_EXIT_DNSSEC_BOGUS;
	} else if (tlsa_ret == DANE_EXIT_TLSA_PARAM_ERR) {
		free_tlsalist(&tlsa_list);
		return DANE_EXIT_TLSA_PARAM_ERR;
	} else if (tlsa_ret == DANE_EXIT_NO_TLSA_RECORD) {
		free_tlsalist(&tlsa_list);
		return DANE_EXIT_NO_TLSA_RECORD;
	} else if (tlsa_ret == DANE_EXIT_RESOLVER_FAILED) {
		free_tlsalist(&tlsa_list);
		return DANE_EXIT_RESOLVER_FAILED;
	}

	if (debug) {
		print_tlsalist(&tlsa_list);
	}

	int i;
	if (certcount > 0) {

		if (debug) {
			printf(DEBUG_PREFIX_CER "Browser's certificate chain is used\n");
		}

		for (i = 0; i < certcount; i++) {
			int certlen=strlen(certchain[i])/2;
			unsigned char *certbin = (unsigned char *) hextobin(certchain[i]);
			char *certbin2 = hextobin(certchain[i]);   
			cert_tmp_ctx skpi = spkicert(certbin, certlen);

			add_certrecord_bottom(&cert_list, certbin2, certlen, certchain[i],
					skpi.spki_der, skpi.spki_len, skpi.spki_der_hex);

			free(certbin);
			free(certbin2);
			free(skpi.spki_der_hex); /* Messy clean-up. Create a better one. */
			free(skpi.spki_der);
		}//for
	} else {
		if (debug) {
			printf(DEBUG_PREFIX_CER "External certificate chain is used\n");
		}
		strcpy (uri,"https://");
		strncat (uri, domain, strlen(domain));
		tlsa_ret = getcert(uri, domain, port, &cert_list);
		if (tlsa_ret == 0) {
			free_tlsalist(&tlsa_list);
			free_certlist(&cert_list);
			return DANE_EXIT_NO_CERT_CHAIN;
		} //if
	} //if

	if (debug) {
		print_certlist(&cert_list);
	}

	tlsa_res = TLSAValidate(&tlsa_list, &cert_list);

	if (debug) {
		printf(DEBUG_PREFIX_DANE "result: %i\n", tlsa_res);
	}

	free_tlsalist(&tlsa_list);
	free_certlist(&cert_list);
  
	return tlsa_res;
}


//static
//char cert[4096] = {1, 2, 3, 4, 5, 0, };
//
//static
//char *certhex[] = {cert};
//
//
char* certhex[] = {"12345678"};
//char* certhex[] = {"308206BA308205A2A003020102021006DE97E51DC39DC2648DAC72DD4101FC300D06092A864886F70D01010B05003066310B300906035504061302555331153013060355040A130C446967694365727420496E6331193017060355040B13107777772E64696769636572742E636F6D312530230603550403131C44696769436572742048696768204173737572616E63652043412D33301E170D3133303132393030303030305A170D3136303530333132303030305A3072310B3009060355040613025553311630140603550408130D4D6173736163687573657474733110300E0603550407130757616C706F6C65311E301C060355040A131554686520546F722050726F6A6563742C20496E632E3119301706035504030C102A2E746F7270726F6A6563742E6F726730820122300D06092A864886F70D01010105000382010F003082010A0282010100DD6839EF01D244F497A317B08396881897A8B7C60A4F2721E5FE1977344CD7B3D781C158F3B32CC980E8A7E3DE1F6427484B0B39521AE8B7C6C4F571AE595CE34FFF66DE0E4228C7017EEFF3024BC80EBB80B2B9AD028D1D1C7BA6167A629854AC68A89BD81FF4B6527CCC1DA048FDB849F902B990C620FC95E8331F483082678E5F5C945B774C4DF8511E7F3594ECCAD5C0B428C8E6A312A73291137D514441AFD64C704EA26AFE0E541495B3644C084831214DE15354EAEED2A8DB100A9A8A9E21407F432138C3385C3B52981D69BE1337880BC03699BA8F90733F82411EAF09294FD8ACE24001FD9E553EA93F3579856FF8D39F8E882F76EFC0B65FEAFB3D0203010001A382035630820352301F0603551D2304183016801450EA7389DB29FB108F9EE50120D4DE79994883F7301D0603551D0E04160414B1F3B22AD1F98078D5116236299D21BCAE276E66302B0603551D110424302282102A2E746F7270726F6A6563742E6F7267820E746F7270726F6A6563742E6F7267300E0603551D0F0101FF0404030205A0301D0603551D250416301406082B0601050507030106082B0601050507030230610603551D1F045A3058302AA028A0268624687474703A2F2F63726C332E64696769636572742E636F6D2F6361332D6731382E63726C302AA028A0268624687474703A2F2F63726C342E64696769636572742E636F6D2F6361332D6731382E63726C308201C40603551D20048201BB308201B7308201B306096086480186FD6C0101308201A4303A06082B06010505070201162E687474703A2F2F7777772E64696769636572742E636F6D2F73736C2D6370732D7265706F7369746F72792E68746D3082016406082B06010505070202308201561E8201520041006E007900200075007300650020006F00660020007400680069007300200043006500720074006900660069006300610074006500200063006F006E0073007400690074007500740065007300200061006300630065007000740061006E006300650020006F00660020007400680065002000440069006700690043006500720074002000430050002F00430050005300200061006E00640020007400680065002000520065006C00790069006E0067002000500061007200740079002000410067007200650065006D0065006E00740020007700680069006300680020006C0069006D006900740020006C0069006100620069006C00690074007900200061006E0064002000610072006500200069006E0063006F00720070006F00720061007400650064002000680065007200650069006E0020006200790020007200650066006500720065006E00630065002E307B06082B06010505070101046F306D302406082B060105050730018618687474703A2F2F6F6373702E64696769636572742E636F6D304506082B060105050730028639687474703A2F2F636163657274732E64696769636572742E636F6D2F4469676943657274486967684173737572616E636543412D332E637274300C0603551D130101FF04023000300D06092A864886F70D01010B0500038201010015F02C231841C734958B96BD169129F4919CD302F9FF805516FD252988C791156805DBCDDE09C07C6B76617AC02596FB3825705B7285752693C26F13D747825525D70124EBA7A0D6B3A987C70F4718891517D6044AAEB1E7F6461C34E8BEE44C09E1EE2309FE9C12F6D73D560EAC28CF07100313577915C9BD73B86CE8F7D35FB6E9AB3D70E5A3A271B3916F6E7375935A9F3DF983A9468E91439F587375099718D61D94773AAA7F18CD63A3634F1E715E3299C5B558FEBAE401B4D8FB0FB8E25A11AD37114878F8B3381B3C93E6A8F6558E1365072B988CD7B6084918413CDC22E182FE9DFFA3A39BA7B44E9682F1588441F6A7098248AAC86017466AD6F17F"}; 
//*****************************************************************************
// Main function for testing of lib, input: domain name
// ----------------------------------------------------------------------------
int main(int argc, char **argv) 
{

	int res = DANE_EXIT_RESOLVER_FAILED;

	res = CheckDane(certhex, 0, 5, "8.8.8.8", argv[1], argv[2], "tcp", 1);
	
	if (debug) {
		printf(DEBUG_PREFIX_DANE "Main final result: %i\n", res);
	}

	ub_context_free();

	return 1;

}
