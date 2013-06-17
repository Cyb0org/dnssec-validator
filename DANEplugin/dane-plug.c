/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.

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

/* Windows */
  #ifdef RES_WIN
  #include "ldns/config.h"
  #include "ldns/ldns.h"
  #include "libunbound/unbound.h"
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <iphlpapi.h> /* for IP Helper API */
  #include <winreg.h>
  #define DWORD_MAX 0xFFFFFFFF
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

bool ws = false;		         /* write debug info into output file */
bool ds = false;   		/* load root DS key from file */
FILE *dfout;			    /* FILE - for debug information*/
bool debug = true;
bool context = false;
static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static int byteMapLen = sizeof(byteMap);

/* structure to save TLSA records */
typedef struct tlsa_store_ctx_st {   
   char* domain;
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
   char* cert_der;
   int cert_len;
   char* cert_der_hex;
   char* spki_der;
   int spki_len;
   char* spki_der_hex;
  struct cert_store_ctx_st *next;
} cert_store_ctx; 

/* pointer structure to save certificate records */
struct cert_store_head {
    struct cert_store_ctx_st *first;
};

/* structure to save certificate records */
typedef struct cert_tmp_st {
   char* spki_der;
   int spki_len;
   char* spki_der_hex;
} cert_tmp_ctx; 


/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO *out) {
  int sockfd;
  char hostname[256] = "";
  char    portnum[6] = "443";
  char      proto[6] = "";
  char      *tmp_ptr = NULL;
  int           port;
  struct hostent *host;
  struct sockaddr_in dest_addr;

#ifdef WIN32
   WSADATA wsaData;
   WORD version;
   int error;

   version = MAKEWORD( 2, 0 );

   error = WSAStartup( version, &wsaData );

   /* check for error */
   if ( error != 0 )
   {
       return -1;
   }

   /* check for correct version */
   if ( LOBYTE( wsaData.wVersion ) != 2 ||
        HIBYTE( wsaData.wVersion ) != 0 )
   {
       /* incorrect WinSock version */
       WSACleanup();
       return -1;
   }
#endif

  //Remove the final / from url_str, if there is one
  if(url_str[strlen(url_str)] == '/')
    url_str[strlen(url_str)] = '\0';

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
    if (debug) BIO_printf(out, DEBUG_PREFIX "Error: Cannot resolve hostname %s.\n",  hostname);
    abort();
  }

  //create the basic TCP socket                                
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd == -1)
  {
    if (debug) printf(DEBUG_PREFIX "error opening socket");
    return -1;
  }

  dest_addr.sin_family=AF_INET;
  dest_addr.sin_port=htons(port);
  dest_addr.sin_addr.s_addr = 0;
  dest_addr.sin_addr.s_addr = *(unsigned long*)host->h_addr_list[0];

  //Zeroing the rest of the struct       
  memset(&(dest_addr.sin_zero), '\0', 8);
  tmp_ptr = inet_ntoa(dest_addr.sin_addr);

  //Try to make the host connect here                          *
  if ( connect(sockfd, (struct sockaddr *) &dest_addr,sizeof(struct sockaddr_in)) == -1 ) {
    if (debug) BIO_printf(out, DEBUG_PREFIX "Error: Cannot connect to host %s [%s] on port %d.\n",
             hostname, tmp_ptr, port);
  }

  return sockfd;
}

/* ---------------------------------------------------------- *
 * char* get_dnssec_status(uint8_t dnssec_status)		*
 * ---------------------------------------------------------- */
char* get_dnssec_status(uint8_t dnssec_status){
  switch (dnssec_status) {
    case 0: return "INSECURE";
    case 1: return "SECURE";
    case 2: return "BOGUS";
    default: return "ERROR";
  }
}

/* ---------------------------------------------------------- *
 * char* get_dnssec_status(uint8_t dnssec_status)		*
 * ---------------------------------------------------------- */
void add_tlsarecord(struct tlsa_store_head *tlsa_list, char *domain, uint8_t dnssec_status, uint8_t cert_usage, uint8_t selector, uint8_t matching_type, uint8_t *association, size_t association_size, char* assochex) 
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

void add_tlsarecord_bottom(struct tlsa_store_head *tlsa_list, char *domain, uint8_t dnssec_status, uint8_t cert_usage, uint8_t selector, uint8_t matching_type, uint8_t *association, size_t association_size, char* assochex) 
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
	 if (tlsa_list->first) {
	    tlsa_store_ctx *tmp = tlsa_list->first;
	     while (tmp->next) tmp = tmp->next;
             tmp->next = field_tlsa; 
         }
	 else {
      	    tlsa_list->first = field_tlsa;
         }
}

/* ---------------------------------------------------------- *
 * char* get_dnssec_status(uint8_t dnssec_status)		*
 * ---------------------------------------------------------- */
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
                    add_tlsarecord_bottom(&tlsa_list_new, tmp->domain, tmp->dnssec_status, tmp->cert_usage, tmp->selector, tmp->matching_type, tmp->association, tmp->association_size, (char*)tmp->assochex); 
                }
                break;
            case CA_TA_ADDED:
            case EE_TA_ADDED:
                if (policy & ALLOW_TYPE_23) {
                    add_tlsarecord_bottom(&tlsa_list_new, tmp->domain, tmp->dnssec_status, tmp->cert_usage, tmp->selector, tmp->matching_type, tmp->association, tmp->association_size, (char*)tmp->assochex); 
                }
                break;
            default:
                break;
        }; 
    }
    return tlsa_list_new;
}


/* ---------------------------------------------------------- *
 * char* get_dnssec_status(uint8_t dnssec_status)		*
 * ---------------------------------------------------------- */
void print_tlsalist(const struct tlsa_store_head *tlsa_list) {
   struct tlsa_store_ctx_st *tmp;
   tmp=tlsa_list->first;
   while (tmp != NULL) {
       printf(DEBUG_PREFIX "---------------------------------------------\n");
       printf(DEBUG_PREFIX "%s: dnssec: %s (%d), cert usage: %d, selector: %d, matching type: %d, assoc.hex: %s, assoc.size: %zu \n", tmp->domain, get_dnssec_status(tmp->dnssec_status), tmp->dnssec_status, tmp->cert_usage, tmp->selector, tmp->matching_type, tmp->assochex, tmp->association_size);
      tmp = tmp->next;
   } // while
   printf(DEBUG_PREFIX "---------------------------------------------\n");
} 

/* ---------------------------------------------------------- *
 * char* get_dnssec_status(uint8_t dnssec_status)		*
 * ---------------------------------------------------------- */
void free_tlsalist(struct tlsa_store_head *tlsa_list) {     
  if (tlsa_list->first != NULL) {
     tlsa_store_ctx *field, *pom;
     field = tlsa_list->first->next;
     while (field != NULL) {
         pom = field->next;
	 free(field->domain);
	 free(field->assochex);
         free(field);
         field = pom;
     } // while
     tlsa_list->first->next = NULL;
  } // if
}

/* ---------------------------------------------------------- */
/* Utility function to convert nibbles (4 bit values) into a hex character representation *
* ---------------------------------------------------------- */
void add_certrecord(struct cert_store_head *cert_list, char* cert_der, int cert_len, char* cert_der_hex,  char* spki_der, int spki_len,  char* spki_der_hex) 
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



void add_certrecord_bottom (struct cert_store_head *cert_list, char* cert_der, int cert_len, char* cert_der_hex,  char* spki_der, int spki_len,  char* spki_der_hex) 
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
	 if (cert_list->first) {
	    cert_store_ctx *tmp = cert_list->first;
	     while (tmp->next) tmp = tmp->next;
             tmp->next = field_cert; 
         }
	 else {
      	    cert_list->first = field_cert;
         }
}


/* ---------------------------------------------------------- */
/* Convert a buffer of binary values into a hex string representation *
* ---------------------------------------------------------- */
void print_certlist(struct cert_store_head *cert_list) {
   struct cert_store_ctx_st *tmp;
   tmp=cert_list->first;
   while (tmp != NULL) {
       printf(DEBUG_PREFIX_CER "---------------------------------------------\n");
       printf(DEBUG_PREFIX_CER "certlen: %i\n%s\nspkilen: %i\n%s\n", tmp->cert_len, tmp->cert_der_hex, tmp->spki_len, tmp->spki_der_hex);
      tmp = tmp->next;
   } // while
   printf(DEBUG_PREFIX_CER "---------------------------------------------\n");
} 

/* ---------------------------------------------------------- */
/* Convert a buffer of binary values into a hex string representation *
* ---------------------------------------------------------- */
void free_certlist(struct cert_store_head *cert_list) {     
  if (cert_list->first != NULL) {
     cert_store_ctx *field, *pom;
     field = cert_list->first->next;
     while (field != NULL) {
         pom = field->next;
	 free(field->cert_der);
	 free(field->spki_der);
	 free(field->cert_der_hex);
	 free(field->spki_der_hex);
         free(field);
         field = pom;
     } // while
     cert_list->first->next = NULL;
  } // if
}

/* ---------------------------------------------------------- */
/* Utility function to convert nibbles (4 bit values) into a hex character representation *
* ---------------------------------------------------------- */
static char nibbleToChar(uint8_t nibble)
{
	if (nibble < byteMapLen) return byteMap[nibble];
	return '*';
}

/* ---------------------------------------------------------- */
/* Convert a buffer of binary values into a hex string representation *
* ---------------------------------------------------------- */
char *bintohex(uint8_t *bytes, size_t buflen)
{
	char *retval;
	int i;
	buflen=buflen*2;
	retval = malloc(buflen*2 + 1);
	for (i=0; i<buflen; i++) {
		retval[i*2] = nibbleToChar(bytes[i] >> 4);
		retval[i*2+1] = nibbleToChar(bytes[i] & 0x0f);
	}
    	retval[i] = '\0';
	return retval;
}


/* ---------------------------------------------------------- *
* Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
* ---------------------------------------------------------- */
int hex_to_int(char c){
	if(c >=97) c=c-32;
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

/* ---------------------------------------------------------- *
* Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
* ---------------------------------------------------------- */
int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}

/* ---------------------------------------------------------- *
* Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
* ---------------------------------------------------------- */
char *mystrcat(char *str1, char *str2) {

	char *str;
	if (!str1) str1 = "";
	if (!str2) str2 = "";
	str = malloc(strlen(str1) + strlen(str2) + 1);
	if (str) sprintf(str, "%s%s", str1, str2);
	return str;
}

/* ---------------------------------------------------------- *
* Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
* ---------------------------------------------------------- */
char* hextobin(char* data){

        int length = strlen(data);
        int i, j;
	char buffer[2048] = "";
	char *ret;
        assert((length % 2) == 0);
        for(i = 0, j = 0; i < length; i+=2, ++j){
                buffer[j] = hex_to_ascii(data[i], data[i+1]);
        }
        ret = malloc(length + 1);
	memcpy(ret, buffer, length);
        return ret;
}

/* ---------------------------------------------------------- *
* Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
* ---------------------------------------------------------- */
void getcert(char* dest_url, struct cert_store_head *cert_list) {

  EVP_PKEY 	      *pkey = NULL;
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  STACK_OF(X509)     *chain = NULL;
  X509_NAME       *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  int len2;
  unsigned char *buf2;
  char *hex2;
  int len;
  unsigned char *buf;
  char *hex;

  //These function calls initialize openssl for correct work.
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  if(SSL_library_init() < 0)
    if (debug) BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");


  method = SSLv23_client_method();


  if ( (ctx = SSL_CTX_new(method)) == NULL)
    if (debug) BIO_printf(outbio, "Unable to create a new SSL context structure.\n");


  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);


  ssl = SSL_new(ctx);


  server = create_socket(dest_url, outbio);
  if(server == 0)
    if (debug) BIO_printf(outbio, "Error TCP connection to: %s.\n", dest_url);


  SSL_set_fd(ssl, server);


  if ( SSL_connect(ssl) != 1 )
    if (debug) BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);

  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    if (debug) BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);

    buf = NULL;
    len = i2d_X509(cert, &buf);
    hex = bintohex((uint8_t*)buf, len);

  if ((pkey = X509_get_pubkey(cert)) == NULL)
    if (debug) BIO_printf(outbio, "Error getting public key from certificate");


  if (pkey) {
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        if (debug) BIO_printf(outbio, "%d bit RSA Key\n", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        if (debug) BIO_printf(outbio, "%d bit DSA Key\n", EVP_PKEY_bits(pkey));
        break;
      default:
        if (debug) BIO_printf(outbio, "%d bit non-RSA/DSA Key\n", EVP_PKEY_bits(pkey));
        break;
    }
  }

    buf2 = NULL;
    len2 = i2d_PUBKEY(pkey, &buf2);
    hex2 = bintohex((uint8_t*)buf2, len2);
    add_certrecord_bottom(cert_list, (char*)buf, len, hex, (char*)buf2,len2, hex2); 


  chain = SSL_get_peer_cert_chain(ssl);
  if (chain == NULL)
    if (debug) BIO_printf(outbio, "Error: Could not get a certificate chain: %s.\n", dest_url); 
  int value = sk_X509_num(chain);
  BIO_printf(outbio, "CHAIN N:\n%i\n", value);

  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);


  //BIO_printf(outbio, "Displaying the certificate subject data:\n");
  //X509_NAME_print_ex(outbio, certname, 0, 0);
  //BIO_printf(outbio, "\n");

  EVP_PKEY_free(pkey);
  SSL_free(ssl);
#ifdef WIN32
   closesocket(server);
   WSACleanup();
#else
   close(server);
#endif
  SSL_CTX_free(ctx);
  if (debug) BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
  //return(hex);
}

/* ---------------------------------------------------------- *
 * opensslDigest(const EVP_MD *md, const char *data, int len)
 * ---------------------------------------------------------- */
cert_tmp_ctx spkicert(const unsigned char* certder, int len){
  
  cert_tmp_ctx tmp;
  BIO  *outbio = NULL;
  EVP_PKEY *pkey = NULL;
  X509* cert;
  cert = d2i_X509(NULL, &certder, len);
  outbio  = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  if ((pkey = X509_get_pubkey(cert)) == NULL)
    BIO_printf(outbio, "Error getting public key from certificate");

    int len2;
    unsigned char *buf2;
    char *hex2;
    buf2 = NULL;
    len2 = i2d_PUBKEY(pkey, &buf2);
    hex2 = bintohex((uint8_t*)buf2, len2);
    tmp.spki_der=(char*)buf2; 
    tmp.spki_len=len2;
    tmp.spki_der_hex=hex2; 
    return tmp;
}

/* ---------------------------------------------------------- *
 * opensslDigest(const EVP_MD *md, const char *data, int len)
 * ---------------------------------------------------------- */
char *opensslDigest(const EVP_MD *md, const char *data, int len) {
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

/* ---------------------------------------------------------- *
 * char *sha256(char *data, int len)			      
 * ---------------------------------------------------------- */
char *sha256(char *data, int len) {
    if (debug) printf(DEBUG_PREFIX_DANE "sha256\n");
    return opensslDigest(EVP_sha256(), data, len);
}

/* ---------------------------------------------------------- *
 * char *sha512(char *data, int len)			      *
 * ---------------------------------------------------------- */
char *sha512(char *data, int len) {
    if (debug) printf(DEBUG_PREFIX_DANE "sha512\n");
    return opensslDigest(EVP_sha512(), data, len);
}

/* ---------------------------------------------------------- *
 * char *selectorData(uint8_t selector)			      *
 * ---------------------------------------------------------- */
char *selectorData(uint8_t selector, struct cert_store_head *cert_list) {
    if (debug) printf(DEBUG_PREFIX_DANE "selectorData->selector: %i \n",selector);
    switch (selector) {
        case FULL:
            return cert_list->first->cert_der;
        case SPKI:
           return cert_list->first->spki_der;
        default:
            return NULL;
    };
}

/* ---------------------------------------------------------- *
 * char *matchingData(uint8_t matching_type, uint8_t selector)*
 * ---------------------------------------------------------- */
char *matchingData(uint8_t matching_type, uint8_t selector, struct cert_store_head *cert_list) {  
    char* data = selectorData(selector, cert_list);
    if (debug) printf(DEBUG_PREFIX_DANE "matchingData->matching_type: %i \n",matching_type);
    switch (matching_type) {
        case EXACT:
            return data;
        case SHA256:
	    if (selector==1) return sha256(data, cert_list->first->spki_len);
	    else return sha256(data, cert_list->first->cert_len);
        case SHA512:
	    if (selector==1) return sha512(data, cert_list->first->spki_len);
	    else return sha512(data, cert_list->first->cert_len);
        default:
            return NULL;
    }
}

/* ---------------------------------------------------------- *
 * int eeCertMatch
 * ---------------------------------------------------------- */
int eeCertMatch(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list) 
{
     if (debug) printf(DEBUG_PREFIX_DANE "eeCertMatch\n");     
     int ret_val = -1;
     char *data = matchingData(tlsa_list->first->matching_type, tlsa_list->first->selector, cert_list);
     if (strcmp ((const char*)data,(const char*)tlsa_list->first->assochex) == 0) {
           ret_val = 0; //index 0 - the EE cert - matched

     }
     if (debug) printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
     if (debug) printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_list->first->assochex);

     free(data);
     return ret_val;
}

/* ---------------------------------------------------------- *
 * int caCertMatch		
 * ---------------------------------------------------------- */
int caCertMatch(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list) 
{
     if (debug) printf(DEBUG_PREFIX_DANE "caCertMatch\n");
     int ret_val = -1;
     int i = 0;
     cert_list->first = cert_list->first->next;
     while (cert_list->first != NULL) {
	   i++;
	   char *data = matchingData(tlsa_list->first->matching_type, tlsa_list->first->selector, cert_list);
     	   if (strcmp ((const char*)data,(const char*)tlsa_list->first->assochex) == 0) {
               return i;
	   }
	   if (debug) printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
	   if (debug) printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_list->first->assochex);

           free(data);	  
	   cert_list->first = cert_list->first->next;
    } //while
    return ret_val;
}

/* ---------------------------------------------------------- *
 * int  chainCertMatch		
 * ---------------------------------------------------------- */
int chainCertMatch(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list) 
{
     if (debug) printf(DEBUG_PREFIX_DANE "chainCertMatch\n");
     int ret_val = -1;
     int i = 0;
     while (cert_list->first != NULL) {
	   char *data = matchingData(tlsa_list->first->matching_type, tlsa_list->first->selector, cert_list);
     	   if (strcmp ((const char*)data,(const char*)tlsa_list->first->assochex) == 0) {
               return i;
	   }
	   if (debug) printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
	   if (debug) printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_list->first->assochex);

           free(data);	  
	   cert_list->first = cert_list->first->next;
	   i++;
    } //while
    return ret_val;
}

/* ---------------------------------------------------------- *
 * char* get_dnssec_status(uint8_t dnssec_status)		*
 * ---------------------------------------------------------- */
int TLSAValidate(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list){
   int idx = -1;
   while (tlsa_list->first != NULL) {	
      idx = -1;
      switch (tlsa_list->first->dnssec_status) {
        case 0:
            return idx;
        case 2:
            return idx;
        case 1:
	     if (debug) printf(DEBUG_PREFIX_DANE "TLSAValidate->cert_usage: %i \n",tlsa_list->first->cert_usage);
	     switch (tlsa_list->first->cert_usage) {
	        case CA_CERT_PIN:			
  			idx = caCertMatch(tlsa_list, cert_list);
			break;            	
        	case CA_TA_ADDED:
			idx = chainCertMatch(tlsa_list, cert_list);
			break; 
	        case EE_CERT_PIN:
		case EE_TA_ADDED:	    
			idx = eeCertMatch(tlsa_list, cert_list);
	  	        break; // continue checking
                default:
                    break; // unknown cert usage, skip
  	     } // switch
            break; // continue checking
       } // switch
   tlsa_list->first = tlsa_list->first->next;
   if (idx>=0) return idx;
   } // while

  return idx;
}

//*****************************************************************************
// Get TLSA record throught unbound query
// ----------------------------------------------------------------------------
int get_tlsa_record(struct tlsa_store_head *tlsa_list, struct ub_result *result, char* domain)
{	
	int i;
        int exitcode = 0;
	uint8_t sec_status = 0;

	/* show tlsa_first result */
	if(result->havedata) {

		/* show security status */
		if(result->secure) {
			sec_status = 1;
		} else if(result->bogus) {
			sec_status = 2;
		} else 	{
    			sec_status = 0;
	        }

                ldns_pkt *packet;
                ldns_status parse_status = ldns_wire2pkt(&packet, (uint8_t*)(result->answer_packet), result->answer_len);
                
                if (parse_status != LDNS_STATUS_OK) {
                       if (debug) printf(DEBUG_PREFIX "Failed to parse response packet\n");
                        return 1;
                }
                
                ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(packet, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);		
                for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
                        /* extract first rdf, which is the whole TLSA record */
                        ldns_rr *rr = ldns_rr_list_rr(rrs, i);
                        
                        // Since ldns 1.6.14, RR for TLSA is parsed into 4 RDFs 
                        // instead of 1 RDF in ldns 1.6.13.
                        if (ldns_rr_rd_count(rr) < 4) {
                               if (debug) printf(DEBUG_PREFIX "RR %d hasn't enough fields\n", i);
                                return 1;
                        }

                        ldns_rdf *rdf_cert_usage    = ldns_rr_rdf(rr, 0),
                                 *rdf_selector      = ldns_rr_rdf(rr, 1),
                                 *rdf_matching_type = ldns_rr_rdf(rr, 2),
                                 *rdf_association   = ldns_rr_rdf(rr, 3);
                        
                        if (ldns_rdf_size(rdf_cert_usage)       != 1 ||
                            ldns_rdf_size(rdf_selector)         != 1 ||
                            ldns_rdf_size(rdf_matching_type)    != 1 ||
                            ldns_rdf_size(rdf_association)      < 0
                            ) {
                                if (debug) printf(DEBUG_PREFIX "Improperly formatted TLSA RR %d\n", i);
                                return 1;
                        }

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
			add_tlsarecord_bottom(tlsa_list, domain, sec_status, cert_usage, selector, matching_type, association, association_size, asshex);
			free(asshex);
                        ldns_rr_free(rr);
                }
                
                 if (packet) ldns_pkt_free(packet);
                 if (rrs) ldns_rr_list_free(rrs);
        } else {
                if (debug) printf(DEBUG_PREFIX "%s: Unbound haven't received any data. ", domain);
                //return 1;
        }
	//print_tlsalist(tlsa_first);
	ub_resolve_free(result);
	return exitcode;
}


//*****************************************************************************
// free ub context (erase cache data from ub context)
// ----------------------------------------------------------------------------
void ub_context_free(struct ub_ctx* ctx){
    if (context==true) { 
      ub_ctx_delete(ctx);
      context = false;
    }
} //ub_context_free


//*****************************************************************************
// free ub context (erase cache data from ub context)
// ----------------------------------------------------------------------------
struct ub_ctx* ResolverInit(struct ub_ctx* ctx, bool usefwd, char *optdnssrv) {

   int ub_retval;
   ctx = ub_ctx_create();
   char *fwd_addr;
   char delims[] = " ";
 printf(DEBUG_PREFIX "resolver: %s\n", optdnssrv);

   if(!ctx) {
        if (debug) printf(DEBUG_PREFIX "Error: could not create unbound context\n");
	if (ws) fprintf(dfout, DEBUG_PREFIX "Error: could not create unbound context\n");

       } // if

    /* read public keys of root zone for DNSSEC verification */
    // ds true = zone key will be set from file root.key
    //    false = zone key will be set from TA constant
    if (ds) {
       if ((ub_retval=ub_ctx_add_ta_file(ctx, "root.key")) != 0) {
          if (debug) printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
          if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));

       }
    }
    else {
       if ((ub_retval=ub_ctx_add_ta(ctx, TA)) != 0) {
          if (debug) printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
          if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
	
	}
        if ((ub_retval=ub_ctx_set_option(ctx, "dlv-anchor:", DLV))) {
  	  if (debug) printf(DEBUG_PREFIX "Error adding DLV keys: %s\n", ub_strerror(ub_retval));
          if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding DLV keys: %s\n", ub_strerror(ub_retval));
        }
     } // if (ds)   
 

     // set resolver/forawarder if it was set in options
     if (usefwd) {

     if (strcmp (optdnssrv,"") != 0) {

        fwd_addr = strtok(optdnssrv, delims);
        // set ip addresses of resolvers into ub context
        while (fwd_addr != NULL) {
		      if ((ub_retval=ub_ctx_set_fwd(ctx, optdnssrv)) != 0) {
		        if (debug) printf(DEBUG_PREFIX "Error adding resolver IP address: %s\n", ub_strerror(ub_retval));
  		      if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding resolver IP address: %s\n", ub_strerror(ub_retval));
		      } //if            	  
	     fwd_addr = strtok(NULL, delims);
	     } //while
  	  }  
    	else {
       	 if ((ub_retval = ub_ctx_resolvconf(ctx, NULL)) != 0) {
        	 if (debug)	printf(DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n", ub_strerror(ub_retval), strerror(errno));
	         if (ws)	fprintf(dfout, DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n", ub_strerror(ub_retval), strerror(errno));
        }   
      }
    } // if (usefwd)

    return ctx;
}

//*****************************************************************************
// _443._tcp.www.nic.cz
// ----------------------------------------------------------------------------
char* get_tlsa_query(char* domain, char* port, char* protocol) {

    char *tlsa_query = mystrcat("_", port);
    	   tlsa_query = mystrcat(tlsa_query, "._");
           tlsa_query = mystrcat(tlsa_query, protocol);
    	   tlsa_query = mystrcat(tlsa_query, ".");	  
	   tlsa_query = mystrcat(tlsa_query, domain);
   return tlsa_query;
}

//*****************************************************************************
// Main DANE check function
// ----------------------------------------------------------------------------
short CheckDane(char* certchain[], int certcount, const uint16_t options, char *optdnssrv, char* domain, char* port, char* protocol, int policy) {

   struct ub_result *result = NULL;
   struct tlsa_store_head tlsa_list;
   struct cert_store_head cert_list;        	
   struct ub_ctx* ctx = NULL;
   int tlsa_res = -1;
   tlsa_list.first = NULL;
   cert_list.first = NULL;
   int tlsa_ret, retval;
   char uri[256];

    if (!context) {
	ctx = ResolverInit(ctx, false, optdnssrv);
	context = true;
    }

    retval = ub_resolve(ctx, get_tlsa_query(domain,port,protocol), LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN , &result);
    if(retval != 0) {
		if (debug) printf(DEBUG_PREFIX "resolve error: %s\n", ub_strerror(retval));
		return 1;
     }

     tlsa_ret = get_tlsa_record(&tlsa_list, result, domain);

     if (debug) print_tlsalist(&tlsa_list);

     if (certcount > 0) {
	    if (debug) printf(DEBUG_PREFIX_CER "External certchain is used\n");

	    for (int i = 0; i < certcount; i++) {	    
	    int certlen=strlen(certchain[i])/2;
    	    cert_tmp_ctx skpi= spkicert((const unsigned char*)hextobin(certchain[i]),certlen);
	    add_certrecord_bottom(&cert_list, hextobin(certchain[i]), certlen, certchain[i], skpi.spki_der, skpi.spki_len, skpi.spki_der_hex); 
	     }//for
      }
     else {
        if (debug) printf(DEBUG_PREFIX_CER "Get certchain now\n");	
       strcpy (uri,"https://");
       strncat (uri, domain, strlen(domain));
       getcert(uri, &cert_list);
     }

     if (debug) print_certlist(&cert_list);

     tlsa_res = TLSAValidate(&tlsa_list,&cert_list);

     if (debug) printf(DEBUG_PREFIX_DANE "result: %i\n", tlsa_res);

     free_tlsalist(&tlsa_list);
     free_certlist(&cert_list);	
  
     return tlsa_res;
}



int main(int argc, char **argv) {
        char* st[] = { "308205bb308204a3a003020102020300c67e300d06092a864886f70d01010505003040310b300906035504061302555331173015060355040a130e47656f54727573742c20496e632e311830160603550403130f47656f54727573742053534c204341301e170d3131303830323130353533395a170d3133313030333037323533325a3081c3312930270603550405132065467647614d31626f4344496f3453712f3571336e3235714e50373876334967310b3009060355040613025553311730150603550408130e4e6f727468204361726f6c696e613110300e0603550407130752616c6569676831143012060355040a130b5265642048617420496e63312a3028060355040b1321436f72706f7261746520496e667261737472756374757265205365727669636573311c301a06035504030c132a2e6665646f726170726f6a6563742e6f726730820222300d06092a864886f70d01010105000382020f003082020a0282020100b79b8acb003dbde0a21c93185e789afb6cbb2fbcbc50d09f64db0e8e13819c90aaa6e89bbf52d658566cb2b30d19bf21054bac92090bc10d0171af34c9b8173fcc0d6e8b8dabbbe182d6a90ab98928997a8e6674843341098c20ec0722d75e53d8d139569e4295f0d2384148b77841e2c185bf3ffb2846f58df9a343869c0d899814f01effb1566a3324622ca035b406774fc1802053a2adf2f8d12f7e2f61d4dba1ce8fdf51f9a9cf4099e6a9de280a8a07297ced0a53362d8f47f42d4125d4576bce8c6eaffaeb02b85a56be679c54abb09ac32f324b4a071bee057d21b3807cc970509f0a7bb991d6c3404fff86778a4e0b7ba46d506506b2cb7e90acd1a6dc37f3775ac37ffaf81d6dff35dfee30664e81879ddd654651575b013f94fee48c5e17542f3f49a40ec21a9bb9d0dab87d25ae0769f42eb6900f9e8ca09259431200443204a82edfac47fd645b388508a01079591fc26d5d4af985c406716a57d5cb521a4372d3b3ecbeb89b35447d82257e469064daa858be02ab3816913e39d2a1cb4e85fd536e7147db188b353fb7ec0114f28aefd7315faf7adf15f788446da8ee539b193faa995bd27e1bf5af8cf5427eed3d2cf58b6ceec901f2b2706e3c5e99ff504a4b894fb0b6dd226c2e9036b5e4f1203112cd2aaa9a14cba9f239e95102700f1787bde7b9681933686fb030ad7b222ddde6ae0d21a91dc9cb41a30203010001a382013830820134301f0603551d230418301680144279541b61cd552b3e63d53c4857f59ffb45ce4a300e0603551d0f0101ff0404030204b0301d0603551d250416301406082b0601050507030106082b0601050507030230310603551d11042a302882132a2e6665646f726170726f6a6563742e6f726782116665646f726170726f6a6563742e6f7267303d0603551d1f043630343032a030a02e862c687474703a2f2f677473736c2d63726c2e67656f74727573742e636f6d2f63726c732f677473736c2e63726c301d0603551d0e0416041464e6c0c17f4d7254d58d7a66c9affbdf7cc7583b300c0603551d130101ff04023000304306082b0601050507010104373035303306082b060105050730028627687474703a2f2f677473736c2d6169612e67656f74727573742e636f6d2f677473736c2e637274300d06092a864886f70d010105050003820101000b629cfcd30288cb3c1b1400da6991be70b2fbb6c7b5cf63314f6c404e7a7f88a9574cc5e322b2334fd5b6a6df8d5beb6104bcc8f9322ac6eaed2442209f279db185ef5835ca0184fb6d082c3a96001def9314fe0a2d5db475f7fc2bb3570e7429ff11b147466c03a6e22c82a1d4a50c17586a9f29b441c33faebc77cd7dcb40d2d5842ef81ade8ae5a14aeef7ea5b2ef4a847f47de3949b1bebb6c6b6bc79b5d755ee9a76bf97d38dc5cb27d9f7ae7535de31e6429592fd7aab7b0556bebb82143ecb3e77faf744569da16bece6a70df7650236ef106b9123d32cbfdd024413675cf7b0dcdb87eefa2936602895df78dd5c0a6b3afe3a87d7c1f586ca4e41b5", 
"308203d9308202c1a00302010202030236d0300d06092a864886f70d01010505003042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c204341301e170d3130303231393232333932365a170d3230303231383232333932365a3040310b300906035504061302555331173015060355040a130e47656f54727573742c20496e632e311830160603550403130f47656f54727573742053534c20434130820122300d06092a864886f70d01010105000382010f003082010a028201010090b380c1e4e546ad70603dbae514dd9e8a5e8b755ae6ca6d41a523e83985267aa755779a48a1927e3a1e1af127aba34c39cccb3d47af81ae166a5c37ef4541fdfb9a973ca0439dc6df1721d18aa256c203498412813ec90a546066b98c54e4f9e6f994f1e05f7511f229b9e486a2b189ada61e832963b2f0541c850b7ae7e12e0dafa4bdcde7b15ad78c055a0e4b73288b755d34d8770be17462e2713062d8bc8a05e531634a54896a3378a74e55241d97ef1ae412c60f3018b4344de1d8233b215b2d3019250e74f7a4214ba0a420c96ccd9856c0f2a85f3e2675a00df836888a2c5a7d6730a90fd199702e78e15126af557a24be8c390d779dde02c30cbd1f0203010001a381d93081d6300e0603551d0f0101ff040403020106301d0603551d0e041604144279541b61cd552b3e63d53c4857f59ffb45ce4a301f0603551d23041830168014c07a98688d89fbab05640c117daa7d65b8cacc4e30120603551d130101ff040830060101ff020100303a0603551d1f04333031302fa02da02b8629687474703a2f2f63726c2e67656f74727573742e636f6d2f63726c732f6774676c6f62616c2e63726c303406082b0601050507010104283026302406082b060105050730018618687474703a2f2f6f6373702e67656f74727573742e636f6d300d06092a864886f70d01010505000382010100d4ef5384e81abda18b04c0a9f55fa11078455db2576a4e24cb654e3197919ad424f8e2276670319cc1625406e7971d3a9ac0a429480aaf24c7a8c49a54c17c4c784c2b682c5d17a654784c46e280c31f387112d2d753e3548550b802cbee633af856894d55bb2ec0c8187786310b0b70f07e3583a42a13645667345d165f73ac7b0624da4f506d2aabd04d5341c28ebb710349298618cf21424c74625115c56fa8efc427e51b33dd5a88d77f12d1a761251fd5e0dc1dcf1a10d8a0cb5f8cfa0ce5bf71ffe55d441da63e8747fa1a4e8383123f88669598799a85eb0247cd25e3f206044e99ca5ca06e7abbdda3901a4533efbf3ed204c4b6e02a8565413e10d4",
"308203543082023ca0030201020203023456300d06092a864886f70d01010505003042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c204341301e170d3032303532313034303030305a170d3232303532313034303030305a3042310b300906035504061302555331163014060355040a130d47656f547275737420496e632e311b30190603550403131247656f547275737420476c6f62616c20434130820122300d06092a864886f70d01010105000382010f003082010a0282010100dacc186330fdf417231a567e5bdf3c6c38e471b77891d4bca1d84cf8a843b603e94d21070888da582f663929bd05788b9d38e805b76a7e71a4e6c460a6b0ef80e489280f9e25d6ed83f3ada691c798c9421835149dad9846922e4fcaf18743c11695572d50ef892d807a57adf2ee5f6bd2008db914f8141535d9c046a37b72c891bfc9552bcdd0973e9c2664ccdfce831971ca4ee6d4d57ba919cd55dec8ecd25e3853e55c4f8c2dfe502336fc66e6cb8ea4391900b7950239910b0efe382ed11d059af64d3e6f0f071daf2c1e8f6039e2fa36531339d45e262bdb3da814bd32eb180328520471e5ab333de138bb073684629c79ea1630f45fc02be8716be4f90203010001a3533051300f0603551d130101ff040530030101ff301d0603551d0e04160414c07a98688d89fbab05640c117daa7d65b8cacc4e301f0603551d23041830168014c07a98688d89fbab05640c117daa7d65b8cacc4e300d06092a864886f70d0101050500038201010035e3296ae52f5d548e2950949f991a14e48f782a6294a227679ed0cf1a5e47e9c1b2a4cfdd411a054e9b4bee4a6f5552b324a1370aeb64762a2e2cf3fd3b7590bffa71d8c73d37d2b5059562b9a6de893d367b38774897aca6208f2ea6c90cc2b2994500c7ce11512222e0a5eab615480964ea5e4f74f7053ec78a520cdb15b4bd6d9be5c6b15468a9e36990b69aa50fb8b93f207dae4ab5b89ce41db6abe694a5c1c783addbf527870e046cd5ffdda05ded8752b72b1502ae39a66a74e9dac4e7bc4d341ea95c4d335f92092f88665d7797c71d7613a9d5e5f116091135d5acdb2471702c98560bd917b4d1e3512b5e75e8d5d0dc4f34edc2056680a1cbe633"}; 



 CheckDane(st, 0, 5, "8.8.8.8", argv[1], "443", "tcp", 1);
}

