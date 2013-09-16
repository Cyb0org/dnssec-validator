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
#include "dane_states.gen"


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
bool ws = false;		         /* write debug info into output file */
bool ds = false;   		/* load root DS key from file */
FILE *dfout;			    /* FILE - for debug information*/
bool debug = true;
bool context = false;
static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static int byteMapLen = sizeof(byteMap);
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------
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
//----------------------------------------------------------------------------
//----------------------------------------------------------------------------


//*****************************************************************************
// read input options into a structure
// ----------------------------------------------------------------------------
void ds_init_opts(const uint16_t options) {
  opts.debug = options & DANE_INPUT_FLAG_DEBUGOUTPUT;
  opts.usefwd = options & DANE_INPUT_FLAG_USEFWD;
}


//*****************************************************************************
// Helper function (SSL conection)
// create_socket() creates the socket & TCP-connect to server
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (return DNSSEC status)
// ----------------------------------------------------------------------------
char* get_dnssec_status(uint8_t dnssec_status){
  switch (dnssec_status) {
    case 0: return "INSECURE";
    case 1: return "SECURE";
    case 2: return "BOGUS";
    default: return "ERROR";
  }
}

//*****************************************************************************
// Helper function (add new record in the TLSA list - first)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (add new record in the TLSA list - last)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (sorte TLSA list base on Policy)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (print TLSA list)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (free TLSA list)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (add new record in the certificate list - first)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (add new record in the certificate list - last)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (print certificate list)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (free certificate list)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Utility function to convert nibbles (4 bit values) into a hex character representation
// ----------------------------------------------------------------------------
static char nibbleToChar(uint8_t nibble)
{
	if (nibble < byteMapLen) return byteMap[nibble];
	return '*';
}

//*****************************************************************************
// Helper function (binary data to hex string conversion)
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Helper function (hex to int)
// ----------------------------------------------------------------------------
int hex_to_int(char c){
	if(c >=97) c=c-32;
        int first = c / 16 - 3;
        int second = c % 16;
        int result = first*10 + second;
        if(result > 9) result--;
        return result;
}

//*****************************************************************************
// Helper function (hex to char)
// ----------------------------------------------------------------------------
int hex_to_ascii(char c, char d){
        int high = hex_to_int(c) * 16;
        int low = hex_to_int(d);
        return high+low;
}

//*****************************************************************************
// Helper function (string concatenation)
// ----------------------------------------------------------------------------
char *mystrcat(char *str1, char *str2) {

	char *str;
	if (!str1) str1 = "";
	if (!str2) str2 = "";
	str = malloc(strlen(str1) + strlen(str2) + 1);
	if (str) sprintf(str, "%s%s", str1, str2);
	return str;
}

//*****************************************************************************
// HEX string to Binary data convertor
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// Get certificates from SSL handshake
// Add certificate into structure
// Helper function 
// return success or error
// ----------------------------------------------------------------------------
int getcert(char* dest_url, struct cert_store_head *cert_list) {

  int ret = 0;
  EVP_PKEY 	      *pkey = NULL;
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  STACK_OF(X509)     *chain = NULL;
  //X509_NAME       *certname = NULL;
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
  if (debug) BIO_printf(outbio, "#cert in chain: %i\n", value);

  X509 *cert2 = NULL;
  int i = 0;
  if (chain && sk_X509_num(chain)) {        
        for (i = 1; i < sk_X509_num(chain); i++) {
	        if (debug) PEM_write_bio_X509(outbio, sk_X509_value(chain, i));
		buf = NULL;
		cert2 = sk_X509_value(chain, i);
    		len = i2d_X509(cert2, &buf);
    		hex = bintohex((uint8_t*)buf, len);
  		if ((pkey = X509_get_pubkey(cert2)) == NULL)
    		    if (debug) BIO_printf(outbio, "Error getting public key from certificate");
	        buf2 = NULL;
                len2 = i2d_PUBKEY(pkey, &buf2);
 		hex2 = bintohex((uint8_t*)buf2, len2);
	 	add_certrecord_bottom(cert_list, (char*)buf, len, hex, (char*)buf2,len2, hex2); 
    	 } //for
   }//if

  //certname = X509_NAME_new();
  //certname = X509_get_subject_name(cert);

  EVP_PKEY_free(pkey);
  SSL_free(ssl);
#ifdef WIN32
   closesocket(server);
   WSACleanup();
#else
   close(server);
#endif
  SSL_CTX_free(ctx);
  ret = 1;
  if (debug) BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
  return ret;
}

//*****************************************************************************
// DANE algorithm (spkicert)
// Get SPKI from binary data of certificate
// return struct (binary SPKI, SPKI length, SPKI in HEX format and its length 
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// DANE algorithm (opensslDigest)
// return binary data of certifiacte or SPKI encode by sha256, sha512 as HEX string
// ----------------------------------------------------------------------------
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

//*****************************************************************************
// DANE algorithm
// return binary data of certifiacte or SPKI encode by sha256
// ----------------------------------------------------------------------------
char *sha256(char *data, int len) {
    if (debug) printf(DEBUG_PREFIX_DANE "sha256\n");
    return opensslDigest(EVP_sha256(), data, len);
}

//*****************************************************************************
// DANE algorithm
// return binary data of certifiacte or SPKI encode by sha512
// ----------------------------------------------------------------------------
char *sha512(char *data, int len) {
    if (debug) printf(DEBUG_PREFIX_DANE "sha512\n");
    return opensslDigest(EVP_sha512(), data, len);
}

//*****************************************************************************
// DANE algorithm  (selector)
// return binary data of certifiacte or SPKI
// ----------------------------------------------------------------------------
char *selectorData(uint8_t selector, struct cert_store_head *cert_list) {
    if (debug) printf(DEBUG_PREFIX_DANE "selectorData->selector: %i \n",selector);
    switch (selector) {
        case FULL:
        	   return cert_list->first->cert_der;
        case SPKI:
	           return cert_list->first->spki_der;
        default:
	     	   if (debug) printf(DEBUG_PREFIX_DANE "Wrong value of selector parameter: %i \n",selector);
                   return "x";
    };
}

//*****************************************************************************
// DANE algorithm (matching_type)
// return binary data of certifiacte or SPKI encode in SHA256, SHA512
// ----------------------------------------------------------------------------
char *matchingData(uint8_t matching_type, uint8_t selector, struct cert_store_head *cert_list) {  
    if (debug) printf(DEBUG_PREFIX_DANE "matching_type: %i \n",matching_type);
    char* data = selectorData(selector, cert_list);
    if (strcmp ((const char*)data,"x") == 0) return "x"; 
    switch (matching_type) {
        case EXACT:
            return data;
        case SHA256:
	    if (selector==SPKI) return sha256(data, cert_list->first->spki_len);
	    else return sha256(data, cert_list->first->cert_len);
        case SHA512:
	    if (selector==SPKI) return sha512(data, cert_list->first->spki_len);
	    else return sha512(data, cert_list->first->cert_len);
        default:
	    if (debug) printf(DEBUG_PREFIX_DANE "Wrong value of matching_type parameter: %i \n",matching_type);
            return "x";
    }
}

//*****************************************************************************
// TLSA validation of EE certificate (type 1)
// Binary data codes EE certificate
// Servers certificate must coresponde EE certificate in TLSA
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
int eeCertMatch1(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list) 
{
     if (debug) printf(DEBUG_PREFIX_DANE "eeCertMatch\n");     
     int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE1;
     char *data = matchingData(tlsa_list->first->matching_type, tlsa_list->first->selector, cert_list);
     if (strcmp ((const char*)data,"x") == 0) return DANE_EXIT_TLSA_PARAM_ERR;
     if (strcmp ((const char*)data,(const char*)tlsa_list->first->assochex) == 0) {
           ret_val = DANE_EXIT_VALIDATION_SUCCESS_TYPE1; 
     }
     if (debug) printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
     if (debug) printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_list->first->assochex);

     free(data);
     return ret_val;
}


//*****************************************************************************
// TLSA validation of EE certificate (type 3)
// Binary data codes EE certificate
// Servers certificate must coresponde EE certificate in TLSA
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
int eeCertMatch3(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list) 
{
     if (debug) printf(DEBUG_PREFIX_DANE "eeCertMatch\n");     
     int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE3;
     char *data = matchingData(tlsa_list->first->matching_type, tlsa_list->first->selector, cert_list);
     if (strcmp ((const char*)data,"x") == 0) return DANE_EXIT_TLSA_PARAM_ERR;
     if (strcmp ((const char*)data,(const char*)tlsa_list->first->assochex) == 0) {
           ret_val = DANE_EXIT_VALIDATION_SUCCESS_TYPE3; 
     }
     if (debug) printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
     if (debug) printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_list->first->assochex);

     free(data);
     return ret_val;
}

//*****************************************************************************
// TLSA validation CA certificate (type 0)
// Binary data codes CA certificate
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
int caCertMatch(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list) 
{
     if (debug) printf(DEBUG_PREFIX_DANE "caCertMatch\n");
     int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE0;
     int i = 0;
     cert_list->first = cert_list->first->next;
     while (cert_list->first != NULL) {
	   i++;
	   char *data = matchingData(tlsa_list->first->matching_type, tlsa_list->first->selector, cert_list);
	   if (strcmp ((const char*)data,"x") == 0) return DANE_EXIT_TLSA_PARAM_ERR;
     	   if (strcmp ((const char*)data,(const char*)tlsa_list->first->assochex) == 0) {
               return DANE_EXIT_VALIDATION_SUCCESS_TYPE0;
	   }
	   if (debug) printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
	   if (debug) printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_list->first->assochex);

           free(data);	  
	   cert_list->first = cert_list->first->next;
    } //while
    return ret_val;
}

//*****************************************************************************
// TLSA validation new trust anchor (type 2)
// Binary data codes CA certificate
// This certificate is use as new trust anchor
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
int chainCertMatch(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list) 
{
     if (debug) printf(DEBUG_PREFIX_DANE "chainCertMatch\n");
     int ret_val = DANE_EXIT_VALIDATION_FALSE_TYPE2;
     int i = 0;
     while (cert_list->first != NULL) {
	   char *data = matchingData(tlsa_list->first->matching_type, tlsa_list->first->selector, cert_list);
	   if (strcmp ((const char*)data,"x") == 0) return DANE_EXIT_TLSA_PARAM_ERR;
     	   if (strcmp ((const char*)data,(const char*)tlsa_list->first->assochex) == 0) {
               return DANE_EXIT_VALIDATION_SUCCESS_TYPE2;
	   }
	   if (debug) printf(DEBUG_PREFIX_DANE "CERT: %s\n", data);
	   if (debug) printf(DEBUG_PREFIX_DANE "TLSA: %s\n", tlsa_list->first->assochex);

           free(data);	  
	   cert_list->first = cert_list->first->next;
	   i++;
    } //while
    return ret_val;
}

//*****************************************************************************
// Main TLSA validation function
// Validates and compares TLSA records with certificate or SPKI
// return 1 if validation is success or 0 if not or x<0 when error
// ----------------------------------------------------------------------------
int TLSAValidate(struct tlsa_store_head *tlsa_list, struct cert_store_head *cert_list){
   int idx = DANE_EXIT_VALIDATION_FALSE;
   while (tlsa_list->first != NULL) {	
      idx = DANE_EXIT_VALIDATION_FALSE;
      switch (tlsa_list->first->dnssec_status) {
        case 0:
            return DANE_EXIT_DNSSEC_UNSECURED;
        case 2:
            return DANE_EXIT_DNSSEC_BOGUS;
        case 1:
	     if (debug) printf(DEBUG_PREFIX_DANE "TLSAValidate->cert_usage: %i \n",tlsa_list->first->cert_usage);
	     switch (tlsa_list->first->cert_usage) {
	        case CA_CERT_PIN: //2			
  			idx = caCertMatch(tlsa_list, cert_list);
			break;            	
        	case CA_TA_ADDED: //0
			idx = chainCertMatch(tlsa_list, cert_list);
			break; 
	        case EE_CERT_PIN: //1
			idx = eeCertMatch1(tlsa_list, cert_list);
	  	        break; // continue checking
		case EE_TA_ADDED: //3	    
			idx = eeCertMatch3(tlsa_list, cert_list);
	  	        break; // continue checking
                default:
			if (debug) printf(DEBUG_PREFIX_DANE "Wrong value of cert_usage parameter: %i \n",tlsa_list->first->cert_usage);
			return DANE_EXIT_TLSA_PARAM_ERR;
                    	break; // unknown cert usage, skip
  	     } // switch
            break; // continue checking
       } // switch
   tlsa_list->first = tlsa_list->first->next;
   if (idx > DANE_EXIT_VALIDATION_FALSE) return idx;
   } // while

  return idx;
}

//*****************************************************************************
// Get TLSA records from DNS response for particulary domain name
// Store the TLSA record into TLSA structure and add structure in the list
// return 1 if success or 0 when TLSA record is wrong or missing
// ----------------------------------------------------------------------------
int get_tlsa_record(struct tlsa_store_head *tlsa_list, struct ub_result *result, char* domain)
{	
   int i;
   int exitcode = DANE_EXIT_RESOLVER_FAILED;
   uint8_t sec_status = 0;


   /* show security status */
   if(result->secure) {
     sec_status = 1;
	/* show tlsa_first result */
	if(result->havedata) {

		if (debug) printf(DEBUG_PREFIX " Domain is secure...check tlsa record...\n");

                ldns_pkt *packet;
                ldns_status parse_status = ldns_wire2pkt(&packet, (uint8_t*)(result->answer_packet), result->answer_len);
                
                if (parse_status != LDNS_STATUS_OK) {
                       if (debug) printf(DEBUG_PREFIX "Failed to parse response packet\n");
			ub_resolve_free(result);
                        return DANE_EXIT_RESOLVER_FAILED;
                }
                
                ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(packet, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);		
                for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
                        /* extract first rdf, which is the whole TLSA record */
                        ldns_rr *rr = ldns_rr_list_rr(rrs, i);
                        
                        // Since ldns 1.6.14, RR for TLSA is parsed into 4 RDFs 
                        // instead of 1 RDF in ldns 1.6.13.
                        if (ldns_rr_rd_count(rr) < 4) {
                               if (debug) printf(DEBUG_PREFIX "RR %d hasn't enough fields\n", i);
				ub_resolve_free(result);
                                return DANE_EXIT_RESOLVER_FAILED;
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
				ub_resolve_free(result);
                                return DANE_EXIT_RESOLVER_FAILED;
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
                exitcode = 1;                
                if (packet) ldns_pkt_free(packet);
                if (rrs) ldns_rr_list_free(rrs);
        } else {
                if (debug) printf(DEBUG_PREFIX "Unbound haven't received any data for %s. ", domain);
		exitcode = DANE_EXIT_NO_TLSA_RECORD;
        }
    } else if(result->bogus) {
	sec_status = 2;
	exitcode = DANE_EXIT_DNSSEC_BOGUS;
	if (debug) printf(DEBUG_PREFIX "Domain is bogus: %s \n", result->why_bogus);
    } else {
    	sec_status = 0;
	exitcode = DANE_EXIT_DNSSEC_UNSECURED;
	if (debug) printf(DEBUG_PREFIX " Domain is insecure...\n");
    }

   //print_tlsalist(tlsa_first);
   ub_resolve_free(result);
   return exitcode;
}


//*****************************************************************************
// free unbound context (erase cache data from ub context), ctx = NULL
// external API
// ----------------------------------------------------------------------------
void ub_context_free(struct ub_ctx* ctx){
    if (context==true) { 
      ub_ctx_delete(ctx);
      context = false;
    }
} //ub_context_free


//*****************************************************************************
// Unbound resolver initialization, set of forwarder
// returnunbound context structure ctx (init)
// ----------------------------------------------------------------------------
struct ub_ctx* ResolverInit(struct ub_ctx* ctx, bool usefwd, char *optdnssrv)
{
   int ub_retval;
   ctx = ub_ctx_create();
   char *fwd_addr;
   char delims[] = " ";
   if (debug) printf(DEBUG_PREFIX "resolver: %s\n", optdnssrv);

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
// Function char* get_tlsa_query
// return _port._protocol.domain e.g: _443._tcp.www.nic.cz
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
short CheckDane(char* certchain[], int certcount, const uint16_t options, char *optdnssrv, char* domain,  char* port, char* protocol, int policy) {

   struct ub_result* result;
   struct tlsa_store_head tlsa_list;
   struct cert_store_head cert_list;        	
   int tlsa_res = -1;
   tlsa_list.first = NULL;
   cert_list.first = NULL;
   int tlsa_ret, retval;
   char uri[256];
   int ub_retval;
   char *fwd_addr;
   char delims[] = " ";
   bool usefwd = false;
   ub_retval = 0;
   short exitcode = DANE_EXIT_RESOLVER_FAILED;

   ds_init_opts(options);
   debug = opts.debug;
   usefwd = opts.usefwd;

  //-----------------------------------------------
  // Unbound resolver initialization, set forwarder 
  if (!context) {
    ctx = ub_ctx_create();
	  if(!ctx) {
		    if (debug) printf(DEBUG_PREFIX "Error: could not create unbound context\n");
		    if (ws) fprintf(dfout, DEBUG_PREFIX "Error: could not create unbound context\n");
		    return exitcode;
	  }
    context = true;
    // set resolver/forawarder if it was set in options
    if (usefwd) {
       if (strcmp (optdnssrv,"") != 0) {
	    fwd_addr = strtok(optdnssrv, delims);
	    // set ip addresses of resolvers into ub context
            while (fwd_addr != NULL) {
		      if ((ub_retval=ub_ctx_set_fwd(ctx, optdnssrv)) != 0) {
		        if (debug) printf(DEBUG_PREFIX "Error adding resolver IP address: %s\n", 
									ub_strerror(ub_retval));
  		        if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding resolver IP address: %s\n", 
									ub_strerror(ub_retval));
			return exitcode;
		      } //if            	  
	     fwd_addr = strtok(NULL, delims);
	     } //while
  	}  
    	else {
       	    if ((ub_retval = ub_ctx_resolvconf(ctx, NULL)) != 0) {
                 if (debug) printf(DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n", 
							ub_strerror(ub_retval), strerror(errno));
	         if (ws) fprintf(dfout, DEBUG_PREFIX "Error reading resolv.conf: %s. errno says: %s\n",
				 ub_strerror(ub_retval), strerror(errno));
		return exitcode;
            }   
        }
      } // if(usefwd)
      /* read public keys of root zone for DNSSEC verification */
      // ds true = zone key will be set from file root.key
      //    false = zone key will be set from TA constant
      if (ds) {
	      if ((ub_retval=ub_ctx_add_ta_file(ctx, "root.key")) != 0) {
      		    if (debug)	printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
      		    if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
		    return exitcode;
              }
      }
      else {
		if ((ub_retval=ub_ctx_add_ta(ctx, TA)) != 0) {
		        if (debug) printf(DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
		        if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding keys: %s\n", ub_strerror(ub_retval));
			return exitcode;
		}
	}// if (ds)   
	// set dlv-anchor
	if ((ub_retval=ub_ctx_set_option(ctx, "dlv-anchor:", DLV))) {
    		if (debug) printf(DEBUG_PREFIX "Error adding DLV keys: %s\n", ub_strerror(ub_retval));
	        if (ws) fprintf(dfout, DEBUG_PREFIX "Error adding DLV keys: %s\n", ub_strerror(ub_retval));
		return exitcode;      
        } 
    } // end of init resolver
    //------------------------------------------------------------

    // create TLSA query 
    retval = ub_resolve(ctx, get_tlsa_query(domain,port,protocol), LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN , &result);
    if(retval != 0) {
		if (debug) printf(DEBUG_PREFIX "resolve error: %s\n", ub_strerror(retval));
		return exitcode;
     }

     // get TLSA records from response
     tlsa_ret = get_tlsa_record(&tlsa_list, result, domain);
     if (tlsa_ret==DANE_EXIT_DNSSEC_UNSECURED) return DANE_EXIT_DNSSEC_UNSECURED;
     else if (tlsa_ret==DANE_EXIT_DNSSEC_BOGUS) return DANE_EXIT_DNSSEC_BOGUS;
     else if (tlsa_ret==DANE_EXIT_NO_TLSA_RECORD) return DANE_EXIT_NO_TLSA_RECORD;
     else if (tlsa_ret==DANE_EXIT_RESOLVER_FAILED) return DANE_EXIT_RESOLVER_FAILED;

     if (debug) print_tlsalist(&tlsa_list);

     int i;
     if (certcount > 0) {
	    if (debug) printf(DEBUG_PREFIX_CER "External certchain is used\n");

	    for ( i = 0; i < certcount; i++) {	    
	    int certlen=strlen(certchain[i])/2;
    	    cert_tmp_ctx skpi= spkicert((const unsigned char*)hextobin(certchain[i]),certlen);
	    add_certrecord_bottom(&cert_list, hextobin(certchain[i]), certlen, certchain[i], skpi.spki_der, skpi.spki_len, skpi.spki_der_hex); 
	     }//for
      }
     else {
        if (debug) printf(DEBUG_PREFIX_CER "Get certchain now\n");	
       strcpy (uri,"https://");
       strncat (uri, domain, strlen(domain));
       tlsa_ret = getcert(uri, &cert_list);
       if (tlsa_ret==0) return DANE_EXIT_NO_CERT_CHAIN;
     }

     if (debug) print_certlist(&cert_list);

     tlsa_res = TLSAValidate(&tlsa_list,&cert_list);

     if (debug) printf(DEBUG_PREFIX_DANE "result: %i\n", tlsa_res);

     free_tlsalist(&tlsa_list);
     free_certlist(&cert_list);	
  
     return tlsa_res;
}

//*****************************************************************************
// Main function for testing of lib, input: domain name
// ----------------------------------------------------------------------------
int main(int argc, char **argv) {

 int res = DANE_EXIT_RESOLVER_FAILED;
 char* certhex[] = {"000000FF00"}; 
 res = CheckDane(certhex, 0, 5, "8.8.8.8", argv[1], "443", "tcp", 1);
 if (debug) printf(DEBUG_PREFIX_DANE "Final result: %i\n", res);
 return 1;
}
