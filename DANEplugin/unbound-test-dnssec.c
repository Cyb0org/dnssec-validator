#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "unbound.h"
#include "ldns/ldns.h"
#include "ldns/packet.h"
#include "ldns/wire2host.h"
#include "openssl/x509.h"
#include "openssl/evp.h"

char *prefix = "_443._tcp.";

static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static int byteMapLen = sizeof(byteMap);

typedef struct TLSArecordsrtuct {   /* structure to save TLSA record */
   char* domain;
   uint8_t dnssec_status;
   uint8_t cert_usage;
   uint8_t selector;
   uint8_t matching_type;
   uint8_t *association;
   size_t association_size;
   char* assochex; 
   struct TLSArecordsrtuct *next;
} TLSArecordList;
TLSArecordList *first = NULL;

char *opensslDigest(const EVP_MD *md, const char *data) {
    EVP_MD_CTX mdctx;
    unsigned int md_len;
    unsigned char md_value[64]; // enough bytes for SHA2 family up to SHA-512
    char* digest = "";
    
    assert(md);
    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, md, NULL);
    EVP_DigestUpdate(&mdctx, data, strlen(data));
    EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
    EVP_MD_CTX_cleanup(&mdctx);


   // char *asshex; 
   // asshex = bintohex((uint8_t)md_value,(size_t )md_len);

    digest = malloc(strlen((char*)md_value) + 1);
    strcpy(digest,(char*)md_value);
    return digest;
}

char *sha256(const char *data) {
    return opensslDigest(EVP_sha256(), data);
}

char *sha512(const char *data) {
    return opensslDigest(EVP_sha512(), data);
}


char *selectorData(uint8_t selector) {
    switch (selector) {
        case 0:
            return "aaaaaaaaaaaaaaaaaaaaaaaaaaa";
        case 1:
            return "sdagdgfgdfgdf";
        default:
            return "Error";
    };
}


char *matchingData(uint8_t matching_type, uint8_t selector) {

    char* data = selectorData(selector);
    
    switch (matching_type) {
        case 0:
            return data;
        case 1:
            return sha256(data);
        case 2:
            return sha512(data);
        default:
            return data;
    }
}

char* get_dnssec_status(uint8_t dnssec_status){
  switch (dnssec_status) {
    case 0: return "INSECURE";
    case 1: return "SECURE";
    case 2: return "BOGUS";
    default: return "ERROR";
  }

}

void add_tlsarecord(TLSArecordList **first, char *domain, uint8_t dnssec_status, uint8_t cert_usage, uint8_t selector, uint8_t matching_type, uint8_t *association, size_t association_size, char* assochex) 
{
	 TLSArecordList *field_tlsa;
         field_tlsa = *first;
	 field_tlsa = malloc(sizeof(TLSArecordList));
 	 field_tlsa->domain = malloc(strlen(domain) + 1);
 	 strcpy(field_tlsa->domain, domain);
	 field_tlsa->dnssec_status = dnssec_status;
	 field_tlsa->cert_usage = cert_usage;
	 field_tlsa->selector = selector;
	 field_tlsa->matching_type = matching_type;
	 field_tlsa->association = association;
	 field_tlsa->association_size = association_size;
 	 field_tlsa->assochex = malloc(strlen(assochex) + 1);
 	 strcpy(field_tlsa->assochex, assochex);
	 field_tlsa->next = *first;
	 *first = field_tlsa;
}

void print_tlsalist(TLSArecordList *first) {
   while (first != NULL) {
       printf("---------------------------------------------\n");
       printf("%s: dnssec: %s (%d), cert usage: %d, selector: %d, matching type: %d, assoc.data: %s\n",
             first->domain, get_dnssec_status(first->dnssec_status), first->dnssec_status, first->cert_usage, first->selector, first->matching_type, first->assochex);
      first = first->next;
   } // while
   printf("---------------------------------------------\n");
} 

 void free_tlsalist(TLSArecordList *first) {     
  if (first != NULL) {
     TLSArecordList *field, *pom;
     field = first->next;
     while (field != NULL) {
         pom = field->next;
	 free(field->domain);
	 free(field->assochex);
         free(field);
         field = pom;
     } // while
     first->next = NULL;
  } // if
}

/* Utility function to convert nibbles (4 bit values) into a hex character representation */
static char nibbleToChar(uint8_t nibble)
{
	if (nibble < byteMapLen) return byteMap[nibble];
	return '*';
}


/* Convert a buffer of binary values into a hex string representation */
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

char *mystrcat(char *str1, char *str2) {

	char *str;
	if (!str1) str1 = "";
	if (!str2) str2 = "";
	str = malloc(strlen(str1) + strlen(str2) + 1);
	if (str) sprintf(str, "%s%s", str1, str2);
	return str;
}

int eeCertMatch(TLSArecordList field_tlsa) 
{     
     int ret_val = -1;
     char *data = matchingData(field_tlsa.matching_type, field_tlsa.selector);
     if (data == field_tlsa.assochex) {
           ret_val = 0; //index 0 - the EE cert - matched
     }
     printf("MATCH: %s = %s\n", data, field_tlsa.association);
     free(data);
    return ret_val;
}


int TLSAValidate(TLSArecordList *first){

   int ret_val = -1;
   int idx = -1;
   while (first != NULL) {
      switch (first->dnssec_status) {
        case 0:
            return ret_val;
        case 2:
            return ret_val;
        case 1:
	     switch (first->cert_usage) {
	        case 0:
  			idx = eeCertMatch(*first);
			break;            	
        	case 1:
			idx = eeCertMatch(*first);
			 break; 
	        case 2:
		case 3:
	    
			 idx = eeCertMatch(*first);
	  	         break; // continue checking
  	     } // switch
            break; // continue checking
       } // switch
   first = first->next;
   } // while
  printf("TLSA result: %i\n", idx);
  return ret_val;
}




/*
int caCertMatch(TLSArecordList field_tlsa) 
{
    for (int i = 1; i < m_certChain.size(); i++) {
        try {
            if (m_certChain[i].matchingData(tlsa.matchingType, tlsa.selector) == tlsa.association) {
                return i;
            }
        }
        catch (const CertificateException& ) {
            continue; // cert parsing failed
        }
    }
    
    return -1;
}

int chainCertMatch(TLSArecordList field_tlsa) 
{
    for (int i = 0; i < m_certChain.size(); i++) {
        try {
            if (m_certChain[i].matchingData(tlsa.matchingType, tlsa.selector) == tlsa.association) {
                return i;
            }
        }
        catch (const CertificateException& ) {
            continue; // cert parsing failed
        }
    }
    
    return -1;
}
*/








int TLSAresolve(char* domain)
{
	struct ub_ctx* ctx;
	struct ub_result* result;
	int retval, i;
        int exitcode = 0;
	uint8_t sec_status = 0;
	/* create context */
	ctx = ub_ctx_create();
	if(!ctx) {
		printf("error: could not create unbound context\n");
		return 1;
	}

/*
	if((retval=ub_ctx_set_option(ctx, (char*)"do-udp:", (char*)"no")) != 0) {
		printf("Set port: %s\n", ub_strerror(retval));
		return 1;
	}

	if((retval=ub_ctx_set_option(ctx, (char*)"do-tcp:", (char*)"yes")) != 0) {
		printf("Set port: %s\n", ub_strerror(retval));
		return 1;
	}

*/

	/* read public keys for DNSSEC verification */
	if( (retval=ub_ctx_add_ta(ctx, ".   IN DS   19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5")) != 0) {
		printf("error adding keys: %s\n", ub_strerror(retval));
		return 1;
	}

        if( (retval=ub_ctx_set_option(ctx, "dlv-anchor:", "dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+ cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh"))) {
		printf("error adding DLV keys: %s\n", ub_strerror(retval));
		return 1;
	}
	
	/* query for TLSA */

	
	char *query = mystrcat(prefix, domain);

	retval = ub_resolve(ctx, query, LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN , &result);
	if(retval != 0) {
		printf("resolve error: %s\n", ub_strerror(retval));
		return 1;
	}
	
	free(query);


	/* show first result */
	if(result->havedata) {


		/* show security status */
		if(result->secure) {
			sec_status = 1;
	
                ldns_pkt *packet;
                ldns_status parse_status = ldns_wire2pkt(&packet, (uint8_t*)(result->answer_packet), result->answer_len);
                
                if (parse_status != LDNS_STATUS_OK) {
                        printf("Failed to parse response packet\n");
                        return 1;
                }
                
                ldns_rr_list *rrs = ldns_pkt_rr_list_by_type(packet, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);		
                for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
                        /* extract first rdf, which is the whole TLSA record */
                        ldns_rr *rr = ldns_rr_list_rr(rrs, i);
                        
                        // Since ldns 1.6.14, RR for TLSA is parsed into 4 RDFs 
                        // instead of 1 RDF in ldns 1.6.13.
                        if (ldns_rr_rd_count(rr) < 4) {
                                printf("RR %d hasn't enough fields\n", i);
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
                                printf("Improperly formatted TLSA RR %d\n", i);
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

			add_tlsarecord(&first, domain, sec_status, cert_usage, selector, matching_type, association, association_size, asshex);
			free(asshex);
                        ldns_rr_free(rr);
                }
                
                ldns_pkt_free(packet);
                ldns_rr_list_free(rrs);
        } else {
                printf("%s: we haven't received any data. ", domain);
                //return 1;
        }
	} else if(result->bogus) {
			sec_status = 2;
			exitcode = -1000;
		} else 	{
    			sec_status = 0;
			exitcode = 1000;
	        }

	ub_resolve_free(result);
	ub_ctx_delete(ctx);
	return exitcode;
}



int main(int argc, char **argv)
{
	int i, x;
	argc--;
	printf("Domain number: %i \n",argc);	
	for (i=1; i<=argc; i++) {	
	x=TLSAresolve(argv[i]);	
	} // for
	printf("result: %i \n",x);
	
	print_tlsalist(first);
	TLSAValidate(first);
	free_tlsalist(first);
	return 1;
}
