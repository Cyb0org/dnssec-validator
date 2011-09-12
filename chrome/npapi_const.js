var dnssecExtNPAPIConst = {
  NPAPI_EXIT_FAILED                          : -1, /* domain name resolution failed */
  NPAPI_EXIT_UNKNOWN                         :  0, /* state is unknown */
  NPAPI_EXIT_CONNECTION_INVSIGDOMAIN_SECURED :  1, /* connection is secured, but domain has invalid signature */
  NPAPI_EXIT_NODOMAIN_SIGNATURE_INVALID      :  2, /* domain name does not exist and NSEC/NSEC3 is not valid */
  NPAPI_EXIT_DOMAIN_SIGNATURE_INVALID        :  3, /* domain signature is not valid */
  NPAPI_EXIT_NODOMAIN_UNSECURED              :  4, /* non-existent domain is not secured */
  NPAPI_EXIT_DOMAIN_UNSECURED                :  5, /* domain is not secured */
  NPAPI_EXIT_NODOMAIN_SIGNATURE_VALID        :  6, /* non-existent domain NSEC/NSEC3 is valid, but COT is not established */
  NPAPI_EXIT_AUTH_NODOMAIN_SIGNATURE_VALID   :  7, /* non-existent authoritative domain NSEC/NSEC3 is valid, but COT is not established */
  NPAPI_EXIT_DOMAIN_SIGNATURE_VALID          :  8, /* domain signature is valid, but COT is not established */
  NPAPI_EXIT_AUTH_DOMAIN_SIGNATURE_VALID     :  9, /* authoritative domain signature is valid, but COT is not established */
  NPAPI_EXIT_CONNECTION_NODOMAIN_SECURED     : 10, /* connection is secured, but domain name does not exist */
  NPAPI_EXIT_CONNECTION_DOMAIN_SECURED       : 11, /* both domain and connection are secured */
  NPAPI_INPUT_FLAG_DEBUGOUTPUT               :  1, /* debug output */
  NPAPI_INPUT_FLAG_USETCP                    :  2, /* use TCP instead of default UDP */
  NPAPI_INPUT_FLAG_RESOLVIPV4                :  4, /* resolve IPv4 address (A record) */
  NPAPI_INPUT_FLAG_RESOLVIPV6                :  8, /* resolve IPv6 address (AAAA record) */
};
