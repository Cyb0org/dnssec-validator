	// DNSSEC NPAPI constant returned by binary plugin	
	var dnssecExtNPAPIConst = {
		DNSSEC_EXIT_VALIDATION_OFF                 : -1, /* DNSSEC validation is OFF*/
		DNSSEC_EXIT_WRONG_RESOLVER                 : -2, /* resolver does not support DNSSEC*/	
  		DNSSEC_EXIT_FAILED                         : 0, /* state is unknown or fail*/
		DNSSEC_EXIT_DOMAIN_UNSECURED 		   	   : 1, /* domain is not secured */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_IP   : 2, /* domain name is secured by DNSSEC and the IP address of browser is valid */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_SECURED_NOIP : 3, /* domain name is secured by DNSSEC but the IP address of browser is invalid */
  		DNSSEC_EXIT_CONNECTION_DOMAIN_BOGUS        : 4, /* domain signature is not valid or chain of trust is not established */
  		DNSSEC_EXIT_NODOMAIN_UNSECURED             : 5, /* non-existent domain is not secured */
  		DNSSEC_EXIT_NODOMAIN_SIGNATURE_VALID       : 6, /* non-existent domain is secured by DNSSEC */
  		DNSSEC_EXIT_NODOMAIN_SIGNATURE_INVALID     : 7, /* non-existent domain is not valid or chain of trust is not established */
  		DNSSEC_INPUT_FLAG_DEBUGOUTPUT              : 1, /* debug output */
  		DNSSEC_INPUT_FLAG_USEFWD                   : 2, /* use forwarder instead of default unbound servers */
  		DNSSEC_INPUT_FLAG_RESOLVIPV4               : 4, /* resolve IPv4 address (A record) */
  		DNSSEC_INPUT_FLAG_RESOLVIPV6               : 8, /* resolve IPv6 address (AAAA record) */
	};


	// DANE NPAPI constant returned by binary plugin
	var tlsaExtNPAPIConst = {
  		DANE_EXIT_VALIDATION_SUCCESS_TYPE0	 : 10, /* Validation of TLSA record (type0) is success */
 		DANE_EXIT_VALIDATION_SUCCESS_TYPE1	 : 11, /* Validation of TLSA record (type1) is success */
		DANE_EXIT_VALIDATION_SUCCESS_TYPE2	 : 12, /* Validation of TLSA record (type2) is success */
		DANE_EXIT_VALIDATION_SUCCESS_TYPE3	 : 13, /* Validation of TLSA record (type3) is success */
		DANE_EXIT_WRONG_RESOLVER             : 2, /* resolver does not support DNSSEC*/	
		DANE_EXIT_DNSSEC_SECURED		 : 1,  /* DANE: dnssec is secured - no used now */
		DANE_EXIT_VALIDATION_OFF 		 : 0,  /* Validation of TLSA record is off for this domain */
		DANE_EXIT_RESOLVER_FAILED      		 : -1, /* state is unknown or fail */            
		DANE_EXIT_NO_HTTPS			 : -2, /* current url is not https */
		DANE_EXIT_NO_TLSA_RECORD		 : -3, /* TLSA record for this domain does not exists */
		DANE_EXIT_DNSSEC_UNSECURED		 : -4, /* Dnssec is insecured, TLSA will not starts */
		DANE_EXIT_DNSSEC_BOGUS			 : -5, /* Dnssec signature is bogus, TLSA validation is stop */
		DANE_EXIT_NO_CERT_CHAIN			 : -6, /* No certificate chain for this server */
		DANE_EXIT_CERT_ERROR			 : -7,  /* Certificate error */
		DANE_EXIT_TLSA_PARAM_ERR		 : -8,  /* Wrong parameters of TLSA record */
		DANE_EXIT_VALIDATION_FALSE		 : -9,  /* Validation of TLSA record is false */
		DANE_EXIT_VALIDATION_FALSE_TYPE0	 : -10, /* Validation of TLSA record (type0) is false */
		DANE_EXIT_VALIDATION_FALSE_TYPE1	 : -11, /* Validation of TLSA record (type1) is false */
		DANE_EXIT_VALIDATION_FALSE_TYPE2	 : -12, /* Validation of TLSA record (type2) is false */
		DANE_EXIT_VALIDATION_FALSE_TYPE3	 : -13, /* Validation of TLSA record (type3) is false */
  		DANE_INPUT_FLAG_DEBUGOUTPUT              : 1, /* debug output */
  		DANE_INPUT_FLAG_USEFWD                   : 2, /* use forwarder instead of default unbound servers */
  		DANE_INPUT_FLAG_RESOLVIPV4               : 4, /* resolve IPv4 address (A record) */
  		DANE_INPUT_FLAG_RESOLVIPV6               : 8, /* resolve IPv6 address (AAAA record) */
	};
