	var dnssecExtNPAPIConst = {
  		DNSSEC_EXIT_FAILED                         : 0, /* state is unknown or fail*/
		DNSSEC_EXIT_DOMAIN_UNSECURED 		   : 1, /* domain is not secured */
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


	var tlsaExtNPAPIConst = {
		DANE_EXIT_VALIDATION_OFF		 : -99,
 		DANE_EXIT_NO_TLSA_RECORD		 : -1,
		DANE_EXIT_RESOLVER_FAILED                : -2, 
		DANE_EXIT_DNSSEC_BOGUS			 : -3,
		DANE_EXIT_DNSSEC_UNSECURED		 : -4,
		DANE_EXIT_NO_HTTPS			 : -5,
		DANE_EXIT_TLSA_PARAM_ERR		 : -6,
		DANE_EXIT_NO_CERT_CHAIN			 : -7,

		DANE_EXIT_VALIDATION_FALSE		 : 0,
		DANE_EXIT_VALIDATION_FALSE_TYPE0	 : -10,
		DANE_EXIT_VALIDATION_FALSE_TYPE1	 : -11,
		DANE_EXIT_VALIDATION_FALSE_TYPE2	 : -12,
		DANE_EXIT_VALIDATION_FALSE_TYPE3	 : -13,

		DANE_EXIT_VALIDATION_SUCCESS_TYPE0	 : 10,
		DANE_EXIT_VALIDATION_SUCCESS_TYPE1	 : 11,
		DANE_EXIT_VALIDATION_SUCCESS_TYPE2	 : 12,
		DANE_EXIT_VALIDATION_SUCCESS_TYPE3	 : 13,
	};
