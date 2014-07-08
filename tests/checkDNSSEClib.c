

#include <stdio.h>
#include <stdlib.h>

#include "dnssec-plug.h"


/* ========================================================================= */
/* ========================================================================= */
/*
 * Main funcion. Intended for testing purposes.
 */
int main(void)
/* ========================================================================= */
/* ========================================================================= */
{
	int i;
	char *tmp = NULL;
	const char *dname = "www.nic.cz";
	const char *supplied_address = "8.8.8.8";
	const char *resolver_addresses = "";
	uint16_t options;

	options = 9;

	if (dnssec_validation_init() != 0) {
		fprintf(stderr, "Error initialising context.\n");
		return EXIT_FAILURE;
	}

	i = dnssec_validate(dname, options, resolver_addresses,
	    supplied_address, &tmp);

	fprintf(stdout, "Returned value: \"%d\" %s\n", i, tmp);

	return EXIT_SUCCESS;
}
