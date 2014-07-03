

#include <stdio.h>
#include <stdlib.h>

#include "dane-plug.h"


/* ========================================================================= */
/* ========================================================================= */
/*
 * Main funcion. Intended for testing purposes.
 */
int main(void)
/* ========================================================================= */
/* ========================================================================= */
{
	if (dane_validation_init() != 0) {
		fprintf(stderr, "Error initialising context.\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
