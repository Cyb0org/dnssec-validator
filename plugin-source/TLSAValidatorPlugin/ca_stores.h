/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.
File: DANE/TLSA library
Authors: Martin Straka <martin.straka@nic.cz>
         Karel Slany <karel.slany@nic.cz>

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


#ifndef _CA_STORES_H_
#define _CA_STORES_H_


#include "config_related.h"


#include <openssl/x509.h>


#ifdef __cplusplus
extern "C" {
#endif


/* CA certificate files. */
extern const char *ca_files[];

/* CA certificate directories. */
extern const char *ca_dirs[];


/*!
 * @brief Try to load CA certificates from supplied files and/or directories.
 *
 * @param[in,out] ssl_ctx SSL context.
 * @param[in]     fname_p NULL-terminated list of file names.
 * @param[in]     dirname_p NULL-terminated list of directories.
 * @return 0 on success, -1 else.
 */
int X509_store_add_certs_from_files_and_dirs(SSL_CTX *ssl_ctx,
    const char **fname_p, const char **dirname_p);


/*!
 * @brief Access directories containing CA certificates and store them.
 *
 * @param[in,out] store     X509 certificate store.
 * @param[in]     dirname_p NULL-terminated list of directory names.
 * @return 0 on success, -1 else.
 *
 * @note The function iterates over all files in the directories ans tries to
 * store the certificates.
 */
int X509_store_add_certs_from_dirs(X509_STORE *store, const char **dirname_p);


/*!
 * @brief Load all available certificates from NSS built-in certificates.
 *
 * @param[in,out] store     X509 certificate store.
 * @return 0 on success, -1 else.
 */
int X509_store_add_certs_from_nssckbi(X509_STORE *store);


/* Directories containing cert8.db. */
extern const char * cert8_ca_dirs[];


/*!
 * @brief Access user managed cert8.db files in specified directories.
 *
 * @param[in,out] store     X509 certificate store.
 * @param[in]     dirname_p NULL-terminated list of directory names.
 * @return 0 on success, -1 else.
 */
int X509_store_add_certs_from_cert8_dirs(X509_STORE *store,
    const char **dirname_p);


/*!
 * @brief Access Max OS X CA store and store the certificates.
 *
 * @param[in,out] store X509 certificate store.
 * @return 0 on success, -1 else.
 */
int X509_store_add_certs_from_osx_store(X509_STORE *store);


/*!
 * @brief Access Windows CA store and store the certificates.
 *
 * @param[in,out] store X509 certificate store.
 * @return 0 on success, -1 else.
 */
int X509_store_add_certs_from_win_store(X509_STORE *store);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* !_CA_STORES_H_ */
