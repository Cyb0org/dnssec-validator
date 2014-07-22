#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([dnssec-validator], [2.1.1b], [dnssec-validator2labs.nic.cz])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz -Wall -Werror])
AC_CONFIG_SRCDIR([plugin-source/common/common.c])
AC_CONFIG_HEADERS([plugin-source/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_AWK
AC_PROG_CXX
AC_PROG_CC
AC_PROG_OBJC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_PROG_AR

# Checks for libraries.
AC_PROG_LIBTOOL
LT_INIT

# Pick correct CA store
AC_ARG_WITH(ca_store,
[  --with-ca_store=[auto|directory|nss|osx]	which CA store to use])

AS_CASE([$with_ca_store],
	[auto],		[CA_STORE=1],
	[none],		[CA_STORE=0],
	[directory],	[CA_STORE=1],
	[nss],		[CA_STORE=2],
	[nss_cert8],	[CA_STORE=3],
	[osx],		[CA_STORE=4],
	[*],		[CA_STORE=1])

AC_DEFINE([CA_STORE], [$CA_STORE], [Select which CA store to use])
AM_CONDITIONAL([CA_STORE_DIR], [test $CA_STORE = 1])
AM_CONDITIONAL([CA_STORE_NSS], [test $CA_STORE = 2])
AM_CONDITIONAL([CA_STORE_OSX], [test $CA_STORE = 4])

# FIXME
AM_CONDITIONAL([LOG_DFLT], [true])
AM_CONDITIONAL([LOG_OSX], [false])

# OpenSSL
AC_ARG_WITH(openssl,
[  --with-openssl=DIR        where to find openssl library])

AS_IF([test "$with_openssl" != "no"],[
  PKG_CHECK_MODULES([libcrypto], libcrypto, [
    CPPFLAGS="$CPPFLAGS $libcrypto_CFLAGS"
    LIBS="$LIBS $libcrypto_LIBS"
    with_openssl=yes
  ],[

    for try_openssl in "$with_openssl" "" "/usr/local"; do
      save_LIBS="$LIBS"
      save_CPPFLAGS="$CPPFLAGS"

      AS_IF([test -d "$try_openssl"], [
        libcrypto_CFLAGS="-I$try_openssl/include"
        libcrypto_LIBS="-L$try_openssl/lib"
      ],[
        libcrypto_CFLAGS=""
        libcrypto_LIBS=""
      ])

      CPPFLAGS="$CPPFLAGS $libcrypto_CFLAGS"
      LIBS="$LIBS $libcrypto_LIBS"

      AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto], [
        with_openssl=yes
	break
      ],[
        with_openssl=no
	# do not cache result of AC_SEARCH_LIBS test
	unset ac_cv_search_OpenSSL_add_all_digests
      ])

      CPPFLAGS="$save_CPPFLAGS"
      LIBS="$save_LIBS"
    done

  ])
])

AS_IF([test "$with_openssl" = "no"],[
  AC_MSG_ERROR([OpenSSL library is required.])
])

AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([ldns_dname_new_frm_str], [ldns], [], [AC_MSG_ERROR([ldns not found])])
AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([pthreads not found])])

AC_SEARCH_LIBS([ub_ctx_create], [unbound], [], [AC_MSG_ERROR([libunbound not found])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname inet_ntoa memset socket strchr strerror strspn strstr])

# Set Mozilla OS_TARGET
# https://developer.mozilla.org/en-US/docs/OS_TARGET
AS_CASE([$host_os],
	[linux*], [OS_TARGET=Linux],
	[freebsd*], [OS_TARGET=FreeBSD],
	[dragonfly*], [OS_TARGET=DragonFly],
	[mingw*], [OS_TARGET=WINNT])
AC_SUBST(OS_TARGET)

# Set Mozilla XPCOM_ABI
# https://developer.mozilla.org/en-US/docs/XPCOM_ABI
AC_SUBST(XPCOM_ABI, [$host_cpu])

AC_CONFIG_FILES([
	Makefile
	Version
	install.rdf])
AC_OUTPUT
