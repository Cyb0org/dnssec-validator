#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([dnssec-validator], [2.1.1b], [dnssec-validator-users@lists.nic.cz])
AC_CONFIG_SRCDIR([plugin-source/common/common.h])
AC_CONFIG_HEADERS([plugin-source/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.10 foreign dist-xz -Wall -Werror])

AC_CANONICAL_HOST

# Config header file prefix
AH_TOP([#ifndef _CONFIG_H_])
AH_TOP([#define _CONFIG_H_])
# Config header file suffix
AH_BOTTOM([#endif /* !_CONFIG_H_ */])

# Flags passed by the user
PASSED_CPPFLAGS="$CPPFLAGS"
PASSED_CFLAGS="$CFLAGS"
PASSED_CXXFLAGS="$CXXFLAGS"
PASSED_LDFLAGS="$LDFLAGS"
#PASSED_LIBS="$LIBS"
# Default flags
CORE_CPPFLAGS="$PASSED_CPPFLAGS"
CORE_CFLAGS="$PASSED_CFLAGS -Wall -Wextra -pedantic -std=c99 -Wno-variadic-macros"
CORE_CXXFLAGS="$PASSED_CXXFLAGS -Wall -Wextra -pedantic -std=c++98 -Wno-variadic-macros -fno-exceptions -fno-rtti -fno-common"
CORE_LDFLAGS="$PASSED_LDFLAGS $ADDED_LDFLAGS"
CORE_LIBS=""

# Debugging
AC_MSG_CHECKING([whether to enable debugging])
AC_ARG_ENABLE([debug],
  AS_HELP_STRING([--enable-debug], [Enable debugging.]))
AS_IF([test "x$enable_debug" = "xyes"], [
  AC_MSG_RESULT([yes])
  dnl C preprocessor
  AC_DEFINE(DEBUG, 1, [Define to 1 if debugging functionality desired.])
  CORE_CFLAGS+=" -g -O0 -fno-omit-frame-pointer -fstack-protector -Wuninitialized"
  CORE_CXXFLAGS+=" -g -O0 -fno-omit-frame-pointer -Wuninitialized"
], [
  AC_MSG_RESULT([no])
  dnl C preprocessor
  AC_DEFINE(NDEBUG, 1, [Define to 1 if no debugging functionality desired.])
  CORE_CFLAGS+=" -O3"
  CORE_CXXFLAGS+=" -O3"
])
AC_SUBST(CORE_CPPFLAGS)
AC_SUBST(CORE_CFLAGS)
AC_SUBST(CORE_CXXFLAGS)
AC_SUBST(CORE_LDFLAGS)
AC_SUBST(CORE_LIBS)

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET # Set make command.
AC_PROG_MKDIR_P # mkdir -p
AC_PROG_OBJC

# Checks for libraries.
AC_PROG_LIBTOOL
LT_INIT


###############################################################################
# Core dependencies
###############################################################################

# TODO -- ssl
AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto], [], [AC_MSG_ERROR([libcrypto not found])])
AC_SEARCH_LIBS([ldns_dname_new_frm_str], [ldns], [], [AC_MSG_ERROR([libldns not found])])
AC_SEARCH_LIBS([ub_ctx_create], [unbound], [], [AC_MSG_ERROR([libunbound not found])])

#AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([pthreads not found])])


###############################################################################
# Optonal core dependencies
###############################################################################

# TODO
AM_CONDITIONAL([LOG_DFLT], [true])
AM_CONDITIONAL([LOG_OSX], [false])


# No parameters shall be passed via default variables.
#CPPFLAGS=""
#CFLAGS=""; CXXFLAGS="";
#LDFLAGS=""; LIBS=""


# Checks for header files.
AC_CHECK_HEADERS([ \
  arpa/inet.h \
  limits.h \
  netdb.h \
  netinet/in.h \
  stdint.h \
  stdlib.h \
  string.h \
  sys/socket.h \
  unistd.h \
])

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
AC_CHECK_FUNCS([ \
  gethostbyname \
  inet_ntoa \
  memset \
  socket \
  strchr \
  strerror \
  strspn \
  strstr \
])

# Default preprocessor flags.
#AC_SUBST([AM_CPPFLAGS], [""])

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

AC_CONFIG_FILES([ \
  Makefile \
  core_js-ctypes/Makefile \
])

AC_OUTPUT
