#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([dnssec-validator], [2.2.0], [dnssec-validator-users@lists.nic.cz])
AC_CONFIG_SRCDIR([plugin-source/common/common.h])
AC_CONFIG_HEADERS([plugin-source/config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.10 foreign dist-xz -Wall])

AC_CANONICAL_HOST

sinclude(ax_pthread.m4)

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
CORE_LDFLAGS="$PASSED_LDFLAGS"
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
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET # Set make command.
AC_PROG_MKDIR_P # mkdir -p
AC_PROG_OBJC # OS X only.
AC_PROG_SED

# Checks for libraries.
AC_PROG_LIBTOOL
LT_INIT


# Set Mozilla OS_TARGET
# https://developer.mozilla.org/en-US/docs/OS_TARGET
AS_CASE([$host_os],
  [darwin*], [OS_NAME=Darwin],
  [linux*], [OS_TARGET=Linux],
  [freebsd*], [OS_TARGET=FreeBSD],
  [dragonfly*], [OS_TARGET=DragonFly],
  [mingw*], [OS_TARGET=WINNT]
)
AC_SUBST(OS_TARGET)

# Set Mozilla XPCOM_ABI
# https://developer.mozilla.org/en-US/docs/XPCOM_ABI
#AS_CASE([$host_cpu],
#)
AS_CASE([$host_cpu],
  [i[[3456]]86], [XPCOM_ABI=x86],
  [amd64|x86_64], [XPCOM_ABI=x86_64],
)
AC_SUBST(XPCOM_ABI)

# Set shared library prefixes and suffixes.
AS_CASE([$host_os],
  [darwin*], [
    SO_PREF='lib'
    SO_SUFF='.dylib'
  ],
  [mingw*], [
    SO_PREF=''
    SO_SUFF='.dll'
  ],
  [
    SO_PREF='lib'
    SO_SUFF='.so'
  ]
)
AC_SUBST(SO_PREF)
AC_SUBST(SO_SUFF)


###############################################################################
# Force bits.
###############################################################################

BITS=auto
AC_ARG_WITH([force-bits],
  [AS_HELP_STRING([--with-force-bits=[auto|32|64|fat]], [Architecture bits, 'auto' is default.])],
  [
    # Values are defined in dane-plug.c .
    AS_CASE([$withval],
      [auto], [BITS=auto],
      [32], [BITS=32],
      [64], [BITS=64],
      [fat], [BITS=fat],
      [AC_MSG_WARN(["Unknown force bits option '$withval'."])]
    )
  ])
AS_IF([test "x${BITS}" = "xauto"], [
  AS_CASE([$XPCOM_ABI],
    [x86], [BITS=32],
    [x86_64], [BITS=64],
    [AC_MSG_ERROR([Could not determine architecture.])]
  )
])


###############################################################################
# Core dependencies.
###############################################################################

# Check whether to build and statically link core library dependencies -- default off.
AC_MSG_CHECKING([Whether to build core with statically linked libraries.])
AC_ARG_ENABLE([static-linking],
  AS_HELP_STRING([--enable-static-linking], [Enable statically linked core.]))
AS_IF([test "x$enable_static_linking" = "xyes"], [
  AC_MSG_RESULT([yes]) # Static linking.

  # FIXME: get the CONFIGURE_FLAGS from the environment.

  CORE_CPPFLAGS+=' -I$(top_srcdir)/libs-built/openssl/include'
  CORE_CPPFLAGS+=' -I$(top_srcdir)/libs-built/ldns/include'
  CORE_CPPFLAGS+=' -I$(top_srcdir)/libs-built/unbound/include'

  LIB_CFLAGS=""
  OPENSSL_ARGS=""
  CONFIGURE_ARGS=""
  AS_CASE([$host_os],
    [darwin*], [
      AS_CASE([${BITS}],
        [32], [
          CONFIGURE_ARGS="--target=i686-pc-linux-gnu"
          LIB_CFLAGS="-fPIC -m32"
          OPENSSL_ARGS="darwin-i386-cc ${LIB_CFLAGS}"
        ],
        [64], [
          CONFIGURE_ARGS="--target=x86_64-pc-linux-gnu"
          LIB_CFLAGS="-fPIC -m64"
          OPENSSL_ARGS="darwin64-x86_64-cc ${LIB_CFLAGS}"
        ],
        [fat], [
          CONFIGURE_ARGS=""
          LIB_CFLAGS="${LIB_CFLAGS_MAC} -arch i386 -arch x86_64"
          OPENSSL_ARGS="darwin64-x86_64-cc ${LIB_CFLAGS}"
        ]
      )
      CORE_LIBS+=" -framework Cocoa -framework Security"
      STRIP+=" -x -S"
    ],
    [linux*], [
      AS_CASE([${BITS}],
        [32], [
          CONFIGURE_ARGS="--target=i686-pc-linux-gnu"
          LIB_CFLAGS="-fPIC -m32"
          OPENSSL_ARGS="linux-elf ${LIB_CFLAGS}"
        ],
        [64], [
          CONFIGURE_ARGS="--target=x86_64-pc-linux-gnu"
          LIB_CFLAGS="-fPIC -m64"
          OPENSSL_ARGS="linux-x86_64 ${LIB_CFLAGS}"
        ]
      )
    ],
    [freebsd*], [
    ],
    [mingw*], [
    ]
  )
  AC_SUBST(LIB_CFLAGS)
  AC_SUBST(OPENSSL_ARGS)
  AC_SUBST(CONFIGURE_ARGS)

  # libdl
  # The dlopen() function is in the C library on *BSD systems and in libdl on
  # glibc based systems.
  CPPFLAGS="$PASSED_CPPFLAGS"
  CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
  LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
  AC_SEARCH_LIBS([dlopen], [dl dld], , [
    AC_MSG_ERROR([Could not find dlopen() in expected locations. Install or/and add the comprising library into the list of tested libraries.])
  ])
  CORE_LDFLAGS+=" $LDFLAGS"
  CORE_LIBS+=" $LIBS"

  # libpthread
  CPPFLAGS="$PASSED_CPPFLAGS"
  CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
  LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
  AX_PTHREAD([
    AC_DEFINE(HAVE_PTHREAD, 1, [Define to 1 if libpthread available.])
    CFLAGS=" $PTHREAD_CFLAGS $CFLAGS"
    LDFLAGS=" $LDFLAGS $PTHREAD_CFLAGS"
    LIBS=" $PTHREAD_LIBS $LIBS"
    CC="$PTHREAD_CC"

    AC_CHECK_FUNCS([ \
      pthread_kill \
      pthread_spin_init \
    ])

    CORE_CFLAGS+=" $CFLAGS"
    CORE_LDFLAGS+=" $LDFLAGS"
    CORE_LIBS+=" $LIBS"
  ], [
    AC_MSG_ERROR([Could not find pthread library.])
  ])

  ], [
  AC_MSG_RESULT([no]) # Dynamic linking.

  CPPFLAGS="$PASSED_CPPFLAGS"
  CFLAGS="$PASSED_CFLAGS"; CXXFLAGS="$PASSED_CXXFLAGS";
  LDFLAGS="$PASSED_LDFLAGS"; LIBS=""
  AC_SEARCH_LIBS([SSL_get_peer_cert_chain], [ssl], [], [AC_MSG_ERROR([libssl not found])]) # Only DANE.
  AC_SEARCH_LIBS([OpenSSL_add_all_digests], [crypto], [], [AC_MSG_ERROR([libcrypto not found])])
  AC_SEARCH_LIBS([ldns_dname_new_frm_str], [ldns], [], [AC_MSG_ERROR([libldns not found])])
  AC_SEARCH_LIBS([ub_ctx_create], [unbound], [], [AC_MSG_ERROR([libunbound not found])])
  CORE_LDFLAGS+=" $LDFLAGS"
  CORE_LIBS+=" $LIBS"
  ]
)
dnl conditional compilation
AM_CONDITIONAL([STATIC_CORE], [test "x$enable_static_linking" = "xyes"])


# Check whether to build NPAPI core -- default off.
AC_MSG_CHECKING([Whether to build NPAPI-based extensions.])
AC_ARG_ENABLE([npapi-extensions],
  AS_HELP_STRING([--enable-npapi-extensions], [Build NPAPI extensions.]))
AS_IF([test "x$enable_npapi_extensions" = "xyes"], [
    AC_MSG_RESULT([yes]) # Enable NPAPI.
  ], [
    AC_MSG_RESULT([no]) # Disable NPAPI.
  ]
)
dnl conditional compilation
AM_CONDITIONAL([NPAPI_CORE], [test "x$enable_npapi_extensions" = "xyes"])


###############################################################################
# Optional core dependencies.
###############################################################################

# Pick correct CA store, auto is default.
CA_STORE=-1
AC_ARG_WITH([ca-store],
  [AS_HELP_STRING([--with-ca-store=[auto|directory|none|nss|nss_cert8|osx|win]], [Which CA store to use, 'auto' is default.])],
  [
    # Values are defined in dane-plug.c .
    AS_CASE([$withval],
      [auto], [CA_STORE=-1],
      [none], [CA_STORE=0],
      [directory], [CA_STORE=1],
      [nss], [CA_STORE=2],
      [nss_cert8], [CA_STORE=3],
      [osx], [CA_STORE=4],
      [win], [CA_STORE=5],
      [AC_MSG_WARN(["Unknown CA store option '$withval'."])]
    )
  ])
# Set default value according to the target system.
# FIXME: Missing MinGW.
AS_IF([test $CA_STORE = -1], [
  AS_CASE([$host_os],
    [darwin*], [CA_STORE=4],
    [CA_STORE=1]
  )
])
AS_IF([test $CA_STORE = -1], [
  AC_MSG_ERROR(["CA store could not be determined."])
])
AC_DEFINE_UNQUOTED([CA_STORE], [${CA_STORE}], [Select which CA store to use])
AM_CONDITIONAL([CA_STORE_DIR], [test $CA_STORE = 1])
AM_CONDITIONAL([CA_STORE_NSS], [test $CA_STORE = 2])
AM_CONDITIONAL([CA_STORE_OSX], [test $CA_STORE = 4])

# Select a log target.
LOG_TGT=-1
AC_ARG_WITH([log-tgt],
  [AS_HELP_STRING([--with-log-tgt=[auto,dflt,osx]], [Which log target to use, 'auto' is default.])],
  [
    AS_CASE([$withval],
      [auto], [LOG_TGT=-1],
      [dflt], [LOG_TGT=0],
      [osx], [LOG_TGT=1],
      [AC_MSG_WARN(["Unknown log target option '$withval'."])]
    )
  ])
# Set default value according to the target system.
AS_IF([test $LOG_TGT = -1], [
  AS_CASE([$host_os],
    [darwin*], [LOG_TGT=1],
    [LOG_TGT=0]
  )
])
AS_IF([test $LOG_TGT = -1], [
  AC_MSG_ERROR(["Log target could not be determined."])
])
AM_CONDITIONAL([LOG_DFLT], [test $LOG_TGT = 0])
AM_CONDITIONAL([LOG_OSX], [test $LOG_TGT = 1])


###############################################################################
# Extension packages.
###############################################################################

AM_CONDITIONAL([EXTPKG_MOZZ_JC], [true]) # Mozilla Firefox js-ctypes.
AM_CONDITIONAL([EXTPKG_CR_NM], [true]) # Chromium/Chrome native messaging.
AM_CONDITIONAL([EXTPKG_MOZZ_NP], [test "x$enable_npapi_extensions" = "xyes"]) # Mozilla Firefox NPAPI.


CPPFLAGS="${CORE_CPPFLAGS}"
CFLAGS="${CORE_CFLAGS}"; CXXFLAGS="${CORE_CXXFLAGS}";
#LDFLAGS="${CORE_LDFLAGS}"; LIBS="${CORE_LIBS}"


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

# No parameters shall be passed via default variables.
#CPPFLAGS=""
#CFLAGS=""; CXXFLAGS="";
LDFLAGS=""; LIBS=""

# Default preprocessor flags.
#AC_SUBST([AM_CPPFLAGS], [""])


AC_CONFIG_FILES([ \
  Makefile \
  static-libs/Makefile \
  core_js-ctypes/Makefile \
  core_native-msg/Makefile \
  core_npapi/Makefile \
  add-on/Makefile \
  Version
])

AC_OUTPUT
