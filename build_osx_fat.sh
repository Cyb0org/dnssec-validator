#!/usr/bin/env sh

MAKE_CMD=make

${MAKE_CMD} -f Makefile.main clean
rm -rf FireBreath
git clone https://github.com/firebreath/FireBreath.git FireBreath

CFLAGS="-m32 -arch i386" ${MAKE_CMD} -f Makefile.static_libs LIB_CFLAGS="-m32 -arch i386" OPENSSL_ARGS=darwin-i386-cc CONFIGURE_ARGS=--target=i686-apple-darwin11 OSNAME=MacOSX OSNAME_LC=macosx HWARCH=x86 MAKE_CMD=${MAKE_CMD} STATIC_LINKING=yes && \
${MAKE_CMD} -f Makefile.mac STATIC_LINKING=yes js-ctypes_x86 && \
CFLAGS="-m64 -arch x86_64" ${MAKE_CMD} -f Makefile.static_libs LIB_CFLAGS="-m64 -arch x86_64" OPENSSL_ARGS=darwin64-x86_64-cc CONFIGURE_ARGS=--target=x86_64-apple-darwin11 OSNAME=MacOSX OSNAME_LC=macosx HWARCH=x64 MAKE_CMD=${MAKE_CMD} STATIC_LINKING=yes && \
${MAKE_CMD} -f Makefile.mac STATIC_LINKING=yes js-ctypes_x64 && \
${MAKE_CMD} -f Makefile.mac js-ctypes_fat && \
${MAKE_CMD} -f Makefile.mac static_fat && \
${MAKE_CMD} -f Makefile.mac STATIC_LINKING=yes npapi_fat && \
${MAKE_CMD} -f Makefile.mac xpi_fat
