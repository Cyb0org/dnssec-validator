#!/usr/bin/env sh

export NACL_SDK_ROOT=${HOME}/nacl_sdk/pepper_33
NACL_SDK_DIR=${NACL_SDK_ROOT}/toolchain/linux_x86_glibc/bin

if [ ! -d "${NACL_SDK_ROOT}" ]; then
	echo "Cannot find ${NACL_SDK_ROOT}" >&2
	exit 1
fi

if [ ! -d "${NACL_SDK_DIR}" ]; then
	echo "Cannot find ${NACL_SDK_DIR}" >&2
	exit 1
fi

export AR=i686-nacl-ar
export CC=i686-nacl-gcc
export LD=i686-nacl-ld
export RANLIB=i686-nacl-ranlib
export HOST=i686-nacl
export MACHINE=i686

export PATH=${NACL_SDK_DIR}:${PATH}

SCRIPT_LOCATION=$(dirname $(readlink -f $0))

OPENSSL_DIR=libs/openssl-1.0.1f
LDNS_DIR=libs/ldns-1.6.17
UNBOUND_DIR=libs/unbound-1.4.22

PREFIX=${SCRIPT_LOCATION}/ppapi_built

if [ ! -d "${PREFIX}" ]; then
	mkdir ${PREFIX}
fi

COMPILE_SSL="yes"
COMPILE_LDNS="yes"
COMPILE_UNBOUND="yes"
COMPILE_DNSSEC="yes"

if [ "x${COMPILE_SSL}" = "xyes" ]; then
	#NEWLIB_OPTS="no-dso no-sock no-ui"
	cd ${OPENSSL_DIR}
	make clean
	CMD="./config no-shared no-asm no-hw no-krb5 -D_GNU_SOURCE --prefix=${PREFIX}"
	${CMD} && make && make install
	cd ${SCRIPT_LOCATION}
fi

#exit

if [ "x${COMPILE_LDNS}" = "xyes" ]; then
	cd ${LDNS_DIR}
	make clean
	CMD="./configure --host=${HOST} --disable-shared --with-ssl=${PREFIX} --prefix=${PREFIX} --disable-ldns-config --with-pic --without-pyldnsx"
	${CMD} && make && make install
	cd ${SCRIPT_LOCATION}
fi

#exit

if [ "x${COMPILE_UNBOUND}" = "xyes" ]; then
	cd ${UNBOUND_DIR}
	make clean
	CMD="./configure --host=${HOST} --disable-shared --with-ssl=${PREFIX} --with-ldns=${PREFIX} --prefix=${PREFIX} --with-libunbound-only"
	${CMD} && make && make install
	cd ${SCRIPT_LOCATION}
fi

# exit

if [ "x${COMPILE_DNSSEC}" = "xyes" ]; then
	export CPPFLAGS="-I${PREFIX}/include"
	export LDFLAGS="-L${PREFIX}/lib"
	make -f Makefile.ppapi clean
	make -f Makefile.ppapi
	make -f Makefile.ppapi install
	make -f Makefile.ppapi clean
fi
