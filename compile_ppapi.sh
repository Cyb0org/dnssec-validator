#!/usr/bin/env sh

export NACL_SDK_ROOT=${HOME}/nacl_sdk/pepper_33
if [ ! -d "${NACL_SDK_ROOT}" ]; then
	echo "Cannot find ${NACL_SDK_ROOT}" >&2
	exit 1
fi

export OSNAME=`${NACL_SDK_ROOT}/tools/getos.py`
export X86_TC_PATH=${NACL_SDK_ROOT}/toolchain/${OSNAME}_x86_glibc
export ARM_TC_PATH=${NACL_SDK_ROOT}/toolchain/${OSNAME}_arm_newlib

if [ ! -d "${X86_TC_PATH}" ]; then
	echo "Cannot find ${X86_TC_PATH}" >&2
	exit 1
fi

export PATH=${X86_TC_PATH}/bin:${ARM_TC_PATH}/bin:${PATH}

export CPPFLAGS="-I${NACL_SDK_ROOT}/include"

DEBUG_PPAPI="no"

if [ "x${DEBUG_PPAPI}" = "xyes" ]; then
	# Debugging version of the toolkit.
	export LDFLAGS="-L${NACL_SDK_ROOT}/lib/glibc_x86_32/Debug ${LDFLAGS}"
else
	# Release version of the toolkit.
	export LDFLAGS="-L${NACL_SDK_ROOT}/lib/glibc_x86_32/Release ${LDFLAGS}"
fi

#
# List of supported hosts.
#
HOSTS=""
#MACHINES="i686 x86_64 arm"
MACHINES="i686 x86_64"
#MACHINES="i686"
#MACHINES="x86_64"
#MACHINES="arm"
for MACHINE in ${MACHINES}; do
	HOSTS="${HOSTS} ${MACHINE}-nacl"
done


SCRIPT_LOCATION=$(dirname $(readlink -f $0))

OPENSSL_DIR=libs/openssl-1.0.1f
LDNS_DIR=libs/ldns-1.6.17
UNBOUND_DIR=libs/unbound-1.4.22

BUILT_DIR=${SCRIPT_LOCATION}/ppapi_built

if [ ! -d "${BUILT_DIR}" ]; then
	mkdir ${BUILT_DIR}
fi

for HOST in ${HOSTS}; do
	PREFIX="${BUILT_DIR}/${OSNAME}-${HOST}"
	echo ${PREFIX}
	if [ ! -d "${PREFIX}" ]; then
		mkdir ${PREFIX}
	fi
done

COMPILE_SSL="yes"
COMPILE_LDNS="yes"
COMPILE_UNBOUND="yes"
COMPILE_DNSSEC="yes"

if [ "x${COMPILE_SSL}" = "xyes" ]; then
	for MACHINE in ${MACHINES}; do
		export MACHINE
		export HOST=${MACHINE}-nacl
		export AR=${HOST}-ar
		export CC=${HOST}-gcc
		export CXX=${HOST}-g++
		export LD=${HOST}-ld
		export RANLIB=${HOST}-ranlib

		PREFIX="${BUILT_DIR}/${OSNAME}-${HOST}"

		#NEWLIB_OPTS="no-dso no-sock no-ui"
		cd ${OPENSSL_DIR}
		make clean
		CMD="./config no-shared no-asm no-hw no-krb5 -D_GNU_SOURCE --prefix=${PREFIX}"
		${CMD} && make && make install
		make clean
		cd ${SCRIPT_LOCATION}
	done
fi

#exit

if [ "x${COMPILE_LDNS}" = "xyes" ]; then
	for MACHINE in ${MACHINES}; do
		export MACHINE
		export HOST=${MACHINE}-nacl
		export AR=${HOST}-ar
		export CC=${HOST}-gcc
		export CXX=${HOST}-g++
		export LD=${HOST}-ld
		export RANLIB=${HOST}-ranlib

		PREFIX="${BUILT_DIR}/${OSNAME}-${HOST}"

		cd ${LDNS_DIR}
		make clean
		CMD="./configure --host=${HOST} --disable-shard --with-ssl=${PREFIX} --prefix=${PREFIX} --disable-ldns-config --with-pic --without-pyldnsx"

		# Build in a separate subdirectory.
		BUILD_SUBDIR=_build_${OSNAME}-${HOST}
		if [ -d "${BUILD_SUBDIR}" ]; then
			rm -r ${BUILD_SUBDIR}
		fi
		mkdir ${BUILD_SUBDIR} && cd ${BUILD_SUBDIR}
		.${CMD} && make && make install
		cd .. && rm -r ${BUILD_SUBDIR}

		cd ${SCRIPT_LOCATION}
	done
fi

#exit

if [ "x${COMPILE_UNBOUND}" = "xyes" ]; then
	for MACHINE in ${MACHINES}; do
		export MACHINE
		export HOST=${MACHINE}-nacl
		export AR=${HOST}-ar
		export CC=${HOST}-gcc
		export CXX=${HOST}-g++
		export LD=${HOST}-ld
		export RANLIB=${HOST}-ranlib

		PREFIX="${BUILT_DIR}/${OSNAME}-${HOST}"

		cd ${UNBOUND_DIR}
		make clean
		CMD="./configure --host=${HOST} --disable-shared --with-ssl=${PREFIX} --with-ldns=${PREFIX} --prefix=${PREFIX} --with-libunbound-only"

		# Build in a separate subdirectory.
		BUILD_SUBDIR=_build_${OSNAME}-${HOST}
		if [ -d "${BUILD_SUBDIR}" ]; then
			rm -r ${BUILD_SUBDIR}
		fi
		mkdir ${BUILD_SUBDIR} && cd ${BUILD_SUBDIR}
		.${CMD} && make && make install
		cd .. && rm -r ${BUILD_SUBDIR}

		cd ${SCRIPT_LOCATION}
	done
fi

#exit

if [ "x${COMPILE_DNSSEC}" = "xyes" ]; then
	for MACHINE in ${MACHINES}; do
		export MACHINE
		export HOST=${MACHINE}-nacl
		export AR=${HOST}-ar
		export CC=${HOST}-gcc
		export CXX=${HOST}-g++
		export LD=${HOST}-ld
		export RANLIB=${HOST}-ranlib

		PREFIX="${BUILT_DIR}/${OSNAME}-${HOST}"

		export CPPFLAGS="${CPPFLAGS} -I${PREFIX}/include"
		export LDFLAGS="${LDFLAGS} -L${PREFIX}/lib"

		make -f Makefile.ppapi clean
		make -f Makefile.ppapi
		make -f Makefile.ppapi install
		make -f Makefile.ppapi clean
	done
fi
