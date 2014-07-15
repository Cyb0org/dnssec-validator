#!/usr/bin/env sh

TAR_FILE=arch_$$.tar
TARGZ_FILE=${TAR_FILE}.gz

VERSION_FILE="Version"
if [ -f ${VERSION_FILE} ]; then
	VERSION=`cat ${VERSION_FILE}`
else
	VERSION="x.y.z"
fi

if [ "x${HWARCH}" = "x" ]; then
	HWARCH=unknown
fi

PKGS_DIR=packages
SCRIPT_STUB=install_osx_safari_stub.sh
TARGET_FILE="AS-dnssec-tlsa_validator-${VERSION}-macosx-${HWARCH}.sh"

PLUGIN_SRC_DIR=plugins-lib
ADDON_SRC_DIR=add-on

DNSSEC_DIR=npDNSSECValidatorPlugin.plugin
TLSA_DIR=npTLSAValidatorPlugin.plugin
SAFARIEXT=safari2.safariextz

function cleanup() {
	rm -f "${TAR_FILE}" "${TARGZ_FILE}" "${PKGS_DIR}/${TARGET_FILE}"
}

# Check whether target directory exists.
if [ ! -d "${PKGS_DIR}" ]; then
	mkdir ${PKGS_DIR} || exit 1
fi

# Preparation phase.
cleanup

# Create archive containing plug-in stuff.
if [ ! -d "${PLUGIN_SRC_DIR}/${DNSSEC_DIR}" ]; then
	echo "Directory ${PLUGIN_SRC_DIR}/${DNSSEC_DIR} does not exist." >&2
	cleanup
	exit 1
fi
cd "${PLUGIN_SRC_DIR}/"; tar -cf "../${TAR_FILE}" "./${DNSSEC_DIR}" ; cd ..
if [ ! -d "${PLUGIN_SRC_DIR}/${TLSA_DIR}" ]; then
	echo "Directory ${PLUGIN_SRC_DIR}/${TLSA_DIR} does not exist." >&2
	cleanup
	exit 1
fi
cd "${PLUGIN_SRC_DIR}/"; tar -rf "../${TAR_FILE}" "./${TLSA_DIR}" ; cd ..
if [ ! -f "${ADDON_SRC_DIR}/${SAFARIEXT}" ]; then
	echo "File ${ADDON_SRC_DIR}/${SAFARIEXT} does not exist." >&2
	cleanup
	exit 1
fi
cd "${ADDON_SRC_DIR}"; tar -rf "../${TAR_FILE}" "./${SAFARIEXT}" ; cd ..
gzip "${TAR_FILE}"

cp "${SCRIPT_STUB}" "${PKGS_DIR}/${TARGET_FILE}"
echo "PAYLOAD:" >> "${PKGS_DIR}/${TARGET_FILE}"
cat "${TARGZ_FILE}" >> "${PKGS_DIR}/${TARGET_FILE}"
rm "${TARGZ_FILE}"

chmod +x "${PKGS_DIR}/${TARGET_FILE}"
