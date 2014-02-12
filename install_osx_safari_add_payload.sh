#!/usr/bin/env sh

TAR_FILE=arch_$$.tar
TARGZ_FILE=${TAR_FILE}.gz

SCRIPT_STUB=install_osx_safari_stub.sh
TARGET=install_osx_safari.sh

PLUGIN_SRC_DIR=plugins-lib
ADDON_SRC_DIR=add-on

DNSSEC_DIR=npDNSSECValidatorPlugin.plugin
TLSA_DIR=npTLSAValidatorPlugin.plugin
SAFARIEXT=safari2.safariextz

function cleanup() {
	rm -f ${TAR_FILE} ${TARGZ_FILE} ${TARGET}
}

# Preparation phase.
cleanup

# Create archive containing plugin stuff.
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

cp "${SCRIPT_STUB}" "${TARGET}"
echo "PAYLOAD:" >> "${TARGET}"
cat "${TARGZ_FILE}" >> "${TARGET}"
rm "${TARGZ_FILE}"

chmod +x "${TARGET}"
