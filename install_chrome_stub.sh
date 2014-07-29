#!/usr/bin/env sh

PLUGIN_DIR="${HOME}/Library/Internet Plug-Ins"

DNSSEC_DIR=npDNSSECValidatorPlugin.plugin
TLSA_DIR=npTLSAValidatorPlugin.plugin
SAFARIEXT=safari2.safariextz

uuencode=0
binary=1

untar_payload()
{
	SCRIPT="$0"
	if [ "x$1" != "x" ]; then
		SCRIPT="$1"
	fi

	match=$(grep --text --line-number '^PAYLOAD:$' "${SCRIPT}" | cut -d ':' -f 1)
	payload_start=$((match + 1))
	if [ $binary -ne 0 ]; then
		tail -n +$payload_start "${SCRIPT}" | tar -xzf -
	fi
	if [ $uuencode -ne 0 ]; then
		tail -n +$payload_start "${SCRIPT}" | uudecode | tar -xzf -
	fi
}

USAGE="Usage:\n\t $0 [core_directory]\n"

SCRIPT_NAME=$(basename $0)
BASEDIR=$(dirname $(readlink -f $0))
CORE_DIR=$1

#read -p "Install files? " ans
#if [[ "${ans:0:1}"  ||  "${ans:0:1}" ]]; then
	# Detect whether binary path entered or whether to use default.
	if [ "x${CORE_DIR}" = "x" ]; then
		CORE_DIR="${HOME}"/chrome_native_msg_cores
	fi

	if [ ! -d "${CORE_DIR}" ]; then
		mkdir -p ${CORE_DIR}
	fi

	# Detect where to install JSON file.
	SYSTEM=`uname -s | tr '[:upper:]' '[:lower:]'`
	# https://developer.chrome.com/extensions/messaging#native-messaging
	MANIFEST_DIR=""
	CHROMIUM_MANIFEST_DIR=""
	case "${SYSTEM}" in
	linux)
		MANIFEST_DIR="${HOME}/.config/google-chrome/NativeMessagingHosts"
		# On Linux install to Chromium as well.
		CHROMIUM_MANIFEST_DIR="${HOME}/.config/chromium/NativeMessagingHosts"
		;;
	darwin)
		MANIFEST_DIR="${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts"
		;;
	*)
		echo >&2 "Unsupported system '${SYSTEM}'."
		exit 1
		;;
	esac

	if [ ! -d "${MANIFEST_DIR}" ]; then
		mkdir -p "${MANIFEST_DIR}"
	fi

	if [ -n "${CHROMIUM_MANIFEST_DIR}" ] && [ ! -d "${CHROMIUM_MANIFEST_DIR}" ]; then
		mkdir -p ${CHROMIUM_MANIFEST_DIR}
	fi

	WORK_DIR=`pwd`

	TMP_DIR=`mktemp -d`
	cd "${TMP_DIR}"; untar_payload ${BASEDIR}/${SCRIPT_NAME}; cd "${WORK_DIR}"

	PLUG_FILE=`ls "${TMP_DIR}" | grep plug`
	JSON_IN_FILE=`ls "${TMP_DIR}" | grep json.in`
	CRX_FILE=`ls "${TMP_DIR}" | grep crx`
	JSON_FILE=`echo ${JSON_IN_FILE} | sed -e 's/\.in$//g'`

	# Move binary to location.
	cp "${TMP_DIR}/${PLUG_FILE}" "${CORE_DIR}/${PLUG_FILE}"

	# Update JSON template.
	ESCAPED_PATH=`echo "${CORE_DIR}/${PLUG_FILE}" | sed -e 's/\//\\\\\//g'`
	sed -e "s/[@][^_]*_BINARY[@]/\"${ESCAPED_PATH}\"/g" < "${TMP_DIR}/${JSON_IN_FILE}" > "${MANIFEST_DIR}/${JSON_FILE}"
	if [ -n "${CHROMIUM_MANIFEST_DIR}" ]; then
		sed -e "s/[@][^_]*_BINARY[@]/\"${ESCAPED_PATH}\"/g" < "${TMP_DIR}/${JSON_IN_FILE}" > "${CHROMIUM_MANIFEST_DIR}/${JSON_FILE}"
	fi

	# Move crx file.
	cp "${TMP_DIR}/${CRX_FILE}" "${WORK_DIR}/${CRX_FILE}"
	echo "A CRX file has been created in the current directory."
	echo "Install the file '${WORK_DIR}/${CRX_FILE}' into Google Chrome using drag add drop:"
	echo -e "\t1) Open Google Chrome."
	echo -e "\t2) Open the page chrome://extensions/ ."
	echo -e "\t3) Drag the CRX file into the page and accept the notification."
	echo -e "\t4) Restart Google Chrome."

	# Do remainder of install steps.
	rm -rf "${TMP_DIR}"
#fi

exit 0
