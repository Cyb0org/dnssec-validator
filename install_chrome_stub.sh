#!/usr/bin/env sh

PLUGIN_DIR="${HOME}/Library/Internet Plug-Ins"

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


full_canonical_name()
{
	# Avoids using readlink -f .

	TGT_FILE="$1"

	cd $(dirname "${TGT_FILE}")
	TGT_FILE=$(basename "${TGT_FILE}")

	# Cycle counter.
	CNTR=0

	# Iterate down a (possible) chain of symlinks.
	while [ -L "${TGT_FILE}" ]; do
		TGT_FILE=$(readlink ${TGT_FILE})
		cd $(dirname "${TGT_FILE}")
		TGT_FILE=$(basename "${TGT_FILE}")

		CNTR=$(expr ${CNTR} + 1)
		if [ ${CNTR} -ge 1000 ]; then
			# Probably in a symlink cycle.
			return 1
		fi
	done

	# Compute the canonicalised name by finding the physical path
	# for the directory we're in and appending the target file.
	PHYS_DIR=`pwd -P`
	RESULT="${PHYS_DIR}/${TGT_FILE}"
	echo ${RESULT}
}


CORE_DIR_DFLT="${HOME}/chrome_dnssec_tlsa_cores"

OPTS="acgh"
GETOPT="acgh"

USAGE=""
USAGE="${USAGE}Usage:\n"
USAGE="${USAGE}\t$0 [-${OPTS}] [core_directory]\n"
USAGE="${USAGE}\n"
USAGE="${USAGE}Options:\n"
USAGE="${USAGE}\t-a\tRegister native messaging core to all supported browsers (default).\n"
USAGE="${USAGE}\t-c\tRegister native messaging core to Chromium.\n"
USAGE="${USAGE}\t-g\tRegister native messaging core to Google Chrome.\n"
USAGE="${USAGE}\t-h\tPrints this message.\n"
USAGE="${USAGE}\n"
USAGE="${USAGE}\tcore_directory\n"
USAGE="${USAGE}\t\t-- Path where to install native messaging core binary (default '${CORE_DIR_DFLT}').\n"


CHROMIUM_CORE='no'
G_CHROME_CORE='no'


# Parse options.
set -- `getopt "${GETOPT}" "$@"`
if [ $# -lt 1 ]; then
	echo >&2 "Getopt failed."
	exit 1
fi
while [ $# -gt 0 ]; do
	case "$1" in
	-a)
		;;
	-c)
		CHROMIUM_CORE='yes'
		;;
	-g)
		G_CHROME_CORE='yes'
		;;
	-h)
		echo >&2 -en "${USAGE}"
		exit 0
		;;
	--)
		shift
		break
		;;
	*)
		echo >&2 "Unknown option '$1'."
		exit 1
		;;
	esac
	shift
done

SYSTEM=`uname -s | tr '[:upper:]' '[:lower:]'`

if [ "x${CHROMIUM_CORE}" = 'xno' ] && [ "x${G_CHROME_CORE}" = 'xno' ]; then
	CHROMIUM_CORE='yes'
	G_CHROME_CORE='yes'
fi

if [ "x${CHROMIUM_CORE}" = 'xyes' ] && [ "x${SYSTEM}" = "xdarwin" ]; then
	echo >&2 "Cannot install chromium extension on OS X."
	CHROMIUM_CORE='no'
fi

# Check whether we are going to install to some browser.
if [ "x${CHROMIUM_CORE}" = 'xno' ] && [ "x${G_CHROME_CORE}" = 'xno' ]; then
	echo >&2 "None of supported browser selected."
	exit 1
fi


# readlink behaves differently on OS X.
#SCRIPT_NAME=$(basename $0)
#BASEDIR=$(dirname $(readlink -f $0))
SCRIPT_CANONICAL_NAME=`full_canonical_name "$0"`
CORE_DIR=$1

#read -p "Install files? " ans
#if [[ "${ans:0:1}"  ||  "${ans:0:1}" ]]; then
	# Detect whether binary path entered or whether to use default.
	if [ "x${CORE_DIR}" = "x" ]; then
		CORE_DIR="${HOME}/chrome_native_msg_cores"
	fi

	if [ ! -d "${CORE_DIR}" ]; then
		mkdir -p ${CORE_DIR}
	fi

	# Detect where to install JSON file.
	# https://developer.chrome.com/extensions/messaging#native-messaging
	MANIFEST_DIR=""
	CHROMIUM_MANIFEST_DIR=""
	case "${SYSTEM}" in
	linux)
		# On Linux install to Chromium as well.
		CHROMIUM_MANIFEST_DIR="${HOME}/.config/chromium/NativeMessagingHosts"
		G_CHROME_MANIFEST_DIR="${HOME}/.config/google-chrome/NativeMessagingHosts"
		;;
	darwin)
		G_CHROME_MANIFEST_DIR="${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts"
		;;
	*)
		echo >&2 "Unsupported system '${SYSTEM}'."
		exit 1
		;;
	esac

	if [ "x${CHROMIUM_CORE}" = 'xno' ]; then
		CHROMIUM_MANIFEST_DIR=""
	fi

	if [ "x${G_CHROME_CORE}" = 'xno' ]; then
		G_CHROME_MANIFEST_DIR=""
	fi

	if [ -n "${CHROMIUM_MANIFEST_DIR}" ] && [ ! -d "${CHROMIUM_MANIFEST_DIR}" ]; then
		mkdir -p ${CHROMIUM_MANIFEST_DIR}
	fi

	if [ -n "${G_CHROME_MANIFEST_DIR}" ] && [ ! -d "${G_CHROME_MANIFEST_DIR}" ]; then
		mkdir -p "${G_CHROME_MANIFEST_DIR}"
	fi

	WORK_DIR=`pwd`

	TMP_DIR=`mktemp -d /tmp/valext-XXXXXX`
	cd "${TMP_DIR}"; untar_payload "${SCRIPT_CANONICAL_NAME}"; cd "${WORK_DIR}"

	PLUG_FILE=`ls "${TMP_DIR}" | grep plug`
	JSON_IN_FILE=`ls "${TMP_DIR}" | grep json.in`
	CRX_FILE=`ls "${TMP_DIR}" | grep crx`
	JSON_FILE=`echo ${JSON_IN_FILE} | sed -e 's/\.in$//g'`

	# Move binary to location.
	cp "${TMP_DIR}/${PLUG_FILE}" "${CORE_DIR}/${PLUG_FILE}"

	# Update JSON template.
	ESCAPED_PATH=`echo "${CORE_DIR}/${PLUG_FILE}" | sed -e 's/\//\\\\\//g'`
	if [ -n "${CHROMIUM_MANIFEST_DIR}" ]; then
		sed -e "s/[@][^_]*_BINARY[@]/\"${ESCAPED_PATH}\"/g" < "${TMP_DIR}/${JSON_IN_FILE}" > "${CHROMIUM_MANIFEST_DIR}/${JSON_FILE}"
	fi
	if [ -n "${G_CHROME_MANIFEST_DIR}" ]; then
		sed -e "s/[@][^_]*_BINARY[@]/\"${ESCAPED_PATH}\"/g" < "${TMP_DIR}/${JSON_IN_FILE}" > "${G_CHROME_MANIFEST_DIR}/${JSON_FILE}"
	fi

	# Move crx file.
	cp "${TMP_DIR}/${CRX_FILE}" "${WORK_DIR}/${CRX_FILE}"
	echo ""
	echo "A CRX file has been created in the current directory."
	echo ""
	echo -n "You may now install the file '${WORK_DIR}/${CRX_FILE}' into those browsers:"
	if [ -n "${CHROMIUM_MANIFEST_DIR}" ]; then
		echo -n " 'Chromium'"
	fi
	if [ -n "${G_CHROME_MANIFEST_DIR}" ]; then
		echo -n " 'Google Chrome'"
	fi
	echo ""
	echo -e "\t1) Run the browser."
	echo -e "\t2) Open the page chrome://extensions/ ."
	echo -e "\t3) Drag and drop the CRX file into the page and accept the notification."
	echo -e "\t4) Restart the browser."

	# Do remainder of install steps.
	rm -rf "${TMP_DIR}"
#fi

exit 0
