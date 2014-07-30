#!/usr/bin/env sh


# Script must be run after these commands:
#make -f Makefile.main clean && cmake . && make
#cd tests && make clean && make && cd ..


OPTS="h"
GETOPT="h"

USAGE=""
USAGE="${USAGE}Usage:\n"
USAGE="${USAGE}\t$0 [-${OPTS}] chrome_executable\n"
USAGE="${USAGE}\n"
USAGE="${USAGE}Options:\n"
USAGE="${USAGE}\t-h\tPrints this message.\n"
USAGE="${USAGE}\n"
USAGE="${USAGE}\tchrome_executable\n"
USAGE="${USAGE}\t\t-- name of the Chrome executable (e.g. chromium, google-chrome).\n"

# Parse options.
set -- `getopt "${GETOPT}" "$@"`
if [ $# -lt 1 ]; then
	echo >&2 "Getopt failed."
	exit 1
fi
while [ $# -gt 0 ]; do
	case "$1" in
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


#CHROME_BINARY="google-chrome-stable"
#CHROME_BINARY="chromium"
if [ -z "${CHROME_BINARY}" ]; then
	# CHROME_BINARY may be passed via variable.
	if [ $# -ne 1 ]; then
		echo >&2 -ne "${USAGE}"
		exit 1
	fi
	CHROME_BINARY="$1"
fi

if ! type 1>/dev/null 2>&1 "${CHROME_BINARY}"; then
	echo >&2 "'${CHROME_BINARY}' is not a command."
	exit 1
fi

TARGZ_FILE=arch_$$.tar.gz

VERSION_FILE="Version"
if [ -f ${VERSION_FILE} ]; then
	VERSION=`cat ${VERSION_FILE}`
else
	VERSION="x.y.z"
fi

if [ "x${HWARCH}" = "x" ]; then
	echo >&2 "Variable HWARCH is not set. Consider setting its proper value."
	HWARCH=unknown
fi

SYSTEM=`uname -s | tr '[:upper:]' '[:lower:]'`

TARGET_DNSSEC="GC-dnssec_validator-${VERSION}-${SYSTEM}-${HWARCH}.sh"
TARGET_TLSA="GC-tlsa_validator-${VERSION}-${SYSTEM}-${HWARCH}.sh"

SCRIPT_STUB="install_chrome_stub.sh"

#TEMP_DIR=`mktemp -d`
rm -rf __tmp__ && mkdir __tmp__
TEMP_DIR="__tmp__"


cleanup ()
{
	rm -rf "${TEMP_DIR}" "${TARGZ_FILE}" "${TARGET_DNSSEC}" "${TARGET_TLSA}"
}


#cleanup
if [ ! -d add-on/chrome-dnssec/native-msg_built ]; then
	echo >&2 "Cannot find directory 'add-on/chrome-dnssec/native-msg_built'."
	exit 1
fi
cp -r add-on/chrome-dnssec/native-msg_built ${TEMP_DIR}/dnssec-pkg
mv ${TEMP_DIR}/dnssec-pkg/cz.nic.validator.dnssec.json.in ${TEMP_DIR}/cz.nic.validator.dnssec.json.in
rm -f ${TEMP_DIR}/dnssec-pkg/cz.nic.validator.dnssec.json*
if [ ! -f tests/dnssec-plug ]; then
	echo >&2 "Cannot find file 'tests/dnssec-plug'."
	exit 1
fi
cp tests/dnssec-plug ${TEMP_DIR}/dnssec-plug
if [ ! -f ../chrome_dnssec_validator.pem ]; then
	echo >&2 "Cannot locate '../chrome_dnssec_validator.pem'."
	exit 1
fi
cp ../chrome_dnssec_validator.pem ${TEMP_DIR}/chrome_dnssec_validator.pem
"${CHROME_BINARY}" --pack-extension="${TEMP_DIR}/dnssec-pkg" --pack-extension-key="${TEMP_DIR}/chrome_dnssec_validator.pem"
rm ${TEMP_DIR}/chrome_dnssec_validator.pem
#
cd ${TEMP_DIR}; tar -czf "${TARGZ_FILE}" cz.nic.validator.dnssec.json.in dnssec-plug dnssec-pkg.crx; cd ..
cp "${SCRIPT_STUB}" "${TARGET_DNSSEC}"
echo "PAYLOAD:" >> "${TARGET_DNSSEC}"
cat "${TEMP_DIR}/${TARGZ_FILE}" >> "${TARGET_DNSSEC}"
chmod +x "${TARGET_DNSSEC}"
rm -f ${TARGZ_FILE}


#cleanup
if [ ! -d add-on/chrome-tlsa/native-msg_built ]; then
	echo >&2 "Cannot find directory 'add-on/chrome-tlsa/native-msg_built'."
	exit 1
fi
cp -r add-on/chrome-tlsa/native-msg_built ${TEMP_DIR}/tlsa-pkg
mv ${TEMP_DIR}/tlsa-pkg/cz.nic.validator.tlsa.json.in ${TEMP_DIR}/cz.nic.validator.tlsa.json.in
rm -f ${TEMP_DIR}/tlsa-pkg/cz.nic.validator.tlsa.json*
if [ ! -f tests/dane-plug ]; then
	echo >&2 "Cannot find file 'tests/dane-plug'."
	exit 1
fi
cp tests/dane-plug ${TEMP_DIR}/dane-plug
if [ ! -f ../chrome_tlsa_validator.pem ]; then
	echo >&2 "Cannot locate '../chrome_tlsa_validator.pem'."
	exit 1
fi
cp ../chrome_tlsa_validator.pem ${TEMP_DIR}/chrome_tlsa_validator.pem
"${CHROME_BINARY}" --pack-extension="${TEMP_DIR}/tlsa-pkg" --pack-extension-key="${TEMP_DIR}/chrome_tlsa_validator.pem"
rm ${TEMP_DIR}/chrome_tlsa_validator.pem
#
cd ${TEMP_DIR}; tar -czf "${TARGZ_FILE}" cz.nic.validator.tlsa.json.in dane-plug tlsa-pkg.crx; cd ..
cp "${SCRIPT_STUB}" "${TARGET_TLSA}"
echo "PAYLOAD:" >> "${TARGET_TLSA}"
cat "${TEMP_DIR}/${TARGZ_FILE}" >> "${TARGET_TLSA}"
chmod +x "${TARGET_TLSA}"
rm -f ${TARGZ_FILE}

rm -rf ${TEMP_DIR}
