#!/usr/bin/env sh


# Script must be run after these commands:
#make -f Makefile.main clean && cmake . && make
#cd tests && make clean && make && cd ..


#CHROME_BINARY="google-chrome-stable"
CHROME_BINARY="chromium"

TARGZ_FILE=arch_$$.tar.gz

VERSION_FILE="Version"
if [ -f ${VERSION_FILE} ]; then
	VERSION=`cat ${VERSION_FILE}`
else
	VERSION="x.y.z"
fi

if [ "x${HWARCH}" = "x" ]; then
	HWARCH=unknown
fi

SYSTEM=`uname -s | tr '[:upper:]' '[:lower:]'`

TARGET_DNSSEC="GC-dnssec_validator-${VERSION}-${SYSTEM}-${HWARCH}.sh"
TARGET_TLSA="GC-tlsa_validator-${VERSION}-${SYSTEM}-${HWARCH}.sh"

SCRIPT_STUB="install_chrome_stub.sh"

#TEMP_DIR=`mktemp -d`
rm -rf __tmp__ && mkdir __tmp__
TEMP_DIR="__tmp__"

cleanup () {
	rm -rf "${TEMP_DIR}" "${TARGZ_FILE}" "${TARGET_DNSSEC}" "${TARGET_TLSA}"
}


#cleanup
cp -r add-on/chrome-dnssec/native-msg_built ${TEMP_DIR}/dnssec-pkg
mv ${TEMP_DIR}/dnssec-pkg/cz.nic.validator.dnssec.json.in ${TEMP_DIR}/cz.nic.validator.dnssec.json.in
rm -f ${TEMP_DIR}/dnssec-pkg/cz.nic.validator.dnssec.json*
cp tests/dnssec-plug ${TEMP_DIR}/dnssec-plug
cp ../chrome_dnssec_validator.pem ${TEMP_DIR}/chrome_dnssec_validator.pem
${CHROME_BINARY} --pack-extension="${TEMP_DIR}/dnssec-pkg" --pack-extension-key="${TEMP_DIR}/chrome_dnssec_validator.pem"
rm ${TEMP_DIR}/chrome_dnssec_validator.pem
#
cd ${TEMP_DIR}; tar -czf "${TARGZ_FILE}" cz.nic.validator.dnssec.json.in dnssec-plug dnssec-pkg.crx; cd ..
cp "${SCRIPT_STUB}" "${TARGET_DNSSEC}"
echo "PAYLOAD:" >> "${TARGET_DNSSEC}"
cat "${TEMP_DIR}/${TARGZ_FILE}" >> "${TARGET_DNSSEC}"
chmod +x "${TARGET_DNSSEC}"
rm -f ${TARGZ_FILE}


#cleanup
mkdir ${TEMP_DIR}
cp -r add-on/chrome-tlsa/native-msg_built ${TEMP_DIR}/tlsa-pkg
mv ${TEMP_DIR}/tlsa-pkg/cz.nic.validator.tlsa.json.in ${TEMP_DIR}/cz.nic.validator.tlsa.json.in
rm -f ${TEMP_DIR}/tlsa-pkg/cz.nic.validator.tlsa.json*
cp tests/dane-plug ${TEMP_DIR}/dane-plug
cp ../chrome_tlsa_validator.pem ${TEMP_DIR}/chrome_tlsa_validator.pem
${CHROME_BINARY} --pack-extension="${TEMP_DIR}/tlsa-pkg" --pack-extension-key="${TEMP_DIR}/chrome_tlsa_validator.pem"
rm ${TEMP_DIR}/chrome_tlsa_validator.pem
#
cd ${TEMP_DIR}; tar -czf "${TARGZ_FILE}" cz.nic.validator.tlsa.json.in dane-plug tlsa-pkg.crx; cd ..
cp "${SCRIPT_STUB}" "${TARGET_TLSA}"
echo "PAYLOAD:" >> "${TARGET_TLSA}"
cat "${TEMP_DIR}/${TARGZ_FILE}" >> "${TARGET_TLSA}"
rm -f ${TARGZ_FILE}
chmod +x "${TARGET_TLSA}"


rm -rf ${TEMP_DIR}
