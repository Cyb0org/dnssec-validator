#!/usr/bin/env sh

PLUGIN_DIR="${HOME}/Library/Internet Plug-Ins"

DNSSEC_DIR=npDNSSECValidatorPlugin.plugin
TLSA_DIR=npTLSAValidatorPlugin.plugin
SAFARIEXT=safari2.safariextz

uuencode=0
binary=1

function untar_payload()
{
	match=$(grep --text --line-number '^PAYLOAD:$' $0 | cut -d ':' -f 1)
	payload_start=$((match + 1))
	if [[ $binary -ne 0 ]]; then
		tail -n +$payload_start $0 | tar -xzf -
	fi
	if [[ $uuencode -ne 0 ]]; then
		tail -n +$payload_start $0 | uudecode | tar -xzf -
	fi
}

#read -p "Install files? " ans
#if [[ "${ans:0:1}"  ||  "${ans:0:1}" ]]; then
	untar_payload

	# Do remainder of install steps.
	if [ -e "${PLUGIN_DIR}/${DNSSEC_DIR}" ]; then
		echo "Deleting old ${PLUGIN_DIR}/${DNSSEC_DIR}" >&2
		rm -r "${PLUGIN_DIR}/${DNSSEC_DIR}"
	fi
	echo "Instaling ${PLUGIN_DIR}/${DNSSEC_DIR}"
	mv ${DNSSEC_DIR} "${PLUGIN_DIR}/${DNSSEC_DIR}"
	echo ""

	if [ -e "${PLUGIN_DIR}/${TLSA_DIR}" ]; then
		echo "Deleting old ${PLUGIN_DIR}/${TLSA_DIR}" >&2
		rm -r "${PLUGIN_DIR}/${TLSA_DIR}"
	fi
	echo "Installing ${PLUGIN_DIR}/${TLSA_DIR}"
	mv ${TLSA_DIR} "${PLUGIN_DIR}/${TLSA_DIR}"
	echo ""

	
	echo "Installing ${SAFARIEXT}"
	if ! open "${SAFARIEXT}" ; then
		echo "Installation failed." >&2
	fi
	echo ""
#fi

exit 0
