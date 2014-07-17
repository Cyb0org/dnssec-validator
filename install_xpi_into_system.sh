#!/usr/bin/env sh


USAGE="Usage:\n\t$0 xpi_file [target_directory]\n\t If no target_directory supplied then a default value is tried to be used.\n"

if [ "$#" -eq 0 ] || [ "$#" -gt 2 ]; then
	echo -en "${USAGE}" >&2
	exit 1
fi


XPI_FILE="$1"
EXT_DIR="$2"

# Test file presence.
if [ ! -r "${XPI_FILE}" ]; then
	echo "File '${XPI_FILE}' does not exist or cannot be read." >&2
	exit 1
fi

# For information how to install extensions globally see the following pages:
# http://kb.mozillazine.org/Installing_extensions
# http://kb.mozillazine.org/Installation_directory
# http://kb.mozillazine.org/Determining_plugin_directory_on_Linux

# Test whether extension directory was supplied by the user.
DFLT_EXT_DIR="/usr/lib64/firefox/browser/extensions"
if [ "x${EXT_DIR}" = "x" ]; then
	EXT_DIR="${DFLT_EXT_DIR}"
	echo "Assuming '${EXT_DIR}' to be the default extension directory."
fi

# Test whether we have write access.
if [ ! -d "${EXT_DIR}" ] || [ ! -w "${EXT_DIR}" ]; then
	echo "Directory '${EXT_DIR}' does not exist or you don't have write permissions." >&2
	exit 1
fi


# Extracts the extension id from supplied xpi file.
get_xpi_extension_id() {
	# "//rdf:Description[@about='urn:mozilla:install-manifest']/em:id"

	RDFNS="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	EMNS="http://www.mozilla.org/2004/em-rdf#"

	unzip -p $1 install.rdf | \
	xmllint --xpath "//*[namespace-uri()='${RDFNS}' and name()='Description' and contains(@about, 'urn:mozilla:install-manifest')]/*[namespace-uri()='${EMNS}' and name()='em:id']/text()" -
}


EXT_ID=`get_xpi_extension_id ${XPI_FILE}`
if [ "x${EXT_ID}" = "x" ]; then
	echo "Cannot determine extension id."  >&2
	exit 1
fi

mkdir "${EXT_DIR}/${EXT_ID}"

unzip "${XPI_FILE}" -d "${EXT_DIR}/${EXT_ID}"
