#!/usr/bin/env sh

OPTS="fhl"
USAGE=""
USAGE="${USAGE}Usage:\n"
USAGE="${USAGE}\t$0 [-${OPTS}] command xpi_file [target_directory]\n"
USAGE="${USAGE}\n"
USAGE="${USAGE}\t If no target_directory supplied then a default value is tried to be used.\n"
USAGE="${USAGE}Options:\n"
USAGE="${USAGE}\t-f\t Force command.\n"
USAGE="${USAGE}\t-h\t Prints this message.\n"
USAGE="${USAGE}\t-l\t List installed files and directories.\n"

FORCE=no
LIST=no

# Parse options.
set -- `getopt fhl "$@"`
if [ $# -lt 1 ]; then
	echo >&2 "Getopt failed."
	exit 1
fi
while [ $# -gt 0 ]; do
	case "$1" in
	-f)
		FORCE=yes
		;;
	-h)
		echo >&2 -en "${USAGE}"
		exit 0
		;;
	-l)
		LIST=yes
		;;
	--)
		shift
		break
		;;
	*)
		echo >&2 -en "${USAGE}"
		exit 0
		;;
	esac
	shift
done

# The command xpi_file [target_directory] must be present.
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo >&2 -en "${USAGE}"
	exit 1
fi


CMD="$1"
XPI_FILE="$2"
EXT_DIR="$3"


# Test file presence.
if [ ! -r "${XPI_FILE}" ]; then
	echo >&2 "File '${XPI_FILE}' does not exist or cannot be read."
	exit 1
fi


# For information how to install extensions globally see the following pages:
# http://kb.mozillazine.org/Installing_extensions
# http://kb.mozillazine.org/Installation_directory
# http://kb.mozillazine.org/Determining_plugin_directory_on_Linux


# Extracts the extension id from supplied xpi file.
get_xpi_extension_id() {
	# "//rdf:Description[@about='urn:mozilla:install-manifest']/em:id"

	RDFNS="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
	EMNS="http://www.mozilla.org/2004/em-rdf#"

	unzip -p $1 install.rdf | \
	xmllint --xpath "//*[namespace-uri()='${RDFNS}' and name()='Description' and contains(@about, 'urn:mozilla:install-manifest')]/*[namespace-uri()='${EMNS}' and name()='em:id']/text()" -
}


# Installs the extension.
install_extension() {
	# Test whether extension directory was supplied by the user.
	DFLT_EXT_DIR="/usr/lib64/firefox/browser/extensions"
	if [ "x${EXT_DIR}" = "x" ]; then
		EXT_DIR="${DFLT_EXT_DIR}"
		echo >&2 "Assuming '${EXT_DIR}' to be the default extension directory."
	fi

	# Test whether we have write access.
	if [ ! -d "${EXT_DIR}" ] || [ ! -w "${EXT_DIR}" ]; then
		echo >&2 "Directory '${EXT_DIR}' does not exist or you don't have write permissions."
		exit 1
	fi

	EXT_ID=`get_xpi_extension_id ${XPI_FILE}`
	if [ "x${EXT_ID}" = "x" ]; then
		echo >&2 "Cannot determine extension id."
		exit 1
	fi

	if [ -d "${EXT_DIR}/${EXT_ID}" ]; then
		if [ "x${FORCE}" != "xyes" ] && [ -n "`ls -A ${EXT_DIR}/${EXT_ID}`" ]; then
			echo >&2 "Extension seems to be already installed. Try forcing an overwrite."
			exit 1
		elif [ "x${FORCE}" = "xyes" ] && [ -n "`ls -A ${EXT_DIR}/${EXT_ID}`" ]; then
			if ! rm -r ${EXT_DIR}/${EXT_ID}; then
				echo >&2 "Cannot delete old extension."
				exit 1
			fi
		fi
	fi

	if [ ! -d "${EXT_DIR}/${EXT_ID}" ]; then
		if ! mkdir "${EXT_DIR}/${EXT_ID}"; then
			echo >&2 "Cannot create directory '${EXT_DIR}/${EXT_ID}'."
			exit 1
		fi
	fi

	if ! unzip -q "${XPI_FILE}" -d "${EXT_DIR}/${EXT_ID}"; then
		echo >&2 "Unzip command failed."
		exit 1
	fi

	if [ "x${LIST}" = "xyes" ]; then
		find ${EXT_DIR}/${EXT_ID}/
	fi
}


case ${CMD} in
install)
	install_extension
	;;
*)
	echo >&2 "Unknown command '${CMD}'."
	;;
esac
