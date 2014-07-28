#!/usr/bin/env sh

#autoreconf
#automake
#make distclean

##autoscan
##mv configure.scan configure.ac
#autoheader
#libtoolize -c --install
#aclocal -I m4
#automake --add-missing --copy
#autoconf


#libtoolize -c --install
#autoreconf --install


USAGE="Usage: $0 help|ignore_git"


LIBTOOLIZE=libtoolize

# Determine operating system name.
OS_NAME=`uname -s | tr '[:upper:]' '[:lower:]'`
case ${OS_NAME} in
darwin)
	LIBTOOLIZE=glibtoolize
	;;
*)
	;;
esac


type ${LIBTOOLIZE} >/dev/null 2>&1 || {
	echo >&2 "Require ${LIBTOOLIZE}. Set search PATH or install it. Aborting."
	exit 1
}


build_configure () {
	autoheader
	${LIBTOOLIZE} -c --install
	aclocal -I m4
	automake --add-missing --copy
	autoconf
}

# If the file exists then git versioning is ignored.
BLOCK_FILE=".ignore_git_ver"

CMD_PREDECESSOR=""
CMD_SUCCESSOR=""

# Parse parameters.
for param in $@;
do
	case ${param} in
	help)
		echo ${USAGE}
		exit
		;;
	ignore_git)
		CMD_PREDECESSOR="mkdir ${BLOCK_FILE}"
		CMD_SUCCESSOR="rmdir ${BLOCK_FILE}"
		;;
	*)
		echo >&2 ${USAGE}
		exit 1
		;;
	esac
done


# Remove cache.
rm -rf autom4te.cache
# Remove block file if present;
rm -rf ${BLOCK_FILE}

${CMD_PREDECESSOR}
build_configure
${CMD_SUCCESSOR}
