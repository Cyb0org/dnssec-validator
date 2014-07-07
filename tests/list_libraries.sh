#!/usr/bin/env sh

FUNC_NAME="context_new"
PID=$1

echo process id: ${PID}

for lib in `lsof -p ${PID} | awk '{print $9}' | grep '\.so'`; do
	has=`readelf -Ws ${lib} | grep ' context_new'`
	if [ "x${has}" != "x" ]; then
		echo ${lib} ${has}
	fi
done
