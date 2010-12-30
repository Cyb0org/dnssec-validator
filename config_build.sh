#!/bin/bash
# Build config for build.sh
APP_NAME=dnssec
CHROME_PROVIDERS="content locale skin"
CLEAN_UP=1
ROOT_FILES="COPYING README icon.png"
ROOT_DIRS="defaults platform"
BEFORE_BUILD="make -C xpcom"
AFTER_BUILD=
