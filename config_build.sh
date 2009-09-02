#!/bin/bash
# Build config for build.sh
APP_NAME=dnssec
CHROME_PROVIDERS="content locale skin"
CLEAN_UP=1
ROOT_FILES=
ROOT_DIRS="components"
BEFORE_BUILD="make -C xpcom"
AFTER_BUILD=
