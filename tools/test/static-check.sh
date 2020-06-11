#!/usr/bin/env bash
################################################################################
#                                                                              #
#  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or   #
#  its subsidiaries.                                                           #
#                                                                              #
#  Licensed under the Apache License, Version 2.0 (the "License");             #
#  you may not use this file except in compliance with the License.            #
#  You may obtain a copy of the License at                                     #
#                                                                              #
#     http://www.apache.org/licenses/LICENSE-2.0                               #
#                                                                              #
#  Unless required by applicable law or agreed to in writing, software         #
#  distributed under the License is distributed on an "AS IS" BASIS,           #
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    #
#  See the License for the specific language governing permissions and         #
#  limitations under the License.                                              #
#                                                                              #
################################################################################

set -e
function print_help_and_exit() {
    echo "usage: static-check.sh [OPTIONS] [SRC_PATH]"
    echo ""
    echo "OPTIONS:"
    echo " -checks=LIST  Comma-separated list of checks to run."
    echo "               Special code 'all' enables all available"
    echo "               checks -- https://staticcheck.io/docs/checks."
    echo " -tests        Include test files for static checks."
    echo ""
    echo "SRC_PATH is the source package or file selector."
    echo "If SRC_PATH is not specified, entire current directory tree is"
    echo "included for static analysis."
    echo "If SRC_PATH is a directory, only that directory is included."
    echo "Use Go style wildcard 'xyz/...' to include sub directories."
    echo "All other values are treated as file path prefix. Static checks"
    echo "are run for the directory and resuts are filtered by basename."
    echo ""
    echo "This tool can be run from any Go source directory."
    echo ""
    echo "Examples:"
    echo "static-check.sh           (run for all pkgs under PWD)"
    echo "static-check.sh cvl       (run for cvl pkg only)"
    echo "static-check.sh cvl/...   (run for cvl and its sub-pkgs)"
    echo "static-check.sh translib/version.go   (run for translib pkg"
    echo "                          and show results for version.go only)"
    echo ""
    exit 0
}

# Static checker options
OPTIONS=()
OPTIONS+=( -tests=false )
OPTIONS+=( -checks="all,-ST1000,-ST1003,-ST1005" )

while [[ $# -gt 0 ]]; do
case "$1" in
    -tests|-tests=*|--tests|--tests=*)
        OPTIONS[0]="$1"
        shift ;;
    -checks=*|--checks=*)
        OPTIONS[1]="$1"
        shift ;;
    -checks|--checks)
        OPTIONS[1]="$1=$2";
        shift 2 ;;
    -*) print_help_and_exit ;;
    *)  break ;;
esac
done

# Resolve package name for static checker and grep expression.
# Other options would have been already available in OPTIONS array.
PIPE=(tee)

if [[ $# -gt 1 ]]; then
    print_help_and_exit

elif [[ -z $1 ]]; then
    # No arguments.. Run checks for all packages
    PACKAGE="./..."

elif [[ -d $1 ]]; then
    # Directory name is specified. Run check for that package
    PACKAGE="./$(realpath --relative-to=. $1)"

else
    # Wildcard or file name prefix
    PACKAGE="./$(realpath --relative-to=. $(dirname $1))"
    FILE=$(basename $1)
    if [[ "${FILE:0:1}" == "." ]]; then
        PACKAGE+="/${FILE}"
        FILE=
    else
        PIPE=(grep "${FILE}\|could not analyze\|\(compile\)")
    fi
fi

[[ -z $GOPATH ]] && export GOPATH=/tmp/go

export GOBIN=$(echo ${GOPATH} | sed 's/:.*$//g')/bin

# Download the static checker if not present already
# Run 'go get' from a temp directory to avoid changes to go.mod file
if [[ ! -f ${GOBIN}/staticcheck ]]; then
    pushd $(mktemp -d) > /dev/null
    echo "Installing staticcheck tool into ${GOBIN}"
    go mod init tools
    go get honnef.co/go/tools/cmd/staticcheck@v0.0.1-2020.1.4 #3c17a0d
    popd > /dev/null
    echo ""
fi

TOPDIR=$(git rev-parse --show-toplevel 2> /dev/null || echo ".")

# Run makefile target 'go-deps' if it exists
DIRTY=$(make -sq -C ${TOPDIR} go-deps 2> /dev/null || echo $?)
[[ "${DIRTY}" == "1" ]] &&  \
    make -s -C ${TOPDIR} go-deps

# Rebuild ocbinds if runnig from sonic-mgmt-common directory.
# This allows running static checker directly after git pull.
[[ -f ${TOPDIR}/translib/ocbinds/oc.go ]] && \
    make -s -C ${TOPDIR} translib

echo "Running Go static checks at ${PWD}"
echo "Pacakage = ${PACKAGE}, files = ${FILE}*"
GOFLAGS="-mod=vendor" ${GOBIN}/staticcheck "${OPTIONS[@]}" ${PACKAGE} | "${PIPE[@]}"

[[ ${PIPESTATUS[0]} == 0 ]] && echo "All checks passed!!"
