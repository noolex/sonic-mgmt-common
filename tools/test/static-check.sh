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
PIPE=(tee)

if [[ $# -gt 1 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo ""
    echo "usage: static-check.sh [SRC_PATH]"
    echo ""
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
    echo "1) Run for all packages:"
    echo "   static-check.sh "
    echo ""
    echo "2) Run for specific package:"
    echo "   static-check.sh translib/transformer"
    echo ""
    echo "3) Run for specific package and subpackages:"
    echo "   static-check.sh translib/..."
    echo ""
    echo "4) Run for specific file names:"
    echo "   static-check.sh translib/translib.go"
    echo "   static-check.sh translib/transformer/xfmr_system"
    echo ""
    exit 0

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
    pushd $(mktemp -d)
    go mod init tools
    go get honnef.co/go/tools/cmd/staticcheck@v0.0.1-2020.1.4 #3c17a0d
    popd
    echo ""
fi

TOPDIR=$(git rev-parse --show-toplevel 2> /dev/null || echo ".")

# Run makefile target 'go-deps' if it exists
DIRTY=$(make -sq -C ${TOPDIR} go-deps 2> /dev/null || echo $?)
[[ "${DIRTY}" == "1" ]] &&  \
    make -s -C ${TOPDIR} go-deps

# Rebuild ocbinds if runnig from sonic-mgmt-common directory.
# This allows running static checker directly after git pull.
# Other repos dont use ocbinds directly; hence it can be skipped.
[[ -f ${TOPDIR}/translib/ocbinds/oc.go ]] && \
    make -s -C ${TOPDIR} translib

# Static checker options
OPTIONS=()
OPTIONS+=( -tests=false )
OPTIONS+=( -checks="all,-ST1005,-ST1000,-ST1003" )

echo "Running Go static checks at ${PWD}"
echo "Pacakage = ${PACKAGE}, files = ${FILE}*"
GOFLAGS="-mod=vendor" ${GOBIN}/staticcheck "${OPTIONS[@]}" ${PACKAGE} | "${PIPE[@]}"

