#!/usr/bin/env bash
################################################################################
#                                                                              #
#  Copyright 2021 Broadcom. The term Broadcom refers to Broadcom Inc. and/or   #
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
    echo "usage: format-check.sh [OPTIONS] [SRC_PATH]"
    echo ""
    echo "OPTIONS:"
    echo " -exclude=DIR  Directory to exclude for static checks. It can be repeated"
    echo " -log=FILE     Write static checker logs to a file (and to stdout)."
    echo ""
    echo "SRC_PATH selects source directories for format analysis."
    echo "If SRC_PATH is not specified, whole current directory tree is included."
    echo "If SRC_PATH is a directory, only that directory is included."
    echo "All other values are treated as file path. File's directory is included for"
    exit 0
}

# Format checker options
EXCLUDE=( build patches ocbinds )

while [[ $# -gt 0 ]]; do
case "$1" in
    -exclude=*|--exclude=*)
        EXCLUDE+=( "$(echo $1 | cut -d= -f2-)" )
        shift ;;
    -log=*|--log=*)
        LOGFILE="$(echo $1 | cut -d= -f2-)"
        shift ;;
    -*) print_help_and_exit ;;
    *)  break ;;
esac
done

# pkgpath prints go package path for a directory
function pkgpath() {
	local PKG=$(realpath --relative-to=. $1)
	[[ ${PKG:0:1} == . ]] && echo ${PKG} || echo ./${PKG}
}

FILES=
PACKAGES=
SRC_PATH=

if [[ $# -gt 1 ]]; then
    print_help_and_exit

elif [[ -z $1 ]]; then
    # No args or wildcard path.. Find go packages (dirs containing go files).
    EX=( -path "*/vendor" )  #path patterns to exclude
    for D in "${EXCLUDE[@]}"; do EX+=( -or -path "*/$D" ); done
    PACKAGE_LIST=( $(find "$(pkgpath $(dirname "$1"))" \( "${EX[@]}" \) -prune \
        -or -name "*.go" -printf "%h\n" | sort -u) )
	#PACKAGE=( "${PACKAGE_LIST[@]:1}" )
	#echo "${PACKAGE_LIST[@]}"
	PACKAGES=(${PACKAGE_LIST[@]%%\.})
	FILES=$(find $1 -maxdepth 1 -type f -name "*.go" -printf "%p " )
	SRC_PATH=( "${PACKAGES[@]}" "${FILES}" ) 
elif [[ -d $1 ]]; then
    # Directory name is specified. Run check for that package
    PACKAGES=( "$(pkgpath $1)" )
	SRC_PATH=( "${PACKAGES}" )

else
	FILES=$1
	SRC_PATH=( "${FILES}" )
fi

[[ -z $GO ]] && export GO=go
[[ -z $GOPATH ]] && export GOPATH=/tmp/go
export GOBIN=$(echo ${GOPATH} | sed 's/:.*$//g')/bin
export PATH=$($GO env GOROOT)/bin:${PATH}

# Download goimports format checker if not present already
if [[ ! -f ${GOBIN}/goimports ]]; then
    pushd $(mktemp -d) > /dev/null
    echo "Installing goimports tool into ${GOBIN}"
    go mod init tools
    go get -u golang.org/x/tools/cmd/goimports
    popd > /dev/null
    echo ""
fi

# Create a temporary logfile if not specified thru -log option.
[[ -z ${LOGFILE} ]] && LOGFILE=$(mktemp) || mkdir -p "$(dirname ${LOGFILE})"

echo "Running Go format checks at ${PWD}"
echo "Package = [${PACKAGES[@]}], files = ${FILES}"
echo ""
${GOBIN}/goimports -l ${SRC_PATH[@]} | tee ${LOGFILE}

NUM_ERROR=$(< "$LOGFILE" wc -l)
[[ ${NUM_ERROR} == 0  ]] || echo -e "\n${NUM_ERROR} files have formatting errors.\nPlease find list of files in a log file at ${LOGFILE}\nExecute ${GOBIN}/goimports -w <file> to fix issues.\nExecute ${GOBIN}/goimports -h for more information on formatter tool."

test $((NUM_ERROR)) -lt 1
