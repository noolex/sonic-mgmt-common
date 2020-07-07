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
    echo " -checks=LIST  Comma-separated list of checks to run. Special code 'all'"
    echo "               enables all checks -- https://staticcheck.io/docs/checks."
    echo " -tests        Include test files for static checks."
    echo " -exclude=DIR  Directory to exclude for static checks. It can be repeated"
    echo "               multiple times to specify multiple exclude directories."
    echo " -notfail=FILE Do not treat failures as error for a file or directory."
    echo "               It can be repeated multiple times specify multiple such paths."
    echo "               Special value 'all' selects all directories."
    echo " -log=FILE     Write static checker logs to a file (and to stdout)."
    echo ""
    echo "SRC_PATH selects source directories for static analysis."
    echo "If SRC_PATH is not specified, whole current directory tree is included."
    echo "If SRC_PATH is a directory, only that directory is included. Use Go style"
    echo "wildcard 'xyz/...' to include sub directories."
    echo "All other values are treated as file path. File's directory is included for"
    echo "static checks and results are grepped by file name."
    echo ""
    echo "This tool can be run from any Go source directory."
    echo ""
    echo "Examples:"
    echo "static-check.sh             (run for all pkgs under PWD)"
    echo "static-check.sh cvl         (run for cvl pkg only)"
    echo "static-check.sh cvl/...     (run for cvl and its sub-pkgs)"
    echo "static-check.sh cvl/cvl.go  (show results for cvl.go only)"
    echo ""
    exit 0
}

# Static checker options
OPTIONS=()
OPTIONS+=( -tests=false )
OPTIONS+=( -checks="all,-ST1000,-ST1003,-ST1005" )

EXCLUDE=( build test tests patches ocbinds )
NOTFAIL=()

while [[ $# -gt 0 ]]; do
case "$1" in
    -tests|-tests=*|--tests|--tests=*)
        OPTIONS[0]="$1"
        shift ;;
    -checks=*|--checks=*)
        OPTIONS[1]="$1"
        shift ;;
    -exclude=*|--exclude=*)
        EXCLUDE+=( "$(echo $1 | cut -d= -f2-)" )
        shift ;;
    -notfail=*|--notfail=*)
        NOTFAIL+=( "$(echo $1 | cut -d= -f2-)" )
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

# Resolve package name for static checker and grep expression.
# Other options would have been already available in OPTIONS array.
PIPE=(cat)

if [[ $# -gt 1 ]]; then
    print_help_and_exit

elif [[ -z $1 ]] || [[ $1 == */... ]]; then
    # No args or wildcard path.. Find go packages (dirs containing go files).
    EX=( -path "*/vendor" )  #path patterns to exclude
    for D in "${EXCLUDE[@]}"; do EX+=( -or -path "*/$D" ); done
    PACKAGE=( $(find "$(pkgpath $(dirname "$1"))" \( "${EX[@]}" \) -prune \
        -or -name "*.go" -printf "%h\n" | sort -u) )

elif [[ -d $1 ]]; then
    # Directory name is specified. Run check for that package
    PACKAGE=( "$(pkgpath $1)" )

else
    # File name prefix.. Prepare grep expression to filter the results by file name.
    PACKAGE=( "$(pkgpath $(dirname $1))" )
    FILE=$(basename $1)
    PIPE=(grep "${FILE}\|could not analyze\|\(compile\)")
fi

[[ -z $GO ]] && export GO=go
[[ -z $GOPATH ]] && export GOPATH=/tmp/go
export GOBIN=$(echo ${GOPATH} | sed 's/:.*$//g')/bin
export PATH=$($GO env GOROOT)/bin:${PATH}

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

# ifmake is a utility to run make only if required
function ifmake() {
    [[ "$(make -sq "$@" 2> /dev/null || echo $?)" != "1" ]] || make "$@"
}

# Try to setup dependencies (vendor directory) if the tool is executed
# directly -- not from a Makefile.
if [[ -z ${MAKELEVEL} ]]; then
    ifmake -C ${TOPDIR} go-deps
    ifmake -C ${TOPDIR}/translib ocbinds/ocbinds.go
fi

# Create a temporary logfile if not specified thru -log option.
[[ -z ${LOGFILE} ]] && LOGFILE=$(mktemp) || mkdir -p "$(dirname ${LOGFILE})"

echo "Running Go static checks at ${PWD}"
echo "Pacakage = [${PACKAGE[@]}], files = ${FILE}*"
echo ""
GOFLAGS="-mod=vendor" ${GOBIN}/staticcheck "${OPTIONS[@]}" "${PACKAGE[@]}" | "${PIPE[@]}" | tee ${LOGFILE}

# Count error using the check code printed at end of line, like " (S1005)"
NUM_ERROR=$(grep -c " ([[:alnum:]]*)$" ${LOGFILE} || true)
NUM_IGNORE=0

# Count ignored errors by matching log line's file path with -notfail paths.
# Compilation errors are not ignored.
if [[ ${#NOTFAIL[@]} != 0 ]]; then
    for NF in "${NOTFAIL[@]}"; do
        case ${NF} in
        all)  NOTFAIL_EXPR="^.*\.go:\|"; break ;;
        *.go) NOTFAIL_EXPR+="^$(realpath --relative-to=. ${NF}):\|" ;;
        *)    NOTFAIL_EXPR+="^$(realpath --relative-to=. ${NF})[/]*[^/]*\.go:\|" ;;
        esac
    done

    NOTFAIL_EXPR="${NOTFAIL_EXPR:0:$((${#NOTFAIL_EXPR}-2))}"  # remove "\|" suffix
    NUM_IGNORE=$(grep "^[^[:space:]].*\.go:[0-9]*:[0-9]*: " ${LOGFILE} | \
                    grep -v " (compile)$" | grep -c "${NOTFAIL_EXPR}" || true)
    if [[ ${NUM_IGNORE} != 0 ]]; then
        IGNORE_MSG=", ${NUM_IGNORE} exempted"
        NON_IGNORE=( $(grep -o "^[^[:space:]].*\.go:[0-9]*:[0-9]*:" ${LOGFILE} | \
            grep -v "${NOTFAIL_EXPR}" | sed 's/:[0-9]*:[0-9]*:$//' | sort -u) )
    fi
fi

# Print summary
[[ -z ${NON_IGNORE}   ]] || echo -e "\nNew errors found in: $(printf "\n  %s" "${NON_IGNORE[@]}")"
[[ ${NUM_ERROR} == 0  ]] || echo -e "\n(${NUM_ERROR} errors${IGNORE_MSG}, logs written to ${LOGFILE})"

test $((NUM_ERROR - NUM_IGNORE)) -lt 1
