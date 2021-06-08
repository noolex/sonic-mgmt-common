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

TOPDIR=$(git rev-parse --show-toplevel)
GO=${GO:-go}

TARGS=( -mod=vendor -v -cover )
PARGS=()
PKG=translib
TAG=test

while [[ $# -gt 0 ]]; do
    case "$1" in
    -h|-help|--help)
        echo "usage: $(basename $0) [-pkg PACKAGE] [-run TESTNAME|-bench PATTERN] [-json] [ARGS...]"
        exit 0;;
    -p|-pkg|-package) PKG=$2; shift 2;;
    -r|-run)   TARGS+=( -run "$2" ); shift 2;;
    -b|-bench) TARGS+=( -bench "$2" -run XXX ); shift 2;;
    -j|-json)  TARGS+=( -json ); shift;;
    -nosub)    NOSUBSCRIBE=1; shift;;
    *) PARGS+=( "$1"); shift;;
    esac
done

cd ${TOPDIR}
if [[ ! -d ${PKG} ]] && [[ -d translib/${PKG} ]]; then
    PKG=translib/${PKG}
fi

if [[ -z ${GOPATH} ]]; then
    export GOPATH=/tmp/go
fi

# cvl schema
if [[ -z ${CVL_SCHEMA_PATH} ]]; then
    export CVL_SCHEMA_PATH=${TOPDIR}/build/cvl/schema
fi

# db config file
if [[ -z ${DB_CONFIG_PATH} ]]; then
    export DB_CONFIG_PATH=${TOPDIR}/tools/test/database_config.json
fi

# yang files
if [[ -z ${YANG_MODELS_PATH} ]]; then
    export YANG_MODELS_PATH=${TOPDIR}/build/all_test_yangs
    ${TOPDIR}/tools/test/yangpath_init.sh
fi

# Include extra annotations for translib package
if [[ ${PKG} == translib ]] && [[ -z ${NOSUBSCRIBE} ]]; then
    TAG+=',subscribe_annot'
    for F in $(find models/yang/testdata -name '*-annot.subscribe'); do
        ANNOT=${YANG_MODELS_PATH}/$(basename $F .subscribe).yang
        [[ -f ${ANNOT} ]] || continue
        # Remove last '}' from xxxx-annot.yang and append xxxx-annot.subscribe contents.
        # Assumes there are no comments after the last '}'.
        tac ${ANNOT} | awk 'NF {p=1} p' | tac | sed '$s/}\s*$//' > ${ANNOT}.tmp
        echo -e "\n//===== subscribe test annotations =====\n" >> ${ANNOT}.tmp
        cat $F >> ${ANNOT}.tmp
        echo -e "\n}" >> ${ANNOT}.tmp
        mv ${ANNOT}.tmp ${ANNOT}
    done
fi

[[ -z ${TAG} ]] || TARGS+=( -tags ${TAG} )
[[ "${PARGS[@]}" =~ -(also)?log* ]] || PARGS+=( -logtostderr )

set -x
${GO} test ./${PKG} "${TARGS[@]}" -args "${PARGS[@]}"
