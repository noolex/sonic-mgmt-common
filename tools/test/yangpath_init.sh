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

SRCDIR=$(dirname ${BASH_SOURCE[0]})
TOPDIR=$(git -C ${SRCDIR} rev-parse --show-toplevel)
V=

while [[ $# -gt 0 ]]; do
case "$1" in
    -h|-help|--help)
        echo "$(basename $0) copies yangs and related config files to YANG_MODELS_PATH dirctory."
        echo "Current YANG_MODELS_PATH value is \"${YANG_MODELS_PATH}\""
        exit 0;;
    -v|-verbose|--verbose)
        V="-v"
        shift;;
esac
done

if [[ -z ${YANG_MODELS_PATH} ]]; then
    echo "error: YANG_MODELS_PATH not set"
    exit 1
fi
if [[ ! -f ${TOPDIR}/build/yang/.patchdone ]]; then
    echo "error: yangs are not patched!"
    exit 1
fi

mkdir -p $V ${YANG_MODELS_PATH}
pushd ${YANG_MODELS_PATH} > /dev/null
rm -rf *
PREFIX=$(realpath --relative-to=$PWD ${TOPDIR})
find ${PREFIX}/models/yang/sonic -name "*.yang" -exec ln $V -sf {} \;
find ${PREFIX}/models/yang/annotations -name "*.yang" -exec ln $V -sf {} \;
find ${PREFIX}/build/yang -name "*.yang" -exec ln $V -sf {} \;
ln $V -sf ${PREFIX}/models/yang/version.xml
ln $V -sf ${PREFIX}/config/transformer/models_list
ln $V -sf ${PREFIX}/config/transformer/sonic_table_info.json
popd > /dev/null
