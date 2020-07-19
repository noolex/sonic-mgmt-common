#!/usr/bin/env bash
################################################################################
#                                                                              #
#  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or   #
#  its subsidiaries.                                                           #
#                                                                              #
#  Licensed under the Apache License, Version 2.0 the ("License");             #
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

[[ -z $PYANG ]] && PYANG=pyang || true

REPO=""
if [[ $# -eq 0 ]]; then
	REPO=`git rev-parse --show-toplevel`
	if [[ $? != 0 ]]; then
		echo "MGMT_COMMON_REPO cannot be determined, please pass as first argument to script"
		exit 1
	fi
else
	REPO=$1
	if [[ ! -d $REPO ]]; then
		echo "$REPO does not exists"
		exit 2
	fi
fi

if [[ "$REPO" != *sonic-mgmt-common ]]; then
	echo "This script is tailored to work with sonic-mgmt-common repo only"
	exit 3
fi

YANGDIR=$REPO/models/yang
YANGDIR_COMMON=$YANGDIR/common
YANGDIR_EXTENSIONS=$YANGDIR/extensions

YANG_MOD_FILES=`find $YANGDIR -maxdepth 1 -name '*.yang' | sort`
YANG_MOD_EXTENSION_FILES=`find $YANGDIR_EXTENSIONS -maxdepth 1 -name '*.yang' | sort`
YANG_IETF_MOD_EXT_FILES=`find $YANGDIR_EXTENSIONS -maxdepth 1 -name 'ietf-*.yang' | sort`
PYANG_PLUGIN_DIR=$REPO/tools/pyang/pyang_plugins
exit_code=0

# Execute tools
# check for upgrade issues
echo "Starting YANG upgrade check ...."
$PYANG -f upcheck --ignore-errors --yang-dir $YANGDIR --plugindir $PYANG_PLUGIN_DIR \
	-p $YANGDIR_COMMON:$YANGDIR:$YANGDIR_EXTENSIONS $YANG_MOD_FILES \
	$YANG_MOD_EXTENSION_FILES
if [[ $? != 0 ]]; then
	exit_code=1
fi
echo "++++++ Upgrade check completed ++++++"

# check for openconfig issues
echo "Starting OpenConfig YANG style check ...."
$PYANG -f stcheck --ignore-errors --extensiondir $YANGDIR_EXTENSIONS \
	--plugindir $PYANG_PLUGIN_DIR \
	-p $YANGDIR_COMMON:$YANGDIR:$YANGDIR_EXTENSIONS $YANG_MOD_FILES \
	$YANG_MOD_EXTENSION_FILES
if [[ $? != 0 ]]; then
	exit_code=1
fi
echo "++++++ OpenConfig style check completed ++++++"

# check for lint-strict issues
echo "Starting YANG lint-strict check ...."
$PYANG --strict --lint --extensiondir $YANGDIR_EXTENSIONS \
	--plugindir $PYANG_PLUGIN_DIR -f strictlint \
	-p $YANGDIR_COMMON:$YANGDIR:$YANGDIR_EXTENSIONS \
	$YANG_MOD_EXTENSION_FILES 2> /dev/null
if [[ $? != 0 ]]; then
	exit_code=1
fi
echo "++++++ lint-check check completed ++++++"

# check for IETF issues
echo "Starting YANG IETF check ...."
$PYANG --ietf --plugindir $PYANG_PLUGIN_DIR -f strictlint \
	-p $YANGDIR_COMMON:$YANGDIR:$YANGDIR_EXTENSIONS $YANG_IETF_MOD_EXT_FILES 2> /dev/null
if [[ $? != 0 ]]; then
	exit_code=1
fi
echo "++++++ IETF check completed ++++++"

# TODO: exit with actual code when strict check is enabled
exit_code=0

echo "Exiting with code $exit_code"
exit $exit_code
