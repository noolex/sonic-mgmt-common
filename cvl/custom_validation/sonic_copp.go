////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package custom_validation

import (
	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	"strings"
)

var reserved_names = []string{
	"copp-system-lacp",
	"copp-system-udld",
	"copp-system-stp",
	"copp-system-bfd",
	"copp-system-ptp",
	"copp-system-lldp",
	"copp-system-vrrp",
	"copp-system-iccp",
	"copp-system-ospf",
	"copp-system-bgp",
	"copp-system-pim",
	"copp-system-igmp",
	"copp-system-suppress",
	"copp-system-arp",
	"copp-system-dhcp",
	"copp-system-icmp",
	"copp-system-ip2me",
	"copp-system-subnet",
	"copp-system-nat",
	"copp-system-mtu",
	"copp-system-sflow",
	"copp-system-default",
}

var allowed_attributes = []string{
	"trap_ids",
	"trap_group",
	"queue",
	"trap_priority",
	"cir",
	"cbs",
	"pir",
	"pbs",
	"meter_type",
	"mode",
	"green_action",
	"red_action",
	"yellow_action",
}

func (t *CustomValidation) ValidateCoppName(
	vc *CustValidationCtxt) CVLErrorInfo {

	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName YNodeVal: %v", vc.YNodeVal)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName YCur: %v", vc.YCur)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName Data: %v", vc.CurCfg.Data)

	if vc.CurCfg.VOp != OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	/* allow attribute delete */
	for _, allowed := range allowed_attributes {
		if _, ok := vc.CurCfg.Data[allowed]; ok {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	keys := strings.Split(vc.CurCfg.Key, "|")
	if len(keys) > 1 {
		for _, reserved := range reserved_names {
			if keys[1] == reserved {
				return CVLErrorInfo{
					ErrCode:          CVL_SEMANTIC_ERROR,
					TableName:        keys[0],
					Keys:             keys,
					ConstraintErrMsg: "Reserved copp name cannot be deleted",
					ErrAppTag:        "del-not-allowed",
				}
			}
		}
	}
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName delete operation success")
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
