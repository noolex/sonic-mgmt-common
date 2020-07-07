////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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
	log "github.com/golang/glog"
	"net"
)

func (t *CustomValidation) ValidateVipSubnet(vc *CustValidationCtxt) CVLErrorInfo {

	log.Info("ValidateVipSubnet op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data)

	keyName := vc.CurCfg.Key
	keyNameSplit := strings.Split(keyName, "|")
	vrrpTable := keyNameSplit[0]
	ifName := keyNameSplit[1]
	vipData := vc.CurCfg.Data["vip@"]
	tblName := ""

	if vc.CurCfg.VOp == OP_DELETE || len(vipData) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	log.Info("keyName:", keyName, " vrrpTable:", vrrpTable, " ifName:", ifName, " vipData:", vipData)

  if strings.HasPrefix(ifName, "Ethernet") {
		tblName = "INTERFACE"
	} else if strings.HasPrefix(ifName, "Vlan") {
		tblName = "VLAN_INTERFACE"
	} else if strings.HasPrefix(ifName, "PortChannel") {
		tblName = "PORTCHANNEL_INTERFACE"
	} else {
		util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "VIP not allowed on this type of interface")
		errStr := "VIP not allowed on this type of interface"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: vrrpTable,
			CVLErrDetails: errStr,
			ConstraintErrMsg: errStr,
		}
	}

	var vipSuffix string

	if vrrpTable == "VRRP" {
		vipSuffix = "/32"
	} else {
		vipSuffix = "/128"
	}

	tblNameExt := tblName + "|" + ifName + "|" + "*"

	tableKeys, err:= vc.RClient.Keys(tblNameExt).Result()

	if (err != nil) || (vc.SessCache == nil) {
		log.Info("ValidateVipSubnet interface IP is empty")
		errStr := "Interface does not have IP"
		return CVLErrorInfo {
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: vrrpTable,
			CVLErrDetails: errStr,
			ConstraintErrMsg: errStr,
		}
	}

	ipLLStr := "fe80::/10"
	_, ipNetLL, _ := net.ParseCIDR(ipLLStr)

	vips := strings.Split(vipData, ",")
	for _, vip := range(vips)	{

		vip = vip + vipSuffix
		ipB, _, perr := net.ParseCIDR(vip)

		if ipB == nil || perr != nil {
			continue
		}

	  var found bool = false

		for _, dbKey := range tableKeys {
			ifKeySplit := strings.Split(dbKey, "|")

			ipA, ipNetA, perr := net.ParseCIDR(ifKeySplit[2])

			if ipA == nil || perr != nil {
					continue
			}

			if ipNetA.Contains(ipB) || ipNetLL.Contains(ipB) {
				found = true
				break
			}
		}

		if !found {
			log.Info("ValidateVipSubnet interface overlap IP is empty")
			errStr := "Virtual IP does not belong to interface IP subnet"
			return CVLErrorInfo {
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: vrrpTable,
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
