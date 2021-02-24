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
	"strconv"
)

func (t *CustomValidation) ValidateSagMac(vc *CustValidationCtxt) CVLErrorInfo {
	var valid bool
  keys :=  vc.YNodeVal
	gwmac :=  vc.CurCfg.Data["gwmac"]

	log.Info("ValidateSagMac op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data)

	if vc.CurCfg.VOp == OP_DELETE || len(gwmac) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	if keys == "00:00:00:00:00:00" {
		valid = false
	} else if keys == "ff:ff:ff:ff:ff:ff" {
		valid = false
	} else {
		macSplit := strings.Split(keys, ":")
		macHi, err := strconv.ParseUint(macSplit[0], 16, 8)
		if err != nil {
			valid = false
		} else if macHi & 0x01 == 0x01 {
			valid = false
		} else {
			valid = true
		}
	}

	if (!valid) {
		errStr:= "SAG MAC is not valid, it is either zero, multicast, or broadcast"
		util.CVL_LEVEL_LOG(util.ERROR,"%s",errStr)
		return CVLErrorInfo {
			ErrCode: CVL_SYNTAX_INVALID_INPUT_DATA,
			TableName: "SAG_GLOBAL",
			CVLErrDetails : errStr,
			ConstraintErrMsg : errStr,
		}
	}

	tblName := "SAG_GLOBAL" + "|" + "IP"

	tableData, err:= vc.RClient.HGetAll(tblName).Result()

	log.Info("tableData: ", tableData)

	if (err != nil) || (vc.SessCache == nil) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	dbMac, dbExist := tableData["gwmac"]

	if dbExist {
		log.Info("Existing MAC: ", dbMac)
		errStr:= "SAG MAC cannot be changed/reconfigured, unconfigure and configure SAG MAC"
		util.CVL_LEVEL_LOG(util.ERROR,"%s",errStr)
		return CVLErrorInfo {
			ErrCode: CVL_SYNTAX_INVALID_INPUT_DATA,
			TableName: "SAG_GLOBAL",
			CVLErrDetails : errStr,
			ConstraintErrMsg : errStr,
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}


func (t *CustomValidation) ValidateSagIp(vc *CustValidationCtxt) CVLErrorInfo {
	gwipData :=  vc.CurCfg.Data["gwip@"]
	keyName := vc.CurCfg.Key
	keyNameSplit := strings.Split(keyName, "|")
	ifName := keyNameSplit[1]

	log.Info("ValidateSagIp op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data)

	if vc.CurCfg.VOp == OP_DELETE || len(gwipData) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	tblNameExt := "VLAN_INTERFACE" + "|" + ifName + "|" + "*"

	tableKeys, err:= vc.RClient.Keys(tblNameExt).Result()

	if (err != nil) || (vc.SessCache == nil) {
		log.Info("ValidateSagIp interface IP is empty")
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

    if len(tableKeys) >= 1 {
        errStr := "Anycast IP configuration is not allowed in presence of interface IP"
        log.Error(errStr)
        return CVLErrorInfo {
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: keyName,
            CVLErrDetails: errStr,
            ConstraintErrMsg: errStr,
        }
    }

	gwips := strings.Split(gwipData, ",")
	for _, gwip := range(gwips)	{

		gwIpSplit := strings.Split(gwip, "/")

		for _, dbKey := range tableKeys {
			ifKeySplit := strings.Split(dbKey, "|")

			ifIpSplit := strings.Split(ifKeySplit[2], "/")

			if ((gwIpSplit[0] == ifIpSplit[0]) && (gwIpSplit[1] == ifIpSplit[1])) {

				log.Info("Anycast address cannot be same as interface address")
				errStr := "Anycast address cannot be same as interface address"
				return CVLErrorInfo {
					ErrCode: CVL_SEMANTIC_ERROR,
					TableName: keyNameSplit[0],
					CVLErrDetails: errStr,
					ConstraintErrMsg: errStr,
				}
			}
		}
	}

	if strings.Contains(ifName, ".") {

		vlan_subif_table := "VLAN_SUB_INTERFACE"

		vlan_subif_key := vlan_subif_table + "|" + ifName

		vlan_subif_data, err := vc.RClient.HGetAll(vlan_subif_key).Result()
		if (err != nil) || (vc.SessCache == nil) {
			errStr := "Configure subinterface and vlan id before configuring VRRP"
			return CVLErrorInfo{
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: keyNameSplit[0],
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}

		_, has_vlanid := vlan_subif_data["vlan"]

		if !has_vlanid {
			errStr := "Configure  vlan id on interface before configuring SAG IP"
			return CVLErrorInfo{
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: keyNameSplit[0],
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
