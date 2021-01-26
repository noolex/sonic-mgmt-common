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
	var owner bool = false

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
	} else if strings.HasPrefix(ifName, "Eth") {
		tblName = "VLAN_SUB_INTERFACE"
	} else if strings.HasPrefix(ifName, "Po") {
		tblName = "VLAN_SUB_INTERFACE"
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

		if ipNetLL.Contains(ipB) {
			continue
		}

	  var found bool = false

		for _, dbKey := range tableKeys {
			ifKeySplit := strings.Split(dbKey, "|")

			ipA, ipNetA, perr := net.ParseCIDR(ifKeySplit[2])

			if ipA == nil || perr != nil {
					continue
			}

			if ipB.Equal(ipA) {
				owner = true
			}

			if ipNetA.Contains(ipB) {
				found = true
				break
			}

		}

		if !found {
			log.Info("ValidateVipSubnet interface overlap IP is empty")
			errStr := "Virtual IP does not belong to interface IP subnet"
			return CVLErrorInfo {
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: "VRRP",
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}
	}

	if owner {
		ret, errStr := vrrp_is_valid_owner(vc, vrrpTable, ifName, keyNameSplit[2])

		if !ret {
			return CVLErrorInfo {
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: "VRRP",
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func vrrp_is_vip_owner(vc *CustValidationCtxt, vrrp_table string, vrrp_if_name string, vrid string) bool {
	var if_tbl string


  if strings.HasPrefix(vrrp_if_name, "Ethernet") {
		if_tbl = "INTERFACE"
	} else if strings.HasPrefix(vrrp_if_name, "Vlan") {
		if_tbl = "VLAN_INTERFACE"
	} else if strings.HasPrefix(vrrp_if_name, "PortChannel") {
		if_tbl = "PORTCHANNEL_INTERFACE"
	} else if strings.HasPrefix(vrrp_if_name, "Eth") {
		if_tbl = "VLAN_SUB_INTERFACE"
	} else if strings.HasPrefix(vrrp_if_name, "Po") {
		if_tbl = "VLAN_SUB_INTERFACE"
	} else {
		return false
	}

	if_tbl_ext := if_tbl + "|" + vrrp_if_name + "|" + "*"

	table_keys, err:= vc.RClient.Keys(if_tbl_ext).Result()

	if (err != nil) || (vc.SessCache == nil) {
		return false
	}

	var vip_suffix string

	if vrrp_table == "VRRP" {
		vip_suffix = "/32"
	} else {
		vip_suffix = "/128"
	}

  vrrp_key := vrrp_table + "|" + vrrp_if_name + "|" + vrid

	vrrp_data, err := vc.RClient.HGetAll(vrrp_key).Result()
	if (err != nil) || (vc.SessCache == nil) {
		return false
	}

	vip_data := vrrp_data["vip@"]

	vips := strings.Split(vip_data, ",")
	for _, vip := range(vips)	{

		vip = vip + vip_suffix

		ipA, _, perr := net.ParseCIDR(vip)

		if ipA == nil || perr != nil {
			continue
		}

		for _, db_key := range table_keys {
			if_key_split := strings.Split(db_key, "|")

			ipB, _, perr := net.ParseCIDR(if_key_split[2])

			if ipB == nil || perr != nil {
					continue
			}

			if ipA.Equal(ipB) {
				return true
			}
		}
	}

	return false
}

func vrrp_is_valid_owner(vc *CustValidationCtxt, vrrp_table string, vrrp_if_name string, vrid string) (bool, string) {
	var ret string = "Success"
	var vrrp_track_table string
	vrrp_key := vrrp_table + "|" + vrrp_if_name + "|" + vrid


	vrrp_data, err := vc.RClient.HGetAll(vrrp_key).Result()
	if (err != nil) || (vc.SessCache == nil) {
		return true, ret
	}

	_, has_data := vrrp_data["priority"]

	if has_data {
		ret = "Remove priority before configuring VIP as owner"
		return false, ret
	}

	data, has_data := vrrp_data["pre_empt"]

	if has_data && data == "False"{
		ret = "Enable preempt before configuring VIP as owner"
		return false, ret
	}

	vip := vc.CurCfg.Data["vip@"]

	if strings.Contains(vip, ",") {
		ret = "Cannot have more than one VIP in case of owner"
		return false, ret
	}


	if vrrp_table == "VRRP" {
		vrrp_track_table = "VRRP_TRACK"
	} else {
		vrrp_track_table = "VRRP6_TRACK"
	}

	track_table_ext := vrrp_track_table + "|" + vrrp_if_name + "|" + vrid + "|" + "*"

	track_table_keys, err:= vc.RClient.Keys(track_table_ext).Result()

	if (err != nil) || (vc.SessCache == nil) {
		return true, ret
	}

	if len(track_table_keys) > 0 {
		ret = "Remove track interfaces before configuring VIP as owner"
		return false, ret
	}

	return true, ret

}

func (t *CustomValidation) ValidatePreempt(vc *CustValidationCtxt) CVLErrorInfo {
	preempt_val :=  vc.CurCfg.Data["pre_empt"]
	key := vc.CurCfg.Key
	key_split := strings.Split(key, "|")

	log.Info("ValidatePreempt op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data)

	var owner bool = false

	if ((len(preempt_val) == 0) || ((vc.CurCfg.VOp != OP_DELETE) && (preempt_val == "True"))) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

  owner = vrrp_is_vip_owner(vc, key_split[0], key_split[1], key_split[2])

	if owner {
		log.Info("ValidatePreempt owner ip exist")
		errStr := "Preempt cannot be disabled for owner case"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "VRRP",
			CVLErrDetails: errStr,
			ConstraintErrMsg: errStr,
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}

}

func (t *CustomValidation) ValidateTrack(vc *CustValidationCtxt) CVLErrorInfo {
	var owner bool = false
	var vrrp_table string
	key := vc.CurCfg.Key
	key_split := strings.Split(key, "|")
	track_table := key_split[0]

	log.Info("ValidateTrack op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data)

	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	if track_table == "VRRP_TRACK" {
		vrrp_table = "VRRP"
	} else {
		vrrp_table = "VRRP6"
	}

	owner = vrrp_is_vip_owner(vc, vrrp_table, key_split[1], key_split[2])

	if owner {
		log.Info("ValidateTrack owner ip exist")
		errStr := "Track interface cannot be configured for owner case"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: vrrp_table,
			CVLErrDetails: errStr,
			ConstraintErrMsg: errStr,
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}

}

func (t *CustomValidation) ValidatePriority(vc *CustValidationCtxt) CVLErrorInfo {
	priority_val :=  vc.CurCfg.Data["priority"]
	key := vc.CurCfg.Key
	key_split := strings.Split(key, "|")

	log.Info("ValidatePreempt op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data)

	var owner bool = false

	if vc.CurCfg.VOp == OP_DELETE || len(priority_val) == 0{
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

  owner = vrrp_is_vip_owner(vc, key_split[0], key_split[1], key_split[2])

	if owner {
		log.Info("ValidatePreempt owner ip exist")
		errStr := "Priority cannot be configured for owner case"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "VRRP",
			CVLErrDetails: errStr,
			ConstraintErrMsg: errStr,
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}

}

func (t *CustomValidation) ValidateVrrp(vc *CustValidationCtxt) CVLErrorInfo {
	key := vc.CurCfg.Key
	key_split := strings.Split(key, "|")

	log.Info("ValidateVrrp op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data)

	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	if strings.Contains(key_split[1], ".") {

		vlan_subif_table := "VLAN_SUB_INTERFACE"
		vlan_subif_ip_key := vlan_subif_table + "|" + key_split[1] + "|*"

		vlan_subif_ips, err := vc.RClient.Keys(vlan_subif_ip_key).Result()
		if (err != nil) || (vc.SessCache == nil) {
			errStr := "Configure interface IP before configuring VRRP"
			return CVLErrorInfo{
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: "VRRP",
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}

		if len(vlan_subif_ips) <= 0 {
			errStr := "Configure interface IP before configuring VRRP"
			return CVLErrorInfo{
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: "VRRP",
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}

		vlan_subif_key := vlan_subif_table + "|" + key_split[1]

		vlan_subif_data, err := vc.RClient.HGetAll(vlan_subif_key).Result()
		if (err != nil) || (vc.SessCache == nil) {
			errStr := "Configure subinterface and vlan id before configuring VRRP"
			return CVLErrorInfo{
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: "VRRP",
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}

		_, has_vlanid := vlan_subif_data["vlan"]

		if has_vlanid {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		} else {
			errStr := "Configure  vlan id on interface before configuring VRRP"
			return CVLErrorInfo{
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: "VRRP",
				CVLErrDetails: errStr,
				ConstraintErrMsg: errStr,
			}
		}
	}else {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
}
