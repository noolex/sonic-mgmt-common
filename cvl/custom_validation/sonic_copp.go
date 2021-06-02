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
	"strings"

	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
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
	"copp-system-dhcpl2",
	"default",
}

var Copp_trap_id_valid = map[string][]string{
	"ttl_error":       {"trap", "drop"},
	"lacp":            {"trap", "drop"},
	"bgp":             {"trap", "drop"},
	"bgpv6":           {"trap", "drop"},
	"dhcp":            {"trap", "drop"},
	"dhcpv6":          {"trap", "drop"},
	"ssh":             {"trap", "copy", "drop"},
	"snmp":            {"trap", "drop"},
	"neigh_discovery": {"trap", "copy", "drop"},
	"arp_req":         {"trap", "copy", "drop"},
	"arp_resp":        {"trap", "copy", "drop"},
	"lldp":            {"trap", "drop"},
	"ip2me":           {"trap", "copy", "drop"},
	"sample_packet":   {"trap", "drop"},
	"udld":            {"trap", "drop"},
	"subnet":          {"trap", "copy", "drop"},
	"l3_mtu_error":    {"trap", "drop"},
	"igmp_query":      {"trap", "drop"},
	"bfd":             {"trap", "drop"},
	"bfdv6":           {"trap", "drop"},
	"stp":             {"trap", "drop"},
	"pvrst":           {"trap", "drop"},
	"src_nat_miss":    {"trap", "drop"},
	"dest_nat_miss":   {"trap", "drop"},
	"ptp":             {"trap", "drop"},
	"vrrp":            {"trap", "drop"},
	"vrrpv6":          {"trap", "drop"},
	"pim":             {"trap", "copy", "drop"},
	"arp_suppress":    {"trap"},
	"nd_suppress":     {"trap"},
	"ospf":            {"trap", "copy", "drop"},
	"iccp":            {"trap", "drop"},
	"icmp":            {"trap", "drop"},
	"icmpv6":          {"trap", "drop"},
	"dhcp_l2":         {"trap", "drop"},
	"dhcpv6_l2":       {"trap", "drop"},
}

func (t *CustomValidation) ValidateCoppName(
	vc *CustValidationCtxt) CVLErrorInfo {
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

	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName YNodeVal: %v", vc.YNodeVal)
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
	if keys[0] == "COPP_TRAP" {
		entry, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
		if err == nil {
			/* check if trap_group attribute is present */
			if trap_group, found_field := entry["trap_group"]; found_field {
				if trap_group != "NULL" {
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						TableName:        keys[0],
						Keys:             keys,
						ConstraintErrMsg: "Delete of traps that are still bound is not allowed",
						ErrAppTag:        "del-not-allowed",
					}
				}
			}
		}
	}

	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppName delete operation success")
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) ValidateCoppTrapAction(
	vc *CustValidationCtxt) CVLErrorInfo {

	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapAction operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapAction key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapAction YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapAction YNodeVal: %v", vc.YNodeVal)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapAction YCur: %v", vc.YCur)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapAction Data: %v", vc.CurCfg.Data)

	if vc.CurCfg.VOp == OP_DELETE || len(vc.YNodeVal) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	/* get all COPP_TRAP entries */
	keys, err := vc.RClient.Keys("COPP_TRAP|*").Result()
	if err == nil {
		for _, key := range keys {
			/* for each COPP_TRAP entry found */
			entry, err := vc.RClient.HGetAll(key).Result()
			if err == nil {
				/* check if trap_group attribute is present */
				if trap_group_name, found_field := entry["trap_group"]; found_field {
					/* if trap_group matches name */
					if strings.Split(vc.CurCfg.Key, "|")[1] == trap_group_name {
						/* check if trap_ids is present */
						if str_val, found_field := entry["trap_ids"]; found_field {
							trap_ids := strings.Split(str_val, ",")
							/* for each trap_id */
							for _, trap_id := range trap_ids {
								/* check if action is allowed */
								found := false
								for _, action := range Copp_trap_id_valid[trap_id] {
									if action == vc.YNodeVal {
										found = true
										break
									}
								}
								if !found {
									return CVLErrorInfo{
										ErrCode:          CVL_SEMANTIC_ERROR,
										TableName:        keys[0],
										Keys:             keys,
										ConstraintErrMsg: "The trap_action is not supported for the associated trap_ids",
										ErrAppTag:        "not-supported",
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) ValidateCoppTrapBound(
	vc *CustValidationCtxt) CVLErrorInfo {

	util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateCoppTrapBound operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapBound key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapBound YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapBound YNodeVal: %v", vc.YNodeVal)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapBound YCur: %v", vc.YCur)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapBound Data: %v", vc.CurCfg.Data)

	if vc.CurCfg.VOp == OP_DELETE && len(vc.CurCfg.Data) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	var allowed_attributes = []string{
		"name",
		"trap_ids",
		"trap_action",
		"queue",
		"trap_priority",
		"cir",
		"cbs",
		"pir",
		"pbs",
		"meter_type",
	}

	for _, allowed := range allowed_attributes {
		if _, ok := vc.CurCfg.Data[allowed]; ok {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	keys, err := vc.RClient.Keys("COPP_TRAP|*").Result()
	if vc.YNodeVal != "" {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        keys[0],
			Keys:             keys,
			ConstraintErrMsg: "Mode/Red/Green/Yellow operations are not supported in this release",
			ErrAppTag:        "not-supported",
		}
	}

	/* get all COPP_TRAP entries */
	if err == nil {
		for _, key := range keys {
			/* for each COPP_TRAP entry found */
			entry, err := vc.RClient.HGetAll(key).Result()
			if err == nil {
				if trap_group_name, found_field := entry["trap_group"]; found_field {
					/* if trap_group matches name */
					if strings.Split(vc.CurCfg.Key, "|")[1] == trap_group_name {
						return CVLErrorInfo{
							ErrCode:          CVL_SEMANTIC_ERROR,
							TableName:        keys[0],
							Keys:             keys,
							ConstraintErrMsg: "Mode/Red/Green/Yellow action updates/deletes are not allowed when group is bound to this trap",
							ErrAppTag:        "not-supported",
						}
					}
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func check_trap_id_valid(trap_id string) bool {
	_, found := Copp_trap_id_valid[trap_id]
	return found
}

func (t *CustomValidation) ValidateCoppTrapIds(
	vc *CustValidationCtxt) CVLErrorInfo {

	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds YNodeVal: %v", vc.YNodeVal)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds YCur: %v", vc.YCur)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds Data: %v", vc.CurCfg.Data)

	var allowed_attributes = []string{
		"name",
		"trap_group",
	}

	for _, allowed := range allowed_attributes {
		if _, ok := vc.CurCfg.Data[allowed]; ok {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	keys := strings.Split(vc.CurCfg.Key, "|")
	if vc.CurCfg.VOp == OP_DELETE {
		for _, reserved := range reserved_names {
			if keys[1] == reserved {
				return CVLErrorInfo{
					ErrCode:          CVL_SEMANTIC_ERROR,
					TableName:        keys[0],
					Keys:             keys,
					ConstraintErrMsg: "Trap-ids of reserved traps cannot be deleted",
					ErrAppTag:        "del-not-allowed",
				}
			}
		}
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	inval := vc.CurCfg.Data["trap_ids"]

	if inval != "" {
		trap_ids := strings.Split(inval, ",")
		trap_action := ""
		cfg_trap_ids := ""

		/* retrieve trap_action from associated COPP_GROUP */
		entry, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
		if err == nil {
			util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds found %v", vc.CurCfg.Key)
			if trap_group, found_field := entry["trap_group"]; found_field {
				util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds found %v trap_group", vc.CurCfg.Key)
				entry2, err2 := vc.RClient.HGetAll("COPP_GROUP|" + trap_group).Result()
				if err2 == nil {
					util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds found COPP_GROUP|%v", trap_group)
					if str_val, found_field := entry2["trap_action"]; found_field {
						trap_action = str_val
						util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds found COPP_GROUP|%v trap_action", trap_group)
						util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapIds trap_action %v", trap_action)
					}
				}
			}
			cfg_trap_ids = entry["trap_ids"]
		}
		for _, trap_id := range trap_ids {
			if !check_trap_id_valid(trap_id) {
				return CVLErrorInfo{
					ErrCode:          CVL_SEMANTIC_ERROR,
					TableName:        keys[0],
					Keys:             keys,
					ConstraintErrMsg: "Invalid value passed for trap-ids",
					ErrAppTag:        "invalid-value",
				}
			}
			if trap_action != "" {
				found := false
				for _, trap := range Copp_trap_id_valid[trap_id] {
					if trap == trap_action {
						found = true
						break
					}
				}
				if !found {
					err_str := "Trap_id " + trap_id + " does not support trap_action " + trap_action
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						TableName:        keys[0],
						Keys:             keys,
						ConstraintErrMsg: err_str,
						ErrAppTag:        "invalid-value",
					}
				}
			}
		}
		/* for reserved names, check if operation tries to remove trap_id from list */
		if len(keys) > 1 {
			for _, reserved := range reserved_names {
				if keys[1] == reserved && cfg_trap_ids != "" {
					for _, cfg := range strings.Split(cfg_trap_ids, ",") {
						found := false
						for _, trap_id := range trap_ids {
							if cfg == trap_id {
								found = true
								break
							}
						}
						if !found {
							err_str := "Cannot remove trap-id " + cfg + " from reserved trap " + keys[1]
							return CVLErrorInfo{
								ErrCode:          CVL_SEMANTIC_ERROR,
								TableName:        keys[0],
								Keys:             keys,
								ConstraintErrMsg: err_str,
								ErrAppTag:        "del-not-allowed",
							}
						}
					}
				}
			}
		}
	}
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) ValidateCoppTrapGroup(
	vc *CustValidationCtxt) CVLErrorInfo {

	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup YNodeVal: %v", vc.YNodeVal)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup YCur: %v", vc.YCur)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup Data: %v", vc.CurCfg.Data)

	var allowed_attributes = []string{
		"name",
		"trap_ids",
	}

	for _, allowed := range allowed_attributes {
		if _, ok := vc.CurCfg.Data[allowed]; ok {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	keys := strings.Split(vc.CurCfg.Key, "|")
	if keys[1] == "default" && vc.YNodeVal != "default" {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        keys[1],
			Keys:             keys,
			ConstraintErrMsg: "default group can only be bound to default trap",
			ErrAppTag:        "invalid-value",
		}
	}

	if vc.YNodeVal == "default" && keys[1] != "default" {
		err_str := strings.Split(vc.CurCfg.Key, "|")[1] + " cannot be bound to default trap"
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        keys[1],
			Keys:             keys,
			ConstraintErrMsg: err_str,
			ErrAppTag:        "invalid-value",
		}
	}

	trap_group := vc.CurCfg.Data["trap_group"]

	if trap_group != "" && trap_group != "NULL" {
		entry, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
		if err == nil {
			util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup found %v", vc.CurCfg.Key)
			if trap_ids, found_field := entry["trap_ids"]; found_field {
				util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup found %v trap_ids %v", vc.CurCfg.Key, trap_ids)
				entry2, err2 := vc.RClient.HGetAll("COPP_GROUP|" + trap_group).Result()
				util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup len(entry2) %v", len(entry2))
				if err2 == nil && len(entry2) != 0 {
					util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup found COPP_GROUP|%v", trap_group)
					if trap_action, found_field := entry2["trap_action"]; found_field {
						util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup found COPP_GROUP|%v trap_action", trap_group)
						util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppTrapGroup trap_action %v", trap_action)

						for _, trap_id := range strings.Split(trap_ids, ",") {
							found := false
							for _, trap := range Copp_trap_id_valid[trap_id] {
								if trap == trap_action {
									found = true
									break
								}
							}
							if !found {
								err_str := "The trap_group trap_action setting is not compatible with the trap_id entry " + trap_id
								return CVLErrorInfo{
									ErrCode:          CVL_SEMANTIC_ERROR,
									TableName:        keys[1],
									Keys:             keys,
									ConstraintErrMsg: err_str,
									ErrAppTag:        "invalid-value",
								}
							}
						}
					}
				} else {
					if len(entry2) == 0 {
						return CVLErrorInfo{
							ErrCode:          CVL_SEMANTIC_ERROR,
							TableName:        keys[1],
							Keys:             keys,
							ConstraintErrMsg: "trap_group does not exist",
							ErrAppTag:        "invalid-value",
						}
					}
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) ValidateCoppNotSupported(
	vc *CustValidationCtxt) CVLErrorInfo {

	util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateCoppNotSupported operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppNotSupported key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppNotSupported YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppNotSupported YNodeVal: %v", vc.YNodeVal)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppNotSupported YCur: %v", vc.YCur)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateCoppNotSupported Data: %v", vc.CurCfg.Data)

	var attributes = []string{
		"pir",
		"pbs",
	}

	for _, attrib := range attributes {
		if _, ok := vc.CurCfg.Data[attrib]; ok {
			return CVLErrorInfo{
				ErrCode:          CVL_SEMANTIC_ERROR,
				TableName:        "COPP_GROUP",
				Keys:             strings.Split(vc.CurCfg.Key, "|"),
				ConstraintErrMsg: "pir/pbs operations are not supported in this release",
				ErrAppTag:        "not-supported",
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
