////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom, Inc.                                             //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
	"strings"
)

func init() {
	XlateFuncBind("YangToDb_copp_trap_action_xfmr", YangToDb_copp_trap_action_xfmr)
	XlateFuncBind("DbToYang_copp_trap_action_xfmr", DbToYang_copp_trap_action_xfmr)
	XlateFuncBind("YangToDb_copp_green_action_xfmr", YangToDb_copp_green_action_xfmr)
	XlateFuncBind("DbToYang_copp_green_action_xfmr", DbToYang_copp_green_action_xfmr)
	XlateFuncBind("YangToDb_copp_yellow_action_xfmr", YangToDb_copp_yellow_action_xfmr)
	XlateFuncBind("DbToYang_copp_yellow_action_xfmr", DbToYang_copp_yellow_action_xfmr)
	XlateFuncBind("YangToDb_copp_red_action_xfmr", YangToDb_copp_red_action_xfmr)
	XlateFuncBind("DbToYang_copp_red_action_xfmr", DbToYang_copp_red_action_xfmr)
	XlateFuncBind("YangToDb_copp_meter_type_xfmr", YangToDb_copp_meter_type_xfmr)
	XlateFuncBind("DbToYang_copp_meter_type_xfmr", DbToYang_copp_meter_type_xfmr)
	XlateFuncBind("YangToDb_copp_mode_xfmr", YangToDb_copp_mode_xfmr)
	XlateFuncBind("DbToYang_copp_mode_xfmr", DbToYang_copp_mode_xfmr)
	XlateFuncBind("YangToDb_copp_trap_ids_xfmr", YangToDb_copp_trap_ids_xfmr)
	XlateFuncBind("DbToYang_copp_trap_ids_xfmr", DbToYang_copp_trap_ids_xfmr)
	XlateFuncBind("YangToDb_copp_trap_group_xfmr", YangToDb_copp_trap_group_xfmr)
	XlateFuncBind("DbToYang_copp_trap_group_xfmr", DbToYang_copp_trap_group_xfmr)
}

func getCoppRoot(s *ygot.GoStruct) *ocbinds.OpenconfigCoppExt_Copp {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.Copp
}

func trap_action_enum_to_str(input ocbinds.E_OpenconfigCoppExt_CoppTrapAction) string {
	outval := "NULL"
	switch input {
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_DROP:
		outval = "drop"
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_FORWARD:
		outval = "forward"
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_COPY:
		outval = "copy"
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_COPY_CANCEL:
		outval = "copy_cancel"
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_TRAP:
		outval = "trap"
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_LOG:
		outval = "log"
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_DENY:
		outval = "deny"
	case ocbinds.OpenconfigCoppExt_CoppTrapAction_TRANSIT:
		outval = "transit"
	}
	return outval
}

var YangToDb_copp_trap_action_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var inval ocbinds.E_OpenconfigCoppExt_CoppTrapAction
	if inParams.param == nil {
		log.Info("YangToDb_copp_trap_action_xfmr Error: ")
		return res_map, err
	}
	if inParams.oper == DELETE {
		return res_map, tlerr.InvalidArgsError{Format: "Delete operation is not supported"}
	}

	log.Info("YangToDb_copp_trap_action_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_trap_action_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_trap_action_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	field := "trap_action"
	inval = coppObj.CoppGroups.CoppGroup[name].Config.TrapAction

	outval := trap_action_enum_to_str(inval)

	/* get all COPP_TRAP entries */
	trapTbl, tblErr := inParams.d.GetTable(&db.TableSpec{Name: "COPP_TRAP"})
	if tblErr == nil {
		keys, err := trapTbl.GetKeys()
		if err == nil {
			for _, key := range keys {
				/* for each COPP_TRAP entry found */
				entry, err := trapTbl.GetEntry(key)
				if err == nil {
					/* check if trap_group attribute is present */
					if trap_group_name, found_field := entry.Field["trap_group"]; found_field {
						/* if trap_group matches name */
						if name == trap_group_name {
							/* check if trap_ids is present */
							if str_val, found_field := entry.Field["trap_ids"]; found_field {
								trap_ids := strings.Split(str_val, ",")
								/* for each trap_id */
								for _, trap_id := range trap_ids {
									/* check if action is allowed */
									found := false
									for _, action := range trap_id_valid[trap_id] {
										if action == outval {
											found = true
											break
										}
									}
									if !found {
										err_str := "The action is not supported for the associated trap_ids"
										return res_map, tlerr.InvalidArgsError{Format: err_str}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	log.Info("YangToDb_copp_trap_action_xfmr enc: ", outval, " field: ", field)
	res_map[field] = outval

	return res_map, err
}

var DbToYang_copp_trap_action_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_trap_action_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["COPP_GROUP"][inParams.key].Field["trap_action"]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result["trap-action"] = outval
	}

	return result, err
}

func isTrapTableBound(trap_group_name string, in_db *db.DB) bool {
	/* get all COPP_TRAP entries */
	trapTbl, err := in_db.GetTable(&db.TableSpec{Name: "COPP_TRAP"})
	if err == nil {
		keys, err := trapTbl.GetKeys()
		if err == nil {
			for _, key := range keys {
				/* for each COPP_TRAP entry found */
				entry, err := trapTbl.GetEntry(key)
				if err == nil {
					/* check if trap_group attribute is present */
					if name, found_field := entry.Field["trap_group"]; found_field {
						/* if trap_group matches name */
						if trap_group_name == name {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

var YangToDb_copp_green_action_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var inval ocbinds.E_OpenconfigCoppExt_CoppTrapAction
	if inParams.param == nil {
		log.Info("YangToDb_copp_green_action_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_green_action_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_green_action_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_green_action_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	field := "green_action"
	inval = coppObj.CoppGroups.CoppGroup[name].Config.GreenAction

	if isTrapTableBound(name, inParams.d) {
		return res_map, tlerr.InvalidArgsError{Format: "Green action updates are not allowed when group is bound to this trap"}
	}

	outval := trap_action_enum_to_str(inval)

	log.Info("YangToDb_copp_green_action_xfmr enc: ", outval, " field: ", field)
	res_map[field] = outval

	return res_map, err
}

var DbToYang_copp_green_action_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_green_action_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["COPP_GROUP"][inParams.key].Field["green_action"]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result["green-action"] = outval
	}

	return result, err
}

var YangToDb_copp_yellow_action_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var inval ocbinds.E_OpenconfigCoppExt_CoppTrapAction
	if inParams.param == nil {
		log.Info("YangToDb_copp_yellow_action_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_yellow_action_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_yellow_action_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_yellow_action_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	field := "yellow_action"
	inval = coppObj.CoppGroups.CoppGroup[name].Config.YellowAction

	if isTrapTableBound(name, inParams.d) {
		return res_map, tlerr.InvalidArgsError{Format: "Yellow action updates are not allowed when group is bound to this trap"}
	}

	outval := trap_action_enum_to_str(inval)

	log.Info("YangToDb_copp_yellow_action_xfmr enc: ", outval, " field: ", field)
	res_map[field] = outval

	return res_map, err
}

var DbToYang_copp_yellow_action_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_yellow_action_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["COPP_GROUP"][inParams.key].Field["yellow_action"]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result["yellow-action"] = outval
	}

	return result, err
}

var YangToDb_copp_red_action_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var inval ocbinds.E_OpenconfigCoppExt_CoppTrapAction
	if inParams.param == nil {
		log.Info("YangToDb_copp_red_action_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_red_action_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_red_action_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_red_action_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	field := "red_action"
	inval = coppObj.CoppGroups.CoppGroup[name].Config.RedAction

	if isTrapTableBound(name, inParams.d) {
		return res_map, tlerr.InvalidArgsError{Format: "Red action updates are not allowed when group is bound to this trap"}
	}

	outval := trap_action_enum_to_str(inval)

	log.Info("YangToDb_copp_red_action_xfmr enc: ", outval, " field: ", field)
	res_map[field] = outval

	return res_map, err
}

var DbToYang_copp_red_action_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_red_action_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["COPP_GROUP"][inParams.key].Field["red_action"]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result["red-action"] = outval
	}

	return result, err
}

var YangToDb_copp_meter_type_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var field string
	var inval ocbinds.E_OpenconfigCoppExt_CoppMeterType
	if inParams.param == nil {
		log.Info("YangToDb_copp_meter_type_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_meter_type_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_meter_type_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_meter_type_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	inval = coppObj.CoppGroups.CoppGroup[name].Config.MeterType
	field = "meter_type"

	outval := ""
	switch inval {
	case ocbinds.OpenconfigCoppExt_CoppMeterType_PACKETS:
		outval = "packets"
	case ocbinds.OpenconfigCoppExt_CoppMeterType_BYTES:
		outval = "bytes"
	}

	log.Info("YangToDb_copp_meter_type_xfmr enc: ", outval, " field: ", field)
	res_map[field] = outval

	return res_map, err
}

var DbToYang_copp_meter_type_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_meter_type_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["COPP_GROUP"][inParams.key].Field["meter_type"]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result["meter-type"] = outval
	}

	return result, err
}

var YangToDb_copp_mode_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var field string
	var inval ocbinds.E_OpenconfigCoppExt_CoppMode
	if inParams.param == nil {
		log.Info("YangToDb_copp_mode_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_mode_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_mode_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_mode_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	inval = coppObj.CoppGroups.CoppGroup[name].Config.Mode
	field = "mode"

	if isTrapTableBound(name, inParams.d) {
		return res_map, tlerr.InvalidArgsError{Format: "Mode updates are not allowed when group is bound to this trap"}
	}

	outval := ""
	switch inval {
	case ocbinds.OpenconfigCoppExt_CoppMode_SR_TCM:
		outval = "sr_tcm"
	case ocbinds.OpenconfigCoppExt_CoppMode_TR_TCM:
		outval = "tr_tcm"
	case ocbinds.OpenconfigCoppExt_CoppMode_STORM:
		outval = "storm"
	}

	log.Info("YangToDb_copp_mode_xfmr enc: ", outval, " field: ", field)
	res_map[field] = outval

	return res_map, err
}

var DbToYang_copp_mode_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var field, inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_mode_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	field = "mode"
	inval = data["COPP_GROUP"][inParams.key].Field[field]

	outval := strings.ToUpper(inval)

	if outval != "" {
		result[field] = outval
	}

	return result, err
}

var trap_id_valid = map[string][]string{
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
	"?":               {"trap", "drop"},
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
}

func check_trap_id_valid(trap_id string) bool {
	_, found := trap_id_valid[trap_id]
	return found
}

var YangToDb_copp_trap_ids_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var field string
	var inval string
	if inParams.param == nil {
		log.Info("YangToDb_copp_trap_ids_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_trap_ids_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_trap_ids_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_trap_ids_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	inval = *coppObj.CoppTraps.CoppTrap[name].Config.TrapIds
	field = "trap_ids"

	if inval != "" {
		trap_ids := strings.Split(inval, ",")
		trap_action := ""

		/* retrieve trap_action from associated COPP_GROUP */
		entry, err := inParams.d.GetEntry(&db.TableSpec{Name: "COPP_TRAP"}, db.Key{[]string{name}})
		if err == nil {
			log.Info("YangToDb_copp_trap_ids_xfmr found COPP_TRAP|", name)
			if entry.Has("trap_group") {
				log.Info("YangToDb_copp_trap_ids_xfmr found COPP_TRAP|", name, " trap_group")
				trap_group := entry.Get("trap_group")
				entry2, err2 := inParams.d.GetEntry(&db.TableSpec{Name: "COPP_GROUP"}, db.Key{[]string{trap_group}})
				if err2 == nil {
					log.Info("YangToDb_copp_trap_ids_xfmr found COPP_GROUP|", trap_group)
					if entry2.Has("trap_action") {
						log.Info("YangToDb_copp_trap_ids_xfmr found COPP_GROUP|", trap_group, " trap_action")
						trap_action = entry2.Get("trap_action")
						log.Info("YangToDb_copp_trap_ids_xfmr trap_action ", trap_action)
					}
				}
			}
		}
		for _, trap_id := range trap_ids {
			if !check_trap_id_valid(trap_id) {
				return res_map, tlerr.InvalidArgsError{Format: "Invalid value passed for trap-ids"}
			}
			if trap_action != "" {
				found := false
				for _, trap := range trap_id_valid[trap_id] {
					if trap == trap_action {
						found = true
						break
					}
				}
				if !found {
					err_str := "Trap_id " + trap_id + " does not support trap_action " + trap_action
					return res_map, tlerr.InvalidArgsError{Format: err_str}
				}
			}
		}
	}

	log.Info("YangToDb_copp_trap_ids_xfmr inval: ", inval, " field: ", field)
	res_map[field] = inval

	return res_map, err
}

var DbToYang_copp_trap_ids_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_trap_ids_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["COPP_TRAP"][inParams.key].Field["trap_ids"]

	log.Info("DbToYang_copp_trap_ids_xfmr inval: ", inval)
	if inval != "" {
		result["trap-ids"] = inval
	}

	return result, err
}

var YangToDb_copp_trap_group_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var field string
	var inval string
	if inParams.param == nil {
		log.Info("YangToDb_copp_trap_group_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_trap_group_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_trap_group_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_trap_group_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	inval = *coppObj.CoppTraps.CoppTrap[name].Config.TrapGroup
	field = "trap_group"

	if inval != "" {
		entry, err := inParams.d.GetEntry(&db.TableSpec{Name: "COPP_TRAP"}, db.Key{[]string{name}})
		if err == nil {
			log.Info("YangToDb_copp_trap_group_xfmr found COPP_TRAP|", name)
			if entry.Has("trap_ids") {
				trap_ids := entry.Get("trap_ids")
				log.Info("YangToDb_copp_trap_group_xfmr found COPP_TRAP|", name, " trap_ids ", trap_ids)
				entry2, err2 := inParams.d.GetEntry(&db.TableSpec{Name: "COPP_GROUP"}, db.Key{[]string{inval}})
				if err2 == nil {
					log.Info("YangToDb_copp_trap_group_xfmr found COPP_GROUP|", inval)
					if entry2.Has("trap_action") {
						log.Info("YangToDb_copp_trap_group_xfmr found COPP_GROUP|", inval, " trap_action")
						trap_action := entry2.Get("trap_action")
						log.Info("YangToDb_copp_trap_group_xfmr trap_action ", trap_action)

						for _, trap_id := range strings.Split(trap_ids, ",") {
							found := false
							for _, trap := range trap_id_valid[trap_id] {
								if trap == trap_action {
									found = true
									break
								}
							}
							if !found {
								err_str := "The trap_group trap_action setting is not compatible with the trap_id entry " + trap_id
								return res_map, tlerr.InvalidArgsError{Format: err_str}
							}
						}
					}
				}
			}
		}
	}

	log.Info("YangToDb_copp_trap_group_xfmr inval: ", inval, " field: ", field)
	res_map[field] = inval

	return res_map, err
}

var DbToYang_copp_trap_group_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_copp_trap_group_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	inval = data["COPP_TRAP"][inParams.key].Field["trap_group"]

	log.Info("DbToYang_copp_trap_group_xfmr inval: ", inval)
	if inval != "" {
		result["trap-group"] = inval
	}

	return result, err
}
