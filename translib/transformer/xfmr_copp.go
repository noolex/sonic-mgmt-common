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
}

func getCoppRoot(s *ygot.GoStruct) *ocbinds.OpenconfigCopp_CoppConfig {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.CoppConfig
}

func trap_action_enum_to_str(input ocbinds.E_OpenconfigCopp_CoppTrapAction) string {
	outval := "NULL"
	switch input {
	case ocbinds.OpenconfigCopp_CoppTrapAction_DROP:
		outval = "drop"
	case ocbinds.OpenconfigCopp_CoppTrapAction_FORWARD:
		outval = "forward"
	case ocbinds.OpenconfigCopp_CoppTrapAction_COPY:
		outval = "copy"
	case ocbinds.OpenconfigCopp_CoppTrapAction_COPY_CANCEL:
		outval = "copy_cancel"
	case ocbinds.OpenconfigCopp_CoppTrapAction_TRAP:
		outval = "trap"
	case ocbinds.OpenconfigCopp_CoppTrapAction_LOG:
		outval = "log"
	case ocbinds.OpenconfigCopp_CoppTrapAction_DENY:
		outval = "deny"
	case ocbinds.OpenconfigCopp_CoppTrapAction_TRANSIT:
		outval = "transit"
	}
	return outval
}

var YangToDb_copp_trap_action_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var inval ocbinds.E_OpenconfigCopp_CoppTrapAction
	if inParams.param == nil {
		log.Info("YangToDb_copp_trap_action_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_copp_trap_action_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_copp_trap_action_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	name := pathInfo.Var("name")
	log.Info("YangToDb_copp_trap_action_xfmr name: ", name)

	coppObj := getCoppRoot(inParams.ygRoot)

	field := "trap_action"
	inval = coppObj.CoppGroup[name].TrapAction

	outval := trap_action_enum_to_str(inval)

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

var YangToDb_copp_green_action_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var inval ocbinds.E_OpenconfigCopp_CoppTrapAction
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
	inval = coppObj.CoppGroup[name].GreenAction

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
	var inval ocbinds.E_OpenconfigCopp_CoppTrapAction
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
	inval = coppObj.CoppGroup[name].YellowAction

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
	var inval ocbinds.E_OpenconfigCopp_CoppTrapAction
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
	inval = coppObj.CoppGroup[name].RedAction

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
	var inval ocbinds.E_OpenconfigCopp_CoppMeterType
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

	inval = coppObj.CoppGroup[name].MeterType
	field = "meter_type"

	outval := ""
	switch inval {
	case ocbinds.OpenconfigCopp_CoppMeterType_PACKETS:
		outval = "packets"
	case ocbinds.OpenconfigCopp_CoppMeterType_BYTES:
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
	var inval ocbinds.E_OpenconfigCopp_CoppMode
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

	inval = coppObj.CoppGroup[name].Mode
	field = "mode"

	outval := ""
	switch inval {
	case ocbinds.OpenconfigCopp_CoppMode_SR_TCM:
		outval = "sr_tcm"
	case ocbinds.OpenconfigCopp_CoppMode_TR_TCM:
		outval = "tr_tcm"
	case ocbinds.OpenconfigCopp_CoppMode_STORM:
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

var valid_items = []string{"stp", "lacp", "eapol", "lldp", "pvrst", "igmp_query", "igmp_leave", "igmp_v1_report",
	"igmp_v2_report", "igmp_v3_report", "sample_packet", "switch_cust_range", "arp_req", "arp_resp", "dhcp",
	"ospf", "pim", "vrrp", "bgp", "dhcpv6", "ospfv6", "vrrpv6", "bgpv6", "neigh_discovery", "mld_v1_v2",
	"mld_v1_report", "mld_v1_done", "mld_v2_report", "ip2me", "ssh", "snmp", "router_custom_range",
	"l3_mtu_error", "ttl_error", "udld", "bfd", "bfdv6", "src_nat_miss", "dest_nat_miss", "ptp", "pim",
	"arp_suppress", "nd_suppress", "icmp", "icmpv6", "iccp"}

func check_trap_id_valid(trap_id string) bool {
	for _, item := range valid_items {
		if item == trap_id {
			return true
		}
	}
	return false
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

	inval = *coppObj.CoppTrap[name].TrapIds
	field = "trap_ids"

	if inval != "" {
		trap_ids := strings.Split(inval, ",")
		for _, trap_id := range trap_ids {
			if !check_trap_id_valid(trap_id) {
				return res_map, tlerr.InvalidArgsError{Format: "Invalid value passed for trap-ids"}
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
