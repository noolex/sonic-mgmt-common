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
