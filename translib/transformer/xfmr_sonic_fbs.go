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

package transformer

import (
	"encoding/json"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
	"math"
	"strconv"
	"strings"
)

type ReferingPolicyEntry struct {
	POLICY_NAME string
	PRIORITY    int
	DESCRIPTION *string `json:",omitempty"`
}

type ClassifierEntry struct {
	CLASSIFIER_NAME   string
	DESCRIPTION       *string               `json:",omitempty"`
	MATCH_TYPE        *string               `json:",omitempty"`
	ACL_NAME          *string               `json:",omitempty"`
	ETHER_TYPE        *string               `json:",omitempty"`
	SRC_MAC           *string               `json:",omitempty"`
	DST_MAC           *string               `json:",omitempty"`
	VLAN              *int                  `json:",omitempty"`
	PCP               *int                  `json:",omitempty"`
	DEI               *int                  `json:",omitempty"`
	IP_PROTOCOL       *int                  `json:",omitempty"`
	SRC_IP            *string               `json:",omitempty"`
	DST_IP            *string               `json:",omitempty"`
	SRC_IPV6          *string               `json:",omitempty"`
	DST_IPV6          *string               `json:",omitempty"`
	DSCP              *int                  `json:",omitempty"`
	L4_SRC_PORT       *int                  `json:",omitempty"`
	L4_SRC_PORT_RANGE *string               `json:",omitempty"`
	L4_DST_PORT       *int                  `json:",omitempty"`
	L4_DST_PORT_RANGE *string               `json:",omitempty"`
	TCP_FLAGS         *string               `json:",omitempty"`
	REFERENCES        []ReferingPolicyEntry `json:",omitempty"`
	STATE             *FlowStateEntry       `json:",omitempty"`
}

type ForwardingEgressEntry struct {
	IP_ADDRESS *string `json:",omitempty"`
	VRF        *string `json:",omitempty"`
	PRIORITY   *int    `json:",omitempty"`
	INTERFACE  *string `json:",omitempty"`
}

type PolicyFlowEntry struct {
	CLASS_NAME            string
	PRIORITY              int
	DESCRIPTION           *string                  `json:",omitempty"`
	SET_DSCP              *int                     `json:",omitempty"`
	SET_PCP               *int                     `json:",omitempty"`
	SET_TC                *int                     `json:",omitempty"`
	SET_POLICER_CIR       *uint64                  `json:",omitempty"`
	SET_POLICER_CBS       *uint64                  `json:",omitempty"`
	SET_POLICER_PIR       *uint64                  `json:",omitempty"`
	SET_POLICER_PBS       *uint64                  `json:",omitempty"`
	SET_MIRROR_SESSION    *string                  `json:",omitempty"`
	DEFAULT_PACKET_ACTION *string                  `json:",omitempty"`
	SET_INTERFACE         *[]ForwardingEgressEntry `json:",omitempty"`
	SET_IP_NEXTHOP        *[]ForwardingEgressEntry `json:",omitempty"`
	SET_IPV6_NEXTHOP      *[]ForwardingEgressEntry `json:",omitempty"`
	STATE                 *FlowStateEntry          `json:",omitempty"`
}

type PolicyBindPortEntry struct {
	INTERFACE_NAME string
	STAGE          string
}

//POLICY_NAME key
type PolicyEntry struct {
	POLICY_NAME        string
	TYPE               string
	DESCRIPTION        *string               `json:",omitempty"`
	FLOWS              []PolicyFlowEntry     `json:",omitempty"`
	APPLIED_INTERFACES []PolicyBindPortEntry `json:",omitempty"`
}

type FlowPolicerStateEntry struct {
	CONFORMED_PACKETS       uint64
	CONFORMED_BYTES         uint64
	EXCEED_PACKETS          uint64
	EXCEED_BYTES            uint64
	VIOLATED_PACKETS        uint64
	VIOLATED_BYTES          uint64
	CONFORMED_PACKET_ACTION string
	EXCEED_PACKET_ACTION    string
	VIOLATED_PACKET_ACTION  string

	//POLICER_TABLE in APP DB
	OPERATIONAL_CIR uint64
	OPERATIONAL_CBS uint64
	OPERATIONAL_PIR uint64
	OPERATIONAL_PBS uint64
	UNITS           string
	COLOR_SOURCE    string
	STATUS          string
}

type FlowForwardingStateEntry struct {
	PACKET_ACTION  *string `json:",omitempty"`
	INTERFACE_NAME *string `json:",omitempty"`
	IP_ADDRESS     *string `json:",omitempty"`
	VRF            *string `json:",omitempty"`
	PRIORITY       *int    `json:",omitempty"`
}

type FlowStateEntry struct {
	STATUS          string
	MATCHED_PACKETS uint64
	MATCHED_BYTES   uint64

	POLICER             *FlowPolicerStateEntry    `json:",omitempty"`
	FORWARDING_SELECTED *FlowForwardingStateEntry `json:",omitempty"`
}

type ServicePolicyEntry struct {
	POLICY_NAME string
	TYPE        string
	STAGE       string
	DESCRIPTION *string           `json:",omitempty"`
	FLOWS       []PolicyFlowEntry `json:",omitempty"`
}

type ServicePolicyInterfaceEntry struct {
	INTERFACE_NAME   string
	APPLIED_POLICIES []ServicePolicyEntry
}

func init() {
	XlateFuncBind("rpc_show_classifier", rpc_show_classifier)
	XlateFuncBind("rpc_show_policy", rpc_show_policy)
	XlateFuncBind("rpc_show_service_policy", rpc_show_service_policy)
	XlateFuncBind("rpc_clear_service_policy", rpc_clear_service_policy)
}

func fill_classifier_details(class_name string, classifierTblVal db.Value, classEntry *ClassifierEntry) error {
	classEntry.CLASSIFIER_NAME = class_name

	if str_val, found := classifierTblVal.Field["MATCH_TYPE"]; found {
		classEntry.MATCH_TYPE = &str_val
	}
	if str_val, found := classifierTblVal.Field["DESCRIPTION"]; found {
		classEntry.DESCRIPTION = &str_val
	}
	if str_val, found := classifierTblVal.Field["ACL_NAME"]; found {
		classEntry.ACL_NAME = &str_val
	}
	if str_val, found := classifierTblVal.Field["ETHER_TYPE"]; found {
		classEntry.ETHER_TYPE = &str_val
	}
	if str_val, found := classifierTblVal.Field["SRC_MAC"]; found {
		classEntry.SRC_MAC = &str_val
	}
	if str_val, found := classifierTblVal.Field["DST_MAC"]; found {
		classEntry.DST_MAC = &str_val
	}
	if str_val, found := classifierTblVal.Field["VLAN"]; found {
		vlan_val, _ := strconv.Atoi(str_val)
		classEntry.VLAN = &vlan_val
	}
	if str_val, found := classifierTblVal.Field["PCP"]; found {
		pcp_val, _ := strconv.Atoi(str_val)
		classEntry.PCP = &pcp_val
	}
	if str_val, found := classifierTblVal.Field["DEI"]; found {
		dei_val, _ := strconv.Atoi(str_val)
		classEntry.DEI = &dei_val
	}
	if str_val, found := classifierTblVal.Field["IP_PROTOCOL"]; found {
		ip_proto_val, _ := strconv.Atoi(str_val)
		classEntry.IP_PROTOCOL = &ip_proto_val
	}
	if str_val, found := classifierTblVal.Field["SRC_IP"]; found {
		classEntry.SRC_IP = &str_val
	}
	if str_val, found := classifierTblVal.Field["DST_IP"]; found {
		classEntry.DST_IP = &str_val
	}
	if str_val, found := classifierTblVal.Field["SRC_IPV6"]; found {
		classEntry.SRC_IPV6 = &str_val
	}
	if str_val, found := classifierTblVal.Field["DST_IPV6"]; found {
		classEntry.DST_IPV6 = &str_val
	}
	if str_val, found := classifierTblVal.Field["DSCP"]; found {
		dscp, _ := strconv.Atoi(str_val)
		classEntry.DSCP = &dscp
	}
	if str_val, found := classifierTblVal.Field["L4_SRC_PORT"]; found {
		src_port, _ := strconv.Atoi(str_val)
		classEntry.L4_SRC_PORT = &src_port
	}
	if str_val, found := classifierTblVal.Field["L4_DST_PORT"]; found {
		dst_port, _ := strconv.Atoi(str_val)
		classEntry.L4_SRC_PORT = &dst_port
	}
	if str_val, found := classifierTblVal.Field["L4_SRC_PORT_RANGE"]; found {
		classEntry.L4_SRC_PORT_RANGE = &str_val
	}
	if str_val, found := classifierTblVal.Field["L4_DST_PORT_RANGE"]; found {
		classEntry.L4_DST_PORT_RANGE = &str_val
	}
	if str_val, found := classifierTblVal.Field["TCP_FLAGS"]; found {
		classEntry.TCP_FLAGS = &str_val
	}

	var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
	classReferingPolicyKeys, err := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{Comp: []string{"*", class_name}})
	if err != nil {
		log.Error(err)
		return err
	}

	log.Infof("Sections:", classReferingPolicyKeys)

	for i := 0; i < len(classReferingPolicyKeys); i++ {
		var referringPolicy ReferingPolicyEntry

		policySectionTblVal, err := configDbPtr.GetEntry(POLICY_SECTION_TABLES_TS, classReferingPolicyKeys[i])
		if err != nil {
			log.Errorf("Failed to  find related policy:%v err%v", classReferingPolicyKeys[i], err)
			return err
		}

		log.Infof("In rpc_show_classifier, RPC policySectionTblVal:%v", policySectionTblVal)
		referringPolicy.PRIORITY, _ = strconv.Atoi(policySectionTblVal.Field["PRIORITY"])
		referringPolicy.POLICY_NAME = classReferingPolicyKeys[i].Comp[0]
		if descr, found := policySectionTblVal.Field["DESCRIPTION"]; found {
			referringPolicy.DESCRIPTION = &descr
		}
		classEntry.REFERENCES = append(classEntry.REFERENCES, referringPolicy)
	}

	return nil
}

var rpc_show_classifier RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
	var class_name, match_type string

	log.Infof("Enter")
	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Infof("Error: %v", err)
		log.Error("Failed to  marshal input data; err=%v", err)
		return nil, tlerr.InvalidArgs("Invalid input %s", string(body))
	}

	input, _ := mapData["sonic-flow-based-services:input"]
	mapData = input.(map[string]interface{})
	log.Infof("RPC Input data: %v", mapData)
	configDbPtr := dbs[db.ConfigDB]
	var CLASSIFIER_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "CLASSIFIER_TABLE"}

	var showOutput struct {
		Output struct {
			CLASSIFIERS []ClassifierEntry
		} `json:"sonic-flow-based-services:output"`
	}

	showOutput.Output.CLASSIFIERS = make([]ClassifierEntry, 0)
	arg_class_name, arg_class_name_found := mapData["CLASSIFIER_NAME"].(string)
	arg_match_type, arg_match_type_found := mapData["MATCH_TYPE"].(string)
	if arg_class_name_found && arg_class_name != "" {
		class_name = arg_class_name

		//get classifier db output
		classifierTblVal, err := configDbPtr.GetEntry(CLASSIFIER_TABLE_TS, db.Key{Comp: []string{class_name}})
		log.Infof("Class_name:%v, RPC classifierTblVal:%v", class_name, classifierTblVal)
		if err != nil {
			log.Errorf("Failed to  find classifier:%v err%v", class_name, err)
			return nil, tlerr.NotFound("Classifier %s not found", arg_class_name)
		}

		var classEntry ClassifierEntry
		err = fill_classifier_details(class_name, classifierTblVal, &classEntry)
		if err != nil {
			return nil, err
		}

		showOutput.Output.CLASSIFIERS = append(showOutput.Output.CLASSIFIERS, classEntry)
	} else {
		if arg_match_type_found {
			match_type = arg_match_type
		}

		classifierTbl, err := configDbPtr.GetTable(CLASSIFIER_TABLE_TS)
		if err != nil {
			return nil, err
		}

		classKeys, _ := classifierTbl.GetKeys()
		log.Infof("Match_type:%v RPC classifierTbl:%v, classkeys:%v ", match_type, classifierTbl, classKeys)

		for index, _ := range classKeys {
			class_name = classKeys[index].Comp[0]
			classifierTblVal, err := classifierTbl.GetEntry(classKeys[index])
			if match_type != "" && classifierTblVal.Field["MATCH_TYPE"] != match_type {
				log.Infof("Not matching index:%v class_name:%v match_type:%v ", index, class_name, classifierTblVal.Field["MATCH_TYPE"])
				continue
			}

			var classEntry ClassifierEntry
			err = fill_classifier_details(class_name, classifierTblVal, &classEntry)
			if err != nil {
				continue
			}
			showOutput.Output.CLASSIFIERS = append(showOutput.Output.CLASSIFIERS, classEntry)
		}
	}

	result, err = json.Marshal(&showOutput)
	log.Infof("Err:%v JSONOutput:%v", err, string(result))

	return result, err
}

func fill_policy_section_table_info(policy_name string, class_name string, intf_name string, stage string, policy_type string,
	policySectionTblVal db.Value, dbs [db.MaxDB]*db.DB, fill_state bool, policySectionInfo *PolicyFlowEntry) error {

	log.Infof("Policy:%s Class:%s Intf:%s Stage:%s Type:%s", policy_name, class_name, intf_name, stage, policy_type)

	policySectionInfo.CLASS_NAME = class_name
	policySectionInfo.PRIORITY, _ = strconv.Atoi(policySectionTblVal.Field["PRIORITY"])

	if str_val, found := policySectionTblVal.Field["DESCRIPTION"]; found {
		policySectionInfo.DESCRIPTION = &str_val
	}
	if str_val, found := policySectionTblVal.Field["SET_DSCP"]; found {
		dscp_val, _ := strconv.Atoi(str_val)
		policySectionInfo.SET_DSCP = &dscp_val
	}
	if str_val, found := policySectionTblVal.Field["SET_PCP"]; found {
		pcp_val, _ := strconv.Atoi(str_val)
		policySectionInfo.SET_PCP = &pcp_val
	}
	if str_val, found := policySectionTblVal.Field["SET_TC"]; found {
		tc_val, _ := strconv.Atoi(str_val)
		policySectionInfo.SET_TC = &tc_val
	}
	if str_val, found := policySectionTblVal.Field["SET_POLICER_CIR"]; found {
		val, _ := strconv.ParseUint(str_val, 10, 64)
		policySectionInfo.SET_POLICER_CIR = &val
	}
	if str_val, found := policySectionTblVal.Field["SET_POLICER_CBS"]; found {
		val, _ := strconv.ParseUint(str_val, 10, 64)
		policySectionInfo.SET_POLICER_CBS = &val
	}
	if str_val, found := policySectionTblVal.Field["SET_POLICER_PIR"]; found {
		val, _ := strconv.ParseUint(str_val, 10, 64)
		policySectionInfo.SET_POLICER_PIR = &val
	}
	if str_val, found := policySectionTblVal.Field["SET_POLICER_PBS"]; found {
		val, _ := strconv.ParseUint(str_val, 10, 64)
		policySectionInfo.SET_POLICER_PBS = &val
	}
	if str_val, found := policySectionTblVal.Field["SET_MIRROR_SESSION"]; found {
		policySectionInfo.SET_MIRROR_SESSION = &str_val
	}
	if str_val, found := policySectionTblVal.Field["DEFAULT_PACKET_ACTION"]; found {
		policySectionInfo.DEFAULT_PACKET_ACTION = &str_val
	}
	if ipNhops := policySectionTblVal.GetList("SET_IP_NEXTHOP"); len(ipNhops) > 0 {
		var nextHops []ForwardingEgressEntry
		for i := range ipNhops {
			var ipNhopEntry ForwardingEgressEntry
			nhopSplits := strings.Split(ipNhops[i], "|")
			ipNhopEntry.IP_ADDRESS = &nhopSplits[0]
			if len(nhopSplits[1]) > 0 {
				ipNhopEntry.VRF = &nhopSplits[1]
			}
			if len(nhopSplits[2]) > 0 {
				prio, _ := strconv.Atoi(nhopSplits[2])
				ipNhopEntry.PRIORITY = &prio
			}
			nextHops = append(nextHops, ipNhopEntry)
		}
		policySectionInfo.SET_IP_NEXTHOP = &nextHops
	}
	if ipNhops := policySectionTblVal.GetList("SET_IPV6_NEXTHOP"); len(ipNhops) > 0 {
		var nextHops []ForwardingEgressEntry
		for i := range ipNhops {
			var ipNhopEntry ForwardingEgressEntry
			nhopSplits := strings.Split(ipNhops[i], "|")
			ipNhopEntry.IP_ADDRESS = &nhopSplits[0]
			if len(nhopSplits[1]) > 0 {
				ipNhopEntry.VRF = &nhopSplits[1]
			}
			if len(nhopSplits[2]) > 0 {
				prio, _ := strconv.Atoi(nhopSplits[2])
				ipNhopEntry.PRIORITY = &prio
			}
			nextHops = append(nextHops, ipNhopEntry)
		}
		policySectionInfo.SET_IPV6_NEXTHOP = &nextHops
	}
	if intfs := policySectionTblVal.GetList("SET_INTERFACE"); len(intfs) > 0 {
		var intfEntries []ForwardingEgressEntry
		for i := range intfs {
			var fwdEntry ForwardingEgressEntry
			intfSplits := strings.Split(intfs[i], "|")
			fwdEntry.INTERFACE = &intfSplits[0]
			if len(intfSplits[1]) > 0 {
				prio, _ := strconv.Atoi(intfSplits[1])
				fwdEntry.PRIORITY = &prio
			}
			intfEntries = append(intfEntries, fwdEntry)
		}
		policySectionInfo.SET_INTERFACE = &intfEntries
	}

	if fill_state {
		var state FlowStateEntry
		err := fill_policy_class_state_info(policy_name, class_name, intf_name, stage, policy_type, dbs, &state)
		if err != nil {
			return err
		}
		policySectionInfo.STATE = &state
	}

	return nil
}

func get_counter_diff(currentVal db.Value, lastVal db.Value, field string) uint64 {
	current, _ := strconv.ParseUint(currentVal.Field[field], 10, 64)
	last, _ := strconv.ParseUint(lastVal.Field[field], 10, 64)

	if current < last {
		return math.MaxUint64 - last + current
	} else {
		return current - last
	}
}

func fill_policy_class_state_info(policy_name string, class_name string, interface_name string, bind_dir string,
	policy_type string, dbs [db.MaxDB]*db.DB, state *FlowStateEntry) error {

	countersDbPtr := dbs[db.CountersDB]

	polPbfKey := db.Key{[]string{policy_name, class_name, interface_name, bind_dir}}

	var fbsCtrTbl_ts *db.TableSpec = &db.TableSpec{Name: "FBS_COUNTERS"}
	fbsCtrVal, err := countersDbPtr.GetEntry(fbsCtrTbl_ts, polPbfKey)

	var lastFbsCtrTbl_ts *db.TableSpec = &db.TableSpec{Name: "LAST_FBS_COUNTERS"}
	lastFbsCtrVal, err2 := countersDbPtr.GetEntry(lastFbsCtrTbl_ts, polPbfKey)

	log.Infof("fbsCtrVal:%v", fbsCtrVal)
	if err == nil && err2 == nil {
		state.MATCHED_PACKETS = get_counter_diff(fbsCtrVal, lastFbsCtrVal, "Packets")
		state.MATCHED_BYTES = get_counter_diff(fbsCtrVal, lastFbsCtrVal, "Bytes")

		state.STATUS = "Active"
	} else {
		state.STATUS = "Inactive"
	}

	if strings.EqualFold(policy_type, "QOS") {
		var policer FlowPolicerStateEntry
		var polCntTbl_ts *db.TableSpec = &db.TableSpec{Name: "POLICER_COUNTERS"}
		polCntVal, err := countersDbPtr.GetEntry(polCntTbl_ts, polPbfKey)
		var lastPolCntTbl_ts *db.TableSpec = &db.TableSpec{Name: "LAST_POLICER_COUNTERS"}
		lastPolCntVal, err := countersDbPtr.GetEntry(lastPolCntTbl_ts, polPbfKey)

		log.Infof("polCntVal:%v", polCntVal)
		if err == nil {
			policer.CONFORMED_PACKETS = get_counter_diff(polCntVal, lastPolCntVal, "GreenPackets")
			policer.CONFORMED_BYTES = get_counter_diff(polCntVal, lastPolCntVal, "GreenBytes")
			policer.EXCEED_PACKETS = get_counter_diff(polCntVal, lastPolCntVal, "YellowPackets")
			policer.EXCEED_BYTES = get_counter_diff(polCntVal, lastPolCntVal, "YellowBytes")
			policer.VIOLATED_PACKETS = get_counter_diff(polCntVal, lastPolCntVal, "RedPackets")
			policer.VIOLATED_BYTES = get_counter_diff(polCntVal, lastPolCntVal, "RedBytes")
			policer.STATUS = "Active"
		} else {
			policer.STATUS = "Inactive"
		}

		appDbPtr := dbs[db.ApplDB]
		var POLICER_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICER_TABLE"}
		policerTblVal, err := appDbPtr.GetEntry(POLICER_TABLES_TS, polPbfKey)
		log.Infof("policerTblVal:%v", policerTblVal)
		if err == nil {
			policer.OPERATIONAL_CIR, _ = strconv.ParseUint(policerTblVal.Field["CIR"], 10, 64)
			policer.OPERATIONAL_CBS, _ = strconv.ParseUint(policerTblVal.Field["CBS"], 10, 64)
			policer.OPERATIONAL_PIR, _ = strconv.ParseUint(policerTblVal.Field["PIR"], 10, 64)
			policer.OPERATIONAL_PBS, _ = strconv.ParseUint(policerTblVal.Field["PBS"], 10, 64)

			policer.UNITS = policerTblVal.Field["METER_TYPE"]
			policer.COLOR_SOURCE = policerTblVal.Field["COLOR_SOURCE"]

			policer.CONFORMED_PACKET_ACTION = policerTblVal.Field["GREEN_PACKET_ACTION"]
			policer.EXCEED_PACKET_ACTION = policerTblVal.Field["YELLOW_PACKET_ACTION"]
			policer.VIOLATED_PACKET_ACTION = policerTblVal.Field["RED_PACKET_ACTION"]
		}
		state.POLICER = &policer
	}

	if strings.EqualFold(policy_type, "FORWARDING") {
		var fwdEntry FlowForwardingStateEntry

		stateDbPtr := dbs[db.StateDB]
		pbfTable_ts := &db.TableSpec{Name: "PBF_GROUP_TABLE"}

		pbfKey := db.Key{Comp: []string{strings.Join(polPbfKey.Comp, ":")}}
		val, err := stateDbPtr.GetEntry(pbfTable_ts, pbfKey)
		if err == nil {
			selected := val.Field["CONFIGURED_SELECTED"]
			log.Infof("Key:%v Selected:%v", pbfKey, selected)
			if selected == "DROP" {
				fwdEntry.PACKET_ACTION = &selected
			} else {
				parts := strings.Split(selected, "|")
				if len(parts) == 3 {
					fwdEntry.IP_ADDRESS = &parts[0]
					fwdEntry.VRF = &parts[1]
					if parts[2] != "" {
						prio, _ := strconv.ParseInt(parts[2], 10, 32)
						prio_int := int(prio)
						fwdEntry.PRIORITY = &prio_int
					}
				} else {
					fwdEntry.INTERFACE_NAME = &parts[0]
					if parts[1] != "" {
						prio, _ := strconv.ParseInt(parts[1], 10, 32)
						prio_int := int(prio)
						fwdEntry.PRIORITY = &prio_int
					}
				}
			}
		}
		state.FORWARDING_SELECTED = &fwdEntry
	}

	return nil
}

func fill_policy_details(policy_name string, policyTblVal db.Value, dbs [db.MaxDB]*db.DB, policyEntry *PolicyEntry) error {
	policyEntry.POLICY_NAME = policy_name
	policyEntry.TYPE = policyTblVal.Field["TYPE"]
	if str_val, found := policyTblVal.Field["DESCRIPTION"]; found {
		policyEntry.DESCRIPTION = &str_val
	}

	var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
	referingClassKeys, err := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{[]string{policy_name, "*"}})
	if err != nil {
		log.Error(err)
		return err
	}

	log.Infof("referingClassKeys ==> %v", referingClassKeys)

	for i := 0; i < len(referingClassKeys); i++ {
		log.Infof("key:%v", referingClassKeys[i].Comp)

		policySectionTblVal, err := configDbPtr.GetEntry(POLICY_SECTION_TABLES_TS, referingClassKeys[i])
		if err != nil {
			log.Error("Failed to  find related class:%v err%v", referingClassKeys[i], err)
			return err
		}
		log.Infof("Data:%v", policySectionTblVal)

		var referingClass PolicyFlowEntry
		fill_policy_section_table_info(policy_name, referingClassKeys[i].Comp[1], "", "", "",
			policySectionTblVal, dbs, false, &referingClass)

		policyEntry.FLOWS = append(policyEntry.FLOWS, referingClass)
	}

	var POLICY_BIND_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_BINDING_TABLE"}
	policyBindTbl, bind_err := configDbPtr.GetTable(POLICY_BIND_TABLE_TS)
	if nil != bind_err {
		log.Error(bind_err)
		return bind_err
	}

	log.Infof("In rpc_show_policy, policyBindtbl:%v ", policyBindTbl)
	policyBindKeys, _ := policyBindTbl.GetKeys()

	for index, _ := range policyBindKeys {
		var appliedPort PolicyBindPortEntry
		policyBindTblVal, _ := policyBindTbl.GetEntry(policyBindKeys[index])
		log.Infof("policy_name:%v key:%v policyBindTblVal:%v ", policy_name, policyBindKeys[index], policyBindTblVal)

		for field, value := range policyBindTblVal.Field {
			if value == policy_name {
				field_splits := strings.Split(field, "_")
				policy_bind_dir := field_splits[0]
				appliedPort.INTERFACE_NAME = policyBindKeys[index].Comp[0]
				appliedPort.STAGE = policy_bind_dir
				policyEntry.APPLIED_INTERFACES = append(policyEntry.APPLIED_INTERFACES, appliedPort)
				break
			}
		}
	}

	return nil
}

var rpc_show_policy RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
	log.Infof("Enter")
	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Error("Failed to  marshal input data; err=%v", err)
		return nil, tlerr.InvalidArgs("Invalid input %s", string(body))
	}

	input, _ := mapData["sonic-flow-based-services:input"]
	mapData = input.(map[string]interface{})
	log.Infof("RPC Input data: %v", mapData)
	configDbPtr := dbs[db.ConfigDB]
	var POLICY_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_TABLE"}

	var showOutput struct {
		Output struct {
			POLICIES []PolicyEntry
		} `json:"sonic-flow-based-services:output"`
	}

	showOutput.Output.POLICIES = make([]PolicyEntry, 0)
	policy_name, policy_name_found := mapData["POLICY_NAME"].(string)
	policy_type, policy_type_found := mapData["TYPE"].(string)

	if policy_name_found {
		//get policy db output
		policyTblVal, err := configDbPtr.GetEntry(POLICY_TABLE_TS, db.Key{Comp: []string{policy_name}})
		if err != nil {
			log.Errorf("Failed to  find policy:%v err%v", policy_name, err)
			return nil, err
		}
		log.Infof("In rpc_show_policy, policy_name:%v, RPC policyTblVal:%v", policy_name, policyTblVal)

		var policyEntry PolicyEntry
		err = fill_policy_details(policy_name, policyTblVal, dbs, &policyEntry)
		if err != nil {
			log.Errorf("Failed to fetch policy:%v details err%v", policy_name, err)
			return nil, err
		}
		showOutput.Output.POLICIES = append(showOutput.Output.POLICIES, policyEntry)
	} else {
		policy_type = strings.ToUpper(policy_type)

		policyTbl, err := configDbPtr.GetTable(POLICY_TABLE_TS)
		if nil != err {
			return nil, err
		}
		log.Infof("policy_type:%v, RPC policyTbl:%v", policy_type, policyTbl)

		policyKeys, _ := policyTbl.GetKeys()
		log.Infof("policykeys:%v", policyKeys)
		for index := range policyKeys {
			policy_name = policyKeys[index].Comp[0]
			log.Infof("index:%v policy_name:%v ", index, policy_name)
			policyTblVal, err := policyTbl.GetEntry(policyKeys[index])
			if policy_type_found && policyTblVal.Field["TYPE"] != policy_type {
				log.Infof("index:%v policy_name:%v match_type:%v expected:%v", index, policy_name, policyTblVal.Field["TYPE"], policy_type)
				continue
			}
			var policyEntry PolicyEntry
			err = fill_policy_details(policy_name, policyTblVal, dbs, &policyEntry)
			if err != nil {
				continue
			}
			showOutput.Output.POLICIES = append(showOutput.Output.POLICIES, policyEntry)
		}
	}

	result, err = json.Marshal(&showOutput)
	return result, err
}

var rpc_show_service_policy RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
	log.Infof("Enter")

	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Infof("Error: %v. Input:%s", err, string(body))
		log.Errorf("Failed to  marshal input data; err=%v", err)
		return nil, tlerr.InvalidArgs("Invalid input %s", string(body))
	}

	input, _ := mapData["sonic-flow-based-services:input"]
	mapData = input.(map[string]interface{})
	log.Infof("RPC Input data: %v", mapData)

	var showOutput struct {
		Output struct {
			INTERFACES []ServicePolicyInterfaceEntry
		} `json:"sonic-flow-based-services:output"`
	}

	policy_name, policy_name_found := mapData["POLICY_NAME"].(string)
	interface_name, interface_name_found := mapData["INTERFACE_NAME"].(string)
	policy_type, policy_type_found := mapData["TYPE"].(string)

	if !policy_name_found && !interface_name_found {
		log.Errorf("Policy name and interface name not found")
		return nil, tlerr.InvalidArgs("Interface name or Policy name mandatory")
	}

	configDbPtr := dbs[db.ConfigDB]

	var POLICY_BIND_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_BINDING_TABLE"}

	policyBindTbl, err := configDbPtr.GetTable(POLICY_BIND_TABLE_TS)
	if nil != err {
		return nil, err
	}

	intfServicePolicyData := make(map[string]ServicePolicyInterfaceEntry)

	policyBindKeys, _ := policyBindTbl.GetKeys()
	for index, key := range policyBindKeys {
		if interface_name_found {
			if key.Comp[0] != interface_name {
				log.Infof("Interface:%s Needed:%s. Skip", key.Comp[0], interface_name)
				continue
			}
		}

		policyBindTblVal, _ := policyBindTbl.GetEntry(policyBindKeys[index])
		log.Infof("key:%v policyBindTblVal:%v", policyBindKeys[index], policyBindTblVal)

		for field, value := range policyBindTblVal.Field {
			field_splits := strings.Split(field, "_")

			if policy_name_found {
				if value != policy_name {
					log.Infof("Policy:%s Needed:%s. Skip", value, policy_name)
					continue
				}
			}

			if policy_type_found {
				if !strings.EqualFold(field_splits[1], policy_type) {
					log.Infof("Type:%s Needed:%s. Skip", field_splits[1], policy_type)
					continue
				}
			}

			intfEntry := intfServicePolicyData[key.Comp[0]]
			intfEntry.INTERFACE_NAME = key.Comp[0]

			var policy_entry ServicePolicyEntry
			policy_entry.TYPE = field_splits[1]
			policy_entry.STAGE = field_splits[0]
			policy_entry.POLICY_NAME = value

			log.Infof("Interface:%v Policy:%v Type:%v Stage:%v", key.Comp[0], value, field_splits[1], field_splits[0])

			var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
			referingClassKeys, err := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{[]string{value, "*"}})
			if err != nil {
				log.Error(err)
				return nil, err
			}

			for i := 0; i < len(referingClassKeys); i++ {
				policySectionTblVal, err := configDbPtr.GetEntry(POLICY_SECTION_TABLES_TS, referingClassKeys[i])
				if err != nil {
					return nil, err
				}
				log.Infof("Keys:%v", referingClassKeys[i])

				var referingClassEntry PolicyFlowEntry
				err = fill_policy_section_table_info(value, referingClassKeys[i].Comp[1], key.Comp[0], field_splits[0],
					field_splits[1], policySectionTblVal, dbs, true, &referingClassEntry)
				if nil != err {
					return nil, err
				}

				policy_entry.FLOWS = append(policy_entry.FLOWS, referingClassEntry)
			}

			intfEntry.APPLIED_POLICIES = append(intfEntry.APPLIED_POLICIES, policy_entry)
			intfServicePolicyData[key.Comp[0]] = intfEntry
		}
	}

	if len(intfServicePolicyData) == 0 {
		return nil, tlerr.NotFound("No policy application found")
	}

	for _, val := range intfServicePolicyData {
		showOutput.Output.INTERFACES = append(showOutput.Output.INTERFACES, val)
	}

	result, jerr := json.Marshal(&showOutput)
	if nil != jerr {
		log.Error(jerr)
		return nil, jerr
	}

	return result, nil
}

func clear_policer_counters(key db.Key, countersDbPtr *db.DB) error {
	var polCntTbl_ts *db.TableSpec = &db.TableSpec{Name: "POLICER_COUNTERS"}
	var lastPolCntTbl_ts *db.TableSpec = &db.TableSpec{Name: "LAST_POLICER_COUNTERS"}

	value, err := countersDbPtr.GetEntry(polCntTbl_ts, key)
	if err == nil {
		err = countersDbPtr.CreateEntry(lastPolCntTbl_ts, key, value)
	}

	return err
}

func clear_fbs_counters(key db.Key, countersDbPtr *db.DB) error {
	log.Info(key)

	var CntTbl_ts *db.TableSpec = &db.TableSpec{Name: "FBS_COUNTERS"}
	var lastCntTbl_ts *db.TableSpec = &db.TableSpec{Name: "LAST_FBS_COUNTERS"}

	value, err := countersDbPtr.GetEntry(CntTbl_ts, key)
	if err == nil {
		err = countersDbPtr.CreateEntry(lastCntTbl_ts, key, value)
		log.Infof("Updated Last counter values. Error:%v", err)
	}

	return err
}

var rpc_clear_service_policy RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
	log.Infof("Enter")

	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Infof("Error: %v. Input:%s", err, string(body))
		log.Errorf("Failed to  marshal input data; err=%v", err)
		return nil, tlerr.InvalidArgs("Invalid input %s", string(body))
	}

	input, _ := mapData["sonic-flow-based-services:input"]
	mapData = input.(map[string]interface{})
	log.Infof("RPC Input data: %v", mapData)

	policy_name, policy_name_found := mapData["POLICY_NAME"].(string)
	interface_name, interface_name_found := mapData["INTERFACE_NAME"].(string)
	policy_type, policy_type_found := mapData["TYPE"].(string)

	if !policy_name_found && !interface_name_found {
		log.Errorf("Policy name and interface name not found")
		return nil, tlerr.InvalidArgs("Interface name or Policy name mandatory")
	}

	configDbPtr := dbs[db.ConfigDB]

	var POLICY_BIND_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_BINDING_TABLE"}

	policyBindTbl, err := configDbPtr.GetTable(POLICY_BIND_TABLE_TS)
	if nil != err {
		return nil, err
	}

	var match_found bool
	policyBindKeys, _ := policyBindTbl.GetKeys()
	for index, key := range policyBindKeys {
		if interface_name_found {
			if key.Comp[0] != interface_name {
				log.Infof("Interface:%s Needed:%s. Skip", key.Comp[0], interface_name)
				continue
			}
		}

		policyBindTblVal, _ := policyBindTbl.GetEntry(policyBindKeys[index])
		log.Infof("key:%v policyBindTblVal:%v", policyBindKeys[index], policyBindTblVal)

		for field, value := range policyBindTblVal.Field {
			field_splits := strings.Split(field, "_")

			if policy_name_found {
				if value != policy_name {
					log.Infof("Policy:%s Needed:%s. Skip", value, policy_name)
					continue
				}
			}

			if policy_type_found {
				if !strings.EqualFold(field_splits[1], policy_type) {
					log.Infof("Type:%s Needed:%s. Skip", field_splits[1], policy_type)
					continue
				}
			}

			log.Infof("Interface:%v Policy:%v Type:%v Stage:%v", interface_name, value, field_splits[1], field_splits[0])

			var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
			referingClassKeys, err := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{[]string{value, "*"}})
			if err != nil {
				log.Error(err)
				return nil, err
			}

			match_found = true
			for i := 0; i < len(referingClassKeys); i++ {
				fbsKey := db.Key{Comp: []string{value, referingClassKeys[i].Comp[1], key.Comp[0], field_splits[0]}}
				clear_fbs_counters(fbsKey, dbs[db.CountersDB])
				if field_splits[1] == "QOS" {
					clear_policer_counters(key, dbs[db.CountersDB])
				}
			}
		}
	}
	if !match_found {
		return nil, tlerr.NotFound("No policy application found")
	}

	return result, nil
}
