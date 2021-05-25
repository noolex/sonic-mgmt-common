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
	"fmt"
	"reflect"
	"strconv"
	"strings"

	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	"github.com/go-redis/redis/v7"
	log "github.com/golang/glog"
)

const MAX_FLOWGROUPS = 253

var getFeatureName = map[string]string{
	"IFA":          "IFA",
	"DROPMONITOR":  "Drop Monitor",
	"TAILSTAMPING": "Tailstamping",
}

func log_request_info(vc *CustValidationCtxt, func_name string) {
	log.Info(func_name, ":",
		" operation: ", vc.CurCfg.VOp,
		" Key: ", vc.CurCfg.Key, " Data: ", vc.CurCfg.Data,
		" YNodeName: ", vc.YNodeName, " YNodeVal: ", vc.YNodeVal,
		" Req Data: ", vc.ReqData)
}

func getFeatureStatus(feature string) string {
	stateDBClient := util.NewDbClient("STATE_DB")
	defer func() {
		if stateDBClient != nil {
			stateDBClient.Close()
		}
	}()

	var status string
	status = "UNSUPPORTED"
	if stateDBClient != nil {
		key := "TAM_STATE_FEATURES_TABLE|" + feature
		status, _ = stateDBClient.HGet(key, "op-status").Result()
	}
	return status
}

func CheckInSessions(vc *CustValidationCtxt, table string, identity string, name string) (string, bool) {
	var used bool = false
	var collector string = ""

	sessions, err := vc.RClient.Keys(table + "|*").Result()
	if err == nil {
		for _, sessionKey := range sessions {
			entry, err := vc.RClient.HGetAll(sessionKey).Result()
			if err == nil {
				if name == entry[identity] {
					used = true
				}
				c := entry["collector"]
				if c != "" {
					collector = c
				}
			}
		}
	}
	return collector, used
}

func getFlowGroups(vc *CustValidationCtxt, table string, flowGroup string) (string, bool) {
	matched := false
	matchedFlow := ""
	sessions, err := vc.RClient.Keys(table + "|*").Result()
	if err == nil {
		testGroup, err := vc.RClient.HGetAll("ACL_RULE|TAM|" + flowGroup).Result()
		if err == nil {
			for _, sessionKey := range sessions {
				entry, err := vc.RClient.HGetAll(sessionKey).Result()
				if err == nil {
					currentFlow := entry["flowgroup"]
					if currentFlow != flowGroup {
						currentGroup, err := vc.RClient.HGetAll("ACL_RULE|TAM|" + currentFlow).Result()
						if err == nil {
							delete(currentGroup, "PACKET_ACTION")
							matched = reflect.DeepEqual(testGroup, currentGroup)
							matchedFlow = currentFlow
							break
						}
					}
				}
			}
		}
	}
	return matchedFlow, matched
}

func CheckUsage(vc *CustValidationCtxt, identity string, name string) (map[string]string, bool) {
	var used bool
	var c string
	var collectors = make(map[string]string)

	if (identity == "collector") || (identity == "sample-rate") {
		c, used = CheckInSessions(vc, "TAM_IFA_SESSIONS_TABLE", identity, name)
		collectors["ifa"] = c
		if used {
			return collectors, used
		}
		c, used = CheckInSessions(vc, "TAM_DROPMONITOR_SESSIONS_TABLE", identity, name)
		collectors["dropmonitor"] = c
		if used {
			return collectors, used
		}
	} else if identity == "flowgroup" {
		c, used = CheckInSessions(vc, "TAM_IFA_SESSIONS_TABLE", identity, name)
		collectors["ifa"] = c
		if used {
			return collectors, used
		}
		c, used = CheckInSessions(vc, "TAM_DROPMONITOR_SESSIONS_TABLE", identity, name)
		collectors["dropmonitor"] = c
		if used {
			return collectors, used
		}
		c, used = CheckInSessions(vc, "TAM_TAILSTAMPING_SESSIONS_TABLE", identity, name)
		collectors["tailstamping"] = c
		if used {
			return collectors, used
		}
	}
	return collectors, used
}

func (t *CustomValidation) CollectorValidation(vc *CustValidationCtxt) CVLErrorInfo {
	// do not allow to update, allow only CREATE / DELETE
	log_request_info(vc, "CollectorValidation")

	val, err := vc.RClient.HGet(vc.CurCfg.Key, "ip").Result()
	if err != nil && err != redis.Nil {
		log.Info("CollectorValidation error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	thisCollector := strings.Split(vc.CurCfg.Key, "|")[1]
	if (val != "") && (vc.CurCfg.VOp != OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Collector '%s' is already created.", thisCollector),
			CVLErrDetails:    "Collector exists.",
			ErrAppTag:        "collector-already-exist",
		}
	}

	if (val == "") && (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Collector '%s' does not exist.", thisCollector),
			CVLErrDetails:    "Collector does not exists.",
			ErrAppTag:        "collector-not-exist",
		}
	}

	_, inUse := CheckUsage(vc, "collector", thisCollector)
	if (vc.CurCfg.VOp == OP_DELETE) && inUse {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("One or more sessions are using the collector '%s'.", thisCollector),
			CVLErrDetails:    "Collector is in use.",
			ErrAppTag:        "collector-in-use",
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) SamplerValidation(vc *CustValidationCtxt) CVLErrorInfo {
	// do not allow to update, allow only CREATE / DELETE
	log_request_info(vc, "CollectorValidation")

	val, err := vc.RClient.HGet(vc.CurCfg.Key, "sampling-rate").Result()
	if err != nil && err != redis.Nil {
		log.Info("SamplerValidation error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	thisSampler := strings.Split(vc.CurCfg.Key, "|")[1]
	if (val != "") && (vc.CurCfg.VOp != OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Sampler '%s' is already created.", thisSampler),
			CVLErrDetails:    "Sampler exists.",
			ErrAppTag:        "sampler-already-exist",
		}
	}

	if (val == "") && (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Sampler '%s' does not exist.", thisSampler),
			CVLErrDetails:    "Sampler does not exists.",
			ErrAppTag:        "sampler-not-exist",
		}
	}

	_, inUse := CheckUsage(vc, "sample-rate", thisSampler)
	if (vc.CurCfg.VOp == OP_DELETE) && inUse {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("One or more sessions are using the sampler '%s'.", thisSampler),
			CVLErrDetails:    "Sampler is in use.",
			ErrAppTag:        "sampler-in-use",
		}
	}
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) FlowgroupValidation(vc *CustValidationCtxt) CVLErrorInfo {
	// do not allow to update, allow only CREATE / DELETE
	log_request_info(vc, "FlowgroupValidation")

	val, err := vc.RClient.HGet(vc.CurCfg.Key, "table-name").Result()
	if err != nil && err != redis.Nil {
		log.Info("FlowgroupValidation error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	thisFlowgroup := strings.Split(vc.CurCfg.Key, "|")[1]
	/*
	   if ((val != "") && (vc.CurCfg.VOp != OP_DELETE)) {
	       return CVLErrorInfo{
	           ErrCode: CVL_SEMANTIC_ERROR,
	           ConstraintErrMsg: fmt.Sprintf("Flowgroup '%s' is already created.", thisFlowgroup),
	           CVLErrDetails : "Flowgroup exists.",
	           ErrAppTag : "flowgroup-already-exist",
	       }
	   }
	*/
	if (val == "") && (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Flowgroup '%s' does not exist.", thisFlowgroup),
			CVLErrDetails:    "Flowgroup does not exists.",
			ErrAppTag:        "flowgroup-not-exist",
		}
	}

	_, inUse := CheckUsage(vc, "flowgroup", thisFlowgroup)
	if (vc.CurCfg.VOp == OP_DELETE) && inUse {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("One or more sessions are using the flowgroup '%s'.", thisFlowgroup),
			CVLErrDetails:    "Flowgroup is in use.",
			ErrAppTag:        "flowgroup-in-use",
		}
	}

	if vc.CurCfg.VOp != OP_DELETE {
		var nokey []string
		ls := redis.NewScript(`return #redis.call('KEYS', "TAM_FLOWGROUP_TABLE|*")`)

		//Get current coutnt from Redis
		redisEntries, err := ls.Run(vc.RClient, nokey).Result()
		if err != nil {
			return CVLErrorInfo{ErrCode: CVL_SEMANTIC_ERROR}
		}

		flowsCount := int(redisEntries.(int64))
		//Get count from user request
		for idx := 0; idx < len(vc.ReqData); idx++ {
			if (vc.ReqData[idx].VOp == OP_CREATE) && (strings.HasPrefix(vc.ReqData[idx].Key, "TAM_FLOWGROUP_TABLE|")) {
				flowsCount = flowsCount + 1
			}
		}

		// max flowgroups
		if flowsCount > MAX_FLOWGROUPS {
			return CVLErrorInfo{
				ErrCode:          CVL_SEMANTIC_ERROR,
				ConstraintErrMsg: fmt.Sprintf("Maximum number (%d) of flowgroups are already created.", MAX_FLOWGROUPS),
				CVLErrDetails:    "Config Validation Syntax Error",
				ErrAppTag:        "too-many-elements",
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) UniqueidValidation(vc *CustValidationCtxt) CVLErrorInfo {
	// ID must be unique
	log_request_info(vc, "UniqueidValidation")

	currentId := vc.YNodeVal

	currentSet := make(map[string]bool)
	flowgroupKeys, err := vc.RClient.Keys("TAM_FLOWGROUP_TABLE|*").Result()
	if err == nil {
		for _, flowGroupKey := range flowgroupKeys {
			val, err := vc.RClient.HGet(flowGroupKey, "id").Result()
			if err == nil {
				currentSet[val] = true
			}
		}
	}
	/*
	   if ((currentSet[currentId]) && (vc.CurCfg.VOp != OP_DELETE)) {
	       return CVLErrorInfo{
	           ErrCode: CVL_SEMANTIC_ERROR,
	           ConstraintErrMsg: fmt.Sprintf("Flowgroup with id '%s' is already created.", currentId),
	           CVLErrDetails : "Flowgroup id exists.",
	           ErrAppTag : "flowgroup-id-already-exist",
	       }
	   }
	*/
	id, _ := strconv.Atoi(currentId)
	if ((id < 2) || (id > 254)) && (vc.CurCfg.VOp != OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Invalid flowgroup id(%s), allowed range is 2-254.", currentId),
			CVLErrDetails:    "Invalid flowgroup id.",
			ErrAppTag:        "invalid-flowgroup-id",
		}
	}

	if !(currentSet[currentId]) && (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Flowgroup with id '%s' does not exist.", currentId),
			CVLErrDetails:    "Flowgroup id does not exists.",
			ErrAppTag:        "flowgroup-id-not-exist",
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) IfaSessionValidation(vc *CustValidationCtxt) CVLErrorInfo {
	log_request_info(vc, "IfaSessionValidation")

	status := getFeatureStatus("IFA")
	if (status == "UNSUPPORTED") || (status == "INSUFFICIENT_RESOURCES") {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: "IFA feature is not supported, operation not allowed",
			CVLErrDetails:    "Operation not allowed",
			ErrAppTag:        "operation-not-allowed",
		}
	}

	val, err := vc.RClient.HGet(vc.CurCfg.Key, "flowgroup").Result()
	if err != nil && err != redis.Nil {
		log.Info("IfaSessionValidation error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	thisSession := strings.Split(vc.CurCfg.Key, "|")[1]
	if (val != "") && (vc.CurCfg.VOp != OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Session '%s' is already created.", thisSession),
			CVLErrDetails:    "Session exists.",
			ErrAppTag:        "session-already-exist",
		}
	}

	if (val == "") && (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Session '%s' does not exist.", thisSession),
			CVLErrDetails:    "Session does not exists.",
			ErrAppTag:        "session-not-exist",
		}
	}

	// is flowgroup in use
	thisFlowgroup := vc.CurCfg.Data["flowgroup"]
	collectors, inUse := CheckUsage(vc, "flowgroup", thisFlowgroup)
	if (vc.CurCfg.VOp != OP_DELETE) && inUse {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("One or more sessions are using the flowgroup '%s'.", thisFlowgroup),
			CVLErrDetails:    "Flowgroup is in use.",
			ErrAppTag:        "flowgroup-in-use",
		}
	}

	// only single collector is allowed
	thisCollector, exists := vc.CurCfg.Data["collector"]
	if exists {
		c, e := collectors["ifa"]
		if e {
			if (c != "") && (thisCollector != c) {
				if vc.CurCfg.VOp != OP_DELETE {
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						ConstraintErrMsg: fmt.Sprintf("Only one collector can be used. Collector '%s' is in use.", c),
						CVLErrDetails:    "Only one collector can be used.",
						ErrAppTag:        "single-collector-allowed",
					}
				}
			}
			if vc.CurCfg.VOp != OP_DELETE {
				// Check for protocol of the collector, for IFA, it must be UDP
				tableName := "TAM_COLLECTORS_TABLE|" + thisCollector
				proto, er := vc.RClient.HGet(tableName, "protocol").Result()
				if er != nil {
					log.Info("******========****** Error in Collector protocol query : ", er)
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						ConstraintErrMsg: fmt.Sprintf(" Error in Collector protocol query '%s'", c),
						CVLErrDetails:    "Unknown internal error.",
						ErrAppTag:        "unknown-internal-error",
					}
				}
				if proto != "UDP" {
					log.Info("******========****** Unsupported collector protocol for IFA : ", proto)
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						ConstraintErrMsg: fmt.Sprintf("IFA supports only UDP protocol for collectors. Collector '%s' uses '%s'.", thisCollector, proto),
						CVLErrDetails:    "Invalid Collector protocol for IFA.",
						ErrAppTag:        "invalid-collector-protocol",
					}
				}
			}
		}
	}

	// both collector and sampler can't be specified
	_, collector_exists := vc.CurCfg.Data["collector"]
	_, sampler_exists := vc.CurCfg.Data["sample-rate"]
	if (vc.CurCfg.VOp != OP_DELETE) && (collector_exists && sampler_exists) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: "Collector and Sampler can not be configured together.",
			CVLErrDetails:    "Collector and Sampler can not be configured together.",
			ErrAppTag:        "invalid-usage",
		}
	}

	node_type := vc.CurCfg.Data["node-type"]
	// node type must be INGRESS, if sampler is configured
	if (vc.CurCfg.VOp != OP_DELETE) && ((sampler_exists) && (node_type != "INGRESS")) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: "Node type must be 'ingress' when configuring sampler.",
			CVLErrDetails:    "Node type must be 'ingress' when configuring sampler.",
			ErrAppTag:        "invalid-usage",
		}
	}

	// node type must be EGRESS, if collector is configured
	if (vc.CurCfg.VOp != OP_DELETE) && ((collector_exists) && (node_type != "EGRESS")) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: "Node type must be 'egress' when configuring collector.",
			CVLErrDetails:    "Node type must be 'egress' when configuring collector.",
			ErrAppTag:        "invalid-usage",
		}
	}

	// make sure flowgroup bound to port in case of sampler configured

	// Temporarily suspending this error checking to evaluate pre-configuration
	/*
	   if ((vc.CurCfg.VOp != OP_DELETE) && sampler_exists) {
	       inPorts, _ := vc.RClient.HGet("ACL_RULE|TAM|"+thisFlowgroup, "IN_PORTS@").Result()
	       if (inPorts == "") {
	           return CVLErrorInfo{
	               ErrCode: CVL_SEMANTIC_ERROR,
	               ConstraintErrMsg: fmt.Sprintf("No ports are bound the flowgroup '%s'.", thisFlowgroup),
	               CVLErrDetails : "Port(s) are not bound to the flowgroup",
	               ErrAppTag : "ports-not-bound-to-flowgroup",
	           }
	       }
	   }
	*/

	if vc.CurCfg.VOp != OP_DELETE {
		flow, isMatched := getFlowGroups(vc, "TAM_IFA_SESSIONS_TABLE", thisFlowgroup)
		if isMatched {
			return CVLErrorInfo{
				ErrCode:          CVL_SEMANTIC_ERROR,
				ConstraintErrMsg: fmt.Sprintf("Flowgroup (%v) with similar match criterion is already in use.", flow),
				CVLErrDetails:    "operation-not-allowed",
				ErrAppTag:        "operation-not-allowed",
			}
		}
	}
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) DropMonitorSessionValidation(vc *CustValidationCtxt) CVLErrorInfo {
	log_request_info(vc, "DropMonitorSessionValidation")

	status := getFeatureStatus("DROPMONITOR")
	if (status == "UNSUPPORTED") || (status == "INSUFFICIENT_RESOURCES") {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: "Dropmonitor feature is not supported, operation not allowed",
			CVLErrDetails:    "Operation not allowed",
			ErrAppTag:        "operation-not-allowed",
		}
	}

	val, err := vc.RClient.HGet(vc.CurCfg.Key, "flowgroup").Result()
	if err != nil && err != redis.Nil {
		log.Info("DropMonitorSessionValidation error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	thisSession := strings.Split(vc.CurCfg.Key, "|")[1]
	if (val != "") && (vc.CurCfg.VOp != OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Session '%s' is already created.", thisSession),
			CVLErrDetails:    "Session exists.",
			ErrAppTag:        "session-already-exist",
		}
	}

	if (val == "") && (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Session '%s' does not exist.", thisSession),
			CVLErrDetails:    "Session does not exists.",
			ErrAppTag:        "session-not-exist",
		}
	}

	// is flowgroup in use
	thisFlowgroup := vc.CurCfg.Data["flowgroup"]
	collectors, inUse := CheckUsage(vc, "flowgroup", thisFlowgroup)
	if (vc.CurCfg.VOp != OP_DELETE) && inUse {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("One or more sessions are using the flowgroup '%s'.", thisFlowgroup),
			CVLErrDetails:    "Flowgroup is in use.",
			ErrAppTag:        "flowgroup-in-use",
		}
	}

	// only single collector is allowed
	thisCollector, exists := vc.CurCfg.Data["collector"]
	if exists {
		c, e := collectors["dropmonitor"]
		if e {
			if (c != "") && (thisCollector != c) {
				if vc.CurCfg.VOp != OP_DELETE {
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						ConstraintErrMsg: fmt.Sprintf("Only one collector can be used. Collector '%s' is in use.", c),
						CVLErrDetails:    "Only one collector can be used.",
						ErrAppTag:        "single-collector-allowed",
					}
				}
			}
			if vc.CurCfg.VOp != OP_DELETE {
				// Check for protocol of the collector, for DropMonitor, it must be UDP
				tableName := "TAM_COLLECTORS_TABLE|" + thisCollector
				proto, er := vc.RClient.HGet(tableName, "protocol").Result()
				if er != nil {
					log.Info("******========****** Error in Collector protocol query : ", er)
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						ConstraintErrMsg: fmt.Sprintf(" Error in Collector protocol query '%s'", c),
						CVLErrDetails:    "Unknown internal error.",
						ErrAppTag:        "unknown-internal-error",
					}
				}
				if proto != "UDP" {
					log.Info("******========****** Unsupported collector protocol for DropMonitor : ", proto)
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						ConstraintErrMsg: fmt.Sprintf("DropMonitor supports only UDP protocol for collectors. Collector '%s' uses '%s'.", thisCollector, proto),
						CVLErrDetails:    "Invalid Collector protocol for DropMonitor.",
						ErrAppTag:        "invalid-collector-protocol",
					}
				}
			}
		}
	}

	// make sure flowgroup bound to port in case of sampler configured

	// Temporarily suspending this error checking to evaluate pre-configuration
	/*
	   if (vc.CurCfg.VOp != OP_DELETE) {
	       inPorts, _ := vc.RClient.HGet("ACL_RULE|TAM|"+thisFlowgroup, "IN_PORTS@").Result()
	       if (inPorts == "") {
	           return CVLErrorInfo{
	               ErrCode: CVL_SEMANTIC_ERROR,
	               ConstraintErrMsg: fmt.Sprintf("No ports are bound to the flowgroup '%s'.", thisFlowgroup),
	               CVLErrDetails : "Port(s) are not bound to the flowgroup",
	               ErrAppTag : "ports-not-bound-to-flowgroup",
	           }
	       }
	   }
	*/
	if vc.CurCfg.VOp != OP_DELETE {
		flow, isMatched := getFlowGroups(vc, "TAM_DROPMONITOR_SESSIONS_TABLE", thisFlowgroup)
		if isMatched {
			return CVLErrorInfo{
				ErrCode:          CVL_SEMANTIC_ERROR,
				ConstraintErrMsg: fmt.Sprintf("Flowgroup (%v) with similar match criterion is already in use.", flow),
				CVLErrDetails:    "operation-not-allowed",
				ErrAppTag:        "operation-not-allowed",
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) TailstampingSessionValidation(vc *CustValidationCtxt) CVLErrorInfo {
	log_request_info(vc, "TailstampingSessionValidation")

	status := getFeatureStatus("TAILSTAMPING")
	if (status == "UNSUPPORTED") || (status == "INSUFFICIENT_RESOURCES") {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: "Tailstamping feature is not supported, operation not allowed",
			CVLErrDetails:    "Operation not allowed",
			ErrAppTag:        "operation-not-allowed",
		}
	}

	val, err := vc.RClient.HGet(vc.CurCfg.Key, "flowgroup").Result()
	if err != nil && err != redis.Nil {
		log.Info("TailstampingSessionValidation error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	thisSession := strings.Split(vc.CurCfg.Key, "|")[1]
	if (val != "") && (vc.CurCfg.VOp != OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Session '%s' is already created.", thisSession),
			CVLErrDetails:    "Session exists.",
			ErrAppTag:        "session-already-exist",
		}
	}

	if (val == "") && (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("Session '%s' does not exist.", thisSession),
			CVLErrDetails:    "Session does not exists.",
			ErrAppTag:        "session-not-exist",
		}
	}

	// is flowgroup in use
	thisFlowgroup := vc.CurCfg.Data["flowgroup"]
	_, inUse := CheckUsage(vc, "flowgroup", thisFlowgroup)
	if (vc.CurCfg.VOp != OP_DELETE) && inUse {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			ConstraintErrMsg: fmt.Sprintf("One or more sessions are using the flowgroup '%s'.", thisFlowgroup),
			CVLErrDetails:    "Flowgroup is in use.",
			ErrAppTag:        "flowgroup-in-use",
		}
	}

	if vc.CurCfg.VOp != OP_DELETE {
		flow, isMatched := getFlowGroups(vc, "TAM_TAILSTAMPING_SESSIONS_TABLE", thisFlowgroup)
		if (vc.CurCfg.VOp != OP_DELETE) && isMatched {
			return CVLErrorInfo{
				ErrCode:          CVL_SEMANTIC_ERROR,
				ConstraintErrMsg: fmt.Sprintf("Flowgroup (%v) with similar match criterion is already in use.", flow),
				CVLErrDetails:    "operation-not-allowed",
				ErrAppTag:        "operation-not-allowed",
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) ValidateFeatureStatus(vc *CustValidationCtxt) CVLErrorInfo {

	log_request_info(vc, "ValidateFeatureStatus")

	stateDBClient := util.NewDbClient("STATE_DB")
	defer func() {
		if stateDBClient != nil {
			stateDBClient.Close()
		}
	}()

	if stateDBClient == nil {
		return CVLErrorInfo{
			ErrCode:          CVL_INTERNAL_UNKNOWN,
			ConstraintErrMsg: "Failed to connect to STATE_DB",
			CVLErrDetails:    "Config Validation Error",
			ErrAppTag:        "retry-request",
		}
	}

	// check if feature status is inactive in "STATE_DB"
	// in table TAM_STATE_FEATURES_TABLE.
	thisFeature := strings.Split(vc.CurCfg.Key, "|")
	key := "TAM_STATE_FEATURES_TABLE|" + thisFeature[1]
	featuresInfo, _ := stateDBClient.HGetAll(key).Result()

	if (vc.CurCfg.VOp == OP_CREATE) || (vc.CurCfg.VOp == OP_UPDATE) {
		if (featuresInfo["op-status"] == "INSUFFICIENT_RESOURCES") ||
			(featuresInfo["op-status"] == "UNSUPPORTED") {
			errMsg := ""
			appTag := ""
			if featuresInfo["op-status"] == "INSUFFICIENT_RESOURCES" {
				errMsg = fmt.Sprintf("Insufficient Resources, %v feature can not be enabled.", getFeatureName[thisFeature[1]])
				appTag = "insufficient-resources"
			} else {
				errMsg = fmt.Sprintf("%v feature is not supported.", getFeatureName[thisFeature[1]])
				appTag = "feature-unsupported"
			}
			return CVLErrorInfo{
				ErrCode:          CVL_SEMANTIC_ERROR,
				ConstraintErrMsg: errMsg,
				CVLErrDetails:    errMsg,
				ErrAppTag:        appTag,
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
