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
	"fmt"
	"strconv"
	"strings"

	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	"github.com/go-redis/redis/v7"
	log "github.com/golang/glog"
)

const MAX_ACL_RULE_INSTANCES = 65536
const MAX_ACL_TABLE_INSTANCES = 1024

//ValidateMaxAclRule Allow maximum 65536 ACL rules
/////////////////////////////////////////////
//MAX_ACL_RULE_INSTANCES Path : /sonic-acl/ACL_RULE/ACL_RULE_LIST
//Purpose: Allow maximum 65536 ACL rules
//vc : Custom Validation Context
//Returns -  CVL Error object
func (t *CustomValidation) ValidateMaxAclRule(vc *CustValidationCtxt) CVLErrorInfo {
	var nokey []string
	ls := redis.NewScript(`return #redis.call('KEYS', "ACL_RULE|*")`)

	//Get current coutnt from Redis
	redisEntries, err := ls.Run(vc.RClient, nokey).Result()
	if err != nil {
		return CVLErrorInfo{ErrCode: CVL_SEMANTIC_ERROR}
	}

	aclRuleCount := int(redisEntries.(int64))
	//Get count from user request
	for idx := 0; idx < len(vc.ReqData); idx++ {
		if (vc.ReqData[idx].VOp == OP_CREATE) &&
			(strings.HasPrefix(vc.ReqData[idx].Key, "ACL_RULE|")) {
			aclRuleCount = aclRuleCount + 1
		}
	}

	if aclRuleCount > MAX_ACL_RULE_INSTANCES {
		return CVLErrorInfo{
			ErrCode:       CVL_SEMANTIC_ERROR,
			ErrAppTag:     "too-many-elements",
			Msg:           fmt.Sprintf("Max elements limit %d reached", MAX_ACL_RULE_INSTANCES),
			CVLErrDetails: "Config Validation Syntax Error",
			TableName:     "ACL_RULE",
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//ValidateAclRuleIPAddress Check correct for IP address provided
//Purpose: Check correct for IP address provided
//         based on type IP_TYPE
//vc : Custom Validation Context
//Returns -  CVL Error object
func (t *CustomValidation) ValidateAclRuleIPAddress(
	vc *CustValidationCtxt) CVLErrorInfo {

	if (vc.CurCfg.VOp == OP_DELETE) || (vc.CurCfg.VOp == OP_UPDATE) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	if vc.YNodeVal == "" {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	if vc.YNodeVal == "ANY" || vc.YNodeVal == "IP" ||
		vc.YNodeVal == "IPV4" || vc.YNodeVal == "IPV4ANY" {

		_, srcIpV4exists := vc.CurCfg.Data["SRC_IP"]
		_, dstIpV4exists := vc.CurCfg.Data["DST_IP"]

		if !srcIpV4exists || !dstIpV4exists {
			return CVLErrorInfo{
				ErrCode:   CVL_SEMANTIC_ERROR,
				TableName: "ACL_RULE",
				CVLErrDetails: "IP address is missing for " +
					"IP_TYPE=" + vc.YNodeVal,
			}
		}

	} else if vc.YNodeVal == "ANY" || vc.YNodeVal == "IP" ||
		vc.YNodeVal == "IPV6" || vc.YNodeVal == "IPV6ANY" {

		_, srcIpV6exists := vc.CurCfg.Data["SRC_IPV6"]
		_, dstIpV6exists := vc.CurCfg.Data["DST_IPV6"]

		if !srcIpV6exists || !dstIpV6exists {
			return CVLErrorInfo{
				ErrCode:   CVL_SEMANTIC_ERROR,
				TableName: "ACL_RULE",
				CVLErrDetails: "IP address is missing for " +
					"IP_TYPE=" + vc.YNodeVal,
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

// ValidateLeafConstant Path: generic
// Purpose: To make sure the value of a leaf is not changed after its set during create
// Returns -  CVL Error object
func (t *CustomValidation) ValidateLeafConstant(vc *CustValidationCtxt) CVLErrorInfo {

	log.Infof("ValidateLeafConstant operation %d on %s:%s:%s  ", vc.CurCfg.VOp, vc.CurCfg.Key, vc.YNodeName, vc.YNodeVal)

	if vc.CurCfg.VOp == OP_CREATE || vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	//if vc.CurCfg.VOp == OP_DELETE {
	//	return CVLErrorInfo{ErrCode: CVL_ERROR, Keys: []string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName, Msg: "Field delete not allowed",
	//		ErrAppTag: "delete-not-allowed"}
	//}

	val, err := vc.RClient.HGet(vc.CurCfg.Key, vc.YNodeName).Result()
	if err != nil && err != redis.Nil {
		log.Info("ValidateLeafConstant error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	if err == redis.Nil {
		log.Info("No old value is set. Allow update")
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	log.Infof("ValidateLeafConstant Old value is %s", val)

	if val != vc.YNodeVal {
		log.Errorf("%s:%s value change from %s to %s not allowed", vc.CurCfg.Key, vc.YNodeName, val, vc.YNodeVal)
		return CVLErrorInfo{ErrCode: CVL_ERROR, Keys: []string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName, Msg: "Field update not allowed",
			ErrAppTag: "update-not-allowed"}
	}

	log.Infof("ValidateLeafConstant update doesnt change the value. allow")
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

// ValidateZeroACLCounters ensures that there are no ACL counters present when the counter mode is updated
// Returns -  CVL Error object
func (t *CustomValidation) ValidateZeroACLCounters(vc *CustValidationCtxt) CVLErrorInfo {
	log.Infof("ValidateZeroACLCounters operation %d on %s:%s:%s  ", vc.CurCfg.VOp, vc.CurCfg.Key, vc.YNodeName, vc.YNodeVal)

	if (vc.CurCfg.VOp == OP_CREATE) || (vc.CurCfg.VOp == OP_DELETE) {
		log.Info("ValidateZeroACLCounters create or delete not allowed")
		return CVLErrorInfo{ErrCode: CVL_FAILURE}
	}

	counterDBClient := util.NewDbClient("COUNTERS_DB")
	defer func() {
		if counterDBClient != nil {
			counterDBClient.Close()
		}
	}()

	if counterDBClient == nil {
		return CVLErrorInfo{
			ErrCode:          CVL_INTERNAL_UNKNOWN,
			ConstraintErrMsg: "Failed to connect to COUNTERS_DB",
			CVLErrDetails:    "Config Validation Error",
			ErrAppTag:        "retry-request",
		}
	}

	val, err := vc.RClient.HGet(vc.CurCfg.Key, vc.YNodeName).Result()
	if err != nil && err != redis.Nil {
		log.Info("ValidateZeroACLCounters error getting old value:", err)
		return CVLErrorInfo{ErrCode: CVL_ERROR}
	}

	if val == vc.YNodeVal {
		log.Info("ValidateZeroACLCounters Value %v doesnt change. Allow", val)
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	tableKeys, err := counterDBClient.Keys("ACL_COUNTERS:*").Result()
	if nil != err {
		return CVLErrorInfo{
			ErrCode:          CVL_INTERNAL_UNKNOWN,
			ConstraintErrMsg: "Error getting ACL_COUNTER entries",
			CVLErrDetails:    "Config Validation Error",
			ErrAppTag:        "retry-request",
		}
	}
	if len(tableKeys) > 0 {
		log.Errorf("ValidateZeroACLCounters %v ACL Counters present. Update not allowed", len(tableKeys))
		return CVLErrorInfo{ErrCode: CVL_ERROR, Keys: []string{vc.CurCfg.Key}, Value: vc.YNodeVal,
			Field: vc.YNodeName, Msg: "Counter mode update not allowed", ErrAppTag: "counters-in-use"}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

// ValidateEgressConfig validates the set interface config to ensure no duplicates
// Returns -  CVL Error object
func (t *CustomValidation) ValidateEgressConfig(vc *CustValidationCtxt) CVLErrorInfo {

	log.Infof("ValidateEgressConfig operation %d on %s %s=%s", vc.CurCfg.VOp, vc.CurCfg.Key, vc.YNodeName, vc.YNodeVal)
	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	egressMap := make(map[string]bool)
	data, found := vc.CurCfg.Data[vc.YNodeName+"@"]
	if !found {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	log.Infof("ValidateEgressConfig value is %v", data)

	egresses := strings.Split(data, ",")
	for _, egress := range egresses {
		key := egress[:strings.LastIndex(egress, "|")]
		if _, exists := egressMap[key]; exists {
			return CVLErrorInfo{ErrCode: CVL_ERROR, Keys: []string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
				Msg: "Adding duplicate entries or updating entries not allowed"}
		}
		egressMap[key] = true
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

// ValidateGroupTypeMatches validates if the group type matches the context in which its used
// Returns -  CVL Error object
func (t *CustomValidation) ValidateGroupTypeMatches(vc *CustValidationCtxt) CVLErrorInfo {
	log.Infof("ValidateGroupTypeMatches operation %d on %s %s=%s", vc.CurCfg.VOp, vc.CurCfg.Key, vc.YNodeName, vc.YNodeVal)

	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	err := t.ValidateEgressConfig(vc)
	if err.ErrCode != CVL_SUCCESS {
		return err
	}
	data, found := vc.CurCfg.Data[vc.YNodeName+"@"]
	if !found {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	log.Infof("ValidateGroupTypeMatches value is %v", data)

	grp_type := "IPV4"
	if vc.YNodeName == "SET_IPV6_NEXTHOP_GROUP" {
		grp_type = "IPV6"
	}

	set_groups := strings.Split(data, ",")
	for _, set_group := range set_groups {
		group_name := set_group[:strings.LastIndex(set_group, "|")]
		val, err := vc.RClient.HGet("PBF_NEXTHOP_GROUP|"+group_name, "TYPE").Result()
		if err != nil && err != redis.Nil {
			log.Info("ValidateGroupTypeMatches error getting old value:", err)
			return CVLErrorInfo{ErrCode: CVL_ERROR}
		}
		if err == redis.Nil {
			log.Infof("ValidateGroupTypeMatches group %v doesnt exist", group_name)
			continue
		}
		log.Infof("ValidateGroupTypeMatches group %v type:%v/%v", group_name, grp_type, val)
		if val != grp_type {
			if grp_type == "IPV4" {
				return CVLErrorInfo{
					ErrCode:          CVL_FAILURE,
					ConstraintErrMsg: "Using IPv6 group as IPv4 group is not allowed",
					CVLErrDetails:    "Config Validation Error",
					ErrAppTag:        "invalid-request",
				}
			} else {
				return CVLErrorInfo{
					ErrCode:          CVL_FAILURE,
					ConstraintErrMsg: "Using IPv4 group as IPv6 group is not allowed",
					CVLErrDetails:    "Config Validation Error",
					ErrAppTag:        "invalid-request",
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

// ValidateCpuQueueId validates the trap queue range
// Returns -  CVL Error object
func (t *CustomValidation) ValidateCpuQueueId(vc *CustValidationCtxt) CVLErrorInfo {

	log.Infof("ValidateCpuQueueId operation %d on %s:%s:%s", vc.CurCfg.VOp, vc.CurCfg.Key, vc.YNodeName, vc.YNodeVal)
	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	stateDBClient := util.NewDbClient("STATE_DB")
	defer func() {
		if stateDBClient != nil {
			stateDBClient.Close()
		}
	}()

	if stateDBClient != nil {
		key := "SWITCH_CAPABILITY|switch"
		numCpuQueues, err := stateDBClient.HGet(key, "num_cpu_queues").Result()
		if err == nil {
			maxCount, _ := strconv.Atoi(numCpuQueues)
			if maxCount != 0 {
				availableCount := maxCount
				if maxCount == 48 {
					availableCount = 32 // Remaining 16 Queues are reserved
				} else if maxCount == 32 {
					availableCount = 24 // TD2: Remaining 8 Queues are reserved
				}
				currentQueueId := vc.YNodeVal
				id, _ := strconv.Atoi(currentQueueId)
				if id > (availableCount - 1) {
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						ConstraintErrMsg: fmt.Sprintf("Invalid queue id(%s), allowed value is less than %d on this platform.", currentQueueId, availableCount),
						CVLErrDetails:    "Invalid queue id.",
						ErrAppTag:        "invalid-queue-id",
					}
				}
			}
		}
	}
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
