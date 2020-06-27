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
	"fmt"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
	"github.com/go-redis/redis/v7"
	log "github.com/golang/glog"
	"strings"
)

func init() {
    XlateFuncBind("ports_alias_value_xfmr", acl_ports_alias_value_xfmr)
	XlateFuncBind("rpc_clear_acl_counters", rpc_clear_acl_counters)
}

func acl_ports_alias_value_xfmr(inParams XfmrDbParams) (string, error) {
    var err error

    if !utils.IsAliasModeEnabled() {
        log.Info("Alias mode is not enabled!")
        return inParams.value, err
    }
    parts := strings.Split(inParams.value, ",")
    converted := make([]string, len(parts))

    for idx, part := range parts {
        if inParams.oper == GET {
            converted[idx] = *utils.GetUINameFromNativeName(&part)
        } else {
            converted[idx] = *utils.GetNativeNameFromUIName(&part)
        }
    }
    ret := strings.Join(converted, ",")
    log.Infof("%s => %s", inParams.value, ret)

    return ret, err
}

/* RPC for clear counters */
var rpc_clear_acl_counters RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
	var err error

	log.Infof("Inside rpc_clear_acl_counters: Input: %s", string(body))

	var result struct {
		Output struct {
			Status        string `json:"status"`
			Status_detail string `json:"status-detail"`
		} `json:"sonic-acl:output"`
	}

	/* Get input data */
	var inputParams map[string]interface{}
	err = json.Unmarshal(body, &inputParams)
	if err != nil {
		log.Info("Failed to unmarshall given input data")
		result.Output.Status = "INVALID_PAYLOAD"
		result.Output.Status_detail = "Failed to unmarshall given input data"
		json, _ := json.Marshal(&result)
		return json, tlerr.InvalidArgs("INVALID_PAYLOAD")
	}

	if input, err := inputParams["sonic-acl:input"]; err {
		inputParams = input.(map[string]interface{})
	} else {
		result.Output.Status = "INVALID_PAYLOAD"
		result.Output.Status_detail = "No input"
		json, _ := json.Marshal(&result)
		return json, tlerr.InvalidArgs("INVALID_PAYLOAD")
	}

	log.Info("Input=", inputParams)
	entry, err := dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name: "HARDWARE"},
		db.Key{Comp: []string{"ACCESS_LIST"}})
	if err != nil {
		result.Output.Status = "FAILED"
		result.Output.Status_detail = "Table not found in the database"
		json, _ := json.Marshal(&result)
		return json, tlerr.InvalidArgs("ACL_NOT_FOUND")
	}

	//log.Info("Value=", entry)
	counter_mode, found := entry.Field["COUNTER_MODE"]
	if !found {
		result.Output.Status = "FAILED"
		result.Output.Status_detail = "Counter mode not set"
		json, _ := json.Marshal(&result)
		return json, tlerr.New("FAILED")
	}
	log.Info("Counter mode is ", counter_mode)

	acl_type, found := inputParams["type"]
	if !found {
		result.Output.Status = "INVALID_PAYLOAD"
		result.Output.Status_detail = "ACL Type missing"
		json, _ := json.Marshal(&result)
		return json, tlerr.InvalidArgs("INVALID_PAYLOAD")
	}
	acl_type_str := fmt.Sprintf("%v", acl_type)

	intf_str := ""
	intf, found := inputParams["ifname"]
	if found {
		intf_str = fmt.Sprintf("%v", intf)
		if !strings.EqualFold(counter_mode, "per-interface-rule") {
			result.Output.Status = "COUNTER_MODE_MISMATCH"
			result.Output.Status_detail = "Counter mode is set to per-entry. Per interface counters not available"
			json, _ := json.Marshal(&result)
			return json, tlerr.InvalidArgs("COUNTER_MODE_MISMATCH")
		}
	}

	log.Infof("ACL:%v Intf:%v", acl_type_str, intf_str)

	var acls_list []string
	var intf_list []string

	aclname, found := inputParams["aclname"]
	if !found {
		acltable := &db.TableSpec{Name: "ACL_TABLE"}
		acls, err := dbs[db.ConfigDB].GetKeys(acltable)
		if nil != err {
			result.Output.Status = "FAILED"
			result.Output.Status_detail = "Error getting ACLs from database"
			json, _ := json.Marshal(&result)
			return json, tlerr.New("FAILED")
		}

		acls_list = make([]string, 0, len(acls))
		intf_list = append(intf_list, "*")

		for _, name := range acls {
			if ok, _ := validateAclTypeAndNameMatch(name.Comp[0], acl_type_str, dbs); ok {
				acls_list = append(acls_list, name.Comp[0])
			}
		}
	} else {
		aclname_str := fmt.Sprintf("%v", aclname)
/*
		if acl_type == "L2" {
			aclname_str = aclname_str + "_ACL_L2"
		} else if acl_type == "L3" {
			aclname_str = aclname_str + "_ACL_IPV4"
		} else if acl_type == "L3V6" {
			aclname_str = aclname_str + "_ACL_IPV6"
		}
*/

		ok, data := validateAclTypeAndNameMatch(aclname_str, acl_type_str, dbs)
		if ok {
			acls_list = append(acls_list, aclname_str)
		} else if nil == data {
			result.Output.Status = "ACL_NOT_FOUND"
			result.Output.Status_detail = "ACL Not found"
			json, _ := json.Marshal(&result)
			return json, tlerr.New("ACL_NOT_FOUND")
		} else {
			result.Output.Status = "ACL_TYPE_MISMATCH"
			result.Output.Status_detail = "ACL name and type mismatch"
			json, _ := json.Marshal(&result)
			return json, tlerr.New("ACL_TYPE_MISMATCH")
		}
		log.Info(data)

		if len(intf_str) == 0 {
			if strings.EqualFold(counter_mode, "per-interface-rule") {
				intf_list = data.GetList("ports@")
				if len(intf_list) == 0 {
					intf_list = data.GetList("PORTS@")
				}
			}
		} else {
			bindings := data.GetList("ports@")
			if len(bindings) == 0 {
				bindings = data.GetList("PORTS@")
			}
			for _, port := range bindings {
				if port == intf_str {
					intf_list = append(intf_list, intf_str)
				}
			}
			if len(intf_list) == 0 {
				result.Output.Status = "ACL_BINDING_NOT_FOUND"
				result.Output.Status_detail = "ACL not applied"
				json, _ := json.Marshal(&result)
				return json, tlerr.NotFound("ACL_BINDING_NOT_FOUND")
			}
		}
	}

	lua_script_clear := redis.NewScript(`
        redis.replicate_commands()
        local all_rules = {}
        for p, pattern in ipairs(ARGV) do
            local cursor = "0"
            repeat
                local result = redis.call("SCAN", cursor, "MATCH", pattern)
                cursor = result[1]
                local rules = result[2]
                for i = 1, #rules do
                    all_rules[#all_rules + 1] = rules[i]
                    local key = rules[i]
                    local key2 = "LAST_" .. key
                    local data = redis.call("HGETALL", key)
                    redis.call("HMSET", key2, unpack(data))
                end
            until cursor == "0"
        end
        return all_rules`)

	if nil == lua_script_clear {
		result.Output.Status = "FAILED"
		result.Output.Status_detail = "Error loading lua script"
		json, _ := json.Marshal(&result)
		return json, tlerr.New("FAILED")
	}

	log.Infof("ACLs to clear is %v", acls_list)
	log.Infof("Intfs to clear is %v", intf_list)
	//log.Infof("Lua is %v", lua_script_clear)

	var patterns []string
	if strings.EqualFold(counter_mode, "per-interface-rule") {
		for _, acl := range acls_list {
			for _, intf := range intf_list {
				patterns = append(patterns, fmt.Sprintf("ACL_COUNTERS:%s:*:%s:*", acl, intf))
			}
		}
	} else {
		for _, acl := range acls_list {
			patterns = append(patterns, fmt.Sprintf("ACL_COUNTERS:%s:*", acl))
		}
	}

	log.Infof("Patters are %v", patterns)
	result.Output.Status = "SUCCESS"
	result.Output.Status_detail = ""
	if len(patterns) > 0 {
		var nokey []string
		var args = make([]interface{}, len(patterns))
		for i, pattern := range patterns {
			args[i] = pattern
		}
		data, err := dbs[db.CountersDB].RunScript(lua_script_clear, nokey, args...).Result()
		if nil != err {
			log.Error(err)
			result.Output.Status = "FAILED"
			result.Output.Status_detail = "Error running lua script"
			json, _ := json.Marshal(&result)
			return json, tlerr.New("FAILED")
		} else {
			log.Info("Cleared counters for ", data)
		}
	}

	return json.Marshal(&result)
}

func validateAclTypeAndNameMatch(acl_name string, acl_type string, dbs [db.MaxDB]*db.DB) (bool, *db.Value) {

	acltable := &db.TableSpec{Name: "ACL_TABLE"}
	aclData, err := dbs[db.ConfigDB].GetEntry(acltable, db.Key{Comp: []string{acl_name}})
	if nil != err {
		log.Errorf("ACL:%v-%v Err:%v", acl_name, acl_type, err)
		return false, nil
	}

	aclType, found := aclData.Field["type"]
	if !found {
		aclType, found = aclData.Field["TYPE"]
	}
	if found && strings.EqualFold(aclType, acl_type) {
		log.Infof("ACL:%v-%v is of type %v", acl_name, acl_type, aclType)
		return true, &aclData
	}

	log.Infof("ACL:%v-%v is not of type %v", acl_name, acl_type, aclType)
	return false, nil
}
