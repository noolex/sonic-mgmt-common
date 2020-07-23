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
	"fmt"
	"strings"
)

//ValidateIpv4UnnumIntf Custom validation for Unnumbered interface
func (t *CustomValidation) ValidateIpv4UnnumIntf(vc *CustValidationCtxt) CVLErrorInfo {

	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	if vc.YNodeVal == "" {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS} //Allow empty value
	}

	keys := "LOOPBACK_INTERFACE|" + vc.YNodeVal + "|*"
	util.CVL_LEVEL_LOG(util.INFO, "Keys: %s", keys)
	tableKeys, err := vc.RClient.Keys(keys).Result()

	if err != nil {
		util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "LOOPBACK_INTERFACE is empty or invalid argument")
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	count := 0
	for _, dbKey := range tableKeys {
		if strings.Contains(dbKey, ".") {
			count++
		}
	}

	util.CVL_LEVEL_LOG(util.INFO, "Donor intf IP count: %d", count)
	if count > 1 {
		util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Donor interface has multiple IPv4 address")
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        "LOOPBACK_INTERFACE",
			Keys:             strings.Split(vc.CurCfg.Key, "|"),
			ConstraintErrMsg: "Multiple IPv4 address configured on Donor interface. Cannot configure IP Unnumbered",
			CVLErrDetails:    "Config Validation Error",
			ErrAppTag:        "donor-multi-ipv4-addr",
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//ValidateMtuForPOMemberCount Custom validation for MTU configuration on PortChannel
func (t *CustomValidation) ValidateMtuForPOMemberCount(vc *CustValidationCtxt) CVLErrorInfo {
	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	keys := strings.Split(vc.CurCfg.Key, "|")
	if len(keys) > 0 {
		if keys[0] == "PORTCHANNEL_MEMBER" {
			poName := keys[1]
			intfName := keys[2]

			if vc.CurCfg.VOp == OP_CREATE {
				poData, err := vc.RClient.HGetAll("PORTCHANNEL|" + poName).Result()
				if err != nil {
					return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
				}
				intfData, err1 := vc.RClient.HGetAll("PORT|" + intfName).Result()
				if err1 != nil {
					return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
				}

				poMtu, hasPoMtu := poData["mtu"]
				intfMtu := intfData["mtu"]
				util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateMtuForPOMemberCount: PO MTU=%v and Intf MTU=%v", poMtu, intfMtu)

				if hasPoMtu && poMtu != intfMtu {
					util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Members can't be added to portchannel when member MTU not same as portchannel MTU")
					return CVLErrorInfo{
						ErrCode:          CVL_SEMANTIC_ERROR,
						TableName:        "PORTCHANNEL_MEMBER",
						Keys:             strings.Split(vc.CurCfg.Key, "|"),
						ConstraintErrMsg: "Configuration not allowed when port MTU not same as portchannel MTU",
						ErrAppTag:        "mtu-invalid",
					}
				}

				poMembersKeys, err := vc.RClient.Keys("PORTCHANNEL_MEMBER|" + poName + "|*").Result()
				if err != nil {
				   return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
				}

				if len(poMembersKeys) > 0 {
					intfData, err1 := vc.RClient.HGetAll("PORT|" + intfName).Result()
					if err1 != nil {
						return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
					}

					intfSpeed, intfHasSpeed := intfData["speed"]
					poMemKey := poMembersKeys[0]
					poMember := strings.Split(poMemKey, "|")
					poMemData, err1 := vc.RClient.HGetAll("PORT|" + poMember[2]).Result()
					if err1 != nil {
						return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
					}

					poMemSpeed, poMemHasSpeed := poMemData["speed"]
					if intfHasSpeed && poMemHasSpeed && intfSpeed != poMemSpeed {
						util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Members can't be added to portchannel when member speed is not same as existing members")
						return CVLErrorInfo{
								ErrCode:          CVL_SEMANTIC_ERROR,
								TableName:        "PORT",
								Keys:             strings.Split(vc.CurCfg.Key, "|"),
								ConstraintErrMsg: "Configuration not allowed when port speed is different than existing member of Portchannel.",
								ErrAppTag:        "speed-invalid",
						}
					}
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}


//ValidatePortChannelCreationDeletion Custom validation for PortChannel creation or deletion
func (t *CustomValidation) ValidatePortChannelCreationDeletion(vc *CustValidationCtxt) CVLErrorInfo {
	if vc.CurCfg.VOp == OP_CREATE {

	        keys := strings.Split(vc.CurCfg.Key, "|")
	        if len(keys) > 0 {
		        if keys[0] == "PORTCHANNEL" {
			        poKeys, err := vc.RClient.Keys("PORTCHANNEL" + "|*").Result()
			        if err != nil {
				         return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
			        }

			        if len(poKeys) >= 128 {
				        util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Maximum number of portchannels already created.")
				        return CVLErrorInfo{
					        ErrCode:          CVL_SEMANTIC_ERROR,
					        TableName:        "PORTCHANNEL",
					        Keys:             strings.Split(vc.CurCfg.Key, "|"),
					        ConstraintErrMsg: "Maximum number(128) of portchannels already created in the system. Cannot create new portchannel.",
					        ErrAppTag:        "max-reached",
				        }
			        }
                       }
                }
        }

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) ValidateVlanMember (vc *CustValidationCtxt) CVLErrorInfo {
	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	yangNodeVal := vc.YNodeVal
	yangNodeName := vc.YNodeName
	redisKey := vc.CurCfg.Key
	rediskeyList := strings.SplitN(redisKey, "|", 2)
	tableName := rediskeyList[0]
	tableKey := rediskeyList[1]
	util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateVlanMember: validating table: %v|%v for node: %v[%v]\n", tableName, tableKey, yangNodeName, yangNodeVal)

	if tableName == "VLAN" && yangNodeName == "members" {
		if len(vc.CurCfg.Data) > 0 {
			// On adding or deleting element to leaf-list, always generates UPDATE request
			// and yangNodeVal may be empty. So to determine the correct element on which
			// operation is going, we need to query all elements of leaf-list from DB and
			// compare with leaf-list received in CurCfg.Data.
			membersInReq := vc.CurCfg.Data["members@"]
			tblData, _ := vc.RClient.HGetAll(redisKey).Result()
			membersInDb := tblData["members@"]

			var membersNames []string
			// Data in DB is not present, means new element getting added
			if len(membersInDb) == 0 {
				membersNames = strings.Split(membersInReq, ",")
			} else {
				elemFromDb := strings.Split(membersInDb, ",")
				elemFromReq := strings.Split(membersInReq, ",")
				// Adding interface to leaf-list have entry in request but not in DB
				// Deleting interface from leaf-list have entry in DB but not in request
				// So their difference will provide the interface under operation
				membersNames = util.GetDifference(elemFromDb, elemFromReq)
			}
			util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateVlanMember: validating for member(s): %v\n", membersNames)

			// No Vlan member provided. Skip further validation.
			if len(membersNames) == 0 {
				return CVLErrorInfo{ErrCode: CVL_SUCCESS}
			}

			for _, memberName := range membersNames {
				if len(memberName) == 0 {
					continue
				}
				if strings.HasPrefix(memberName, "PortChannel") {
					// Verify whether Portchannel and its members both are applied for switchport
					pomemberKeys, _ := vc.RClient.Keys("PORTCHANNEL_MEMBER|" + memberName + "|*").Result()
					for _, ky := range pomemberKeys {
						pomemberName := ky[strings.LastIndex(ky, "|")+1:]
						if strings.Contains(membersInReq, pomemberName+",") || strings.HasSuffix(membersInReq, pomemberName) {
							return CVLErrorInfo {
								ErrCode: CVL_SEMANTIC_ERROR,
								TableName: tableName,
								Keys: strings.Split(tableKey, "|"),
								ConstraintErrMsg: "A vlan interface member cannot be part of portchannel which is already a vlan member",
								CVLErrDetails: "Config Validation Semantic Error",
							}
						}
					}
				} else if strings.HasPrefix(memberName, "Ethernet") {
					// Verify if port is already member of any portchannel
					pomemberKeys, _ := vc.RClient.Keys("PORTCHANNEL_MEMBER|*|" + memberName).Result()
					if len(pomemberKeys) > 0 {
						return CVLErrorInfo {
							ErrCode: CVL_SEMANTIC_ERROR,
							TableName: tableName,
							Keys: strings.Split(tableKey, "|"),
							ConstraintErrMsg: "A Portchannel member cannot be added as vlan member",
							CVLErrDetails: "Config Validation Semantic Error",
						}
					}
				}
				// Check for mirror session
				errInf := validateDstPortOfMirrorSession(vc, tableName, tableKey, memberName)
				if errInf.ErrCode != CVL_SUCCESS {
					return errInf
				}
			}
		}
	} else if tableName == "VLAN_MEMBER" && yangNodeName == "ifname" {
		return validateDstPortOfMirrorSession(vc, tableName, tableKey, yangNodeVal)
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func validateDstPortOfMirrorSession(vc *CustValidationCtxt, tableName, tableKey, portName string) CVLErrorInfo {
	if len(portName) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	predicate := fmt.Sprintf("return (h['dst_port'] ~= nil and h['dst_port'] == '%s')", portName)
	entries, _ := util.FILTER_ENTRIES_LUASCRIPT.Run(vc.RClient, []string{}, "MIRROR_SESSION|*", "name", predicate, "dst_port").Result()
	if entries != nil {
		entriesJson := string(entries.(string))
		if strings.Contains(entriesJson, portName) {
			return CVLErrorInfo {
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: tableName,
				Keys: strings.Split(tableKey, "|"),
				ConstraintErrMsg: "Port has mirror session config",
				CVLErrDetails: "Config Validation Semantic Error",
				ErrAppTag:  "portlist-configured-as-dst-port-in-mirror-session",
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
