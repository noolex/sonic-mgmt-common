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
	log "github.com/golang/glog"
	"net"
	"strconv"
)

const (
  //Default MTU of interface
  DEFAULT_MTU = "9100"
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

    key_split := strings.Split(vc.CurCfg.Key, "|")
    if_name := key_split[1]

    if strings.Contains(if_name, "Vlan") {
        sag_tbl_name := "SAG" + "|" + if_name + "|" + "*"

        sag_keys, err:= vc.RClient.Keys(sag_tbl_name).Result()
        if (err != nil) || (vc.SessCache == nil) {
            return CVLErrorInfo{ErrCode: CVL_SUCCESS}
        }

        if len(sag_keys) >= 1 {
            errStr := "IP Unnumbered not allowed when anycast IP is already configured"
            log.Error(errStr)
            return CVLErrorInfo {
                ErrCode: CVL_SEMANTIC_ERROR,
                TableName: vc.CurCfg.Key,
                CVLErrDetails: errStr,
                ConstraintErrMsg: errStr,
            }
        }
    }

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func getSubInterfaceTruncatedName(longName *string) *string {
    var truncatedName string

    if strings.Contains(*longName, "Ethernet") {
        truncatedName = strings.Replace(*longName, "Ethernet", "Eth", -1)
    } else if strings.Contains(*longName, "PortChannel") {
        truncatedName = strings.Replace(*longName, "PortChannel", "Po", -1)
    } else {
        truncatedName = *longName
    }

    return &truncatedName
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

                                portChannelMemberName := *getSubInterfaceTruncatedName(&intfName)
                                subIntfKeys, err2 := vc.RClient.Keys("VLAN_SUB_INTERFACE|" + portChannelMemberName + ".*").Result()
                                if err2 != nil {
                                   return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
                                }

                                if len(subIntfKeys) > 0 {
                                        return CVLErrorInfo{
                                                ErrCode:          CVL_SEMANTIC_ERROR,
                                                TableName:        "VLAN_SUB_INTERFACE",
                                                Keys:             strings.Split(vc.CurCfg.Key, "|"),
                                                ConstraintErrMsg: fmt.Sprintf("Cannot configure %s as member of %s as sub-interface is created on %s.", intfName, poName, intfName),
                                        }
                                }

				poMtu := poData["mtu"]

				// If PO MTU is not configured, choose default MTU.
				if len(poMtu) == 0 {
                                        poMtu = DEFAULT_MTU
				        util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Setting default MTU for PO MTU=%v", poMtu)
                                }

				intfMtu := intfData["mtu"]
				util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateMtuForPOMemberCount: PO MTU=%v and Intf MTU=%v", poMtu, intfMtu)

                                if poMtu != intfMtu {
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

				// Check for VLAN configuration on interface being added as PO member.
				isAccessVlanCfg := intfData["access_vlan"]
				isTrunkVlanCfg := intfData["tagged_vlans@"]

				// Prevent interfaces with VLAN configuration from being added to PO.
				if (len(isAccessVlanCfg) > 0 || len(isTrunkVlanCfg) > 0) {
					return CVLErrorInfo{
							ErrCode:          CVL_SEMANTIC_ERROR,
							TableName:        "PORT",
							Keys:             strings.Split(vc.CurCfg.Key, "|"),
							ConstraintErrMsg: fmt.Sprintf("Configuration not allowed as Vlan configuration exists on %s.", intfName),
							ErrAppTag:        "member-invalid",
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

				total := len(poKeys) + len(vc.ReqData)
				if total > 128 {
				        util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Cannot create more than supported number of portchannels in the system.")
					errStr := "Number of portchannels already created in the system are " + strconv.Itoa(len(poKeys)) + ". Maximum number of portchannel that can be supported are 128."
				        return CVLErrorInfo{
					        ErrCode:          CVL_SEMANTIC_ERROR,
					        TableName:        "PORTCHANNEL",
						Keys:             strings.Split(vc.CurCfg.Key, "|"),
					        ConstraintErrMsg: errStr,
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


func (t *CustomValidation) ValidateIntfIp(vc *CustValidationCtxt) CVLErrorInfo {
	var vrrp_table string
	var vip_suffix string

	log.Info("ValidateIntfIp op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data, "vc.ReqData: ", vc.ReqData, "vc.SessCache", vc.SessCache)

	key := vc.CurCfg.Key
	key_split := strings.Split(key, "|")
	table_name := key_split[0]
	if_name := key_split[1]
	if_ip := key_split[2]

	log.Info("talbe_name:", table_name)

	if len(if_ip) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}


    if vc.CurCfg.VOp != OP_DELETE {
        if strings.Contains(if_name, "Vlan") || strings.Contains(if_name, ".") {
            sag_tbl_name := "SAG" + "|" + if_name + "|" + "*"

            sag_keys, err:= vc.RClient.Keys(sag_tbl_name).Result()
            if (err != nil) || (vc.SessCache == nil) {
                return CVLErrorInfo{ErrCode: CVL_SUCCESS}
            }

            if len(sag_keys) >= 1 {
                errStr := "Interface IP not allowed when anycast IP is already configured"
                log.Error(errStr)
                return CVLErrorInfo {
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: key,
                    CVLErrDetails: errStr,
                    ConstraintErrMsg: errStr,
                }
            }
        } else {
            return CVLErrorInfo{ErrCode: CVL_SUCCESS}
        }
    }

	if strings.Contains(if_ip, ":") {
		vrrp_table = "VRRP6"
		vip_suffix = "/128"
	} else {
		vrrp_table = "VRRP"
		vip_suffix = "/32"
	}

	tbl_name_ext := vrrp_table + "|" + if_name + "|" + "*"

	vrrp_keys, err:= vc.RClient.Keys(tbl_name_ext).Result()

	if (err != nil) || (vc.SessCache == nil) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	if_ip_prefix, if_ip_net, perr := net.ParseCIDR(if_ip)
	if if_ip_prefix == nil || perr != nil {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	ip_ll := "fe80::/10"
	_, ip_net_ll, _ := net.ParseCIDR(ip_ll)

	// Interface IP delete is not allowed as long as VRRP with VIP exist in same subnet

	// Interface IP add and delete is not allowed if VRRP has to transition from/to owner
	// VRRP checks ensure that interface IP is configured before VIP, hence check just delete

  vrrp_del_count := 0

	for _, db_key := range vrrp_keys {

		log.Info("db_key: ", db_key)

		found := false
		if vc.CurCfg.VOp == OP_DELETE {
			for i := 0; i < len(vc.ReqData); i++ {
				if vc.ReqData[i].Key == db_key {
					found = true
					vrrp_del_count++
					log.Info("Allow deletion of VRRP key: ", db_key)
					break
				}
			}

			if found {
				continue;
			}
		}

		vrrp_data, err:= vc.RClient.HGetAll(db_key).Result()

		log.Info("vrrp_data: ", vrrp_data)

		if (err != nil) || (vc.SessCache == nil) {
			continue
		}

		vip_string := vrrp_data["vip@"]

		vips := strings.Split(vip_string, ",")
		for _, vip := range(vips)	{

			vip = vip + vip_suffix
			vip_prefix, _, perr := net.ParseCIDR(vip)

			if vip_prefix == nil || perr != nil {
					continue
			}

			if ip_net_ll.Contains(vip_prefix) {
				continue
			}

			if if_ip_net.Contains(vip_prefix) {
				log.Info("ValidateIp deleting last IP overlapping VIP")
				errStr := "Interface IP is being used by VRRP instance, please delete VRRP virtual IP before deleting/changing interface IP"
				return CVLErrorInfo {
					ErrCode: CVL_SEMANTIC_ERROR,
					TableName: vrrp_table,
					CVLErrDetails: errStr,
					ConstraintErrMsg: errStr,
				}
			}
		}
	}

	if (vc.CurCfg.VOp == OP_DELETE) {

		if (vrrp_table == "VRRP") {

			if_ip_data, _ := vc.RClient.HGetAll(vc.CurCfg.Key).Result()

			_, has_data := if_ip_data["secondary"]

			log.Info("ValidateIntfIp if_ip_data:", if_ip_data, " secondary:", has_data, " vrrp_keys:", vrrp_keys)

			if ((!has_data) && ((len(vrrp_keys) - vrrp_del_count) > 0)) {
				log.Info("Primary IP is deleted, no VRRP instance should be present")
				errStr := "Remove all the VRRP instances before removing interface IP"
				return CVLErrorInfo {
					ErrCode: CVL_SEMANTIC_ERROR,
					TableName: vrrp_table,
					CVLErrDetails: errStr,
					ConstraintErrMsg: errStr,
	                       }
                	}
		} else {

			ipaddr_table := table_name + "|" + if_name + "|" + "*"

			ip_addr_keys, _:= vc.RClient.Keys(ipaddr_table).Result()

			log.Info("ValidateIntfIp ipaddr_table:", ip_addr_keys, " vrrp_keys:", vrrp_keys)

      count := 0
			for _, ip_key := range ip_addr_keys {
				ip_split := strings.Split(ip_key, "|")
				if strings.Contains(ip_split[2], ":") {
					count++
				}
			}

			log.Info("ValidateIntfIp IPv6 count:", count)

			if ((count-1 <= 0) && ((len(vrrp_keys) - vrrp_del_count) > 0)) {
				log.Info("IPv6 address are removed, no VRRP instance should be present")
				errStr := "Remove all the VRRP instances before removing interface IP"
				return CVLErrorInfo {
					ErrCode: CVL_SEMANTIC_ERROR,
					TableName: vrrp_table,
					CVLErrDetails: errStr,
					ConstraintErrMsg: errStr,
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
