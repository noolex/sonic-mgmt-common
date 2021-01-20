////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Dell, Inc.                                                 //
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
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
	"strconv"
	"strings"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init() {
	XlateFuncBind("YangToDb_mclag_domainid_fld_xfmr", YangToDb_mclag_domainid_fld_xfmr)
	XlateFuncBind("DbToYang_mclag_domainid_fld_xfmr", DbToYang_mclag_domainid_fld_xfmr)
	XlateFuncBind("YangToDb_mclag_vlan_name_fld_xfmr", YangToDb_mclag_vlan_name_fld_xfmr)
	XlateFuncBind("DbToYang_mclag_vlan_name_fld_xfmr", DbToYang_mclag_vlan_name_fld_xfmr)
	XlateFuncBind("YangToDb_mclag_interface_subtree_xfmr", YangToDb_mclag_interface_subtree_xfmr)
	XlateFuncBind("DbToYang_mclag_interface_subtree_xfmr", DbToYang_mclag_interface_subtree_xfmr)
	XlateFuncBind("Subscribe_mclag_interface_subtree_xfmr", Subscribe_mclag_interface_subtree_xfmr)

	XlateFuncBind("DbToYang_mclag_domain_oper_status_fld_xfmr", DbToYang_mclag_domain_oper_status_fld_xfmr)
	XlateFuncBind("DbToYang_mclag_domain_role_fld_xfmr", DbToYang_mclag_domain_role_fld_xfmr)
	XlateFuncBind("DbToYang_mclag_domain_system_mac_fld_xfmr", DbToYang_mclag_domain_system_mac_fld_xfmr)
        XlateFuncBind("DbToYang_mclag_domain_delay_restore_start_time_fld_xfmr",
                      DbToYang_mclag_domain_delay_restore_start_time_fld_xfmr)
	XlateFuncBind("YangToDb_mclag_unique_ip_enable_fld_xfmr", YangToDb_mclag_unique_ip_enable_fld_xfmr)
	XlateFuncBind("DbToYang_mclag_unique_ip_enable_fld_xfmr", DbToYang_mclag_unique_ip_enable_fld_xfmr)
}

var YangToDb_mclag_domainid_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	log.Info("YangToDb_mclag_domainid_fld_xfmr: ", inParams.key)

	return res_map, err
}

var DbToYang_mclag_domainid_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Info("DbToYang_mclag_domainid_fld_xfmr: ", inParams.key)
	result["domain-id"], _ = strconv.ParseUint(inParams.key, 10, 32)

	return result, err
}

var YangToDb_mclag_vlan_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	log.Info("YangToDb_mclag_vlan_name_fld_xfmr: ", inParams.key)

	return res_map, err
}

var DbToYang_mclag_vlan_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Info("DbToYang_mclag_vlan_name_fld_xfmr: ", inParams.key)
	result["name"] = inParams.key

	return result, err
}

var DbToYang_mclag_domain_oper_status_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Infof("DbToYang_mclag_domain_oper_status_fld_xfmr --> key: %v", inParams.key)

	stDb := inParams.dbs[db.StateDB]
	mclagEntry, _ := stDb.GetEntry(&db.TableSpec{Name: "MCLAG_TABLE"}, db.Key{Comp: []string{inParams.key}})
	operStatus := mclagEntry.Get("oper_status")
	if operStatus == "up" {
		result["oper-status"], _ = ygot.EnumName(ocbinds.OpenconfigMclag_Mclag_MclagDomains_MclagDomain_State_OperStatus_OPER_UP)
	} else {
		result["oper-status"], _ = ygot.EnumName(ocbinds.OpenconfigMclag_Mclag_MclagDomains_MclagDomain_State_OperStatus_OPER_DOWN)
	}

	return result, err
}

var DbToYang_mclag_domain_role_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Infof("DbToYang_mclag_domain_role_fld_xfmr --> key: %v", inParams.key)

	stDb := inParams.dbs[db.StateDB]
	mclagEntry, _ := stDb.GetEntry(&db.TableSpec{Name: "MCLAG_TABLE"}, db.Key{Comp: []string{inParams.key}})
	role := mclagEntry.Get("role")
	if role == "active" {
		result["role"], _ = ygot.EnumName(ocbinds.OpenconfigMclag_Mclag_MclagDomains_MclagDomain_State_Role_ROLE_ACTIVE)
	} else {
		result["role"], _ = ygot.EnumName(ocbinds.OpenconfigMclag_Mclag_MclagDomains_MclagDomain_State_Role_ROLE_STANDBY)
	}

	return result, err
}

var DbToYang_mclag_domain_system_mac_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Infof("DbToYang_mclag_domain_system_mac_fld_xfmr --> key: %v", inParams.key)

	stDb := inParams.dbs[db.StateDB]
	mclagEntry, _ := stDb.GetEntry(&db.TableSpec{Name: "MCLAG_TABLE"}, db.Key{Comp: []string{inParams.key}})
	sysmac := mclagEntry.Get("system_mac")
	result["system-mac"] = &sysmac

	return result, err
}

var DbToYang_mclag_domain_delay_restore_start_time_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Infof("DbToYang_mclag_domain_delay_restore_start_time_fld_xfmr --> key: %v", inParams.key)

    stDb := inParams.dbs[db.StateDB]
    mclagEntry, _ := stDb.GetEntry(&db.TableSpec{Name: "MCLAG_TABLE"}, db.Key{Comp: []string{inParams.key}})
    if dbval, found := mclagEntry.Field["delay_restore_start_time"]; found {
        ocval, _ := strconv.ParseUint(dbval, 10, 64)
        result["delay-restore-start-time"] = &ocval
    } 

    return result, err
}

var YangToDb_mclag_gw_mac_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	log.Info("YangToDb_mclag_gw_mac_fld_xfmr: ", inParams.key)

	return res_map, err
}

var DbToYang_mclag_gw_mac_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Info("DbToYang_mclag_gw_mac_fld_xfmr: ", inParams.key)

	cdb := inParams.dbs[db.ConfigDB]
	mclagGwEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "MCLAG_GW_MAC_TABLE"}, db.Key{Comp: []string{inParams.key}})
	gwmac := mclagGwEntry.Get("gw_mac")
	
	result["gateway-mac"] = &gwmac

	return result, err
}

var DbToYang_mclag_unique_ip_enable_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Infof("DbToYang_mclag_unique_ip_enable_fld_xfmr --> key: %v", inParams.key)

	configDb := inParams.dbs[db.ConfigDB]
	mclagEntry, _ := configDb.GetEntry(&db.TableSpec{Name: "MCLAG_UNIQUE_IP"}, db.Key{Comp: []string{inParams.key}})
	uniqueIpStatus := mclagEntry.Get("unique_ip")
	if  uniqueIpStatus == "enable" {
		result["unique-ip-enable"], _ = ygot.EnumName(ocbinds.OpenconfigMclag_Mclag_VlanInterfaces_VlanInterface_Config_UniqueIpEnable_ENABLE)
    }
	log.Infof("DbToYang_mclag_unique_ip_enable_fld_xfmr --> result: %v", result)

	return result, err
}

var YangToDb_mclag_unique_ip_enable_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error

    uniqueIpEnable, _ := inParams.param.(ocbinds.E_OpenconfigMclag_Mclag_VlanInterfaces_VlanInterface_Config_UniqueIpEnable) 
	log.Infof("YangToDb_mclag_unique_ip_enable_fld_xfmr: uniqueIpEnable:%v ", uniqueIpEnable)
    if (uniqueIpEnable == ocbinds.OpenconfigMclag_Mclag_VlanInterfaces_VlanInterface_Config_UniqueIpEnable_ENABLE) {
        res_map["unique_ip"] = "enable"
    } else {
	if (inParams.oper == DELETE) {
        	tblName := "MCLAG_UNIQUE_IP"
		pathInfo := NewPathInfo(inParams.uri)
        	tblKey := pathInfo.Var("name")
		log.Infof("YangToDb_mclag_unique_ip_enable_fld_xfmr Delete tblKey %v", tblKey)
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
        	subIntfmap_del := make(map[string]map[string]db.Value)
        	subIntfmap_del[tblName] = make(map[string]db.Value)
        	subIntfmap_del[tblName][tblKey] = db.Value{}
        	subOpMap[db.ConfigDB] = subIntfmap_del
        	inParams.subOpDataMap[DELETE] = &subOpMap
        }
    }

	log.Infof("DbToYang_mclag_unique_ip_enable_fld_xfmr --> result: %v", res_map)
	return res_map, err
}

var YangToDb_mclag_interface_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	res_map := make(map[string]map[string]db.Value)
	mclagIntfTblMap := make(map[string]db.Value)
	log.Info("YangToDb_mclag_interface_subtree_xfmr: ", inParams.ygRoot, inParams.uri)

	mclagObj := getMclagRoot(inParams.ygRoot)
	if mclagObj == nil || mclagObj.Interfaces == nil {
		return res_map, err
	}

	for _, intf := range mclagObj.Interfaces.Interface {
		if intf != nil {
			var mclagdomainId int
			if intf.Config != nil {
                if intf.Config.MclagId  != nil {
                    if strings.HasPrefix(*intf.Name, PORTCHANNEL) {
                        poSplit := strings.Split(*intf.Name, PORTCHANNEL); 
                        poId, _ := strconv.Atoi(poSplit[1])

                        if (uint16(poId) != *intf.Config.MclagId) {
						    return res_map, tlerr.NotSupported("Different MCLAG ID:%v and MCLAG porchannelId:%v for a given mclag interface:%v, needs to be same", *intf.Config.MclagId, poId, *intf.Name)
                        }
                    }
                }
				mclagdomainId = int(*intf.Config.MclagDomainId)
			} else {
				// DomainId info NOT available from URI or body. So make db query.
				mclagIntfKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name: "MCLAG_INTERFACE"})
				if len(mclagIntfKeys) > 0 {
					for _, intfKey := range mclagIntfKeys {
						if intfKey.Get(1) == *intf.Name {
							domainid, _ := strconv.ParseUint(intfKey.Get(0), 10, 32)
							mclagdomainId = int(domainid)
						}
					}
				}
			}
			mclagIntfKey := strconv.Itoa(mclagdomainId) + "|" + *intf.Name
			log.Infof("YangToDb_mclag_interface_subtree_xfmr --> key: %v", mclagIntfKey)

			_, ok := mclagIntfTblMap[mclagIntfKey]
			if !ok {
				mclagIntfTblMap[mclagIntfKey] = db.Value{Field: make(map[string]string)}
			}
            //for DELETE operation dont fill individual fields
	        if inParams.oper != DELETE {
			    mclagIntfTblMap[mclagIntfKey].Field["if_type"] = "PortChannel"
            }
		}
	}

	res_map["MCLAG_INTERFACE"] = mclagIntfTblMap
	return res_map, err
}

var DbToYang_mclag_interface_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	data := (*inParams.dbDataMap)[inParams.curDb]
	mclagObj := getMclagRoot(inParams.ygRoot)
	pathInfo := NewPathInfo(inParams.uri)

	log.Info("DbToYang_mclag_interface_subtree_xfmr: ", data, inParams.ygRoot)

	if isSubtreeRequest(pathInfo.Template, "/openconfig-mclag:mclag/interfaces/interface{name}") {
		mclagIntfKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name: "MCLAG_INTERFACE"})
		if len(mclagIntfKeys) > 0 {
			for _, intfKey := range mclagIntfKeys {
				ifname := intfKey.Get(1)
				if ifname == pathInfo.Var("name") && mclagObj.Interfaces != nil {
					for _, intfData := range mclagObj.Interfaces.Interface {
						fillMclagIntfDetails(inParams, ifname, intfKey.Get(0), intfData)
					}
				}
			}
		}
	} else {
		var mclagIntfData map[string]map[string]string

		mclagIntfTbl := data["MCLAG_INTERFACE"]
		mclagIntfData = make(map[string]map[string]string)
		for key := range mclagIntfTbl {
			//split key into domain-id and if-name
			tokens := strings.Split(key, "|")
			ifname := tokens[1]
			mclagIntfData[ifname] = make(map[string]string)
			mclagIntfData[ifname]["domainid"] = tokens[0]
			mclagIntfData[ifname]["ifname"] = ifname
		}

		for intfId := range mclagIntfData {
			if mclagObj.Interfaces == nil {
				ygot.BuildEmptyTree(mclagObj)
			}
			intfData, _ := mclagObj.Interfaces.NewInterface(intfId)
			fillMclagIntfDetails(inParams, mclagIntfData[intfId]["ifname"], mclagIntfData[intfId]["domainid"], intfData)
		}
	}

	return err
}

func fillMclagIntfDetails(inParams XfmrParams, ifname string, mclagdomainid string, intfData *ocbinds.OpenconfigMclag_Mclag_Interfaces_Interface) {
	if intfData == nil {
		return
	}

	ygot.BuildEmptyTree(intfData)

	domainid, _ := strconv.ParseUint(mclagdomainid, 10, 32)
	did32 := uint32(domainid)

	intfData.Name = &ifname

    //mclagId would be same as the portchannel id
    poSplit := strings.Split(ifname, PORTCHANNEL); 
    poId, _ := strconv.Atoi(poSplit[1])
    mclagId := uint16(poId)

	if intfData.Config != nil {
		intfData.Config.MclagDomainId = &did32
		intfData.Config.Name = &ifname
        intfData.Config.MclagId = &mclagId
		log.Infof("fillMclagIntfDetails--> filled config container with domain:%v and Interface:%v", did32, ifname)
	}

	// Fetch operational data from StateDb and AppDb
	stDb := inParams.dbs[db.StateDB]
	mclagRemoteIntfEntry, _ := stDb.GetEntry(&db.TableSpec{Name: "MCLAG_REMOTE_INTF_TABLE"}, db.Key{Comp: []string{mclagdomainid + "|" + ifname}})
	remoteOperStatus := mclagRemoteIntfEntry.Get("oper_status")

    portIsolate := false
    trafficDisable := false
	mclagLocalIntfEntry, _ := stDb.GetEntry(&db.TableSpec{Name: "MCLAG_LOCAL_INTF_TABLE"}, db.Key{Comp: []string{mclagdomainid + "|" + ifname}})
	portIsolate, _ = strconv.ParseBool(mclagLocalIntfEntry.Get("port_isolate_peer_link"))

	appDb := inParams.dbs[db.ApplDB]
	lagEntry, _ := appDb.GetEntry(&db.TableSpec{Name: "LAG_TABLE"}, db.Key{Comp: []string{ifname}})
	trafficDisable, _ = strconv.ParseBool(lagEntry.Get("traffic_disable"))
    localOperStatus  :=  lagEntry.Get("oper_status")
    if (localOperStatus == "") {
        localOperStatus =  "down"
    }
	log.Infof("fillMclagIntfDetails--> localOperStatus:%v portIsolate:%v trafficDisable:%v", localOperStatus, portIsolate, trafficDisable)

	if intfData.State != nil {
		ygot.BuildEmptyTree(intfData.State)

		intfData.State.MclagDomainId = &did32
		intfData.State.Name = &ifname
        intfData.State.MclagId = &mclagId

		if intfData.State.Local != nil {
			intfData.State.Local.TrafficDisable = &trafficDisable
			intfData.State.Local.PortIsolate    = &portIsolate
            if localOperStatus == "up" {
                intfData.State.Local.OperStatus = ocbinds.OpenconfigMclag_Mclag_Interfaces_Interface_State_Local_OperStatus_OPER_UP
	            log.Infof("fillMclagIntfDetails--> localOperStatus:%v ", localOperStatus)
            } else if localOperStatus == "down" {
                intfData.State.Local.OperStatus = ocbinds.OpenconfigMclag_Mclag_Interfaces_Interface_State_Local_OperStatus_OPER_DOWN
	            log.Infof("fillMclagIntfDetails--> localOperStatus:%v ", localOperStatus)
            }
		}

		if intfData.State.Remote != nil {
			if remoteOperStatus == "up" {
				intfData.State.Remote.OperStatus = ocbinds.OpenconfigMclag_Mclag_Interfaces_Interface_State_Remote_OperStatus_OPER_UP
			} else if remoteOperStatus == "down" {
				intfData.State.Remote.OperStatus = ocbinds.OpenconfigMclag_Mclag_Interfaces_Interface_State_Remote_OperStatus_OPER_DOWN
			}
		}
	}

}

func getMclagRoot(s *ygot.GoStruct) *ocbinds.OpenconfigMclag_Mclag {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.Mclag
}


var Subscribe_mclag_interface_subtree_xfmr SubTreeXfmrSubscribe = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error)  {

     var err error
     var result XfmrSubscOutParams

     pathInfo := NewPathInfo(inParams.uri)
     targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
     log.Infof("Subscribe_mclag_interface_subtree_xfmr:%s; template:%s targetUriPath:%s", pathInfo.Path, pathInfo.Template, targetUriPath)

     if targetUriPath != "/openconfig-mclag:mclag/interfaces/interface" {
         log.Infof("Subscribe attempted on unsupported path:%s; template:%s targetUriPath:%s", pathInfo.Path, pathInfo.Template, targetUriPath)
         return result, err
     }

     ifName := pathInfo.Var("name")
     log.Infof("ifName %v ", ifName)
     domainId := pathInfo.Var("mclag-domain-id")
     log.Infof("domainId %v ", domainId)
     // DomainId info NOT available from URI or body. So make db query.
     if domainId == "" {
         cdb, err := db.NewDB(getDBOptions(db.ConfigDB))
         if err != nil {
             log.Infof("Subscribe_mclag_interface_subtree_xfmr, unable to get configDB, error %v", err)
             return result, err
         }
		 defer cdb.DeleteDB()
         mclagIntfKeys, _ := cdb.GetKeysPattern(&db.TableSpec{Name: "MCLAG_INTERFACE"}, db.Key{[]string{"*", ifName}})
         log.Infof("keys %v ", mclagIntfKeys)
	     if len(mclagIntfKeys) > 0 {
	         for _, intfKey := range mclagIntfKeys {
                 log.Infof("intfKey %v ", intfKey)
	             if intfKey.Get(1) == ifName {
	        	     domainId = intfKey.Get(0)
                     break
	        	  }
	         }
          }
          
      }

     
     result.dbDataMap = make(RedisDbMap)
     if (domainId == "") { 
         log.Infof("Subscribe_mclag_interface_subtree_xfmr resouce not found for ifName:%s ", ifName)
         return result, tlerr.NotFound("Resource not found")
     }

     mclagIntfKey := domainId + "|" + ifName
     log.Infof("Subscribe_mclag_interface_subtree_xfmr path:%s; template:%s targetUriPath:%s key:%s", pathInfo.Path, pathInfo.Template, targetUriPath, mclagIntfKey)
     result.dbDataMap = RedisDbMap{db.ConfigDB:{"MCLAG_INTERFACE":{mclagIntfKey:{}}}} // tablename & table-idx for the inParams.uri

     //result.needCache = true
     //Onchange notification subscription
     //result.onChange = true
     //result.nOpts = new(notificationOpts)
     //result.nOpts.mInterval = 0
     //result.nOpts.pType = OnChange

     return result, err 
}

