//////////////////////////////////////////////////////////////////////////////////
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
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
    "fmt"
	//"math"
	//"strconv"
	"strings"
)

func init() {
	XlateFuncBind("rpc_clear_mac_damp_disabled_ports", rpc_clear_mac_damp_disabled_ports)
}

//get db interface name to port oid map
func getIfNameToOidMap (d *db.DB) (map[string]string, error) {
    tblTs := &db.TableSpec{Name:"COUNTERS_PORT_NAME_MAP"}
    ifNameToOid :=  make(map[string]string)
    ifOidEntry, err := d.GetMapAll(tblTs)
    if err != nil || !ifOidEntry.IsPopulated() {
        log.Error("Reading Port OID map failed.", err)
        return ifNameToOid, err
    }
    for ifName, oid := range ifOidEntry.Field {
        ifNameToOid[ifName] = oid
    }

    return ifNameToOid, nil
}

//get db interface name to bridge port oid map
func getIfOidToBpMap (d *db.DB) (map[string]string, error) {
    ifOidToBpOidMap := make(map[string]string)

    tblName := "ASIC_STATE"
    bridgePortPrefix := "SAI_OBJECT_TYPE_BRIDGE_PORT"
    keys, tblErr := d.GetKeysByPattern(&db.TableSpec{Name: tblName, CompCt:2}, bridgePortPrefix+":*")
    if tblErr != nil {
        log.Error("Get Keys from ASIC_STATE bridge port table failed.", tblErr);
        return ifOidToBpOidMap, tblErr
    }


    if log.V(3) {
        log.Infof("getIfOidToBpMap bridge port keys :%v", keys)
    }
    for _, key := range keys {
        bpKey := key.Comp[1]
        entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
        if dbErr != nil {
            log.Error("DB GetEntry failed for key : ", key)
            continue
        }
        if entry.Has("SAI_BRIDGE_PORT_ATTR_PORT_ID") {
            portOid := entry.Get("SAI_BRIDGE_PORT_ATTR_PORT_ID")
            ifOidToBpOidMap[portOid] = bpKey
        }
    }
    if log.V(3) {
        log.Infof("getIfOidToBpMap if oid to bridge port oid :%v", ifOidToBpOidMap)
    }

    return ifOidToBpOidMap, nil 
}

func util_rpc_clear_mac_damp_disabled_ports(dbs [db.MaxDB]*db.DB, ifname string) (err error) {
    var data  []byte
    var  valLst [2]string

    valLst[0]= "ALL"
    valLst[1]= "ALL"

	if !strings.EqualFold(ifname, "all")  {
		ifname = *(utils.GetNativeNameFromUIName(&ifname))
        log.Infof("Interface name %v ", ifname)
    
        ifNameToOidMap, tblErr := getIfNameToOidMap(dbs[db.CountersDB])
        if tblErr != nil {
            log.Error("Get ifname to port oid mapping table get failed.", tblErr);
			return tblErr
        }
    
        ifOid, found := ifNameToOidMap[ifname]
        if (!found) {
             log.Error("Get ifname to port oid mapping table get failed.");
         	return tlerr.NotFound("No matching interface found")
        }
    
        ifOidToBpOidMap, getErr := getIfOidToBpMap(dbs[db.AsicDB])
        if getErr != nil {
            log.Error("Get ifname to port oid mapping table get failed.", getErr);
            return getErr
        }
        
        bp, bpFound := ifOidToBpOidMap[ifOid]
        if (!bpFound) {
            log.Error("Get ifoid to bridge port get failed.");
         	return tlerr.NotFound("No matching bridge port found")
        }
        valLst[0] = "PORT"
        valLst[1] = bp
   }

   data, err = json.Marshal(valLst)
   if err != nil {
       log.Error("Failed to  marshal input data; err=%v", err)
       return err
   }

   err = dbs[db.ApplDB].Publish("CLEARMACDAMPENINGPORTS",data)
   return err
}

var rpc_clear_mac_damp_disabled_ports RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
	log.Infof("Enter")

	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Infof("Error: %v. Input:%s", err, string(body))
		log.Errorf("Failed to  marshal input data; err=%v", err)
		return nil, tlerr.InvalidArgs("Invalid input %s", string(body))
	}

    input, ok := mapData["sonic-mac-dampening:input"] ; if !ok {
		log.Infof("Invalid input ifname should be either all or specific interface name")
		return nil, tlerr.InvalidArgs("Invalid input ifname should be either all or specific interface name")
    }

	mapData = input.(map[string]interface{})
	log.Infof("RPC Input data: %v", mapData)
	ifname, found := mapData["ifname"] ; if !found {
		log.Infof("Invalid input ifname should be either all or specific interface name")
		return nil, tlerr.InvalidArgs("Invalid input ifname should be either all or specific interface name")
    }

    input_str := fmt.Sprintf("%v", ifname)

    err = util_rpc_clear_mac_damp_disabled_ports(dbs, input_str)
    return nil, err

    /*
	if ifname_found {
		ifname = *(utils.GetNativeNameFromUIName(&ifname))
        log.Infof("Interface name %v ", ifname)
    
        ifNameToOidMap, tblErr := getIfNameToOidMap(dbs[db.CountersDB])
        if tblErr != nil {
            log.Error("Get ifname to port oid mapping table get failed.", tblErr);
			return nil, tblErr
        }
    
        ifOid, found := ifNameToOidMap[ifname]
        if (!found) {
             log.Error("Get ifname to port oid mapping table get failed.");
         	return nil, tlerr.NotFound("No matching interface found")
        }
    
        ifOidToBpOidMap, getErr := getIfOidToBpMap(dbs[db.AsicDB])
        if getErr != nil {
            log.Error("Get ifname to port oid mapping table get failed.", getErr);
            return nil, getErr
        }
        
        bp, bpFound := ifOidToBpOidMap[ifOid]
        if (!bpFound) {
            log.Error("Get ifoid to bridge port get failed.");
         	return nil, tlerr.NotFound("No matching bridge port found")
        }
        valLst[0] = "PORT"
        valLst[1] = bp
   }

   data, err = json.Marshal(valLst)
   if err != nil {
       log.Error("Failed to  marshal input data; err=%v", err)
       return nil, err
   }

   err = dbs[db.ApplDB].Publish("CLEARMACDAMPENINGPORTS",data)
   return nil, err
   */
}
