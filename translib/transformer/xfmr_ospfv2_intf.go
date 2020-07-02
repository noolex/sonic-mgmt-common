//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Broadcom, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer

import (
    "errors"
    "strings"
    "reflect"
    "strconv"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init () {
    XlateFuncBind("YangToDb_ospfv2_interface_subtree_xfmr", YangToDb_ospfv2_interface_subtree_xfmr)
    XlateFuncBind("DbToYang_ospfv2_interface_subtree_xfmr", DbToYang_ospfv2_interface_subtree_xfmr)
}


var YangToDb_ospfv2_interface_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    var ifName string
    subIntfmap := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    reqIfName := pathInfo.Var("name")
    rcvdUri, _ := getYangPathFromUri(inParams.uri)

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: --------Start------")
    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: reqIfName ", reqIfName)
    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: param uri ", inParams.uri)
    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: pathInfo ", pathInfo)
    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: rcvd uri ", rcvdUri)

    addOperation := false
    deleteOperation := false
    if (inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE) {
        addOperation = true
    } else if (inParams.oper == DELETE) {
        deleteOperation = true
    } else {
        errStr := "Invalid operation "
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if reqIfName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    ifName, err = ospfGetNativeIntfName(reqIfName) 
    if (err != nil) {
        errStr := "Invalid OSPF interface name"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr + " " + reqIfName)
        return subIntfmap, tlerr.New(errStr)
    }

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Native ifName ", ifName)

    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]
    tableName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: tblName ", tableName)

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        errStr := "IntfsObj/interface list is empty for " + reqIfName
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        if (deleteOperation) {
            err = delete_ospf_interface_config_all(&inParams, &subIntfmap)
            return subIntfmap, err
        }
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfsObj.Interface[reqIfName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + reqIfName
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr : " + errStr)
        if (deleteOperation) {
            err = delete_ospf_interface_config_all(&inParams, &subIntfmap)
            return subIntfmap, err
        }
        return subIntfmap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[reqIfName]
    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        if (deleteOperation) {
            err = delete_ospf_interface_config_all(&inParams, &subIntfmap)
            return subIntfmap, err
        }
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        if (deleteOperation) {
            err = delete_ospf_interface_config_all(&inParams, &subIntfmap)
            return subIntfmap, err
        }
        return subIntfmap, errors.New(errStr)
    }

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]
    if subIntfObj.Ipv4 == nil {
        errStr := "SubInterface IPv4 node is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        if (deleteOperation) {
            err = delete_ospf_interface_config_all(&inParams, &subIntfmap)
            return subIntfmap, err
        }
        return subIntfmap, errors.New(errStr)
    }

    ospfObj := subIntfObj.Ipv4.Ospfv2
    if (ospfObj == nil) {
        errStr := "Ospfv2 node is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        if (deleteOperation) {
            err = delete_ospf_interface_config_all(&inParams, &subIntfmap)
            return subIntfmap, err
        }
        return subIntfmap, errors.New(errStr)
    }

    if (ospfObj.IfAddresses == nil || len(ospfObj.IfAddresses) < 1) {
        errStr := "Ospfv2 IfAddresses is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        if (deleteOperation) {
            err = delete_ospf_interface_config_all(&inParams, &subIntfmap)
            return subIntfmap, err
        }
        return subIntfmap, errors.New(errStr)
    }

    intfVrfName, _ := get_interface_vrf(&inParams, ifName)

    intfTblName := "OSPFV2_INTERFACE"
    var ospfIfTblSpec *db.TableSpec = &db.TableSpec{Name: intfTblName}
    ospfTblData, err := configDbPtr.GetTable(ospfIfTblSpec)
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("YangToDb_ospfv2_interface_subtree_xfmr: OSPF Interface Table data not found ", errStr)
        return subIntfmap, errors.New(errStr)
    }

    var ospfIntfTblMap map[string]db.Value = make(map[string]db.Value)
    var ospfRespMap map[string]map[string]db.Value = make(map[string]map[string]db.Value)

    ospfOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB][intfTblName] = make(map[string]db.Value)

    ospfAreaTblName := "OSPFV2_ROUTER_AREA"
    var ospfAreaTblMap map[string]db.Value = make(map[string]db.Value)
    ospfAreaOpMapInited := false
    ospfAreaAutoCreate := true

    fieldNameList := []string { "area-id", "authentication-type", "authentication-key", "authentication-key",
                                "authentication-key-id", "authentication-md5-key", "bfd-enable", "dead-interval",
                                "hello-interval", "hello-multiplier", "metric", "mtu-ignore", "network-type",
                                "dead-interval-minimal", "priority", "retransmission-interval", "transmit-delay" }

    addDeletePresent :=false

    for intfAddrKey, intfAddrObj := range ospfObj.IfAddresses {

        intfTblKey := ifName + "|" + intfAddrKey
        ospfCfgObj := intfAddrObj.Config
        ospfIntfDbValue := db.Value{Field: make(map[string]string)}

        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: IfAddresses intfTblKey is ",intfTblKey)

        if (addOperation) {

             log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ADD/UPDATE operation ", inParams.oper)
             newEntry := false

             ospfIfEntry, err := ospfTblData.GetEntry(db.Key{[]string{intfTblKey}})
             if err != nil || len(ospfIfEntry.Field) == 0 {
                  ospfOpMap[db.ConfigDB][intfTblName][intfTblKey] = db.Value{Field: make(map[string]string)}
                  ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field["NULL"] = "NULL"
                  newEntry = true
                  addDeletePresent = true
                  log.Error("YangToDb_ospfv2_interface_subtree_xfmr: Create new entry for ", intfTblKey)
             }

             if (intfAddrObj.Config != nil) {

                 if (!newEntry) {
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf interface update existing entry for ", intfTblKey)
                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey] = db.Value{Field: make(map[string]string)}
                 }

                 if (ospfCfgObj.AreaId != nil) {
                     fieldName := "area-id"
                     areaIdObj := ospfCfgObj.AreaId
                     dbVlaueStr := "NULL"
                     areaIdUnionType := reflect.TypeOf(areaIdObj).Elem()

                     switch areaIdUnionType {
                         case reflect.TypeOf(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_String{}):
                             areaId := (areaIdObj).(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_String)
                             dbVlaueStr = areaId.String
                         case reflect.TypeOf(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_Uint32{}):
                             areaId := (areaIdObj).(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_Uint32)
                             var dbVlaueInt int64 = int64(areaId.Uint32)
                             b0 := strconv.FormatInt((dbVlaueInt >> 24) & 0xff, 10)
                             b1 := strconv.FormatInt((dbVlaueInt >> 16) & 0xff, 10)
                             b2 := strconv.FormatInt((dbVlaueInt >>  8) & 0xff, 10)
                             b3 := strconv.FormatInt((dbVlaueInt      ) & 0xff, 10)
                             dbVlaueStr =  b0 + "." + b1 + "." + b2 + "." + b3
                     }

                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Area id field to ", dbVlaueStr)

                     if (dbVlaueStr != "NULL") {

                         rtrPresent, _ := ospf_router_present_for_interface(&inParams, ifName)
                         if (!rtrPresent) {
                             errStr := "Area configuration not allowed without OSPF router config"
                             log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
                             return subIntfmap, tlerr.New(errStr)
                         }

                         if (!newEntry) {
                             currAreaId := (&ospfIfEntry).Get(fieldName)
                             if (currAreaId != "" && currAreaId != dbVlaueStr) {
                                 errStr := "Must remove previous area config before changing ospf area"
                                 log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
                                 return subIntfmap, tlerr.New(errStr)
                             }
                         }

                         areaNwCfgPresent, err := ospf_area_network_present_for_interface_vrf(&inParams, ifName)
                         if (err != nil) {
                             errStr := "Internal Error: Network area table access failed"
                             log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
                             return subIntfmap, tlerr.New(errStr)
                         } else if (areaNwCfgPresent) {
                             errStr := "Please remove all network commands in ospf router area config first"
                             log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
                             return subIntfmap, tlerr.New(errStr)
                         }

                         if (ospfAreaAutoCreate && intfVrfName != "") {
                              areaId := dbVlaueStr
                              areaPresent, _ := ospf_router_area_present(&inParams, intfVrfName, areaId)
                              if (!areaPresent) {
                                  ospfAreaTblKey := intfVrfName + "|" + areaId

                                  if (!ospfAreaOpMapInited) {
                                      ospfOpMap[db.ConfigDB][ospfAreaTblName] = make(map[string]db.Value)
                                      ospfAreaOpMapInited = true
                                  }

                                  ospfOpMap[db.ConfigDB][ospfAreaTblName][ospfAreaTblKey] = db.Value{Field: make(map[string]string)}
                                  ospfOpMap[db.ConfigDB][ospfAreaTblName][ospfAreaTblKey].Field["NULL"] = "NULL"
 
                                  ospfAreaTblDbValue := db.Value{Field: make(map[string]string)}
                                  ospfAreaTblDbValue.Field["NULL"] = "NULL"

                                  ospfAreaTblMap[ospfAreaTblKey] = ospfAreaTblDbValue
                             }
                         }

                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                         ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                     }
                 }

                 if (ospfCfgObj.AuthenticationType != nil) {
                     fieldName := "authentication-type"

                     dbVlaueStr := *(ospfCfgObj.AuthenticationType)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db authentication field to ", dbVlaueStr)

                     if (dbVlaueStr == "NONE" || dbVlaueStr == "TEXT" || dbVlaueStr == "MD5HMAC") {
                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                         ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                     } else {
                         errStr := "Invalid Authentication type, valid values are NONE, TEXT or MD5HMAC"
                         log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
                         return subIntfmap, tlerr.New(errStr)
                     }
                 }

                 if (ospfCfgObj.AuthenticationKey != nil) {
                     fieldName := "authentication-key"

                     dbVlaueStr := *(ospfCfgObj.AuthenticationKey)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Auth key field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }

                 if (ospfCfgObj.AuthenticationKeyId != nil) {
                     fieldName := "authentication-key-id"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.AuthenticationKeyId)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Auth key id field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }

                 if (ospfCfgObj.AuthenticationMd5Key != nil) {
                     fieldName := "authentication-md5-key"

                     dbVlaueStr := *(ospfCfgObj.AuthenticationMd5Key)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Auth md5key field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
             
                 if (ospfCfgObj.BfdEnable != nil) {
                     fieldName := "bfd-enable"

                     var dbVlaueBool bool = *(ospfCfgObj.BfdEnable)
                     dbVlaueStr := "false"
                     if (dbVlaueBool) {
                         dbVlaueStr = "true"
                     }
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db bfd field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.DeadIntervalMinimal != nil) {
                     fieldName := "dead-interval-minimal"

                     var dbVlaueBool bool = *(ospfCfgObj.DeadIntervalMinimal)
                     dbVlaueStr := "false"
                     if (dbVlaueBool) {
                         dbVlaueStr = "true"
                     }
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db minimal field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.DeadInterval != nil) {
                     fieldName := "dead-interval"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.DeadInterval)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db dead interval field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.HelloInterval != nil) {
                     fieldName := "hello-interval"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.HelloInterval)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db hello interval field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.HelloMultiplier != nil) {
                     fieldName := "hello-multiplier"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.HelloMultiplier)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db hello multiplier field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.Metric != nil) {
                     fieldName := "metric"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.Metric)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db metric field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.MtuIgnore != nil) {
                     fieldName := "mtu-ignore"

                     var dbVlaueBool bool = *(ospfCfgObj.MtuIgnore)
                     dbVlaueStr := "false"
                     if (dbVlaueBool) {
                         dbVlaueStr = "true"
                     }
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db mtu ignore field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.NetworkType != ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_UNSET) {
                     fieldName := "network-type"
                     nw_type := ospfCfgObj.NetworkType

                     dbVlaueStr := "NULL"
                     switch (nw_type) {
                         case ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_BROADCAST_NETWORK:
                             dbVlaueStr = "BROADCAST_NETWORK"
                         case ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_POINT_TO_POINT_NETWORK :
                             dbVlaueStr = "POINT_TO_POINT_NETWORK"
                         default:
                             log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Invalid Network type ", nw_type)
                     }
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db network type field to ", dbVlaueStr)

                     if (dbVlaueStr != "NULL") {
                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                         ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                     }
                 }
                 if (ospfCfgObj.Priority != nil) {
                     fieldName := "priority"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.Priority)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db priority field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.RetransmissionInterval != nil) {
                     fieldName := "retransmission-interval"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.RetransmissionInterval)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db rxmt interval field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }
                 if (ospfCfgObj.TransmitDelay != nil) {
                     fieldName := "transmit-delay"

                     var dbVlaueInt int = int(uint(*(ospfCfgObj.TransmitDelay)))
                     dbVlaueStr := strconv.Itoa(dbVlaueInt)
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db transmit delay field to ", dbVlaueStr)

                     ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                     ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                 }

                 addDeletePresent = true
            }

            /*
            if (inParams.oper == REPLACE) {
                //not sure if this is required
                //ospfOpMap[db.ConfigDB][intfTblName][intfTblKey] = ospfIntfDbValue
                //ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field["NULL"] = "NULL"
            }
            */

            ospfIntfTblMap[intfTblKey] = ospfIntfDbValue
            log.Info("YangToDb_ospfv2_interface_subtree_xfmr: update ospfIntfTblMap ", ospfIntfTblMap)

        } else if (deleteOperation) {

             log.Info("YangToDb_ospfv2_interface_subtree_xfmr: DELETE operation ", inParams.oper)

             ospfIfEntry, err := ospfTblData.GetEntry(db.Key{[]string{intfTblKey}})
             if err != nil || len(ospfIfEntry.Field) == 0 {
                 errStr := "Resource Not Found"
                 log.Error("YangToDb_ospfv2_interface_subtree_xfmr: OSPF Interface empty row ", errStr)
                 continue
             }

             if (ospfCfgObj != nil && !strings.HasSuffix(rcvdUri, "config")) {
                 log.Info("YangToDb_ospfv2_interface_subtree_xfmr: config individual field deletes")
                 fieldDeleted := false

                 for _, fieldName := range fieldNameList {
                     if (strings.HasSuffix(rcvdUri,  fieldName)) {
                         log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete field ", fieldName)

                         if (!fieldDeleted) {
                             ospfOpMap[db.ConfigDB][intfTblName][intfTblKey] = db.Value{Field: make(map[string]string)}
                         }

                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = "NULL"
                         ospfIntfDbValue.Field[fieldName] = "NULL"
                         fieldDeleted = true    
                     }
                 }

                 log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Atleast one field deleted ", fieldDeleted)
                 if (fieldDeleted) {
                     ospfIntfTblMap[intfTblKey] = ospfIntfDbValue
                     addDeletePresent = true
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete field ospfIntfTblMap ", ospfIntfTblMap)
                 }

            } else if (ospfCfgObj == nil && strings.HasSuffix(rcvdUri, "config")) {  //delete entire row

                log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete entire row")

                ospfOpMap[db.ConfigDB][intfTblName][intfTblKey] = db.Value{Field: make(map[string]string)}
                ospfIntfTblMap[intfTblKey] = ospfIntfDbValue
                addDeletePresent = true

                log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete entire row ospfIntfTblMap ", ospfIntfTblMap)
            }

        } //deleteOperation
    }//for IfAddressList

    if (addDeletePresent) {
        inParams.subOpDataMap[inParams.oper] = &ospfOpMap
        ospfRespMap[intfTblName] = ospfIntfTblMap
        if (ospfAreaAutoCreate && ospfAreaOpMapInited) {
            log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Auto creating area ", ospfAreaTblMap)
            ospfRespMap[ospfAreaTblName] = ospfAreaTblMap
        }
    }

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospfRespMap ", ospfRespMap)
    return ospfRespMap, nil
}


var DbToYang_ospfv2_interface_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error
    var ok bool
    var ifName string

    pathInfo := NewPathInfo(inParams.uri)
    reqIfName := pathInfo.Var("name")
    rcvdUri, _ := getYangPathFromUri(inParams.uri)

    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: --------Start------")
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: reqIfName ", reqIfName)
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: param uri ", inParams.uri)
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: pathInfo ", pathInfo)
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: rcvd uri ", rcvdUri)

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    var subIntfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface

    intfsObj := getIntfsRoot(inParams.ygRoot)

    if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
        var ok bool = false
        if intfObj, ok = intfsObj.Interface[reqIfName]; !ok {
            intfObj, _ = intfsObj.NewInterface(reqIfName)
        }
        ygot.BuildEmptyTree(intfObj)
        if intfObj.Subinterfaces == nil {
            ygot.BuildEmptyTree(intfObj.Subinterfaces)
        }
    } else {
        // intfsObj nil, create one
        ygot.BuildEmptyTree(intfsObj)
        intfObj, _ = intfsObj.NewInterface(reqIfName)
        ygot.BuildEmptyTree(intfObj)
    }

    if subIntfObj, ok = intfObj.Subinterfaces.Subinterface[0]; !ok {
        subIntfObj, err = intfObj.Subinterfaces.NewSubinterface(0)
        if err != nil {
            log.Error("DbToYang_ospfv2_interface_subtree_xfmr: Creation of subinterface subtree failed!")
            return err
        }
        ygot.BuildEmptyTree(subIntfObj)
    }

    if subIntfObj.Ipv4 == nil {
        errStr := "Subinterface doesnt have ipv4 object!"
        log.Info("DbToYang_ospfv2_interface_subtree_xfmr:", errStr)
        subIntfObj.Ipv4 = new(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4)
        ygot.BuildEmptyTree(subIntfObj.Ipv4)
    }
    ipv4Obj := subIntfObj.Ipv4

    if ipv4Obj.Ospfv2 == nil {
        errStr := "Ipv4 doesnt have Ospfv2 object!"
        log.Info("DbToYang_ospfv2_interface_subtree_xfmr:", errStr)
        ipv4Obj.Ospfv2 = new(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2)
        ygot.BuildEmptyTree(ipv4Obj.Ospfv2)
    }
    ospfObj := ipv4Obj.Ospfv2

    var ospfCfgObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config
    ospfCfgObj = nil
    ifAddress := ""
    for intfAddrKey, intfAddrConfigObj := range ospfObj.IfAddresses {
        ifAddress = "" + intfAddrKey
        ospfCfgObj = intfAddrConfigObj.Config
        break
    }

    intfTblName := "OSPFV2_INTERFACE"
    var ospfIfTblSpec *db.TableSpec = &db.TableSpec{Name: intfTblName}
    ospfTblData, err := configDbPtr.GetTable(ospfIfTblSpec)
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("DbToYang_ospfv2_interface_subtree_xfmr: OSPF Interface Table data not found ", errStr)
        return err
    }

    intfTblKeys, err := ospfTblData.GetKeys()
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("DbToYang_ospfv2_interface_subtree_xfmr: get keys failed ", errStr)
        return err
    }

    ifName, err = ospfGetNativeIntfName(reqIfName)
    if (err != nil) {
        errStr := "Invalid OSPF interface name"
        log.Info("DbToYang_ospfv2_interface_subtree_xfmr: " + errStr + " " + reqIfName)
        return tlerr.New(errStr)
    }

    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: Native ifName ", ifName)

    fieldNameList := []string { "area-id", "authentication-type", "authentication-key", "authentication-key",
                                "authentication-key-id", "authentication-md5-key", "bfd-enable", "dead-interval",
                                "hello-interval", "hello-multiplier", "metric", "mtu-ignore", "network-type",
                                "dead-interval-minimal", "priority", "retransmission-interval", "transmit-delay" }

    for _, intfTblKey := range intfTblKeys {
        keyIfName := intfTblKey.Get(0)
        keyIfAddress := intfTblKey.Get(1)

        if len(ifName) != 0 && ifName != keyIfName {
           continue
        }

        if len(ifAddress) !=0 && ifAddress != keyIfAddress {
           continue
        }

        ospfIfEntry, err2 := ospfTblData.GetEntry(intfTblKey)
        if err2 != nil || len(ospfIfEntry.Field) == 0 {
            log.Error("YangToDb_ospfv2_interface_subtree_xfmr: Create new entry for ", intfTblKey)
            continue
        }

        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf if key ", intfTblKey)
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf if Entry ", ospfIfEntry)

        if len(ifAddress) == 0 {
            ospfIfAddresses, err2 := ospfObj.NewIfAddresses(keyIfAddress)
            if err2 != nil {
                log.Error("YangToDb_ospfv2_interface_subtree_xfmr: Create new IfAddresses map elt failed ", keyIfAddress)
                continue
            }

            var ospfCfgData ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config
            ospfCfgObj = &ospfCfgData
            ygot.BuildEmptyTree(ospfCfgObj)
            keyIfAddress2 := "" + keyIfAddress
            ospfCfgObj.Address = &keyIfAddress2
            ospfIfAddresses.Config = ospfCfgObj
        }

        readFieldNameList := []string {}
        if (!strings.HasSuffix(rcvdUri, "config")) {
              for _, fieldName := range fieldNameList {
                  if (strings.HasSuffix(rcvdUri, fieldName)) {
                      readFieldNameList = append(readFieldNameList, fieldName)
                  }
             }
        }

        if len(readFieldNameList) == 0 {
            readFieldNameList = fieldNameList
        }

        log.Info("DbToYang_ospfv2_interface_subtree_xfmr: read field name list ", readFieldNameList)

        for _, fieldName := range readFieldNameList {

            fieldValue, ok := ospfIfEntry.Field[fieldName]
            if (!ok) { 
                log.Info("DbToYang_ospfv2_interface_subtree_xfmr: entry does not have field ", fieldName)
                fieldValue = ""
            }

            log.Info("DbToYang_ospfv2_interface_subtree_xfmr: fieldName ", fieldName)
            log.Info("DbToYang_ospfv2_interface_subtree_xfmr: fieldValue ", fieldValue)

            if (fieldName == "bfd-enable") {
                enabled := false
                if fieldValue == "true" {
                   enabled = true
                }
                ospfCfgObj.BfdEnable = &enabled
            }

            if (fieldName == "mtu-ignore") {
                enabled := false
                if fieldValue == "true" {
                   enabled = true
                }
                ospfCfgObj.MtuIgnore = &enabled
            }

            if (fieldName == "dead-interval-minimal") {
                enabled := false
                if fieldValue == "true" {
                   enabled = true
                }
                ospfCfgObj.DeadIntervalMinimal = &enabled
            }

            if len(fieldValue) == 0 {
                continue
            }

            if (fieldName == "area-id") {
                areaIdUnion, err3 := ospfCfgObj.To_OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union(fieldValue)
                if err3 == nil {
                    ospfCfgObj.AreaId = areaIdUnion
                }
            }

            if (fieldName == "authentication-type") {
                ospfCfgObj.AuthenticationType = &fieldValue
            }

            if (fieldName == "authentication-key") {
                ospfCfgObj.AuthenticationKey = &fieldValue
            }

            if (fieldName == "authentication-key-id") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint8(intVal)
                    ospfCfgObj.AuthenticationKeyId = &fieldValueInt
                }
            }

            if (fieldName == "authentication-md5-key") {
                ospfCfgObj.AuthenticationMd5Key = &fieldValue
            }

            if (fieldName == "dead-interval") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint32(intVal)
                    ospfCfgObj.DeadInterval = &fieldValueInt
                }
            }

            if (fieldName == "hello-interval") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint32(intVal)
                    ospfCfgObj.HelloInterval = &fieldValueInt
                }
            }
            if (fieldName == "hello-multiplier") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint32(intVal)
                    ospfCfgObj.HelloMultiplier = &fieldValueInt
                }
            }
            if (fieldName == "metric") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint32(intVal)
                    ospfCfgObj.Metric = &fieldValueInt
                }
            }
            if (fieldName == "network-type") {
                if fieldValue == "BROADCAST_NETWORK" {
                    ospfCfgObj.NetworkType = ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_BROADCAST_NETWORK
                } else if fieldValue == "POINT_TO_POINT_NETWORK" {
                    ospfCfgObj.NetworkType = ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_POINT_TO_POINT_NETWORK
                }
            }
            if (fieldName == "priority") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint8(intVal)
                    ospfCfgObj.Priority = &fieldValueInt
                }
            }
            if (fieldName == "retransmission-interval") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint32(intVal)
                    ospfCfgObj.RetransmissionInterval = &fieldValueInt
                }
            }
            if (fieldName == "transmit-delay") {
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint32(intVal)
                    ospfCfgObj.TransmitDelay = &fieldValueInt
                }
            }

        } //readFieldNameList

    } //intfTblKeys

    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: returning ")
    return err
}



func delete_ospf_interface_config_all(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) (error) {

    var err error
    var ifName string
    var ospfIntfTblMap map[string]db.Value = make(map[string]db.Value)

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: inParams", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    reqIfName := pathInfo.Var("name")

    ifName, err = ospfGetNativeIntfName(reqIfName)
    if (err != nil) {
        errStr := "Invalid OSPF interface name"
        log.Info("delete_ospf_interface_config_all: " + errStr + " " + reqIfName)
        return tlerr.New(errStr)
    }

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Native ifName ", ifName)

    intfTblName := "OSPFV2_INTERFACE"
    var ospfIfTblSpec *db.TableSpec = &db.TableSpec{Name: intfTblName}
    ospfTblData, err := configDbPtr.GetTable(ospfIfTblSpec)
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("YangToDb_ospfv2_interface_subtree_xfmr: OSPF Interface Table data not found ", errStr)
        return errors.New(errStr)
    }

    intfTblKeys, err := ospfTblData.GetKeys()
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("YangToDb_ospfv2_interface_subtree_xfmr: get keys failed ", errStr)
        return errors.New(errStr)
    }

    ospfOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB][intfTblName] = make(map[string]db.Value)

    entryDeleted := false
    for _, intfTblKey := range intfTblKeys {
        keyIfName := intfTblKey.Get(0)
        if keyIfName != ifName {
            log.Error("YangToDb_ospfv2_interface_subtree_xfmr: key ifname doesnt match ",keyIfName)
            continue
        }

        intfTblKey2 := intfTblKey.Get(0) + "|" + intfTblKey.Get(1)
        ospfIntfDbValue := db.Value{Field: make(map[string]string)}
        ospfOpMap[db.ConfigDB][intfTblName][intfTblKey2] = db.Value{Field: make(map[string]string)}
        ospfIntfTblMap[intfTblKey2] = ospfIntfDbValue
        entryDeleted = true
    }

    if entryDeleted {
        inParams.subOpDataMap[inParams.oper] = &ospfOpMap
        (*ospfRespMap)[intfTblName] = ospfIntfTblMap

        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospfRespMap ", ospfRespMap)
        return nil
    }

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: no entries to delete for ", ifName)
    return nil
}


func get_interface_vrf(inParams *XfmrParams, ifName string) (string, error) {
    log.Info("get_interface_vrf: ifName ", ifName)
    if (ifName == "") {
        errStr := "Empty interface name"
        log.Info("get_interface_vrf: ", errStr)
        return "", errors.New(errStr)
    }

    intfType, _, typeErr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || typeErr != nil {
        log.Info("get_interface_vrf: Invalid interface type IntfTypeUnset err ", typeErr);
        return "", typeErr
    }

    intfTbl := IntfTypeTblMap[intfType]
    intfEntry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:intfTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})
    if dbErr != nil || !intfEntry.IsPopulated() {
        log.Info("get_interface_vrf: intf db get entry fail err ", dbErr);
        return "default", nil
    }

    ifVrfName := (&intfEntry).Get("vrf_name")
    if (ifVrfName == "") {
        ifVrfName = "default"
        log.Info("get_interface_vrf: intf vrfs name set to ", ifVrfName)
    }

    log.Info("get_interface_vrf: intf vrfs name is ", ifVrfName)
    return ifVrfName, nil
}

func ospf_router_present_for_interface(inParams *XfmrParams, ifName string) (bool, error) {

    log.Info("ospf_router_present_for_interface: ifName ", ifName)
    if (ifName == "") {
        errStr := "Empty interface name"
        log.Info("ospf_router_present_for_interface: ", errStr)
        return false, errors.New(errStr)
    }

    ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
    if (ifErr != nil) {
        log.Info("ospf_router_present_for_interface: intf vrfs ger err ", ifErr)
        return false, ifErr
    }

    return ospf_router_present(inParams, ifVrfName)
}

func ospf_area_network_present_for_interface_vrf(inParams *XfmrParams, ifName string) (bool, error) {

    log.Info("ospf_area_network_present_for_interface_vrf: ifName ", ifName)
    if (ifName == "") {
        errStr := "Empty interface name"
        log.Info("ospf_area_network_present_for_interface_vrf: ", errStr)
        return false, errors.New(errStr)
    }

    ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
    if (ifErr != nil) {
        log.Info("ospf_area_network_present_for_interface_vrf: intf vrfs ger err ", ifErr)
        return false, ifErr
    }

    ospfNwTblName := "OSPFV2_ROUTER_AREA_NETWORK"
    var ospfNwTblSpec *db.TableSpec = &db.TableSpec{Name: ospfNwTblName}
    ospfNwTblData, err1 := configDbPtr.GetTable(ospfNwTblSpec)
    if err1 != nil {
        errStr := "OSPF area network table Not Found"
        log.Error("ospf_area_network_present_for_interface_vrf: OSPF Area Nw Table data not found ", errStr)
        return false, nil
    }

    ospfNwTblKeys, err2 := ospfNwTblData.GetKeys()
    if err2 != nil {
        errStr := "Area network table get keys failed"
        log.Error("ospf_area_network_present_for_interface_vrf: get keys failed ", errStr)
        return false, err2
    }

    for _, ospfNwTblKey := range ospfNwTblKeys {
        nwVrfName := ospfNwTblKey.Get(0) 
        if ifVrfName == nwVrfName {
           log.Info("ospf_router_area_network_present: network config present with key ", ospfNwTblKey)
           return true, nil
        }
    }

    log.Info("ospf_area_network_present_for_interface_vrf: area nw config not present in vrf ", ifVrfName)
    return false, nil
}

func ospf_area_id_present_in_interfaces(inParams *XfmrParams, vrfName string) (bool, error) {

    log.Info("ospf_area_id_present_in_interfaces: vrfName ", vrfName)
    if (vrfName == "") {
        errStr := "Empty VRF name"
        log.Info("ospf_area_id_present_in_interfaces: ", errStr)
        return false, errors.New(errStr)
    }

    ospfIntfTblName := "OSPFV2_INTERFACE"
    var ospfIntfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfIntfTblName}
    ospfIntfTblData, err := configDbPtr.GetTable(ospfIntfTblSpec)
    if err != nil {
        errStr := "OSPF Interface table not found"
        log.Error("ospf_area_id_present_in_interfaces: OSPF Interface Table data not found ", errStr)
        return false, nil
    }

    ospfIntfTblKeys, err := ospfIntfTblData.GetKeys()
    if err != nil {
        errStr := "Interface Table get keys Failed"
        log.Error("ospf_area_id_present_in_interfaces: get keys failed ", errStr)
        return false, nil
    }

    for _, ospfIntfTblKey := range ospfIntfTblKeys {
        ifName := ospfIntfTblKey.Get(0)

        ospfIfEntry, err2 := ospfIntfTblData.GetEntry(ospfIntfTblKey)
        if err2 != nil || len(ospfIfEntry.Field) == 0 {
            log.Error("ospf_area_id_present_in_interfaces: Create new entry for ", ospfIntfTblKey)
            continue
        }

        areaId := (& ospfIfEntry).Get("area-id")
        if (areaId == "") {
            continue
        }

        ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
        if (ifErr != nil) {
            log.Info("ospf_area_id_present_in_interfaces: intf vrfs ger err ", ifErr)
            continue
        }

        if (ifVrfName == vrfName) {
            log.Info("ospf_area_id_present_in_interfaces: interface has area config ", ospfIntfTblKey)
            return true, nil
        }
    }

    log.Info("ospf_area_id_present_in_interfaces: no area config in ospf interfaces of ", vrfName)
    return false, nil
}


func delete_ospf_interfaces_for_vrf(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) (error) {

    var err error
    var ospfIntfTblMap map[string]db.Value = make(map[string]db.Value)

    if (inParams.oper != DELETE) {
        log.Info("delete_ospf_interfaces_for_vrf: non delete operation")
        return nil
    }

    log.Info("delete_ospf_interfaces_for_vrf: -------------********---------------")
    pathInfo := NewPathInfo(inParams.uri)
    ospfVrfName := pathInfo.Var("name")
    ospfIdentifier := pathInfo.Var("identifier")
    ospfInstanceNumber := pathInfo.Var("name#2")

    if len(pathInfo.Vars) <  3 {
        log.Info("delete_ospf_interfaces_for_vrf: path info no vars")
        return nil  
    }

    if (ospfVrfName == "") {
        log.Info("delete_ospf_interfaces_for_vrf: path info no vrf Name")
        return nil 
    }

    if !strings.Contains(ospfIdentifier, "OSPF") {
        log.Info("delete_ospf_interfaces_for_vrf: path info no OSPF identifier")
        return nil 
    }

    if len(ospfInstanceNumber) == 0 {
        log.Info("delete_ospf_interfaces_for_vrf: path info no OSPF instance")
        return nil 
    }

    rcvdUri, uriErr := getYangPathFromUri(inParams.uri)
    if (uriErr != nil) {
        log.Info("delete_ospf_interfaces_for_vrf: getYangPathFromUri error ", uriErr)
        return nil
    }

    log.Info("delete_ospf_interfaces_for_vrf: rcvdUri ", rcvdUri)
    if (!strings.HasSuffix(rcvdUri, "protocols/protocol/ospfv2/global")) {
        log.Info("delete_ospf_interfaces_for_vrf: rcvdUri not ospfv2/global")
        return nil
    }

    log.Info("delete_ospf_interfaces_for_vrf: OSPF router Vrf name ", ospfVrfName);

    fieldNameList := []string { "area-id" }

    ospfIntfTblName := "OSPFV2_INTERFACE"
    var ospfIfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfIntfTblName}
    ospfIntfTblData, err := configDbPtr.GetTable(ospfIfTblSpec)
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("delete_ospf_interfaces_for_vrf: OSPF Interface Table data not found ", errStr)
        return nil
    }

    ospfIntfTblKeys, err := ospfIntfTblData.GetKeys()
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("delete_ospf_interfaces_for_vrf: get keys failed ", errStr)
        return nil
    }

    ospfOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB][ospfIntfTblName] = make(map[string]db.Value)

    entryDeleted := false
    for _, ospfIntfTblKey := range ospfIntfTblKeys {
        ifName := ospfIntfTblKey.Get(0)
        log.Info("delete_ospf_interfaces_for_vrf: intf name ", ifName);

        ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
        if (ifErr != nil) {
            log.Info("delete_ospf_interfaces_for_vrf: intf vrfs ger err ", ifErr)
            continue
        }

        if ifVrfName != ospfVrfName {
            log.Info("delete_ospf_interfaces_for_vrf: intf vrfs doesnt match ", ifVrfName)
            continue
        }

        ospfIntfTblKey2 := ospfIntfTblKey.Get(0) + "|" + ospfIntfTblKey.Get(1)

        if (len(fieldNameList) == 0) {
             ospfIntfDbValue := db.Value{Field: make(map[string]string)}
             ospfOpMap[db.ConfigDB][ospfIntfTblName][ospfIntfTblKey2] = db.Value{Field: make(map[string]string)}
             ospfIntfTblMap[ospfIntfTblKey2] = ospfIntfDbValue
             entryDeleted = true
        } else {
            fieldDeleted := false
            ospfIntfDbValue := db.Value{Field: make(map[string]string)}
            for _, fieldName := range fieldNameList {
                log.Info("delete_ospf_interfaces_for_vrf: delete field ", fieldName)
                if (!fieldDeleted) {
                    ospfOpMap[db.ConfigDB][ospfIntfTblName][ospfIntfTblKey2] = db.Value{Field: make(map[string]string)}
                }

                ospfOpMap[db.ConfigDB][ospfIntfTblName][ospfIntfTblKey2].Field[fieldName] = "NULL"
                ospfIntfDbValue.Field[fieldName] = "NULL"
                fieldDeleted = true
            }
            if fieldDeleted {
                ospfIntfTblMap[ospfIntfTblKey2] = ospfIntfDbValue
                entryDeleted = true
            }
        }
    }// for ospfIntfTblKey

    if entryDeleted {
        inParams.subOpDataMap[inParams.oper] = &ospfOpMap
        (*ospfRespMap)[ospfIntfTblName] = ospfIntfTblMap

        log.Info("delete_ospf_interfaces_for_vrf: entryDeleted  ospfRespMap ", ospfRespMap)
        return nil
    }

    log.Info("delete_ospf_interfaces_for_vrf: no entries to delete for ospfVrfName", ospfVrfName)
    return nil
}
