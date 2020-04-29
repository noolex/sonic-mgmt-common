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
)

func init () {
    XlateFuncBind("YangToDb_ospfv2_interface_subtree_xfmr", YangToDb_ospfv2_interface_subtree_xfmr)
    XlateFuncBind("DbToYang_ospfv2_interface_subtree_xfmr", DbToYang_ospfv2_interface_subtree_xfmr)
}



var YangToDb_ospfv2_interface_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    subIntfmap := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    rcvdUri, _ := getYangPathFromUri(inParams.uri)

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: --------Start------")
    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ifName ", ifName)
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

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

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
        errStr := "IntfsObj/interface list is empty for " + ifName
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfsObj.Interface[ifName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[ifName]
    if intfObj == nil {
        errStr := "Interface Object null"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]

    if subIntfObj.Ipv4 == nil {
        errStr := "SubInterface IPv4 node is not set"
        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    ospfObj := subIntfObj.Ipv4.Ospfv2
    if addOperation {
        if ospfObj == nil {
            errStr := "SubInterface Ospf node is not set"
            log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
            return subIntfmap, errors.New(errStr)
        }
        if ospfObj.IfAddresses == nil || len(ospfObj.IfAddresses) < 1 {
            errStr := "SubInterfaceInterface Address List node is not set"
            log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
            return subIntfmap, errors.New(errStr)
        }
    }

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: subIntfObj ", subIntfObj)
    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospfObj", *ospfObj)

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

    if (deleteOperation && (ospfObj == nil  || (ospfObj.IfAddresses == nil || len(ospfObj.IfAddresses) < 1))) {

       log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Delete at ospfObj or IfAddresses")

       intfTblKeys, err := ospfTblData.GetKeys()
       if err != nil {
            errStr := "Resource Not Found"
            log.Error("YangToDb_ospfv2_interface_subtree_xfmr: get keys failed ", errStr)
            return subIntfmap, errors.New(errStr)
       }

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
           ospfRespMap[intfTblName] = ospfIntfTblMap

           log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospfRespMap ", ospfRespMap)
           return ospfRespMap, nil
       }

       log.Info("YangToDb_ospfv2_interface_subtree_xfmr: no intries to delete for ", ifName)
       return subIntfmap, nil
    }

    fieldNameList := []string { "area-id", "authentication-type", "authentication-key", "authentication-key",
                                "authentication-key-id", "authentication-md5-key", "bfd-enable", "dead-interval",
                                "hello-interval", "hello-multiplier", "metric", "mtu-ignore", "network-type",
                                "priority", "retransmission-interval", "transmit-delay" }

    addDeletePresent :=false

    for intfAddrKey, intfAddrObj := range ospfObj.IfAddresses {

        intfTblKey := ifName + "|" + intfAddrKey
        ospfCfgObj := intfAddrObj.Config
        ospfIntfDbValue := db.Value{Field: make(map[string]string)}

        log.Info("YangToDb_ospfv2_interface_subtree_xfmr: IfAddresses intfTblKey is ",intfTblKey)

        if (addOperation) {

             log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ADD/UPDATE operation ", inParams.oper)
             new_entry := false

             ospfIfEntry, err := ospfTblData.GetEntry(db.Key{[]string{intfTblKey}})
             if err != nil || len(ospfIfEntry.Field) == 0 {
                  ospfOpMap[db.ConfigDB][intfTblName][intfTblKey] = db.Value{Field: make(map[string]string)}
                  ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field["NULL"] = "NULL"
                  new_entry = true
                  addDeletePresent = true
                  log.Error("YangToDb_ospfv2_interface_subtree_xfmr: Create new entry for ", intfTblKey)
             }

             if (intfAddrObj.Config != nil) {

                 if new_entry == false { 
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
                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                         ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                     }
                 }
                 if (ospfCfgObj.Authentication != nil)  {
                     if (ospfCfgObj.Authentication.AuthenticationType != ocbinds.OpenconfigOspfv2Ext_OSPF_AUTHENTICATION_TYPE_UNSET) {
                         fieldName := "authentication-type"
                         auth_type := ospfCfgObj.Authentication.AuthenticationType

                         dbVlaueStr := "NULL"
                         switch (auth_type) {
                             case ocbinds.OpenconfigOspfv2Ext_OSPF_AUTHENTICATION_TYPE_AUTH_NONE:
                                 dbVlaueStr = "AUTH_NONE"
                             case ocbinds.OpenconfigOspfv2Ext_OSPF_AUTHENTICATION_TYPE_TEXT :
                                 dbVlaueStr = "TEXT"
                             case ocbinds.OpenconfigOspfv2Ext_OSPF_AUTHENTICATION_TYPE_MD5HMAC :
                                 dbVlaueStr = "MD5HMAC"
                             default:
                                 log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Invalid Authentication type ", auth_type)
                         }
                         log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db authentication field to ", dbVlaueStr)

                         if (dbVlaueStr != "NULL") {
                            ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                            ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                         }
                     }
                     if (ospfCfgObj.Authentication.AuthenticationKey != nil) {
                         fieldName := "authentication-key"

                         dbVlaueStr := *(ospfCfgObj.Authentication.AuthenticationKey)
                         log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Auth key field to ", dbVlaueStr)

                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                         ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                     }
                     if (ospfCfgObj.Authentication.AuthenticationKeyId != nil) {
                         fieldName := "authentication-key-id"

                         var dbVlaueInt int = int(uint(*(ospfCfgObj.Authentication.AuthenticationKeyId)))
                         dbVlaueStr := strconv.Itoa(dbVlaueInt)
                         log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Auth key id field to ", dbVlaueStr)

                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                         ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                     }
                     if (ospfCfgObj.Authentication.AuthenticationMd5Key != nil) {
                         fieldName := "authentication-md5-key"

                         dbVlaueStr := *(ospfCfgObj.Authentication.AuthenticationMd5Key)
                         log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Auth md5key field to ", dbVlaueStr)

                         ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field[fieldName] = dbVlaueStr
                         ospfIntfDbValue.Field[fieldName] = dbVlaueStr
                     }
                 }
                 if (ospfCfgObj.BfdEnable != nil) {
                     fieldName := "bfd-enable"

                     dbVlaueStr := "true"
                     log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db bgd field to ", dbVlaueStr)

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

                     dbVlaueStr := "true"
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

            if (inParams.oper == REPLACE) {
                //not sure if this is required
                //ospfOpMap[db.ConfigDB][intfTblName][intfTblKey] = ospfIntfDbValue
                //ospfOpMap[db.ConfigDB][intfTblName][intfTblKey].Field["NULL"] = "NULL"
            }

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

             if (ospfCfgObj != nil && strings.HasSuffix(rcvdUri, "config") == false) {
                 log.Info("YangToDb_ospfv2_interface_subtree_xfmr: config individual field deletes")
                 fieldDeleted := false

                 for _, fieldName := range fieldNameList {
                     if (strings.HasSuffix(rcvdUri,  fieldName)) {
                         log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete field ", fieldName)

                         if fieldDeleted == false {
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
    }

    log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospfRespMap ", ospfRespMap)
    return ospfRespMap, nil
}


var DbToYang_ospfv2_interface_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error
    var ok bool

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    rcvdUri, _ := getYangPathFromUri(inParams.uri)

    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: --------Start------")
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: ifName ", ifName)
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: param uri ", inParams.uri)
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: pathInfo ", pathInfo)
    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: rcvd uri ", rcvdUri)

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    var subIntfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
    var ipv4Obj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4
    var ospfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2
    //var ospfCfgObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config

    intfsObj := getIntfsRoot(inParams.ygRoot)

    if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
        var ok bool = false
        if intfObj, ok = intfsObj.Interface[ifName]; !ok {
            intfObj, _ = intfsObj.NewInterface(ifName)
        }
        ygot.BuildEmptyTree(intfObj)
        if intfObj.Subinterfaces == nil {
            ygot.BuildEmptyTree(intfObj.Subinterfaces)
        }
    } else {
        // intfsObj nil, create one
        ygot.BuildEmptyTree(intfsObj)
        intfObj, _ = intfsObj.NewInterface(ifName)
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

    if ipv4Obj == nil {
        errStr := "Subinterface doesnt have ipv4 object!"
        log.Error("DbToYang_ospfv2_interface_subtree_xfmr:", errStr)
        return err
    }
    ygot.BuildEmptyTree(ipv4Obj)

    ospfObj = ipv4Obj.Ospfv2
    if ospfObj == nil {
        errStr := "Ipv4 doesnt have Ospfv2 object!"
        log.Error("DbToYang_ospfv2_interface_subtree_xfmr:", errStr)
        return err
    }
    ygot.BuildEmptyTree(ospfObj)

    /*   TBD
    ospfCfgObj = nil1
    ifAddress := "" 
    ospfIfAddressesList := ospfObj.IfAddresses
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

    fieldNameList := []string { "area-id", "authentication-type", "authentication-key", "authentication-key",
                                "authentication-key-id", "authentication-md5-key", "bfd-enable", "dead-interval",
                                "hello-interval", "hello-multiplier", "metric", "mtu-ignore", "network-type",
                                "priority", "retransmission-interval", "transmit-delay" }
            
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
            var ospfCfgData ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config
            ospfCfgObj = &ospfCfgData
            ygot.BuildEmptyTree(ospfCfgObj) 

            ospfCfgObj.Address = &keyIfAddress
            ospfIfAddresses, err2 := ospfObj.NewIfAddresses(ifAddress)
            if err2 != nil {
                log.Error("YangToDb_ospfv2_interface_subtree_xfmr: Create new ospfIfAddressesList failed ", ifAddress)
                continue
            }
            ospfIfAddresses.Config = ospfCfgObj
            ospfIfAddressesList[ifAddress] = ospfIfAddresses
        } 

        readFieldNameList := []string {}
        if (strings.HasSuffix(rcvdUri, "config") == false) {
              for _, fieldName := range fieldNameList {
                  if (strings.HasSuffix(rcvdUri, fieldName)) {
                      readFieldNameList = append(readFieldNameList, fieldName)
                  }
             }
        }

        if len(readFieldNameList) == 0 {
            readFieldNameList = fieldNameList
        }

        log.Info("DbToYang_ospfv2_interface_subtree_xfmr: read filed name list ", readFieldNameList)

        for _, fieldName := range readFieldNameList {  
         
            fieldValue, ok := ospfIfEntry.Field[fieldName]
            if ok == false {
                log.Info("DbToYang_ospfv2_interface_subtree_xfmr: entry does nothave fieled ", fieldName)
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
                if (ospfCfgObj.Authentication == nil) {
                    ygot.BuildEmptyTree(ospfCfgObj.Authentication)
                }

                if  fieldValue == "AUTH_NONE" {
                    ospfCfgObj.Authentication.AuthenticationType = ocbinds.OpenconfigOspfv2Ext_OSPF_AUTHENTICATION_TYPE_AUTH_NONE
                } else if  fieldValue == "TEXT" {
                    ospfCfgObj.Authentication.AuthenticationType = ocbinds.OpenconfigOspfv2Ext_OSPF_AUTHENTICATION_TYPE_TEXT
                } else if  fieldValue == "MD5HMAC" {
                    ospfCfgObj.Authentication.AuthenticationType = ocbinds.OpenconfigOspfv2Ext_OSPF_AUTHENTICATION_TYPE_MD5HMAC
                }
            }

            if (fieldName == "authentication-key") { 
                if (ospfCfgObj.Authentication == nil) {
                    ygot.BuildEmptyTree(ospfCfgObj.Authentication)
                } 
                ospfCfgObj.Authentication.AuthenticationKey = &fieldValue
            }
            if (fieldName == "authentication-key-id") {  
                if (ospfCfgObj.Authentication == nil) {
                    ygot.BuildEmptyTree(ospfCfgObj.Authentication)
                } 
                if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
                    fieldValueInt := uint8(intVal)
                    ospfCfgObj.Authentication.AuthenticationKeyId = &fieldValueInt
                }
            }
            if (fieldName == "authentication-md5-key") {  
                if (ospfCfgObj.Authentication == nil) {
                    ygot.BuildEmptyTree(ospfCfgObj.Authentication)
                } 
                ospfCfgObj.Authentication.AuthenticationMd5Key = &fieldValue
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

    TBD */


    log.Info("DbToYang_ospfv2_interface_subtree_xfmr: returning ")
    return err
}

