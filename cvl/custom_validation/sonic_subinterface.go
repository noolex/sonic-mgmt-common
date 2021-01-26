////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2021 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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
        "strings"
        util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
        "fmt"
        //log "github.com/golang/glog"
    )

const (
    MAX_SUBINTF   uint32 = 750 
    MAX_SUBINTF_PER_INTF uint32 = 250
)

func (t *CustomValidation) ValidateSubInterfaceVlanID(vc *CustValidationCtxt) CVLErrorInfo {
    
    //log.Info("ValidateSubInterfaceVlanID op:", vc.CurCfg.VOp, "\nkey:", vc.CurCfg.Key, "\ndata:", vc.CurCfg.Data, "\nvc.ReqData: ", vc.ReqData, "\nvc.SessCache", vc.SessCache)

    if (vc.CurCfg.VOp == OP_DELETE) {
         return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    if _, ok := vc.CurCfg.Data["vlan"] ; !ok {
        //vlan not in data
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    key := strings.Split(vc.CurCfg.Key, "|")[1]

    keys := "VLAN_SUB_INTERFACE|"+strings.Split(key,".")[0]+"*"
    tableKeys, err := vc.RClient.Keys(keys).Result()

    if err != nil {
        util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "VLAN_SUB_INTERFACE is empty")
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    for _, dbKey := range tableKeys {
        d := strings.Split(dbKey,"|")
        if len(d) > 2 {
            continue
        }
        currentData, _ := vc.RClient.HGetAll(dbKey).Result()
        if vlan, ok := currentData["vlan"] ; ok {
            if key == d[1] {
                if vlan != vc.CurCfg.Data["vlan"] {
                   util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Another subinterface has same vlan id configured")
                    return CVLErrorInfo{
                        ErrCode:          CVL_SEMANTIC_ERROR,
                        TableName:        "VLAN_SUB_INTERFACE",
                        Keys:             strings.Split(vc.CurCfg.Key, "|"),
                        ConstraintErrMsg: "Cannot update vlan-id of a subinterface",
                        CVLErrDetails:    "Config Validation Error",
                        ErrAppTag:        "subif-vlanid-update-not-allowed",
                    } 
                }
            } else {
                if vlan == vc.CurCfg.Data["vlan"] {
                    util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Another subinterface has same vlan id configured")
                    return CVLErrorInfo{
                        ErrCode:          CVL_SEMANTIC_ERROR,
                        TableName:        "VLAN_SUB_INTERFACE",
                        Keys:             strings.Split(vc.CurCfg.Key, "|"),
                        ConstraintErrMsg: "Cannot configure same vlan-id on multiple sub-interfaces on same parent interface",
                        CVLErrDetails:    "Config Validation Error",
                        ErrAppTag:        "no-unique-subif-vlanid",
                    }
                }
            }
        }
    }

    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func validateSubInterfaceScaleLimits(vc *CustValidationCtxt) CVLErrorInfo {
    
    //log.Info("validateSubInterfaceCreationDeletion op:", vc.CurCfg.VOp, "\nkey:", vc.CurCfg.Key, "\ndata:", vc.CurCfg.Data, "\nvc.ReqData: ", vc.ReqData, "\nvc.SessCache", vc.SessCache)
    
    if (vc.CurCfg.VOp == OP_DELETE) {
         return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    subIntfList, err := vc.RClient.Keys("VLAN_SUB_INTERFACE|*").Result()
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
    }
    total_subif := uint32(0)
    total_if_subif := uint32(0)
    current_subif := strings.Split(vc.CurCfg.Key,"|")[1]
    current_subif_parent := strings.Split(current_subif,".")[0]
    current_subif_index := strings.Split(current_subif,".")[1]
    for _, subIntf := range subIntfList {
        if keys := strings.Split(subIntf,"|"); len(keys) <= 2 {
            if keys[1] != current_subif {
                total_subif++
                if current_subif_parent == strings.Split(keys[1],".")[0] && current_subif_index != strings.Split(keys[1],".")[1] {
                    total_if_subif++
                }
            }
        }
    }
    if total_subif >=  MAX_SUBINTF {
        return CVLErrorInfo{
            ErrCode:          CVL_SEMANTIC_ERROR,
            TableName:        "VLAN_SUB_INTERFACE",
            Keys:             strings.Split(vc.CurCfg.Key, "|"),
            ConstraintErrMsg: fmt.Sprintf("Maximum subinterface limit of %d reached.", MAX_SUBINTF),
            CVLErrDetails:    "Config Validation Error",
        }
    }
    if total_if_subif >=  MAX_SUBINTF_PER_INTF {
        return CVLErrorInfo{
            ErrCode:          CVL_SEMANTIC_ERROR,
            TableName:        "VLAN_SUB_INTERFACE",
            Keys:             strings.Split(vc.CurCfg.Key, "|"),
            ConstraintErrMsg: fmt.Sprintf("Maximum subinterface limit of %d per interface reached.", MAX_SUBINTF_PER_INTF),
            CVLErrDetails:    "Config Validation Error",
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func getSubInterfaceFullName(shortName *string) *string {
    var fullName string

    if strings.Contains(*shortName, "Eth") {
        fullName = strings.Replace(*shortName, "Eth", "Ethernet", -1)
    } else if strings.Contains(*shortName, "Po") {
        fullName = strings.Replace(*shortName, "Po", "PortChannel", -1)
    } else {
        fullName = *shortName
    }

    return &fullName
}

func (t *CustomValidation) ValidateSubInterfaceIntf(vc *CustValidationCtxt) CVLErrorInfo {

    //log.Info("ValidateSubInterfaceIntf op:", vc.CurCfg.VOp, "\nkey:", vc.CurCfg.Key, "\ndata:", vc.CurCfg.Data, "\nvc.ReqData: ", vc.ReqData, "\nvc.SessCache", vc.SessCache)
    
    res := validateSubInterfaceScaleLimits(vc)
    if res.ErrCode != CVL_SUCCESS {
        return res
    }

    key := strings.Split(vc.CurCfg.Key, "|")[1]
    if_name :=strings.Split(key,".")[0]
    parentIfName := *getSubInterfaceFullName(&if_name)

    poMembersKeys, err := vc.RClient.Keys("PORTCHANNEL_MEMBER|" + "*" + "|" + parentIfName).Result()
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_SEMANTIC_KEY_NOT_EXIST}
    }

    if len(poMembersKeys) > 0 {
        return CVLErrorInfo{
            ErrCode:          CVL_SEMANTIC_ERROR,
            TableName:        "VLAN_SUB_INTERFACE",
            Keys:             strings.Split(vc.CurCfg.Key, "|"),
            ConstraintErrMsg: fmt.Sprintf("Cannot configure sub-interface as %s is a member of portchannel.", parentIfName),
            CVLErrDetails:    "Config Validation Error",
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

