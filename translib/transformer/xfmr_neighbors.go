//////////////////////////////////////////////////////////////////////////
//
// Copyright 2019 Dell, Inc.
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
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "encoding/json"
    "fmt"
    "os/exec"
    "bufio"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init () {
    XlateFuncBind("DbToYang_neigh_tbl_get_all_ipv4_xfmr", DbToYang_neigh_tbl_get_all_ipv4_xfmr)
    XlateFuncBind("YangToDb_neigh_tbl_get_all_ipv4_xfmr", YangToDb_neigh_tbl_get_all_ipv4_xfmr)
    XlateFuncBind("DbToYang_neigh_tbl_get_all_ipv6_xfmr", DbToYang_neigh_tbl_get_all_ipv6_xfmr)
    XlateFuncBind("YangToDb_neigh_tbl_get_all_ipv6_xfmr", YangToDb_neigh_tbl_get_all_ipv6_xfmr)
    XlateFuncBind("DbToYang_neigh_tbl_key_xfmr", DbToYang_neigh_tbl_key_xfmr)
    XlateFuncBind("YangToDb_neigh_tbl_key_xfmr", YangToDb_neigh_tbl_key_xfmr)
    XlateFuncBind("rpc_clear_neighbors", rpc_clear_neighbors)
}

const (
    NEIGH_IPv4_PREFIX = "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/neighbors"
    NEIGH_IPv4_PREFIX_IP = NEIGH_IPv4_PREFIX+"/neighbor"
    NEIGH_IPv4_PREFIX_STATE_IP = NEIGH_IPv4_PREFIX_IP+"/state/ip"
    NEIGH_IPv4_PREFIX_STATE_LL = NEIGH_IPv4_PREFIX_IP+"/state/link-layer-address"
    NEIGH_IPv6_PREFIX = "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/neighbors"
    NEIGH_IPv6_PREFIX_IP = NEIGH_IPv6_PREFIX+"/neighbor"
    NEIGH_IPv6_PREFIX_STATE_IP = NEIGH_IPv6_PREFIX_IP+"/state/ip"
    NEIGH_IPv6_PREFIX_STATE_LL = NEIGH_IPv6_PREFIX_IP+"/state/link-layer-address"
)

var YangToDb_neigh_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var neightbl_key string
    var err error

    log.Info("YangToDb_neigh_tbl_key_xfmr - inParams: ", inParams)
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("name")

    if len(intfName) <= 0 {
        errStr := "Interface name is missing"
        log.Error("YangToDb_neigh_tbl_key_xfmr - ", errStr)
        err := tlerr.InvalidArgsError{Format: errStr}
        return "", err
    }

    ipAddr := pathInfo.Var("ip")
    if len(ipAddr) <= 0 {
        log.Info("YangToDb_neigh_tbl_key_xfmr - IP Address not found, returning empty key")
        return "", err
    }

    neightbl_key = intfName + ":" +  ipAddr
    log.Info("YangToDb_neigh_tbl_key_xfmr - key returned: ", neightbl_key)

    return neightbl_key, err
}

var DbToYang_neigh_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error

    log.Info("DbToYang_neigh_tbl_key_xfmr - inParams: ", inParams)
    mykey := strings.Split(inParams.key,":")

    rmap["ip"] =  inParams.key[(len(mykey[0])+1):]
    return rmap, err
}

func delete_neigh_interface_config_all(inParams *XfmrParams, neighRespMap *map[string]map[string]db.Value) (error) {

    var err error
    var neighIntfTblMap map[string]db.Value = make(map[string]db.Value)

    log.Info("delete_neigh_interface_config_all: inParams", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")

    neighTblName := "NEIGH"
    var neighTblSpec *db.TableSpec = &db.TableSpec{Name: neighTblName}
    neighTblData, err := configDbPtr.GetTable(neighTblSpec)
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("delete_neigh_interface_config_all: Neigh Interface Table data not found ", errStr)
        return errors.New(errStr)
    }

    intfTblKeys, err := neighTblData.GetKeys()
    if err != nil {
        errStr := "Resource Not Found"
        log.Error("delete_neigh_interface_config_all: get keys failed ", errStr)
        return errors.New(errStr)
    }

    neighOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    neighOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    neighOpMap[db.ConfigDB][neighTblName] = make(map[string]db.Value)

    entryDeleted := false
    for _, intfTblKey := range intfTblKeys {
        keyIfName := intfTblKey.Get(0)
        if keyIfName != ifName {
            log.Error("delete_neigh_interface_config_all:: key ifname doesnt match ",keyIfName)
            continue
        }

        intfTblKey2 := intfTblKey.Get(0) + "|" + intfTblKey.Get(1)
        neighIntfDbValue := db.Value{Field: make(map[string]string)}
        neighOpMap[db.ConfigDB][neighTblName][intfTblKey2] = db.Value{Field: make(map[string]string)}
        neighIntfTblMap[intfTblKey2] = neighIntfDbValue
        entryDeleted = true
    }

    if entryDeleted {
        inParams.subOpDataMap[inParams.oper] = &neighOpMap
        (*neighRespMap)[neighTblName] = neighIntfTblMap

        log.Info("delete_neigh_interface_config_all::: neighRespMap ", neighRespMap)
        return nil
    }

    log.Info("delete_neigh_interface_config_all: no intries to delete for ", ifName)
    return nil
}

var YangToDb_neigh_tbl_get_all_ipv4_xfmr SubTreeXfmrYangToDb = func (inParams XfmrParams) (map[string]map[string]db.Value, error)  {
    var neighTblKey string
    var neighTblName string

    var staticMacStr string
    var staticIpStr string
    var err error
    valueMap := make(map[string]db.Value)
    neighIntfmap := make(map[string]map[string]db.Value)
    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: --------Start------")

    addOperation := false
    deleteOperation := false
    if (inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE) {
        addOperation = true
    } else if (inParams.oper == DELETE) {
        deleteOperation = true
    } else {
        errStr := "Invalid operation "
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        return neighIntfmap, err
    }

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    rcvdUri, _ := getYangPathFromUri(inParams.uri)

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        errStr := "IntfsObj/interface list is empty for " + ifName
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    intfObj := intfsObj.Interface[ifName]
    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]

    if subIntfObj.Ipv4 == nil {
        errStr := "SubInterface IPv4 node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    neighTblName = "NEIGH"

    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:", ifName)
    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:", inParams.uri)
    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: pathInfo ", pathInfo)
    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: rcvd uri ", rcvdUri)

    if subIntfObj.Ipv4.Neighbors == nil {
        errStr := "SubInterface Neighbors node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    arpObj := subIntfObj.Ipv4.Neighbors.Neighbor
    if arpObj == nil {
        errStr := "arpObj node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: arpObj ", arpObj)
    for k:= range arpObj {
        staticIpStr = *arpObj[k].Ip
    }

    if (addOperation) {
        for _,v := range arpObj {
            staticMacStr = *v.Config.LinkLayerAddress
            log.Info("YangToDb_intf_static_arp_subtree_xfmr: staticMacStrd ", staticMacStr)
        }

        neighTblKey = ifName + "|" + staticIpStr
        log.Info(" ADD operation ", inParams.oper)
        log.Info(" staticIpStr ", staticIpStr)
        log.Info(" neighTblKey ", neighTblKey)
        log.Info(" staticMacStr ", staticMacStr)
        valueMap[neighTblKey] = db.Value{Field: make(map[string]string)}
        valueMap[neighTblKey].Field["family"] = "IPv4"
        valueMap[neighTblKey].Field["neigh"] = staticMacStr
        neighIntfmap[neighTblName] = valueMap
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: valueMap ", valueMap[neighTblKey])
    } else if (deleteOperation) {
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: staticIpStr ", staticIpStr)
        neighTblKey = ifName + "|" + staticIpStr
        var neighTblSpec *db.TableSpec = &db.TableSpec{Name: neighTblName}
        neighTblData, _ := configDbPtr.GetTable(neighTblSpec)

        neighEntry, err := neighTblData.GetEntry(db.Key{[]string{neighTblKey}})
        if err != nil || len(neighEntry.Field) == 0 {
            errStr := "Resource Not Found"
            log.Error(" Static arp empty row ", errStr)
            return neighIntfmap, err
        }

        valueMap[neighTblKey] = db.Value{Field: make(map[string]string)}
        valueMap[neighTblKey].Field["family"] = "NULL"
        valueMap[neighTblKey].Field["neigh"] = "NULL"
        neighIntfmap[neighTblName] = valueMap
    }
    return neighIntfmap, err
}

var YangToDb_neigh_tbl_get_all_ipv6_xfmr SubTreeXfmrYangToDb = func (inParams XfmrParams) (map[string]map[string]db.Value, error)  {
    var neighTblKey string
    var neighTblName string

    var staticMacStr string
    var staticIpStr string
    var err error
    valueMap := make(map[string]db.Value)
    neighIntfmap := make(map[string]map[string]db.Value)
    pathInfo := NewPathInfo(inParams.uri)
    log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: --------Start------")

    addOperation := false
    deleteOperation := false
    if (inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE) {
        addOperation = true
    } else if (inParams.oper == DELETE) {
        deleteOperation = true
    } else {
        errStr := "Invalid operation "
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        return neighIntfmap, err
    }

    ifName := pathInfo.Var("name")
    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }
    rcvdUri, _ := getYangPathFromUri(inParams.uri)

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        errStr := "IntfsObj/interface list is empty for " + ifName
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    intfObj := intfsObj.Interface[ifName]
    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]
    neighTblName = "NEIGH"

    log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:", ifName)
    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:", inParams.uri)
    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: pathInfo ", pathInfo)
    log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: rcvd uri ", rcvdUri)

     if subIntfObj.Ipv6 == nil {
        errStr := "SubInterface IPv6 node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    if subIntfObj.Ipv6.Neighbors == nil {
        errStr := "SubInterface Neighbors node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    arpObj := subIntfObj.Ipv6.Neighbors.Neighbor
    if arpObj == nil {
        errStr := "SubInterface IPv6 node is not set"
        log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        if (deleteOperation) {
            delete_neigh_interface_config_all(&inParams, &neighIntfmap)
            return neighIntfmap, nil
        }
        return neighIntfmap, nil
    }

    log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:: arpObj ", arpObj)
    for k:= range arpObj {
        staticIpStr = *arpObj[k].Ip
    }
 
    if (addOperation) {
        for _,v := range arpObj {
            staticMacStr = *v.Config.LinkLayerAddress
            log.Info("YangToDb_intf_static_arp_subtree_xfmr: staticMacStrd ", staticMacStr)
        }
        neighTblKey = ifName + "|" + staticIpStr

        log.Info(" ADD operation ", inParams.oper)
        log.Info(" staticIpStr ", staticIpStr)
        log.Info(" neighTblKey ", neighTblKey)
        log.Info(" staticMacStr ", staticMacStr)
        valueMap[neighTblKey] = db.Value{Field: make(map[string]string)}
        valueMap[neighTblKey].Field["family"] = "IPv6"
        valueMap[neighTblKey].Field["neigh"] = staticMacStr
        neighIntfmap[neighTblName] = valueMap
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: valueMap ", valueMap[neighTblKey])
    } else if (deleteOperation) {
        log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: staticIpStr ", staticIpStr)
        neighTblKey = ifName + "|" + staticIpStr
        var neighTblSpec *db.TableSpec = &db.TableSpec{Name: neighTblName}
        neighTblData, _ := configDbPtr.GetTable(neighTblSpec)

        neighEntry, err := neighTblData.GetEntry(db.Key{[]string{neighTblKey}})
        if err != nil || len(neighEntry.Field) == 0 {
            errStr := "Resource Not Found"
            log.Error(" Static arp empty row ", errStr)
            return neighIntfmap, err
        }

        valueMap[neighTblKey] = db.Value{Field: make(map[string]string)}
        valueMap[neighTblKey].Field["family"] = "NULL"
        valueMap[neighTblKey].Field["neigh"] = "NULL"
        neighIntfmap[neighTblName] = valueMap
    } 
    return neighIntfmap, err
} 

var DbToYang_neigh_tbl_get_all_ipv4_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var ok bool
    var i int

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr - targetUriPath: ", targetUriPath)

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    var subIntfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
    var neighObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Neighbors_Neighbor

    intfNameRcvd := pathInfo.Var("name")

    if intfNameRcvd == "" {
        errStr := "Interface KEY not present"
        log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        return nil
    }

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        errStr := "IntfsObj/interface list is empty for " + intfNameRcvd
        log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
        return nil
    }
    ipAddrRcvd := pathInfo.Var("ip")

    if intfObj, ok = intfsObj.Interface[intfNameRcvd]; !ok {
        intfObj, err = intfsObj.NewInterface(intfNameRcvd)
        if err != nil {
            log.Error("Creation of interface subtree failed!")
            return nil
        }
    }
    ygot.BuildEmptyTree(intfObj)

    if subIntfObj, ok = intfObj.Subinterfaces.Subinterface[0]; !ok {
        subIntfObj, err = intfObj.Subinterfaces.NewSubinterface(0)
        if err != nil {
            log.Error("Creation of subinterface subtree failed!")
            return nil
        }
    }
    ygot.BuildEmptyTree(subIntfObj)

    var neighTblTs = &db.TableSpec{Name: "NEIGH_TABLE"}
    var appDb = inParams.dbs[db.ApplDB]
    tbl, err := appDb.GetTable(neighTblTs)

    if err != nil {
        log.Error("DbToYang_neigh_tbl_get_all_ipv4_xfmr: App-DB get for list of neighbors failed!")
        return err
    }
    keys, _ := tbl.GetKeys()

    for _, key := range keys {
        intfName := key.Comp[0]
        if (len(key.Comp) == 2) {
            continue
        }
        ipAddr := ""
        for i = 1; i < len(key.Comp)-1; i++ {
            if (key.Comp[i] == " ") {
                ipAddr = ipAddr + ":"
                continue
            }
            ipAddr = ipAddr + key.Comp[i] + ":"
        }
        ipAddr = ipAddr + key.Comp[i]
        neighKeyStr := intfName + ":" + ipAddr
        log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr - ipAddr =", ipAddr)
        log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr - neighKeyStr: ", neighKeyStr)
        entry, dbErr := appDb.GetEntry(&db.TableSpec{Name:"NEIGH_TABLE"}, db.Key{Comp: []string{neighKeyStr}})
        log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr - entry: ", entry)

        if dbErr != nil || len(entry.Field) == 0 {
            log.Error("DbToYang_neigh_tbl_get_all_ipv4_xfmr: App-DB get neighbor entry failed neighKeyStr:", neighKeyStr)
            return err
        }

        linkAddr := entry.Field["neigh"]
    	log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr - linkAddr: ", linkAddr)
        addrFamily := entry.Field["family"]
    	log.Info("DbToYang_neigh_tbl_get_all_ipv4_xfmr - addrFamily: ", addrFamily)

        /*The transformer returns complete table regardless of the interface.
          First check if the interface and IP of this redis entry matches one
          available in the received URI
        */
        if (strings.Contains(targetUriPath, "ipv4") && addrFamily != "IPv4") ||
            (intfName != intfNameRcvd ) {
                log.Info("Skipping entry: ", entry, "for interface: ", intfName, " and IP:", ipAddr,
                         "interface received: ", intfNameRcvd, " IP received: ", ipAddrRcvd)
                continue
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_STATE_LL) {
            if neighObj, ok = subIntfObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.LinkLayerAddress = &linkAddr
            break
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_STATE_IP) {
            if neighObj, ok = subIntfObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.Ip = &ipAddr
            break
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_IP) {
            if neighObj, ok = subIntfObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.Ip = &ipAddr
            neighObj.State.LinkLayerAddress = &linkAddr
            break
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX) {
            if neighObj, ok = subIntfObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.Ip = &ipAddr
            neighObj.State.LinkLayerAddress = &linkAddr
        }
    }
    return err
}

var DbToYang_neigh_tbl_get_all_ipv6_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var ok bool
    var i int

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr - targetUriPath: ", targetUriPath)

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    var subIntfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
    var neighObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv6_Neighbors_Neighbor


    intfNameRcvd := pathInfo.Var("name")
    if intfNameRcvd == "" {
        errStr := "Interface KEY not present"
        log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        return errors.New(errStr)
    }

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        errStr := "IntfsObj/interface list is empty for " + intfNameRcvd
        log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
        return errors.New(errStr)
    }
    ipAddrRcvd := pathInfo.Var("ip")

    if intfObj, ok = intfsObj.Interface[intfNameRcvd]; !ok {
        intfObj, err = intfsObj.NewInterface(intfNameRcvd)
        if err != nil {
            log.Error("Creation of interface subtree failed!")
            return err
        }
    }
    ygot.BuildEmptyTree(intfObj)

    if subIntfObj, ok = intfObj.Subinterfaces.Subinterface[0]; !ok {
        subIntfObj, err = intfObj.Subinterfaces.NewSubinterface(0)
        if err != nil {
            log.Error("Creation of subinterface subtree failed!")
            return err
        }
    }
    ygot.BuildEmptyTree(subIntfObj)

    var neighTblTs = &db.TableSpec{Name: "NEIGH_TABLE"}
    var appDb = inParams.dbs[db.ApplDB]
    tbl, err := appDb.GetTable(neighTblTs)

    if err != nil {
        log.Error("DbToYang_neigh_tbl_get_all_ipv6_xfmr: App-DB get for list of neighbors failed!")
        return err
    }
    keys, _ := tbl.GetKeys()

    for _, key := range keys {
        intfName := key.Comp[0]
        if (len(key.Comp) == 2) {
            continue
        }
        ipAddr := ""
        for i = 1; i < len(key.Comp)-1; i++ {
            if (key.Comp[i] == " ") {
                ipAddr = ipAddr + ":"
                continue
            }
            ipAddr = ipAddr + key.Comp[i] + ":"
        }
        ipAddr = ipAddr + key.Comp[i]
        neighKeyStr := intfName + ":" + ipAddr
        log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr - ipAddr =", ipAddr)
        log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr - neighKeyStr: ", neighKeyStr)
        entry, dbErr := appDb.GetEntry(&db.TableSpec{Name:"NEIGH_TABLE"}, db.Key{Comp: []string{neighKeyStr}})
        log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr - entry: ", entry)

        if dbErr != nil || len(entry.Field) == 0 {
            log.Error("DbToYang_neigh_tbl_get_all_ipv6_xfmr: App-DB get neighbor entry failed neighKeyStr:", neighKeyStr)
            return err
        }

        linkAddr := entry.Field["neigh"]
    	log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr - linkAddr: ", linkAddr)
        addrFamily := entry.Field["family"]
    	log.Info("DbToYang_neigh_tbl_get_all_ipv6_xfmr - addrFamily: ", addrFamily)

        /*The transformer returns complete table regardless of the interface.
          First check if the interface and IP of this redis entry matches one
          available in the received URI
        */
        if (strings.Contains(targetUriPath, "ipv6") && addrFamily != "IPv6") ||
            (intfName != intfNameRcvd ) {
                log.Info("Skipping entry: ", entry, "for interface: ", intfName, " and IP:", ipAddr,
                         "interface received: ", intfNameRcvd, " IP received: ", ipAddrRcvd)
                continue
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_STATE_LL) {
            if neighObj, ok = subIntfObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.LinkLayerAddress = &linkAddr
            break
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_STATE_IP) {
            if neighObj, ok = subIntfObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.Ip = &ipAddr
            break
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_IP) {
            if neighObj, ok = subIntfObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.Ip = &ipAddr
            neighObj.State.LinkLayerAddress = &linkAddr
            break
        } else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX) {
            if neighObj, ok = subIntfObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
                neighObj, err = subIntfObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
                if err != nil {
                    log.Error("Creation of neighbor subtree failed!")
                    return err
                }
            }
            ygot.BuildEmptyTree(neighObj)
            neighObj.State.Ip = &ipAddr
            neighObj.State.LinkLayerAddress = &linkAddr
        }
    }
    return err
}

func getNonDefaultVrfInterfaces(d *db.DB)(map[string]string) {
    var nonDefaultVrfIntfs = make(map[string]string)

    tblList := []string{"INTERFACE", "VLAN_INTERFACE", "PORTCHANNEL_INTERFACE"}
    for _, tbl := range tblList {
        tblObj, err := d.GetTable(&db.TableSpec{Name:tbl})
        if err != nil {
           continue
        }

         keys, _ := tblObj.GetKeys()
         for _, key := range keys {
            entry, err := d.GetEntry(&db.TableSpec{Name: tbl}, key)
            if(err != nil) {
                continue
            }

            log.Info("Key: ", key.Get(0))
            if input, ok := entry.Field["vrf_name"]; ok {
                input_str := fmt.Sprintf("%v", input)
                nonDefaultVrfIntfs[key.Get(0)] = input_str
                log.Info("VRF Found -- intf: ", key.Get(0), " input_str: ", input_str)
            } else {
                log.Info("VRF No Found -- intf: ", key.Get(0))
            }
        }
    }

    entry, _ := d.GetEntry(&db.TableSpec{Name: "MGMT_VRF_CONFIG"}, db.Key{Comp: []string{"vrf_global"}})
    if _, ok := entry.Field["mgmtVrfEnabled"]; ok {
        nonDefaultVrfIntfs["eth0"] = "mgmt"
    }

    return nonDefaultVrfIntfs
}

func isValidVrf(d *db.DB, vrfName string)(bool) {

    vrfObj, err := d.GetTable(&db.TableSpec{Name:"VRF"})
    if err != nil {
        return false
    }

    keys, _ := vrfObj.GetKeys()
    for _, key := range keys {
        log.Info("isValidVrf - key: ", key.Get(0), " vrfname: ", vrfName)
        if (key.Get(0) == vrfName) {
            return true
        }
    }

    /*check mgmt vrf*/
    if vrfName == "mgmt" {
        entry, _ := d.GetEntry(&db.TableSpec{Name: "MGMT_VRF_CONFIG"}, db.Key{Comp: []string{"vrf_global"}})
        if _, ok := entry.Field["mgmtVrfEnabled"]; ok {
            return true
        }
     }
     return false
}

func clear_default_vrf(fam_switch string, d *db.DB)  string {
    var err error
    var cmd *exec.Cmd

    vrfList := getNonDefaultVrfInterfaces(d)

    cmd = exec.Command("ip", fam_switch, "neigh", "show", "all")
    cmd.Dir = "/bin"

    out, err := cmd.StdoutPipe()
    if err != nil {
        log.Info("Can't get stdout pipe: ", err)
        return "% Error: Internal error"
    }

    err = cmd.Start()
    if err != nil {
        log.Info("cmd.Start() failed with: ", err)
        return "% Error: Internal error"
    }

    in := bufio.NewScanner(out)
    for in.Scan() {
        line := in.Text()

        if strings.Contains(line, "lladdr") {
            list := strings.Fields(line)
            ip := list[0]
            intf := list[2]

            if (vrfList[intf] != "") {
                continue
            }

            if strings.Contains(line, "PERMANENT") {
                continue
            }

            _, e := exec.Command("ip", fam_switch, "neigh", "del", ip, "dev", intf).Output()
            if e != nil {
               log.Info("Eror: ", e)
               return "% Error: Internal error"
            }
        }
    }

    return "Success"
}


func clear_vrf(fam_switch string, vrf string) string {
    var err error
    var status string
    var count int
    status = "% Error: Internal error"

    if (len(vrf) <= 0) {
        log.Error("Missing VRF name, returning")
        return status
    }


    for count = 1;  count <= 3; count++ {
        if (vrf == "all") {
            log.Info("Executing: ip ", fam_switch, " -s ", "-s ", "neigh ", "flush ", "all")
            _, err = exec.Command("ip", fam_switch, "-s", "-s", "neigh", "flush", "all").Output()
        } else {
            log.Info("Executing: ip ", fam_switch, " -s ", "-s ", "neigh ", "flush ", "all ", "vrf ", vrf)
             _, err = exec.Command("ip", fam_switch, "-s", "-s", "neigh", "flush", "all", "vrf", vrf).Output()
        }
        if err != nil {
            log.Error("clear_vrf - ", err)
            if (strings.Contains(err.Error(), "255")) {
                continue
            } else {
                break
            }
        }

        status = "Success"
        break
    }

    return status
}

func clear_ip(ip string, fam_switch string, vrf string, d *db.DB) string {
    var cmd *exec.Cmd
    var isValidIp bool = false

    vrfList := getNonDefaultVrfInterfaces(d)

    //get interfaces first associated with this ip
    if (len(vrf) > 0 && vrf != "all") {
        cmd = exec.Command("ip", fam_switch, "neigh", "show", ip, "vrf", vrf)
    } else {
        cmd = exec.Command("ip", fam_switch, "neigh", "show", ip)
    }
    cmd.Dir = "/bin"

    out, err := cmd.StdoutPipe()
    if err != nil {
        log.Error("Can't get stdout pipe: ", err)
        return "% Error: Internal error"
    }

    err = cmd.Start()
    if err != nil {
        log.Error("cmd.Start() failed with: ", err)
        return "% Error: Internal error"
    }

    in := bufio.NewScanner(out)
    for in.Scan() {
        line := in.Text()
        list := strings.Fields(line)
        intf := list[2]

        if (vrfList[intf] == vrf || vrf == "all") {
            log.Info("Executing: ip ", fam_switch, " neigh ", "del ", ip, " dev ", intf)
            _, err := exec.Command("ip", fam_switch, "neigh", "del", ip, "dev", intf).Output()
            if err != nil {
                log.Error("clear_ip - ", err)
                return "% Error: Internal error"
            }
        }
        isValidIp = true
    }

    if isValidIp {
        return "Success"
    } else {
        return "Error: IP address " + ip + " not found"
    }
}

func clear_intf(intf string, fam_switch string) string {
    var isValidIntf bool = false

    cmd := exec.Command("ip", fam_switch, "neigh", "show", "dev", intf)
    cmd.Dir = "/bin"

    out, err := cmd.StdoutPipe()
    if err != nil {
        log.Error("Can't get stdout pipe: ", err)
        return "% Error: Internal error"
    }

    err = cmd.Start()
    if err != nil {
        log.Error("cmd.Start() failed with: ", err)
        return "% Error: Internal error"
    }

    in := bufio.NewScanner(out)
    for in.Scan() {
        line := in.Text()

        if strings.Contains(line, "Cannot find device") {
            log.Error("Error: ", line)
            return line
        }

        list := strings.Fields(line)
        ip := list[0]
        log.Info("Executing: ip ", fam_switch, " neigh ", "del ", ip, " dev ", intf)
        _, err := exec.Command("ip", fam_switch, "neigh", "del", ip, "dev", intf).Output()
        if err != nil {
            log.Error("clear_intf - ", err)
            return "% Error: Internal error"
        }
        isValidIntf = true
    }

    if isValidIntf {
        return "Success"
    } else {
        return "Error: Interface " + intf + " not found"
    }
}

var rpc_clear_neighbors RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_clear_neighbors")
    var err error
    var status string
    var fam_switch string = "-4"
    var intf string = ""
    var ip string = ""
    var vrf string = ""

    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil, err
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-neighbor:output"`
    }

    if input, ok := mapData["sonic-neighbor:input"]; ok {
        mapData = input.(map[string]interface{})
    } else {
        result.Output.Status = "Invalid input"
        return json.Marshal(&result)
    }

    if input, ok := mapData["family"]; ok {
        input_str := fmt.Sprintf("%v", input)
        family := input_str
        if strings.EqualFold(family, "IPv6") || family == "1" {
            fam_switch = "-6"
        }
    }

    if input, ok := mapData["ifname"]; ok {
        input_str := fmt.Sprintf("%v", input)
        sonicIfName := utils.GetNativeNameFromUIName(&input_str)
        log.Info("Converted Interface name = ", *sonicIfName)
        intf = *sonicIfName
    }

    if input, ok := mapData["ip"]; ok {
        input_str := fmt.Sprintf("%v", input)
        ip = input_str
    }

    if input, ok := mapData["vrf"]; ok {
        input_str := fmt.Sprintf("%v", input)
        vrf = input_str
    }

    if input, ok := mapData["all_vrfs"].(bool); ok {
        if input {
           vrf = "all"
        }
    }

    if (len (vrf) > 0 && vrf != "all") {
        if (!isValidVrf(dbs[db.ConfigDB], vrf)) {
            result.Output.Status = "% Error: VRF " +  vrf + " not found"
            log.Error(result.Output.Status)
            return json.Marshal(&result)
        }
    }

    if len(intf) > 0 {
        status = clear_intf(intf, fam_switch)
    } else if len(ip) > 0 {
        status = clear_ip(ip, fam_switch, vrf, dbs[db.ConfigDB])
    } else if len(vrf) > 0 {
        status = clear_vrf(fam_switch, vrf)
    } else {
        status = clear_default_vrf(fam_switch, dbs[db.ConfigDB])
    }

    result.Output.Status = status

    log.Info("result: ", result.Output.Status)
    return json.Marshal(&result)
}
