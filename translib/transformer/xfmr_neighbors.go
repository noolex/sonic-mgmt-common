//////////////////////////////////////////////////////////////////////////
//
// Copyright 2019 Dell, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	   http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("DbToYang_neigh_tbl_get_all_ipv4_xfmr", DbToYang_neigh_tbl_get_all_ipv4_xfmr)
	XlateFuncBind("YangToDb_neigh_tbl_get_all_ipv4_xfmr", YangToDb_neigh_tbl_get_all_ipv4_xfmr)
	XlateFuncBind("DbToYang_neigh_tbl_get_all_ipv6_xfmr", DbToYang_neigh_tbl_get_all_ipv6_xfmr)
	XlateFuncBind("YangToDb_neigh_tbl_get_all_ipv6_xfmr", YangToDb_neigh_tbl_get_all_ipv6_xfmr)
	XlateFuncBind("DbToYang_neigh_tbl_key_xfmr", DbToYang_neigh_tbl_key_xfmr)
	XlateFuncBind("YangToDb_neigh_tbl_key_xfmr", YangToDb_neigh_tbl_key_xfmr)
	XlateFuncBind("DbToYang_routed_vlan_neigh_tbl_get_all_ipv4_xfmr", DbToYang_routed_vlan_neigh_tbl_get_all_ipv4_xfmr)
	XlateFuncBind("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr", YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr)
	XlateFuncBind("DbToYang_routed_vlan_neigh_tbl_get_all_ipv6_xfmr", DbToYang_routed_vlan_neigh_tbl_get_all_ipv6_xfmr)
	XlateFuncBind("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr", YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr)
	XlateFuncBind("DbToYang_routed_vlan_neigh_tbl_key_xfmr", DbToYang_routed_vlan_neigh_tbl_key_xfmr)
	XlateFuncBind("YangToDb_routed_vlan_neigh_tbl_key_xfmr", YangToDb_routed_vlan_neigh_tbl_key_xfmr)
	XlateFuncBind("rpc_clear_neighbors", rpc_clear_neighbors)
	XlateFuncBind("Subscribe_neigh_tbl_get_all_ipv4_xfmr", Subscribe_neigh_tbl_get_all_ipv4_xfmr)
	XlateFuncBind("Subscribe_neigh_tbl_get_all_ipv6_xfmr", Subscribe_neigh_tbl_get_all_ipv6_xfmr)
	XlateFuncBind("Subscribe_routed_vlan_neigh_tbl_get_all_ipv4_xfmr", Subscribe_routed_vlan_neigh_tbl_get_all_ipv4_xfmr)
	XlateFuncBind("Subscribe_routed_vlan_neigh_tbl_get_all_ipv6_xfmr", Subscribe_routed_vlan_neigh_tbl_get_all_ipv6_xfmr)
	XlateFuncBind("YangToDb_neighbor_global_key_xfmr", YangToDb_neighbor_global_key_xfmr)
	XlateFuncBind("DbToYangPath_neigh_tbl_path_xfmr", DbToYangPath_neigh_tbl_path_xfmr)
}

const (
	NEIGH_IPv4_PREFIX           = "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/neighbors"
	NEIGH_IPv4_PREFIX_IP        = NEIGH_IPv4_PREFIX + "/neighbor"
	NEIGH_IPv4_PREFIX_STATE     = NEIGH_IPv4_PREFIX + "/neighbor/state"
	NEIGH_IPv4_PREFIX_STATE_IP  = NEIGH_IPv4_PREFIX_IP + "/state/ip"
	NEIGH_IPv4_PREFIX_STATE_LL  = NEIGH_IPv4_PREFIX_IP + "/state/link-layer-address"
	NEIGH_IPv4_PREFIX_CONFIG    = NEIGH_IPv4_PREFIX + "/neighbor/config"
	NEIGH_IPv4_PREFIX_CONFIG_IP = NEIGH_IPv4_PREFIX_IP + "/config/ip"
	NEIGH_IPv4_PREFIX_CONFIG_LL = NEIGH_IPv4_PREFIX_IP + "/config/link-layer-address"
	NEIGH_IPv6_PREFIX           = "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/neighbors"
	NEIGH_IPv6_PREFIX_IP        = NEIGH_IPv6_PREFIX + "/neighbor"
	NEIGH_IPv6_PREFIX_STATE     = NEIGH_IPv6_PREFIX + "/neighbor/state"
	NEIGH_IPv6_PREFIX_STATE_IP  = NEIGH_IPv6_PREFIX_IP + "/state/ip"
	NEIGH_IPv6_PREFIX_STATE_LL  = NEIGH_IPv6_PREFIX_IP + "/state/link-layer-address"
	NEIGH_IPv6_PREFIX_CONFIG    = NEIGH_IPv6_PREFIX + "/neighbor/config"
	NEIGH_IPv6_PREFIX_CONFIG_IP = NEIGH_IPv6_PREFIX_IP + "/config/ip"
	NEIGH_IPv6_PREFIX_CONFIG_LL = NEIGH_IPv6_PREFIX_IP + "/config/link-layer-address"
)

const (
	NEIGH_IPv4_ROUTED_VLAN_PREFIX           = "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/neighbors"
	NEIGH_IPv4_ROUTED_VLAN_PREFIX_IP        = NEIGH_IPv4_ROUTED_VLAN_PREFIX + "/neighbor"
	NEIGH_IPv4_ROUTED_VLAN_PREFIX_STATE     = NEIGH_IPv4_ROUTED_VLAN_PREFIX + "/neighbor/state"
	NEIGH_IPv4_ROUTED_VLAN_PREFIX_STATE_IP  = NEIGH_IPv4_ROUTED_VLAN_PREFIX_IP + "/state/ip"
	NEIGH_IPv4_ROUTED_VLAN_PREFIX_STATE_LL  = NEIGH_IPv4_ROUTED_VLAN_PREFIX_IP + "/state/link-layer-address"
	NEIGH_IPv4_ROUTED_VLAN_PREFIX_CONFIG    = NEIGH_IPv4_ROUTED_VLAN_PREFIX + "/neighbor/config"
	NEIGH_IPv4_ROUTED_VLAN_PREFIX_CONFIG_IP = NEIGH_IPv4_ROUTED_VLAN_PREFIX_IP + "/config/ip"
	NEIGH_IPv4_ROUTED_VLAN_PREFIX_CONFIG_LL = NEIGH_IPv4_ROUTED_VLAN_PREFIX_IP + "/config/link-layer-address"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX           = "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/neighbors"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX_IP        = NEIGH_IPv6_ROUTED_VLAN_PREFIX + "/neighbor"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX_STATE     = NEIGH_IPv6_ROUTED_VLAN_PREFIX + "/neighbor/state"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX_STATE_IP  = NEIGH_IPv6_ROUTED_VLAN_PREFIX_IP + "/state/ip"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX_STATE_LL  = NEIGH_IPv6_ROUTED_VLAN_PREFIX_IP + "/state/link-layer-address"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX_CONFIG    = NEIGH_IPv6_ROUTED_VLAN_PREFIX + "/neighbor/config"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX_CONFIG_IP = NEIGH_IPv6_ROUTED_VLAN_PREFIX_IP + "/config/ip"
	NEIGH_IPv6_ROUTED_VLAN_PREFIX_CONFIG_LL = NEIGH_IPv6_ROUTED_VLAN_PREFIX_IP + "/config/link-layer-address"
)

const (
	PREFIX             = 0
	PREFIX_IP          = 1
	PREFIX_STATE_IP    = 2
	PREFIX_STATE_LL    = 3
	PREFIX_CONFIG_IP   = 4
	PREFIX_CONFIG_LL   = 5
	PREFIXv6           = 0
	PREFIX_IPv6        = 1
	PREFIX_STATE_IPv6  = 2
	PREFIX_STATE_LLv6  = 3
	PREFIX_CONFIG_IPv6 = 4
	PREFIX_CONFIG_LLv6 = 5
	PREFIX_CONFIG      = 6
	PREFIX_STATE       = 7
)

var YangToDb_neigh_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var neightbl_key string
	var err error

	log.Info("YangToDb_neigh_tbl_key_xfmr - inParams: ", inParams)
	pathInfo := NewPathInfo(inParams.uri)

	rcvdIfName, ifName, subIdxStr, subIdx, ifNameInDb, err1 := neighGetifNameFrmPathInfo(*pathInfo)
	log.Infof("YangToDb_neigh_tbl_key_xfmr : RcvdName: %s, NativeName: %s, subIdxStr: %s, subIdx: %d, ifNameInDb: %s, err1: %s", rcvdIfName, ifName, subIdxStr, subIdx, ifNameInDb, err1)

	log.Info("YangToDb_neigh_tbl_key_xfmr : pathInfo ", pathInfo)
	log.Info("YangToDb_neigh_tbl_key_xfmr : inParams.uri ", inParams.uri)

	if len(rcvdIfName) <= 0 {
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

	neightbl_key = ifNameInDb + ":" + ipAddr
	log.Info("YangToDb_neigh_tbl_key_xfmr - key returned: ", neightbl_key)

	return neightbl_key, err
}

var DbToYang_neigh_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	var err error

	log.Info("DbToYang_neigh_tbl_key_xfmr - inParams: ", inParams)
	mykey := strings.Split(inParams.key, ":")

	rmap["ip"] = inParams.key[(len(mykey[0]) + 1):]
	return rmap, err
}

var YangToDb_routed_vlan_neigh_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var neightbl_key string
	var err error

	log.Info("YangToDb_routed_vlan_neigh_tbl_key_xfmr - inParams: ", inParams)
	pathInfo := NewPathInfo(inParams.uri)
	intfName := pathInfo.Var("name")

	if len(intfName) <= 0 {
		errStr := "Interface name is missing"
		log.Error("YangToDb_routed_vlan_neigh_tbl_key_xfmr - ", errStr)
		err := tlerr.InvalidArgsError{Format: errStr}
		return "", err
	}

	ipAddr := pathInfo.Var("ip")
	if len(ipAddr) <= 0 {
		log.Info("YangToDb_routed_vlan_neigh_tbl_key_xfmr - IP Address not found, returning empty key")
		return "", err
	}

	neightbl_key = intfName + ":" + ipAddr
	log.Info("YangToDb_routed_vlan_neigh_tbl_key_xfmr - key returned: ", neightbl_key)

	return neightbl_key, err
}

var DbToYang_routed_vlan_neigh_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	var err error

	log.Info("DbToYang_routed_vlan_neigh_tbl_key_xfmr - inParams: ", inParams)
	mykey := strings.Split(inParams.key, ":")

	rmap["ip"] = inParams.key[(len(mykey[0]) + 1):]
	return rmap, err
}

var YangToDb_neighbor_global_key_xfmr = func(inParams XfmrParams) (string, error) {
	log.Info("YangToDb_neighbor_global_key_xfmr: ", inParams.ygRoot, inParams.uri)
	return "Values", nil
}

func delete_neigh_interface_config_all(inParams *XfmrParams, neighRespMap *map[string]map[string]db.Value) error {

	var neighIntfTblMap map[string]db.Value = make(map[string]db.Value)
	var keyPattern string

	log.Info("delete_neigh_interface_config_all: inParams", inParams)

	pathInfo := NewPathInfo(inParams.uri)
	ifNameRcvd, ifName, subIdxStr, subIdx, ifNameInDb, err1 := neighGetifNameFrmPathInfo(*pathInfo)
	log.Infof("delete_neigh_interface_config_all: RcvdName: %s, NativeName: %s, subIdxStr: %s, subIdx: %d, ifNameInDb: %s, err1: %s", ifNameRcvd, ifName, subIdxStr, subIdx, ifNameInDb, err1)

	neighTblName := "NEIGH"

	var configDb = inParams.dbs[db.ConfigDB]
	var neighTblTs = &db.TableSpec{Name: "NEIGH", CompCt: 2}

	ipAddrRcvd := pathInfo.Var("ip")
	if len(ipAddrRcvd) > 0 {
		keyPattern = ifNameInDb + "|" + ipAddrRcvd
	} else {
		keyPattern = ifNameInDb + "|*"
	}

	keys, _ := configDb.GetKeysByPattern(neighTblTs, keyPattern)
	log.Info("delete_neigh_interface_config_all::: neighTbl keys ", keys)

	/*
	   neighOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
	   neighOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)

	*/

	if inParams.subOpDataMap[inParams.oper] == nil {
		_subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		inParams.subOpDataMap[inParams.oper] = &_subOpMap
	}

	subOpMap := inParams.subOpDataMap[inParams.oper]

	if (*subOpMap)[db.ConfigDB] == nil {
		(*subOpMap)[db.ConfigDB] = make(map[string]map[string]db.Value)
	}

	log.Info("subOpMap ", *subOpMap)

	entryDeleted := false
	for _, intfTblKey := range keys {
		keyIfName := intfTblKey.Get(0)
		if keyIfName != ifNameInDb {
			log.Error("delete_neigh_interface_config_all:: key ifname doesnt match ", keyIfName)
			continue
		}

		if !entryDeleted {
			(*subOpMap)[db.ConfigDB][neighTblName] = make(map[string]db.Value)
		}

		intfTblKey2 := intfTblKey.Get(0) + "|" + intfTblKey.Get(1)
		neighIntfDbValue := db.Value{Field: make(map[string]string)}
		/*
		   neighOpMap[db.ConfigDB][neighTblName][intfTblKey2] = db.Value{Field: make(map[string]string)}
		*/
		(*subOpMap)[db.ConfigDB][neighTblName][intfTblKey2] = db.Value{Field: make(map[string]string)}

		neighIntfTblMap[intfTblKey2] = neighIntfDbValue
		entryDeleted = true
	}

	if entryDeleted {
		/*
		   inParams.subOpDataMap[inParams.oper] = &neighOpMap
		*/
		(*neighRespMap)[neighTblName] = neighIntfTblMap

		log.Info("delete_neigh_interface_config_all::: neighRespMap, subOpMap", neighRespMap, *subOpMap)
		return nil
	}

	log.Info("delete_neigh_interface_config_all: no Entries to delete for ", ifNameInDb)
	return nil
}

func neighGetNativeIntfName(ifName string) (string, error) {
	var errStr string

	if ifName == "" {
		errStr = "Empty interface name received"
		err := tlerr.InvalidArgsError{Format: errStr}
		log.Infof("neighGetNativeIntfName: %s.", errStr)
		return ifName, err
	}

	if !utils.IsAliasModeEnabled() {
		if strings.Contains(ifName, "/") {
			errStr = "Invalid portname " + ifName + ", standard interface naming not enabled"
			log.Infof("neighGetNativeIntfName: %s.", errStr)
			return ifName, errors.New(errStr)
		} else {
			log.Infof("neighGetNativeIntfName: alias mode disabled return same name %s", ifName)
			return ifName, nil
		}
	}

	nonPhyIntfPrefixes := []string{"PortChannel", "Portchannel", "portchannel",
		"Vlan", "VLAN", "vlan", "VLINK"}

	for _, intfPrefix := range nonPhyIntfPrefixes {
		if strings.HasPrefix(ifName, intfPrefix) {
			log.V(1).Infof("neighGetNativeIntfName: non physical interface %s.", ifName)
			return ifName, nil
		}
	}

	nativeNamePtr := utils.GetNativeNameFromUIName(&ifName)
	log.Infof("neighGetNativeIntfName: ifName %s native %s.", ifName, *nativeNamePtr)
	return *nativeNamePtr, nil
}

func neighGetSubInterfaceShortName(longName *string) *string {

	//Got error while using utils "getSubInterfaceShortName not declared by package utils (compile)"
	//shortName := utils.getSubInterfaceShortName(longName)
	var shortName string

	if strings.Contains(*longName, "Ethernet") {
		shortName = strings.Replace(*longName, "Ethernet", "Eth", -1)
	} else if strings.Contains(*longName, "PortChannel") {
		shortName = strings.Replace(*longName, "PortChannel", "Po", -1)
	} else {
		shortName = *longName
	}

	log.V(3).Infof("neighGetSubInterfaceShortName %s => %s", *longName, shortName)

	return &shortName
}

//Get ifName formats from inParams
func neighGetifNameFrmPathInfo(pathInfo PathInfo) (string, string, string, uint32, string, error) {
	var subIdx uint32

	rcvdIfName := pathInfo.Var("name")
	subIdxStr := pathInfo.Var("index")

	nativeIfName, _ := neighGetNativeIntfName(rcvdIfName)
	ifNameInDb := nativeIfName

	if subIdxStr != "0" && subIdxStr != "" {
		tmpIdx, _ := strconv.Atoi(subIdxStr)
		subIdx = uint32(tmpIdx)

		nativeIfName = nativeIfName + "." + subIdxStr
		ifNameInDb = *neighGetSubInterfaceShortName(&nativeIfName)
	}

	log.Info("neighGetIfNameFrmPathInfo: RcvdIfName: " + rcvdIfName + " nativeIfName: " + nativeIfName + " ifNameInDb: " + ifNameInDb)

	return rcvdIfName, nativeIfName, subIdxStr, subIdx, ifNameInDb, nil
}

var YangToDb_neigh_tbl_get_all_ipv4_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
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
	if inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE {
		addOperation = true
	} else if inParams.oper == DELETE {
		deleteOperation = true
	} else {
		errStr := "Invalid operation "
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		return neighIntfmap, err
	}

	pathInfo := NewPathInfo(inParams.uri)
	uriIfName, ifName, subIdxStr, subIdx, ifNameInDb, err1 := neighGetifNameFrmPathInfo(*pathInfo)
	log.Infof("YangToDb_neigh_tbl_key_all_ipv4_xfmr : uriIfName/RcvdName: %s, NativeName: %s, subIdxStr: %s, subIdx: %d, ifNameInDb: %s, err1: %s", uriIfName, ifName, subIdxStr, subIdx, ifNameInDb, err1)

	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + ifName
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	intfObj := intfsObj.Interface[uriIfName]
	if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
		errStr := "SubInterface node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	if _, ok := intfObj.Subinterfaces.Subinterface[subIdx]; !ok {
		errStr := "SubInterface node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	subIntfObj := intfObj.Subinterfaces.Subinterface[subIdx]

	if subIntfObj.Ipv4 == nil {
		errStr := "SubInterface IPv4 node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	neighTblName = "NEIGH"

	rcvdUri, _ := getYangPathFromUri(inParams.uri)

	log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:", ifName)
	log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:", inParams.uri)
	log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: pathInfo ", pathInfo)
	log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: rcvd uri ", rcvdUri)

	if subIntfObj.Ipv4.Neighbors == nil {
		errStr := "SubInterface Neighbors node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	arpObj := subIntfObj.Ipv4.Neighbors.Neighbor
	if arpObj == nil {
		errStr := "arpObj node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: arpObj ", arpObj)
	for k := range arpObj {
		staticIpStr = *arpObj[k].Ip
	}

	if addOperation {
		for _, v := range arpObj {
			staticMacStr = *v.Config.LinkLayerAddress
			log.Info("YangToDb_neigh_tbl_get_all)ipv4_xfmr:: staticMacStrd ", staticMacStr)
		}
		//neighTblKey = ifName + "|" + staticIpStr
		neighTblKey = ifNameInDb + "|" + staticIpStr
		log.Info(" ADD operation ", inParams.oper)
		log.Info(" staticIpStr ", staticIpStr)
		log.Info(" neighTblKey ", neighTblKey)
		log.Info(" staticMacStr ", staticMacStr)
		valueMap[neighTblKey] = db.Value{Field: make(map[string]string)}
		valueMap[neighTblKey].Field["family"] = "IPv4"
		valueMap[neighTblKey].Field["neigh"] = staticMacStr
		neighIntfmap[neighTblName] = valueMap
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: valueMap ", valueMap[neighTblKey])
	} else if deleteOperation {
		log.Info("YangToDb_neigh_tbl_get_all_ipv4_xfmr:: staticIpStr ", staticIpStr)
		//neighTblKey = ifName + "|" + staticIpStr
		neighTblKey = ifNameInDb + "|" + staticIpStr
		var neighTblSpec *db.TableSpec = &db.TableSpec{Name: neighTblName}
		neighTblData, _ := configDbPtr.GetTable(neighTblSpec)
		neighEntry, err := neighTblData.GetEntry(db.Key{[]string{neighTblKey}})
		if err != nil || len(neighEntry.Field) == 0 {
			errStr := "Resource Not Found"
			log.Error(" Static arp empty row ", errStr)
			return neighIntfmap, err
		}
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		subIntfmap_del := make(map[string]map[string]db.Value)
		subIntfmap_del[neighTblName] = make(map[string]db.Value)
		subIntfmap_del[neighTblName][neighTblKey] = db.Value{}
		subOpMap[db.ConfigDB] = subIntfmap_del
		inParams.subOpDataMap[DELETE] = &subOpMap
	}
	return neighIntfmap, err
}

var Subscribe_neigh_tbl_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	log.Info("------------------------------Entering Subscribe_neigh_tbl_xfmr")

	var err error
	var result XfmrSubscOutParams

	pathInfo := NewPathInfo(inParams.uri)
	origTargetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	log.Infof("----------------------------------------Subscribe_neigh_tbl_xfmr:- subscProc:%v URI: %s", inParams.subscProc, inParams.uri)
	log.Infof("-------------------------------------------Subscribe_neigh_tbl_xfmr:- Target URI path: %s", origTargetUriPath)

	targetUriPath := origTargetUriPath[len("/openconfig-interfaces:interfaces/interface"):]

	if strings.HasPrefix(targetUriPath, "/subinterfaces") {
		targetUriPath = targetUriPath[len("/subinterfaces/subinterface"):]
	} else {
		targetUriPath = targetUriPath[len("/openconfig-vlan:routed-vlan"):]
	}

	if strings.HasPrefix(targetUriPath, "/openconfig-if-ip:ipv4") {
		targetUriPath = targetUriPath[len("/openconfig-if-ip:ipv4/neighbors"):]
	} else {
		targetUriPath = targetUriPath[len("/openconfig-if-ip:ipv6/neighbors"):]
	}

	if targetUriPath == "" || targetUriPath == "/neighbor" {
		result.isVirtualTbl = true
		log.Info("----------------------------------Subscribe_neigh_tbl_xfmr:- result.isVirtualTbl: ", result.isVirtualTbl)
		return result, err
	}

	result.onChange = OnchangeEnable
	result.nOpts = &notificationOpts{}
	result.nOpts.pType = OnChange
	result.isVirtualTbl = false

	tableName := ""
	ipKey := ""
	ifKey := ""

	uriIfName := pathInfo.Var("name")
	if uriIfName == "" || uriIfName == "*" {
		ifKey = "*"
	} else {
		sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
		ifKey = *sonicIfName
	}

	if targetUriPath == "/neighbor/state" {
		tableName = "NEIGH_TABLE"
	} else {
		tableName = "NEIGH"
	}

	ipKey = pathInfo.Var("ip")
	if ipKey == "" {
		ipKey = "*"
	}

	log.Infof("------------------------------------------------path:%v ifKey:%v, ipKey:%v tbl:[%v]", origTargetUriPath, ifKey, ipKey, tableName)

	keyName := ""
	if targetUriPath == "/neighbor/config" {
		keyName = ifKey + "|" + ipKey
		result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB: {tableName: {keyName: {"neigh": "link-layer-address"}}}}
	} else if targetUriPath == "/neighbor/state" {
		keyName = ifKey + ":" + ipKey
		result.dbDataMap = RedisDbSubscribeMap{db.ApplDB: {tableName: {keyName: {"neigh": "link-layer-address"}}}}
	}

	log.Info("-------------------------------------------------------------Subscribe_neigh_tbl_xfmr:- result dbDataMap: ", result.dbDataMap)
	log.Info("--------------------------------------------------------Subscribe_neigh_tbl_xfmr:- result secDbDataMap: ", result.secDbDataMap)

	return result, err

	result.isVirtualTbl = true
	log.Info("Subscribe_neigh_tbl_xfmr:- result.isVirtualTbl: ", result.isVirtualTbl)
	return result, err
}

var Subscribe_neigh_tbl_get_all_ipv4_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	return Subscribe_neigh_tbl_xfmr(inParams)
}

var Subscribe_neigh_tbl_get_all_ipv6_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	return Subscribe_neigh_tbl_xfmr(inParams)
}

var Subscribe_routed_vlan_neigh_tbl_get_all_ipv4_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	return Subscribe_neigh_tbl_xfmr(inParams)
}

var Subscribe_routed_vlan_neigh_tbl_get_all_ipv6_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	return Subscribe_neigh_tbl_xfmr(inParams)
}

var YangToDb_neigh_tbl_get_all_ipv6_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
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
	if inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE {
		addOperation = true
	} else if inParams.oper == DELETE {
		deleteOperation = true
	} else {
		errStr := "Invalid operation "
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		return neighIntfmap, err
	}

	uriIfName, ifName, subIdxStr, subIdx, ifNameInDb, err1 := neighGetifNameFrmPathInfo(*pathInfo)
	log.Infof("YangToDb_neigh_tbl_key_all_ipv4_xfmr : uriIfName/RcvdName: %s, NativeName: %s, subIdxStr: %s, subIdx: %d, ifNameInDb: %s, err1: %s", uriIfName, ifName, subIdxStr, subIdx, ifNameInDb, err1)

	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + ifName
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	intfObj := intfsObj.Interface[uriIfName]
	if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
		errStr := "SubInterface node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	if _, ok := intfObj.Subinterfaces.Subinterface[subIdx]; !ok {
		errStr := "SubInterface node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	subIntfObj := intfObj.Subinterfaces.Subinterface[subIdx]
	neighTblName = "NEIGH"

	rcvdUri, _ := getYangPathFromUri(inParams.uri)

	log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:", ifName)
	log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:", inParams.uri)
	log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:: pathInfo ", pathInfo)
	log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:: rcvd uri ", rcvdUri)

	if subIntfObj.Ipv6 == nil {
		errStr := "SubInterface IPv6 node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	if subIntfObj.Ipv6.Neighbors == nil {
		errStr := "SubInterface Neighbors node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	arpObj := subIntfObj.Ipv6.Neighbors.Neighbor
	if arpObj == nil {
		errStr := "SubInterface IPv6 node is not set"
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:: arpObj ", arpObj)
	for k := range arpObj {
		staticIpStr = *arpObj[k].Ip
	}

	if addOperation {
		for _, v := range arpObj {
			staticMacStr = *v.Config.LinkLayerAddress
			log.Info("YangToDb_intf_static_arp_subtree_xfmr: staticMacStrd ", staticMacStr)
		}
		//neighTblKey = ifName + "|" + staticIpStr
		neighTblKey = ifNameInDb + "|" + staticIpStr

		log.Info(" ADD operation ", inParams.oper)
		log.Info(" staticIpStr ", staticIpStr)
		log.Info(" neighTblKey ", neighTblKey)
		log.Info(" staticMacStr ", staticMacStr)
		valueMap[neighTblKey] = db.Value{Field: make(map[string]string)}
		valueMap[neighTblKey].Field["family"] = "IPv6"
		valueMap[neighTblKey].Field["neigh"] = staticMacStr
		neighIntfmap[neighTblName] = valueMap
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:: valueMap ", valueMap[neighTblKey])
	} else if deleteOperation {
		log.Info("YangToDb_neigh_tbl_get_all_ipv6_xfmr:: staticIpStr ", staticIpStr)
		//neighTblKey = ifName + "|" + staticIpStr
		neighTblKey = ifNameInDb + "|" + staticIpStr
		var neighTblSpec *db.TableSpec = &db.TableSpec{Name: neighTblName}
		neighTblData, _ := configDbPtr.GetTable(neighTblSpec)
		neighEntry, err := neighTblData.GetEntry(db.Key{[]string{neighTblKey}})
		if err != nil || len(neighEntry.Field) == 0 {
			errStr := "Resource Not Found"
			log.Error(" Static arp empty row ", errStr)
			return neighIntfmap, err
		}
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		subIntfmap_del := make(map[string]map[string]db.Value)
		subIntfmap_del[neighTblName] = make(map[string]db.Value)
		subIntfmap_del[neighTblName][neighTblKey] = db.Value{}
		subOpMap[db.ConfigDB] = subIntfmap_del
		inParams.subOpDataMap[DELETE] = &subOpMap
	}
	return neighIntfmap, err
}

func fillRoutedVlanIpv4NeighborObject(inParams *XfmrParams, pathInfo *PathInfo, dbNum db.DBNum, msgType int, tblName string, delim string) error {
	var err error
	var ok bool
	var keyPattern string

	var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
	var routedVlanObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan
	var neighObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Neighbors_Neighbor

	intfNameRcvd, ifName, subIdxStr, subIdx, ifNameInDb, err1 := neighGetifNameFrmPathInfo(*pathInfo)
	log.Infof("fillRoutedVlanIpv4NeighborObject: RcvdName: %s, NativeName: %s, subIdxStr: %s, subIdx: %d, ifNameInDb: %s, err1: %s", intfNameRcvd, ifName, subIdxStr, subIdx, ifNameInDb, err1)

	if intfNameRcvd == "" {
		errStr := "Interface KEY not present"
		log.Info("fillRoutedVlanIpv4NeighborObject: " + errStr)
		return nil
	}

	/*If interface type is not Vlan, return*/
	if !strings.HasPrefix(intfNameRcvd, "Vlan") {
		errStr := "Invalid interface type: " + intfNameRcvd
		log.Error("fillRoutedVlanIpv4NeighborObject - ", errStr)
		return nil
	}

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + intfNameRcvd
		log.Error("fillRoutedVlanIpv4NeighborObject : " + errStr)
		return nil
	}

	if intfObj, ok = intfsObj.Interface[intfNameRcvd]; !ok {
		intfObj, err = intfsObj.NewInterface(intfNameRcvd)
		if err != nil {
			log.Error("Creation of interface subtree failed!")
			return nil
		}
	}
	ygot.BuildEmptyTree(intfObj)

	routedVlanObj = intfObj.RoutedVlan
	if routedVlanObj == nil {
		log.Error("Creation of subinterface subtree failed!")
		return nil
	}
	ygot.BuildEmptyTree(routedVlanObj)

	var dbPtr = inParams.dbs[dbNum]
	var neighTblTs = &db.TableSpec{Name: tblName, CompCt: 2}

	ipAddrRcvd := pathInfo.Var("ip")
	if len(ipAddrRcvd) > 0 {
		keyPattern = intfNameRcvd + delim + ipAddrRcvd
	} else {
		keyPattern = intfNameRcvd + delim + "*"
	}

	keys, _ := dbPtr.GetKeysByPattern(neighTblTs, keyPattern)
	log.Info("Interface Name: ", intfNameRcvd, ", keyPattern: ", keyPattern, " msgType: ", msgType)

	log.Info("Interface Name(Standard, Native):  (", intfNameRcvd, ", ", ifNameInDb, "),  keyPattern: ", keyPattern, " msgType: ", msgType)
	for _, key := range keys {
		/*separate ip and interface*/
		intfName := key.Comp[0]
		ipAddr := key.Comp[1]

		if strings.Contains(ipAddr, ":") { // It's an IPv6 entry; continue
			continue
		}

		neighKeyStr := intfName + delim + ipAddr
		entry, dbErr := dbPtr.GetEntry(&db.TableSpec{Name: tblName}, key)
		if dbErr != nil || len(entry.Field) == 0 {
			log.Error("fillRoutedVlanIpv4NeighborObject : get neighbor entry failed neighKeyStr:", neighKeyStr)
			return err
		}

		linkAddr := entry.Field["neigh"]

		if msgType == PREFIX_STATE_LL {
			if neighObj, ok = routedVlanObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.State.LinkLayerAddress = &linkAddr
			break
		} else if msgType == PREFIX_STATE_IP {
			if neighObj, ok = routedVlanObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.State.Ip = &ipAddr
			break
		} else if msgType == PREFIX_CONFIG_LL {
			if neighObj, ok = routedVlanObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.LinkLayerAddress = &linkAddr
			break
		} else if msgType == PREFIX_CONFIG_IP {
			if neighObj, ok = routedVlanObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			break
		} else if msgType == PREFIX_CONFIG {
			if neighObj, ok = routedVlanObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			neighObj.Config.LinkLayerAddress = &linkAddr
		} else if msgType == PREFIX_STATE {
			if neighObj, ok = routedVlanObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
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

	return nil
}

func fillRoutedVlanIpv6NeighborObject(inParams *XfmrParams, pathInfo *PathInfo, dbNum db.DBNum, msgType int, tblName string, delim string) error {
	var err error
	var ok bool
	var keyPattern string

	var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
	var routedVlanObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan
	var neighObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv6_Neighbors_Neighbor

	intfNameRcvd, ifName, subIdxStr, subIdx, ifNameInDb, err1 := neighGetifNameFrmPathInfo(*pathInfo)
	log.Infof("fillRoutedVlanIpv6NeighborObject: RcvdName: %s, NativeName: %s, subIdxStr: %s, subIdx: %d, ifNameInDb: %s, err1: %s", intfNameRcvd, ifName, subIdxStr, subIdx, ifNameInDb, err1)

	if intfNameRcvd == "" {
		errStr := "Interface KEY not present"
		log.Info("fillRoutedVlanIpv6NeighborObject : " + errStr)
		return nil
	}

	/*If interface type is not Vlan, return*/
	if !strings.HasPrefix(intfNameRcvd, "Vlan") {
		errStr := "Invalid interface type: " + intfNameRcvd
		log.Error("fillRoutedVlanIpv6NeighborObject - ", errStr)
		return nil
	}

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + intfNameRcvd
		log.Error("fillRoutedVlanIpv6NeighborObject: " + errStr)
		return nil
	}

	if intfObj, ok = intfsObj.Interface[intfNameRcvd]; !ok {
		intfObj, err = intfsObj.NewInterface(intfNameRcvd)
		if err != nil {
			log.Error("Creation of interface subtree failed!")
			return nil
		}
	}
	ygot.BuildEmptyTree(intfObj)
	routedVlanObj = intfObj.RoutedVlan
	if routedVlanObj == nil {
		log.Error("Creation of subinterface subtree failed!")
		return nil
	}
	ygot.BuildEmptyTree(routedVlanObj)

	var dbPtr = inParams.dbs[dbNum]
	var neighTblTs = &db.TableSpec{Name: tblName, CompCt: 2}

	ipAddrRcvd := pathInfo.Var("ip")
	if len(ipAddrRcvd) > 0 {
		/* IPv6 address in the DB is in lower case */
		ipAddrRcvd = strings.ToLower(ipAddrRcvd)
		keyPattern = ifNameInDb + delim + ipAddrRcvd
	} else {
		keyPattern = ifNameInDb + delim + "*"
	}
	log.Info("Interface Name(Standard, Native):  (", ifName, ", ", ifNameInDb, "),	keyPattern: ", keyPattern)
	keys, _ := dbPtr.GetKeysByPattern(neighTblTs, keyPattern)
	log.Info("Interface Name: ", intfNameRcvd, ", keyPattern: ", keyPattern, " msgType: ", msgType)

	for _, key := range keys {
		/*separate ip and interface*/
		intfName := key.Comp[0]
		ipAddr := key.Comp[1]

		if !strings.Contains(ipAddr, ":") { // It's an IPv4 entry; continue
			continue
		}

		neighKeyStr := intfName + delim + ipAddr
		entry, dbErr := dbPtr.GetEntry(&db.TableSpec{Name: tblName}, key)
		if dbErr != nil || len(entry.Field) == 0 {
			log.Error("fillRoutedVlanIpv6NeighborObject : get neighbor entry failed neighKeyStr:", neighKeyStr)
			return err
		}

		linkAddr := entry.Field["neigh"]

		if msgType == PREFIX_STATE_LLv6 {
			if neighObj, ok = routedVlanObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.State.LinkLayerAddress = &linkAddr
			break
		} else if msgType == PREFIX_STATE_IPv6 {
			if neighObj, ok = routedVlanObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.State.Ip = &ipAddr
			break
		} else if msgType == PREFIX_CONFIG_LLv6 {
			if neighObj, ok = routedVlanObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.LinkLayerAddress = &linkAddr
			break
		} else if msgType == PREFIX_CONFIG_IPv6 {
			if neighObj, ok = routedVlanObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			break
		} else if msgType == PREFIX_CONFIG {
			if neighObj, ok = routedVlanObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			neighObj.Config.LinkLayerAddress = &linkAddr
		} else if msgType == PREFIX_STATE {
			if neighObj, ok = routedVlanObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = routedVlanObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
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

	return nil
}

var DbToYang_routed_vlan_neigh_tbl_get_all_ipv4_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

	var msgType int

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	/* avoid string comparison in the loop and figure the msgType here*/
	if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX_STATE_LL) {
		msgType = PREFIX_STATE_LL
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX_STATE_IP) {
		msgType = PREFIX_STATE_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX_CONFIG_LL) {
		msgType = PREFIX_CONFIG_LL
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX_CONFIG_IP) {
		msgType = PREFIX_CONFIG_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX_IP) {
		msgType = PREFIX_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX) {
		msgType = PREFIX
	}

	if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX_CONFIG) {
		msgType = PREFIX_CONFIG
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_ROUTED_VLAN_PREFIX_STATE) {
		msgType = PREFIX_STATE
	}

	var msg int
	if msgType == PREFIX || msgType == PREFIX_IP || msgType == PREFIX_CONFIG || msgType == PREFIX_CONFIG_IP || msgType == PREFIX_CONFIG_LL {
		if msgType == PREFIX || msgType == PREFIX_IP {
			msg = PREFIX_CONFIG
		} else {
			msg = msgType
		}
		if err := fillRoutedVlanIpv4NeighborObject(&inParams, pathInfo, db.ConfigDB, msg, "NEIGH", "|"); err != nil {
			return err
		}
	}
	if msgType == PREFIX || msgType == PREFIX_IP || msgType == PREFIX_STATE || msgType == PREFIX_STATE_IP || msgType == PREFIX_STATE_LL {
		if msgType == PREFIX || msgType == PREFIX_IP {
			msg = PREFIX_STATE
		} else {
			msg = msgType
		}
		if err := fillRoutedVlanIpv4NeighborObject(&inParams, pathInfo, db.ApplDB, msg, "NEIGH_TABLE", ":"); err != nil {
			return err
		}
	}

	return nil

}

var DbToYang_routed_vlan_neigh_tbl_get_all_ipv6_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var msgType int

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	/* avoid string comparison in the loop and figure the msgType here*/
	if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX_STATE_LL) {
		msgType = PREFIX_STATE_LL
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX_STATE_IP) {
		msgType = PREFIX_STATE_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX_CONFIG_LL) {
		msgType = PREFIX_CONFIG_LLv6
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX_CONFIG_IP) {
		msgType = PREFIX_CONFIG_IPv6
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX_IP) {
		msgType = PREFIX_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX) {
		msgType = PREFIX
	}

	if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX_CONFIG) {
		msgType = PREFIX_CONFIG
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_ROUTED_VLAN_PREFIX_STATE) {
		msgType = PREFIX_STATE
	}

	var msg int
	if msgType == PREFIXv6 || msgType == PREFIX_IPv6 || msgType == PREFIX_CONFIG || msgType == PREFIX_CONFIG_IPv6 || msgType == PREFIX_CONFIG_LLv6 {
		if msgType == PREFIXv6 || msgType == PREFIX_IPv6 {
			msg = PREFIX_CONFIG
		} else {
			msg = msgType
		}
		if err := fillRoutedVlanIpv6NeighborObject(&inParams, pathInfo, db.ConfigDB, msg, "NEIGH", "|"); err != nil {
			return err
		}
	}
	if msgType == PREFIXv6 || msgType == PREFIX_IPv6 || msgType == PREFIX_STATE || msgType == PREFIX_STATE_IPv6 || msgType == PREFIX_STATE_LLv6 {
		if msgType == PREFIXv6 || msgType == PREFIX_IPv6 {
			msg = PREFIX_STATE
		} else {
			msg = msgType
		}
		if err := fillRoutedVlanIpv6NeighborObject(&inParams, pathInfo, db.ApplDB, msg, "NEIGH_TABLE", ":"); err != nil {
			return err
		}
	}

	return nil
}

func fillIpv4NeighborObject(inParams *XfmrParams, pathInfo *PathInfo, dbNum db.DBNum, msgType int, tblName string, delim string) error {
	var err error
	var ok bool
	var keyPattern string

	var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
	var subIntfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
	var neighObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Neighbors_Neighbor

	intfNameRcvd := pathInfo.Var("name")

	if intfNameRcvd == "" {
		errStr := "Interface KEY not present"
		log.Info("fillIpv4NeighborObject : " + errStr)
		return nil
	}

	/*If interface type is Vlan, return*/
	if len(intfNameRcvd) > 4 && strings.HasPrefix(intfNameRcvd, "Vlan") {
		errStr := "Invalid interface type: " + intfNameRcvd
		log.Error("fillIpv4NeighborObject - ", errStr)
		return nil
	}

	nativeIntfName := utils.GetNativeNameFromUIName(&intfNameRcvd)

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + intfNameRcvd
		log.Error("fillIpv4NeighborObject: " + errStr)
		return nil
	}

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
	var dbPtr = inParams.dbs[dbNum]
	var neighTblTs = &db.TableSpec{Name: tblName, CompCt: 2}

	ipAddrRcvd := pathInfo.Var("ip")
	if len(ipAddrRcvd) > 0 {
		keyPattern = *nativeIntfName + delim + ipAddrRcvd
	} else {
		keyPattern = *nativeIntfName + delim + "*"
	}

	keys, _ := dbPtr.GetKeysByPattern(neighTblTs, keyPattern)
	log.Info("Interface Name(Standard, Native):  (", intfNameRcvd, ", ", *nativeIntfName, "),  keyPattern: ", keyPattern, " msgType: ", msgType)
	for _, key := range keys {
		/*separate ip and interface*/
		intfName := key.Comp[0]
		ipAddr := key.Comp[1]

		if strings.Contains(ipAddr, ":") { // It's an IPv6 entry; continue
			continue
		}

		neighKeyStr := intfName + delim + ipAddr
		entry, dbErr := dbPtr.GetEntry(&db.TableSpec{Name: tblName}, key)
		if dbErr != nil || len(entry.Field) == 0 {
			log.Error("fillIpv4NeighborObject : get neighbor entry failed neighKeyStr:", neighKeyStr)
			return err
		}

		linkAddr := entry.Field["neigh"]

		if msgType == PREFIX_STATE_LL {
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
		} else if msgType == PREFIX_STATE_IP {
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
		} else if msgType == PREFIX_CONFIG_LL {
			if neighObj, ok = subIntfObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = subIntfObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.LinkLayerAddress = &linkAddr
			break
		} else if msgType == PREFIX_CONFIG_IP {
			if neighObj, ok = subIntfObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = subIntfObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			break
		} else if msgType == PREFIX_CONFIG {
			if neighObj, ok = subIntfObj.Ipv4.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = subIntfObj.Ipv4.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			neighObj.Config.LinkLayerAddress = &linkAddr
		} else if msgType == PREFIX_STATE {
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

	return nil
}

func fillIpv6NeighborObject(inParams *XfmrParams, pathInfo *PathInfo, dbNum db.DBNum, msgType int, tblName string, delim string) error {
	var err error
	var ok bool
	var keyPattern string

	var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
	var subIntfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
	var neighObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv6_Neighbors_Neighbor

	intfNameRcvd := pathInfo.Var("name")

	if intfNameRcvd == "" {
		errStr := "Interface KEY not present"
		log.Info("fillIpv6NeighborObject: " + errStr)
		return nil
	}

	/*If interface type is Vlan, return*/
	if len(intfNameRcvd) > 4 && strings.HasPrefix(intfNameRcvd, "Vlan") {
		errStr := "Invalid interface type: " + intfNameRcvd
		log.Error("fillIpv6NeighborObject - ", errStr)
		return nil
	}

	nativeIntfName := utils.GetNativeNameFromUIName(&intfNameRcvd)

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + intfNameRcvd
		log.Error("fillIpv6NeighborObject: " + errStr)
		return nil
	}

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
	var dbPtr = inParams.dbs[dbNum]
	var neighTblTs = &db.TableSpec{Name: tblName, CompCt: 2}

	ipAddrRcvd := pathInfo.Var("ip")
	if len(ipAddrRcvd) > 0 {
		keyPattern = *nativeIntfName + delim + ipAddrRcvd
	} else {
		keyPattern = *nativeIntfName + delim + "*"
	}

	keys, _ := dbPtr.GetKeysByPattern(neighTblTs, keyPattern)
	log.Info("Interface Name(Standard, Native):  (", intfNameRcvd, ", ", *nativeIntfName, "),  keyPattern: ", keyPattern, " msgType: ", msgType)
	for _, key := range keys {
		/*separate ip and interface*/
		intfName := key.Comp[0]
		ipAddr := key.Comp[1]

		if !strings.Contains(ipAddr, ":") { // It's an IPv4 entry; continue
			continue
		}

		neighKeyStr := intfName + delim + ipAddr
		entry, dbErr := dbPtr.GetEntry(&db.TableSpec{Name: tblName}, key)
		if dbErr != nil || len(entry.Field) == 0 {
			log.Error("fillIpv6NeighborObject : get neighbor entry failed neighKeyStr:", neighKeyStr)
			return err
		}

		linkAddr := entry.Field["neigh"]

		if msgType == PREFIX_STATE_LLv6 {
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
		} else if msgType == PREFIX_STATE_IPv6 {
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
		} else if msgType == PREFIX_CONFIG_LLv6 {
			if neighObj, ok = subIntfObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = subIntfObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.LinkLayerAddress = &linkAddr
			break
		} else if msgType == PREFIX_CONFIG_IPv6 {
			if neighObj, ok = subIntfObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = subIntfObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			break
		} else if msgType == PREFIX_CONFIG {
			if neighObj, ok = subIntfObj.Ipv6.Neighbors.Neighbor[ipAddr]; !ok {
				neighObj, err = subIntfObj.Ipv6.Neighbors.NewNeighbor(ipAddr)
				if err != nil {
					log.Error("Creation of neighbor subtree failed!")
					return err
				}
			}
			ygot.BuildEmptyTree(neighObj)
			neighObj.Config.Ip = &ipAddr
			neighObj.Config.LinkLayerAddress = &linkAddr
		} else if msgType == PREFIX_STATE {
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

	return nil
}

var DbToYang_neigh_tbl_get_all_ipv4_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var msgType int

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	/* avoid string comparison in the loop and figure the msgType here*/
	if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_STATE_LL) {
		msgType = PREFIX_STATE_LL
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_STATE_IP) {
		msgType = PREFIX_STATE_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_CONFIG_LL) {
		msgType = PREFIX_CONFIG_LL
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_CONFIG_IP) {
		msgType = PREFIX_CONFIG_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_IP) {
		msgType = PREFIX_IP
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX) {
		msgType = PREFIX
	}

	if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_CONFIG) {
		msgType = PREFIX_CONFIG
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv4_PREFIX_STATE) {
		msgType = PREFIX_STATE
	}

	var msg int
	if msgType == PREFIX || msgType == PREFIX_IP || msgType == PREFIX_CONFIG || msgType == PREFIX_CONFIG_IP || msgType == PREFIX_CONFIG_LL {
		if msgType == PREFIX || msgType == PREFIX_IP {
			msg = PREFIX_CONFIG
		} else {
			msg = msgType
		}
		if err := fillIpv4NeighborObject(&inParams, pathInfo, db.ConfigDB, msg, "NEIGH", "|"); err != nil {
			return err
		}
	}
	if msgType == PREFIX || msgType == PREFIX_IP || msgType == PREFIX_STATE || msgType == PREFIX_STATE_IP || msgType == PREFIX_STATE_LL {
		if msgType == PREFIX || msgType == PREFIX_IP {
			msg = PREFIX_STATE
		} else {
			msg = msgType
		}
		if err := fillIpv4NeighborObject(&inParams, pathInfo, db.ApplDB, msg, "NEIGH_TABLE", ":"); err != nil {
			return err
		}
	}

	return nil
}

var DbToYang_neigh_tbl_get_all_ipv6_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var msgType int

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	/* avoid string comparison in the loop and figure the msgType here*/
	if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_STATE_LL) {
		msgType = PREFIX_STATE_LLv6
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_STATE_IP) {
		msgType = PREFIX_STATE_IPv6
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_CONFIG_LL) {
		msgType = PREFIX_CONFIG_LLv6
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_CONFIG_IP) {
		msgType = PREFIX_CONFIG_IPv6
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_IP) {
		msgType = PREFIX_IPv6
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX) {
		msgType = PREFIXv6
	}

	if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_CONFIG) {
		msgType = PREFIX_CONFIG
	} else if strings.HasPrefix(targetUriPath, NEIGH_IPv6_PREFIX_STATE) {
		msgType = PREFIX_STATE
	}

	var msg int
	if msgType == PREFIXv6 || msgType == PREFIX_IPv6 || msgType == PREFIX_CONFIG || msgType == PREFIX_CONFIG_IPv6 || msgType == PREFIX_CONFIG_LLv6 {
		if msgType == PREFIXv6 || msgType == PREFIX_IPv6 {
			msg = PREFIX_CONFIG
		} else {
			msg = msgType
		}
		if err := fillIpv6NeighborObject(&inParams, pathInfo, db.ConfigDB, msg, "NEIGH", "|"); err != nil {
			return err
		}
	}
	if msgType == PREFIXv6 || msgType == PREFIX_IPv6 || msgType == PREFIX_STATE || msgType == PREFIX_STATE_IPv6 || msgType == PREFIX_STATE_LLv6 {
		if msgType == PREFIXv6 || msgType == PREFIX_IPv6 {
			msg = PREFIX_STATE
		} else {
			msg = msgType
		}
		if err := fillIpv6NeighborObject(&inParams, pathInfo, db.ApplDB, msg, "NEIGH_TABLE", ":"); err != nil {
			return err
		}
	}
	return nil
}

var YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var neighTblKey string
	var neighTblName string

	var staticMacStr string
	var staticIpStr string
	var err error
	valueMap := make(map[string]db.Value)
	neighIntfmap := make(map[string]map[string]db.Value)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: --------Start------")

	addOperation := false
	deleteOperation := false
	if inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE {
		addOperation = true
	} else if inParams.oper == DELETE {
		deleteOperation = true
	} else {
		errStr := "Invalid operation "
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		return neighIntfmap, err
	}

	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("name")
	rcvdUri, _ := getYangPathFromUri(inParams.uri)

	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + ifName
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	intfObj := intfsObj.Interface[ifName]

	if intfObj.RoutedVlan == nil {
		// Handling the scenario for Interface instance delete at interfaces/interface[name] level or subinterfaces container level
		errStr := "routed-vlan node doesn't exist"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	vlanIntfObj := intfObj.RoutedVlan

	neighTblName = "NEIGH"

	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr:", ifName)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr:", inParams.uri)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr:: pathInfo ", pathInfo)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr:: rcvd uri ", rcvdUri)

	if vlanIntfObj.Ipv4 == nil || vlanIntfObj.Ipv4.Neighbors == nil {
		errStr := "vlanInterface Neighbors node is not set"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	arpObj := vlanIntfObj.Ipv4.Neighbors.Neighbor
	if arpObj == nil {
		errStr := "arpObj node is not set"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: arpObj ", arpObj)
	for k := range arpObj {
		staticIpStr = *arpObj[k].Ip
	}

	if addOperation {
		for _, v := range arpObj {
			staticMacStr = *v.Config.LinkLayerAddress
			log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr: staticMacStrd ", staticMacStr)
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
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr:: valueMap ", valueMap[neighTblKey])
	} else if deleteOperation {
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv4_xfmr:: staticIpStr ", staticIpStr)
		neighTblKey = ifName + "|" + staticIpStr
		var neighTblSpec *db.TableSpec = &db.TableSpec{Name: neighTblName}
		neighTblData, _ := configDbPtr.GetTable(neighTblSpec)
		neighEntry, err := neighTblData.GetEntry(db.Key{[]string{neighTblKey}})
		if err != nil || len(neighEntry.Field) == 0 {
			errStr := "Resource Not Found"
			log.Error(" Static arp empty row ", errStr)
			return neighIntfmap, err
		}
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		subIntfmap_del := make(map[string]map[string]db.Value)
		subIntfmap_del[neighTblName] = make(map[string]db.Value)
		subIntfmap_del[neighTblName][neighTblKey] = db.Value{}
		subOpMap[db.ConfigDB] = subIntfmap_del
		inParams.subOpDataMap[DELETE] = &subOpMap
	}
	return neighIntfmap, err
}

var YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var neighTblKey string
	var neighTblName string

	var staticMacStr string
	var staticIpStr string
	var err error
	valueMap := make(map[string]db.Value)
	neighIntfmap := make(map[string]map[string]db.Value)
	pathInfo := NewPathInfo(inParams.uri)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: --------Start------")

	addOperation := false
	deleteOperation := false
	if inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE {
		addOperation = true
	} else if inParams.oper == DELETE {
		deleteOperation = true
	} else {
		errStr := "Invalid operation "
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		return neighIntfmap, err
	}

	ifName := pathInfo.Var("name")
	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}
	rcvdUri, _ := getYangPathFromUri(inParams.uri)

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + ifName
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	intfObj := intfsObj.Interface[ifName]

	if intfObj.RoutedVlan == nil {
		// Handling the scenario for Interface instance delete at interfaces/interface[name] level or subinterfaces container level
		errStr := "routed-vlan node doesn't exist"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	vlanIntfObj := intfObj.RoutedVlan
	neighTblName = "NEIGH"

	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr:", ifName)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr:", inParams.uri)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr:: pathInfo ", pathInfo)
	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr:: rcvd uri ", rcvdUri)

	if vlanIntfObj.Ipv6 == nil || vlanIntfObj.Ipv6.Neighbors == nil {
		errStr := "vlanInterface Neighbors node is not set"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	arpObj := vlanIntfObj.Ipv6.Neighbors.Neighbor
	if arpObj == nil {
		errStr := "SubInterface IPv6 node is not set"
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: " + errStr)
		if deleteOperation {
			delete_neigh_interface_config_all(&inParams, &neighIntfmap)
			return neighIntfmap, nil
		}
		return neighIntfmap, nil
	}

	log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr:: arpObj ", arpObj)
	for k := range arpObj {
		staticIpStr = *arpObj[k].Ip
	}

	if addOperation {
		for _, v := range arpObj {
			staticMacStr = *v.Config.LinkLayerAddress
			log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr: staticMacStrd ", staticMacStr)
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
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr:: valueMap ", valueMap[neighTblKey])
	} else if deleteOperation {
		log.Info("YangToDb_routed_vlan_neigh_tbl_get_all_ipv6_xfmr:: staticIpStr ", staticIpStr)
		neighTblKey = ifName + "|" + staticIpStr
		var neighTblSpec *db.TableSpec = &db.TableSpec{Name: neighTblName}
		neighTblData, _ := configDbPtr.GetTable(neighTblSpec)
		neighEntry, err := neighTblData.GetEntry(db.Key{[]string{neighTblKey}})
		if err != nil || len(neighEntry.Field) == 0 {
			errStr := "Resource Not Found"
			log.Error(" Static arp empty row ", errStr)
			return neighIntfmap, err
		}
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		subIntfmap_del := make(map[string]map[string]db.Value)
		subIntfmap_del[neighTblName] = make(map[string]db.Value)
		subIntfmap_del[neighTblName][neighTblKey] = db.Value{}
		subOpMap[db.ConfigDB] = subIntfmap_del
		inParams.subOpDataMap[DELETE] = &subOpMap
	}
	return neighIntfmap, err
}

var DbToYangPath_neigh_tbl_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) error {

	dbKey := ""

	log.Info("-------------------------- DbToYangPath_neigh_tbl_path_xfmr: params: ", params)

	uiName := utils.GetUINameFromNativeName(&params.tblKeyComp[0])

	params.ygPathKeys["/openconfig-interfaces:interfaces/interface/name"] = *uiName

	if params.tblName == "NEIGH" || params.tblName == "NEIGH_TABLE" {
		addrPath := "/openconfig-if-ip:ipv4/neighbors/neighbor/ip"

		/* For APPL_DB IPv6 case, addr is split [fe80  56bf 64ff feba 3bc0/64] instead of
		[fe80::56bf:64ff:feba:3bc0/64]
		Handle this case
		*/
		dbKey = strings.Join(params.tblKeyComp[1:], ":")

		if len(params.tblKeyComp) > 2 || strings.Contains(dbKey, ":") {
			addrPath = "/openconfig-if-ip:ipv6/neighbors/neighbor/ip"
		}

		ipKey := dbKey // NEIGH Keys doesn't have mask; Only IP Address

		if strings.HasPrefix(params.tblKeyComp[0], "Vlan") {
			params.ygPathKeys["/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan"+addrPath] = ipKey
		} else {
			params.ygPathKeys["/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface"+"/index"] = "0"
			params.ygPathKeys["/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface"+addrPath] = ipKey
		}

	}

	log.Infof("---------------------------------DbToYangPath_neigh_tbl_path_xfmr:  tblName:%v dbKey:[%v] params.ygPathKeys: %v", params.tblName, dbKey, params.ygPathKeys)
	return nil
}

func getIntfVrfMapping(d *db.DB) map[string]string {
	nonDefaultVrfIntfs := make(map[string]string)

	tblList := []string{"INTERFACE", "VLAN_INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_SUB_INTERFACE"}
	for _, tbl := range tblList {
		tblObj, err := d.GetTable(&db.TableSpec{Name: tbl})
		if err != nil {
			continue
		}

		keys, _ := tblObj.GetKeys()
		for _, key := range keys {
			if len(key.Comp) > 1 {
				continue
			}

			entry, err := tblObj.GetEntry(key)
			if err != nil {
				continue
			}

			if input, ok := entry.Field["vrf_name"]; ok {
				input_str := fmt.Sprintf("%v", input)
				nonDefaultVrfIntfs[key.Get(0)] = input_str
			} else {
				nonDefaultVrfIntfs[key.Get(0)] = ""
			}
		}
	}

	entry, _ := d.GetEntry(&db.TableSpec{Name: "MGMT_VRF_CONFIG"}, db.Key{Comp: []string{"vrf_global"}})
	if _, ok := entry.Field["mgmtVrfEnabled"]; ok {
		nonDefaultVrfIntfs["eth0"] = "mgmt"
	} else {
		nonDefaultVrfIntfs["eth0"] = ""
	}

	return nonDefaultVrfIntfs
}

func isValidVrf(configDb *db.DB, vrfName string) bool {

	status := false
	if vrfName == "mgmt" { /*check for mgmt vrf first*/
		entry, _ := configDb.GetEntry(&db.TableSpec{Name: "MGMT_VRF_CONFIG"}, db.Key{Comp: []string{"vrf_global"}})
		if _, ok := entry.Field["mgmtVrfEnabled"]; ok {
			status = true
		}
	} else {
		entry, err := configDb.GetEntry(&db.TableSpec{Name: "VRF"}, db.Key{Comp: []string{vrfName}})
		if err == nil && len(entry.Field) > 0 {
			log.Info("VRF found: ", vrfName)
			status = true
		}
	}
	return status
}

func status(msg string, err error) string {
	if err != nil {
		log.Error(msg, ": ", err)
		return "% Error: Internal error"
	} else {
		return "Success"
	}
}

func clear_default_vrf(fam_switch string, d *db.DB) string {
	var err error
	log.Info("In clear_default_vrf()")
	intfVrfMap := getIntfVrfMapping(d)
	for intfName, vrfName := range intfVrfMap {
		if len(vrfName) > 0 {
			continue
		}
		log.Info("Executing: ip ", fam_switch, " neigh ", "flush ", "dev ", intfName)
		_, err = exec.Command("ip", fam_switch, "neigh", "flush", "dev", intfName).Output()
		if err != nil {
			log.Error("clear_default_vrf(): ", err)
			return "% Error: Internal error"
		}
	}
	return "Success"
}

func clear_vrf(fam_switch string, vrf string) string {
	var err error

	log.Info("In clear_vrf()")
	if len(vrf) <= 0 {
		log.Error("clear_vrf(): Missing VRF name, returning")
		return "% Error: Internal error"
	}

	if vrf == "all" {
		log.Info("Executing: ip ", fam_switch, " neigh", " flush", " all")
		_, err = exec.Command("ip", fam_switch, "neigh", "flush", "all").Output()
	} else {
		log.Info("Executing: ip ", fam_switch, " neigh ", "flush ", "all ", "vrf ", vrf)
		_, err = exec.Command("ip", fam_switch, "neigh", "flush", "all", "vrf", vrf).Output()
	}

	return status("clear_vrf()", err)
}

func clear_ip(ip string, fam_switch string, vrf string, d *db.DB) string {
	var err error
	log.Info("In clear_ip()")

	if vrf == "all" { /*flush ip from all VRFs*/
		log.Info("Executing: ip ", fam_switch, " neigh ", "flush ", ip)
		_, err = exec.Command("ip", fam_switch, "neigh", "flush", ip).Output()
		return status("clear_ip()", err)
	} else if len(vrf) > 0 { /*flush ip from the given VRF*/
		log.Info("Executing: ip ", fam_switch, " neigh ", "flush ", ip, " vrf ", vrf)
		_, err = exec.Command("ip", fam_switch, "neigh", "flush", ip, "vrf", vrf).Output()
		return status("clear_ip()", err)
	}

	/*Clear IP from default VRF*/
	intfVrfMap := getIntfVrfMapping(d)
	for intfName, vrfName := range intfVrfMap {
		if len(vrfName) > 0 {
			continue
		}
		log.Info("Executing: ip ", fam_switch, " neigh ", "flush ", "dev ", intfName, " ", ip)
		_, err = exec.Command("ip", fam_switch, "neigh", "flush", "dev", intfName, ip).Output()
		if err != nil {
			return status("clear_ip()", err)
		}
	}
	return "Success"
}

func clear_intf(intf string, fam_switch string) string {
	var err error
	log.Info("In clear_intf()")

	log.Info("ip ", fam_switch, " neigh ", "flush ", "dev ", intf)
	_, err = exec.Command("ip", fam_switch, "neigh", "flush", "dev", intf).Output()

	return status("clear_intf()", err)
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

	if len(vrf) > 0 && vrf != "all" {
		if !isValidVrf(dbs[db.ConfigDB], vrf) {
			result.Output.Status = "% Error: VRF " + vrf + " not found"
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
