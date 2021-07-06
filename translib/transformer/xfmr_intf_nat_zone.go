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
	"errors"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("YangToDb_intf_nat_zone_xfmr", YangToDb_intf_nat_zone_xfmr)
	XlateFuncBind("DbToYang_intf_nat_zone_xfmr", DbToYang_intf_nat_zone_xfmr)
	XlateFuncBind("Subscribe_intf_nat_zone_xfmr", Subscribe_intf_nat_zone_xfmr)
}

var YangToDb_intf_nat_zone_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	natZoneMap := make(map[string]map[string]db.Value)

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		log.Info("YangToDb_intf_nat_zone_xfmr: IntfsObj/interface list is empty.")
		return natZoneMap, errors.New("IntfsObj/Interface is not specified")
	}
	pathInfo := NewPathInfo(inParams.uri)
	ifUIName := pathInfo.Var("name")

	if ifUIName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_intf_nat_zone_xfmr : " + errStr)
		return natZoneMap, errors.New(errStr)
	}

	if _, ok := intfsObj.Interface[ifUIName]; !ok {
		errStr := "Interface entry not found in Ygot tree, ifname: " + ifUIName
		log.Info("YangToDb_intf_nat_zone_xfmr : " + errStr)
		return natZoneMap, errors.New(errStr)
	}

	intfObj := intfsObj.Interface[ifUIName]

	if intfObj.NatZone == nil || intfObj.NatZone.Config == nil || intfObj.NatZone.Config.NatZone == nil {
		if inParams.oper != DELETE {
			log.Info("YangToDb Interface nat zone config is not valid - ", ifUIName)
			return natZoneMap, errors.New("YangToDb Interface nat zone config is not valid - " + ifUIName)
		}
	}

	ifName := utils.GetNativeNameFromUIName(&ifUIName)

	intfType, _, ierr := getIntfTypeByName(*ifName)
	if intfType == IntfTypeUnset || ierr != nil {
		errStr := "Invalid interface type IntfTypeUnset"
		log.Info("YangToDb_intf_nat_zone_xfmr : " + errStr)
		return natZoneMap, errors.New(errStr)
	}
	intTbl := IntfTypeTblMap[intfType]
	tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

	if inParams.oper == DELETE {
		entry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name: tblName}, db.Key{Comp: []string{*ifName}})
		if dbErr != nil {
			log.Info("Failed to read DB entry, " + tblName + " " + *ifName)
			return natZoneMap, nil
		}
		if !entry.Has("nat_zone") {
			log.Info("NAT zone config not present, " + tblName + " " + *ifName)
			return natZoneMap, nil
		}
		if _, ok := natZoneMap[tblName]; !ok {
			natZoneMap[tblName] = make(map[string]db.Value)
		}
		// Handling the scenario for top level Interface instance delete
		if intfObj.NatZone == nil {
			//Return map with key
			natZoneMap[tblName][*ifName] = db.Value{Field: make(map[string]string)}
			return natZoneMap, err
		}
		m := make(map[string]string)
		data := db.Value{Field: m}

		// If NAT Zone is the last L3 config, then remove the INTERFACE table (INTERFACE/VLAN_INTERFACE/PORTCHANNEL_INTERFACE/LOOPBACK_INTERFACE)
		// Else remove only the nat_zone attribute
		intfKey, _ := inParams.d.GetKeysByPattern(&db.TableSpec{Name: tblName}, *ifName+"|*")

		if log.V(5) {
			log.Infof("Table Name : %v, Intf Name : %v", tblName, *ifName)
			log.Infof("INTERFACE Table Keys: %v, Length : %v", intfKey, len(intfKey))
		}

		sagTblKey, _ := inParams.d.GetKeysByPattern(&db.TableSpec{Name: "SAG"}, *ifName+"|*")
		if log.V(5) {
			log.Infof("SAG Table Keys: %v, Length : %v", sagTblKey, len(sagTblKey))
		}

		if len(intfKey) != 1 { // Indicates other L3 configurations using INTERFACE table (like IP address config)
			data.Set("nat_zone", "")
		} else if len(sagTblKey) != 0 { // Indicates IP anycast address configuration
			data.Set("nat_zone", "")
		} else if len(entry.Field) == 2 { // Indicates other L3 configurations inside INTERFACE table (like IPv6 enable)
			if !entry.Has("NULL") {
				data.Set("nat_zone", "")
			}
		} else if len(entry.Field) != 1 { // Indicates other L3 configurations inside INTERFACE table
			data.Set("nat_zone", "")
		}

		natZoneMap[tblName][*ifName] = data
	} else {
		m := make(map[string]string)
		data := db.Value{Field: m}
		data.Set("nat_zone", strconv.Itoa(int(*intfObj.NatZone.Config.NatZone)))
		if _, ok := natZoneMap[tblName]; !ok {
			natZoneMap[tblName] = make(map[string]db.Value)
		}
		natZoneMap[tblName][*ifName] = data
	}
	log.Info("NAT Zone map :", natZoneMap)
	return natZoneMap, err
}

var Subscribe_intf_nat_zone_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	if log.V(3) {
		log.Info("Entering Subscribe_intf_nat_zone_xfmr")
	}
	var err error
	var result XfmrSubscOutParams

	pathInfo := NewPathInfo(inParams.uri)
	origTargetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	if inParams.subscProc == TRANSLATE_SUBSCRIBE {
		// to handle the TRANSLATE_SUBSCRIBE

		if origTargetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone" {
			result.isVirtualTbl = true
			log.Info("Subscribe_intf_ip_addr_xfmr:- uri:%v, subscProc:%v result.isVirtualTbl: ", inParams.uri, inParams.subscProc, result.isVirtualTbl)
			return result, err
		}

		natConfigPath := "/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone/config"
		natStatePath := "/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone/state"

		result.onChange = OnchangeEnable
		result.nOpts = &notificationOpts{}
		result.nOpts.pType = OnChange
		result.isVirtualTbl = false

		uriIfName := pathInfo.Var("name")
		tableName := ""
		ifKey := ""

		if uriIfName == "" || uriIfName == "*" {
			ifKey = "*"
		} else {
			sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
			ifKey = *sonicIfName
		}

		if ifKey != "*" {
			intfType, _, _ := getIntfTypeByName(ifKey)
			intTbl := IntfTypeTblMap[intfType]
			if origTargetUriPath == natStatePath {
				tableName = intTbl.appDb.intfTN
			} else {
				tableName = intTbl.cfgDb.intfTN
			}
		}

		log.Infof("Subscribe_intf_nat_zone_xfmr: URI:%v ifKey:%v, tbl:[%v]", inParams.uri, ifKey, tableName)

		if origTargetUriPath == natConfigPath {
			if tableName != "" {
				result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB: {tableName: {ifKey: {"nat_zone": "nat-zone"}}}}
			} else {
				result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB: {"INTERFACE": {ifKey: {"nat_zone": "nat-zone"}},
					"VLAN_INTERFACE":        {ifKey: {"nat_zone": "nat-zone"}},
					"LOOPBACK_INTERFACE":    {ifKey: {"nat_zone": "nat-zone"}},
					"PORTCHANNEL_INTERFACE": {ifKey: {"nat_zone": "nat-zone"}}}}
			}
		} else if origTargetUriPath == natStatePath {
			if tableName != "" {
				result.dbDataMap = RedisDbSubscribeMap{db.ApplDB: {tableName: {ifKey: {"nat_zone": "nat-zone"}}}}
			} else {
				result.dbDataMap = RedisDbSubscribeMap{db.ApplDB: {"INTF_TABLE": {ifKey: {"nat_zone": "nat-zone"}}}}
			}
		}

		log.Info("Subscribe_intf_nat_zone_xfmr:- result dbDataMap: ", result.dbDataMap)
		log.Info("Subscribe_intf_nat_zone_xfmr:- result secDbDataMap: ", result.secDbDataMap)

		return result, err
	}

	result.isVirtualTbl = true
	log.Info("Subscribe_intf_ip_addr_xfmr:- uri:%v, subscProc:%v result.isVirtualTbl: ", inParams.uri, inParams.subscProc, result.isVirtualTbl)

	return result, err
}

var DbToYang_intf_nat_zone_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	intfsObj := getIntfsRoot(inParams.ygRoot)
	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("name")
	targetUriPath, err := getYangPathFromUri(inParams.uri)
	log.Info("targetUriPath is ", targetUriPath)
	var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface

	intfType, _, ierr := getIntfTypeByName(ifName)
	if intfType == IntfTypeUnset || ierr != nil {
		errStr := "Invalid interface type IntfTypeUnset"
		log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
		return errors.New(errStr)
	}
	intTbl := IntfTypeTblMap[intfType]

	config, state := false, false

	if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone/config") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/nat-zone/config") {
		config = true
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone/state") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/nat-zone/state") {
		state = true
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/nat-zone") {
		config = true
		state = true
	} else {
		return errors.New("DbToYang_intf_nat_zone_xfmr : Invalid URI, " + inParams.uri)
	}

	ifUIName := utils.GetUINameFromNativeName(&ifName)
	if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
		var ok bool = false
		if intfObj, ok = intfsObj.Interface[*ifUIName]; !ok {
			intfObj, _ = intfsObj.NewInterface(*ifUIName)
		}
	} else {
		ygot.BuildEmptyTree(intfsObj)
		intfObj, _ = intfsObj.NewInterface(*ifUIName)
	}
	ygot.BuildEmptyTree(intfObj)
	ygot.BuildEmptyTree(intfObj.NatZone)
	if config {
		ygot.BuildEmptyTree(intfObj.NatZone.Config)
		entry, dbErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name: intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})
		if dbErr != nil {
			log.Info("Failed to read DB entry, " + intTbl.cfgDb.intfTN + " " + ifName)
			return nil
		}
		if entry.Has("nat_zone") {
			var natZone uint8
			value, _ := strconv.Atoi(entry.Get("nat_zone"))
			natZone = uint8(value)
			intfObj.NatZone.Config.NatZone = &natZone
		} else {
			intfObj.NatZone.Config.NatZone = nil
		}
	}
	if state {
		ygot.BuildEmptyTree(intfObj.NatZone.State)
		entry, dbErr := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name: intTbl.appDb.intfTN}, db.Key{Comp: []string{ifName}})
		if dbErr != nil {
			log.Info("Failed to read DB entry, " + intTbl.appDb.intfTN + " " + ifName)
			return nil
		}
		if entry.Has("nat_zone") {
			var natZone uint8
			value, _ := strconv.Atoi(entry.Get("nat_zone"))
			natZone = uint8(value)
			intfObj.NatZone.State.NatZone = &natZone
		} else {
			intfObj.NatZone.State.NatZone = nil
		}
	}

	return err
}
