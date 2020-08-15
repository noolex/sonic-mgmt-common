////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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
    "errors"
    "strings"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
)

func init () {
    XlateFuncBind("YangToDb_unnumbered_intf_xfmr", YangToDb_unnumbered_intf_xfmr)
    XlateFuncBind("DbToYang_unnumbered_intf_xfmr", DbToYang_unnumbered_intf_xfmr)
    XlateFuncBind("YangToDb_routed_vlan_unnumbered_intf_xfmr", YangToDb_routed_vlan_unnumbered_intf_xfmr)
    XlateFuncBind("DbToYang_routed_vlan_unnumbered_intf_xfmr", DbToYang_routed_vlan_unnumbered_intf_xfmr)
    XlateFuncBind("Subscribe_unnumbered_intf_xfmr", Subscribe_unnumbered_intf_xfmr)
}

var Subscribe_unnumbered_intf_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    keyName := pathInfo.Var("name")

    //Get correct interface table to be modified. Start
    intfType, _, ierr := getIntfTypeByName(keyName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("Subscribe_unnumbered_intf_xfmr: " + errStr)
        return result, errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, db.ConfigDB)
    log.Info("Subscribe_unnumbered_intf_xfmr: Table: ", tblName, " TargetURI: ", targetUriPath, " Key: ", keyName)

    if (keyName != "") {
        result.dbDataMap = RedisDbMap{db.ConfigDB:{tblName:{keyName:{}}}}
    } else {
        errStr := "Interface name not present in request"
        log.Info("Subscribe_unnumbered_intf_xfmr: " + errStr)
        return result, errors.New(errStr)
    }
    result.isVirtualTbl = false
    log.Info("Subscribe_unnumbered_intf_xfmr resultMap:", result.dbDataMap)
    return result, err
}

/* Validates whether Donor interface has multiple IPv4 Address configured on it */
func validateMultiIPForDonorIntf(d *db.DB, ifName *string) bool {

	tables := []string{"INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE"}
	donor_intf := false
	log.Info("validateMultiIPForDonorIntf : intfName", ifName)
	for _, table := range tables {
		intfTble, err := d.GetTable(&db.TableSpec{Name:table})
		if err != nil {
			continue
		}

		intfKeys, _ := intfTble.GetKeys()
		for _, intfName := range intfKeys {
			intfEntry, err := d.GetEntry(&db.TableSpec{Name: table}, intfName)
			if(err != nil) {
				continue
			}

			unnumbered, ok := intfEntry.Field["unnumbered"]
			if ok {
				if unnumbered == *ifName {
					donor_intf = true
					break
				}
			}
		}
	}

	if donor_intf {
		loIntfTble, err := d.GetTable(&db.TableSpec{Name:"LOOPBACK_INTERFACE"})
		if err != nil {
			log.Info("Table read error : return false")
			return false
		}

		loIntfKeys, _ := loIntfTble.GetKeys()
		for _, loIntfName := range loIntfKeys {
			if len(loIntfName.Comp) > 1 && strings.Contains(loIntfName.Comp[0], *ifName){
				if strings.Contains(loIntfName.Comp[1], ".") {
					log.Info("Multi IP exists")
					return true
				}
			}
		}
	}
	return false
}


func intf_unnumbered_del(tblName *string, inParams *XfmrParams, ifdb map[string]string, ifName *string) error  {
    var err error
	log.Info("DELETE Unnum Intf:=", *tblName, *ifName)

	entry, _ := inParams.d.GetEntry(&db.TableSpec{Name:*tblName}, db.Key{Comp: []string{*ifName}})
	if len(entry.Field) > 1 {
		ifdb[UNNUMBERED] = ""
	} else {
		intfIPKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:*tblName})
		if len(intfIPKeys) > 0 {
			for i := range intfIPKeys {
				if len(intfIPKeys[i].Comp) > 1 {
					ifdb[UNNUMBERED] = ""
					break;
				}
			}
		}
	}

    return err
}

func validateUnnumIntfExistsForDonorIntf(d *db.DB, donorIfName *string) bool {

	tables := []string{"INTERFACE", "PORTCHANNEL_INTERFACE", "VLAN_INTERFACE"}

	for _, table := range tables {
		intfTable, err := d.GetTable(&db.TableSpec{Name:table})
		if err != nil {
			continue
		}

		keys, _ := intfTable.GetKeys()
		for _, key := range keys {
			if len(key.Comp) > 2 {
				continue
			}

			intfEntry, _ := intfTable.GetEntry(key)
			if intfEntry.Get("unnumbered") == *donorIfName {
				return true
			}
		}
	}
	return false
}

func validateUnnumEntryExists(d *db.DB, tblName *string, ifName *string) bool {
    entry, err := d.GetEntry(&db.TableSpec{Name:*tblName}, db.Key{Comp: []string{*ifName}})
    if err != nil {
        return false
    }

    if entry.Get("unnumbered") != "" {
        return true
    } else {
        return false
    }
}

var YangToDb_unnumbered_intf_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    subIntfmap := make(map[string]map[string]db.Value)

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_unnumbered_intf_xfmr: IntfsObj/interface list is empty.")
        return subIntfmap, errors.New("IntfsObj/Interface is not specified")
    }

    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("YangToDb_unnumbered_intf_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_unnumbered_intf_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfsObj.Interface[uriIfName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_unnumbered_intf_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[uriIfName]
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_unnumbered_intf_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }
    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        // Delete is for Interface instance / sub-interfaces container level
        if inParams.oper == DELETE {
            return nil, nil
        } 
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_unnumbered_intf_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        log.Info("YangToDb_unnumbered_intf_xfmr : No Unnumbered IP interface handling required")
        return subIntfmap, err
    }
    subIntfObj := intfObj.Subinterfaces.Subinterface[0]

    ifdb := make(map[string]string)
    if _, ok := subIntfmap[tblName]; !ok {
        subIntfmap[tblName] = make(map[string]db.Value)
    }

    if subIntfObj.Ipv4 == nil || subIntfObj.Ipv4.Unnumbered == nil || subIntfObj.Ipv4.Unnumbered.InterfaceRef == nil {
        //Delete is for IPv4 container
        if inParams.oper == DELETE {
            if validateUnnumEntryExists(inParams.d, &tblName, &ifName) {
                err = intf_unnumbered_del(&tblName, &inParams, ifdb, &ifName)
                if err != nil {
                    return subIntfmap, err
                }
                value := db.Value{Field: ifdb}
                subIntfmap[tblName][ifName] = value
                log.Info("subIntfmap", subIntfmap)
                return subIntfmap, err
            } else {
                return nil, nil
            }
        }
        errStr := "IPv4 ygot structure missing"
        log.Info("YangToDb_unnumbered_intf_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    log.Info("subIntfObj:=", subIntfObj)
    if subIntfObj.Ipv4 != nil && subIntfObj.Ipv4.Unnumbered != nil && subIntfObj.Ipv4.Unnumbered.InterfaceRef != nil {
        if inParams.oper == DELETE {
            err = intf_unnumbered_del(&tblName, &inParams, ifdb, &ifName)
            if err != nil {
                return subIntfmap, err
            }
            value := db.Value{Field: ifdb}
            subIntfmap[tblName][ifName] = value
            return subIntfmap, err
        }
        unnumberedObj := subIntfObj.Ipv4.Unnumbered.InterfaceRef
        if unnumberedObj.Config != nil {
            log.Info("Unnum Intf:=", *unnumberedObj.Config.Interface)
            ifdb[UNNUMBERED] = *unnumberedObj.Config.Interface
        }
        value := db.Value{Field: ifdb}

		if inParams.oper == REPLACE || inParams.oper == CREATE {
			subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
			resMap := make(map[string]map[string]db.Value)
			resMap[tblName] = make(map[string]db.Value)
			resMap[tblName][ifName] = value
			subOpMap[db.ConfigDB] = resMap
			log.Info("subOpMap: ", subOpMap)
			inParams.subOpDataMap[UPDATE] = &subOpMap
		} else {
        	subIntfmap[tblName][ifName] = value
		}
    }

    log.Info("YangToDb_unnumbered_intf_xfmr : subIntfmap : ", subIntfmap)
    return subIntfmap, err
}

var DbToYang_unnumbered_intf_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    log.Info("db to yang - unnumbered sub tree and ifname: ", ifName)
    sonicIfName := utils.GetNativeNameFromUIName(&ifName)
    log.Infof("DbToYang_unnumbered_intf_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName
    targetUriPath, err := getYangPathFromUri(inParams.uri)

    log.Info("targetUriPath is ", targetUriPath)

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("DbToYang_unnumbered_intf_xfmr: " + errStr)
        return errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces") {
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
                intfObj, _ = intfsObj.NewInterface(uriIfName)
            }
            ygot.BuildEmptyTree(intfObj)
            if intfObj.Subinterfaces == nil {
                ygot.BuildEmptyTree(intfObj.Subinterfaces)
            }
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(uriIfName)
            ygot.BuildEmptyTree(intfObj)
        }

        var subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
        if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
            _, err = intfObj.Subinterfaces.NewSubinterface(0)
            if err != nil {
                log.Error("Creation of subinterface subtree failed!")
                return err
            }
        }

        subIntf = intfObj.Subinterfaces.Subinterface[0]
        ygot.BuildEmptyTree(subIntf)
        ygot.BuildEmptyTree(subIntf.Ipv4)
        ygot.BuildEmptyTree(subIntf.Ipv4.Unnumbered)
        ygot.BuildEmptyTree(subIntf.Ipv4.Unnumbered.InterfaceRef)

        if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/unnumbered/interface-ref/state") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/unnumbered/interface-ref/state") {
            entry, dbErr := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name:intTbl.appDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read app DB entry, " + intTbl.appDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                subIntf.Ipv4.Unnumbered.InterfaceRef.State.Interface = &value
                log.Info("State Unnum Intf : " + value)
            }
        } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/unnumbered/interface-ref/config") ||
                strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/unnumbered/interface-ref/config") {
            entry, dbErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read DB entry, " + intTbl.cfgDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                subIntf.Ipv4.Unnumbered.InterfaceRef.Config.Interface = &value
                log.Info("Config Unnum Intf: " + value)
            }
        } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/unnumbered/interface-ref") ||
                strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/openconfig-interfaces:unnumbered/interface-ref") {
            entry, dbErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read Config DB entry, " + intTbl.cfgDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                subIntf.Ipv4.Unnumbered.InterfaceRef.Config.Interface = &value
                log.Info("Config Unnum Intf: " + value)
            }

            entry, dbErr = inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name:intTbl.appDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read app DB entry, " + intTbl.appDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                subIntf.Ipv4.Unnumbered.InterfaceRef.State.Interface = &value
                log.Info("State Unnum Intf : " + value)
            }
        }
    }
    return err
}

var YangToDb_routed_vlan_unnumbered_intf_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_routed_vlan_unnumbered_intf_xfmr: IntfsObj/interface list is empty.")
        return resMap, errors.New("IntfsObj/Interface is not specified")
    }

    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("YangToDb_routed_vlan_unnumbered_intf_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_routed_vlan_unnumbered_intf_xfmr: " + errStr)
        return resMap, errors.New(errStr)
    }

    if _, ok := intfsObj.Interface[uriIfName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_routed_vlan_unnumbered_intf_xfmr : " + errStr)
        return resMap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[uriIfName]
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_routed_vlan_unnumbered_intf_xfmr : " + errStr)
        return resMap, errors.New(errStr)
    }
    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

    if intfObj.RoutedVlan == nil {
        // Delete is for Interface instance / routed-vlan container level
        if inParams.oper == DELETE {
            return nil, nil
        } 
        errStr := "Routed vlan node is not set"
        log.Info("YangToDb_routed_vlan_unnumbered_intf_xfmr : " + errStr)
        return resMap, errors.New(errStr)
    }

    ipv4Obj := intfObj.RoutedVlan.Ipv4

    ifdb := make(map[string]string)
    if _, ok := resMap[tblName]; !ok {
        resMap[tblName] = make(map[string]db.Value)
    }

    if ipv4Obj == nil || ipv4Obj.Unnumbered == nil || ipv4Obj.Unnumbered.InterfaceRef == nil {
        //Delete is for IPv4 container
        if inParams.oper == DELETE {
            if validateUnnumEntryExists(inParams.d, &tblName, &ifName) {
                err = intf_unnumbered_del(&tblName, &inParams, ifdb, &ifName)
                if err != nil {
                    return resMap, err
                }
                value := db.Value{Field: ifdb}
                resMap[tblName][ifName] = value
                log.Info("resMap: ", resMap)
                return resMap, err
            } else {
                return nil, nil
            }
        }
        errStr := "IPv4 ygot structure missing"
        log.Info("YangToDb_routed_vlan_unnumbered_intf_xfmr : " + errStr)
        return resMap, errors.New(errStr)
    }

    if ipv4Obj != nil && ipv4Obj.Unnumbered != nil && ipv4Obj.Unnumbered.InterfaceRef != nil {
        if inParams.oper == DELETE {
            err = intf_unnumbered_del(&tblName, &inParams, ifdb, &ifName)
            if err != nil {
                return resMap, err
            }
            value := db.Value{Field: ifdb}
            resMap[tblName][ifName] = value
            return resMap, err
        }
        unnumberedObj := ipv4Obj.Unnumbered.InterfaceRef
        if unnumberedObj.Config != nil {
            log.Info("Unnum Intf:=", *unnumberedObj.Config.Interface)
            ifdb[UNNUMBERED] = *unnumberedObj.Config.Interface
        }
        value := db.Value{Field: ifdb}

		if inParams.oper == REPLACE || inParams.oper == CREATE {
			subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
			subResMap := make(map[string]map[string]db.Value)
			subResMap[tblName] = make(map[string]db.Value)
			subResMap[tblName][ifName] = value
			subOpMap[db.ConfigDB] = subResMap
			log.Info("subOpMap: ", subOpMap)
			inParams.subOpDataMap[UPDATE] = &subOpMap
		} else {
        	resMap[tblName][ifName] = value
		}
    }

    log.Info("YangToDb_routed_vlan_unnumbered_intf_xfmr : resMap : ", resMap)
    return resMap, err
}

var DbToYang_routed_vlan_unnumbered_intf_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    log.Info("db to yang - unnumbered sub tree and ifname: ", ifName)
    sonicIfName := utils.GetNativeNameFromUIName(&ifName)
    log.Infof("DbToYang_routed_vlan_unnumbered_intf_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName
    targetUriPath, err := getYangPathFromUri(inParams.uri)

    log.Info("targetUriPath is ", targetUriPath)

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("DbToYang_routed_vlan_unnumbered_intf_xfmr: " + errStr)
        return errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan") {
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
                intfObj, _ = intfsObj.NewInterface(uriIfName)
            }
            ygot.BuildEmptyTree(intfObj)
            if intfObj.RoutedVlan == nil {
                ygot.BuildEmptyTree(intfObj.RoutedVlan)
            }
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(uriIfName)
            ygot.BuildEmptyTree(intfObj)
        }

        routedVlanObj := intfObj.RoutedVlan
        ygot.BuildEmptyTree(routedVlanObj)
        ygot.BuildEmptyTree(routedVlanObj.Ipv4)
        ygot.BuildEmptyTree(routedVlanObj.Ipv4.Unnumbered)
        ygot.BuildEmptyTree(routedVlanObj.Ipv4.Unnumbered.InterfaceRef)

        if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/unnumbered/interface-ref/state") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/ipv4/unnumbered/interface-ref/state") {
            entry, dbErr := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name:intTbl.appDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read app DB entry, " + intTbl.appDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                routedVlanObj.Ipv4.Unnumbered.InterfaceRef.State.Interface = &value
                log.Info("State Unnum Intf : " + value)
            }
        } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/unnumbered/interface-ref/config") ||
                strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/ipv4/unnumbered/interface-ref/config") {
            entry, dbErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read DB entry, " + intTbl.cfgDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                routedVlanObj.Ipv4.Unnumbered.InterfaceRef.Config.Interface = &value
                log.Info("Config Unnum Intf: " + value)
            }
        } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/unnumbered/interface-ref") ||
                strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/openconfig-interfaces:unnumbered/interface-ref") {
            entry, dbErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read Config DB entry, " + intTbl.cfgDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                routedVlanObj.Ipv4.Unnumbered.InterfaceRef.Config.Interface = &value
                log.Info("Config Unnum Intf: " + value)
            }

            entry, dbErr = inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name:intTbl.appDb.intfTN}, db.Key{Comp: []string{ifName}})

            if dbErr != nil {
                log.Info("Failed to read app DB entry, " + intTbl.appDb.intfTN + " " + ifName)
                return nil
            }

            if entry.Has(UNNUMBERED) {
                value := entry.Get(UNNUMBERED)
                routedVlanObj.Ipv4.Unnumbered.InterfaceRef.State.Interface = &value
                log.Info("State Unnum Intf : " + value)
            }
        }
    }
    return err
}
