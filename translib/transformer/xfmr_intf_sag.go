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
	XlateFuncBind("YangToDb_intf_sag_ip_xfmr", YangToDb_intf_sag_ip_xfmr)
	XlateFuncBind("DbToYang_intf_sag_ip_xfmr", DbToYang_intf_sag_ip_xfmr)
	XlateFuncBind("YangToDb_intf_sag_subif_ip_xfmr", YangToDb_intf_sag_subif_ip_xfmr)
	XlateFuncBind("DbToYang_intf_sag_subif_ip_xfmr", DbToYang_intf_sag_subif_ip_xfmr)
}

var YangToDb_intf_sag_ip_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	subIntfmap := make(map[string]map[string]db.Value)
	var last_sag4 bool = false
	var last_sag6 bool = false

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		log.Info("YangToDb_intf_sag_ip_xfmr: IntfsObj/interface list is empty.")
		return subIntfmap, errors.New("IntfsObj/Interface is not specified")
	}

	pathInfo := NewPathInfo(inParams.uri)
	uriIfName := pathInfo.Var("name")
	ifName := uriIfName

	sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
	log.Infof("YangToDb_intf_sag_ip_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
	ifName = *sonicIfName

	log.Info("YangToDb_intf_sag_ip_xfmr Ifname: " + ifName)
	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_intf_sag_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	if _, ok := intfsObj.Interface[uriIfName]; !ok {
		errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
		log.Info("YangToDb_intf_sag_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	intfObj := intfsObj.Interface[uriIfName]

	if intfObj.RoutedVlan == nil {
		if inParams.oper == DELETE {
			log.Info("Top level Interface instance delete for SAG: ", ifName)
			//return intf_sag_ip_del(inParams, ifName)
			return nil, nil
		}
		errStr := "RoutedVlan node is not set"
		log.Info("YangToDb_intf_sag_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	intfType, _, ierr := getIntfTypeByName(ifName)
	if intfType == IntfTypeUnset || ierr != nil {
		errStr := "Invalid interface type IntfTypeUnset"
		log.Info("YangToDb_intf_sag_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	intTbl := IntfTypeTblMap[intfType]
	tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

	subIntfObj := intfObj.RoutedVlan

	var gwIPListStr string
	sagIPMap := make(map[string]db.Value)
	vlanIntfMap := make(map[string]db.Value)
	vlanIntfMap[ifName] = db.Value{Field: make(map[string]string)}
	vlanEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})

	if subIntfObj.Ipv4 != nil && subIntfObj.Ipv4.SagIpv4 != nil {
		sagIpv4Obj := subIntfObj.Ipv4.SagIpv4

		if sagIpv4Obj.Config != nil {
			log.Info("SAG IP:=", sagIpv4Obj.Config.StaticAnycastGateway)

			var templen uint8
			tempIP := strings.Split(sagIpv4Obj.Config.StaticAnycastGateway[0], "/")

			if !validIPv4(tempIP[0]) {
				errStr := "Invalid IPv4 Gateway address " + sagIpv4Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			tlen, _ := strconv.Atoi(tempIP[1])
			templen = uint8(tlen)
			err = validateIpPrefixForIntfType(IntfTypeVlan, &tempIP[0], &templen, true)
			if err != nil || templen == 0 {
				errStr := "Invalid IPv4 Gateway length " + sagIpv4Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			if inParams.oper != DELETE {
				_, oerr := validateIpOverlap(inParams.d, ifName, sagIpv4Obj.Config.StaticAnycastGateway[0], "VLAN_INTERFACE", false)

				if oerr != nil {
					log.Error(oerr)
					return nil, tlerr.InvalidArgsError{Format: oerr.Error()}
				}

			}

			sagIPv4Key := ifName + "|IPv4"

			sagIPv4Entry, _ := inParams.d.GetEntry(&db.TableSpec{Name: "SAG"}, db.Key{Comp: []string{sagIPv4Key}})

			if inParams.oper == DELETE {
				gwIPListStr = sagIpv4Obj.Config.StaticAnycastGateway[0]
				if sagIPv4Entry.IsPopulated() {
					if strings.Count(sagIPv4Entry.Field["gwip@"], ",") == 0 {

						if gwIPListStr != sagIPv4Entry.Field["gwip@"] {
							errStr := "IP anycast does not exist on the interface " + sagIpv4Obj.Config.StaticAnycastGateway[0]
							err = tlerr.InvalidArgsError{Format: errStr}
							return subIntfmap, err
						}

						if len(vlanEntry.Field) == 1 {
							if _, ok := vlanEntry.Field["NULL"]; ok {
								subIntfmap[tblName] = vlanIntfMap
							}
						}

						last_sag4 = true
						subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
						subIntfmap_del := make(map[string]map[string]db.Value)
						subIntfmap_del["SAG"] = make(map[string]db.Value)
						subIntfmap_del["SAG"][sagIPv4Key] = db.Value{}
						subOpMap[db.ConfigDB] = subIntfmap_del
						inParams.subOpDataMap[DELETE] = &subOpMap

					}
				}
			} else {
				if !vlanEntry.IsPopulated() {
					vlanIntfMap[ifName].Field["NULL"] = "NULL"
					subIntfmap[tblName] = vlanIntfMap
				}

				if sagIPv4Entry.IsPopulated() {
					gwIPListStr = sagIPv4Entry.Field["gwip@"]
					gwIPListStr = gwIPListStr + "," + sagIpv4Obj.Config.StaticAnycastGateway[0]
				} else {
					gwIPListStr = sagIpv4Obj.Config.StaticAnycastGateway[0]
				}
			}

			if !last_sag4 {
				sagIPMap[sagIPv4Key] = db.Value{Field: make(map[string]string)}
				sagIPMap[sagIPv4Key].Field["gwip@"] = gwIPListStr

				subIntfmap["SAG"] = sagIPMap
			}
		}
	}

	if subIntfObj.Ipv6 != nil && subIntfObj.Ipv6.SagIpv6 != nil {
		sagIpv6Obj := subIntfObj.Ipv6.SagIpv6

		if sagIpv6Obj.Config != nil {
			log.Info("SAG IP:=", sagIpv6Obj.Config.StaticAnycastGateway)

			var templen uint8
			tempIP := strings.Split(sagIpv6Obj.Config.StaticAnycastGateway[0], "/")

			if !validIPv6(tempIP[0]) {
				errStr := "Invalid IPv6 Gateway address " + sagIpv6Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			tlen, _ := strconv.Atoi(tempIP[1])
			templen = uint8(tlen)
			err = validateIpPrefixForIntfType(IntfTypeVlan, &tempIP[0], &templen, false)
			if err != nil || templen == 0 {
				errStr := "Invalid IPv6 Gateway length " + sagIpv6Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			if inParams.oper != DELETE {
				_, oerr := validateIpOverlap(inParams.d, ifName, sagIpv6Obj.Config.StaticAnycastGateway[0], "VLAN_INTERFACE", false)

				if oerr != nil {
					log.Error(oerr)
					return nil, tlerr.InvalidArgsError{Format: oerr.Error()}
				}
			}

			sagIPv6Key := ifName + "|IPv6"

			sagIPv6Entry, _ := inParams.d.GetEntry(&db.TableSpec{Name: "SAG"}, db.Key{Comp: []string{sagIPv6Key}})

			if inParams.oper == DELETE {
				gwIPListStr = sagIpv6Obj.Config.StaticAnycastGateway[0]
				if sagIPv6Entry.IsPopulated() {
					if strings.Count(sagIPv6Entry.Field["gwip@"], ",") == 0 {

						if gwIPListStr != sagIPv6Entry.Field["gwip@"] {
							errStr := "IP anycast does not exist on the interface " + sagIpv6Obj.Config.StaticAnycastGateway[0]
							err = tlerr.InvalidArgsError{Format: errStr}
							return subIntfmap, err
						}

						if len(vlanEntry.Field) == 1 {
							if _, ok := vlanEntry.Field["NULL"]; ok {
								subIntfmap[tblName] = vlanIntfMap
							}
						}

						last_sag6 = true
						subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
						subIntfmap_del := make(map[string]map[string]db.Value)
						subIntfmap_del["SAG"] = make(map[string]db.Value)
						subIntfmap_del["SAG"][sagIPv6Key] = db.Value{}
						subOpMap[db.ConfigDB] = subIntfmap_del
						inParams.subOpDataMap[DELETE] = &subOpMap
					}
				}
			} else {
				if !vlanEntry.IsPopulated() {
					vlanIntfMap[ifName].Field["NULL"] = "NULL"
					subIntfmap[tblName] = vlanIntfMap
				}

				if sagIPv6Entry.IsPopulated() {
					gwIPListStr = sagIPv6Entry.Field["gwip@"]
					gwIPListStr = gwIPListStr + "," + sagIpv6Obj.Config.StaticAnycastGateway[0]
				} else {
					gwIPListStr = sagIpv6Obj.Config.StaticAnycastGateway[0]
				}
			}

			if !last_sag6 {
				sagIPMap[sagIPv6Key] = db.Value{Field: make(map[string]string)}
				sagIPMap[sagIPv6Key].Field["gwip@"] = gwIPListStr

				subIntfmap["SAG"] = sagIPMap
			}
		}
	}

	log.Info("YangToDb_intf_sag_ip_vlan : subIntfmap : ", subIntfmap)

	return subIntfmap, err
}

var YangToDb_intf_sag_subif_ip_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	subIntfmap := make(map[string]map[string]db.Value)
	var last_sag4 bool = false
	var last_sag6 bool = false

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		log.Info("YangToDb_intf_sag_subif_ip_xfmr: IntfsObj/interface list is empty.")
		return subIntfmap, errors.New("IntfsObj/Interface is not specified")
	}

	pathInfo := NewPathInfo(inParams.uri)
	uriIfName := pathInfo.Var("name")
	ifName := uriIfName

	index := pathInfo.Var("index")
	var i32 uint32
	i32 = 0
	if index != "" {
		i64, _ := strconv.ParseUint(index, 10, 32)
		i32 = uint32(i64)
	}

	sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
	log.Infof("YangToDb_intf_sag_subif_ip_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
	ifName = *sonicIfName

	log.Info("YangToDb_intf_sag_subif_ip_xfmr Ifname: " + ifName)
	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_intf_sag_subif_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	if _, ok := intfsObj.Interface[uriIfName]; !ok {
		errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
		log.Info("YangToDb_intf_sag_subif_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	intfObj := intfsObj.Interface[uriIfName]

	if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
		if inParams.oper == DELETE {
			return nil, nil
		}
		errStr := "SubInterface node is not set"
		log.Info("YangToDb_intf_sag_subif_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	if _, ok := intfObj.Subinterfaces.Subinterface[i32]; !ok {
		log.Info("YangToDb_intf_sag_subif_ip_xfmr : Not required for sub intf")
		return subIntfmap, err
	}

	intfType, _, ierr := getIntfTypeByName(ifName)
	if intfType == IntfTypeUnset || ierr != nil {
		errStr := "Invalid interface type IntfTypeUnset"
		log.Info("YangToDb_intf_sag_ip_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	intTbl := IntfTypeTblMap[intfType]
	tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

	if i32 > 0 {
		tblName = "VLAN_SUB_INTERFACE"
		if strings.HasPrefix(ifName, "Ethernet") {
			ifName = strings.Replace(ifName, "Ethernet", "Eth", -1) + "." + index
		} else if strings.HasPrefix(ifName, "PortChannel") {
			ifName = strings.Replace(ifName, "PortChannel", "Po", -1) + "." + index
		}
	}

	subIntfObj := intfObj.Subinterfaces.Subinterface[i32]

	var gwIPListStr string
	sagIPMap := make(map[string]db.Value)
	vlanIntfMap := make(map[string]db.Value)
	vlanIntfMap[ifName] = db.Value{Field: make(map[string]string)}
	vlanEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})

	if subIntfObj.Ipv4 != nil && subIntfObj.Ipv4.SagIpv4 != nil {
		sagIpv4Obj := subIntfObj.Ipv4.SagIpv4

		if sagIpv4Obj.Config != nil {
			log.Info("SAG IP:=", sagIpv4Obj.Config.StaticAnycastGateway)

			var templen uint8
			tempIP := strings.Split(sagIpv4Obj.Config.StaticAnycastGateway[0], "/")

			if !validIPv4(tempIP[0]) {
				errStr := "Invalid IPv4 Gateway address " + sagIpv4Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			tlen, _ := strconv.Atoi(tempIP[1])
			templen = uint8(tlen)
			err = validateIpPrefixForIntfType(IntfTypeVlan, &tempIP[0], &templen, true)
			if err != nil || templen == 0 {
				errStr := "Invalid IPv4 Gateway length " + sagIpv4Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			if inParams.oper != DELETE {
				_, oerr := validateIpOverlap(inParams.d, ifName, sagIpv4Obj.Config.StaticAnycastGateway[0], "VLAN_SUB_INTERFACE", false)

				if oerr != nil {
					log.Error(oerr)
					return nil, tlerr.InvalidArgsError{Format: oerr.Error()}
				}

			}

			sagIPv4Key := ifName + "|IPv4"

			sagIPv4Entry, _ := inParams.d.GetEntry(&db.TableSpec{Name: "SAG"}, db.Key{Comp: []string{sagIPv4Key}})

			if inParams.oper == DELETE {
				gwIPListStr = sagIpv4Obj.Config.StaticAnycastGateway[0]
				if sagIPv4Entry.IsPopulated() {
					if strings.Count(sagIPv4Entry.Field["gwip@"], ",") == 0 {

						if gwIPListStr != sagIPv4Entry.Field["gwip@"] {
							errStr := "IP anycast does not exist on the interface " + sagIpv4Obj.Config.StaticAnycastGateway[0]
							err = tlerr.InvalidArgsError{Format: errStr}
							return subIntfmap, err
						}

						if len(vlanEntry.Field) == 1 {
							if _, ok := vlanEntry.Field["NULL"]; ok {
								subIntfmap[tblName] = vlanIntfMap
							}
						}

						last_sag4 = true
						subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
						subIntfmap_del := make(map[string]map[string]db.Value)
						subIntfmap_del["SAG"] = make(map[string]db.Value)
						subIntfmap_del["SAG"][sagIPv4Key] = db.Value{}
						subOpMap[db.ConfigDB] = subIntfmap_del
						inParams.subOpDataMap[DELETE] = &subOpMap

					}
				}
			} else {
				if !vlanEntry.IsPopulated() {
					vlanIntfMap[ifName].Field["NULL"] = "NULL"
					subIntfmap[tblName] = vlanIntfMap
				}

				if sagIPv4Entry.IsPopulated() {
					gwIPListStr = sagIPv4Entry.Field["gwip@"]
					gwIPListStr = gwIPListStr + "," + sagIpv4Obj.Config.StaticAnycastGateway[0]
				} else {
					gwIPListStr = sagIpv4Obj.Config.StaticAnycastGateway[0]
				}
			}

			if !last_sag4 {
				sagIPMap[sagIPv4Key] = db.Value{Field: make(map[string]string)}
				sagIPMap[sagIPv4Key].Field["gwip@"] = gwIPListStr

				subIntfmap["SAG"] = sagIPMap
			}
		}
	}

	if subIntfObj.Ipv6 != nil && subIntfObj.Ipv6.SagIpv6 != nil {
		sagIpv6Obj := subIntfObj.Ipv6.SagIpv6

		if sagIpv6Obj.Config != nil {
			log.Info("SAG IP:=", sagIpv6Obj.Config.StaticAnycastGateway)

			var templen uint8
			tempIP := strings.Split(sagIpv6Obj.Config.StaticAnycastGateway[0], "/")

			if !validIPv6(tempIP[0]) {
				errStr := "Invalid IPv6 Gateway address " + sagIpv6Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			tlen, _ := strconv.Atoi(tempIP[1])
			templen = uint8(tlen)
			err = validateIpPrefixForIntfType(IntfTypeVlan, &tempIP[0], &templen, false)
			if err != nil || templen == 0 {
				errStr := "Invalid IPv6 Gateway length " + sagIpv6Obj.Config.StaticAnycastGateway[0]
				err = tlerr.InvalidArgsError{Format: errStr}
				return subIntfmap, err
			}

			if inParams.oper != DELETE {
				_, oerr := validateIpOverlap(inParams.d, ifName, sagIpv6Obj.Config.StaticAnycastGateway[0], "VLAN_SUB_INTERFACE", false)

				if oerr != nil {
					log.Error(oerr)
					return nil, tlerr.InvalidArgsError{Format: oerr.Error()}
				}
			}

			sagIPv6Key := ifName + "|IPv6"

			sagIPv6Entry, _ := inParams.d.GetEntry(&db.TableSpec{Name: "SAG"}, db.Key{Comp: []string{sagIPv6Key}})

			if inParams.oper == DELETE {
				gwIPListStr = sagIpv6Obj.Config.StaticAnycastGateway[0]
				if sagIPv6Entry.IsPopulated() {
					if strings.Count(sagIPv6Entry.Field["gwip@"], ",") == 0 {

						if gwIPListStr != sagIPv6Entry.Field["gwip@"] {
							errStr := "IP anycast does not exist on the interface " + sagIpv6Obj.Config.StaticAnycastGateway[0]
							err = tlerr.InvalidArgsError{Format: errStr}
							return subIntfmap, err
						}

						if len(vlanEntry.Field) == 1 {
							if _, ok := vlanEntry.Field["NULL"]; ok {
								subIntfmap[tblName] = vlanIntfMap
							}
						}

						last_sag6 = true
						subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
						subIntfmap_del := make(map[string]map[string]db.Value)
						subIntfmap_del["SAG"] = make(map[string]db.Value)
						subIntfmap_del["SAG"][sagIPv6Key] = db.Value{}
						subOpMap[db.ConfigDB] = subIntfmap_del
						inParams.subOpDataMap[DELETE] = &subOpMap
					}
				}
			} else {
				if !vlanEntry.IsPopulated() {
					vlanIntfMap[ifName].Field["NULL"] = "NULL"
					subIntfmap[tblName] = vlanIntfMap
				}

				if sagIPv6Entry.IsPopulated() {
					gwIPListStr = sagIPv6Entry.Field["gwip@"]
					gwIPListStr = gwIPListStr + "," + sagIpv6Obj.Config.StaticAnycastGateway[0]
				} else {
					gwIPListStr = sagIpv6Obj.Config.StaticAnycastGateway[0]
				}
			}

			if !last_sag6 {
				sagIPMap[sagIPv6Key] = db.Value{Field: make(map[string]string)}
				sagIPMap[sagIPv6Key].Field["gwip@"] = gwIPListStr

				subIntfmap["SAG"] = sagIPMap
			}
		}
	}

	log.Info("YangToDb_intf_sag_subif_ip_xfmr : subIntfmap : ", subIntfmap)

	return subIntfmap, err
}

/*
func intf_sag_ip_del(inParams XfmrParams , ifName string) (map[string]map[string]db.Value, error) {
    var err error
    vlanIntfmap := make(map[string]map[string]db.Value)

    sagIPv4Key := ifName + "|IPv4"
		sagIPv4Entry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"SAG"}, db.Key{Comp: []string{sagIPv4Key}})

    sagIPv6Key := ifName + "|IPv6"
		sagIPv6Entry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"SAG"}, db.Key{Comp: []string{sagIPv6Key}})

    if sagIPv4Entry.IsPopulated() || sagIPv6Entry.IsPopulated() {
        vlanIntfmap["SAG"] = make(map[string]db.Value)
        vlanIntfmap["VLAN_INTERFACE"] = make(map[string]db.Value)
        vlanIntfmap["VLAN_INTERFACE"][ifName] = db.Value{}
    }

    if sagIPv4Entry.IsPopulated() {
        vlanIntfmap["SAG"][sagIPv4Key] = db.Value{}
    }

    if sagIPv6Entry.IsPopulated() {
        vlanIntfmap["SAG"][sagIPv6Key] = db.Value{}
    }

    log.Info("intf_sag_ip_del: Delete SAG IP address list ", vlanIntfmap,  " ", err)
    return vlanIntfmap, err
}
*/

var DbToYang_intf_sag_ip_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
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
		log.Info("DbToYang_intf_sag_ip_xfmr : " + errStr)
		return errors.New(errStr)
	}

	ipv4_req := false
	ipv6_req := false
	var sagIPKey string

	if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/ipv4/sag-ipv4") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/sag-ipv4") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/openconfig-interfaces-ext:sag-ipv4") {
		ipv4_req = true
		sagIPKey = ifName + "|IPv4"
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/ipv6/sag-ipv6") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/sag-ipv6") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/openconfig-interfaces-ext:sag-ipv6") {
		ipv6_req = true
		sagIPKey = ifName + "|IPv6"
	}

	sagIPEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: "SAG"}, db.Key{Comp: []string{sagIPKey}})
	sagGwIPList := sagIPEntry.Get("gwip@")
	sagGwIPMap := strings.Split(sagGwIPList, ",")

	if sagGwIPMap[0] == "" {
		return err
	}

	if ipv4_req || ipv6_req {
		if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
			var ok bool = false
			if intfObj, ok = intfsObj.Interface[ifName]; !ok {
				intfObj, _ = intfsObj.NewInterface(ifName)
				ygot.BuildEmptyTree(intfObj)
			}
		} else {
			ygot.BuildEmptyTree(intfsObj)
			intfObj, _ = intfsObj.NewInterface(ifName)
			ygot.BuildEmptyTree(intfObj)
		}

		if intfObj.RoutedVlan == nil {
			var _routedvlan ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan
			intfObj.RoutedVlan = &_routedvlan
			ygot.BuildEmptyTree(intfObj.RoutedVlan)
		}

		routedvlan := intfObj.RoutedVlan

		if ipv4_req {
			ygot.BuildEmptyTree(routedvlan.Ipv4)
			ygot.BuildEmptyTree(routedvlan.Ipv4.SagIpv4)
			routedvlan.Ipv4.SagIpv4.Config.StaticAnycastGateway = sagGwIPMap
			routedvlan.Ipv4.SagIpv4.State.StaticAnycastGateway = sagGwIPMap
		} else if ipv6_req {
			ygot.BuildEmptyTree(routedvlan.Ipv6)
			ygot.BuildEmptyTree(routedvlan.Ipv6.SagIpv6)
			routedvlan.Ipv6.SagIpv6.Config.StaticAnycastGateway = sagGwIPMap
			routedvlan.Ipv6.SagIpv6.State.StaticAnycastGateway = sagGwIPMap
		}
	}

	return err
}

var DbToYang_intf_sag_subif_ip_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
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
		log.Info("DbToYang_intf_sag_subif_ip_xfmr : " + errStr)
		return errors.New(errStr)
	}

	ipv4_req := false
	ipv6_req := false
	var sagIPKey string

	_idx := pathInfo.Var("index")
	temp_idx, _ := strconv.Atoi(_idx)
	idx := uint32(temp_idx)

	ifDbName := *utils.GetSubInterfaceDBKeyfromParentInterfaceAndSubInterfaceID(&ifName, &_idx)
	/*
	  if strings.HasPrefix(ifName, "Ethernet") {
	      ifName = strings.Replace(ifName, "Ethernet", "Eth", -1) + "." + _idx
	  } else if strings.HasPrefix(ifName, "PortChannel") {
	      ifName = strings.Replace(ifName, "PortChannel", "Po", -1) + "." + _idx
	  }
	*/

	if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/sag-ipv4") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/sag-ipv4") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/openconfig-interfaces-ext:sag-ipv4") {

		ipv4_req = true
		sagIPKey = ifDbName + "|IPv4"
	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/sag-ipv6") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/sag-ipv6") ||
		strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/openconfig-interfaces-ext:sag-ipv6") {

		ipv6_req = true
		sagIPKey = ifDbName + "|IPv6"
	}

	sagIPEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: "SAG"}, db.Key{Comp: []string{sagIPKey}})
	sagGwIPList := sagIPEntry.Get("gwip@")
	sagGwIPMap := strings.Split(sagGwIPList, ",")

	if sagGwIPMap[0] == "" {
		return err
	}

	if ipv4_req || ipv6_req {

		/*
			if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
				var ok bool = false
				if intfObj, ok = intfsObj.Interface[ifName]; !ok {
					intfObj, _ = intfsObj.NewInterface(ifName)
					ygot.BuildEmptyTree(intfObj)
				}
			} else {
				ygot.BuildEmptyTree(intfsObj)
				intfObj, _ = intfsObj.NewInterface(ifName)
				ygot.BuildEmptyTree(intfObj)
			}
		*/

		intfObj = intfsObj.Interface[ifName]

		if intfObj.Subinterfaces == nil {
			var _subintfs ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces
			intfObj.Subinterfaces = &_subintfs
			ygot.BuildEmptyTree(intfObj.Subinterfaces)
		}
		/*
		   var subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface

		   if _, ok := intfObj.Subinterfaces.Subinterface[idx]; !ok {
		   	subIntf, err = intfObj.Subinterfaces.NewSubinterface(idx)
		   	if err != nil {
		   		log.Error("Creation of subinterface subtree failed!")
		   		return err
		   	}
		   	ygot.BuildEmptyTree(subIntf)
		   }
		*/

		subIntf := intfObj.Subinterfaces.Subinterface[idx]
		ygot.BuildEmptyTree(subIntf)

		if ipv4_req {
			ygot.BuildEmptyTree(subIntf.Ipv4)
			ygot.BuildEmptyTree(subIntf.Ipv4.SagIpv4)
			subIntf.Ipv4.SagIpv4.Config.StaticAnycastGateway = sagGwIPMap
			subIntf.Ipv4.SagIpv4.State.StaticAnycastGateway = sagGwIPMap
		} else if ipv6_req {
			ygot.BuildEmptyTree(subIntf.Ipv6)
			ygot.BuildEmptyTree(subIntf.Ipv6.SagIpv6)
			subIntf.Ipv6.SagIpv6.Config.StaticAnycastGateway = sagGwIPMap
			subIntf.Ipv6.SagIpv6.State.StaticAnycastGateway = sagGwIPMap
		}
	}

	return err
}
