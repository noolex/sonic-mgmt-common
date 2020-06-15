//////////////////////////////////////////////////////////////////////////
//
// Copyright 2019 BRCM, Inc.
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
    "strconv"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
	  "encoding/json"
)

func init () {
    XlateFuncBind("YangToDb_intf_vrrp_xfmr", YangToDb_intf_vrrp_xfmr)
    XlateFuncBind("DbToYang_intf_vrrp_xfmr", DbToYang_intf_vrrp_xfmr)
    XlateFuncBind("rpc_show_vrrp", rpc_show_vrrp)
  	XlateFuncBind("rpc_show_vrrp6", rpc_show_vrrp6)
}

type VrrpSummaryEntry struct {
	Ifname            string
	Vrid              int
  CurrPrio          int
  ConfPrio          int
  State             uint8
  Vip               string    `json:",omitempty"`
}

type VrrpSummary struct {
	VrppSummEntry  []VrrpSummaryEntry `json:",omitempty"`
}

var YangToDb_intf_vrrp_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err, oerr error
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subIntfmap := make(map[string]map[string]db.Value)
    subIntfmap_del := make(map[string]map[string]db.Value)
    var value db.Value
    var overlapIP string

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
	  intfType, _, ierr := getIntfTypeByName(ifName)

    if IntfTypeVxlan == intfType {
	    return subIntfmap, nil
    }

    log.Info("inParams:", inParams)
    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_intf_vrrp_xfmr : IntfsObj/interface list is empty.")
        return subIntfmap, errors.New("IntfsObj/Interface is not specified")
    }

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }
    /* Validate whether the Interface is configured as member-port associated with any vlan */
    if intfType == IntfTypeEthernet || intfType == IntfTypePortChannel {
        err = validateIntfAssociatedWithVlan(inParams.d, &ifName)
        if err != nil {
            return subIntfmap, err
        }
    }
    /* Validate whether the Interface is configured as member-port associated with any portchannel */
    if intfType == IntfTypeEthernet {
        err = validateIntfAssociatedWithPortChannel(inParams.d, &ifName)
        if err != nil {
            errStr := "IP config is not permitted on LAG member port."
            return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
        }
    }

    if _, ok := intfsObj.Interface[ifName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[ifName]

    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }
    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        log.Info("YangToDb_intf_vrrp_xfmr : No IP address handling required")
        return subIntfmap, err
    }

    log.Info("Processing YangToDb_intf_vrrp_xfmr")

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]

    entry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})
    if dbErr != nil || !entry.IsPopulated() {
        ifdb := make(map[string]string)
        ifdb["NULL"] = "NULL"
        value := db.Value{Field: ifdb}
        if _, ok := subIntfmap[tblName]; !ok {
            subIntfmap[tblName] = make(map[string]db.Value)
        }
        subIntfmap[tblName][ifName] = value

    }

    if subIntfObj.Ipv4 != nil && subIntfObj.Ipv4.Addresses != nil {
        for ip, _ := range subIntfObj.Ipv4.Addresses.Address {
            addr := subIntfObj.Ipv4.Addresses.Address[ip]

            if addr.Vrrp != nil {

                log.Info("addr.Vrrp present")

                for virtual_router_id, _ := range addr.Vrrp.VrrpGroup {
                    vrrp_rtr := addr.Vrrp.VrrpGroup[virtual_router_id]

                    t := make(map[string]string)
                    vrrp_key := ifName + "|" + strconv.Itoa(int(virtual_router_id))
                    vips := ""
                    vrrpEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"VRRP"}, db.Key{Comp: []string{vrrp_key}})


                    if vrrp_rtr.Config != nil {

                        t["vrid"] = strconv.Itoa(int(virtual_router_id))

                        vip_count := 0
                        if vrrpEntry.IsPopulated() {
                            vips, _ = vrrpEntry.Field["vip@"]
                            vip_count = strings.Count(vips, ",")
                            vip_count += 1
                        }

                        log.Info("vips:", vips)

                        if vrrp_rtr.Config.VirtualAddress != nil {

                            if ((inParams.oper != DELETE) && (vip_count >= 4)) {
                                errStr := "Max allowed virtual IP on an VRRP instance is 4"
                                log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                return subIntfmap, errors.New(errStr)
                            }

                            for vip_id, _ := range vrrp_rtr.Config.VirtualAddress {
                                if (vips == "" || inParams.oper == DELETE) {
                                    vips =  vrrp_rtr.Config.VirtualAddress[vip_id]
                                } else {
                                    vips = vips + "," + vrrp_rtr.Config.VirtualAddress[vip_id]
                                }
                            }
                            t["vip@"] = vips
                        }

                        if vrrp_rtr.Config.Priority != nil {
                            t["priority"] = strconv.Itoa(int(*vrrp_rtr.Config.Priority))
                        }

                        if vrrp_rtr.Config.Preempt != nil {
                            if (bool(*vrrp_rtr.Config.Preempt)) {
                                t["pre_empt"] = "True"
                            } else {
                                t["pre_empt"] = "False"
                            }
                        }
                        if vrrp_rtr.Config.Version != nil {
                            t["version"] = strconv.Itoa(int(*vrrp_rtr.Config.Version))
                        }

                        if vrrp_rtr.Config.AdvertisementInterval != nil {
                            t["adv_interval"] = strconv.Itoa(int(*vrrp_rtr.Config.AdvertisementInterval))
                        }

                        log.Info("In config : subIntfmap : ",  subIntfmap)


                    }

                    track_exist := false

                    if (vrrp_rtr.VrrpTrackInterface != nil) {


                        for track_if, _ := range vrrp_rtr.VrrpTrackInterface {
                            vrrp_track_data := vrrp_rtr.VrrpTrackInterface[track_if]

                            log.Info("track if name:", track_if)

                            track_table := make(map[string]string)
                            track_key := ifName + "|" + strconv.Itoa(int(virtual_router_id)) + "|" + track_if

                            if vrrp_track_data.Config != nil {

                                if vrrp_track_data.Config.PriorityIncrement != nil {
                                    track_table["priority_increment"] = strconv.Itoa(int(*vrrp_track_data.Config.PriorityIncrement))
                                }
                            }

                            track_value := db.Value{Field: track_table}
                            if _, ok := subIntfmap["VRRP_TRACK"]; !ok {
                                subIntfmap["VRRP_TRACK"] = make(map[string]db.Value)
                            }

                            subIntfmap["VRRP_TRACK"][track_key] = track_value

                            track_exist = true
                        }

                        log.Info("In track : subIntfmap : ",  subIntfmap)

                    }

                    if ((inParams.oper != DELETE) || (inParams.oper == DELETE && track_exist == false)) {
                        value := db.Value{Field: t}
                        if _, ok := subIntfmap["VRRP"]; !ok {
                            subIntfmap["VRRP"] = make(map[string]db.Value)
                        }
                        subIntfmap["VRRP"][vrrp_key] = value
                    }

                   log.Info("Outside : subIntfmap : ",  subIntfmap)

                }
            } else if (inParams.oper != DELETE) {
                  log.Info("Delete all VRRP entries & track from the table : ",  subIntfmap)
            }
        }
    }

    if subIntfObj.Ipv6 != nil && subIntfObj.Ipv6.Addresses != nil {
        for ip, _ := range subIntfObj.Ipv6.Addresses.Address {
            addr := subIntfObj.Ipv6.Addresses.Address[ip]

            if addr.Vrrp != nil {

                log.Info("addr.Vrrp present")

                for virtual_router_id, _ := range addr.Vrrp.VrrpGroup {
                    vrrp_rtr := addr.Vrrp.VrrpGroup[virtual_router_id]

                    t := make(map[string]string)
                    vrrp_key := ifName + "|" + strconv.Itoa(int(virtual_router_id))
                    vips := ""
                    vrrpEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"VRRP6"}, db.Key{Comp: []string{vrrp_key}})


                    if vrrp_rtr.Config != nil {

                        t["vrid"] = strconv.Itoa(int(virtual_router_id))

                        vip_count := 0
                        if vrrpEntry.IsPopulated() {
                            vips, _ = vrrpEntry.Field["vip@"]
                            vip_count = strings.Count(vips, ",")
                            vip_count += 1
                        }

                        log.Info("vips:", vips)

                        if vrrp_rtr.Config.VirtualAddress != nil {

                            if ((inParams.oper != DELETE) && (vip_count >= 4)) {
                                errStr := "Max allowed virtual IP on an VRRP instance is 4"
                                log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                return subIntfmap, errors.New(errStr)
                            }

                            for vip_id, _ := range vrrp_rtr.Config.VirtualAddress {
                                if (vips == "" || inParams.oper == DELETE) {
                                    vips =  vrrp_rtr.Config.VirtualAddress[vip_id]
                                } else {
                                    vips = vips + "," + vrrp_rtr.Config.VirtualAddress[vip_id]
                                }
                            }
                            t["vip@"] = vips
                        }

                        if vrrp_rtr.Config.Priority != nil {
                            t["priority"] = strconv.Itoa(int(*vrrp_rtr.Config.Priority))
                        }

                        if vrrp_rtr.Config.Preempt != nil {
                            if (bool(*vrrp_rtr.Config.Preempt)) {
                                t["pre_empt"] = "True"
                            } else {
                                t["pre_empt"] = "False"
                            }
                        }
                        if vrrp_rtr.Config.Version != nil {
                            t["version"] = strconv.Itoa(int(*vrrp_rtr.Config.Version))
                        }

                        if vrrp_rtr.Config.AdvertisementInterval != nil {
                            t["adv_interval"] = strconv.Itoa(int(*vrrp_rtr.Config.AdvertisementInterval))
                        }

                        log.Info("In config : subIntfmap : ",  subIntfmap)

                    }

                    track_exist := false

                    if (vrrp_rtr.VrrpTrackInterface != nil) {

                        for track_if, _ := range vrrp_rtr.VrrpTrackInterface {
                            vrrp_track_data := vrrp_rtr.VrrpTrackInterface[track_if]

                            log.Info("track if name:", track_if)

                            track_table := make(map[string]string)
                            track_key := ifName + "|" + strconv.Itoa(int(virtual_router_id)) + "|" + track_if

                            if vrrp_track_data.Config != nil {

                                if vrrp_track_data.Config.PriorityIncrement != nil {
                                    track_table["priority_increment"] = strconv.Itoa(int(*vrrp_track_data.Config.PriorityIncrement))
                                }
                            }

                            track_value := db.Value{Field: track_table}
                            if _, ok := subIntfmap["VRRP6_TRACK"]; !ok {
                                subIntfmap["VRRP6_TRACK"] = make(map[string]db.Value)
                            }

                            subIntfmap["VRRP6_TRACK"][track_key] = track_value

                            track_exist = true

                        }

                        log.Info("In track : subIntfmap : ",  subIntfmap)
                    }

                    if ((inParams.oper != DELETE) || (inParams.oper == DELETE && track_exist == false)) {
                        value := db.Value{Field: t}
                        if _, ok := subIntfmap["VRRP6"]; !ok {
                            subIntfmap["VRRP6"] = make(map[string]db.Value)
                        }
                        subIntfmap["VRRP6"][vrrp_key] = value
                    }

                    log.Info("Outside : subIntfmap : ",  subIntfmap)
                }
            }
        }
    }

    if oerr != nil {
        if overlapIP == "" {
            log.Error(oerr)
            return nil, tlerr.InvalidArgsError{Format: oerr.Error()}
        } else {
            subIntfmap_del[tblName] = make(map[string]db.Value)
            key := ifName + "|" + overlapIP
            subIntfmap_del[tblName][key] = value
            subOpMap[db.ConfigDB] = subIntfmap_del
            log.Info("subOpMap: ", subOpMap)
            inParams.subOpDataMap[DELETE] = &subOpMap
        }
    }

    log.Info("YangToDb_intf_vrrp_xfmr : subIntfmap : ",  subIntfmap)
    return subIntfmap, err
}

func getVrrpByName(dbCl *db.DB, tblName string, ifName string, isvrid bool, vrid string) (map[string]db.Value, error) {
    var err error
    vrrpMap := make(map[string]db.Value)

    log.Info("Updating VRRP Info from DB to Internal DS for Interface Name : ", ifName)

    vrrpTable, err := dbCl.GetTable(&db.TableSpec{Name:tblName})
    if err != nil {
        return vrrpMap, err
    }

    keys, err := vrrpTable.GetKeys()
    log.Info("Found %d VRRP table keys", len(keys))

    for x, key := range keys {

        log.Info("VRRP index & keys", x, key.Get(0), key.Get(1))


        if key.Get(0) != ifName {
            continue
        }

        if isvrid && key.Get(1) != vrid {
            continue
        }

        vrrpInfo, _ := dbCl.GetEntry(&db.TableSpec{Name:tblName}, key)
        vrrpMap[key.Comp[0] + "|" + key.Comp[1]] = vrrpInfo
    }

    if (isvrid && len(vrrpMap) == 0) {
        err = errors.New("VRRP entry not found")
    }
    return vrrpMap, err
}


func getVrrpTrackByName(dbCl *db.DB, tblName string, ifName string, vrid string) (map[string]db.Value, error) {
    var err error
    vrrpTrackMap := make(map[string]db.Value)

    log.Info("Updating VRRPTRACK Info from DB to Internal DS for Interface Name : ", ifName)

    vrrpTrackTable, err := dbCl.GetTable(&db.TableSpec{Name:tblName})
    if err != nil {
        return vrrpTrackMap, err
    }

    keys, err := vrrpTrackTable.GetKeys()
    log.Info("Found %d VRRPTRACK table keys", len(keys))

    for x, key := range keys {

        log.Info("VRRP index & keys", x, key.Get(0), key.Get(1))


        if key.Get(0) != ifName {
            continue
        }

        if key.Get(1) != vrid {
            continue
        }

        vrrpTrackInfo, _ := dbCl.GetEntry(&db.TableSpec{Name:tblName}, key)
        vrrpTrackMap[key.Comp[0] + "|" + key.Comp[1] + "|" + key.Comp[2]] = vrrpTrackInfo
    }
    return vrrpTrackMap, err
}

func getVrrpState(dbCl *db.DB, tblName string, ifName string, keyIp string, keySuffix string, vrid string) (uint8) {
    var err error

    log.Info("Checking APP DB for VRRP instance %s interface %s vip %s%s", vrid, ifName, keyIp, keySuffix)

    _, err = dbCl.GetTable(&db.TableSpec{Name:tblName})
    if err != nil {
        return 0
    }

    ifup := isIntfUp(dbCl, ifName)

    if (ifup != true) {
        return 0
    }

    key := ifName + "|" + keyIp + keySuffix

    _, err = dbCl.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{key}})

    if err != nil {
        return 1
    }

    return 2
}

func isIntfUp(dbCl *db.DB, ifName string) (bool) {

    log.Info("Checking interface status for VRRP:", ifName)

    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("isIntfUp - Invalid interface type IntfTypeUnset")
        return false
    }

    if IntfTypeVxlan == intfType {
	      return false
    }

    intTbl := IntfTypeTblMap[intfType]

    tblName := intTbl.appDb.portTN

    _, err := dbCl.GetTable(&db.TableSpec{Name:tblName})

    if err != nil {
        return false
    }

    prtInst, _ := dbCl.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})

    log.Info("Portstatus:", prtInst)

    adminStatus, _ := prtInst.Field[PORT_ADMIN_STATUS]

    if adminStatus != "up" {
        return false
    }

    operStatus, _ := prtInst.Field[PORT_OPER_STATUS]

    if operStatus != "up" {
        return false
    }

    return true
}

func getVrrpTrackPriority(dbs [db.MaxDB]*db.DB, tblName string, ifName string, vrid string) (uint8) {
    var track_priority uint8
    track_priority = 0

    log.Info("In getVrrpTrackPriority")
    vrrpTrackMap, _ := getVrrpTrackByName(dbs[db.ConfigDB], tblName, ifName, vrid)

    for vrrpTrackKey, vrrpTrackData := range vrrpTrackMap {
        vrrpTrackKeySplit := strings.Split(vrrpTrackKey, "|")
        trackIfname := vrrpTrackKeySplit[2]
        ifup := isIntfUp(dbs[db.ApplDB], trackIfname)
        if ifup == true {
            priority, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
            track_priority += uint8(priority)
        }
    }

    return track_priority
}

func handleVrrpGetByTargetURI (inParams XfmrParams, targetUriPath string, ifName string, intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface) error {
    vrrpMap := make(map[string]db.Value)
    var err error
    var isvrid bool

    log.Info("handleVrrpGetByTargetURI")
    pathInfo := NewPathInfo(inParams.uri)

    vrid := pathInfo.Var("virtual-router-id")
    if len(vrid) == 0 {
        isvrid = false
    } else {
        isvrid = true
    }

    intfType, _, ierr := getIntfTypeByName(ifName)

    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
        return errors.New(errStr)
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/config") ||
       strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, true, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, false, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/config") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, false, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/state") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, true, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, true, true, true)

    }
    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/config") ||
       strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, true, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, false, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/config") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, false, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/state") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, true, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group") ||
            strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, true, true, true)

    }

    log.Info("err:", err)
    return err
}


func convertVrrpMapToOC (inParams XfmrParams, targetUriPath string, ifName string, vrrpMap map[string]db.Value, ifInfo *ocbinds.OpenconfigInterfaces_Interfaces_Interface, isConfig bool, isState bool, isTrackConfig bool, isTrackState bool) error {
    var subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
    var err error
    var v4Flag bool
    var v4Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Addresses_Address
    var v6Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv6_Addresses_Address
    vrrpTrackMap := make(map[string]db.Value)

    v4Flag = false

    log.Info("convertVrrpMapToOC")

    if _, ok := ifInfo.Subinterfaces.Subinterface[0]; !ok {
        subIntf, err = ifInfo.Subinterfaces.NewSubinterface(0)
        if err != nil {
            log.Error("Creation of subinterface subtree failed!")
            return err
        }
    }

    subIntf = ifInfo.Subinterfaces.Subinterface[0]
    ygot.BuildEmptyTree(subIntf)

    pathInfo := NewPathInfo(inParams.uri)
    ipB := pathInfo.Var("ip")
    if len(ipB) == 0 {
        return err
    }


    vridStr := pathInfo.Var("virtual-router-id")
    if len(vridStr) == 0 {
        log.Info("Missing key in convertVrrpMapToOC")
        return err
    }

    if len(vrrpMap) == 0 {
        log.Info("VRRP entry not present")
        errors.New("VRRP entry not found" )
        return err
    }

    vrid64, err := strconv.ParseUint(vridStr, 10, 8)
    vrid := uint8(vrid64)

    if validIPv4(ipB) {
        if _, ok := subIntf.Ipv4.Addresses.Address[ipB]; !ok {
            v4Address, _ = subIntf.Ipv4.Addresses.NewAddress(ipB)
        }
        v4Address = subIntf.Ipv4.Addresses.Address[ipB]
        v4Flag = true
    } else if validIPv6(ipB) {
        if _, ok := subIntf.Ipv6.Addresses.Address[ipB]; !ok {
            v6Address, _ = subIntf.Ipv6.Addresses.NewAddress(ipB)
        }
        v6Address = subIntf.Ipv6.Addresses.Address[ipB]
    } else {
        log.Error("Invalid IP address " + ipB)
        return err
    }


    for _, vrrpData := range vrrpMap {

        if v4Flag {

            log.Info("for ipv4")

            var vrrp4 *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Addresses_Address_Vrrp_VrrpGroup

            if _, ok := v4Address.Vrrp.VrrpGroup[vrid]; !ok {
                vrrp4, err = v4Address.Vrrp.NewVrrpGroup(vrid)
            }

            vrrp4 = v4Address.Vrrp.VrrpGroup[vrid]

            ygot.BuildEmptyTree(vrrp4)
            pvrid := new(uint8)
            *pvrid = vrid
            vrrp4.VirtualRouterId = pvrid
            var state uint8
            state = 0

            if isState {

              priority := 100
              if vrrpData.Has("priority") {
                  priority, _ = strconv.Atoi(vrrpData.Get("priority"))
              }
              ppriority := new(uint8)
              *ppriority  = uint8(priority)
              vrrp4.State.Priority = ppriority

              advintv := 1
              if vrrpData.Has("adv_interval") {
                  advintv, _ = strconv.Atoi(vrrpData.Get("adv_interval"))
              }
              padvintv := new(uint16)
              *padvintv  = uint16(advintv)
              vrrp4.State.AdvertisementInterval = padvintv

              preemptstr := "True"
              if vrrpData.Has("pre_empt") {
                  preemptstr = vrrpData.Get("pre_empt")
              }
              ppreempt := new(bool)
              if "True" == preemptstr {
                  *ppreempt = true
              } else {
                  *ppreempt = false
              }
              vrrp4.State.Preempt = ppreempt

              if vrrpData.Has("vip@") {
                  vipstr := vrrpData.Get("vip@")
                  vipmap := strings.Split(vipstr, ",")
                  vrrp4.State.VirtualAddress = vipmap

                  state = getVrrpState(inParams.dbs[db.ApplDB], "VRRP_TABLE", ifName, vipmap[0], "/32", vridStr)

              }

              pstate := new(uint8)
              *pstate  = uint8(state)
              vrrp4.State.State = pstate

              version := 2
              if vrrpData.Has("version") {
                  version, _ = strconv.Atoi(vrrpData.Get("version"))
              }
              pversion := new(uint8)
              *pversion  = uint8(version)
              vrrp4.State.Version = pversion

            }
            if isConfig {
                priority := 100
                if vrrpData.Has("priority") {
                    priority, _ = strconv.Atoi(vrrpData.Get("priority"))
                }
                ppriority := new(uint8)
                *ppriority  = uint8(priority)
                vrrp4.Config.Priority = ppriority

                advintv := 1
                if vrrpData.Has("advert_int") {
                    advintv, _ = strconv.Atoi(vrrpData.Get("advert_int"))
                }
                padvintv := new(uint16)
                *padvintv  = uint16(advintv)
                vrrp4.Config.AdvertisementInterval = padvintv

                preemptstr := "True"
                if vrrpData.Has("pre_empt") {
                    preemptstr = vrrpData.Get("pre_empt")
                }
                ppreempt := new(bool)
                if "True" == preemptstr {
                    *ppreempt = true
                } else {
                    *ppreempt = false
                }
                vrrp4.Config.Preempt = ppreempt

                if vrrpData.Has("vip@") {
                    vipstr := vrrpData.Get("vip@")
                    vipmap := strings.Split(vipstr, ",")
                    vrrp4.Config.VirtualAddress = vipmap
                }

                version := 2
                if vrrpData.Has("version") {
                    version, _ = strconv.Atoi(vrrpData.Get("version"))
                }
                pversion := new(uint8)
                *pversion  = uint8(version)
                vrrp4.Config.Version = pversion
            }


            if (isTrackState || isTrackConfig) {

                vrrpTrackMap, err = getVrrpTrackByName(inParams.dbs[db.ConfigDB], "VRRP_TRACK", ifName, vridStr)
                log.Info("vrrpTrackMap: ", vrrpTrackMap)


                for vrrpTrackKey, vrrpTrackData := range vrrpTrackMap {

                    log.Info("vrrpTrackKey: vrrpTrackData: ", vrrpTrackKey, vrrpTrackData)

                    vrrpTrackKeySplit := strings.Split(vrrpTrackKey, "|")

                    trackIfname := pathInfo.Var("vrrp-track-interface")

                    if trackIfname == "" {
                        trackIfname = vrrpTrackKeySplit[2]
                    }

                    log.Info("trackIfname: ", trackIfname)

                    if _, ok := vrrp4.VrrpTrackInterface[trackIfname]; !ok {
                        vrrp4.NewVrrpTrackInterface(trackIfname)
                    }

                    if vrrpTrackData.Has("priority_increment") {

                        ygot.BuildEmptyTree(vrrp4.VrrpTrackInterface[trackIfname])


                        ppriority_increment := new(uint8)
                        ppriority_incr_state := new(uint8)
                        priority_increment, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
                        *ppriority_increment  = uint8(priority_increment)
                        *ppriority_incr_state  = uint8(priority_increment)

                        if (isTrackConfig) {
                            vrrp4.VrrpTrackInterface[trackIfname].Config.PriorityIncrement = ppriority_increment
                        }

                        if (isTrackState) {

                            ifup := isIntfUp(inParams.dbs[db.ApplDB], trackIfname)
                            if ifup == false {
                                *ppriority_incr_state = 0
                            }

                            vrrp4.VrrpTrackInterface[trackIfname].State.PriorityIncrement = ppriority_incr_state
                        }

                        if (isTrackConfig) {
                            vrrp4.VrrpTrackInterface[trackIfname].Config.PriorityIncrement = ppriority_increment
                        }

                        log.Info("PriorityIncrement: ", ppriority_incr_state)
                    }
                }
            }
        } else {

            log.Info("for ipv6")

            var vrrp6 *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv6_Addresses_Address_Vrrp_VrrpGroup

            if _, ok := v6Address.Vrrp.VrrpGroup[vrid]; !ok {
                vrrp6, err = v6Address.Vrrp.NewVrrpGroup(vrid)
            }

            vrrp6 = v6Address.Vrrp.VrrpGroup[vrid]

            ygot.BuildEmptyTree(vrrp6)
            pvrid := new(uint8)
            *pvrid = vrid
            vrrp6.VirtualRouterId = pvrid
            var state uint8
            state = 0

            if isState {

              priority := 100
              if vrrpData.Has("priority") {
                  priority, _ = strconv.Atoi(vrrpData.Get("priority"))
              }
              ppriority := new(uint8)
              *ppriority  = uint8(priority)
              vrrp6.State.Priority = ppriority

              advintv := 1
              if vrrpData.Has("adv_interval") {
                  advintv, _ = strconv.Atoi(vrrpData.Get("adv_interval"))
              }
              padvintv := new(uint16)
              *padvintv  = uint16(advintv)
              vrrp6.State.AdvertisementInterval = padvintv

              preemptstr := "True"
              if vrrpData.Has("pre_empt") {
                  preemptstr = vrrpData.Get("pre_empt")
              }
              ppreempt := new(bool)
              if "True" == preemptstr {
                  *ppreempt = true
              } else {
                  *ppreempt = false
              }
              vrrp6.State.Preempt = ppreempt

              if vrrpData.Has("vip@") {
                  vipstr := vrrpData.Get("vip@")
                  vipmap := strings.Split(vipstr, ",")
                  vrrp6.State.VirtualAddress = vipmap

                  state = getVrrpState(inParams.dbs[db.ApplDB], "VRRP_TABLE", ifName, vipmap[0], "/128", vridStr)

              }

              pstate := new(uint8)
              *pstate  = uint8(state)
              vrrp6.State.State = pstate

              version := 3
              if vrrpData.Has("version") {
                  version, _ = strconv.Atoi(vrrpData.Get("version"))
              }
              pversion := new(uint8)
              *pversion  = uint8(version)
              vrrp6.State.Version = pversion

            }
            if isConfig {
              priority := 100
              if vrrpData.Has("priority") {
                  priority, _ = strconv.Atoi(vrrpData.Get("priority"))
              }
              ppriority := new(uint8)
              *ppriority  = uint8(priority)
              vrrp6.Config.Priority = ppriority

              advintv := 1
              if vrrpData.Has("advert_int") {
                  advintv, _ = strconv.Atoi(vrrpData.Get("advert_int"))
              }
              padvintv := new(uint16)
              *padvintv  = uint16(advintv)
              vrrp6.Config.AdvertisementInterval = padvintv

              preemptstr := "True"
              if vrrpData.Has("pre_empt") {
                  preemptstr = vrrpData.Get("pre_empt")
              }
              ppreempt := new(bool)
              if "True" == preemptstr {
                  *ppreempt = true
              } else {
                  *ppreempt = false
              }
              vrrp6.Config.Preempt = ppreempt

              if vrrpData.Has("vip@") {
                  vipstr := vrrpData.Get("vip@")
                  vipmap := strings.Split(vipstr, ",")
                  vrrp6.Config.VirtualAddress = vipmap
              }

              version := 3
              if vrrpData.Has("version") {
                  version, _ = strconv.Atoi(vrrpData.Get("version"))
              }
              pversion := new(uint8)
              *pversion  = uint8(version)
              vrrp6.Config.Version = pversion

            }

            if (isTrackState || isTrackConfig) {
                vrrpTrackMap, err = getVrrpTrackByName(inParams.dbs[db.ConfigDB], "VRRP6_TRACK", ifName, vridStr)
                log.Info("vrrpTrackMap: ", vrrpTrackMap)


                for vrrpTrackKey, vrrpTrackData := range vrrpTrackMap {

                    log.Info("vrrpTrackKey: vrrpTrackData: ", vrrpTrackKey, vrrpTrackData)

                    vrrpTrackKeySplit := strings.Split(vrrpTrackKey, "|")

                    trackIfname := pathInfo.Var("vrrp-track-interface")

                    if trackIfname == "" {
                        trackIfname = vrrpTrackKeySplit[2]
                    }

                    log.Info("trackIfname: ", trackIfname)

                    if _, ok := vrrp6.VrrpTrackInterface[trackIfname]; !ok {
                        vrrp6.NewVrrpTrackInterface(trackIfname)
                    }

                    if vrrpTrackData.Has("priority_increment") {

                        ygot.BuildEmptyTree(vrrp6.VrrpTrackInterface[trackIfname])


                        ppriority_increment := new(uint8)
                        ppriority_incr_state := new(uint8)
                        priority_increment, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
                        *ppriority_increment  = uint8(priority_increment)
                        *ppriority_incr_state  = uint8(priority_increment)

                        if (isTrackConfig) {
                            vrrp6.VrrpTrackInterface[trackIfname].Config.PriorityIncrement = ppriority_increment
                        }

                        if (isTrackState) {

                            ifup := isIntfUp(inParams.dbs[db.ApplDB], trackIfname)
                            if ifup == false {
                                *ppriority_incr_state = 0
                            }

                            vrrp6.VrrpTrackInterface[trackIfname].State.PriorityIncrement = ppriority_incr_state
                        }

                        log.Info("PriorityIncrement: ", priority_increment)
                    }
                }
            }
        }
    }

    log.Info("err:", err)
    return err
}


var DbToYang_intf_vrrp_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("name")
    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath is ", targetUriPath)
    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface

    log.Info("DbToYang_intf_vrrp_xfmr")

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces") {
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[intfName]; !ok {
                intfObj, _ = intfsObj.NewInterface(intfName)
            }
            ygot.BuildEmptyTree(intfObj)
            if intfObj.Subinterfaces == nil {
                ygot.BuildEmptyTree(intfObj.Subinterfaces)
            }
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(intfName)
            ygot.BuildEmptyTree(intfObj)
        }


    } else {
        err = errors.New("Invalid URI : " + targetUriPath)
    }
    err = handleVrrpGetByTargetURI(inParams, targetUriPath, intfName, intfObj)

    log.Info("err:", err)

    if err != nil {
        return tlerr.NotFound("Resource Not Found")
    }
    return err
}


func vrrp_show_summary (body []byte, dbs [db.MaxDB]*db.DB, tableName string, trackTableName string) (result []byte, err error) {
    var vip_suffix string

    log.Infof("Enter rpc_show_vrrp")

	  var VRRP_TABLE_TS *db.TableSpec = &db.TableSpec{Name: tableName}
    if tableName == "VRRP" {
        vip_suffix = "/32"
    } else {
        vip_suffix = "/128"
    }

    var showOutput struct {
	      Output struct {
			      Vrrp [] VrrpSummaryEntry
        } `json:"sonic-vrrp:output"`
    }

    showOutput.Output.Vrrp = make([]VrrpSummaryEntry, 0)

    vrrpTbl, err := dbs[db.ConfigDB].GetTable(VRRP_TABLE_TS)
    if nil != err {
        return nil, err
    }

    vrrpKeys, _ := vrrpTbl.GetKeys()
    for _, key := range vrrpKeys {
        vrrpData, _ := vrrpTbl.GetEntry(key)

        log.Infof("vrrpData:", vrrpData)

        var vrrpsummaryentry VrrpSummaryEntry
        var state uint8
        state = 0
        priority := 100

        vrrpsummaryentry.Ifname = key.Get(0)
        vrrpsummaryentry.Vrid, _ = strconv.Atoi(key.Get(1))

        if vrrpData.Has("priority") {
            priority, _ = strconv.Atoi(vrrpData.Get("priority"))
        }
        vrrpsummaryentry.ConfPrio = priority
        vrrpsummaryentry.CurrPrio = priority
        vrrpsummaryentry.CurrPrio += int(getVrrpTrackPriority(dbs, trackTableName, key.Get(0), key.Get(1)))

        if vrrpData.Has("vip@") {
            vipstr := vrrpData.Get("vip@")
            vipmap := strings.Split(vipstr, ",")
            vrrpsummaryentry.Vip = vipmap[0]
            state = getVrrpState(dbs[db.ApplDB], "VRRP_TABLE", key.Get(0), vipmap[0], vip_suffix, key.Get(1))
        }

        vrrpsummaryentry.State = state

        showOutput.Output.Vrrp = append(showOutput.Output.Vrrp, vrrpsummaryentry)

    }

    log.Infof("vrrp all summary:", showOutput.Output.Vrrp)

    result, err = json.Marshal(&showOutput)
	  return result, err

}

var rpc_show_vrrp RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {

	  log.Infof("Enter rpc_show_vrrp")

    result, err = vrrp_show_summary(body, dbs, "VRRP", "VRRP_TRACK")
	  return result, err

}

var rpc_show_vrrp6 RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {

	  log.Infof("Enter rpc_show_vrrp6")

    result, err = vrrp_show_summary(body, dbs, "VRRP6", "VRRP6_TRACK")
	  return result, err

}
