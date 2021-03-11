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
    "github.com/Azure/sonic-mgmt-common/translib/utils"
	  "encoding/json"
    "net"
)

func init () {
    XlateFuncBind("YangToDb_intf_vrrp_xfmr", YangToDb_intf_vrrp_xfmr)
    XlateFuncBind("DbToYang_intf_vrrp_xfmr", DbToYang_intf_vrrp_xfmr)
    XlateFuncBind("Subscribe_intf_vrrp_xfmr", Subscribe_intf_vrrp_xfmr)
    XlateFuncBind("Subscribe_intf_vlan_vrrp_xfmr", Subscribe_intf_vlan_vrrp_xfmr)
    XlateFuncBind("YangToDb_intf_vlan_vrrp_xfmr", YangToDb_intf_vlan_vrrp_xfmr)
    XlateFuncBind("DbToYang_intf_vlan_vrrp_xfmr", DbToYang_intf_vlan_vrrp_xfmr)
    XlateFuncBind("rpc_show_vrrp", rpc_show_vrrp)
  	XlateFuncBind("rpc_show_vrrp6", rpc_show_vrrp6)
    XlateFuncBind("vrrp_alias_xfmr", vrrp_alias_xfmr)
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
    var err error
    subIntfmap := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")

    idx := pathInfo.Var("index")
    var i32 uint32
    i32 = 0
    if idx != "" {
        i64, _ := strconv.ParseUint(idx, 10, 32)
        i32 = uint32(i64)
    }

    _ifName := utils.GetNativeNameFromUIName(&uriIfName)
    ifName := *_ifName
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

    if _, ok := intfsObj.Interface[uriIfName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[uriIfName]

    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[i32]; !ok {
        log.Info("YangToDb_intf_vrrp_xfmr : No IP address handling required")
        return subIntfmap, err
    }

    log.Info("Processing YangToDb_intf_vrrp_xfmr")

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

    subIntfObj := intfObj.Subinterfaces.Subinterface[i32]

    if i32 > 0 {
        tblName = "VLAN_SUB_INTERFACE"
        if strings.HasPrefix(ifName, "Ethernet") {
            ifName = strings.Replace(ifName, "Ethernet", "Eth", -1) + "." + idx
        } else if strings.HasPrefix(ifName, "PortChannel") {
            ifName = strings.Replace(ifName, "PortChannel", "Po", -1) + "." + idx
        }
    }

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
        for ip := range subIntfObj.Ipv4.Addresses.Address {
            addr := subIntfObj.Ipv4.Addresses.Address[ip]

            if addr.Vrrp != nil {

                log.Info("addr.Vrrp present")

                for virtual_router_id := range addr.Vrrp.VrrpGroup {
                    vrrp_rtr := addr.Vrrp.VrrpGroup[virtual_router_id]

                    t := make(map[string]string)
                    vrrp_key := ifName + "|" + strconv.Itoa(int(virtual_router_id))
                    vips := ""
                    vrrpEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"VRRP"}, db.Key{Comp: []string{vrrp_key}})


                    if vrrp_rtr.Config != nil {

                        if inParams.oper != DELETE {
                            t["vrid"] = strconv.Itoa(int(virtual_router_id))
                        }

                        if vrrpEntry.IsPopulated() {
                            vips = vrrpEntry.Field["vip@"]
                        }

                        log.Info("vips:", vips)

                        if vrrp_rtr.Config.VirtualAddress != nil {

                            for vip_id := range vrrp_rtr.Config.VirtualAddress {
                                if (vips == "" || inParams.oper == DELETE) {
                                    vips =  vrrp_rtr.Config.VirtualAddress[vip_id]
                                } else {
                                    vips = vips + "," + vrrp_rtr.Config.VirtualAddress[vip_id]
                                }
                            }
                            t["vip@"] = vips
                        }

                        if vrrp_rtr.Config.Priority != nil {

                            base_priority := int(*vrrp_rtr.Config.Priority)

                            track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), "", true, false))

                            if base_priority + track_priority > 254 {
                                errStr := "VRRP instance priority and track priority exceeds 254"
                                log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                            }

                            t["priority"] = strconv.Itoa(int(*vrrp_rtr.Config.Priority))
                        }

                        if vrrp_rtr.Config.Preempt != nil {
                            if (bool(*vrrp_rtr.Config.Preempt)) {
                                t["pre_empt"] = "True"
                            } else {
                                t["pre_empt"] = "False"
                            }
                        }

                        if vrrp_rtr.Config.UseV2Checksum != nil {
                            if (bool(*vrrp_rtr.Config.UseV2Checksum)) {
                                t["use_v2_checksum"] = "True"
                            } else {
                                t["use_v2_checksum"] = "False"
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

                    if (vrrp_rtr.VrrpTrack != nil && vrrp_rtr.VrrpTrack.VrrpTrackInterface != nil) {


                        for track_if := range vrrp_rtr.VrrpTrack.VrrpTrackInterface {
                            vrrp_track_data := vrrp_rtr.VrrpTrack.VrrpTrackInterface[track_if]

                            log.Info("track if name:", track_if)

                            /*

                            if strings.Contains(track_if, ".") {
                                if strings.HasPrefix(track_if, "Ethernet") {
                                    track_if = strings.Replace(track_if, "Ethernet", "Eth", -1) + "." + idx
                                } else if strings.HasPrefix(track_if, "PortChannel") {
                                    track_if = strings.Replace(track_if, "PortChannel", "po", -1) + "." + idx
                                }
                            }

                            */

                            _trackifNativeName := utils.GetNativeNameFromUIName(&track_if)
                            trackifNativeName := *_trackifNativeName

                            log.Info("track if native name:", trackifNativeName)

                            track_table := make(map[string]string)
                            track_key := ifName + "|" + strconv.Itoa(int(virtual_router_id)) + "|" + trackifNativeName

                            if vrrp_track_data.Config != nil {

                                if vrrp_track_data.Config.PriorityIncrement != nil {
                                    if ifName == trackifNativeName || ifName == track_if {
                                        errStr := "VRRP track interface cannot be same as VRRP instance interface"
                                        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }

                                    base_priority := 100
                                    if vrrpEntry.Has("priority") {
                                        base_priority, _ = strconv.Atoi(vrrpEntry.Get("priority"))
                                    }
                                    new_priority := int(*vrrp_track_data.Config.PriorityIncrement)
                                    track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), trackifNativeName, true, true))

                                    if (base_priority + track_priority + new_priority) > 254 {
                                        errStr := "VRRP instance priority and track priority exceeds 254"
                                        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }

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

                    if ((inParams.oper != DELETE) || (inParams.oper == DELETE && !track_exist)) {
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
        for ip := range subIntfObj.Ipv6.Addresses.Address {
            addr := subIntfObj.Ipv6.Addresses.Address[ip]

            if addr.Vrrp != nil {

                log.Info("addr.Vrrp present")

                for virtual_router_id := range addr.Vrrp.VrrpGroup {
                    vrrp_rtr := addr.Vrrp.VrrpGroup[virtual_router_id]

                    t := make(map[string]string)
                    vrrp_key := ifName + "|" + strconv.Itoa(int(virtual_router_id))
                    vips := ""
                    vrrpEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"VRRP6"}, db.Key{Comp: []string{vrrp_key}})


                    if vrrp_rtr.Config != nil {

                        t["vrid"] = strconv.Itoa(int(virtual_router_id))

                        if vrrpEntry.IsPopulated() {
                            vips = vrrpEntry.Field["vip@"]
                        }

                        log.Info("vips:", vips)

                        if vrrp_rtr.Config.VirtualAddress != nil {

                            for vip_id := range vrrp_rtr.Config.VirtualAddress {
                                if (vips == "" || inParams.oper == DELETE) {
                                    vips =  vrrp_rtr.Config.VirtualAddress[vip_id]
                                } else {
                                    vips = vips + "," + vrrp_rtr.Config.VirtualAddress[vip_id]
                                }
                            }
                            t["vip@"] = vips
                        }

                        if vrrp_rtr.Config.Priority != nil {
                            base_priority := int(*vrrp_rtr.Config.Priority)

                            track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP6_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), "", true, false))

                            if base_priority + track_priority > 254 {
                                errStr := "VRRP instance priority and track priority exceeds 254"
                                log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                            }
                            t["priority"] = strconv.Itoa(int(*vrrp_rtr.Config.Priority))
                        }

                        if vrrp_rtr.Config.Preempt != nil {
                            if (bool(*vrrp_rtr.Config.Preempt)) {
                                t["pre_empt"] = "True"
                            } else {
                                t["pre_empt"] = "False"
                            }
                        }

                        if vrrp_rtr.Config.AdvertisementInterval != nil {
                            t["adv_interval"] = strconv.Itoa(int(*vrrp_rtr.Config.AdvertisementInterval))
                        }

                        log.Info("In config : subIntfmap : ",  subIntfmap)

                    }

                    track_exist := false

                    if (vrrp_rtr.VrrpTrack != nil && vrrp_rtr.VrrpTrack.VrrpTrackInterface != nil) {

                        for track_if := range vrrp_rtr.VrrpTrack.VrrpTrackInterface {
                            vrrp_track_data := vrrp_rtr.VrrpTrack.VrrpTrackInterface[track_if]

                            log.Info("track if name:", track_if)

                            /*
                            if strings.Contains(track_if, ".") {
                                if strings.HasPrefix(track_if, "Ethernet") {
                                    track_if = strings.Replace(track_if, "Ethernet", "Eth", -1) + "." + idx
                                } else if strings.HasPrefix(track_if, "PortChannel") {
                                    track_if = strings.Replace(track_if, "PortChannel", "po", -1) + "." + idx
                                }
                            }
                            */

                            _trackifNativeName := utils.GetNativeNameFromUIName(&track_if)
                            trackifNativeName := *_trackifNativeName

                            log.Info("track if native name:", trackifNativeName)

                            track_table := make(map[string]string)
                            track_key := ifName + "|" + strconv.Itoa(int(virtual_router_id)) + "|" + trackifNativeName

                            if vrrp_track_data.Config != nil {

                                if vrrp_track_data.Config.PriorityIncrement != nil {

                                    if ifName == trackifNativeName || ifName == track_if {
                                        errStr := "VRRP track interface cannot be same as VRRP instance interface"
                                        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }

                                    base_priority := 100
                                    if vrrpEntry.Has("priority") {
                                        base_priority, _ = strconv.Atoi(vrrpEntry.Get("priority"))
                                    }
                                    new_priority := int(*vrrp_track_data.Config.PriorityIncrement)
                                    track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP6_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), trackifNativeName, true, true))

                                    if (base_priority + track_priority + new_priority) > 254 {
                                        errStr := "VRRP instance priority and track priority exceeds 254"
                                        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }
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

                    if ((inParams.oper != DELETE) || (inParams.oper == DELETE && !track_exist)) {
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

    log.Info("YangToDb_intf_vrrp_xfmr : subIntfmap : ",  subIntfmap)
    return subIntfmap, err
}

var YangToDb_intf_vlan_vrrp_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    subIntfmap := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    _ifName := utils.GetNativeNameFromUIName(&uriIfName)
    ifName := *_ifName
	  intfType, _, ierr := getIntfTypeByName(ifName)

    if IntfTypeVxlan == intfType {
	    return subIntfmap, nil
    }

    log.Info("inParams:", inParams)
    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_intf_vlan_vrrp_xfmr : IntfsObj/interface list is empty.")
        return subIntfmap, errors.New("IntfsObj/Interface is not specified")
    }

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_intf_vlan_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_vlan_vrrp_xfmr : " + errStr)
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

    if _, ok := intfsObj.Interface[uriIfName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_intf_vlan_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[uriIfName]

    if intfObj.RoutedVlan == nil {
        errStr := "RoutedVlan node is not set"
        log.Info("YangToDb_intf_vlan_vrrp_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    log.Info("Processing YangToDb_intf_vlan_vrrp_xfmr")

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

    subIntfObj := intfObj.RoutedVlan

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
        for ip := range subIntfObj.Ipv4.Addresses.Address {
            addr := subIntfObj.Ipv4.Addresses.Address[ip]

            if addr.Vrrp != nil {

                log.Info("addr.Vrrp present")

                for virtual_router_id := range addr.Vrrp.VrrpGroup {
                    vrrp_rtr := addr.Vrrp.VrrpGroup[virtual_router_id]

                    t := make(map[string]string)
                    vrrp_key := ifName + "|" + strconv.Itoa(int(virtual_router_id))
                    vips := ""
                    vrrpEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"VRRP"}, db.Key{Comp: []string{vrrp_key}})


                    if vrrp_rtr.Config != nil {

                        if inParams.oper != DELETE {
                            t["vrid"] = strconv.Itoa(int(virtual_router_id))
                        }

                        if vrrpEntry.IsPopulated() {
                            vips = vrrpEntry.Field["vip@"]
                        }

                        log.Info("vips:", vips)

                        if vrrp_rtr.Config.VirtualAddress != nil {

                            for vip_id := range vrrp_rtr.Config.VirtualAddress {
                                if (vips == "" || inParams.oper == DELETE) {
                                    vips =  vrrp_rtr.Config.VirtualAddress[vip_id]
                                } else {
                                    vips = vips + "," + vrrp_rtr.Config.VirtualAddress[vip_id]
                                }
                            }
                            t["vip@"] = vips
                        }

                        if vrrp_rtr.Config.Priority != nil {

                            base_priority := int(*vrrp_rtr.Config.Priority)

                            track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), "", true, false))

                            if base_priority + track_priority > 254 {
                                errStr := "VRRP instance priority and track priority exceeds 254"
                                log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                            }

                            t["priority"] = strconv.Itoa(int(*vrrp_rtr.Config.Priority))
                        }

                        if vrrp_rtr.Config.Preempt != nil {
                            if (bool(*vrrp_rtr.Config.Preempt)) {
                                t["pre_empt"] = "True"
                            } else {
                                t["pre_empt"] = "False"
                            }
                        }

                        if vrrp_rtr.Config.UseV2Checksum != nil {
                            if (bool(*vrrp_rtr.Config.UseV2Checksum)) {
                                t["use_v2_checksum"] = "True"
                            } else {
                                t["use_v2_checksum"] = "False"
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

                    if (vrrp_rtr.VrrpTrack != nil && vrrp_rtr.VrrpTrack.VrrpTrackInterface != nil) {


                        for track_if := range vrrp_rtr.VrrpTrack.VrrpTrackInterface {
                            vrrp_track_data := vrrp_rtr.VrrpTrack.VrrpTrackInterface[track_if]

                            log.Info("track if name:", track_if)

                            _trackifNativeName := utils.GetNativeNameFromUIName(&track_if)
                            trackifNativeName := *_trackifNativeName

                            log.Info("track if native name:", trackifNativeName)

                            track_table := make(map[string]string)
                            track_key := ifName + "|" + strconv.Itoa(int(virtual_router_id)) + "|" + trackifNativeName

                            if vrrp_track_data.Config != nil {

                                if vrrp_track_data.Config.PriorityIncrement != nil {
                                    if ifName == trackifNativeName {
                                        errStr := "VRRP track interface cannot be same as VRRP instance interface"
                                        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }

                                    base_priority := 100
                                    if vrrpEntry.Has("priority") {
                                        base_priority, _ = strconv.Atoi(vrrpEntry.Get("priority"))
                                    }
                                    new_priority := int(*vrrp_track_data.Config.PriorityIncrement)
                                    track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), trackifNativeName, true, true))

                                    if (base_priority + track_priority + new_priority) > 254 {
                                        errStr := "VRRP instance priority and track priority exceeds 254"
                                        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }

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

                    if ((inParams.oper != DELETE) || (inParams.oper == DELETE && !track_exist)) {
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
        for ip := range subIntfObj.Ipv6.Addresses.Address {
            addr := subIntfObj.Ipv6.Addresses.Address[ip]

            if addr.Vrrp != nil {

                log.Info("addr.Vrrp present")

                for virtual_router_id := range addr.Vrrp.VrrpGroup {
                    vrrp_rtr := addr.Vrrp.VrrpGroup[virtual_router_id]

                    t := make(map[string]string)
                    vrrp_key := ifName + "|" + strconv.Itoa(int(virtual_router_id))
                    vips := ""
                    vrrpEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"VRRP6"}, db.Key{Comp: []string{vrrp_key}})


                    if vrrp_rtr.Config != nil {

                        t["vrid"] = strconv.Itoa(int(virtual_router_id))

                        if vrrpEntry.IsPopulated() {
                            vips = vrrpEntry.Field["vip@"]
                        }

                        log.Info("vips:", vips)

                        if vrrp_rtr.Config.VirtualAddress != nil {

                            for vip_id := range vrrp_rtr.Config.VirtualAddress {
                                if (vips == "" || inParams.oper == DELETE) {
                                    vips =  vrrp_rtr.Config.VirtualAddress[vip_id]
                                } else {
                                    vips = vips + "," + vrrp_rtr.Config.VirtualAddress[vip_id]
                                }
                            }
                            t["vip@"] = vips
                        }

                        if vrrp_rtr.Config.Priority != nil {
                            base_priority := int(*vrrp_rtr.Config.Priority)

                            track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP6_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), "", true, false))

                            if base_priority + track_priority > 254 {
                                errStr := "VRRP instance priority and track priority exceeds 254"
                                log.Info("YangToDb_intf_vlan_vrrp_xfmr : " + errStr)
                                return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                            }
                            t["priority"] = strconv.Itoa(int(*vrrp_rtr.Config.Priority))
                        }

                        if vrrp_rtr.Config.Preempt != nil {
                            if (bool(*vrrp_rtr.Config.Preempt)) {
                                t["pre_empt"] = "True"
                            } else {
                                t["pre_empt"] = "False"
                            }
                        }

                        if vrrp_rtr.Config.AdvertisementInterval != nil {
                            t["adv_interval"] = strconv.Itoa(int(*vrrp_rtr.Config.AdvertisementInterval))
                        }

                        log.Info("In config : subIntfmap : ",  subIntfmap)

                    }

                    track_exist := false

                    if (vrrp_rtr.VrrpTrack != nil && vrrp_rtr.VrrpTrack.VrrpTrackInterface != nil) {

                        for track_if := range vrrp_rtr.VrrpTrack.VrrpTrackInterface {
                            vrrp_track_data := vrrp_rtr.VrrpTrack.VrrpTrackInterface[track_if]

                            log.Info("track if name:", track_if)

                            _trackifNativeName := utils.GetNativeNameFromUIName(&track_if)
                            trackifNativeName := *_trackifNativeName

                            log.Info("track if native name:", trackifNativeName)

                            track_table := make(map[string]string)
                            track_key := ifName + "|" + strconv.Itoa(int(virtual_router_id)) + "|" + trackifNativeName

                            if vrrp_track_data.Config != nil {

                                if vrrp_track_data.Config.PriorityIncrement != nil {

                                    if ifName == trackifNativeName {
                                        errStr := "VRRP track interface cannot be same as VRRP instance interface"
                                        log.Info("YangToDb_intf_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }

                                    base_priority := 100
                                    if vrrpEntry.Has("priority") {
                                        base_priority, _ = strconv.Atoi(vrrpEntry.Get("priority"))
                                    }
                                    new_priority := int(*vrrp_track_data.Config.PriorityIncrement)
                                    track_priority := int(getVrrpTrackPriority(inParams.d, nil, "VRRP6_TRACK", ifName, strconv.Itoa(int(virtual_router_id)), trackifNativeName, true, true))

                                    if (base_priority + track_priority + new_priority) > 254 {
                                        errStr := "VRRP instance priority and track priority exceeds 254"
                                        log.Info("YangToDb_intf_vlan_vrrp_xfmr : " + errStr)
                                        return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
                                    }
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

                    if ((inParams.oper != DELETE) || (inParams.oper == DELETE && !track_exist)) {
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

    log.Info("YangToDb_intf_vlan_vrrp_xfmr : subIntfmap : ",  subIntfmap)
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

    if (!ifup) {
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

    if strings.Contains(ifName, ".") {
        tblName = "PORT_TABLE"
    }

    _, err := dbCl.GetTable(&db.TableSpec{Name:tblName})

    if err != nil {
        return false
    }



    prtInst, _ := dbCl.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})
    log.Info("Portstatus:", prtInst)

    if strings.Contains(ifName, ".") {
        intfInst, _ := dbCl.GetEntry(&db.TableSpec{Name:"INTF_TABLE"}, db.Key{Comp: []string{ifName}})

        adminStatus := intfInst.Field[PORT_ADMIN_STATUS]

        if adminStatus != "up" {
            return false
        }
    } else {
        adminStatus := prtInst.Field[PORT_ADMIN_STATUS]

        if adminStatus != "up" {
            return false
        }
    }

    operStatus := prtInst.Field[PORT_OPER_STATUS]

    return operStatus == "up"
}

func getVrrpTrackPriority(cfg *db.DB, app *db.DB, tblName string, ifName string, vrid string, inTrackIf string, from_cfg bool, exclude_track bool) (uint8) {
    var track_priority uint8
    track_priority = 0

    log.Info("In getVrrpTrackPriority")
    vrrpTrackMap, _ := getVrrpTrackByName(cfg, tblName, ifName, vrid)

    for vrrpTrackKey, vrrpTrackData := range vrrpTrackMap {
        vrrpTrackKeySplit := strings.Split(vrrpTrackKey, "|")
        trackIfname := vrrpTrackKeySplit[2]

        if (exclude_track && (trackIfname == inTrackIf)) {
            continue
        }

        if from_cfg {
            priority, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
            track_priority += uint8(priority)
        } else {
            ifup := isIntfUp(app, trackIfname)
            if ifup {
                priority, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
                track_priority += uint8(priority)
            }
        }
    }

    return track_priority
}

func getVrrpOwnerPriority(d *db.DB, vrrpData db.Value, ifName string, isIpv6 bool) (priority uint8) {
    priority = 100
    var allIntfKeys []db.Key
    var vip_suffix string

    if vrrpData.Has("priority") {
        _priority, _ := strconv.Atoi(vrrpData.Get("priority"))
        priority = uint8(_priority)
    }

    if (!vrrpData.Has("vip@")) {
        return priority
    }

    vipStr := vrrpData.Get("vip@")
    vipMap := strings.Split(vipStr, ",")

    if isIpv6 {
        vip_suffix = "/128"
    } else {
        vip_suffix = "/32"
    }

    vip := vipMap[0] + vip_suffix

    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        return priority
    }

    ipA, _, perr := net.ParseCIDR(vip)
    if ipA == nil || perr != nil {
        return priority
    }

    for key := range IntfTypeTblMap {
        intTbl := IntfTypeTblMap[key]
        keys, err := d.GetKeys(&db.TableSpec{Name:intTbl.cfgDb.intfTN})
        if err != nil {
            log.Info("Failed to get keys; err=%v", err)
            return priority
        }
        allIntfKeys = append(allIntfKeys, keys...)
    }

    if len(allIntfKeys) > 0 {
        for _, key := range allIntfKeys {

            if len(key.Comp) < 2 {
                continue
            }

            if ifName != key.Get(0) {
                continue
            }

            ipB, _, perr := net.ParseCIDR(key.Get(1))
            //Check if key has IP, if not continue
            if ipB == nil || perr != nil {
                continue
            }

            if ipA.Equal(ipB) {
              priority = 255
              break
            }
        }
    }

    return priority
}

func handleVrrpGetByTargetURI (inParams XfmrParams, targetUriPath string, ifName string, intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface) error {
    vrrpMap := make(map[string]db.Value)
    var err error
    var isvrid bool

    log.Info("handleVrrpGetByTargetURI:", vrrpMap)
    pathInfo := NewPathInfo(inParams.uri)
    _idx := pathInfo.Var("index")
    temp_idx, _ := strconv.Atoi(_idx)
    idx := uint32(temp_idx)

    vrid := pathInfo.Var("virtual-router-id")
    if len(vrid) == 0 {
        isvrid = false
    } else {
        isvrid = true
    }

    intfType, _, ierr := getIntfTypeByName(ifName)

    if _idx != "0" {
        if strings.HasPrefix(ifName, "Ethernet") {
            ifName = strings.Replace(ifName, "Ethernet", "Eth", -1) + "." + _idx
        } else if strings.HasPrefix(ifName, "PortChannel") {
            ifName = strings.Replace(ifName, "PortChannel", "Po", -1) + "." + _idx
        }
    }

    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
        return errors.New(errStr)
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/config") ||
       strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/config") {

         vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
         log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
         convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, false, false, true, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/config") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/config") {

         vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
         log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
         convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, true, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, false, false, false, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/interface-tracking/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, false, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/vrrp/vrrp-group/config") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, false, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/config") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, true, false, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, false, true, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/vrrp/vrrp-group/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, true, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, true, true, true, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/vrrp/vrrp-group") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv4 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, true, true, true)
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/config") ||
       strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, false, false, true, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/interface/routed-vlan/ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/config") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, true, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, false, false, false, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/interface-tracking/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, false, false, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/config") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, true, false, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/vrrp/vrrp-group/config") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/config") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, false, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, false, true, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/vrrp/vrrp-group/state") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/state") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, false, true, false, false)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToOC(inParams, targetUriPath, ifName, idx, vrrpMap, intfObj, true, true, true, true)

    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/vrrp/vrrp-group") ||
              strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group") {

        vrrpMap, err = getVrrpByName(inParams.dbs[db.ConfigDB], "VRRP6", ifName, isvrid, vrid)
        log.Info("handleVrrpGetByTargetURI : ipv6 config vrrpMap - : ", vrrpMap)
        convertVrrpMapToVlanOC(inParams, targetUriPath, ifName, vrrpMap, intfObj, true, true, true, true)

    }

    log.Info("err:", err)
    return err
}


func convertVrrpMapToOC (inParams XfmrParams, targetUriPath string, ifName string, subintfid uint32, vrrpMap map[string]db.Value, ifInfo *ocbinds.OpenconfigInterfaces_Interfaces_Interface, isConfig bool, isState bool, isTrackConfig bool, isTrackState bool) error {
    var subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
    var err error
    var v4Flag bool
    var v4Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Addresses_Address
    var v6Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv6_Addresses_Address
    vrrpTrackMap := make(map[string]db.Value)

    v4Flag = false

    log.Info("convertVrrpMapToOC:", vrrpTrackMap)

    if _, ok := ifInfo.Subinterfaces.Subinterface[subintfid]; !ok {
        _, err = ifInfo.Subinterfaces.NewSubinterface(subintfid)
        if err != nil {
            log.Error("Creation of subinterface subtree failed!")
            return err
        }
    }

    subIntf = ifInfo.Subinterfaces.Subinterface[subintfid]
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
        return err
    }

    vrid64, err := strconv.ParseUint(vridStr, 10, 8)
    vrid := uint8(vrid64)

    if validIPv4(ipB) {
        if _, ok := subIntf.Ipv4.Addresses.Address[ipB]; !ok {
            v4Address, _ = subIntf.Ipv4.Addresses.NewAddress(ipB)
        } else {
            v4Address = subIntf.Ipv4.Addresses.Address[ipB]
        }
        v4Flag = true
    } else if validIPv6(ipB) {
        if _, ok := subIntf.Ipv6.Addresses.Address[ipB]; !ok {
            v6Address, _ = subIntf.Ipv6.Addresses.NewAddress(ipB)
        } else {
            v6Address = subIntf.Ipv6.Addresses.Address[ipB]
        }
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
            } else {
                vrrp4 = v4Address.Vrrp.VrrpGroup[vrid]
            }

            ygot.BuildEmptyTree(vrrp4)
            pvrid := new(uint8)
            *pvrid = vrid
            vrrp4.VirtualRouterId = pvrid
            var state uint8
            state = 0

            if isState {

              priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
              vrrp4.State.Priority = &priority

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
              if preemptstr == "True"{
                  *ppreempt = true
              } else {
                  *ppreempt = false
              }
              vrrp4.State.Preempt = ppreempt

              UseV2ChecksumStr := "False"
              if vrrpData.Has("use_v2_checksum") {
                  UseV2ChecksumStr = vrrpData.Get("use_v2_checksum")
              }

              UseV2Checksum := new(bool)
              if UseV2ChecksumStr == "True"{
                  *UseV2Checksum = true
              } else {
                  *UseV2Checksum = false
              }
              vrrp4.State.UseV2Checksum = UseV2Checksum

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
                priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
                vrrp4.Config.Priority = &priority

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
                if preemptstr == "True"{
                    *ppreempt = true
                } else {
                    *ppreempt = false
                }
                vrrp4.Config.Preempt = ppreempt

                UseV2ChecksumStr := "False"
                if vrrpData.Has("use_v2_checksum") {
                    UseV2ChecksumStr = vrrpData.Get("use_v2_checksum")
                }

                UseV2Checksum := new(bool)
                if UseV2ChecksumStr == "True"{
                    *UseV2Checksum = true
                } else {
                    *UseV2Checksum = false
                }
                vrrp4.Config.UseV2Checksum = UseV2Checksum

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

                    _trackIfUIName := utils.GetUINameFromNativeName(&trackIfname)
                    trackIfUIName := *_trackIfUIName

                    log.Info("trackIfname: ", trackIfname)
                    log.Info("trackIfUIname: ", trackIfUIName)

                    /*
                    if strings.Contains(trackIfUIName, ".") {
                        if strings.HasPrefix(trackIfUIName, "Eth") {
                            trackIfUIName = strings.Replace(trackIfUIName, "Eth", "Ethernet", -1)
                        } else if strings.HasPrefix(trackIfUIName, "po") {
                            trackIfUIName = strings.Replace(trackIfUIName, "po", "PortChannel", -1)
                        }
                    }
                    */

                    if _, ok := vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName]; !ok {
                        vrrp4.VrrpTrack.NewVrrpTrackInterface(trackIfUIName)
                    }

                    if vrrpTrackData.Has("priority_increment") {

                        ygot.BuildEmptyTree(vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName])


                        ppriority_increment := new(uint8)
                        ppriority_incr_state := new(uint8)
                        priority_increment, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
                        *ppriority_increment  = uint8(priority_increment)
                        *ppriority_incr_state  = uint8(priority_increment)

                        if (isTrackConfig) {
                            vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName].Config.PriorityIncrement = ppriority_increment
                        }

                        if (isTrackState) {

                            ifup := isIntfUp(inParams.dbs[db.ApplDB], trackIfname)
                            if !ifup {
                                *ppriority_incr_state = 0
                            }

                            vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName].State.PriorityIncrement = ppriority_incr_state
                        }

                        if (isTrackConfig) {
                            vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName].Config.PriorityIncrement = ppriority_increment
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
            } else {
                vrrp6 = v6Address.Vrrp.VrrpGroup[vrid]
            }


            ygot.BuildEmptyTree(vrrp6)
            pvrid := new(uint8)
            *pvrid = vrid
            vrrp6.VirtualRouterId = pvrid
            var state uint8
            state = 0

            if isState {

              priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
              vrrp6.State.Priority = &priority

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
              if preemptstr == "True"{
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
              priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
              vrrp6.Config.Priority = &priority

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
              if preemptstr == "True"{
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

                    _trackIfUIName := utils.GetUINameFromNativeName(&trackIfname)
                    trackIfUIName := *_trackIfUIName

                    log.Info("trackIfname: ", trackIfname)
                    log.Info("trackIfUIName: ", trackIfUIName)

                    /*
                    if strings.Contains(trackIfUIName, ".") {
                        if strings.HasPrefix(trackIfUIName, "Eth") {
                            trackIfUIName = strings.Replace(trackIfUIName, "Eth", "Ethernet", -1)
                        } else if strings.HasPrefix(trackIfUIName, "po") {
                            trackIfUIName = strings.Replace(trackIfUIName, "po", "PortChannel", -1)
                        }
                    }
                    */

                    if _, ok := vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName]; !ok {
                        vrrp6.VrrpTrack.NewVrrpTrackInterface(trackIfUIName)
                    }

                    if vrrpTrackData.Has("priority_increment") {

                        ygot.BuildEmptyTree(vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName])


                        ppriority_increment := new(uint8)
                        ppriority_incr_state := new(uint8)
                        priority_increment, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
                        *ppriority_increment  = uint8(priority_increment)
                        *ppriority_incr_state  = uint8(priority_increment)

                        if (isTrackConfig) {
                            vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName].Config.PriorityIncrement = ppriority_increment
                        }

                        if (isTrackState) {

                            ifup := isIntfUp(inParams.dbs[db.ApplDB], trackIfname)
                            if !ifup {
                                *ppriority_incr_state = 0
                            }

                            vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName].State.PriorityIncrement = ppriority_incr_state
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

func convertVrrpMapToVlanOC (inParams XfmrParams, targetUriPath string, ifName string, vrrpMap map[string]db.Value, ifInfo *ocbinds.OpenconfigInterfaces_Interfaces_Interface, isConfig bool, isState bool, isTrackConfig bool, isTrackState bool) error {
    var subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan
    var err error
    var v4Flag bool
    var v4Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Addresses_Address
    var v6Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv6_Addresses_Address
    vrrpTrackMap := make(map[string]db.Value)

    v4Flag = false

    log.Info("convertVrrpMapToVlanOC:", vrrpTrackMap)

    subIntf = ifInfo.RoutedVlan
    ygot.BuildEmptyTree(subIntf)

    pathInfo := NewPathInfo(inParams.uri)
    ipB := pathInfo.Var("ip")
    if len(ipB) == 0 {
        return err
    }


    vridStr := pathInfo.Var("virtual-router-id")
    if len(vridStr) == 0 {
        log.Info("Missing key in convertVrrpMapToVlanOC")
        return err
    }

    if len(vrrpMap) == 0 {
        log.Info("VRRP entry not present")
        return err
    }

    vrid64, err := strconv.ParseUint(vridStr, 10, 8)
    vrid := uint8(vrid64)

    if validIPv4(ipB) {
        if _, ok := subIntf.Ipv4.Addresses.Address[ipB]; !ok {
            v4Address, _ = subIntf.Ipv4.Addresses.NewAddress(ipB)
        } else {
            v4Address = subIntf.Ipv4.Addresses.Address[ipB]
        }
        v4Flag = true
    } else if validIPv6(ipB) {
        if _, ok := subIntf.Ipv6.Addresses.Address[ipB]; !ok {
            v6Address, _ = subIntf.Ipv6.Addresses.NewAddress(ipB)
        } else {
            v6Address = subIntf.Ipv6.Addresses.Address[ipB]
        }
    } else {
        log.Error("Invalid IP address " + ipB)
        return err
    }

    for _, vrrpData := range vrrpMap {

        if v4Flag {

            log.Info("for ipv4")

            var vrrp4 *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Addresses_Address_Vrrp_VrrpGroup

            if _, ok := v4Address.Vrrp.VrrpGroup[vrid]; !ok {
                vrrp4, err = v4Address.Vrrp.NewVrrpGroup(vrid)
            } else {
                vrrp4 = v4Address.Vrrp.VrrpGroup[vrid]
            }

            ygot.BuildEmptyTree(vrrp4)
            pvrid := new(uint8)
            *pvrid = vrid
            vrrp4.VirtualRouterId = pvrid
            var state uint8
            state = 0

            if isState {

              priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
              vrrp4.State.Priority = &priority

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
              if preemptstr == "True"{
                  *ppreempt = true
              } else {
                  *ppreempt = false
              }
              vrrp4.State.Preempt = ppreempt

              UseV2ChecksumStr := "False"
              if vrrpData.Has("use_v2_checksum") {
                  UseV2ChecksumStr = vrrpData.Get("use_v2_checksum")
              }

              UseV2Checksum := new(bool)
              if UseV2ChecksumStr == "True"{
                  *UseV2Checksum = true
              } else {
                  *UseV2Checksum = false
              }
              vrrp4.State.UseV2Checksum = UseV2Checksum


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
                priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
                vrrp4.Config.Priority = &priority

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
                if preemptstr == "True"{
                    *ppreempt = true
                } else {
                    *ppreempt = false
                }
                vrrp4.Config.Preempt = ppreempt

                UseV2ChecksumStr := "False"
                if vrrpData.Has("use_v2_checksum") {
                    UseV2ChecksumStr = vrrpData.Get("use_v2_checksum")
                }

                UseV2Checksum := new(bool)
                if UseV2ChecksumStr == "True"{
                    *UseV2Checksum = true
                } else {
                    *UseV2Checksum = false
                }
                vrrp4.Config.UseV2Checksum = UseV2Checksum

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

                    _trackIfUIName := utils.GetUINameFromNativeName(&trackIfname)
                    trackIfUIName := *_trackIfUIName

                    log.Info("trackIfname: ", trackIfname)
                    log.Info("trackIfUIname: ", trackIfUIName)

                    if _, ok := vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName]; !ok {
                        vrrp4.VrrpTrack.NewVrrpTrackInterface(trackIfUIName)
                    }

                    if vrrpTrackData.Has("priority_increment") {

                        ygot.BuildEmptyTree(vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName])


                        ppriority_increment := new(uint8)
                        ppriority_incr_state := new(uint8)
                        priority_increment, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
                        *ppriority_increment  = uint8(priority_increment)
                        *ppriority_incr_state  = uint8(priority_increment)

                        if (isTrackConfig) {
                            vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName].Config.PriorityIncrement = ppriority_increment
                        }

                        if (isTrackState) {

                            ifup := isIntfUp(inParams.dbs[db.ApplDB], trackIfname)
                            if !ifup {
                                *ppriority_incr_state = 0
                            }

                            vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName].State.PriorityIncrement = ppriority_incr_state
                        }

                        if (isTrackConfig) {
                            vrrp4.VrrpTrack.VrrpTrackInterface[trackIfUIName].Config.PriorityIncrement = ppriority_increment
                        }

                        log.Info("PriorityIncrement: ", ppriority_incr_state)
                    }
                }
            }
        } else {

            log.Info("for ipv6")

            var vrrp6 *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv6_Addresses_Address_Vrrp_VrrpGroup

            if _, ok := v6Address.Vrrp.VrrpGroup[vrid]; !ok {
                vrrp6, err = v6Address.Vrrp.NewVrrpGroup(vrid)
            } else {
                vrrp6 = v6Address.Vrrp.VrrpGroup[vrid]
            }


            ygot.BuildEmptyTree(vrrp6)
            pvrid := new(uint8)
            *pvrid = vrid
            vrrp6.VirtualRouterId = pvrid
            var state uint8
            state = 0

            if isState {

              priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
              vrrp6.State.Priority = &priority

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
              if preemptstr == "True"{
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
              priority := getVrrpOwnerPriority(inParams.d, vrrpData, ifName, false)
              vrrp6.Config.Priority = &priority

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
              if preemptstr == "True"{
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

                    _trackIfUIName := utils.GetUINameFromNativeName(&trackIfname)
                    trackIfUIName := *_trackIfUIName

                    log.Info("trackIfname: ", trackIfname)
                    log.Info("trackIfUIName: ", trackIfUIName)

                    if _, ok := vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName]; !ok {
                        vrrp6.VrrpTrack.NewVrrpTrackInterface(trackIfUIName)
                    }

                    if vrrpTrackData.Has("priority_increment") {

                        ygot.BuildEmptyTree(vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName])


                        ppriority_increment := new(uint8)
                        ppriority_incr_state := new(uint8)
                        priority_increment, _ := strconv.Atoi(vrrpTrackData.Get("priority_increment"))
                        *ppriority_increment  = uint8(priority_increment)
                        *ppriority_incr_state  = uint8(priority_increment)

                        if (isTrackConfig) {
                            vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName].Config.PriorityIncrement = ppriority_increment
                        }

                        if (isTrackState) {

                            ifup := isIntfUp(inParams.dbs[db.ApplDB], trackIfname)
                            if !ifup {
                                *ppriority_incr_state = 0
                            }

                            vrrp6.VrrpTrack.VrrpTrackInterface[trackIfUIName].State.PriorityIncrement = ppriority_incr_state
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
    targetUriPath, _ := getYangPathFromUri(inParams.uri)
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


    }

    _ifName := utils.GetNativeNameFromUIName(&intfName)
    ifName := *_ifName

    err = handleVrrpGetByTargetURI(inParams, targetUriPath, ifName, intfObj)

    log.Info("err:", err)

    if err != nil {
        return tlerr.NotFound("Resource Not Found")
    }
    return err
}

var DbToYang_intf_vlan_vrrp_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("name")
    targetUriPath, _ := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath is ", targetUriPath)
    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface

    log.Info("DbToYang_intf_vlan_vrrp_xfmr")

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan") {
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[intfName]; !ok {
                intfObj, _ = intfsObj.NewInterface(intfName)
            }
            ygot.BuildEmptyTree(intfObj)
            if intfObj.RoutedVlan == nil {
                ygot.BuildEmptyTree(intfObj.RoutedVlan)
            }
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(intfName)
            ygot.BuildEmptyTree(intfObj)
        }
    }

    _ifName := utils.GetNativeNameFromUIName(&intfName)
    ifName := *_ifName

    err = handleVrrpGetByTargetURI(inParams, targetUriPath, ifName, intfObj)

    log.Info("err:", err)

    if err != nil {
        return tlerr.NotFound("Resource Not Found")
    }
    return err
}

func vrrp_show_summary (body []byte, dbs [db.MaxDB]*db.DB, tableName string, trackTableName string) (result []byte, err error) {
    var vip_suffix string
    var isIpv6 bool

    log.Infof("Enter rpc_show_vrrp")

	  var VRRP_TABLE_TS *db.TableSpec = &db.TableSpec{Name: tableName}
    if tableName == "VRRP" {
        vip_suffix = "/32"
        isIpv6 = false
    } else {
        vip_suffix = "/128"
        isIpv6 = true
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

        ifName :=  key.Get(0)
        ifUIName := utils.GetUINameFromNativeName(&ifName)

        /*
        if strings.Contains(*ifUIName, ".") {

            if strings.HasPrefix(*ifUIName, "Eth") {
                *ifUIName = strings.Replace(*ifUIName, "Eth", "Ethernet", -1)
            } else if strings.HasPrefix(*ifUIName, "po") {
                *ifUIName = strings.Replace(*ifUIName, "po", "PortChannel", -1)
            }
        }
        */

        vrrpsummaryentry.Ifname = *ifUIName
        vrrpsummaryentry.Vrid, _ = strconv.Atoi(key.Get(1))

        priority := getVrrpOwnerPriority(dbs[db.ConfigDB], vrrpData, ifName, isIpv6)

        vrrpsummaryentry.ConfPrio = int(priority)
        vrrpsummaryentry.CurrPrio = int(priority)
        vrrpsummaryentry.CurrPrio += int(getVrrpTrackPriority(dbs[db.ConfigDB], dbs[db.ApplDB], trackTableName, key.Get(0), key.Get(1), "", false, false))

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

var Subscribe_intf_vrrp_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string
    var trackStr string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    idx := pathInfo.Var("index")

    if targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group" ||
       targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group" {
         tableName = "VRRP"
    } else if targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group" ||
              targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group" {
         tableName = "VRRP6"
    } else if targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/vrrp/vrrp-group/vrrp-track/vrrp-track-interface" ||
              targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/openconfig-interfaces-ext:vrrp-track/vrrp-track-interface" {
        tableName = "VRRP_TRACK"
        _trackIf := pathInfo.Var("track-intf")
        trackIf := utils.GetNativeNameFromUIName(&_trackIf)
        trackStr = "|" + *trackIf
    } else if targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/vrrp/vrrp-group/vrrp-track/vrrp-track-interface" ||
              targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/openconfig-interfaces-ext:vrrp-track/vrrp-track-interface" {
        tableName = "VRRP6_TRACK"
        _trackIf := pathInfo.Var("track-intf")
        trackIf := utils.GetNativeNameFromUIName(&_trackIf)
        trackStr = "|" + *trackIf
    } else {
        log.Infof("Subscribe attempted on unsupported path:%s; template:%s targetUriPath:%s", pathInfo.Path, pathInfo.Template, targetUriPath)
        return result, err
    }

    _ifName     := pathInfo.Var("name")
    vrId       := pathInfo.Var("virtual-router-id")

    ifName := utils.GetNativeNameFromUIName(&_ifName)

    if idx != "0" {
        // tblName = "VLAN_SUB_INTERFACE"

        if strings.HasPrefix(*ifName, "Ethernet") {
            *ifName = strings.Replace(*ifName, "Ethernet", "Eth", -1) + "." + idx
        } else if strings.HasPrefix(*ifName, "PortChannel") {
            *ifName = strings.Replace(*ifName, "PortChannel", "Po", -1) + "." + idx
        }
    }

    var redisKey string = *ifName + "|" + vrId + trackStr

    log.Info("redisKey:", tableName, *ifName, vrId, redisKey, trackStr)

    result.dbDataMap = make(RedisDbSubscribeMap)
    log.Infof("Subscribe_intf_vrrp_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, redisKey)

    result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{tableName:{redisKey:{}}}}   // tablename & table-idx for the inParams.uri
    result.needCache = true
    result.onChange = OnchangeEnable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

var Subscribe_intf_vlan_vrrp_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string
    var trackStr string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    if targetUriPath == "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/vrrp/vrrp-group" ||
       targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group" {
         tableName = "VRRP"
    } else if targetUriPath == "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/vrrp/vrrp-group" ||
              targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group" {
         tableName = "VRRP6"
    } else if targetUriPath == "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/vrrp/vrrp-group/vrrp-track/vrrp-track-interface" ||
              targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/vrrp/vrrp-group/openconfig-interfaces-ext:vrrp-track/vrrp-track-interface" {
        tableName = "VRRP_TRACK"
        _trackIf := pathInfo.Var("track-intf")
        trackIf := utils.GetNativeNameFromUIName(&_trackIf)
        trackStr = "|" + *trackIf
    } else if targetUriPath == "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/vrrp/vrrp-group/vrrp-track/vrrp-track-interface" ||
              targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/vrrp/vrrp-group/openconfig-interfaces-ext:vrrp-track/vrrp-track-interface" {
        tableName = "VRRP6_TRACK"
        _trackIf := pathInfo.Var("track-intf")
        trackIf := utils.GetNativeNameFromUIName(&_trackIf)
        trackStr = "|" + *trackIf
    } else {
        log.Infof("Subscribe attempted on unsupported path:%s; template:%s targetUriPath:%s", pathInfo.Path, pathInfo.Template, targetUriPath)
        return result, err
    }

    _ifName     := pathInfo.Var("name")
    vrId       := pathInfo.Var("virtual-router-id")

    ifName := utils.GetNativeNameFromUIName(&_ifName)
    var redisKey string = *ifName + "|" + vrId + trackStr

    log.Info("redisKey:", tableName, *ifName, vrId, redisKey, trackStr)

    result.dbDataMap = make(RedisDbSubscribeMap)
    log.Infof("Subscribe_intf_vlan_vrrp_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, redisKey)

    result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{tableName:{redisKey:{}}}}   // tablename & table-idx for the inParams.uri
    result.needCache = true
    result.onChange = OnchangeEnable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

func vrrp_alias_xfmr(inParams XfmrDbParams) (string, error) {
    if len(inParams.value) == 0 || !utils.IsAliasModeEnabled() {
        return inParams.value, nil
    }

    ifNameList := strings.Split(inParams.value, ",")
    log.Infof("vrrp_alias_xfmr:- Operation Type - %d Interface list - %s", inParams.oper, ifNameList)
    var aliasList []string
    for _, ifName := range ifNameList {
        var convertedName *string
        if inParams.oper == GET {
            convertedName = utils.GetUINameFromNativeName(&ifName)
        } else {
            convertedName = utils.GetNativeNameFromUIName(&ifName)
        }
        aliasList = append(aliasList, *convertedName)
    }
    return strings.Join(aliasList, ","), nil
}

