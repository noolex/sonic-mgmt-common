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
    "reflect"
	log "github.com/golang/glog"
    bmp "github.com/boljen/go-bitmap"
    "github.com/facette/natsort"
	"github.com/openconfig/ygot/ygot"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
)

const (
    STP_APP_DB_PORT_TABLE          = "_STP_PORT_TABLE"
    STP_APP_DB_VLAN_TABLE          = "_STP_VLAN_TABLE"
    STP_APP_DB_VLAN_PORT_TABLE     = "_STP_VLAN_PORT_TABLE"

    STP_DEFAULT_ROOT_GUARD_TIMEOUT = "30"
    STP_DEFAULT_FORWARD_DELAY      = "15"
    STP_DEFAULT_HELLO_INTERVAL     = "2"
    STP_DEFAULT_MAX_AGE            = "20"
    STP_DEFAULT_BRIDGE_PRIORITY    = "32768"
    STP_DEFAULT_BPDU_FILTER        = "false"
    STP_DEFAULT_LOOP_GUARD         = "false"
    STP_DEFAULT_PORTFAST           = "false"
)

func init() {
    XlateFuncBind("YangToDb_stp_global_xfmr", YangToDb_stp_global_xfmr)
    XlateFuncBind("DbToYang_stp_global_xfmr", DbToYang_stp_global_xfmr)

    //XlateFuncBind("YangToDb_stp_vlan_key_xfmr", YangToDb_stp_vlan_key_xfmr)
    //XlateFuncBind("DbToYang_stp_vlan_key_xfmr", DbToYang_stp_vlan_key_xfmr)
    XlateFuncBind("YangToDb_stp_vlan_xfmr", YangToDb_stp_vlan_xfmr)
    XlateFuncBind("DbToYang_stp_vlan_xfmr", DbToYang_stp_vlan_xfmr)
    XlateFuncBind("Subscribe_stp_vlan_xfmr", Subscribe_stp_vlan_xfmr)

    XlateFuncBind("YangToDb_stp_port_xfmr", YangToDb_stp_port_xfmr)
    XlateFuncBind("DbToYang_stp_port_xfmr", DbToYang_stp_port_xfmr)
    XlateFuncBind("Subscribe_stp_port_xfmr", Subscribe_stp_port_xfmr)

    XlateFuncBind("YangToDb_stp_vlan_port_xfmr", YangToDb_stp_vlan_port_xfmr)
    XlateFuncBind("DbToYang_stp_vlan_port_xfmr", DbToYang_stp_vlan_port_xfmr)
    XlateFuncBind("Subscribe_stp_vlan_port_xfmr", Subscribe_stp_vlan_port_xfmr)
    XlateFuncBind("stp_pre_xfmr", stp_pre_xfmr)
}

var g_stpSupported interface{}

func is_stp_feature_supported() bool {
    var applDbPtr, _ = db.NewDB(getDBOptions(db.ApplDB))
    defer applDbPtr.DeleteDB()	

    switchTableEntry, err := applDbPtr.GetEntry(&db.TableSpec{Name: "SWITCH_TABLE"}, db.Key{[]string{"switch"}})
    if err != nil {
        return false
    }

    return switchTableEntry.Has("stp_supported")
}


var stp_pre_xfmr PreXfmrFunc = func(inParams XfmrParams) (error) {
    if g_stpSupported == nil {
        g_stpSupported = is_stp_feature_supported()
    }

    if g_stpSupported == false {
        return tlerr.NotSupported("Spanning-tree is not supported with this software package")
    }
    return nil
}


func getStpRoot (s *ygot.GoStruct) *ocbinds.OpenconfigSpanningTree_Stp {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.Stp
}

/*
func getMaxStpInstances() (int, error) {

    dbs, err := getAllDbs(true)
    if err != nil {
        return 0, err
    }
    defer closeAllDbs(dbs[:])

    stateDB := dbs[db.StateDB]
    stpStateDbEntry, err := stateDB.GetEntry(&db.TableSpec{Name: STP_STATE_TABLE}, db.Key{[]string{"GLOBAL"}})
    if err != nil {
        return 0, err
    }
    max_inst, err := strconv.Atoi((&stpStateDbEntry).Get("max_stp_inst"))
    if err != nil {
        return 0, err
    }
    log.Infof("Hardware Supported Max Stp Instances: %d", max_inst)
    if max_inst > PVST_MAX_INSTANCES {
        max_inst = PVST_MAX_INSTANCES
    }

    return max_inst, nil
}
*/

func check_max_stp_limit_reached(d *db.DB, vlanIdList []int) error {
    var configEnableVlanMap map[string]bool = make(map[string]bool)
    totalStpVlans := 0

    for _, vlanId := range vlanIdList {
        vlanName := "Vlan"+strconv.Itoa(int(vlanId))
        if !isVlanCreated(d, vlanName) {
            log.Infof("check_max_stp_limit_reached: Vlan %s is not configured", vlanName)
            return tlerr.NotFound("Vlan %s is not configured", vlanName)
        }

        configEnableVlanMap[vlanName] = true
        totalStpVlans++
    }

    if totalStpVlans == 0 {
        // nothing to enable
        return nil
    }

    max_stp_instances, err := getMaxStpInstances()
    if err != nil {
        log.Info("getMaxStpInstances Failed : ",err)
        return err
    }

    stpVlanTable, err := d.GetTable(&db.TableSpec{Name: STP_VLAN_TABLE})
    if err != nil {
        return err
    }
    stpVlanKeys, err := stpVlanTable.GetKeys()
    if err != nil {
        return err
    }
    
    for i := range stpVlanKeys {
        stpVlanDBEntry, err := stpVlanTable.GetEntry(stpVlanKeys[i])
        if err == nil && (&stpVlanDBEntry).Get("enabled") == "true" {
            if _, ok := configEnableVlanMap[stpVlanKeys[i].Get(0)]; !ok {
                //increment only if its not enabled in config
                totalStpVlans++
            }
        }
    }

    if totalStpVlans > max_stp_instances {
        log.Infof("Error - exceeds MAX_STP_INST(%d), disable atleast %d vlans", max_stp_instances, (totalStpVlans - max_stp_instances))
        return tlerr.NotSupported("Error - exceeds maximum spanning-tree instances(%d) supported, disable STP for atleast %d vlans", max_stp_instances, (totalStpVlans - max_stp_instances))
    }

    return nil
}

func getStpModeFromConfigDb(d *db.DB) (string, error) {
    stpGlobalDbEntry, err := d.GetEntry(&db.TableSpec{Name: STP_GLOBAL_TABLE}, db.Key{[]string{"GLOBAL"}})
    if err != nil {
        return "", err
    }
    return (&stpGlobalDbEntry).Get("mode"), nil
}

func convertOcStpModeToInternal(mode ocbinds.E_OpenconfigSpanningTreeTypes_STP_PROTOCOL) string {
    switch mode {
        case ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_MSTP:
            return "mstp"
        case ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_PVST:
            return "pvst"
        case ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_RAPID_PVST:
            return "rpvst"
        case ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_RSTP:
            return "rstp"
        default:
            return ""
    }
}

func convertInternalStpModeToOc(mode string) []ocbinds.E_OpenconfigSpanningTreeTypes_STP_PROTOCOL {
    var stpModes []ocbinds.E_OpenconfigSpanningTreeTypes_STP_PROTOCOL
    if len(mode) > 0 {
        switch mode {
        case "pvst":
            stpModes = append(stpModes, ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_PVST)
        case "rpvst":
            stpModes = append(stpModes, ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_RAPID_PVST)
        case "mstp":
            stpModes = append(stpModes, ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_MSTP)
        case "rstp":
            stpModes = append(stpModes, ocbinds.OpenconfigSpanningTreeTypes_STP_PROTOCOL_RSTP)
        }
    }
    return stpModes
}

func isVlanMember(d *db.DB, vlanName string, ifName string) (bool) {
    _, err := d.GetEntry(&db.TableSpec{Name: "VLAN_MEMBER"}, db.Key{[]string{vlanName, ifName}})
    return err == nil
}



func getAllInterfacesFromVlanMemberTable(d *db.DB) ([]string, error) {
    var intfList []string

    keys, err := d.GetKeys(&db.TableSpec{Name: "VLAN_MEMBER"})
    if err != nil {
        return intfList, err
    }
    for i := range keys {
        key := keys[i]
        if !contains(intfList, (&key).Get(1)) {
            intfList = append(intfList, (&key).Get(1))
        }
    }
    return intfList, err
}

func enableStpMode(d *db.DB, mode string, stpGlobalMap map[string]string, stpPortMap map[string]db.Value, stpVlanMap map[string]db.Value) error {
    var err error

    err = enableStpForInterfaces(d, mode, stpPortMap)
    if err != nil {
        return err
    }

    err = enableStpForVlans(d, stpGlobalMap, stpVlanMap)

    return err
}

func enableStpForInterfaces(d *db.DB, mode string, stpPortMap map[string]db.Value) error {
    defaultDBValues := db.Value{Field: map[string]string{}}
    (&defaultDBValues).Set("enabled", "true")
    (&defaultDBValues).Set("root_guard", "false")
    (&defaultDBValues).Set("bpdu_guard", "false")
    (&defaultDBValues).Set("bpdu_filter", "global")
    (&defaultDBValues).Set("bpdu_guard_do_disable", "false")
    (&defaultDBValues).Set("portfast", "false")
    (&defaultDBValues).Set("uplink_fast", "false")
    if mode == "rpvst" {
        (&defaultDBValues).Set("link_type", "auto")
        (&defaultDBValues).Set("loop_guard", "false")
    }

    portList, err := getAllInterfacesFromVlanMemberTable(d)
    if err != nil {
        return err
    }

    for i := range portList {
        stpPortMap[portList[i]] = defaultDBValues
    }

    log.Info("enableStpForInterfaces stpPortMap:", stpPortMap)
    return err
}

func enableStpForVlans(d *db.DB, stpGlobalMap map[string]string, stpVlanMap map[string]db.Value) error {
    fwdDelay  := stpGlobalMap["forward_delay"]
    helloTime := stpGlobalMap["hello_time"]
    maxAge    := stpGlobalMap["max_age"]
    priority  := stpGlobalMap["priority"]

    vlanKeys, err := d.GetKeys(&db.TableSpec{Name: "VLAN"})
    if err != nil {
        return err
    }

    max_stp_instances, err := getMaxStpInstances()
    if err != nil {
        log.Info("getMaxStpInstances Failed : ",err)
        return tlerr.NotSupported("Operation Not Supported")
    }

    totalVlansCount := len(vlanKeys)
    if totalVlansCount > max_stp_instances {
        // when STP is getting enabled globally,
        // disabledVlansCount = number of entries in STP_VLAN_TABLE
        stpDisabledVlanKeys, _ := d.GetKeys(&db.TableSpec{Name: STP_VLAN_TABLE})
        disabledVlansCount := len(stpDisabledVlanKeys)
        if (totalVlansCount - disabledVlansCount) > max_stp_instances {
            log.Infof("Exceeds MAX_STP_INSTANCE(%d), Disable STP on %d Vlans", max_stp_instances, (totalVlansCount - disabledVlansCount - max_stp_instances))
            return tlerr.NotSupported("Error - exceeds maximum spanning-tree instances(%d) supported, disable STP for atleast %d vlans", max_stp_instances, (totalVlansCount - disabledVlansCount - max_stp_instances))
        }
    }

    var vlanList []string
    for i := range vlanKeys {
        vlanKey := vlanKeys[i]
        _, err := d.GetEntry(&db.TableSpec{Name: STP_VLAN_TABLE}, vlanKey)
        if err != nil {
            // append to vlan list only for non-existing entries
            vlanList = append(vlanList, (&vlanKey).Get(0))
        }
    }

    // Sort vlanList in natural order such that 'Vlan2' < 'Vlan10'
    natsort.Sort(vlanList)

    for i := range vlanList {
        if i < max_stp_instances {
            defaultDBValues := db.Value{Field: map[string]string{}}
            (&defaultDBValues).Set("enabled", "true")
            (&defaultDBValues).Set("forward_delay", fwdDelay)
            (&defaultDBValues).Set("hello_time", helloTime)
            (&defaultDBValues).Set("max_age", maxAge)
            (&defaultDBValues).Set("priority", priority)

            stpVlanMap[vlanList[i]] = defaultDBValues
        }
    }

    log.Info("enableStpForVlans stpVlanMap:", stpVlanMap)
    return err
}

func updateStpGlobalDataToVlans (d *db.DB, stpGlobalMap map[string]string, stpVlanMap map[string]db.Value) error {
    stpGlobalDBEntry, err := d.GetEntry(&db.TableSpec{Name: STP_GLOBAL_TABLE}, db.Key{[]string{"GLOBAL"}})
    if err != nil {
        return err
    }

    stpVlanKeys, err := d.GetKeys(&db.TableSpec{Name: STP_VLAN_TABLE})
    if err != nil {
        return err
    }

    for i := range stpVlanKeys {
        stpVlanEntry, _ := d.GetEntry(&db.TableSpec{Name: STP_VLAN_TABLE}, stpVlanKeys[i])

        updateStpVlan := false
        for fld := range stpGlobalMap {
            if fld != "rootguard_timeout" && fld != "bpdu_filter" && fld != "loop_guard" && fld != "portfast" {
                if (&stpVlanEntry).Get(fld) == (&stpGlobalDBEntry).Get(fld) {
                    (&stpVlanEntry).Set(fld, stpGlobalMap[fld])
                    updateStpVlan = true
                }
            }
        }

        if updateStpVlan {
            stpVlanMap[stpVlanKeys[i].Get(0)] = stpVlanEntry 
        }
    }

    log.Info("updateStpGlobalDataToVlans stpVlanMap:", stpVlanMap)
    return nil
}

func handleStpGlobalDeletion(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    log.Info("handleStpGlobalDeletion targetUriPath: ", targetUriPath)

    if targetUriPath == "/openconfig-spanning-tree:stp/global" ||
       targetUriPath == "/openconfig-spanning-tree:stp/global/config" ||
       targetUriPath == "/openconfig-spanning-tree:stp/global/config/enabled-protocol" {
        resMap[STP_VLAN_PORT_TABLE] = nil 
        resMap[STP_VLAN_TABLE] = nil 
        resMap[STP_PORT_TABLE] = nil 
        resMap[STP_GLOBAL_TABLE] = nil 
        return resMap, err
    }

    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subResMap := make(map[string]map[string]db.Value)
    subResMap[STP_GLOBAL_TABLE] = make(map[string]db.Value)
    stpGlobalMap := make(map[string]string)
    stpVlanMap := make(map[string]db.Value)

    stpGlobalDBEntry, err := inParams.d.GetEntry(&db.TableSpec{Name: STP_GLOBAL_TABLE}, db.Key{[]string{"GLOBAL"}})
    if err != nil {
        return nil, tlerr.NotSupported("STP not enabled Globally") 
    }

    xpath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)

    var fldName, valStr string
    if strings.HasSuffix(xpath, "disabled-vlans") {
        fldName = "disabled-vlans"
        stp := getStpRoot(inParams.ygRoot)
        if stp == nil || stp.Global == nil || stp.Global.Config == nil || stp.Global.Config.DisabledVlans == nil {
            log.Info("handleStpGlobalDeletion: stp is empty")
            return nil, errors.New("Stp is not specified")
        }

        var vlanIdList []int
        if len(stp.Global.Config.DisabledVlans) != 0 {
            vlanIdList, err = convertOcStpDisabledVlansToInternal(stp.Global.Config.DisabledVlans)
            if err != nil {
                log.Info("handleStpGlobalDeletion: STP Disabled VLANs fetch failed")
                return nil, errors.New("STP Disabled VLANs fetch failed")
            }
        } else {
            // basically enable STP for all VLANs
            vlanIdList, _ = getAllStpDisabledVlansList(inParams.d)
            if err != nil {
                log.Info("handleStpGlobalDeletion: STP Disabled VLANs fetch failed")
                return nil, errors.New("STP Disabled VLANs fetch failed")
            }
        }

        err = check_max_stp_limit_reached(inParams.d, vlanIdList)
        if err != nil {
            return nil, err
        }

        var mandatoryFields = [4]string{"forward_delay", "hello_time", "max_age", "priority"} 

        for _, vlanId := range vlanIdList {
            vlanName := "Vlan"+strconv.Itoa(int(vlanId))
            stpVlanEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: STP_VLAN_TABLE}, db.Key{[]string{vlanName}})
            stpVlanModEntry := db.Value{Field: map[string]string{}}
            (&stpVlanModEntry).Set("enabled", "true")

            for _,field := range mandatoryFields {
                if !stpVlanEntry.Has(field) {
                    (&stpVlanModEntry).Set(field, (&stpGlobalDBEntry).Get(field))
                }
            }

            stpVlanMap[vlanName] = stpVlanModEntry
        }
    } 

    if strings.HasSuffix(xpath, "rootguard-timeout") {
        fldName = "rootguard_timeout"
        valStr = STP_DEFAULT_ROOT_GUARD_TIMEOUT
    }

    if strings.HasSuffix(xpath, "hello-time") {
        fldName = "hello_time"
        valStr = STP_DEFAULT_HELLO_INTERVAL
    }

    if strings.HasSuffix(xpath, "max-age") {
        fldName = "max_age"
        valStr = STP_DEFAULT_MAX_AGE
    }

    if strings.HasSuffix(xpath, "forwarding-delay") {
        fldName = "forward_delay"
        valStr = STP_DEFAULT_FORWARD_DELAY
    }

    if strings.HasSuffix(xpath, "bridge-priority") {
        fldName = "priority"
        valStr = STP_DEFAULT_BRIDGE_PRIORITY
    }

    if strings.HasSuffix(xpath, "bpdu-filter") {
        fldName = "bpdu_filter"
        valStr = STP_DEFAULT_BPDU_FILTER
    }

    if strings.HasSuffix(xpath, "loop-guard") {
        fldName = "loop_guard"
        valStr = STP_DEFAULT_LOOP_GUARD
    }

    if strings.HasSuffix(xpath, "portfast") {
        fldName = "portfast"
        valStr = STP_DEFAULT_PORTFAST
    }

    
    if fldName != "disabled-vlans" {
        stpGlobalMap[fldName] = valStr
    }

    if fldName != "rootguard_timeout" && fldName != "bpdu_filter" && fldName != "disabled-vlans" {
        stpVlanKeys, err := inParams.d.GetKeys(&db.TableSpec{Name: STP_VLAN_TABLE})
        if err != nil {
            return nil, err
        }

        for i := range stpVlanKeys {
            stpVlanEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: STP_VLAN_TABLE}, stpVlanKeys[i])

            if (&stpVlanEntry).Get(fldName) == (&stpGlobalDBEntry).Get(fldName) {
                (&stpVlanEntry).Set(fldName, stpGlobalMap[fldName])
            }
    
            stpVlanMap[stpVlanKeys[i].Get(0)] = stpVlanEntry
        }
    }

    if len(stpGlobalMap) != 0 {
        subResMap[STP_GLOBAL_TABLE]["GLOBAL"] = db.Value{Field: stpGlobalMap}
    }

    if len(stpVlanMap) != 0 {
        subResMap[STP_VLAN_TABLE] = stpVlanMap
    }

    subOpMap[db.ConfigDB] = subResMap
    log.Info("handleStpGlobalDeletion subOpMap: ", subOpMap)
    inParams.subOpDataMap[UPDATE] = &subOpMap
    return resMap, err
}

// This API returns Disabled VLANs List
func getAllStpDisabledVlansList(d *db.DB) ([]int, error) {
    var disabledStpVlanIdList []int = nil
    stpVlanTable, err := d.GetTable(&db.TableSpec{Name: STP_VLAN_TABLE})
    if err != nil {
        return disabledStpVlanIdList, err
    }

    stpVlanTableKeys, err := stpVlanTable.GetKeys()
    if err != nil {
        return disabledStpVlanIdList, err
    }
    
    for i := range stpVlanTableKeys {
        stpVlanEntry, err := stpVlanTable.GetEntry(stpVlanTableKeys[i])
        if err == nil && (&stpVlanEntry).Get("enabled") == "false" {
            vlanName := stpVlanTableKeys[i].Get(0)
            vlanId, _ := strconv.Atoi(strings.Replace(vlanName, "Vlan", "", 1))
            disabledStpVlanIdList = append(disabledStpVlanIdList, vlanId)
        }
    }

    return disabledStpVlanIdList, nil
}

// This API returns Disabled VLANs in OC format with range (.. , )
func getStpDisabledVlansRangeList(d *db.DB) ([]string) {
    var stpVlanList []string

    stpVlanTable, err := d.GetTable(&db.TableSpec{Name: STP_VLAN_TABLE})
    if err != nil {
        log.Info("getStpDisabledVlansRangeList : error in fetch of STP_VLAN_TABLE")
        return nil
    }

    stpVlanTablekeys, err := stpVlanTable.GetKeys()
    if err != nil {
        log.Info("getStpDisabledVlansRangeList : STP_VLAN_TABLE keys error")
        return nil
    }
    
    numSetBits := 0
    vlanBmp := bmp.New(4096)
    for i := range stpVlanTablekeys {
        stpVlanEntry, err := stpVlanTable.GetEntry(stpVlanTablekeys[i])
        if err != nil {
            log.Info("getStpDisabledVlansRangeList : STP_VLAN_TABLE entry fetch failed")
            return nil
        }
        
        if is_enabled, _ := strconv.ParseBool((&stpVlanEntry).Get("enabled")); !is_enabled {
            vlanId, _ := strconv.Atoi(strings.Replace(stpVlanTablekeys[i].Comp[0], "Vlan", "", 1))
            vlanBmp.Set(vlanId, true)
            numSetBits++
        }
    }

    stpVlanList = convertVlanBmpToVlanRangeUnionList(vlanBmp, numSetBits)

    log.Info("getStpDisabledVlansRangeList: stpVlanList: ", stpVlanList)
    return stpVlanList
}

func convertVlanBmpToVlanRangeUnionList(vlanBmp bmp.Bitmap, numSetBits int)  []string {
    var vlanRangeList []string
    vlanStart := 0
    vlanBmpLen := vlanBmp.Len()

    if numSetBits == 0 {
        return vlanRangeList
    }

    if numSetBits == -1 {
        numSetBits = vlanBmpLen
    }

    i := 0
    for i=1;i<vlanBmpLen; i++ {
        if numSetBits == 0 {
            break
        }
        
        if vlanBmp.Get(i) {
            numSetBits--
            if vlanStart == 0 {
                vlanStart = i
            }
        } else {
            if vlanStart != 0 {
                vlanEnd := i-1
                if vlanStart != vlanEnd {
                    vlanRangeList = append(vlanRangeList, strconv.Itoa(vlanStart)+".."+strconv.Itoa(vlanEnd))
                } else {
                    vlanRangeList = append(vlanRangeList, strconv.Itoa(vlanStart))
                }
                vlanStart = 0
                vlanEnd = 0
            }
        }
    }

    if vlanStart != 0 {
        vlanEnd := i-1
        if vlanStart != vlanEnd {
            vlanRangeList = append(vlanRangeList, strconv.Itoa(vlanStart)+".."+strconv.Itoa(vlanEnd))
        } else {
            vlanRangeList = append(vlanRangeList, strconv.Itoa(vlanStart))
        }
    }

    return vlanRangeList
}

func convertOcStpDisabledVlansToInternal (ocVlanList []ocbinds.OpenconfigSpanningTree_Stp_Global_Config_DisabledVlans_Union)  ([]int, error) {
    var vlanIdList []int

    if ocVlanList == nil {
        return vlanIdList, nil
    }

    for _, item := range ocVlanList {
        vlanType := reflect.TypeOf(item).Elem()
        switch vlanType {
            case reflect.TypeOf(ocbinds.OpenconfigSpanningTree_Stp_Global_Config_DisabledVlans_Union_String{}):
                vlanStr := item.(*ocbinds.OpenconfigSpanningTree_Stp_Global_Config_DisabledVlans_Union_String)
                if strings.Contains(vlanStr.String, "..") {
                    vlanRangeStr := strings.Split( vlanStr.String, "..")
                
                    vlanStart, err := strconv.Atoi(vlanRangeStr[0])
                    if err != nil {
                        return nil , tlerr.InvalidArgs("Invalid Input %s", err)
                    }
                    vlanEnd, err := strconv.Atoi(vlanRangeStr[1])
                    if err != nil {
                        return nil , tlerr.InvalidArgs("Invalid Input %s", err)
                    }
    
                    for i:=vlanStart; i<=vlanEnd; i++ {
                        vlanIdList = append(vlanIdList, i)
                    }
                } else {
                    // workaround : infra sometimes sends "100" as a string instead of int
                    vlanId, _ := strconv.Atoi(vlanStr.String)
                    vlanIdList = append(vlanIdList, vlanId)
                }

            case reflect.TypeOf(ocbinds.OpenconfigSpanningTree_Stp_Global_Config_DisabledVlans_Union_Uint16{}):
                vlanIdList = append(vlanIdList, int(item.(*ocbinds.OpenconfigSpanningTree_Stp_Global_Config_DisabledVlans_Union_Uint16).Uint16))
        }
    }
    return vlanIdList, nil
}

func convertInternalStpDisabledVlansToOc(stpGlobal *ocbinds.OpenconfigSpanningTree_Stp_Global, stpDisabledVlanList []string, isConfig bool) {
    for _,item := range stpDisabledVlanList {
        if strings.Contains(item, "..") {
            if isConfig {
                configDisabledVlansUnion, _ := stpGlobal.Config.To_OpenconfigSpanningTree_Stp_Global_Config_DisabledVlans_Union(item)
                stpGlobal.Config.DisabledVlans = append(stpGlobal.Config.DisabledVlans, configDisabledVlansUnion)
            } else {
                stateDisabledVlansUnion, _ := stpGlobal.State.To_OpenconfigSpanningTree_Stp_Global_State_DisabledVlans_Union(item)
                stpGlobal.State.DisabledVlans = append(stpGlobal.State.DisabledVlans, stateDisabledVlansUnion)
            }
        } else {
            vlanId, _ := strconv.Atoi(item)
            if isConfig {
                configDisabledVlansUnion, _ := stpGlobal.Config.To_OpenconfigSpanningTree_Stp_Global_Config_DisabledVlans_Union(uint16(vlanId))
                stpGlobal.Config.DisabledVlans = append(stpGlobal.Config.DisabledVlans, configDisabledVlansUnion)
            } else {
                stateDisabledVlansUnion, _ := stpGlobal.State.To_OpenconfigSpanningTree_Stp_Global_State_DisabledVlans_Union(uint16(vlanId))
                stpGlobal.State.DisabledVlans = append(stpGlobal.State.DisabledVlans, stateDisabledVlansUnion)
            }
        }
    }
}

func convertOcStpGlobalToInternal(stpGlobalConf *ocbinds.OpenconfigSpanningTree_Stp_Global_Config, stpGlobalMap map[string]string, stpVlanMap map[string]db.Value, mode string, cfgMode string, setDefaultFlag bool) error {
    var err error

    if stpGlobalConf.BridgePriority != nil {
        priorityVal := int(*stpGlobalConf.BridgePriority)
        if (priorityVal % 4096) != 0 {
            return tlerr.InvalidArgs("Priority value should be multiple of 4096")
        }
        stpGlobalMap["priority"] = strconv.Itoa(priorityVal)
    } else if setDefaultFlag {
        stpGlobalMap["priority"] = STP_DEFAULT_BRIDGE_PRIORITY 
    }
    
    if stpGlobalConf.ForwardingDelay != nil {
        stpGlobalMap["forward_delay"] = strconv.Itoa(int(*stpGlobalConf.ForwardingDelay))
    } else if setDefaultFlag {
        stpGlobalMap["forward_delay"] = STP_DEFAULT_FORWARD_DELAY
    }

    if stpGlobalConf.HelloTime != nil {
        stpGlobalMap["hello_time"] = strconv.Itoa(int(*stpGlobalConf.HelloTime))
    } else if setDefaultFlag {
        stpGlobalMap["hello_time"] = STP_DEFAULT_HELLO_INTERVAL
    }

    if stpGlobalConf.MaxAge != nil {
        stpGlobalMap["max_age"] = strconv.Itoa(int(*stpGlobalConf.MaxAge))
    } else if setDefaultFlag {
        stpGlobalMap["max_age"] = STP_DEFAULT_MAX_AGE
    }

    if stpGlobalConf.RootguardTimeout != nil {
        stpGlobalMap["rootguard_timeout"] = strconv.Itoa(int(*stpGlobalConf.RootguardTimeout))
    } else if setDefaultFlag {
        stpGlobalMap["rootguard_timeout"] = STP_DEFAULT_ROOT_GUARD_TIMEOUT
    }

    if stpGlobalConf.BpduFilter != nil {
        if *stpGlobalConf.BpduFilter {
            stpGlobalMap["bpdu_filter"] = "true" 
        } else {
            stpGlobalMap["bpdu_filter"] = "false" 
        }
    } else if setDefaultFlag {
        stpGlobalMap["bpdu_filter"] = STP_DEFAULT_BPDU_FILTER
    }

    if stpGlobalConf.LoopGuard != nil {
        if *stpGlobalConf.LoopGuard {
            stpGlobalMap["loop_guard"] = "true" 
        } else {
            stpGlobalMap["loop_guard"] = "false" 
        }
    } else if setDefaultFlag {
        if mode == "rpvst" || cfgMode == "rpvst" {
            stpGlobalMap["loop_guard"] = STP_DEFAULT_LOOP_GUARD
        }
    }

    if stpGlobalConf.Portfast != nil {
        if *stpGlobalConf.Portfast {
            stpGlobalMap["portfast"] = "true" 
        } else {
            stpGlobalMap["portfast"] = "false" 
        }
    } else if setDefaultFlag {
        if mode == "pvst" || cfgMode == "pvst" {
            stpGlobalMap["portfast"] = STP_DEFAULT_PORTFAST
        }
    }

    if stpGlobalConf.DisabledVlans != nil && len(stpGlobalConf.DisabledVlans) != 0 {
        vlanIdList, _ := convertOcStpDisabledVlansToInternal(stpGlobalConf.DisabledVlans)

        for _, vlanId := range vlanIdList {
            vlanName := "Vlan"+strconv.Itoa(int(vlanId))
            disabledVlanEntry := db.Value{Field: map[string]string{}}
            (&disabledVlanEntry).Set("enabled", "false")
            stpVlanMap[vlanName] = disabledVlanEntry
        }
    }
    return err
}

func convertInternalStpGlobalToOc(d *db.DB, targetUriPath string, stpGlobal *ocbinds.OpenconfigSpanningTree_Stp_Global)error {
    var err error

    stpGlobalEntry, _ := d.GetEntry(&db.TableSpec{Name: STP_GLOBAL_TABLE}, db.Key{[]string{"GLOBAL"}})
    stpDisabledVlanList := getStpDisabledVlansRangeList(d)

    if stpGlobal != nil {

        var num uint64
        num, _ = strconv.ParseUint(stpGlobalEntry.Get("priority"), 10, 32)
        priority := uint32(num)

        num, _ = strconv.ParseUint(stpGlobalEntry.Get("forward_delay"), 10, 8)
        fwdDelay := uint8(num)

        num, _ = strconv.ParseUint(stpGlobalEntry.Get("hello_time"), 10, 8)
        helloTime := uint8(num)

        num, _ = strconv.ParseUint(stpGlobalEntry.Get("max_age"), 10, 8)
        maxAge := uint8(num)

        num, _ = strconv.ParseUint(stpGlobalEntry.Get("rootguard_timeout"), 10, 16)
        rootGTimeout := uint16(num)

        bpduFilter, _ := strconv.ParseBool(stpGlobalEntry.Get("bpdu_filter"))
        loopGuard, _ := strconv.ParseBool(stpGlobalEntry.Get("loop_guard"))
        portFast, _ := strconv.ParseBool(stpGlobalEntry.Get("portfast"))


        ygot.BuildEmptyTree(stpGlobal)

        if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/global/config") {
            stpGlobal.Config.EnabledProtocol = convertInternalStpModeToOc(stpGlobalEntry.Get("mode"))
            stpGlobal.Config.BridgePriority = &priority
            stpGlobal.Config.ForwardingDelay = &fwdDelay
            stpGlobal.Config.HelloTime = &helloTime
            stpGlobal.Config.MaxAge = &maxAge
            stpGlobal.Config.RootguardTimeout = &rootGTimeout
            stpGlobal.Config.BpduFilter = &bpduFilter
            stpGlobal.Config.LoopGuard = &loopGuard
            stpGlobal.Config.Portfast = &portFast
            convertInternalStpDisabledVlansToOc(stpGlobal, stpDisabledVlanList, true)
        } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/global/state") {
            stpGlobal.State.EnabledProtocol = convertInternalStpModeToOc(stpGlobalEntry.Get("mode"))
            stpGlobal.State.BridgePriority = &priority
            stpGlobal.State.ForwardingDelay = &fwdDelay
            stpGlobal.State.HelloTime = &helloTime
            stpGlobal.State.MaxAge = &maxAge
            stpGlobal.State.RootguardTimeout = &rootGTimeout
            stpGlobal.State.BpduFilter = &bpduFilter
            stpGlobal.State.LoopGuard = &loopGuard
            stpGlobal.State.Portfast = &portFast
            convertInternalStpDisabledVlansToOc(stpGlobal, stpDisabledVlanList, false)
        } else {
            stpGlobal.Config.EnabledProtocol = convertInternalStpModeToOc(stpGlobalEntry.Get("mode"))
            stpGlobal.Config.BridgePriority = &priority
            stpGlobal.Config.ForwardingDelay = &fwdDelay
            stpGlobal.Config.HelloTime = &helloTime
            stpGlobal.Config.MaxAge = &maxAge
            stpGlobal.Config.RootguardTimeout = &rootGTimeout
            stpGlobal.Config.BpduFilter = &bpduFilter
            stpGlobal.Config.LoopGuard = &loopGuard
            stpGlobal.Config.Portfast = &portFast
            convertInternalStpDisabledVlansToOc(stpGlobal, stpDisabledVlanList, true)

            stpGlobal.State.EnabledProtocol = convertInternalStpModeToOc(stpGlobalEntry.Get("mode"))
            stpGlobal.State.BridgePriority = &priority
            stpGlobal.State.ForwardingDelay = &fwdDelay
            stpGlobal.State.HelloTime = &helloTime
            stpGlobal.State.MaxAge = &maxAge
            stpGlobal.State.RootguardTimeout = &rootGTimeout
            stpGlobal.State.BpduFilter = &bpduFilter
            stpGlobal.State.LoopGuard = &loopGuard
            stpGlobal.State.Portfast = &portFast
            convertInternalStpDisabledVlansToOc(stpGlobal, stpDisabledVlanList, false)
        }
    }

    log.Info("convertInternalStpGlobalToOc config: ", stpGlobal.Config)
    log.Info("convertInternalStpGlobalToOc state: ", stpGlobal.State)
    return err
}

var YangToDb_stp_global_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)
    stpGlobalMap := make(map[string]string)
    stpPortMap := make(map[string]db.Value)
    stpVlanMap := make(map[string]db.Value)

    if inParams.oper == DELETE {
        resMap, err = handleStpGlobalDeletion(inParams) 
        log.Info("YangToDb_stp_global_xfmr resMap: ", resMap)
        return resMap, err
    }

    stp := getStpRoot(inParams.ygRoot)
	if stp == nil || stp.Global == nil || stp.Global.Config == nil {
		log.Info("YangToDb_stp_global_xfmr: stp is empty")
		return nil, errors.New("Stp is not specified")
	}

    if len(stp.Global.Config.EnabledProtocol) > 1 {
		log.Info("YangToDb_stp_proto_mode_xfmr: multiple mode not supported")
		return nil, errors.New("Multiple mode not supported")
    }

    var mode string
    if stp.Global.Config.EnabledProtocol != nil {
        mode = convertOcStpModeToInternal(stp.Global.Config.EnabledProtocol[0])
    }

    cfgMode, _ := getStpModeFromConfigDb(inParams.d)
    if mode != "" && cfgMode != "" && cfgMode != mode {
        return nil, tlerr.InvalidArgs("STP mode is configured as %s", cfgMode)
    }

    setDefaultFlag := (inParams.oper == CREATE || inParams.oper == REPLACE)

    err = convertOcStpGlobalToInternal(stp.Global.Config, stpGlobalMap, stpVlanMap, mode, cfgMode, setDefaultFlag)
    if err != nil {
        return nil, err
    }

    switch inParams.oper {
        case CREATE:
            if len(cfgMode) == 0 && mode != "" {
                stpGlobalMap["mode"] = mode
                err = enableStpMode(inParams.d, mode, stpGlobalMap, stpPortMap, stpVlanMap)
                if err != nil {
                    return nil, err
                }
            }
        case REPLACE, UPDATE:
            if len(cfgMode) == 0 && mode != "" {
                stpGlobalMap["mode"] = mode
                err = enableStpMode(inParams.d, mode, stpGlobalMap, stpPortMap, stpVlanMap)
                if err != nil {
                    return nil, err
                }
            } else {
                updateStpGlobalDataToVlans(inParams.d, stpGlobalMap, stpVlanMap) 
            }
    }

    if len(stpGlobalMap) != 0 {
        resMap[STP_GLOBAL_TABLE] = make(map[string]db.Value)
        resMap[STP_GLOBAL_TABLE]["GLOBAL"] = db.Value{Field: stpGlobalMap}
    }

    if len(stpPortMap) != 0 {
        resMap[STP_PORT_TABLE] = stpPortMap
    }
        
    if len(stpVlanMap) != 0 {
        resMap[STP_VLAN_TABLE] = stpVlanMap
    }

    log.Info("YangToDb_stp_global_xfmr resMap: ", resMap)
    return resMap, err
}

var DbToYang_stp_global_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    stp := getStpRoot(inParams.ygRoot)
    if stp == nil {
        log.Info("Stp is nil")
        ygot.BuildEmptyTree(stp)
    }

    err = convertInternalStpGlobalToOc(inParams.d, targetUriPath, stp.Global)
    return err
}

func isVlanCreated(d *db.DB, vlanName string) bool{
    _, err := d.GetEntry(&db.TableSpec{Name: "VLAN"}, db.Key{[]string{vlanName}})
    return err == nil
}

func convertOcRpvstVlanToInternal(rpvstVlanConf *ocbinds.OpenconfigSpanningTree_Stp_RapidPvst_Vlan, stpVlanMap map[string]string, setDefaultFlag bool) error {
    var err error
    
    if rpvstVlanConf.Config != nil {
        if rpvstVlanConf.Config.BridgePriority != nil {
            priorityVal := int(*rpvstVlanConf.Config.BridgePriority)
            if (priorityVal % 4096) != 0 {
                return tlerr.InvalidArgs("Priority value should be multiple of 4096")
            }
            stpVlanMap["priority"] = strconv.Itoa(priorityVal)
        } else if setDefaultFlag {
            stpVlanMap["priority"] = STP_DEFAULT_BRIDGE_PRIORITY 
        }
        
        if rpvstVlanConf.Config.ForwardingDelay != nil {
            stpVlanMap["forward_delay"] = strconv.Itoa(int(*rpvstVlanConf.Config.ForwardingDelay))
        } else if setDefaultFlag {
            stpVlanMap["forward_delay"] = STP_DEFAULT_FORWARD_DELAY
        }

        if rpvstVlanConf.Config.HelloTime != nil {
            stpVlanMap["hello_time"] = strconv.Itoa(int(*rpvstVlanConf.Config.HelloTime)) 
        } else if setDefaultFlag {
            stpVlanMap["hello_time"] = STP_DEFAULT_HELLO_INTERVAL
        }

        if rpvstVlanConf.Config.MaxAge != nil {
            stpVlanMap["max_age"] = strconv.Itoa(int(*rpvstVlanConf.Config.MaxAge)) 
        } else if setDefaultFlag {
            stpVlanMap["max_age"] = STP_DEFAULT_MAX_AGE
        }
    }

    return err
}

func convertOcPvstVlanToInternal(pvstVlanConf *ocbinds.OpenconfigSpanningTree_Stp_Pvst_Vlan, stpVlanMap map[string]string, setDefaultFlag bool) error {
    var err error
    
    if pvstVlanConf.Config != nil {
        if pvstVlanConf.Config.BridgePriority != nil {
            priorityVal := int(*pvstVlanConf.Config.BridgePriority)
            if (priorityVal % 4096) != 0 {
                return tlerr.InvalidArgs("Priority value should be multiple of 4096")
            }
            stpVlanMap["priority"] = strconv.Itoa(priorityVal)
        } else if setDefaultFlag {
            stpVlanMap["priority"] = STP_DEFAULT_BRIDGE_PRIORITY 
        }
        
        if pvstVlanConf.Config.ForwardingDelay != nil {
            stpVlanMap["forward_delay"] = strconv.Itoa(int(*pvstVlanConf.Config.ForwardingDelay))
        } else if setDefaultFlag {
            stpVlanMap["forward_delay"] = STP_DEFAULT_FORWARD_DELAY
        }

        if pvstVlanConf.Config.HelloTime != nil {
            stpVlanMap["hello_time"] = strconv.Itoa(int(*pvstVlanConf.Config.HelloTime)) 
        } else if setDefaultFlag {
            stpVlanMap["hello_time"] = STP_DEFAULT_HELLO_INTERVAL
        }

        if pvstVlanConf.Config.MaxAge != nil {
            stpVlanMap["max_age"] = strconv.Itoa(int(*pvstVlanConf.Config.MaxAge)) 
        } else if setDefaultFlag {
            stpVlanMap["max_age"] = STP_DEFAULT_MAX_AGE
        }
    }

    return err
}

func handleStpVlanDeletion(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    var vlanName string
    if len(pathInfo.Var("vlan-id")) > 0 {
        vlanName = "Vlan" + pathInfo.Var("vlan-id")
    }

    log.Info("handleStpVlanDeletion targetUriPath: ", targetUriPath)

    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subResMap := make(map[string]map[string]db.Value)
    subResMap[STP_VLAN_TABLE] = make(map[string]db.Value)
    stpVlanMap := make(map[string]string)

    if inParams.requestUri == "/openconfig-spanning-tree:stp" { 
        log.Info("handleStpVlanDeletion Parent level delete Request URI: ", inParams.requestUri)
        return nil, nil
    }

    stpGlobalDBEntry, err := inParams.d.GetEntry(&db.TableSpec{Name: STP_GLOBAL_TABLE}, db.Key{[]string{"GLOBAL"}})
    if err != nil {
        return nil, err
    }

    fwdDelay := (&stpGlobalDBEntry).Get("forward_delay")
    helloTime := (&stpGlobalDBEntry).Get("hello_time")
    maxAge := (&stpGlobalDBEntry).Get("max_age")
    priority := (&stpGlobalDBEntry).Get("priority")

    xpath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)

    if strings.HasSuffix(xpath, "hello-time") {
        stpVlanMap["hello_time"] = helloTime 
    }

    if strings.HasSuffix(xpath, "max-age") {
        stpVlanMap["max_age"] = maxAge 
    }
            
    if strings.HasSuffix(xpath, "bridge-priority") {
        stpVlanMap["priority"] = priority 
    }

    if strings.HasSuffix(xpath, "forwarding-delay") {
        stpVlanMap["forward_delay"] = fwdDelay 
    }

    mode, _ := getStpModeFromConfigDb(inParams.d)
    if vlanName == "" {
        stp := getStpRoot(inParams.ygRoot)

        if isSubtreeRequest(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst") {
            if mode != "rpvst" {
                return nil, nil 
            }
            for vlanId := range stp.RapidPvst.Vlan {
                vlanName = "Vlan"+strconv.Itoa(int(vlanId))
                if !isVlanCreated(inParams.d, vlanName) {
                    log.Infof("handleStpVlanDeletion: Vlan %s is not configured", vlanName)
                    return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
                }
                subResMap[STP_VLAN_TABLE][vlanName] = db.Value{Field: stpVlanMap}
            }
        } else if isSubtreeRequest(targetUriPath, "/openconfig-spanning-tree:stp/openconfig-spanning-tree-ext:pvst") {
            if mode != "pvst" {
                return nil, nil 
            }
            for vlanId := range stp.Pvst.Vlan {
                vlanName = "Vlan"+strconv.Itoa(int(vlanId))
                if !isVlanCreated(inParams.d, vlanName) {
                    log.Infof("handleStpVlanDeletion: Vlan %s is not configured", vlanName)
                    return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
                }
                subResMap[STP_VLAN_TABLE][vlanName] = db.Value{Field: stpVlanMap}
            }
        }
    } else {
        if !isVlanCreated(inParams.d, vlanName) {
            log.Infof("handleStpVlanDeletion: Vlan %s is not configured", vlanName)
            return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
        }
        subResMap[STP_VLAN_TABLE][vlanName] = db.Value{Field: stpVlanMap}
    }

    subOpMap[db.ConfigDB] = subResMap
    log.Info("handleStpVlanDeletion subOpMap: ", subOpMap)
    inParams.subOpDataMap[UPDATE] = &subOpMap

    return resMap, err
}

func convertInternalRpvstVlanToOc(inParams XfmrParams, vlanName string, targetUriPath string, rpvstVlanConf *ocbinds.OpenconfigSpanningTree_Stp_RapidPvst_Vlan) {
    rpvstVlanData, err := inParams.d.GetEntry(&db.TableSpec{Name: STP_VLAN_TABLE}, db.Key{[]string{vlanName}})
    if err != nil {
        log.Info("convertInternalRpvstVlanToOc: Error in retrieving STP_VLAN_TABLE for : ", vlanName)
    }

    rpvstAppDbVlanData, err := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name: STP_APP_DB_VLAN_TABLE}, db.Key{[]string{vlanName}})
    if err != nil {
        log.Info("convertInternalRpvstVlanToOc: Error in retrieving APP STP_VLAN_TABLE for : ", vlanName)
    }

    var stpEnabled bool
    var num uint64
    var priority uint32
    var fwdDelay uint8
    var helloTime uint8
    var maxAge uint8
    vlanId, _ := strconv.Atoi(strings.Replace(vlanName, "Vlan", "", 1))
    vlan := uint16(vlanId)

    if rpvstVlanData.IsPopulated() {
        stpEnabled, _ = strconv.ParseBool((&rpvstVlanData).Get("enabled"))
        num, _ = strconv.ParseUint((&rpvstVlanData).Get("priority"), 10, 32)
        priority = uint32(num)
        num, _ = strconv.ParseUint((&rpvstVlanData).Get("forward_delay"), 10, 8)
        fwdDelay = uint8(num)
        num, _ = strconv.ParseUint((&rpvstVlanData).Get("hello_time"), 10, 8)
        helloTime = uint8(num)
        num, _ = strconv.ParseUint((&rpvstVlanData).Get("max_age"), 10, 8)
        maxAge = uint8(num)
    }

    //APP DB
    var opMaxAge uint8
    var opHelloTime uint8
    var opForwardDelay uint8
    var opHoldTime uint8
    var opRootMaxAge uint8
    var opRootHelloTime uint8
    var opRootForwardDelay uint8
    var opStpInstance uint16
    var opRootCost uint32
    var opLastTopologyChange uint64
    var opTopologyChanges uint64
    var bridgeId string
    var desigRootAddr string
    var desigBridgeId string
    var rootPortStr string
    var rootPortUIName string
    if rpvstAppDbVlanData.IsPopulated() {
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("max_age"), 10, 8)
        opMaxAge = uint8(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("hello_time"), 10, 8)
        opHelloTime = uint8(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("forward_delay"), 10, 8)
        opForwardDelay = uint8(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("hold_time"), 10, 8)
        opHoldTime = uint8(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("root_max_age"), 10, 8)
        opRootMaxAge = uint8(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("root_hello_time"), 10, 8)
        opRootHelloTime = uint8(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("root_forward_delay"), 10, 8)
        opRootForwardDelay = uint8(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("stp_instance"), 10, 16)
        opStpInstance = uint16(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("root_path_cost"), 10, 32)
        opRootCost = uint32(num)
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("last_topology_change"), 10, 64)
        opLastTopologyChange = num
        num, _ = strconv.ParseUint((&rpvstAppDbVlanData).Get("topology_change_count"), 10, 64)
        opTopologyChanges = num
        bridgeId = (&rpvstAppDbVlanData).Get("bridge_id")
        desigRootAddr = (&rpvstAppDbVlanData).Get("root_bridge_id")
        desigBridgeId = (&rpvstAppDbVlanData).Get("desig_bridge_id")
        rootPortStr = (&rpvstAppDbVlanData).Get("root_port")
        rootPortUIName = *(utils.GetUINameFromNativeName(&rootPortStr))
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst/vlan/config") {
        rpvstVlanConf.Config.VlanId = &vlan
        //rpvstVlanConf.Config.SpanningTreeEnable = &stpEnabled
        rpvstVlanConf.Config.BridgePriority = &priority
        rpvstVlanConf.Config.ForwardingDelay = &fwdDelay
        rpvstVlanConf.Config.HelloTime = &helloTime
        rpvstVlanConf.Config.MaxAge = &maxAge
    } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst/vlan/state") {
        rpvstVlanConf.State.VlanId = &vlan
        rpvstVlanConf.State.SpanningTreeEnable = &stpEnabled
        rpvstVlanConf.State.BridgePriority = &priority
        rpvstVlanConf.State.MaxAge = &opMaxAge
        rpvstVlanConf.State.HelloTime = &opHelloTime
        rpvstVlanConf.State.ForwardingDelay = &opForwardDelay
        rpvstVlanConf.State.HoldTime = &opHoldTime
        rpvstVlanConf.State.RootMaxAge = &opRootMaxAge
        rpvstVlanConf.State.RootHelloTime = &opRootHelloTime
        rpvstVlanConf.State.RootForwardDelay = &opRootForwardDelay
        rpvstVlanConf.State.StpInstance = &opStpInstance
        rpvstVlanConf.State.RootCost = &opRootCost
        rpvstVlanConf.State.LastTopologyChange = &opLastTopologyChange
        rpvstVlanConf.State.TopologyChanges = &opTopologyChanges
        rpvstVlanConf.State.BridgeAddress = &bridgeId
        rpvstVlanConf.State.DesignatedRootAddress = &desigRootAddr
        rpvstVlanConf.State.DesignatedBridgeId = &desigBridgeId
        rpvstVlanConf.State.RootPortName = &rootPortUIName
    } else {
        rpvstVlanConf.Config.VlanId = &vlan
        //rpvstVlanConf.Config.SpanningTreeEnable = &stpEnabled
        rpvstVlanConf.Config.BridgePriority = &priority
        rpvstVlanConf.Config.ForwardingDelay = &fwdDelay
        rpvstVlanConf.Config.HelloTime = &helloTime
        rpvstVlanConf.Config.MaxAge = &maxAge

        rpvstVlanConf.State.VlanId = &vlan
        rpvstVlanConf.State.SpanningTreeEnable = &stpEnabled
        rpvstVlanConf.State.BridgePriority = &priority
        rpvstVlanConf.State.MaxAge = &opMaxAge
        rpvstVlanConf.State.HelloTime = &opHelloTime
        rpvstVlanConf.State.ForwardingDelay = &opForwardDelay
        rpvstVlanConf.State.HoldTime = &opHoldTime
        rpvstVlanConf.State.RootMaxAge = &opRootMaxAge
        rpvstVlanConf.State.RootHelloTime = &opRootHelloTime
        rpvstVlanConf.State.RootForwardDelay = &opRootForwardDelay
        rpvstVlanConf.State.StpInstance = &opStpInstance
        rpvstVlanConf.State.RootCost = &opRootCost
        rpvstVlanConf.State.LastTopologyChange = &opLastTopologyChange
        rpvstVlanConf.State.TopologyChanges = &opTopologyChanges
        rpvstVlanConf.State.BridgeAddress = &bridgeId
        rpvstVlanConf.State.DesignatedRootAddress = &desigRootAddr
        rpvstVlanConf.State.DesignatedBridgeId = &desigBridgeId
        rpvstVlanConf.State.RootPortName = &rootPortUIName
    }

    log.Info("convertInternalRpvstVlanToOc config:", rpvstVlanConf.Config)
    log.Info("convertInternalRpvstVlanToOc state:", rpvstVlanConf.State)
}

func convertInternalPvstVlanToOc(inParams XfmrParams, vlanName string, targetUriPath string, pvstVlanConf *ocbinds.OpenconfigSpanningTree_Stp_Pvst_Vlan) {
    pvstVlanData, err := inParams.d.GetEntry(&db.TableSpec{Name: STP_VLAN_TABLE}, db.Key{[]string{vlanName}})
    if err != nil {
        log.Info("convertInternalPvstVlanToOc: Error in retrieving STP_VLAN_TABLE for : ", vlanName)
    }
    
    stpAppDbVlanData, err := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name: STP_APP_DB_VLAN_TABLE}, db.Key     {[]string{vlanName}})
    if err != nil {
        log.Info("convertInternalPvstVlanToOc: Error in retrieving APP STP_VLAN_TABLE for : ", vlanName)
    }

    var stpEnabled bool
    var num uint64
    var priority uint32
    var fwdDelay uint8
    var helloTime uint8
    var maxAge uint8
    vlanId, _ := strconv.Atoi(strings.Replace(vlanName, "Vlan", "", 1))
    vlan := uint16(vlanId)

    if pvstVlanData.IsPopulated() {
        stpEnabled, _ = strconv.ParseBool((&pvstVlanData).Get("enabled"))
        num, _ = strconv.ParseUint((&pvstVlanData).Get("priority"), 10, 32)
        priority = uint32(num)
        num, _ = strconv.ParseUint((&pvstVlanData).Get("forward_delay"), 10, 8)
        fwdDelay = uint8(num)
        num, _ = strconv.ParseUint((&pvstVlanData).Get("hello_time"), 10, 8)
        helloTime = uint8(num)
        num, _ = strconv.ParseUint((&pvstVlanData).Get("max_age"), 10, 8)
        maxAge = uint8(num)
    }

    //APP DB
    var opMaxAge uint8
    var opHelloTime uint8
    var opForwardDelay uint8
    var opHoldTime uint8
    var opRootMaxAge uint8
    var opRootHelloTime uint8
    var opRootForwardDelay uint8
    var opStpInstance uint16
    var opRootCost uint32
    var opLastTopologyChange uint64
    var opTopologyChanges uint64
    var bridgeId string
    var desigRootAddr string
    var desigBridgeId string
    var rootPortStr string
    var rootPortUIName string
    if stpAppDbVlanData.IsPopulated() {
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("max_age"), 10, 8)
        opMaxAge = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("hello_time"), 10, 8)
        opHelloTime = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("forward_delay"), 10, 8)
        opForwardDelay = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("hold_time"), 10, 8)
        opHoldTime = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("root_max_age"), 10, 8)
        opRootMaxAge = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("root_hello_time"), 10, 8)
        opRootHelloTime = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("root_forward_delay"), 10, 8)
        opRootForwardDelay = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("stp_instance"), 10, 16)
        opStpInstance = uint16(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("root_path_cost"), 10, 32)
        opRootCost = uint32(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("last_topology_change"), 10, 64)
        opLastTopologyChange = num
        num, _ = strconv.ParseUint((&stpAppDbVlanData).Get("topology_change_count"), 10, 64)
        opTopologyChanges = num
        bridgeId = (&stpAppDbVlanData).Get("bridge_id")
        desigRootAddr = (&stpAppDbVlanData).Get("root_bridge_id")
        desigBridgeId = (&stpAppDbVlanData).Get("desig_bridge_id")
        rootPortStr = (&stpAppDbVlanData).Get("root_port")
        rootPortUIName = *(utils.GetUINameFromNativeName(&rootPortStr))
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/pvst/vlan/config") {
        pvstVlanConf.Config.VlanId = &vlan
        //pvstVlanConf.Config.SpanningTreeEnable = &stpEnabled
        pvstVlanConf.Config.BridgePriority = &priority
        pvstVlanConf.Config.ForwardingDelay = &fwdDelay
        pvstVlanConf.Config.HelloTime = &helloTime
        pvstVlanConf.Config.MaxAge = &maxAge
    } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/pvst/vlan/state") {
        pvstVlanConf.State.VlanId = &vlan
        pvstVlanConf.State.SpanningTreeEnable = &stpEnabled
        pvstVlanConf.State.BridgePriority = &priority
        pvstVlanConf.State.MaxAge = &opMaxAge
        pvstVlanConf.State.HelloTime = &opHelloTime
        pvstVlanConf.State.ForwardingDelay = &opForwardDelay
        pvstVlanConf.State.HoldTime = &opHoldTime
        pvstVlanConf.State.RootMaxAge = &opRootMaxAge
        pvstVlanConf.State.RootHelloTime = &opRootHelloTime
        pvstVlanConf.State.RootForwardDelay = &opRootForwardDelay
        pvstVlanConf.State.StpInstance = &opStpInstance
        pvstVlanConf.State.RootCost = &opRootCost
        pvstVlanConf.State.LastTopologyChange = &opLastTopologyChange
        pvstVlanConf.State.TopologyChanges = &opTopologyChanges
        pvstVlanConf.State.BridgeAddress = &bridgeId
        pvstVlanConf.State.DesignatedRootAddress = &desigRootAddr
        pvstVlanConf.State.DesignatedBridgeId = &desigBridgeId
        pvstVlanConf.State.RootPortName = &rootPortUIName
    } else {
        pvstVlanConf.Config.VlanId = &vlan
        //pvstVlanConf.Config.SpanningTreeEnable = &stpEnabled
        pvstVlanConf.Config.BridgePriority = &priority
        pvstVlanConf.Config.ForwardingDelay = &fwdDelay
        pvstVlanConf.Config.HelloTime = &helloTime
        pvstVlanConf.Config.MaxAge = &maxAge

        pvstVlanConf.State.VlanId = &vlan
        pvstVlanConf.State.SpanningTreeEnable = &stpEnabled
        pvstVlanConf.State.BridgePriority = &priority
        pvstVlanConf.State.MaxAge = &opMaxAge
        pvstVlanConf.State.HelloTime = &opHelloTime
        pvstVlanConf.State.ForwardingDelay = &opForwardDelay
        pvstVlanConf.State.HoldTime = &opHoldTime
        pvstVlanConf.State.RootMaxAge = &opRootMaxAge
        pvstVlanConf.State.RootHelloTime = &opRootHelloTime
        pvstVlanConf.State.RootForwardDelay = &opRootForwardDelay
        pvstVlanConf.State.StpInstance = &opStpInstance
        pvstVlanConf.State.RootCost = &opRootCost
        pvstVlanConf.State.LastTopologyChange = &opLastTopologyChange
        pvstVlanConf.State.TopologyChanges = &opTopologyChanges
        pvstVlanConf.State.BridgeAddress = &bridgeId
        pvstVlanConf.State.DesignatedRootAddress = &desigRootAddr
        pvstVlanConf.State.DesignatedBridgeId = &desigBridgeId
        pvstVlanConf.State.RootPortName = &rootPortUIName
    }

    log.Info("convertInternalPvstVlanToOc config:", pvstVlanConf.Config)
    log.Info("convertInternalPvstVlanToOc state:", pvstVlanConf.State)
}

var YangToDb_stp_vlan_key_xfmr = func(inParams XfmrParams) (string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    stpVlanKey := pathInfo.Var("vlan-id")
    if stpVlanKey != "" {
        stpVlanKey = "Vlan" + pathInfo.Var("vlan-id")
    }
    log.Info("YangToDb_stp_vlan_key_xfmr stpVlanKey: ", stpVlanKey)
	return stpVlanKey, nil
}

var DbToYang_stp_vlan_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    resMap := make(map[string]interface{})

    resMap["vlan-id"], _ = strconv.Atoi(strings.Replace(inParams.key, "Vlan", "", 1))
    log.Info("DbToYang_stp_vlan_key_xfmr: key: ", inParams.key, " resMap: ", resMap)
    return resMap, nil
}

var Subscribe_stp_vlan_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    keyName := "Vlan" + pathInfo.Var("vlan-id")

    log.Info("Subscribe_stp_vlan_xfmr: TargetURI: ", targetUriPath, " Key: ", keyName)

    if (keyName != "") {
        result.dbDataMap = RedisDbMap{db.ConfigDB:{STP_VLAN_TABLE:{keyName:{}}}}
    } else {
        errStr := "STP VLAN not present in request"
        log.Info("Subscribe_stp_vlan_xfmr: " + errStr)
    
        return result, errors.New(errStr)
    }

    result.isVirtualTbl = false
    log.Info("Subscribe_stp_vlan_xfmr resultMap:", result.dbDataMap)
    return result, err
}

var YangToDb_stp_vlan_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)
    stpVlanMap := make(map[string]string)

    if inParams.oper == DELETE {
        resMap, err = handleStpVlanDeletion(inParams)
        log.Info("YangToDb_stp_vlan_xfmr resMap: ", resMap)
        return resMap, err
    }

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    var vlanName string
    if len(pathInfo.Var("vlan-id")) > 0 {
        vlanName = "Vlan" + pathInfo.Var("vlan-id")
    }

    stp := getStpRoot(inParams.ygRoot)

    mode, _ := getStpModeFromConfigDb(inParams.d)
    log.Info("YangToDb_stp_vlan_xfmr targetUriPath: ", targetUriPath, " mode: ", mode, " vlanName:", vlanName)

    setDefaultFlag := (inParams.oper == CREATE || inParams.oper == REPLACE)

    if isSubtreeRequest(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst") {
        if mode != "rpvst" {
            return nil, nil 
        }

        if stp == nil || stp.RapidPvst == nil || stp.RapidPvst.Vlan == nil {
            log.Info("YangToDb_stp_vlan_xfmr: stp is empty")
            return nil, errors.New("Stp is not specified")
        }
        
        if vlanName == "" {
            for vlanId := range stp.RapidPvst.Vlan {
                vlanName = "Vlan"+strconv.Itoa(int(vlanId))
                if !isVlanCreated(inParams.d, vlanName) {
                    log.Infof("YangToDb_stp_vlan_xfmr: Vlan %s is not configured", vlanName)
                    return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
                }

                if stp.RapidPvst.Vlan[uint16(vlanId)] != nil && stp.RapidPvst.Vlan[uint16(vlanId)].Interfaces != nil && stp.RapidPvst.Vlan[uint16(vlanId)].Interfaces.Interface != nil {
                    ifNameList := stp.RapidPvst.Vlan[uint16(vlanId)].Interfaces.Interface
                    for ifName := range ifNameList {
                        sonicIfName := utils.GetNativeNameFromUIName(&ifName)
                        if ok := isVlanMember(inParams.d, vlanName, *sonicIfName); !ok {
                            log.Infof("YangToDb_stp_vlan_xfmr: %s is not a member of Vlan %s", ifName, vlanName)
                            return nil, tlerr.NotFound("%s is not a member of Vlan %s", ifName, vlanName)
                        }
                    }
                }
            }

            for vlanId := range stp.RapidPvst.Vlan {
                err = convertOcRpvstVlanToInternal(stp.RapidPvst.Vlan[uint16(vlanId)], stpVlanMap, setDefaultFlag)
            }
        } else {
            if !isVlanCreated(inParams.d, vlanName) {
                log.Infof("YangToDb_stp_vlan_xfmr: Vlan %s is not configured", vlanName)
                return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
            }
            vlan_id, _ := strconv.Atoi(pathInfo.Var("vlan-id"))
            err = convertOcRpvstVlanToInternal(stp.RapidPvst.Vlan[uint16(vlan_id)], stpVlanMap, setDefaultFlag)
        }
    } else if isSubtreeRequest(targetUriPath, "/openconfig-spanning-tree:stp/openconfig-spanning-tree-ext:pvst") {
        if mode != "pvst" {
            return nil, nil 
        }

        if stp == nil || stp.Pvst == nil || stp.Pvst.Vlan == nil {
            log.Info("YangToDb_stp_vlan_xfmr: stp is empty")
            return nil, errors.New("Stp is not specified")
        }

        if vlanName == "" {
            for vlanId := range stp.Pvst.Vlan {
                vlanName = "Vlan"+strconv.Itoa(int(vlanId))
                if !isVlanCreated(inParams.d, vlanName) {
                    log.Infof("YangToDb_stp_vlan_xfmr: Vlan %s is not configured", vlanName)
                    return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
                }

                if stp.Pvst.Vlan[uint16(vlanId)] != nil && stp.Pvst.Vlan[uint16(vlanId)].Interfaces != nil && stp.Pvst.Vlan[uint16(vlanId)].Interfaces.Interface != nil {
                    ifNameList := stp.Pvst.Vlan[uint16(vlanId)].Interfaces.Interface
                    for ifName := range ifNameList {
                        sonicIfName := utils.GetNativeNameFromUIName(&ifName)
                        if ok := isVlanMember(inParams.d, vlanName, *sonicIfName); !ok {
                            log.Infof("YangToDb_stp_vlan_xfmr: %s is not a member of Vlan %s", ifName, vlanName)
                            return nil, tlerr.NotFound("%s is not a member of Vlan %s", ifName, vlanName)
                        }
                    }
                }
            }

            for vlanId := range stp.Pvst.Vlan {
                err = convertOcPvstVlanToInternal(stp.Pvst.Vlan[uint16(vlanId)], stpVlanMap, setDefaultFlag)
            }
        } else {
            if !isVlanCreated(inParams.d, vlanName) {
                log.Infof("YangToDb_stp_vlan_xfmr: Vlan %s is not configured", vlanName)
                return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
            }
            vlan_id, _ := strconv.Atoi(pathInfo.Var("vlan-id"))
            err = convertOcPvstVlanToInternal(stp.Pvst.Vlan[uint16(vlan_id)], stpVlanMap, setDefaultFlag)
        }
    }

    if err == nil {
        resMap[STP_VLAN_TABLE] = make(map[string]db.Value)
        resMap[STP_VLAN_TABLE][vlanName] = db.Value{Field: stpVlanMap}
    }

    log.Info("YangToDb_stp_vlan_xfmr resMap: ", resMap)
    return resMap, err
}

var DbToYang_stp_vlan_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error

    stp := getStpRoot(inParams.ygRoot)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _, _ := XfmrRemoveXPATHPredicates(pathInfo.Path)

    var vlanName string
    if len(pathInfo.Var("vlan-id")) > 0 {
        vlanName = "Vlan" + pathInfo.Var("vlan-id")
    }

    log.Info("DbToYang_stp_vlan_xfmr vlanName: ", vlanName, " targetUriPath is ", targetUriPath)

    if stp == nil {
        log.Info("Stp is nil")
        ygot.BuildEmptyTree(stp)
    }

    mode, _ := getStpModeFromConfigDb(inParams.d)

    if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst/vlan") {
        if mode != "rpvst" {
            return nil
        }

        if vlanName == "" {
            stpVlanKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:STP_VLAN_TABLE})
            stpVlanPortKeys, _ := inParams.dbs[db.ApplDB].GetKeys(&db.TableSpec{Name:STP_APP_DB_VLAN_PORT_TABLE})
            for _, dbkey := range stpVlanKeys {
                vlanName := dbkey.Get(0)
                
                vlan_id, _ := strconv.Atoi(strings.Replace(vlanName, "Vlan", "", 1))
                rpvstVlanConf := stp.RapidPvst.Vlan[uint16(vlan_id)]
                if rpvstVlanConf == nil {
                    rpvstVlanConf, _ = stp.RapidPvst.NewVlan(uint16(vlan_id))
                }
                ygot.BuildEmptyTree(rpvstVlanConf)
                convertInternalRpvstVlanToOc(inParams, vlanName, targetUriPath, rpvstVlanConf)

                //fetch all interfaces under this vlan
                for _, dbkey := range stpVlanPortKeys {
                    if dbkey.Get(0) != vlanName {
                        continue
                    }

                    ifName := dbkey.Get(1)
                    uriIfName := *(utils.GetUINameFromNativeName(&ifName))
                    if uriIfName == "" {
                        log.Info("uriIfName NULL")
                        err = errors.New("uriIfName NULL")
                        return err
                    }
                    rpvstVlanIntfConf := rpvstVlanConf.Interfaces.Interface[uriIfName]
                    if rpvstVlanIntfConf == nil {
                        rpvstVlanIntfConf, _ = rpvstVlanConf.Interfaces.NewInterface(uriIfName)
                    }
                    ygot.BuildEmptyTree(rpvstVlanIntfConf)

                    convertInternalRpvstVlanIntfToOc(inParams, vlanName, ifName, uriIfName, targetUriPath, rpvstVlanIntfConf)
                }
            }
        } else {
            vlan_id, _ := strconv.Atoi(pathInfo.Var("vlan-id"))
            rpvstVlanConf := stp.RapidPvst.Vlan[uint16(vlan_id)]
            ygot.BuildEmptyTree(rpvstVlanConf)
            convertInternalRpvstVlanToOc(inParams, vlanName, targetUriPath, rpvstVlanConf)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/pvst/vlan") {
        if mode != "pvst" {
            return nil
        }

        if vlanName == "" {
            stpVlanKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:STP_VLAN_TABLE})
            stpVlanPortKeys, _ := inParams.dbs[db.ApplDB].GetKeys(&db.TableSpec{Name:STP_APP_DB_VLAN_PORT_TABLE})
            for _, dbkey := range stpVlanKeys {
                vlanName := dbkey.Get(0)
                
                vlan_id, _ := strconv.Atoi(strings.Replace(vlanName, "Vlan", "", 1))
                pvstVlanConf := stp.Pvst.Vlan[uint16(vlan_id)]
                if pvstVlanConf == nil {
                    pvstVlanConf, _ = stp.Pvst.NewVlan(uint16(vlan_id))
                }
                ygot.BuildEmptyTree(pvstVlanConf)
                convertInternalPvstVlanToOc(inParams, vlanName, targetUriPath, pvstVlanConf)

                //fetch all interfaces under this vlan
                for _, dbkey := range stpVlanPortKeys {
                    if dbkey.Get(0) != vlanName {
                        continue
                    }

                    ifName := dbkey.Get(1)
                    uriIfName := *(utils.GetUINameFromNativeName(&ifName))
                    if uriIfName == "" {
                        log.Info("uriIfName NULL")
                        err = errors.New("uriIfName NULL")
                        return err
                    }
                    pvstVlanIntfConf := pvstVlanConf.Interfaces.Interface[uriIfName]
                    if pvstVlanIntfConf == nil {
                        pvstVlanIntfConf, _ = pvstVlanConf.Interfaces.NewInterface(uriIfName)
                    }
                    ygot.BuildEmptyTree(pvstVlanIntfConf)

                    convertInternalPvstVlanIntfToOc(inParams, vlanName, ifName, uriIfName, targetUriPath, pvstVlanIntfConf)
                }
            }
        } else {
            vlan_id, _ := strconv.Atoi(pathInfo.Var("vlan-id"))
            pvstVlanConf := stp.Pvst.Vlan[uint16(vlan_id)]
            ygot.BuildEmptyTree(pvstVlanConf)
            convertInternalPvstVlanToOc(inParams, vlanName, targetUriPath, pvstVlanConf)
        }
    }
    return err
}

func convertOcStpIntfToInternal(d *db.DB, stpIntfConf *ocbinds.OpenconfigSpanningTree_Stp_Interfaces_Interface, stpPortMap map[string]string, setDefaultFlag bool) error {
    var err error
    
    if stpIntfConf.Config != nil {
        if stpIntfConf.Config.BpduGuard != nil {
            if *stpIntfConf.Config.BpduGuard {
                stpPortMap["bpdu_guard"] = "true"
                stpPortMap["bpdu_guard_do_disable"] = "false"
            } else {
                stpPortMap["bpdu_guard"] = "false"
                stpPortMap["bpdu_guard_do_disable"] = "false"
            }
        }

        if stpIntfConf.Config.BpduFilter != nil {
            if *stpIntfConf.Config.BpduFilter {
                stpPortMap["bpdu_filter"] = "enable"
            } else {
                stpPortMap["bpdu_filter"] = "disable"
            }
        } else if setDefaultFlag {
            stpPortMap["bpdu_filter"] = "global"
        }

        if stpIntfConf.Config.BpduGuardPortShutdown != nil {
            if *stpIntfConf.Config.BpduGuardPortShutdown {
                stpPortMap["bpdu_guard"] = "true"
                stpPortMap["bpdu_guard_do_disable"] = "true"
            } else {
                stpPortMap["bpdu_guard"] = "false"
                stpPortMap["bpdu_guard_do_disable"] = "false"
            }
        }

        if stpIntfConf.Config.Portfast != nil {
            if *stpIntfConf.Config.Portfast {
                stpPortMap["portfast"] = "true"
            } else {
                stpPortMap["portfast"] = "false"
            }
        }

        if stpIntfConf.Config.UplinkFast != nil {
            if *stpIntfConf.Config.UplinkFast {
                stpPortMap["uplink_fast"] = "true"
            } else {
                stpPortMap["uplink_fast"] = "false"
            }
        }

        if stpIntfConf.Config.SpanningTreeEnable != nil {
            if *stpIntfConf.Config.SpanningTreeEnable {
                stpPortMap["enabled"] = "true"
            } else {
                stpPortMap["enabled"] = "false"
            }
        }

        if stpIntfConf.Config.Cost != nil {
            stpPortMap["path_cost"] = strconv.Itoa(int(*stpIntfConf.Config.Cost))
        }

        if stpIntfConf.Config.PortPriority != nil {
            stpPortMap["priority"] = strconv.Itoa(int(*stpIntfConf.Config.PortPriority))
        }

        mode, _ := getStpModeFromConfigDb(d)
        if mode == "rpvst" {
            if stpIntfConf.Config.Guard == ocbinds.OpenconfigSpanningTree_StpGuardType_ROOT {
                stpPortMap["root_guard"] = "true"
                stpPortMap["loop_guard"] = "false"
            } else if stpIntfConf.Config.Guard == ocbinds.OpenconfigSpanningTree_StpGuardType_LOOP {
                stpPortMap["root_guard"] = "false"
                stpPortMap["loop_guard"] = "true"
            } else if stpIntfConf.Config.Guard == ocbinds.OpenconfigSpanningTree_StpGuardType_NONE {
                stpPortMap["root_guard"] = "false"
                stpPortMap["loop_guard"] = "none"
            }
        } else {
            if stpIntfConf.Config.Guard == ocbinds.OpenconfigSpanningTree_StpGuardType_ROOT {
                stpPortMap["root_guard"] = "true"
            } else if stpIntfConf.Config.Guard == ocbinds.OpenconfigSpanningTree_StpGuardType_LOOP {
                stpPortMap["loop_guard"] = "true"
            } else if stpIntfConf.Config.Guard == ocbinds.OpenconfigSpanningTree_StpGuardType_NONE {
                stpPortMap["root_guard"] = "false"
            }
        }

        ////   For RPVST+   /////
        if stpIntfConf.Config.EdgePort == ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_ENABLE {
            stpPortMap["edge_port"] = "true"
        } else if stpIntfConf.Config.EdgePort == ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_DISABLE {
            stpPortMap["edge_port"] = "false"
        }

        if stpIntfConf.Config.LinkType == ocbinds.OpenconfigSpanningTree_StpLinkType_P2P {
            stpPortMap["link_type"] = "point-to-point"
        } else if stpIntfConf.Config.LinkType == ocbinds.OpenconfigSpanningTree_StpLinkType_SHARED {
            stpPortMap["link_type"] = "shared"
        }
    }

    return err
}

func handleStpIntfDeletion(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    if inParams.requestUri == "/openconfig-spanning-tree:stp" { 
        log.Info("handleStpIntfDeletion Parent level delete Request URI: ", inParams.requestUri)
        return nil, nil
    }

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("handleStpIntfDeletion: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    log.Info("handleStpIntfDeletion targetUriPath: ", targetUriPath)

    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subResMap := make(map[string]map[string]db.Value)
    subResMap[STP_PORT_TABLE] = make(map[string]db.Value)
    stpPortMap := make(map[string]string)
    stpPortDelMap := make(map[string]string)

    xpath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)

    if strings.HasSuffix(xpath, "guard") {
        stpPortMap["root_guard"] = "false" 
        mode, _ := getStpModeFromConfigDb(inParams.d)
        if mode == "rpvst" {
            stpPortMap["loop_guard"] = "false" 
        }
    }

    if strings.HasSuffix(xpath, "bpdu-guard") {
        stpPortDelMap["bpdu_guard"] = "" 
    }

    if strings.HasSuffix(xpath, "bpdu-filter") {
        stpPortMap["bpdu_filter"] = "global" 
    }

    if strings.HasSuffix(xpath, "portfast") {
        stpPortDelMap["portfast"] = "" 
    }

    if strings.HasSuffix(xpath, "uplink-fast") {
        stpPortDelMap["uplink_fast"] = "" 
    }

    if strings.HasSuffix(xpath, "bpdu-guard-port-shutdown") {
        stpPortDelMap["bpdu_guard_do_disable"] = "" 
    }

    if strings.HasSuffix(xpath, "cost") {
        stpPortDelMap["path_cost"] = "" 
    }

    if strings.HasSuffix(xpath, "port-priority") {
        stpPortDelMap["priority"] = "" 
    }

    if strings.HasSuffix(xpath, "spanning-tree-enable") {
        stpPortDelMap["enabled"] = "" 
    }

    if strings.HasSuffix(xpath, "edge-port") {
        stpPortDelMap["edge_port"] = "" 
    }

    if strings.HasSuffix(xpath, "link-type") {
        stpPortMap["link_type"] = "auto" 
    }

    if len(stpPortDelMap) != 0 {
        resMap[STP_PORT_TABLE] = make(map[string]db.Value)
        resMap[STP_PORT_TABLE][ifName] = db.Value{Field: stpPortDelMap} 
    }

    if len(stpPortMap) != 0 {
        subResMap[STP_PORT_TABLE][ifName] = db.Value{Field: stpPortMap}
        subOpMap[db.ConfigDB] = subResMap
        log.Info("handleStpIntfDeletion subOpMap: ", subOpMap)
        inParams.subOpDataMap[UPDATE] = &subOpMap
    }

    return resMap, err
}

func convertInternalStpIntfToOc (inParams XfmrParams, ifName string, targetUriPath string, stpIntf *ocbinds.OpenconfigSpanningTree_Stp_Interfaces_Interface) error {
    stpIntfData, err := inParams.d.GetEntry(&db.TableSpec{Name: STP_PORT_TABLE}, db.Key{[]string{ifName}})
    if err != nil {
        log.Info("convertInternalStpIntfToOc: Error in retrieving STP_PORT_TABLE for Intf: ", ifName)
    }

    stpAppDbIntfData, err := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name: STP_APP_DB_PORT_TABLE}, db.Key{[]string{ifName}})
    if err != nil {
        log.Info("convertInternalStpIntfToOc: Error in retrieving APP STP_PORT_TABLE for Intf: ", ifName)
    }

    var stpEnabled bool
    var bpduGuardEnabled bool
    var bpduGuardPortShut bool
    var uplinkFast bool
    var portFast bool
    var bpduFilterEnabled bool
    var bpduFilterEnabledSet bool = false
    var num uint64
    var rootGuardEnabled bool
    var loopGuardEnabled string
    var edgePortEnabled bool
    var linkTypeVal string
    var priority uint8 
    var priority_set bool = false 
    var cost uint32 = 0
    if stpIntfData.IsPopulated() {
        stpEnabled, _ = strconv.ParseBool((&stpIntfData).Get("enabled"))
        bpduGuardEnabled, _ = strconv.ParseBool((&stpIntfData).Get("bpdu_guard"))
        bpduGuardPortShut, _ = strconv.ParseBool((&stpIntfData).Get("bpdu_guard_do_disable"))
        uplinkFast, _ = strconv.ParseBool((&stpIntfData).Get("uplink_fast"))
        portFast, _ = strconv.ParseBool((&stpIntfData).Get("portfast"))

        bpduFilterVal := (&stpIntfData).Get("bpdu_filter")
        if bpduFilterVal == "enable" {
            bpduFilterEnabled = true
            bpduFilterEnabledSet = true
        } else if bpduFilterVal == "disable" {
            bpduFilterEnabled = false
            bpduFilterEnabledSet = true
        }

        rootGuardEnabled, _ = strconv.ParseBool((&stpIntfData).Get("root_guard"))
        loopGuardEnabled = (&stpIntfData).Get("loop_guard")
        if len(stpIntfData.Field["edge_port"]) != 0 {
            edgePortEnabled, _ = strconv.ParseBool((&stpIntfData).Get("edge_port"))
        }
        linkTypeVal = (&stpIntfData).Get("link_type")

        if len(stpIntfData.Field["priority"]) != 0 {
            num, _ = strconv.ParseUint((&stpIntfData).Get("priority"), 10, 8)
            priority = uint8(num)
            priority_set = true
        }

        if len(stpIntfData.Field["path_cost"]) != 0 {
            num, err = strconv.ParseUint((&stpIntfData).Get("path_cost"), 10, 32)
            cost = uint32(num)
        }
    }

    //APP DB
    var bpduGuardShut bool
    var opPortFast bool
    var bpduFilter bool
    var opEdgePortType string
    var opLinkType string
    if stpAppDbIntfData.IsPopulated() {
        opBpduGuardShut := (&stpAppDbIntfData).Get("bpdu_guard_shutdown")
        if opBpduGuardShut == "yes" {
            bpduGuardShut = true
        } else {
            bpduGuardShut = false
        }

        opPortfast := (&stpAppDbIntfData).Get("port_fast")
        if opPortfast == "yes" {
            opPortFast = true
        } else {
            opPortFast = false
        }

        opBpduFilter := (&stpAppDbIntfData).Get("bpdu_filter")
        if opBpduFilter == "yes" {
            bpduFilter = true
        } else {
            bpduFilter = false
        }

        opEdgePortType = (&stpAppDbIntfData).Get("edge_port")
        opLinkType = (&stpAppDbIntfData).Get("link_type")
    }

    if stpIntf != nil {
        if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/interfaces/interface/config") {
            if stpIntfData.IsPopulated() {
                stpIntf.Config.Name = &ifName
                stpIntf.Config.SpanningTreeEnable = &stpEnabled
                stpIntf.Config.BpduGuard = &bpduGuardEnabled
                if bpduFilterEnabledSet {
                    stpIntf.Config.BpduFilter = &bpduFilterEnabled
                }
                stpIntf.Config.BpduGuardPortShutdown = &bpduGuardPortShut
                stpIntf.Config.UplinkFast = &uplinkFast
                stpIntf.Config.Portfast = &portFast

                if rootGuardEnabled {
                    stpIntf.Config.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_ROOT
                } else if loopGuardEnabled == "true" {
                    stpIntf.Config.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_LOOP
                } else if loopGuardEnabled == "none" {
                    stpIntf.Config.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_NONE
                }

                if edgePortEnabled {
                    stpIntf.Config.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_ENABLE
                } else {
                    stpIntf.Config.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_DISABLE
                }

                switch linkTypeVal {
                    case "shared":
                        stpIntf.Config.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_SHARED
                    case "point-to-point":
                        stpIntf.Config.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_P2P
                }

                if priority_set {
                    stpIntf.Config.PortPriority = &priority
                }
                if cost != 0 {
                    stpIntf.Config.Cost = &cost
                }
            }
        } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/interfaces/interface/state") {
            if stpAppDbIntfData.IsPopulated() {
                stpIntf.State.Name = &ifName
                stpIntf.State.SpanningTreeEnable = &stpEnabled
                stpIntf.State.BpduGuard = &bpduGuardEnabled
                stpIntf.State.UplinkFast = &uplinkFast

                if rootGuardEnabled {
                    stpIntf.State.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_ROOT
                } else if loopGuardEnabled == "true" {
                    stpIntf.State.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_LOOP
                } else if loopGuardEnabled == "none" {
                    stpIntf.State.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_NONE
                }

                if priority_set {
                    stpIntf.State.PortPriority = &priority
                }
                if cost != 0 {
                    stpIntf.State.Cost = &cost
                }

                stpIntf.State.BpduGuardShutdown = &bpduGuardShut
                stpIntf.State.Portfast = &opPortFast
                stpIntf.State.BpduFilter = &bpduFilter

                if opEdgePortType == "yes" {
                    stpIntf.State.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_ENABLE
                } else if opEdgePortType == "no" {
                    stpIntf.State.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_DISABLE
                }

                if opLinkType == "shared" {
                    stpIntf.State.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_SHARED
                } else if opLinkType == "point-to-point" {
                    stpIntf.State.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_P2P
                }
            }
        } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/interfaces/interface") {
            if stpIntfData.IsPopulated() {
                stpIntf.Config.Name = &ifName
                stpIntf.Config.SpanningTreeEnable = &stpEnabled
                stpIntf.Config.BpduGuard = &bpduGuardEnabled
                stpIntf.Config.BpduFilter = &bpduFilterEnabled
                stpIntf.Config.BpduGuardPortShutdown = &bpduGuardPortShut
                stpIntf.Config.UplinkFast = &uplinkFast
                stpIntf.Config.Portfast = &portFast

                if rootGuardEnabled {
                    stpIntf.Config.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_ROOT
                } else if loopGuardEnabled == "true" {
                    stpIntf.Config.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_LOOP
                } else if loopGuardEnabled == "none" {
                    stpIntf.Config.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_NONE
                }

                if edgePortEnabled {
                    stpIntf.Config.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_ENABLE
                } else {
                    stpIntf.Config.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_DISABLE
                }

                switch linkTypeVal {
                    case "shared":
                        stpIntf.Config.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_SHARED
                    case "point-to-point":
                        stpIntf.Config.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_P2P
                }

                if priority_set {
                    stpIntf.Config.PortPriority = &priority
                }
                if cost != 0 {
                    stpIntf.Config.Cost = &cost
                }
            }

            if stpAppDbIntfData.IsPopulated() {
                stpIntf.State.Name = &ifName
                stpIntf.State.SpanningTreeEnable = &stpEnabled
                stpIntf.State.BpduGuard = &bpduGuardEnabled
                stpIntf.State.UplinkFast = &uplinkFast

                if rootGuardEnabled {
                    stpIntf.State.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_ROOT
                } else if loopGuardEnabled == "true" {
                    stpIntf.State.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_LOOP
                } else if loopGuardEnabled == "none" {
                    stpIntf.State.Guard = ocbinds.OpenconfigSpanningTree_StpGuardType_NONE
                }

                if priority_set {
                    stpIntf.State.PortPriority = &priority
                }
                if cost != 0 {
                    stpIntf.State.Cost = &cost
                }

                stpIntf.State.BpduGuardShutdown = &bpduGuardShut
                stpIntf.State.Portfast = &opPortFast
                stpIntf.State.BpduFilter = &bpduFilter

                if opEdgePortType == "yes" {
                    stpIntf.State.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_ENABLE
                } else if opEdgePortType == "no" {
                    stpIntf.State.EdgePort = ocbinds.OpenconfigSpanningTreeTypes_STP_EDGE_PORT_EDGE_DISABLE
                }

                if opLinkType == "shared" {
                    stpIntf.State.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_SHARED
                } else if opLinkType == "point-to-point" {
                    stpIntf.State.LinkType = ocbinds.OpenconfigSpanningTree_StpLinkType_P2P
                }
            }
        }
    }

    log.Info("convertInternalStpIntfToOc config:", stpIntf.Config)
    log.Info("convertInternalStpIntfToOc state:", stpIntf.State)
    return err
}

var Subscribe_stp_port_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    uriIfName := pathInfo.Var("name")
    keyName := uriIfName

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("Subscribe_stp_port_xfmr: Interface name retrieved from alias : %s is %s", keyName, *sonicIfName)
    keyName = *sonicIfName

    log.Info("Subscribe_stp_port_xfmr: TargetURI: ", targetUriPath, " Key: ", keyName)

    if (keyName != "") {
        result.dbDataMap = RedisDbMap{db.ConfigDB:{STP_PORT_TABLE:{keyName:{}}}}
    } else {
        errStr := "STP PORT not present in request"
        log.Info("Subscribe_stp_port_xfmr: " + errStr)
        return result, errors.New(errStr)
    }

    result.isVirtualTbl = false
    log.Info("Subscribe_stp_port_xfmr resultMap:", result.dbDataMap)
    return result, err
}

var YangToDb_stp_port_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)
    stpPortMap := make(map[string]string)

    if inParams.oper == DELETE {
        resMap, err = handleStpIntfDeletion(inParams)
        log.Info("YangToDb_stp_port_xfmr resMap: ", resMap)
        return resMap, err
    }

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    stp := getStpRoot(inParams.ygRoot)

    mode, _ := getStpModeFromConfigDb(inParams.d)
    log.Info("YangToDb_stp_port_xfmr targetUriPath: ", targetUriPath, " mode: ", mode, " ifName:", ifName)


    if stp == nil || stp.Interfaces == nil {
        log.Info("YangToDb_stp_port_xfmr: stp is empty")
        return nil, errors.New("Stp is not specified")
    }

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("YangToDb_stp_port_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    if _, ok := stp.Interfaces.Interface[uriIfName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + uriIfName
        log.Info("YangToDb_stp_port_xfmr : " + errStr)
        return resMap, errors.New(errStr)
    }

    setDefaultFlag := (inParams.oper == CREATE || inParams.oper == REPLACE)
    err = convertOcStpIntfToInternal(inParams.d, stp.Interfaces.Interface[uriIfName], stpPortMap, setDefaultFlag)

    if err == nil {
        resMap[STP_PORT_TABLE] = make(map[string]db.Value)
        resMap[STP_PORT_TABLE][ifName] = db.Value{Field: stpPortMap}
    }

    log.Info("YangToDb_stp_port_xfmr resMap: ", resMap)
    return resMap, err
}

var DbToYang_stp_port_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error

    stp := getStpRoot(inParams.ygRoot)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    ifName := pathInfo.Var("name")

    log.Info("DbToYang_stp_port_xfmr targetUriPath: ", targetUriPath)

    if stp == nil {
        log.Info("Stp is nil")
        ygot.BuildEmptyTree(stp)
    }

    uriIfName := ifName
    sonicIfName := utils.GetNativeNameFromUIName(&ifName)
    log.Infof("DbToYang_stp_port_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    if ifName == "" {
        log.Info("ifName NULL")
        err = errors.New("ifName NULL")
        return err
    }

    stpIntf, ok := stp.Interfaces.Interface[uriIfName]
    if !ok {
        stpIntf, err = stp.Interfaces.NewInterface(uriIfName)
        if err != nil {
            log.Info("Creation of interface subtree failed!")
            return err
        }
        ygot.BuildEmptyTree(stpIntf)
    }
    
    err = convertInternalStpIntfToOc(inParams, ifName, targetUriPath, stpIntf)

    return err
}

func convertOcRpvstVlanIntfToInternal(d *db.DB, rpvstVlanIntfConf *ocbinds.OpenconfigSpanningTree_Stp_RapidPvst_Vlan_Interfaces_Interface, stpVlanPortMap map[string]string, oper int, vlanIntfKey string) {

    stpVlanIntfData, _ := d.GetEntry(&db.TableSpec{Name: STP_VLAN_PORT_TABLE}, db.Key{[]string{vlanIntfKey}})
    setDefaultFlag := (oper == CREATE || oper == REPLACE)

    if rpvstVlanIntfConf.Config != nil {
        if rpvstVlanIntfConf.Config.Cost != nil {
            if oper == DELETE {
                if stpVlanIntfData.Has("path_cost") {
                    if len(stpVlanIntfData.Field) > 1 {
                        stpVlanPortMap["path_cost"] = strconv.Itoa(int(*rpvstVlanIntfConf.Config.Cost))
                    }
                } else {
                    stpVlanPortMap["path_cost"] = ""
                }
            } else {
                stpVlanPortMap["path_cost"] = strconv.Itoa(int(*rpvstVlanIntfConf.Config.Cost))
            }
        } else if setDefaultFlag {
            stpVlanPortMap["path_cost"] = "200"
        }

        if rpvstVlanIntfConf.Config.PortPriority != nil {
            if oper == DELETE {
                if stpVlanIntfData.Has("priority") {
                    if len(stpVlanIntfData.Field) > 1 {
                        stpVlanPortMap["priority"] = strconv.Itoa(int(*rpvstVlanIntfConf.Config.PortPriority))
                    }
                } else {
                    stpVlanPortMap["priority"] = ""
                }
            } else {
                stpVlanPortMap["priority"] = strconv.Itoa(int(*rpvstVlanIntfConf.Config.PortPriority))
            }
        } else if setDefaultFlag {
            stpVlanPortMap["priority"] = "128" 
        }
    }
}

func convertOcPvstVlanIntfToInternal(d *db.DB, pvstVlanIntfConf *ocbinds.OpenconfigSpanningTree_Stp_Pvst_Vlan_Interfaces_Interface, stpVlanPortMap map[string]string, oper int, vlanIntfKey string) {

    stpVlanIntfData, _ := d.GetEntry(&db.TableSpec{Name: STP_VLAN_PORT_TABLE}, db.Key{[]string{vlanIntfKey}})
    setDefaultFlag := (oper == CREATE || oper == REPLACE)

    if pvstVlanIntfConf.Config != nil {
        if pvstVlanIntfConf.Config.Cost != nil {
            if oper == DELETE {
                if stpVlanIntfData.Has("path_cost") {
                    if len(stpVlanIntfData.Field) > 1 {
                        stpVlanPortMap["path_cost"] = strconv.Itoa(int(*pvstVlanIntfConf.Config.Cost))
                    }
                } else {
                    stpVlanPortMap["path_cost"] = ""
                }
            } else {
                stpVlanPortMap["path_cost"] = strconv.Itoa(int(*pvstVlanIntfConf.Config.Cost))
            }
        } else if setDefaultFlag {
            stpVlanPortMap["path_cost"] = "200"
        }

        if pvstVlanIntfConf.Config.PortPriority != nil {
            if oper == DELETE {
                if stpVlanIntfData.Has("priority") {
                    if len(stpVlanIntfData.Field) > 1 {
                        stpVlanPortMap["priority"] = strconv.Itoa(int(*pvstVlanIntfConf.Config.PortPriority))
                    }
                } else {
                    stpVlanPortMap["priority"] = ""
                }
            } else {
                stpVlanPortMap["priority"] = strconv.Itoa(int(*pvstVlanIntfConf.Config.PortPriority))
            }
        } else if setDefaultFlag {
            stpVlanPortMap["priority"] = "128" 
        }
    }
}

func convertInternalRpvstVlanIntfToOc(inParams XfmrParams, vlanName string, ifName string, uriIfName string, targetUriPath string, rpvstVlanIntf *ocbinds.OpenconfigSpanningTree_Stp_RapidPvst_Vlan_Interfaces_Interface) {
    stpVlanIntfData, err := inParams.d.GetEntry(&db.TableSpec{Name: STP_VLAN_PORT_TABLE}, db.Key{[]string{vlanName+"|"+ifName}})
    if err != nil {
        log.Info("convertInternalRpvstVlanIntfToOc: No STP_VLAN_PORT_TABLE for : ", vlanName, ifName)
    }

    stpAppDbVlanIntfData, err := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name: STP_APP_DB_VLAN_PORT_TABLE}, db.Key{[]string{vlanName+":"+ifName}})
    if err != nil {
        log.Info("convertInternalRpvstVlanIntfToOc: No APP STP_VLAN_PORT_TABLE for : ", vlanName, ifName)
    }

    log.Info("convertInternalRpvstVlanIntfToOc vlanName:", vlanName, " ifName: ", ifName)
    var num uint64
    var cost uint32
    var portPriority uint8
    var priority_set bool = false 
    if stpVlanIntfData.IsPopulated() {
        if len(stpVlanIntfData.Field["path_cost"]) != 0 {
            num, _ = strconv.ParseUint((&stpVlanIntfData).Get("path_cost"), 10, 32)
            cost = uint32(num)
        }

        if len(stpVlanIntfData.Field["priority"]) != 0 {
            num, _ = strconv.ParseUint((&stpVlanIntfData).Get("priority"), 10, 8)
            portPriority = uint8(num)
            priority_set = true
        }
    }
    
    var opPortNum uint16
    var opcost uint32
    var opPortPriority uint8
    var opDesigCost uint32
    var opDesigPortNum uint16
    var opRootGuardTimer uint16
    var opFwtrans uint64
    var desigRootAddr string
    var desigBridgeAddr string
    var portState string
    var portRole string
    var opBpduSent uint64
    var opBpduReceived uint64
    var opTcnSent uint64
    var opTcnReceived uint64
    var opConfigBpduSent uint64
    var opConfigBpduReceived uint64
    if stpAppDbVlanIntfData.IsPopulated() {
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("port_num"), 10, 16)
        opPortNum = uint16(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("path_cost"), 10, 32)
        opcost = uint32(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("priority"), 10, 8)
        opPortPriority = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("desig_cost"), 10, 32)
        opDesigCost = uint32(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("desig_port"), 10, 16)
        opDesigPortNum = uint16(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("root_guard_timer"), 10, 16)
        opRootGuardTimer = uint16(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("fwd_transitions"), 10, 64)
        opFwtrans = num
        desigRootAddr = (&stpAppDbVlanIntfData).Get("desig_root")
        desigBridgeAddr = (&stpAppDbVlanIntfData).Get("desig_bridge")
        portState = (&stpAppDbVlanIntfData).Get("port_state")
        portRole = (&stpAppDbVlanIntfData).Get("role")

        //Counters
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("bpdu_sent"), 10, 64)
        opBpduSent = num
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("bpdu_received"), 10, 64)
        opBpduReceived = num
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("tc_sent"), 10, 64)
        opTcnSent = num
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("tc_received"), 10, 64)
        opTcnReceived = num
    
        // For RPVST+ only
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("config_bpdu_sent"), 10, 64)
        opConfigBpduSent = num
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("config_bpdu_received"), 10, 64)
        opConfigBpduReceived = num
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst/vlan/interfaces/interface/config") {
        if stpVlanIntfData.IsPopulated() {
            rpvstVlanIntf.Config.Name = &uriIfName
            if cost != 0 {
                rpvstVlanIntf.Config.Cost = &cost
            }

            if priority_set {
                rpvstVlanIntf.Config.PortPriority = &portPriority
            }
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst/vlan/interfaces/interface/state") {
        rpvstVlanIntf.State.Name = &uriIfName
        rpvstVlanIntf.State.PortPriority = &portPriority
        rpvstVlanIntf.State.PortNum = &opPortNum
        rpvstVlanIntf.State.Cost = &opcost
        rpvstVlanIntf.State.PortPriority = &opPortPriority
        rpvstVlanIntf.State.DesignatedCost = &opDesigCost
        rpvstVlanIntf.State.DesignatedPortNum = &opDesigPortNum
        rpvstVlanIntf.State.RootGuardTimer = &opRootGuardTimer
        rpvstVlanIntf.State.ForwardTransisitions = &opFwtrans
        rpvstVlanIntf.State.DesignatedRootAddress = &desigRootAddr
        rpvstVlanIntf.State.DesignatedBridgeAddress = &desigBridgeAddr

        switch portState {
        case "DISABLED":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_DISABLED
        case "DISCARDING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_DISCARDING
        case "LISTENING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LISTENING
        case "LEARNING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LEARNING
        case "FORWARDING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_FORWARDING
        case "BPDU-DIS":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_BPDU_DIS
        case "ROOT-INC":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_ROOT_INC
        case "LOOP-INC":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LOOP_INC
        }

        switch portRole {
        case "ROOT":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ROOT
        case "DESIGNATED":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DESIGNATED
        case "ALTERNATE":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ALTERNATE
        case "BACKUP":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_BACKUP
        case "DISABLED":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DISABLED
        }

        if rpvstVlanIntf.State.Counters != nil {
            rpvstVlanIntf.State.Counters.BpduSent = &opBpduSent
            rpvstVlanIntf.State.Counters.BpduReceived = &opBpduReceived
            rpvstVlanIntf.State.Counters.TcnSent = &opTcnSent
            rpvstVlanIntf.State.Counters.TcnReceived = &opTcnReceived
            rpvstVlanIntf.State.Counters.ConfigBpduSent = &opConfigBpduSent
            rpvstVlanIntf.State.Counters.ConfigBpduReceived = &opConfigBpduReceived
        }
    } else {
        if stpVlanIntfData.IsPopulated() {
            rpvstVlanIntf.Config.Name = &uriIfName
            if cost != 0 {
                rpvstVlanIntf.Config.Cost = &cost
            }

            if priority_set {
                rpvstVlanIntf.Config.PortPriority = &portPriority
            }
        }

        rpvstVlanIntf.State.Name = &uriIfName
        rpvstVlanIntf.State.PortPriority = &portPriority
        rpvstVlanIntf.State.PortNum = &opPortNum
        rpvstVlanIntf.State.Cost = &opcost
        rpvstVlanIntf.State.PortPriority = &opPortPriority
        rpvstVlanIntf.State.DesignatedCost = &opDesigCost
        rpvstVlanIntf.State.DesignatedPortNum = &opDesigPortNum
        rpvstVlanIntf.State.RootGuardTimer = &opRootGuardTimer
        rpvstVlanIntf.State.ForwardTransisitions = &opFwtrans
        rpvstVlanIntf.State.DesignatedRootAddress = &desigRootAddr
        rpvstVlanIntf.State.DesignatedBridgeAddress = &desigBridgeAddr

        switch portState {
        case "DISABLED":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_DISABLED
        case "DISCARDING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_DISCARDING
        case "LISTENING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LISTENING
        case "LEARNING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LEARNING
        case "FORWARDING":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_FORWARDING
        case "BPDU-DIS":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_BPDU_DIS
        case "ROOT-INC":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_ROOT_INC
        case "LOOP-INC":
            rpvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LOOP_INC
        }

        switch portRole {
        case "ROOT":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ROOT
        case "DESIGNATED":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DESIGNATED
        case "ALTERNATE":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ALTERNATE
        case "BACKUP":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_BACKUP
        case "DISABLED":
            rpvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DISABLED
        }

        if rpvstVlanIntf.State.Counters != nil {
            rpvstVlanIntf.State.Counters.BpduSent = &opBpduSent
            rpvstVlanIntf.State.Counters.BpduReceived = &opBpduReceived
            rpvstVlanIntf.State.Counters.TcnSent = &opTcnSent
            rpvstVlanIntf.State.Counters.TcnReceived = &opTcnReceived
            rpvstVlanIntf.State.Counters.ConfigBpduSent = &opConfigBpduSent
            rpvstVlanIntf.State.Counters.ConfigBpduReceived = &opConfigBpduReceived
        }
    }

    log.Info("convertInternalRpvstVlanIntfToOc config:", rpvstVlanIntf.Config)
    log.Info("convertInternalRpvstVlanIntfToOc state:", rpvstVlanIntf.State)
}

func convertInternalPvstVlanIntfToOc(inParams XfmrParams, vlanName string, ifName string, uriIfName string, targetUriPath string, pvstVlanIntf *ocbinds.OpenconfigSpanningTree_Stp_Pvst_Vlan_Interfaces_Interface) {
    stpVlanIntfData, err := inParams.d.GetEntry(&db.TableSpec{Name: STP_VLAN_PORT_TABLE}, db.Key{[]string{vlanName+"|"+ifName}})
    if err != nil {
        log.Info("convertInternalPvstVlanIntfToOc: No STP_VLAN_PORT_TABLE for : ", vlanName, ifName)
    }

    stpAppDbVlanIntfData, err := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name: STP_APP_DB_VLAN_PORT_TABLE}, db.Key{[]string{vlanName+":"+ifName}})
    if err != nil {
        log.Info("convertInternalPvstVlanIntfToOc: No APP STP_VLAN_PORT_TABLE for : ", vlanName, ifName)
    }

    var num uint64
    var cost uint32
    var portPriority uint8
    var priority_set bool = false 
    if stpVlanIntfData.IsPopulated() {
        if len(stpVlanIntfData.Field["path_cost"]) != 0 {
            num, _ = strconv.ParseUint((&stpVlanIntfData).Get("path_cost"), 10, 32)
            cost = uint32(num)
        }

        if len(stpVlanIntfData.Field["priority"]) != 0 {
            num, _ = strconv.ParseUint((&stpVlanIntfData).Get("priority"), 10, 8)
            portPriority = uint8(num)
            priority_set = true
        }
    }
    
    var opPortNum uint16
    var opcost uint32
    var opPortPriority uint8
    var opDesigCost uint32
    var opDesigPortNum uint16
    var opRootGuardTimer uint16
    var opFwtrans uint64
    var desigRootAddr string
    var desigBridgeAddr string
    var portState string
    var portRole string
    var opBpduSent uint64
    var opBpduReceived uint64
    var opTcnSent uint64
    var opTcnReceived uint64

    if stpAppDbVlanIntfData.IsPopulated() {
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("port_num"), 10, 16)
        opPortNum = uint16(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("path_cost"), 10, 32)
        opcost = uint32(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("priority"), 10, 8)
        opPortPriority = uint8(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("desig_cost"), 10, 32)
        opDesigCost = uint32(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("desig_port"), 10, 16)
        opDesigPortNum = uint16(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("root_guard_timer"), 10, 16)
        opRootGuardTimer = uint16(num)
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("fwd_transitions"), 10, 64)
        opFwtrans = num
        desigRootAddr = (&stpAppDbVlanIntfData).Get("desig_root")
        desigBridgeAddr = (&stpAppDbVlanIntfData).Get("desig_bridge")
        portState = (&stpAppDbVlanIntfData).Get("port_state")
        portRole = (&stpAppDbVlanIntfData).Get("role")

        //Counters
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("bpdu_sent"), 10, 64)
        opBpduSent = num
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("bpdu_received"), 10, 64)
        opBpduReceived = num
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("tc_sent"), 10, 64)
        opTcnSent = num
        num, _ = strconv.ParseUint((&stpAppDbVlanIntfData).Get("tc_received"), 10, 64)
        opTcnReceived = num
    }
    
    if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/pvst/vlan/openconfig-spanning-tree:interfaces/interface/config") {
        if stpVlanIntfData.IsPopulated() {
            pvstVlanIntf.Config.Name = &uriIfName
            if cost != 0 {
                pvstVlanIntf.Config.Cost = &cost
            }

            if priority_set {
                pvstVlanIntf.Config.PortPriority = &portPriority
            }
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/pvst/vlan/openconfig-spanning-tree:interfaces/interface/state") {
        pvstVlanIntf.State.Name = &uriIfName
        pvstVlanIntf.State.PortPriority = &portPriority
        pvstVlanIntf.State.PortNum = &opPortNum
        pvstVlanIntf.State.Cost = &opcost
        pvstVlanIntf.State.PortPriority = &opPortPriority
        pvstVlanIntf.State.DesignatedCost = &opDesigCost
        pvstVlanIntf.State.DesignatedPortNum = &opDesigPortNum
        pvstVlanIntf.State.RootGuardTimer = &opRootGuardTimer
        pvstVlanIntf.State.ForwardTransisitions = &opFwtrans
        pvstVlanIntf.State.DesignatedRootAddress = &desigRootAddr
        pvstVlanIntf.State.DesignatedBridgeAddress = &desigBridgeAddr

        switch portState {
        case "DISABLED":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_DISABLED
        case "BLOCKING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_BLOCKING
        case "LISTENING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LISTENING
        case "LEARNING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LEARNING
        case "FORWARDING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_FORWARDING
        case "BPDU-DIS":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_BPDU_DIS
        case "ROOT-INC":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_ROOT_INC
        }

        switch portRole {
        case "ROOT":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ROOT
        case "DESIGNATED":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DESIGNATED
        case "ALTERNATE":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ALTERNATE
        case "BACKUP":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_BACKUP
        case "DISABLED":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DISABLED
        }

        if pvstVlanIntf.State.Counters != nil {
            pvstVlanIntf.State.Counters.BpduSent = &opBpduSent
            pvstVlanIntf.State.Counters.BpduReceived = &opBpduReceived
            pvstVlanIntf.State.Counters.TcnSent = &opTcnSent
            pvstVlanIntf.State.Counters.TcnReceived = &opTcnReceived
        }
    } else {
        if stpVlanIntfData.IsPopulated() {
            pvstVlanIntf.Config.Name = &uriIfName
            if cost != 0 {
                pvstVlanIntf.Config.Cost = &cost
            }

            if priority_set {
                pvstVlanIntf.Config.PortPriority = &portPriority
            }
        }

        pvstVlanIntf.State.Name = &uriIfName
        pvstVlanIntf.State.PortPriority = &portPriority
        pvstVlanIntf.State.PortNum = &opPortNum
        pvstVlanIntf.State.Cost = &opcost
        pvstVlanIntf.State.PortPriority = &opPortPriority
        pvstVlanIntf.State.DesignatedCost = &opDesigCost
        pvstVlanIntf.State.DesignatedPortNum = &opDesigPortNum
        pvstVlanIntf.State.RootGuardTimer = &opRootGuardTimer
        pvstVlanIntf.State.ForwardTransisitions = &opFwtrans
        pvstVlanIntf.State.DesignatedRootAddress = &desigRootAddr
        pvstVlanIntf.State.DesignatedBridgeAddress = &desigBridgeAddr

        switch portState {
        case "DISABLED":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_DISABLED
        case "BLOCKING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_BLOCKING
        case "LISTENING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LISTENING
        case "LEARNING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_LEARNING
        case "FORWARDING":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_FORWARDING
        case "BPDU-DIS":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_BPDU_DIS
        case "ROOT-INC":
            pvstVlanIntf.State.PortState = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_STATE_ROOT_INC
        }

        switch portRole {
        case "ROOT":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ROOT
        case "DESIGNATED":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DESIGNATED
        case "ALTERNATE":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_ALTERNATE
        case "BACKUP":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_BACKUP
        case "DISABLED":
            pvstVlanIntf.State.Role = ocbinds.OpenconfigSpanningTreeTypes_STP_PORT_ROLE_DISABLED
        }

        if pvstVlanIntf.State.Counters != nil {
            pvstVlanIntf.State.Counters.BpduSent = &opBpduSent
            pvstVlanIntf.State.Counters.BpduReceived = &opBpduReceived
            pvstVlanIntf.State.Counters.TcnSent = &opTcnSent
            pvstVlanIntf.State.Counters.TcnReceived = &opTcnReceived
        }
    }

    log.Info("convertInternalPvstVlanIntfToOc config:", pvstVlanIntf.Config)
    log.Info("convertInternalPvstVlanIntfToOc state:", pvstVlanIntf.State)
}

var Subscribe_stp_vlan_port_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    vlanName := "Vlan" + pathInfo.Var("vlan-id")
    keyName := vlanName + ":" + pathInfo.Var("name")

    log.Info("Subscribe_stp_vlan_port_xfmr: TargetURI: ", targetUriPath, " Key: ", keyName)

    if (keyName != "") {
        result.dbDataMap = RedisDbMap{db.ApplDB:{STP_APP_DB_VLAN_PORT_TABLE:{keyName:{}}}}
    } else {
        errStr := "STP PORT not present in request"
        log.Info("Subscribe_stp_vlan_port_xfmr: " + errStr)
        return result, errors.New(errStr)
    }

    result.isVirtualTbl = false
    log.Info("Subscribe_stp_vlan_port_xfmr resultMap:", result.dbDataMap)
    return result, err
}

var YangToDb_stp_vlan_port_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    resMap := make(map[string]map[string]db.Value)
    stpVlanPortMap := make(map[string]string)

    stp := getStpRoot(inParams.ygRoot)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    vlanName := "Vlan" + pathInfo.Var("vlan-id")
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    if inParams.requestUri == "/openconfig-spanning-tree:stp" { 
        log.Info("YangToDb_stp_vlan_port_xfmr Parent level delete Request URI: ", inParams.requestUri)
        return nil, nil
    }

    if !isVlanCreated(inParams.d, vlanName) {
        log.Infof("YangToDb_stp_vlan_port_xfmr : Vlan %s is not configured", vlanName)
        return nil, tlerr.NotFound("Vlan %s is not configured", vlanName)
    }

    mode, _ := getStpModeFromConfigDb(inParams.d)
    log.Info("YangToDb_stp_vlan_port_xfmr targetUriPath: ", targetUriPath, " mode: ", mode, " vlanName:", vlanName)
    vlan_id, _ := strconv.Atoi(pathInfo.Var("vlan-id"))

    if isSubtreeRequest(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst") {
        if mode != "rpvst" {
            return nil, nil 
        }

        if stp == nil || stp.RapidPvst == nil || stp.RapidPvst.Vlan == nil {
            log.Info("YangToDb_stp_vlan_port_xfmr: stp is empty")
            return nil, errors.New("Stp is not specified")
        }

        if ifName == "" {
            for uriIfName := range stp.RapidPvst.Vlan[uint16(vlan_id)].Interfaces.Interface {
                rpvstVlanIntfConf := stp.RapidPvst.Vlan[uint16(vlan_id)].Interfaces.Interface[uriIfName]
                
                sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
                log.Infof("YangToDb_stp_vlan_port_xfmr: Interface name retrieved from alias : %s is %s", uriIfName, *sonicIfName)
                ifName = *sonicIfName
                convertOcRpvstVlanIntfToInternal(inParams.d, rpvstVlanIntfConf, stpVlanPortMap, inParams.oper, vlanName+"|"+ifName)

                stpVlanPortKey := vlanName + "|" + ifName
                resMap[STP_VLAN_PORT_TABLE] = make(map[string]db.Value)
                resMap[STP_VLAN_PORT_TABLE][stpVlanPortKey] = db.Value{Field: stpVlanPortMap}
            }
        } else {
            rpvstVlanIntfConf, ok := stp.RapidPvst.Vlan[uint16(vlan_id)].Interfaces.Interface[uriIfName]
            if !ok {
                errStr := "Interface entry not found in Ygot tree, ifname: " + uriIfName
                log.Info("YangToDb_stp_vlan_port_xfmr : " + errStr)
                return resMap, errors.New(errStr)
            }

            sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
            log.Infof("YangToDb_stp_vlan_port_xfmr: Interface name retrieved from alias : %s is %s", uriIfName, *sonicIfName)
            ifName = *sonicIfName
            convertOcRpvstVlanIntfToInternal(inParams.d, rpvstVlanIntfConf, stpVlanPortMap, inParams.oper, vlanName+"|"+ifName)
    
            stpVlanPortKey := vlanName + "|" + ifName
            resMap[STP_VLAN_PORT_TABLE] = make(map[string]db.Value)
            resMap[STP_VLAN_PORT_TABLE][stpVlanPortKey] = db.Value{Field: stpVlanPortMap}
        }
    } else if isSubtreeRequest(targetUriPath, "/openconfig-spanning-tree:stp/openconfig-spanning-tree-ext:pvst") {
        if mode != "pvst" {
            return nil, nil 
        }

        if stp == nil || stp.Pvst == nil || stp.Pvst.Vlan == nil {
            log.Info("YangToDb_stp_vlan_port_xfmr: stp is empty")
            return nil, errors.New("Stp is not specified")
        }
    
        if ifName == "" {
            for uriIfName := range stp.Pvst.Vlan[uint16(vlan_id)].Interfaces.Interface {
                pvstVlanIntfConf := stp.Pvst.Vlan[uint16(vlan_id)].Interfaces.Interface[uriIfName]
                
                sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
                log.Infof("YangToDb_stp_vlan_port_xfmr: Interface name retrieved from alias : %s is %s", uriIfName, *sonicIfName)
                ifName = *sonicIfName

                convertOcPvstVlanIntfToInternal(inParams.d, pvstVlanIntfConf, stpVlanPortMap, inParams.oper, vlanName+"|"+ifName)
                stpVlanPortKey := vlanName + "|" + ifName
                resMap[STP_VLAN_PORT_TABLE] = make(map[string]db.Value)
                resMap[STP_VLAN_PORT_TABLE][stpVlanPortKey] = db.Value{Field: stpVlanPortMap}
            }
        } else {
            pvstVlanIntfConf, ok := stp.Pvst.Vlan[uint16(vlan_id)].Interfaces.Interface[uriIfName]
            if !ok {
                errStr := "Interface entry not found in Ygot tree, ifname: " + uriIfName
                log.Info("YangToDb_stp_vlan_port_xfmr : " + errStr)
                return resMap, errors.New(errStr)
            }

            sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
            log.Infof("YangToDb_stp_vlan_port_xfmr: Interface name retrieved from alias : %s is %s", uriIfName, *sonicIfName)
            ifName = *sonicIfName

            convertOcPvstVlanIntfToInternal(inParams.d, pvstVlanIntfConf, stpVlanPortMap, inParams.oper, vlanName+"|"+ifName) 
            stpVlanPortKey := vlanName + "|" + ifName
            resMap[STP_VLAN_PORT_TABLE] = make(map[string]db.Value)
            resMap[STP_VLAN_PORT_TABLE][stpVlanPortKey] = db.Value{Field: stpVlanPortMap}
        }
    } else {
        log.Info("Unsupported URI: ", targetUriPath)
        return nil, nil
    }

    log.Info("YangToDb_stp_vlan_port_xfmr resMap: ", resMap)
    return resMap, err
}

var DbToYang_stp_vlan_port_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error

    stp := getStpRoot(inParams.ygRoot)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _, _ := XfmrRemoveXPATHPredicates(pathInfo.Path)
    //targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    vlanName := "Vlan" + pathInfo.Var("vlan-id")
    vlan_id, _ := strconv.Atoi(pathInfo.Var("vlan-id"))
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    log.Info("DbToYang_stp_vlan_port_xfmr: vlanName: ", vlanName, " ifName: ", ifName)
    if !isVlanCreated(inParams.d, vlanName) {
        log.Infof("DbToYang_stp_vlan_port_xfmr : Vlan %s is not configured", vlanName)
        return nil
    }

    if stp == nil {
        log.Info("Stp is nil")
        ygot.BuildEmptyTree(stp)
    }

    mode, _ := getStpModeFromConfigDb(inParams.d)
    log.Info("DbToYang_stp_vlan_port_xfmr: targetUriPath: ", targetUriPath, " mode: ", mode)

    if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/rapid-pvst/vlan/interfaces/interface") {
        if mode != "rpvst" {
            return nil
        }

        rpvstVlanConf := stp.RapidPvst.Vlan[uint16(vlan_id)]
        if rpvstVlanConf == nil {
            ygot.BuildEmptyTree(rpvstVlanConf)
        }

        if ifName == "" {
            stpVlanPortKeys, _ := inParams.dbs[db.ApplDB].GetKeys(&db.TableSpec{Name:STP_APP_DB_VLAN_PORT_TABLE})
            for _, dbkey := range stpVlanPortKeys {
                if dbkey.Get(0) != vlanName {
                    continue
                }

                ifName := dbkey.Get(1)
                uriIfName := *(utils.GetUINameFromNativeName(&ifName))
                if uriIfName == "" {
                    log.Info("uriIfName NULL")
                    err = errors.New("uriIfName NULL")
                    return err
                }
        
                rpvstVlanIntfConf := rpvstVlanConf.Interfaces.Interface[uriIfName]
                if rpvstVlanIntfConf == nil {
                    rpvstVlanIntfConf, _ = rpvstVlanConf.Interfaces.NewInterface(uriIfName)
                }
                ygot.BuildEmptyTree(rpvstVlanIntfConf)

                convertInternalRpvstVlanIntfToOc(inParams, vlanName, ifName, uriIfName, targetUriPath, rpvstVlanIntfConf)
            }
        } else {
            sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
            log.Infof("DbToYang_stp_vlan_port_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
            ifName = *sonicIfName
            rpvstVlanConf := stp.RapidPvst.Vlan[uint16(vlan_id)]
            if rpvstVlanConf == nil {
                ygot.BuildEmptyTree(rpvstVlanConf)
            }
        
            rpvstVlanIntfConf := rpvstVlanConf.Interfaces.Interface[uriIfName]
            if rpvstVlanIntfConf == nil {
                rpvstVlanIntfConf, _ = rpvstVlanConf.Interfaces.NewInterface(uriIfName)
            }
            ygot.BuildEmptyTree(rpvstVlanIntfConf)

            convertInternalRpvstVlanIntfToOc(inParams, vlanName, ifName, uriIfName, targetUriPath, rpvstVlanIntfConf)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-spanning-tree:stp/pvst/vlan/interfaces/interface") {
        if mode != "pvst" {
            return nil
        }
        pvstVlanConf := stp.Pvst.Vlan[uint16(vlan_id)]
        if pvstVlanConf == nil {
            ygot.BuildEmptyTree(pvstVlanConf)
        }

        if ifName == "" {
            stpVlanPortKeys, _ := inParams.dbs[db.ApplDB].GetKeys(&db.TableSpec{Name:STP_APP_DB_VLAN_PORT_TABLE})
            for _, dbkey := range stpVlanPortKeys {
                if dbkey.Get(0) != vlanName {
                    continue
                }

                ifName := dbkey.Get(1)
                uriIfName := *(utils.GetUINameFromNativeName(&ifName))
                if uriIfName == "" {
                    log.Info("uriIfName NULL")
                    err = errors.New("uriIfName NULL")
                    return err
                }
        
                pvstVlanIntfConf := pvstVlanConf.Interfaces.Interface[uriIfName]
                if pvstVlanIntfConf == nil {
                    pvstVlanIntfConf, _ = pvstVlanConf.Interfaces.NewInterface(uriIfName)
                }
                ygot.BuildEmptyTree(pvstVlanIntfConf)

                convertInternalPvstVlanIntfToOc(inParams, vlanName, ifName, uriIfName, targetUriPath, pvstVlanIntfConf)
            }
        } else {
            sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
            log.Infof("DbToYang_stp_vlan_port_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
            ifName = *sonicIfName
            pvstVlanConf := stp.Pvst.Vlan[uint16(vlan_id)]
            if pvstVlanConf == nil {
                ygot.BuildEmptyTree(pvstVlanConf)
            }
        
            pvstVlanIntfConf := pvstVlanConf.Interfaces.Interface[uriIfName]
            if pvstVlanIntfConf == nil {
                pvstVlanIntfConf, _ = pvstVlanConf.Interfaces.NewInterface(uriIfName)
            }
            ygot.BuildEmptyTree(pvstVlanIntfConf)

            convertInternalPvstVlanIntfToOc(inParams, vlanName, ifName, uriIfName, targetUriPath, pvstVlanIntfConf)
        }
    }
    
    return err 
}
