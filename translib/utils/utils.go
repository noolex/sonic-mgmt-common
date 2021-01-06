////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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


package utils

import (
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/cvl"
    "sync"
    "strings"
    "fmt"
    "strconv"
    log "github.com/golang/glog"
)

/* Needed to deserialize FEC info */
const (
    INTF_SEPARATOR = "<>"
    LANE_SEPARATOR = "|"
    SPEED_SEPARATOR = "--"
    FEC_SEPARATOR = ","
    INTF_TO_LANE_SEPARATOR = "@"
    SPEED_TO_FEC_SEPARATOR = "="
    LANE_TO_SPEED_SEPARATOR = ":"
    DB_TABLE_NAME_FEC_INFO = "INTERFACE"
    DB_KEY_NAME_FEC_INFO = "FEC_INFO"
    DB_FIELD_NAME_DEFAULT_FEC_MODES = "Intf_Default_Fec_Modes"
    DB_FIELD_NAME_SUPPORTED_FEC_MODES = "Intf_Supported_Fec_Modes"
)

/* Representation of FEC derivation table */
type fec_info_t map[string]map[string]map[string][]string

type vlan_member_list struct {
    tagged []string
    untagged []string //list of eth or portchannel interfaces 
}

var vlanMemberCache map[string]*vlan_member_list//*sync.Map

/* Cached map of the default FEC modes */
var default_fec_modes_cache fec_info_t
/* Cached map of the supported FEC modes */
var supported_fec_modes_cache fec_info_t

// Maintaining aliasMode based on the following flag
var aliasMode bool = false

// Interface Name to Alias Map
var ifNameAliasMap *sync.Map
// Alias to Interface Name Map
var aliasIfNameMap *sync.Map

func init() {
    portNotifSubscribe();
    populateAliasDS()
    devMetaNotifSubscribe();
}

// GenerateMemberPortsSliceFromString Convert string to slice
func GenerateMemberPortsSliceFromString(memberPortsStr *string) []string {
    if len(*memberPortsStr) == 0 {
        return nil
    }
    memberPorts := strings.Split(*memberPortsStr, ",")
    return memberPorts
}

// Input: range 10-100 or 10..100
func extractVlanIdsfrmRng(rngStr string, vlanLst *[]string) error {
    log.Info("-----------extractVlanIdsfrmRng------")
    var err error
    var res []string
    if strings.Contains(rngStr, "..") {
        res = strings.Split(rngStr, "..")
    }
    if strings.Contains(rngStr, "-") {
        res = strings.Split(rngStr, "-")
    }
    if len(res) != 0 {
        low, _ := strconv.Atoi(res[0])
        high, _ := strconv.Atoi(res[1])
        for id := low; id <= high; id++ {
            *vlanLst = append(*vlanLst, "Vlan"+strconv.Itoa(id))
        }
    }
    return err
}

func getDBOptions(dbNo db.DBNum, isWriteDisabled bool) db.Options {
    var opt db.Options

    switch dbNo {
    case db.ApplDB, db.CountersDB, db.AsicDB:
        opt = getDBOptionsWithSeparator(dbNo, "", ":", ":", isWriteDisabled)
    case db.FlexCounterDB, db.LogLevelDB, db.ConfigDB, db.StateDB, db.ErrorDB, db.UserDB:
        opt = getDBOptionsWithSeparator(dbNo, "", "|", "|", isWriteDisabled)
    }

    return opt
}

func getDBOptionsWithSeparator(dbNo db.DBNum, initIndicator string, tableSeparator string, keySeparator string, isWriteDisabled bool) db.Options {
    return (db.Options{
        DBNo:               dbNo,
        InitIndicator:      initIndicator,
        TableNameSeparator: tableSeparator,
        KeySeparator:       keySeparator,
        IsWriteDisabled:    isWriteDisabled,
    })
}

func updateCacheForPort(portKey *db.Key, d *db.DB) {
    portName := portKey.Get(0)
    portEntry, err := d.GetEntry(&db.TableSpec{Name:"PORT"}, *portKey)
    if err != nil {
        log.Errorf("Retrieval of entry for port: %s failed from port table", portName)
        return
    }
    if !portEntry.IsPopulated() {
        log.Errorf("PortEntry populated for port: %s failed", portName)
        return
    }
    aliasName, ok := portEntry.Field["alias"]
    if !ok {
        // don't return error, keep populating data structures
        log.V(3).Infof("Alias field not present for port: %s", portName)
        return
    }
    existingAliasName, ok := ifNameAliasMap.Load(portName)
    if ok {
        log.V(3).Infof("Alias name : %s already present for %s, updating with new alias name : %s", existingAliasName.(string), portName, aliasName)
    }
    ifNameAliasMap.Store(portName, aliasName)

    existingIfName, ok := aliasIfNameMap.Load(aliasName)
    if ok {
        log.V(3).Infof("Port name : %s already present for %s, updating with new port name : %s", existingIfName.(string), aliasName, portName)
    }
    aliasIfNameMap.Store(aliasName, portName)
    log.V(3).Infof("alias cache updated %s <==> %s", portName, aliasName)

    taggedVlanVal, ok := portEntry.Field["tagged_vlans@"]
    if ok {
        var taggedVlanSlice []string
        vlanRngSlice := GenerateMemberPortsSliceFromString(&taggedVlanVal)
        for _, vlanStr := range vlanRngSlice {
            if strings.Contains(vlanStr, "-") {
                _ = extractVlanIdsfrmRng(vlanStr, &taggedVlanSlice)
            } else {
                taggedVlanSlice = append(taggedVlanSlice, vlanStr)
            }
        }
        for _, vlan := range taggedVlanSlice {
            member_list, ok := vlanMemberCache[vlan]
            found := false
            if !ok {
                member_list = &vlan_member_list{}
            } else {
                //Check if portName already in tagged list
                for _, item := range member_list.tagged {
                    if item == portName {
                        found = true
                        break
                    }
                }
            }
            if !found { //Add portName to tagged list
                member_list.tagged = append(member_list.tagged, portName)
                vlanMemberCache[vlan] = member_list  //TODO:cache store only non-existing vlans
            }
        }
    }
    vlanVal, ok := portEntry.Field["access_vlan"]
    if ok {
        found := false
        member_list, ok := vlanMemberCache[vlanVal]
        if !ok {
            member_list = &vlan_member_list{}
        } else {
            //Check if portName already in untagged list
            for _, item := range member_list.untagged {
                if item == portName {
                    found = true
                    break
                }
            }
        }
        if !found { //Add portName to untagged list
            member_list.untagged = append(member_list.untagged, portName)
            vlanMemberCache[vlanVal] = member_list  //TODO:cache store only non-existing vlans
        }
    }
}

func deleteFromCacheForPort(portKey *db.Key) {
    portName := portKey.Get(0)

    aliasName, ok := ifNameAliasMap.Load(portName)
    if !ok {
        log.V(3).Infof("Port name %s not in Alias cache", portName)
        return
    }
    ifNameAliasMap.Delete(portName)

    _, _ok := aliasIfNameMap.Load(aliasName)
    if !_ok {
        log.V(3).Infof("Alias name %s for corresponding Port name %s not in Alias cache", aliasName, portName)
        return
    }
    aliasIfNameMap.Delete(aliasName)
    log.V(3).Infof("Deleted %s <==> %s from alias cache", portName, aliasName)
}


func portNotifHandler(d *db.DB, skey *db.SKey, key *db.Key, event db.SEvent) error {
    log.V(3).Info("***handler: d: ", d, " skey: ", *skey, " key: ", *key,
           " event: ", event)
    switch event {
    case db.SEventHSet, db.SEventHDel:
        updateCacheForPort(key, d)
    case db.SEventDel:
        deleteFromCacheForPort(key)
    }
    return nil
}

func dbNotifSubscribe(ts db.TableSpec, key db.Key, handler db.HFunc) error {

    var skeys []*db.SKey = make([]*db.SKey, 1)
    skeys[0] = & (db.SKey { 
        Ts: &ts,
        Key: &key,
        SEMap: map[db.SEvent]bool {
            db.SEventHSet:  true,
            db.SEventHDel:  true,
            db.SEventDel:   true,
        },
    })

    _,e := db.SubscribeDB(db.Options {
        DBNo              : db.ConfigDB,
        InitIndicator     : "CONFIG_DB_INITIALIZED",
        TableNameSeparator: "|",
        KeySeparator      : "|",
    }, skeys, handler)

    return e
}

func portNotifSubscribe() {
    var akey db.Key
    tsa := db.TableSpec { Name: "PORT" }

    ca := make([]string, 1)
    ca[0] = "*"
    akey = db.Key { Comp: ca}

    e := dbNotifSubscribe(tsa, akey, portNotifHandler)
    if e != nil {
        log.Info("dbNotifSubscribe() returns error : ", e)
    }

    log.Info("PORT table subscribe done....");
}

func devMetaNotifHandler(d *db.DB, skey *db.SKey, key *db.Key, event db.SEvent) error {
    log.V(3).Info("***handler: d: ", d, " skey: ", *skey, " key: ", *key,
           " event: ", event)
    switch event {
    case db.SEventHSet, db.SEventHDel:
        updateAliasFromDB(key, d)
    }

    return nil
}

func updateAliasFromDB(key *db.Key, d *db.DB) {
    key0 := key.Get(0)
    entry, err := d.GetEntry(&db.TableSpec{Name:"DEVICE_METADATA"}, *key)
    if err != nil {
        log.Errorf("Retrieval of entry for %s failed from port table", key0)
        return
    }
    aliasVal, ok := entry.Field["intf_naming_mode"]
    if !ok {
        // don't return error, keep populating data structures
        aliasMode = false
        log.V(3).Infof("intf_naming_mode not present, disabling alias mode")
        return
    }
    aliasMode = (aliasVal == "standard")
    log.V(3).Infof("aliasMode set to %v", aliasMode);
}

func devMetaNotifSubscribe() {
    var akey db.Key
    tsa := db.TableSpec { Name: "DEVICE_METADATA" }

    ca := make([]string, 1)
    ca[0] = "*"
    akey = db.Key { Comp: ca}

    e := dbNotifSubscribe(tsa, akey, devMetaNotifHandler)
    if e != nil {
        log.Info("dbNotifSubscribe() returns error : ", e)
    }

    log.Info("DEVICE_METADATA table subscribe done....");
}

func populateAliasDS() error {
    var err error

    ifNameAliasMap = new(sync.Map)
    aliasIfNameMap = new(sync.Map)
    vlanMemberCache = make(map[string]*vlan_member_list)

    d, err := db.NewDB(getDBOptions(db.ConfigDB, false))
    if err != nil {
        log.Error("Instantiation of config-db failed!")
        return err
    }
    portTbl, err := d.GetTable(&db.TableSpec{Name: "PORT"})
    if err != nil {
        log.Error("Get PORT table failed")
        return err
    }
    portKeys, err := portTbl.GetKeys()
    if err != nil {
        log.Error("Retrieval of keys from PORT table failed!")
        return err
    }
    for _, portKey := range portKeys {
        updateCacheForPort(&portKey, d)
    }

    updateAliasFromDB(&db.Key{Comp: []string{"localhost"}}, d)

    return err
}

func IsAliasModeEnabled() bool {
    return  aliasMode
}

func GetAliasMode() bool {
    return aliasMode
}

func SetAliasMode(enableMode bool) {
    aliasMode = enableMode
}

// GetNativeNameFromUIName returns physical interface name for alias-name
func GetNativeNameFromUIName(uiName *string) *string {
	if !IsAliasModeEnabled() {
		return uiName
	}

	parts := strings.Split(*uiName, ",")
	converted := make([]string, len(parts))
	for idx, part := range parts {
		ifName, ok := aliasIfNameMap.Load(*uiName)
		if ok {
			converted[idx] = ifName.(string)
		} else {
			converted[idx] = part
		}
	}
	ret := strings.Join(converted, ",")
	log.V(3).Infof("%s => %s", *uiName, ret)

	return &ret
}

// GetUINameFromNativeName returns alias-name for physical interface Name
func GetUINameFromNativeName(ifName *string) *string {
	if !IsAliasModeEnabled() {
		return ifName
	}

	parts := strings.Split(*ifName, ",")
	converted := make([]string, len(parts))
	for idx, part := range parts {
		aliasName, ok := ifNameAliasMap.Load(part)
		if ok {
			converted[idx] = aliasName.(string)
		} else {
			converted[idx] = part
		}
	}
	ret := strings.Join(converted, ",")
	log.V(3).Infof("%s => %s", *ifName, ret)

	return &ret
}

func IsValidAliasName(ifName *string) bool {
    _, ok := aliasIfNameMap.Load(*ifName)
    return ok
}

// GetFromCacheVlanMemberList Get tagged/untagged list for given vlan
func GetFromCacheVlanMemberList(vlanName string) ([]string, []string) {
    if memberlist, ok := vlanMemberCache[vlanName]; ok {
        return memberlist.tagged, memberlist.untagged
    }
    return nil, nil
}

// SortAsPerTblDeps - sort transformer result table list based on dependencies (using CVL API) tables to be used for CRUD operations
func SortAsPerTblDeps(tblLst []string) ([]string, error) {
        var resultTblLst []string
        var err error
        logStr := "Failure in CVL API to sort table list as per dependencies."

        cvSess, cvlRetSess := cvl.ValidationSessOpen()
        if cvlRetSess != cvl.CVL_SUCCESS {

                log.Errorf("Failure in creating CVL validation session object required to use CVl API(sort table list as per dependencies) - %v", cvlRetSess)
                err = fmt.Errorf("%v", logStr)
                return resultTblLst, err
        }
        cvlSortDepTblList, cvlRetDepTbl := cvSess.SortDepTables(tblLst)
        if cvlRetDepTbl != cvl.CVL_SUCCESS {
                log.Warningf("Failure in cvlSess.SortDepTables: %v", cvlRetDepTbl)
                cvl.ValidationSessClose(cvSess)
                err = fmt.Errorf("%v", logStr)
                return resultTblLst, err
        }
        log.Info("cvlSortDepTblList = ", cvlSortDepTblList)
        resultTblLst = cvlSortDepTblList

        cvl.ValidationSessClose(cvSess)
        return resultTblLst, err

}

// RemoveElement - Remove a specific string from a list of strings
func RemoveElement(sl []string, str string) []string {
    for i := 0; i < len(sl); i++ {
        if sl[i] == str {
            sl = append(sl[:i], sl[i+1:]...)
            i--
            break
        }
    }
    return sl
}

// Load_fec_info_from_db_to_cache : Load the FEC data from the DB into cache
func load_fec_info_from_db_to_cache() {
    serialized_default_fec_modes_string := ""
    serialized_supported_fec_modes_string := ""


    d, err := db.NewDB(getDBOptions(db.StateDB, false))
    if err != nil {
        log.Error("Instantiation of StateDB failed!")
    }

    serialized_db_entries, err := d.GetEntry(&db.TableSpec{Name:DB_TABLE_NAME_FEC_INFO}, db.Key{Comp: []string{DB_KEY_NAME_FEC_INFO}})
    if err != nil {
        log.Error("Unable to read supported and default FEC info from DB")
        return
    }
    // Read default
    serialized_default_fec_modes_string = serialized_db_entries.Get(DB_FIELD_NAME_DEFAULT_FEC_MODES)
    // Read supported
    serialized_supported_fec_modes_string = serialized_db_entries.Get(DB_FIELD_NAME_SUPPORTED_FEC_MODES)

    // Get the map from the flattened string
    default_fec_modes_cache = deserialize_fec_to_map(serialized_default_fec_modes_string)

    supported_fec_modes_cache = deserialize_fec_to_map(serialized_supported_fec_modes_string)
    log.Info("Done with FEC deserialize")
    log.Info("Deserialized default FEC: ", default_fec_modes_cache)
    log.Info("Deserialized default FEC: ", supported_fec_modes_cache)
}

func deserialize_fec_to_map(serialized_fec_str string) fec_info_t {
    if serialized_fec_str == ""{
        log.Info("Nothing to deserialize")
        return nil
    }
    ret_map := make(fec_info_t)

    intf_tokens := strings.Split(serialized_fec_str, INTF_SEPARATOR)
    for _, intf_tok := range intf_tokens {
        intf_lane_combo := strings.Split(intf_tok, INTF_TO_LANE_SEPARATOR)
        lane_info_map := make(map[string]map[string][]string)

        // Split by LANE_SEPARATOR to get the tokens by lane
        lane_tokens := strings.Split(intf_lane_combo[1], LANE_SEPARATOR)
        for _, lane_tok := range lane_tokens {
            speed_info_map := make(map[string][]string)
            // Get the right lane
            lane_speed_combo := strings.Split(lane_tok, LANE_TO_SPEED_SEPARATOR)
            speed_tokens := strings.Split(lane_speed_combo[1], SPEED_SEPARATOR)

            for _, speed_tok := range speed_tokens {
                speed_fec_combo :=  strings.Split(speed_tok, SPEED_TO_FEC_SEPARATOR)
                speed_info_map[speed_fec_combo[0]] = strings.Split(speed_fec_combo[1], FEC_SEPARATOR)
            }
            lane_info_map[lane_speed_combo[0]] = speed_info_map
        }
        ret_map[intf_lane_combo[0]] = lane_info_map
    }
    return ret_map
}

// Get_supported_fec_list : For the given params, what are the FEC modes allowed
func Get_supported_fec_list(ifname string, lane_count int, speed string) []string{
    lane_c := strconv.Itoa(lane_count)

    if len(supported_fec_modes_cache) == 0 {
        log.Info("Running one-time loading of FEC info from DB to cache")
        load_fec_info_from_db_to_cache()
    }

    if supp_list, ok := supported_fec_modes_cache[ifname][lane_c][speed]; ok {
        return supp_list
    }
    return []string{"none"}
}
// Get_default_fec : For the given params, whats the default FEC mode
func Get_default_fec(ifname string, lane_count int, speed string) string{
    lane_c := strconv.Itoa(lane_count)

    if len(default_fec_modes_cache) == 0 {
        log.Info("Running one-time loading of FEC info from DB to cache")
        load_fec_info_from_db_to_cache()
    }

    if ret, ok := default_fec_modes_cache[ifname][lane_c][speed]; ok {
        // Use the first value
        return string(ret[0])
    }
    // Default when no data available
    return "none"
}

// Is_fec_mode_valid : Given the params, is the specified FEC mode valid for the params?
func Is_fec_mode_valid(ifname string, lane_count int, speed string, fec string) bool {

    supp_list := Get_supported_fec_list(ifname, lane_count, speed)

    for _, val := range supp_list{
        if val == fec{
            return true
        }
    }
    return false
}

func GetSubInterfaceShortName(longName *string) *string {
    var shortName string

    parts := strings.Split(*longName, ".")
    parentif := parts[0]
    subif := parts[1]

    parentif = *GetNativeNameFromUIName(&parentif)
    fullName := parentif+"."+subif

    if strings.Contains(fullName, "Ethernet") {
        shortName = strings.Replace(fullName, "Ethernet", "Eth", -1)
    } else if strings.Contains(fullName, "PortChannel") {
        shortName = strings.Replace(fullName, "PortChannel", "po", -1)
    } else {
        shortName = fullName
    }

    log.V(3).Infof("GetSubInterfaceShortName %s => %s", *longName, shortName)

    return &shortName
}

func GetSubInterfaceLongName(shortName *string) *string {
    var longName string

    if strings.Contains(*shortName, "Eth") {
        longName = strings.Replace(*shortName, "Eth", "Ethernet", -1)
    } else if strings.Contains(*shortName, "po") {
        longName = strings.Replace(*shortName, "po", "PortChannel", -1)
    } else {
        longName = *shortName
    }

    parts := strings.Split(longName, ".")
    parentif := parts[0]
    subif := parts[1]

    parentif = *GetUINameFromNativeName(&parentif)
    longName = parentif+"."+subif

    log.V(3).Infof("GetSubInterfaceLongName %s => %s", *shortName, longName)

    return &longName
}

func GetSubInterfaceDBKeyfromParentInterfaceAndSubInterfaceID (parentIf *string, subId *string) *string {
    longkey := *GetNativeNameFromUIName(parentIf) + "." + *subId
    key := *GetSubInterfaceShortName(&longkey)
    log.V(3).Infof("GetSubInterfaceDBKeyfromParentInterfaceAndSubInterfaceID %s + %s => %s", *parentIf, *subId, key)
    return &key
}
