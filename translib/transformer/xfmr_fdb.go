package transformer

import (
    "errors"
    "strings"
    "strconv"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    log "github.com/golang/glog"
)

func init () {
    XlateFuncBind("YangToDb_fdb_mac_table_xfmr", YangToDb_fdb_mac_table_xfmr)
    XlateFuncBind("DbToYang_fdb_mac_table_xfmr", DbToYang_fdb_mac_table_xfmr)
    XlateFuncBind("rpc_clear_fdb", rpc_clear_fdb)
    XlateFuncBind("DbToYang_fdb_mac_table_count_xfmr", DbToYang_fdb_mac_table_count_xfmr)
    XlateFuncBind("Subscribe_fdb_mac_table_xfmr", Subscribe_fdb_mac_table_xfmr)
}

const (
    FDB_TABLE                = "FDB_TABLE"
    SONIC_ENTRY_TYPE_STATIC  = "SAI_FDB_ENTRY_TYPE_STATIC"
    SONIC_ENTRY_TYPE_DYNAMIC = "SAI_FDB_ENTRY_TYPE_DYNAMIC"
    ENTRY_TYPE               = "entry-type"
)

var FDB_ENTRY_TYPE_MAP = map[string]string{
    strconv.FormatInt(int64(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry_State_EntryType_STATIC), 10): SONIC_ENTRY_TYPE_STATIC,
    strconv.FormatInt(int64(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry_State_EntryType_DYNAMIC), 10): SONIC_ENTRY_TYPE_DYNAMIC,
}

var rpc_clear_fdb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var  valLst [2]string
    var data  []byte
    var mapData map[string]interface{}

    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Error("Failed to unmarshal input body; err=%v", err)
    }

    input := mapData["sonic-fdb:input"]
    mapData = input.(map[string]interface{})

    valLst[0]= "ALL"
    valLst[1] = "ALL"

    if value, ok := mapData["VLAN"].(string) ; ok {
        valLst[0]= "VLAN"
        valLst[1] = value
    }
    if value, ok := mapData["PORT"].(string) ; ok {
        valLst[0]= "PORT"
        /* If Alias mode is enabled, get native name from alias name */
        cvtdName := utils.GetNativeNameFromUIName(&value)
        valLst[1] = *cvtdName
    }
    data, err = json.Marshal(valLst)

    if err != nil {
        log.Error("Failed to  marshal input data; err=%v", err)
        return nil, err
    }

    err = dbs[db.ApplDB].Publish("FLUSHFDBREQUEST",data)
    return nil, err
}


func getFdbRoot (s *ygot.GoStruct, instance string, build bool) *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb {
    var fdbObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb

    deviceObj := (*s).(*ocbinds.Device)
    niObj := deviceObj.NetworkInstances

    if instance == "" {
        instance = "default"
    }
    if niObj != nil {
        if niObj.NetworkInstance != nil && len(niObj.NetworkInstance) > 0 {
            if _, ok := niObj.NetworkInstance[instance]; ok {
                niInst := niObj.NetworkInstance[instance]
                if niInst.Fdb != nil {
                    fdbObj = niInst.Fdb
                }
            }
        }
    }

    if fdbObj == nil && (build) {
        if niObj.NetworkInstance == nil || len(niObj.NetworkInstance) < 1 {
            ygot.BuildEmptyTree(niObj)
        }
        var niInst *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance
        if _, ok := niObj.NetworkInstance[instance]; !ok {
            niInst, _  = niObj.NewNetworkInstance(instance)
        } else {
            niInst = niObj.NetworkInstance[instance]
        }
        ygot.BuildEmptyTree(niInst)
        if niInst.Fdb == nil {
            ygot.BuildEmptyTree(niInst.Fdb)
        }
        fdbObj = niInst.Fdb
    }

    return fdbObj
}

func getFdbMacTableRoot (s *ygot.GoStruct, instance string, build bool) *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable {
    var fdbMacTableObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable

    deviceObj := (*s).(*ocbinds.Device)
    niObj := deviceObj.NetworkInstances

    if instance == "" {
        instance = "default"
    }
    if niObj != nil {
        if niObj.NetworkInstance != nil && len(niObj.NetworkInstance) > 0 {
            if _, ok := niObj.NetworkInstance[instance]; ok {
                niInst := niObj.NetworkInstance[instance]
                if niInst.Fdb != nil {
                    fdbMacTableObj = niInst.Fdb.MacTable
                }
            }
        }
    }

    if fdbMacTableObj == nil && (build) {
        if niObj.NetworkInstance == nil || len(niObj.NetworkInstance) < 1 {
            ygot.BuildEmptyTree(niObj)
        }
        var niInst *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance
        if _, ok := niObj.NetworkInstance[instance]; !ok {
            niInst, _  = niObj.NewNetworkInstance(instance)
        } else {
            niInst = niObj.NetworkInstance[instance]
        }
        ygot.BuildEmptyTree(niInst)
        if niInst.Fdb.MacTable == nil {
            ygot.BuildEmptyTree(niInst.Fdb)
        }
        fdbMacTableObj = niInst.Fdb.MacTable
    }

    return fdbMacTableObj
}

func validateMacAddr (macAdd string) string {
    macAddr := strings.ToLower(macAdd)
    errStr := ""
    if macAddr == "00:00:00:00:00:00" {
        errStr = "Invalid (Zero) MAC address"
    } else if macAddr == "ff:ff:ff:ff:ff:ff" {
        errStr = "Invalid (Broadcast) MAC address"
    } else {
        macSplit := strings.Split(macAddr, ":")
        macHi, err := strconv.ParseUint(macSplit[0], 16, 8)
        if err != nil {
            errStr = "Invalid MAC address"
        } else if macHi & 0x01 == 0x01 {
            errStr = "Invalid (Multicast) MAC address"
        } else {
            return errStr
        }
    }
    return errStr
}

var YangToDb_fdb_mac_table_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    pathInfo := NewPathInfo(inParams.uri)
    macAddr := pathInfo.Var("mac-address")
    vlan := pathInfo.Var("vlan")
    instance := pathInfo.Var("name")
    targetUriPath, err  := getYangPathFromUri(inParams.uri)
    if err != nil {
        log.Error("getASICStateMaps failed.")
        return nil, err
    }

    if strings.HasPrefix(instance, "Vrf") || strings.HasPrefix(instance, "mgmt") {
        log.Info("YangToDb_fdb_mac_table_xfmr Ignoring OP:",inParams.oper," for FDB on VRF:", instance)
        return nil, err
    }

    log.Info("YangToDb_fdb_mac_table_xfmr =>", inParams)

    key := "Vlan" + vlan + "|" + macAddr
    var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)
    var fdbTblMap map[string]db.Value = make(map[string]db.Value)
    dbV := db.Value{Field: make(map[string]string)}

    macTbl := getFdbMacTableRoot(inParams.ygRoot, instance, true)
    if macTbl == nil {
        log.Info("YangToDb_fdb_mac_table_xfmr - getFdbMacTableRoot returned nil, for URI: ", inParams.uri)
        return nil, err
    }
    ygot.BuildEmptyTree(macTbl)

    switch inParams.oper {
    case DELETE:
        fdbTblMap[key] = dbV
        res_map["FDB"] = fdbTblMap
        return res_map, nil
    case CREATE:
        fallthrough
    case UPDATE:
        if targetUriPath == "/openconfig-network-instance:network-instances/network-instance/fdb/mac-table/entries/entry/interface/interface-ref/config"{
            errStr := validateMacAddr(macAddr)
            if errStr != "" {
                log.Error(errStr)
                return nil, tlerr.InvalidArgsError{Format:errStr}
            }
            vlanId, _ := strconv.Atoi(vlan)
            var mcEntryKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry_Key
            mcEntryKey.MacAddress = macAddr
            mcEntryKey.Vlan = uint16(vlanId)
            intfRef := macTbl.Entries.Entry[mcEntryKey]
            intfName := intfRef.Interface.InterfaceRef.Config.Interface
            dbV.Field["port"] = *intfName
            fdbTblMap[key] = dbV
            res_map["FDB"] = fdbTblMap
            return res_map, nil
        }
    }
    return nil, err
}

func getOidToIntfNameMap (d *db.DB) (map[string]string, error) {
    tblTs := &db.TableSpec{Name:"COUNTERS_PORT_NAME_MAP"}
    oidToIntf :=  make(map[string]string)
    intfOidEntry, err := d.GetMapAll(tblTs)
    if err != nil || !intfOidEntry.IsPopulated() {
        log.Error("Reading Port OID map failed.", err)
        return oidToIntf, err
    }
    for intf, oid := range intfOidEntry.Field {
        oidToIntf[oid] = intf
    }

    return oidToIntf, nil
}

func getASICStateMaps (d *db.DB) (map[string]string, map[string]string, map[string]map[string]db.Value, error) {
    oidTOVlan := make(map[string]string)
    brPrtOidToIntfOid := make(map[string]string)
    fdbMap := make(map[string]map[string]db.Value)

    tblName := "ASIC_STATE"
    vlanPrefix := "SAI_OBJECT_TYPE_VLAN"
    bridgePortPrefix := "SAI_OBJECT_TYPE_BRIDGE_PORT"
    fdbPrefix := "SAI_OBJECT_TYPE_FDB_ENTRY"

    keys, tblErr := d.GetKeys(&db.TableSpec{Name:tblName, CompCt:2} )
    if tblErr != nil {
        log.Error("Get Keys from ASIC_STATE table failed.", tblErr);
        return oidTOVlan, brPrtOidToIntfOid, fdbMap, tblErr
    }

    for _, key := range keys {

        if key.Comp[0] == vlanPrefix {
            vlanKey := key.Comp[1]
            entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
            if dbErr != nil {
                log.Error("DB GetEntry failed for key : ", key)
                continue
            }
            if entry.Has("SAI_VLAN_ATTR_VLAN_ID") {
                oidTOVlan[vlanKey] = entry.Get("SAI_VLAN_ATTR_VLAN_ID")
            }
        } else if key.Comp[0] == bridgePortPrefix {
            brPKey := key.Comp[1]
            entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
            if dbErr != nil {
                log.Error("DB GetEntry failed for key : ", key)
                continue
            }
            if entry.Has("SAI_BRIDGE_PORT_ATTR_PORT_ID") {
                brPrtOidToIntfOid[brPKey] = entry.Get("SAI_BRIDGE_PORT_ATTR_PORT_ID")
            }
        } else if key.Comp[0] == fdbPrefix {
            jsonData := make(map[string]interface{})
            err := json.Unmarshal([]byte(key.Get(1)), &jsonData)
            if err != nil {
                log.Info("Failed parsing json")
                continue
            }
            bvid := jsonData["bvid"].(string)
            macstr := jsonData["mac"].(string)

            entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
            if dbErr != nil {
                log.Error("DB GetEntry failed for key : ", key)
                continue
            }
            if _, ok := fdbMap[bvid]; !ok {
                fdbMap[bvid] = make(map[string]db.Value)
            }
            fdbMap[bvid][macstr] = entry
        } else {
            continue
        }
    }
    return oidTOVlan, brPrtOidToIntfOid, fdbMap, nil
}

func fdbMacTableGetAll (inParams XfmrParams) error {

    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")
    macTbl := getFdbMacTableRoot(inParams.ygRoot, instance, true)
    oidToVlan, brPrtOidToIntfOid, fdbMap, _ := getASICStateMaps(inParams.dbs[db.AsicDB])
    OidInfMap,_  := getOidToIntfNameMap(inParams.dbs[db.CountersDB])

    ygot.BuildEmptyTree(macTbl.Entries)

    for vlanOid, vlanEntry := range fdbMap {
        if _, ok  := oidToVlan[vlanOid]; !ok {
            continue
        }
        vlan := oidToVlan[vlanOid]
        for mac := range vlanEntry {
            fdbMacTableGetEntry(inParams, vlan, mac, OidInfMap, oidToVlan, brPrtOidToIntfOid, fdbMap, macTbl)
        }
    }
    return nil
}

func fdbMacTableGetEntry(inParams XfmrParams, vlan string,  macAddress string, oidInfMap map[string]string, oidTOVlan map[string]string, brPrtOidToIntfOid map[string]string, fdbMap map[string]map[string]db.Value, macTbl *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable) error {
    var err error

    vlanOid := findInMap(oidTOVlan, vlan)
    vlanId, _ := strconv.Atoi(vlan)

    pathInfo := NewPathInfo(inParams.uri)
    niName := pathInfo.Var("name")


    // if network instance is a VLAN instance, only get entries for this VLAN.
    if strings.HasPrefix(niName, "Vlan") {
        niVlanId := strings.TrimPrefix(niName, "Vlan")
        if vlan != niVlanId {
            return nil
        }
    }

    mcEntries := macTbl.Entries
    var mcEntry *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry
    var mcEntryKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry_Key
    mcEntryKey.MacAddress = macAddress
    mcEntryKey.Vlan = uint16(vlanId)

    if _, ok := fdbMap[vlanOid]; !ok {
        errStr := "vlanOid entry not found in FDB map, vlanOid: " + vlanOid
        log.Error(errStr)
        return errors.New(errStr)
    }
    if _, ok := fdbMap[vlanOid][macAddress]; !ok {
        errStr := "macAddress entry not found FDB map, macAddress: " + macAddress
        log.Error(errStr)
        return errors.New(errStr)
    }
    entry := fdbMap[vlanOid][macAddress]
    if _, ok := mcEntries.Entry[mcEntryKey]; !ok {
        _, err := mcEntries.NewEntry(macAddress, uint16(vlanId))
        if err != nil {
            log.Error("FDB NewEntry create failed." + vlan + " " + macAddress)
            return errors.New("FDB NewEntry create failed, " + vlan + " " + macAddress)
        }
    }

    mcEntry  = mcEntries.Entry[mcEntryKey]
    ygot.BuildEmptyTree(mcEntry)
    mcMac := new(string)
    mcVlan := new(uint16)
    *mcMac = macAddress
    *mcVlan = uint16(vlanId)
    ygot.BuildEmptyTree(mcEntry.Config)
    mcEntry.Config.MacAddress = mcMac
    mcEntry.Config.Vlan = mcVlan
    ygot.BuildEmptyTree(mcEntry.State)
    mcEntry.State.MacAddress = mcMac
    mcEntry.State.Vlan = mcVlan
    if entry.Has("SAI_FDB_ENTRY_ATTR_TYPE") {
        fdbEntryType := entry.Get("SAI_FDB_ENTRY_ATTR_TYPE")
        if fdbEntryType == SONIC_ENTRY_TYPE_STATIC {
            mcEntry.State.EntryType = ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry_State_EntryType_STATIC
        } else {
            mcEntry.State.EntryType = ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry_State_EntryType_DYNAMIC
        }
    }

    var fdbEntryRemoteIpAddress = new(string)
    if  entry.Has("SAI_FDB_ENTRY_ATTR_ENDPOINT_IP") {
        *fdbEntryRemoteIpAddress = entry.Get("SAI_FDB_ENTRY_ATTR_ENDPOINT_IP")
    } else {
        *fdbEntryRemoteIpAddress = "0.0.0.0"
    }

    if *fdbEntryRemoteIpAddress == "0.0.0.0" {
        if  entry.Has("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID") {
            intfOid := findInMap(brPrtOidToIntfOid, entry.Get("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID"))
            if intfOid != "" {
                intfName := new(string)
                *intfName = findInMap(oidInfMap, intfOid)
                if *intfName != "" {
                    /* If Alias mode is enabled, get alias name from native name */
                    cvtdName := utils.GetUINameFromNativeName(intfName)
                    ygot.BuildEmptyTree(mcEntry.Interface)
                    ygot.BuildEmptyTree(mcEntry.Interface.InterfaceRef)
                    ygot.BuildEmptyTree(mcEntry.Interface.InterfaceRef.Config)
                    mcEntry.Interface.InterfaceRef.Config.Interface = cvtdName
                    ygot.BuildEmptyTree(mcEntry.Interface.InterfaceRef.State)
                    mcEntry.Interface.InterfaceRef.State.Interface = cvtdName
                }
            }
        }
    } else {
        ygot.BuildEmptyTree(mcEntry.Peer)
        ygot.BuildEmptyTree(mcEntry.Peer.Config)
        ygot.BuildEmptyTree(mcEntry.Peer.State)
        mcEntry.Peer.State.PeerIp = fdbEntryRemoteIpAddress
    }

    return err
}

var DbToYang_fdb_mac_table_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")
    vlan := pathInfo.Var("vlan")
    macAddress := pathInfo.Var("mac-address")

    if strings.HasPrefix(instance, "Vrf") {
        return nil
    }

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath is ", targetUriPath)

    macTbl := getFdbMacTableRoot(inParams.ygRoot, instance, true)
    if macTbl == nil {
        log.Info("DbToYang_fdb_mac_table_xfmr - getFdbMacTableRoot returned nil, for URI: ", inParams.uri)
        return errors.New("Not able to get FDB MacTable root.");
    }

    ygot.BuildEmptyTree(macTbl)
    if vlan == "" || macAddress == "" {
        err = fdbMacTableGetAll (inParams)
    } else {
        vlanString := strings.HasPrefix(vlan, "Vlan")
        if (vlanString) {
            vlan = strings.Replace(vlan, "", "Vlan", 1)
        }
        oidToVlan, brPrtOidToIntfOid, fdbMap, err := getASICStateMaps(inParams.dbs[db.AsicDB])
        if err != nil {
            log.Error("getASICStateMaps failed.")
            return err
        }
        oidInfMap,_  := getOidToIntfNameMap(inParams.dbs[db.CountersDB])
        err = fdbMacTableGetEntry(inParams, vlan, macAddress, oidInfMap, oidToVlan, brPrtOidToIntfOid, fdbMap, macTbl)
        if err != nil {
            log.Error("Failed to fetch MAC table entry; err=%v", err)
        }
    }

    return err
}


var DbToYang_fdb_mac_table_count_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var staticCount,dynamicCount uint32 = 0,0
    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")

    fdbTbl := getFdbRoot(inParams.ygRoot, instance, true)
    if fdbTbl == nil {
        log.Info("DbToYang_fdb_mac_table_count_xfmr - getFdbRoot returned nil, for URI: ", inParams.uri)
        return errors.New("Not able to get FDB root.");
    }
    ygot.BuildEmptyTree(fdbTbl)

    oidToVlan, _, fdbMap, _ := getASICStateMaps(inParams.dbs[db.AsicDB])
    for vlanOid, vlanEntry := range fdbMap {
        if _, ok  := oidToVlan[vlanOid]; !ok {
            continue
        }
        for mac := range vlanEntry {
            entry := fdbMap[vlanOid][mac]
            if entry.Has("SAI_FDB_ENTRY_ATTR_TYPE") {
                fdbEntryType := entry.Get("SAI_FDB_ENTRY_ATTR_TYPE")
                if fdbEntryType == SONIC_ENTRY_TYPE_STATIC {
                    staticCount++
                } else {
                    dynamicCount++
                }
            }
        }
    }
    countTbl := fdbTbl.State
    countTbl.StaticCount = &staticCount
    countTbl.DynamicCount = &dynamicCount

    return err
}

var Subscribe_fdb_mac_table_xfmr = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    log.Info("Entering Subscribe_fdb_mac_table_xfmr")
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)
    pathInfo := NewPathInfo(inParams.uri)
    macAddr := pathInfo.Var("mac-address")
    vlan := pathInfo.Var("vlan")
    keyName := "Vlan" + vlan + "|" + macAddr
    tblName := "FDB"
    result.dbDataMap = RedisDbMap{db.ConfigDB:{tblName:{keyName:{}}}}

    result.needCache = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 15
    result.nOpts.pType = OnChange
    log.Info("Returning Subscribe_fdb_mac_table_xfmr, result:", result)
    return result, err
}

