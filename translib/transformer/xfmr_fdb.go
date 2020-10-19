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
    XlateFuncBind("YangToDb_mac_aging_time_xfmr", YangToDb_mac_aging_time_xfmr)
    XlateFuncBind("DbToYang_mac_aging_time_xfmr", DbToYang_mac_aging_time_xfmr)
    XlateFuncBind("rpc_clear_fdb", rpc_clear_fdb)
    XlateFuncBind("DbToYang_fdb_mac_table_count_xfmr", DbToYang_fdb_mac_table_count_xfmr)
    XlateFuncBind("Subscribe_fdb_mac_table_xfmr", Subscribe_fdb_mac_table_xfmr)
}

const (
    FDB_TABLE                = "FDB_TABLE"
    SONIC_ENTRY_TYPE_STATIC  = "SAI_FDB_ENTRY_TYPE_STATIC"
    SONIC_ENTRY_TYPE_DYNAMIC = "SAI_FDB_ENTRY_TYPE_DYNAMIC"
    ENTRY_TYPE               = "entry-type"
    DEFAULT_MAC_AGING_TIME   = "600"
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
        log.Error("YangToDb_fdb_mac_table_xfmr failed.")
        return nil, err
    }

    if strings.HasPrefix(instance, "Vrf") || strings.HasPrefix(instance, "mgmt") {
        log.Info("YangToDb_fdb_mac_table_xfmr Ignoring OP:",inParams.oper," for FDB on VRF:", instance)
        return nil, err
    }

    log.Info("YangToDb_fdb_mac_table_xfmr =>", inParams)

    var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)
    var fdbTblMap map[string]db.Value = make(map[string]db.Value)

    if len(pathInfo.Vars) < 3  {
        if (inParams.oper == DELETE) {
           /* For parent level DELETE just return FDB table" */
           res_map["FDB"] = fdbTblMap
           return res_map, nil
        }
    }

    key := "Vlan" + vlan + "|" + macAddr
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

func getASICStateMaps (inParams XfmrParams, vlanIdArg string) (map[string]map[string]db.Value, error) {
    oidTOVlan := make(map[string]string)
    brPrtOidToIntfOid := make(map[string]string)
    fdbMap := make(map[string]map[string]db.Value)
    d := inParams.dbs[db.AsicDB]

    tempFdb , present := inParams.txCache.Load("FDBASIC")
    if present {
        fdbMapCache,_ := tempFdb.(map[string]map[string]db.Value)
        if vlanIdArg != "" {
            fdbMap[vlanIdArg] = fdbMapCache[vlanIdArg]
        } else {
            fdbMap = fdbMapCache
        }
        if log.V(3) {
            log.Infof("getASICStateMaps - cache present FDB cache: %v", fdbMapCache)
            log.Infof("getASICStateMaps - VLAN %s FDB cache: %v ", vlanIdArg, fdbMap)
        }

        return fdbMap, nil
    }

    tblName := "ASIC_STATE"
    vlanPrefix := "SAI_OBJECT_TYPE_VLAN"
    bridgePortPrefix := "SAI_OBJECT_TYPE_BRIDGE_PORT"
    fdbPrefix := "SAI_OBJECT_TYPE_FDB_ENTRY"

    if log.V(3) {
        log.Infof("getASICStateMaps VLAN id :%s", vlanIdArg)
    }
    keys, tblErr := d.GetKeysByPattern(&db.TableSpec{Name: tblName, CompCt:2}, vlanPrefix+":*")
    if tblErr != nil {
        log.Error("Get Keys from ASIC_STATE VLAN table failed.", tblErr);
        return fdbMap, tblErr
    }
    var vlanOid string = ""
    for _, key := range keys {
        vlanKey := key.Comp[1]
        entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
        if dbErr != nil {
            log.Error("DB GetEntry failed for key : ", key)
            continue
        }
        if entry.Has("SAI_VLAN_ATTR_VLAN_ID") {
            vlanId := entry.Get("SAI_VLAN_ATTR_VLAN_ID")
            oidTOVlan[vlanKey] = vlanId
            if vlanIdArg != "" && (vlanId == vlanIdArg) {
                vlanOid = vlanKey
                break
            }
        }
    }
    if log.V(3) {
        log.Infof("getASICStateMaps OID to VLAN :%v", oidTOVlan)
    }

    keys, tblErr = d.GetKeysByPattern(&db.TableSpec{Name: tblName, CompCt:2}, bridgePortPrefix+":*")
    if tblErr != nil {
        log.Error("Get Keys from ASIC_STATE bridge port table failed.", tblErr);
        return fdbMap, tblErr
    }
    if log.V(3) {
        log.Infof("getASICStateMaps bridge port keys :%v", keys)
    }
    for _, key := range keys {
        brPKey := key.Comp[1]
        entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
        if dbErr != nil {
            log.Error("DB GetEntry failed for key : ", key)
            continue
        }
        if entry.Has("SAI_BRIDGE_PORT_ATTR_PORT_ID") {
            brPrtOidToIntfOid[brPKey] = entry.Get("SAI_BRIDGE_PORT_ATTR_PORT_ID")
        }
    }
    if log.V(3) {
        log.Infof("getASICStateMaps Port OID to Intf OID :%v", brPrtOidToIntfOid)
    }

    keys, tblErr = d.GetKeysByPattern(&db.TableSpec{Name: tblName, CompCt:2}, fdbPrefix+":*")
    if tblErr != nil {
        log.Error("Get Keys from ASIC_STATE FDB table failed.", tblErr);
        return fdbMap, tblErr
    }
    oidInfMap,_ := getOidToIntfNameMap(inParams.dbs[db.CountersDB])
    for _, key := range keys {
        if log.V(3) {
            log.Infof("getASICStateMaps FDB :%v", key)
        }
        if vlanOid != "" && (!strings.Contains(key.Comp[1], vlanOid)) {
            if log.V(3) {
                log.Infof("getASICStateMaps FDB SKIPPING for :%v", key)
            }
            continue
        }
        jsonData := make(map[string]interface{})
        err := json.Unmarshal([]byte(key.Comp[1]), &jsonData)
        if err != nil {
            log.Error("Failed parsing json for key ", key)
            continue
        }
        bvid := jsonData["bvid"]. (string)
        if _, ok  := oidTOVlan[bvid]; !ok {
            continue
        }
        vlanId := oidTOVlan[bvid]
        macstr := jsonData["mac"].(string)

        entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
        if dbErr != nil {
            log.Error("DB GetEntry failed for key : ", key)
            continue
        }
        if _, ok := fdbMap[vlanId]; !ok {
            fdbMap[vlanId] = make(map[string]db.Value)
        }
        if entry.Has("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID") {
            intfOid := findInMap(brPrtOidToIntfOid, entry.Get("SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID"))
            if intfOid != "" {
                intfName := findInMap(oidInfMap, intfOid)
                if intfName != "" {
                    /* If Alias mode is enabled, get alias name from native name */
                    cvtdName := utils.GetUINameFromNativeName(&intfName)
                    entry.Field["INTF_NAME"] = *cvtdName
                }
            }
        }
        fdbMap[vlanId][macstr] = entry
    }
    if !present && (vlanIdArg == "") {
        inParams.txCache.Store("FDBASIC", fdbMap)
        if log.V(3) {
            log.Infof("getASICStateMaps - cached FDB info: %v", fdbMap)
        }
    }
    return fdbMap, nil
}

func fdbMacTableGetAll (inParams XfmrParams, vlanId string) error {

    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")
    macTbl := getFdbMacTableRoot(inParams.ygRoot, instance, true)
    fdbMap, _ := getASICStateMaps(inParams, vlanId)

    ygot.BuildEmptyTree(macTbl.Entries)

    for vlan, macs := range fdbMap {
        for mac := range macs {
            fdbMacTableGetEntry(inParams, vlan, mac, fdbMap, macTbl)
        }
    }
    return nil
}

func fdbMacTableGetEntry(inParams XfmrParams, vlan string,  macAddress string, fdbMap map[string]map[string]db.Value, macTbl *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable) error {
    var err error

    vlanId, _ := strconv.Atoi(vlan)

    mcEntries := macTbl.Entries
    var mcEntry *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry
    var mcEntryKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Fdb_MacTable_Entries_Entry_Key
    mcEntryKey.MacAddress = macAddress
    mcEntryKey.Vlan = uint16(vlanId)

    if _, ok := fdbMap[vlan]; !ok {
        errStr := "vlan entry not found in FDB map, vlan: " + vlan
        log.Error(errStr)
        return errors.New(errStr)
    }
    if _, ok := fdbMap[vlan][macAddress]; !ok {
        errStr := "macAddress entry not found FDB map, macAddress: " + macAddress
        log.Error(errStr)
        return errors.New(errStr)
    }
    entry := fdbMap[vlan][macAddress]
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
        if entry.Has("INTF_NAME") {
            ifName := entry.Get("INTF_NAME")
            ygot.BuildEmptyTree(mcEntry.Interface)
            ygot.BuildEmptyTree(mcEntry.Interface.InterfaceRef)
            ygot.BuildEmptyTree(mcEntry.Interface.InterfaceRef.Config)
            mcEntry.Interface.InterfaceRef.Config.Interface = &ifName
            ygot.BuildEmptyTree(mcEntry.Interface.InterfaceRef.State)
            mcEntry.Interface.InterfaceRef.State.Interface = &ifName
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

    if strings.HasPrefix(instance, "Vrf") || strings.HasPrefix(instance, "mgmt") {
        return nil
    }
    var vlanId string = ""
    vlanString := strings.HasPrefix(instance, "Vlan")
    if (vlanString) {
        vlanId = strings.TrimPrefix(instance, "Vlan")
    }

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    if log.V(3) {
        log.Infof("targetUriPath %s vlan %s", targetUriPath, vlanId)
    }

    macTbl := getFdbMacTableRoot(inParams.ygRoot, instance, true)
    if macTbl == nil {
        log.Info("DbToYang_fdb_mac_table_xfmr - getFdbMacTableRoot returned nil, for URI: ", inParams.uri)
        return errors.New("Not able to get FDB MacTable root.");
    }

    ygot.BuildEmptyTree(macTbl)
    if vlan == "" || macAddress == "" {
        err = fdbMacTableGetAll (inParams, vlanId)
    } else {
        vlanString := strings.HasPrefix(vlan, "Vlan")
        if (vlanString) {
            vlan = strings.Replace(vlan, "", "Vlan", 1)
        }
        fdbMap, err := getASICStateMaps(inParams, vlan)
        if err != nil {
            log.Error("getASICStateMaps failed.")
            return err
        }
        err = fdbMacTableGetEntry(inParams, vlan, macAddress, fdbMap, macTbl)
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
    if strings.HasPrefix(instance, "Vrf") || strings.HasPrefix(instance, "mgmt") {
        return nil
    }

    var vlan string = ""
    vlanString := strings.HasPrefix(instance, "Vlan")
    if (vlanString) {
        vlan = strings.TrimPrefix(instance, "Vlan")
    }

    fdbTbl := getFdbRoot(inParams.ygRoot, instance, true)
    if fdbTbl == nil {
        log.Info("DbToYang_fdb_mac_table_count_xfmr - getFdbRoot returned nil, for URI: ", inParams.uri)
        return errors.New("Not able to get FDB root.");
    }
    ygot.BuildEmptyTree(fdbTbl)

    fdbMap, _ := getASICStateMaps(inParams, vlan)
    for vlan, macs := range fdbMap {
        for mac := range macs {
            entry := fdbMap[vlan][mac]
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

var DbToYang_mac_aging_time_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")

    if (instance != "default") {
        if log.V(3) {
            log.Info("DbToYang_mac_aging_time_xfmr Ignoring GET for MAC-aging on ", instance)
            return err
        }
    }
    fdbTbl := getFdbRoot(inParams.ygRoot, instance, true)
    if fdbTbl == nil {
        log.Error("DbToYang_mac_aging_time_xfmr - getFdbRoot returned nil, for URI: ", inParams.uri)
        return errors.New("Not able to get FDB root.");
    }
    ygot.BuildEmptyTree(fdbTbl)

    var configDB = inParams.dbs[db.ConfigDB]
    var switchTable = &db.TableSpec{Name: "SWITCH"}
    switchTbl, err := configDB.GetTable(switchTable)
    if err != nil {
        log.Error("DbToYang_mac_aging_time_xfmr Can't get table SWITCH")
        return err
    }

    keys, err := switchTbl.GetKeys()
    if err != nil {
        log.Error("DbToYang_mac_aging_time_xfmr Can't get keys from table")
        return  err
    }
    var macKeyCode,macAgingValue string
    for _, key := range keys {
        macKeyCode = key.Get(0)
        macAgingEntry, err := switchTbl.GetEntry(db.Key{Comp: []string{macKeyCode}})
        if err != nil {
            log.Error("Can't get entry with key: ", macKeyCode)
            return err
        }

        if macAgingEntry.Has("fdb_aging_time") {
            macAgingValue = macAgingEntry.Get("fdb_aging_time")
        }
    }
    macAgingValueInt, _ := strconv.Atoi(macAgingValue)
    macAgingTable := fdbTbl.Config
    macVal := uint32(macAgingValueInt)
    macAgingTable.MacAgingTime = &macVal

    return err
}


var YangToDb_mac_aging_time_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")
    targetUriPath, err  := getYangPathFromUri(inParams.uri)
    if err != nil {
        log.Error(" YangToDb_mac_aging_time_xfmr get targetUriPath failed.")
        return nil, err
    }

    if (instance != "default") {
        errStr := "Operation: "+strconv.Itoa(inParams.oper)+" not allowed for MAC aging-time on: "+instance
        log.Error(errStr)
        if inParams.oper != DELETE {
            return nil, tlerr.InvalidArgsError{Format:errStr}
        }
        return nil, err
    }

    var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)
    var switchMap map[string]db.Value = make(map[string]db.Value)

    key := "switch"
    dbV := db.Value{Field: make(map[string]string)}

    switch inParams.oper {
    case DELETE:
        tblName := "SWITCH"
        tblKey := "switch"
        subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
        subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        subOpMap[db.ConfigDB][tblName] = make(map[string]db.Value)
        subOpMap[db.ConfigDB][tblName][tblKey] = db.Value{Field: make(map[string]string)}
        subOpMap[db.ConfigDB][tblName][tblKey].Field["fdb_aging_time"] = DEFAULT_MAC_AGING_TIME

        inParams.subOpDataMap[UPDATE] = &subOpMap
        return nil, nil

    case CREATE:
        fallthrough
    case UPDATE:
        if targetUriPath == "/openconfig-network-instance:network-instances/network-instance/fdb/config"{
            fdbTbl := getFdbRoot(inParams.ygRoot, instance, true)
            if fdbTbl == nil {
                log.Error("YangToDb_mac_aging_time_xfmr - getFdbRoot returned nil, for URI: ", inParams.uri)
                return nil, errors.New("Not able to get FDB root.");
            }
            ygot.BuildEmptyTree(fdbTbl)
            macAgingTime := fdbTbl.Config.MacAgingTime
            macAgT := strconv.Itoa(int(*macAgingTime))
            dbV.Field["fdb_aging_time"] = macAgT
            switchMap[key] = dbV
            res_map["SWITCH"] = switchMap
            return res_map, nil
        }
    }
    return nil, err
}

