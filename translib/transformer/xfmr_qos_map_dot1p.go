package transformer

import (
    "strings"
    "strconv"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)
func init () {
    XlateFuncBind("YangToDb_qos_dot1p_fwd_group_xfmr", YangToDb_qos_dot1p_fwd_group_xfmr)
    XlateFuncBind("DbToYang_qos_dot1p_fwd_group_xfmr", DbToYang_qos_dot1p_fwd_group_xfmr)
    XlateFuncBind("Subscribe_qos_dot1p_fwd_group_xfmr", Subscribe_qos_dot1p_fwd_group_xfmr)
    XlateFuncBind("YangToDb_qos_dot1p_to_tc_map_fld_xfmr", YangToDb_qos_dot1p_to_tc_map_fld_xfmr)
    XlateFuncBind("DbToYang_qos_dot1p_to_tc_map_fld_xfmr", DbToYang_qos_dot1p_to_tc_map_fld_xfmr)
 
}

var Subscribe_qos_dot1p_fwd_group_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    map_type := "DOT1P_TO_TC_MAP"
    return Subscribe_qos_map_xfmr(inParams, map_type)
}



var YangToDb_qos_dot1p_fwd_group_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    map_type := "DOT1P_TO_TC_MAP"

    if inParams.oper == DELETE {
        return qos_map_delete_xfmr(inParams, map_type)
    }

    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("YangToDb_qos_dot1p_fwd_group_xfmr: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    name := pathInfo.Var("name")
    targetUriPath, err := getYangPathFromUri(inParams.uri)

    log.Info("YangToDb: name: ", name)
    log.Info("targetUriPath:",  targetUriPath)

    /* parse the inParams */
    qosObj := getQosRoot(inParams.ygRoot)
    if qosObj == nil {
        return res_map, err
    }

    mapObj, ok := qosObj.Dot1PMaps.Dot1PMap[name]
    if !ok {
        return res_map, err
    }

    d :=  inParams.d
    if d == nil  {
        log.Infof("unable to get configDB")
        return res_map, err
    }

    map_entry := make(map[string]db.Value)
    map_key := name
    map_entry[map_key] = db.Value{Field: make(map[string]string)}
    log.Info("map_key : ", map_key)

    if !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/dot1p-maps/dot1p-map/dot1p-map-entries/dot1p-map-entry") &&
       !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/openconfig-qos-maps-ext:dot1p-maps/dot1p-map/dot1p-map-entries/dot1p-map-entry") {
        log.Info("YangToDb: map entry unspecified, return the map")
        res_map[map_type] = map_entry
        return res_map, err
    }

    str := qos_map_oc_yang_key_map[map_type]
    log.Info("key string: " , str)
    entry_key := pathInfo.Var(qos_map_oc_yang_key_map[map_type])
    log.Info("entry_key : ", entry_key)
    if entry_key == "" {
        return res_map, err
    }

    tmp, _ := strconv.ParseUint(entry_key, 10, 8)
    tmp2 := uint8(tmp)
    log.Info("entry_key in val: ", tmp2)

    if (inParams.oper == CREATE || inParams.oper == UPDATE ) && 
        strings.Contains(inParams.requestUri, "-entry[" + str + "=") {
        mapCfg, err := get_map_entry_by_map_name(inParams.d, map_type, map_key)
        if err == nil { 
            _, ok := mapCfg.Field[entry_key]
            if !ok {
                log.Info("Entry not exist; cannot create it with key in URI itself")
                err = tlerr.NotFound("Resource not found")
                return res_map, err
            }
        }
    }

    entry, ok := mapObj.Dot1PMapEntries.Dot1PMapEntry[tmp2]
    if !ok  {
        log.Info("entry is nil.")
        return res_map, err
    }

    val :=  *(entry.Config.FwdGroup)

    map_entry[map_key].Field[entry_key] = val 

    log.Info("map key : ", map_key, " entry_key: ", entry_key)
    res_map[map_type] = map_entry

    return res_map, err


    return res_map, err
}


func fill_dot1p_map_info_by_name(inParams XfmrParams, dot1PMaps * ocbinds.OpenconfigQos_Qos_Dot1PMaps, name string) error {

    map_type := "DOT1P_TO_TC_MAP"

    mapObj, ok := dot1PMaps.Dot1PMap[name]
    if !ok {
        mapObj, _ = dot1PMaps.NewDot1PMap(name)
        ygot.BuildEmptyTree(mapObj)
        mapObj.Name = &name

    }

    var mapEntries ocbinds.OpenconfigQos_Qos_Dot1PMaps_Dot1PMap_Dot1PMapEntries
    if mapObj.Dot1PMapEntries == nil {
        mapObj.Dot1PMapEntries = &mapEntries
    }

    var mapObjCfg ocbinds.OpenconfigQos_Qos_Dot1PMaps_Dot1PMap_Config
    if mapObj.Config == nil {
        mapObj.Config = &mapObjCfg
    }

    var mapObjSta ocbinds.OpenconfigQos_Qos_Dot1PMaps_Dot1PMap_State
    if mapObj.State == nil {
        mapObj.State = &mapObjSta
    }

    dbSpec := &db.TableSpec{Name: map_type}

    key :=db.Key{Comp: []string{name}}
    
    log.Info("key: ", key)

    mapCfg, err := inParams.d.GetEntry(dbSpec, key) 
    if  err != nil {
        log.Info("No dot1p-to-tc-map with a name of : ", name)
        return nil
    }

    log.Info("current entry: ", mapCfg)

    mapObj.Config.Name = &name
    mapObj.State.Name = &name


    pathInfo := NewPathInfo(inParams.uri)
    entry_key := pathInfo.Var(qos_map_oc_yang_key_map[map_type])
    var tmp_cfg ocbinds.OpenconfigQos_Qos_Dot1PMaps_Dot1PMap_Dot1PMapEntries_Dot1PMapEntry_Config
    var tmp_sta ocbinds.OpenconfigQos_Qos_Dot1PMaps_Dot1PMap_Dot1PMapEntries_Dot1PMapEntry_State
    entry_added :=  0
    for k, v := range mapCfg.Field {
        if k == "NULL" {
            continue
        }

        if entry_key != "" && k!= entry_key {
            continue
        }

        tmp, _ := strconv.ParseUint(k, 10, 8)
        key := uint8(tmp)
	value := v

        entryObj, ok := mapObj.Dot1PMapEntries.Dot1PMapEntry[key]
        if !ok {
            entryObj, _ = mapObj.Dot1PMapEntries.NewDot1PMapEntry(key)
            ygot.BuildEmptyTree(entryObj)
            ygot.BuildEmptyTree(entryObj.Config)
            ygot.BuildEmptyTree(entryObj.State)
        }

        entryObj.Dot1P = &key

        if entryObj.Config == nil {
            entryObj.Config = &tmp_cfg
        }
        entryObj.Config.Dot1P = &key
        entryObj.Config.FwdGroup = &value


        if entryObj.State == nil {
            entryObj.State = &tmp_sta
        }
        entryObj.State.Dot1P = &key
        entryObj.State.FwdGroup = &value

        entry_added = entry_added + 1

        log.Info("Added entry: ", entryObj)
    }

    log.Info("Done fetching dot1p-map : ", name)

    if entry_key != "" && entry_added == 0 {
        err = tlerr.NotFoundError{Format:"Resource not found"}
        log.Info("Resource not found.")
        return err
    }

    return nil
}

var DbToYang_qos_dot1p_fwd_group_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    name := pathInfo.Var("name")

    log.Info("inParams: ", inParams)

    qosObj := getQosRoot(inParams.ygRoot)

    if qosObj == nil {
        ygot.BuildEmptyTree(qosObj)
    }

    if qosObj.Dot1PMaps == nil {
        ygot.BuildEmptyTree(qosObj.Dot1PMaps)
    }

    dbSpec := &db.TableSpec{Name: "DOT1P_TO_TC_MAP"}

    map_added := 0
    var keyPattern string
    if  name != "" {
        keyPattern = name
    } else {
        keyPattern = "*"
    }

    keys, _ := inParams.d.GetKeysByPattern(dbSpec, keyPattern)
    for _, key := range keys {
        log.Info("key: ", key)

        map_name := key.Comp[0]

        map_added = map_added + 1 

        err = fill_dot1p_map_info_by_name(inParams, qosObj.Dot1PMaps, map_name)

        if err != nil {
           return err
        }
    }

    if name != "" && map_added == 0 {
        err = tlerr.NotFoundError{Format:"Resource not found"}
        log.Info("Resource not found.")
        return err
    }

    return err
}




var DbToYang_qos_dot1p_to_tc_map_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    return DbToYang_qos_intf_qos_map_xfmr(inParams, "DOT1P_TO_TC_MAP")
}



var YangToDb_qos_dot1p_to_tc_map_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    return YangToDb_qos_intf_qos_map_xfmr(inParams, "DOT1P_TO_TC_MAP")
}

