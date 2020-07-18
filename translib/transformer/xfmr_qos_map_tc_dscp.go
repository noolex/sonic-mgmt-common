package transformer

import (
    "strings"
    "strconv"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
)
func init () {
    XlateFuncBind("YangToDb_qos_fwd_group_dscp_xfmr", YangToDb_qos_fwd_group_dscp_xfmr)
    XlateFuncBind("DbToYang_qos_fwd_group_dscp_xfmr", DbToYang_qos_fwd_group_dscp_xfmr)
    XlateFuncBind("Subscribe_qos_fwd_group_dscp_xfmr", Subscribe_qos_fwd_group_dscp_xfmr)
    XlateFuncBind("YangToDb_qos_tc_to_dscp_map_fld_xfmr", YangToDb_qos_tc_to_dscp_map_fld_xfmr)
    XlateFuncBind("DbToYang_qos_tc_to_dscp_map_fld_xfmr", DbToYang_qos_tc_to_dscp_map_fld_xfmr)
 
}

var Subscribe_qos_fwd_group_dscp_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    map_type := "TC_TO_DSCP_MAP"
    return Subscribe_qos_map_xfmr(inParams, map_type)
}



func qos_fwd_group_dscp_map_delete_xfmr(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_fwd_group_dscp_map_delete_xfmr: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    map_name := pathInfo.Var("name")
    log.Info("YangToDb: map name: ", map_name)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)


    var map_entry db.Value

    if map_name != "" {
        map_entry, err = get_map_entry_by_map_name(inParams.d, "TC_TO_DSCP_MAP", map_name)
        if err != nil {
            err = tlerr.InternalError{Format:"Instance Not found"}
            log.Info("map name not found.")
            return res_map, err
        }
    }

    if !strings.HasPrefix(targetUriPath,
    "/openconfig-qos:qos/openconfig-qos-maps-ext:forwarding-group-dscp-maps/forwarding-group-dscp-map") {
        log.Info("YangToDb: map name unspecified, using delete_by_map_name")
        return qos_map_delete_by_map_name(inParams, "TC_TO_DSCP_MAP", map_name)
    }

    tc := pathInfo.Var("fwd-group")
    if tc == "" {
        log.Info("YangToDb: TC unspecified, using delete_by_map_name")
        return qos_map_delete_by_map_name(inParams, "TC_TO_DSCP_MAP", map_name)
    } else  {
        _, exist := map_entry.Field[tc]
        if !exist { 
            err = tlerr.InternalError{Format:"TC value Not found"}
            log.Info("TC value not found.")
            return res_map, err
        }
    }

    /* update "map" table field only */
    rtTblMap := make(map[string]db.Value)
    rtTblMap[map_name] = db.Value{Field: make(map[string]string)}
    rtTblMap[map_name].Field[tc] = ""

    res_map["TC_TO_DSCP_MAP"] = rtTblMap

    return res_map, err

}


var YangToDb_qos_fwd_group_dscp_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    if inParams.oper == DELETE {
        return qos_fwd_group_dscp_map_delete_xfmr(inParams)
    }

    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("YangToDb_qos_fwd_group_dscp_xfmr: ", inParams.ygRoot, inParams.uri)
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

    mapObj, ok := qosObj.ForwardingGroupDscpMaps.ForwardingGroupDscpMap[name]
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
    log.Info("YangToDb_qos_fwd_group_dscp_xfmr - entry_key : ", map_key)

    if targetUriPath == "/openconfig-qos:qos/forwarding-group-dscp-maps/forwarding-group-dscp-map" ||
       targetUriPath == "/openconfig-qos:qos/openconfig-qos-maps-ext:forwarding-group-dscp-maps/forwarding-group-dscp-map" {
        if inParams.oper == DELETE {

            res_map["TC_TO_DSCP_MAP"] = map_entry
            return res_map, err
        }

        // no op at this level
        return res_map, err
    }


    if !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/forwarding-group-dscp-maps/forwarding-group-dscp-map/forwarding-group-dscp-map-entries/forwarding-group-dscp-map-entry") &&
       !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/openconfig-qos-maps-ext:forwarding-group-dscp-maps/forwarding-group-dscp-map/forwarding-group-dscp-map-entries/forwarding-group-dscp-map-entry") {
        log.Info("YangToDb: map entry unspecified, stop here")
        res_map["TC_TO_DSCP_MAP"] = map_entry
        return res_map, err
    }

    tc := pathInfo.Var("fwd-group")
    if tc == "" {
        return res_map, err
    }
    log.Info("tc: ", tc)

    // tmp, _ := strconv.ParseUint(tc, 10, 8)
    // tc_val := string(tmp)

    entry, ok := mapObj.ForwardingGroupDscpMapEntries.ForwardingGroupDscpMapEntry[tc]
    if !ok  {
        log.Info("entry is nil.")
        return res_map, err
    }

    dscp := uint8(0)
    if inParams.oper == CREATE ||
       inParams.oper == UPDATE {
        dscp =  *(entry.Config.Dscp)
    }

    map_entry[map_key].Field[tc] = strconv.FormatUint(uint64(dscp), 10)

    log.Info("YangToDb_qos_fwd_group_dscp_xfmr - entry_key : ", map_key)
    res_map["TC_TO_DSCP_MAP"] = map_entry

    return res_map, err
}


func fill_fwd_group_dscp_map_info_by_name(inParams XfmrParams, fwdGrpDscpMaps * ocbinds.OpenconfigQos_Qos_ForwardingGroupDscpMaps, name string) error {


    mapObj, ok := fwdGrpDscpMaps.ForwardingGroupDscpMap[name]
    if !ok {
        mapObj, _ = fwdGrpDscpMaps.NewForwardingGroupDscpMap(name)
        ygot.BuildEmptyTree(mapObj)
        mapObj.Name = &name

    }

    var mapEntries ocbinds.OpenconfigQos_Qos_ForwardingGroupDscpMaps_ForwardingGroupDscpMap_ForwardingGroupDscpMapEntries

    if mapObj.ForwardingGroupDscpMapEntries == nil {
        mapObj.ForwardingGroupDscpMapEntries = &mapEntries
    }

    var mapObjCfg ocbinds.OpenconfigQos_Qos_ForwardingGroupDscpMaps_ForwardingGroupDscpMap_Config
    if mapObj.Config == nil {
        mapObj.Config = &mapObjCfg
    }

    var mapObjSta ocbinds.OpenconfigQos_Qos_ForwardingGroupDscpMaps_ForwardingGroupDscpMap_State
    if mapObj.State == nil {
        mapObj.State = &mapObjSta
    }

    dbSpec := &db.TableSpec{Name: "TC_TO_DSCP_MAP"}

    key :=db.Key{Comp: []string{name}}
    
    log.Info("key: ", key)

    mapCfg, err := inParams.d.GetEntry(dbSpec, key) 
    if  err != nil {
        log.Info("No tc-to-dscp-map with a name of : ", name)
        return nil
    }

    log.Info("current entry: ", mapCfg)

    mapObj.Config.Name = &name
    mapObj.State.Name = &name


    pathInfo := NewPathInfo(inParams.uri)
    log.Info("pathInfo.Var: ", pathInfo.Var)

    tc := pathInfo.Var("fwd-group")

    var tmp_cfg ocbinds.OpenconfigQos_Qos_ForwardingGroupDscpMaps_ForwardingGroupDscpMap_ForwardingGroupDscpMapEntries_ForwardingGroupDscpMapEntry_Config
    var tmp_sta ocbinds.OpenconfigQos_Qos_ForwardingGroupDscpMaps_ForwardingGroupDscpMap_ForwardingGroupDscpMapEntries_ForwardingGroupDscpMapEntry_State
    entry_added :=  0
    for k, v := range mapCfg.Field {
        if k == "NULL" {
            continue
        }

        if tc != "" && k!= tc {
            continue
        }

        tmp, _ := strconv.ParseUint(v, 10, 8)
        dscp := uint8(tmp)
        tc_val := k

        entryObj, ok := mapObj.ForwardingGroupDscpMapEntries.ForwardingGroupDscpMapEntry[tc_val]
        if !ok {
            entryObj, _ = mapObj.ForwardingGroupDscpMapEntries.NewForwardingGroupDscpMapEntry(tc_val)
            ygot.BuildEmptyTree(entryObj)
            ygot.BuildEmptyTree(entryObj.Config)
            ygot.BuildEmptyTree(entryObj.State)
        }

        entryObj.FwdGroup = &tc_val

        if entryObj.Config == nil {
            entryObj.Config = &tmp_cfg
        }
        entryObj.Config.FwdGroup = &tc_val
        entryObj.Config.Dscp = &dscp


        if entryObj.State == nil {
            entryObj.State = &tmp_sta
        }
        entryObj.State.FwdGroup = &tc_val
        entryObj.State.Dscp = &dscp

        entry_added = entry_added + 1

        log.Info("Added entry: ", entryObj)
    }

    log.Info("Done fetching tc-dscp-map : ", name)

    if tc != "" && entry_added == 0 {
        err = tlerr.NotFoundError{Format:"Instance Not found"}
        log.Info("Instance not found.")
        return err
    }

    return nil
}

var DbToYang_qos_fwd_group_dscp_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    name := pathInfo.Var("name")

    log.Info("inParams: ", inParams)

    qosObj := getQosRoot(inParams.ygRoot)

    if qosObj == nil {
        ygot.BuildEmptyTree(qosObj)
    }

    if qosObj.ForwardingGroupDscpMaps == nil {
        ygot.BuildEmptyTree(qosObj.ForwardingGroupDscpMaps)
    }

    dbSpec := &db.TableSpec{Name: "TC_TO_DSCP_MAP"}

    map_added := 0
    keys, _ := inParams.d.GetKeys(dbSpec)
    for _, key := range keys {
        log.Info("key: ", key)

        map_name := key.Comp[0]
        if name != ""  && name != map_name{
            continue
        } 

        map_added = map_added + 1 

        err = fill_fwd_group_dscp_map_info_by_name(inParams, qosObj.ForwardingGroupDscpMaps, map_name)

        if err != nil {
           return err
        }
    }

    if name != "" && map_added == 0 {
        err = tlerr.NotFoundError{Format:"Instance Not found"}
        log.Info("Instance not found.")
        return err
    }

    return err
}



var DbToYang_qos_tc_to_dscp_map_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("Entering DbToYang_qos_tc_to_dscp_map_fld_xfmr ", inParams)

    res_map := make(map[string]interface{})

    pathInfo := NewPathInfo(inParams.uri)

    if_name := pathInfo.Var("interface-id")

    dbIfName := utils.GetNativeNameFromUIName(&if_name)
    dbSpec := &db.TableSpec{Name: "PORT_QOS_MAP"}

    key := db.Key{Comp: []string{*dbIfName}}
    ifCfg, err := inParams.d.GetEntry(dbSpec, key)
    if  err != nil {
        log.Info("No port_qos_map with a name of : ", dbIfName)
        return res_map, nil
    }
 
    log.Info("current entry: ", ifCfg)
    value, ok := ifCfg.Field["tc_to_dscp_map"]
    if ok {
        log.Info("value = ", value)
        res_map["forwarding-group-to-dscp"] = DbLeafrefToString(value, "TC_TO_DSCP_MAP")
    }
    return res_map, nil
}



var YangToDb_qos_tc_to_dscp_map_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("Entering YangToDb_qos_tc_to_dscp_map_fld_xfmr ===> ", inParams)

    pathInfo := NewPathInfo(inParams.uri)

    if_name := pathInfo.Var("interface-id")

    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    if qosIntfsObj == nil {
        return res_map, err
    }

    intfObj, ok := qosIntfsObj.Interface[if_name]
    if !ok {
        return res_map, err
    }

    map_name := *(intfObj.InterfaceMaps.Config.ForwardingGroupToDscp)

    if len(map_name) == 0 {
        log.Error("map name is Missing")
        return res_map, err
    }

    log.Info("map name is : ", map_name)
    res_map["tc_to_dscp_map"] = StringToDbLeafref(map_name, "TC_TO_DSCP_MAP")
    return res_map, err
}

