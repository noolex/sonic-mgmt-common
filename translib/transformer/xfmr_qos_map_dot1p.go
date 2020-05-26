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
    XlateFuncBind("YangToDb_qos_dot1p_to_tc_map_fld_xfmr", YangToDb_qos_dot1p_to_tc_map_fld_xfmr)
    XlateFuncBind("DbToYang_qos_dot1p_to_tc_map_fld_xfmr", DbToYang_qos_dot1p_to_tc_map_fld_xfmr)
 
}


func qos_dot1p_map_delete_xfmr(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_dot1p_map_delete_xfmr: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    map_name := pathInfo.Var("name")
    log.Info("YangToDb: map name: ", map_name)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)


    var map_entry db.Value

    if map_name != "" {
        map_entry, err = get_map_entry_by_map_name(inParams.d, "DOT1P_TO_TC_MAP", map_name)
        if err != nil {
            err = tlerr.InternalError{Format:"Instance Not found"}
            log.Info("map name not found.")
            return res_map, err
        }
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/openconfig-qos-maps-ext:dot1p-maps/dot1p-map") == false {
        log.Info("YangToDb: map name unspecified, using delete_by_map_name")
        return qos_map_delete_by_map_name(inParams, "DOT1P_TO_TC_MAP", map_name)
    }

    dot1p := pathInfo.Var("dot1p")
    if dot1p == "" {
        log.Info("YangToDb: map name unspecified, using delete_by_map_name")
        return qos_map_delete_by_map_name(inParams, "DOT1P_TO_TC_MAP", map_name)
    } else  {
        _, exist := map_entry.Field[dot1p]
        if !exist { 
            err = tlerr.InternalError{Format:"DOT1P value Not found"}
            log.Info("DOT1P value not found.")
            return res_map, err
        }
    }

    /* update "map" table field only */
    rtTblMap := make(map[string]db.Value)
    rtTblMap[map_name] = db.Value{Field: make(map[string]string)}
    rtTblMap[map_name].Field[dot1p] = ""

    res_map["DOT1P_TO_TC_MAP"] = rtTblMap

    return res_map, err

}


var YangToDb_qos_dot1p_fwd_group_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    if inParams.oper == DELETE {
        return qos_dot1p_map_delete_xfmr(inParams)
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
    log.Info("YangToDb_qos_classifier_xfmr - entry_key : ", map_key)

    if targetUriPath == "/openconfig-qos:qos/dot1p-maps/dot1p-map" ||
       targetUriPath == "/openconfig-qos:qos/openconfig-qos-maps-ext:dot1p-maps/dot1p-map" {
        if inParams.oper == DELETE {

            res_map["DOT1P_TO_TC_MAP"] = map_entry
            return res_map, err
        }

        // no op at this level
        return res_map, err
    }


    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/dot1p-maps/dot1p-map/dot1p-map-entries/dot1p-map-entry") == false  &&
       strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/openconfig-qos-maps-ext:dot1p-maps/dot1p-map/dot1p-map-entries/dot1p-map-entry") == false {
        log.Info("YangToDb: map entry unspecified, stop here")
        return res_map, err
    }

    dot1p := pathInfo.Var("dot1p")
    if dot1p == "" {
	return res_map, err
    }
    log.Info("dot1p: ", dot1p)

    tmp, _ := strconv.ParseUint(dot1p, 10, 8)
    dot1p_val := uint8(tmp)

    entry, ok := mapObj.Dot1PMapEntries.Dot1PMapEntry[dot1p_val]
    if !ok  {
        log.Info("entry is nil.")
        return res_map, err
    }

    tc := ""
    if inParams.oper == CREATE ||
       inParams.oper == UPDATE {
        tc =  *(entry.Config.FwdGroup)
    }

    map_entry[map_key].Field[dot1p] = tc

    log.Info("YangToDb_qos_classifier_xfmr - entry_key : ", map_key)
    res_map["DOT1P_TO_TC_MAP"] = map_entry

    return res_map, err
}

var DbToYang_qos_dot1p_fwd_group_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

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

    mapObj, ok := qosObj.Dot1PMaps.Dot1PMap[name]
    if !ok {
        mapObj, _ = qosObj.Dot1PMaps.NewDot1PMap(name)
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

    // Classifier
    dbSpec := &db.TableSpec{Name: "DOT1P_TO_TC_MAP"}

    key :=db.Key{Comp: []string{name}}
    
    log.Info("key: ", key)

    mapCfg, err := inParams.d.GetEntry(dbSpec, key) 
    if  err != nil {
        log.Info("No dot1p-to-tc-map with a name of : ", name)
        return nil
    }

    log.Info("current entry: ", mapCfg)

    mapObj.Config.Name = &name


    dot1p := pathInfo.Var("dot1p")
    var tmp_cfg ocbinds.OpenconfigQos_Qos_Dot1PMaps_Dot1PMap_Dot1PMapEntries_Dot1PMapEntry_Config
    var tmp_sta ocbinds.OpenconfigQos_Qos_Dot1PMaps_Dot1PMap_Dot1PMapEntries_Dot1PMapEntry_State
    for k, v := range mapCfg.Field {
        if dot1p != "" && k!= dot1p {
            continue
        }

        tmp, _ := strconv.ParseUint(k, 10, 8)
        dot1p_val := uint8(tmp)
	fwdGrp := v

        entryObj, ok := mapObj.Dot1PMapEntries.Dot1PMapEntry[dot1p_val]
        if !ok {
            entryObj, _ = mapObj.Dot1PMapEntries.NewDot1PMapEntry(dot1p_val)
            ygot.BuildEmptyTree(entryObj)
            ygot.BuildEmptyTree(entryObj.Config)
            ygot.BuildEmptyTree(entryObj.State)
        }

        entryObj.Dot1P = &dot1p_val

        if entryObj.Config == nil {
            entryObj.Config = &tmp_cfg
        }
        entryObj.Config.Dot1P = &dot1p_val
        entryObj.Config.FwdGroup = &fwdGrp


        if entryObj.State == nil {
            entryObj.State = &tmp_sta
        }
        entryObj.State.Dot1P = &dot1p_val
        entryObj.State.FwdGroup = &fwdGrp


        log.Info("Added entry: ", entryObj)
    }

    log.Info("Done fetching dot1p-map : ", name)

    return nil
}



var DbToYang_qos_dot1p_to_tc_map_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("Entering DbToYang_qos_dot1p_to_tc_map_fld_xfmr ", inParams)

    res_map := make(map[string]interface{})

    pathInfo := NewPathInfo(inParams.uri)

    if_name := pathInfo.Var("interface-id")

    dbSpec := &db.TableSpec{Name: "PORT_QOS_MAP"}

    key := db.Key{Comp: []string{if_name}}
    qCfg, _ := inParams.d.GetEntry(dbSpec, key) 

    log.Info("current entry: ", qCfg)
    value, _ := qCfg.Field["dot1p_to_tc_map"] 

    log.Info("value = ", value)
    res_map["dot1p-to-forwarding-group"] = DbLeafrefToString(value,  "DOT1P_TO_TC_MAP")
    return res_map, nil
}



var YangToDb_qos_dot1p_to_tc_map_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("Entering YangToDb_qos_dot1p_to_tc_map_fld_xfmr ===> ", inParams)

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

    map_name := *(intfObj.InterfaceMaps.Config.Dot1PToForwardingGroup)

    if len(map_name) == 0 {
        log.Error("map name is Missing")
        return res_map, err
    }

    log.Info("map name is : ", map_name)
    res_map["dot1p_to_tc_map"] = StringToDbLeafref(map_name, "DOT1P_TO_TC_MAP")
    return res_map, err
}

