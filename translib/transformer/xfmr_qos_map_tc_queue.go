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
    XlateFuncBind("YangToDb_qos_tc_queue_xfmr", YangToDb_qos_tc_queue_xfmr)
    XlateFuncBind("DbToYang_qos_tc_queue_xfmr", DbToYang_qos_tc_queue_xfmr)
    XlateFuncBind("Subscribe_qos_tc_queue_xfmr", Subscribe_qos_tc_queue_xfmr)
    XlateFuncBind("YangToDb_qos_tc_to_queue_map_fld_xfmr", YangToDb_qos_tc_to_queue_map_fld_xfmr)
    XlateFuncBind("DbToYang_qos_tc_to_queue_map_fld_xfmr", DbToYang_qos_tc_to_queue_map_fld_xfmr)

}

var Subscribe_qos_tc_queue_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    map_type := "TC_TO_QUEUE_MAP"
    return Subscribe_qos_map_xfmr(inParams, map_type)
}




var YangToDb_qos_tc_queue_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    map_type := "TC_TO_QUEUE_MAP"

    if inParams.oper == DELETE {
        return qos_map_delete_xfmr(inParams, map_type) 
    }

    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("YangToDb_qos_tc_queue_xfmr: ", inParams.ygRoot, inParams.uri)
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

    mapObj, ok := qosObj.ForwardingGroupQueueMaps.ForwardingGroupQueueMap[name]
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

    if !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/forwarding-group-queue-maps/forwarding-group-queue-map/forwarding-group-queue-map-entries/forwarding-group-queue-map-entry")   &&
       !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/openconfig-qos-maps-ext:forwarding-group-queue-maps/forwarding-group-queue-map/forwarding-group-queue-map-entries/forwarding-group-queue-map-entry")  {
        log.Info("YangToDb: map entry unspecified, return the map")

        res_map[map_type] = map_entry
        return res_map, err
    }

    entry_key := pathInfo.Var(qos_map_oc_yang_key_map[map_type])
    log.Info("entry_key : ", entry_key)
    if entry_key == "" {
        return res_map, err
    }

    entry, ok := mapObj.ForwardingGroupQueueMapEntries.ForwardingGroupQueueMapEntry[entry_key]
    if !ok  {
        log.Info("entry is nil.")
        return res_map, err
    }

    val :=  *(entry.Config.OutputQueueIndex)

    map_entry[map_key].Field[entry_key] = strconv.Itoa(int(val))

    log.Info("map key : ", map_key, " entry_key: ", entry_key)
    res_map[map_type] = map_entry

    return res_map, err
}


func fill_tc_map_info_by_name(inParams XfmrParams, forwardingGroupQueueMaps * ocbinds.OpenconfigQos_Qos_ForwardingGroupQueueMaps, name string) error {

    map_type := "TC_TO_QUEUE_MAP"

    mapObj, ok := forwardingGroupQueueMaps.ForwardingGroupQueueMap[name]
    if !ok {
        mapObj, _ = forwardingGroupQueueMaps.NewForwardingGroupQueueMap(name)
        ygot.BuildEmptyTree(mapObj)
        mapObj.Name = &name

    }

    var mapEntries ocbinds.OpenconfigQos_Qos_ForwardingGroupQueueMaps_ForwardingGroupQueueMap_ForwardingGroupQueueMapEntries
    if mapObj.ForwardingGroupQueueMapEntries == nil {
        mapObj.ForwardingGroupQueueMapEntries = &mapEntries
    }

    var mapObjCfg ocbinds.OpenconfigQos_Qos_ForwardingGroupQueueMaps_ForwardingGroupQueueMap_Config
    if mapObj.Config == nil {
        mapObj.Config = &mapObjCfg
    }

    var mapObjSta ocbinds.OpenconfigQos_Qos_ForwardingGroupQueueMaps_ForwardingGroupQueueMap_State
    if mapObj.State == nil {
        mapObj.State = &mapObjSta
    }


    key :=db.Key{Comp: []string{name}}
    log.Info("key: ", key)

    dbSpec := &db.TableSpec{Name: map_type}
    mapCfg, err := inParams.d.GetEntry(dbSpec, key) 
    if  err != nil {
        log.Info("No map with a name of : ", name)
        return nil
    }

    log.Info("current entry: ", mapCfg)

    mapObj.Config.Name = &name
    mapObj.State.Name = &name


    pathInfo := NewPathInfo(inParams.uri)
    entry_key := pathInfo.Var(qos_map_oc_yang_key_map[map_type])
    log.Info("pathInfo.Var: ", pathInfo.Var)
    var tmp_cfg ocbinds.OpenconfigQos_Qos_ForwardingGroupQueueMaps_ForwardingGroupQueueMap_ForwardingGroupQueueMapEntries_ForwardingGroupQueueMapEntry_Config
    var tmp_sta ocbinds.OpenconfigQos_Qos_ForwardingGroupQueueMaps_ForwardingGroupQueueMap_ForwardingGroupQueueMapEntries_ForwardingGroupQueueMapEntry_State
    entry_added :=  0
    for k, v := range mapCfg.Field {
        if k == "NULL" {
            continue
        }

        if entry_key != "" && k!= entry_key {
            continue
        }

        key := k
        tmp, _ := strconv.ParseUint(v, 10, 8)
        value := uint8(tmp)

        entryObj, ok := mapObj.ForwardingGroupQueueMapEntries.ForwardingGroupQueueMapEntry[key]
        if !ok {
            entryObj, _ = mapObj.ForwardingGroupQueueMapEntries.NewForwardingGroupQueueMapEntry(key)
            ygot.BuildEmptyTree(entryObj)
            ygot.BuildEmptyTree(entryObj.Config)
            ygot.BuildEmptyTree(entryObj.State)
        }

        entryObj.FwdGroup = &key

        if entryObj.Config == nil {
            entryObj.Config = &tmp_cfg
        }
        entryObj.Config.FwdGroup = &key
        entryObj.Config.OutputQueueIndex = &value


        if entryObj.State == nil {
            entryObj.State = &tmp_sta
        }
        entryObj.State.FwdGroup = &key
        entryObj.State.OutputQueueIndex = &value

        entry_added = entry_added + 1

        log.Info("Added entry: ", entryObj)
    }

    log.Info("Done fetching forwarding-group-queue-map : ", name)

    if entry_key != "" && entry_added == 0 {
        err = tlerr.NotFoundError{Format:"Resource not found"}
        log.Info("Resource not found.")
        return err
    }

    return nil
}


var DbToYang_qos_tc_queue_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    name := pathInfo.Var("name")

    log.Info("inParams: ", inParams)

    qosObj := getQosRoot(inParams.ygRoot)

    if qosObj == nil {
        ygot.BuildEmptyTree(qosObj)
    }

    if qosObj.ForwardingGroupQueueMaps == nil {
        ygot.BuildEmptyTree(qosObj.ForwardingGroupQueueMaps)
    }

    dbSpec := &db.TableSpec{Name: "TC_TO_QUEUE_MAP"}

    map_added := 0
    keys, _ := inParams.d.GetKeys(dbSpec)
    for _, key := range keys {
        log.Info("key: ", key)

        map_name := key.Comp[0]
        if name != ""  && name != map_name{
            continue
        } 

        map_added = map_added + 1 

        err = fill_tc_map_info_by_name(inParams, qosObj.ForwardingGroupQueueMaps, map_name)

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


var DbToYang_qos_tc_to_queue_map_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    return DbToYang_qos_intf_qos_map_xfmr(inParams, "TC_TO_QUEUE_MAP")
}



var YangToDb_qos_tc_to_queue_map_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    return YangToDb_qos_intf_qos_map_xfmr(inParams, "TC_TO_QUEUE_MAP")
}

