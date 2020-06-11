package transformer

import (
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)


func get_map_entry_by_map_name(d *db.DB, map_type string, map_name string) (db.Value, error) {

    ts := &db.TableSpec{Name: map_type}
    keys, _ := d.GetKeys(ts);

    log.Info("keys: ", keys)

    entry, err := d.GetEntry(ts, db.Key{Comp: []string{map_name}})
    if err != nil {
        log.Info("not able to find the map entry in DB ", map_name)
        return entry, err
    }

    return entry , nil
}


var qos_map_oc_yang_key_map = map[string]string {
    "DSCP_TO_TC_MAP":   "dscp",
    "DOT1P_TO_TC_MAP":  "dot1p",
    "TC_TO_QUEUE_MAP":  "fwd-group",
    "TC_TO_PRIORITY_GROUP_MAP":  "fwd-group",
    "PFC_PRIORITY_TO_QUEUE_MAP": "pfc-priority",
}

func targetUriPathContainsMapName (uri string, map_type string) bool {
    if map_type == "DSCP_TO_TC_MAP" &&
        strings.HasPrefix(uri, "/openconfig-qos:qos/openconfig-qos-maps-ext:dscp-maps/dscp-map") == false {
        return true
    }

    if map_type == "DOT1P_TO_TC_MAP" &&
        strings.HasPrefix(uri, "/openconfig-qos:qos/openconfig-qos-maps-ext:dot1p-maps/dot1p-map") == false {
        return true
    }

    if map_type == "TC_TO_QUEUE_MAP" &&
        strings.HasPrefix(uri, "/openconfig-qos:qos/openconfig-qos-maps-ext:forwarding-group-queue-maps/forwarding-group-queue-map") == false {
        return true
    }

    if map_type == "TC_TO_PRIORITY_GROUP_MAP" &&
        strings.HasPrefix(uri, "/openconfig-qos:qos/openconfig-qos-maps-ext:forwarding-group-priority-group-maps/forwarding-group-priority-group-map") == false {
        return true
    }

    if map_type == "PFC_PRIORITY_TO_QUEUE_MAP" &&
        strings.HasPrefix(uri, "/openconfig-qos:qos/openconfig-qos-maps-ext:pfc-priority-queue-maps/pfc-priority-queue-map") == false {
        return true
    }

    return false

}

func qos_map_delete_xfmr(inParams XfmrParams, map_type string) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_map_delete_xfmr: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    map_name := pathInfo.Var("name")
    log.Info("YangToDb: map name: ", map_name)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)


    var map_entry db.Value

    if map_name != "" {
        map_entry, err = get_map_entry_by_map_name(inParams.d, map_type, map_name)
        if err != nil {
            err = tlerr.InternalError{Format:"Instance Not found"}
            log.Info("map name not found.")
            return res_map, err
        }
    }

    if targetUriPathContainsMapName(targetUriPath, map_type) {
        log.Info("YangToDb: map name unspecified, using delete_by_map_name")
        return qos_map_delete_by_map_name(inParams, map_type, map_name)
    }

    entry_key := pathInfo.Var(qos_map_oc_yang_key_map[map_type])
    if entry_key == "" {
        log.Info("YangToDb: map key field unspecified, using delete_by_map_name")
        return qos_map_delete_by_map_name(inParams, map_type, map_name)
    } else  {
        _, exist := map_entry.Field[entry_key]
        if !exist { 
            err = tlerr.InternalError{Format:"Field Name Value Not found"}
            log.Info("Field Name value not found.", entry_key)
            return res_map, err
        }
    }

    /* update "map" table field only */
    rtTblMap := make(map[string]db.Value)
    rtTblMap[map_name] = db.Value{Field: make(map[string]string)}
    rtTblMap[map_name].Field[entry_key] = ""

    res_map[map_type] = rtTblMap

    return res_map, err

}


func qos_map_delete_all_map(inParams XfmrParams, map_type string) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_map_delete_all_map: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)

    ts := &db.TableSpec{Name: map_type}
    keys, _ := inParams.d.GetKeys(ts);

    log.Info("keys: ", keys)

    /* update "map" table */
    rtTblMap := make(map[string]db.Value)

    for _, key := range keys {
        // validation: skip in-used map 

        map_name := key.Comp[0]
        if isMapInUse(inParams.d, map_type, map_name) {
             continue
        }

        rtTblMap[map_name] = db.Value{Field: make(map[string]string)}
    }

    log.Info("qos_map_delete_all_map ")
    res_map[map_type] = rtTblMap

    return res_map, err
}

func getIntfsByMapName(d *db.DB, map_type string, map_name string) ([]string) {
    var s []string

    log.Info("map_name ", map_name)


    // PORT_QOS_MAP
    tbl_list := []string{"PORT_QOS_MAP"}

    for  _, tbl_name := range tbl_list {

        dbSpec := &db.TableSpec{Name: tbl_name}

        keys, _ := d.GetKeys(dbSpec)
        for _, key := range keys {
            log.Info("key: ", key)
            qCfg, _ := d.GetEntry(dbSpec, key)
            log.Info("qCfg: ", qCfg)
            mapref , ok := qCfg.Field[map_type] 
            if !ok {
                continue
            }
            log.Info("mapref: ", mapref)

            mapref = DbLeafrefToString(mapref, map_type)

            if mapref == map_name {
                intf_name := key.Get(0)

                log.Info("intf_name added to the referenece list: ", intf_name)

                s = append(s, intf_name)  
            }
        }
    }

    return s
}

func isMapInUse(d *db.DB, map_type string, map_name string)(bool) {
    // read intfs refering to the map
    intfs := getIntfsByMapName(d, map_type, map_name)
    if  len(intfs) == 0 {
        log.Info("No active user of the map: ", map_name)
        return false
    }
    
    log.Info("map is in use: ", map_name)
    return true
}

func qos_map_delete_by_map_name(inParams XfmrParams, map_type string,  map_name string) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_map_delete_by_map_name: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)
    log.Info("map_name: ", map_name)

    if map_name == "" {
        return qos_map_delete_all_map(inParams, map_type)
    }

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)

    // validation
    if isMapInUse(inParams.d, map_type, map_name) {
        err = tlerr.InternalError{Format:"Disallow to delete an active map"}
        log.Info("Disallow to delete an active map: ", map_name)
        return res_map, err
    }

    /* update "map" table */
    rtTblMap := make(map[string]db.Value)
    rtTblMap[map_name] = db.Value{Field: make(map[string]string)}

    log.Info("qos_map_delete_by_map_name - : ", map_type, map_name)
    res_map[map_type] = rtTblMap

    return res_map, err
}



func StringToDbLeafref(name string, prefix string) (string) {
    return "[" + prefix + "|" + name + "]"
}

func DbLeafrefToString(leafrefstr string, prefix string) (string) {
    name := strings.Trim(leafrefstr, "[]")
    name = strings.TrimPrefix(name, prefix + "|")
    return name 
}



var map_type_name_in_oc_yang = map[string]string {
    "DSCP_TO_TC_MAP":           "dscp-to-forwarding-group",
    "DOT1P_TO_TC_MAP":          "dot1p-to-forwarding-group",
    "TC_TO_QUEUE_MAP":          "forwarding-group-to-queue",
    "TC_TO_PRIORITY_GROUP_MAP": "forwarding-group-to-priority-group",
    "PFC_PRIORITY_TO_QUEUE_MAP":"pfc-priority-to-queue",
}

var map_type_name_in_db = map[string]string {
    "DSCP_TO_TC_MAP":           "dscp_to_tc_map",
    "DOT1P_TO_TC_MAP":          "dot1p_to_tc_map",
    "TC_TO_QUEUE_MAP":          "tc_to_queue_map",
    "TC_TO_PRIORITY_GROUP_MAP": "tc_to_pg_map",
    "PFC_PRIORITY_TO_QUEUE_MAP":"pfc_priority_to_queue_map",
}

func DbToYang_qos_intf_qos_map_xfmr(inParams XfmrParams, map_type string) (map[string]interface{}, error) {
    log.Info("Entering DbToYang_qos_intf_qos_map_xfmr", inParams)

    res_map := make(map[string]interface{})

    pathInfo := NewPathInfo(inParams.uri)

    if_name := pathInfo.Var("interface-id")

    dbSpec := &db.TableSpec{Name: "PORT_QOS_MAP"}

    key := db.Key{Comp: []string{if_name}}
    qCfg, _ := inParams.d.GetEntry(dbSpec, key) 

    log.Info("current entry: ", qCfg)
    db_attr_name, ok := map_type_name_in_db[map_type]
    if !ok {
        log.Info("map_type not implemented", map_type)
        return res_map, nil
    }

    value, _ := qCfg.Field[db_attr_name] 
    log.Info("value = ", value)

    attr_name, ok := map_type_name_in_oc_yang[map_type]
    if !ok {
        log.Info("map_type not implemented", map_type)
        return res_map, nil
    }

    res_map[attr_name] = DbLeafrefToString(value,  map_type)
    return res_map, nil
}


func YangToDb_qos_intf_qos_map_xfmr(inParams XfmrParams, map_type string)  (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("Entering YangToDb_qos_intf_qos_map_xfmr===> ", inParams)

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

    var map_name string
    if map_type == "DSCP_TO_TC_MAP" {
        map_name = *(intfObj.InterfaceMaps.Config.DscpToForwardingGroup)
    } else if map_type == "DOT1P_TO_TC_MAP" {
        map_name = *(intfObj.InterfaceMaps.Config.Dot1PToForwardingGroup)
    } else if map_type == "TC_TO_QUEUE_MAP" {
        map_name = *(intfObj.InterfaceMaps.Config.ForwardingGroupToQueue)
    } else if map_type == "TC_TO_PRIORITY_GROUP_MAP" {
        map_name = *(intfObj.InterfaceMaps.Config.ForwardingGroupToPriorityGroup)
    } else if map_type == "PFC_PRIORITY_TO_QUEUE_MAP" {
        map_name = *(intfObj.InterfaceMaps.Config.PfcPriorityToQueue)
    }

    if inParams.oper == DELETE {
        attr_name, ok := map_type_name_in_db[map_type]
        if !ok {
            log.Info("map_type not implemented", map_type)
            err = tlerr.InternalError{Format:"Not Implemented"}
            return res_map, err
        }
        res_map[attr_name] = ""
        return res_map, err
    }

    if len(map_name) == 0 {
        log.Error("map name is Missing")
        return res_map, err
    }

    log.Info("map name is : ", map_name)
    attr_name, ok := map_type_name_in_db[map_type]
    if !ok {
        log.Info("map_type not implemented", map_type)
    } else {
        res_map[attr_name] = StringToDbLeafref(map_name, map_type)
    }

    return res_map, err
}


