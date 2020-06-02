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


