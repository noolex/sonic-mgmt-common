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
    XlateFuncBind("qos_fwdgrp_table_xfmr", qos_fwdgrp_table_xfmr)
    XlateFuncBind("YangToDb_qos_fwdgrp_tbl_key_xfmr", YangToDb_qos_fwdgrp_tbl_key_xfmr)
    XlateFuncBind("DbToYang_qos_fwdgrp_tbl_key_xfmr", DbToYang_qos_fwdgrp_tbl_key_xfmr)
    XlateFuncBind("DbToYang_qos_fwdgrp_fld_xfmr", DbToYang_qos_fwdgrp_fld_xfmr)

    XlateFuncBind("YangToDb_qos_dscp_fwd_group_xfmr", YangToDb_qos_dscp_fwd_group_xfmr)
    XlateFuncBind("DbToYang_qos_dscp_fwd_group_xfmr", DbToYang_qos_dscp_fwd_group_xfmr)
    XlateFuncBind("YangToDb_qos_dscp_to_tc_map_fld_xfmr", YangToDb_qos_dscp_to_tc_map_fld_xfmr)
    XlateFuncBind("DbToYang_qos_dscp_to_tc_map_fld_xfmr", DbToYang_qos_dscp_to_tc_map_fld_xfmr)

}


var YangToDb_qos_dscp_fwd_group_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    map_type := "DSCP_TO_TC_MAP"

    if inParams.oper == DELETE {
        return qos_map_delete_xfmr(inParams, map_type)
    }

    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("YangToDb_qos_dscp_fwd_group_xfmr: ", inParams.ygRoot, inParams.uri)
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

    mapObj, ok := qosObj.DscpMaps.DscpMap[name]
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

    if !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/dscp-maps/dscp-map/dscp-map-entries/dscp-map-entry")  &&
       !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/openconfig-qos-maps-ext:dscp-maps/dscp-map/dscp-map-entries/dscp-map-entry") {
        log.Info("YangToDb: map entry unspecified, stop here")
        return res_map, err
    }

    str := qos_map_oc_yang_key_map[map_type]
    log.Info("key string: " , str)
    entry_key := pathInfo.Var(str)
    //entry_key := pathInfo.Var("dscp")
    log.Info("entry_key : ", entry_key)
    if entry_key == "" {
        return res_map, err
    }

    tmp, _ := strconv.ParseUint(entry_key, 10, 8)
    tmp2 := uint8(tmp)
    log.Info("entry_key in val: ", tmp2)

    entry, ok := mapObj.DscpMapEntries.DscpMapEntry[tmp2]
    if !ok  {
        log.Info("entry is nil.")
        return res_map, err
    }

    val :=  *(entry.Config.FwdGroup)

    map_entry[map_key].Field[entry_key] = val 

    log.Info("map key : ", map_key, " entry_key: ", entry_key)
    res_map[map_type] = map_entry

    return res_map, err

}


func fill_dscp_map_info_by_name(inParams XfmrParams, dscpMaps * ocbinds.OpenconfigQos_Qos_DscpMaps, name string) error {

    map_type := "DSCP_TO_TC_MAP"

    mapObj, ok := dscpMaps.DscpMap[name]
    if !ok {
        mapObj, _ = dscpMaps.NewDscpMap(name)
        ygot.BuildEmptyTree(mapObj)
        mapObj.Name = &name

    }

    var mapEntries ocbinds.OpenconfigQos_Qos_DscpMaps_DscpMap_DscpMapEntries
    if mapObj.DscpMapEntries == nil {
        mapObj.DscpMapEntries = &mapEntries
    }

    var mapObjCfg ocbinds.OpenconfigQos_Qos_DscpMaps_DscpMap_Config
    if mapObj.Config == nil {
        mapObj.Config = &mapObjCfg
    }

    var mapObjSta ocbinds.OpenconfigQos_Qos_DscpMaps_DscpMap_State
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
    var tmp_cfg ocbinds.OpenconfigQos_Qos_DscpMaps_DscpMap_DscpMapEntries_DscpMapEntry_Config
    var tmp_sta ocbinds.OpenconfigQos_Qos_DscpMaps_DscpMap_DscpMapEntries_DscpMapEntry_State
    entry_added :=  0
    for k, v := range mapCfg.Field {
        if entry_key != "" && k!= entry_key {
            continue
        }

        tmp, _ := strconv.ParseUint(k, 10, 8)
        key := uint8(tmp)
        value := v

        entryObj, ok := mapObj.DscpMapEntries.DscpMapEntry[key]
        if !ok {
            entryObj, _ = mapObj.DscpMapEntries.NewDscpMapEntry(key)
            ygot.BuildEmptyTree(entryObj)
            ygot.BuildEmptyTree(entryObj.Config)
            ygot.BuildEmptyTree(entryObj.State)
        }

        entryObj.Dscp = &key

        if entryObj.Config == nil {
            entryObj.Config = &tmp_cfg
        }
        entryObj.Config.Dscp = &key
        entryObj.Config.FwdGroup = &value


        if entryObj.State == nil {
            entryObj.State = &tmp_sta
        }
        entryObj.State.Dscp = &key
        entryObj.State.FwdGroup = &value

        entry_added = entry_added + 1

        log.Info("Added entry: ", entryObj)
    }

    log.Info("Done fetching dscp-map : ", name)

    if entry_key != "" && entry_added == 0 {
        err = tlerr.NotFoundError{Format:"Instance Not found"}
        log.Info("Instance not found.")
        return err
    }

    return nil
}


var DbToYang_qos_dscp_fwd_group_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    name := pathInfo.Var("name")

    log.Info("inParams: ", inParams)

    qosObj := getQosRoot(inParams.ygRoot)

    if qosObj == nil {
        ygot.BuildEmptyTree(qosObj)
    }

    if qosObj.DscpMaps == nil {
        ygot.BuildEmptyTree(qosObj.DscpMaps)
    }

    dbSpec := &db.TableSpec{Name: "DSCP_TO_TC_MAP"}

    map_added := 0
    keys, _ := inParams.d.GetKeys(dbSpec)
    for _, key := range keys {
        log.Info("key: ", key)

        map_name := key.Comp[0]
        if name != ""  && name != map_name{
            continue
        } 

        map_added = map_added + 1 

        err = fill_dscp_map_info_by_name(inParams, qosObj.DscpMaps, map_name)

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


var fwd_grp_list = []string{"0", "1", "2", "3", "4", "5", "6", "7"}
/* Validate whether Fwd Grp exists in DB */
func validateQosFwdGrp(fwdGrpName string) error {

    log.Info(" validateQosFwdGrp - fwdGrpName ", fwdGrpName);
    if fwdGrpName  == "" {
        return nil
    }

    for _, grp := range fwd_grp_list {
        if grp == fwdGrpName {
            return nil
        }
    }
    errStr := "Invalid Fwd Grop:" + fwdGrpName
    log.Error(errStr)
    return tlerr.InvalidArgsError{Format:errStr}
}


var qos_fwdgrp_table_xfmr TableXfmrFunc = func (inParams XfmrParams) ([]string, error) {
    var tblList []string
    var key string
    var err error

    log.Info(" TableXfmrFunc - Uri: ", inParams.uri);
    pathInfo := NewPathInfo(inParams.uri)
    fwdGrpName:= pathInfo.Var("name");

    if (inParams.oper != GET) {
        return tblList, err
    }

    tblList = append(tblList, "QOS_FWD_GROUP")
    if len(fwdGrpName) != 0 {
        key = fwdGrpName
        log.Info("TableXfmrFunc - qos_fwdgrp_table_xfmr key is present, curr DB ", inParams.curDb)

        err = validateQosFwdGrp(fwdGrpName)
        if err != nil {
            return tblList, err
        }

        if (inParams.dbDataMap != nil) {
            if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"]; !ok {
                (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"] = make(map[string]db.Value)
            }
            if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"][key]; !ok {
                (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"][key] = db.Value{Field: make(map[string]string)}
                (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"][key].Field["NULL"] = "NULL"
            }
        }
    } else {
        log.Info("TableXfmrFunc - qos_fwdgrp_table_xfmr key is not present, curr DB ", inParams.curDb)
        if(inParams.dbDataMap != nil) {

            if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"]; !ok {
                (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"] = make(map[string]db.Value)
            }
            for _, grp := range fwd_grp_list {
                if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"][grp]; !ok {
                    (*inParams.dbDataMap)[db.ConfigDB]["QOS_FWD_GROUP"][grp] = db.Value{Field: make(map[string]string)}
                }
            }
        }
    }
    return tblList, nil
}

var YangToDb_qos_fwdgrp_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var fwdName string
    log.Info("Entering YangToDb_qos_fwdgrp_tbl_key_xfmr Uri ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    fwdName = pathInfo.Var("name")
    log.Info("Fwd Grp name: ", fwdName)
    err = validateQosFwdGrp(fwdName)
    if err != nil {
        return fwdName, err
    }
    return fwdName, err
}

var DbToYang_qos_fwdgrp_tbl_key_xfmr  KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("Entering DbToYang_qos_fwdgrp_tbl_key_xfmr ", inParams.uri)

    res_map := make(map[string]interface{})

    log.Info("Fwd Grp Name = ", inParams.key)
    res_map["name"] = inParams.key
    return res_map, nil
}

var DbToYang_qos_fwdgrp_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("Entering DbToYang_qos_fwdgrp_fld_xfmr ", inParams.uri)

    res_map := make(map[string]interface{})

    log.Info("Fwd Grp = ", inParams.key)
    res_map["name"] = inParams.key
    return res_map, nil
}


var DbToYang_qos_dscp_to_tc_map_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    return DbToYang_qos_intf_qos_map_xfmr(inParams, "DSCP_TO_TC_MAP")
}



var YangToDb_qos_dscp_to_tc_map_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    return YangToDb_qos_intf_qos_map_xfmr(inParams, "DSCP_TO_TC_MAP")
}

