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

    XlateFuncBind("YangToDb_qos_fwd_group_queue_xfmr", YangToDb_qos_fwd_group_queue_xfmr)
    XlateFuncBind("DbToYang_qos_fwd_group_queue_xfmr", DbToYang_qos_fwd_group_queue_xfmr)

    XlateFuncBind("YangToDb_qos_dscp_fwd_group_xfmr", YangToDb_qos_dscp_fwd_group_xfmr)
    XlateFuncBind("DbToYang_qos_dscp_fwd_group_xfmr", DbToYang_qos_dscp_fwd_group_xfmr)
    XlateFuncBind("YangToDb_qos_dscp_to_tc_map_fld_xfmr", YangToDb_qos_dscp_to_tc_map_fld_xfmr)
    XlateFuncBind("DbToYang_qos_dscp_to_tc_map_fld_xfmr", DbToYang_qos_dscp_to_tc_map_fld_xfmr)
 
}


var YangToDb_qos_dscp_fwd_group_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

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
    log.Info("YangToDb_qos_classifier_xfmr - entry_key : ", map_key)

    if targetUriPath == "/openconfig-qos:qos/dscp-maps/dscp-map" ||
       targetUriPath == "/openconfig-qos:qos/openconfig-qos-maps-ext:dscp-maps/dscp-map" {
        if inParams.oper == DELETE {

            res_map["DSCP_TO_TC_MAP"] = map_entry
            return res_map, err
        }

        // no op at this level
        return res_map, err
    }


    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/dscp-maps/dscp-map/dscp-map-entries/dscp-map-entry") == false  &&
       strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/openconfig-qos-maps-ext:dscp-maps/dscp-map/dscp-map-entries/dscp-map-entry") == false {
        log.Info("YangToDb: map entry unspecified, stop here")
        return res_map, err
    }

    dscp := pathInfo.Var("dscp")
    log.Info("dscp: ", dscp)

    tmp, _ := strconv.ParseUint(dscp, 10, 8)
    dscp_val := uint8(tmp)

    entry, ok := mapObj.DscpMapEntries.DscpMapEntry[dscp_val]
    if !ok  {
        log.Info("entry is nil.")
        return res_map, err
    }

    tc := ""
    if inParams.oper == CREATE ||
       inParams.oper == UPDATE {
        tc =  *(entry.Config.FwdGroup)
    }

    map_entry[map_key].Field[dscp] = tc

    log.Info("YangToDb_qos_classifier_xfmr - entry_key : ", map_key)
    res_map["DSCP_TO_TC_MAP"] = map_entry

    return res_map, err
}

var DbToYang_qos_dscp_fwd_group_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

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

    mapObj, ok := qosObj.DscpMaps.DscpMap[name]
    if !ok {
        mapObj, _ = qosObj.DscpMaps.NewDscpMap(name)
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

    // Classifier
    dbSpec := &db.TableSpec{Name: "DSCP_TO_TC_MAP"}

    key :=db.Key{Comp: []string{name}}
    
    log.Info("key: ", key)

    mapCfg, err := inParams.d.GetEntry(dbSpec, key) 
    if  err != nil {
        log.Info("No dscp-to-tc-map with a name of : ", name)
        return nil
    }

    log.Info("current entry: ", mapCfg)

    mapObj.Config.Name = &name

    for k, v := range mapCfg.Field {
        tmp, _ := strconv.ParseUint(k, 10, 8)
        dscp_val := uint8(tmp)

        entryObj, _ := mapObj.DscpMapEntries.NewDscpMapEntry(dscp_val)
        ygot.BuildEmptyTree(entryObj)
        ygot.BuildEmptyTree(entryObj.Config)

        entryObj.Dscp = &dscp_val

        entryObj.Config.Dscp = &dscp_val
    
        fwdGrp := v
        entryObj.Config.FwdGroup = &fwdGrp
    }

    log.Info("Done fetching dscp-map : ", name)

    return nil
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

var YangToDb_qos_fwd_group_queue_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("YangToDb_qos_fwd_group_queue_xfmr: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    name := pathInfo.Var("name")
    targetUriPath, err := getYangPathFromUri(inParams.uri)

    log.Info("YangToDb: name: ", name)
    log.Info("targetUriPath:",  targetUriPath)

    /* parse the inParams */
    // TODO

    return res_map, err
}

var DbToYang_qos_fwd_group_queue_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    // TODO

    return nil
}



func StringToDbLeafref(name string, prefix string) (string) {
    return "[" + prefix + "|" + name + "]"
}

func DbLeafrefToString(leafrefstr string, prefix string) (string) {
    name := strings.Trim(leafrefstr, "[]")
    name = strings.TrimPrefix(name, prefix + "|")
    return name 
}

var DbToYang_qos_dscp_to_tc_map_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("Entering DbToYang_qos_dscp_to_tc_map_fld_xfmr ", inParams)

    res_map := make(map[string]interface{})

    pathInfo := NewPathInfo(inParams.uri)

    if_name := pathInfo.Var("interface-id")

    dbSpec := &db.TableSpec{Name: "PORT_QOS_MAP"}

    key := db.Key{Comp: []string{if_name}}
    qCfg, _ := inParams.d.GetEntry(dbSpec, key) 

    log.Info("current entry: ", qCfg)
    value, _ := qCfg.Field["dscp_to_tc_map"] 

    log.Info("Tc to Queue map = ", value)
    res_map["dscp-to-forwarding-group"] = DbLeafrefToString(value,  "DSCP_TO_TC_MAP")
    return res_map, nil
}



var YangToDb_qos_dscp_to_tc_map_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("Entering YangToDb_qos_dscp_to_tc_map_fld_xfmr ===> ", inParams)

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

    map_name := *(intfObj.InterfaceMaps.Config.DscpToForwardingGroup)

    if len(map_name) == 0 {
        log.Error("map name is Missing")
        return res_map, err
    }

    log.Info("map name is : ", map_name)
    res_map["dscp_to_tc_map"] = StringToDbLeafref(map_name, "DSCP_TO_TC_MAP")
    return res_map, err
}

