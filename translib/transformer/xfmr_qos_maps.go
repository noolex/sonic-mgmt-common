package transformer

import (
//    "errors"
//    "strconv"
//    "strings"
//    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
//    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
//    "encoding/json"
//    "time"
//    "fmt"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init () {
    XlateFuncBind("qos_fwdgrp_table_xfmr", qos_fwdgrp_table_xfmr)
    XlateFuncBind("YangToDb_qos_fwdgrp_tbl_key_xfmr", YangToDb_qos_fwdgrp_tbl_key_xfmr)
    XlateFuncBind("DbToYang_qos_fwdgrp_tbl_key_xfmr", DbToYang_qos_fwdgrp_tbl_key_xfmr)
    XlateFuncBind("DbToYang_qos_fwdgrp_fld_xfmr", DbToYang_qos_fwdgrp_fld_xfmr)
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


