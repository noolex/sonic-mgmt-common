////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "strconv"
    "strings"
)

func init() {
    XlateFuncBind("YangToDb_loadshare_mode_ipv4_fld_xfmr", YangToDb_loadshare_mode_ipv4_fld_xfmr)
    XlateFuncBind("DbToYang_loadshare_mode_ipv4_fld_xfmr", DbToYang_loadshare_mode_ipv4_fld_xfmr)
    XlateFuncBind("Subscribe_loadshare_mode_ipv4_fld_xfmr", Subscribe_loadshare_mode_ipv4_fld_xfmr)
    XlateFuncBind("YangToDb_loadshare_mode_ipv6_fld_xfmr", YangToDb_loadshare_mode_ipv6_fld_xfmr)
    XlateFuncBind("DbToYang_loadshare_mode_ipv6_fld_xfmr", DbToYang_loadshare_mode_ipv6_fld_xfmr)
    XlateFuncBind("Subscribe_loadshare_mode_ipv6_fld_xfmr", Subscribe_loadshare_mode_ipv6_fld_xfmr)
    XlateFuncBind("YangToDb_loadshare_mode_seed_fld_xfmr", YangToDb_loadshare_mode_seed_fld_xfmr)
    XlateFuncBind("DbToYang_loadshare_mode_seed_fld_xfmr", DbToYang_loadshare_mode_seed_fld_xfmr)
    XlateFuncBind("Subscribe_loadshare_mode_seed_fld_xfmr", Subscribe_loadshare_mode_seed_fld_xfmr)
    XlateFuncBind("DbToYang_loadshare_mode_state_xfmr", DbToYang_loadshare_mode_state_xfmr)
    XlateFuncBind("loadshare_seed_table_xfmr", loadshare_seed_table_xfmr)
    XlateFuncBind("YangToDb_loadshare_mode_seed_key_xfmr", YangToDb_loadshare_mode_seed_key_xfmr)
    XlateFuncBind("YangToDb_loadshare_mode_ipv4_key_xfmr", YangToDb_loadshare_mode_ipv4_key_xfmr)
    XlateFuncBind("YangToDb_loadshare_mode_ipv6_key_xfmr", YangToDb_loadshare_mode_ipv6_key_xfmr)
    XlateFuncBind("loadshare_post_xfmr", loadshare_post_xfmr)
}

type LoadshareModeHistoryEntry struct {
    Timestamp   string    `json:"timestamp"`
    Event       string    `json:"event,omitempty"`
}

var loadshare_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    if inParams.oper == DELETE {
        if inParams.skipOrdTblChk != nil {
            *inParams.skipOrdTblChk  = true
        }
    }
    log.Infof("loadshare_post_xfmr returned : %v, skipOrdTblChk: %v", (*inParams.dbDataMap)[db.ConfigDB], *inParams.skipOrdTblChk)
    return (*inParams.dbDataMap)[db.ConfigDB], nil
}

var YangToDb_loadshare_mode_seed_key_xfmr = func(inParams XfmrParams) (string, error) {
        log.Info("YangToDb_loadshare_mode_seed_key_xfmr: ", inParams.ygRoot, inParams.uri)
        return "hash", nil
}

var YangToDb_loadshare_mode_ipv4_key_xfmr = func(inParams XfmrParams) (string, error) {
        log.Info("YangToDb_loadshare_mode_ipv4_key_xfmr: ", inParams.ygRoot, inParams.uri)
        return "ipv4", nil
}

var YangToDb_loadshare_mode_ipv6_key_xfmr = func(inParams XfmrParams) (string, error) {
        log.Info("YangToDb_loadshare_mode_ipv6_key_xfmr: ", inParams.ygRoot, inParams.uri)
        return "ipv6", nil
}

var YangToDb_loadshare_mode_ipv4_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_loadshare_mode_ipv4_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_loadshare_mode_ipv4_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_loadshare_mode_ipv4_fld_xfmr: ", inParams.key)
    cdb := inParams.dbs[db.ConfigDB]
    lbEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "ECMP_LOADSHARE_TABLE_IPV4"}, db.Key{Comp: []string{inParams.key}})
    ipv4 := lbEntry.Get("ipv4")
	
    result["ipv4"] = &ipv4

    return result, err
}

var Subscribe_loadshare_mode_ipv4_fld_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    tableName = "ECMP_LOADSHARE_TABLE_IPV4"
    Id := pathInfo.Var("ipv4")

    log.Info("redisKey:", Id)

    result.dbDataMap = make(RedisDbMap)
    log.Infof("Subscribe_loadshare_mode_ipv4_fld_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, Id)

    result.dbDataMap = RedisDbMap{db.ConfigDB:{tableName:{Id:{}}}}
    result.needCache = true
    result.onChange = OnchangeEnable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

var YangToDb_loadshare_mode_ipv6_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_loadshare_mode_ipv6_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_loadshare_mode_ipv6_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_loadshare_mode_ipv6_fld_xfmr: ", inParams.key)

    cdb := inParams.dbs[db.ConfigDB]
    lbEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "ECMP_LOADSHARE_TABLE_IPV6"}, db.Key{Comp: []string{inParams.key}})
    ipv6 := lbEntry.Get("ipv6")
	
    result["ipv6"] = &ipv6

    return result, err
}

var Subscribe_loadshare_mode_ipv6_fld_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    tableName = "ECMP_LOADSHARE_TABLE_IPV6"
    Id := pathInfo.Var("ipv6")

    log.Info("redisKey:", Id)

    result.dbDataMap = make(RedisDbMap)
    log.Infof("Subscribe_loadshare_mode_ipv6_fld_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, Id)

    result.dbDataMap = RedisDbMap{db.ConfigDB:{tableName:{Id:{}}}}
    result.needCache = true
    result.onChange = OnchangeEnable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

var YangToDb_loadshare_mode_seed_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_loadshare_mode_seed_fld_xfmr: ", inParams.key)


    return res_map, err
}

var DbToYang_loadshare_mode_seed_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_loadshare_mode_seed_fld_xfmr: ", inParams.key)

    cdb := inParams.dbs[db.ConfigDB]
    lbEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "ECMP_LOADSHARE_TABLE_SEED"}, db.Key{Comp: []string{inParams.key}})
    seed := lbEntry.Get("hash")
	
    result["hash"] = &seed

    return result, err
}

var Subscribe_loadshare_mode_seed_fld_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    tableName = "ECMP_LOADSHARE_TABLE_SEED"
    Id := pathInfo.Var("hash")

    log.Info("redisKey:", Id)

    result.dbDataMap = make(RedisDbMap)
    log.Infof("Subscribe_loadshare_mode_hash_fld_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, Id)

    result.dbDataMap = RedisDbMap{db.ConfigDB:{tableName:{Id:{}}}}
    result.needCache = true
    result.onChange = OnchangeEnable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

var DbToYang_loadshare_mode_state_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    var appDb = inParams.dbs[db.ApplDB]

    log.Info("DbToYang_hash_mode_state_xfmr - pathInfo: ", pathInfo)
    log.Info("DbToYang_hash_mode_state_xfmr - targetUriPath: ", targetUriPath)

    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    switchKeyStr := "switch"
    entry, dbErr := appDb.GetEntry(&db.TableSpec{Name:"SWITCH_TABLE"}, db.Key{Comp: []string{switchKeyStr}})
    if dbErr != nil || len(entry.Field) == 0 {
        log.Error("DbToYang_loadshare_mode_state_xfmr: App-DB get neighbor entry failed neighKeyStr:", switchKeyStr)
        return err
    }

    log.Info("DbToYang_loadshare_mode_state_xfmr entry ", entry)
    if strings.HasPrefix(targetUriPath, "/openconfig-loadshare-mode-ext:loadshare/seed-attrs") {
        var lbSeedAttrObj *ocbinds.OpenconfigLoadshareModeExt_Loadshare_SeedAttrs = deviceObj.Loadshare.SeedAttrs
        log.Info("DbToYang_loadshare_mode_state_xfmr: ecmp_hash_seed ",entry.Field["ecmp_hash_seed"])

        if lbSeedAttrObj != nil && lbSeedAttrObj.State != nil {
            ygot.BuildEmptyTree(lbSeedAttrObj)
            ygot.BuildEmptyTree(lbSeedAttrObj.State)
            ecmpHash := entry.Get("ecmp_hash_seed")
            _value, _ := strconv.Atoi(ecmpHash)
            value := uint32(_value)
            lbSeedAttrObj.State.EcmpHashSeed = &value
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-loadshare-mode-ext:loadshare/ipv4-attrs") {
        var lbIpv4AttrObj *ocbinds.OpenconfigLoadshareModeExt_Loadshare_Ipv4Attrs = deviceObj.Loadshare.Ipv4Attrs
        log.Info("DbToYang_loadshare_mode_state_xfmr: ecmp_hash_fields_ipv4 ",entry.Field["ecmp_hash_fields_ipv4"])

        if lbIpv4AttrObj != nil && lbIpv4AttrObj.State != nil {
            ygot.BuildEmptyTree(lbIpv4AttrObj)
            ygot.BuildEmptyTree(lbIpv4AttrObj.State)
            trueIpv4Val := true
            keyIpv4Val := "ipv4"
            if strings.Contains(entry.Field["ecmp_hash_fields_ipv4"], "ipv4") {
                lbIpv4AttrObj.State.Ipv4 = &keyIpv4Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv4"], "ipv4_dst_ip") {
                lbIpv4AttrObj.State.Ipv4DstIp = &trueIpv4Val
            }
            if strings.Contains(entry.Field["ecmp_hash_fields_ipv4"], "ipv4_src_ip") {
                lbIpv4AttrObj.State.Ipv4SrcIp = &trueIpv4Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv4"], "ipv4_l4_dst_port") {
                lbIpv4AttrObj.State.Ipv4L4DstPort = &trueIpv4Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv4"], "ipv4_l4_src_port") {
                lbIpv4AttrObj.State.Ipv4L4SrcPort = &trueIpv4Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv4"], "ipv4_protocol") {
                lbIpv4AttrObj.State.Ipv4IpProto = &trueIpv4Val
            }

            if strings.Contains(entry.Field["ecmp_hash_mode_ipv4"], "ipv4_symmetric") {
                lbIpv4AttrObj.State.Ipv4Symmetric = &trueIpv4Val
            }
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-loadshare-mode-ext:loadshare/ipv6-attrs") {
        var lbIpv6AttrObj *ocbinds.OpenconfigLoadshareModeExt_Loadshare_Ipv6Attrs = deviceObj.Loadshare.Ipv6Attrs
        log.Info("DbToYang_loadshare_mode_state_xfmr: ecmp_hash_fields_ipv6 ",entry.Field["ecmp_hash_fields_ipv6"])

        if lbIpv6AttrObj != nil && lbIpv6AttrObj.State != nil {
            ygot.BuildEmptyTree(lbIpv6AttrObj)
            ygot.BuildEmptyTree(lbIpv6AttrObj.State)
            trueIpv6Val := true
            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_dst_ip") {
                lbIpv6AttrObj.State.Ipv6DstIp = &trueIpv6Val
            }
            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_src_ip") {
                lbIpv6AttrObj.State.Ipv6SrcIp = &trueIpv6Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_l4_dst_port") {
                lbIpv6AttrObj.State.Ipv6L4DstPort = &trueIpv6Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_l4_src_port") {
                lbIpv6AttrObj.State.Ipv6L4SrcPort = &trueIpv6Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_next_hdr") {
                lbIpv6AttrObj.State.Ipv6NextHdr = &trueIpv6Val
            }

            if strings.Contains(entry.Field["ecmp_hash_mode_ipv6"], "ipv6_symmetric") {
                lbIpv6AttrObj.State.Ipv6Symmetric = &trueIpv6Val
            }
        }
    }
    return err
}

func get_lb_seed_cfg_tbl_entry (inParams XfmrParams, tableName string) (bool) {
    var err error

    TableKey := "hash" 

    lbIpv4TblTs := &db.TableSpec{Name:tableName}
    lbIpv4EntryKey := db.Key{Comp:[]string{TableKey}}

    _, err = configDbPtr.GetEntry(lbIpv4TblTs, lbIpv4EntryKey);
    if (err != nil) {
        return false
    } else {
        log.Info("get_lb_ipv4_cfg_tbl_entry: entry found")
        return true
    }
}

var loadshare_seed_table_xfmr TableXfmrFunc = func (inParams XfmrParams)  ([]string, error) {
    var tblList []string

    log.Info("loadshare_seed_table_xfmr Enter")

    tblList = append(tblList, "ECMP_LOADSHARE_TABLE_SEED")
    if (inParams.dbDataMap != nil) {
        if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["ECMP_LOADSHARE_TABLE_SEED"]; !ok {
                    (*inParams.dbDataMap)[db.ConfigDB]["ECMP_LOADSHARE_TABLE_SEED"] = make(map[string]db.Value)
        }
    } else {
        if found := get_lb_seed_cfg_tbl_entry(inParams, "ECMP_LOADSHARE_TABLE_SEED") ; !found {
            if (nil != inParams.isVirtualTbl) {
                *inParams.isVirtualTbl = true
            }
        }
        return tblList,nil
    }

    return tblList, nil
}
