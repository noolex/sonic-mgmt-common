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
    "github.com/Azure/sonic-mgmt-common/translib/db"
)

func init() {
    XlateFuncBind("YangToDb_loadbalance_mode_ipv4_fld_xfmr", YangToDb_loadbalance_mode_ipv4_fld_xfmr)
    XlateFuncBind("DbToYang_loadbalance_mode_ipv4_fld_xfmr", DbToYang_loadbalance_mode_ipv4_fld_xfmr)
    XlateFuncBind("Subscribe_loadbalance_mode_ipv4_fld_xfmr", Subscribe_loadbalance_mode_ipv4_fld_xfmr)
    XlateFuncBind("YangToDb_loadbalance_mode_ipv6_fld_xfmr", YangToDb_loadbalance_mode_ipv6_fld_xfmr)
    XlateFuncBind("DbToYang_loadbalance_mode_ipv6_fld_xfmr", DbToYang_loadbalance_mode_ipv6_fld_xfmr)
    XlateFuncBind("Subscribe_loadbalance_mode_ipv6_fld_xfmr", Subscribe_loadbalance_mode_ipv6_fld_xfmr)
    XlateFuncBind("YangToDb_loadbalance_mode_seed_fld_xfmr", YangToDb_loadbalance_mode_seed_fld_xfmr)
    XlateFuncBind("DbToYang_loadbalance_mode_seed_fld_xfmr", DbToYang_loadbalance_mode_seed_fld_xfmr)
    XlateFuncBind("Subscribe_loadbalance_mode_seed_fld_xfmr", Subscribe_loadbalance_mode_seed_fld_xfmr)
    XlateFuncBind("DbToYang_loadbalance_mode_state_xfmr", DbToYang_loadbalance_mode_state_xfmr)
}

type LoadbalanceModeHistoryEntry struct {
    Timestamp   string    `json:"timestamp"`
    Event       string    `json:"event,omitempty"`
}

var YangToDb_loadbalance_mode_ipv4_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_loadbalance_mode_ipv4_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_loadbalance_mode_ipv4_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_loadbalance_mode_ipv4_fld_xfmr: ", inParams.key)
    cdb := inParams.dbs[db.ConfigDB]
    lbEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "ECMP_LOADBALANCE_TABLE_IPV4"}, db.Key{Comp: []string{inParams.key}})
    ipv4 := lbEntry.Get("ipv4")
	
    result["ipv4"] = &ipv4

    return result, err
}

var Subscribe_loadbalance_mode_ipv4_fld_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    tableName = "ECMP_LOADBALANCE_TABLE_IPV4"
    Id := pathInfo.Var("ipv4")

    log.Info("redisKey:", Id)

    result.dbDataMap = make(RedisDbMap)
    log.Infof("Subscribe_loadbalance_mode_ipv4_fld_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, Id)

    result.dbDataMap = RedisDbMap{db.ConfigDB:{tableName:{Id:{}}}}
    result.needCache = true
    result.onChange = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

var YangToDb_loadbalance_mode_ipv6_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_loadbalance_mode_ipv6_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_loadbalance_mode_ipv6_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_loadbalance_mode_ipv6_fld_xfmr: ", inParams.key)

    cdb := inParams.dbs[db.ConfigDB]
    lbEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "ECMP_LOADBALANCE_TABLE_IPV6"}, db.Key{Comp: []string{inParams.key}})
    ipv6 := lbEntry.Get("ipv6")
	
    result["ipv6"] = &ipv6

    return result, err
}

var Subscribe_loadbalance_mode_ipv6_fld_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    tableName = "ECMP_LOADBALANCE_TABLE_IPV6"
    Id := pathInfo.Var("ipv6")

    log.Info("redisKey:", Id)

    result.dbDataMap = make(RedisDbMap)
    log.Infof("Subscribe_loadbalance_mode_ipv6_fld_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, Id)

    result.dbDataMap = RedisDbMap{db.ConfigDB:{tableName:{Id:{}}}}
    result.needCache = true
    result.onChange = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

var YangToDb_loadbalance_mode_seed_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_loadbalance_mode_seed_fld_xfmr: ", inParams.key)


    return res_map, err
}

var DbToYang_loadbalance_mode_seed_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_loadbalance_mode_seed_fld_xfmr: ", inParams.key)

    cdb := inParams.dbs[db.ConfigDB]
    lbEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "ECMP_LOADBALANCE_TABLE_SEED"}, db.Key{Comp: []string{inParams.key}})
    seed := lbEntry.Get("hash")
	
    result["hash"] = &seed

    return result, err
}

var Subscribe_loadbalance_mode_seed_fld_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    var tableName string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    tableName = "ECMP_LOADBALANCE_TABLE_SEED"
    Id := pathInfo.Var("hash")

    log.Info("redisKey:", Id)

    result.dbDataMap = make(RedisDbMap)
    log.Infof("Subscribe_loadbalance_mode_hash_fld_xfmr path:%s; template:%s targetUriPath:%s key:%s",
               pathInfo.Path, pathInfo.Template, targetUriPath, Id)

    result.dbDataMap = RedisDbMap{db.ConfigDB:{tableName:{Id:{}}}}
    result.needCache = true
    result.onChange = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

var DbToYang_loadbalance_mode_state_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("DbToYang_hash_mode_state_xfmr - pathInfo: ", pathInfo)
    log.Info("DbToYang_hash_mode_state_xfmr - targetUriPath: ", targetUriPath)
    //deviceObj := (*inParams.ygRoot).(*ocbinds.Device)

    return err
}


