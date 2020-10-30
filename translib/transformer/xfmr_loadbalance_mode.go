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
    var appDb = inParams.dbs[db.ApplDB]
    hashKeyRecvd := pathInfo.Var("hash")
    v4KeyRecvd := pathInfo.Var("ipv4")
    v6KeyRecvd := pathInfo.Var("ipv6")

    log.Info("DbToYang_hash_mode_state_xfmr - pathInfo: ", pathInfo)
    log.Info("DbToYang_hash_mode_state_xfmr - targetUriPath: ", targetUriPath)
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    switchKeyStr := "switch"
    entry, dbErr := appDb.GetEntry(&db.TableSpec{Name:"SWITCH_TABLE"}, db.Key{Comp: []string{switchKeyStr}})
    if dbErr != nil || len(entry.Field) == 0 {
        log.Error("DbToYang_loadbalance_mode_state_xfmr: App-DB get neighbor entry failed neighKeyStr:", switchKeyStr)
        return err
    }

    if len(hashKeyRecvd) > 0 {
        var lbSeedAttrsObj *ocbinds.OpenconfigLoadbalanceModeExt_SeedAttrs
        var lbSeedAttrObj *ocbinds.OpenconfigLoadbalanceModeExt_SeedAttrs_SeedAttr

        lbSeedAttrsObj = deviceObj.SeedAttrs
        log.Info("DbToYang_loadbalance_mode_state_xfmr: ecmp_hash_fields_ipv4 ",entry.Field["ecmp_hash_fields_ipv4"])

        ygot.BuildEmptyTree(lbSeedAttrsObj)
        if lbSeedAttrsObj != nil && lbSeedAttrsObj.SeedAttr != nil && len(lbSeedAttrsObj.SeedAttr) > 0 {
            var ok bool = false
            if lbSeedAttrObj, ok = lbSeedAttrsObj.SeedAttr["hash"]; !ok {
                lbSeedAttrObj, _ = lbSeedAttrsObj.NewSeedAttr("hash")
            }
            ygot.BuildEmptyTree(lbSeedAttrObj)
            ygot.BuildEmptyTree(lbSeedAttrObj.State)
            ecmpHash := entry.Get("ecmp_hash_seed")
            _value, _ := strconv.Atoi(ecmpHash)
            value := uint32(_value)
            lbSeedAttrObj.State.EcmpHashSeed = &value
        } 
    }

    if len(v6KeyRecvd) > 0 {
        var lbIpv6AttrsObj *ocbinds.OpenconfigLoadbalanceModeExt_Ipv6Attrs
        var lbIpv6AttrObj *ocbinds.OpenconfigLoadbalanceModeExt_Ipv6Attrs_Ipv6Attr
        lbIpv6AttrsObj = deviceObj.Ipv6Attrs
        log.Info("DbToYang_loadbalance_mode_state_xfmr: ecmp_hash_fields_ipv6 ",entry.Field["ecmp_hash_fields_ipv6"])

        ygot.BuildEmptyTree(lbIpv6AttrsObj)


        if lbIpv6AttrsObj != nil && lbIpv6AttrsObj.Ipv6Attr != nil && len(lbIpv6AttrsObj.Ipv6Attr) > 0 {
            var ok bool = false
            if lbIpv6AttrObj, ok = lbIpv6AttrsObj.Ipv6Attr["ipv6"]; !ok {
                lbIpv6AttrObj, _ = lbIpv6AttrsObj.NewIpv6Attr("ipv6")
            }

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
        }
    }

    if len(v4KeyRecvd) > 0 {
        var lbIpv4AttrsObj *ocbinds.OpenconfigLoadbalanceModeExt_Ipv4Attrs
        var lbIpv4AttrObj *ocbinds.OpenconfigLoadbalanceModeExt_Ipv4Attrs_Ipv4Attr
        lbIpv4AttrsObj = deviceObj.Ipv4Attrs
        log.Info("DbToYang_loadbalance_mode_state_xfmr: ecmp_hash_fields_ipv4 ",entry.Field["ecmp_hash_fields_ipv4"])

        ygot.BuildEmptyTree(lbIpv4AttrsObj)
        if lbIpv4AttrsObj != nil && lbIpv4AttrsObj.Ipv4Attr != nil && len(lbIpv4AttrsObj.Ipv4Attr) > 0 {
            var ok bool = false
            if lbIpv4AttrObj, ok = lbIpv4AttrsObj.Ipv4Attr["ipv4"]; !ok {
                lbIpv4AttrObj, _ = lbIpv4AttrsObj.NewIpv4Attr("ipv4")
            }

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
                lbIpv4AttrObj.State.Ipv4Protocol = &trueIpv4Val
            }

            ecmpHash := entry.Get("ecmp_hash_seed")
            _value, _ := strconv.Atoi(ecmpHash)
            value := uint32(_value)
            lbIpv4AttrObj.State.EcmpHashSeed = &value
            trueIpv6Val := true
            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_dst_ip") {
                lbIpv4AttrObj.State.Ipv6DstIp = &trueIpv6Val
            }
            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_src_ip") {
                lbIpv4AttrObj.State.Ipv6SrcIp = &trueIpv6Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_l4_dst_port") {
                lbIpv4AttrObj.State.Ipv6L4DstPort = &trueIpv6Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_l4_src_port") {
                lbIpv4AttrObj.State.Ipv6L4SrcPort = &trueIpv6Val
            }

            if strings.Contains(entry.Field["ecmp_hash_fields_ipv6"], "ipv6_next_hdr") {
                lbIpv4AttrObj.State.Ipv6NextHdr = &trueIpv6Val
            }
        }
    }
    return err
}


