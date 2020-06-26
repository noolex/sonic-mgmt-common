////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
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
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "strconv"
    log "github.com/golang/glog"
)

func init () {
    XlateFuncBind("YangToDb_storm_value_xfmr", YangToDb_storm_value_xfmr)
    XlateFuncBind("DbToYang_storm_value_xfmr", DbToYang_storm_value_xfmr)
    XlateFuncBind("YangToDb_storm_type_key_xfmr", YangToDb_storm_type_key_xfmr)
    XlateFuncBind("DbToYang_storm_type_key_xfmr", DbToYang_storm_type_key_xfmr)
}

func DbToYang_storm_type_key_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var stormKey string
    log.Info("DbToYang_storm_type_key_xfmr: key=\"%s\"", inParams.key)
    result := make(map[string]interface{})
    stormKey = inParams.key
    log.Info(stormKey)

    stormVals := strings.Split(stormKey,"|")
    if (stormVals[1] == "broadcast") {
        result["storm-type"] = "BROADCAST"
    } else if (stormVals[1] == "unknown-unicast") {
        result["storm-type"] = "UNKNOWN_UNICAST"
    } else if (stormVals[1] == "unknown-multicast") {
        result["storm-type"] = "UNKNOWN_MULTICAST"
    }
    result["ifname"] = stormVals[0]

    log.Info(result)

    return result, nil
}

var YangToDb_storm_type_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var stormKey string
    log.Info("Entering YangToDb_storm_type_key_xfmr")
    pathInfo := NewPathInfo(inParams.requestUri)
    log.Info(pathInfo)
    pathInfo = NewPathInfo(inParams.uri)
    log.Info(pathInfo)
    intfName := pathInfo.Var("name")
    stormType := pathInfo.Var("storm-type")
    log.Info(intfName)
    log.Info(stormType)

    if (stormType == "BROADCAST") {
        stormKey = intfName+"|"+"broadcast"
    } else if (stormType == "UNKNOWN_UNICAST") {
        stormKey = intfName+"|"+"unknown-unicast"
    } else if (stormType == "UNKNOWN_MULTICAST") {
        stormKey = intfName+"|"+"unknown-multicast"
    }

    log.Info(stormKey)
    return stormKey, nil
}

func DbToYang_storm_value_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("DbToYang_storm_value_xfmr: key=\"%s\"", inParams.key)
    var stormKey string
    result := make(map[string]interface{})
    stormKey = inParams.key
    log.Info(stormKey)

    stormVals := strings.Split(stormKey,"|")
    if (stormVals[1] == "broadcast") {
        result["storm-type"] = "BROADCAST"
    } else if (stormVals[1] == "unknown-unicast") {
        result["storm-type"] = "UNKNOWN_UNICAST"
    } else if (stormVals[1] == "unknown-multicast") {
        result["storm-type"] = "UNKNOWN_MULTICAST"
    }
    result["ifname"] = stormVals[0]
    
    entry, err := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:"PORT_STORM_CONTROL"}, db.Key{Comp: []string{stormKey}})
    if err == nil {
        value := entry.Field["kbps"]
        result["kbps"],_ = strconv.ParseFloat(value,64)
    }

    log.Info(result)
    return result, nil
}

var YangToDb_storm_value_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    log.Info("Entering YangToDb_storm_value_xfmr")

    return res_map, nil
}
