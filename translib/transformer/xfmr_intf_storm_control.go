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
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "strconv"
    log "github.com/golang/glog"
)

func init () {
    XlateFuncBind("YangToDb_storm_value_xfmr", YangToDb_storm_value_xfmr)
    XlateFuncBind("DbToYang_storm_value_xfmr", DbToYang_storm_value_xfmr)
    XlateFuncBind("YangToDb_storm_type_key_xfmr", YangToDb_storm_type_key_xfmr)
    XlateFuncBind("DbToYang_storm_type_key_xfmr", DbToYang_storm_type_key_xfmr)
    XlateFuncBind("YangToDb_storm_ifname_xfmr", YangToDb_storm_ifname_xfmr)
    XlateFuncBind("DbToYang_storm_ifname_xfmr", DbToYang_storm_ifname_xfmr)
}

func DbToYang_storm_type_key_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var stormKey string
    result := make(map[string]interface{})
    stormKey = inParams.key
    if log.V(3) {
        log.Infof("DbToYang_storm_type_key_xfmr: key:%s stormKey:%s", inParams.key,stormKey)
    }

    stormVals := strings.Split(stormKey,"|")
    if (stormVals[1] == "broadcast") {
        result["storm-type"] = "BROADCAST"
    } else if (stormVals[1] == "unknown-unicast") {
        result["storm-type"] = "UNKNOWN_UNICAST"
    } else if (stormVals[1] == "unknown-multicast") {
        result["storm-type"] = "UNKNOWN_MULTICAST"
    } else {
        log.Errorf("Invalid storm-type:%s",stormVals[1])
        return result, tlerr.InvalidArgs("Invalid storm-type: %s", stormVals[1])
    }
    //result["ifname"] = stormVals[0]

    if log.V(3) {
        log.Info(result)
    }

    return result, nil
}

var YangToDb_storm_type_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var stormKey string
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("name")
    stormType := pathInfo.Var("storm-type")
    if log.V(3) {
        log.Infof("Entering YangToDb_storm_type_key_xfmr intf:%s storm-type:%s",intfName,stormType)
    }
    if (stormType == "") {
        return "", nil
    } else if (stormType == "BROADCAST") {
        stormKey = intfName+"|"+"broadcast"
    } else if (stormType == "UNKNOWN_UNICAST") {
        stormKey = intfName+"|"+"unknown-unicast"
    } else if (stormType == "UNKNOWN_MULTICAST") {
        stormKey = intfName+"|"+"unknown-multicast"
    } else {
        log.Errorf("Invalid storm-type:%s",stormType)
        return "", tlerr.InvalidArgs("Invalid storm-type: %s", stormType)
    }
    if log.V(3) {
        log.Infof("Returning stormKey:%s",stormKey)
    }
    return stormKey, nil
}

func DbToYang_storm_value_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var stormKey string
    result := make(map[string]interface{})
    stormKey = inParams.key
    if log.V(3) {
        log.Infof("DbToYang_storm_value_xfmr: key:%s stormKey:%s", inParams.key,stormKey)
    }

    stormVals := strings.Split(stormKey,"|")
    if (stormVals[1] == "broadcast") {
        result["storm-type"] = "BROADCAST"
    } else if (stormVals[1] == "unknown-unicast") {
        result["storm-type"] = "UNKNOWN_UNICAST"
    } else if (stormVals[1] == "unknown-multicast") {
        result["storm-type"] = "UNKNOWN_MULTICAST"
    } else {
        log.Errorf("Invalid storm-type:%s",stormVals[1])
        return result, tlerr.InvalidArgs("Invalid storm-type: %s", stormVals[1])
    }
    //result["ifname"] = stormVals[0]
    
    entry, err := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:"PORT_STORM_CONTROL"}, db.Key{Comp: []string{stormKey}})
    if err == nil {
        value := entry.Field["kbps"]
        result["kbps"],_ = strconv.ParseFloat(value,64)
    } else {
        log.Error("Error ", err)
        return result, tlerr.NotFound("Resource Not Found")
    }
    if log.V(3) {
        log.Info(result)
    }
    return result, nil
}

var YangToDb_storm_value_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info("Entering YangToDb_storm_value_xfmr")
    }
    res_map := make(map[string]string)
    return res_map, nil
}

func DbToYang_storm_ifname_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var stormKey string
    result := make(map[string]interface{})
    stormKey = inParams.key
    if log.V(3) {
        log.Infof("DbToYang_storm_ifname_xfmr: key:%s stormKey:%s", inParams.key,stormKey)
    }
    stormVals := strings.Split(stormKey,"|")
    result["ifname"] = stormVals[0]
    if log.V(3) {
        log.Info(result)
    }
    return result, nil
}

var YangToDb_storm_ifname_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info("Entering YangToDb_storm_ifname_xfmr")
    }
    res_map := make(map[string]string)
    return res_map, nil
}
