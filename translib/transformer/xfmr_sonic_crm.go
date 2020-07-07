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
    "fmt"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "encoding/json"
)

func init() {
    XlateFuncBind("rpc_crm_stats", rpc_crm_stats)
}

/* RPC for CRM_STATS and CRM_ACL_GROUP_STATS */
var rpc_crm_stats RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {

    var str string
    var idx int
    var err error
    var mapData map[string]interface{}

    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Error("Failed to unmarshall given input data")
        return nil, err
    }
    input := mapData["sonic-system-crm:input"]
    mapData = input.(map[string]interface{})

    rule := ""
    if value, ok := mapData["rule"].(string) ; ok {
        rule = value
    }

    proto := ""
    if value, ok := mapData["type"].(string) ; ok {
        proto = value
    }

    d := dbs[db.CountersDB]
    d.Opts.KeySeparator = ":"
    d.Opts.TableNameSeparator = ":"

    tbl := db.TableSpec { Name: "CRM" }
    key := db.Key { Comp : [] string { } }
    if (rule != "") && (proto != "") {
        key.Comp = append(key.Comp, "ACL_STATS")
        key.Comp = append(key.Comp, rule)
        key.Comp = append(key.Comp, proto)
    } else {
        key.Comp = append(key.Comp, "STATS")
    }

    val, err := d.GetEntry(&tbl, key)

    if err == nil {
        idx = 0
        str = str + "{\n"
        str = str + "  \"sonic-system-crm:output\": {\n"
        for k, v := range val.Field {
            str = str + fmt.Sprintf("    \"%s\": %s", k, v)
            if (idx < len(val.Field) - 1) {
                str = str + ",\n"
            } else {
                str = str + "\n"
            }
            idx = idx + 1
        }
        str = str + "  }\n"
        str = str + "}"
    }

    return []byte(str), err
}
