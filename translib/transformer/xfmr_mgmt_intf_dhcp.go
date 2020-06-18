//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Dell, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "net"
    log "github.com/golang/glog"
    "fmt"
    "encoding/json"
)

func init () {
    XlateFuncBind("rpc_renew_dhcp_lease", rpc_renew_dhcp_lease)
}

func intfIPcountGet(tblName string, d *db.DB, intfName string, ipv4Cnt *int, ipv6Cnt *int) error {
    if (ipv4Cnt == nil || ipv6Cnt == nil) {
        return nil
    }
    *ipv4Cnt = 0
    *ipv6Cnt = 0
    intfIPKeys, _ := d.GetKeys(&db.TableSpec{Name:tblName})
    if len(intfIPKeys) > 0 {
        for _, key := range intfIPKeys {
            if len(key.Comp) < 2 {
                continue
            }
            if intfName == key.Get(0) {
                ipB, _, _ := net.ParseCIDR(key.Get(1))
                if validIPv4(ipB.String()) {
                    *ipv4Cnt = *ipv4Cnt + 1
                } else if validIPv6(ipB.String()) {
                    *ipv6Cnt = *ipv6Cnt + 1
                }
            }
        }
    }
    return nil
}

/* RPC for DHCP lease renew */

var rpc_renew_dhcp_lease RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string`json:"status-detail"`
        } `json:"sonic-mgmt-interface:output"`
    }

    result.Output.Status = 1
    /* Unmarshal input data */
    var mapData map[string]interface{}
    err= json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        result.Output.Status_detail = fmt.Sprintf("Error: Internal error!")
        return json.Marshal(&result)
    }
    input, _ := mapData["sonic-mgmt-interface:input"]
    mapData = input.(map[string]interface{})
    portname := mapData["portname"]
    ifName := portname.(string)
    log.Info("rpc_renew_dhcp_lease: intfName: ", ifName)

    intfType, _, ierr := getIntfTypeByName(ifName)
    if ierr != nil || intfType != IntfTypeMgmt {
        log.Errorf("Extracting Interface type for Interface: %s failed or not supported!", ifName)
        result.Output.Status_detail = fmt.Sprintf("Error: Not supported interface: " + ifName)
        return json.Marshal(&result)
    }

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, db.ConfigDB)
    var ipv4Count int
    var ipv6Count int

    intfIPcountGet(tblName, dbs[db.ConfigDB], ifName, &ipv4Count, &ipv6Count)
    if (ipv4Count > 0) && (ipv6Count > 0) {
        log.Info("Static IP's configured for " + ifName)
        result.Output.Status_detail = fmt.Sprintf("Error: Static IP's configured for " + ifName)
        return json.Marshal(&result)
    }
    var options []string
    options = append(options, ifName)

    if ipv4Count == 0 {
        options = append(options, "ipv4")
    }
    if ipv6Count == 0 {
        options = append(options, "ipv6")
    }

    query_result := HostQuery("renew_dhcp_lease.action", options)
    log.Info("rpc_renew_dhcp_lease ", query_result)
    if query_result.Err != nil || query_result.Body[0].(int32) != 0 {
        result.Output.Status_detail = fmt.Sprintf("ERROR: Internal error!")
    } else {
        result.Output.Status = 0
        result.Output.Status_detail = "Success"
    }
    return json.Marshal(&result)
}

