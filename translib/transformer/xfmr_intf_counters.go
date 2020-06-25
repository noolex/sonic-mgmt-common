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
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    log "github.com/golang/glog"
    "encoding/json"
)

func init () {
    XlateFuncBind("rpc_get_interface_counters", rpc_get_interface_counters)
    XlateFuncBind("rpc_clear_relay_counters", rpc_clear_relay_counters)
}



// InterfaceObj is the output record for get interface counters RPC
type InterfaceObj struct {
    Name string `json:"name"`
    State struct {
        Oper_Status string `json:"oper-status"`
        Counters struct {
            In_Octets              uint64 `json:"in-octets"`
            In_Pkts                uint64 `json:"in-pkts"`
            In_Discards            uint64 `json:"in-discards"`
            In_Errors              uint64 `json:"in-errors"`
            In_Oversize_Frames     uint64 `json:"in-oversize-frames"`
            Out_Octets             uint64 `json:"out-octets"`
            Out_Pkts               uint64 `json:"out-pkts"`
            Out_Discards           uint64 `json:"out-discards"`
            Out_Errors             uint64 `json:"out-errors"`
            Out_Oversize_Frames    uint64 `json:"out-oversize-frames"`
        } `json:"counters"`
    } `json:"state"`
}

var rpcCountersMap = map[string][]string {
    "in-octets"           : {"SAI_PORT_STAT_IF_IN_OCTETS"},
    "in-pkts"             : {"SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS", "SAI_PORT_STAT_IF_IN_UCAST_PKTS"},
    "in-discards"         : {"SAI_PORT_STAT_IF_IN_DISCARDS"},
    "in-errors"           : {"SAI_PORT_STAT_IF_IN_ERRORS"},
    "in-oversize-frames"  : {"SAI_PORT_STAT_ETHER_RX_OVERSIZE_PKTS"},
    "out-octets"          : {"SAI_PORT_STAT_IF_OUT_OCTETS"},
    "out-pkts"            : {"SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS", "SAI_PORT_STAT_IF_OUT_UCAST_PKTS"},
    "out-discards"        : {"SAI_PORT_STAT_IF_OUT_DISCARDS"},
    "out-errors"          : {"SAI_PORT_STAT_IF_OUT_ERRORS"},
    "out-oversize-frames" : {"SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS"},
}

func checkPrefixMatch(pList []string, str string) bool {
    for _, prefix := range pList {
        if strings.HasPrefix(str, prefix) {
            return true
        }
    }
    return false
}

var rpc_get_interface_counters = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string `json:"status-detail"`
            Interfaces struct {
                Interface map[string]InterfaceObj `json:"interface"`
            } `json:"interfaces"`
        } `json:"sonic-counters:output"`
    }

    result.Output.Status = 1
    result.Output.Interfaces.Interface = make(map[string]InterfaceObj)

    pList := []string {"Ethernet", "PortChannel"}

    portOidmapTs := &db.TableSpec{Name: "COUNTERS_PORT_NAME_MAP"}
    ifCountInfo, err := dbs[db.CountersDB].GetMapAll(portOidmapTs)
    if err != nil {
        result.Output.Status_detail = "Server error, data not found!"
        return json.Marshal(&result)
    }
    cntTs := &db.TableSpec{Name: "COUNTERS"}
    cntTs_cp := &db.TableSpec { Name: "COUNTERS_BACKUP" }

    for  ifName, oid := range ifCountInfo.Field {
        if checkPrefixMatch(pList, ifName) {
            var intfObj InterfaceObj
            entry, dbErr := dbs[db.CountersDB].GetEntry(cntTs, db.Key{Comp: []string{oid}})
            if dbErr != nil {
                log.Info("rpc_get_interface_counters : not able find the oid entry in DB Counters table")
                continue
            }
            entry_backup, dbErr := dbs[db.CountersDB].GetEntry(cntTs_cp, db.Key{Comp: []string{oid}})
            if dbErr != nil {
                m := make(map[string]string)
                for  attr := range entry.Field {
                    m[attr] = "0"
                }
                m["LAST_CLEAR_TIMESTAMP"] = "0"
                entry_backup = db.Value{Field: m}
            }
            intfType,_,_ := getIntfTypeByName(ifName)
            intTbl := IntfTypeTblMap[intfType]
            prtEntry, prtErr := dbs[db.ApplDB].GetEntry(&db.TableSpec{Name:intTbl.appDb.portTN}, db.Key{Comp: []string{ifName}})
            if prtErr != nil {
                log.Info("rpc_get_interface_counters : PORT entry not found in AppDb " + ifName)
                continue
            }
            uiName := *utils.GetUINameFromNativeName(&ifName)
            intfObj.Name = uiName
            intfObj.State.Oper_Status = "DOWN"
            operStatus, ok := prtEntry.Field[PORT_OPER_STATUS]
            if ok {
                if operStatus == "up" {
                    intfObj.State.Oper_Status = "UP"
                }
            }

            var e error
            for attr, dbAttrList := range rpcCountersMap  {
                cnt_val  := uint64(0)
                for _, dbAttr := range dbAttrList {
                    var val *uint64
                    e = getCounters(&entry, &entry_backup, dbAttr, &val)
                    if e != nil {
                        log.Info("RPC getCounters failed, ", e)
                        continue
                    }
                    cnt_val = cnt_val + *val
                }
                switch attr {
                case "in-octets":
                    intfObj.State.Counters.In_Octets = cnt_val
                case "in-pkts":
                    intfObj.State.Counters.In_Pkts = cnt_val
                case "in-discards":
                    intfObj.State.Counters.In_Discards = cnt_val
                case "in-errors":
                    intfObj.State.Counters.In_Errors = cnt_val
                case "in-oversize-frames":
                    intfObj.State.Counters.In_Oversize_Frames = cnt_val
                case "out-octets":
                    intfObj.State.Counters.Out_Octets = cnt_val
                case "out-pkts":
                    intfObj.State.Counters.Out_Pkts = cnt_val
                case "out-discards":
                    intfObj.State.Counters.Out_Discards = cnt_val
                case "out-errors":
                    intfObj.State.Counters.Out_Errors = cnt_val
                case "out-oversize-frames":
                    intfObj.State.Counters.Out_Oversize_Frames = cnt_val
                }
            }
            result.Output.Interfaces.Interface[uiName] = intfObj
        }
    }

    result.Output.Status = 0
    result.Output.Status_detail = "Success!"
    return json.Marshal(&result)
}

var rpc_clear_relay_counters RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    log.Infof("Inside rpc_clear_relay_counters: Input: %s\n", string(body))

    var input map[string]interface{}
    err = json.Unmarshal(body, &input)
    if err != nil {
        log.Infof("UnMarshall Error %v\n", err)
        return nil, err
    }

    var  valLst [2]string
    var  data  []byte
    var  ipv4type string
    var  ipv6type string

    i := input["sonic-counters:input"].(map[string]interface{})

    ipv4type = i["ipv4-relay-param"].(string)
    ipv6type = i["ipv6-relay-param"].(string)

    if ipv4type != "NULL" && ipv6type == "NULL" {
        valLst[0] = "V4-INTERFACE"
        valLst[1] = i["ipv4-relay-param"].(string)

    } else if ipv4type == "NULL" && ipv6type != "NULL" {
        valLst[0] = "V6-INTERFACE"
        valLst[1] = i["ipv6-relay-param"].(string)

    } else {
        log.Infof("Error - Unknown family type\n")
        return nil, err
    }

    data, err = json.Marshal(valLst)

    if err != nil {
        log.Error("Failed to  marshal input data; err=%v", err)
        return nil, err
    }

    log.Infof("DHCP RELAY DATA Published: %v\n", string(data))
    err = dbs[db.ApplDB].Publish("DHCP_RELAY_NOTIFICATIONS",data)

    return nil, err
}

