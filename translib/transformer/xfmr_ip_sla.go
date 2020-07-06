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
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "strconv"
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "fmt"
)

func init() {
    XlateFuncBind("YangToDb_ip_sla_id_fld_xfmr", YangToDb_ip_sla_id_fld_xfmr)
    XlateFuncBind("DbToYang_ip_sla_id_fld_xfmr", DbToYang_ip_sla_id_fld_xfmr)
    XlateFuncBind("DbToYang_ip_sla_state_xfmr", DbToYang_ip_sla_state_xfmr)
    XlateFuncBind("rpc_show_ipsla_history", rpc_show_ipsla_history)
    XlateFuncBind("rpc_clear_ipsla_counters", rpc_clear_ipsla_counters)
}

type IpslaHistoryEntry struct {
    timestamp   string
    event       string    `json:",omitempty"`
}

// showOutput.Output.History = make([]IpslaHistory, 0)

var YangToDb_ip_sla_id_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_ip_sla_id_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_ip_sla_id_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_ip_sla_id_fld_xfmr: ", inParams.key)
    result["ip-sla-id"], _ = strconv.ParseUint(inParams.key, 10, 32)

    return result, err
}

var DbToYang_ip_sla_state_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("DbToYang_ip_sla_state_xfmr - pathInfo: ", pathInfo)
    log.Info("DbToYang_ip_sla_state_xfmr - targetUriPath: ", targetUriPath)
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    var ipSlasObj *ocbinds.OpenconfigIpSla_IpSlas
    var ipSlaObj *ocbinds.OpenconfigIpSla_IpSlas_IpSla
    ipSlasObj = deviceObj.IpSlas
    ygot.BuildEmptyTree(ipSlasObj)
    ipSlaIdRecvd := pathInfo.Var("ip-sla-id")
    log.Info("DbToYang_ip_sla_state_xfmr  ipSlaIdRecvd: ", ipSlaIdRecvd)

    log.Info("XfmrParams:", inParams)

    if len(ipSlaIdRecvd) <= 0 {
        return err
    }

    _ipSlaIdKey, _ := strconv.Atoi(ipSlaIdRecvd)
    ipSlaIdKey := uint16(_ipSlaIdKey)

    if ipSlasObj != nil && ipSlasObj.IpSla != nil && len(ipSlasObj.IpSla) > 0 {
        var ok bool = false
        if ipSlaObj, ok = ipSlasObj.IpSla[ipSlaIdKey]; !ok {
            ipSlaObj, _ = ipSlasObj.NewIpSla(ipSlaIdKey)
        }
        ygot.BuildEmptyTree(ipSlaObj)
        ygot.BuildEmptyTree(ipSlaObj.State)
    } else {
        ygot.BuildEmptyTree(ipSlasObj)
        ipSlaObj, _ = ipSlasObj.NewIpSla(ipSlaIdKey)
        ygot.BuildEmptyTree(ipSlaObj)
        ygot.BuildEmptyTree(ipSlaObj.State)
    }

    log.Info("DbToYang_ip_sla_state_xfmr  Valid key received ipSlaIdRecvd: ", ipSlaIdRecvd)

    IpSlaFillStaticState(inParams, ipSlaIdRecvd, ipSlaObj.State)
    IpSlaFillDynamicState(inParams, ipSlaIdRecvd, ipSlaObj.State)

    return err
}


func IpSlaFillStaticState(inParams XfmrParams, ipSlaIdKey string, output *ocbinds.OpenconfigIpSla_IpSlas_IpSla_State) {

    cfgDbEntry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:"IP_SLA"}, db.Key{Comp: []string{ipSlaIdKey}})
    log.Info("DbToYang_ip_sla_state_xfmr - entry: ", cfgDbEntry)
    log.Info("DbToYang_ip_sla_state_xfmr - ipSlaIdKey : ", ipSlaIdKey)

    if dbErr != nil || len(cfgDbEntry.Field) == 0 {
        log.Error("DbToYang_ip_sla_state_xfmr: Config-DB get entry failed KeyStr:", ipSlaIdKey)
        return
    }

    if cfgDbEntry.Has("frequency") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("frequency"))
        value := uint16(_value)
        output.Frequency = &value
    }

    if cfgDbEntry.Has("timeout") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("timeout"))
        value := uint16(_value)
        output.Timeout = &value
    }

    if cfgDbEntry.Has("threshold") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("threshold"))
        value := uint16(_value)
        output.Threshold = &value
    }

    if cfgDbEntry.Has("icmp_dst_ip") {
        value := cfgDbEntry.Get("icmp_dst_ip")
        output.IcmpDstIp = &value
    }

    if cfgDbEntry.Has("icmp_size") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("icmp_size"))
        value := uint16(_value)
        output.IcmpSize = &value
    }

    if cfgDbEntry.Has("icmp_tos") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("icmp_tos"))
        value := uint16(_value)
        output.IcmpTos = &value
    }

    if cfgDbEntry.Has("icmp_ttl") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("icmp_ttl"))
        value := uint16(_value)
        output.IcmpTtl = &value
    }

    if cfgDbEntry.Has("icmp_source_ip") {
        value := cfgDbEntry.Get("icmp_source_ip")
        output.IcmpSourceIp = &value
    }

    if cfgDbEntry.Has("icmp_source_interface") {
        _value := cfgDbEntry.Get("icmp_source_interface")
        value := utils.GetUINameFromNativeName(&_value)
        output.IcmpSourceInterface = value
    }

    if cfgDbEntry.Has("icmp_vrf") {
        value := cfgDbEntry.Get("icmp_vrf")
        output.IcmpVrf = &value
    }

    if cfgDbEntry.Has("tcp_source_ip") {
        value := cfgDbEntry.Get("tcp_source_ip")
        output.TcpSourceIp = &value
    }

    if cfgDbEntry.Has("tcp_dst_ip") {
        value := cfgDbEntry.Get("tcp_dst_ip")
        output.TcpDstIp = &value
    }

    if cfgDbEntry.Has("tcp_source_interface") {
        _value := cfgDbEntry.Get("tcp_source_interface")
        value := utils.GetUINameFromNativeName(&_value)
        output.TcpSourceInterface = value
    }

    if cfgDbEntry.Has("tcp_source_port") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("tcp_source_port"))
        value := uint16(_value)
        output.TcpSourcePort = &value
    }

    if cfgDbEntry.Has("tcp_dst_port") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("tcp_dst_port"))
        value := uint16(_value)
        output.TcpDstPort = &value
    }

    if cfgDbEntry.Has("tcp-vrf") {
        value := cfgDbEntry.Get("tcp-vrf")
        output.TcpVrf = &value
    }

    if cfgDbEntry.Has("tcp_tos") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("tcp_tos"))
        value := uint16(_value)
        output.TcpTos = &value
    }

    if cfgDbEntry.Has("tcp_ttl") {
        _value, _ := strconv.Atoi(cfgDbEntry.Get("tcp_ttl"))
        value := uint16(_value)
        output.TcpTtl = &value
    }

}


func IpSlaFillDynamicState(inParams XfmrParams, ipSlaIdKey string, State *ocbinds.OpenconfigIpSla_IpSlas_IpSla_State) {

    vtysh_cmd := "show ip sla " + ipSlaIdKey + " detail json"
    ipSlaJson, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to fetch IP SLA data for key:%s. Err: %s", ipSlaIdKey, cmd_err)
        return
    }

    log.Info("Dynamic state:", ipSlaJson)

    ipSlaDataJson := ipSlaJson

    log.Info(ipSlaDataJson)

    if value, ok := ipSlaDataJson["state"].(string) ; ok {

        if value == "Up" {
            ret := "OPER_UP"
            if ipSlaDataJson["type"] == "TCP-connect" {
                State.TcpOperationState = &ret
            } else {
                State.IcmpOperationState = &ret
            }
        } else {
            ret := "OPER_DOWN"
            if ipSlaDataJson["type"] == "TCP-connect" {
                State.TcpOperationState = &ret
            } else {
                State.IcmpOperationState = &ret
            }
        }

        if value, ok := ipSlaDataJson["state_transitions"] ; ok {
            _value := uint16(value.(float64))
            State.TransitionCount = &_value
        }

        if value, ok := ipSlaDataJson["last_state_change"].(string) ; ok {
            State.Timestamp = &value
        }

        if value, ok := ipSlaDataJson["icmp_echo_request_counter"] ; ok {
            _value := uint16(value.(float64))
            State.IcmpEchoReqCounter = &_value
        }

        if value, ok := ipSlaDataJson["icmp_echo_reply_counter"] ; ok {
            _value := uint16(value.(float64))
            State.IcmpEchoReplyCounter = &_value
        }

        if value, ok := ipSlaDataJson["icmp_echo_error_counter"] ; ok {
            _value := uint16(value.(float64))
            State.IcmpErrorCounter = &_value
        }

        if value, ok := ipSlaDataJson["icmp_echo_invalid_resp_counter"] ; ok {
            _value := uint16(value.(float64))
            State.IcmpFailCounter = &_value
        }

        if value, ok := ipSlaDataJson["tcp_connect_request_counter"] ; ok {
            _value := uint16(value.(float64))
            State.TcpConnectReqCounter = &_value
        }

        if value, ok := ipSlaDataJson["tcp_connect_success_counter"] ; ok {
            _value := uint16(value.(float64))
            State.TcpConnectSuccessCounter = &_value
        }

        if value, ok := ipSlaDataJson["tcp_connect_error_counter"] ; ok {
            _value := uint16(value.(float64))
            State.TcpConnectFailCounter = &_value
        }
    }

}

func ipsla_show_history (body []byte, dbs [db.MaxDB]*db.DB, tableName string) (result []byte, err error) {

    log.Infof("Enter ipsla_show_history")

    var showOutput struct {
        Output struct {
        Status        string `json:"status"`
        Status_detail string `json:"status-detail"`
        History [] IpslaHistoryEntry
        } `json:"sonic-ip-sla:output"`
    }

    /* Get input data */
    var inputParams map[string]interface{}
    err = json.Unmarshal(body, &inputParams)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        showOutput.Output.Status = "INVALID_PAYLOAD"
        showOutput.Output.Status_detail = "Failed to unmarshall given input data"
        json, _ := json.Marshal(&result)
        return json, tlerr.InvalidArgs("INVALID_PAYLOAD")
    }

    if input, err := inputParams["sonic-ip-sla:input"]; err {
        inputParams = input.(map[string]interface{})
    } else {
        showOutput.Output.Status = "INVALID_PAYLOAD"
        showOutput.Output.Status_detail = "No input"
        json, _ := json.Marshal(&result)
        return json, tlerr.InvalidArgs("INVALID_PAYLOAD")
    }

    log.Info("Input=", inputParams)

    ipSlaIdKey, found := inputParams["ip_sla_id"]
    if !found {
        showOutput.Output.Status = "INVALID_PAYLOAD"
        showOutput.Output.Status_detail = "IPSLA SLA-ID missing"
        json, _ := json.Marshal(&result)
        return json, tlerr.InvalidArgs("INVALID_PAYLOAD")
    }

    showOutput.Output.History = make([]IpslaHistoryEntry, 0)

    ipSlaIdStr := fmt.Sprintf("%v", ipSlaIdKey)
    vtysh_cmd := "show ip sla " + ipSlaIdStr + " history json"
    ipSlaJson, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to fetch IP SLA data for key:%s. Err: %s", ipSlaIdKey, cmd_err)
        return
    }

    for key, value := range ipSlaJson {
        ipSlaDataJson := value.(map[string]interface{})
        log.Info(key)
        log.Info(ipSlaDataJson)

        var ipslahistoryentry IpslaHistoryEntry

        if value, ok := ipSlaDataJson["timestamp"].(string) ; ok {
            ipslahistoryentry.timestamp = value
        }

        if value, ok := ipSlaDataJson["event"].(string) ; ok {
            ipslahistoryentry.event = value
        }

        showOutput.Output.History = append(showOutput.Output.History, ipslahistoryentry)
    }

    log.Infof("ip sla history:", showOutput.Output.History)

    result, err = json.Marshal(&showOutput)
    return result, err

}

var rpc_show_ipsla_history RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {

    log.Infof("Enter rpc_show_ipsla_history")

    result, err = ipsla_show_history(body, dbs, "IP_SLA")
    return result, err

}


var rpc_clear_ipsla_counters RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string `json:"status-detail"`
        } `json:"sonic-ipsla-clear:output"`
    }

    log.Infof("Enter rpc_clear_ipsla_counters")


    /* Get input data */
    var inputParams map[string]interface{}
    err = json.Unmarshal(body, &inputParams)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        result.Output.Status = 1
        result.Output.Status_detail = "Failed to unmarshall given input data"
        return json.Marshal(&result)
    }

    if input, err := inputParams["sonic-ip-sla:input"]; err {
        inputParams = input.(map[string]interface{})
    } else {
        result.Output.Status = 1
        result.Output.Status_detail = "No input"
        return json.Marshal(&result)
    }

    log.Info("Input=", inputParams)

    ipSlaIdKey, found := inputParams["ip_sla_id"]
    if !found {
        result.Output.Status = 1
        result.Output.Status_detail = "IPSLA SLA-ID missing"
        return json.Marshal(&result)
    }

    ipSlaIdStr := fmt.Sprintf("%v", ipSlaIdKey)
    vtysh_cmd := "clear ip sla " + ipSlaIdStr
    _, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to clear IP SLA data for key:", ipSlaIdStr, " err: %s", cmd_err)
        result.Output.Status = 1
        result.Output.Status_detail = fmt.Sprintf("Error: %s.", cmd_err)
    } else {
        result.Output.Status = 0
        result.Output.Status_detail = "Success: Cleared Counters"
    }

    return json.Marshal(&result)
}
