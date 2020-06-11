package transformer

import (
    "errors"
    "strings"
    log "github.com/golang/glog"
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
)


func init () {
    XlateFuncBind("YangToDb_route_table_conn_key_xfmr", YangToDb_route_table_conn_key_xfmr)
    XlateFuncBind("DbToYang_route_table_conn_key_xfmr", DbToYang_route_table_conn_key_xfmr)
    XlateFuncBind("YangToDb_route_table_addr_family_xfmr", YangToDb_route_table_addr_family_xfmr)
    XlateFuncBind("DbToYang_route_table_addr_family_xfmr", DbToYang_route_table_addr_family_xfmr)
    XlateFuncBind("rpc_show_ip_route", rpc_show_ip_route)
}

var YangToDb_route_table_addr_family_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_route_table_addr_family_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    entry_key := inParams.key
    key := strings.Split(entry_key, "|")
    family := key[3]
    af := ""

    if family == "ipv4" {
        af = "IPV4"
    } else if family == "ipv6" {
        af = "IPV6"
    } else {
        return result, errors.New("Unsupported family " + family)
    }

    result["address-family"] = af

    return result, err
}

var YangToDb_route_table_conn_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    log.Info("YangToDb_route_table_conn_key_xfmr***", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    niName     :=  pathInfo.Var("name")
    srcProto   := pathInfo.Var("src-protocol")
    dstProto   := pathInfo.Var("dst-protocol")
    afName     := pathInfo.Var("address-family")

    if len(pathInfo.Vars) < 3 {
        return "", nil
    }

    if len(niName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return niName, err
    }

    var family string
    var source string
    var destination string

    if strings.Contains(afName, "IPV4") {
        family = "ipv4"
    } else if strings.Contains(afName, "IPV6") {
        family = "ipv6"
    } else {
        log.Info("Unsupported address-family " + afName)
        return family, errors.New("Unsupported address-family " + afName)
    }

    if strings.Contains(srcProto, "DIRECTLY_CONNECTED") {
        source = "connected"
    } else if strings.Contains(srcProto, "OSPF3") {
        source = "ospf3"
    } else if strings.Contains(srcProto, "OSPF") {
        source = "ospf"
    } else if strings.Contains(srcProto, "STATIC") {
        source = "static"
    } else {
        log.Info("Unsupported protocol " + srcProto)
        return family, errors.New("Unsupported protocol " + srcProto)
    }

    if strings.Contains(dstProto, "BGP") {
        destination = "bgp"
    } else {
        log.Info("Unsupported protocol " + dstProto)
        return family, errors.New("Unsupported protocol " + dstProto)
    }

    key := niName + "|" + source + "|" + destination + "|" + family 

    log.Info("TableConnection key: ", key)

    return key, nil
}

var DbToYang_route_table_conn_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_route_table_conn_key_xfmr: ", entry_key)

    key := strings.Split(entry_key, "|")
    source := key[1]
    destination := key[2]
    family := key[3]
 
    var src_proto string
    var dst_proto string
    var af string

    if source == "connected" {
        src_proto = "DIRECTLY_CONNECTED"
    } else if source == "static" {
        src_proto = "STATIC"
    } else if source == "ospf" {
        src_proto = "OSPF"
    } else if source == "ospf3" {
        src_proto = "OSPF3"
    } else {
        return rmap, errors.New("Unsupported src protocol " + source)
    }

    if destination == "bgp" {
        dst_proto = "BGP"
    } else {
        return rmap, errors.New("Unsupported dst protocol " + destination)
    }

    if family == "ipv4" {
        af = "IPV4"
    } else if family == "ipv6" {
        af = "IPV6"
    } else {
        return rmap, errors.New("Unsupported family " + family)
    }
    rmap["src-protocol"] = src_proto
    rmap["dst-protocol"] = dst_proto
    rmap["address-family"] = af 

    return rmap, nil
}

var rpc_show_ip_route RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_show_ip_route")
    var cmd string
    var af_str, vrf_name, options string
    var err error
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil,  errors.New("RPC show ip route, invalid input")
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-ip-show:output"`
    }

    log.Info("In rpc_show_route, RPC data:", mapData)

    input := mapData["sonic-ip-show:input"]
    mapData = input.(map[string]interface{})

    log.Info("In rpc_show_route, RPC Input data:", mapData)

    if value, ok := mapData["vrf-name"].(string) ; ok {
        if value != "" {
            vrf_name = "vrf " + value + " "
        }
    }

    af_str = "ip "
    if value, ok := mapData["family"].(string) ; ok {
        if value == "IPv4" {
            af_str = "ip "
        } else if value == "IPv6" {
            af_str = "ipv6 "
        }
    }
    if value, ok := mapData["prefix"].(string) ; ok {
        if value != "" {
            options = value + " "
        }
    } else if value, ok := mapData["summary"].(bool) ; ok {
        if value {
            options = "summary "
        }
    } else if value, ok := mapData["static"].(bool) ; ok {
        if value {
            options = "static "
        }
    } else if value, ok := mapData["connected"].(bool) ; ok {
        if value {
            options = "connected "
        }
    } else if value, ok := mapData["bgp"].(bool) ; ok {
        if value {
            options = "bgp "
        }
    } else if value, ok := mapData["ospf"].(bool) ; ok {
        if value {
            options = "ospf "
        }
    }

    cmd = "show "
    if af_str != "" {
       cmd = cmd + af_str
    }

    cmd = cmd + "route "

    if vrf_name != "" {
        cmd = cmd + vrf_name
    }

    if options != "" {
        cmd = cmd + options
    }

    cmd = cmd + "json"

    bgpOutput, err := exec_raw_vtysh_cmd(cmd)
    if err != nil {
        log.Info("Failed to execute FRR command")
        return nil,  errors.New("Internal error!")
    }

    result.Output.Status = bgpOutput

    if options == "summary " {
         /* just rib and fib counts, no interface names */
         return json.Marshal(&result)
    }

    var routeDict map[string]interface{}
    if err := json.Unmarshal([]byte(bgpOutput), &routeDict); err != nil {
        log.Infof("Error found in unmarshalling json output from vtysh - #show ip route json!")
        return json.Marshal(&result)
    }
    for ipAddr, _ := range routeDict {
        routeMapJson := routeDict[ipAddr]
        routeMapSlice := routeMapJson.([]interface{})
        for _, routeEntry := range routeMapSlice {
            routeMap := routeEntry.(map[string]interface{})
            nextHopInterface, ok := routeMap["nexthops"]
            if !ok {
                log.Errorf("nextHops not present in routeDictionary for IP: %s", ipAddr)
                continue
            }
            nextHopSlice := nextHopInterface.([]interface{})
            for _, nextHopEntry := range nextHopSlice {
                nextHopMap := nextHopEntry.(map[string]interface{})
                ifNameVal, ok := nextHopMap["interfaceName"]
                if !ok {
                    log.Errorf("interfaceName entry not present in nextHops for IP: %s", ipAddr)
                    continue
                }
                ifName := ifNameVal.(string)
                sonicName := utils.GetUINameFromNativeName(&ifName)
                nextHopMap["interfaceName"] = *sonicName
            }
        }
    }
    modifiedBgpOp, err := json.Marshal(&routeDict)
    if err != nil {
      log.Error("Marshalling modified BGP output failed!")
      return json.Marshal(&result)
    }
    result.Output.Status = string(modifiedBgpOp)
    return json.Marshal(&result)
}
