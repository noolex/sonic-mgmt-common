package transformer

import (
	log "github.com/golang/glog"
    "strings"
    "strconv"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "encoding/json"
)

const (
  TFTP uint16 = 69
  DNS uint16 = 53
  NTP uint16 = 37
  NetBIOSNA uint16 = 137
  NetBIOSDS uint16 = 138
  TACACS uint16 = 49
)

func getDefaultPortList () []uint16 {
    list := []uint16{ TFTP, DNS, NTP, NetBIOSNA, NetBIOSDS, TACACS }
    return list
}

func init() {
	XlateFuncBind("YangToDb_ip_helper_global_key_xfmr", YangToDb_ip_helper_global_key_xfmr)
    XlateFuncBind("YangToDb_ip_helper_interface_counter_key_xfmr", YangToDb_ip_helper_interface_counter_key_xfmr)
    XlateFuncBind("YangToDb_ip_helper_enable_xfmr", YangToDb_ip_helper_enable_xfmr)
    XlateFuncBind("DbToYang_ip_helper_enable_xfmr", DbToYang_ip_helper_enable_xfmr)

    XlateFuncBind("YangToDb_ip_helper_ports_xfmr", YangToDb_ip_helper_ports_xfmr)
    XlateFuncBind("DbToYang_ip_helper_ports_xfmr", DbToYang_ip_helper_ports_xfmr)

    XlateFuncBind("rpc_clear_ip_helper", clear_ip_helper)

    XlateFuncBind("ip_helper_post_xfmr", ip_helper_post_xfmr)
}

var clear_ip_helper RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    log.Info("clear_ip_helper called")
    var  valLst [2]string
    var data  []byte
    var mapData map[string]interface{}

    json.Unmarshal(body, &mapData)

    input := mapData["openconfig-ip-helper:input"]
    mapData = input.(map[string]interface{})

    valLst[0]= "ALL"
    valLst[1] = "ALL"

    if value, ok := mapData["INTERFACE"].(string) ; ok {
        valLst[0]= "INTERFACE"
        valLst[1] = value
    }
    data, err = json.Marshal(valLst)

    if err != nil {
        log.Error("Failed to  marshal input data; err=%v", err)
        return nil, err
    }

    err = dbs[db.ApplDB].Publish("IP_HELPER_NOTIFICATIONS",data)
    log.Info("clear ip helper exiting: err ", err)
    return nil, err
}

var YangToDb_ip_helper_global_key_xfmr = func(inParams XfmrParams) (string, error) {
	log.Info("YangToDb_ip_helper_global_key_xfmr: ", inParams.ygRoot, inParams.uri)
	return "Ports", nil
}

var YangToDb_ip_helper_interface_counter_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    log.Info("YangToDb_ip_helper_interface_counter_key_xfmr: ", inParams.ygRoot, inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    log.Info("YangToDb_intf_tbl_key_xfmr: ifName ", ifName)
    return ifName, nil
}

var YangToDb_ip_helper_enable_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    log.Info("YangToDb_ip_helper_enable_xfmr: Entered")
    res_map := make(map[string]string)

    if inParams.oper == DELETE {
        res_map["admin_mode"] = "disable"
        log.Info("YangToDb_ip_helper_enable_xfmr: Exiting ", res_map)
        return res_map, nil
    }

    enabled, _ := inParams.param.(*bool)
    var enStr string
    if *enabled {
        enStr = "enable"
    } else {
        enStr = "disable"
    }
    res_map["admin_mode"] = enStr
    log.Info("YangToDb_ip_helper_enable_xfmr: Exiting ", res_map)

    return res_map, nil
}

var DbToYang_ip_helper_enable_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_ip_helper_enable_xfmr: Entered ")

    data := (*inParams.dbDataMap)[inParams.curDb]

    tblName := "UDP_BROADCAST_FORWARDING"
    if _, ok := data[tblName]; !ok {
        log.Info("DbToYang_ip_helper_enable_xfmr table not found : ", tblName)
        return result, errors.New("table not found : " + tblName)
    }

    pTbl := data[tblName]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_ip_helper_enable_xfmr key not found : ", inParams.key)
        return result, errors.New("key not found : " + inParams.key)
    }
    prtInst := pTbl[inParams.key]
    adminStatus, ok := prtInst.Field["admin_mode"]
    if ok {
        if adminStatus == "enable" {
            result["enable"] = true
        } else {
            result["enable"] = false
        }
    } 

    log.Info("DbToYang_ip_helper_enable_xfmr: Exiting ", result)
    return result, err
}

func getIpHelperRoot (s *ygot.GoStruct) *ocbinds.OpenconfigIpHelper_IpHelper {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.IpHelper
}

var YangToDb_ip_helper_ports_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var new_list []uint16
    var exclude_list []uint16
    log.Info("YangToDb_ip_helper_ports_xfmr: Entered")
    ipHelperRoot := getIpHelperRoot(inParams.ygRoot)

    if ipHelperRoot == nil {
        log.Info("YangToDb_ip_helper_ports_xfmr: ipHelper obj is empty.")
        return res_map, errors.New("iphelper is not specified")
    }

    inPorts := ipHelperRoot.Config.Ports
    log.Info("YangToDb_ip_helper_ports_xfmr: ports in request", inPorts)

    ipHelperDBEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"UDP_BROADCAST_FORWARDING"}, db.Key{Comp: []string{"Ports"}})
    if (ipHelperDBEntry.Has("include_ports@")) {
        dbvalue := strings.Split(ipHelperDBEntry.Field["include_ports@"], ",")
        log.Info("YangToDb_ip_helper_ports_xfmr: include_ports present in db ", dbvalue)
        dbvalueint := make([]uint16, len(dbvalue))
        for i := range dbvalue {
            s, _ := strconv.ParseUint(dbvalue[i], 10, 16)
            dbvalueint[i] = uint16(s)
        }
        switch inParams.oper {
            case CREATE:
                fallthrough
            case REPLACE:
                log.Info("Not supported")
            case UPDATE:
                new_list = append(dbvalueint,inPorts...)
                exclude_list = []uint16{}
                for _, p := range getDefaultPortList() {
                    for _, q := range inPorts {
                        if p == q {
                            exclude_list = append(exclude_list,p)
                            //any default port in the new list need to be removed from exclude list       
                        }
                    }
                }
                log.Info("Ports to be removed from exclude list ", exclude_list)
                if len(exclude_list) > 0 {
                    s2, _ := json.Marshal(exclude_list)
                    excludeString := strings.Trim(string(s2),"[]")
                    var updSubDataMap = make(RedisDbMap)
                    updSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                    updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"] = make(map[string]db.Value)
                    updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"] = db.Value{Field: make(map[string]string)}
                    updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"].Field["exclude_default_ports@"] = excludeString
                    //remove default ports in new list from exclude list
                    inParams.subOpDataMap[DELETE] = &updSubDataMap
                }
            case DELETE:
                new_list = inPorts
                exclude_list = []uint16{}
                for _, p := range getDefaultPortList() {
                    for _, q := range inPorts {
                        if p == q {
                            exclude_list = append(exclude_list,p)
                            //any default port in the delete request need to be added to exclude list
                        }
                    }
                }
                log.Info("Ports to be added to exclude list ", exclude_list)
                s2, _ := json.Marshal(exclude_list)
                excludeString := strings.Trim(string(s2),"[]")
                var updSubDataMap = make(RedisDbMap)
                updSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"] = make(map[string]db.Value)
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"] = db.Value{Field: make(map[string]string)}
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"].Field["exclude_default_ports@"] = excludeString
                //add default ports deleted from include_ports to exclude list
                inParams.subOpDataMap[UPDATE] = &updSubDataMap
        }
    } else {
        log.Info("YangToDb_ip_helper_ports_xfmr: include_ports not present in db ")
        dbvalueint := getDefaultPortList()
        switch inParams.oper {
            case CREATE:
                fallthrough
            case REPLACE:
                log.Info("Not supported")
            case UPDATE:
                new_list = append(dbvalueint,inPorts...)
            case DELETE:
                defaultList := getDefaultPortList()
                new_list = []uint16{}
                exclude_list = []uint16{}
                for _, p := range defaultList {
                    found := false
                    for _, q := range inPorts {
                        if p == q {
                            found = true
                            exclude_list = append(exclude_list,p)
                            //add default ports deleted from include_ports to exclude list
                        }
                    }
                    if !found {
                        new_list = append(new_list,p)
                    }
                    found = false
                }
                log.Info("Ports to be added to exclude list ", exclude_list)
                s, _ := json.Marshal(new_list)
                defaultString := strings.Trim(string(s),"[]")
                s2, _ := json.Marshal(exclude_list)
                excludeString := strings.Trim(string(s2),"[]")

                var updSubDataMap = make(RedisDbMap)
                updSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"] = make(map[string]db.Value)
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"] = db.Value{Field: make(map[string]string)}
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"].Field["include_ports@"] = defaultString
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"].Field["exclude_default_ports@"] = excludeString
                //add default ports deleted from include_ports to exclude list
                inParams.subOpDataMap[UPDATE] = &updSubDataMap
        }
    }

    var newString string
    s, _ := json.Marshal(new_list)
    newString = strings.Trim(string(s),"[]")
    res_map["include_ports@"] = newString
    log.Info("YangToDb_ip_helper_ports_xfmr: Exiting ", res_map)
    return res_map, nil
}

var DbToYang_ip_helper_ports_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_ip_helper_enable_xfmr: Entered")
    data := (*inParams.dbDataMap)[inParams.curDb]

    tblName := "UDP_BROADCAST_FORWARDING"
    if _, ok := data[tblName]; !ok {
        log.Info("DbToYang_ip_helper_enable_xfmr table not found : ", tblName)
        return result, errors.New("table not found : " + tblName)
    }

    pTbl := data[tblName]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_ip_helper_enable_xfmr key not found : ", inParams.key)
        return result, errors.New("key not found : " + inParams.key)
    }
    prtInst := pTbl[inParams.key]
    dbports, ok := prtInst.Field["include_ports@"]
    if ok {
        dbvalue := strings.Split(dbports, ",")
        dbvalueint := make([]uint16, len(dbvalue))
        for i := range dbvalue {
            s, _ := strconv.ParseUint(dbvalue[i], 10, 16)
            dbvalueint[i] = uint16(s)
        }
        result["ports"] = dbvalueint
    } else {
        result["ports"] = getDefaultPortList()
    }

    log.Info("DbToYang_ip_helper_enable_xfmr: Exiting ", result)
    return result, err
}

var ip_helper_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    retDbDataMap := (*inParams.dbDataMap)[inParams.curDb]
    DEFAULT_UDP_PORTS := getDefaultPortList()
    log.Info("ip_helper_post_xfmr called. oper ", inParams.oper)

    ipHelperDBEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"UDP_BROADCAST_FORWARDING"}, db.Key{Comp: []string{"Ports"}})
    if (ipHelperDBEntry.Has("include_ports@")) {
        log.Info("ip_helper_post_xfmr include_ports present in db, do nothing")
        return retDbDataMap, err
    } else {
        log.Info("ip_helper_post_xfmr include_ports not present in db")
        var defaultPortString string
        s, _ := json.Marshal(DEFAULT_UDP_PORTS)
        defaultPortString = strings.Trim(string(s),"[]")
        tbl := retDbDataMap["UDP_BROADCAST_FORWARDING"]
        entry := tbl["Ports"]
        if _, ok := entry.Field["include_ports@"] ; ok {
            log.Info("request has include ports, do nothing")
        } else {
            log.Info("request does not have ports, add default ports")
            entry.Field["include_ports@"] = defaultPortString
        }
    }

    return retDbDataMap, err
}
