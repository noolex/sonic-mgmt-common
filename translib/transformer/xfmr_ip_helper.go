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

    XlateFuncBind("DbToYang_ip_helper_default_ports_xfmr", DbToYang_ip_helper_default_ports_xfmr)

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
    log.Info("YangToDb_intf_tbl_key_xfmr: pathInfo ", pathInfo)
    ifName := pathInfo.Var("name")
    log.Info("YangToDb_intf_tbl_key_xfmr: ifName ", ifName)
    return ifName, nil
}

var YangToDb_ip_helper_enable_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    if inParams.oper == DELETE {
        res_map["admin_mode"] = "disable"
        /*var delSubDataMap = make(RedisDbMap)
        delSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        //dbDataMap[DELETE][db.ConfigDB][depEntkeyList[0]][depEntkeyList[1]].Field[depEntAttr] = ""
        delSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"].Field["admin_mode"] = ""
        inParams.subOpDataMap[DELETE] = &delSubDataMap*/
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

    return res_map, nil
}

var DbToYang_ip_helper_enable_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

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

    ipHelperRoot := getIpHelperRoot(inParams.ygRoot)

    if ipHelperRoot == nil {
        log.Info("YangToDb_ip_helper_ports_xfmr: ipHelper obj is empty.")
        return res_map, errors.New("iphelper is not specified")
    }

    inPorts := ipHelperRoot.Config.Ports

    log.Info("ygot ports", inPorts)

    ipHelperDBEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"UDP_BROADCAST_FORWARDING"}, db.Key{Comp: []string{"Ports"}})
    if (ipHelperDBEntry.Has("include_ports@")) {
        log.Info("include_ports present in db")
        dbvalue := strings.Split(ipHelperDBEntry.Field["include_ports@"], ",")
        log.Info(dbvalue)
        dbvalueint := make([]uint16, len(dbvalue))
        for i := range dbvalue {
            s, _ := strconv.ParseUint(dbvalue[i], 10, 16)
            log.Info(s)
            dbvalueint[i] = uint16(s)
        }
        log.Info(dbvalueint)
        switch inParams.oper {
            case CREATE:
                fallthrough
            case REPLACE:
                log.Info("Not supported")
            case UPDATE:
                log.Info("Update")
                log.Info(inPorts)
                new_list = append(dbvalueint,inPorts...)
                exclude_list = []uint16{}
                for _, p := range getDefaultPortList() {
                    //found := false
                    for _, q := range inPorts {
                        if p == q {
                            //found = true 
                            exclude_list = append(exclude_list,p)       
                        }
                    }
                    /*if !found {
                        exclude_list = append(exclude_list,p)
                    }
                    found = false*/
                }
                log.Info(exclude_list)
                if len(exclude_list) > 0 {

                    s2, _ := json.Marshal(exclude_list)
                    excludeString := strings.Trim(string(s2),"[]")

                    log.Info(excludeString)

                    var updSubDataMap = make(RedisDbMap)
                    updSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                    updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"] = make(map[string]db.Value)
                    updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"] = db.Value{Field: make(map[string]string)}
                    updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"].Field["exclude_default_ports@"] = excludeString
                    inParams.subOpDataMap[DELETE] = &updSubDataMap
                }
            case DELETE:
                log.Info("Delete")
                new_list = inPorts
                exclude_list = []uint16{}
                for _, p := range getDefaultPortList() {
                    //found := false
                    for _, q := range inPorts {
                        if p == q {
                            //found = true
                            exclude_list = append(exclude_list,p)
                        }
                    }
                    /*if !found {
                        new_list = append(new_list,p)
                    }*/
                    //found = false
                }
                log.Info(exclude_list)

                s2, _ := json.Marshal(exclude_list)
                excludeString := strings.Trim(string(s2),"[]")

                log.Info(excludeString)

                var updSubDataMap = make(RedisDbMap)
                updSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"] = make(map[string]db.Value)
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"] = db.Value{Field: make(map[string]string)}
                updSubDataMap[db.ConfigDB]["UDP_BROADCAST_FORWARDING"]["Ports"].Field["exclude_default_ports@"] = excludeString
                inParams.subOpDataMap[UPDATE] = &updSubDataMap
        }
        log.Info(new_list)
    } else {
        log.Info("include_ports not present in db")
        dbvalueint := getDefaultPortList()
        log.Info(dbvalueint)
        switch inParams.oper {
            case CREATE:
                fallthrough
            case REPLACE:
                log.Info("Not supported")
            case UPDATE:
                log.Info("Update")
                log.Info(inPorts)
                new_list = append(dbvalueint,inPorts...)
                log.Info(new_list)
            case DELETE:
                log.Info("Delete")
                defaultList := getDefaultPortList()
                new_list = []uint16{}
                exclude_list = []uint16{}
                for _, p := range defaultList {
                    found := false
                    for _, q := range inPorts {
                        if p == q {
                            found = true
                            exclude_list = append(exclude_list,p)
                        }
                    }
                    if !found {
                        new_list = append(new_list,p)
                    }
                    found = false
                }
                log.Info(new_list)
                log.Info(exclude_list)
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
                inParams.subOpDataMap[UPDATE] = &updSubDataMap
        }
    }

    log.Info(new_list)

    var newString string
    s, _ := json.Marshal(new_list)
    newString = strings.Trim(string(s),"[]")
    res_map["include_ports@"] = newString

    /*var excludeString string
    s2, _ := json.Marshal(exclude_list)
    excludeString = strings.Trim(string(s2),"[]")
    res_map["exclude_ports@"] = excludeString*/

    return res_map, nil
}

var DbToYang_ip_helper_ports_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

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
        log.Info("DB ports exist")
        log.Info(dbports)
    } 
    result["ports"] = getDefaultPortList()

    return result, err
}

var DbToYang_ip_helper_default_ports_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    //list := make([]interface{}, 2)
    //list[0] = 23
    //list[1] = 24

    result["default-enabled-ports"] = getDefaultPortList()

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
        dbvalue := ipHelperDBEntry.Field["include_ports@"]
        log.Info(dbvalue)
        return retDbDataMap, err
    } else {
        log.Info("ip_helper_post_xfmr include_ports not present in db")
        //var addPorts string
        var defaultPortString string
        s, _ := json.Marshal(DEFAULT_UDP_PORTS)
        defaultPortString = strings.Trim(string(s),"[]")
        log.Info("Fill default value ", defaultPortString)
        tbl := retDbDataMap["UDP_BROADCAST_FORWARDING"]
        entry := tbl["Ports"]
        log.Info(entry, DEFAULT_UDP_PORTS)
        if _, ok := entry.Field["include_ports@"] ; ok {
            log.Info("request has include ports, do nothing")
            /*if (inParams.oper == UPDATE) {
                addPorts = entry.Field["include_ports@"] 
            }*/
        } else {
            log.Info("request does not have ports, add default ports")
            entry.Field["include_ports@"] = defaultPortString
        }
        //entry.Field["include_ports@"] = defaultPortString + "," + addPorts
    }

    return retDbDataMap, err
}
