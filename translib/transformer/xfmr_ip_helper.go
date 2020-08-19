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
    "github.com/Azure/sonic-mgmt-common/translib/utils"
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

    XlateFuncBind("ip_helper_table_xfmr", ip_helper_table_xfmr)
    XlateFuncBind("YangToDb_ip_helper_intf_tbl_key_xfmr", YangToDb_ip_helper_intf_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ip_helper_intf_tbl_key_xfmr", DbToYang_ip_helper_intf_tbl_key_xfmr)
}

var ip_helper_table_xfmr TableXfmrFunc = func (inParams XfmrParams) ([]string, error) {
    var tblList []string
    var err error

    log.Info("ip_helper_table_xfmr - Uri: ", inParams.uri);
    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)

    ifName := pathInfo.Var("id");
    log.Info(ifName)

    if ifName == "" {
        log.Info("ip_helper_table_xfmr key is not present")
        if _, ok := dbIdToTblMap[inParams.curDb]; !ok {
            log.Info("ip_helper_table_xfmr db id entry not present")
            return tblList, errors.New("Key not present")
        } else {
            return dbIdToTblMap[inParams.curDb], nil
        }
    }

    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("ip_helper_table_xfmr - Invalid interface type IntfTypeUnset");
        return tblList, errors.New("Invalid interface type IntfTypeUnset");
    }

    intTbl := IntfTypeTblMap[intfType]
    log.Info("ip_helper_table_xfmr - targetUriPath : ", targetUriPath)

    tblList = append(tblList, intTbl.cfgDb.intfTN)

    log.Info("ip_helper_table_xfmr - Returning tblList", tblList)
    return tblList, err
}

var YangToDb_ip_helper_intf_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("id")
    log.Info(ifName)
    return ifName, err
}

var DbToYang_ip_helper_intf_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    var tblList string
    res_map := make(map[string]interface{})
    log.Info("DbToYang_ip_helper_intf_tbl_key_xfmr: ", inParams.key)

    if (inParams.key != "") {
        var configDb, _ = db.NewDB(getDBOptions(db.ConfigDB))

        intfType, _, _ := getIntfTypeByName(inParams.key)

        intTbl := IntfTypeTblMap[intfType]
        tblList = intTbl.cfgDb.intfTN

        db_if_name_ptr := utils.GetNativeNameFromUIName(&inParams.key)
        dbifName := *db_if_name_ptr

        entry, dbErr := configDb.GetEntry(&db.TableSpec{Name:tblList}, db.Key{Comp: []string{dbifName}})
        configDb.DeleteDB()
        if dbErr != nil {
            log.Info("Failed to read interface from config DB, " + tblList + " " + dbifName)
            return res_map, dbErr
        }

        if (entry.Get("helper_addresses@") != "")  {
            //Check if ip helper is valid for the interface
            res_map["id"] = inParams.key
        }
    }
    log.Info("DbToYang_ip_helper_intf_tbl_key_xfmr: res_map", res_map)
    return res_map, err
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
    ifName := pathInfo.Var("id")
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
    if (ipHelperDBEntry.Has("include_ports@") || ipHelperDBEntry.Has("exclude_default_ports@")) {
        var dbvalue []string
        if (ipHelperDBEntry.Has("include_ports@")) {
            dbvalue = strings.Split(ipHelperDBEntry.Field["include_ports@"], ",")
        } 
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

    requestUri, _ := getYangPathFromUri(inParams.requestUri)
    if strings.Contains(requestUri, "openconfig-ip-helper:ip-helper/interfaces") {
        //do nothing
        return retDbDataMap, err
    }

    ipHelperDBEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:"UDP_BROADCAST_FORWARDING"}, db.Key{Comp: []string{"Ports"}})
    if (ipHelperDBEntry.Has("include_ports@") || ipHelperDBEntry.Has("exclude_default_ports@")) {
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
