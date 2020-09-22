package transformer

import (
 "fmt"
 "strings"
 "strconv"
 "errors"
 "path/filepath"
 "github.com/openconfig/ygot/ygot"
 "github.com/Azure/sonic-mgmt-common/translib/db"
 "github.com/Azure/sonic-mgmt-common/translib/utils"
 "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
  log "github.com/golang/glog"
)

const (
    SNMP_AGENT_TABLE_NAME   = "SNMP_AGENT_ADDRESS_CONFIG"
)


func init() {
  XlateFuncBind("snmp_alias_value_xfmr",            snmp_alias_value_xfmr)

  XlateFuncBind("YangToDb_snmp_system_key_xfmr",        YangToDb_snmp_system_key_xfmr)

  XlateFuncBind("Subscribe_snmp_listen_subtree_xfmr",    Subscribe_snmp_listen_subtree_xfmr)
  XlateFuncBind("YangToDb_snmp_listen_subtree_xfmr",     YangToDb_snmp_listen_subtree_xfmr)
  XlateFuncBind("DbToYang_snmp_listen_subtree_xfmr",     DbToYang_snmp_listen_subtree_xfmr)

  XlateFuncBind("YangToDb_snmp_trap_fld_xfmr",      YangToDb_snmp_trap_fld_xfmr)
  XlateFuncBind("DbToYang_snmp_trap_fld_xfmr",      DbToYang_snmp_trap_fld_xfmr)

  XlateFuncBind("YangToDb_snmp_engine_key_xfmr",    YangToDb_snmp_engine_key_xfmr)

  XlateFuncBind("YangToDb_snmp_group_name_xfmr",    YangToDb_snmp_group_name_xfmr)

  XlateFuncBind("YangToDb_snmp_member_key_xfmr",    YangToDb_snmp_member_key_xfmr)
  XlateFuncBind("DbToYang_snmp_member_key_xfmr",    DbToYang_snmp_member_key_xfmr)

  XlateFuncBind("YangToDb_snmp_access_key_xfmr",    YangToDb_snmp_access_key_xfmr)
  XlateFuncBind("DbToYang_snmp_access_key_xfmr",    DbToYang_snmp_access_key_xfmr)

  XlateFuncBind("YangToDb_snmp_tag_name_xfmr",      YangToDb_snmp_tag_name_xfmr)
  XlateFuncBind("DbToYang_snmp_tag_name_xfmr",      DbToYang_snmp_tag_name_xfmr)
}

var YangToDb_snmp_system_key_xfmr = func(inParams XfmrParams) (string, error) {
  log.Info("YangToDb_snmp_system_key_xfmr            uri: ", inParams.uri)
  return "SYSTEM", nil
}

var YangToDb_snmp_engine_key_xfmr = func(inParams XfmrParams) (string, error) {
  log.Info("YangToDb_snmp_engine_key_xfmr            uri: ", inParams.uri)

  return "GLOBAL", nil
}

func YangToDb_snmp_group_name_xfmr(inParams XfmrParams) (map[string]string, error) {
  data := map[string]string{ "NULL": "NULL" }
  log.Info("*** YangToDb_snmp_group_name_xfmr        map: ", data)
  return data, nil
}

var YangToDb_snmp_member_key_xfmr = func(inParams XfmrParams) (string, error) {
  var entry_key string
  log.Info("YangToDb_snmp_member_key_xfmr            uri: ", inParams.uri)
  log.Info("YangToDb_snmp_member_key_xfmr            key: ", inParams.key)

  pathInfo := NewPathInfo(inParams.uri)
  gName := pathInfo.Var("name")
  sName := pathInfo.Var("security-name")

  if len(sName) == 0 {
    entry_key = gName
  } else {
    entry_key = gName + "|" + sName
  }

  log.Info("YangToDb_snmp_member_key_xfmr   Key Returned: ", entry_key)
  return entry_key, nil
}

var DbToYang_snmp_member_key_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
  rmap := make(map[string]interface{})
  log.Info("DbToYang_snmp_member_key_xfmr            uri: ", inParams.uri)
  log.Info("DbToYang_snmp_member_key_xfmr            key: ", inParams.key)

  keys := strings.Split(inParams.key, "|")
  secName := keys[1]
  rmap["security-name"] = secName
  log.Info("DbToYang_snmp_member_key_xfmr   Key Returned: ", rmap)
  return rmap, nil
}

var YangToDb_snmp_access_key_xfmr = func(inParams XfmrParams) (string, error) {
  var entry_key string
  log.Info("YangToDb_snmp_access_key_xfmr            uri: ", inParams.uri)
  log.Info("YangToDb_snmp_access_key_xfmr            key: ", inParams.key)

  pathInfo := NewPathInfo(inParams.uri)
  gName := pathInfo.Var("name")
  context := pathInfo.Var("context")
  secModel := pathInfo.Var("security-model")
  secLevel := pathInfo.Var("security-level")

  if len(context) == 0 {
    entry_key = gName
  } else {
    entry_key = gName + "|" + context + "|" + secModel + "|" + secLevel
  }

  log.Info("YangToDb_snmp_access_key_xfmr   Key Returned: ", entry_key)
  return entry_key, nil
}

var DbToYang_snmp_access_key_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
  rmap := make(map[string]interface{})
  log.Info("DbToYang_snmp_access_key_xfmr            uri: ", inParams.uri)
  log.Info("DbToYang_snmp_access_key_xfmr            key: ", inParams.key)

  keys := strings.Split(inParams.key, "|")
  context  := keys[1]
  secModel := keys[2]
  secLevel := keys[3]
  rmap["context"] = context
  rmap["security-model"] = secModel
  rmap["security-level"] = secLevel
  log.Info("DbToYang_snmp_access_key_xfmr   Key Returned: ", rmap)
  return rmap, nil
}

var YangToDb_snmp_tag_name_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    if inParams.param == nil {
        return res_map, errors.New("No Params")
    }

    log.Info("YangToDb_snmp_tag_name_xfmr   oper=", inParams.oper)
    if inParams.oper == DELETE {
        res_map["tag@"] = ""
        return res_map, nil
    }
    if inParams.oper != UPDATE {
        return res_map, errors.New("No UPDATE operation")
    }

    members := inParams.param.([]string)
    if len(members) == 1 {
        new_tag := fmt.Sprintf("%v", members[0])
        res_map["tag@"] = new_tag
        return res_map, nil
    }
    if len(members) != 2 {
        return res_map, errors.New("Invalid Params")
    }

    /* Translate original port name to native port name, if needed */
    org_ifname := fmt.Sprintf("%v", members[1])
    var nat_ifname_str string
    if utils.IsAliasModeEnabled() {
        nat_ifname := utils.GetNativeNameFromUIName(&org_ifname)
        nat_ifname_str = *nat_ifname
        log.Info("YangToDb_snmp_tag_name_xfmr  ", org_ifname, " -> ", nat_ifname_str)
    } else {
        nat_ifname_str = org_ifname
    }

    new_tag := fmt.Sprintf("%v,%v", members[0], nat_ifname_str)
    res_map["tag@"] = new_tag
    return res_map, nil
}

var DbToYang_snmp_tag_name_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]

    log.Info("YangToDb_snmp_tag_name_xfmr   oper=", inParams.oper)
    pTbl := data["SNMP_SERVER_TARGET"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_snmp_tag_name_xfmr SNMP_SERVER_TARGET not found : ", inParams.key)
        return result, errors.New("SNMP_SERVER_TARGET not found : " + inParams.key)
    }
    pSystemKey := pTbl[inParams.key]
    str, ok := pSystemKey.Field["tag@"]

    if ok {
        members := strings.Split(str, ",")
        if (len(members) != 1) && (len(members) != 2) {
            return result, errors.New("SNMP_SERVER_TARGET , tag not found : " + inParams.key)
        }
        if len(members) == 2 {
            /* Translate native port name to original port name, if needed */
            if utils.IsAliasModeEnabled() {
                org_ifname := fmt.Sprintf("%v", members[1])
                nat_ifname := utils.GetUINameFromNativeName(&org_ifname)
                nat_ifname_str := *nat_ifname
                log.Info("DbToYang_snmp_tag_name_xfmr  ", org_ifname, " -> ", nat_ifname_str)
                members[1] = nat_ifname_str
            }
        }
        result["tag"] = members
    } else {
        log.Info("tag field not found in SNMP_SERVER_TARGET")
    }

    return result, nil
}

var YangToDb_snmp_trap_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    log.Info("YangToDb_snmp_trap_fld_xfmr    uri: ", inParams.uri)

    res_map := make(map[string]string)

    var err error
    if inParams.param == nil {
        err = errors.New("No Params");
        return res_map, err
    }
    if inParams.oper == DELETE {
        res_map["traps"] = ""
        return res_map, nil
    }

    log.Info("YangToDb_snmp_trap_fld_xfmr   inParams.param : ", inParams.param)
    log.Info("YangToDb_snmp_trap_fld_xfmr   inParams.key : ", inParams.key)
    able, _ := inParams.param.(*bool)
    _, field := filepath.Split(inParams.uri)
    log.Info("YangToDb_ptp_boolean_xfmr able: ", *able, " field: ", field)

    if         (*able) {
        res_map["traps"] = "enable"
    }  else if (!*able) {
        res_map["traps"] = "disable"
    } else {
        err = errors.New("Enable/Disable Missing");
        return res_map, err
    }

    return res_map, nil
}

var DbToYang_snmp_trap_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("DbToYang_snmp_trap_fld_xfmr     uri : ", inParams.uri)
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]

    pTbl := data["SNMP_SERVER"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_snmp_trap_fld_xfmr SNMP_SERVER not found : ", inParams.key)
        return result, errors.New("SNMP_SERVER not found : " + inParams.key)
    }
    pSystemKey := pTbl[inParams.key]
    able, ok := pSystemKey.Field["traps"]

    if ok {
        if (able == "enable") {
            result["trap-enable"] = true
        } else if (able == "disable") {
            result["trap-enable"] = false
        }
    } else {
        log.Info("traps field not found in SNMP_SERVER|SYSTEM")
    }

    return result, nil
}

func getEngineRoot (s *ygot.GoStruct) *ocbinds.IETFSnmp_Snmp_Engine {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Snmp.Engine
}

var Subscribe_snmp_listen_subtree_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams

    log.Info("Subscribe_snmp_listen_subtree_xfmr  uri: ", inParams.uri)

    /* no need to verify dB data */
    result.isVirtualTbl = true
    return result, err
}

var YangToDb_snmp_listen_subtree_xfmr  SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    log.Info("YangToDb_snmp_listen_subtree_xfmr           URI: ", inParams.uri)

    res_map := make(map[string]map[string]db.Value)

    engineObj := getEngineRoot(inParams.ygRoot)
    if engineObj == nil {
        log.Info("YangToDb_snmp_listen_subtree_xfmr : Empty component.")
        return res_map, errors.New("Cannot get root node.")
    }

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("YangToDb_snmp_listen_subtree_xfmr targetUriPath: ", targetUriPath)

    listenName := pathInfo.Var("name")

    if listenName != "" {
        listenObj, ok := engineObj.Listen[listenName]
        if !ok {
            return res_map, errors.New("Cannot get listen node.")
        }

        var key strings.Builder
        var keyName string
        var entryName  string
        if (inParams.oper == DELETE) {
            log.Info("YangToDb_snmp_listen_subtree_xfmr        delete: ", listenName)
            if (targetUriPath == "/ietf-snmp:snmp/engine/listen") || (targetUriPath == "/ietf-snmp:snmp/engine/listen/udp") {
                AgentAddrTblTs := db.TableSpec {Name: SNMP_AGENT_TABLE_NAME}
                keys, verr := inParams.d.GetKeys(&AgentAddrTblTs)
                if verr != nil {
                    log.Errorf("Unable to get DB keys from SNMP_AGENT_TABLE_NAME, error=%v", verr)
                    return res_map, verr
                }
                for i := 0; i < len(keys); i++ {
                    log.Info("YangToDb_snmp_listen_subtree_xfmr           key: ", keys[i])
                    entry, err := inParams.d.GetEntry(&db.TableSpec{Name: SNMP_AGENT_TABLE_NAME}, keys[i])
                    if err == nil {
                        if entry.Has("name") {
                            entryName = entry.Get("name")
                        } else {
                            entryName = keys[i].Get(0)
                        }
                        log.Infof("DbToYang_snmp_listen_subtree_xfmr       entryName: %v", entryName )

                        if entryName == listenName {
                            fmt.Fprintf(&key, "%s|%s|%s", keys[i].Get(0), keys[i].Get(1), keys[i].Get(2))
                            keyName = key.String()
                            log.Info("YangToDb_snmp_listen_subtree_xfmr        delete: ", keyName)

                            verr = inParams.d.DeleteEntry(&AgentAddrTblTs, keys[i])
                            if verr != nil {
                                log.Errorf("Unable to delete DB entry: %s from SNMP_AGENT_TABLE_NAME, error=%v", keys[i], verr)
                                return res_map, verr
                            }
                        }
                    }
                }
            } else {
                return res_map, errors.New("The URI is not valid for a delete operation.")
            }

        } else if (inParams.oper == UPDATE) {
            log.Info("YangToDb_snmp_listen_subtree_xfmr        update: ", listenName)
            ipAddr := *listenObj.Udp.Ip
            port := *listenObj.Udp.Port

            iface := ""
            if listenObj.Udp.Interface != nil {
                iface = *listenObj.Udp.Interface
                /* Translate original port name to native port name */
                if utils.IsAliasModeEnabled() {
                    nat_ifname := utils.GetNativeNameFromUIName(&iface)
                    nat_ifname_str := *nat_ifname
                    log.Info("YangToDb_snmp_listen_subtree_xfmr  ", iface, " -> ", nat_ifname_str)
                    iface = nat_ifname_str
                }
            }
            res_map[SNMP_AGENT_TABLE_NAME] = make(map[string]db.Value)
            fmt.Fprintf(&key, "%s|%d|%s", ipAddr, port, iface)
            keyName = key.String()
            log.Info("YangToDb_snmp_listen_subtree_xfmr       keyName: ", keyName)

            res_map[SNMP_AGENT_TABLE_NAME][keyName] = db.Value{Field: map[string]string{}}
            dbVal := res_map[SNMP_AGENT_TABLE_NAME][keyName]

            (&dbVal).Set("name", listenName)
        }
    }

    return res_map, nil
}

var DbToYang_snmp_listen_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    log.Info("DbToYang_snmp_listen_subtree_xfmr            uri : ", inParams.uri)

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("DbToYang_snmp_listen_subtree_xfmr  targetUriPath :", targetUriPath)

    engineObj := getEngineRoot(inParams.ygRoot)
    if engineObj == nil {
        return nil
    }

    uri := ""
    index := strings.Index(targetUriPath, "listen")
    if index >= 0 {
        uri = targetUriPath[index:]
    }
    log.Info("DbToYang_snmp_listen_subtree_xfmr            uri : ", uri)

    dataBase := inParams.d

    keys, tblErr := dataBase.GetKeysPattern(&(db.TableSpec{Name: SNMP_AGENT_TABLE_NAME}), db.Key{Comp: []string{"*"}})
    if tblErr == nil {
        var err   error
        var name  string
        var ip    string
        var port  string
        var iface string
        var temp  int
        var ok    bool
        var listenObj *ocbinds.IETFSnmp_Snmp_Engine_Listen

        if uri == "listen" {
            if len(keys) > 0 {
                ygot.BuildEmptyTree(engineObj)
            }
            for _, key := range keys {
                ip    = key.Comp[0]
                port  = key.Comp[1]
                iface = key.Comp[2]
                log.Infof("DbToYang_snmp_listen_subtree_xfmr   ip port iface: %v %v %v", ip, port, iface )
                entry, err := dataBase.GetEntry(&db.TableSpec{Name: SNMP_AGENT_TABLE_NAME}, key)

                if err != nil {
                    log.Infof("Failed to get value: %v", err)
                    return err
                }

                if entry.Has("name") {
                    name = entry.Get("name")
                } else {
                    name = ip
                }

                log.Infof("DbToYang_snmp_listen_subtree_xfmr           entry: %v", entry )
                log.Infof("DbToYang_snmp_listen_subtree_xfmr            name: %v", name )

                listenObj, ok = engineObj.Listen[name]
                if !ok {
                    listenObj, err = engineObj.NewListen(name)
                    if err != nil {
                        log.Infof("Failed to get new listen object: %v", err)
                        return err
                    }
                }
                listenObj.Udp = new(ocbinds.IETFSnmp_Snmp_Engine_Listen_Udp)

                listenObj.Udp.Ip         = new(string)
                *listenObj.Udp.Ip        = ip

                temp, _ = strconv.Atoi(port)
                listenObj.Udp.Port       = new(uint16)
                *listenObj.Udp.Port      = uint16(temp)

                if (iface != "") {
                    if utils.IsAliasModeEnabled() {
                        org_ifname := iface
                        nat_ifname := utils.GetUINameFromNativeName(&org_ifname)
                        nat_ifname_str := *nat_ifname
                        log.Info("DbToYang_snmp_listen_subtree_xfmr  ", org_ifname, " -> ", nat_ifname_str)
                        iface = nat_ifname_str
                    }
                    listenObj.Udp.Interface  = new(string)
                    *listenObj.Udp.Interface = iface
                }

            }

        } else if uri == "listen/udp" {

            name := pathInfo.Var("name")
            log.Info("DbToYang_snmp_listen_subtree_xfmr           name : ", name)
            listenObj, err = engineObj.NewListen(ip)
            if err != nil {
                log.Infof("Failed to get new listen object: %v", err)
                return err
            }
            listenObj.Udp = new(ocbinds.IETFSnmp_Snmp_Engine_Listen_Udp)
            ygot.BuildEmptyTree(listenObj)

            for _, key := range keys {
                log.Info("DbToYang_snmp_listen_subtree_xfmr            key : ", key)
                log.Info("DbToYang_snmp_listen_subtree_xfmr       key.Comp : ", key.Comp)
                ip    = key.Comp[0]
                port  = key.Comp[1]
                iface = key.Comp[2]
                log.Info("DbToYang_snmp_listen_subtree_xfmr             ip : ", ip)
                log.Info("DbToYang_snmp_listen_subtree_xfmr           port : ", port)
                log.Info("DbToYang_snmp_listen_subtree_xfmr          iface : ", iface)

                if strings.Compare(name, ip) == 0 {
                    listenObj.Udp.Ip         = new(string)
                    *listenObj.Udp.Ip        = ip

                    temp, _ = strconv.Atoi(port)
                    listenObj.Udp.Port       = new(uint16)
                    *listenObj.Udp.Port      = uint16(temp)

                    if (iface != "") {
                        if utils.IsAliasModeEnabled() {
                            org_ifname := iface
                            nat_ifname := utils.GetUINameFromNativeName(&org_ifname)
                            nat_ifname_str := *nat_ifname
                            log.Info("DbToYang_snmp_listen_subtree_xfmr  ", org_ifname, " -> ", nat_ifname_str)
                            iface = nat_ifname_str
                        }
                        listenObj.Udp.Interface  = new(string)
                        *listenObj.Udp.Interface = iface
                    }

                    log.Info("DbToYang_snmp_listen_subtree_xfmr            err : ", err)
                    log.Info("DbToYang_snmp_listen_subtree_xfmr  listenObj.Udp : ", listenObj.Udp)
                    break
                }
            }
        }
    }
    return nil
}

func snmp_alias_value_xfmr(inParams XfmrDbParams) (string, error) {
    var err error
    var uiName string

    ifName := inParams.value
    log.Infof("+++ snmp_alias_value_xfmr: op=%v: ifname='%v' +++", inParams.oper, ifName)

    if !utils.IsAliasModeEnabled() {
        return ifName, err
    }

    for i, s := range strings.Split(ifName, ",") {
        var convertedName *string

        if inParams.oper == GET {
            convertedName = utils.GetUINameFromNativeName(&s)
        } else {
            convertedName = utils.GetNativeNameFromUIName(&s)
        }
        if i > 0 {
            uiName += ","
        }
        uiName += *convertedName
    }
    return uiName, err
}
