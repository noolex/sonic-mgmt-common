package transformer

import (
    "strings"
    "strconv"
    "errors"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)
func init () {
    XlateFuncBind("YangToDb_qos_intf_pfc_xfmr", YangToDb_qos_intf_pfc_xfmr)
    XlateFuncBind("DbToYang_qos_intf_pfc_xfmr", DbToYang_qos_intf_pfc_xfmr)
    XlateFuncBind("Subscribe_qos_intf_pfc_xfmr", Subscribe_qos_intf_pfc_xfmr)
}

func isQosPortDbEntryFound(d *db.DB, if_name string, table string) (bool) {

    if d == nil {
        log.Infof("unable to get configDB")
        return false
    }

    dbspec := &db.TableSpec { Name: table }
    _, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    return err == nil
}

func doGetIntfPfcPriority(d *db.DB, if_name string) (string) {
    if d == nil {
        log.Infof("unable to get configDB")
        return ""
    }

    dbspec := &db.TableSpec { Name: "PORT_QOS_MAP" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        if log.V(3) {
            log.Info("doGetIntfPfcPriority: if_name ", if_name, " No pfc_enable ")
        }

        return ""
    }
    pfc_enable, ok := dbEntry.Field["pfc_enable"]
    if ok {
        if log.V(3) {
            log.Info("doGetIntfPfcPriority: if_name ", if_name, " pfc_enable ", pfc_enable)
        }
        return pfc_enable
    } else if log.V(3) {
        log.Info("doGetIntfPfcPriority: if_name ", if_name, " No pfc_enable ")
    }
    return ""
}

func doGetIntfPfcAsymmetricCfg(d *db.DB, if_name string) (bool) {

    if d == nil {
        log.Infof("unable to get configDB")
        return false
    }

    dbspec := &db.TableSpec { Name: "PORT" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        if log.V(3) {
            log.Info("doGetIntfPfcAsymmetricCfg: if_name ", if_name, " No PFC Asymmetric ")
        }
        return false
    }
    pfc_asym, ok := dbEntry.Field["pfc_asym"]
    if ok && (pfc_asym == "on") {
        if log.V(3) {
            log.Info("doGetIntfPfcAsymmetricCfg: if_name ", if_name, " pfc_asym ", pfc_asym)
        }
        return true
    } else if log.V(3) {
        log.Info("doGetIntfPfcAsymmetricCfg: if_name ", if_name, " No PFC Asymmetric ")
    }
    return false
}


func qos_intf_pfc_delete_xfmr(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)


    pathInfo := NewPathInfo(inParams.uri)
    ifname := pathInfo.Var("interface-id")
    db_if_name := utils.GetNativeNameFromUIName(&ifname)
    if_name := *db_if_name
    dbkey := if_name

    log.Info("qos_intf_pfc_delete_xfmr: ", inParams.ygRoot, inParams.uri, " if_name ", if_name)
    portQosMapEntry := isQosPortDbEntryFound(inParams.d, if_name, "PORT_QOS_MAP")
    portEntry := isQosPortDbEntryFound(inParams.d, if_name, "PORT")

    requestUriPath, err := getYangPathFromUri(inParams.requestUri)
    if (requestUriPath == "/openconfig-qos:qos/interfaces/interface" ||
        requestUriPath ==  "/openconfig-qos:qos/interfaces" ||
        requestUriPath ==  "/openconfig-qos:qos") {
        if !strings.HasPrefix(if_name, "Eth") {
            log.Info("qos_intf_pfc_delete_xfmr: Not Ethernet interface ", if_name)
            return res_map, err
        }
    } else if !portQosMapEntry && !portEntry {
        err = tlerr.NotFoundError{Format:"Resource not found"}
        return res_map, err
    }
    targetUriPath, err := getYangPathFromUri(inParams.uri)
    if (targetUriPath == "/openconfig-qos:qos/interfaces/interface/pfc") {
        targetUriPath  = "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc"
    }
    if log.V(3) {
        log.Info("targetUriPath: ",  targetUriPath)
    }
    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority") ||
       strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/pfc/pfc-priorities/pfc-priority") {
        pfc_priority := pathInfo.Var("dot1p")
        pfc_enable := doGetIntfPfcPriority(inParams.d, if_name)
        pfc_prio_disable := pfc_priority
        var prev_pfc_fld bool
        if len(pfc_enable) != 0 {
            prev_pfc_fld = true
        } else {
            log.Info("qos_intf_pfc_delete_xfmr: No pfc_enable field to delete ")
            err = tlerr.NotFoundError{Format:"Resource not found"}
            return res_map, err
        }
        if log.V(3) {
            log.Info("qos_intf_pfc_delete_xfmr : present_pfc_enable - ",
            pfc_enable,  "pfc_prio_disable - ", pfc_prio_disable)
        }
        if len(pfc_enable) != 0 && len(pfc_prio_disable) != 0 {
            if strings.Contains(pfc_enable, pfc_prio_disable) {
                pfc_enable = strings.Replace(pfc_enable, pfc_prio_disable + ",", "", 1)
                pfc_enable = strings.Replace(pfc_enable, pfc_prio_disable, "", 1)
            }
        }

        pfc_enable = strings.TrimSuffix(pfc_enable, ",")

        if log.V(3) {
            log.Info("YangToDb_qos_intf_pfc_xfmr : pfc_enable - ", pfc_enable)
        }

        if prev_pfc_fld && (len(pfc_enable) != 0)  {
            if log.V(3) {
                log.Info("YangToDb_qos_intf_pfc_xfmr : Update pfc_enable fld - ", pfc_enable)
            }
            subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

            if _, ok := subOpMap[db.ConfigDB]; !ok {
                subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
            }
            if _, ok := subOpMap[db.ConfigDB]["PORT_QOS_MAP"]; !ok {
                subOpMap[db.ConfigDB]["PORT_QOS_MAP"] = make(map[string]db.Value)
            }
            subOpMap[db.ConfigDB]["PORT_QOS_MAP"][if_name] = db.Value{Field: make(map[string]string)}
            subOpMap[db.ConfigDB]["PORT_QOS_MAP"][if_name].Field["pfc_enable"] = pfc_enable

            inParams.subOpDataMap[UPDATE] = &subOpMap
        } else if len(pfc_enable) == 0 {
            if log.V(3) {
                log.Info("YangToDb_qos_intf_pfc_xfmr : Delete pfc_enable fld - ", pfc_enable)
            }
            portQosMapTblMap := make(map[string]db.Value)
            entry := db.Value{Field: make(map[string]string)}
            entry.Set("pfc_enable",  "")
            portQosMapTblMap[dbkey] = entry
            res_map["PORT_QOS_MAP"] = portQosMapTblMap
        }
        log.Info("qos_intf_pfc_delete_xfmr: End, res_map: ", res_map)
        return res_map, err
    }

    if (strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities") ||
        strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/pfc/pfc-priorities")) && portQosMapEntry {
        portQosMapTblMap := make(map[string]db.Value)
        entry := db.Value{Field: make(map[string]string)}
        entry.Set("pfc_enable",  "")
        portQosMapTblMap[dbkey] = entry
        res_map["PORT_QOS_MAP"] = portQosMapTblMap

        log.Info("qos_intf_pfc_delete_xfmr: End, res_map: ", res_map)
        return res_map, err
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/config") ||
       strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/pfc/config") ||
       (targetUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc") && portEntry {

        portTblMap := make(map[string]db.Value)
        entry := db.Value{Field: make(map[string]string)}
        entry.Set("pfc_asym",  "off")
        portTblMap[dbkey] = entry
        res_map["PORT"] = portTblMap
        if _, ok := subOpMap[db.ConfigDB]; !ok {
            subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        }
        if _, ok := subOpMap[db.ConfigDB]["PORT"]; !ok {
            subOpMap[db.ConfigDB]["PORT"] = make(map[string]db.Value)
        }
        subOpMap[db.ConfigDB]["PORT"][if_name] = db.Value{Field: make(map[string]string)}
        subOpMap[db.ConfigDB]["PORT"][if_name].Field["pfc_asym"] = "off"

        inParams.subOpDataMap[UPDATE] = &subOpMap

    }

    if targetUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc" && portQosMapEntry {
        portQosMapTblMap := make(map[string]db.Value)
        entry := db.Value{Field: make(map[string]string)}
        entry.Set("pfc_enable",  "")
        portQosMapTblMap[dbkey] = entry
        res_map["PORT_QOS_MAP"] = portQosMapTblMap
    }

    log.Info("qos_intf_pfc_delete_xfmr: End, res_map: ", res_map)

    return res_map, err
}

var YangToDb_qos_intf_pfc_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    var err error
    res_map := make(map[string]map[string]db.Value)
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    var pfc_cfg bool = false
    var pfc_prio_enable []string
    var pfc_prio_disable []string

    log.Info("YangToDb_qos_intf_pfc_xfmr: ", inParams.ygRoot, inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ifname := pathInfo.Var("interface-id")
    db_if_name := utils.GetNativeNameFromUIName(&ifname)
    if_name := *db_if_name

    if inParams.oper == DELETE {
        return qos_intf_pfc_delete_xfmr(inParams)
    }

    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    if qosIntfsObj == nil {
        return res_map, err
    }

    intfObj, ok := qosIntfsObj.Interface[ifname]
    if !ok {
        return res_map, err
    }

    pfcObj := intfObj.Pfc
    if pfcObj == nil {
        return res_map, err
    }

    pfcConfig := pfcObj.Config
    if pfcConfig != nil {
        dbkey := if_name

        portTblMap := make(map[string]db.Value)
        entry := db.Value{Field: make(map[string]string)}

        if pfcConfig.Asymmetric != nil {
            if *pfcConfig.Asymmetric {
                entry.Set("pfc_asym",  "on")
                portTblMap[dbkey] = entry
                res_map["PORT"] = portTblMap
            } else {
                entry.Set("pfc_asym",  "off")
                portTblMap[dbkey] = entry
                res_map["PORT"] = portTblMap
            }
        }
    }

    pfcPrioritiesObj := pfcObj.PfcPriorities
    if (pfcPrioritiesObj != nil) {
        dbkey := if_name
        portQosMapTblMap := make(map[string]db.Value)
        entry := db.Value{Field: make(map[string]string)}
        for prio, data := range pfcPrioritiesObj.PfcPriority {
            if data.Config == nil {
                errStr := "PFC Priority [Config DATA]  invalid."
                log.Info("YangToDb_qos_intf_pfc_xfmr : " + errStr)
                return res_map, errors.New(errStr)
            }

            if data.Config != nil {
                if data.Config.Enable != nil {
                    priority := strconv.FormatInt(int64(prio), 10)
                    if *data.Config.Enable {
                        if log.V(3) {
                            log.Info("YangToDb_qos_intf_pfc_xfmr : dbkey - ", dbkey, " Add Priority - ", priority)
                        }
                        pfc_prio_enable = append(pfc_prio_enable, priority)
                    } else {
                        if log.V(3) {
                            log.Info("YangToDb_qos_intf_pfc_xfmr : dbkey - ", dbkey, " Del Priroity - ", priority)
                        }
                        pfc_prio_disable = append(pfc_prio_disable, priority)
                    }
                    pfc_cfg = true
                }
            }
        }

        if pfc_cfg {
            var prev_pfc_fld bool
            pfc_enable := doGetIntfPfcPriority(inParams.d, if_name)
            if len(pfc_enable) != 0 {
               prev_pfc_fld = true
           }
           if log.V(3) {
               log.Info("YangToDb_qos_intf_pfc_xfmr : pfc_enable - ", pfc_enable, " pfc_prio_enable - ",
               pfc_prio_enable, " pfc_prio_disable - ", pfc_prio_disable)
           }
            if len(pfc_enable) != 0 {
                for _, del_prio := range pfc_prio_disable {
                    if strings.Contains(pfc_enable, del_prio) {
                        pfc_enable = strings.Replace(pfc_enable, del_prio + ",", "", 1)
                        pfc_enable = strings.Replace(pfc_enable, del_prio, "", 1)
                    }
                }
            }

            for _, add_prio := range pfc_prio_enable {
                if !strings.Contains(pfc_enable, add_prio) {
                    if len(pfc_enable) != 0 {
                        pfc_enable += ","
                    }
                    pfc_enable += add_prio
                }
            }

            pfc_enable = strings.TrimSuffix(pfc_enable, ",")

            if log.V(3) {
                log.Info("YangToDb_qos_intf_pfc_xfmr : pfc_enable - ", pfc_enable)
            }
            if len(pfc_enable) != 0 {
                entry.Set("pfc_enable", pfc_enable)
                portQosMapTblMap[dbkey] = entry
            }

            if prev_pfc_fld && len(pfc_enable) == 0 {
                if log.V(3) {
                    log.Info("YangToDb_qos_intf_pfc_xfmr : Delete pfc_enable fld - ", pfc_enable)
                }
                if _, ok := subOpMap[db.ConfigDB]; !ok {
                    subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                }
                if _, ok := subOpMap[db.ConfigDB]["PORT_QOS_MAP"]; !ok {
                    subOpMap[db.ConfigDB]["PORT_QOS_MAP"] = make(map[string]db.Value)
                }
                subOpMap[db.ConfigDB]["PORT_QOS_MAP"][if_name] = db.Value{Field: make(map[string]string)}
                subOpMap[db.ConfigDB]["PORT_QOS_MAP"][if_name].Field["pfc_enable"] = pfc_enable

                inParams.subOpDataMap[DELETE] = &subOpMap
            } else {
                res_map["PORT_QOS_MAP"] = portQosMapTblMap
            }
        }
    }

    log.Info("YangToDb_qos_intf_pfc_xfmr: End, res_map: ", res_map)
    return res_map, err
}

func intf_pfc_priroity_cfg_attr_get (inParams XfmrParams, attrUri string, if_name string, dot1p string,
              prioCfgObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_PfcPriorities_PfcPriority_Config) error {

    if log.V(3) {
       log.Info("intf_pfc_priroity_cfg_attr_get - if_name ", if_name, " dot1p " , dot1p, " attrUri ", attrUri)
    }
    if prioCfgObj == nil {
        errStr := "Invalid params for PFC Config attr get."
        log.Info("intf_pfc_priroity_cfg_attr_get: " + errStr)
        return errors.New(errStr)
    }
    curAttrUri := attrUri
    switch (attrUri) {
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc":
         curAttrUri = curAttrUri + "/pfc-priorities"
         fallthrough
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities":
         curAttrUri = curAttrUri + "/pfc-priority"
         fallthrough
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority":
         curAttrUri = curAttrUri + "/config"
         fallthrough
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority/config":
        attrList := []string {"enable"}
        for _, val := range attrList {
            curAttrUri = curAttrUri + "/" + val
            intf_pfc_priroity_cfg_attr_get (inParams, curAttrUri, if_name, dot1p, prioCfgObj)
        }
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority/config/enable":
        pfc_enable := doGetIntfPfcPriority(inParams.d, if_name)
        pfc_prio, _ := strconv.Atoi(dot1p)
        pfc_p := uint8(pfc_prio)
        prioCfgObj.Dot1P = &pfc_p
        prioCfgObj.Enable = new(bool)
        if strings.Contains(pfc_enable, dot1p) {
           *prioCfgObj.Enable = true
        } else {
            *prioCfgObj.Enable = false
        }
    default:
        return nil
    }
    return nil
}

func intf_pfc_priroity_state_attr_get (inParams XfmrParams, attrUri string, if_name string, dot1p string,
              prioStateObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_PfcPriorities_PfcPriority_State) error {

    if log.V(3) {
       log.Info("intf_pfc_priroity_state_attr_get - if_name ", if_name, " dot1p " , dot1p, " attrUri ", attrUri)
    }
    if prioStateObj == nil {
        errStr := "Invalid params for PFC State attr get."
        log.Info("intf_pfc_priroity_state_attr_get: " + errStr)
        return errors.New(errStr)
    }

    curAttrUri := attrUri
    switch (attrUri) {
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc":
        curAttrUri = curAttrUri + "/pfc-priorities"
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities":
        curAttrUri = curAttrUri + "/pfc-priority"
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority":
        curAttrUri = curAttrUri + "/state"
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority/state":
        attrList := []string {"enable", "statistics"}
        for _, val := range attrList {
            _curAttrUri := curAttrUri + "/" + val
            if val == "statistics" {
                ygot.BuildEmptyTree(prioStateObj.Statistics)
            }
            intf_pfc_priroity_state_attr_get (inParams, _curAttrUri, if_name, dot1p, prioStateObj)
        }
        /* Place holder for counters */
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority/state/enable":
        pfc_enable := doGetIntfPfcPriority(inParams.d, if_name)
        prioStateObj.Enable = new(bool)
        pfc_prio, _ := strconv.Atoi(dot1p)
        pfc_p := uint8(pfc_prio)
        prioStateObj.Dot1P = &pfc_p
        if strings.Contains(pfc_enable, dot1p) {
            *prioStateObj.Enable = true
        } else {
            *prioStateObj.Enable = false
        }
    case "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities/pfc-priority/state/statistics":
        pfc_prio, _ := strconv.Atoi(dot1p)
        pfc_p := uint8(pfc_prio)
        getPfcStats (inParams, if_name, pfc_p, inParams.dbs[db.CountersDB], prioStateObj.Statistics)
    default:
        return nil
    }
    return nil
}

func getPfcQueueIDs(inParams XfmrParams, if_name string, dbs [db.MaxDB]*db.DB) ([]string) {
    var     err  error
    q_list := []string{}

    var queueCountInfo db.Value
    var present bool
    oidMap, present := inParams.txCache.Load("COUNTERS_QUEUE_NAME_MAP")
    if !present {
        queueOidMapTs := &db.TableSpec{Name: "COUNTERS_QUEUE_NAME_MAP"}
        queueCountInfo, err = dbs[db.CountersDB].GetMapAll(queueOidMapTs)
        if err != nil {
            log.Info("getPfcQueueIDs    err: ", err)
            return q_list
        }

        inParams.txCache.Store("COUNTERS_QUEUE_NAME_MAP", queueCountInfo)
        log.V(3).Info("Loading queueCountInfo")
    } else {
        queueCountInfo = oidMap.(db.Value)
        log.V(3).Info("Reuse queueCountInfo ")
    }

    for queue, oid := range queueCountInfo.Field {
        if strings.HasPrefix(queue, if_name) && oid != "" {
            elements := strings.Split(queue, ":")
            if len(elements) >= 2 {
                q_list = append(q_list, elements[1])
            }
        }
    }
    return q_list
}

var DbToYang_qos_intf_pfc_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    pathInfo := NewPathInfo(inParams.uri)

    ifname := pathInfo.Var("interface-id")
    dbIfName := utils.GetNativeNameFromUIName(&ifname)
    if_name := *dbIfName
    log.Info("DbToYang_qos_intf_pfc_xfmr: ", inParams.uri, " if_name ", if_name)
    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    if qosIntfsObj == nil {
        return nil
    }

    intfObj, ok := qosIntfsObj.Interface[ifname]
    if !ok {
        return nil
    }

    pfcObj := intfObj.Pfc
    if pfcObj == nil {
        return nil
    }
    ygot.BuildEmptyTree(intfObj.Pfc)

    targetUriPath, _ := getYangPathFromUri(inParams.uri)
    if (targetUriPath == "/openconfig-qos:qos/interfaces/interface/pfc") {
       targetUriPath  = "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc"
    }
    log.Info("targetUriPath: ",  targetUriPath)
    pfc_asym := doGetIntfPfcAsymmetricCfg(inParams.d, if_name)
    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/config") ||
       (targetUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc") {
       ygot.BuildEmptyTree(pfcObj.Config)
       if pfc_asym {
           pfcObj.Config.Asymmetric = &pfc_asym
       }
    }
    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/state") ||
       (targetUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc") {
       ygot.BuildEmptyTree(pfcObj.State)
       if pfc_asym {
           pfcObj.State.Asymmetric = &pfc_asym
       }
    }


    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-priorities") ||
       (targetUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc") {
       dot1p := pathInfo.Var("dot1p")
       if intfObj.Pfc.PfcPriorities == nil {
           ygot.BuildEmptyTree(intfObj.Pfc.PfcPriorities)
       }

       pfcPrioritiesTblObj := intfObj.Pfc.PfcPriorities

       for prio := range [8]int{} {
           pfc_prio := strconv.Itoa(prio)
           if dot1p != "" && pfc_prio != dot1p {
               continue
           }

           dot1p_val := uint8(prio)

           prioObj, ok := pfcPrioritiesTblObj.PfcPriority[dot1p_val]
           if !ok {
               prioObj, _ = pfcPrioritiesTblObj.NewPfcPriority(dot1p_val)
           }
           ygot.BuildEmptyTree(prioObj)
           ygot.BuildEmptyTree(prioObj.Config)
           ygot.BuildEmptyTree(prioObj.State)

           intf_pfc_priroity_cfg_attr_get(inParams, targetUriPath, if_name, pfc_prio, prioObj.Config)
           intf_pfc_priroity_state_attr_get(inParams, targetUriPath, if_name, pfc_prio, prioObj.State)
       }
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/pfc-queue") ||
       (targetUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc") {
       q_list := []string{}
       queue := pathInfo.Var("queue")
       if intfObj.Pfc.PfcQueue == nil {
           ygot.BuildEmptyTree(intfObj.Pfc.PfcQueue)
       }

       pfcQueueTblObj := intfObj.Pfc.PfcQueue
       if queue != "" {
           q_list = append(q_list, queue)
       } else {
           q_list = getPfcQueueIDs(inParams, ifname, inParams.dbs)
       }

       state_flag := strings.HasSuffix(targetUriPath, "state")
       config_flag := strings.HasSuffix(targetUriPath, "config")
       stats_flag := strings.HasSuffix(targetUriPath, "statistics")

       for _, q := range q_list {
           q32_val,err := strconv.Atoi(q)
           if err != nil {
               continue
           }
           q_val := uint8(q32_val)
           qObj, ok := pfcQueueTblObj.PfcQueue[q_val]
           if !ok {
               qObj, _ = pfcQueueTblObj.NewPfcQueue(q_val)
           }
           ygot.BuildEmptyTree(qObj)
           if !state_flag && !stats_flag {
               ygot.BuildEmptyTree(qObj.Config)
               qc_val := q_val
               qObj.Config.Queue = new(uint8)
               qObj.Config.Queue = &qc_val
           }
           if !config_flag && !stats_flag {
               ygot.BuildEmptyTree(qObj.State)
               qs_val := q_val
               qObj.State.Queue = new(uint8)
               qObj.State.Queue = &qs_val
           }
           if !state_flag && !config_flag {
               ygot.BuildEmptyTree(qObj.Statistics)

               if getPfcQueueStats(inParams, if_name, q_val, inParams.dbs[db.CountersDB], qObj.Statistics) != nil {
                  log.Errorf("DbToYang_qos_intf_pfc_xfmr: Failed to read PFC stats for interface %s queue %s", if_name, q)
                  continue
               }
           }
       }
   }

   return nil
}

var Subscribe_qos_intf_pfc_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams

    pathInfo := NewPathInfo(inParams.uri)

    ifname := pathInfo.Var("interface-id")
    dbIfName := utils.GetNativeNameFromUIName(&ifname)
    if_name := *dbIfName
    log.Info("Subscribe_qos_intf_pfc_xfmr: ", inParams.uri, " if_name ", if_name)

    result.dbDataMap = make(RedisDbSubscribeMap)

    result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{"PORT_QOS_MAP":{if_name:{}}}}   // tablename & table-idx for the inParams.uri
    result.isVirtualTbl = true
    result.needCache = true
    result.onChange = OnchangeEnable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}
