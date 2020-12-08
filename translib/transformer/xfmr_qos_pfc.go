package transformer

import (
    log "github.com/golang/glog"
    "strings"
    "errors"
    "strconv"
    "fmt"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "encoding/json"
    "time"
)

func init() {
  XlateFuncBind("YangToDb_flex_counter_key_xfmr",               YangToDb_flex_counter_key_xfmr)
  XlateFuncBind("DbToYang_flex_counter_key_xfmr",               DbToYang_flex_counter_key_xfmr)

  XlateFuncBind("YangToDb_poll_interval_key_xfmr",              YangToDb_poll_interval_key_xfmr)

  XlateFuncBind("YangToDb_counter_poll_fld_xfmr",               YangToDb_counter_poll_fld_xfmr)
  XlateFuncBind("DbToYang_counter_poll_fld_xfmr",               DbToYang_counter_poll_fld_xfmr)

  XlateFuncBind("YangToDb_qos_intf_pfcwd_st_xfmr",              YangToDb_qos_intf_pfcwd_st_xfmr)
  XlateFuncBind("DbToYang_qos_intf_pfcwd_st_xfmr",              DbToYang_qos_intf_pfcwd_st_xfmr)
  XlateFuncBind("Subscribe_qos_intf_pfcwd_st_xfmr",             Subscribe_qos_intf_pfcwd_st_xfmr)

  XlateFuncBind("YangToDb_qos_intf_pfcwd_action_fld_xfmr",      YangToDb_qos_intf_pfcwd_action_fld_xfmr)
  XlateFuncBind("DbToYang_qos_intf_pfcwd_action_fld_xfmr",      DbToYang_qos_intf_pfcwd_action_fld_xfmr)

  XlateFuncBind("DbToYang_qos_intf_pfc_counters_st_xfmr",       DbToYang_qos_intf_pfc_counters_st_xfmr)

  XlateFuncBind("DbToYang_qos_intf_pfc_queue_counters_st_xfmr", DbToYang_qos_intf_pfc_queue_counters_st_xfmr)

  XlateFuncBind("rpc_clear_qos_pfc", rpc_clear_qos_pfc)
}

func isPfcWdEntryFound(d *db.DB, if_name string) (bool) {

    if d == nil {
        log.Infof("unable to get configDB")
        return false
    }

    dbspec := &db.TableSpec { Name: "PFC_WD" }
    _, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    return err == nil
}


var YangToDb_flex_counter_key_xfmr = func(inParams XfmrParams) (string, error) {
    log.Info("YangToDb_flex_counter_key_xfmr            uri: ", inParams.uri)

    return "PFCWD", nil
}

var DbToYang_flex_counter_key_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("DbToYang_flex_counter_key_xfmr            uri: ", inParams.uri)
    rmap := make(map[string]interface{})

    log.Info("DbToYang_flex_counter_key_xfmr   Key Returned: ", rmap)
    return rmap, nil
}

var YangToDb_poll_interval_key_xfmr = func(inParams XfmrParams) (string, error) {
    log.Info("YangToDb_poll_interval_key_xfmr            uri: ", inParams.uri)

    return "GLOBAL", nil
}

var YangToDb_counter_poll_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    log.Info("YangToDb_counter_poll_fld_xfmr    uri: ", inParams.uri)
    res_map := make(map[string]string)

    var err error
    if inParams.param == nil {
        err = errors.New("No Params");
        return res_map, err
    }
    if inParams.oper == DELETE {
        res_map["FLEX_COUNTER_STATUS"] = ""
        return res_map, nil
    }

    able, _ := inParams.param.(ocbinds.E_OpenconfigQos_Qos_PfcWatchdog_Flex_Config_CounterPoll)
    log.Info("YangToDb_counter_poll_fld_xfmr   able : ", able)

    if         (able == ocbinds.OpenconfigQos_Qos_PfcWatchdog_Flex_Config_CounterPoll_ENABLE) {
        res_map["FLEX_COUNTER_STATUS"] = "enable"
    }  else if (able == ocbinds.OpenconfigQos_Qos_PfcWatchdog_Flex_Config_CounterPoll_DISABLE) {
        res_map["FLEX_COUNTER_STATUS"] = "disable"
    } else {
        err = errors.New("Enable/Disable Missing");
        return res_map, err
    }

    return res_map, nil
}

var DbToYang_counter_poll_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("DbToYang_counter_poll_fld_xfmr     uri : ", inParams.uri)
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]

    pTbl := data["FLEX_COUNTER_TABLE"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_counter_poll_fld_xfmr FLEX_COUNTER_TABLE not found : ", inParams.key)
        return result, errors.New("FLEX_COUNTER_TABLE not found : " + inParams.key)
    }
    pGrpKey := pTbl[inParams.key]
    able, ok := pGrpKey.Field["FLEX_COUNTER_STATUS"]
    log.Info("DbToYang_counter_poll_fld_xfmr   able : ", able)

    if ok {
        if (able == "enable") {
            result["counter-poll"] = "ENABLE"
        } else if (able == "disable") {
            result["counter-poll"] = "DISABLE"
        }
    } else {
        log.Info("FLEX_COUNTER_STATUS field not found in DB")
    }
    return result, err
}

var YangToDb_qos_intf_pfcwd_action_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    log.Info("YangToDb_qos_intf_pfcwd_action_fld_xfmr    uri: ", inParams.uri)

    res_map := make(map[string]string)

    var err error
    if inParams.param == nil {
        err = errors.New("No Params");
        return res_map, err
    }
    if inParams.oper == DELETE {
        res_map["action"] = ""
        return res_map, nil
    }

    action, _ := inParams.param.(ocbinds.E_OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action)
    log.Info("YangToDb_qos_intf_pfcwd_action_fld_xfmr  action: ", action)

    if         (action == ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_DROP) {
        res_map["action"] = "drop"
    }  else if (action == ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_FORWARD) {
        res_map["action"] = "forward"
    }  else if (action == ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_ALERT) {
        res_map["action"] = "alert"
    } else {
        err = errors.New("Action Missing");
        return res_map, err
    }

    return res_map, nil
}

var DbToYang_qos_intf_pfcwd_action_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("DbToYang_qos_intf_pfcwd_action_fld_xfmr   uri : ", inParams.uri)
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]

    pTbl := data["PFC_WD"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_qos_intf_pfcwd_action_fld_xfmr PFC_WD not found : ", inParams.key)
        return result, errors.New("PFC_WD not found : " + inParams.key)
    }
    pGrpKey := pTbl[inParams.key]
    action, ok := pGrpKey.Field["action"]
    log.Info("DbToYang_qos_intf_pfcwd_action_fld_xfmr  action : ", action)

    if ok {
        if (action == "drop") {
            result["action"] = "DROP"
        } else if (action == "forward") {
            result["action"] = "FORWARD"
        } else if (action == "alert") {
            result["action"] = "ALERT"
        }
    } else {
        log.Info("action field not found in DB")
    }
    return result, err
}

var Subscribe_qos_intf_pfcwd_st_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var result XfmrSubscOutParams

    log.Info("Subscribe_qos_intf_pfcwd_st_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    ifname := pathInfo.Var("interface-id")
    dbIfName := utils.GetNativeNameFromUIName(&ifname)
    if_name := *dbIfName
    log.Info("Subscribe_qos_intf_pfc_xfmr: ", if_name)

    result.dbDataMap = make(RedisDbMap)
    log.Infof("Subscribe_qos_intf_pfcwd_st_xfmr path:%s; template:%s targetUriPath:%s key:%s",
              pathInfo.Path, pathInfo.Template, targetUriPath, if_name)

    result.dbDataMap = RedisDbMap{db.ConfigDB:{"PFC_WD":{if_name:{}}}}   // tablename & table-idx for the inParams.uri
    result.needCache = true
    result.onChange = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, nil
}

var YangToDb_qos_intf_pfcwd_st_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    log.Info("YangToDb_qos_intf_pfcwd_st_xfmr            uri : ", inParams.uri)

    var err error
    res_map := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)

    ifname := pathInfo.Var("interface-id")
    db_if_name := utils.GetNativeNameFromUIName(&ifname)
    if_name := *db_if_name
    log.Info("YangToDb_qos_intf_pfcwd_st_xfmr ifname :", if_name)
    if (inParams.oper == DELETE) {
        isEntry := isPfcWdEntryFound(inParams.d, if_name)

        requestUriPath, _ := getYangPathFromUri(inParams.requestUri)
        if (requestUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc" ||
            requestUriPath ==  "/openconfig-qos:qos/interfaces/interface/pfc" ||
            requestUriPath ==  "/openconfig-qos:qos/interfaces/interface" ||
            requestUriPath ==  "/openconfig-qos:qos/interfaces" ||
            requestUriPath ==  "/openconfig-qos:qos") {
            if !isEntry {
                log.Info("YangToDb_qos_intf_pfcwd_st_xfmr: No Entry, res_map: ", res_map)
                return res_map, err
            }

            dbkey := if_name
            pfcwdTblMap := make(map[string]db.Value)
            entry := db.Value{Field: make(map[string]string)}
            pfcwdTblMap[dbkey] = entry
            res_map["PFC_WD"] = pfcwdTblMap
            log.Info("YangToDb_qos_intf_pfcwd_st_xfmr: ", res_map)
            return res_map, err
        } else if((requestUriPath == "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/watchdog") ||
                  (requestUriPath == "/openconfig-qos:qos/interfaces/interface/pfc/watchdog")){
            if !isEntry {
              err = tlerr.NotFoundError{Format:"Resource not found"}
              return res_map, err
            }
            dbkey := if_name
            pfcwdTblMap := make(map[string]db.Value)
            entry := db.Value{Field: make(map[string]string)}
            pfcwdTblMap[dbkey] = entry
            res_map["PFC_WD"] = pfcwdTblMap
            log.Info("YangToDb_qos_intf_pfcwd_st_xfmr : ", res_map)
            return res_map, err
        }
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

    wdObj := pfcObj.Watchdog
    if wdObj == nil {
        return res_map, err
    }

    wdConfig := wdObj.Config
    if wdConfig != nil {
        dbkey := if_name

        pfcwdTblMap := make(map[string]db.Value)
        entry := db.Value{Field: make(map[string]string)}

        if wdConfig.DetectionTime != nil {
            detectTime := strconv.FormatInt(int64(*wdConfig.DetectionTime), 10)
            log.Info("YangToDb_qos_intf_pfcwd_st_xfmr    detectTime :", detectTime)
            entry.Set("detection_time", detectTime)
        }
        if wdConfig.RestorationTime != nil {
            restoreTime := strconv.FormatInt(int64(*wdConfig.RestorationTime), 10)
            log.Info("YangToDb_qos_intf_pfcwd_st_xfmr    restoreTime :", restoreTime)
            entry.Set("restoration_time", restoreTime)
        }
        action := wdConfig.Action
        if action != 0 {
            log.Info("YangToDb_qos_intf_pfcwd_st_xfmr         action :", action)
            if         (action == ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_DROP) {
                entry.Set("action", "drop")
            }  else if (action == ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_FORWARD) {
                entry.Set("action", "forward")
            }  else if (action == ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_ALERT) {
                entry.Set("action", "alert")
            }
        }
        pfcwdTblMap[dbkey] = entry
        res_map["PFC_WD"] = pfcwdTblMap
    }

    log.Info("YangToDb_qos_intf_pfcwd_st_xfmr        res_map : ", res_map)
    return res_map, err
}

func doGetIntfPfcWdAction(d *db.DB, if_name string) (string) {
    if log.V(3) { 
        log.Info("doGetIntfPfcWdAction   if_name : ", if_name)
    }
    if d == nil {
        log.Infof("unable to get configDB")
        return ""
    }
    dbspec := &db.TableSpec { Name: "PFC_WD" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        return ""
    }

    action, ok := dbEntry.Field["action"]
    if ok {
        if log.V(3) { 
            log.Info("doGetIntfPfcWdAction   action : ", action)
        }
        return action;
    } else if log.V(3) {
        log.Info("No PFC WD Action Time")
    }

    return ""
}

func doGetIntfPfcWdDetect(d *db.DB, if_name string) (int) {
    if log.V(3) { 
        log.Info("doGetIntfPfcWdDetect     if_name : ", if_name)
    }
    if d == nil {
        log.Infof("unable to get configDB")
        return 0
    }
    dbspec := &db.TableSpec { Name: "PFC_WD" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        return 0
    }

    detectTime, ok := dbEntry.Field["detection_time"]
    if ok && (detectTime != "") {
        if log.V(3) { 
            log.Info("doGetIntfPfcWdDetect  detectTime : ", detectTime)
        }
        value, err := strconv.Atoi(detectTime)
        if err != nil {
            return 0;
        }
        return value;
    } else if log.V(3) {
        log.Info("doGetIntfPfcWdDetect  No PFC WD Detection Time")
    }
    return 0;
}

func doGetIntfPfcWdRestore(d *db.DB, if_name string) (int) {
    if log.V(3) { 
        log.Info("doGetIntfPfcWdRestore    if_name : ", if_name)
    }
    if d == nil {
        log.Infof("unable to get configDB")
        return 0
    }
    dbspec := &db.TableSpec { Name: "PFC_WD" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        return 0
    }

    restoreTime, ok := dbEntry.Field["restoration_time"]
    if ok && (restoreTime != "") {
        if log.V(3) { 
            log.Info("doGetIntfPfcWdRestore restoreTime : ", restoreTime)
        }
        value, err := strconv.Atoi(restoreTime)
        if err != nil {
            return 0;
        }
        return value;
    } else if log.V(3) {
        log.Info("doGetIntfPfcWdRestore  No PFC WD Restoration Time")
    }
    return 0;
}

var DbToYang_qos_intf_pfcwd_st_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    pathInfo := NewPathInfo(inParams.uri)

    ifname := pathInfo.Var("interface-id")
    dbIfName := utils.GetNativeNameFromUIName(&ifname)
    if_name := *dbIfName
    log.Info("DbToYang_qos_intf_pfcwd_st_xfmr  uri : ", inParams.uri, " if_name : ", if_name)
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

    wdObj := pfcObj.Watchdog
    if wdObj == nil {
        return nil
    }
    ygot.BuildEmptyTree(wdObj)

    targetUriPath, _ := getYangPathFromUri(inParams.uri)
    if (targetUriPath == "/openconfig-qos:qos/interfaces/interface/pfc/watchdog") {
        targetUriPath  = "/openconfig-qos:qos/interfaces/interface/openconfig-qos-ext:pfc/watchdog"
    }

    detectTime  := uint32(doGetIntfPfcWdDetect(inParams.d, if_name))
    restoreTime := uint32(doGetIntfPfcWdRestore(inParams.d, if_name))
    actionStr   := doGetIntfPfcWdAction(inParams.d, if_name)

    ygot.BuildEmptyTree(wdObj.Config)
    ygot.BuildEmptyTree(wdObj.State)

    getAction := false
    getDetect := false
    getRestore := false
    if strings.Contains(targetUriPath, "restoration-time") {
        getRestore = true
    } else if strings.Contains(targetUriPath, "detection-time") {
        getDetect = true
    } else if strings.Contains(targetUriPath, "action") {
        getAction = true
    } else {
        getRestore = true
        getDetect = true
        getAction = true
    }

    if getDetect {
        if log.V(3) { 
            log.Info("DbToYang_qos_intf_pfcwd_st_xfmr   detectTime : ", detectTime)
        }
        if detectTime != 0 {
            wdObj.Config.DetectionTime = &detectTime
            wdObj.State.DetectionTime  = &detectTime
        }
    }
    if getRestore {
        if log.V(3) { 
            log.Info("DbToYang_qos_intf_pfcwd_st_xfmr   restoreTime : ", restoreTime)
        }
        if restoreTime != 0 {
            wdObj.Config.RestorationTime = &restoreTime
            wdObj.State.RestorationTime  = &restoreTime
      }
    }

    if getAction {
        if log.V(3) { 
            log.Info("DbToYang_qos_intf_pfcwd_st_xfmr     actionStr : ", actionStr)
        }
        if  actionStr != "" {
            action := ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_UNSET
            if  actionStr == "drop" {
                action = ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_DROP
            } else if actionStr == "forward" {
                action = ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_FORWARD
            } else if actionStr == "alert" {
                action = ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_Watchdog_Config_Action_ALERT
         }
         wdObj.Config.Action = action
         wdObj.State.Action  = action
       }
    }

   return nil
}

func getTheCounter(entry *db.Value, attr string, counter_val *uint64 ) error {
    var ok bool = false
    var err error
    val1, ok := entry.Field[attr]
    if !ok {
        return errors.New("Attr " + attr + "doesn't exist in IF table Map!")
    }

    if len(val1) > 0 {
        v, _ := strconv.ParseUint(val1, 10, 64)
        *counter_val = v
        return nil
    }
    return err
}

func getPfcStats (inParams XfmrParams, ifName string, cos uint8, d *db.DB, stats *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_PfcPriorities_PfcPriority_State_Statistics) (error) {
    if log.V(3) {
      log.Infof("getPfcStats      Intf: %s  CoS: %v", ifName, cos)
    }
    var ifCountInfo db.Value
    var present bool
    var err error
    oidMap, present := inParams.txCache.Load("COUNTERS_PORT_NAME_MAP")
    if !present {
        portOidmapTs := &db.TableSpec{Name: "COUNTERS_PORT_NAME_MAP"}
        ifCountInfo, err = d.GetMapAll(portOidmapTs)
        if err != nil {
            log.Info("getPfcStats    err: ", err)
            return err
        }

        inParams.txCache.Store("COUNTERS_PORT_NAME_MAP", ifCountInfo)
        if log.V(3) {
            log.Info("Loading ifCountInfo ")
        }
    } else {
        ifCountInfo = oidMap.(db.Value)
        if log.V(3) {
            log.Info("Reuse ifCountInfo ")
        }
    }

    var rxCntr uint64;
    var txCntr uint64;
    counters := &db.TableSpec{Name: "COUNTERS"}
    oid := ifCountInfo.Field[ifName]
    if log.V(3) {
       log.Infof("getPfcStats      oid: '%v'", oid)
    }
    entry, err := d.GetEntry(counters, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Info("getPfcStats    err: ", err)
        return err
    }

    field := fmt.Sprintf("SAI_PORT_STAT_PFC_%1d_TX_PKTS", cos)
    getTheCounter(&entry, field, &txCntr)
    field = fmt.Sprintf("SAI_PORT_STAT_PFC_%1d_RX_PKTS", cos)
    getTheCounter(&entry, field, &rxCntr)

    counters = &db.TableSpec{Name: "COUNTERS_BACKUP"}
    entry, err = d.GetEntry(counters, db.Key{Comp: []string{oid}})
    if err == nil {
        var backupCntr uint64;
        field = fmt.Sprintf("SAI_PORT_STAT_PFC_%1d_TX_PKTS", cos)
        getTheCounter(&entry, field, &backupCntr)
        txCntr = txCntr - backupCntr
        field = fmt.Sprintf("SAI_PORT_STAT_PFC_%1d_RX_PKTS", cos)
        getTheCounter(&entry, field, &backupCntr)
        rxCntr = rxCntr - backupCntr
    } else {
        // it is OK that a snapshot does not exist. Just means the counters have not been "cleared"
        err = nil
        if log.V(3) {
           log.Info("getPfcStats      counter snapshot does not exist.")
        }
    }

    stats.PauseFramesRx = &rxCntr
    stats.PauseFramesTx = &txCntr

    return err
}

func getPfcQueueStats (inParams XfmrParams, ifName string, queue uint8, d *db.DB, stats *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_PfcQueue_PfcQueue_Statistics) (error) {

    log.V(3).Infof("getPfcQueue      Intf: %s  Queue: %v", ifName, queue)
    qCounterKey := ifName + ":" + strconv.FormatUint(uint64(queue), 10)
    log.V(3).Info("getPfcQueue   qCounterKey:", qCounterKey)
    var queueCountInfo db.Value
    var present bool
    var err error
    oidMap, present := inParams.txCache.Load("COUNTERS_QUEUE_NAME_MAP")
    if !present {
        queueOidMapTs := &db.TableSpec{Name: "COUNTERS_QUEUE_NAME_MAP"}
        queueCountInfo, err = d.GetMapAll(queueOidMapTs)
        if err != nil {
            log.Info("getPfcQueue    err: ", err)
            return err
        }

        inParams.txCache.Store("COUNTERS_QUEUE_NAME_MAP", queueCountInfo)
        log.V(3).Info("Loading queueCountInfo")
    } else {
        queueCountInfo = oidMap.(db.Value)
        log.V(3).Info("Reuse queueCountInfo ")
    }

    oid := queueCountInfo.Field[qCounterKey]
    log.V(3).Info("getPfcQueue      oid :", oid)

    counters := &db.TableSpec{Name: "COUNTERS"}
    entry, err := d.GetEntry(counters, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Info("getPfcQueue    err: ", err)
        return err
    }

    var rxDropsCntr uint64;
    var rxDropsLastCntr uint64;
    var rxPacketsCntr uint64;
    var rxPacketsLastCntr uint64;
    var stormDetectCntr uint64;
    var stormRestoreCntr uint64;
    var txDropsCntr uint64;
    var txDropsLastCntr uint64;
    var txPacketsCntr uint64;
    var txPacketsLastCntr uint64;

    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_DEADLOCK_DETECTED", &stormDetectCntr)
    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_DEADLOCK_RESTORED", &stormRestoreCntr)

    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_RX_DROPPED_PACKETS", &rxDropsCntr)
    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_RX_DROPPED_PACKETS_LAST", &rxDropsLastCntr)
    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_RX_PACKETS", &rxPacketsCntr)
    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_RX_PACKETS_LAST", &rxPacketsLastCntr)

    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_TX_DROPPED_PACKETS", &txDropsCntr)
    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_TX_DROPPED_PACKETS_LAST", &txDropsLastCntr)
    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_TX_PACKETS", &txPacketsCntr)
    getTheCounter(&entry, "PFC_WD_QUEUE_STATS_TX_PACKETS_LAST", &txPacketsLastCntr)

    stats.RxDrop = &rxDropsCntr
    stats.RxDropLast = &rxDropsLastCntr
    stats.RxOk = &rxPacketsCntr
    stats.RxOkLast = &rxPacketsLastCntr
    stats.TxDrop = &txDropsCntr
    stats.TxDropLast = &txDropsLastCntr
    stats.TxOk = &txPacketsCntr
    stats.TxOkLast = &txPacketsLastCntr
    stats.StormDetected = &stormDetectCntr
    stats.StormRestored = &stormRestoreCntr

    return err
}

var DbToYang_qos_intf_pfc_counters_st_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
  var err error
  pathInfo := NewPathInfo(inParams.uri)
  ifname := pathInfo.Var("interface-id")
  dbIfName := utils.GetNativeNameFromUIName(&ifname)
  if_name := *dbIfName
  log.Info("DbToYang_qos_intf_pfc_counters_st_xfmr: uri: ", inParams.uri, " if_name ", if_name)
  dot1p  := pathInfo.Var("dot1p")
  cos32, _ := strconv.Atoi(dot1p)
  cos := uint8(cos32)
  qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
  if qosIntfsObj == nil {
      return nil
  }

  intfObj, ok := qosIntfsObj.Interface[ifname]
  if !ok {
      return nil
  }

  prioObj, ok := intfObj.Pfc.PfcPriorities.PfcPriority[cos]
  if !ok {
      return nil
  }

  statsObj := prioObj.State.Statistics
  if statsObj == nil {
      return nil
  }

  ygot.BuildEmptyTree(statsObj)

  err = getPfcStats(inParams,if_name, cos, inParams.dbs[db.CountersDB], statsObj)

  return err
}

var DbToYang_qos_intf_pfc_queue_counters_st_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
  var err error

  pathInfo := NewPathInfo(inParams.uri)
  ifname := pathInfo.Var("interface-id")
  dbIfName := utils.GetNativeNameFromUIName(&ifname)
  if_name := *dbIfName
  log.Info("DbToYang_qos_intf_pfc_queue_counters_st_xfmr: uri: ", inParams.uri," if_name ", if_name)
  queue  := pathInfo.Var("queue")
  queue32, _ := strconv.Atoi(queue)
  que := uint8(queue32)

  qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
  if qosIntfsObj == nil {
      return nil
  }

  intfObj, ok := qosIntfsObj.Interface[ifname]
  if !ok {
      return nil
  }

  queueObj, ok := intfObj.Pfc.PfcQueue.PfcQueue[que]
  if !ok {
      return nil
  }

  statsObj := queueObj.Statistics
  if statsObj == nil {
      return nil
  }

  ygot.BuildEmptyTree(statsObj)

  err = getPfcQueueStats(inParams, if_name, que, inParams.dbs[db.CountersDB], statsObj)

  return err
}

/* Reset counter values in COUNTERS_BACKUP table for given OID */
func resetPfcQueueCounters(d *db.DB, oid string) (error,error) {
    var verr,cerr error
    CountrTblTs := db.TableSpec {Name: "COUNTERS"}
    CountrTblTsCp := db.TableSpec { Name: "COUNTERS_BACKUP" }
    value, verr := d.GetEntry(&CountrTblTs, db.Key{Comp: []string{oid}})
    if verr == nil {
        secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        cerr = d.CreateEntry(&CountrTblTsCp, db.Key{Comp: []string{oid}}, value)
    }
    return verr, cerr
}

func resetPfcInterfaceQueueCounters(inputStr string, dbs [db.MaxDB]*db.DB) (string, error) {
    var     err  error
    var     errString   string
    log.Info("resetPfcInterfaceQueueCounters - Clear counters for given interface name: ", inputStr)

    queueOidMapTs := &db.TableSpec{Name: "COUNTERS_QUEUE_NAME_MAP"}
    queueCountInfo, err := dbs[db.CountersDB].GetMapAll(queueOidMapTs)
    if err != nil {
        log.Info("resetPfcInterfaceQueueCounters    err: ", err)
        errString = fmt.Sprintf("Error: Could not retreive queue counter names for %s", inputStr)
        return errString, err
    }

    ok, id := getIdFromIntfName(&inputStr) ; if !ok {
        log.Info("resetPfcInterfaceQueueCounters    Invalid Interface format")
        err = tlerr.InvalidArgsError{Format:"Invalid Interface"}
        errString = fmt.Sprintf("Error: Clear PFC Counters not supported for %s", inputStr)
        return errString, err
    }
    if strings.HasPrefix(inputStr, "Ethernet") {
        inputStr = "Ethernet" + id
    } else {
        log.Info("resetPfcInterfaceQueueCounters    Invalid Interface")
        err = tlerr.InvalidArgsError{Format:"Invalid Interface"}
        errString = fmt.Sprintf("Error: Clear PFC Counters not supported for %s", inputStr)
        return errString, err
    }

    for queue, oid := range queueCountInfo.Field {
        if strings.HasPrefix(queue, inputStr) {
            verr, cerr := resetPfcQueueCounters(dbs[db.CountersDB], oid)
                    
            if verr != nil {
                errString = fmt.Sprintf("Error: Failed to get counter values from COUNTERS table for %s", inputStr)
                return errString, verr
            }
            if cerr != nil {
                log.Info("Failed to reset counters values")
                errString = fmt.Sprintf("Error: Failed to reset counters values for %s.", inputStr)
                return errString, cerr
            }
        }
    }

    return "No Error", err
}

var rpc_clear_qos_pfc RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var     err         error
    var     errString   string
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string`json:"status-detail"`
        } `json:"sonic-qos-pfc:output"`
    }
    log.Info("rpc_clear_qos_pfc:")

    result.Output.Status = 1
    /* Get input data */
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        result.Output.Status_detail = "Error: Failed to unmarshall given input data"
        return json.Marshal(&result)
    }

    input := mapData["sonic-qos-pfc:input"]
    mapData = input.(map[string]interface{})
    input = mapData["interface-param"]
    input_str := fmt.Sprintf("%v", input)
    sonicName := utils.GetNativeNameFromUIName(&input_str)
    input_str = *sonicName

    portOidmapTs := &db.TableSpec{Name: "COUNTERS_PORT_NAME_MAP"}
    ifCountInfo, err := dbs[db.CountersDB].GetMapAll(portOidmapTs)
    if err != nil {
        result.Output.Status_detail = "Error: Port-OID (Counters) get for all the interfaces failed!"
        return json.Marshal(&result)
    }

    if (input_str == "all") || (input_str == "Ethernet") {
        log.Info("rpc_clear_qos_pfc : Reset counters for Ethernet interface type")
        for  intf := range ifCountInfo.Field {
            if strings.HasPrefix(intf, "Ethernet") {
                errString, err = resetPfcInterfaceQueueCounters(intf, dbs)
                if err != nil {
                    log.Info(errString)
                    result.Output.Status_detail = errString
                    return json.Marshal(&result)
                }
            }
        }
    } else {
        errString, err = resetPfcInterfaceQueueCounters(input_str, dbs)
        if err != nil {
            log.Info(errString)
            result.Output.Status_detail = errString
            return json.Marshal(&result)
        }
    }

    result.Output.Status = 0
    result.Output.Status_detail = "Success: PFC Watchdog Counters Cleared"
    return json.Marshal(&result)
}
