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
)
 
func init() {
  XlateFuncBind("YangToDb_flex_counter_key_xfmr",               YangToDb_flex_counter_key_xfmr)
  XlateFuncBind("DbToYang_flex_counter_key_xfmr",               DbToYang_flex_counter_key_xfmr)

  XlateFuncBind("YangToDb_poll_interval_key_xfmr",              YangToDb_poll_interval_key_xfmr)

  XlateFuncBind("YangToDb_counter_poll_fld_xfmr",               YangToDb_counter_poll_fld_xfmr)
  XlateFuncBind("DbToYang_counter_poll_fld_xfmr",               DbToYang_counter_poll_fld_xfmr)

  XlateFuncBind("YangToDb_qos_intf_pfcwd_st_xfmr",              YangToDb_qos_intf_pfcwd_st_xfmr)
  XlateFuncBind("DbToYang_qos_intf_pfcwd_st_xfmr",              DbToYang_qos_intf_pfcwd_st_xfmr)

  XlateFuncBind("YangToDb_qos_intf_pfcwd_action_fld_xfmr",      YangToDb_qos_intf_pfcwd_action_fld_xfmr)
  XlateFuncBind("DbToYang_qos_intf_pfcwd_action_fld_xfmr",      DbToYang_qos_intf_pfcwd_action_fld_xfmr)

  XlateFuncBind("DbToYang_qos_intf_pfc_counters_st_xfmr",       DbToYang_qos_intf_pfc_counters_st_xfmr)

  XlateFuncBind("DbToYang_qos_intf_pfc_queue_counters_st_xfmr", DbToYang_qos_intf_pfc_queue_counters_st_xfmr)
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

var YangToDb_qos_intf_pfcwd_st_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    log.Info("YangToDb_qos_intf_pfcwd_st_xfmr            uri : ", inParams.uri)

    var err error
    res_map := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)

    ifname := pathInfo.Var("interface-id")
    db_if_name := utils.GetNativeNameFromUIName(&ifname)
    if_name := *db_if_name
    log.Info("YangToDb_qos_intf_pfcwd_st_xfmr         ifname :", ifname)

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
    log.Info("doGetIntfPfcWdAction   if_name : ", if_name)

    if d == nil {
        log.Infof("unable to get configDB")
        return ""
    }
    dbspec := &db.TableSpec { Name: "PFC_WD" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        log.Error("No Entry found e = ", err)
        return ""
    }

    action, ok := dbEntry.Field["action"]
    if ok {
        log.Info("doGetIntfPfcWdAction   action : ", action)
        return action;
    } else {
        log.Info("No PFC WD Action Time")
    }

    return ""
}

func doGetIntfPfcWdDetect(d *db.DB, if_name string) (int) {
    log.Info("doGetIntfPfcWdDetect     if_name : ", if_name)

    if d == nil {
        log.Infof("unable to get configDB")
        return 0
    }
    dbspec := &db.TableSpec { Name: "PFC_WD" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        log.Error("No Entry found e = ", err)
        return 0
    }

    detectTime, ok := dbEntry.Field["detection_time"]
    if ok && (detectTime != "") {
        log.Info("doGetIntfPfcWdDetect  detectTime : ", detectTime)
        value, err := strconv.Atoi(detectTime)
        if err != nil {
            return 0;
        }
        return value;
    } else {
        log.Info("doGetIntfPfcWdDetect  No PFC WD Detection Time")
    }
    return 0;
}

func doGetIntfPfcWdRestore(d *db.DB, if_name string) (int) {
    log.Info("doGetIntfPfcWdRestore    if_name : ", if_name)

    if d == nil {
        log.Infof("unable to get configDB")
        return 0
    }
    dbspec := &db.TableSpec { Name: "PFC_WD" }

    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{if_name}})
    if err != nil {
        log.Error("No Entry found e = ", err)
        return 0
    }

    restoreTime, ok := dbEntry.Field["restoration_time"]
    if ok && (restoreTime != "") {
        log.Info("doGetIntfPfcWdRestore restoreTime : ", restoreTime)
        value, err := strconv.Atoi(restoreTime)
        if err != nil {
            return 0;
        }
        return value;
    } else {
        log.Info("doGetIntfPfcWdRestore  No PFC WD Restoration Time")
    }
    return 0;
}

var DbToYang_qos_intf_pfcwd_st_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    log.Info("DbToYang_qos_intf_pfcwd_st_xfmr       uri : ", inParams.uri)

    pathInfo := NewPathInfo(inParams.uri)

    ifname := pathInfo.Var("interface-id")
    dbIfName := utils.GetNativeNameFromUIName(&ifname)
    if_name := *dbIfName
    log.Info("DbToYang_qos_intf_pfcwd_st_xfmr   if_name : ", if_name)

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
        log.Info("DbToYang_qos_intf_pfcwd_st_xfmr   detectTime : ", detectTime)
        if detectTime != 0 {
            wdObj.Config.DetectionTime = &detectTime
            wdObj.State.DetectionTime  = &detectTime
        }
    }
    if getRestore {
        log.Info("DbToYang_qos_intf_pfcwd_st_xfmr   restoreTime : ", restoreTime)
        if restoreTime != 0 {
            wdObj.Config.RestorationTime = &restoreTime
            wdObj.State.RestorationTime  = &restoreTime
      }
    }

    if getAction {
        log.Info("DbToYang_qos_intf_pfcwd_st_xfmr     actionStr : ", actionStr)
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

func getPfcStats (ifName string, cos uint8, d *db.DB, stats *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_PfcPriorities_PfcPriority_State_Statistics) (error) {
    log.Infof("getPfcStats      Intf: %s  CoS: %v", ifName, cos)

    portOidmapTs := &db.TableSpec{Name: "COUNTERS_PORT_NAME_MAP"}
    ifCountInfo, err := d.GetMapAll(portOidmapTs)
    if err != nil {
        log.Info("getPfcStats    err: ", err)
        return err
    }

    var rxCntr uint64;
    var txCntr uint64;
    counters := &db.TableSpec{Name: "COUNTERS"}
    oid := ifCountInfo.Field[ifName]
    entry, err := d.GetEntry(counters, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Info("getPfcStats    err: ", err)
        return err
    }

    field := fmt.Sprintf("SAI_PORT_STAT_PFC_%1d_TX_PKTS", cos)
    getTheCounter(&entry, field, &txCntr)
    field = fmt.Sprintf("SAI_PORT_STAT_PFC_%1d_RX_PKTS", cos)
    getTheCounter(&entry, field, &rxCntr)

    stats.PauseFramesRx = &rxCntr
    stats.PauseFramesTx = &txCntr

    return err
}

func getPfcQueueStats (ifName string, queue uint8, d *db.DB, stats *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Pfc_PfcQueue_PfcQueue_Statistics) (error) {
    log.Infof("getPfcQueue      Intf: %s  Queue: %v", ifName, queue)

    qCounterKey := ifName + ":" + strconv.FormatUint(uint64(queue), 10)
    log.Info("getPfcQueue   qCounterKey:", qCounterKey)

    queueOidMapTs := &db.TableSpec{Name: "COUNTERS_QUEUE_NAME_MAP"}
    queueCountInfo, err := d.GetMapAll(queueOidMapTs)
    if err != nil {
        log.Info("getPfcQueue    err: ", err)
        return err
    }

    counters := &db.TableSpec{Name: "COUNTERS"}
    oid := queueCountInfo.Field[qCounterKey]
    log.Info("getPfcQueue      oid :", oid)
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
  log.Info("DbToYang_qos_intf_pfc_counters_st_xfmr       uri: ", inParams.uri)

  var err error

  pathInfo := NewPathInfo(inParams.uri)
  ifname := pathInfo.Var("interface-id")
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

  err = getPfcStats(ifname, cos, inParams.dbs[db.CountersDB], statsObj)

  return err
}

var DbToYang_qos_intf_pfc_queue_counters_st_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
  log.Info("DbToYang_qos_intf_pfc_queue_counters_st_xfmr       uri: ", inParams.uri)

  var err error

  pathInfo := NewPathInfo(inParams.uri)
  ifname := pathInfo.Var("interface-id")
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

  err = getPfcQueueStats(ifname, que, inParams.dbs[db.CountersDB], statsObj)

  return err
}
