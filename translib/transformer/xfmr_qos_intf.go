package transformer

import (
    "strings"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
)
func init () {
    XlateFuncBind("YangToDb_qos_intf_sched_policy_xfmr", YangToDb_qos_intf_sched_policy_xfmr)
    XlateFuncBind("DbToYang_qos_intf_sched_policy_xfmr", DbToYang_qos_intf_sched_policy_xfmr)
}


func getSchedulerIds(sp_name string) ([]string, error) { 
    var sched_ids []string

    d, err := db.NewDB(getDBOptions(db.ConfigDB))

    if err != nil {
        log.Infof("getSchedulerIds, unable to get configDB, error %v", err)
        return sched_ids, err
    }


    defer d.DeleteDB()

    ts := &db.TableSpec{Name: "SCHEDULER"}
    keys, err := d.GetKeys(ts)
    for  _, key := range keys {
        if len(key.Comp) < 1 {
            continue
        }

        key0 := key.Get(0)
        log.Info("Key0 : ", key0)

        log.Info("Current key comp[0]: ", key.Comp[0])
        var spname string;
        var spseq string;

        if strings.Contains(key.Comp[0], "@") {
            s := strings.Split(key.Comp[0], "@")
            spname = s[0]
            spseq = s[1]
        } else {
            spname = key.Comp[0]
            spseq = "0"
        }
        log.Infof("sp_name %v spname %v spseq %v", sp_name, spname, spseq)
        if strings.Compare(sp_name, spname) == 0 {
            log.Infof("Add sp_name %v spname %v spseq %v", sp_name, spname, spseq)
            sched_ids = append(sched_ids, spseq)
        }
    }

    log.Info("sp_name: ", sp_name, "sched_ids: ", sched_ids)
    return sched_ids, err
}


var YangToDb_qos_intf_sched_policy_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("YangToDb_qos_intf_sched_policy_xfmr: ", inParams.ygRoot, inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    if_name := pathInfo.Var("interface-id")

    // For "no scheduler-policy"
    if inParams.oper == DELETE {
        return qos_intf_sched_policy_delete(inParams, if_name)
    }

    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    if qosIntfsObj == nil {
        return res_map, err
    }

    intfObj, ok := qosIntfsObj.Interface[if_name]
    if !ok {
        return res_map, err
    }

    outputObj := intfObj.Output
    if outputObj == nil {
        return res_map, err
    }

    sched_pol := outputObj.SchedulerPolicy
    if sched_pol == nil {
        return res_map, err
    }

    config := sched_pol.Config
    if config == nil {
        return res_map, err
    }

    sp_name := config.Name

    sp_name_str := *sp_name

    log.Info("YangToDb: sp_name: ", *sp_name)

    queueTblMap := make(map[string]db.Value)
    portQosTblMap := make(map[string]db.Value)
    log.Info("YangToDb_qos_intf_sched_policy_xfmr: ", inParams.ygRoot, inParams.uri)

    // read scheduler policy and its schedulers (seq).
    scheduler_ids, _ := getSchedulerIds(sp_name_str)

    // Use "if_name:seq" to form DB key for QUEUE or "if_name" as key for PORT, write "if_name@seq" as its scheduler profile
    for _, seq := range scheduler_ids {
        key := if_name
        if seq != SCHEDULER_PORT_SEQUENCE {
            key = key + "|" + seq
            qKey := if_name + ":" + seq
            err = validateQosConfigQueue(inParams, qKey)
            if err != nil {
                log.Infof("YangToDb_qos_scheduler_xfmr --> sequence: %v in sp_name %v is not valid for interface: %v",
                seq, sp_name_str, qKey)
                continue
            }
        }
        db_sp_name := sp_name_str + "@" + seq
        log.Infof("YangToDb_qos_intf_sched_policy_xfmr --> key: %v, db_sp_name: %v", key, db_sp_name)

        pTbl := &queueTblMap
        if  seq == SCHEDULER_PORT_SEQUENCE {
            pTbl = &portQosTblMap
        }

        _, ok := (*pTbl)[key]
        if !ok {
            (*pTbl)[key] = db.Value{Field: make(map[string]string)}
        }
        (*pTbl)[key].Field["scheduler"] = StringToDbLeafref(db_sp_name, "SCHEDULER")
    }

    res_map["QUEUE"] = queueTblMap
    res_map["PORT_QOS_MAP"] = portQosTblMap

    log.Info("res_map: ", res_map)

    log.Info("YangToDb_qos_intf_sched_policy_xfmr: End ", inParams.ygRoot, inParams.uri)
    return res_map, err

}

// return the first matching INTF Queue or PORT_QOS_MAP entry with a valid Schedule Policy 
func doGetIntfSchedulerPolicy(d *db.DB, if_name string) (string) {

    log.Info("doGetIntfSchedulerPolicy: if_name ", if_name)

    if d == nil {
        log.Infof("unable to get configDB")
        return ""
    }

    // QUEUE or PORT_QOS_MAP
    tbl_list := []string{"QUEUE", "PORT_QOS_MAP"}
    for _, tbl_name := range tbl_list {
        dbSpec := &db.TableSpec{Name: tbl_name}

        keys, _ := d.GetKeys(dbSpec)
        log.Info("keys: ", keys)
        for  _, key := range keys {
            if len(key.Comp) < 1 {
                continue
            }

            s := strings.Split(key.Comp[0], "|")

            if strings.Compare(if_name, s[0]) == 0 {
                qCfg, _ := d.GetEntry(dbSpec, key) 
                log.Info("current entry: ", qCfg)
                sched, ok := qCfg.Field["scheduler"] 
                log.Info("sched: ", sched)
                if ok {
                    sched = DbLeafrefToString(sched, "SCHEDULER")
                    sp := strings.Split(sched, "@")
                    log.Info("sp[0]: ", sp[0]);
                    return sp[0]
                }
            }
        }
    }

    return ""
}


func qos_intf_sched_policy_delete(inParams XfmrParams, if_name string) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("os_intf_sched_policy_delete: ", inParams.ygRoot, inParams.uri)

    queueTblMap := make(map[string]db.Value)
    portQosTblMap := make(map[string]db.Value)
    pTbl := &queueTblMap

    d :=  inParams.d
    if d == nil  {
        log.Infof("unable to get configDB")
        return res_map, err
    }

    // QUEUE or PORT_QOS_MAP
    tbl_list := []string{"QUEUE", "PORT_QOS_MAP"}
    var port_sched bool
    var queue_sched bool

    for _, tbl_name := range tbl_list {
        dbSpec := &db.TableSpec{Name: tbl_name}

        if tbl_name == "PORT_QOS_MAP" {
            pTbl = &portQosTblMap
        } else {
            pTbl = &queueTblMap
        }

        keys, _ := d.GetKeys(dbSpec)
        log.Info("keys: ", keys)
        for  _, key := range keys {
            if len(key.Comp) < 1 {
                continue
            }

            s := strings.Split(key.Comp[0], "|")

            if strings.Compare(if_name, s[0]) == 0 {
                qCfg, _ := d.GetEntry(dbSpec, key) 
                log.Info("current entry: ", qCfg)
                _, ok := qCfg.Field["scheduler"] 
                if ok {
                    // find a entry with a scheduler config, to be deleted
                    new_key := key.Comp[0]
                    if tbl_name == "QUEUE" {
                        new_key = new_key + "|" +  key.Comp[1]
                        queue_sched = true
                    } else {
                        port_sched = true
                    }
                    log.Info("new key in rtTbl: ", new_key)
                    _, ok := (*pTbl)[new_key]
                    if !ok {
                        (*pTbl)[new_key] = db.Value{Field: make(map[string]string)}
                    }
                    (*pTbl)[new_key].Field["scheduler"] = ""
                }
            }
        }
    }

    if queue_sched == true {
        res_map["QUEUE"] = queueTblMap
    }
    if port_sched == true {
        res_map["PORT_QOS_MAP"] = portQosTblMap
    }

    log.Info("res_map: ", res_map)

    log.Info("os_intf_sched_policy_delete: End ", inParams.ygRoot, inParams.uri)
    return res_map, err

}

var DbToYang_qos_intf_sched_policy_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    log.Info("DbToYang_qos_intf_sched_policy_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    intfName := pathInfo.Var("interface-id")

    log.Info("inParams: ", inParams)

    sp := doGetIntfSchedulerPolicy(inParams.d, intfName)

    if strings.Compare(sp, "") == 0 {
        log.Info("No scheduler policy found on this interface")
        return nil
    }

    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)

    if qosIntfsObj == nil {
        ygot.BuildEmptyTree(qosIntfsObj)
    }

    var intfObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface
    if qosIntfsObj != nil && qosIntfsObj.Interface != nil && len(qosIntfsObj.Interface) > 0 {
        var ok bool = false
        if intfObj, ok = qosIntfsObj.Interface[intfName]; !ok {
            intfObj, _ = qosIntfsObj.NewInterface(intfName)
        }
        ygot.BuildEmptyTree(intfObj)
        intfObj.InterfaceId = &intfName

        if intfObj.Output == nil {
            ygot.BuildEmptyTree(intfObj.Output)
        }

    } else {
        ygot.BuildEmptyTree(qosIntfsObj)
        intfObj, _ = qosIntfsObj.NewInterface(intfName)
        ygot.BuildEmptyTree(intfObj)
        intfObj.InterfaceId = &intfName

        if intfObj.Output == nil {
            ygot.BuildEmptyTree(intfObj.Output)
        }
    }

    ygot.BuildEmptyTree(intfObj.Output.SchedulerPolicy)
    spObj := intfObj.Output.SchedulerPolicy
    if spObj == nil {
        ygot.BuildEmptyTree(spObj)
    }

    spObjCfg := spObj.Config
    if spObjCfg == nil {
        ygot.BuildEmptyTree(spObjCfg)
    }
    spObjState := spObj.State
    if spObjState == nil {
        ygot.BuildEmptyTree(spObjState)
    }

    spObjCfg.Name = &sp;
    spObjState.Name = &sp;
    log.Info("Done fetching interface scheduler policy: ", sp)
    log.Info("intfObj.InterfaceId / spObjCfg.Name: ", *intfObj.InterfaceId, " ", *spObjCfg.Name)

    return nil
}


