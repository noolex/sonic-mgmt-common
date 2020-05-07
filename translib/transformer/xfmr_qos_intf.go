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

        s := strings.Split(key.Comp[0], "@")


        if strings.Compare(sp_name, s[0]) == 0 {
            sched_ids = append(sched_ids, s[1])
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
	log.Info("YangToDb_qos_intf_sched_policy_xfmr: ", inParams.ygRoot, inParams.uri)

    // For "no scheduler-policy", fill the current sp_name of the interface
    if inParams.oper == DELETE {
        sp_name_str = doGetIntfQueueSchedulerPolicy(inParams.dbs[db.ConfigDB], if_name)

        if strings.Compare(sp_name_str, "") == 0 {
            log.Info("No scheduler policy found on this interface")
            return res_map, err 
        }
    }

    // read scheduler policy and its schedulers (seq).
    scheduler_ids, _ := getSchedulerIds(sp_name_str)

    // Use "if_name:seq" to form DB key for QUEUE, write "if_name@seq" as its scheduler profile
    for _, seq := range scheduler_ids {
        queueKey := if_name + "|" + seq
        db_sp_name := sp_name_str + "@" + seq
		log.Infof("YangToDb_qos_intf_sched_policy_xfmr --> key: %v, db_sp_name: %v", queueKey, db_sp_name)

        _, ok := queueTblMap[queueKey]
	    if !ok {
	        queueTblMap[queueKey] = db.Value{Field: make(map[string]string)}
	    }
	    queueTblMap[queueKey].Field["scheduler"] = db_sp_name
	}

	res_map["QUEUE"] = queueTblMap

    log.Info("res_map: ", res_map)

    log.Info("YangToDb_qos_intf_sched_policy_xfmr: End ", inParams.ygRoot, inParams.uri)
	return res_map, err

}

func doGetIntfQueueSchedulerPolicy(d *db.DB, if_name string) (string) {

    log.Info("doGetIntfQueueSchedulerPolicy: if_name ", if_name)

    var err error
    if d == nil {
        d, err = db.NewDB(getDBOptions(db.ConfigDB))
        if err != nil {
            log.Infof("unable to get configDB, error %v", err)
            return ""
        }
    }

    // QUEUE
    dbSpec := &db.TableSpec{Name: "QUEUE"}

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
                sp := strings.Split(sched, "@")
                log.Info("sp[0]: ", sp[0]);
                return sp[0]
            }
        }
    }

    return ""
}


var DbToYang_qos_intf_sched_policy_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    log.Info("DbToYang_qos_intf_sched_policy_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    intfName := pathInfo.Var("interface-id")

    log.Info("inParams: ", inParams)

    sp := doGetIntfQueueSchedulerPolicy(inParams.dbs[db.ConfigDB] , intfName)

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

    spObj := intfObj.Output.SchedulerPolicy
    if spObj == nil {
        ygot.BuildEmptyTree(spObj)
    }

    spObjCfg := spObj.Config
    if spObjCfg == nil {
        ygot.BuildEmptyTree(spObjCfg)
    }

    spObjCfg.Name = &sp;
    log.Info("Done fetching interface scheduler policy: ", sp)
    log.Info("intfObj.InterfaceId / spObjCfg.Name: ", *intfObj.InterfaceId, " ", *spObjCfg.Name)

    return nil
}


