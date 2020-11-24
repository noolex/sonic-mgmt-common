package transformer

import (
    "strings"
    "strconv"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)
func init () {
    XlateFuncBind("YangToDb_qos_scheduler_xfmr", YangToDb_qos_scheduler_xfmr)
    XlateFuncBind("DbToYang_qos_scheduler_xfmr", DbToYang_qos_scheduler_xfmr)
    XlateFuncBind("Subscribe_qos_scheduler_xfmr", Subscribe_qos_scheduler_xfmr)

}

const (
    SCHEDULER_PORT_SEQUENCE string = "255"
    SCHEDULER_MIN_RATE_BPS uint64 =  4000
    SCHEDULER_MIN_BURST_BYTES int =  250
    SCHEDULER_MAX_BURST_BYTES int =  125000000
    SCHEDULER_MAX_RATE_PPS uint64 =  100000
    SCHEDULER_MAX_BURST_PACKETS int =  100000
)

var Subscribe_qos_scheduler_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    print ("targetUriPath:", targetUriPath)

    seq := pathInfo.Var("sequence")
    if seq == "" {
        seq = "*"
    }

    name   :=  pathInfo.Var("name")

    result.dbDataMap = make(RedisDbMap)
    log.Info("XfmrSubscribe_qos_scheduler_xfmr")
    result.dbDataMap = RedisDbMap{db.ConfigDB:{"SCHEDULER":{name+"@"+seq:{}}}}  // tablename & table-idx for the inParams.uri
    result.needCache = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    log.Info("Returning Subscribe_qos_scheduler_xfmr")
    return result, err
}

func getQueuesBySchedulerName(scheduler string) ([]string) {
    var s []string

    log.Info("scheduler_name ", scheduler)

    d, err := db.NewDB(getDBOptions(db.ConfigDB))
    if err != nil {
        log.Infof("getQueuesBySchedulerName, unable to get configDB, error %v", err)
        return s
    }

    defer d.DeleteDB()
    // QUEUE
    dbSpec := &db.TableSpec{Name: "QUEUE"}

    keys, _ := d.GetKeys(dbSpec)
    for _, key := range keys {
        log.Info("key: ", key)
        qCfg, _ := d.GetEntry(dbSpec, key)
        log.Info("qCfg: ", qCfg)
        sched, ok := qCfg.Field["scheduler"]
        if !ok {
            continue
        }
        log.Info("scheduler: ", sched)

        sched = strings.Trim(sched, "[]")

        if sched == scheduler {
            intf_name := key.Get(0)
            qid := key.Get(1)
            queue_name := intf_name + "|" + qid

            log.Info("queue_name added to the referenece list: ", queue_name)

            s = append(s, queue_name)
        }
    }

    return s
}

func getIntfsBySchedulerName(scheduler string) ([]string) {
    var s []string

    log.Info("scheduler_name ", scheduler)

    d, err := db.NewDB(getDBOptions(db.ConfigDB))
    if err != nil {
        log.Infof("getIntfsBySchedulerName, unable to get configDB, error %v", err)
        return s
    }
	defer d.DeleteDB()

    dbSpec := &db.TableSpec{Name: "PORT_QOS_MAP"}

    keys, _ := d.GetKeys(dbSpec)
    for _, key := range keys {
        log.Info("key: ", key)
        qCfg, _ := d.GetEntry(dbSpec, key)
        log.Info("qCfg: ", qCfg)
        sched, ok := qCfg.Field["scheduler"]
        if !ok {
            continue
        }
        log.Info("scheduler: ", sched)

        if sched == scheduler {
            intf_name := key.Get(0)

            log.Info("intf_name added to the referenece list: ", intf_name)

            s = append(s, intf_name)
        }
    }

    return s
}


func getIntfsBySPName(sp_name string) ([]string) {
    var s []string

    log.Info("sp_name ", sp_name)

    d, err := db.NewDB(getDBOptions(db.ConfigDB))
    if err != nil {
        log.Infof("getIntfsBySPName, unable to get configDB, error %v", err)
        return s
    }

	defer d.DeleteDB()


    // QUEUE & PORT_QOS_MAP
    tbl_list := []string{"QUEUE", "PORT_QOS_MAP"}

    for  _, tbl_name := range tbl_list {
        dbSpec := &db.TableSpec{Name: tbl_name}

        keys, _ := d.GetKeys(dbSpec)
        for _, key := range keys {
            qCfg, _ := d.GetEntry(dbSpec, key)
            sched , ok := qCfg.Field["scheduler"]
            if !ok {
                continue
            }

            sched = DbLeafrefToString(sched, "SCHEDULER")

            str := strings.Split(sched, "@")

            if str[0] == sp_name {
                intf_name := key.Get(0)

                s = append(s, intf_name)
            }
        }
    }

    return s
}

func isSchedulerPolicyInUse(sp_name string)(bool) {
    // read intfs refering to the scheduler profile
    intfs := getIntfsBySPName(sp_name)
    if  len(intfs) == 0 {
        log.Info("No active user of the scheduler policy: ", sp_name)
        return false
    }

    log.Info("scheduler policy is in use: ", sp_name)
    return true
}

func isLastSchedulerInActivePolicy(sched_name string) (bool) {
    s := strings.Split(sched_name, "@")
    if len(s) < 2 {
        log.Info("sched_name error: ", sched_name)
        return false
    }

    // read intfs refering to the scheduler profile
    intfs := getIntfsBySPName(s[0])
    if  len(intfs) == 0 {
        log.Info("No active user of the scheduler policy", s[0])
        return false
    }

    // read schedulers in the scheduler profile
    sched_ids, _ := getSchedulerIds(s[0])
    for _, sched_id := range sched_ids {
        if s[1] != sched_id {
            log.Info("found extra scheduler in the same policy ", s[1])
            return false
        }
    }

    log.Info("Last scheduler in the same policy!")
    return true
}

func isLastSchedulerField(sched_key string, attr string) (bool) {

    d, err := db.NewDB(getDBOptions(db.ConfigDB))

    if err != nil {
        log.Infof("isLastSchedulerField, unable to get configDB, error %v", err)
        return false
    }


    defer d.DeleteDB()

    ts := &db.TableSpec{Name: "SCHEDULER"}
    entry, err := d.GetEntry(ts, db.Key{Comp: []string{sched_key}})

    if err != nil {
        log.Info("err in getting sp entry: ", sched_key)
        return false
    }

    if len(entry.Field) == 1 {
        _, ok := entry.Field[attr]
        return ok
    }

    return false
}

func isLastSchedulerFields(sched_key string, attrs []string) (bool) {

    d, err := db.NewDB(getDBOptions(db.ConfigDB))

    if err != nil {
        log.Infof("isLastSchedulerFields, unable to get configDB, error %v", err)
        return false
    }


    defer d.DeleteDB()

    ts := &db.TableSpec{Name: "SCHEDULER"}
    entry, err := d.GetEntry(ts, db.Key{Comp: []string{sched_key}})

    if err != nil {
        log.Info("err in getting sp entry: ", sched_key)
        return false
    }

    for _, field := range entry.Field {
        log.Info("containing field: ", field)

        found := false
        for _, attr := range attrs {
            if field == attr {
                found = true
                break
            }
        }
        if !found {
            // entry has extra field other than the queries fields
            return false
        }
    }

    return true
}

func get_schedulers_by_sp_name(sp_name string) ([]string) {
    var sched_list []string

    d, err := db.NewDB(getDBOptions(db.ConfigDB))

    if err != nil {
        log.Infof("getSchedulerIds, unable to get configDB, error %v", err)
        return sched_list
    }


    defer d.DeleteDB()
    var keyPattern string
    ts := &db.TableSpec{Name: "SCHEDULER"}
    if sp_name == "" {
        keyPattern = "*"
    } else {
        keyPattern = sp_name + "@*"
    }

    keys, _ := d.GetKeysByPattern(ts, keyPattern)
    for _, key := range keys {
        if sp_name == "" ||
           key.Comp[0] == sp_name ||
           strings.HasPrefix(key.Comp[0], sp_name+"@") {
            sched_list = append(sched_list, key.Comp[0])
        }
    }

    log.Info("matching schedulers: ", sched_list)
    return sched_list
}

func qos_scheduler_delete_all_sp(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_scheduler_delete_all_sp: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)

    /* get all matching schedulers */
    sched_keys := get_schedulers_by_sp_name("")

    /* update "scheduler" table */
    sched_entry := make(map[string]db.Value)
    var sched_del bool = false
    for _, sched_key := range sched_keys {
        str := strings.Split(sched_key, "@")
        sp_name := str[0]

        // validation: skip in-used scheduler policy
        if isSchedulerPolicyInUse(sp_name) {
             continue
        }
        sched_del = true
        sched_entry[sched_key] = db.Value{Field: make(map[string]string)}
    }

    log.Info("qos_scheduler_delete_all_sp ")
    if sched_del {
        res_map["SCHEDULER"] = sched_entry
    }
    // no need to clean Queue DB as only unused scheduler policy is allowed to be deleted

    return res_map, err
}

func qos_scheduler_delete_by_sp_name(inParams XfmrParams, sp_name string) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_scheduler_delete_by_sp_name: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)
    log.Info("sp_name: ", sp_name)

    if sp_name == "" {
        return qos_scheduler_delete_all_sp(inParams)
    }

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)

    // validation
    if isSchedulerPolicyInUse(sp_name) {
        err = tlerr.InternalError{Format:"Disallow to delete an active scheduler policy"}
        log.Info("Disallow to delete an active scheduler policy: ", sp_name)
        return res_map, err
    }

    /* get all matching schedulers */
    sched_keys := get_schedulers_by_sp_name(sp_name)

    /* update "scheduler" table */
    sched_entry := make(map[string]db.Value)

    for _, sched_key := range sched_keys {
        sched_entry[sched_key] = db.Value{Field: make(map[string]string)}
    }

    log.Info("qos_scheduler_delete_by_sp_name - : ", sp_name)
    res_map["SCHEDULER"] = sched_entry

    // no need to clean Queue DB as only unused scheduler policy is allowed to be deleted

    return res_map, err
}


func qos_scheduler_delete_xfmr(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("qos_scheduler_delete_xfmr: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)

    pathInfo := NewPathInfo(inParams.uri)
    sp_name := pathInfo.Var("name")
    log.Info("YangToDb: policy name: ", sp_name)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)


    var scheds []string
    if sp_name != "" {
        scheds = get_schedulers_by_sp_name(sp_name)
        if len(scheds) == 0 {
            err = tlerr.InternalError{Format:"Instance Not found"}
            log.Info("Scheduler policy not found.")
            return res_map, err
        }
    }

    if !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler")  {
        log.Info("YangToDb: scheduler sequence unspecified, using delete_by_sp_name")
        return qos_scheduler_delete_by_sp_name(inParams, sp_name)
    }

    seq := pathInfo.Var("sequence")
    if seq == "" {
        log.Info("YangToDb: scheduler sequence unspecified, using delete_by_sp_name")
        return qos_scheduler_delete_by_sp_name(inParams, sp_name)
    } else  {
        found := false
        for _, sched := range scheds {
            if sched == sp_name + "@" + seq {
                found = true
                break
            }
        }
        if !found {
            err = tlerr.InternalError{Format:"Instance Not found"}
            log.Info("Scheduler not found.")
            return res_map, err
        }
    }

    /* update "scheduler" table */
    sched_entry := make(map[string]db.Value)
    sched_key := sp_name+"@"+seq
    sched_entry[sched_key] = db.Value{Field: make(map[string]string)}

    if targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/priority" {
        log.Info("Handling No PRIORITY ")

        if isLastSchedulerInActivePolicy(sched_key) &&
           isLastSchedulerField(sched_key, "type") {
            err = tlerr.InternalError{Format:"Last scheduler used by interface cannot be deleted"}
            log.Info("Not allow the last field to be deleted")
            log.Info("Disallow to delete the last scheduler in an actively used policy: ", sched_key)
            return res_map, err
        }

        log.Info("field Type is set for attribute deletion")
        sched_entry[sched_key].Field["type"] = "STRICT"
    }

    if (targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/openconfig-qos-ext:weight" ||
       targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/weight") {
        log.Info("Handling No Weight ")

        if isLastSchedulerInActivePolicy(sched_key) &&
           isLastSchedulerField(sched_key, "weight") {
            err = tlerr.InternalError{Format:"Last scheduler used by interface cannot be deleted"}
            log.Info("Not allow the last field to be deleted")
            log.Info("Disallow to delete the last scheduler in an actively used policy: ", sched_key)
            return res_map, err
        }

        log.Info("field Weight is set for attribute deletion")
        sched_entry[sched_key].Field["weight"] = "0"
    }

    if targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/openconfig-qos-ext:meter-type" {
        log.Info("Handling No Meter-type ")

        if isLastSchedulerInActivePolicy(sched_key) &&
           isLastSchedulerField(sched_key, "meter_type") {
            err = tlerr.InternalError{Format:"Last scheduler used by interface cannot be deleted"}
            log.Info("Not allow the last field to be deleted")
            log.Info("Disallow to delete the last scheduler in an actively used policy: ", sched_key)
            return res_map, err
        }

        log.Info("field Meter-type is set for attribute deletion")
        sched_entry[sched_key].Field["meter_type"] = "0"
    }


    attrs := []string{"cbs", "pbs", "cir" , "pir"}
    if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/two-rate-three-color") {
        log.Info("Handling deleting all rate info")

        attr := strings.TrimPrefix(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/two-rate-three-color")
        if attr != "" {
            attr = strings.TrimPrefix(attr, "/config")
            if attr != "" {
                attr = strings.TrimPrefix(attr, "/")
                if  attr != "" {
                    if  attr == "bc" {
                        attr = "cbs"
                    } else  {
                        if attr == "be" {
                            attr = "pbs"
                        }
                    }

                    attrs = []string{attr}
                }
            }
        }

        if isLastSchedulerInActivePolicy(sched_key) &&
           isLastSchedulerFields(sched_key, attrs) {
            err = tlerr.InternalError{Format:"Last scheduler used by interface cannot be deleted"}
            log.Info("Not allow the last fields to be deleted")
            log.Info("Disallow to delete the last scheduler in an actively used policy: ", sched_key)
            return res_map, err
        }

        log.Info("fields are set for attribute deletion")
        for _, field_name := range attrs {
            sched_entry[sched_key].Field[field_name] = "0"
        }
    }


    if targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler" {
        log.Info("checking last scheduler in an acitive policy")
        if isLastSchedulerInActivePolicy(sched_key) {
            err = tlerr.InternalError{Format:"Last scheduler used by interface cannot be deleted"}
            log.Info("Disallow to delete the last scheduler in an actively used policy: ", sched_key)
            return res_map, err
        }
    }

    log.Info("qos_scheduler_delete_xfmr - entry_key : ", sched_key)
    res_map["SCHEDULER"] = sched_entry

    /* update "Queue" table or "PORT_QOS_MAP" for to-be-deleted scheduler if the scheduler profile is used by intfs*/
    rtTblMap := make(map[string]db.Value)

    if targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler" ||
       (targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/openconfig-qos-ext:meter-type" && isLastSchedulerField(sched_key, "meter_type")) ||
       (targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/priority" && isLastSchedulerField(sched_key, "type")) ||
       ((targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/openconfig-qos-ext:weight" || targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config/weight") && isLastSchedulerField(sched_key, "weight")) ||
       (strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/two-rate-three-color") && isLastSchedulerFields(sched_key, attrs)) {

        // one specific scheduler is deleted

        // read interface queues refering to the scheduler in db
        var keys []string
        if  seq != SCHEDULER_PORT_SEQUENCE {
            keys = getQueuesBySchedulerName(sched_key)
        } else {
            keys = getIntfsBySchedulerName(sched_key)
        }

        for _, key:= range keys {
            log.Infof("YangToDb_qos_scheduler_xfmr --> key: %v, db_sp_name: %v", key, sched_key)

            _, ok := rtTblMap[key]
            if !ok {
                rtTblMap[key] = db.Value{Field: make(map[string]string)}
            }
            rtTblMap[key].Field["scheduler"] = ""
        }
        if len(keys) != 0 {
            if  seq != SCHEDULER_PORT_SEQUENCE {
                res_map["QUEUE"] = rtTblMap
            } else {
                res_map["PORT_QOS_MAP"] = rtTblMap
            }
        }
    }

    log.Infof("qos_scheduler_delete_xfmr --> res_map %v", res_map)
    return res_map, err

}


var YangToDb_qos_scheduler_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    if inParams.oper == DELETE {
        return qos_scheduler_delete_xfmr(inParams)
    }

    var err error
    res_map := make(map[string]map[string]db.Value)

    log.Info("YangToDb_qos_scheduler_xfmr: ", inParams.ygRoot, inParams.uri)
    log.Info("inParams: ", inParams)


    pathInfo := NewPathInfo(inParams.uri)
    sp_name := pathInfo.Var("name")
    log.Info("YangToDb: policy name: ", sp_name)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)

    /* parse the inParams */
    qosObj := getQosRoot(inParams.ygRoot)
    if qosObj == nil {
        return res_map, err
    }

    spObj, ok := qosObj.SchedulerPolicies.SchedulerPolicy[sp_name]
    if !ok {
        log.Info("YangToDb: No policy name: ", sp_name)
        return res_map, err
    }

    if !strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler") {
        log.Info("YangToDb: scheduler sequence unspecified, stop here")
        return res_map, err
    }

    seq :=  ""
    var seq_val uint32 = 0
    for seq_val = range spObj.Schedulers.Scheduler {
        // expect only one scheduler (sequence#) in the request
        log.Info("YangToDb: Scheduler obj: ", sp_name, " seq_val ", seq_val)
        seq =strconv.Itoa(int(seq_val))
        break;
    }

    if seq == "" {
        // no op
        log.Info("YangToDb: no sequence specified")
        return res_map, err
    }


    schedObj, ok := spObj.Schedulers.Scheduler[uint32(seq_val)]
    if !ok {
        log.Info("YangToDb: No Scheduler obj: ", sp_name, " sequence: ", seq, " seq_val ", seq_val)
        return res_map, err
    }

    /* update "scheduler" table */
    sched_entry := make(map[string]db.Value)
    sched_key := sp_name+"@"+seq
    sched_entry[sched_key] = db.Value{Field: make(map[string]string)}

    if ((inParams.oper == CREATE) ||
        (inParams.oper == REPLACE) ||
        (inParams.oper == UPDATE)) {
        var cir uint64 = 0
        var pir uint64 = 0
        var prev_pir_exist bool = false
        var prev_cir_exist bool = false
        var val string
        var prev_pir uint64 = 0
        var prev_cir uint64 = 0
        var prev_type_exist bool = false
        var prev_weight_exist bool = false
        var prev_type string
        var prev_weight uint64 = 0

        log.Info("key: ", sched_key)
        ts := &db.TableSpec{Name: "SCHEDULER"}
        prev_entry, entry_err := inParams.d.GetEntry(ts, db.Key{Comp: []string{sched_key}})
        if entry_err == nil {
           log.Info("current entry: ", prev_entry)
           if val, prev_cir_exist = prev_entry.Field["cir"]; prev_cir_exist {
              prev_cir, _ = strconv.ParseUint(val, 10, 64)
           }

           if val, prev_pir_exist = prev_entry.Field["pir"]; prev_pir_exist {
              prev_pir, _ = strconv.ParseUint(val, 10, 64)
           }
           if val, prev_type_exist = prev_entry.Field["type"]; prev_type_exist {
               prev_type = val
           }

           if val, prev_weight_exist = prev_entry.Field["weight"]; prev_weight_exist {
               prev_weight, _ = strconv.ParseUint(val, 10, 32)
           }
       }

        if schedObj.TwoRateThreeColor != nil && schedObj.TwoRateThreeColor.Config != nil {
            if schedObj.TwoRateThreeColor.Config.Bc != nil  {
                cbs := (int)(*schedObj.TwoRateThreeColor.Config.Bc)
                if sp_name != "copp-scheduler-policy" {
                    if cbs < SCHEDULER_MIN_BURST_BYTES || cbs > SCHEDULER_MAX_BURST_BYTES {
                        err = tlerr.InternalError{Format:"CBS must be greater than or equal to 250 Bytes and less than or equal to 125000000 Bytes"}
                        log.Info("CBS must be greater than or equal to 250 Bytes and less than or equal to 125000000 Bytes")
                        return res_map, err
                    }
                } else {
                    if cbs > SCHEDULER_MAX_BURST_PACKETS {
                        err = tlerr.InternalError{Format:"CBS must be less than or equal to 100000 Packets"}
                        log.Info("CBS must be less than or equal to 100000 Packets")
                        return res_map, err
                    }
                }

                sched_entry[sched_key].Field["cbs"] = strconv.Itoa(cbs)
            }

            if schedObj.TwoRateThreeColor.Config.Be != nil  {
                pbs := (int)(*schedObj.TwoRateThreeColor.Config.Be)
                if sp_name != "copp-scheduler-policy" {
                    if pbs < SCHEDULER_MIN_BURST_BYTES || pbs > SCHEDULER_MAX_BURST_BYTES {
                        err = tlerr.InternalError{Format:"CBS must be greater than or equal to 250 Bytes and less than or equal to 125000000 Bytes"}
                        log.Info("CBS must be greater than or equal to 250 Bytes and less than or equal to 125000000 Bytes")
                        return res_map, err
                    }
                } else {
                    if pbs > SCHEDULER_MAX_BURST_PACKETS {
                        err = tlerr.InternalError{Format:"PBS must be less than or equal to 100000 Packets"}
                        log.Info("PBS must be less than or equal to 100000 Packets")
                        return res_map, err
                    }
                }
                sched_entry[sched_key].Field["pbs"] = strconv.Itoa(pbs)
            }

            if schedObj.TwoRateThreeColor.Config.Cir != nil  {
                if sp_name != "copp-scheduler-policy" {
                    cir = (uint64)(*schedObj.TwoRateThreeColor.Config.Cir)/8
                    // Min 32 Kbps  ==  4 KBps == 4000 Bps
                    if cir < SCHEDULER_MIN_RATE_BPS {
                        err = tlerr.InternalError{Format:"CIR must be greater than 32Kbp/4KBps/4000Bps"}
                        log.Info("CIR must be greater than 32Kbps/4KBps/4000Bps")
                        return res_map, err
                    }
                } else {
                    cir = (uint64)(*schedObj.TwoRateThreeColor.Config.Cir)
                    if cir > SCHEDULER_MAX_RATE_PPS {
                        err = tlerr.InternalError{Format:"CIR must be lesser than 100000 pps"}
                        log.Info("CIR must be lesser than 100000pps")
                        return res_map, err
                    }
                }
                if schedObj.TwoRateThreeColor.Config.Pir == nil {
                   if prev_pir_exist && (cir > prev_pir) {
                       err = tlerr.InternalError{Format:"PIR must be greater than or equal to CIR"}
                       log.Info("PIR must be greater than or equal to CIR")
                       return res_map, err
                   }
                }
                sched_entry[sched_key].Field["cir"] = strconv.FormatUint(cir, 10)
            }

            if schedObj.TwoRateThreeColor.Config.Pir != nil  {
                if sp_name != "copp-scheduler-policy" {
                    pir = (uint64)(*schedObj.TwoRateThreeColor.Config.Pir)/8
                    if pir < SCHEDULER_MIN_RATE_BPS {
                        err = tlerr.InternalError{Format:"PIR must be greater than 32Kbp/4KBps/4000Bps"}
                        log.Info("CIR must be greater than 32Kbps/4KBps/4000Bps")
                        return res_map, err
                    }
                } else {
                    pir = (uint64)(*schedObj.TwoRateThreeColor.Config.Pir)
                    if pir > SCHEDULER_MAX_RATE_PPS {
                        err = tlerr.InternalError{Format:"PIR must be lesser than 100000 pps"}
                        log.Info("PIR must be lesser than 100000pps")
                        return res_map, err
                    }
                }

                if schedObj.TwoRateThreeColor.Config.Cir == nil {
                    if prev_cir_exist && (prev_cir > pir) {
                        err = tlerr.InternalError{Format:"PIR must be greater than or equal to CIR"}
                        log.Info("PIR must be greater than or equal to CIR")
                        return res_map, err
                    }
                } else {
                    if cir > pir {
                        err = tlerr.InternalError{Format:"PIR must be greater than or equal to CIR"}
                        log.Info("PIR must be greater than or equal to CIR")
                        return res_map, err
                    }
                }
                sched_entry[sched_key].Field["pir"] = strconv.FormatUint(pir,10)
            }

            intfs := getIntfsBySPName(sp_name)
            if  len(intfs) > 0 {
                dbSpec := &db.TableSpec{Name: "PORT"}
                for _, intf := range intfs {
                    log.Info("intf: ", intf)
                    portCfg, _ := inParams.d.GetEntry(dbSpec, db.Key{Comp: []string{intf}})
                    speed, ok := portCfg.Field["speed"]
                    if !ok {
                        continue
                    }
                    speed_Mbps, _ := strconv.ParseUint(speed, 10, 64)
                    speed_Bps := speed_Mbps * 1000 * 1000/8
                    if (cir > speed_Bps ||  pir > speed_Bps) {
                        err = tlerr.InternalError{Format:"PIR/CIR must be less than or equal to port speed"}
                        log.Info("PIR/CIR must be less than or equal to port speed")
                        return res_map, err
                    }
                }
            }
        }

        if schedObj.Config != nil  {

            if schedObj.Config.Priority == ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_STRICT {
                sched_entry[sched_key].Field["type"] = "STRICT"
                prev_type = sched_entry[sched_key].Field["type"]
            } else if schedObj.Config.Priority == ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_DWRR {
                sched_entry[sched_key].Field["type"] = "DWRR"
                prev_type = sched_entry[sched_key].Field["type"]
            } else if schedObj.Config.Priority == ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_WRR {
                sched_entry[sched_key].Field["type"] = "WRR"
                prev_type = sched_entry[sched_key].Field["type"]
            }

            if schedObj.Config.Weight != nil  {
                sched_entry[sched_key].Field["weight"] = strconv.Itoa((int)(*schedObj.Config.Weight))
                prev_weight = (uint64)(*schedObj.Config.Weight)
            }

            if prev_type == "STRICT" && prev_weight != 0 {
                err = tlerr.InternalError{Format:"Strict priority scheduling can not be configured with weight"}
                log.Info("Strict priority scheduling can not be configured with weight")
                return res_map, err
            }

            if schedObj.Config.MeterType == ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_MeterType_PACKETS {
                sched_entry[sched_key].Field["meter_type"] = "packets"
            } else if schedObj.Config.MeterType == ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_MeterType_BYTES {
                sched_entry[sched_key].Field["meter_type"] = "bytes"
            }
        }
    }

    log.Info("YangToDb_qos_scheduler_xfmr - entry_key : ", sched_key)
    res_map["SCHEDULER"] = sched_entry

    /* update "Queue" table or "Port" table for newly created scheduler if the scheduler profile is used by intfs*/
    queueTblMap := make(map[string]db.Value)
    portQosTblMap := make(map[string]db.Value)

    if inParams.oper == CREATE ||
       inParams.oper == UPDATE {
        // read intfs refering to the scheduler profile
        intfs := getIntfsBySPName(sp_name)

        // Use "if_name:seq" to form DB key for QUEUE or "if_name" as key for PORT, write "if_name@seq" as its scheduler profile
        for _, if_name := range intfs {
            key := if_name
            if seq != SCHEDULER_PORT_SEQUENCE {
                key = key + "|" + seq
            }
            db_sp_name := sp_name + "@" + seq
            log.Infof("YangToDb_qos_scheduler_xfmr --> key: %v, db_sp_name: %v", key, db_sp_name)

            pTbl := &queueTblMap
            if seq == SCHEDULER_PORT_SEQUENCE {
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
    }


    return res_map, err

}

var DbToYang_qos_scheduler_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    log.Info("DbToYang_qos_scheduler_xfmr - inParams.uri: ", inParams.uri)
    var get_all_sp bool
    pathInfo := NewPathInfo(inParams.uri)
    sp_name := pathInfo.Var("name")
    sp_seq := pathInfo.Var("sequence")

    targetUriPath, _ := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath: ",  targetUriPath)

    if targetUriPath == "/openconfig-qos:qos/scheduler-policies/scheduler-policy" {
       get_all_sp = true;
        log.Info("get_all_sp: ", get_all_sp)
    } else if sp_name == "" {
        errStr := "Invalid Scheduler Policy:" + sp_name
        log.Error(errStr)
        return tlerr.InvalidArgsError{Format:errStr}
    }
    qosObj := getQosRoot(inParams.ygRoot)

    if qosObj == nil {
        ygot.BuildEmptyTree(qosObj)
    }
    var sp_config, sp_state, sched_config, sched_state, t23c_config, t23c_state bool
    if strings.Compare(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy") == 0 {
        sp_config, sp_state, sched_config, sched_state, t23c_config , t23c_state = true, true, true, true,true,true
    } else if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/config") {
        sp_config = true
    } else if strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/state") {
        sp_state = true
    } else if strings.Compare( targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers") == 0 {
        sched_config, sched_state, t23c_config, t23c_state = true, true, true, true
    } else if strings.Compare(targetUriPath, "/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler") == 0 {
        sched_config, sched_state, t23c_config, t23c_state = true, true, true, true
    } else if strings.HasPrefix(targetUriPath,"/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/config") {
        sched_config = true
    } else if strings.HasPrefix(targetUriPath,"/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/state") {
        sched_state = true
    } else if strings.Compare(targetUriPath,"/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/two-rate-three-color") == 0 {
        t23c_config, t23c_state = true, true
    } else if strings.HasPrefix(targetUriPath,"/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/two-rate-three-color/config") {
        t23c_config = true
    } else if strings.HasPrefix(targetUriPath,"/openconfig-qos:qos/scheduler-policies/scheduler-policy/schedulers/scheduler/two-rate-three-color/state") {
        t23c_state = true
    }

    // Scheduler
    var keyPattern string
    dbSpec := &db.TableSpec{Name: "SCHEDULER"}
    if sp_name == "" {
        keyPattern = "*"
    } else {
        keyPattern = sp_name + "@*"
    }

    keys, _ := inParams.dbs[db.ConfigDB].GetKeysByPattern(dbSpec, keyPattern)
    for  _, key := range keys {
        if log.V(3) {
            log.Info("current key: ", key)
        }
        if len(key.Comp) < 1 {
            continue
        }
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

        if sp_name != "" && strings.Compare(sp_name, spname) != 0 {
            continue
        }

        if sp_seq != "" && strings.Compare(sp_seq, spseq) != 0 {
            continue
        }

        var seq uint32
        tmp, _ := strconv.ParseUint(spseq, 10, 32)
        seq = (uint32) (tmp)

        if log.V(3) {
            log.Infof("Fill scheduler policy in scheduler: spname %v spseq %v", spname, spseq)
        }
        spObj, ok := qosObj.SchedulerPolicies.SchedulerPolicy[spname]
        if !ok {
            spObj, _ = qosObj.SchedulerPolicies.NewSchedulerPolicy(spname)
            ygot.BuildEmptyTree(spObj)
            if spObj.Schedulers == nil {
                ygot.BuildEmptyTree(spObj.Schedulers)
            }
        } else {
            ygot.BuildEmptyTree(spObj)
            if spObj.Schedulers == nil {
                ygot.BuildEmptyTree(spObj.Schedulers)
            }
        }

        if sp_config {
            spObj.Name = &spname
            spObj.Config.Name = &spname
        }
        if sp_state {
            spObj.Name = &spname
            spObj.State.Name = &spname
        }

        if (!sched_config &&  !sched_state && !t23c_config && !t23c_state ) {
            continue
        }

        schedObj, ok := spObj.Schedulers.Scheduler[seq]
        if !ok {
            schedObj, _ = spObj.Schedulers.NewScheduler(seq)
            ygot.BuildEmptyTree(schedObj)
        } else if (schedObj != nil)  {
            ygot.BuildEmptyTree(schedObj)
        }
        if (schedObj.TwoRateThreeColor != nil)  {
            ygot.BuildEmptyTree(schedObj.TwoRateThreeColor)
        }

        schedCfg, _ := inParams.dbs[db.ConfigDB].GetEntry(dbSpec, key)

        if log.V(3) {
            log.Info("current entry: ", schedCfg)
        }
        if val, exist := schedCfg.Field["cbs"]; exist {
            tmp,_ = strconv.ParseUint(val, 10, 32)
            bc := uint32(tmp)
            if t23c_config {
                schedObj.TwoRateThreeColor.Config.Bc = &bc
            }
            if t23c_state {
                schedObj.TwoRateThreeColor.State.Bc = &bc
            }
        }

        if val, exist := schedCfg.Field["pbs"]; exist {
            tmp,_ = strconv.ParseUint(val, 10, 32)
            be := uint32(tmp)
            if t23c_config {
                schedObj.TwoRateThreeColor.Config.Be = &be
            }
            if t23c_state {
                schedObj.TwoRateThreeColor.State.Be = &be
            }
        }

        if val, exist := schedCfg.Field["cir"]; exist {
            cir,_ := strconv.ParseUint(val, 10, 64)
            if spname != "copp-scheduler-policy" {
                cir = cir * 8
            }
            if t23c_config {
                schedObj.TwoRateThreeColor.Config.Cir = &cir
            }
            if t23c_state {
                schedObj.TwoRateThreeColor.State.Cir = &cir
            }
         }

        if val, exist := schedCfg.Field["pir"]; exist {
            pir,_ := strconv.ParseUint(val, 10, 64)
            if spname != "copp-scheduler-policy" {
                pir = pir * 8
            }
            if t23c_config {
                schedObj.TwoRateThreeColor.Config.Pir = &pir
            }
            if t23c_state {
                schedObj.TwoRateThreeColor.State.Pir = &pir
            }
        }

        if val, exist := schedCfg.Field["type"]; exist {
            if sched_config {
               if val == "STRICT" {
                   schedObj.Config.Priority = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_STRICT
               } else if val == "DWRR" {
                   schedObj.Config.Priority = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_DWRR
               } else if val == "WRR" {
                   schedObj.Config.Priority = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_WRR
               }
            }

            if sched_state {
                if val == "STRICT" {
                    schedObj.State.Priority = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_STRICT
                } else if val == "DWRR" {
                    schedObj.State.Priority = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_DWRR
                } else if val == "WRR" {
                    schedObj.State.Priority = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_Priority_WRR
                }
            }
        }

        if val, exist := schedCfg.Field["weight"]; exist {
            tmp,_ = strconv.ParseUint(val, 10, 32)
            weight := uint8(tmp)
            if sched_config {
                schedObj.Config.Weight = &weight
            }
            if sched_state {
                schedObj.State.Weight = &weight
            }
        }

        if val, exist := schedCfg.Field["meter_type"]; exist {
            if sched_config {
                if val == "packets" {
                    schedObj.Config.MeterType = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_MeterType_PACKETS
                } else if val == "bytes" {
                    schedObj.Config.MeterType = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_Config_MeterType_BYTES
                }
            }
            if sched_state {
                if val == "packets" {
                    schedObj.State.MeterType = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_State_MeterType_PACKETS
                } else if val == "bytes" {
                    schedObj.State.MeterType = ocbinds.OpenconfigQos_Qos_SchedulerPolicies_SchedulerPolicy_Schedulers_Scheduler_State_MeterType_BYTES
                }
            }
        }
    }

    log.Info("DbToYang_qos_scheduler_xfmr - Done")
    return nil
}
