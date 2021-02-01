package transformer

import (
    "errors"
    "strconv"
    "strings"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "encoding/json"
    "time"
    "fmt"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
)

var qCounterTblAttr [] string = []string {"transmit-pkts", "transmit-octets", "dropped-pkts", "dropped-octets", "transmit-pkts-per-second", "transmit-octets-per-second", "transmit-bits-per-second" }
var pgCounterTblAttr [] string = []string {"headroom-watermark", "headroom-persistent-watermark", "shared-watermark", "shared-persistent-watermark", "headroom-watermark-percent", "headroom-persistent-watermark-percent", "shared-watermark-percent", "shared-persistent-watermark-percent" }

var ECN_MAP = map[string]string{
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_NONE), 10): "ecn_none",
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_GREEN), 10): "ecn_green",
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_YELLOW), 10): "ecn_yellow",
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_RED), 10): "ecn_red",
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_GREEN_YELLOW), 10): "ecn_green_yellow",
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_GREEN_RED), 10): "ecn_green_red",
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_YELLOW_RED), 10): "ecn_yellow_red",
    strconv.FormatInt(int64(ocbinds.OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn_ECN_ALL), 10): "ecn_all",
}



func init () {
    XlateFuncBind("qos_intf_table_xfmr", qos_intf_table_xfmr)
    XlateFuncBind("YangToDb_qos_intf_tbl_key_xfmr", YangToDb_qos_intf_tbl_key_xfmr)
    XlateFuncBind("DbToYang_qos_intf_tbl_key_xfmr", DbToYang_qos_intf_tbl_key_xfmr)
    XlateFuncBind("YangToDb_qos_intf_intf_id_fld_xfmr", YangToDb_qos_intf_intf_id_fld_xfmr)
    XlateFuncBind("DbToYang_qos_intf_intf_id_fld_xfmr", DbToYang_qos_intf_intf_id_fld_xfmr)
    XlateFuncBind("YangToDb_qos_intf_intfref_intf_fld_xfmr", YangToDb_qos_intf_intfref_intf_fld_xfmr)
    XlateFuncBind("DbToYang_qos_intf_intfref_intf_fld_xfmr", DbToYang_qos_intf_intfref_intf_fld_xfmr)

    XlateFuncBind("YangToDb_qos_get_one_intf_all_q_counters_xfmr", YangToDb_qos_get_one_intf_all_q_counters_xfmr)
    XlateFuncBind("DbToYang_qos_get_one_intf_all_q_counters_xfmr", DbToYang_qos_get_one_intf_all_q_counters_xfmr)
    XlateFuncBind("Subscribe_qos_get_one_intf_all_q_counters_xfmr", Subscribe_qos_get_one_intf_all_q_counters_xfmr)
    XlateFuncBind("YangToDb_qos_get_one_intf_all_pg_counters_xfmr", YangToDb_qos_get_one_intf_all_pg_counters_xfmr)
    XlateFuncBind("DbToYang_qos_get_one_intf_all_pg_counters_xfmr", DbToYang_qos_get_one_intf_all_pg_counters_xfmr)
    XlateFuncBind("Subscribe_qos_get_one_intf_all_pg_counters_xfmr", Subscribe_qos_get_one_intf_all_pg_counters_xfmr)
    XlateFuncBind("DbToYang_threshold_breach_counter_field_xfmr", DbToYang_threshold_breach_counter_field_xfmr)
    XlateFuncBind("rpc_clear_qos", rpc_clear_qos)

    // WRED 
    XlateFuncBind("YangToDb_wred_profile_name_empty_fld_xfmr", YangToDb_wred_profile_name_empty_fld_xfmr)
    XlateFuncBind("YangToDb_wred_profile_name_fld_xfmr", YangToDb_wred_profile_name_fld_xfmr)
    XlateFuncBind("DbToYang_wred_profile_name_fld_xfmr", DbToYang_wred_profile_name_fld_xfmr)
    XlateFuncBind("YangToDb_wred_ecn_fld_xfmr", YangToDb_wred_ecn_fld_xfmr)
    XlateFuncBind("DbToYang_wred_ecn_fld_xfmr", DbToYang_wred_ecn_fld_xfmr)
    XlateFuncBind("YangToDb_qos_threshold_breach_key_xfmr", YangToDb_qos_threshold_breach_key_xfmr)
    XlateFuncBind("DbToYang_qos_threshold_breach_key_xfmr", DbToYang_qos_threshold_breach_key_xfmr)
    XlateFuncBind("rpc_oc_clear_threshold_breach", rpc_oc_clear_threshold_breach)

    // THRESHOLD Configuration 
    XlateFuncBind("YangToDb_tam_threshold_key_xfmr", YangToDb_tam_threshold_key_xfmr)
    XlateFuncBind("DbToYang_tam_threshold_key_xfmr", DbToYang_tam_threshold_key_xfmr)
    XlateFuncBind("DbToYang_tam_threshold_field_xfmr", DbToYang_tam_threshold_field_xfmr)
    XlateFuncBind("YangToDb_tam_threshold_field_xfmr", YangToDb_tam_threshold_field_xfmr)
    
	// Watermark Configuration 
    XlateFuncBind("YangToDb_tam_watermark_key_xfmr", YangToDb_tam_watermark_key_xfmr)
    XlateFuncBind("DbToYang_tam_watermark_key_xfmr", DbToYang_tam_watermark_key_xfmr)
	XlateFuncBind("rpc_watermarks_clear_cb", rpc_watermarks_clear_cb)

	// Watermark Configuration (Telemetry) 
    XlateFuncBind("YangToDb_telemetry_watermark_key_xfmr", YangToDb_telemetry_watermark_key_xfmr)
    XlateFuncBind("DbToYang_telemetry_watermark_key_xfmr", DbToYang_telemetry_watermark_key_xfmr)
    XlateFuncBind("qos_post_xfmr", qos_post_xfmr)

}


var rpc_watermarks_clear_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        var out_list []string
        var exec_cmd_list []string
        log.Info("rpc_watermarks_clear_cb body:", string(body))

        var result struct {
                Output struct {
                        Status int32 `json:"status"`
                        Status_detail []string`json:"status-detail"`
                } `json:"openconfig-qos-ext:output"`
        }
        var operand struct {
                Input struct {
                     Buffer string `json:"buffer"`
                     BufferType string `json:"buffer-type"`
                     WatermarkType string `json:"watermark-type"`
                } `json:"openconfig-qos-ext:input"`
        }

       err := json.Unmarshal(body, &operand)
       if err != nil {
                result.Output.Status = 1
                out_list = append(out_list, "[FAILED] unmarshal input: " + err.Error())
                result.Output.Status_detail  = out_list
                return json.Marshal(&result)
       }
       buffer := operand.Input.Buffer
       bufferType := operand.Input.BufferType
       watermarkType := operand.Input.WatermarkType

       exec_cmd_list = append(exec_cmd_list, "sonic-clear")
       exec_cmd_list = append(exec_cmd_list,   buffer)
       exec_cmd_list = append(exec_cmd_list,   watermarkType)
       exec_cmd_list = append(exec_cmd_list,   bufferType)

        exec_cmd := strings.Join(exec_cmd_list," ")

    return watermarks_clear_operation(exec_cmd)
}

func watermarks_clear_operation(exec_cmd string) ([]byte, error) {

   log.Info("watermarks_clear_operation cmd:", exec_cmd)
        var out_list []string

   	var result struct {
    		Output struct {
          		Status int32 `json:"status"`
          		Status_detail []string`json:"status-detail"`
      		} `json:"openconfig-qos-ext:output"`
    	}


        host_output := HostQuery("infra_host.exec_cmd", exec_cmd)
        if host_output.Err != nil {
              log.Errorf("watermarks_clear_operation: host Query FAILED: err=%v", host_output.Err)
              result.Output.Status = 1
              out_list  = append(out_list, host_output.Err.Error()) 
              out_list  = append(out_list, "[ FAILED ] host query") 
              result.Output.Status_detail  = out_list 
              return json.Marshal(&result)
        }

        var output string
        output, _ = host_output.Body[1].(string)
        _output := strings.TrimLeft(output,"\n")
        failure_status :=  strings.Contains(_output, "FAILED")
        success_status :=  strings.Contains(_output, "SUCCESS")

        if (failure_status || !success_status) {
           out_list = strings.Split(_output,"\n")
        } else { 
           _out_list := strings.Split(_output,"\n")
           for index, each := range _out_list {
                 i := strings.Index(each, "SUCCESS")
                 if i != -1 {
                     out_list = append(out_list, _out_list[index])
                 }
           }
        }

        result.Output.Status = 0
        result.Output.Status_detail  = out_list 
        return json.Marshal(&result)
}

var DbToYang_tam_threshold_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    return res_map, nil
}

var YangToDb_tam_threshold_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    return res_map, nil
}

var YangToDb_tam_threshold_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var dbKey strings.Builder
	pathInfo := NewPathInfo(inParams.uri)
	vbuffer := pathInfo.Var("buffer")
	vtype := pathInfo.Var("type")
	vport := pathInfo.Var("port")
	vindex := pathInfo.Var("index")
	
	dbKey.WriteString(vbuffer)
	dbKey.WriteString("|")
	dbKey.WriteString(vtype)
	dbKey.WriteString("|")
	dbKey.WriteString(vport)
	dbKey.WriteString("|")
	dbKey.WriteString(vindex)

	var newkey = dbKey.String()
	return newkey, nil
}

var DbToYang_tam_threshold_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var flds = strings.Split(inParams.key, "|")

    rmap := make(map[string]interface{})
	rmap["buffer"] = flds[0]
	rmap["type"] = flds[1]
	rmap["port"] = flds[2]
	idx, err := strconv.Atoi(flds[3])
	if (err == nil) {
		rmap["index"] = idx
	}
   return rmap, nil
}

var YangToDb_tam_watermark_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var newkey = "SNAPSHOT_INTERVAL";
	return newkey, nil
}

var DbToYang_tam_watermark_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
	return rmap, nil
}

var YangToDb_telemetry_watermark_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var newkey = "TELEMETRY_INTERVAL";
	return newkey, nil
}

var DbToYang_telemetry_watermark_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
	return rmap, nil
}



func getQosRoot (s *ygot.GoStruct) *ocbinds.OpenconfigQos_Qos {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Qos
}

func getQosIntfRoot (s *ygot.GoStruct) *ocbinds.OpenconfigQos_Qos_Interfaces {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Qos.Interfaces
}

var DbToYang_qos_name_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    res_map := make(map[string]interface{})
    res_map["name"] =  inParams.key
    return res_map, err
}

func doGetAllQueueOidMap(d *db.DB) (db.Value, error) {

    // COUNTERS_QUEUE_NAME_MAP
    dbSpec := &db.TableSpec{Name: "COUNTERS_QUEUE_NAME_MAP"}
    queueOidMap, err := d.GetMapAll(dbSpec)
    if err != nil {
        log.Info("queueOidMap get failed")
    }
    return queueOidMap, err
}

func doGetAllQueueTypeMap(d *db.DB) (db.Value, error) {

    // COUNTERS_QUEUE_TYPE_MAP
    queueTs := &db.TableSpec{Name: "COUNTERS_QUEUE_TYPE_MAP"}
    queueTypeMap, err := d.GetMapAll(queueTs)
    if err != nil {
        log.Info("queueTypeMap get failed")
    }

    return queueTypeMap, err
}

func doGetAllPriorityGroupOidMap(d *db.DB) (db.Value, error) {

    // COUNTERS_PG_NAME_MAP
    dbSpec := &db.TableSpec{Name: "COUNTERS_PG_NAME_MAP"}
    pgOidMap, err := d.GetMapAll(dbSpec)
    if err != nil {
        log.Info("pgOidMap get failed")
    }

    return pgOidMap, err
}

func getIntfQCountersTblKey (d *db.DB, ifQKey string) (string, error) {
    var oid string
    var err error

    queueOidMap, _ := doGetAllQueueOidMap(d);

    if queueOidMap.IsPopulated() {
        _, ok := queueOidMap.Field[ifQKey]
        if !ok {
            err = errors.New("OID info not found from Counters DB for interface queue: " + ifQKey)
        } else {
            oid = queueOidMap.Field[ifQKey]
        }
    } else {
        err = errors.New("Get for OID info from all the interfaces queues from Counters DB failed!")
    }

    return oid, err
}

func getIntfPGCountersTblKey (d *db.DB, ifPGKey string) (string, error) {
    var oid string
    var err error

    priorityGroupOidMap, _ := doGetAllPriorityGroupOidMap(d);

    if priorityGroupOidMap.IsPopulated() {
        _, ok := priorityGroupOidMap.Field[ifPGKey]
        if !ok {
            err = errors.New("OID info not found from Counters DB for interface priorityGroup: " + ifPGKey)
        } else {
            oid = priorityGroupOidMap.Field[ifPGKey]
        }
    } else {
        err = errors.New("Get for OID info from all the interfaces priorityGroups from Counters DB failed!")
    }

    return oid, err
}

func getQosCounters(entry *db.Value, attr string, counter_val **uint64 ) error {

    var ok bool = false
    var err error
    val, ok := entry.Field[attr]

    if ok && len(val) > 0 {
        v, _ := strconv.ParseUint(val, 10, 64)
        *counter_val = &v
        return nil
    } else {
        log.Info("getQosCounters: ", "Attr " + attr + "doesn't exist in table Map!")
    }
    return err
}

func getQosOffsetCounters(entry *db.Value, entry_backup *db.Value, attr string, counter_val **uint64 ) error {

    var ok bool = false
    var err error
    val1, ok := entry.Field[attr]

    if !ok {
        return errors.New("Attr " + attr + "doesn't exist in table Map!")
    }
    val2, ok := entry_backup.Field[attr]
    if !ok {
        return errors.New("Attr " + attr + "doesn't exist in the table Map!")
    }

    if len(val1) > 0 {
        v, _ := strconv.ParseUint(val1, 10, 64)
        v_backup, _ := strconv.ParseUint(val2, 10, 64)
        val := v-v_backup
        *counter_val = &val
        return nil
    }
    return err
}

func getPersistentWatermark(d *db.DB, oid string, entry *db.Value)  (error) {
    var err error
    ts := &db.TableSpec{Name: "PERSISTENT_WATERMARKS"}
    *entry, err = d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Info("getPersistentWatermark: not able to find the oid entry in DB ")
        return err
    }

    return err
}

func resetPersistentWatermark(d *db.DB, oid string, count_type string, buff_type string)  (error) {
    var cerr error
    ts := &db.TableSpec{Name: "PERSISTENT_WATERMARKS"}
    value, verr := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if verr == nil {
        secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        if count_type == "priority-group" {
            if buff_type == "headroom" {
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_XOFF_ROOM_WATERMARK"] = "0"
            } else if buff_type == "shared" {
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_SHARED_WATERMARK"] = "0"
            } else {
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_XOFF_ROOM_WATERMARK"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_SHARED_WATERMARK"] = "0"
            }
        } else if count_type == "queue" {
            value.Field["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"] = "0"
            value.Field["SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK_BYTES"] = "0"
        }
        cerr = d.CreateEntry(ts, db.Key{Comp: []string{oid}}, value)
    }
    return cerr
}

func getUserWatermark(d *db.DB, oid string, entry *db.Value)  (error) {
    var err error
    ts := &db.TableSpec{Name: "USER_WATERMARKS"}
    *entry, err = d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Info("getUserWatermark: not able to find the oid entry in DB ")
        return err
    }

    return err
}

func resetUserWatermark(d *db.DB, oid string, count_type string, buff_type string)  (error) {
    var cerr error
    ts := &db.TableSpec{Name: "USER_WATERMARKS"}
    value, verr := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if verr == nil {
        secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        if count_type == "priority-group" {
            if buff_type == "headroom" {
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_XOFF_ROOM_WATERMARK"] = "0"
            } else if buff_type == "shared" {
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_SHARED_WATERMARK"] = "0"
            } else {
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_XOFF_ROOM_WATERMARK"] = "0"
                value.Field["SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_SHARED_WATERMARK"] = "0"
            }

        } else if count_type == "queue" {
            value.Field["SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"] = "0"
            value.Field["SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK"] = "0"
        }
        cerr = d.CreateEntry(ts, db.Key{Comp: []string{oid}}, value)
    }
    return cerr
}


func getQueueSpecificCounterAttr(targetUriPath string, entry *db.Value, entry_backup *db.Value, counters *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue_State) (bool, error) {

    var e error

    switch targetUriPath {

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/transmit-pkts":
        e = getQosOffsetCounters(entry, entry_backup, "SAI_QUEUE_STAT_PACKETS", &counters.TransmitPkts)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/transmit-octets":
        e = getQosOffsetCounters(entry, entry_backup, "SAI_QUEUE_STAT_BYTES", &counters.TransmitOctets)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/dropped-pkts":
        e = getQosOffsetCounters(entry, entry_backup, "SAI_QUEUE_STAT_DROPPED_PACKETS", &counters.DroppedPkts)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/dropped-octets":
        e = getQosOffsetCounters(entry, entry_backup, "SAI_QUEUE_STAT_DROPPED_BYTES", &counters.DroppedOctets)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/transmit-pkts-per-second":
        e = getQosCounters(entry, "SAI_QUEUE_STAT_PACKETS_PER_SECOND", &counters.TransmitPktsPerSecond)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/transmit-octets-per-second":
        e = getQosCounters(entry, "SAI_QUEUE_STAT_BYTES_PER_SECOND", &counters.TransmitOctetsPerSecond)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/transmit-bits-per-second":
        e = getQosCounters(entry, "SAI_QUEUE_STAT_BITS_PER_SECOND", &counters.TransmitBitsPerSecond)
        return true, e

    default:
        log.Infof(targetUriPath + " - Not an interface state counter attribute or unsupported")
    }
    return false, nil
}

func getCounterAndBackupByOid(inParams XfmrParams, oid string, entry *db.Value, entry_backup *db.Value) (error) {
   
    var dbErr error
    cntTs := &db.TableSpec{Name: "COUNTERS"}
    *entry, dbErr = inParams.dbs[inParams.curDb].GetEntry(cntTs, db.Key{Comp: []string{oid}})
    if dbErr != nil {
        log.Info("getCounterAndBackupByOid : not able to find the oid entry in DB Counters table")
        return dbErr
    }

    cntTs_cp := &db.TableSpec { Name: "COUNTERS_BACKUP" }
    *entry_backup, dbErr = inParams.dbs[inParams.curDb].GetEntry(cntTs_cp, db.Key{Comp: []string{oid}})
    if dbErr != nil {
        m := make(map[string]string)
        /* Frame backup data with 0 as counter values */
        for  attr := range entry.Field {
            m[attr] = "0"
        }
        m["LAST_CLEAR_TIMESTAMP"] = "0"
        *entry_backup = db.Value{Field: m}
    }

    return nil
}

 
func populateQCounters (inParams XfmrParams, targetUriPath string, oid string, counter *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue_State) (error) {

    var err error
    var count *uint64
    var entry db.Value
    var entry_backup db.Value
    switch (targetUriPath) {
    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state":
        dbErr := getCounterAndBackupByOid(inParams,oid, &entry, &entry_backup)
        if dbErr != nil {
            log.Info("populateQCounters : not able to find the oid entry in DB Counters table")
            return dbErr
        }

        for _, attr := range qCounterTblAttr {
            uri := targetUriPath + "/" + attr
            if ok, err := getQueueSpecificCounterAttr(uri, &entry, &entry_backup, counter); !ok || err != nil {
                log.Info("Get Counter URI failed :", uri)
            }
        }

        err = getUserWatermark(inParams.dbs[inParams.curDb], oid, &entry)
        if err == nil {
            getQosCounters(&entry, "SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES", &counter.Watermark)
            getQosCounters(&entry, "SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK", &count)
            counter_percent := uint8(*count)
            counter.WatermarkPercent = &counter_percent
        }

        err = getPersistentWatermark(inParams.dbs[inParams.curDb], oid, &entry)
        if err == nil {
            getQosCounters(&entry, "SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES", &counter.PersistentWatermark)
            getQosCounters(&entry, "SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK", &count)
            counter_percent := uint8(*count)
            counter.PersistentWatermarkPercent = &counter_percent
        }

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/watermark":
        getUserWatermark(inParams.dbs[inParams.curDb], oid, &entry)
        err = getQosCounters(&entry, "SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES", &counter.Watermark)

    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/watermark-percent":
        getUserWatermark(inParams.dbs[inParams.curDb], oid, &entry)
        err = getQosCounters(&entry, "SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK", &count)
        counter_percent := uint8(*count)
        counter.WatermarkPercent = &counter_percent
    // persisten-watermark resides on separate DB table
    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/persistent-watermark":
        getPersistentWatermark(inParams.dbs[inParams.curDb], oid, &entry)
        err = getQosCounters(&entry, "SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES", &counter.PersistentWatermark)

    // persisten-watermark resides on separate DB table
    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state/persistent-watermark-percent":
        getPersistentWatermark(inParams.dbs[inParams.curDb], oid, &entry)
        err = getQosCounters(&entry, "SAI_QUEUE_PERCENT_STAT_SHARED_WATERMARK", &count)
        counter_percent := uint8(*count)
        counter.PersistentWatermarkPercent = &counter_percent

    default:
        log.Info("Entering default branch")
        dbErr := getCounterAndBackupByOid(inParams, oid, &entry, &entry_backup)
        if dbErr != nil {
            log.Info("populateQCounters : not able to find the oid entry in DB Counters table")
            return dbErr
        }
        _, err = getQueueSpecificCounterAttr(targetUriPath, &entry, &entry_backup, counter)
    }

    return err
}

/* Reset counter values in COUNTERS_BACKUP table for given OID */
func resetQosCounters(d *db.DB, oid string) (error,error) {
    var verr,cerr error
    CountrTblTs := db.TableSpec {Name: "COUNTERS"}
    CountrTblTsCp := db.TableSpec { Name: "COUNTERS_BACKUP" }
    value, verr := d.GetEntry(&CountrTblTs, db.Key{Comp: []string{oid}})
    if verr == nil {
        secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        cerr = d.CreateEntry(&CountrTblTsCp, db.Key{Comp: []string{oid}}, value)
        log.Info("resetQosCounters: ", oid)
    }
    return verr, cerr
}


func getQTrafficType (queueTypeMap db.Value, oid string, counter *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue_State) () {
    var ac = "AC"
    var mc = "MC"
    var uc = "UC"
    counter.TrafficType =  &ac

    q_type, ok := queueTypeMap.Field[oid]
    if !ok {
        log.Info("Queue oid is not mapped in Queue-Type-Map")
        counter.TrafficType =  &ac
        return
    } else {
        if strings.Compare(q_type, "SAI_QUEUE_TYPE_MULTICAST") == 0 {
            counter.TrafficType =  &mc
        } else {
            if strings.Compare(q_type, "SAI_QUEUE_TYPE_UNICAST") == 0 {
                counter.TrafficType =  &uc
            } else {
                counter.TrafficType =  &ac
            }
        }
    }
}

func getQType (queueTypeMap db.Value, oid string) (string) {

    q_type, ok := queueTypeMap.Field[oid]
    if !ok {
        log.Info("Queue oid is not mapped in Queue-Type-Map")
        return "AC"
    } else {
        if strings.Compare(q_type, "SAI_QUEUE_TYPE_MULTICAST") == 0 {
            return "MC"
        } else {
            if strings.Compare(q_type, "SAI_QUEUE_TYPE_UNICAST") == 0 {
                return "UC"
            } else {
                return "AC"
            }
        }
    }
}

func getPriorityGroupSpecificCounterAttr(targetUriPath string, per_entry *db.Value, user_entry *db.Value, counter *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups_PriorityGroup_State) (bool, error) {

    var e error
    var count *uint64
    switch targetUriPath {
    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/headroom-watermark":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/headroom-watermark":
        e = getQosCounters(user_entry, "SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES", &counter.HeadroomWatermark)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/headroom-persistent-watermark":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/headroom-persistent-watermark":
        e = getQosCounters(per_entry, "SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES", &counter.HeadroomPersistentWatermark)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/shared-watermark":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/shared-watermark":
        e = getQosCounters(user_entry, "SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES", &counter.SharedWatermark)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/shared-persistent-watermark":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/shared-persistent-watermark":
        e = getQosCounters(per_entry, "SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES", &counter.SharedPersistentWatermark)
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/headroom-watermark-percent":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/headroom-watermark-percent":
        e = getQosCounters(user_entry, "SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_XOFF_ROOM_WATERMARK", &count)
        counter_percent := uint8(*count)
        counter.HeadroomWatermarkPercent = &counter_percent
    return true, e

    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/headroom-persistent-watermark-percent":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/headroom-persistent-watermark-percent":
        e = getQosCounters(per_entry, "SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_XOFF_ROOM_WATERMARK", &count)
        counter_percent := uint8(*count)
        counter.HeadroomPersistentWatermarkPercent = &counter_percent
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/shared-watermark-percent":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/shared-watermark-percent":
        e = getQosCounters(user_entry, "SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_SHARED_WATERMARK", &count)
        counter_percent := uint8(*count)
        counter.SharedWatermarkPercent = &counter_percent
        return true, e

    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state/shared-persistent-watermark-percent":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state/shared-persistent-watermark-percent":
        e = getQosCounters(per_entry, "SAI_INGRESS_PRIORITY_GROUP_PERCENT_STAT_SHARED_WATERMARK", &count)
        counter_percent := uint8(*count)
        counter.SharedPersistentWatermarkPercent = &counter_percent
        return true, e

    default:
        log.Infof(targetUriPath + " - Not an interface PG counter attribute or unsupported")
    }
    return false, nil
}

func populatePriorityGroupCounters (inParams XfmrParams, targetUriPath string, oid string, counter *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups_PriorityGroup_State) (error) {

    var err error
    var per_entry db.Value
    var user_entry db.Value
    err = getPersistentWatermark(inParams.dbs[inParams.curDb], oid, &per_entry)
    if err != nil {
        log.Info("populatePriorityGroupCounters: Get Persistent Entry failed ")
        return err
    }

    err = getUserWatermark(inParams.dbs[inParams.curDb], oid, &user_entry)
    if err != nil {
        log.Info("populatePriorityGroupCounters: Get User Entry failed ")
        return err
    }

    switch (targetUriPath) {
    case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state":
        for _, attr := range pgCounterTblAttr {
            uri := targetUriPath + "/" + attr
            if ok, err := getPriorityGroupSpecificCounterAttr(uri, &per_entry, &user_entry, counter); !ok || err != nil {
                log.Info("Get Counter URI failed :", uri)
            }
        }
    
    default:
        _, err = getPriorityGroupSpecificCounterAttr(targetUriPath, &per_entry, &user_entry, counter)
    }

    return err
}

/* Validate whether intf exists in DB */
func validateQosIntf(confd *db.DB, dbs [db.MaxDB]*db.DB, intfName string) error {

    log.Info(" validateQosIntf - intfName ", intfName);
    if intfName  == "" {
        return nil
    }

    if intfName  == "CPU" {
        return nil
    }
    var d *db.DB

    if (confd != nil) {
        log.Info(" validateQosIntf - confd intfName ", intfName);
        d = confd
    } else {
        log.Info(" validateQosIntf - Read from dbs intfName ", intfName);
        d = dbs[db.ConfigDB]
    }
    if (d != nil) {
        entry, err := d.GetEntry(&db.TableSpec{Name:"PORT"}, db.Key{Comp: []string{intfName}})
        if err != nil || !entry.IsPopulated() {
            entry, err := d.GetEntry(&db.TableSpec{Name:"PORTCHANNEL"}, db.Key{Comp: []string{intfName}})
            if err != nil || !entry.IsPopulated() {
                // entry, err := d.GetEntry(&db.TableSpec{Name:"VLAN_INTERFACE"}, db.Key{Comp: []string{intfName}})
                entry, err := d.GetEntry(&db.TableSpec{Name:"VLAN"}, db.Key{Comp: []string{intfName}})
                if err != nil || !entry.IsPopulated() {
                    errStr := "Interface " + intfName + " is not available."
                    log.Error(errStr)
                    return tlerr.InvalidArgsError{Format:errStr}
                }
            }
        }
    }
    log.Info(" validateQosIntf - intfName ", intfName, " success ");
    return nil
}

func getDbQueueName(queueName string) (string, error) {
    log.Info(" getDbQueueName - queueName ", queueName);

    if strings.Contains(queueName, ":") {
        queue := strings.Split(queueName, ":")
        dbIntfName := utils.GetNativeNameFromUIName(&queue[0])
        dbQueueName := *dbIntfName + ":" + queue[1]
        log.Info(" getDbQueueName - dbQueueName ", dbQueueName);
        return dbQueueName, nil
    }
    errStr := "Invalid Queue: " + queueName
    log.Error(errStr)
    return queueName, tlerr.InvalidArgsError{Format:errStr}
}

func getDbPgName(pgName string) (string, error) {
    log.Info(" getDbPgName - pgName ", pgName);
    if strings.Contains(pgName, ":") {
        pg := strings.Split(pgName, ":")
        dbIntfName := utils.GetNativeNameFromUIName(&pg[0])
        dbPgName := *dbIntfName + ":" + pg[1]
        log.Info(" getDbPgName - dbPgName ", dbPgName);
        return dbPgName, nil
    }
    errStr := "Invalid Priroity Group: " + pgName
    log.Error(errStr)
    return pgName, tlerr.InvalidArgsError{Format:errStr}

}

/* Validate whether intf queues valid or not */
func validateQosIntfQueue(dbs [db.MaxDB]*db.DB, intfName string, queueName string) error {

    log.Info(" validateQosIntfQueue -intfName ", intfName, " queueName ", queueName);

    if !strings.Contains(queueName, ":") {
        errStr := "Invalid Queue: " + queueName
        log.Error(errStr)
        return tlerr.InvalidArgsError{Format:errStr}
    }
    queue := strings.Split(queueName, ":")
    if (intfName != queue[0]) {
        errStr := "Invalid Queue: " + queueName + " on interface " + intfName
        log.Error(errStr)
        return tlerr.InvalidArgsError{Format:errStr}
    }

    if (dbs[db.CountersDB] != nil) {
        _, err := getIntfQCountersTblKey(dbs[db.CountersDB], queueName)
        if err != nil {
            errStr := "Invalid Queue: " + queueName + " on interface " + intfName
            log.Error(errStr)
            return tlerr.InvalidArgsError{Format:errStr}
        }
    }
    return nil
}

/* Validate whether intf pg valid or not */

func validateQosIntfPg(dbs [db.MaxDB]*db.DB, intfName string, pgName string) error {

    log.Info(" validateQosIntfPg -intfName ", intfName, " pgName ", pgName);
    if !strings.Contains(pgName, ":") {
        errStr := "Invalid Priority group: " + pgName
        log.Error(errStr)
        return tlerr.InvalidArgsError{Format:errStr}
    }

    pg := strings.Split(pgName, ":")
    if (intfName != pg[0]) {
        errStr := "Invalid Priority Group: " + pgName + "on interface " + intfName
        return tlerr.InvalidArgsError{Format:errStr}
    }

    if (dbs[db.CountersDB] != nil) {
        _, err := getIntfPGCountersTblKey(dbs[db.CountersDB], pgName)
        if err != nil {
            errStr := "Invalid Priority Group: " + pgName + "on interface " + intfName
            log.Error(errStr)
            return tlerr.InvalidArgsError{Format:errStr}
        }
    }
    return nil
}

func validateQosQueue(dbs [db.MaxDB]*db.DB, queueName string) error {

    log.Info(" validateQosQueue - queueName ", queueName);
    if (dbs[db.CountersDB] != nil) {
        _, err := getIntfQCountersTblKey(dbs[db.CountersDB], queueName)
        if err != nil {
            errStr := "Invalid Queue:" + queueName
            log.Error(errStr)
            return tlerr.InvalidArgsError{Format:errStr}
        }
    }

    return nil
}

func validateQosPg(dbs [db.MaxDB]*db.DB, pgName string) error {

    log.Info(" validateQosPg - pgName ", pgName);
    if (dbs[db.CountersDB] != nil) {
        _, err := getIntfPGCountersTblKey(dbs[db.CountersDB], pgName)
        if err != nil {
            errStr := "Invalid Priority Group:" + pgName
            log.Error(errStr)
            return tlerr.InvalidArgsError{Format:errStr}
        }
    }
    return nil
}

var DbToYang_qos_get_one_intf_one_q_counters_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    log.Info("inParams.uri is: %s", inParams.uri)
    intfName := pathInfo.Var("interface-id")
    dbIntfName := utils.GetNativeNameFromUIName(&intfName)
    queueName := pathInfo.Var("name")
    targetUriPath, _ := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath is ", targetUriPath)

    dbQueueName, err := getDbQueueName(queueName)
    if err != nil {
        log.Info("DbToYang_qos_get_one_intf_one_q_counters_xfmr - invalid queue ", queueName)
        return err
    }

    err = validateQosIntfQueue(inParams.dbs, *dbIntfName, dbQueueName)
    if err != nil {
        log.Info("DbToYang_qos_get_one_intf_one_q_counters_xfmr - invalid interface ",
                 *dbIntfName, " queue ", queueName, " db qname ", dbQueueName)
        return err
    }


    var state_counters * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue_State
    var cfg * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue_Config

    if qosIntfsObj != nil && qosIntfsObj.Interface != nil && len(qosIntfsObj.Interface) > 0 {
        queuesObj := qosIntfsObj.Interface[intfName].Output.Queues

        var queueObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue
        if queuesObj != nil {
            queueObj = queuesObj.Queue[queueName]
            ygot.BuildEmptyTree(queueObj)
        }
        if queueObj != nil {
            state_counters = queueObj.State
            cfg = queueObj.Config
        }
    }

    var oid string

    switch targetUriPath {
    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue":
        fallthrough
    case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/config":
        if cfg == nil  {
            log.Info("DbToYang_qos_get_one_intf_one_q_counters_xfmr - cfg is nil")
            return err
        }
        cfg.Name = &queueName
    }

    switch targetUriPath {
        case "/openconfig-qos:qos/interfaces/interface/output/queues/queue":
            targetUriPath = targetUriPath + "/state"
            fallthrough
        case "/openconfig-qos:qos/interfaces/interface/output/queues/queue/state":
            if state_counters == nil  {
                log.Info("DbToYang_qos_get_one_intf_one_q_counters_xfmr - state_counters is nil")
                return err
            }

            state_counters.Name = &queueName

            oid, err = getIntfQCountersTblKey(inParams.dbs[inParams.curDb], dbQueueName)
            if err != nil {
                log.Info(err)
                return err
            }

            queueTypeMap, _ := doGetAllQueueTypeMap(inParams.dbs[inParams.curDb]);

            getQTrafficType(queueTypeMap, oid, state_counters)

            err = populateQCounters(inParams, targetUriPath, oid, state_counters)
        default:
            if state_counters == nil  {
                log.Info("DbToYang_qos_get_one_intf_one_q_counters_xfmr - state_counters is nil")
                return err
            }

            state_counters.Name = &queueName

            oid, err = getIntfQCountersTblKey(inParams.dbs[inParams.curDb], dbQueueName)
            if err != nil {
                log.Info(err)
                return err
            }

            queueTypeMap, _ := doGetAllQueueTypeMap(inParams.dbs[inParams.curDb]);

            getQTrafficType(queueTypeMap, oid, state_counters)

            err = populateQCounters(inParams, targetUriPath, oid, state_counters)
    }
    log.Info("DbToYang_qos_get_one_intf_one_q_counters_xfmr - finished ")

    return err
}

var YangToDb_qos_get_one_intf_all_q_counters_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)
    if (inParams.oper != GET) {
        return res_map, tlerr.NotSupported("Operation Not Supported")
    }
    return res_map, err
}
var DbToYang_qos_get_one_intf_all_q_counters_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    log.Info("DbToYang_qos_get_one_intf_all_q_counters_xfmr - started ")


    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("interface-id")
    dbIntfName := utils.GetNativeNameFromUIName(&intfName)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    if strings.HasPrefix(targetUriPath,"/openconfig-qos:qos/interfaces/interface/output/queues/queue"){
        log.Info("DbToYang_qos_get_one_intf_all_q_counters_xfmr - interface specific ")
        return DbToYang_qos_get_one_intf_one_q_counters_xfmr(inParams)
    }

    if (!strings.HasPrefix(targetUriPath, "/openconfig-qos:qos/interfaces/interface/output/queues")) {
        log.Info("unexpected uri path: ", targetUriPath)
        return err
    }

    targetUriPath = targetUriPath + "/queue/state"

    var intfObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface
    if qosIntfsObj != nil && qosIntfsObj.Interface != nil && len(qosIntfsObj.Interface) > 0 {
        var ok bool = false
        if intfObj, ok = qosIntfsObj.Interface[intfName]; !ok {
            intfObj, _ = qosIntfsObj.NewInterface(intfName)
        }
        ygot.BuildEmptyTree(intfObj)
    } else {
        ygot.BuildEmptyTree(qosIntfsObj)
        intfObj, _ = qosIntfsObj.NewInterface(intfName)
        ygot.BuildEmptyTree(intfObj)
    }

    var queuesObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues
    if intfObj != nil {
        if intfObj.Output != nil {
            ygot.BuildEmptyTree(intfObj.Output)
        }
        queuesObj = intfObj.Output.Queues
        if queuesObj != nil {
            ygot.BuildEmptyTree(queuesObj)
        }
    }

    var queueOidMap db.Value
    var present bool
    oidMap, present := inParams.txCache.Load("COUNTERS_QUEUE_NAME_MAP")
    if !present {
        queueOidMap, _ = doGetAllQueueOidMap(inParams.dbs[inParams.curDb]);
        inParams.txCache.Store("COUNTERS_QUEUE_NAME_MAP", queueOidMap)
        log.V(3).Info("Loading queueOidMap")
    } else {
        queueOidMap = oidMap.(db.Value)
        log.V(3).Info("Reuse queueOidMap")
    }

    queueOidMapFields := queueOidMap.Field

    var queueTypeMap db.Value
    typeMap, present := inParams.txCache.Load("COUNTERS_QUEUE_TYPE_MAP")
    if !present {
        queueTypeMap, _ = doGetAllQueueTypeMap(inParams.dbs[inParams.curDb]);
        inParams.txCache.Store("COUNTERS_QUEUE_TYPE_MAP", queueTypeMap)
        log.V(3).Info("Loading queueTypeMap")
    } else {
        queueTypeMap = typeMap.(db.Value)
        log.V(3).Info("Reuse queueTypeMap")
    }

    for keyString, oid := range queueOidMapFields {
        s := strings.Split(keyString, ":")

        ifName := s[0]
        queueName := s[1]

        if ifName == "" {
            continue
        }
        if queueName == "" {
            continue
        }

        if strings.Compare(ifName, *dbIntfName) != 0  {
            continue
        }

        queueName = intfName + ":" + queueName
        queueObj, _ := queuesObj.NewQueue(queueName)
        ygot.BuildEmptyTree(queueObj)
        queueObj.Name = &queueName
        if queueObj.State == nil {
            ygot.BuildEmptyTree(queueObj.State)
        }

        var state_counters * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue_State
        var cfg * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Output_Queues_Queue_Config
        state_counters = queueObj.State
        cfg = queueObj.Config

        if state_counters == nil  {
            log.Info("DbToYang_qos_get_one_intf_all_q_counters_xfmr - state_counters is nil")
            return err
        }

        if cfg == nil  {
            log.Info("DbToYang_qos_get_one_intf_all_q_counters_xfmr - cfg is nil")
            return err
        }

        cfg.Name = &queueName
        state_counters.Name = &queueName

        getQTrafficType(queueTypeMap, oid, state_counters)

        err = populateQCounters(inParams, targetUriPath, oid, state_counters)

    }

    log.Info("DbToYang_qos_get_one_intf_all_q_counters_xfmr - finished ")

    return err
}

var Subscribe_qos_get_one_intf_all_q_counters_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams

    log.Info("Subscribe_qos_get_one_intf_all_q_counters_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    ifname := pathInfo.Var("interface-id")
    dbIfName := utils.GetNativeNameFromUIName(&ifname)
    if_name := *dbIfName
    log.Info("Subscribe_qos_get_one_intf_all_q_counters_xfmr: ", if_name)

    result.dbDataMap = make(RedisDbSubscribeMap)
    log.Infof("Subscribe_qos_get_one_intf_all_q_counters_xfmr path:%s; template:%s targetUriPath:%s key:%s",
              pathInfo.Path, pathInfo.Template, targetUriPath, if_name)

    result.isVirtualTbl = true
    result.needCache = true
    result.onChange = OnchangeDisable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}
var DbToYang_qos_get_one_intf_one_pg_counters_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    log.Info("inParams.uri is: %s", inParams.uri)
    intfName := pathInfo.Var("interface-id")
    dbIntfName := utils.GetNativeNameFromUIName(&intfName)
    pgName := pathInfo.Var("name")

    targetUriPath, _ := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath is ", targetUriPath)

    dbPgName, err := getDbPgName(pgName)
    if err != nil {
        log.Info("DbToYang_qos_get_one_intf_one_pg_counters_xfmr - invalid pg ", pgName)
        return err
    }

    err = validateQosIntfPg(inParams.dbs, *dbIntfName, dbPgName)
    if err != nil {
        return err
    }

    var state_counters * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups_PriorityGroup_State
    var cfg * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups_PriorityGroup_Config
    var pgObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups_PriorityGroup

    if qosIntfsObj != nil && qosIntfsObj.Interface != nil && len(qosIntfsObj.Interface) > 0 {
        pgsObj := qosIntfsObj.Interface[intfName].Input.PriorityGroups

        if pgsObj != nil {
            pgObj = pgsObj.PriorityGroup[pgName]
            ygot.BuildEmptyTree(pgObj)
        }
        if pgObj != nil {
            pgObj.Name = &pgName
            if pgObj.State == nil {
                ygot.BuildEmptyTree(pgObj.State)
            }
            if pgObj.Config == nil {
                ygot.BuildEmptyTree(pgObj.Config)
            }
            state_counters = pgObj.State
            cfg = pgObj.Config
        }
    }

    switch targetUriPath {
        case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group":
            fallthrough
        case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group":
            fallthrough
        case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/config":
            fallthrough
        case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/config":
            if cfg == nil  {
                log.Info("DbToYang_qos_get_one_intf_one_pg_counters_xfmr - cfg is nil")
                return err
            }
            cfg.Name = &pgName
    }

    var oid string

    switch targetUriPath {
         case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group":
             targetUriPath = targetUriPath + "/state"
             fallthrough
         case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group":
             targetUriPath = targetUriPath + "/state"
             fallthrough
         case "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group/state":
             fallthrough
         case "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group/state":
             if state_counters == nil  {
                 log.Info("DbToYang_qos_get_one_intf_one_pg_counters_xfmr - state_counters is nil")
                 return err
             }
             state_counters.Name = &pgName

             oid, err = getIntfPGCountersTblKey(inParams.dbs[inParams.curDb], dbPgName)
             if err != nil {
                 log.Info(err)
                 return err
             }
             err = populatePriorityGroupCounters(inParams, targetUriPath, oid, state_counters)
         default:
             log.Info("Entering default branch")
             if state_counters == nil  {
                 log.Info("DbToYang_qos_get_one_intf_one_pg_counters_xfmr - state_counters is nil")
                 return err
             }
             state_counters.Name = &pgName

             oid, err = getIntfPGCountersTblKey(inParams.dbs[inParams.curDb], dbPgName)
             if err != nil {
                 log.Info(err)
                 return err
             }

             err = populatePriorityGroupCounters(inParams, targetUriPath, oid, state_counters)

    }
    log.Info("DbToYang_qos_get_one_intf_one_pg_counters_xfmr - finished ")

    return err
}

var YangToDb_qos_get_one_intf_all_pg_counters_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)
    if (inParams.oper != GET) {
        return res_map, tlerr.NotSupported("Operation Not Supported")
    }
    return res_map, err
}

var DbToYang_qos_get_one_intf_all_pg_counters_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    log.Info("DbToYang_qos_get_one_intf_all_pg_counters_xfmr - started ")


    qosIntfsObj := getQosIntfRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("interface-id")
    dbIntfName := utils.GetNativeNameFromUIName(&intfName)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    if (strings.Contains(targetUriPath, "/openconfig-qos:qos/interfaces/interface/input/priority-groups/priority-group")  ||
    strings.Contains(targetUriPath, "/openconfig-qos:qos/interfaces/interface/input/openconfig-qos-ext:priority-groups/priority-group") ){
        return DbToYang_qos_get_one_intf_one_pg_counters_xfmr(inParams)
    }

    if (!strings.Contains(targetUriPath, "priority-groups")) {
        log.Info("unexpected uri path: ", targetUriPath)
        return err
    }

    targetUriPath = targetUriPath + "/priority-group/state"

    var intfObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface
    if qosIntfsObj != nil && qosIntfsObj.Interface != nil && len(qosIntfsObj.Interface) > 0 {
        var ok bool = false
        if intfObj, ok = qosIntfsObj.Interface[intfName]; !ok {
            intfObj, _ = qosIntfsObj.NewInterface(intfName)
        }
        ygot.BuildEmptyTree(intfObj)
    } else {
        ygot.BuildEmptyTree(qosIntfsObj)
        intfObj, _ = qosIntfsObj.NewInterface(intfName)
        ygot.BuildEmptyTree(intfObj)
    }

    var priorityGroupsObj *ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups
    if intfObj != nil {
        if intfObj.Input != nil {
            ygot.BuildEmptyTree(intfObj.Input)
        }
        priorityGroupsObj = intfObj.Input.PriorityGroups
        if priorityGroupsObj != nil {
            ygot.BuildEmptyTree(priorityGroupsObj)
        }
    }

    var priorityGroupMap db.Value
    var present bool
    pgMap, present := inParams.txCache.Load("COUNTERS_PG_NAME_MAP")
    if !present {
        priorityGroupMap, _ = doGetAllPriorityGroupOidMap(inParams.dbs[inParams.curDb]);
        inParams.txCache.Store("COUNTERS_PG_NAME_MAP", priorityGroupMap)
        log.V(3).Info("Loading priorityGroupMap")
    } else {
        priorityGroupMap = pgMap.(db.Value)
        log.V(3).Info("Reuse priorityGroupMap")
    }

    priorityGroupMapFields := priorityGroupMap.Field

    for keyString, oid := range priorityGroupMapFields {
        s := strings.Split(keyString, ":")

        ifName := s[0]
        priorityGroupName := s[1]

        if ifName == "" {
            continue
        }
        if priorityGroupName == "" {
            continue
        }

        if strings.Compare(ifName, *dbIntfName) != 0  {
            continue
        }

        priorityGroupName = intfName + ":" + priorityGroupName
        priorityGroupObj, _ := priorityGroupsObj.NewPriorityGroup(priorityGroupName)
        ygot.BuildEmptyTree(priorityGroupObj)
 
        priorityGroupObj.Name = &priorityGroupName
        if priorityGroupObj.State == nil {
            ygot.BuildEmptyTree(priorityGroupObj.State)
        }
        if priorityGroupObj.Config == nil {
            ygot.BuildEmptyTree(priorityGroupObj.Config)
        }

        var state_counters * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups_PriorityGroup_State
        var cfg * ocbinds.OpenconfigQos_Qos_Interfaces_Interface_Input_PriorityGroups_PriorityGroup_Config
        state_counters = priorityGroupObj.State
        cfg = priorityGroupObj.Config

        if state_counters == nil  {
            log.Info("DbToYang_qos_get_one_intf_all_pg_counters_xfmr - state_counters is nil")
            return err
        }

        if cfg == nil  {
            log.Info("DbToYang_qos_get_one_intf_all_pg_counters_xfmr - cfg is nil")
            return err
        }

        state_counters.Name = &priorityGroupName
        cfg.Name = &priorityGroupName

        err = populatePriorityGroupCounters(inParams, targetUriPath, oid, state_counters)

    }

    log.Info("DbToYang_qos_get_one_intf_all_pg_counters_xfmr - finished ")

    return err
}

var Subscribe_qos_get_one_intf_all_pg_counters_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams

    log.Info("Subscribe_qos_get_one_intf_all_pg_counters_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    ifname := pathInfo.Var("interface-id")
    dbIfName := utils.GetNativeNameFromUIName(&ifname)
    if_name := *dbIfName
    log.Info("Subscribe_qos_get_one_intf_all_pg_counters_xfmr: ", if_name)

    result.dbDataMap = make(RedisDbSubscribeMap)
    log.Infof("Subscribe_qos_get_one_intf_all_pg_counters_xfmr path:%s; template:%s targetUriPath:%s key:%s",
              pathInfo.Path, pathInfo.Template, targetUriPath, if_name)

    result.isVirtualTbl = true
    result.needCache = true
    result.onChange = OnchangeDisable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, err
}

/* RPC for clear counters */
var rpc_clear_qos RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_clear_bgp")
    var err error
    var status string
    var counter_type, queue, pg, ifname, qbufftype, pgbufftype string
    var dbQueueName, dbPgName string
    var clearall, wred, persistent bool
    var watermarks, counters bool
    var mapData map[string]interface{}
    var dbIntfName *string
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil, err
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-qos-clear:output"`
    }

    log.Info("In rpc_clear_qos ", mapData)

    input := mapData["sonic-qos-clear:input"]
    mapData = input.(map[string]interface{})

    log.Info("In rpc_clear_qos ", mapData)

    if value, ok := mapData["counter-type"].(string) ; ok {
        counter_type = value
        log.Info("In counter-type ", counter_type)
    }

    if counter_type == "queue" {

        if cMapData, ok := mapData["counters"].(map[string]interface{}) ; ok {
            if value, ok := cMapData["all"].(bool) ; ok {
                clearall = value
                log.Info("In clearall", clearall)
            }
            if value, ok := cMapData["interface"].(string) ; ok {
                log.Info("In interface ", value)
                ifname = value
            }
            if value, ok := cMapData["queue"].(string) ; ok {
                log.Info("In queue ", value)
                queue = value
            }
            if value, ok := cMapData["wred"].(bool) ; ok {
                wred = value
                log.Info("In wred ", wred)
            }
            counters = true
        }

        if wMapData, ok := mapData["watermarks"].(map[string]interface{}) ; ok {
            if value, ok := wMapData["persistent"].(bool) ; ok {
                log.Info("In persistent", value)
                persistent = value
            }

            if value, ok := wMapData["queue-type"].(string) ; ok {
                log.Info("In queue-type ", value)
                if value == "unicast" {
                    qbufftype = "UC"
                }  else if value == "multicast" {
                    qbufftype = "MC"
                } else {
                    qbufftype = "AC"
                }
            }

            if value, ok := wMapData["all"].(bool) ; ok {
                clearall = value
                log.Info("In clearall", clearall)
            }
            if value, ok := wMapData["interface"].(string) ; ok {
                log.Info("In interface ", value)
                ifname = value
            }
            if value, ok := wMapData["queue"].(string) ; ok {
                log.Info("In queue ", value)
                queue = value
            }
            watermarks = true
        }

        if ifname != "" {
            dbIntfName = utils.GetNativeNameFromUIName(&ifname)
            err = validateQosIntf(nil, dbs, *dbIntfName)
            if err != nil {
                log.Info("Invalid interface ", ifname)
                result.Output.Status = fmt.Sprintf("Error: Invalid interface %s", ifname)
                return json.Marshal(&result)
            }
        }

        if queue != "" {
            dbQueueName, err = getDbQueueName(queue)
            if err != nil {
                log.Info("Invalid queue ", queue)
                result.Output.Status = fmt.Sprintf("Error: Invalid queue %s", queue)
                return json.Marshal(&result)
            }

            err = validateQosQueue(dbs, dbQueueName)
            if err != nil {
                log.Info("Invalid queue ", queue)
                result.Output.Status = fmt.Sprintf("Error: Invalid queue %s", queue)
                return json.Marshal(&result)
            }
        }

        queueOidMap, _ := doGetAllQueueOidMap(dbs[db.CountersDB]);

        queueOidMapFields := queueOidMap.Field

        queueTypeMap, _ := doGetAllQueueTypeMap(dbs[db.CountersDB]);

        for keyString, oid := range queueOidMapFields {
            s := strings.Split(keyString, ":")

            intfName := s[0]
            queueName := s[1]

            if intfName == "" {
                continue
            }

            if queueName == "" {
                continue
            }

            if ifname != "" &&  *dbIntfName != intfName {
                continue
            }

            q := strings.Split(dbQueueName, ":")
            if queue != "" &&  ((q[1] != queueName) || (q[0] != intfName)) {
                continue
            }

            qType := getQType(queueTypeMap, oid)


            if qbufftype != "" && qbufftype != "AC" && qbufftype != qType {
                continue
            }

            log.Info("In intfName ", intfName, " queueName ", queueName,  " getQType: ", qType)
            if (counters) { 
                verr, cerr := resetQosCounters(dbs[db.CountersDB], oid)
                if verr != nil || cerr != nil {
                    log.Info("Failed to reset counters for ", intfName, " queue", queueName)
                    result.Output.Status = fmt.Sprintf("Error: OID info not found in COUNTERS for intf %s queue %s", intfName, queueName)
                    return json.Marshal(&result)
                } else {
                    log.Info("Counters reset for ", intfName, " queue", queueName)
                }
            } else if (watermarks) {
                if (persistent) {
                    cerr := resetPersistentWatermark(dbs[db.CountersDB], oid, "queue", "shared")
                    if cerr != nil {
                        log.Info("Failed to reset counters for ", intfName, " queue", queueName)
                        result.Output.Status = fmt.Sprintf("Error: OID info not found in PERSISTENT_WATERMARKS for intf %s queue %s", intfName, queueName)
                        return json.Marshal(&result)
                    } else {
                        log.Info("Counters reset for ", intfName, " queue", queueName)
                    }
                } else {

                    log.Info("Counters reset for ", intfName, " queue", queueName)
                    cerr := resetUserWatermark(dbs[db.CountersDB], oid, "queue", "shared")
                    if cerr != nil {
                        log.Info("Failed to reset counters for ", intfName, " queue", queueName)
                        result.Output.Status = fmt.Sprintf("Error: OID info not found in USER_WATERMARKS for intf %s queue %s", intfName, queueName)
                        return json.Marshal(&result)
                    } else {
                        log.Info("Counters reset for ", intfName, " queue", queueName)
                    }
                }
            }
        }
    }

    if counter_type == "priority-group" {
        if cMapData, ok := mapData["counters"].(map[string]interface{}) ; ok {
            log.Info("In cMapData ", cMapData)
            if value, ok := cMapData["all"].(bool) ; ok {
                log.Info("In clearall", value)
            }
            if value, ok := cMapData["interface"].(string) ; ok {
                log.Info("In interface ", value)
                 ifname = value
            }
            if value, ok := mapData["priority-group"].(string) ; ok {
                log.Info("In Pg ", value)
                pg = value
            }
        }

        if wMapData, ok := mapData["watermarks"].(map[string]interface{}) ; ok {
            if value, ok := wMapData["persistent"].(bool) ; ok {
                log.Info("In persistent", value)
                persistent = value
            }
            if value, ok := wMapData["pg-type"].(string) ; ok {
                log.Info("In pg-type ", value)
                 pgbufftype = value
            }
            if value, ok := wMapData["all"].(bool) ; ok {
                log.Info("In clearall", value)
            }
            if value, ok := wMapData["interface"].(string) ; ok {
                log.Info("In interface ", value)
                 ifname = value
            }
            if value, ok := mapData["priority-group"].(string) ; ok {
                log.Info("In Pg ", value)
                pg = value
            }
            watermarks = true
        }
        if ifname != "" {
            dbIntfName = utils.GetNativeNameFromUIName(&ifname)
            err = validateQosIntf(nil, dbs, *dbIntfName)
            if err != nil {
                log.Info("Invalid interface ", ifname)
                result.Output.Status = fmt.Sprintf("Error: Invalid interface %s", ifname)
                return json.Marshal(&result)
            }
        }

        if pg != "" {
            dbPgName, err = getDbPgName(pg)
            if err != nil {
                log.Info("Invalid priority group ", pg)
                result.Output.Status = fmt.Sprintf("Error: Invalid priority group %s", pg)
                return json.Marshal(&result)
            }

            err = validateQosPg(dbs, dbPgName)
            if err != nil {
                log.Info("Invalid priority group ", pg)
                result.Output.Status = fmt.Sprintf("Error: Invalid priority group %s", pg)
                return json.Marshal(&result)
            }
        }

        priorityGroupOidMap, _ := doGetAllPriorityGroupOidMap(dbs[db.CountersDB]);

        priorityGroupOidMapFields := priorityGroupOidMap.Field

        for keyString, oid := range priorityGroupOidMapFields {
            s := strings.Split(keyString, ":")

            intfName := s[0]
            priorityGroupName := s[1]

            if intfName == "" {
                continue
            }

            if priorityGroupName == "" {
                continue
            }

            if ifname != "" && *dbIntfName != intfName {
                continue
            }

            p := strings.Split(dbPgName, ":")
            if pg != "" &&((p[0] != intfName) || (p[1] != priorityGroupName)) {
                continue
            }

            log.Info("In intfName ", intfName, " priorityGroupName ", priorityGroupName, " oid ", oid)

            if (counters) {
                verr, cerr := resetQosCounters(dbs[db.CountersDB], oid)
                if verr != nil || cerr != nil {
                    log.Info("Failed to reset counters for ", intfName, " pg ", priorityGroupName)
                    result.Output.Status = fmt.Sprintf("Error: OID info not found in COUNTERS for intf %s pgName %s", intfName, priorityGroupName)
                    return json.Marshal(&result)
                } else {
                    log.Info("Counters reset for ", intfName, " pg ", priorityGroupName)
                }
            } else if (watermarks) {
                if (persistent) {
                    cerr := resetPersistentWatermark(dbs[db.CountersDB], oid, "priority-group", pgbufftype)
                    if cerr != nil {
                        log.Info("Failed to reset counters for ", intfName, " pg ", priorityGroupName)
                        result.Output.Status = fmt.Sprintf("Error: OID info not found in PERSISTENT_WATERMARKS for intf %s pgName %s", intfName, priorityGroupName)
                        return json.Marshal(&result)
                    } else {
                        log.Info("Counters reset for ", intfName, " pg ", priorityGroupName)
                    }
                } else {
                    cerr := resetUserWatermark(dbs[db.CountersDB], oid, "priority-group", pgbufftype)
                    if cerr != nil {
                        log.Info("Failed to reset counters for ", intfName, " pg ", priorityGroupName)
                        result.Output.Status = fmt.Sprintf("Error: OID info not found in USER_WATERMARKS for intf %s pgName %s", intfName, priorityGroupName)
                        return json.Marshal(&result)
                    } else {
                        log.Info("Counters reset for ", intfName, " pg ", priorityGroupName)
                    }
                }
            }
        }
    }

    status = "Success: Cleared Counters"
    result.Output.Status = status
    return json.Marshal(&result)
}

var THRESHOLD_BREACH_COUNTER_MAP = map[string]string{
    "SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES"    : "counter",
    "SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES" : "counter",
    "SAI_QUEUE_STAT_SHARED_WATERMARK_BYTES"                     : "counter",
}

var DbToYang_threshold_breach_counter_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    result := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_threshold_breach_counter_field_xfmr", data, inParams.ygRoot)

    for watermark_str := range  THRESHOLD_BREACH_COUNTER_MAP {
        // try each one of the strings
        val, found := data["THRESHOLD_BREACH_TABLE"][inParams.key].Field[watermark_str] 
        if  found {
            result["counter"] = val
            break
        }
    }

    return result, nil
}

var qos_intf_table_xfmr TableXfmrFunc = func (inParams XfmrParams) ([]string, error) {
    var tblList []string
    var key string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    ifName := pathInfo.Var("interface-id");
    if log.V(3) {
        log.Info("qos_intf_table_xfmr - Uri: ", inParams.uri, " requestUri ", inParams.requestUri, 
                 " targetUriPath ", targetUriPath, " ifName ", ifName);
    }
    tbl_name := "QOS_PORT"
    if len(ifName) != 0 {
        dbifName := utils.GetNativeNameFromUIName(&ifName)
        key = ifName
        if log.V(3) {
            log.Info("qos_intf_table_xfmr - intf_table_xfmr Intf key is present, curr DB ", inParams.curDb)
        }

        if utils.IsIntfSubInterface(dbifName) {
            tbl_name = "VLAN_SUB_INTERFACE"
        } else if strings.HasPrefix(*dbifName, "Eth") {
            tbl_name = "PORT"
        } else if strings.HasPrefix(*dbifName, "CPU") {
            tbl_name = "QOS_PORT"
            *inParams.isVirtualTbl = true
        } else if strings.HasPrefix(*dbifName, "Vlan") {
            tbl_name = "VLAN"
        } else if strings.HasPrefix(*dbifName, "PortChannel") {
            tbl_name = "PORTCHANNEL"
        } else {
            log.Info("qos_intf_table_xfmr - Invalid interface type");
            return tblList, errors.New("Invalid interface type");
        }

        if (inParams.dbDataMap != nil) {
            if _, ok := (*inParams.dbDataMap)[db.ConfigDB][tbl_name]; !ok {
                (*inParams.dbDataMap)[db.ConfigDB][tbl_name] = make(map[string]db.Value)
            }
            if _, ok := (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key]; !ok {
                (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key] = db.Value{Field: make(map[string]string)}
                (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key].Field["NULL"] = "NULL"
            }
        }
    } else {
        tbl_name := "QOS_PORT"
        *inParams.isVirtualTbl = true
        if log.V(3) {
            log.Info("TableXfmrFunc - intf_table_xfmr Intf key is not present, curr DB ", inParams.curDb)
        }
        if(inParams.dbDataMap != nil) {
            if _, ok := (*inParams.dbDataMap)[db.ConfigDB][tbl_name]; !ok {
                (*inParams.dbDataMap)[db.ConfigDB][tbl_name] = make(map[string]db.Value)
            } else {
                tblList = append(tblList, tbl_name)
                return tblList, nil
            }

            intfKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:"PORT"})
            if len(intfKeys) > 0 {
                for _, intfKey := range intfKeys {

                    ifName = intfKey.Get(0)
                    if_name := utils.GetUINameFromNativeName(&ifName)
                    key := *if_name
                    if _, ok := (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key]; !ok {
                        (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key] = db.Value{Field: make(map[string]string)}
                        (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key].Field["NULL"] = "NULL"
                    }
                }
            }

            key = "CPU"
            if _, ok := (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key]; !ok {
                (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key] = db.Value{Field: make(map[string]string)}
            }
            mapIntfKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:"PORT_QOS_MAP"})
            if len(mapIntfKeys) > 0 {
                if _, ok := (*inParams.dbDataMap)[db.ConfigDB][tbl_name]; !ok {
                    (*inParams.dbDataMap)[db.ConfigDB][tbl_name] = make(map[string]db.Value)
                }
                for _, mapIntfKey := range mapIntfKeys {

                    ifName = mapIntfKey.Get(0)
                    if_name := utils.GetUINameFromNativeName(&ifName)
                    key := *if_name
                    if _, ok := (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key]; !ok {
                        (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key] = db.Value{Field: make(map[string]string)}
                        (*inParams.dbDataMap)[db.ConfigDB][tbl_name][key].Field["NULL"] = "NULL"
                    }
                }
            } 
        }
    }
    tblList = append(tblList, tbl_name)
    return tblList, nil
}
var YangToDb_qos_intf_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ifName string
    pathInfo := NewPathInfo(inParams.uri)
    ifName = pathInfo.Var("interface-id")
    if log.V(3) {
        log.Info("Entering YangToDb_qos_intf_tbl_key_xfmr Uri ", inParams.uri, " interface ", ifName)
    }
    return ifName, err
}

var DbToYang_qos_intf_tbl_key_xfmr  KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    res_map["interface-id"] = inParams.key 
    if log.V(3) {
       log.Info("Entering DbToYang_qos_intf_tbl_key_xfmr - End ", inParams.uri, " res_map ", res_map)
    }
    return res_map, nil
}

var YangToDb_qos_intf_intf_id_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    requestUriPath, _ := getYangPathFromUri(inParams.requestUri)
    if (inParams.oper != GET && requestUriPath == "/openconfig-qos:qos/interfaces/interface/interface-id" ) {
        return res_map, tlerr.NotSupported("Operation Not Supported")
    }
    return res_map, nil
}

var DbToYang_qos_intf_intf_id_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    res_map["interface-id"] = inParams.key 
    return res_map, nil
}

var YangToDb_qos_intf_intfref_intf_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    if log.V(3) {
        log.Info("YangToDb_qos_intf_intfref_intf_fld_xfmr: ", inParams.key)
    }
    requestUriPath, _ := getYangPathFromUri(inParams.requestUri)
    if (inParams.oper != GET && requestUriPath == "/openconfig-qos:qos/interfaces/interface/interface-ref" ) {
        return res_map, tlerr.NotSupported("Operation Not Supported")
    }

    return res_map, nil
}

var DbToYang_qos_intf_intfref_intf_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    res_map["interface"] = inParams.key 
    if log.V(3) {
        log.Info("Entering DbToYang_qos_intf_intfref_intf_fld_xfmr - End ", inParams.uri, " res_map ", res_map)
    }
    return res_map, nil
}

var YangToDb_wred_profile_name_empty_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    if log.V(3) {
       log.Info("YangToDb_wred_profile_name_empty_fld_xfmr: ", inParams.key)
    }
    return res_map, nil
}

var YangToDb_wred_profile_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    if log.V(3) {
       log.Info("YangToDb_wred_profile_name_fld_xfmr: ", inParams.key)
    }
    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_wred_profile_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error
    /*name attribute corresponds to key in redis table*/
    key := inParams.key
    log.Info("DbToYang_wred_profile_name_fld_xfmr: ", key)
    setTblKey := strings.Split(key, "|")
    setName := setTblKey[0]

    res_map["name"] = setName
    return res_map, err
}

var YangToDb_wred_ecn_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	if inParams.param == nil {
	    res_map["ecn"] = ""
	    return res_map, err
	}
	ecn, _ := inParams.param.(ocbinds.E_OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn)
	log.Info("YangToDb_wred_ecn_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " ecn: ", ecn)
	res_map["ecn"] = findInMap(ECN_MAP, strconv.FormatInt(int64(ecn), 10))
	return res_map, err
}

var DbToYang_wred_ecn_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_wred_ecn_fld_xfmr ", data, inParams.key)

    opt, ok := data["WRED_PROFILE"][inParams.key].Field["ecn"]
    if ok {
        oc_ecn := findInMap(ECN_MAP, opt)
        n, _ := strconv.ParseInt(oc_ecn, 10, 64)
        result["ecn"] = ocbinds.E_OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn(n).ΛMap()["E_OpenconfigQos_Qos_WredProfiles_WredProfile_Config_Ecn"][n].Name
    }
    log.Info("DbToYang_wred_ecn_fld_xfmr ", result)
	return result, err
}

var YangToDb_qos_threshold_breach_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var id string
    log.Info("Entering YangToDb_qos_threshold_breach_key_xfmr Uri ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    id = pathInfo.Var("id")
    if len(id) == 0 {
       log.Info("YangToDb_qos_threshold_breach_key_xfmr- no key ")
       return id, err
    }
    breach_id := "breach-report:" + id
    log.Info("YangToDb_qos_threshold_breach_key_xfmr - breach_id ", breach_id)
    return breach_id, err
}

var DbToYang_qos_threshold_breach_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var id string
    res_map := make(map[string]interface{})

    if strings.Contains(inParams.key, ":") {
       id = strings.Split(inParams.key, ":")[1]
    } else {
       id = inParams.key
    }

    res_map["id"] = id
    log.Info("DbToYang_qos_threshold_breach_key_xfmr ", inParams.uri, "breach_id = ", inParams.key, "res_map - ", res_map)
    return res_map, nil
}


/* RPC for clear threshold breach */
var rpc_oc_clear_threshold_breach RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string`json:"status-detail"`
        } `json:"openconfig-qos-ext:output"`
    }
    result.Output.Status = 1
    /* Get input data */
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Errorf("Failed to unmarshall given input data, error=%v", err)
        result.Output.Status_detail = "Error: Unable to unmarshall given input data"
        return json.Marshal(&result)
    }
    input := mapData["openconfig-qos-ext:input"]
    mapData = input.(map[string]interface{})
    input = mapData["breach-event-id"]
    input_str := fmt.Sprintf("%v", input)
    log.Info("INPUT received! : ", input_str)

    log.Info("rpc_oc_clear_threshold_breach, Clear threshold breaches for breach_event_id: ", input_str)
    verr := clearThresholdBreaches(dbs[db.CountersDB], input_str)
    if verr != nil {
		log.Errorf("Unable to clear threshold breaches for breach_event_id: %v, error=%v", input_str, verr)
    } else {
        log.Info("Threshold breaches successfully cleared for breach_event_id: ", input_str)
    }
    result.Output.Status = 0
    result.Output.Status_detail = "Success: Cleared threshold breaches"
    return json.Marshal(&result)
}

func qos_interface_post_xfmr (inParams XfmrParams, retDbDataMap map[string]map[string]db.Value, ifName string) (error) {
    
    qos_port_tbl := "PORT_QOS_MAP"
    if ifName == "CPU" {
        if _, ok :=  retDbDataMap[qos_port_tbl]; ok {
            log.Infof("qos_post_xfmr - Skip CPU delete")
            delete(retDbDataMap[qos_port_tbl], ifName)
        }
        return nil
    }
    if _, ok := (*inParams.dbDataMap)[db.ConfigDB][qos_port_tbl][ifName]; ok {
        retDbDataMap[qos_port_tbl][ifName] = db.Value{Field: make(map[string]string)}
    } else if strings.HasPrefix(ifName, "Vlan") || strings.HasPrefix(ifName, "PortChannel") {
        log.Info("qos_post_xfmr - Update Vlan or PortChannel to delete, ifName ", ifName)
        entry, err := inParams.d.GetEntry(&db.TableSpec{Name:qos_port_tbl}, db.Key{Comp: []string{ifName}})
        if err != nil || entry.IsPopulated() {
            if _, ok := retDbDataMap[qos_port_tbl]; !ok {
                retDbDataMap[qos_port_tbl] = make(map[string]db.Value)
            }
            retDbDataMap[qos_port_tbl][ifName] = db.Value{Field: make(map[string]string)}
        }
    }

    return nil
}

func qos_queue_post_xfmr (inParams XfmrParams, retDbDataMap map[string]map[string]db.Value, dbQKey db.Key) (error) {

    qCfg, _ := inParams.d.GetEntry(&db.TableSpec{Name:"QUEUE"}, dbQKey)
    var q_sched_present bool = false
    _, ok := qCfg.Field["scheduler"]
    if ok {
        q_sched_present = true
    }

    var qKey_str string = dbQKey.Get(0) + "|" + dbQKey.Get(1)
    if strings.Contains(qKey_str, "CPU") {
        delete(retDbDataMap["QUEUE"], qKey_str)
        log.Info("qos_post_xfmr- Skip delete CPU QUEUE Settings - ", qKey_str)
        return nil
    }

    log.Info("qos_post_xfmr- Update QUEUE with wred_policy - ", qKey_str)
    if _, ok := retDbDataMap["QUEUE"][qKey_str]; !ok {
        retDbDataMap["QUEUE"][qKey_str] = db.Value{Field: make(map[string]string)}
    }

    /* If only WRED field, then delete QUEUE entry else delete only wred_profile */
    if q_sched_present {
       retDbDataMap["QUEUE"][qKey_str].Field["wred_profile"] = ""
    } else {
       retDbDataMap["QUEUE"][qKey_str] = db.Value{Field: make(map[string]string)}
    }

    return nil
}
var qos_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    log.Info("qos_post_xfmr - inParams.uri: ", inParams.uri)

    if (inParams.dbDataMap != nil) {
        retDbDataMap := (*inParams.dbDataMap)[db.ConfigDB]
        if inParams.oper == DELETE {
            log.Info(" qos_post_xfmr - Received retDbDataMap from xfmrs ", retDbDataMap)
            requestUriPath, _ := getYangPathFromUri(inParams.requestUri)

            if (requestUriPath == "/openconfig-qos:qos/interfaces/interface" ||
                requestUriPath ==  "/openconfig-qos:qos/interfaces" ||
                requestUriPath ==  "/openconfig-qos:qos") {

                pathInfo := NewPathInfo(inParams.uri)
                ifName := pathInfo.Var("interface-id");

                log.Info("qos_post_xfmr - Uri ifName: ", ifName);

                if len(ifName) != 0 {
                   dbifName := utils.GetNativeNameFromUIName(&ifName)
                   ifName = *dbifName
                }
                /* DELETE at interface/interfaces/qos will trigger every sub trees. 
                 * Infra will not include direct fields like interface-maps to clear. 
                 * We need to include map fileds or delete fileds return from other subtrees.
                 * Delete interface can remove PORT_QOS_MAP entry. Overwirte map entry with 
                 * empty fileds to clear everything.
                 * 
                 * 
                 * To flush maps on Vlan, Portchannel add explicity port_qos_map entry
                 * CPU is assigned with copp, do not allow delete. 
                 */
                qos_port_tbl := "PORT_QOS_MAP"

                if len(ifName) != 0 {
                   qos_interface_post_xfmr(inParams, retDbDataMap, ifName)
                } else {
                    /* Delete all port_qos_map entries */
                    mapIntfKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:qos_port_tbl})
                    if len(mapIntfKeys) > 0 {
                        for _, mapIntfKey := range mapIntfKeys {
                            k_ifName := mapIntfKey.Get(0)
                            if_name := utils.GetUINameFromNativeName(&k_ifName)
                            key := *if_name
                            qos_interface_post_xfmr(inParams, retDbDataMap, key)
                        }
                    }
                }
            }
            /* QUEUE table has 2 fields scheduler and wred_policy.  
             * Scheduler will be deleted from interface/schduelr-policy, should not delete entire QUEUE table 
             * by request /openconfig-qos:qos/queues/queue or /openconfig-qos:qos/queues
             * Delete only wred_policy
             * From Xfmr we can get empty QUEUE map. Should avoid because it clears COPP configs
             */
            if (requestUriPath == "/openconfig-qos:qos/queues/queue" ||
                requestUriPath ==  "/openconfig-qos:qos/queues" ||
                requestUriPath ==  "/openconfig-qos:qos") {
                log.Info("qos_post_xfmr - Delete Queues/queue, Updated retDbDataMap: ", retDbDataMap)
                for table, keyInstance := range retDbDataMap {
                    if table != "QUEUE" {
                        continue
                    }

                    if requestUriPath == "/openconfig-qos:qos/queues/queue" {
                        for dbKey := range keyInstance {
                            if strings.Contains(dbKey, "CPU") {
                                return retDbDataMap, tlerr.NotSupported("Operation Not Supported")
                            } else {
                                s := strings.Split(dbKey, "|")
                                qKey := db.Key{Comp: []string{s[0], s[1]}}
                                qos_queue_post_xfmr(inParams, retDbDataMap, qKey)
                            }
                        }
                    } else {
                        log.Info("qos_post_xfmr - Delete all queues wred_policy")
                        qKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:"QUEUE"})
                        if len(qKeys) > 0 {
                            for _, qKey := range qKeys {
                                qos_queue_post_xfmr(inParams, retDbDataMap, qKey)
                            }
                        }
                        /* To Avoid CPU copp scheduler cleanup on queue */
                        if len(retDbDataMap["QUEUE"]) == 0 {
                            log.Info("qos_post_xfmr- Remove empty QUEUE table, to avoid COPP configs remove")
                            delete(retDbDataMap, "QUEUE")
                        }
                    }
                }
            }

            if (requestUriPath ==  "/openconfig-qos:qos") {
                log.Info("qos_post_xfmr - Updates retDbDataMap while scheduler ", retDbDataMap)
                log.Info("qos_post_xfmr - Delete All schedulers except copp")
                sKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:"SCHEDULER"})
                if len(sKeys) > 0 {
                    for _, sKey := range sKeys {
                        var sKey_str string = sKey.Get(0) 
                        if strings.Contains(sKey_str, "copp-scheduler-policy") {
                            log.Info("qos_post_xfmr - Skip add CPU copp scheduler to delete - ", sKey_str)
                            continue
                        }

                        log.Info("qos_post_xfmr: Update scheduler to delete - ", sKey_str)
                        if _, ok := retDbDataMap["SCHEDULER"]; !ok {
                            retDbDataMap["SCHEDULER"] = make(map[string]db.Value)
                        }

                        if _, ok := retDbDataMap["SCHEDULER"][sKey_str]; !ok {
                            retDbDataMap["SCHEDULER"][sKey_str] = db.Value{Field: make(map[string]string)}
                        }
                    }
                }
                /* Avoid Delete Copp scheduler policy */
                if _, ok := retDbDataMap["SCHEDULER"]; ok {
                    if len(retDbDataMap["SCHEDULER"]) == 0 {
                        log.Info("qos_post_xfmr- Remove empty SCHEDULER table, to avoid COPP configs remove")
                        delete(retDbDataMap, "SCHEDULER")
                    }
                }
            }
        }
        log.Infof("qos_post_xfmr- Return result : %v", retDbDataMap)
        return retDbDataMap, nil
    }
    return nil, nil
}
