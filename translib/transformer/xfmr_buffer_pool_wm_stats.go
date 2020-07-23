package transformer

import (
    "fmt"
    "strconv"
    "time"
    "encoding/json"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/db"
)
func init () {
    XlateFuncBind("rpc_get_buffer_pool_wm_stats", rpc_get_buffer_pool_wm_stats)
    XlateFuncBind("rpc_clear_buffer_pool_wm_stats", rpc_clear_buffer_pool_wm_stats)
}

var rpc_get_buffer_pool_wm_stats RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte,err error) {

    var count *uint64
    var watermark_stats_type, watermark_type string

    type BufferPoolStatsEntry struct {
        Poolname string
        StatsValue uint64
    }
    var showOutput struct {
                Output struct {
                        Buffer_pool_list []BufferPoolStatsEntry
			Status string `json:"response"`
                } `json:"sonic-buffer-pool:output"`
        }
    showOutput.Output.Buffer_pool_list = make([]BufferPoolStatsEntry, 0)

    /* Get input data */
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Errorf("Failed to unmarshall given input data, error=%v", err)
        return json.Marshal(&result)
    }
    input := mapData["sonic-buffer-pool:input"]
    mapData = input.(map[string]interface{})

    if value, ok := mapData["watermark-type"].(string) ; ok {
        watermark_type = value
    }

    if value, ok := mapData["watermark-stats-type"].(string) ; ok {
        watermark_stats_type = value
    }

    if watermark_stats_type == "percentage" {
	watermark_stats_type = "SAI_BUFFER_POOL_PERCENT_STAT_WATERMARK"
    } else {
	watermark_stats_type = "SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"
    }

    bufferpoolOidMap, _ := doGetAllBufferpoolOidMap(dbs[db.CountersDB]);
    bufferpoolOidMapFields := bufferpoolOidMap.Field

    for poolName, oid := range bufferpoolOidMapFields {

	if watermark_type ==  "persistant-watermark" {
		err = getBufferPoolPersistentWatermark(dbs[db.CountersDB], oid, watermark_stats_type, &count)
	} else {
		err = getBufferPoolUserWatermark(dbs[db.CountersDB], oid, watermark_stats_type, &count)
	}

	if err != nil {
		log.Info("Failed to get buffer pool watermark counters.")
		showOutput.Output.Status = fmt.Sprintf("Error: Failed to get %s watermark counters from PERSISTENT_WATERMARKS/USER_WATERMARKS table.", poolName)
                return json.Marshal(&result)
	}

	var entry BufferPoolStatsEntry
	entry.Poolname  = poolName
	entry.StatsValue  = *count
	showOutput.Output.Buffer_pool_list = append(showOutput.Output.Buffer_pool_list, entry)
    }

    showOutput.Output.Status = "Success: Buffer pool watermark counters returned successfully."
    result, err = json.Marshal(&showOutput)

    return result, err
}

/* RPC for clear buffer pool counters */
var rpc_clear_buffer_pool_wm_stats RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_clear_buffer_pool_wm_stats.")
    var err, cerr error
    var watermark_type string
    var mapData map[string]interface{}

    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil, err
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-buffer-pool:output"`
    }

    log.Info("In rpc_clear_buffer_pool_wm_stats: ", mapData)

    input := mapData["sonic-buffer-pool:input"]
    mapData = input.(map[string]interface{})

    if value, ok := mapData["watermark-type"].(string) ; ok {
        watermark_type = value
    }

    bufferpoolOidMap, _ := doGetAllBufferpoolOidMap(dbs[db.CountersDB]);
    bufferpoolOidMapFields := bufferpoolOidMap.Field

    for poolName, oid := range bufferpoolOidMapFields {

	if watermark_type == "persistant-watermark" {
		cerr = resetPersistentWatermarkCounters(dbs[db.CountersDB], oid)
	} else {
		cerr = resetUserWatermarkCounters(dbs[db.CountersDB], oid)
	}

	if cerr != nil {
		log.Info("Failed to reset counters for ", poolName)
		result.Output.Status = fmt.Sprintf("Error: OID info not found in PERSISTENT_WATERMARKS/USER_WATERMARKS table for buffer pool %s ", poolName)
		return json.Marshal(&result)
	}
    }

    result.Output.Status = "Success: Cleared Buffer pool watermark Counters"
    return json.Marshal(&result)
}

func getBufferPoolPersistentWatermark(d *db.DB, oid string, stat_key string, count **uint64)  (error) {
    ts := &db.TableSpec{Name: "PERSISTENT_WATERMARKS"}
    entry, err := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Info("getBufferPoolPersistentWatermark: not able to find the oid entry in DB ")
        return err
    }

    err = getBufferPoolStats(&entry, stat_key, count)

    return err
}

func getBufferPoolUserWatermark(d *db.DB, oid string, stat_key string, count **uint64)  (error) {
    ts := &db.TableSpec{Name: "USER_WATERMARKS"}
    entry, err := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Info("getBufferPoolUserWatermark: not able to find the oid entry in DB ")
        return err
    }

    err = getBufferPoolStats(&entry, stat_key, count)

    return err
}

func getBufferPoolStats(entry *db.Value, attr string, counter_val **uint64 ) error {

    var ok bool = false
    var err error
    val, ok := entry.Field[attr]

    if ok && len(val) > 0 {
        v, _ := strconv.ParseUint(val, 10, 64)
        *counter_val = &v
        return nil
    } else {
        log.Info("getBufferPoolStats: ", "Attr " + attr + "doesn't exist in table Map!")
    }
    return err
}

func resetPersistentWatermarkCounters(d *db.DB, oid string)  (error) {
    var cerr error
    ts := &db.TableSpec{Name: "PERSISTENT_WATERMARKS"}
    value, verr := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if verr == nil {
	secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        value.Field["SAI_BUFFER_POOL_PERCENT_STAT_WATERMARK"] = "0"
        value.Field["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"] = "0"
        cerr = d.CreateEntry(ts, db.Key{Comp: []string{oid}}, value)
    }
    return cerr
}

func doGetAllBufferpoolOidMap(d *db.DB) (db.Value, error) {

    // COUNTERS_BUFFER_POOL_NAME_MAP
    dbSpec := &db.TableSpec{Name: "COUNTERS_BUFFER_POOL_NAME_MAP"}
    bufferpoolOidMap, err := d.GetMapAll(dbSpec)
    if err != nil {
        log.Info("Error: BufferpoolOidMap failed")
    }

    return bufferpoolOidMap, err
}

func resetUserWatermarkCounters(d *db.DB, oid string)  (error) {
    var cerr error
    ts := &db.TableSpec{Name: "USER_WATERMARKS"}
    value, verr := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if verr == nil {
	secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        value.Field["SAI_BUFFER_POOL_PERCENT_STAT_WATERMARK"] = "0"
        value.Field["SAI_BUFFER_POOL_STAT_WATERMARK_BYTES"] = "0"
        cerr = d.CreateEntry(ts, db.Key{Comp: []string{oid}}, value)
    }
    return cerr
}
