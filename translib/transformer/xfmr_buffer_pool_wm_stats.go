package transformer

import (
    "fmt"
    "strconv"
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
			Status string `json:"status"`
                } `json:"sonic-buffer-pool:output"`
        }
    showOutput.Output.Buffer_pool_list = make([]BufferPoolStatsEntry, 0)

    /* Get input data */
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Errorf("Failed to unmarshall given input data: %v, error=%v", mapData, err)
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

    bufferpoolOidMap, erroid  := doGetAllBufferpoolOidMap(dbs[db.CountersDB]);

    if erroid != nil {
        showOutput.Output.Status = "Buffer pool configuration missing on the system! Please configure buffer pools"
        return json.Marshal(&result)
    }

    bufferpoolOidMapFields := bufferpoolOidMap.Field

    for poolName, oid := range bufferpoolOidMapFields {

	if watermark_type ==  "persistant-watermark" {
		err = getBufferPoolPersistentWatermark(dbs[db.CountersDB], oid, watermark_stats_type, &count)
	} else {
		err = getBufferPoolUserWatermark(dbs[db.CountersDB], oid, watermark_stats_type, &count)
	}

	if err != nil {
		log.Warning("Couldn't get buffer pool watermark counters.")
		showOutput.Output.Status = fmt.Sprintf("Couldn't get %s watermark counters from PERSISTENT_WATERMARKS/USER_WATERMARKS table.", poolName)
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

    var err error
    var watermark_type, status string
    var mapData map[string]interface{}
    var varList [2]string
    var watermarkReqdata []byte

    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Warning("Failed to unmarshall given input data: %v, error=%v", mapData, err)
        return nil, err
    }

    var result struct {
        Output struct {
              Status string `json:"status"`
        } `json:"sonic-buffer-pool:output"`
    }

    input := mapData["sonic-buffer-pool:input"]
    mapData = input.(map[string]interface{})

    if value, ok := mapData["watermark-type"].(string) ; ok {
        watermark_type = value
    }

    if watermark_type == "persistant-watermark" {
	varList[0] = "PERSISTENT"
    } else {
	varList[0] = "USER"
    }

    varList[1] = "BUFFER_POOL"

    watermarkReqdata, err = json.Marshal(varList)

    if err != nil {
        log.Warningf("Failed to marshal varList; err=%v", err)
        return nil, err
    }

    err = dbs[db.ApplDB].Publish("WATERMARK_CLEAR_REQUEST", watermarkReqdata)

    if err != nil {
	status = "Couldn't publish Bufferpool watermark stats clear notification message"
    }
	status = "Success: Cleared Buffer pool watermark Counters"

    result.Output.Status = status
    return json.Marshal(&result)
}

func getBufferPoolPersistentWatermark(d *db.DB, oid string, stat_key string, count **uint64)  (error) {
    ts := &db.TableSpec{Name: "PERSISTENT_WATERMARKS"}
    entry, err := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Warning("getBufferPoolPersistentWatermark: Couldn't find oid %v in PERSISTENT_WATERMARKS table", oid)
        return err
    }

    err = getBufferPoolStats(&entry, stat_key, count)
    if err != nil {
	log.Warning("getBufferPoolStats: Couldn't find attribute %v in PERSISTENT_WATERMARKS table", stat_key)
    }

    return err
}

func getBufferPoolUserWatermark(d *db.DB, oid string, stat_key string, count **uint64)  (error) {
    ts := &db.TableSpec{Name: "USER_WATERMARKS"}
    entry, err := d.GetEntry(ts, db.Key{Comp: []string{oid}})
    if err != nil {
        log.Warning("getBufferPoolUserWatermark: Couldn't find oid %v in USER_WATERMARKS table", oid)
        return err
    }

    err = getBufferPoolStats(&entry, stat_key, count)
    if err != nil {
	log.Warning("getBufferPoolStats: Couldn't find attribute %v in USER_WATERMARKS table", stat_key)
    }

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
        log.Warning("getBufferPoolStats: ", "Attr " + attr + "doesn't exist in table Map!")
    }
    return err
}

func doGetAllBufferpoolOidMap(d *db.DB) (db.Value, error) {

    // COUNTERS_BUFFER_POOL_NAME_MAP
    dbSpec := &db.TableSpec{Name: "COUNTERS_BUFFER_POOL_NAME_MAP"}
    bufferpoolOidMap, err := d.GetMapAll(dbSpec)
    if err != nil {
        log.Warning("Couldn't get BufferPoolOidMap")
    }

    return bufferpoolOidMap, err
}
