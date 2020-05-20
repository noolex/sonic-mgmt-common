//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Broadcom, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer

import (
    "fmt"
    "encoding/json"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/db"
)

func init () {
    XlateFuncBind("rpc_clear_threshold_breach", rpc_clear_threshold_breach)
}

/* RPC for clear threshold breach */
var rpc_clear_threshold_breach RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string`json:"status-detail"`
        } `json:"sonic-threshold:output"`
    }
    result.Output.Status = 1
    /* Get input data */
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Errorf("Failed to unmarshall given input data, error=%v", err)
        result.Output.Status_detail = fmt.Sprintf("Error: Unable to unmarshall given input data")
        return json.Marshal(&result)
    }
    input, _ := mapData["sonic-threshold:input"]
    mapData = input.(map[string]interface{})
    input = mapData["breach_event_id"]
    input_str := fmt.Sprintf("%v", input)
    log.Info("INPUT received! : ", input_str)

    log.Info("rpc_clear_threshold_breach, Clear threshold breaches for breach_event_id: ", input_str)
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

/* Clear all or a given threshold breach event from THRESHOLD_BREACH_TABLE table */

func clearThresholdBreaches(d *db.DB, input_str string) (error) {
    var verr error
    ThresholdBreachTblTs := db.TableSpec {Name: "THRESHOLD_BREACH_TABLE"}
    if input_str == "all" {
	keys, verr := d.GetKeys(&ThresholdBreachTblTs)
        if verr != nil {
                log.Errorf("Unable to get DB keys from THRESHOLD_BREACH_TABLE, error=%v", verr)
		return verr
        }
        for i := 0; i < len(keys); i++ {
            verr = d.DeleteEntry(&ThresholdBreachTblTs, keys[i])
            if verr != nil {
                  log.Errorf("Unable to delete DB entry: %s from THRESHOLD_BREACH_TABLE, error=%v", keys[i], verr)
		  return verr
            }
        }
    } else {
        keys := fmt.Sprintf("breach-report:%v", input_str)
        verr = d.DeleteEntry(&ThresholdBreachTblTs, db.Key{Comp: []string{keys}})
	if verr != nil {
                  log.Errorf("Unable to delete DB entry:%s from THRESHOLD_BREACH_TABLE, error=%v", keys, verr)
		  return verr
            }
    }
    return verr
}
