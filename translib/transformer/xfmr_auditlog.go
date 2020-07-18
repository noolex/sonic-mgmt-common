////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Dell, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "fmt"
    "os"
    "bufio"
    log "github.com/golang/glog"
)

const BRIEF_AUDIT_SIZE = 20

func init() {
    XlateFuncBind("rpc_showauditlog_cb", rpc_showauditlog_cb)
    XlateFuncBind("rpc_clearauditlog_cb", rpc_clearauditlog_cb)
}

var rpc_showauditlog_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {

    var showaudit struct {
        Output struct {
        Result []string `json:"audit-content"`
        } `json:"sonic-show-auditlog:output"`
    }

    var inputData map[string]interface{}
    err := json.Unmarshal(body, &inputData)
    if err != nil {
        fmt.Println("%Error: Failed to parse rpc input; err=%v", err)
        return nil,err
    }

    var v interface{}
    v = "brief"
    input := inputData["sonic-auditlog:input"]
    if (input != nil) {
        inputData = input.(map[string]interface{})
        v = inputData["content-type"]
    }

    // open audit.log
    f, err := os.Open("/host_var/log/audit.log")
    if err != nil {
        fmt.Println("File reading error", err)
        return nil, err
    }
    defer f.Close()

    // if input is 'all', read audit.log.1 first and then audit.log
    if v == "all" {
        f1, err := os.Open("/host_var/log/audit.log.1")
        if err == nil {
            scanner := bufio.NewScanner(f1)
            for scanner.Scan() {
                showaudit.Output.Result = append(showaudit.Output.Result, string(scanner.Text()))
            }
        }
        defer f1.Close()

        // read audit.log
        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
            showaudit.Output.Result = append(showaudit.Output.Result, string(scanner.Text()))
        }
    } else {
        // brief output - get last 20 lines
        var tmpResult []string
        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
            tmpResult = append(tmpResult, string(scanner.Text()))
        }
        lenx := len(tmpResult)
        j := BRIEF_AUDIT_SIZE
        if lenx < BRIEF_AUDIT_SIZE {
            j = lenx
        }
        for i := 0; i < j; i++ {
            showaudit.Output.Result = append(showaudit.Output.Result, tmpResult[lenx-i-1])
        }
    }

    result, _ := json.Marshal(&showaudit)
    return result, nil
}

var rpc_clearauditlog_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {

    host_output := HostQuery("clearaudit.action")
    if host_output.Err != nil {
        log.Errorf("%Error: ClearAudit host exec failed: err=%v", host_output.Err)
        log.Flush()
        return nil, host_output.Err
    }

    return nil, nil
}

