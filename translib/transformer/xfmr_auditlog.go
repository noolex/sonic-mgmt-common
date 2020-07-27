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
    "errors"
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "fmt"
    "os"
    "bufio"
)

const BRIEF_AUDIT_SIZE = 20

func init() {
    XlateFuncBind("rpc_showauditlog_cb", rpc_showauditlog_cb)
    XlateFuncBind("rpc_clearauditlog_cb", rpc_clearauditlog_cb)
}

func _read_file(fname string, data *[]string) (error) {
    f, err := os.Open(fname)
    if err != nil {
        fmt.Println("File reading error", err)
        return err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        *data = append(*data, string(scanner.Text()))
    }
    return nil
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
        return nil,err
    }

    var v interface{}
    v = "brief"
    input := inputData["sonic-auditlog:input"]
    if (input != nil) {
        inputData = input.(map[string]interface{})
        v = inputData["content-type"]
    }

    // if input is 'all', read audit.log.1 first and then audit.log
    if v == "all" {
        _read_file("/host_var/log/audit.log.1", &showaudit.Output.Result)
        _read_file("/host_var/log/audit.log", &showaudit.Output.Result)
    } else {
        // brief output - get last 20 lines
        var tmpResult []string

        _read_file("/host_var/log/audit.log", &tmpResult)

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
        return nil, errors.New("Operation failed")
    }

    return nil, nil
}

