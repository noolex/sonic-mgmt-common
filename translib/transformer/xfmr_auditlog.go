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
    "bytes"
    "io/ioutil"
    log "github.com/golang/glog"
)

func init() {
    XlateFuncBind("rpc_showauditlog_cb", rpc_showauditlog_cb)
    XlateFuncBind("rpc_clearauditlog_cb", rpc_clearauditlog_cb)
}

var rpc_showauditlog_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {

    var showaudit struct {
        Output struct {
        Result string `json:"audit-content"`
        } `json:"sonic-show-auditlog:output"`
    }

    var inputData map[string]interface{}
    err := json.Unmarshal(body, &inputData)
    if err != nil {
        fmt.Println("%Error: Failed to parse rpc input; err=%v", err)
        return nil,err
    }

    input := inputData["sonic-auditlog:input"]
    inputData = input.(map[string]interface{})

    var v interface{}
    v = inputData["content-type"]

    if v == "brief" {
        f, err := os.Open("/var/log/audit.log")
        if err != nil {
            fmt.Println("File reading error", err)
            return nil, err
        }
        defer f.Close()

        fileinfo, err := f.Stat()
        if err != nil {
            fmt.Println(err)
            return nil, err
        }
        filesize := fileinfo.Size()
        buffer := make([]byte, 8192)
        if filesize > 8192 {
            _, err = f.ReadAt(buffer, (filesize-8192))
        } else {
            _, err = f.ReadAt(buffer, filesize)
        }

        if err != nil {
            fmt.Println(err)
            return nil, err
        }

        res1 := bytes.Index(buffer, []byte("\n"))

        showaudit.Output.Result = string(buffer[res1:])
    } else {
        data, err := ioutil.ReadFile("/var/log/audit.log")
        if err != nil {
            fmt.Println("File reading error", err)
            return nil,err
        }
        fmt.Println("Contents of file:", string(data))
        showaudit.Output.Result = string(data)
    }

    result, _ := json.Marshal(&showaudit)

    return result, nil
}

var rpc_clearauditlog_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    return nil, nil
}

