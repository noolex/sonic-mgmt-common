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
    "io/ioutil"
)

func init() {
    XlateFuncBind("rpc_showauditlog_cb", rpc_showauditlog_cb)
}

var rpc_showauditlog_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {

    var showaudit struct {
        Output struct {
        Result string `json:"audit-content"`
        } `json:"sonic-show-auditlog:output"`
    }

    dat, err := ioutil.ReadFile("/var/log/audit.log")
    if err != nil {
        fmt.Println("File reading error", err)
        return nil, err
    }

    showaudit.Output.Result = string(dat)

    //showaudit.Output.Result = "Hello World!"
    result, _ := json.Marshal(&showaudit)

    return result, nil
}
