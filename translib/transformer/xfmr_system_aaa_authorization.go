////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
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
        "strings"
//        "errors"
        "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
//        "github.com/Azure/sonic-mgmt-common/translib/db"
//        "github.com/Azure/sonic-mgmt-common/translib/tlerr"
        log "github.com/golang/glog"
)

func init () {
    XlateFuncBind("YangToDb_authorization_set_key_xfmr", YangToDb_authorization_set_key_xfmr)
    XlateFuncBind("YangToDb_authorization_method_xfmr", YangToDb_authorization_method_xfmr)
    XlateFuncBind("DbToYang_authorization_method_xfmr", DbToYang_authorization_method_xfmr)
}

var YangToDb_authorization_set_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    return "authorization", nil
}

var YangToDb_authorization_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_authorization_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string

    auth_method, _ := inParams.param.([]ocbinds.OpenconfigSystem_System_Aaa_Authorization_Login_Config_AuthorizationMethod_Union)
    for _, method := range auth_method {
        v := (method).(*ocbinds.OpenconfigSystem_System_Aaa_Authorization_Login_Config_AuthorizationMethod_Union_String)
        log.Info("YangToDb_authorization_method_xfmr: method - ", v.String)

        if (len(db_auth_method) == 0) {
            db_auth_method = v.String
        } else {
            db_auth_method = db_auth_method + "," + v.String
        }
    }

    log.Info( "YangToDb_authorization_method_xfmr: auth-method: ", db_auth_method)
    res_map :=  make(map[string]string)
    res_map["login"] = db_auth_method 
    return res_map, nil
}

var DbToYang_authorization_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_authorization_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["login"]
    if ok {
        log.Info("DbToYang_authorization_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["authorization-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}

