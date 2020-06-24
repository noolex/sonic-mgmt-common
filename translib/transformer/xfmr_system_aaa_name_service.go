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
    XlateFuncBind("YangToDb_name_service_set_key_xfmr", YangToDb_name_service_set_key_xfmr)
    XlateFuncBind("YangToDb_passwd_method_xfmr", YangToDb_passwd_method_xfmr)
    XlateFuncBind("DbToYang_passwd_method_xfmr", DbToYang_passwd_method_xfmr)
    XlateFuncBind("YangToDb_shadow_method_xfmr", YangToDb_shadow_method_xfmr)
    XlateFuncBind("DbToYang_shadow_method_xfmr", DbToYang_shadow_method_xfmr)
    XlateFuncBind("YangToDb_group_method_xfmr", YangToDb_group_method_xfmr)
    XlateFuncBind("DbToYang_group_method_xfmr", DbToYang_group_method_xfmr)
    XlateFuncBind("YangToDb_netgroup_method_xfmr", YangToDb_netgroup_method_xfmr)
    XlateFuncBind("DbToYang_netgroup_method_xfmr", DbToYang_netgroup_method_xfmr)
    XlateFuncBind("YangToDb_sudoers_method_xfmr", YangToDb_sudoers_method_xfmr)
    XlateFuncBind("DbToYang_sudoers_method_xfmr", DbToYang_sudoers_method_xfmr)
}

var YangToDb_name_service_set_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    return "nss", nil
}

/*
func mt2string (mt ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE) string {
    var vString string
    switch(mt) {
    case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_AAA_NAME_SERVICE_LOGIN:
        vString = "login"
    case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LOCAL:
        vString = "local"
    case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_RADIUS_ALL:
        vString = "radius"
    case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_TACACS_ALL:
        vString = "tacacs+"
    case ocbinds.OpenconfigAaaTypes_AAA_METHOD_TYPE_LDAP_ALL:
        vString = "ldap"
    default:
        vString = ""
    }

    return vString
}

var YangToDb_passwd_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_passwd_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string

    auth_method, _ := inParams.param.([]ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE)
    var method interface {}
    for _, method = range auth_method {
        v := (method).(ocbinds.E_OpenconfigAaaTypes_AAA_METHOD_TYPE)
        log.Info("YangToDb_auth_method_xfmr: method - ", v)

        vString := mt2string(v)
        if (len(db_auth_method) == 0) {
            db_auth_method = vString
        } else {
            db_auth_method = db_auth_method + "," + vString
        }
    }

    log.Info( "YangToDb_passwd_method_xfmr: auth-method: ", db_auth_method)
    res_map :=  make(map[string]string)
    res_map["passwd"] = db_auth_method 
    return res_map, nil
}

var DbToYang_passwd_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_passwd_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["passwd"]
    if ok {
        log.Info("DbToYang_passwd_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["passwd-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}
*/

var YangToDb_passwd_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_passwd_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string

    auth_method, _ := inParams.param.([]ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_PasswdMethod_Union)
    for _, method := range auth_method {
        v := (method).(*ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_PasswdMethod_Union_String)
        log.Info("YangToDb_passwd_method_xfmr: method - ", v.String)

        if (len(db_auth_method) == 0) {
            db_auth_method = v.String
        } else {
            db_auth_method = db_auth_method + "," + v.String
        }
    }

    log.Info( "YangToDb_passwd_method_xfmr: passwd-method: ", db_auth_method)
    res_map :=  make(map[string]string)
    res_map["passwd"] = db_auth_method 
    return res_map, nil
}

var DbToYang_passwd_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_passwd_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["passwd"]
    if ok {
        log.Info("DbToYang_passwd_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["passwd-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}

var YangToDb_shadow_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_shadow_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string

    auth_method, _ := inParams.param.([]ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_ShadowMethod_Union)
    for _, method := range auth_method {
        v := (method).(*ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_ShadowMethod_Union_String)
        log.Info("YangToDb_shadow_method_xfmr: method - ", v.String)

        if (len(db_auth_method) == 0) {
            db_auth_method = v.String
        } else {
            db_auth_method = db_auth_method + "," + v.String
        }
    }

    log.Info( "YangToDb_shadow_method_xfmr: shadow-method: ", db_auth_method)
    res_map :=  make(map[string]string)
    res_map["shadow"] = db_auth_method 
    return res_map, nil
}

var DbToYang_shadow_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_shadow_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["shadow"]
    if ok {
        log.Info("DbToYang_shadow_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["shadow-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}

var YangToDb_group_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_group_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string

    auth_method, _ := inParams.param.([]ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_GroupMethod_Union)
    for _, method := range auth_method {
        v := (method).(*ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_GroupMethod_Union_String)
        log.Info("YangToDb_group_method_xfmr: method - ", v.String)

        if (len(db_auth_method) == 0) {
            db_auth_method = v.String
        } else {
            db_auth_method = db_auth_method + "," + v.String
        }
    }

    log.Info( "YangToDb_group_method_xfmr: group-method: ", db_auth_method)
    res_map :=  make(map[string]string)
    res_map["group"] = db_auth_method 
    return res_map, nil
}

var DbToYang_group_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_group_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["group"]
    if ok {
        log.Info("DbToYang_group_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["group-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}

var YangToDb_netgroup_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_netgroup_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string

    auth_method, _ := inParams.param.([]ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_NetgroupMethod_Union)
    for _, method := range auth_method {
        v := (method).(*ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_NetgroupMethod_Union_String)
        log.Info("YangToDb_netgroup_method_xfmr: method - ", v.String)

        if (len(db_auth_method) == 0) {
            db_auth_method = v.String
        } else {
            db_auth_method = db_auth_method + "," + v.String
        }
    }

    log.Info( "YangToDb_netgroup_method_xfmr: netgroup-method: ", db_auth_method)
    res_map :=  make(map[string]string)
    res_map["netgroup"] = db_auth_method 
    return res_map, nil
}

var DbToYang_netgroup_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_netgroup_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["netgroup"]
    if ok {
        log.Info("DbToYang_netgroup_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["netgroup-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}

var YangToDb_sudoers_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_sudoers_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string

    auth_method, _ := inParams.param.([]ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_SudoersMethod_Union)
    for _, method := range auth_method {
        v := (method).(*ocbinds.OpenconfigSystem_System_Aaa_NameService_Config_SudoersMethod_Union_String)
        log.Info("YangToDb_sudoers_method_xfmr: method - ", v.String)

        if (len(db_auth_method) == 0) {
            db_auth_method = v.String
        } else {
            db_auth_method = db_auth_method + "," + v.String
        }
    }

    log.Info( "YangToDb_sudoers_method_xfmr: sudoers-method: ", db_auth_method)
    res_map :=  make(map[string]string)
    res_map["sudoers"] = db_auth_method 
    return res_map, nil
}

var DbToYang_sudoers_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_sudoers_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["sudoers"]
    if ok {
        log.Info("DbToYang_sudoers_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["sudoers-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}

