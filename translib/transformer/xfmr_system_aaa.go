////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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
        "unicode"
        "strings"
        "errors"
        "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
        "github.com/Azure/sonic-mgmt-common/translib/db"
        "github.com/Azure/sonic-mgmt-common/translib/tlerr"
        log "github.com/golang/glog"
        "encoding/base64"
)

const (
        SECRET_KEY_ATTR = "passkey"
)

const (
        SECRET_KEY_LEN = 65
)
const (
        AAA_SECRET_PASSWORD = "ktbSJeed7apq9dZHOD1O5wW9cvSaRWjW767qLyFEurDTSNEvHdYspaCuEzZcMg8R"
)

const (
        SECRET_KEY_ENCRYPTED_ATTR = "encrypted"
)
const (
        YANG_SECRET_KEY_ATTR = "secret-key"
)

func init () {
    XlateFuncBind("YangToDb_global_sg_name_xfmr", YangToDb_global_sg_name_xfmr)
    XlateFuncBind("YangToDb_global_sg_key_xfmr", YangToDb_global_sg_key_xfmr)
    XlateFuncBind("DbToYang_global_sg_key_xfmr", DbToYang_global_sg_key_xfmr)
    XlateFuncBind("global_sg_tbl_xfmr", global_sg_tbl_xfmr)
    XlateFuncBind("YangToDb_auth_set_key_xfmr", YangToDb_auth_set_key_xfmr)
    XlateFuncBind("YangToDb_server_key_xfmr", YangToDb_server_key_xfmr)
    XlateFuncBind("DbToYang_server_key_xfmr", DbToYang_server_key_xfmr)
    XlateFuncBind("server_table_xfmr", server_table_xfmr)
    XlateFuncBind("YangToDb_server_name_xfmr", YangToDb_server_name_xfmr)
    XlateFuncBind("YangToDb_server_ipaddr_xfmr", YangToDb_server_ipaddr_xfmr)
    XlateFuncBind("DbToYang_server_ipaddr_xfmr", DbToYang_server_ipaddr_xfmr)
    XlateFuncBind("YangToDb_server_vrf_name_xfmr", YangToDb_server_vrf_name_xfmr)
    XlateFuncBind("DbToYang_server_vrf_name_xfmr", DbToYang_server_vrf_name_xfmr)
    XlateFuncBind("YangToDb_auth_method_xfmr", YangToDb_auth_method_xfmr)
    XlateFuncBind("DbToYang_auth_method_xfmr", DbToYang_auth_method_xfmr)
    XlateFuncBind("YangToDb_ssh_server_vrf_name", YangToDb_ssh_server_vrf_name)
    XlateFuncBind("DbToYang_ssh_server_vrf_name", DbToYang_ssh_server_vrf_name)
    XlateFuncBind("YangToDb_syslog_server_ip_fld_xfmr", YangToDb_syslog_server_ip_fld_xfmr)
    XlateFuncBind("DbToYang_syslog_server_ip_fld_xfmr", DbToYang_syslog_server_ip_fld_xfmr)
    XlateFuncBind("YangToDb_secret_key_value_xfmr", YangToDb_secret_key_value_xfmr)
    XlateFuncBind("DbToYang_secret_key_value_xfmr", DbToYang_secret_key_value_xfmr)
    XlateFuncBind("YangToDb_secret_key_encrypted_xfmr", YangToDb_secret_key_encrypted_xfmr)
    XlateFuncBind("DbToYang_secret_key_encrypted_xfmr", DbToYang_secret_key_encrypted_xfmr)

  // LDAP
    XlateFuncBind("YangToDb_ldap_use_type_field_xfmr", YangToDb_ldap_use_type_field_xfmr)
    XlateFuncBind("DbToYang_ldap_use_type_field_xfmr", DbToYang_ldap_use_type_field_xfmr)
    XlateFuncBind("YangToDb_ldap_ssl_field_xfmr", YangToDb_ldap_ssl_field_xfmr)
    XlateFuncBind("DbToYang_ldap_ssl_field_xfmr", DbToYang_ldap_ssl_field_xfmr)
    XlateFuncBind("YangToDb_ldap_scope_field_xfmr", YangToDb_ldap_scope_field_xfmr)
    XlateFuncBind("DbToYang_ldap_scope_field_xfmr", DbToYang_ldap_scope_field_xfmr)
    XlateFuncBind("YangToDb_ldap_server_map_key_xfmr", YangToDb_ldap_server_map_key_xfmr)
    XlateFuncBind("DbToYang_ldap_server_map_key_xfmr", DbToYang_ldap_server_map_key_xfmr)
    XlateFuncBind("system_post_xfmr", system_post_xfmr)
    XlateFuncBind("DbToYangPath_sys_server_group_path_xfmr", DbToYangPath_sys_server_group_path_xfmr)
    XlateFuncBind("DbToYangPath_sys_server_path_xfmr", DbToYangPath_sys_server_path_xfmr)
    XlateFuncBind("DbToYangPath_ldap_map_path_xfmr", DbToYangPath_ldap_map_path_xfmr)
}

// authMethodFind takes a slice and looks for an element in it. If found it will
// return True, otherwise False
func authMethodFind(val string) (bool) {
    methods := [4]string{
       "local",
       "tacacs+",
       "radius",
       "ldap",
    }

    for _, item := range methods {
        if item == val {
            return true
        }
    }
    return false
}

func ValidateTacplusServerNotUseMgmtVRF(d *db.DB) error {
    var err error
    if log.V(3) {
        log.Infof("ValidateAnyTacplusServerUseMgmtVRF")
    }

    tpsTblSpec := &db.TableSpec{Name:"TACPLUS_SERVER"}
    tpsKeys, _ := d.GetKeys(tpsTblSpec)
    log.Infof("ValidateTacplusServerNotUseMgmtVRF: tpsKeys %v", tpsKeys)

    for idx := range tpsKeys {
        tpsEntry, _ := d.GetEntry(tpsTblSpec, tpsKeys[idx])
        vrfName := (&tpsEntry).Get("vrf")
        if (vrfName == "mgmt") {
            errStr := "Management VRF is used by TACACS+ server"
            log.Info("ValidateTacplusServerNotUseMgmtVRF: ", errStr);
            err = tlerr.InvalidArgsError{Format: errStr}
            break
        }
    }
    return err
}

var YangToDb_auth_method_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_auth_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri, "param: ", inParams.param)
    }

    var db_auth_method string
    res_map :=  make(map[string]string)

    auth_method, _ := inParams.param.([]ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union)
    for _, method := range auth_method {
        v := (method).(*ocbinds.OpenconfigSystem_System_Aaa_Authentication_Config_AuthenticationMethod_Union_String)
        log.Info("YangToDb_auth_method_xfmr: method - ", v.String)

        if !authMethodFind(v.String) {
            err := errors.New("Invalid login method")
            return res_map, err
        }

        if (len(db_auth_method) == 0) {
            db_auth_method = v.String
        } else {
            db_auth_method = db_auth_method + "," + v.String
        }
    }

    log.Info( "YangToDb_auth_method_xfmr: auth-method: ", db_auth_method)
    res_map["login"] = db_auth_method 
    return res_map, nil
}

var YangToDb_server_vrf_name_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    var errStr string

    log.Infof("YangToDb_server_vrf_name_xfmr: ygRoot %v uri %v", inParams.ygRoot, inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    log.Infof("YangToDb_server_vrf_name_xfmr: pathInfo %v", pathInfo)

    servergroupName := pathInfo.Var("name")

    key := inParams.key
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    systemObj := deviceObj.System
    if systemObj == nil {
        errStr = "System container is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }
    aaaObj := systemObj.Aaa
    if aaaObj == nil {
        errStr = "Aaa container is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }
    serverGroupsObj := aaaObj.ServerGroups
    if serverGroupsObj == nil {
        errStr = "Server-groups container is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }

    serverGroupObj, ok := serverGroupsObj.ServerGroup["TACACS"]
    if !ok {
        serverGroupObj = serverGroupsObj.ServerGroup["RADIUS"]
    }
    if serverGroupObj == nil {
        errStr = "Server-group TACACS or RADIUS entry is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }

    serversObj := serverGroupObj.Servers
    if serversObj == nil {
        errStr = "Servers container is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }
    serverObj := serversObj.Server[key]
    if serverObj == nil {
        errStr = "Server entry for address " + key + " is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }
    configObj := serverObj.Config
    if serversObj == nil {
        errStr = "Server config is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }
    vrfObj := configObj.Vrf
    if serversObj == nil {
        errStr = "Vrf config is missing"
        log.Info("YangToDb_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }

    vrfName := *vrfObj

    log.Infof("YangToDb_server_vrf_name_xfmr: Address %v VRF %v", key, vrfName)

    if vrfName == "mgmt" {
        if strings.Contains(servergroupName, "TACACS") {
            err = validateMgmtVrfExists(inParams.d)
        }
        if err == nil {
            res_map["vrf"] = vrfName
        }
    } else {
        res_map["vrf"] = vrfName
    }
    return res_map, err
}

var DbToYang_server_vrf_name_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error
    var errStr string

    log.Infof("DbToYang_server_vrf_name_xfmr: ygRoot %v uri %v", inParams.ygRoot, inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    log.Infof("DbToYang_server_vrf_name_xfmr: pathInfo %v", pathInfo)

    servergroupName := pathInfo.Var("name")

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_server_vrf_name_xfmr: ", data, "inParams :", inParams)

    serverTbl, ok := data["TACPLUS_SERVER"]
    if !ok {
        serverTbl = data["RADIUS_SERVER"]
    }
    if serverTbl == nil {
        errStr = "Invalid server group name: " + servergroupName 
        log.Info("DbToYang_server_vrf_name_xfmr: ", errStr)
        err = tlerr.InvalidArgsError{Format: errStr}
        return res_map, err
    }

    serverConfig := serverTbl[inParams.key]
    if vrfName, ok := serverConfig.Field["vrf"]; ok {
        res_map["vrf"] = vrfName
        log.Infof("DbToYang_server_vrf_name_xfmr: vrfName %v", vrfName)
    }

    return res_map, err
}

var DbToYang_auth_method_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info( "DbToYang_auth_method_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    var err error
    rmap := make(map[string]interface{})
    data := (*inParams.dbDataMap)[inParams.curDb]
    db_auth_method, ok := data["AAA"][inParams.key].Field["login"]
    if ok {
        log.Info("DbToYang_auth_method_xfmr: db_auth_method: ", db_auth_method)
        rmap["authentication-method"] = strings.Split(db_auth_method, ",")
    }
    return rmap, err
}

var YangToDb_auth_set_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    return "authentication", nil
}

var YangToDb_server_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    if log.V(3) {
        log.Info( "YangToDb_server_key_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }
    pathInfo := NewPathInfo(inParams.uri)
    serverkey := pathInfo.Var("address")

    return serverkey, nil
}

var DbToYang_server_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{}, 1)
        var err error

        log.Info("DbToYang_server_key_xfmr: ", inParams.key)

        res_map["address"] = inParams.key

        return  res_map, err
}


var server_table_xfmr TableXfmrFunc = func(inParams XfmrParams) ([]string, error) {
    var err error;
    if log.V(3) {
        log.Info( "server_table_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    pathInfo := NewPathInfo(inParams.uri)
    servergroupname := pathInfo.Var("name")
    tables := make([]string, 0, 2)
    if strings.Contains(servergroupname, "RADIUS") {
        tables = append(tables, "RADIUS_SERVER")
    } else if strings.Contains(servergroupname, "TACACS") {
        tables = append(tables, "TACPLUS_SERVER")
	} else if servergroupname == "LDAP" {
		tables = append(tables, "LDAP_SERVER")        
    } else if inParams.oper == GET || servergroupname == "*" {
        tables = append(tables, "RADIUS_SERVER")
        tables = append(tables, "TACPLUS_SERVER")
        tables = append(tables, "LDAP_SERVER")
    } else {
        err = errors.New("Invalid server group name")
    }

    return tables, err
}

var YangToDb_server_ipaddr_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    log.Info( "YangToDb_server_ipaddr_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    res_map :=  make(map[string]string)
	res_map["NULL"] = "NULL"	
    return res_map, nil
}

var DbToYang_server_ipaddr_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_server_ipaddr_xfmr: ", data, "inParams : ", inParams)

    entry_key := inParams.key
    key := strings.Split(entry_key, "|")
    address := key[0]
    result["address"] = address

    return result, err
}

var YangToDb_server_name_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_server_name_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    res_map :=  make(map[string]string)
    res_map["NULL"] = "NULL"
    return res_map, nil
}

func YangToDb_ssh_server_vrf_name(inParams XfmrParams) (map[string]string, error) {
	return make(map[string]string), nil
}

func DbToYang_ssh_server_vrf_name(inParams XfmrParams) (map[string]interface{}, error) {
	log.V(1).Infof("DbToYang_ssh_server_vrf_name: key=\"%s\"", inParams.key)
	result := make(map[string]interface{})
    if len((*inParams.dbDataMap)[inParams.curDb]) > 0{
	    result["vrf-name"] = inParams.key
    }
	return result, nil
}

func YangToDb_syslog_server_ip_fld_xfmr(inParams XfmrParams) (map[string]string, error) {
	return make(map[string]string), nil
}

func DbToYang_syslog_server_ip_fld_xfmr(inParams XfmrParams) (map[string]interface{}, error) {
	log.V(1).Infof("DbToYang_syslog_server_ip_fld_xfmr: key=\"%s\"", inParams.key)
	result := make(map[string]interface{})
    if len((*inParams.dbDataMap)[inParams.curDb]) > 0{
	    result["host"] = inParams.key
    }
	return result, nil
}

var YangToDb_global_sg_name_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info( "YangToDb_global_sg_name_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    res_map :=  make(map[string]string)
    res_map["NULL"] = "NULL"
    return res_map, nil
}

var YangToDb_global_sg_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    if log.V(3) {
        log.Info( "YangToDb_global_sg_key_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }
    pathInfo := NewPathInfo(inParams.uri)
    servergroupname := pathInfo.Var("name")
    var retKey string
	if len(servergroupname) > 0 {
		retKey = "global"
	}
    
	if servergroupname == "LDAP" {
		retKey = "global"
	} else if servergroupname == "LDAP_NSS" {
		retKey = "nss"
	} else if servergroupname == "LDAP_PAM" {
		retKey = "pam"
	} else if servergroupname == "LDAP_SUDO" {
		retKey = "sudo"
	}
	
    return retKey, nil
}

var DbToYang_global_sg_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error

    log.Info("DbToYang_global_sg_key_xfmr: inParams.key: ", inParams.key, ", inParams.table: ", inParams.table)
    
	if inParams.table == "LDAP" {
        if inParams.key == "global" {
        	res_map["name"] = "LDAP"
        } else if inParams.key == "nss" {
			res_map["name"] = "LDAP_NSS"
		} else if inParams.key == "pam" {
			res_map["name"] = "LDAP_PAM"
		} else if inParams.key == "sudo" {
			res_map["name"] = "LDAP_SUDO"
		}
	}

    return  res_map, err
}

var global_sg_tbl_xfmr TableXfmrFunc = func(inParams XfmrParams) ([]string, error) {
    var err error

    if log.V(3) {
        log.Info( "global_sg_tbl_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    pathInfo := NewPathInfo(inParams.uri)
    servergroupname := pathInfo.Var("name")
    tables := make([]string, 0, 2)
    if strings.Contains(servergroupname, "RADIUS") {
        tables = append(tables, "RADIUS")
        // if the request is for specific server-group, get server list as well
        if inParams.uri == "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]" {
            tables = append(tables, "RADIUS_SERVER")
        }
    } else if strings.Contains(servergroupname, "TACACS") {
        tables = append(tables, "TACPLUS")
        // if the request is for specific server-group, get server list as well
        if inParams.uri == "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]" {
            tables = append(tables, "TACPLUS_SERVER")
        }
    } else if servergroupname == "LDAP" || servergroupname == "LDAP_NSS" || servergroupname == "LDAP_PAM" || servergroupname == "LDAP_SUDO" {
        tables = append(tables, "LDAP")
    } else if inParams.oper == GET || servergroupname == "*" {
        tables = append(tables, "RADIUS")
        tables = append(tables, "RADIUS_SERVER")
        tables = append(tables, "TACPLUS")
        tables = append(tables, "LDAP")
        tables = append(tables, "TACPLUS_SERVER")
    } else if len(servergroupname) > 0 {
        err = errors.New("Invalid server group name")
    }

    if log.V(3) {
        log.Info( "global_sg_tbl_xfmr: tables: ", tables,
            " err: ", err)
    }

    return tables, err
}

var YangToDb_ldap_use_type_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
	
    log.Info("YangToDb_ldap_use_type_field_xfmr: inParams.param: ", inParams.param)
    useTypeEnum, ok := inParams.param.(ocbinds.E_OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType)
    var useTypeVal string
    if ok {
    	if useTypeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType_ALL {
    		useTypeVal = "all"
    	} else if useTypeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType_NSS {
    		useTypeVal = "nss"
    	} else if useTypeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType_SUDO {
    		useTypeVal = "sudo"
    	} else if useTypeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType_PAM {
    		useTypeVal = "pam"
		} else if useTypeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType_NSS_SUDO {
		    useTypeVal = "nss_sudo"
		} else if useTypeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType_NSS_PAM {
			useTypeVal = "nss_pam"
		} else if useTypeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Servers_Server_Ldap_Config_UseType_SUDO_PAM {
			useTypeVal = "sudo_pam"
		}

   	    res_map["use_type"] = useTypeVal
    }
    log.Info("YangToDb_ldap_use_type_field_xfmr: res_map: ", res_map)
    return res_map, err
}

var DbToYang_ldap_use_type_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error
	
    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_ldap_use_type_field_xfmr: ", data, "inParams :", inParams)
    useTypeVal := data["LDAP_SERVER"][inParams.key].Field["use_type"]
    if len(useTypeVal) > 0 {
    	res_map["use-type"] = strings.ToUpper(useTypeVal)
    }
    log.Info("DbToYang_ldap_use_type_field_xfmr: res_map :", res_map)
    return res_map, err
}

var YangToDb_ldap_scope_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
	
    log.Info("YangToDb_ldap_scope_field_xfmr: inParams.param: ", inParams.param)
    scopeEnum, ok := inParams.param.(ocbinds.E_OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Ldap_Config_Scope)
    var scopeVal string
    if ok {
    	if scopeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Ldap_Config_Scope_SUB {
    		scopeVal = "sub"
    	} else if scopeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Ldap_Config_Scope_ONE {
    		scopeVal = "one"
    	} else if scopeEnum == ocbinds.OpenconfigSystem_System_Aaa_ServerGroups_ServerGroup_Ldap_Config_Scope_BASE {
    		scopeVal = "base"
    	}
    	if len (scopeVal) > 0 || inParams.oper == DELETE {
	    	res_map["scope"] = scopeVal
    	}
    }
    log.Info("YangToDb_ldap_scope_field_xfmr: res_map: ", res_map)
    return res_map, err	
}

var DbToYang_ldap_scope_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error
	
    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_ldap_scope_field_xfmr: ", data, "inParams :", inParams)
    scopeVal := data["LDAP"][inParams.key].Field["scope"]
    if len (scopeVal) > 0 {
    	res_map["scope"] = strings.ToUpper(scopeVal)
    }
    log.Info("DbToYang_ldap_scope_field_xfmr: res_map :", res_map)
    return res_map, err
}

var YangToDb_ldap_ssl_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
	
    log.Info("YangToDb_ldap_ssl_field_xfmr: inParams.param: ", inParams.param)
    sslEnum, ok := inParams.param.(ocbinds.E_OpenconfigAaaLdapExt_LdapSslType)
    var sslVal string
    if ok {
    	if sslEnum == ocbinds.OpenconfigAaaLdapExt_LdapSslType_ON {
    		sslVal = "on"
    	} else if sslEnum == ocbinds.OpenconfigAaaLdapExt_LdapSslType_OFF {
    		sslVal = "off"
    	} else if sslEnum == ocbinds.OpenconfigAaaLdapExt_LdapSslType_START_TLS {
    		sslVal = "start_tls"
    	}
    	if len (sslVal) > 0 || inParams.oper == DELETE {
	    	res_map["ssl"] = sslVal	
    	}
    }
    log.Info("YangToDb_ldap_ssl_field_xfmr: res_map: ", res_map)
    return res_map, err
}

var DbToYang_ldap_ssl_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error
	
    pathInfo := NewPathInfo(inParams.uri)
    serverAddr := pathInfo.Var("address")
    tblName := "LDAP"
	if len(serverAddr) > 0 {
		tblName = "LDAP_SERVER"
	}
    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_ldap_ssl_field_xfmr: data: ", data, ", inParams :", inParams)
    sslVal := data[tblName][inParams.key].Field["ssl"]
    log.Info("DbToYang_ldap_ssl_field_xfmr: tblName: ", tblName, ", sslVal :", sslVal)
    if len(sslVal) > 0 {
    	res_map["ssl"] = strings.ToUpper(sslVal)
    }
    log.Info("DbToYang_ldap_ssl_field_xfmr: res_map :", res_map)
    return res_map, err
}

var YangToDb_ldap_server_map_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    if log.V(3) {
        log.Info( "YangToDb_ldap_server_map_key_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }
    pathInfo := NewPathInfo(inParams.uri)
    mapName := pathInfo.Var("name#2")
    mapKey := pathInfo.Var("from")
    var retKey string
    if len(mapName) > 0 && len(mapKey) > 0 {
    	retKey = mapName+"|"+mapKey
    }
    return retKey, nil
}

var DbToYang_ldap_server_map_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error

    log.Info("DbToYang_ldap_server_map_key_xfmr: inParams.key: ", inParams.key)
   
	keyList := strings.Split(inParams.key, "|")
	
	if len(keyList) == 2 {
		res_map["name"] = keyList[0]
		res_map["from"] = keyList[1]
	}
	
	log.Info("DbToYang_ldap_server_map_key_xfmr: res_map: ", res_map)
	
    return  res_map, err
}

var system_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	log.Info("system_post_xfmr called - inParams.requestUri: ", inParams.requestUri)

	retDbDataMap := (*inParams.dbDataMap)[inParams.curDb]
    if inParams.oper == DELETE {
    	xpath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)
    	log.Info("system_post_xfmr xpath: ", xpath)
    	if strings.HasSuffix(xpath, "/server-group") || strings.HasSuffix(xpath, "/server-groups") ||
	    	strings.HasSuffix(xpath, "/aaa") || strings.HasSuffix(xpath, "/openconfig-system:system") {  
    		pathInfo := NewPathInfo(inParams.requestUri)
			servergroupname := pathInfo.Var("name") 
    		if servergroupname == "LDAP" || len(servergroupname) == 0 {
    			log.Infof("system_post_xfmr handling LDAP server group..")
		        if len(servergroupname) == 0 {
		        	retDbDataMap["LDAP"] = make(map[string]db.Value)
		        }
		        retDbDataMap["LDAP_SERVER"] = make(map[string]db.Value)
		        retDbDataMap["LDAP_MAP"] = make(map[string]db.Value)
    		}
    	}
    }
    
    log.Infof("system_post_xfmr returned : %v, skipOrdTblChk: %v", retDbDataMap, *inParams.skipOrdTblChk)
    return retDbDataMap, nil
}

var DbToYangPath_sys_server_group_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) (error) {
    sgRoot := "/openconfig-system:system/aaa/server-groups/server-group"

    log.Info("DbToYangPath_sys_server_group_path_xfmr: params: ", params)

    if params.tblName == "LDAP" {
        if len(params.tblKeyComp) > 0 {
            ygKeyVal := ""
            switch params.tblKeyComp[0] {
            case "global":
                ygKeyVal = "LDAP"
            case "nss":
                ygKeyVal = "LDAP_NSS"
            case "pam":
                ygKeyVal = "LDAP_PAM"
            case "sudo":
                ygKeyVal = "LDAP_SUDO"
            }
            params.ygPathKeys[sgRoot + "/name"] = ygKeyVal
        }
    }

    if params.tblName == "RADIUS" {
        if len(params.tblKeyComp) > 0 {
            ygKeyVal := ""
            switch params.tblKeyComp[0] {
            case "global":
                ygKeyVal = "RADIUS"
            }
            params.ygPathKeys[sgRoot + "/name"] = ygKeyVal
        }
    }

    if params.tblName == "TACPLUS" {
        if len(params.tblKeyComp) > 0 {
            ygKeyVal := ""
            switch params.tblKeyComp[0] {
            case "global":
                ygKeyVal = "TACACS"
            }
            params.ygPathKeys[sgRoot + "/name"] = ygKeyVal
        }
    }

    log.Info("DbToYangPath_sys_server_group_path_xfmr:- params.ygPathKeys: ", params.ygPathKeys)

    return nil
}

var DbToYangPath_sys_server_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) (error) {
    sgRoot := "/openconfig-system:system/aaa/server-groups/server-group"
    sysServer := sgRoot + "/servers/server"

    log.Info("DbToYangPath_sys_server_path_xfmr: params: ", params)

    if params.tblName == "LDAP_SERVER" {
        params.ygPathKeys[sgRoot + "/name"] = "LDAP"
        if len(params.tblKeyComp) > 0 {
            params.ygPathKeys[sysServer + "/address"] = params.tblKeyComp[0]
        }
    }

    if params.tblName == "RADIUS_SERVER" {
        params.ygPathKeys[sgRoot + "/name"] = "RADIUS"
        if len(params.tblKeyComp) > 0 {
            params.ygPathKeys[sysServer + "/address"] = params.tblKeyComp[0]
        }
    }

    if params.tblName == "TACPLUS_SERVER" {
        params.ygPathKeys[sgRoot + "/name"] = "TACACS"
        if len(params.tblKeyComp) > 0 {
            params.ygPathKeys[sysServer + "/address"] = params.tblKeyComp[0]
        }
    }

    log.Info("DbToYangPath_sys_server_path_xfmr:- params.ygPathKeys: ", params.ygPathKeys)

    return nil
}

var DbToYangPath_ldap_map_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) (error) {
    sgRoot := "/openconfig-system:system/aaa/server-groups/server-group"
    ldapMap := sgRoot + "/openconfig-aaa-ldap-ext:ldap/maps/map"

    log.Info("DbToYangPath_ldap_map_path_xfmr: params: ", params)

    if params.tblName == "LDAP_MAP" {
        params.ygPathKeys[sgRoot + "/name"] = "LDAP"
        if len(params.tblKeyComp) == 2 {
            params.ygPathKeys[ldapMap + "/name"] = params.tblKeyComp[0]
            params.ygPathKeys[ldapMap + "/from"] = params.tblKeyComp[1]
        }
    }

    log.Info("DbToYangPath_ldap_map_path_xfmr:- params.ygPathKeys: ", params.ygPathKeys)

    return nil
}

var YangToDb_secret_key_value_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    var encrypted *bool = nil

    if (inParams.oper == DELETE) {
        res_map[SECRET_KEY_ATTR] = ""
        return res_map, nil
    }

    pathInfo := NewPathInfo(inParams.uri)
    log.Info("YangToDb_secret_key_value_xfmr - pathInfo: ", pathInfo)

    key_value := inParams.param.(*string)

    servergroupname := pathInfo.Var("name")
    log.Info("YangToDb_secret_key_value_xfmr - servergroupname : ", servergroupname)

    sysObj := getSystemRootObject(inParams)
    aaaData := sysObj.Aaa

    // Get KeyEncrytped value and use it to determin if need to perform encryt the string
    address := pathInfo.Var("address")

    if (len(address) > 0) {
        if (strings.Compare(servergroupname, "RADIUS") == 0) {
            encrypted = aaaData.ServerGroups.ServerGroup[servergroupname].Servers.Server[address].Radius.Config.Encrypted
        } else if (strings.Compare(servergroupname, "TACACS") == 0) {
            encrypted = aaaData.ServerGroups.ServerGroup[servergroupname].Servers.Server[address].Tacacs.Config.Encrypted
        }
    } else {
        encrypted = aaaData.ServerGroups.ServerGroup[servergroupname].Config.Encrypted
    }

    // go ahead and decrypt
    if ((encrypted == nil) || (!*encrypted)) {
        log.Info("YangToDb_secret_key_value_xfmr - received plaintext: ")
        // if input is plaintext string, validate the string
        if ((strings.ContainsAny(*key_value, ",#")) ||
                    (strings.Contains(*key_value, " "))) {
                        errStr := "Invalid password"
                        log.Info("YangToDb_secret_key_value_xfmr, error ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
        }

        key_value_byte := []byte(*key_value)
        encrypted_key_value, err := openssl(key_value_byte, "enc", "-aes-128-cbc", "-A", "-a", "-salt", "-pass", "pass:"+AAA_SECRET_PASSWORD)
        if (err != nil) {
            log.Info("YangToDb_secret_key_value_xfmr, encryption failed with err ", err)
            return res_map, err
        }

        encrypted_str := string([]byte(encrypted_key_value))
        encrypted_str = strings.TrimFunc(encrypted_str, func(r rune) bool {
            return !unicode.IsGraphic(r)
        })
        log.Info("YangToDb_secret_key_value_xfmr: encrypted_str ", encrypted_str)
        res_map[SECRET_KEY_ATTR] = encrypted_str
    } else {
        log.Info("YangToDb_secret_key_value_xfmr - received encrypted key: ")
        // If the key value is encrypted, then validate it by decryption to prevent setting a bad key value in the configDB
        decrypt_data, err := base64.StdEncoding.DecodeString(*key_value)
        if (err != nil) {
                        errStr := "Invalid encrypted text"
                        log.Info("YangToDb_secret_key_value_xfmr, error ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
        }
        decrypt_data_byte := []byte(decrypt_data)
        _, err = openssl(decrypt_data_byte, "enc", "-aes-128-cbc", "-d", "-salt", "-pass", "pass:"+AAA_SECRET_PASSWORD)
        if (err != nil) {
                        errStr := "Decryption to plaintext failed, invalid encrypted text"
                        log.Info("YangToDb_secret_key_value_xfmr, error ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
        }
        res_map[SECRET_KEY_ATTR] = *key_value
    }

    return res_map, nil
}

var DbToYang_secret_key_value_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    log.Info("DbToYang_secret_key_encrypted_xfmr - pathInfo: ", pathInfo)
    servergroupname := pathInfo.Var("name")
    log.Info("DbToYang_secret_key_encrypted_xfmr - servergroupname: ", servergroupname)
    data := (*inParams.dbDataMap)[inParams.curDb]

    if strings.Contains(servergroupname, "RADIUS") {
        key_tbl := data["RADIUS"]
        if strings.HasPrefix(inParams.uri, "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/servers/server") {
            key_tbl = data["RADIUS_SERVER"]
        }
        key_entry := key_tbl[inParams.key]
        key_value := key_entry.Field[SECRET_KEY_ATTR]
        res_map[YANG_SECRET_KEY_ATTR] = key_value
    } else if strings.Contains(servergroupname, "TACACS") {
        key_tbl := data["TACPLUS"]
        if strings.HasPrefix(inParams.uri, "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server"){
            key_tbl = data["TACPLUS_SERVER"]
        }
        key_entry := key_tbl[inParams.key]
        key_value := key_entry.Field[SECRET_KEY_ATTR]
        if (len(key_value) > 0) {
            res_map[YANG_SECRET_KEY_ATTR] = key_value
        }
    }

    return res_map, err
}

var YangToDb_secret_key_encrypted_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    var err error
    return nil, err
}

var DbToYang_secret_key_encrypted_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error

    res_map[SECRET_KEY_ENCRYPTED_ATTR] = true

    return res_map, err
}

