
package transformer

import (
    "errors"
    "strconv"
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
)

//const sock_addr = "/etc/sonic/frr/bgpd_client_sock"

func init () {

    XlateFuncBind("YangToDb_ospfv2_router_tbl_key_xfmr", YangToDb_ospfv2_router_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_tbl_key_xfmr", DbToYang_ospfv2_router_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_enable_fld_xfmr", YangToDb_ospfv2_router_enable_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_enable_fld_xfmr", DbToYang_ospfv2_router_enable_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_area_tbl_key_xfmr", YangToDb_ospfv2_router_area_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_tbl_key_xfmr", DbToYang_ospfv2_router_area_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_area_area_id_fld_xfmr", YangToDb_ospfv2_router_area_area_id_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_area_id_fld_xfmr", DbToYang_ospfv2_router_area_area_id_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_area_policy_tbl_key_xfmr", YangToDb_ospfv2_router_area_policy_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_policy_tbl_key_xfmr", DbToYang_ospfv2_router_area_policy_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_area_policy_src_area_fld_xfmr", YangToDb_ospfv2_router_area_policy_src_area_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_policy_src_area_fld_xfmr", DbToYang_ospfv2_router_area_policy_src_area_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_area_network_tbl_key_xfmr", YangToDb_ospfv2_router_area_network_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_network_tbl_key_xfmr", DbToYang_ospfv2_router_area_network_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_network_prefix_fld_xfmr", YangToDb_ospfv2_router_network_prefix_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_network_prefix_fld_xfmr", DbToYang_ospfv2_router_network_prefix_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_area_virtual_link_tbl_key_xfmr", YangToDb_ospfv2_router_area_virtual_link_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_virtual_link_tbl_key_xfmr", DbToYang_ospfv2_router_area_virtual_link_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_area_vl_remote_router_id_fld_xfmr", YangToDb_ospfv2_router_area_vl_remote_router_id_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_vl_remote_router_id_fld_xfmr", DbToYang_ospfv2_router_area_vl_remote_router_id_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_area_policy_import_list_fld_xfmr", YangToDb_ospfv2_router_area_policy_import_list_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_policy_import_list_fld_xfmr", DbToYang_ospfv2_router_area_policy_import_list_fld_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_area_policy_export_list_fld_xfmr", YangToDb_ospfv2_router_area_policy_export_list_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_policy_export_list_fld_xfmr", DbToYang_ospfv2_router_area_policy_export_list_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_area_policy_address_range_tbl_key_xfmr", YangToDb_ospfv2_router_area_policy_address_range_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_policy_address_range_tbl_key_xfmr", DbToYang_ospfv2_router_area_policy_address_range_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_area_policy_address_range_prefix_fld_xfmr", YangToDb_ospfv2_router_area_policy_address_range_prefix_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_area_policy_address_range_prefix_fld_xfmr", DbToYang_ospfv2_router_area_policy_address_range_prefix_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_distribute_route_tbl_key_xfmr", YangToDb_ospfv2_router_distribute_route_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_distribute_route_tbl_key_xfmr", DbToYang_ospfv2_router_distribute_route_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_distribute_route_protocol_fld_xfmr", YangToDb_ospfv2_router_distribute_route_protocol_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_distribute_route_protocol_fld_xfmr", DbToYang_ospfv2_router_distribute_route_protocol_fld_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_distribute_route_access_list_fld_xfmr", YangToDb_ospfv2_router_distribute_route_access_list_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_distribute_route_access_list_fld_xfmr", DbToYang_ospfv2_router_distribute_route_access_list_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr", YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_passive_interface_tbl_key_xfmr", DbToYang_ospfv2_router_passive_interface_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_passive_interface_name_fld_xfmr", YangToDb_ospfv2_router_passive_interface_name_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_passive_interface_name_fld_xfmr", DbToYang_ospfv2_router_passive_interface_name_fld_xfmr)
    XlateFuncBind("YangToDb_ospfv2_router_passive_interface_address_fld_xfmr", YangToDb_ospfv2_router_passive_interface_address_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_router_passive_interface_address_fld_xfmr", DbToYang_ospfv2_router_passive_interface_address_fld_xfmr)

    XlateFuncBind("YangToDb_ospfv2_interface_tbl_key_xfmr", YangToDb_ospfv2_interface_tbl_key_xfmr)
    XlateFuncBind("DbToYang_ospfv2_interface_tbl_key_xfmr", DbToYang_ospfv2_interface_tbl_key_xfmr)
    XlateFuncBind("YangToDb_ospfv2_interface_name_fld_xfmr", YangToDb_ospfv2_interface_name_fld_xfmr)
    XlateFuncBind("DbToYang_ospfv2_interface_name_fld_xfmr", DbToYang_ospfv2_interface_name_fld_xfmr)

}

func getOspfv2Root (inParams XfmrParams) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2, string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    ospfv2VrfName := pathInfo.Var("name")
    ospfv2Identifier := pathInfo.Var("identifier")
    ospfv2InstanceNumber := pathInfo.Var("name#2")
    var err error

    if len(pathInfo.Vars) <  3 {
        return nil, "", errors.New("Invalid Key length")
    }

    if len(ospfv2VrfName) == 0 {
        return nil, "", errors.New("vrf name is missing")
    }

    if !strings.Contains(ospfv2Identifier, "OSPF") {
        return nil, "", errors.New("Protocol ID OSPF is missing")
    }
 
    if len(ospfv2InstanceNumber) == 0 {
        return nil, "", errors.New("Protocol Insatnce Id is missing")
    }

    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    jsonStr, err := ygot.EmitJSON(deviceObj, &ygot.EmitJSONConfig{
           Format:         ygot.RFC7951,
           Indent:         "  ",
           SkipValidation: true,
           RFC7951Config: &ygot.RFC7951JSONConfig{
                   AppendModuleName: true,
           },
    })
    log.Info("################################")
    log.Infof(" getOspfv2Root App ygot jsonStr: %v", jsonStr)
    log.Info("################################")  

    netInstsObj := deviceObj.NetworkInstances

    if netInstsObj.NetworkInstance == nil {
        return nil, "", errors.New("Network-instances container missing")
    }

    netInstObj := netInstsObj.NetworkInstance[ospfv2VrfName]
    if netInstObj == nil {
        return nil, "", errors.New("Network-instance obj for OSPFv2 missing")
    }

    if netInstObj.Protocols == nil || len(netInstObj.Protocols.Protocol) == 0 {
        return nil, "", errors.New("Network-instance protocols-container for OSPFv2 missing or protocol-list empty")
    }

    var protoKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Key
    protoKey.Identifier = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF
    protoKey.Name = ospfv2InstanceNumber
    protoInstObj := netInstObj.Protocols.Protocol[protoKey]
    if protoInstObj == nil {
        return nil, "", errors.New("Network-instance OSPFv2-Protocol obj missing")
    }

    if protoInstObj.Ospfv2 == nil {
        var _Ospfv2_obj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2
        protoInstObj.Ospfv2 = &_Ospfv2_obj
        ygot.BuildEmptyTree (protoInstObj.Ospfv2)
    }

    return protoInstObj.Ospfv2, ospfv2VrfName, err
}



var YangToDb_ospfv2_router_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error

    log.Info("YangToDb_ospfv2_router_tbl_key_xfmr - URI: ", inParams.uri)

    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName := pathInfo.Var("name")
    ospfv2Identifier := pathInfo.Var("identifier")
    ospfv2InstanceNumber := pathInfo.Var("name#2")

    if len(pathInfo.Vars) <  3 {
        return "", errors.New("Invalid Key length")
    }

    if len(ospfv2VrfName) == 0 {
        return "", errors.New("vrf name is missing")
    }

    if !strings.Contains(ospfv2Identifier,"OSPF") {
        return "", errors.New("OSPF ID is missing")
    }

    if len(ospfv2InstanceNumber) == 0 {
        return "", errors.New("Protocol instance number Name is missing")
    }

    log.Info("URI VRF ", ospfv2VrfName)

    log.Info("YangToDb_ospfv2_router_tbl_key_xfmr returned Key: ", ospfv2VrfName)
    return ospfv2VrfName, err
}


func YangToDb_ospfv2_validate_acl_name(inParams XfmrParams, fieldName string) (map[string]string, error) {
    var err error
    res_map := make(map[string]string)

    if (inParams.param.(*string) != nil) {
        aclName := * (inParams.param.(*string))
        /* Further validation TBD */
        res_map[fieldName] = "" + aclName
        return res_map, err
    }

    return res_map, errors.New("Invalid Acl Name")
}


func DbToYang_ospfv2_validate_acl_name(inParams XfmrParams, fieldName string) (map[string]interface{}, error) {
    var err error
    res_map := make(map[string]interface{})

    if ((inParams.param != nil) && (inParams.param.(*string) != nil)) {
        fieldValue := * (inParams.param.(*string))
        aclName := fieldValue
        /* Further validation TBD */
        res_map[fieldName] = aclName
        return res_map, err
    }

    return res_map, errors.New("Invalid Acl Name")
}


var DbToYang_ospfv2_router_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error

    ospfv2RouterTableKey := inParams.key
    log.Info("DbToYang_ospfv2_router_tbl_key: ", ospfv2RouterTableKey)

    res_map["name"] = ospfv2RouterTableKey

    log.Info("DbToYang_ospfv2_router_tbl_key_xfmr key: ", res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_enable_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_enable_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    ospfv2RouterTableKey := inParams.key
    log.Info("DbToYang_ospfv2_router_enable_fld_xfmr: ", ospfv2RouterTableKey)

    res_map["name"] = ospfv2RouterTableKey
    return res_map, err
}


func getAreaDotted(areaString string) string {
    if len(areaString) == 0 {
       log.Info("getAreaDotted: Null area id received")
       return ""
    }

    areaInt, err := strconv.ParseInt(areaString, 10, 64)
    if err == nil {
        b0 := strconv.FormatInt((areaInt >> 24) & 0xff, 10)
        b1 := strconv.FormatInt((areaInt >> 16) & 0xff, 10)
        b2 := strconv.FormatInt((areaInt >> 8) & 0xff, 10)
        b3 := strconv.FormatInt((areaInt & 0xff), 10)
         
        areaDotted :=  b0 + "." + b1 + "." + b2 + "." + b3
        log.Info("getAreaDotted: ", areaDotted)
        return areaDotted
     }

     log.Info("getAreaDotted: ", areaString) 
     return areaString
}


var YangToDb_ospfv2_router_area_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ospfv2VrfName string

    log.Info("YangToDb_ospfv2_router_area_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName    =  pathInfo.Var("name")
    ospfv2Identifier      := pathInfo.Var("identifier")
    ospfv2InstanceNumber  := pathInfo.Var("name#2")
    ospfv2AreaId   := pathInfo.Var("identifier#2")

    if len(pathInfo.Vars) <  4 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return ospfv2VrfName, err
    }

    if len(ospfv2VrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }
    if !strings.Contains(ospfv2Identifier,"OSPF") {
        err = errors.New("OSPF ID is missing");
        log.Info("OSPF ID is missing")
        return "", err
    }
    if len(ospfv2InstanceNumber) == 0 {
        err = errors.New("OSPF intance number/name is missing");
        log.Info("Protocol Name is Missing")
        return "", err
    }
    if len(ospfv2AreaId) == 0 {
        log.Info("OSPF area Id is Missing")
        return "", nil
    }

    ospfv2AreaId = getAreaDotted(ospfv2AreaId)

    log.Info("URI VRF", ospfv2VrfName)
    log.Info("URI Area Id", ospfv2AreaId)

    pAreaTableKey := ospfv2VrfName + "|" + ospfv2AreaId

    log.Info("YangToDb_ospfv2_router_area_tbl_key_xfmr: pAreaTableKey - ", pAreaTableKey)
    return pAreaTableKey, nil
}



var DbToYang_ospfv2_router_area_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_router_area_tbl_key: entry key - ", entry_key)

    areaTableKeys := strings.Split(entry_key, "|")

    if len(areaTableKeys) >= 2 {
       res_map["identifier"] = areaTableKeys[1]
    }

    log.Info("DbToYang_ospfv2_router_area_tbl_key: res_map - ", res_map)
    return res_map, nil
}

var YangToDb_ospfv2_router_area_area_id_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_area_area_id_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    areaTableKeys := strings.Split(entry_key, "|")

    if len(areaTableKeys) >= 2 {
        res_map["identifier"] = areaTableKeys[1]
    }

    log.Info("DbToYang_ospfv2_router_area_area_id_fld_xfmr: res_map - ", res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_area_policy_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ospfv2VrfName string

    log.Info("YangToDb_ospfv2_router_area_policy_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName    =  pathInfo.Var("name")
    ospfv2Identifier      := pathInfo.Var("identifier")
    ospfv2InstanceNumber  := pathInfo.Var("name#2")
    ospfv2AreaId   := pathInfo.Var("src-area")

    if len(pathInfo.Vars) <  4 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return ospfv2VrfName, err
    }

    if len(ospfv2VrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }
    if !strings.Contains(ospfv2Identifier,"OSPF") {
        err = errors.New("OSPF ID is missing");
        log.Info("OSPF ID is missing")
        return "", err
    }
    if len(ospfv2InstanceNumber) == 0 {
        err = errors.New("OSPF intance number/name is missing");
        log.Info("Protocol Name is Missing")
        return "", err
    }
    if len(ospfv2AreaId) == 0 {
        err = errors.New("OSPF area Id is missing")
        log.Info("OSPF area Id is Missing")
        return "", err
    }

    ospfv2AreaId = getAreaDotted(ospfv2AreaId)

    log.Info("URI VRF", ospfv2VrfName)
    log.Info("URI Area Id", ospfv2AreaId)

    pAreaTableKey := ospfv2VrfName + "|" + ospfv2AreaId

    log.Info("YangToDb_ospfv2_router_area_policy_tbl_key_xfmr: pAreaTableKey - ", pAreaTableKey)
    return pAreaTableKey, nil
}


var DbToYang_ospfv2_router_area_policy_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_router_area_policy_tbl_key: entry key - ", entry_key)

    areaTableKeys := strings.Split(entry_key, "|")

    if len(areaTableKeys) >= 2 {
       res_map["src-area"] = areaTableKeys[1]
    }

    log.Info("DbToYang_ospfv2_router_area_policy_tbl_key: res_map - ", res_map)
    return res_map, nil
}


var YangToDb_ospfv2_router_area_policy_src_area_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_area_policy_src_area_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    areaTableKeys := strings.Split(entry_key, "|")

    if len(areaTableKeys) >= 2 {
        res_map["src-area"] = areaTableKeys[1]
    }

    log.Info("DbToYang_ospfv2_router_area_policy_src_area_fld_xfmr: res_map - ", res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_area_policy_export_list_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map, err := YangToDb_ospfv2_validate_acl_name(inParams, "export-list")
    log.Infof("YangToDb_ospfv2_router_area_policy_export_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
    return res_map, err        
}


var DbToYang_ospfv2_router_area_policy_export_list_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    res_map, err :=  DbToYang_ospfv2_validate_acl_name(inParams, "export-list")
    log.Infof("DbToYang_ospfv2_router_area_policy_export_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_area_policy_import_list_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map, err := YangToDb_ospfv2_validate_acl_name(inParams, "import-list")
    log.Infof("YangToDb_ospfv2_router_area_policy_import_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
    return res_map, err
}


var DbToYang_ospfv2_router_area_policy_import_list_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    res_map, err :=  DbToYang_ospfv2_validate_acl_name(inParams, "import-list")
    log.Infof("DbToYang_ospfv2_router_area_policy_import_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_area_network_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ospfv2VrfName string

    log.Info("YangToDb_ospfv2_router_area_network_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName    =  pathInfo.Var("name")
    ospfv2Identifier      := pathInfo.Var("identifier")
    ospfv2InstanceNumber  := pathInfo.Var("name#2")
    ospfv2AreaId   := pathInfo.Var("identifier#2")
    ospfv2NetworkPrefix   := pathInfo.Var("address-prefix")

    if len(pathInfo.Vars) <  5 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return ospfv2VrfName, err
    }

    if len(ospfv2VrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }
    if !strings.Contains(ospfv2Identifier,"OSPF") {
        err = errors.New("OSPF ID is missing");
        log.Info("OSPF ID is missing")
        return "", err
    }
    if len(ospfv2InstanceNumber) == 0 {
        err = errors.New("OSPF intance number/name is missing");
        log.Info("Protocol Name is Missing")
        return "", err
    }

    if len(ospfv2AreaId) == 0 {
        err = errors.New("OSPF area Id is missing")
        log.Info("OSPF area Id is Missing")
        return "", err
    }

    ospfv2AreaId = getAreaDotted(ospfv2AreaId)

    if len(ospfv2NetworkPrefix) == 0 {
        err = errors.New("OSPF area Network prefix is missing")
        log.Info("OSPF area Network prefix is Missing")
        return "", err
    }

    log.Info("URI VRF ", ospfv2VrfName)
    log.Info("URI Area Id ", ospfv2AreaId)
    log.Info("URI Network ", ospfv2NetworkPrefix)

    pNetworkTableKey := ospfv2VrfName + "|" + ospfv2AreaId + "|" + ospfv2NetworkPrefix

    log.Info("YangToDb_ospfv2_router_area_network_tbl_key_xfmr: pNetworkTableKey - ", pNetworkTableKey)
    return pNetworkTableKey, nil
}


var DbToYang_ospfv2_router_area_network_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_router_area_network_tbl_key: entry key - ", entry_key)

    netowrkTableKeys := strings.Split(entry_key, "|")

    if len(netowrkTableKeys) >= 3 {
       res_map["address-prefix"] = netowrkTableKeys[2]
    }

    log.Info("DbToYang_ospfv2_router_area_network_tbl_key: res_map - ", res_map)
    return res_map, nil
}

var YangToDb_ospfv2_router_network_prefix_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    pathInfo := NewPathInfo(inParams.uri)
    ospfv2VrfName :=  pathInfo.Var("name")
    if len(ospfv2VrfName) == 0 {
        err := errors.New("VRF name is missing");
        log.Info("YangToDb_ospfv2_router_network_prefix_fld_xfmr: VRF Name is Missing")
        return res_map, err
    }

    intfAreaIdPresent, err := ospf_area_id_present_in_interfaces(&inParams, ospfv2VrfName)
    if err != nil {
        log.Info("YangToDb_ospfv2_router_network_prefix_fld_xfmr: intfAreaIdPresent check Failed")
        return res_map, tlerr.New("Internal error: Interface area id config check failed")
    } else if (intfAreaIdPresent) {
        log.Info("YangToDb_ospfv2_router_network_prefix_fld_xfmr: intfAreaIdPresent")
        return res_map, tlerr.New("Please remove all interface area-id configurations first")
    }

    res_map["NULL"] = "NULL"
    return res_map, nil
}


var DbToYang_ospfv2_router_network_prefix_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    netowrkTableKeys := strings.Split(entry_key, "|")

    if len(netowrkTableKeys) >= 3 {
        res_map["address-prefix"] = netowrkTableKeys[2]
    }

    log.Info("DbToYang_ospfv2_router_network_prefix_fld_xfmr: res_map - ", res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_area_virtual_link_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ospfv2VrfName string

    log.Info("YangToDb_ospfv2_router_area_virtual_link_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName    =  pathInfo.Var("name")
    ospfv2Identifier      := pathInfo.Var("identifier")
    ospfv2InstanceNumber  := pathInfo.Var("name#2")
    ospfv2AreaId   := pathInfo.Var("identifier#2")
    ospfv2RemoteRouterId   := pathInfo.Var("remote-router-id")

    if len(pathInfo.Vars) <  5 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return ospfv2VrfName, err
    }

    if len(ospfv2VrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }

    if !strings.Contains(ospfv2Identifier,"OSPF") {
        err = errors.New("OSPF ID is missing");
        log.Info("OSPF ID is missing")
        return "", err
    }

    if len(ospfv2InstanceNumber) == 0 {
        err = errors.New("OSPF intance number/name is missing");
        log.Info("Protocol Name is Missing")
        return "", err
    }

    if len(ospfv2AreaId) == 0 {
        err = errors.New("OSPF area Id is missing")
        log.Info("OSPF area Id is Missing")
        return "", err
    }

    ospfv2AreaId = getAreaDotted(ospfv2AreaId)

    if len(ospfv2RemoteRouterId) == 0 {
        err = errors.New("OSPF area VL remote router Id is missing")
        log.Info("OSPF area VL remote router Id is Missing")
        return "", err
    }

    log.Info("URI VRF ", ospfv2VrfName)
    log.Info("URI Area Id ", ospfv2AreaId)
    log.Info("URI Virtual link remote router Id ", ospfv2RemoteRouterId)

    pVirtualLinkTableKey := ospfv2VrfName + "|" + ospfv2AreaId + "|" + ospfv2RemoteRouterId

    log.Info("YangToDb_ospfv2_router_area_virtual_link_tbl_key_xfmr: pVirtualLinkTableKey - ", pVirtualLinkTableKey)
    return pVirtualLinkTableKey, nil
}


var DbToYang_ospfv2_router_area_virtual_link_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_router_area_virtual_link_tbl_key: entry key - ", entry_key)

    virtualLinkTableKey := strings.Split(entry_key, "|")

    if len(virtualLinkTableKey) >= 3 {
        res_map["remote-router-id"] = virtualLinkTableKey[2]
    }

    log.Info("DbToYang_ospfv2_router_area_virtual_link_tbl_key: res_map - ", res_map)
    return res_map, nil
}

var YangToDb_ospfv2_router_area_vl_remote_router_id_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_area_vl_remote_router_id_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    virtualLinkTableKey := strings.Split(entry_key, "|")

    if len(virtualLinkTableKey) >= 3 {
       res_map["remote-router-id"] = virtualLinkTableKey[2]
    }
    return res_map, err
}

var YangToDb_ospfv2_router_area_policy_address_range_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ospfv2VrfName string

    log.Info("YangToDb_ospfv2_router_area_policy_address_range_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName           = pathInfo.Var("name")
    ospfv2Identifier       := pathInfo.Var("identifier")
    ospfv2InstanceNumber   := pathInfo.Var("name#2")
    ospfv2policySourceArea := pathInfo.Var("src-area")
    ospfv2AddressRange     := pathInfo.Var("address-prefix")

    if len(pathInfo.Vars) <  5 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return ospfv2VrfName, err
    }

    if len(ospfv2VrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }

    if !strings.Contains(ospfv2Identifier,"OSPF") {
        err = errors.New("OSPF ID is missing");
        log.Info("OSPF ID is missing")
        return "", err
    }

    if len(ospfv2InstanceNumber) == 0 {
        err = errors.New("OSPF intance number/name is missing");
        log.Info("Protocol Name is Missing")
        return "", err
    }

    if len(ospfv2policySourceArea) == 0 {
        log.Info("OSPF area Id is Missing")
        return "", nil
    }

    ospfv2policySourceArea = getAreaDotted(ospfv2policySourceArea)

    if len(ospfv2AddressRange) == 0 {
        log.Info("OSPF area Address Range prefix is Missing")
        return "", nil
    }

    log.Info("URI VRF ", ospfv2VrfName)
    log.Info("URI Area Id ", ospfv2policySourceArea)
    log.Info("URI Address Range ", ospfv2AddressRange)

    pAddressRangeTableKey := ospfv2VrfName + "|" + ospfv2policySourceArea + "|" + ospfv2AddressRange

    log.Info("YangToDb_ospfv2_router_area_policy_address_range_tbl_key_xfmr: pAddressRangeTableKey - ", pAddressRangeTableKey)
    return pAddressRangeTableKey, nil
}


var DbToYang_ospfv2_router_area_policy_address_range_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_router_area_policy_address_range_tbl_key: entry key - ", entry_key)

    addressRAngeTableKey := strings.Split(entry_key, "|")

    if len(addressRAngeTableKey) >= 3 {
        res_map["address-prefix"] = addressRAngeTableKey[2]
    }

    log.Info("DbToYang_ospfv2_router_area_policy_address_range_tbl_key: res_map - ", res_map)
    return res_map, nil
}


var YangToDb_ospfv2_router_area_policy_address_range_prefix_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_area_policy_address_range_prefix_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    addressRAngeTableKey := strings.Split(entry_key, "|")

    if len(addressRAngeTableKey) >= 3 {
        res_map["address-prefix"] = addressRAngeTableKey[2]
    }

    log.Info("DbToYang_ospfv2_router_area_policy_address_range_prefix_fld_xfmr: res_map - ", res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_distribute_route_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ospfv2VrfName string

    log.Info("YangToDb_ospfv2_router_distribute_route_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName    =  pathInfo.Var("name")
    ospfv2Identifier      := pathInfo.Var("identifier")
    ospfv2InstanceNumber  := pathInfo.Var("name#2")
    distributionProtocol  := pathInfo.Var("protocol")
    distributionDirection := pathInfo.Var("direction")

    if len(pathInfo.Vars) <  5 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return ospfv2VrfName, err
    }

    if len(ospfv2VrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }
    if !strings.Contains(ospfv2Identifier,"OSPF") {
        err = errors.New("OSPF ID is missing");
        log.Info("OSPF ID is missing")
        return "", err
    }
    if len(ospfv2InstanceNumber) == 0 {
        err = errors.New("OSPF intance number/name is missing");
        log.Info("Protocol Name is Missing")
        return "", err
    }

    if len(distributionProtocol) == 0 {
        log.Info("OSPF Route Distriburion protocol name Missing")
        return "", nil
    }

    if len(distributionDirection) == 0 {
        log.Info("OSPF Route Distriburion direction is Missing")
        return "", nil
    }

    log.Info("URI VRF ", ospfv2VrfName)
    log.Info("URI route distribution protocol ", distributionProtocol)
    log.Info("URI route distribution direction ", distributionDirection)

    tempkey1 := strings.Split(distributionProtocol, ":")
    if len(tempkey1) > 1 {
        distributionProtocol = tempkey1[1]
    }

    tempkey2 := strings.Split(distributionDirection, ":")
    if len(tempkey2) > 1 {
        distributionDirection = tempkey2[1]
    }
   
    pdistributionTableKey := ospfv2VrfName + "|" + distributionProtocol + "|" + distributionDirection

    log.Info("YangToDb_ospfv2_router_distribute_route_tbl_key_xfmr: pdistributionTableKey - ", pdistributionTableKey)
    return pdistributionTableKey, nil
}


var DbToYang_ospfv2_router_distribute_route_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_router_distribute_route_tbl_key: entry key - ", entry_key)

    distributionTableKeys := strings.Split(entry_key, "|")

    if len(distributionTableKeys) >= 3 {
        res_map["direction"] = distributionTableKeys[2]
    }

    log.Info("DbToYang_ospfv2_router_distribute_route_tbl_key: res_map - ", res_map)
    return res_map, nil
}

var YangToDb_ospfv2_router_distribute_route_protocol_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_distribute_route_protocol_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    distributionTableKeys := strings.Split(entry_key, "|")

    if len(distributionTableKeys) >= 3 {
        res_map["protocol"] = distributionTableKeys[1]
    }
    return res_map, err
}

var YangToDb_ospfv2_router_distribute_route_direction_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_distribute_route_direction_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    distributionTableKeys := strings.Split(entry_key, "|")

    if len(distributionTableKeys) >= 3 {
        res_map["direction"] = distributionTableKeys[2]
    }
    return res_map, err
}


var YangToDb_ospfv2_router_distribute_route_access_list_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map, err := YangToDb_ospfv2_validate_acl_name(inParams, "access-list")
    log.Infof("YangToDb_ospfv2_router_area_policy_access_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
    return res_map, err
}

var DbToYang_ospfv2_router_distribute_route_access_list_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    res_map, err :=  DbToYang_ospfv2_validate_acl_name(inParams, "access-list")
    log.Infof("DbToYang_ospfv2_router_distribute_route_access_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
    return res_map, err
}


var YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var ospfv2VrfName string

    log.Info("YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    ospfv2VrfName    =  pathInfo.Var("name")
    ospfv2Identifier      := pathInfo.Var("identifier")
    ospfv2InstanceNumber  := pathInfo.Var("name#2")
    passiveIfName  := pathInfo.Var("name#3")
    passiveIfAddress := pathInfo.Var("address")

    if len(pathInfo.Vars) < 5 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return ospfv2VrfName, err
    }

    if len(ospfv2VrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }

    if !strings.Contains(ospfv2Identifier,"OSPF") {
        err = errors.New("OSPF ID is missing");
        log.Info("OSPF ID is missing")
        return "", err
    }

    if len(ospfv2InstanceNumber) == 0 {
        err = errors.New("OSPF intance number/name is missing");
        log.Info("Protocol Name is Missing")
        return "", err
    }

    if len(passiveIfName) == 0 {
        log.Info("OSPF Route Distriburion protocol name Missing")
        return "", nil
    }

    if len(passiveIfAddress) == 0 {
        log.Info("OSPF Route Distriburion protocol name Missing")
        return "", nil
    }

    log.Info("URI VRF ", ospfv2VrfName)
    log.Info("URI route distribution passiveIfName ", passiveIfName)
    log.Info("URI route distribution passiveIfAddress ", passiveIfAddress)

    tempkey1 := strings.Split(passiveIfName, ":")
    if len(tempkey1) > 1 {
        passiveIfName = tempkey1[1]
    }

    tempkey1 = strings.Split(passiveIfAddress, ":")
    if len(tempkey1) > 1 {
        passiveIfAddress = tempkey1[1]
    }

    passiveIfTableKey := ospfv2VrfName + "|" + passiveIfName  + "|" + passiveIfAddress

    log.Info("YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr: passiveIfTableKey - ", passiveIfTableKey)
    return passiveIfTableKey, nil
}

var DbToYang_ospfv2_router_passive_interface_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_router_passive_interface_tbl_key: entry key - ", entry_key)

    passiveIfTableKeys := strings.Split(entry_key, "|")

    if len(passiveIfTableKeys) >= 3 {
        res_map["name"] = passiveIfTableKeys[1]
        res_map["address"] = passiveIfTableKeys[2]
    }

    log.Info("DbToYang_ospfv2_router_passive_interface_tbl_key: res_map - ", res_map)
    return res_map, nil
}

var YangToDb_ospfv2_router_passive_interface_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_passive_interface_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    passiveIfTableKeys := strings.Split(entry_key, "|")

    if len(passiveIfTableKeys) >= 3 {
        res_map["name"] = passiveIfTableKeys[1]
    }
    return res_map, err
}

var YangToDb_ospfv2_router_passive_interface_address_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_router_passive_interface_address_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    passiveIfTableKeys := strings.Split(entry_key, "|")

    if len(passiveIfTableKeys) >= 3 {
        res_map["address"] = passiveIfTableKeys[2]
    }
    return res_map, err
}


var YangToDb_ospfv2_interface_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var interfaceVrfName string

    log.Info("YangToDb_ospfv2_interface_tbl_key_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    interfaceVrfName     = "default" //pathInfo.Var("name")
    ospfv2InterfaceName  := pathInfo.Var("name")
    ospfv2InterfaceId    := pathInfo.Var("index")

    if len(pathInfo.Vars) <  2 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return interfaceVrfName, err
    }

    if len(interfaceVrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return "", err
    }

    if len(ospfv2InterfaceName) == 0 {
        err = errors.New("OSPF interface name is missing");
        log.Info("OSPF interface name is Missing")
        return "", err
    }

    if len(ospfv2InterfaceId) == 0 {
        err = errors.New("OSPF interface identifier missing");
        log.Info("OSPF sub-interface identifier is Missing")
        return "", err
    }

    log.Info("URI VRF ", interfaceVrfName)
    log.Info("URI interface name ", ospfv2InterfaceName)
    log.Info("URI Sub interface Id ", ospfv2InterfaceId)

    pInterfaceTableKey := ospfv2InterfaceName

    log.Info("YangToDb_ospfv2_interface_tbl_key_xfmr: pInterfaceTableKey - ", pInterfaceTableKey)
    return pInterfaceTableKey, nil
}


var DbToYang_ospfv2_interface_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_interface_tbl_key: entry key - ", entry_key)

    /*
    interfaceTableKeys := strings.Split(entry_key, "|")

    if len(interfaceTableKeys) >= 1 {
        res_map["name"] = interfaceTableKeys[0]
        res_map["index"] = 0 
    }
    */

    log.Info("DbToYang_ospfv2_interface_tbl_key: res_map - ", res_map)
    return res_map, nil
}


var YangToDb_ospfv2_interface_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_ospfv2_interface_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    res_map := make(map[string]interface{})

    entry_key := inParams.key
    log.Info("DbToYang_ospfv2_interface_name_fld_xfmr: entry key - ", entry_key)

    /*
    interfaceTableKeys := strings.Split(entry_key, "|")

    if len(interfaceTableKeys) >= 1 {
        res_map["name"] = interfaceTableKeys[0]
        res_map["index"] = 0
    }
    */

    log.Info("DbToYang_ospfv2_interface_name_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

