
package transformer

import (
    "errors"
    "strconv"
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
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

func getOspfUriPath(inParams *XfmrParams) (string, error) {

    yangPath, err := getYangPathFromUri(inParams.uri)
    if (err != nil) {
        log.Info("getOspfUriPath: getYangPathFromUri failed ", err)
        return "", err
    }

    log.Infof("getOspfUriPath: yangPath %s", yangPath)

    uriPath := ""
    uriBlockList := strings.Split(yangPath, "/")
    for _, uriBlock := range uriBlockList {
        if uriBlock == ""  {  
            continue
        } 
            
        uriSubBlockList := strings.Split(uriBlock, ":")
        listLen := len(uriSubBlockList)
        if (listLen != 0) {
            uriPath = uriPath + "/" + uriSubBlockList[listLen - 1]
        }
    }
     
    log.Infof("getOspfUriPath: uriPath %s", uriPath)  
    return uriPath, nil 
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

func ospfGetNativeIntfName(ifName string) (string, error) {
   var errStr string

   if (ifName == "" ) {
       errStr = "Empty interface name received"
       log.Infof("ospfGetNativeIntfName: %s.", errStr)
       return ifName, errors.New(errStr)
   }

   if (!utils.IsAliasModeEnabled()) {
       if (strings.Contains(ifName,"/")) {
           errStr = "Invalid portname " + ifName + ", standard interface naming not enabled"
           log.Infof("ospfGetNativeIntfName: %s.", errStr)
           return ifName, errors.New(errStr)
       } else {
           log.Infof("ospfGetNativeIntfName: alias mode disabled return same name %s", ifName)
           return ifName, nil
       }
   }

   nonPhyIntfPrefixes := []string { "PortChannel", "Portchannel", "portchannel", 
                                     "Vlan", "VLAN", "vlan", "VLINK" }

   for _, intfPrefix := range nonPhyIntfPrefixes {
       if (strings.HasPrefix(ifName, intfPrefix)) {
           log.Infof("ospfGetNativeIntfName: non physical interface %s.", ifName)
           return ifName, nil
       }
   }

   nativeNamePtr := utils.GetNativeNameFromUIName(&ifName)
   log.Infof("ospfGetNativeIntfName: ifName %s native %s.", ifName, *nativeNamePtr)
   return *nativeNamePtr, nil
}

func ospfGetUIIntfName(ifName string) (string, error) {
   var errStr string

   if (ifName == "" ) {
       errStr = "Empty interface name received"
       log.Infof("ospfGetUIIntfName: %s.", errStr)
       return ifName, errors.New(errStr)
   }

   if (!utils.IsAliasModeEnabled()) {
       log.Infof("ospfGetUIIntfName: alias mode disabled return same name %s", ifName)
       return ifName, nil 
   }

   nonPhyIntfPrefixes := []string { "PortChannel", "Portchannel", "portchannel",
                                     "Vlan", "VLAN", "vlan", "VLINK" }

   for _, intfPrefix := range nonPhyIntfPrefixes {
       if (strings.HasPrefix(ifName, intfPrefix)) {
           log.Infof("ospfGetUIIntfName: non physical interface %s, return same name.", ifName)
           return ifName, nil
       }
   }

   uiNamePtr := utils.GetUINameFromNativeName(&ifName)
   log.Infof("ospfGetUIIntfName: ifName %s uiName %s.", ifName, *uiNamePtr)
   return *uiNamePtr, nil
}


func get_ospf_router_info_from_uri(inParams *XfmrParams) (string, string, string, error) {

    log.Info("get_ospf_router_info_from_uri: inParams.uri ", inParams.uri)
 
    rcvdUri, err := getOspfUriPath(inParams)
    if err != nil {
        errStr := "GetYangPathFromUri Failed " 
        log.Info("get_ospf_router_info_from_uri: ", errStr)
        return "", "", "", errors.New(errStr)
    }

    if (!strings.Contains(rcvdUri, "protocol/ospfv2")) {
        errStr := "Not an OSPF URI " + rcvdUri
        log.Info("get_ospf_router_info_from_uri: ", errStr)
        return "", "", "", errors.New(errStr)
    }

    pathInfo := NewPathInfo(inParams.uri)
    ospfVrfName :=  pathInfo.Var("name")
    ospfIdentifier := pathInfo.Var("identifier")
    ospfInstanceNumber := pathInfo.Var("name#2")

    if (ospfVrfName == "") {
        errStr := "Input URI doesnot contain ospf VRF name"
        log.Info("get_ospf_router_info_from_uri: ", errStr)
        return "", "", "", errors.New(errStr)
    }

    if (ospfIdentifier != "OSPF") {
        errStr := "Input URI doesnot contain ospf identifier name"
        log.Info("get_ospf_router_info_from_uri: ", errStr)
        return "", "", "", errors.New(errStr)
    }

    if len(ospfInstanceNumber) == 0 {
        errStr := "Input URI doesnot contain ospf instance number"
        log.Info("get_ospf_router_info_from_uri: ", errStr)
        return "", "", "", errors.New(errStr)
    }

    log.Infof("get_ospf_router_info_from_uri: vrf %s id %s instance %s.",
                   ospfVrfName, ospfIdentifier, ospfInstanceNumber)

    return ospfVrfName, ospfIdentifier, ospfInstanceNumber, nil
}


var YangToDb_ospfv2_router_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error

    log.Info("YangToDb_ospfv2_router_tbl_key_xfmr: inParams.uri ", inParams.uri)

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

    intfAreaIdPresent, err := ospf_area_id_present_in_interfaces(&inParams, ospfv2VrfName, "*")
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

    passiveIfName, err = ospfGetNativeIntfName(passiveIfName)
    if (err != nil) {
        return "", tlerr.New("Invalid passive interface name.")
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
        passiveIfName, _ := ospfGetUIIntfName(passiveIfTableKeys[1])
        res_map["name"] = passiveIfName 
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
        passiveIfName, _ := ospfGetUIIntfName(passiveIfTableKeys[1]) 
        res_map["name"] = passiveIfName  
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

    ospfv2InterfaceName, err = ospfGetNativeIntfName(ospfv2InterfaceName)
    if (err != nil) {
        return "", tlerr.New("Invalid OSPF interface name.")
    }

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


func ospfv2_config_post_xfmr(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) (error) {

    var err error

    err = nil
    rcvdUri, uriErr := getOspfUriPath(inParams)
    if (uriErr != nil) {
        log.Info("ospfv2_config_post_xfmr: getOspfUriPath failed ", uriErr)
        return uriErr
    }

    if (inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE) {
        log.Info("ospfv2_config_post_xfmr for ADD/UPDATE operation")

        autoCreateOspfArea := true
        if (autoCreateOspfArea) {
            if (strings.Contains(rcvdUri, "protocols/protocol/ospfv2")) {
                if (strings.Contains(rcvdUri, "openconfig-ospfv2-ext:networks/network") ||
                    strings.Contains(rcvdUri, "virtual-links/virtual-link") ||
                    strings.Contains(rcvdUri, "inter-area-policy/ranges/range")) {
                    err = ospf_auto_create_ospf_router_area(inParams, ospfRespMap)
                    if (err != nil) {
                        log.Info("ospfv2_config_post_xfmr: ospf_auto_create_ospf_router_area failed ", err)
                        return err
                    }
                }
            }
        }
    } else if inParams.oper == DELETE {
        log.Info("ospfv2_config_post_xfmr: for DELETE operation")

        if (strings.Contains(rcvdUri, "protocols/protocol/ospfv2")) {
            /* OSPFv2 uri */
            if (strings.HasSuffix(rcvdUri, "protocols/protocol/ospfv2") ||
                strings.HasSuffix(rcvdUri, "protocols/protocol/ospfv2/global")) {
                /* ospf router delete */
                err = delete_ospf_interfaces_for_vrf(inParams, ospfRespMap)
                if (err != nil) {
                    log.Info("ospfv2_config_post_xfmr: delete_ospf_interfaces_for_vrf failed ", err)
                    return err
                }
            } else {
                if (strings.Contains(rcvdUri, "route-distribution-policies")) {
                    /* ospf router redistribute delete */
                    err = delete_ospf_router_redistribute_entry(inParams, ospfRespMap)
                    if (err != nil) {
                        log.Info("ospfv2_config_post_xfmr: delete_ospf_router_redistribute_entry failed ", err)
                        return err
                    }
                }

                if (strings.Contains(rcvdUri, "areas/area")) {
                    err = validate_ospf_router_area_delete(inParams, ospfRespMap)
                    if (err != nil) {
                        log.Info("ospfv2_config_post_xfmr: validate_ospf_router_area_delete failed ", err)
                        return err
                    }
                }
            }
        }
    }

    return err
}


func ospf_router_present(inParams *XfmrParams, vrfName string) (bool, error) {

    log.Info("ospf_router_present: vrfName ", vrfName)
    if (vrfName == "") {
        errStr := "Empty vrfName name"
        log.Info("ospf_router_present: ", errStr)
        return false, errors.New(errStr)
    }

    ospfTblName := "OSPFV2_ROUTER"
    var ospfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfTblName}
    ospfTblData, err1 := configDbPtr.GetTable(ospfTblSpec)
    if err1 != nil {
        log.Info("ospf_router_present: get ospf router table failed ", err1)
        return false, err1
    }

    ospfTblKeys, err2 := ospfTblData.GetKeys()
    if err2 != nil {
        log.Info("ospf_router_present: router table get keys failed ", err2)
        return false, err2
    }

    for _, ospfTblKey := range ospfTblKeys {
        keyVrfName := ospfTblKey.Get(0)
        if keyVrfName == vrfName {
            log.Info("ospf_router_present: ospf router present with key ", ospfTblKey)
            return true, nil
        }
    }

    log.Info("ospf_router_present: ospf router not present in vrf ", vrfName)
    return false, nil
}

func ospf_router_area_present(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

    log.Infof("ospf_router_area_present: vrfName %s areaId %s", vrfName, areaId)
    if (vrfName == "") {
        errStr := "Empty vrfName name"
        log.Info("ospf_router_area_present: ", errStr)
        return false, errors.New(errStr)
    }

    if (areaId == "") {
        errStr := "Empty areaId"
        log.Info("ospf_router_area_present: ", errStr)
        return false, errors.New(errStr)
    }

    ospfTblName := "OSPFV2_ROUTER_AREA"
    var ospfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfTblName}
    ospfTblData, err1 := configDbPtr.GetTable(ospfTblSpec)
    if err1 != nil {
        log.Info("ospf_router_present: get ospf router area table failed ", err1)
        return false, err1
    }

    ospfTblKeys, err2 := ospfTblData.GetKeys()
    if err2 != nil {
        log.Info("ospf_router_area_present: router area table get keys failed ", err2)
        return false, err2
    }

    for _, ospfTblKey := range ospfTblKeys {
        keyVrfName := ospfTblKey.Get(0)
        keyAreaId := ospfTblKey.Get(1)
        if (keyVrfName == vrfName && keyAreaId == areaId) {
            log.Info("ospf_router_area_present: ospf router area present with key ", ospfTblKey)
            return true, nil
        }
    }

    log.Infof("ospf_router_area_present: ospf router area %s not present in vrf %s", areaId, vrfName)
    return false, nil
}

func ospf_router_area_network_present(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

    log.Infof("ospf_router_area_network_present: vrfName %s areaId %s.", vrfName, areaId)
    if (vrfName == "") {
        errStr := "Empty vrf name"
        log.Info("ospf_router_area_network_present: ", errStr)
        return false, errors.New(errStr)
    }

    ospfTblName := "OSPFV2_ROUTER_AREA_NETWORK"
    var ospfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfTblName}
    ospfTblData, err1 := configDbPtr.GetTable(ospfTblSpec)
    if err1 != nil {
        errStr := "OSPF area network table Not Found"
        log.Error("ospf_router_area_network_present: Area Table data not found ", errStr)
        return false, nil
    }

    ospfTblKeys, err2 := ospfTblData.GetKeys()
    if err2 != nil {
        errStr := "Area network table get keys failed"
        log.Error("ospf_router_area_network_present: get keys failed ", errStr)
        return false, err2
    }

    for _, ospfTblKey := range ospfTblKeys {
        keyVrfName := ospfTblKey.Get(0)
        keyAreaId := ospfTblKey.Get(1)

        if (keyVrfName == vrfName) {
           if (areaId == "" || areaId == "*") {
               log.Info("ospf_router_area_network_present: network config present with key ", ospfTblKey)
               return true, nil
           } else {
               if (keyAreaId == areaId) {
                   log.Info("ospf_router_area_network_present: network config present with key ", ospfTblKey)
                   return true, nil
               }    
           } 
        }
    }

    log.Info("ospf_router_area_network_present: area network config not present in vrf ", vrfName)
    return false, nil
}

func ospf_router_area_virtual_link_present(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

    log.Infof("ospf_router_area_virtual_link_present: vrfName %s areaId %s.", vrfName, areaId)
    if (vrfName == "") {
        errStr := "Empty vrf name"
        log.Info("ospf_router_area_virtual_link_present: ", errStr)
        return false, errors.New(errStr)
    }

    ospfTblName := "OSPFV2_ROUTER_AREA_VIRTUAL_LINK"
    var ospfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfTblName}
    ospfTblData, err1 := configDbPtr.GetTable(ospfTblSpec)
    if err1 != nil {
        errStr := "OSPF area network table Not Found"
        log.Error("ospf_router_area_virtual_link_present: VL Table data not found ", errStr)
        return false, nil
    }

    ospfTblKeys, err2 := ospfTblData.GetKeys()
    if err2 != nil {
        errStr := "Area network table get keys failed"
        log.Error("ospf_router_area_virtual_link_present: get keys failed ", errStr)
        return false, err2
    }

    for _, ospfTblKey := range ospfTblKeys {
        keyVrfName := ospfTblKey.Get(0)
        keyAreaId := ospfTblKey.Get(1)

        if (keyVrfName == vrfName) {
           if (areaId == "" || areaId == "*") {
               log.Info("ospf_router_area_virtual_link_present: VL config present with key ", ospfTblKey)
               return true, nil
           } else {
               if (keyAreaId == areaId) {
                   log.Info("ospf_router_area_virtual_link_present: VL config present with key ", ospfTblKey)
                   return true, nil
               }
           }
        }
    }

    log.Info("ospf_router_area_virtual_link_present: area network config not present in vrf ", vrfName)
    return false, nil
}

func ospf_router_area_address_range_present(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

    log.Infof("ospf_router_area_address_range_present: vrfName %s areaId %s.", vrfName, areaId)
    if (vrfName == "") {
        errStr := "Empty vrf name"
        log.Info("ospf_router_area_address_range_present: ", errStr)
        return false, errors.New(errStr)
    }

    ospfTblName := "OSPFV2_ROUTER_AREA_POLICY_ADDRESS_RANGE"
    var ospfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfTblName}
    ospfTblData, err1 := configDbPtr.GetTable(ospfTblSpec)
    if err1 != nil {
        errStr := "OSPF area network table Not Found"
        log.Error("ospf_router_area_address_range_present: AR Table data not found ", errStr)
        return false, nil
    }

    ospfTblKeys, err2 := ospfTblData.GetKeys()
    if err2 != nil {
        errStr := "Area network table get keys failed"
        log.Error("ospf_router_area_address_range_present: get keys failed ", errStr)
        return false, err2
    }

    for _, ospfTblKey := range ospfTblKeys {
        keyVrfName := ospfTblKey.Get(0)
        keyAreaId := ospfTblKey.Get(1)

        if (keyVrfName == vrfName) {
           if (areaId == "" || areaId == "*") {
               log.Info("ospf_router_area_address_range_present: AR config present with key ", ospfTblKey)
               return true, nil
           } else {
               if (keyAreaId == areaId) {
                   log.Info("ospf_router_area_address_range_present: AR config present with key ", ospfTblKey)
                   return true, nil
               }
           }
        }
    }

    log.Info("ospf_router_area_address_range_present: area network config not present in vrf ", vrfName)
    return false, nil
}

func create_ospf_area_entry(inParams *XfmrParams, vrfName string, areaId string, ospfRespMap *map[string]map[string]db.Value) (error) {
    log.Infof("create_ospf_area_entry: vrfName %s areaId %s", vrfName, areaId)
    if (vrfName == "") {
        errStr := "Empty vrf name"
        log.Info("create_ospf_area_entry: ", errStr)
        return errors.New(errStr)
    }

    if (areaId == "") {
        errStr := "Empty area id"
        log.Info("create_ospf_area_entry: ", errStr)
        return errors.New(errStr)
    }

    routerPresent, _ := ospf_router_present(inParams, vrfName)
    if !routerPresent {
        errStr := "OSPF router not present in vrf " + vrfName
        log.Info("create_ospf_area_entry: ", errStr)
        return errors.New(errStr)
    }

    areaPresent, _ := ospf_router_area_present(inParams, vrfName, areaId)
    if areaPresent {
        log.Infof("create_ospf_area_entry: area id entry already present")
        return nil
    } 

    ospfTblName := "OSPFV2_ROUTER_AREA"
    ospfTblKey := vrfName + "|" + areaId

    ospfOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB][ospfTblName] = make(map[string]db.Value)
    ospfOpMap[db.ConfigDB][ospfTblName][ospfTblKey] = db.Value{Field: make(map[string]string)}
    ospfOpMap[db.ConfigDB][ospfTblName][ospfTblKey].Field["NULL"] = "NULL"
    inParams.subOpDataMap[CREATE] = &ospfOpMap

    ospfTblDbValue := db.Value{Field: make(map[string]string)}
    ospfTblDbValue.Field["NULL"] = "NULL"

    ospfTblMap := make(map[string]db.Value)
    ospfTblMap[ospfTblKey] = ospfTblDbValue
    (*ospfRespMap)[ospfTblName] = ospfTblMap 

    return nil
}

func ospf_auto_create_ospf_router_area(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) (error) {
    log.Info("ospf_auto_create_ospf_router_area: ", inParams.uri)

    rcvdUri, _ := getOspfUriPath(inParams)
    autoCreate := false

    log.Info("ospf_auto_create_ospf_router_area: rcvdUri ", rcvdUri)

    if (strings.Contains(rcvdUri, "protocols/protocol/ospfv2")) {
        if (strings.Contains(rcvdUri, "openconfig-ospfv2-ext:networks/network")) {
            autoCreate = true
        } else if (strings.Contains(rcvdUri, "virtual-links/virtual-link")) {
            autoCreate = true
        } else if (strings.Contains(rcvdUri, "inter-area-policy/ranges/range")) {
            autoCreate = true
        }
    }

    if (!autoCreate) {
        log.Info("ospf_auto_create_ospf_router_area: uris dont match, no autocreate")
        return nil
    }

    pathInfo := NewPathInfo(inParams.uri)
    ospfVrfName :=  pathInfo.Var("name")
    ospfAreaId := pathInfo.Var("identifier#2")

    log.Infof("ospf_auto_create_ospf_router_area: ospfVrfName %s ospfAreaId %s", ospfVrfName, ospfAreaId)
    if (ospfVrfName == "" || ospfAreaId == "") {
        log.Info("ospf_auto_create_ospf_router_area: invalid vrf name or area Id")
        return nil
    }

    log.Infof("ospf_auto_create_ospf_router_area: Auto create area %s in vrf %s", ospfAreaId, ospfVrfName)
    return create_ospf_area_entry(inParams, ospfVrfName, ospfAreaId, ospfRespMap)
}

func validate_ospf_router_area_delete(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) (error) {

    if (inParams.oper != DELETE) {
        log.Info("validate_ospf_router_area_delete: non delete operation")
        return nil
    }

    pathInfo := NewPathInfo(inParams.uri)
    rcvdUri, uriErr := getOspfUriPath(inParams)
    if (uriErr != nil) {
        log.Info("validate_ospf_router_area_delete: getOspfUriPath error ", uriErr)
        return nil
    }

    areaDelete := false
    if (strings.HasSuffix(rcvdUri, "areas") ||
        strings.HasSuffix(rcvdUri, "areas/area") ||
        strings.HasSuffix(rcvdUri, "areas/area/config")) {
        areaDelete = true
    }

    if (!areaDelete) {
        log.Info("validate_ospf_router_area_delete: rcvdUri not area delete ")
        return nil
    }

    ospfVrfName, _, _, uerr := get_ospf_router_info_from_uri(inParams)
    if uerr != nil {
        log.Info("validate_ospf_router_area_delete: get ospf router info failed ", uerr)
        return nil
    }

    ospfAreaId := pathInfo.Var("identifier#2")
    if len(ospfAreaId) == 0 {
        log.Info("OSPF area Id is Missing")
        return nil
    }
    ospfAreaId = getAreaDotted(ospfAreaId)

    errStr := "Delete interface area, network, address-range and virtual links in the area first"

    ifAreaPresent, _ := ospf_area_id_present_in_interfaces(inParams, ospfVrfName, ospfAreaId)  
    if (ifAreaPresent) {
        log.Info("validate_ospf_router_area_delete: Area config present under interface")
        return tlerr.New(errStr)
    }

    nwAreaPresent, _ := ospf_router_area_network_present(inParams, ospfVrfName, ospfAreaId)  
    if (nwAreaPresent) {
        log.Info("validate_ospf_router_area_delete: Area config present under network config")
        return tlerr.New(errStr)
    }

    vlAreaPresent, _ := ospf_router_area_virtual_link_present(inParams, ospfVrfName, ospfAreaId)  
    if (vlAreaPresent) {
        log.Info("validate_ospf_router_area_delete: Area config present under virtual link config")
        return tlerr.New(errStr)
    }

    arAreaPresent, _ := ospf_router_area_address_range_present(inParams, ospfVrfName, ospfAreaId)  
    if (arAreaPresent) {
        log.Info("validate_ospf_router_area_delete: Area config present under address range config")
        return tlerr.New(errStr)
    }

    log.Info("validate_ospf_router_area_delete: dependent are configs not present ")
    return nil
}

func delete_ospf_router_redistribute_entry(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) (error) {
    if (inParams.oper != DELETE) {
        log.Info("delete_ospf_router_redistribute_entry: non delete operation")
        return nil
    }

    log.Info("delete_ospf_router_redistribute_entry: inParams.uri ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    rcvdUri, uriErr := getOspfUriPath(inParams)
    if (uriErr != nil) {
        log.Info("delete_ospf_router_redistribute_entry: getOspfUriPath error ", uriErr)
        return nil
    }

    log.Info("delete_ospf_router_redistribute_entry: rcvdUri ", rcvdUri)
    if (!strings.Contains(rcvdUri, "protocols/protocol/ospfv2/global")) {
        log.Info("delete_ospf_router_redistribute_entry: rcvdUri not ospfv2/global")
        return nil
    }

    if (!strings.Contains(rcvdUri, "route-distribution-policies")) {
        log.Info("delete_ospf_router_redistribute_entry: rcvdUri not distribute-list")
        return nil
    }

    ospfVrfName, _, _, uerr := get_ospf_router_info_from_uri(inParams)
    if uerr != nil {
         log.Info("delete_ospf_router_redistribute_entry: ", uerr)
         return nil
    }

    redistProtocol  := pathInfo.Var("protocol")
    redistDirection := pathInfo.Var("direction")

    if len(redistProtocol) == 0 {
        log.Info("delete_ospf_router_redistribute_entry: protocol name Missing")
        return nil
    }

    if len(redistDirection) == 0 {
        log.Info("delete_ospf_router_redistribute_entry: direction is Missing")
        return nil
    }

    if (redistDirection != "IMPORT") {
        log.Info("delete_ospf_router_redistribute_entry: not import direction")
        return nil
    }

    fieldNameList := []string { "BGP", "STATIC", "KERNEL", "DIRECTLY_CONNECTED" }
    validProtocol := false
    for _, fieldName := range fieldNameList { 
        if (redistProtocol == fieldName) {
            validProtocol = true
            break
        }
    }
  
    if (!validProtocol) {
        log.Info("delete_ospf_router_redistribute_entry: not valid protocol")
        return nil
    }

    redistTableKey := ospfVrfName + "|" + redistProtocol + "|" + redistDirection

    ospfTblName := "OSPFV2_ROUTER_DISTRIBUTE_ROUTE"
    var ospfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfTblName}
    ospfTblData, err := configDbPtr.GetTable(ospfTblSpec)
    if err != nil {
        errStr := "Distribute table get failed"
        log.Error("delete_ospf_router_redistribute_entry: OSPF Interface Table data not found ", errStr)
        return nil
    }

    ospfTblKeys, err := ospfTblData.GetKeys()
    if err != nil {
        errStr := "Distribute table get keys failed"
        log.Error("delete_ospf_router_redistribute_entry: get keys failed ", errStr)
        return nil
    }

    ospfOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    ospfOpMap[db.ConfigDB][ospfTblName] = make(map[string]db.Value)
    ospfTblMap := make(map[string]db.Value)

    entryDeleted := false
    for _, ospfTblKey := range ospfTblKeys {
        keyVrfName := ospfTblKey.Get(0)
        keyProtocol := ospfTblKey.Get(1)
        keyDirection := ospfTblKey.Get(2)

        if (keyVrfName != ospfVrfName || 
            keyProtocol != redistProtocol || 
            keyDirection != redistDirection ) {
            continue
        }

        log.Error("delete_ospf_router_redistribute_entry: delete entry ", redistTableKey)

        ospfDbValue := db.Value{Field: make(map[string]string)}
        ospfOpMap[db.ConfigDB][ospfTblName][redistTableKey] = db.Value{Field: make(map[string]string)}
        ospfTblMap[redistTableKey] = ospfDbValue
        entryDeleted = true
    }

    if entryDeleted {
        inParams.subOpDataMap[inParams.oper] = &ospfOpMap
        (*ospfRespMap)[ospfTblName] = ospfTblMap

        log.Info("delete_ospf_router_redistribute_entry: ospfRespMap ", ospfRespMap)
        return nil
    }

    log.Info("delete_ospf_router_redistribute_entry: no entries to delete for ", redistTableKey)
    return nil
}



