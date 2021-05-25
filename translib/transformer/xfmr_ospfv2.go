package transformer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {

	XlateFuncBind("ospfv2_validate_proto", validate_ospfv2_protocol)
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
	XlateFuncBind("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr", YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr)
	XlateFuncBind("DbToYang_ospfv2_router_area_vl_authentication_key_fld_xfmr", DbToYang_ospfv2_router_area_vl_authentication_key_fld_xfmr)

	XlateFuncBind("YangToDb_ospfv2_router_area_vlmd_auth_tbl_key_xfmr", YangToDb_ospfv2_router_area_vlmd_auth_tbl_key_xfmr)
	XlateFuncBind("DbToYang_ospfv2_router_area_vlmd_auth_tbl_key_xfmr", DbToYang_ospfv2_router_area_vlmd_auth_tbl_key_xfmr)
	XlateFuncBind("YangToDb_ospfv2_router_area_vlmd_auth_key_id_fld_xfmr", YangToDb_ospfv2_router_area_vlmd_auth_key_id_fld_xfmr)
	XlateFuncBind("DbToYang_ospfv2_router_area_vlmd_auth_key_id_fld_xfmr", DbToYang_ospfv2_router_area_vlmd_auth_key_id_fld_xfmr)
	XlateFuncBind("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr", YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr)
	XlateFuncBind("DbToYang_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr", DbToYang_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr)

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
	XlateFuncBind("YangToDb_ospfv2_router_passive_interface_subinterface_fld_xfmr", YangToDb_ospfv2_router_passive_interface_subinterface_fld_xfmr)
	XlateFuncBind("DbToYang_ospfv2_router_passive_interface_subinterface_fld_xfmr", DbToYang_ospfv2_router_passive_interface_subinterface_fld_xfmr)

	XlateFuncBind("YangToDb_ospfv2_interface_tbl_key_xfmr", YangToDb_ospfv2_interface_tbl_key_xfmr)
	XlateFuncBind("DbToYang_ospfv2_interface_tbl_key_xfmr", DbToYang_ospfv2_interface_tbl_key_xfmr)
	XlateFuncBind("YangToDb_ospfv2_interface_name_fld_xfmr", YangToDb_ospfv2_interface_name_fld_xfmr)
	XlateFuncBind("DbToYang_ospfv2_interface_name_fld_xfmr", DbToYang_ospfv2_interface_name_fld_xfmr)

}

func validate_ospfv2_protocol(inParams XfmrParams) bool {
	pathInfo := NewPathInfo(inParams.uri)
	proto := pathInfo.Var("name#2")
	protoId := pathInfo.Var("identifier")
	return protoId == "OSPF" && proto == "ospfv2"
}

func getOspfUriPath(inParams *XfmrParams) (string, error) {

	yangPath, err := getYangPathFromUri(inParams.uri)
	if err != nil {
		log.Info("getOspfUriPath: getYangPathFromUri failed ", err)
		return "", err
	}

	log.Infof("getOspfUriPath: yangPath %s", yangPath)

	uriPath := ""
	uriBlockList := strings.Split(yangPath, "/")
	for _, uriBlock := range uriBlockList {
		if uriBlock == "" {
			continue
		}

		uriSubBlockList := strings.Split(uriBlock, ":")
		listLen := len(uriSubBlockList)
		if listLen != 0 {
			uriPath = uriPath + "/" + uriSubBlockList[listLen-1]
		}
	}

	log.Infof("getOspfUriPath: uriPath %s", uriPath)
	return uriPath, nil
}

func ospfGetInparamOperation(inParams *XfmrParams) (bool, bool, bool, error) {
	log.Infof("ospfGetInparamOperation: inparam operation %d", inParams.oper)
	if inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE {
		return true, false, false, nil
	} else if inParams.oper == DELETE {
		return false, true, false, nil
	} else if inParams.oper == GET {
		return false, false, true, nil
	}
	errStr := "Invalid Inparam operation"
	log.Infof("ospfGetInparamOperation: %s %d ", errStr, inParams.oper)
	return false, false, false, tlerr.New(errStr)
}

func getOspfv2Root(inParams XfmrParams) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2, string, error) {
	pathInfo := NewPathInfo(inParams.uri)
	ospfv2VrfName := pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	var err error

	if len(pathInfo.Vars) < 3 {
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
		ygot.BuildEmptyTree(protoInstObj.Ospfv2)
	}

	return protoInstObj.Ospfv2, ospfv2VrfName, err
}

func ospfGetNetworkInstance(inParams *XfmrParams, vrfName string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance, string, bool, error) {
	log.Infof("ospfGetNetworkInstance: get vrf %s.", vrfName)
	ending := false
	objKey := ""

	deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
	if deviceObj == nil {
		errStr := "Device object not set"
		log.Info("ospfGetNetworkInstance: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	nwInstsObj := deviceObj.NetworkInstances
	if nwInstsObj == nil {
		errStr := "Device Network-instances object not set"
		log.Info("ospfGetNetworkInstance: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	if nwInstsObj.NetworkInstance == nil {
		errStr := "Network-instances container missing"
		log.Info("ospfGetNetworkInstance: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	var nwInstObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance
	if vrfName != "" {
		nwInstObj = nwInstsObj.NetworkInstance[vrfName]
	} else {
		for _, nwInstObjElt := range nwInstsObj.NetworkInstance {
			if nwInstObjElt != nil {
				nwInstObj = nwInstObjElt
				break
			}
		}
	}

	if nwInstObj == nil {
		errStr := "Network-instance container missing for vrf " + vrfName
		log.Info("ospfGetNetworkInstance: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	instVrfName := ""
	if nwInstObj.Name != nil {
		instVrfName = *nwInstObj.Name
		if vrfName != "" && instVrfName != vrfName {
			errStr := "vrfName " + vrfName + " doesnt match instVrfName " + instVrfName
			log.Info("ospfGetNetworkInstance: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}
		objKey = instVrfName
	}

	log.Infof("ospfGetNetworkInstance: found vrf entry %s ending %t", objKey, ending)
	return nwInstObj, objKey, ending, nil
}

func ospfGetRouterObject(inParams *XfmrParams, vrfName string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2, string, bool, error) {
	log.Infof("ospfGetRouterObject: get vrf %s.", vrfName)
	ending := false

	nwInstObj, objKey, ending, err := ospfGetNetworkInstance(inParams, vrfName)
	if nwInstObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Network instance Protocols object ends"
		log.Info("ospfGetRouterObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	if nwInstObj.Protocols == nil || len(nwInstObj.Protocols.Protocol) == 0 {
		errStr := "Network instance Protocols object missing "
		log.Info("ospfGetRouterObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	var protoKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Key
	protoKey.Identifier = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF
	protoKey.Name = "ospfv2"
	protoObj := nwInstObj.Protocols.Protocol[protoKey]
	if protoObj == nil {
		errStr := "Network instance Protocol identifier OSPF:ospfv2 not present"
		log.Info("ospfGetRouterObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ospfv2Obj := protoObj.Ospfv2
	if ospfv2Obj == nil {
		errStr := "Ospfv2 object not present in protocols"
		log.Info("ospfGetRouterObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if ospfv2Obj.Global == nil &&
		ospfv2Obj.Areas == nil &&
		ospfv2Obj.RouteTables == nil {
		ending = true
	}

	log.Infof("ospfGetRouterObject: found router entry %s ending %t", objKey, ending)
	return ospfv2Obj, objKey, ending, nil
}

func ospfGetRouterGlobalObject(inParams *XfmrParams, vrfName string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global, string, bool, error) {
	log.Infof("ospfGetRouterGlobalObject: get vrf %s.", vrfName)
	ending := false

	ospfv2Obj, objKey, ending, err := ospfGetRouterObject(inParams, vrfName)
	if ospfv2Obj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router object ends"
		log.Info("ospfGetRouterGlobalObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	globalObj := ospfv2Obj.Global
	if globalObj == nil {
		errStr := "Ospfv2 global object not present"
		log.Info("ospfGetRouterGlobalObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if globalObj.Config == nil &&
		globalObj.Distance == nil &&
		globalObj.InterAreaPropagationPolicies == nil &&
		globalObj.PassiveInterfaces == nil &&
		globalObj.RouteDistributionPolicies == nil &&
		globalObj.Timers == nil {
		ending = true
	}

	log.Infof("ospfGetRouterGlobalObject: found vrf %s ending %t", objKey, ending)
	return globalObj, objKey, ending, nil
}

func ospfGetRouterGlobalIaPolicyObject(inParams *XfmrParams, vrfName string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies, string, bool, error) {
	log.Infof("ospfGetRouterGlobalIaPolicyObject: get vrf %s.", vrfName)
	ending := false

	globalObj, objKey, ending, err := ospfGetRouterGlobalObject(inParams, vrfName)
	if globalObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router global object ends"
		log.Info("ospfGetRouterGlobalIaPolicyObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	iaPolObj := globalObj.InterAreaPropagationPolicies
	if iaPolObj == nil {
		errStr := "Ospfv2 global IA policy object not present"
		log.Info("ospfGetRouterGlobalIaPolicyObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if len(iaPolObj.InterAreaPolicy) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterGlobalIaPolicyObject: found vrf %s ending %t", objKey, ending)
	return iaPolObj, objKey, ending, nil
}

func ospfGetRouterIaPolicyList(inParams *XfmrParams, vrfName string) (*map[ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Config_SrcArea_Union]*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy, string, bool, error) {
	log.Infof("ospfGetRouterIaPolicyList: get vrf %s area list", vrfName)
	ending := false

	iaPolObj, objKey, ending, err := ospfGetRouterGlobalIaPolicyObject(inParams, vrfName)
	if iaPolObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router IA policy object ends"
		log.Info("ospfGetRouterIaPolicyList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	iapolListObj := &iaPolObj.InterAreaPolicy
	if iapolListObj == nil {
		errStr := "Ospfv2 areas list not present"
		log.Info("ospfGetRouterIaPolicyList: ", errStr)
		return nil, objKey, true, errors.New(errStr)
	}

	if len(iaPolObj.InterAreaPolicy) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterIaPolicyList: found entry %s ending %t", objKey, ending)
	return iapolListObj, objKey, ending, nil
}

func ospfGetAreaStringFromSrcAreaId(areaIdObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Config_SrcArea_Union) (string, error) {

	areaIdStr := ""
	if areaIdObj == nil {
		return "", errors.New("Nil Area Identifier union")
	}

	areaIdUnionType := reflect.TypeOf(*areaIdObj).Elem()
	switch areaIdUnionType {
	case reflect.TypeOf(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Config_SrcArea_Union_String{}):
		areaId := (*areaIdObj).(*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Config_SrcArea_Union_String)
		areaIdStr = areaId.String
	case reflect.TypeOf(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Config_SrcArea_Union_Uint32{}):
		areaId := (*areaIdObj).(*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Config_SrcArea_Union_Uint32)
		areaIdStr = ospfGetDottedAreaFromUint32(areaId.Uint32)
	}

	if areaIdStr == "" {
		log.Info("ospfGetAreaStringFromSrcAreaId: area id type ", areaIdUnionType)
		return "", errors.New("Area Id conversion failed")
	}

	log.Infof("ospfGetAreaStringFromSrcAreaId: %s success", areaIdStr)
	return areaIdStr, nil
}

func ospfGetRouterIaPolicySrcAreaObject(inParams *XfmrParams, vrfName string, areaId string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy, string, bool, error) {
	log.Infof("ospfGetRouterIaPolicySrcAreaObject: get vrf %s area %s.", vrfName, areaId)
	ending := false

	iapolListObj, objKey, ending, err := ospfGetRouterIaPolicyList(inParams, vrfName)
	if iapolListObj == nil {
		return nil, objKey, false, err
	}

	if ending {
		errStr := "Ospfv2 IA areas object ends"
		log.Info("ospfGetRouterIaPolicySrcAreaObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	var srcAreaObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy
	for srcAreaKey, srcAreaObjElt := range *iapolListObj {
		keyArea, _ := ospfGetAreaStringFromSrcAreaId(&srcAreaKey)
		if keyArea == "" {
			keyArea, _ = ospfGetAreaStringFromSrcAreaId(&srcAreaObjElt.SrcArea)
			if keyArea == "" {
				log.Info("ospfGetRouterAreaObject: get area string failed")
				continue
			}
		}

		if areaId != "" {
			if keyArea == areaId {
				srcAreaObj = srcAreaObjElt
				objKey += "|" + keyArea
				break
			}
		} else if srcAreaObjElt != nil {
			srcAreaObj = srcAreaObjElt
			objKey += "|" + keyArea
			break
		}
	}

	if srcAreaObj == nil {
		if areaId != "" {
			errStr := "Requested ia policy src area not present"
			log.Info("ospfGetRouterIaPolicySrcAreaObject: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}

		ending = true
		errStr := "Ia policy source Area not present in src area list"
		log.Info("ospfGetRouterIaPolicySrcAreaObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if srcAreaObj.Config == nil &&
		srcAreaObj.FilterListIn == nil &&
		srcAreaObj.FilterListOut == nil &&
		srcAreaObj.Ranges == nil {
		ending = true
	}

	log.Infof("ospfGetRouterIaPolicySrcAreaObject: found entry %s ending %t", objKey, ending)
	return srcAreaObj, objKey, ending, nil
}

func ospfGetRouterPolicyRangeList(inParams *XfmrParams, vrfName string, areaId string) (*map[string]*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Ranges_Range, string, bool, error) {
	log.Infof("ospfGetRouterPolicyRangeList: get vrf %s area %s nw list", vrfName, areaId)
	ending := false

	srcAreaObj, objKey, ending, err := ospfGetRouterIaPolicySrcAreaObject(inParams, vrfName, areaId)
	if srcAreaObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router Src area object ends"
		log.Info("ospfGetRouterPolicyRangeList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	if srcAreaObj.Ranges == nil {
		errStr := "Ospfv2 router Src area ranges object ends"
		log.Info("ospfGetRouterPolicyRangeList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	rangesListObj := &srcAreaObj.Ranges.Range
	if rangesListObj == nil {
		errStr := "Ospfv2 areas network list not present"
		log.Info("ospfGetRouterPolicyRangeList: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	if len(srcAreaObj.Ranges.Range) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterPolicyRangeList: found entry %s ending %t", objKey, ending)
	return rangesListObj, objKey, ending, nil
}

func ospfGetRouterPolicyRangeObject(inParams *XfmrParams, vrfName string, areaId string, rangePrefix string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Ranges_Range, string, bool, error) {
	log.Infof("ospfGetRouterPolicyRangeObject: get vrf %s area %s range %s object.", vrfName, areaId, rangePrefix)
	ending := false

	rangesListObj, objKey, ending, err := ospfGetRouterPolicyRangeList(inParams, vrfName, areaId)
	if rangesListObj == nil {
		return nil, objKey, false, err
	}

	if ending {
		errStr := "Ospfv2 area Network list object ends"
		log.Info("ospfGetRouterPolicyRangeObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	var rangeObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_InterAreaPropagationPolicies_InterAreaPolicy_Ranges_Range
	for rangeKey, rangeObjElt := range *rangesListObj {
		if rangePrefix != "" {
			if rangeKey == rangePrefix {
				rangeObj = rangeObjElt
				objKey += "|" + rangeKey
				break
			}
		} else if rangeObjElt != nil {
			rangeObj = rangeObjElt
			objKey += "|" + rangeKey
			break
		}
	}

	if rangeObj == nil {
		if rangePrefix != "" {
			errStr := "Requested area network not present"
			log.Info("ospfGetRouterPolicyRangeObject: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}

		ending = true
		errStr := "Area network not present in network list"
		log.Info("ospfGetRouterPolicyRangeObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if rangeObj.Config == nil {
		ending = true
	}

	log.Infof("ospfGetRouterPolicyRangeObject: found entry %s ending %t", objKey, ending)
	return rangeObj, objKey, ending, nil
}

func ospfGetRouterPassiveIntfList(inParams *XfmrParams, vrfName string) (*map[ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_PassiveInterfaces_PassiveInterface_Key]*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_PassiveInterfaces_PassiveInterface, string, bool, error) {
	log.Infof("ospfGetRouterPassiveIntfList: get vrf %s list", vrfName)
	ending := false

	globalObj, objKey, ending, err := ospfGetRouterGlobalObject(inParams, vrfName)
	if globalObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router global object ends"
		log.Info("ospfGetRouterPassiveIntfList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	if globalObj.PassiveInterfaces == nil {
		errStr := "Ospfv2 router passive interfaces object ends"
		log.Info("ospfGetRouterPassiveIntfList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	passIntfListObj := &globalObj.PassiveInterfaces.PassiveInterface
	if passIntfListObj == nil {
		errStr := "Ospfv2 passive list not present"
		log.Info("ospfGetRouterPassiveIntfList: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	if len(globalObj.PassiveInterfaces.PassiveInterface) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterPassiveIntfList: found entry %s ending %t", objKey, ending)
	return passIntfListObj, objKey, ending, nil
}

func ospfGetRouterPassiveIntfObject(inParams *XfmrParams, vrfName string, ifName string, ifAddr string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_PassiveInterfaces_PassiveInterface, string, bool, error) {
	log.Infof("ospfGetRouterPassiveIntfObject: get vrf %s ifName %s ifAddr %s object.", vrfName, ifName, ifAddr)
	ending := false

	passIntfListObj, objKey, ending, err := ospfGetRouterPassiveIntfList(inParams, vrfName)
	if passIntfListObj == nil {
		return nil, objKey, false, err
	}

	if ending {
		errStr := "Ospfv2 area pass interfacelist object ends"
		log.Info("ospfGetRouterPassiveIntfObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	var passIntfObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Global_PassiveInterfaces_PassiveInterface
	for passIfKey, passIntfObjElt := range *passIntfListObj {
		passiveIfName := passIfKey.Name
		if passIfKey.Subinterface != 0 {
			passiveIfName = passIfKey.Name + "." + fmt.Sprintf("%d", passIfKey.Subinterface)
		}

		passiveIfName, _, _, _, _ = getNativeInterfaceName(passiveIfName)
		if ifName != "" {
			if passiveIfName == ifName && passIfKey.Address == ifAddr {
				passIntfObj = passIntfObjElt
				objKey += "|" + passiveIfName + "|" + passIfKey.Address
				break
			}
		} else if passIntfObjElt != nil {
			passIntfObj = passIntfObjElt
			objKey += "|" + passiveIfName + "|" + passIfKey.Address
			break
		}
	}

	if passIntfObj == nil {
		if ifName != "" {
			errStr := "Requested passive interface not present"
			log.Info("ospfGetRouterPassiveIntfObject: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}

		ending = true
		errStr := "Interface not present in passive interface list"
		log.Info("ospfGetRouterPassiveIntfObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if passIntfObj.Config == nil {
		ending = true
	}

	log.Infof("ospfGetRouterPassiveIntfObject: found entry %s ending %t", objKey, ending)
	return passIntfObj, objKey, ending, nil
}

func ospfGetAreaStringFromAreaId(areaIdObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Config_Identifier_Union) (string, error) {

	areaIdStr := ""
	if areaIdObj == nil {
		return "", errors.New("Nil Area Identifier union")
	}

	areaIdUnionType := reflect.TypeOf(*areaIdObj).Elem()
	switch areaIdUnionType {
	case reflect.TypeOf(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Config_Identifier_Union_String{}):
		areaId := (*areaIdObj).(*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Config_Identifier_Union_String)
		areaIdStr = areaId.String
	case reflect.TypeOf(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Config_Identifier_Union_Uint32{}):
		areaId := (*areaIdObj).(*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Config_Identifier_Union_Uint32)
		areaIdStr = ospfGetDottedAreaFromUint32(areaId.Uint32)
	}

	if areaIdStr == "" {
		log.Info("ospfGetAreaStringFromAreaId: area id type ", areaIdUnionType)
		return "", errors.New("Area Id conversion failed")
	}

	log.Infof("ospfGetAreaStringFromAreaId: %s success", areaIdStr)
	return areaIdStr, nil
}

func ospfGetRouterAreaList(inParams *XfmrParams, vrfName string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas, string, bool, error) {
	log.Infof("ospfGetRouterAreaList: get vrf %s area list", vrfName)
	ending := false

	ospfv2Obj, objKey, ending, err := ospfGetRouterObject(inParams, vrfName)
	if ospfv2Obj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router object ends"
		log.Info("ospfGetRouterAreaList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	areaListObj := ospfv2Obj.Areas
	if areaListObj == nil {
		errStr := "Ospfv2 areas list not present"
		log.Info("ospfGetRouterAreaList: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	if len(areaListObj.Area) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterAreaList: found vrf %s ending %t", vrfName, ending)
	return areaListObj, objKey, ending, nil
}

func ospfGetRouterAreaObject(inParams *XfmrParams, vrfName string, areaId string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area, string, bool, error) {
	log.Infof("ospfGetRouterAreaObject: get vrf %s area %s.", vrfName, areaId)
	ending := false

	areasObj, objKey, ending, err := ospfGetRouterAreaList(inParams, vrfName)
	if areasObj == nil {
		return nil, objKey, false, err
	}

	if ending {
		errStr := "Ospfv2 areas object ends"
		log.Info("ospfGetRouterAreaObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	var areaObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area
	for areaKey, areaObjElt := range areasObj.Area {
		keyArea, _ := ospfGetAreaStringFromAreaId(&areaKey)
		if keyArea == "" {
			keyArea, _ = ospfGetAreaStringFromAreaId(&areaObjElt.Identifier)
			if keyArea == "" {
				log.Info("ospfGetRouterAreaObject: get area string failed")
				continue
			}
		}

		if areaId != "" {
			if keyArea == areaId {
				areaObj = areaObjElt
				objKey += "|" + keyArea
				break
			}
		} else if areaObjElt != nil {
			areaObj = areaObjElt
			objKey += "|" + keyArea
			break
		}
	}

	if areaObj == nil {
		if areaId != "" {
			errStr := "Requested area not present"
			log.Info("ospfGetRouterAreaObject: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}

		ending = true
		errStr := "Area not present in area list"
		log.Info("ospfGetRouterAreaObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if areaObj.Config == nil &&
		areaObj.Networks == nil &&
		areaObj.Stub == nil &&
		areaObj.VirtualLinks == nil {
		ending = true
	}

	log.Infof("ospfGetRouterAreaObject: found entry %s ending %t", objKey, ending)
	return areaObj, objKey, ending, nil
}

func ospfGetRouterAreaNetwokList(inParams *XfmrParams, vrfName string, areaId string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Networks, string, bool, error) {
	log.Infof("ospfGetRouterAreaNetwokList: get vrf %s area %s nw list", vrfName, areaId)
	ending := false

	areaObj, objKey, ending, err := ospfGetRouterAreaObject(inParams, vrfName, areaId)
	if areaObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router area object ends"
		log.Info("ospfGetRouterAreaNetwokList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	nwListObj := areaObj.Networks
	if nwListObj == nil {
		errStr := "Ospfv2 areas network list not present"
		log.Info("ospfGetRouterAreaNetwokList: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	if len(nwListObj.Network) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterAreaNetwokList: found vrf %s area %s ending %t", vrfName, areaId, ending)
	return nwListObj, objKey, ending, nil
}

func ospfGetRouterAreaNetworkObject(inParams *XfmrParams, vrfName string, areaId string, nwPrefix string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Networks_Network, string, bool, error) {
	log.Infof("ospfGetRouterAreaNetworkObject: get vrf %s area %s nw %s object.", vrfName, areaId, nwPrefix)
	ending := false

	nwsObj, objKey, ending, err := ospfGetRouterAreaNetwokList(inParams, vrfName, areaId)
	if nwsObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 area Network list object ends"
		log.Info("ospfGetRouterAreaNetworkObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	var nwObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_Networks_Network
	for nwKey, nwObjElt := range nwsObj.Network {
		if nwPrefix != "" {
			if nwKey == nwPrefix {
				nwObj = nwObjElt
				objKey += "|" + nwKey
				break
			}
		} else if nwObjElt != nil {
			nwObj = nwObjElt
			objKey += "|" + nwKey
			break
		}
	}

	if nwObj == nil {
		if nwPrefix != "" {
			errStr := "Requested area network not present"
			log.Info("ospfGetRouterAreaNetworkObject: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}

		ending = true
		errStr := "Area network not present in network list"
		log.Info("ospfGetRouterAreaNetworkObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if nwObj.Config == nil {
		ending = true
	}

	log.Infof("ospfGetRouterAreaNetworkObject: found entry %s ending %t", objKey, ending)
	return nwObj, objKey, ending, nil
}

func ospfGetRouterAreaVlinkList(inParams *XfmrParams, vrfName string, areaId string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_VirtualLinks, string, bool, error) {
	log.Infof("ospfGetRouterAreaNetwokList: get vrf %s area %s nw list", vrfName, areaId)
	ending := false

	areaObj, objKey, ending, err := ospfGetRouterAreaObject(inParams, vrfName, areaId)
	if areaObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router area object ends"
		log.Info("ospfGetRouterAreaVlinkList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	vlinkListObj := areaObj.VirtualLinks
	if vlinkListObj == nil {
		errStr := "Ospfv2 areas vl list not present"
		log.Info("ospfGetRouterAreaVlinkList: ", errStr)
		return nil, objKey, false, errors.New(errStr)
	}

	if len(vlinkListObj.VirtualLink) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterAreaVlinkList: found entry %s ending %t", objKey, ending)
	return vlinkListObj, objKey, ending, nil
}

func ospfGetRouterAreaVlinkObject(inParams *XfmrParams, vrfName string, areaId string, rmtId string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_VirtualLinks_VirtualLink, string, bool, error) {
	log.Infof("ospfGetRouterAreaVlinkObject: get vrf %s area %s rmtId %s object.", vrfName, areaId, rmtId)
	ending := false

	vlinkListObj, objKey, ending, err := ospfGetRouterAreaVlinkList(inParams, vrfName, areaId)
	if vlinkListObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 area vl list object ends"
		log.Info("ospfGetRouterAreaVlinkObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	var vlinkObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_VirtualLinks_VirtualLink
	for vlinkKey, vlinkObjElt := range vlinkListObj.VirtualLink {
		if rmtId != "" {
			if vlinkKey == rmtId {
				vlinkObj = vlinkObjElt
				objKey += "|" + vlinkKey
				break
			}
		} else if vlinkObjElt != nil {
			vlinkObj = vlinkObjElt
			objKey += "|" + vlinkKey
			break
		}
	}

	if vlinkObj == nil {
		if rmtId != "" {
			errStr := "Requested area vl not present"
			log.Info("ospfGetRouterAreaVlinkObject: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}

		ending = true
		errStr := "Area vl not present in vl list"
		log.Info("ospfGetRouterAreaVlinkObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if vlinkObj.Config == nil &&
		vlinkObj.MdAuthentications == nil {
		ending = true
	}

	log.Infof("ospfGetRouterAreaVlinkObject: found entry %s ending %t", objKey, ending)
	return vlinkObj, objKey, ending, nil
}

func ospfGetRouterAreaVlinkMdAuthList(inParams *XfmrParams, vrfName string, areaId string, rmtId string) (*map[uint8]*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_VirtualLinks_VirtualLink_MdAuthentications_MdAuthentication, string, bool, error) {
	log.Infof("ospfGetRouterAreaVlinkMdAuthList: get vrf %s area %s vl rmtid %s", vrfName, areaId, rmtId)
	ending := false

	vlObj, objKey, ending, err := ospfGetRouterAreaVlinkObject(inParams, vrfName, areaId, rmtId)
	if vlObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 router area vl object ends"
		log.Info("ospfGetRouterAreaVlinkMdAuthList: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	if vlObj.MdAuthentications == nil {
		errStr := "Ospfv2 areas vl MdAuthentications obj not present"
		log.Info("ospfGetRouterAreaVlinkMdAuthList: ", errStr)
		return nil, objKey, true, errors.New(errStr)
	}

	vlMdAuthListObj := &(vlObj.MdAuthentications.MdAuthentication)
	if len(vlObj.MdAuthentications.MdAuthentication) == 0 {
		ending = true
	}

	log.Infof("ospfGetRouterAreaVlinkMdAuthList: found entry %s ending %t", objKey, ending)
	return vlMdAuthListObj, objKey, ending, nil
}

func ospfGetRouterAreaVlinkMdAuthObject(inParams *XfmrParams, vrfName string, areaId string, rmtId string, mdKeyId uint8) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_VirtualLinks_VirtualLink_MdAuthentications_MdAuthentication, string, bool, error) {
	log.Infof("ospfGetRouterAreaVlinkObject: get vrf %s area %s rmtId %s keyid %d.", vrfName, areaId, rmtId, mdKeyId)
	ending := false

	vlMdAuthListObj, objKey, ending, err := ospfGetRouterAreaVlinkMdAuthList(inParams, vrfName, areaId, rmtId)
	if vlMdAuthListObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		errStr := "Ospfv2 area vl md list object ends"
		log.Info("ospfGetRouterAreaVlinkMdAuthObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	var vlMdObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Ospfv2_Areas_Area_VirtualLinks_VirtualLink_MdAuthentications_MdAuthentication
	for vlMdKey, vlMdObjElt := range *vlMdAuthListObj {
		if mdKeyId != 0 {
			if vlMdKey == mdKeyId {
				vlMdObj = vlMdObjElt
				objKey += "|" + fmt.Sprintf("%d", vlMdKey)
				break
			}
		} else if vlMdObjElt != nil {
			vlMdObj = vlMdObjElt
			objKey += "|" + fmt.Sprintf("%d", vlMdKey)
			break
		}
	}

	if vlMdObj == nil {
		if mdKeyId != 0 {
			errStr := "Requested vl md key entry not present"
			log.Info("ospfGetRouterAreaVlinkMdAuthObject: ", errStr)
			return nil, objKey, false, errors.New(errStr)
		}

		ending = true
		errStr := "Area vl md auth not present in auth list"
		log.Info("ospfGetRouterAreaVlinkMdAuthObject: ", errStr)
		return nil, objKey, ending, errors.New(errStr)
	}

	ending = false
	if vlMdObj.Config == nil {
		ending = true
	}

	log.Infof("ospfGetRouterAreaVlinkMdAuthObject: found entry %s ending %t", objKey, ending)
	return vlMdObj, objKey, ending, nil
}

var YangToDb_ospfv2_router_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error

	log.Info("YangToDb_ospfv2_router_tbl_key_xfmr: inParams.uri ", inParams.uri)

	pathInfo := NewPathInfo(inParams.uri)

	ospfv2VrfName := pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")

	if len(pathInfo.Vars) < 3 {
		return "", errors.New("Invalid Key length")
	}

	if len(ospfv2VrfName) == 0 {
		return "", errors.New("vrf name is missing")
	}

	if !strings.Contains(ospfv2Identifier, "OSPF") {
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

	if inParams.param.(*string) != nil {
		aclName := *(inParams.param.(*string))
		/* Further validation TBD */
		res_map[fieldName] = "" + aclName
		return res_map, err
	}

	return res_map, errors.New("Invalid Acl Name")
}

func DbToYang_ospfv2_validate_acl_name(inParams XfmrParams, fieldName string) (map[string]interface{}, error) {
	var err error
	res_map := make(map[string]interface{})

	if (inParams.param != nil) && (inParams.param.(*string) != nil) {
		fieldValue := *(inParams.param.(*string))
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

func ospfGetDottedAreaFromUint32(areaInt uint32) string {
	var areaIdInt int64 = int64(areaInt)
	b0 := strconv.FormatInt((areaIdInt>>24)&0xff, 10)
	b1 := strconv.FormatInt((areaIdInt>>16)&0xff, 10)
	b2 := strconv.FormatInt((areaIdInt>>8)&0xff, 10)
	b3 := strconv.FormatInt((areaIdInt)&0xff, 10)
	areaIdStr := b0 + "." + b1 + "." + b2 + "." + b3
	log.Infof("ospfGetDottedAreaFromUint32: %d is %s", areaInt, areaIdStr)
	return areaIdStr
}

func getAreaDotted(areaString string) string {
	if len(areaString) == 0 {
		log.Info("getAreaDotted: Null area id received")
		return ""
	}
	areaInt, err := strconv.ParseInt(areaString, 10, 64)
	if err == nil {
		b0 := strconv.FormatInt((areaInt>>24)&0xff, 10)
		b1 := strconv.FormatInt((areaInt>>16)&0xff, 10)
		b2 := strconv.FormatInt((areaInt>>8)&0xff, 10)
		b3 := strconv.FormatInt((areaInt & 0xff), 10)
		areaDotted := b0 + "." + b1 + "." + b2 + "." + b3
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

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	ospfv2AreaId := pathInfo.Var("identifier#2")

	if len(pathInfo.Vars) < 4 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return ospfv2VrfName, err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}
	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}
	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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
	pathInfo := NewPathInfo(inParams.uri)
	niName := pathInfo.Var("name")

	areaTableKeys := strings.Split(inParams.key, "|")

	if (len(areaTableKeys) < 2) || niName != areaTableKeys[0] {
		return nil, nil
	}

	res_map := make(map[string]interface{})

	res_map["identifier"] = areaTableKeys[1]

	log.Info("DbToYang_ospfv2_router_area_tbl_key: entry key:", inParams.key, " res_map:", res_map)
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

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	ospfv2AreaId := pathInfo.Var("src-area")

	if len(pathInfo.Vars) < 4 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return ospfv2VrfName, err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}
	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}
	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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
	pathInfo := NewPathInfo(inParams.uri)

	niName := pathInfo.Var("name")

	areaTableKeys := strings.Split(inParams.key, "|")

	if niName != areaTableKeys[0] {
		return nil, nil
	}
	res_map := make(map[string]interface{})
	log.Info("DbToYang_ospfv2_router_area_policy_tbl_key: entry key - ", inParams.key)

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

	res_map, err := DbToYang_ospfv2_validate_acl_name(inParams, "export-list")
	log.Infof("DbToYang_ospfv2_router_area_policy_export_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
	return res_map, err
}

var YangToDb_ospfv2_router_area_policy_import_list_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

	res_map, err := YangToDb_ospfv2_validate_acl_name(inParams, "import-list")
	log.Infof("YangToDb_ospfv2_router_area_policy_import_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
	return res_map, err
}

var DbToYang_ospfv2_router_area_policy_import_list_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	res_map, err := DbToYang_ospfv2_validate_acl_name(inParams, "import-list")
	log.Infof("DbToYang_ospfv2_router_area_policy_import_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
	return res_map, err
}

var YangToDb_ospfv2_router_area_network_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error
	var ospfv2VrfName string

	log.Info("YangToDb_ospfv2_router_area_network_tbl_key_xfmr: ", inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	ospfv2AreaId := pathInfo.Var("identifier#2")
	ospfv2NetworkPrefix := pathInfo.Var("address-prefix")

	if len(pathInfo.Vars) < 5 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return ospfv2VrfName, err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}
	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}
	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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
	ospfv2VrfName := pathInfo.Var("name")
	if len(ospfv2VrfName) == 0 {
		err := errors.New("VRF name is missing")
		log.Info("YangToDb_ospfv2_router_network_prefix_fld_xfmr: VRF Name is Missing")
		return res_map, err
	}

	intfAreaIdPresent, err := ospf_area_id_present_in_interfaces(&inParams, ospfv2VrfName, "*")
	if err != nil {
		log.Info("YangToDb_ospfv2_router_network_prefix_fld_xfmr: intfAreaIdPresent check Failed")
		return res_map, tlerr.New("Internal error: Interface area id config check failed")
	} else if intfAreaIdPresent {
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

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	ospfv2AreaId := pathInfo.Var("identifier#2")
	ospfv2RemoteRouterId := pathInfo.Var("remote-router-id")

	if len(pathInfo.Vars) < 5 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return ospfv2VrfName, err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}

	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}

	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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

	addOp, _, _, _ := ospfGetInparamOperation(&inParams)
	if addOp && ospfv2AreaId == "0.0.0.0" {
		errStr := "Configuring virtual links over the backbone is not allowed"
		log.Info("YangToDb_ospfv2_router_area_virtual_link_tbl_key_xfmr: ", errStr)
		return "", tlerr.New(errStr)
	}

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

var YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

	var err error
	res_map := make(map[string]string)

	if (inParams.param != nil) && (inParams.param.(*string) != nil) {
		authKeyStr := ""
		tblKeys := strings.Split(inParams.key, "|")
		if len(tblKeys) != 3 {
			errStr := "Invalid key param " + inParams.key
			log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: ", errStr)
			return res_map, tlerr.New(errStr)
		}

		vlinkObj, _, _, _ := ospfGetRouterAreaVlinkObject(&inParams, tblKeys[0], tblKeys[1], tblKeys[2])
		if vlinkObj == nil || vlinkObj.Config == nil {
			errStr := "Virtual link get auth key from inparam failed"
			log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: ", errStr)
			return res_map, tlerr.New(errStr)
		}

		if vlinkObj.Config.AuthenticationKey == nil {
			if inParams.oper == DELETE {
				res_map["authentication-key"] = ""
				return res_map, err
			}
			errStr := "Virtual link Md Auth key empty"
			log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: ", errStr)
			return res_map, tlerr.New(errStr)
		}

		encryptedKey := false
		if vlinkObj.Config.AuthenticationKeyEncrypted != nil {
			encryptedKey = *(vlinkObj.Config.AuthenticationKeyEncrypted)
		}

		authKeyStr = *(vlinkObj.Config.AuthenticationKey)

		if inParams.oper == DELETE {
			res_map["authentication-key"] = authKeyStr
			return res_map, err
		}

		keyLength := len(authKeyStr)
		if !encryptedKey && keyLength > 8 {
			errStr := "Authentication key shall be max 8 charater long"
			log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: " + errStr)
			return res_map, tlerr.New(errStr)
		}

		if authKeyStr == "" {
			errStr := "Inparam authentication key is empty"
			log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: ", errStr)
			authKeyStr = *(inParams.param.(*string))
		}

		encLen := ospf_get_min_encryption_length()
		if encryptedKey && keyLength < encLen {
			errStr := fmt.Sprintf("Encrypted authentication key shall be min %d character long", encLen)
			log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: " + errStr)
			return res_map, tlerr.New(errStr)
		}

		if !encryptedKey {
			encPasswd, err := ospf_encrypt_password(authKeyStr, false)
			if err != nil {
				log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: paswd encrypt failed")
				return res_map, err
			}
			authKeyStr = encPasswd
		}

		res_map["authentication-key"] = authKeyStr
	}

	log.Info("YangToDb_ospfv2_router_area_vl_authentication_key_fld_xfmr: respmap ", res_map)
	return res_map, nil
}

var DbToYang_ospfv2_router_area_vl_authentication_key_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	res_map := make(map[string]interface{})

	if (inParams.param != nil) && (inParams.param.(*string) != nil) {
		authKeyStr := *(inParams.param.(*string))

		res_map["authentication-key"] = authKeyStr
		return res_map, err
	}

	log.Info("DbToYang_ospfv2_router_area_vl_authentication_key_fld_xfmr: respmap ", res_map)
	return res_map, nil
}

var YangToDb_ospfv2_router_area_vlmd_auth_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error
	var ospfv2VrfName string

	log.Info("YangToDb_ospfv2_router_area_vlmd_auth_tbl_key_xfmr: ", inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	ospfv2AreaId := pathInfo.Var("identifier#2")
	ospfv2RemoteRouterId := pathInfo.Var("remote-router-id")
	ospfv2VlAuthKeyId := pathInfo.Var("authentication-key-id")

	if len(pathInfo.Vars) < 6 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length ", pathInfo.Vars)
		return "", err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}

	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}

	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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

	ospfv2RemoteRouterId = getAreaDotted(ospfv2RemoteRouterId)

	if len(ospfv2VlAuthKeyId) == 0 {
		err = errors.New("OSPF VL MD authentication key id missing")
		log.Info("VL MD authentication key id missing")
		return "", err
	}

	log.Info("URI VRF ", ospfv2VrfName)
	log.Info("URI Area Id ", ospfv2AreaId)
	log.Info("URI Virtual link remote router Id ", ospfv2RemoteRouterId)
	log.Info("URI Virtual link Auth key Id ", ospfv2VlAuthKeyId)

	pVirtualLinkAuthTableKey := ospfv2VrfName + "|" + ospfv2AreaId + "|" + ospfv2RemoteRouterId + "|" + ospfv2VlAuthKeyId

	log.Info("YangToDb_ospfv2_router_area_vlmd_auth_tbl_key_xfmr: pVirtualLinkAuthTableKey - ", pVirtualLinkAuthTableKey)
	return pVirtualLinkAuthTableKey, nil
}

var DbToYang_ospfv2_router_area_vlmd_auth_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	entry_key := inParams.key
	log.Info("DbToYang_ospfv2_router_area_vlmd_auth_tbl_key_xfmr: entry key - ", entry_key)

	virtualLinkAuthTableKey := strings.Split(entry_key, "|")

	if len(virtualLinkAuthTableKey) >= 4 {
		intKeyid, err := strconv.Atoi(virtualLinkAuthTableKey[3])
		if err == nil {
			res_map["authentication-key-id"] = uint8(intKeyid)
		}
	}

	log.Info("DbToYang_ospfv2_router_area_vlmd_auth_tbl_key_xfmr: res_map ", res_map)
	return res_map, nil
}

var YangToDb_ospfv2_router_area_vlmd_auth_key_id_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

	res_map := make(map[string]string)

	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_ospfv2_router_area_vlmd_auth_key_id_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	res_map := make(map[string]interface{})

	entry_key := inParams.key
	virtualLinkAuthTableKey := strings.Split(entry_key, "|")

	if len(virtualLinkAuthTableKey) >= 4 {
		intKeyid, err := strconv.Atoi(virtualLinkAuthTableKey[3])
		if err == nil {
			res_map["authentication-key-id"] = uint8(intKeyid)
		}
	}

	log.Info("DbToYang_ospfv2_router_area_vlmd_auth_key_id_fld_xfmr: respmap ", res_map)
	return res_map, nil
}

var YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

	var err error
	res_map := make(map[string]string)

	if (inParams.param != nil) && (inParams.param.(*string) != nil) {
		md5KeyStr := ""
		tblKeys := strings.Split(inParams.key, "|")
		if len(tblKeys) != 4 {
			errStr := "Invalid key param " + inParams.key
			log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: ", errStr)
			return res_map, tlerr.New(errStr)
		}

		authKeyIdInt, _ := strconv.Atoi(tblKeys[3])
		authKeyId := uint8(authKeyIdInt)
		vlMdAuthObj, _, _, _ := ospfGetRouterAreaVlinkMdAuthObject(&inParams, tblKeys[0], tblKeys[1], tblKeys[2], authKeyId)
		if vlMdAuthObj == nil || vlMdAuthObj.Config == nil {
			errStr := "Virtual link Md Auth object get from inparam failed"
			log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: ", errStr)
			return res_map, tlerr.New(errStr)
		}

		if vlMdAuthObj.Config.AuthenticationMd5Key == nil {
			if inParams.oper == DELETE {
				res_map["authentication-key"] = ""
				return res_map, err
			}
			errStr := "Virtual link Md Auth key empty"
			log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: ", errStr)
			return res_map, tlerr.New(errStr)
		}

		encryptedKey := false
		if vlMdAuthObj.Config.AuthenticationKeyEncrypted != nil {
			encryptedKey = *(vlMdAuthObj.Config.AuthenticationKeyEncrypted)
		}

		md5KeyStr = *(vlMdAuthObj.Config.AuthenticationMd5Key)

		if inParams.oper == DELETE {
			res_map["authentication-key"] = md5KeyStr
			return res_map, err
		}

		keyLength := len(md5KeyStr)
		if !encryptedKey && keyLength > 16 {
			errStr := "Authentication key shall be max 16 charater long"
			log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: " + errStr)
			return res_map, tlerr.New(errStr)
		}

		if md5KeyStr == "" {
			errStr := "Inparam authentication key is empty"
			log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: ", errStr)
			md5KeyStr = *(inParams.param.(*string))
		}

		encLen := ospf_get_min_encryption_length()
		if encryptedKey && keyLength < encLen {
			errStr := fmt.Sprintf("Encrypted authentication key shall be min %d character long", encLen)
			log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: " + errStr)
			return res_map, tlerr.New(errStr)
		}

		if !encryptedKey {
			encPasswd, err := ospf_encrypt_password(md5KeyStr, false)
			if err != nil {
				log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: paswd encrypt failed")
				return res_map, err
			}
			md5KeyStr = encPasswd
		}

		res_map["authentication-md5-key"] = md5KeyStr
	}

	log.Info("YangToDb_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: respmap ", res_map)
	return res_map, nil
}

var DbToYang_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	res_map := make(map[string]interface{})

	if (inParams.param != nil) && (inParams.param.(*string) != nil) {
		md5KeyStr := *(inParams.param.(*string))

		res_map["authentication-md5-key"] = md5KeyStr
		return res_map, err
	}

	log.Info("DbToYang_ospfv2_router_area_vlmd_auth_md5_key_fld_xfmr: respmap ", res_map)
	return res_map, nil
}

var YangToDb_ospfv2_router_area_policy_address_range_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error
	var ospfv2VrfName string

	log.Info("YangToDb_ospfv2_router_area_policy_address_range_tbl_key_xfmr: ", inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	ospfv2policySourceArea := pathInfo.Var("src-area")
	ospfv2AddressRange := pathInfo.Var("address-prefix")

	if len(pathInfo.Vars) < 5 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return ospfv2VrfName, err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}

	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}

	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	distributionProtocol := pathInfo.Var("protocol")
	distributionDirection := pathInfo.Var("direction")

	if len(pathInfo.Vars) < 5 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return ospfv2VrfName, err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}
	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}
	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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

	res_map, err := DbToYang_ospfv2_validate_acl_name(inParams, "access-list")
	log.Infof("DbToYang_ospfv2_router_distribute_route_access_list_fld_xfmr: key %s res_map %v", inParams.key, res_map)
	return res_map, err
}

var YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error
	var ospfv2VrfName string

	log.Info("YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr: ", inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	ospfv2VrfName = pathInfo.Var("name")
	ospfv2Identifier := pathInfo.Var("identifier")
	ospfv2InstanceNumber := pathInfo.Var("name#2")
	passiveIfName := pathInfo.Var("name#3")
	passiveIfSubIf := pathInfo.Var("subinterface")
	passiveIfAddress := pathInfo.Var("address")

	if len(pathInfo.Vars) < 5 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return ospfv2VrfName, err
	}

	if len(ospfv2VrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}

	if !strings.Contains(ospfv2Identifier, "OSPF") {
		err = errors.New("OSPF ID is missing")
		log.Info("OSPF ID is missing")
		return "", err
	}

	if len(ospfv2InstanceNumber) == 0 {
		err = errors.New("OSPF intance number/name is missing")
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
	log.Info("URI passiveIfName ", passiveIfName)
	log.Info("URI passiveIfAddress ", passiveIfAddress)

	tempkey1 := strings.Split(passiveIfName, ":")
	if len(tempkey1) > 1 {
		passiveIfName = tempkey1[1]
	}

	nativePassiveIfName := passiveIfName

	if passiveIfSubIf != "0" && passiveIfSubIf != "" {
		passiveIfName = passiveIfName + "." + passiveIfSubIf
		nativePassiveIfName = passiveIfName

		/* Note: It is not required to convert the keys into native form
		 * in table key transformers. This YangToDb call gets called with
		 * Key in UI name format. We need to return the table key in
		 * UI name format itself. Mgmt infra, at the time of creating
		 * table entry, will automatically conver UI name to native name
		 * and create table entry with native name key.
		 */
	}

	tempkey1 = strings.Split(passiveIfAddress, ":")
	if len(tempkey1) > 1 {
		passiveIfAddress = tempkey1[1]
	}

	passiveIfTableKey := ospfv2VrfName + "|" + nativePassiveIfName + "|" + passiveIfAddress

	log.Info("YangToDb_ospfv2_router_passive_interface_tbl_key_xfmr: passiveIfTableKey - ", passiveIfTableKey)
	return passiveIfTableKey, nil
}

var DbToYang_ospfv2_router_passive_interface_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	entry_key := inParams.key
	log.Info("DbToYang_ospfv2_router_passive_interface_tbl_key: entry key - ", entry_key)

	passiveIfTableKeys := strings.Split(entry_key, "|")

	if len(passiveIfTableKeys) >= 3 {
		_, ifName, _, subIfIdx, _ := getUserInterfaceName(passiveIfTableKeys[1])
		res_map["name"] = ifName
		res_map["subinterface"] = subIfIdx
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
		_, ifName, _, _, _ := getUserInterfaceName(passiveIfTableKeys[1])
		res_map["name"] = ifName
	}
	return res_map, err
}

var YangToDb_ospfv2_router_passive_interface_subinterface_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

	res_map := make(map[string]string)

	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_ospfv2_router_passive_interface_subinterface_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	res_map := make(map[string]interface{})

	entry_key := inParams.key
	passiveIfTableKeys := strings.Split(entry_key, "|")

	if len(passiveIfTableKeys) >= 3 {
		_, _, _, subIfIdx, _ := getUserInterfaceName(passiveIfTableKeys[1])
		res_map["subinterface"] = subIfIdx
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

	interfaceVrfName = "default" //pathInfo.Var("name")
	ospfv2InterfaceName := pathInfo.Var("name")
	ospfv2InterfaceId := pathInfo.Var("index")

	if len(pathInfo.Vars) < 2 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return interfaceVrfName, err
	}

	if len(interfaceVrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}

	if len(ospfv2InterfaceName) == 0 {
		err = errors.New("OSPF interface name is missing")
		log.Info("OSPF interface name is Missing")
		return "", err
	}

	if len(ospfv2InterfaceId) == 0 {
		err = errors.New("OSPF interface identifier missing")
		log.Info("OSPF sub-interface identifier is Missing")
		return "", err
	}

	log.Info("URI VRF ", interfaceVrfName)
	log.Info("URI interface name ", ospfv2InterfaceName)
	log.Info("URI Sub interface Id ", ospfv2InterfaceId)

	uriFullIfName, _, _, _, err := getInParamIfName(&inParams)
	if err != nil {
		err = errors.New("OSPF interface name error")
		log.Info("OSPF uri full name error")
		return "", err
	}

	ospfv2InterfaceName, _, _, _, err = getNativeInterfaceName(uriFullIfName)
	if err != nil {
		err = errors.New("OSPF interface name conversion error")
		log.Info("OSPF native interface conversion error")
		return "", err
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

func ospf_get_table_keys(inParams *XfmrParams, tblName string) ([]db.Key, error) {
	var err error
	log.Infof("ospf_get_table_keys: tblName %s ", tblName)

	if tblName == "" {
		errStr := "Empty Table name parameter"
		log.Info("ospf_get_table_keys: ", errStr)
		return nil, errors.New(errStr)
	}

	var tblSpec *db.TableSpec = &db.TableSpec{Name: tblName}
	tblData, err := configDbPtr.GetTable(tblSpec)
	if err != nil {
		log.Error("ospf_get_table_keys: get table failed ", err)
		return nil, err
	}

	var tblKeys []db.Key
	tblKeys, err = tblData.GetKeys()
	if err != nil {
		log.Info("ospf_get_table_keys: get keys failed ", err)
		return nil, err
	}

	log.Info("ospf_get_table_keys: table keys ", tblKeys)
	return tblKeys, nil
}

func ospf_table_entry_present(inParams *XfmrParams, tblName string, tblKey string) (bool, error) {

	log.Infof("ospf_table_entry_present: tblName %s tblKey %s", tblName, tblKey)

	if tblName == "" || tblKey == "" {
		errStr := "Empty Table name or key parameter"
		log.Info("ospf_table_entry_present: ", errStr)
		return false, errors.New(errStr)
	}

	inKeyList := strings.Split(tblKey, "|")
	inKeyLen := len(inKeyList)
	entryPresent := false

	dbTblKeys, err := ospf_get_table_keys(inParams, tblName)
	if err != nil {
		errStr := "Table get keys Failed"
		log.Info("ospf_interface_entry_present: Table get keys failed ", errStr)
		return false, nil
	}

	for _, dbTblKey := range dbTblKeys {
		dbTblKeyLen := dbTblKey.Len()
		if inKeyLen > dbTblKeyLen {
			log.Infof("ospf_interface_entry_present: inkey length %d greater than dbkey %d", inKeyLen, dbTblKeyLen)
			break
		}

		keyMatched := true
		if tblKey != "*" {
			for idx, inKey := range inKeyList {
				if inKey != "*" {
					if inKey != dbTblKey.Get(idx) {
						keyMatched = false
						break
					}
				}
			}
		}

		if keyMatched {
			entryPresent = true
			break
		}
	}

	log.Infof("ospf_table_entry_present: entry %s %s present %t", tblName, tblKey, entryPresent)
	return entryPresent, nil
}

func ospf_update_subop_respmap(inParams *XfmrParams, action int,
	tblName string, tblKey string,
	respMap *map[string]map[string]db.Value) error {

	log.Infof("ospf_update_subop_respmap: Action %d tblName %s tblKey %s", action, tblName, tblKey)

	if !(action == UPDATE || action == CREATE || action == REPLACE || action == DELETE) {
		errStr := "Invalid Action or operation "
		log.Info("ospf_update_subop_respmap: ", errStr)
		return errors.New(errStr)
	}

	if inParams == nil || respMap == nil {
		errStr := "Nil inparams or respMap"
		log.Info("ospf_update_subop_respmap: ", errStr)
		return errors.New(errStr)
	}

	if tblName == "" || tblKey == "" {
		errStr := "Empty Table name or key parameter"
		log.Info("ospf_update_subop_respmap: ", errStr)
		return errors.New(errStr)
	}

	updateStr := ""

	subOpMap, found := inParams.subOpDataMap[action]
	if !found || (found && subOpMap == nil) {
		newSubOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		inParams.subOpDataMap[action] = &newSubOpMap
		subOpMap = inParams.subOpDataMap[action]
		updateStr += " DataMap"
	}

	if _, found := (*subOpMap)[db.ConfigDB]; !found {
		(*subOpMap)[db.ConfigDB] = make(map[string]map[string]db.Value)
		updateStr += " ConfigDB"
	}

	if _, found := (*subOpMap)[db.ConfigDB][tblName]; !found {
		(*subOpMap)[db.ConfigDB][tblName] = make(map[string]db.Value)
		updateStr += " tblName"
	}

	if _, found := (*subOpMap)[db.ConfigDB][tblName][tblKey]; !found {
		(*subOpMap)[db.ConfigDB][tblName][tblKey] = db.Value{Field: make(map[string]string)}
		updateStr += " tblkey"
	}

	if updateStr != "" {
		log.Info("ospf_update_subop_respmap: created subOpData", updateStr)
		updateStr = ""
	}

	if _, found = (*respMap)[tblName]; !found {
		(*respMap)[tblName] = make(map[string]db.Value)
		updateStr += " tblName"
	}

	if _, found = (*respMap)[tblName][tblKey]; !found {
		(*respMap)[tblName][tblKey] = db.Value{Field: make(map[string]string)}
		updateStr += " tblKey"
	}

	if updateStr != "" {
		log.Info("ospf_update_subop_respmap: created respMap", updateStr)
	}

	return nil
}

func ospf_update_table_entry(inParams *XfmrParams, action int,
	tblName string, tblKey string,
	fldName string, fldValue string,
	respMap *map[string]map[string]db.Value) error {

	log.Infof("ospf_update_table_entry: Action %d tblName %s tblKey %s", action, tblName, tblKey)

	err := ospf_update_subop_respmap(inParams, action, tblName, tblKey, respMap)
	if err != nil {
		log.Info("ospf_update_table_entry: update subopmap resp map failed")
		return err
	}

	checkEntryPresence := false
	if checkEntryPresence {
		entryPresent, _ := ospf_table_entry_present(inParams, tblName, tblKey)
		if entryPresent {
			if fldName == "" || fldName == "NULL" {
				log.Info("ospf_update_table_entry: table entry already present")
				return nil
			}
		} else if action == DELETE {
			log.Info("ospf_update_table_entry: table entry doesnt exist")
			return nil
		}
	}

	if fldName != "" || fldValue != "" {
		log.Infof("ospf_update_table_entry: fldName %s fldValue %s.", fldName, fldValue)
	}

	subOpMap := inParams.subOpDataMap[action]

	if action == UPDATE || action == CREATE || action == REPLACE {
		if fldName == "" {
			(*subOpMap)[db.ConfigDB][tblName][tblKey].Field["NULL"] = "NULL"
			(*respMap)[tblName][tblKey].Field["NULL"] = "NULL"
			log.Info("ospf_update_table_entry: update new row with key ", tblKey)
		} else {
			(*subOpMap)[db.ConfigDB][tblName][tblKey].Field[fldName] = fldValue
			(*respMap)[tblName][tblKey].Field[fldName] = fldValue
			log.Infof("ospf_update_table_entry: updated row field %s %s ", fldName, fldValue)
		}
	}

	if action == DELETE {
		if fldName != "" {
			(*subOpMap)[db.ConfigDB][tblName][tblKey].Field[fldName] = "NULL"
			(*respMap)[tblName][tblKey].Field[fldName] = "NULL"
			log.Infof("ospf_update_table_entry: delete row field %s %s ", fldName, fldValue)
		} else {
			(*subOpMap)[db.ConfigDB][tblName][tblKey] = db.Value{Field: make(map[string]string)}
			(*respMap)[tblName][tblKey] = db.Value{Field: make(map[string]string)}
			log.Infof("ospf_update_table_entry: row delete overriding existing field deletes")
		}
	}

	log.Info("ospf_update_table_entry: updated subOpMap ", (*subOpMap))
	log.Info("ospf_update_table_entry: updated respMap ", (*respMap))
	return nil
}

func ospf_update_table_entries(inParams *XfmrParams, action int,
	tblName string, tblKey string,
	tblFieldMap map[string]string,
	respMap *map[string]map[string]db.Value) error {

	log.Infof("ospf_update_table_entries: Action %d tblName %s tblKey %s", action, tblName, tblKey)
	log.Info("ospf_update_table_entries: tblFieldMap ", tblFieldMap)

	err := ospf_update_subop_respmap(inParams, action, tblName, tblKey, respMap)
	if err != nil {
		log.Info("ospf_update_table_entries: update subopmap resp map failed")
		return err
	}

	subOpMap := inParams.subOpDataMap[action]

	if action == UPDATE || action == CREATE || action == REPLACE {
		if len(tblFieldMap) == 0 {
			(*subOpMap)[db.ConfigDB][tblName][tblKey].Field["NULL"] = "NULL"
			(*respMap)[tblName][tblKey].Field["NULL"] = "NULL"
			log.Info("ospf_update_table_entries: create new row with key ", tblKey)
		} else {
			for fldName, fldValue := range tblFieldMap {
				(*subOpMap)[db.ConfigDB][tblName][tblKey].Field[fldName] = fldValue
				(*respMap)[tblName][tblKey].Field[fldName] = fldValue
			}
			log.Info("ospf_update_table_entries: updated row fields ", tblFieldMap)
		}
	}

	if action == DELETE {
		if len(tblFieldMap) == 0 {
			log.Info("ospf_update_table_entries: deleted table row ", tblKey)
		} else {
			for fldName := range tblFieldMap {
				(*subOpMap)[db.ConfigDB][tblName][tblKey].Field[fldName] = "NULL"
				(*respMap)[tblName][tblKey].Field[fldName] = "NULL"
			}
			log.Info("ospf_update_table_entries: deleted row fields ", tblFieldMap)
		}
	}

	log.Info("ospf_update_table_entries: updated subOpMap ", (*subOpMap))
	log.Info("ospf_update_table_entries: updated respMap ", (*respMap))
	return nil
}

func ospf_delete_table_entry(inParams *XfmrParams,
	tblName string, tblKey string,
	respMap *map[string]map[string]db.Value) error {

	log.Infof("ospf_delete_table_entry: tblName %s tblKey %s", tblName, tblKey)

	if inParams == nil || respMap == nil {
		errStr := "Nil inparams or respMap"
		log.Info("ospf_delete_table_entry: ", errStr)
		return errors.New(errStr)
	}

	if tblName == "" || tblKey == "" {
		errStr := "Empty Table name or key parameter"
		log.Info("ospf_delete_table_entry: ", errStr)
		return errors.New(errStr)
	}

	inKeyList := strings.Split(tblKey, "|")
	inKeyLen := len(inKeyList)

	dbTblKeys, err := ospf_get_table_keys(inParams, tblName)
	if err != nil {
		errStr := "Table get keys Failed"
		log.Info("ospf_delete_table_entry: Table get keys failed ", errStr)
		return nil
	}

	deleteCount := 0
	for _, dbTblKey := range dbTblKeys {
		dbTblKeyLen := dbTblKey.Len()
		if inKeyLen > dbTblKeyLen {
			log.Infof("ospf_delete_table_entry: inkey length %d greater than dbkey %d", inKeyLen, dbTblKeyLen)
			continue
		}

		keyMatched := true
		if tblKey != "*" {
			for idx, inKey := range inKeyList {
				if inKey != "*" {
					if inKey != dbTblKey.Get(idx) {
						keyMatched = false
						break
					}
				}
			}
		}

		if !keyMatched {
			continue
		}

		dbKeyStr := ""
		for idx := 0; idx < dbTblKeyLen; idx++ {
			if dbKeyStr == "" {
				dbKeyStr = dbTblKey.Get(idx)
			} else {
				dbKeyStr = dbKeyStr + "|" + dbTblKey.Get(idx)
			}
		}

		if dbKeyStr != "" {
			log.Info("ospf_delete_table_entry: delete entry ", dbKeyStr)
			err := ospf_update_table_entry(inParams, DELETE, tblName, dbKeyStr, "", "", respMap)
			if err != nil {
				log.Info("ospf_delete_table_entry: table update for del failed ", dbKeyStr)
				return err
			}
			deleteCount = deleteCount + 1
		}
	}

	log.Infof("ospf_delete_table_entry: %d entries deleted in %s with key %s", deleteCount, tblName, tblKey)
	return nil
}

func ospf_get_table_entry(inParams *XfmrParams, tblName string, tblKey string) (db.Value, error) {

	var tblEntry db.Value
	var err error
	log.Infof("ospf_get_table_entry: tblName %s tblKey %s", tblName, tblKey)

	if tblName == "" || tblKey == "" {
		errStr := "Empty Table name or key parameter"
		log.Info("ospf_get_table_entry: ", errStr)
		return tblEntry, errors.New(errStr)
	}

	var tblSpec *db.TableSpec = &db.TableSpec{Name: tblName}
	tblData, err1 := configDbPtr.GetTable(tblSpec)
	if err1 != nil {
		log.Error("ospf_get_table_entry: GetTable failed")
		return tblEntry, err
	}

	tblEntry, err = tblData.GetEntry(db.Key{[]string{tblKey}})
	if err != nil {
		log.Info("ospf_get_table_entry: table data GetEntry failed")
		return tblEntry, err
	}

	if len(tblEntry.Field) == 0 {
		errStr := "Empty table entry field"
		log.Info("ospf_get_table_entry: ", errStr)
		return tblEntry, tlerr.New(errStr)
	}

	log.Info("ospf_get_table_entry: present ", tblEntry)
	return tblEntry, nil
}

func ospf_get_table_entry_field(inParams *XfmrParams, tblName string, tblKey string, fieldName string) (bool, string, error) {

	var tblEntry db.Value
	var err error
	log.Infof("ospf_get_table_entry_field: tblName %s tblKey %s fieldName %s", tblName, tblKey, fieldName)

	if tblName == "" || tblKey == "" || fieldName == "" {
		errStr := "Empty Table name or tblkey or fieldname parameter"
		log.Info("ospf_get_table_entry_field: ", errStr)
		return false, "", errors.New(errStr)
	}

	var tblSpec *db.TableSpec = &db.TableSpec{Name: tblName}
	tblData, err1 := configDbPtr.GetTable(tblSpec)
	if err1 != nil {
		log.Info("ospf_get_table_entry_field: GetTable err ", err1)
		return false, "", err1
	}

	tblEntry, err = tblData.GetEntry(db.Key{[]string{tblKey}})
	if err != nil {
		log.Info("ospf_get_table_entry_field: table data GetEntry failed")
		return false, "", nil
	}

	if len(tblEntry.Field) == 0 {
		errStr := "Empty table entry"
		log.Info("ospf_get_table_entry_field: ", errStr)
		return false, "", nil
	}

	fieldValue := (&tblEntry).Get(fieldName)
	log.Infof("ospf_get_table_entry_field: field %s value is %s.", fieldName, fieldValue)
	return true, fieldValue, nil
}

func ospf_config_present(inParams *XfmrParams, tblName string, tblKey string, ignoreFieldMap []string) (bool, error) {

	log.Infof("ospf_config_present: tblName %s tblKey %s ignoreFieldMap %v", tblName, tblKey, ignoreFieldMap)

	if tblName == "" || tblKey == "" {
		errStr := "Empty Table name or key parameter"
		log.Info("ospf_config_present: ", errStr)
		return false, nil
	}

	inKeyList := strings.Split(tblKey, "|")
	inKeyLen := len(inKeyList)

	var tblSpec *db.TableSpec = &db.TableSpec{Name: tblName}
	tblData, err1 := configDbPtr.GetTable(tblSpec)
	if err1 != nil {
		log.Error("ospf_config_present: GetTable failed for ", tblName)
		return false, err1
	}

	dbTblKeys, err2 := tblData.GetKeys()
	if err2 != nil {
		log.Info("ospf_config_present: get keys failed ", err2)
		return false, err2
	}

	for _, dbTblKey := range dbTblKeys {
		dbTblKeyLen := dbTblKey.Len()
		if inKeyLen > dbTblKeyLen {
			log.Infof("ospf_config_present: inkey length %d greater than dbkey %d", inKeyLen, dbTblKeyLen)
			continue
		}

		keyMatched := true
		if tblKey != "*" {
			for idx, inKey := range inKeyList {
				if inKey != "*" {
					if inKey != dbTblKey.Get(idx) {
						keyMatched = false
						break
					}
				}
			}
		}

		if !keyMatched {
			continue
		}

		tblEntry, err := tblData.GetEntry(dbTblKey)
		if err != nil {
			log.Info("ospf_config_present: table data GetEntry failed")
			continue
		}

		for fieldName := range tblEntry.Field {
			fieldNameIgnore := false
			for _, ignoreFieldName := range ignoreFieldMap {
				if fieldName == ignoreFieldName {
					fieldNameIgnore = true
					break
				}
			}

			if !fieldNameIgnore {
				log.Infof("ospf_config_present: config present with key %v tblEntry %v", dbTblKey, tblEntry)
				log.Infof("ospf_config_present: config %s present in record %v", fieldName, dbTblKey)
				return true, nil
			}
		}
	}

	log.Info("ospf_config_present: config not present for ", tblKey)
	return false, nil
}

func ospfv2_config_post_xfmr(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) error {

	var err error
	log.Info("ospfv2_config_post_xfmr: --------- ospf post xfmr ----------")

	err = nil
	rcvdUri, uriErr := getOspfUriPath(inParams)
	if uriErr != nil {
		log.Info("ospfv2_config_post_xfmr: getOspfUriPath failed ", uriErr)
		return uriErr
	}

	ospfObj, vrfName, _, _ := ospfGetRouterObject(inParams, "")
	if ospfObj == nil || vrfName == "" {
		log.Info("ospfv2_config_post_xfmr: ospf router not in request")
		return nil
	}

	log.Info("ospfv2_config_post_xfmr: inParams subOpDataMap ", inParams.subOpDataMap)
	for subop, opData := range inParams.subOpDataMap {
		log.Infof("ospfv2_config_post_xfmr: input subop %d subOpData %v", subop, *opData)
	}
	log.Info("ospfv2_config_post_xfmr: input respmap ", *ospfRespMap)

	if inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE {
		log.Info("ospfv2_config_post_xfmr for ADD/UPDATE/REPLACE operation ", inParams.oper)

		err = ospf_auto_create_ospf_router_area(inParams, ospfRespMap)
		if err != nil {
			log.Info("ospfv2_config_post_xfmr: ospf_auto_create_ospf_router_area failed ", err)
			return err
		}

		if ospfObj != nil && ospfObj.Global != nil {
			err = ospf_add_del_passive_interface_config(inParams, ospfRespMap)
			if err != nil {
				log.Info("ospfv2_config_post_xfmr: passive intf add failed ", err)
				return err
			}
		}

	} else if inParams.oper == DELETE {
		log.Info("ospfv2_config_post_xfmr: for DELETE operation")

		if strings.HasSuffix(rcvdUri, "protocols/protocol/ospfv2") ||
			strings.HasSuffix(rcvdUri, "protocols/protocol/ospfv2/global") {
			/* ospf router delete */
			err = delete_ospf_interfaces_for_vrf(inParams, ospfRespMap)
			if err != nil {
				log.Info("ospfv2_config_post_xfmr: delete_ospf_interfaces_for_vrf failed ", err)
				return err
			}

		} else {
			if strings.Contains(rcvdUri, "route-distribution-policies") {
				/* ospf router redistribute delete */
				err = delete_ospf_router_redistribute_entry(inParams, ospfRespMap)
				if err != nil {
					log.Info("ospfv2_config_post_xfmr: delete_ospf_router_redistribute_entry failed ", err)
					return err
				}
			}

			if strings.Contains(rcvdUri, "areas/area") {
				err = validate_ospf_router_area_delete(inParams, ospfRespMap)
				if err != nil {
					log.Info("ospfv2_config_post_xfmr: validate_ospf_router_area_delete failed ", err)
					return err
				}
			}

			if strings.HasSuffix(rcvdUri, "area/virtual-links") ||
				strings.HasSuffix(rcvdUri, "area/virtual-links/virtual-link") {
				err = validate_ospf_router_vlmd_auth_delete(inParams, ospfRespMap)
				if err != nil {
					log.Info("ospfv2_config_post_xfmr: validate_ospf_router_vlmd_auth_delete failed ", err)
					return err
				}
			}

			if strings.HasSuffix(rcvdUri, "ospfv2/global/config/passive-interface-default") ||
				strings.Contains(rcvdUri, "ospfv2/global/passive-interfaces") ||
				strings.Contains(rcvdUri, "ospfv2/global/passive-interfaces/passive-interface") {
				err = ospf_add_del_passive_interface_config(inParams, ospfRespMap)
				if err != nil {
					log.Info("ospfv2_config_post_xfmr: passive intf del failed ", err)
					return err
				}
			}
		}
	}

	log.Info("ospfv2_config_post_xfmr: return subOpDataMap ", inParams.subOpDataMap)
	for subop, opData := range inParams.subOpDataMap {
		log.Infof("ospfv2_config_post_xfmr: return subop %d subOpData %v", subop, *opData)
	}
	log.Info("ospfv2_config_post_xfmr: return respmap ", *ospfRespMap)
	return nil
}

func ospf_router_present(inParams *XfmrParams, vrfName string) (bool, error) {

	log.Info("ospf_router_present: vrfName ", vrfName)
	if vrfName == "" {
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
	if vrfName == "" {
		errStr := "Empty vrfName name"
		log.Info("ospf_router_area_present: ", errStr)
		return false, errors.New(errStr)
	}

	if areaId == "" {
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
		if keyVrfName == vrfName && keyAreaId == areaId {
			log.Info("ospf_router_area_present: ospf router area present with key ", ospfTblKey)
			return true, nil
		}
	}

	log.Infof("ospf_router_area_present: ospf router area %s not present in vrf %s", areaId, vrfName)
	return false, nil
}

func ospf_router_area_network_present(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

	log.Infof("ospf_router_area_network_present: vrfName %s areaId %s.", vrfName, areaId)
	if vrfName == "" {
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
		log.Info("ospf_router_area_network_present: get keys failed ", errStr)
		return false, err2
	}

	for _, ospfTblKey := range ospfTblKeys {
		keyVrfName := ospfTblKey.Get(0)
		keyAreaId := ospfTblKey.Get(1)

		if keyVrfName == vrfName {
			if areaId == "" || areaId == "*" {
				log.Info("ospf_router_area_network_present: network config present with key ", ospfTblKey)
				return true, nil
			} else {
				if keyAreaId == areaId {
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
	if vrfName == "" {
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
		log.Info("ospf_router_area_virtual_link_present: get keys failed ", errStr)
		return false, err2
	}

	for _, ospfTblKey := range ospfTblKeys {
		keyVrfName := ospfTblKey.Get(0)
		keyAreaId := ospfTblKey.Get(1)

		if keyVrfName == vrfName {
			if areaId == "" || areaId == "*" {
				log.Info("ospf_router_area_virtual_link_present: VL config present with key ", ospfTblKey)
				return true, nil
			} else {
				if keyAreaId == areaId {
					log.Info("ospf_router_area_virtual_link_present: VL config present with key ", ospfTblKey)
					return true, nil
				}
			}
		}
	}

	log.Info("ospf_router_area_virtual_link_present: area network config not present in vrf ", vrfName)
	return false, nil
}

func ospf_router_area_vlmd_auth_present(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

	log.Infof("ospf_router_area_vlmd_auth_present: vrfName %s areaId %s.", vrfName, areaId)
	if vrfName == "" {
		errStr := "Empty vrf name"
		log.Info("ospf_router_area_vlmd_auth_present: ", errStr)
		return false, errors.New(errStr)
	}

	vlAuthTblName := "OSPFV2_ROUTER_AREA_VLMD_AUTHENTICATION"
	vlAuthTblKey := vrfName + "|" + areaId + "|" + "*" + "|" + "*"

	found, err := ospf_table_entry_present(inParams, vlAuthTblName, vlAuthTblKey)
	log.Info("ospf_router_area_vlmd_auth_present: vl auth entry found is ", found)
	return found, err
}

func ospf_router_area_address_range_present(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

	log.Infof("ospf_router_area_address_range_present: vrfName %s areaId %s.", vrfName, areaId)
	if vrfName == "" {
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
		log.Info("ospf_router_area_address_range_present: get keys failed ", errStr)
		return false, err2
	}

	for _, ospfTblKey := range ospfTblKeys {
		keyVrfName := ospfTblKey.Get(0)
		keyAreaId := ospfTblKey.Get(1)

		if keyVrfName == vrfName {
			if areaId == "" || areaId == "*" {
				log.Info("ospf_router_area_address_range_present: AR config present with key ", ospfTblKey)
				return true, nil
			} else {
				if keyAreaId == areaId {
					log.Info("ospf_router_area_address_range_present: AR config present with key ", ospfTblKey)
					return true, nil
				}
			}
		}
	}

	log.Info("ospf_router_area_address_range_present: area network config not present in vrf ", vrfName)
	return false, nil
}

func create_ospf_area_entry(inParams *XfmrParams, vrfName string, areaId string, ospfRespMap *map[string]map[string]db.Value) error {
	log.Infof("create_ospf_area_entry: vrfName %s areaId %s", vrfName, areaId)
	if vrfName == "" {
		errStr := "Empty vrf name"
		log.Info("create_ospf_area_entry: ", errStr)
		return errors.New(errStr)
	}

	if areaId == "" {
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

	err := ospf_update_table_entry(inParams, inParams.oper, ospfTblName, ospfTblKey, "enable", "true", ospfRespMap)
	if err != nil {
		log.Info("create_ospf_area_entry: create area entry failed ", err)
		return err
	}

	log.Infof("create_ospf_area_entry: Areas entry %s added respmap", ospfTblKey)
	return nil
}

func ospf_auto_create_ospf_router_area(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) error {
	log.Info("ospf_auto_create_ospf_router_area: ", inParams.uri)

	ospfObj, vrfName, _, _ := ospfGetRouterObject(inParams, "")
	if ospfObj == nil || vrfName == "" {
		log.Info("ospf_auto_create_ospf_router_area: ospf router not in request")
		return nil
	}

	areaId := ""
	vlinkId := ""
	oldAreaId := ""

	_, vlinkKey, _, _ := ospfGetRouterAreaVlinkMdAuthObject(inParams, vrfName, areaId, "", 0)
	if vlinkKey != "" {
		log.Info("ospf_auto_create_ospf_router_area: vlinkKey ", vlinkKey)
		keyFields := strings.Split(vlinkKey, "|")

		// vrfName | areaId | vlinkId | keyId
		if len(keyFields) >= 3 {
			//req is add area+1
			vrfName = keyFields[0]
			areaId = keyFields[1]
		}
		if len(keyFields) >= 4 {
			//req is add vlink+1
			vlinkId = keyFields[2]
		}

		if areaId != "" {
			log.Infof("ospf_auto_create_ospf_router_area: Auto create area %s in vrf %s", areaId, vrfName)
			create_ospf_area_entry(inParams, vrfName, areaId, ospfRespMap)
		}

		if vlinkId != "" {
			log.Infof("ospf_auto_create_ospf_router_area: Auto create area vl %s in area %s", vlinkId, areaId)
			create_ospf_area_vlink_entry(inParams, vrfName, areaId, vlinkId, ospfRespMap)
		}
	}

	_, nwAreaKey, _, _ := ospfGetRouterAreaNetworkObject(inParams, vrfName, "", "")
	if nwAreaKey != "" {
		log.Info("ospf_auto_create_ospf_router_area: nwAreaKey ", nwAreaKey)
		keyFields := strings.Split(nwAreaKey, "|")

		oldAreaId = areaId
		areaId = ""

		// vrfName | areaId | nw
		if len(keyFields) >= 3 {
			//req is add area+1
			vrfName = keyFields[0]
			if keyFields[1] != oldAreaId {
				areaId = keyFields[1]
			}
		}

		if areaId != "" {
			log.Infof("ospf_auto_create_ospf_router_area: Auto create area %s in vrf %s", areaId, vrfName)
			create_ospf_area_entry(inParams, vrfName, areaId, ospfRespMap)
		}
		areaId = oldAreaId
	}

	_, polAreaKey, _, _ := ospfGetRouterPolicyRangeObject(inParams, vrfName, "", "")
	if polAreaKey != "" {
		log.Info("ospf_auto_create_ospf_router_area: polAreaKey ", polAreaKey)
		keyFields := strings.Split(polAreaKey, "|")

		oldAreaId = areaId
		areaId = ""

		// vrfName | srcArea | range
		if len(keyFields) >= 3 {
			//req is add srcarea+1
			vrfName = keyFields[0]
			if keyFields[1] != oldAreaId {
				areaId = keyFields[1]
			}
		}

		if areaId != "" {
			log.Infof("ospf_auto_create_ospf_router_area: Auto create area %s in vrf %s", areaId, vrfName)
			create_ospf_area_entry(inParams, vrfName, areaId, ospfRespMap)
		}
	}

	log.Info("ospf_auto_create_ospf_router_area: done")
	return nil
}

func validate_ospf_router_area_delete(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) error {

	if inParams.oper != DELETE {
		log.Info("validate_ospf_router_area_delete: non delete operation")
		return nil
	}

	pathInfo := NewPathInfo(inParams.uri)
	rcvdUri, uriErr := getOspfUriPath(inParams)
	if uriErr != nil {
		log.Info("validate_ospf_router_area_delete: getOspfUriPath error ", uriErr)
		return nil
	}

	ospfObj, ospfVrfName, _, _ := ospfGetRouterObject(inParams, "")
	if ospfObj == nil || ospfVrfName == "" {
		log.Info("validate_ospf_router_area_delete: get ospf router info failed ")
		return nil
	}

	areaDelete := false
	if strings.HasSuffix(rcvdUri, "areas") ||
		strings.HasSuffix(rcvdUri, "areas/area") ||
		strings.HasSuffix(rcvdUri, "areas/area/config") {
		areaDelete = true
	}

	if !areaDelete {
		log.Info("validate_ospf_router_area_delete: rcvdUri not area delete ")
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
	if ifAreaPresent {
		log.Info("validate_ospf_router_area_delete: Area config present under interface")
		return tlerr.New(errStr)
	}

	nwAreaPresent, _ := ospf_router_area_network_present(inParams, ospfVrfName, ospfAreaId)
	if nwAreaPresent {
		log.Info("validate_ospf_router_area_delete: Area config present under network config")
		return tlerr.New(errStr)
	}

	vlAreaPresent, _ := ospf_router_area_virtual_link_present(inParams, ospfVrfName, ospfAreaId)
	if vlAreaPresent {
		log.Info("validate_ospf_router_area_delete: Area config present under virtual link config")
		return tlerr.New(errStr)
	}

	vlmdAreaPresent, _ := ospf_router_area_vlmd_auth_present(inParams, ospfVrfName, ospfAreaId)
	if vlmdAreaPresent {
		log.Info("validate_ospf_router_area_delete: Area config present under virtual link md config")
		return tlerr.New(errStr)
	}

	arAreaPresent, _ := ospf_router_area_address_range_present(inParams, ospfVrfName, ospfAreaId)
	if arAreaPresent {
		log.Info("validate_ospf_router_area_delete: Area config present under address range config")
		return tlerr.New(errStr)
	}

	log.Info("validate_ospf_router_area_delete: dependent are configs not present ")
	return nil
}

func delete_ospf_router_redistribute_entry(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) error {
	if inParams.oper != DELETE {
		log.Info("delete_ospf_router_redistribute_entry: non delete operation")
		return nil
	}

	log.Info("delete_ospf_router_redistribute_entry: inParams.uri ", inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	rcvdUri, uriErr := getOspfUriPath(inParams)
	if uriErr != nil {
		log.Info("delete_ospf_router_redistribute_entry: getOspfUriPath error ", uriErr)
		return nil
	}

	log.Info("delete_ospf_router_redistribute_entry: rcvdUri ", rcvdUri)

	ospfObj, ospfVrfName, _, _ := ospfGetRouterObject(inParams, "")
	if ospfObj == nil || ospfVrfName == "" {
		log.Info("delete_ospf_router_redistribute_entry: ospf router not in request")
		return nil
	}

	if !strings.Contains(rcvdUri, "protocols/protocol/ospfv2/global") {
		log.Info("delete_ospf_router_redistribute_entry: rcvdUri not ospfv2/global")
		return nil
	}

	if !strings.Contains(rcvdUri, "route-distribution-policies") {
		log.Info("delete_ospf_router_redistribute_entry: rcvdUri not distribute-list")
		return nil
	}

	redistProtocol := pathInfo.Var("protocol")
	redistDirection := pathInfo.Var("direction")

	if len(redistProtocol) == 0 {
		log.Info("delete_ospf_router_redistribute_entry: protocol name Missing")
		return nil
	}

	if len(redistDirection) == 0 {
		log.Info("delete_ospf_router_redistribute_entry: direction is Missing")
		return nil
	}

	if redistDirection != "IMPORT" {
		log.Info("delete_ospf_router_redistribute_entry: not import direction")
		return nil
	}

	fieldNameList := []string{"BGP", "STATIC", "KERNEL", "DIRECTLY_CONNECTED"}
	validProtocol := false
	for _, fieldName := range fieldNameList {
		if redistProtocol == fieldName {
			validProtocol = true
			break
		}
	}

	if !validProtocol {
		log.Info("delete_ospf_router_redistribute_entry: not valid protocol")
		return nil
	}

	redistTableName := "OSPFV2_ROUTER_DISTRIBUTE_ROUTE"
	redistTableKey := ospfVrfName + "|" + redistProtocol + "|" + redistDirection

	err := ospf_delete_table_entry(inParams, redistTableName, redistTableKey, ospfRespMap)
	if err != nil {
		log.Info("delete_ospf_router_redistribute_entry: entry delete failed ", err)
		return err
	}

	log.Info("delete_ospf_router_redistribute_entry: entry delete for ", redistTableKey)
	return nil
}

func create_ospf_area_vlink_entry(inParams *XfmrParams, vrfName string, areaId string, vlinkId string, ospfRespMap *map[string]map[string]db.Value) error {
	log.Infof("create_ospf_area_vlink_entry: vrfName %s areaId %s vlinkId %s", vrfName, areaId, vlinkId)
	if vrfName == "" {
		errStr := "Empty vrf name"
		log.Info("create_ospf_area_vlink_entry: ", errStr)
		return errors.New(errStr)
	}

	if areaId == "" {
		errStr := "Empty area id"
		log.Info("create_ospf_area_vlink_entry: ", errStr)
		return errors.New(errStr)
	}

	if vlinkId == "" {
		errStr := "Empty vlink id"
		log.Info("create_ospf_area_vlink_entry: ", errStr)
		return errors.New(errStr)
	}

	vlTblName := "OSPFV2_ROUTER_AREA_VIRTUAL_LINK"
	vlTblKey := vrfName + "|" + areaId + "|" + vlinkId

	found, _ := ospf_table_entry_present(inParams, vlTblName, vlTblKey)
	if found {
		log.Infof("create_ospf_area_vlink_entry: entry %s already exists ", vlTblKey)
		return nil
	}

	err := ospf_update_table_entry(inParams, inParams.oper, vlTblName, vlTblKey, "enable", "true", ospfRespMap)
	if err != nil {
		log.Info("create_ospf_area_vlink_entry: create vl failed for ", vlTblKey)
		return err
	}

	log.Info("create_ospf_area_vlink_entry: create vl success for ", vlTblKey)
	return nil
}

func ospf_delete_all_vlmd_auth_config(inParams *XfmrParams, vrfName string, areaId string, linkId string, ospfRespMap *map[string]map[string]db.Value) error {
	var err error
	log.Infof("ospf_delete_all_vlmd_auth_config: vrf %s areaId %s linkId %s.", vrfName, areaId, linkId)

	vlAuthTblName := "OSPFV2_ROUTER_AREA_VLMD_AUTHENTICATION"
	vlAuthTblKey := vrfName + "|" + areaId + "|" + linkId + "|" + "*"

	err = ospf_delete_table_entry(inParams, vlAuthTblName, vlAuthTblKey, ospfRespMap)
	if err != nil {
		log.Info("ospf_delete_all_vlmd_auth_config: entry delete failed ", err)
	}

	log.Info("ospf_delete_all_vlmd_auth_config: success for ", vlAuthTblKey)
	return nil
}

func validate_ospf_router_vlmd_auth_delete(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) error {
	var err error
	if inParams.oper != DELETE {
		log.Info("validate_ospf_router_vlmd_auth_delete: non delete operation")
		return nil
	}

	vrfName := ""
	areaId := ""
	vlinkId := "*"

	_, vlinkKey, _, _ := ospfGetRouterAreaVlinkMdAuthObject(inParams, vrfName, areaId, "", 0)
	if vlinkKey != "" {
		log.Info("validate_ospf_router_vlmd_auth_delete: vlinkKey ", vlinkKey)
		keyFields := strings.Split(vlinkKey, "|")

		if len(keyFields) >= 2 {
			//req is del area
			vrfName = keyFields[0]
			areaId = keyFields[1]

			if len(keyFields) == 3 {
				//req is delete vlink
				vlinkId = keyFields[2]
			}
		}

		if vrfName != "" && areaId != "" {
			err = ospf_delete_all_vlmd_auth_config(inParams, vrfName, areaId, vlinkId, ospfRespMap)
			if err != nil {
				log.Info("validate_ospf_router_vlmd_auth_delete: clmd config del failed ", err)
				return err
			}
		} else {
			log.Info("validate_ospf_router_vlmd_auth_delete: inParams.key empty")
		}
	}

	return nil
}

func ospf_delete_all_pass_intf_config(inParams *XfmrParams, vrfName string, ifName string, ifAddr string, ospfRespMap *map[string]map[string]db.Value) error {
	var err error
	log.Infof("ospf_delete_all_pass_intf_config: vrf %s ifName %s ifAddr %s.", vrfName, ifName, ifAddr)

	passIntfTblName := "OSPFV2_ROUTER_PASSIVE_INTERFACE"
	passIntfTblKey := vrfName + "|" + ifName + "|" + ifAddr

	err = ospf_delete_table_entry(inParams, passIntfTblName, passIntfTblKey, ospfRespMap)
	if err != nil {
		log.Info("ospf_delete_all_pass_intf_config: entry delete failed ", err)
	}

	log.Info("ospf_delete_all_pass_intf_config: success for ", passIntfTblKey)
	return nil
}

func ospf_add_del_passive_interface_config(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) error {

	log.Infof("ospf_add_del_passive_interface_config: post xfmr operation %d.", inParams.oper)

	globalObj, objKey, ending, _ := ospfGetRouterGlobalObject(inParams, "")
	if globalObj == nil || ending {
		log.Info("ospf_add_del_passive_interface_config: not ospf global obj request")
		return nil
	}

	objKeyList := strings.Split(objKey, "|")
	if len(objKeyList) < 1 {
		log.Info("ospf_add_del_passive_interface_config: invalid obj key", objKey)
		return nil
	}

	vrfName := objKeyList[0]
	if vrfName == "" {
		log.Info("ospf_add_del_passive_interface_config: empty vrf name")
		return nil
	}

	ospfTblName := "OSPFV2_ROUTER"
	ospfTblKey := vrfName
	fieldName := "passive-interface-default"

	dfltCfgPresent, fieldValue, _ := ospf_get_table_entry_field(inParams, ospfTblName, ospfTblKey, fieldName)
	log.Infof("ospf_add_del_passive_interface_config: dfltCfgPresent %t fieldValue %s.", dfltCfgPresent, fieldValue)

	currPassIfDefault := false
	if dfltCfgPresent && fieldValue == "" {
		dfltCfgPresent = false
	}
	if dfltCfgPresent && fieldValue == "true" {
		currPassIfDefault = true
	}
	log.Infof("ospf_add_del_passive_interface_config: dfltCfgPresent %t currPassIfDefault %t", dfltCfgPresent, currPassIfDefault)

	if inParams.oper == UPDATE || inParams.oper == CREATE || inParams.oper == REPLACE {

		if globalObj.Config != nil && globalObj.Config.PassiveInterfaceDefault != nil {
			log.Info("ospf_add_del_passive_interface_config: pass intf default add request")

			newPassIfDefault := *globalObj.Config.PassiveInterfaceDefault
			log.Infof("ospf_add_del_passive_interface_config: curr %t new %t", currPassIfDefault, newPassIfDefault)

			passIntfTblName := "OSPFV2_ROUTER_PASSIVE_INTERFACE"
			passIntfTblKey := vrfName + "|*|*"

			if dfltCfgPresent {
				if currPassIfDefault == newPassIfDefault {
					log.Info("ospf_add_del_passive_interface_config: config same as existing")
					return nil
				}
			}

			passIfsPresent, _ := ospf_table_entry_present(inParams, passIntfTblName, passIntfTblKey)
			if passIfsPresent {
				errStr := "Please unconfigure all passive interface configurations first"
				log.Info("ospf_add_del_passive_interface_config: ", errStr)
				return tlerr.New(errStr)
			}

			log.Info("ospf_add_del_passive_interface_config: pass if default allowed")
			return nil
		}

		if globalObj.PassiveInterfaces != nil {
			log.Info("ospf_add_del_passive_interface_config: pass intf name add request")

			passIntfObj, objKey, ending, _ := ospfGetRouterPassiveIntfObject(inParams, "", "", "")
			if passIntfObj == nil || ending {
				log.Info("ospf_add_del_passive_interface_config: pass intf object not found")
				return nil
			}

			if passIntfObj.Config == nil {
				log.Info("ospf_add_del_passive_interface_config: pass intf object config not found")
				return nil
			}

			passIfTblName := "OSPFV2_ROUTER_PASSIVE_INTERFACE"
			passIfTblKey := objKey
			fieldName := "non-passive"

			npCfgPresent, fieldValue, _ := ospf_get_table_entry_field(inParams, passIfTblName, passIfTblKey, fieldName)
			log.Infof("ospf_add_del_passive_interface_config: npCfgPresent %t nonpassive %s.", npCfgPresent, fieldValue)

			currNonPassive := false
			if npCfgPresent && fieldValue == "" {
				npCfgPresent = false
			}
			if npCfgPresent && fieldValue == "true" {
				currNonPassive = true
			}
			log.Infof("ospf_add_del_passive_interface_config: npCfgPresent %t currNonPassive %t", npCfgPresent, currNonPassive)

			newNonPassive := false
			if passIntfObj.Config.NonPassive != nil {
				newNonPassive = *passIntfObj.Config.NonPassive
				log.Info("ospf_add_del_passive_interface_config: newNonPassive ", newNonPassive)
			}

			if npCfgPresent && currNonPassive == newNonPassive {
				log.Info("ospf_add_del_passive_interface_config: interface passive type same ", newNonPassive)
				return nil
			}

			if dfltCfgPresent && currPassIfDefault {
				if newNonPassive {
					log.Info("ospf_add_del_passive_interface_config: setting interface type to non-passive")
				} else {
					log.Info("ospf_add_del_passive_interface_config: setting interface type to passive")
					errStr := "Only non passive type config is allowed with passive-interface default"
					log.Info("ospf_add_del_passive_interface_config: ", errStr)
					return tlerr.New(errStr)
				}
			} else {
				if newNonPassive {
					errStr := "Non Passive interface config allowed only with passive-interface default"
					log.Info("ospf_add_del_passive_interface_config: ", errStr)
					return tlerr.New(errStr)
				} else {
					log.Info("ospf_add_del_passive_interface_config: setting interface type to passive")
				}
			}

			if passIntfObj.Config.NonPassive == nil {
				log.Info("ospf_add_del_passive_interface_config: auto add non-passive as false")
				err := ospf_update_table_entry(inParams, inParams.oper, passIfTblName, passIfTblKey, fieldName, "false", ospfRespMap)
				if err != nil {
					errStr := "Auto update of nonpassive attribute as false failed"
					log.Info("ospf_add_del_passive_interface_config: ", err)
					return tlerr.New(errStr)
				}
			}

			log.Info("ospf_add_del_passive_interface_config: passive interface update allowed")
		}

	} else if inParams.oper == DELETE {
		log.Info("ospf_add_del_passive_interface_config: unconfig passive intf default")

		rcvdUri, uriErr := getOspfUriPath(inParams)
		if uriErr != nil {
			log.Info("ospf_add_del_passive_interface_config: getOspfUriPath failed ", uriErr)
			return nil
		}

		if strings.HasSuffix(rcvdUri, "ospfv2/global/config/passive-interface-default") {
			log.Info("ospf_add_del_passive_interface_config: pass intf default del request")

			if dfltCfgPresent {
				passIntfTblName := "OSPFV2_ROUTER_PASSIVE_INTERFACE"
				passIntfTblKey := vrfName + "|*|*"

				passIfsPresent, _ := ospf_table_entry_present(inParams, passIntfTblName, passIntfTblKey)
				if passIfsPresent {
					errStr := "Please unconfigure all passive interface configurations first"
					log.Info("ospf_add_del_passive_interface_config: ", errStr)
					return tlerr.New(errStr)
				}

				err := ospf_delete_all_pass_intf_config(inParams, vrfName, "*", "*", ospfRespMap)
				if err != nil {
					log.Info("ospf_add_del_passive_interface_config: passive intf config del failed ", err)
					return err
				}
			}
		}

		if strings.Contains(rcvdUri, "ospfv2/global/passive-interfaces") {
			log.Info("ospf_add_del_passive_interface_config: pass intf name  del request")

			if strings.HasSuffix(rcvdUri, "config/non-passive") {
				errStr := "Passive interface type delete not allowed, try deleting passive interface"
				log.Info("ospf_add_del_passive_interface_config: ", errStr)
				return tlerr.New(errStr)
			}

			log.Info("ospf_add_del_passive_interface_config: pasive interface deleted allowed")
		}
	}

	return nil
}

func ospf_encrypt_string(decryptedStr string, keyStr string) (string, error) {
	log.Info("ospf_encrypt_string: descriptedStr ", decryptedStr)
	if keyStr == "" {
		keyStr = "78ej6t3p8024s2r5"
	}

	key := []byte(keyStr)
	data := []byte(decryptedStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	encryptedStr := base64.RawURLEncoding.EncodeToString(ciphertext)

	log.Info("ospf_encrypt_string: encryptedStr ", encryptedStr)
	return encryptedStr, nil
}

func ospf_decrypt_string(encryptedStr string, keyStr string) (string, error) {
	log.Info("ospf_decrypt_string: encryptedStr ", encryptedStr)
	if keyStr == "" {
		keyStr = "78ej6t3p8024s2r5"
	}

	key := []byte(keyStr)
	ciphertext, err := base64.RawURLEncoding.DecodeString(encryptedStr)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	decryptedStr := string(ciphertext)
	log.Info("ospf_decrypt_string: decryptedStr ", decryptedStr)
	return decryptedStr, nil
}

func ospf_remove_escape_sequence(inStr string) string {
	log.Info("ospf_remove_escape_sequence: ", inStr)
	outStr := inStr
	escapeChars := false
	if escapeChars {
		//strings.Replace(inStr, "\\", "", -1)
		maxLen := 32
		outSlice := make([]byte, maxLen)
		checkSlice := []byte("\\#")
		inStrLen := len(inStr)
		inSlice := []byte(inStr)
		log.Info("ospf_remove_escape_sequence: inSlice ", inSlice)
		j := 0
		for i := 0; i < inStrLen && i < maxLen; i++ {
			escapeByte := false
			if i+1 < inStrLen {
				if inSlice[i] == checkSlice[0] {
					for k := range checkSlice {
						if inSlice[i+1] == checkSlice[k] {
							outSlice[j] = inSlice[i+1]
							j++
							i++
							escapeByte = true
							break
						}
					}
				}
			}
			if !escapeByte {
				outSlice[j] = inSlice[i]
				j++
			}
		}

		log.Info("ospf_remove_escape_sequence: outSlice ", outSlice)
		outStr = fmt.Sprintf("%s", outSlice[:j])
	}

	log.Infof("ospf_remove_escape_sequence: fmt outStr %s Length %d", outStr, len(outStr))
	return outStr
}

func ospf_get_password_max_length() int {
	passwdMaxLen := 16
	log.Info("ospf_get_password_max_length: passwdMaxLen ", passwdMaxLen)
	return passwdMaxLen
}

func ospf_get_min_encryption_length() int {
	minEncLen := 2 * ospf_get_password_max_length()
	log.Info("ospf_get_min_encryption_length: minEncLen ", minEncLen)
	return minEncLen
}

func ospf_encrypt_password(passwordStr string, localEncryption bool) (string, error) {

	log.Infof("ospf_encrypt_password: passwd %s encrption local %t", passwordStr, localEncryption)

	if passwordStr == "" {
		errStr := "Password cannot be empty string"
		log.Info("ospf_encrypt_password: ", errStr)
		return "", tlerr.New(errStr)
	}

	//localEncryption = true
	if localEncryption {
		encryptedPasswd, err := ospf_encrypt_string(passwordStr, "")
		if err != nil {
			errStr := "Failed to create local password encryption"
			log.Info("ospf_encrypt_password: ", err)
			return "", tlerr.New(errStr)
		}

		ospf_decrypt_string(encryptedPasswd, "")
		log.Info("ospf_encrypt_password: locally encrypted passwd ", encryptedPasswd)
		return encryptedPasswd, nil
	}

	passwdMaxLen := ospf_get_password_max_length()
	cmd := fmt.Sprintf("show bgp encrypt %s max-length %d json", passwordStr, passwdMaxLen)
	jsonOutput, cmdErr := exec_vtysh_cmd(cmd)
	if cmdErr != nil {
		errStr := "Failed to generate password encryption"
		log.Info("ospf_encrypt_password: " + errStr)
		return "", tlerr.New(errStr)
	}

	encryptedPasswd, ok := jsonOutput["Encrypted_string"].(string)
	if !ok {
		errStr := "Failed to generate or read password encryption"
		log.Info("ospf_encrypt_password: " + errStr)
		return "", tlerr.New(errStr)
	}

	log.Info("ospf_encrypt_password: frr encrypted passwd ", encryptedPasswd)
	return encryptedPasswd, nil
}
