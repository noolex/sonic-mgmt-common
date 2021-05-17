//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Broadcom.
// The term Broadcom refers to Broadcom Inc. and/or its subsidiaries.
//
//////////////////////////////////////////////////////////////////////////

package transformer

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("YangToDb_ospfv2_interface_subtree_xfmr", YangToDb_ospfv2_interface_subtree_xfmr)
	XlateFuncBind("DbToYang_ospfv2_interface_subtree_xfmr", DbToYang_ospfv2_interface_subtree_xfmr)
	XlateFuncBind("Subscribe_ospfv2_interface_subtree_xfmr", Subscribe_ospfv2_interface_subtree_xfmr)
	XlateFuncBind("YangToDb_ospfv2_interface_md_auth_subtree_xfmr", YangToDb_ospfv2_interface_md_auth_subtree_xfmr)
	XlateFuncBind("DbToYang_ospfv2_interface_md_auth_subtree_xfmr", DbToYang_ospfv2_interface_md_auth_subtree_xfmr)
	XlateFuncBind("Subscribe_ospfv2_interface_md_auth_subtree_xfmr", Subscribe_ospfv2_interface_md_auth_subtree_xfmr)
}

func getInterfaceNameSplits(inputIfName string) (string, string) {
	ifName := inputIfName
	subIfStr := ""

	if strings.Contains(inputIfName, ".") {
		ifNameParts := strings.Split(inputIfName, ".")
		ifName = ifNameParts[0]
		if len(ifNameParts) >= 2 {
			subIfStr = ifNameParts[1]
		}
	}

	log.Infof("getInterfaceNameSplits: inputIfName %s ifName %s subIfStr %s",
		inputIfName, ifName, subIfStr)

	return ifName, subIfStr
}

func getUriIfName(inputUri string) (string, string, string, uint32, error) {

	pathInfo := NewPathInfo(inputUri)
	ifName := pathInfo.Var("name")
	subIfStr := pathInfo.Var("index")

	if ifName == "" {
		errStr := "URI does not have interface name"
		log.Info("getUriIfName: " + errStr)
		return "", "", "", 0, tlerr.New(errStr)
	}

	uriIfName := ifName
	subIfIndex := uint32(0)

	if subIfStr != "0" && subIfStr != "" {
		subIfIndex1, _ := strconv.Atoi(subIfStr)
		subIfIndex = uint32(subIfIndex1)
		uriIfName = ifName + "." + subIfStr
	} else {
		subIfStr = ""
	}

	log.Infof("getUriIfName: uriIfName %s ifName %s subIfStr %s subIfIndex %d.",
		uriIfName, ifName, subIfStr, subIfIndex)

	return uriIfName, ifName, subIfStr, subIfIndex, nil
}

func getInParamIfName(inParams *XfmrParams) (string, string, string, uint32, error) {
	//for now uru, later try to get it from ygot object too
	return getUriIfName(inParams.uri)
}

func getNativeInterfaceName(inputIfName string) (string, string, string, uint32, error) {
	var errStr string

	if inputIfName == "" {
		errStr = "Empty interface name received"
		log.Infof("getNativeInterfaceName: %s.", errStr)
		return "", "", "", 0, errors.New(errStr)
	}

	nonPhyIntfPrefixes := []string{"Vlan", "VLAN", "vlan", "VLINK"}

	for _, intfPrefix := range nonPhyIntfPrefixes {
		if strings.HasPrefix(inputIfName, intfPrefix) {
			log.Infof("getNativeInterfaceName: non physical interface %s.", inputIfName)
			return inputIfName, inputIfName, "", 0, nil
		}
	}

	if !utils.IsAliasModeEnabled() {
		if strings.Contains(inputIfName, "/") {
			errStr = "Invalid portname " + inputIfName + ", standard interface naming not enabled"
			log.Infof("getNativeInterfaceName: %s.", errStr)
			return inputIfName, inputIfName, "", 0, errors.New(errStr)
		}
	}

	nativeIfNamePtr := utils.GetNativeNameFromUIName(&inputIfName)
	if nativeIfNamePtr == nil {
		errStr = "Interface native name conversion failed"
		log.Infof("getNativeInterfaceName: %s.", errStr)
		return inputIfName, inputIfName, "", 0, errors.New(errStr)
	}

	nativeIfName := *nativeIfNamePtr

	ifName, subIfStr := getInterfaceNameSplits(nativeIfName)

	subIfIndex := uint32(0)
	if subIfStr != "0" && subIfStr != "" {
		subIfIndex1, _ := strconv.Atoi(subIfStr)
		subIfIndex = uint32(subIfIndex1)
	} else {
		subIfStr = ""
	}

	backVerify := false
	if backVerify {
		uriFullIfName, uriIfName, _, _, err := getUserInterfaceName(nativeIfName)
		if err != nil {
			log.Error("getNativeInterfaceName: Interface name back conversion error ", err)
			return inputIfName, inputIfName, "", 0, err
		}

		log.Infof("getNativeInterfaceName: back verify uriFullIfName %s uriIfName %s ",
			uriFullIfName, uriIfName)

		if uriFullIfName != inputIfName {
			errStr = "Name conversion back verify mismatch, " + uriFullIfName + " vs " + "inputIfName"
			log.Error("getNativeInterfaceName: ", errStr)
			return inputIfName, inputIfName, "", 0, errors.New(errStr)
		}
	}

	log.Infof("getNativeInterfaceName: inputIfName %s nativeIfName %s ifName %s subIfStr %s subIfIndex %d.",
		inputIfName, nativeIfName, ifName, subIfStr, subIfIndex)

	return nativeIfName, ifName, subIfStr, subIfIndex, nil
}

func getUserInterfaceName(inputIfName string) (string, string, string, uint32, error) {
	var errStr string

	if inputIfName == "" {
		errStr = "Empty interface name received"
		log.Infof("getUserInterfaceName: %s.", errStr)
		return inputIfName, "", "", 0, errors.New(errStr)
	}

	nonPhyIntfPrefixes := []string{"Vlan", "VLAN", "vlan", "VLINK"}
	for _, intfPrefix := range nonPhyIntfPrefixes {
		if strings.HasPrefix(inputIfName, intfPrefix) {
			log.Infof("getUserInterfaceName: non physical interface %s, return same name.", inputIfName)
			return inputIfName, inputIfName, "", 0, nil
		}
	}

	userIfNamePtr := utils.GetUINameFromNativeName(&inputIfName)
	if userIfNamePtr == nil {
		errStr = "Interface user interface name conversion failed"
		log.Infof("getUserInterfaceName: %s.", errStr)
		return inputIfName, inputIfName, "", 0, errors.New(errStr)
	}

	uiIfName := *userIfNamePtr

	//hack for bug in utils.GetUINameFromNativeName when UI name passed
	uiIfName = strings.ReplaceAll(uiIfName, "Etherneternet", "Ethernet")
	uiIfName = strings.ReplaceAll(uiIfName, "PortChannelrtChannel", "PortChannel")

	ifName, subIfStr := getInterfaceNameSplits(uiIfName)

	subIfIndex := uint32(0)
	if subIfStr != "0" && subIfStr != "" {
		subIfIndex1, _ := strconv.Atoi(subIfStr)
		subIfIndex = uint32(subIfIndex1)
	} else {
		subIfStr = ""
	}

	//log.V(3).Infof
	log.Infof("getUserInterfaceName: inputIfName %s uiIfName %s ifName %s subIfStr %s subIfIndex %d",
		inputIfName, uiIfName, ifName, subIfStr, subIfIndex)

	//returns name like Ethernet28.10
	return uiIfName, ifName, subIfStr, subIfIndex, nil
}

func ospfGetIntfOspfObject(inParams *XfmrParams, inIfName string) (*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2, string, bool, error) {

	var intfOspfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2
	log.Infof("ospfGetIntfOspfObject: get ospf interface %s.", inIfName)
	objKey := ""

	_, uriIfName, subIfStr, subIfIndex, err := getInParamIfName(inParams)
	if err != nil {
		log.Info("ospfGetIntfOspfObject: uri and native if get failed")
		return nil, objKey, false, err
	}

	objKey = uriIfName
	if subIfStr != "" {
		objKey = uriIfName + "." + subIfStr
	}

	if inIfName != "" && uriIfName != inIfName {
		errStr := "Uri interface is " + uriIfName + "and not " + inIfName
		log.Info("ospfGetIntfOspfObject: " + errStr)
		return nil, objKey, false, tlerr.New(errStr)
	}

	routedVlan := false
	if strings.HasPrefix(uriIfName, "Vlan") {
		routedVlan = true
	}

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		errStr := "IntfsObj/interface list is empty for " + uriIfName
		log.Info("ospfGetIntfOspfObject: " + errStr)
		return nil, objKey, false, tlerr.New(errStr)
	}

	if _, ok := intfsObj.Interface[uriIfName]; !ok {
		errStr := "Interface entry not found in Ygot tree, ifname: " + uriIfName
		log.Info("ospfGetIntfOspfObject : " + errStr)
		return nil, objKey, false, tlerr.New(errStr)
	}

	intfObj := intfsObj.Interface[uriIfName]

	if !routedVlan {
		if intfObj.Subinterfaces == nil {
			log.Info("ospfGetIntfOspfObject: SubInterfaces node is not set")
			return nil, objKey, true, nil
		}

		if _, ok := intfObj.Subinterfaces.Subinterface[subIfIndex]; !ok {
			log.Info("ospfGetIntfOspfObject: SubInterface node is not set")
			return nil, objKey, true, nil
		}

		subIntfObj := intfObj.Subinterfaces.Subinterface[subIfIndex]
		ipv4Obj := subIntfObj.Ipv4

		if ipv4Obj == nil {
			log.Info("ospfGetIntfOspfObject: SubInterface IPv4 node is not set")
			return nil, objKey, true, nil
		}

		intfOspfObj = ipv4Obj.Ospfv2
	}

	if routedVlan {
		if intfObj.RoutedVlan == nil {
			log.Info("ospfGetIntfOspfObject: RoutedVlan not set")
			return nil, objKey, true, nil
		}

		ipv4Obj := intfObj.RoutedVlan.Ipv4
		if (ipv4Obj) == nil {
			log.Info("ospfGetIntfOspfObject: RoutedVlan IPv4 node is not set")
			return nil, objKey, true, nil
		}

		intfOspfObj = (*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2)(unsafe.Pointer(ipv4Obj.Ospfv2))
	}

	if intfOspfObj == nil {
		log.Info("ospfGetIntfOspfObject: Ospf object not set")
		return nil, objKey, true, nil
	}

	ending := false
	if intfOspfObj.IfAddresses == nil {
		ending = true
	}

	log.Infof("ospfGetIntfOspfObject: found intf %s ending %t", uriIfName, ending)
	return intfOspfObj, objKey, ending, nil
}

func ospfGetIntfOspfAddresssList(inParams *XfmrParams, ifName string) (map[string]*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses, string, bool, error) {
	log.Infof("ospfGetIntfOspfAddresssList: get interface %s address list", ifName)

	intfOspfObj, objKey, ending, err := ospfGetIntfOspfObject(inParams, ifName)
	if intfOspfObj == nil {
		return nil, objKey, ending, err
	}

	if ending {
		log.Info("ospfGetIntfOspfAddresssList: Intf Ospf object ends")
		return nil, objKey, ending, nil
	}

	intAddrsListObj := intfOspfObj.IfAddresses
	if len(intAddrsListObj) == 0 {
		ending = true
	}

	log.Infof("ospfGetIntfOspfAddresssList: found entry %s ending %t", objKey, ending)
	return intAddrsListObj, objKey, ending, nil
}

func ospfGetIntfOspfAddresssObject(inParams *XfmrParams, ifName string, ifAddress string) (*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses, string, bool, error) {
	log.Infof("ospfGetIntfOspfAddresssObject: get interface %s address list", ifName)
	ending := false

	intfAddrsListObj, objKey, ending, err := ospfGetIntfOspfAddresssList(inParams, ifName)
	if len(intfAddrsListObj) == 0 {
		log.Info("ospfGetIntfOspfAddresssObject: Intf Ospf address list object ends")
		return nil, objKey, ending, err
	}

	if ending {
		log.Info("ospfGetIntfOspfAddresssObject: Intf Ospf address list object ends")
		return nil, objKey, ending, nil
	}

	ending = false
	var intfAddrObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses
	for intfAddrKey, intfAddrObjElt := range intfAddrsListObj {
		if ifAddress != "" {
			if intfAddrKey == ifAddress {
				intfAddrObj = intfAddrObjElt
				break
			}
		} else if intfAddrObjElt != nil {
			intfAddrObj = intfAddrObjElt
			break
		}
	}

	if intfAddrObj == nil {
		if ifAddress != "" {
			log.Info("ospfGetIntfOspfAddresssObject: Requested Intf Ospf address not present")
			return nil, objKey, false, nil
		}

		ending = true
		log.Info("ospfGetIntfOspfAddresssObject: Intf Ospf address not present in address list")
		return nil, objKey, ending, nil
	}

	ending = false
	if intfAddrObj.Config == nil &&
		intfAddrObj.MdAuthentications == nil {
		ending = true
	}

	log.Infof("ospfGetIntfOspfAddresssObject: found entry %s ending %t", objKey, ending)
	return intfAddrObj, objKey, ending, nil
}

func ospfFillIntfOspfObject(inParams *XfmrParams, uriIfName string, subIfStr string) (*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2, string, error) {
	var err error
	var ok bool

	if uriIfName == "" {
		errStr := "Empty uri interface name"
		log.Info("ospfFillIntfOspfObject:", errStr)
		return nil, "", tlerr.New(errStr)
	}

	var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
	var subIntfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
	var ospfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2

	intfsObj := getIntfsRoot(inParams.ygRoot)

	if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
		var ok bool = false
		if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
			intfObj, _ = intfsObj.NewInterface(uriIfName)
		}
		ygot.BuildEmptyTree(intfObj)
		if intfObj.Subinterfaces == nil {
			ygot.BuildEmptyTree(intfObj.Subinterfaces)
		}
	} else {
		// intfsObj nil, create one
		ygot.BuildEmptyTree(intfsObj)
		intfObj, _ = intfsObj.NewInterface(uriIfName)
		ygot.BuildEmptyTree(intfObj)
	}

	routedVlan := false
	if strings.HasPrefix(uriIfName, "Vlan") {
		routedVlan = true
	}

	if routedVlan {
		if intfObj.RoutedVlan == nil {
			errStr := "Ipv4 doesnt have RoutedVlan object!"
			log.Info("ospfFillIntfOspfObject:", errStr)
			intfObj.RoutedVlan = new(ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan)
			ygot.BuildEmptyTree(intfObj.RoutedVlan)
		}

		routedVlanObj := intfObj.RoutedVlan

		if routedVlanObj.Ipv4 == nil {
			errStr := "Routed vlan doesnt have ipv4 object!"
			log.Info("ospfFillIntfOspfObject:", errStr)
			routedVlanObj.Ipv4 = new(ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4)
			ygot.BuildEmptyTree(routedVlanObj.Ipv4)
		}
		ipv4Obj := routedVlanObj.Ipv4

		if ipv4Obj.Ospfv2 == nil {
			errStr := "Ipv4 doesnt have Ospfv2 object!"
			log.Info("ospfFillIntfOspfObject:", errStr)
			ipv4Obj.Ospfv2 = new(ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2)
			ygot.BuildEmptyTree(ipv4Obj.Ospfv2)
		}

		ospfObj = (*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2)(unsafe.Pointer(ipv4Obj.Ospfv2))

	} else {

		subIfIndex := uint32(0)
		if subIfStr != "0" && subIfStr != "" {
			subIfIndex1, _ := strconv.Atoi(subIfStr)
			subIfIndex = uint32(subIfIndex1)
		}

		if subIntfObj, ok = intfObj.Subinterfaces.Subinterface[subIfIndex]; !ok {
			subIntfObj, err = intfObj.Subinterfaces.NewSubinterface(subIfIndex)
			if err != nil {
				log.Error("ospfFillIntfOspfObject: Creation of subinterface subtree failed!")
				return nil, "", err
			}
			ygot.BuildEmptyTree(subIntfObj)
		}

		if subIntfObj.Ipv4 == nil {
			errStr := "Subinterface doesnt have ipv4 object!"
			log.Info("ospfFillIntfOspfObject:", errStr)
			subIntfObj.Ipv4 = new(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4)
			ygot.BuildEmptyTree(subIntfObj.Ipv4)
		}

		ipv4Obj := subIntfObj.Ipv4
		if ipv4Obj.Ospfv2 == nil {
			errStr := "Ipv4 doesnt have Ospfv2 object!"
			log.Info("ospfFillIntfOspfObject:", errStr)
			ipv4Obj.Ospfv2 = new(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2)
			ygot.BuildEmptyTree(ipv4Obj.Ospfv2)
		}

		ospfObj = ipv4Obj.Ospfv2
	}

	log.Info("ospfFillIntfOspfObject: filled intf ", uriIfName)
	return ospfObj, uriIfName, nil
}

var Subscribe_ospfv2_interface_subtree_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {

	var err error
	var result XfmrSubscOutParams

	pathInfo := NewPathInfo(inParams.uri)
	log.Info("Subscribe_ospfv2_interface_subtree_xfmr: pathInfo ", pathInfo)

	result.dbDataMap = make(RedisDbSubscribeMap)
	result.isVirtualTbl = false

	uriFullIfName, uriIfName, _, _, _ := getUriIfName(inParams.uri)
	if uriIfName == "" {
		errStr := "Empty OSPFv2 interface name"
		log.Info("Subscribe_ospfv2_interface_subtree_xfmr: " + errStr)
		return result, tlerr.New(errStr)
	}

	nativeIfName, _, _, _, err := getNativeInterfaceName(uriFullIfName)
	if err != nil {
		errStr := "Invalid OSPFv2 interface name"
		log.Info("Subscribe_ospfv2_interface_subtree_xfmr: " + errStr + " " + uriIfName)
		return result, tlerr.New(errStr)
	}

	ifAddress := pathInfo.Var("address")
	if ifAddress == "" {
		errStr := "Empty OSPF interface address"
		log.Info("Subscribe_ospfv2_interface_subtree_xfmr: " + errStr)
		return result, tlerr.New(errStr)
	}

	ospfIntfTbl := "OSPFV2_INTERFACE"
	ospfIntfTblKey := nativeIfName + "|" + ifAddress
	result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB: {ospfIntfTbl: {ospfIntfTblKey: {}}}}

	log.Info("Subscribe_ospfv2_interface_subtree_xfmr: ospfIntfTblKey " + ospfIntfTblKey)
	return result, nil
}

var YangToDb_ospfv2_interface_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	ospfRespMap := make(map[string]map[string]db.Value)

	log.Info("YangToDb_ospfv2_interface_subtree_xfmr: -------- ospf if subtree ------")
	log.Info("YangToDb_ospfv2_interface_subtree_xfmr: param uri ", inParams.uri)

	addOperation, deleteOperation, getOp, err := ospfGetInparamOperation(&inParams)
	if err != nil || getOp {
		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ", err)
		return ospfRespMap, err
	}

	uriFullIfName, uriIfName, _, _, err := getInParamIfName(&inParams)
	if err != nil {
		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: getInParamIfName failed")
		return ospfRespMap, err
	}

	nativeIfName, _, _, _, err := getNativeInterfaceName(uriFullIfName)
	if err != nil {
		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: getNativeInterfaceName failed")
		return ospfRespMap, err
	}

	log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: uriIfName %s nativeIfName %s", uriIfName, nativeIfName)
	rcvdUri, _ := getOspfUriPath(&inParams)

	routedVlan := false
	if strings.HasPrefix(nativeIfName, "Vlan") {
		routedVlan = true
	}

	ospfObj, _, ending, err := ospfGetIntfOspfObject(&inParams, "")
	if err != nil {
		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: get intObj failed")
		return ospfRespMap, err
	}

	if ospfObj == nil || ending {
		if deleteOperation {
			err = ospf_delete_all_interface_config(&inParams, nativeIfName, "*", &ospfRespMap)
			return ospfRespMap, err
		}
		return ospfRespMap, nil
	}

	tempWord := false
	if tempWord {
		ospfGetIntfOspfAddresssObject(&inParams, uriIfName, "")
	}

	if ospfObj.IfAddresses == nil || len(ospfObj.IfAddresses) < 1 {
		errStr := "Ospfv2 IfAddresses is not set"
		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
		if deleteOperation {
			err = ospf_delete_all_interface_config(&inParams, nativeIfName, "*", &ospfRespMap)
			return ospfRespMap, err
		}
		return ospfRespMap, errors.New(errStr)
	}

	intfVrfName, _ := get_interface_vrf(&inParams, nativeIfName)

	intfTblName := "OSPFV2_INTERFACE"
	areaTblName := "OSPFV2_ROUTER_AREA"
	savedSubOpMap := inParams.subOpDataMap[inParams.oper]
	inParams.subOpDataMap[inParams.oper] = nil

	fieldNameList := []string{"area-id", "authentication-type", "authentication-key", "bfd-enable",
		"dead-interval", "dead-interval-minimal", "hello-interval", "hello-multiplier",
		"metric", "mtu-ignore", "network-type", "priority", "retransmission-interval",
		"transmit-delay", "authentication-key-encrypted"}

	for intfAddrKey, intfAddrObj := range ospfObj.IfAddresses {

		intfTblKey := nativeIfName + "|" + intfAddrKey
		ospfCfgObj := intfAddrObj.Config
		ospfRVlanCfgObj := (*ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2_IfAddresses_Config)(unsafe.Pointer(ospfCfgObj))

		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: IfAddresses intfTblKey is ", intfTblKey)

		if addOperation {

			log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ADD/UPDATE operation ", inParams.oper)

			intfUpdateMap := make(map[string]string)

			intfEntryPresent := true
			intfTblEntry, err := ospf_get_table_entry(&inParams, intfTblName, intfTblKey)
			if err != nil {
				log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf tbl entry not present")
				intfEntryPresent = false
			}

			if !intfEntryPresent {
				intfUpdateMap["enable"] = "true"
				log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf interface create new entry")
			}

			if intfAddrObj.Config != nil {

				if !intfEntryPresent {
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf interface update existing entry for ", intfTblKey)
				}

				if ospfCfgObj.AreaId != nil {
					fieldName := "area-id"
					dbVlaueStr := "NULL"

					if routedVlan {
						areaIdObj := ospfRVlanCfgObj.AreaId
						areaIdUnionType := reflect.TypeOf(areaIdObj).Elem()
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: routed vlan area id type ", areaIdUnionType)
						switch areaIdUnionType {
						case reflect.TypeOf(ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_String{}):
							areaId := (areaIdObj).(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_String)
							dbVlaueStr = areaId.String
						case reflect.TypeOf(ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_Uint32{}):
							areaId := (areaIdObj).(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_Uint32)
							dbVlaueStr = ospfGetDottedAreaFromUint32(areaId.Uint32)
						}

					} else {
						areaIdObj := ospfCfgObj.AreaId
						areaIdUnionType := reflect.TypeOf(areaIdObj).Elem()
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: subinterface area id type ", areaIdUnionType)
						switch areaIdUnionType {
						case reflect.TypeOf(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_String{}):
							areaId := (areaIdObj).(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_String)
							dbVlaueStr = areaId.String
						case reflect.TypeOf(ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_Uint32{}):
							areaId := (areaIdObj).(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union_Uint32)
							dbVlaueStr = ospfGetDottedAreaFromUint32(areaId.Uint32)
						}
					}

					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Area id field to ", dbVlaueStr)

					if dbVlaueStr != "NULL" {

						rtrPresent, _ := ospf_router_present_for_interface(&inParams, nativeIfName)
						if !rtrPresent {
							errStr := "Area configuration not allowed without OSPF router config"
							log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
							return ospfRespMap, tlerr.New(errStr)
						}

						if intfEntryPresent {
							currAreaId := (&intfTblEntry).Get(fieldName)
							if currAreaId != "" && currAreaId != dbVlaueStr {
								errStr := "Must remove previous area config before changing ospf area"
								log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
								return ospfRespMap, tlerr.New(errStr)
							}
						}

						areaNwCfgPresent, err := ospf_area_network_present_for_interface_vrf(&inParams, nativeIfName)
						if err != nil {
							errStr := "Internal Error: Network area table access failed"
							log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
							return ospfRespMap, tlerr.New(errStr)
						} else if areaNwCfgPresent {
							errStr := "Please remove all network commands in ospf router area config first"
							log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
							return ospfRespMap, tlerr.New(errStr)
						}

						if intfVrfName != "" {
							areaId := dbVlaueStr
							areaPresent, _ := ospf_router_area_present(&inParams, intfVrfName, areaId)
							if !areaPresent {
								areaTblKey := intfVrfName + "|" + areaId
								err := ospf_update_table_entry(&inParams, inParams.oper, areaTblName, areaTblKey, "", "", &ospfRespMap)
								if err != nil {
									log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: ospf router area %s add failed", areaTblKey)
									return ospfRespMap, err
								}
							}
						}

						intfUpdateMap[fieldName] = dbVlaueStr
					}
				}

				if ospfCfgObj.AuthenticationType != nil {
					fieldName := "authentication-type"

					dbVlaueStr := *(ospfCfgObj.AuthenticationType)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db authentication field to ", dbVlaueStr)

					if dbVlaueStr == "NONE" || dbVlaueStr == "TEXT" || dbVlaueStr == "MD5HMAC" {
						intfUpdateMap[fieldName] = dbVlaueStr
					} else {
						errStr := "Invalid Authentication type, valid values are NONE, TEXT or MD5HMAC"
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
						return ospfRespMap, tlerr.New(errStr)
					}
				}

				if ospfCfgObj.AuthenticationKeyEncrypted != nil {
					//fieldName := "authentication-key-encrypted"

					if ospfCfgObj.AuthenticationKeyEncrypted == nil {
						errStr := "Authentication key must be provided along with encryption attribute"
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
						return ospfRespMap, tlerr.New(errStr)
					}

					var dbVlaueBool bool = *(ospfCfgObj.AuthenticationKeyEncrypted)
					dbVlaueStr := "false"
					if dbVlaueBool {
						dbVlaueStr = "true"
					}
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: encrypted field is ", dbVlaueStr)
				}

				if ospfCfgObj.AuthenticationKey != nil {
					fieldName := "authentication-key"

					dbVlaueStr := *(ospfCfgObj.AuthenticationKey)
					strippedStr := ospf_remove_escape_sequence(dbVlaueStr)
					log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: rcvd %s stripped %s", dbVlaueStr, strippedStr)
					dbVlaueStr = strippedStr
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db Auth key field to ", dbVlaueStr)

					encryptedKey := false
					if ospfCfgObj.AuthenticationKeyEncrypted != nil {
						encryptedKey = *(ospfCfgObj.AuthenticationKeyEncrypted)
					}

					keyLength := len(dbVlaueStr)
					if !encryptedKey && keyLength > 8 {
						errStr := "Authentication key shall be max 8 charater long"
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
						return ospfRespMap, tlerr.New(errStr)
					}

					encLen := ospf_get_min_encryption_length()
					if encryptedKey && keyLength < encLen {
						errStr := fmt.Sprintf("Encrypted authentication key shall be minimum %d character long", encLen)
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
						return ospfRespMap, tlerr.New(errStr)
					}

					if !encryptedKey {
						encPasswd, err := ospf_encrypt_password(dbVlaueStr, false)
						if err != nil {
							log.Info("YangToDb_ospfv2_interface_subtree_xfmr: paswd encrypt failed")
							return ospfRespMap, err
						}
						dbVlaueStr = encPasswd
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: encrypted passwd ", dbVlaueStr)
					}

					intfUpdateMap[fieldName] = dbVlaueStr

					fieldName = "authentication-key-encrypted"
					intfUpdateMap[fieldName] = "true"
				}

				if ospfCfgObj.BfdEnable != nil {
					fieldName := "bfd-enable"

					if intfAddrKey != "0.0.0.0" {
						errStr := "Interface BFD config allowed only with interface IPv4 address 0.0.0.0"
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
						return ospfRespMap, tlerr.New(errStr)
					}

					var dbVlaueBool bool = *(ospfCfgObj.BfdEnable)
					dbVlaueStr := "false"
					if dbVlaueBool {
						dbVlaueStr = "true"
					}

					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db bfd field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.DeadIntervalMinimal != nil {
					fieldName := "dead-interval-minimal"

					var dbVlaueBool bool = *(ospfCfgObj.DeadIntervalMinimal)
					dbVlaueStr := "false"
					if dbVlaueBool {
						dbVlaueStr = "true"
					}

					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db minimal field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.DeadInterval != nil {
					fieldName := "dead-interval"

					var dbVlaueInt int = int(uint(*(ospfCfgObj.DeadInterval)))
					dbVlaueStr := strconv.Itoa(dbVlaueInt)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db dead interval field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.HelloInterval != nil {
					fieldName := "hello-interval"

					var dbVlaueInt int = int(uint(*(ospfCfgObj.HelloInterval)))
					dbVlaueStr := strconv.Itoa(dbVlaueInt)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db hello interval field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.HelloMultiplier != nil {
					fieldName := "hello-multiplier"

					var dbVlaueInt int = int(uint(*(ospfCfgObj.HelloMultiplier)))
					dbVlaueStr := strconv.Itoa(dbVlaueInt)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db hello multiplier field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.Metric != nil {
					fieldName := "metric"

					var dbVlaueInt int = int(uint(*(ospfCfgObj.Metric)))
					dbVlaueStr := strconv.Itoa(dbVlaueInt)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db metric field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.MtuIgnore != nil {
					fieldName := "mtu-ignore"

					var dbVlaueBool bool = *(ospfCfgObj.MtuIgnore)
					dbVlaueStr := "false"
					if dbVlaueBool {
						dbVlaueStr = "true"
					}
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db mtu ignore field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.NetworkType != ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_UNSET {
					fieldName := "network-type"
					nw_type := ospfCfgObj.NetworkType

					if intfAddrKey != "0.0.0.0" {
						errStr := "Interface network type config allowed only with interface IPv4 address 0.0.0.0"
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
						return ospfRespMap, tlerr.New(errStr)
					}

					dbVlaueStr := "NULL"
					switch nw_type {
					case ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_BROADCAST_NETWORK:
						dbVlaueStr = "BROADCAST_NETWORK"
					case ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_POINT_TO_POINT_NETWORK:
						dbVlaueStr = "POINT_TO_POINT_NETWORK"
					default:
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: Invalid Network type ", nw_type)
					}
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db network type field to ", dbVlaueStr)

					if dbVlaueStr != "NULL" {
						intfUpdateMap[fieldName] = dbVlaueStr
					}
				}
				if ospfCfgObj.Priority != nil {
					fieldName := "priority"

					var dbVlaueInt int = int(uint(*(ospfCfgObj.Priority)))
					dbVlaueStr := strconv.Itoa(dbVlaueInt)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db priority field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.RetransmissionInterval != nil {
					fieldName := "retransmission-interval"

					var dbVlaueInt int = int(uint(*(ospfCfgObj.RetransmissionInterval)))
					dbVlaueStr := strconv.Itoa(dbVlaueInt)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db rxmt interval field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
				if ospfCfgObj.TransmitDelay != nil {
					fieldName := "transmit-delay"

					var dbVlaueInt int = int(uint(*(ospfCfgObj.TransmitDelay)))
					dbVlaueStr := strconv.Itoa(dbVlaueInt)
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: set db transmit delay field to ", dbVlaueStr)
					intfUpdateMap[fieldName] = dbVlaueStr
				}
			}

			if len(intfUpdateMap) != 0 {
				err := ospf_update_table_entries(&inParams, inParams.oper, intfTblName, intfTblKey, intfUpdateMap, &ospfRespMap)
				if err != nil {
					log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf field list updt failed")
					return ospfRespMap, err
				}
			}

		} else if deleteOperation {

			log.Info("YangToDb_ospfv2_interface_subtree_xfmr: DELETE operation ", inParams.oper)

			if intfAddrKey != "0.0.0.0" {
				if strings.HasSuffix(rcvdUri, "bfd-enable") ||
					strings.HasSuffix(rcvdUri, "network-type") {
					errStr := "Interface network type and BFD unconfig allowed only with interface address 0.0.0.0"
					log.Info("YangToDb_ospfv2_interface_subtree_xfmr: " + errStr)
					return ospfRespMap, tlerr.New(errStr)
				}
			}

			if ospfCfgObj != nil && !strings.HasSuffix(rcvdUri, "config") {
				log.Info("YangToDb_ospfv2_interface_subtree_xfmr: config individual field deletes")

				intfUpdateMap := make(map[string]string)

				for _, fieldName := range fieldNameList {
					if strings.HasSuffix(rcvdUri, fieldName) {
						log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete field ", fieldName)
						intfUpdateMap[fieldName] = "NULL"

						if fieldName == "authentication-key" {
							intfUpdateMap["authentication-key-encrypted"] = "NULL"
						}
					}
				}

				if len(intfUpdateMap) != 0 {
					err := ospf_update_table_entries(&inParams, inParams.oper, intfTblName, intfTblKey, intfUpdateMap, &ospfRespMap)
					if err != nil {
						log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf field list updt failed")
						return ospfRespMap, err
					}
				}

			} else if ospfCfgObj == nil &&
				(strings.HasSuffix(rcvdUri, "config") ||
					strings.HasSuffix(rcvdUri, "ospfv2/if-addresses")) { //delete entire row

				log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete entire row")

				err := ospf_update_table_entry(&inParams, inParams.oper, intfTblName, intfTblKey, "", "", &ospfRespMap)
				if err != nil {
					log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf entry delete")
					return ospfRespMap, err
				}

				log.Info("YangToDb_ospfv2_interface_subtree_xfmr: delete entire row")
			}

		} //deleteOperation
	} //for IfAddressList

	if len(ospfRespMap) == 0 && savedSubOpMap != nil {
		inParams.subOpDataMap[inParams.oper] = savedSubOpMap
	}

	log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospfRespMap ", ospfRespMap)
	return ospfRespMap, nil
}

var DbToYang_ospfv2_interface_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error

	pathInfo := NewPathInfo(inParams.uri)
	subIfStr := pathInfo.Var("index")

	log.Info("DbToYang_ospfv2_interface_subtree_xfmr: --------Start------")
	log.Info("DbToYang_ospfv2_interface_subtree_xfmr: param uri ", inParams.uri)
	log.Info("DbToYang_ospfv2_interface_subtree_xfmr: pathInfo ", pathInfo)

	uriFullIfName, uriIfName, _, _, err := getInParamIfName(&inParams)
	if err != nil {
		log.Info("DbToYang_ospfv2_interface_subtree_xfmr: getInParamIfName failed")
		return err
	}

	nativeIfName, _, _, _, err := getNativeInterfaceName(uriFullIfName)
	if err != nil {
		log.Info("DbToYang_ospfv2_interface_subtree_xfmr: getNativeInterfaceName failed")
		return err
	}

	rcvdUri, _ := getOspfUriPath(&inParams)

	routedVlan := false
	if strings.HasPrefix(uriIfName, "Vlan") {
		routedVlan = true
	}

	ospfObj, _, err := ospfFillIntfOspfObject(&inParams, uriIfName, subIfStr)
	if ospfObj == nil || err != nil {
		log.Info("DbToYang_ospfv2_interface_subtree_xfmr: Failed to fill ospf object")
		return err
	}

	var ospfCfgObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config
	ospfCfgObj = nil

	var err2 error
	var found bool
	fillOneAddress := ""
	for intfAddrKey := range ospfObj.IfAddresses {
		fillOneAddress = "" + intfAddrKey
		break
	}

	if fillOneAddress != "" {
		log.Infof("DbToYang_ospfv2_interface_subtree_xfmr: get one addr %s entry", fillOneAddress)
	} else {
		log.Infof("DbToYang_ospfv2_interface_subtree_xfmr: get all addr entries")
	}

	intfTblName := "OSPFV2_INTERFACE"
	var ospfIfTblSpec *db.TableSpec = &db.TableSpec{Name: intfTblName}
	ospfTblData, err := configDbPtr.GetTable(ospfIfTblSpec)
	if err != nil {
		errStr := "Resource Not Found"
		log.Error("DbToYang_ospfv2_interface_subtree_xfmr: OSPF Interface Table data not found ", errStr)
		return err
	}

	intfTblKeys, err := ospfTblData.GetKeys()
	if err != nil {
		errStr := "Ospf interface table key fer error"
		log.Info("DbToYang_ospfv2_interface_subtree_xfmr: get keys failed ", errStr)
		return err
	}

	intfAuthTblName := "OSPFV2_INTERFACE_MD_AUTHENTICATION"
	var ospfIfAuthTblSpec *db.TableSpec = &db.TableSpec{Name: intfAuthTblName}
	ospfIfAuthTblData, err := configDbPtr.GetTable(ospfIfAuthTblSpec)
	if err != nil {
		errStr := "Resource Not Found"
		log.Error("DbToYang_ospfv2_interface_subtree_xfmr: OSPF Interface MdAuth Table data not found ", errStr)
		return err
	}

	intfAuthTblKeys, err := ospfIfAuthTblData.GetKeys()
	if err != nil {
		errStr := "Resource Not Found"
		log.Info("DbToYang_ospfv2_interface_subtree_xfmr: MdAuth get keys failed ", errStr)
		return err
	}

	log.Info("DbToYang_ospfv2_interface_subtree_xfmr: nativeIfName ", nativeIfName)

	fieldNameList := []string{"area-id", "authentication-type", "authentication-key", "bfd-enable",
		"dead-interval", "dead-interval-minimal", "hello-interval", "hello-multiplier",
		"metric", "mtu-ignore", "network-type", "priority", "retransmission-interval",
		"transmit-delay"}

	authFieldNameList := []string{"authentication-md5-key"}

	var intfAddrObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses

	for _, intfTblKey := range intfTblKeys {
		keyIfName := intfTblKey.Get(0)
		keyIfAddress := intfTblKey.Get(1)

		if len(nativeIfName) != 0 && nativeIfName != keyIfName {
			continue
		}

		if fillOneAddress != "" {
			if keyIfAddress != fillOneAddress {
				continue
			}
		}

		intfAddrObj = nil
		if intfAddrObj, found = ospfObj.IfAddresses[keyIfAddress]; !found {
			intfAddrObj, err2 = ospfObj.NewIfAddresses(keyIfAddress)
			if err2 != nil {
				log.Error("DbToYang_ospfv2_interface_subtree_xfmr: Create new IfAddresses map elt failed ", keyIfAddress)
				continue
			}
			ygot.BuildEmptyTree(intfAddrObj)
		}

		if intfAddrObj.Config == nil {
			var ospfCfgObj ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config
			intfAddrObj.Config = &ospfCfgObj
		}

		ospfCfgObj = intfAddrObj.Config
		ospfRVlanCfgObj := (*ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2_IfAddresses_Config)(unsafe.Pointer(ospfCfgObj))

		ospfIfEntry, err2 := ospfTblData.GetEntry(intfTblKey)
		if err2 != nil || len(ospfIfEntry.Field) == 0 {
			log.Info("YangToDb_ospfv2_interface_subtree_xfmr: get entry err for ", intfTblKey)
			continue
		}

		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf if key ", intfTblKey)
		log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf if Entry ", ospfIfEntry)

		readFieldNameList := []string{}
		if !strings.HasSuffix(rcvdUri, "config") {
			for _, fieldName := range fieldNameList {
				if strings.HasSuffix(rcvdUri, fieldName) {
					readFieldNameList = append(readFieldNameList, fieldName)
				}
			}
		}

		if len(readFieldNameList) == 0 {
			readFieldNameList = fieldNameList
		}

		log.Info("DbToYang_ospfv2_interface_subtree_xfmr: read field name list ", readFieldNameList)

		for _, fieldName := range readFieldNameList {

			fieldValue, ok := ospfIfEntry.Field[fieldName]
			if !ok {
				//log.Info("DbToYang_ospfv2_interface_subtree_xfmr: entry does not have field ", fieldName)
				fieldValue = ""
			}

			log.Infof("DbToYang_ospfv2_interface_subtree_xfmr: fieldName %s fieldValue %s.", fieldName, fieldValue)

			if fieldName == "bfd-enable" {
				enabled := false
				if fieldValue == "true" {
					enabled = true
				}

				if fieldValue != "" {
					ospfCfgObj.BfdEnable = &enabled
				}
			}

			if fieldName == "mtu-ignore" {
				enabled := false
				if fieldValue == "true" {
					enabled = true
				}

				if fieldValue != "" {
					ospfCfgObj.MtuIgnore = &enabled
				}
			}

			if fieldName == "dead-interval-minimal" {
				enabled := false
				if fieldValue == "true" {
					enabled = true
				}

				if fieldValue != "" {
					ospfCfgObj.DeadIntervalMinimal = &enabled
				}
			}

			if len(fieldValue) == 0 {
				continue
			}

			if fieldName == "area-id" {
				if routedVlan {
					areaIdUnion, err3 := ospfRVlanCfgObj.To_OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union(fieldValue)
					if err3 == nil {
						ospfRVlanCfgObj.AreaId = areaIdUnion
					}
				} else {
					areaIdUnion, err3 := ospfCfgObj.To_OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_Config_AreaId_Union(fieldValue)
					if err3 == nil {
						ospfCfgObj.AreaId = areaIdUnion
					}
				}
			}

			if fieldName == "authentication-type" {
				ospfCfgObj.AuthenticationType = &fieldValue
			}

			if fieldName == "authentication-key" {
				ospfCfgObj.AuthenticationKey = &fieldValue
			}

			if fieldName == "authentication-key-encrypted" {
				enabled := true
				ospfCfgObj.AuthenticationKeyEncrypted = &enabled
			}

			if fieldName == "dead-interval" {
				if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
					fieldValueInt := uint32(intVal)
					ospfCfgObj.DeadInterval = &fieldValueInt
				}
			}

			if fieldName == "hello-interval" {
				if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
					fieldValueInt := uint32(intVal)
					ospfCfgObj.HelloInterval = &fieldValueInt
				}
			}
			if fieldName == "hello-multiplier" {
				if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
					fieldValueInt := uint32(intVal)
					ospfCfgObj.HelloMultiplier = &fieldValueInt
				}
			}
			if fieldName == "metric" {
				if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
					fieldValueInt := uint32(intVal)
					ospfCfgObj.Metric = &fieldValueInt
				}
			}
			if fieldName == "network-type" {
				if fieldValue == "BROADCAST_NETWORK" {
					ospfCfgObj.NetworkType = ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_BROADCAST_NETWORK
				} else if fieldValue == "POINT_TO_POINT_NETWORK" {
					ospfCfgObj.NetworkType = ocbinds.OpenconfigOspfTypes_OSPF_NETWORK_TYPE_POINT_TO_POINT_NETWORK
				}
			}
			if fieldName == "priority" {
				if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
					fieldValueInt := uint8(intVal)
					ospfCfgObj.Priority = &fieldValueInt
				}
			}
			if fieldName == "retransmission-interval" {
				if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
					fieldValueInt := uint32(intVal)
					ospfCfgObj.RetransmissionInterval = &fieldValueInt
				}
			}
			if fieldName == "transmit-delay" {
				if intVal, err3 := strconv.Atoi(fieldValue); err3 == nil {
					fieldValueInt := uint32(intVal)
					ospfCfgObj.TransmitDelay = &fieldValueInt
				}
			}

		} //readFieldNameList

		for _, intfAuthTblKey := range intfAuthTblKeys {
			keyIfAuthName := intfAuthTblKey.Get(0)
			keyIfAuthAddress := intfAuthTblKey.Get(1)
			keyIfAuthKeyId := intfAuthTblKey.Get(2)

			if keyIfAuthName != keyIfName || keyIfAuthAddress != keyIfAddress {
				continue
			}

			keyIdInt, err := strconv.Atoi(keyIfAuthKeyId)
			if err != nil || keyIdInt < 1 || keyIdInt > 255 {
				log.Info("DbToYang_ospfv2_interface_subtree_xfmr: Invalid Auth Key Id ", keyIfAuthKeyId)
				continue
			}
			keyIdUint8 := uint8(keyIdInt)

			if intfAddrObj.MdAuthentications == nil {
				var mdAuths ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_MdAuthentications
				intfAddrObj.MdAuthentications = &mdAuths
			}

			var intfMdAuthObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_MdAuthentications_MdAuthentication

			if intfMdAuthObj, found = intfAddrObj.MdAuthentications.MdAuthentication[keyIdUint8]; !found {
				intfMdAuthObj, err2 = intfAddrObj.MdAuthentications.NewMdAuthentication(keyIdUint8)
				if err2 != nil {
					log.Error("DbToYang_ospfv2_interface_subtree_xfmr: Create new IfAddresses map elt failed ", keyIfAuthAddress)
					continue
				}
				ygot.BuildEmptyTree(intfMdAuthObj)
			}

			if intfMdAuthObj.Config == nil {
				var cfgObj ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_MdAuthentications_MdAuthentication_Config
				intfMdAuthObj.Config = &cfgObj
				ygot.BuildEmptyTree(intfMdAuthObj.Config)
			}

			intfMdAuthCfgObj := intfMdAuthObj.Config

			ospfIfAuthEntry, err2 := ospfIfAuthTblData.GetEntry(intfAuthTblKey)
			if err2 != nil || len(ospfIfAuthEntry.Field) == 0 {
				log.Info("DbToYang_ospfv2_interface_subtree_xfmr: get entry err for ", intfAuthTblKey)
				continue
			}

			log.Info("DbToYang_ospfv2_interface_subtree_xfmr: ospf if md auth key ", intfAuthTblKey)
			log.Info("DbToYang_ospfv2_interface_subtree_xfmr: ospf if md authEntry ", ospfIfAuthEntry)

			for _, authFieldName := range authFieldNameList {

				authFieldValue, ok := ospfIfAuthEntry.Field[authFieldName]
				if !ok {
					//log.Info("DbToYang_ospfv2_interface_subtree_xfmr: mdauth entry does not have field ", authFieldName)
					authFieldValue = ""
				}

				log.Infof("DbToYang_ospfv2_interface_subtree_xfmr: authFieldName %s value %s", authFieldName, authFieldValue)

				if authFieldName == "authentication-md5-key" {
					intfMdAuthCfgObj.AuthenticationMd5Key = &authFieldValue
					encrypted := true
					intfMdAuthCfgObj.AuthenticationKeyEncrypted = &encrypted
				}

			} //readAuthFieldNameList
		} //intfAuthTblKeys

		if fillOneAddress != "" {
			log.Infof("DbToYang_ospfv2_interface_subtree_xfmr: found %s", fillOneAddress)
		}

	} //intfTblKeys

	log.Info("DbToYang_ospfv2_interface_subtree_xfmr: returning ")
	return err
}

func ospf_delete_all_interface_config(inParams *XfmrParams, ifName string, ifAddress string, ospfRespMap *map[string]map[string]db.Value) error {
	var err error
	log.Infof("ospf_delete_all_interface_md_auth_config: ifName %s ifAddress %s.", ifName, ifAddress)

	err = ospf_delete_all_interface_md_auth_config(inParams, ifName, ifAddress, ospfRespMap)
	if err != nil {
		log.Info("ospf_delete_all_interface_config: int md auth entries failed ")
		return err
	}

	intfTblName := "OSPFV2_INTERFACE"
	intfTblKey := ifName + "|" + ifAddress

	err = ospf_delete_table_entry(inParams, intfTblName, intfTblKey, ospfRespMap)
	if err != nil {
		log.Info("ospf_delete_all_interface_config: del ospf intf failed ")
		return err
	}

	log.Info("ospf_delete_all_interface_config: success for ", ifName)
	return nil
}

func get_interface_vrf(inParams *XfmrParams, ifName string) (string, error) {
	if ifName == "" {
		errStr := "Empty interface name"
		log.Info("get_interface_vrf: ", errStr)
		return "", errors.New(errStr)
	}

	intfType, _, typeErr := getIntfTypeByName(ifName)
	if intfType == IntfTypeUnset || typeErr != nil {
		log.Info("get_interface_vrf: Invalid interface type IntfTypeUnset err ", typeErr)
		return "", typeErr
	}

	intfTbl := IntfTypeTblMap[intfType]
	intfEntry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name: intfTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})
	if dbErr != nil {
		log.Infof("get_interface_vrf: intf %s db get entry fail err %v", ifName, dbErr)
		return "default", nil
	}

	if !intfEntry.IsPopulated() {
		log.Infof("get_interface_vrf: intf %s entry not populated", ifName)
		return "default", nil
	}

	ifVrfName := (&intfEntry).Get("vrf_name")
	if ifVrfName == "" {
		log.Infof("get_interface_vrf: intf %s vrfs name set to default", ifName)
		return "default", nil
	}

	log.Infof("get_interface_vrf: intf %s vrfs name is %s", ifName, ifVrfName)
	return ifVrfName, nil
}

func ospf_router_present_for_interface(inParams *XfmrParams, ifName string) (bool, error) {

	log.Info("ospf_router_present_for_interface: ifName ", ifName)
	if ifName == "" {
		errStr := "Empty interface name"
		log.Info("ospf_router_present_for_interface: ", errStr)
		return false, errors.New(errStr)
	}

	ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
	if ifErr != nil {
		log.Info("ospf_router_present_for_interface: intf vrfs ger err ", ifErr)
		return false, ifErr
	}

	return ospf_router_present(inParams, ifVrfName)
}

func ospf_area_network_present_for_interface_vrf(inParams *XfmrParams, ifName string) (bool, error) {

	log.Info("ospf_area_network_present_for_interface_vrf: ifName ", ifName)
	if ifName == "" {
		errStr := "Empty interface name"
		log.Info("ospf_area_network_present_for_interface_vrf: ", errStr)
		return false, errors.New(errStr)
	}

	ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
	if ifErr != nil {
		log.Info("ospf_area_network_present_for_interface_vrf: intf vrfs ger err ", ifErr)
		return false, ifErr
	}

	return ospf_router_area_network_present(inParams, ifVrfName, "*")
}

func ospf_area_id_present_in_interfaces(inParams *XfmrParams, vrfName string, areaId string) (bool, error) {

	log.Infof("ospf_area_id_present_in_interfaces: vrfName %s areaId %s.", vrfName, areaId)
	if vrfName == "" {
		errStr := "Empty VRF name"
		log.Info("ospf_area_id_present_in_interfaces: ", errStr)
		return false, errors.New(errStr)
	}

	ospfIntfTblName := "OSPFV2_INTERFACE"
	var ospfIntfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfIntfTblName}
	ospfIntfTblData, err := configDbPtr.GetTable(ospfIntfTblSpec)
	if err != nil {
		errStr := "OSPF Interface table not found"
		log.Error("ospf_area_id_present_in_interfaces: OSPF Interface Table data not found ", errStr)
		return false, nil
	}

	ospfIntfTblKeys, err := ospfIntfTblData.GetKeys()
	if err != nil {
		errStr := "Interface Table get keys Failed"
		log.Info("ospf_area_id_present_in_interfaces: get keys failed ", errStr)
		return false, nil
	}

	for _, ospfIntfTblKey := range ospfIntfTblKeys {
		ifName := ospfIntfTblKey.Get(0)

		ospfIfEntry, err2 := ospfIntfTblData.GetEntry(ospfIntfTblKey)
		if err2 != nil || len(ospfIfEntry.Field) == 0 {
			log.Info("ospf_area_id_present_in_interfaces: get entry err for ", ospfIntfTblKey)
			continue
		}

		ifAreaId := (&ospfIfEntry).Get("area-id")
		if ifAreaId == "" {
			continue
		}

		ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
		if ifErr != nil {
			log.Info("ospf_area_id_present_in_interfaces: intf vrfs ger err ", ifErr)
			continue
		}

		if ifVrfName == vrfName {
			if areaId == "" || areaId == "*" {
				log.Info("ospf_area_id_present_in_interfaces: interface has area config ", ospfIntfTblKey)
				return true, nil
			} else {
				if areaId == ifAreaId {
					log.Info("ospf_area_id_present_in_interfaces: interface has area config ", ospfIntfTblKey)
					return true, nil
				}
			}
		}
	}

	log.Info("ospf_area_id_present_in_interfaces: no area config in ospf interfaces of ", vrfName)
	return false, nil
}

func delete_ospf_interface_area_ids(inParams *XfmrParams, vrfName string, areaId string, ospfRespMap *map[string]map[string]db.Value) error {

	var err error
	log.Infof("delete_ospf_interface_area_ids: vrfName %s areaId %s", vrfName, areaId)

	if vrfName == "" {
		errStr := "Empty vrf name"
		log.Info("delete_ospf_interface_area_ids: ", errStr)
		return errors.New(errStr)
	}

	ospfIntfTblName := "OSPFV2_INTERFACE"
	var ospfIfTblSpec *db.TableSpec = &db.TableSpec{Name: ospfIntfTblName}
	ospfIntfTblData, err := configDbPtr.GetTable(ospfIfTblSpec)
	if err != nil {
		errStr := "Resource Not Found"
		log.Error("delete_ospf_interface_area_ids: OSPF Interface Table data not found ", errStr)
		return nil
	}

	ospfIntfTblKeys, err := ospfIntfTblData.GetKeys()
	if err != nil {
		errStr := "Resource Not Found"
		log.Error("delete_ospf_interface_area_ids: get keys failed ", errStr)
		return nil
	}

	ospfOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
	ospfOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
	ospfOpMap[db.ConfigDB][ospfIntfTblName] = make(map[string]db.Value)
	ospfIntfTblMap := make(map[string]db.Value)

	entryDeleted := false
	fieldName := "area-id"

	for _, ospfIntfTblKey := range ospfIntfTblKeys {
		ifName := ospfIntfTblKey.Get(0)
		log.Info("delete_ospf_interface_area_ids: intf name ", ifName)

		ifVrfName, ifErr := get_interface_vrf(inParams, ifName)
		if ifErr != nil {
			continue
		}

		if ifVrfName != vrfName {
			log.Infof("delete_ospf_interface_area_ids: vrf name %s %s dont match", ifVrfName, vrfName)
			continue
		}

		ospfIfEntry, err2 := ospfIntfTblData.GetEntry(ospfIntfTblKey)
		if err2 != nil {
			log.Info("delete_ospf_interface_area_ids: Get entry err for ", ospfIntfTblKey)
			continue
		}

		log.Info("delete_ospf_interface_area_ids: ospf record ", ospfIfEntry)

		ifAreaId := ""
		lastField := true

		ospfIfEntryLen := len(ospfIfEntry.Field)
		if ospfIfEntryLen > 0 {

			ifAreaId = (&ospfIfEntry).Get("area-id")
			if ifAreaId == "" {
				log.Info("delete_ospf_interface_area_ids: area-id field not present in ", ospfIntfTblKey)
				if ospfIfEntryLen == 1 {
					if (&ospfIfEntry).Get("NULL") == "" {
						log.Info("delete_ospf_interface_area_ids: last null field in record ", ospfIntfTblKey)
						continue
					}
				}
			} else {
				//input area id match request present
				if areaId != "" && areaId != "*" {
					if ifAreaId != areaId {
						log.Info("delete_ospf_interface_area_ids: area-ids do not match in ", ospfIntfTblKey)
						continue
					}
				}
			}

			if ospfIfEntryLen > 1 {
				log.Info("delete_ospf_interface_area_ids: area-id isnot last field in ", ospfIntfTblKey)
				lastField = false
			}
		}

		ospfIntfTblKey2 := ospfIntfTblKey.Get(0) + "|" + ospfIntfTblKey.Get(1)

		if lastField {
			log.Infof("delete_ospf_interface_area_ids: last field, delete %s entire record", ospfIntfTblKey2)
		} else {
			log.Infof("delete_ospf_interface_area_ids: delete %s field %s", ospfIntfTblKey2, fieldName)
		}

		ospfOpMap[db.ConfigDB][ospfIntfTblName][ospfIntfTblKey2] = db.Value{Field: make(map[string]string)}
		if !lastField {
			ospfOpMap[db.ConfigDB][ospfIntfTblName][ospfIntfTblKey2].Field[fieldName] = "NULL"
		}

		ospfIntfDbValue := db.Value{Field: make(map[string]string)}
		if !lastField {
			ospfIntfDbValue.Field[fieldName] = "NULL"
		}
		ospfIntfTblMap[ospfIntfTblKey2] = ospfIntfDbValue
		entryDeleted = true
	}

	if entryDeleted {
		inParams.subOpDataMap[inParams.oper] = &ospfOpMap
		(*ospfRespMap)[ospfIntfTblName] = ospfIntfTblMap

		log.Info("delete_ospf_interface_area_ids: entryDeleted  ospfRespMap ", ospfRespMap)
		return nil
	}

	log.Info("delete_ospf_interface_area_ids: no entries to delete for vrfName ", vrfName)
	return nil
}

func delete_ospf_interfaces_for_vrf(inParams *XfmrParams, ospfRespMap *map[string]map[string]db.Value) error {

	if inParams.oper != DELETE {
		log.Info("delete_ospf_interfaces_for_vrf: non delete operation")
		return nil
	}

	log.Info("delete_ospf_interfaces_for_vrf: -------------del ospf del intf ---------------")

	rcvdUri, uriErr := getOspfUriPath(inParams)
	if uriErr != nil {
		log.Info("delete_ospf_interfaces_for_vrf: getOspfUriPath error ", uriErr)
		return nil
	}

	log.Info("delete_ospf_interfaces_for_vrf: rcvdUri ", rcvdUri)

	if !(strings.HasSuffix(rcvdUri, "protocols/protocol/ospfv2") ||
		strings.HasSuffix(rcvdUri, "protocols/protocol/ospfv2/global")) {
		log.Info("delete_ospf_interfaces_for_vrf: rcvdUri not ospfv2/global")
		return nil
	}

	ospfObj, ospfVrfName, _, _ := ospfGetRouterObject(inParams, "")
	if ospfObj == nil || ospfVrfName == "" {
		log.Info("delete_ospf_interfaces_for_vrf: ospf router not in request")
		return nil
	}

	log.Info("delete_ospf_interfaces_for_vrf: OSPF router Vrf name ", ospfVrfName)

	return delete_ospf_interface_area_ids(inParams, ospfVrfName, "*", ospfRespMap)
}

var Subscribe_ospfv2_interface_md_auth_subtree_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {

	var err error
	var result XfmrSubscOutParams

	pathInfo := NewPathInfo(inParams.uri)
	log.Info("Subscribe_ospfv2_interface_md_auth_subtree_xfmr: pathInfo ", pathInfo)

	result.dbDataMap = make(RedisDbSubscribeMap)
	result.isVirtualTbl = false

	uriFullIfName, uriIfName, _, _, _ := getUriIfName(inParams.uri)
	if uriIfName == "" {
		errStr := "Empty OSPFv2 interface name"
		log.Info("Subscribe_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
		return result, tlerr.New(errStr)
	}

	nativeIfName, _, _, _, err := getNativeInterfaceName(uriFullIfName)
	if err != nil {
		errStr := "Invalid OSPFv2 interface name"
		log.Info("Subscribe_ospfv2_interface_md_auth_subtree_xfmr: " + errStr + " " + uriIfName)
		return result, tlerr.New(errStr)
	}

	ifAddress := pathInfo.Var("address")
	if ifAddress == "" {
		errStr := "Empty OSPF interface address"
		log.Info("Subscribe_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
		return result, tlerr.New(errStr)
	}

	authKeyId := pathInfo.Var("authentication-key-id")
	if authKeyId == "" {
		errStr := "Empty OSPF interface authKeyId"
		log.Info("Subscribe_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
		return result, tlerr.New(errStr)
	}

	ospfIntfAuthTbl := "OSPFV2_INTERFACE_MD_AUTHENTICATION"
	ospfIntfAuthTblKey := nativeIfName + "|" + ifAddress + "|" + authKeyId
	result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB: {ospfIntfAuthTbl: {ospfIntfAuthTblKey: {}}}}

	log.Info("Subscribe_ospfv2_interface_md_auth_subtree_xfmr: ospfIntfAuthTblKey ", ospfIntfAuthTblKey)
	return result, nil
}

var YangToDb_ospfv2_interface_md_auth_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

	var err error
	ospfRespMap := make(map[string]map[string]db.Value)

	log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: -------- ospf if auth subtree ------")
	log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: param uri ", inParams.uri)

	addOperation, deleteOperation, getOp, err := ospfGetInparamOperation(&inParams)
	if err != nil || getOp {
		log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: ", err)
		return ospfRespMap, err
	}

	uriFullIfName, uriIfName, _, _, err := getInParamIfName(&inParams)
	if err != nil {
		log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: getInParamIfName failed")
		return ospfRespMap, err
	}

	nativeIfName, _, _, _, err := getNativeInterfaceName(uriFullIfName)
	if err != nil {
		log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: getNativeInterfaceName failed")
		return ospfRespMap, err
	}

	log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: uriIfName %s nativeIfName %s", uriIfName, nativeIfName)
	rcvdUri, _ := getOspfUriPath(&inParams)

	ospfObj, _, ending, err := ospfGetIntfOspfObject(&inParams, "")
	if err != nil {
		log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: get intObj failed")
		return ospfRespMap, err
	}

	if ospfObj == nil || ending {
		if deleteOperation {
			err = ospf_delete_all_interface_md_auth_config(&inParams, nativeIfName, "*", &ospfRespMap)
			return ospfRespMap, err
		}
		return ospfRespMap, nil
	}

	if ospfObj.IfAddresses == nil || len(ospfObj.IfAddresses) < 1 {
		errStr := "Ospfv2 IfAddresses is not set"
		log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
		if deleteOperation {
			err = ospf_delete_all_interface_md_auth_config(&inParams, nativeIfName, "*", &ospfRespMap)
			return ospfRespMap, err
		}
		return ospfRespMap, errors.New(errStr)
	}

	intfTblName := "OSPFV2_INTERFACE"
	intfAuthTblName := "OSPFV2_INTERFACE_MD_AUTHENTICATION"
	savedSubOpMap := inParams.subOpDataMap[inParams.oper]
	inParams.subOpDataMap[inParams.oper] = nil

	fieldNameList := []string{"authentication-md5-key", "authentication-key-encrypted"}

	for intfAddrKey, intfAddrObj := range ospfObj.IfAddresses {

		if intfAddrObj.MdAuthentications == nil || len(intfAddrObj.MdAuthentications.MdAuthentication) < 1 {
			if deleteOperation {
				err := ospf_delete_all_interface_md_auth_config(&inParams, nativeIfName, intfAddrKey, &ospfRespMap)
				if err != nil {
					log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: all auth del failed")
					return ospfRespMap, err
				}
			}
			continue
		}

		intfTblKey := nativeIfName + "|" + intfAddrKey

		intfEntryPresent := true
		_, err := ospf_get_table_entry(&inParams, intfTblName, intfTblKey) //intfTblEntry
		if err != nil {
			log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf tbl entry not present")
			intfEntryPresent = false
		}

		if addOperation && !intfEntryPresent {
			err := ospf_update_table_entry(&inParams, inParams.oper, intfTblName, intfTblKey, "enable", "true", &ospfRespMap)
			if err != nil {
				log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: ospf interface create failed ", inParams.oper)
				return ospfRespMap, err
			}
		}

		intfAuthObjList := intfAddrObj.MdAuthentications.MdAuthentication
		for intfAuthKeyId, intfAuthObj := range intfAuthObjList {

			intfAuthKeyIdStr := strconv.Itoa(int(intfAuthKeyId))
			intfAuthTblKey := nativeIfName + "|" + intfAddrKey + "|" + intfAuthKeyIdStr
			ospfAuthCfgObj := intfAuthObj.Config

			log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: intfAuthTblKey is ", intfAuthTblKey)

			intfAuthEntryPresent := true
			_, err := ospf_get_table_entry(&inParams, intfAuthTblName, intfAuthTblKey) //intfAuthTblEntry
			if err != nil {
				log.Info("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf tbl entry not present")
				intfAuthEntryPresent = false
			}

			if addOperation {
				log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: ADD/UPDATE operation ", inParams.oper)

				intfUpdateMap := make(map[string]string)

				if intfAuthEntryPresent {
					errStr := "Authentication key-id already present delete and reconfig"
					log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
					return ospfRespMap, tlerr.New(errStr)
				}

				intfUpdateMap["enable"] = "true"
				log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: New entry ", intfAuthTblKey)

				if intfAuthObj.Config != nil {

					if ospfAuthCfgObj.AuthenticationKeyEncrypted != nil {
						//fieldName := "authentication-key-encrypted"
						if ospfAuthCfgObj.AuthenticationMd5Key == nil {
							errStr := "Authentication key must be provided along with encryption attribute"
							log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
							return ospfRespMap, tlerr.New(errStr)
						}

						var dbVlaueBool bool = *(ospfAuthCfgObj.AuthenticationKeyEncrypted)
						dbVlaueStr := "false"
						if dbVlaueBool {
							dbVlaueStr = "true"
						}
						log.Infof("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: encrypted field is %t", dbVlaueStr)
					}

					if ospfAuthCfgObj.AuthenticationMd5Key != nil {
						fieldName := "authentication-md5-key"

						dbVlaueStr := *(ospfAuthCfgObj.AuthenticationMd5Key)
						strippedStr := ospf_remove_escape_sequence(dbVlaueStr)
						log.Infof("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: rcvd %s stripped %s", dbVlaueStr, strippedStr)
						dbVlaueStr = strippedStr

						log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: set db Auth key field to ", dbVlaueStr)

						encryptedKey := false
						if ospfAuthCfgObj.AuthenticationKeyEncrypted != nil {
							encryptedKey = *(ospfAuthCfgObj.AuthenticationKeyEncrypted)
						}

						keyLength := len(dbVlaueStr)
						if !encryptedKey && keyLength > 16 {
							errStr := "Authentication key shall be max 16 charater long"
							log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
							return ospfRespMap, tlerr.New(errStr)
						}

						encLen := ospf_get_min_encryption_length()
						if encryptedKey && keyLength < encLen {
							errStr := fmt.Sprintf("Encrypted authentication key shall be minimum %d character long", encLen)
							log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: " + errStr)
							return ospfRespMap, tlerr.New(errStr)
						}

						if !encryptedKey {
							encPasswd, err := ospf_encrypt_password(dbVlaueStr, false)
							if err != nil {
								log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: paswd encrypt failed")
								return ospfRespMap, err
							}
							dbVlaueStr = encPasswd
						}

						intfUpdateMap[fieldName] = dbVlaueStr

						fieldName = "authentication-key-encrypted"
						intfUpdateMap[fieldName] = "true"
					}
				}

				if len(intfUpdateMap) != 0 {
					err := ospf_update_table_entries(&inParams, inParams.oper, intfAuthTblName, intfAuthTblKey, intfUpdateMap, &ospfRespMap)
					if err != nil {
						log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf field list updt failed")
						return ospfRespMap, err
					}
					log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: update present")
				}

			} else if deleteOperation {

				log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: DELETE operation ", inParams.oper)
				intfUpdateMap := make(map[string]string)

				if !intfAuthEntryPresent {
					log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: OSPF Interface entry not found ")
					continue
				}

				if ospfAuthCfgObj != nil && !strings.HasSuffix(rcvdUri, "config") {
					log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: config individual field deletes")

					for _, fieldName := range fieldNameList {
						if strings.HasSuffix(rcvdUri, fieldName) {
							log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: delete field ", fieldName)
							intfUpdateMap[fieldName] = "NULL"

							if fieldName == "authentication-md5-key" {
								intfUpdateMap["authentication-key-encrypted"] = "NULL"
							}
						}
					}

					if len(intfUpdateMap) != 0 {
						err := ospf_update_table_entries(&inParams, inParams.oper, intfAuthTblName, intfAuthTblKey, intfUpdateMap, &ospfRespMap)
						if err != nil {
							log.Infof("YangToDb_ospfv2_interface_subtree_xfmr: ospf intf field list updt failed")
							return ospfRespMap, err
						}
						log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: Atleast one field deleted")
					}

				} else if ospfAuthCfgObj == nil &&
					(strings.HasSuffix(rcvdUri, "md-authentications/md-authentication/config") ||
						strings.HasSuffix(rcvdUri, "md-authentications/md-authentication")) { //delete entire row

					log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: delete entire row")

					err := ospf_update_table_entry(&inParams, inParams.oper, intfAuthTblName, intfAuthTblKey, "", "", &ospfRespMap)
					if err != nil {
						log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: ospf intf auth row del failed", inParams.oper)
						return ospfRespMap, err
					}

					log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: delete entire row ")
				}

			} //deleteOperation
		} //for MdAuthenticationsList
	} //for IfAddressList

	if len(ospfRespMap) == 0 && savedSubOpMap != nil {
		inParams.subOpDataMap[inParams.oper] = savedSubOpMap
	}

	log.Info("YangToDb_ospfv2_interface_md_auth_subtree_xfmr: ospfRespMap ", ospfRespMap)
	return ospfRespMap, nil
}

var DbToYang_ospfv2_interface_md_auth_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	var nativeIfName string

	pathInfo := NewPathInfo(inParams.uri)

	log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: --------db if md auth------")
	log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: param uri ", inParams.uri)
	log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: pathInfo ", pathInfo)

	uriFullIfName, uriIfName, _, _, err := getInParamIfName(&inParams)
	if err != nil {
		log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: getInParamIfName failed")
		return err
	}

	nativeIfName, _, subIfStr, _, err := getNativeInterfaceName(uriFullIfName)
	if err != nil {
		log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: getNativeInterfaceName failed")
		return err
	}

	routedVlan := false
	if strings.HasPrefix(uriIfName, "Vlan") {
		routedVlan = true
	}
	log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: routedVlan ", routedVlan)

	ospfObj, _, err := ospfFillIntfOspfObject(&inParams, uriIfName, subIfStr)
	if ospfObj == nil || err != nil {
		log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: Failed to fill ospf object")
		return err
	}

	var err2 error
	var found bool
	fillOneAddress := ""
	fillOneKeyId := ""
	for intfAddrKey, intfAddrObjElt := range ospfObj.IfAddresses {
		fillOneAddress = "" + intfAddrKey
		if intfAddrObjElt.MdAuthentications != nil {
			for mdKeyId := range intfAddrObjElt.MdAuthentications.MdAuthentication {
				fillOneKeyId = fmt.Sprintf("%d", mdKeyId)
				break
			}
		}
		break
	}

	if fillOneAddress != "" || fillOneKeyId != "" {
		log.Infof("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: get addr %s keyid %s.", fillOneAddress, fillOneKeyId)
	} else {
		log.Infof("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: get all addr and keys")
	}

	intfTblName := "OSPFV2_INTERFACE_MD_AUTHENTICATION"
	var ospfIfTblSpec *db.TableSpec = &db.TableSpec{Name: intfTblName}
	ospfTblData, err := configDbPtr.GetTable(ospfIfTblSpec)
	if err != nil {
		errStr := "Resource Not Found"
		log.Error("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: OSPF Interface Table data not found ", errStr)
		return err
	}

	intfTblKeys, err := ospfTblData.GetKeys()
	if err != nil {
		errStr := "Resource Not Found"
		log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: get keys failed ", errStr)
		return err
	}

	log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: Native nativeIfName ", nativeIfName)

	readFieldNameList := []string{"authentication-md5-key"} //, "authentication-key-encrypted" }

	var intfAddrObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses
	var intfMdAuthObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_MdAuthentications_MdAuthentication

	for _, intfTblKey := range intfTblKeys {
		keyIfName := intfTblKey.Get(0)
		keyIfAddress := intfTblKey.Get(1)
		keyIfKeyId := intfTblKey.Get(2)

		if nativeIfName != "" && nativeIfName != keyIfName {
			continue
		}

		if fillOneAddress != "" {
			if keyIfAddress != fillOneAddress {
				continue
			}
			if fillOneKeyId != "" {
				if keyIfKeyId != fillOneKeyId {
					continue
				}
			}
		}

		keyIdInt, err := strconv.Atoi(keyIfKeyId)
		if err != nil || keyIdInt < 1 || keyIdInt > 255 {
			log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: Invalid Auth Key Id ", keyIfKeyId)
			continue
		}
		keyIdUint8 := uint8(keyIdInt)

		intfAddrObj = nil
		intfMdAuthObj = nil

		if intfAddrObj, found = ospfObj.IfAddresses[keyIfAddress]; !found {
			intfAddrObj, err2 = ospfObj.NewIfAddresses(keyIfAddress)
			if err2 != nil {
				log.Error("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: Create new IfAddresses map elt failed ", keyIfAddress)
				continue
			}
			ygot.BuildEmptyTree(intfAddrObj)
			var mdAuths ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_MdAuthentications
			intfAddrObj.MdAuthentications = &mdAuths
		}

		if intfAddrObj.MdAuthentications == nil {
			var mdAuths ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_MdAuthentications
			intfAddrObj.MdAuthentications = &mdAuths
		}

		if intfMdAuthObj, found = intfAddrObj.MdAuthentications.MdAuthentication[keyIdUint8]; !found {
			intfMdAuthObj, err2 = intfAddrObj.MdAuthentications.NewMdAuthentication(keyIdUint8)
			if err2 != nil {
				log.Error("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: Create new IfAddresses map elt failed ", keyIfAddress)
				continue
			}
			ygot.BuildEmptyTree(intfMdAuthObj)
		}

		if intfMdAuthObj.Config == nil {
			var cfgObj ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Ospfv2_IfAddresses_MdAuthentications_MdAuthentication_Config
			intfMdAuthObj.Config = &cfgObj
			ygot.BuildEmptyTree(intfMdAuthObj.Config)
		}

		intfMdAuthCfgObj := intfMdAuthObj.Config

		ospfIfEntry, err2 := ospfTblData.GetEntry(intfTblKey)
		if err2 != nil || len(ospfIfEntry.Field) == 0 {
			log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: get entry err for ", intfTblKey)
			continue
		}

		log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: ospf if md auth key ", intfTblKey)
		log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: ospf if  md authEntry ", ospfIfEntry)

		for _, fieldName := range readFieldNameList {

			fieldValue, ok := ospfIfEntry.Field[fieldName]
			if !ok {
				//log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: entry does not have field ", fieldName)
				fieldValue = ""
			}

			log.Infof("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: fieldName %s fieldValue %s.", fieldName, fieldValue)

			if fieldName == "authentication-md5-key" {
				intfMdAuthCfgObj.AuthenticationMd5Key = &fieldValue
				encrypted := true
				intfMdAuthCfgObj.AuthenticationKeyEncrypted = &encrypted
			}

		} //readFieldNameList

		if fillOneAddress != "" && fillOneKeyId != "" {
			log.Infof("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: found %s %s", fillOneAddress, fillOneKeyId)
		}

	} //intfTblKeys

	log.Info("DbToYang_ospfv2_interface_md_auth_subtree_xfmr: returning ")
	return err
}

func ospf_delete_all_interface_md_auth_config(inParams *XfmrParams, ifName string, ifAddress string, ospfRespMap *map[string]map[string]db.Value) error {
	var err error
	log.Infof("ospf_delete_all_interface_md_auth_config: ifName %s ifAddress %s.", ifName, ifAddress)

	intfAuthTblName := "OSPFV2_INTERFACE_MD_AUTHENTICATION"
	intfAuthTblKey := ifName + "|" + ifAddress

	err = ospf_delete_table_entry(inParams, intfAuthTblName, intfAuthTblKey, ospfRespMap)
	if err != nil {
		log.Info("ospf_delete_all_interface_md_auth_config: failed ")
		return err
	}

	log.Info("ospf_delete_all_interface_md_auth_config: success for ", ifName)
	return nil
}

func ospf_interface_config_present(inParams *XfmrParams, ifName string) bool {

	var err error
	log.Infof("ospf_interface_config_present: ifName %s", ifName)

	if ifName == "" {
		log.Error("ospf_interface_config_present: empty intfName parameter")
		return false
	}

	nativeIfName, _, _, _, err := getNativeInterfaceName(ifName)
	if err != nil {
		log.Error("ospf_interface_config_present: get native interface name failed")
		return false
	}

	intfTblName := "OSPFV2_INTERFACE"
	intfTblKey := nativeIfName + "|" + "*"

	ignoreFieldMap := []string{"enable", "authentication-key-encrypted", "dead-interval-minimal"}

	intfEntryPresent, _ := ospf_config_present(inParams, intfTblName, intfTblKey, ignoreFieldMap)
	if intfEntryPresent {
		log.Info("ospf_interface_config_present: ospf interface config present")
		return true
	}

	intfAuthTblName := "OSPFV2_INTERFACE_MD_AUTHENTICATION"
	intfAuthTblKey := nativeIfName + "|" + "*" + "|" + "*"

	ignoreFieldMap = []string{"enable", "authentication-key-encrypted"}

	intfAuthEntryPresent, _ := ospf_config_present(inParams, intfAuthTblName, intfAuthTblKey, ignoreFieldMap)
	if intfAuthEntryPresent {
		log.Info("ospf_interface_config_present: ospf interface md auth config present")
		return true
	}

	log.Info("ospf_interface_config_present: ospf interface config not present")
	return false
}
