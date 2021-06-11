package transformer

import (
	"encoding/json"
	"errors"
	_ "fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("DbToYang_ipv4_route_get_xfmr", DbToYang_ipv4_route_get_xfmr)
	XlateFuncBind("DbToYang_ipv6_route_get_xfmr", DbToYang_ipv6_route_get_xfmr)
	XlateFuncBind("DbToYang_ipv4_mroute_get_xfmr", DbToYang_ipv4_mroute_get_xfmr)
	XlateFuncBind("Subscribe_ipv4_mroute_get_xfmr", Subscribe_ipv4_mroute_get_xfmr)
	XlateFuncBind("rpc_show_ipmroute", rpc_show_ipmroute)
	XlateFuncBind("rpc_clear_ipmroute", rpc_clear_ipmroute)
}

func getIpRoot(inParams XfmrParams) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts, string, string, uint64, error) {
	pathInfo := NewPathInfo(inParams.uri)
	niName := pathInfo.Var("name")
	prefix := pathInfo.Var("prefix")
	_nhindex, _ := strconv.Atoi(pathInfo.Var("index"))
	nhindex := uint64(_nhindex)
	var err error

	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	if len(niName) == 0 {
		return nil, "", "", 0, errors.New("vrf name is missing")
	}
	if !((niName == "default") || (niName == "mgmt") || (strings.HasPrefix(niName, "Vrf"))) {
		return nil, "", "", 0, errors.New("vrf name is invalid for AFT tables get operation")
	}

	deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
	netInstsObj := deviceObj.NetworkInstances

	netInstObj := netInstsObj.NetworkInstance[niName]
	if netInstObj == nil {
		netInstObj, _ = netInstsObj.NewNetworkInstance(niName)
	}
	ygot.BuildEmptyTree(netInstObj)

	netInstAftsObj := netInstObj.Afts

	if netInstAftsObj == nil {
		ygot.BuildEmptyTree(netInstObj)
		netInstAftsObj = netInstObj.Afts
	}
	ygot.BuildEmptyTree(netInstAftsObj)
	log.Infof(" niName %s targetUriPath %s prefix %s nhindex %s", niName, targetUriPath, prefix, nhindex)

	return netInstAftsObj, niName, prefix, nhindex, err
}

func util_iprib_get_native_ifname_from_ui_ifname(pUiIfname *string, pNativeIfname *string) {
	if pUiIfname == nil || pNativeIfname == nil {
		return
	}
	if len(*pUiIfname) == 0 {
		return
	}
	*pNativeIfname = *pUiIfname
	_pNativeIfname := utils.GetNativeNameFromUIName(pUiIfname)
	if _pNativeIfname != nil && len(*_pNativeIfname) != 0 {
		*pNativeIfname = *_pNativeIfname
	}
}

func util_iprib_get_ui_ifname_from_native_ifname(pNativeIfname *string, pUiIfname *string) {
	if pUiIfname == nil || pNativeIfname == nil {
		return
	}
	if len(*pNativeIfname) == 0 {
		return
	}
	*pUiIfname = *pNativeIfname
	_pUiIfname := utils.GetUINameFromNativeName(pNativeIfname)
	if _pUiIfname != nil && len(*_pUiIfname) != 0 {
		*pUiIfname = *_pUiIfname
	}
}

func parse_protocol_type(jsonProtocolType string, originType *ocbinds.E_OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE) {

	switch jsonProtocolType {
	case "static":
		*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC
	case "connected":
		*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_DIRECTLY_CONNECTED
	case "bgp":
		*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_BGP
	case "ospf":
		*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF
	case "ospf3":
		*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF3
	default:
		*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_UNSET
	}
}

func fill_ipv4_nhop_entry(nexthopsArr []interface{},
	ipv4NextHops *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry_NextHops,
	nhindex uint64) error {
	var err error
	var index uint64

	for _, nextHops := range nexthopsArr {

		switch t := nextHops.(type) {

		case map[string]interface{}:
			var nextHop *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry_NextHops_NextHop
			nextHopsMap := nextHops.(map[string]interface{})
			isactive, ok := nextHopsMap["active"]

			if !ok || isactive == false {
				log.Infof("Nexthop is not active, skip")
				break
			}

			index += 1
			/* if user specified specific next-hop index, just return that
			   otherwise retun all.*/
			if nhindex != 0 && nhindex != index {
				continue
			}
			nextHop = ipv4NextHops.NextHop[index]
			if nextHop == nil {
				nextHop, err = ipv4NextHops.NewNextHop(uint64(index))
				if err != nil {
					return errors.New("Operational Error")
				}
			}
			ygot.BuildEmptyTree(nextHop)

			var state ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry_NextHops_NextHop_State
			state.Index = nextHop.Index

			for nextHopKey, nextHopVal := range nextHopsMap {
				if nextHopKey == "interfaceName" {
					intfName := nextHopVal.(string)
					ygot.BuildEmptyTree(nextHop.InterfaceRef)
					nextHop.InterfaceRef.State.Interface = &intfName
				} else if nextHopKey == "ip" {
					ip := nextHopVal.(string)
					state.IpAddress = &ip
				} else if nextHopKey == "directlyConnected" {
					isDirectlyConnected := nextHopVal.(bool)
					state.DirectlyConnected = &isDirectlyConnected
				}
			}
			nextHop.State = &state
		default:
			log.Infof("Unhandled nextHops type [%s]", t)
		}
	}
	return err
}

func fill_ipv4_entry(prfxValArr []interface{},
	prfxKey string,
	aftsObjIpv4 *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast,
	nhindex uint64) error {
	var err error
	var ipv4Entry *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry
	for _, prfxValArrVal := range prfxValArr {
		log.Infof("prfxValMap_type[%s]", reflect.TypeOf(prfxValArrVal))
		switch t := prfxValArrVal.(type) {

		case map[string]interface{}:

			prfxValArrValMap := prfxValArrVal.(map[string]interface{})
			if _, ok := prfxValArrValMap["selected"]; !ok {
				log.Infof("Route is not selected, skip %s", prfxKey)
				break
			}
			var ok bool
			if ipv4Entry, ok = aftsObjIpv4.Ipv4Entry[prfxKey]; !ok {
				ipv4Entry, err = aftsObjIpv4.NewIpv4Entry(prfxKey)
				if err != nil {
					return errors.New("Operational Error")
				}
			}
			ygot.BuildEmptyTree(ipv4Entry)
			ipv4Entry.State.Prefix = &prfxKey

			for prfxValKey, prfxValVal := range prfxValArrValMap {

				if prfxValKey == "protocol" {
					parse_protocol_type(prfxValVal.(string), &ipv4Entry.State.OriginProtocol)
				} else if prfxValKey == "distance" {
					distance := (uint32)(prfxValVal.(float64))
					ipv4Entry.State.Distance = &distance
				} else if prfxValKey == "metric" {
					metric := (uint32)(prfxValVal.(float64))
					ipv4Entry.State.Metric = &metric
				} else if prfxValKey == "uptime" {
					uptime := prfxValVal.(string)
					ipv4Entry.State.Uptime = &uptime
					log.Infof("uptime: [%s]", ipv4Entry.State.Uptime)
				} else if prfxValKey == "nexthops" {
					err = fill_ipv4_nhop_entry(prfxValVal.([]interface{}), ipv4Entry.NextHops, nhindex)
					if err != nil {
						return err
					}
				}
			}

		default:
			log.Infof("Unhandled prfxValArrVal : type [%s]", t)
		}
	}
	return err
}

func fill_ipv6_nhop_entry(nexthopsArr []interface{},
	ipv6NextHops *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry_NextHops,
	nhindex uint64) error {

	var err error
	var index uint64
	for _, nextHops := range nexthopsArr {

		switch t := nextHops.(type) {

		case map[string]interface{}:
			var nextHop *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry_NextHops_NextHop

			nextHopsMap := nextHops.(map[string]interface{})
			isactive, ok := nextHopsMap["active"]

			if !ok || isactive == false {
				log.Infof("Nexthop is not active, skip")
				break
			}
			index += 1
			/* if user specified specific next-hop index, just return that
			   otherwise retun all.*/
			if nhindex != 0 && nhindex != index {
				continue
			}
			nextHop = ipv6NextHops.NextHop[index]
			if nextHop == nil {
				nextHop, err = ipv6NextHops.NewNextHop(uint64(index))
				if err != nil {
					return errors.New("Operational Error")
				}
			}
			ygot.BuildEmptyTree(nextHop)

			var state ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry_NextHops_NextHop_State
			state.Index = nextHop.Index

			for nextHopKey, nextHopVal := range nextHopsMap {
				if nextHopKey == "interfaceName" {
					intfName := nextHopVal.(string)
					ygot.BuildEmptyTree(nextHop.InterfaceRef)
					nextHop.InterfaceRef.State.Interface = &intfName
				} else if nextHopKey == "ip" {
					ip := nextHopVal.(string)
					state.IpAddress = &ip
				} else if nextHopKey == "directlyConnected" {
					isDirectlyConnected := nextHopVal.(bool)
					state.DirectlyConnected = &isDirectlyConnected
				}
			}
			nextHop.State = &state
		default:
			log.Infof("Unhandled nextHops type [%s]", t)
		}
	}
	return err
}

func fill_ipv6_entry(prfxValArr []interface{},
	prfxKey string,
	aftsObjIpv6 *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast,
	nhindex uint64) error {

	var err error
	var ipv6Entry *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry
	for _, prfxValArrVal := range prfxValArr {
		log.Infof("prfxValMap_type[%s]", reflect.TypeOf(prfxValArrVal))
		switch t := prfxValArrVal.(type) {

		case map[string]interface{}:
			// skip non-selected routes.

			prfxValArrValMap := prfxValArrVal.(map[string]interface{})
			if _, ok := prfxValArrValMap["selected"]; !ok {
				log.Infof("Route is not selected, skip %s", prfxKey)
				break
			}
			var ok bool
			if ipv6Entry, ok = aftsObjIpv6.Ipv6Entry[prfxKey]; !ok {
				ipv6Entry, err = aftsObjIpv6.NewIpv6Entry(prfxKey)
				if err != nil {
					return errors.New("Operational Error")
				}
			}

			ygot.BuildEmptyTree(ipv6Entry)
			ipv6Entry.State.Prefix = &prfxKey

			for prfxValKey, prfxValVal := range prfxValArrValMap {

				if prfxValKey == "protocol" {
					parse_protocol_type(prfxValVal.(string), &ipv6Entry.State.OriginProtocol)
				} else if prfxValKey == "distance" {
					distance := (uint32)(prfxValVal.(float64))
					ipv6Entry.State.Distance = &distance
				} else if prfxValKey == "metric" {
					metric := (uint32)(prfxValVal.(float64))
					ipv6Entry.State.Metric = &metric
				} else if prfxValKey == "uptime" {
					uptime := prfxValVal.(string)
					ipv6Entry.State.Uptime = &uptime
					log.Infof("uptime: [%s]", ipv6Entry.State.Uptime)
				} else if prfxValKey == "nexthops" {
					err = fill_ipv6_nhop_entry(prfxValVal.([]interface{}), ipv6Entry.NextHops, nhindex)
					if err != nil {
						return err
					}
				}
			}

		default:
			log.Infof("Unhandled prfxValArrVal : type [%s]", t)
		}
	}
	return err
}

var DbToYang_ipv4_route_get_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

	var err error
	var aftsObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts
	var niName string
	var prefix string
	var nhindex uint64

	aftsObj, niName, prefix, nhindex, err = getIpRoot(inParams)

	_ = niName

	if err != nil {
		return err
	}

	aftsObjIpv4 := aftsObj.Ipv4Unicast
	if aftsObjIpv4 == nil {
		return errors.New("Network-instance IPv4 unicast object missing")
	}
	ygot.BuildEmptyTree(aftsObjIpv4)

	var outputJson map[string]interface{}
	cmd := "show ip route vrf " + niName
	if len(prefix) > 0 {
		cmd += " "
		cmd += prefix
	}
	cmd += " json"
	log.Infof("vty cmd [%s]", cmd)

	if outputJson, err = exec_vtysh_cmd(cmd); err == nil {

		for prfxKey, prfxVal := range outputJson {
			if outError, ok := outputJson["warning"]; ok {
				log.Errorf("\"%s\" VTYSH-cmd execution failed with error-msg ==> \"%s\" !!", cmd, outError)
				return errors.New("Operational error")
			}

			err = fill_ipv4_entry(prfxVal.([]interface{}), prfxKey, aftsObjIpv4, nhindex)

			if err != nil {
				return err
			}
		}
	}
	return err
}

var DbToYang_ipv6_route_get_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

	var err error
	var aftsObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts
	var niName string
	var prefix string
	var nhindex uint64

	aftsObj, niName, prefix, nhindex, err = getIpRoot(inParams)
	_ = niName

	if err != nil {
		return err
	}

	aftsObjIpv6 := aftsObj.Ipv6Unicast
	if aftsObjIpv6 == nil {
		return errors.New("Network-instance IPv6 unicast object missing")
	}
	ygot.BuildEmptyTree(aftsObjIpv6)

	var outputJson map[string]interface{}
	cmd := "show ipv6 route vrf " + niName
	if len(prefix) > 0 {
		cmd += " "
		cmd += prefix
	}
	cmd += " json"
	log.Infof("vty cmd [%s]", cmd)

	if outputJson, err = exec_vtysh_cmd(cmd); err == nil {

		for prfxKey, prfxVal := range outputJson {
			if outError, ok := outputJson["warning"]; ok {
				log.Errorf("\"%s\" VTYSH-cmd execution failed with error-msg ==> \"%s\" !!", cmd, outError)
				return errors.New("Operational error")
			}

			err = fill_ipv6_entry(prfxVal.([]interface{}), prfxKey, aftsObjIpv6, nhindex)

			if err != nil {
				return err
			}
		}
	}
	return err
}

type _xfmr_ipv4_mroute_state_key struct {
	niName  string
	grpAddr string
	srcAddr string
	oifKey  string
}

func fill_ipv4_mroute_state_info(inParams XfmrParams, ipv4MrouteStateKey _xfmr_ipv4_mroute_state_key, srcAddrData map[string]interface{},
	srcEntryStateObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State) bool {
	srcEntryStateObj.SourceAddress = &ipv4MrouteStateKey.srcAddr

	if value, ok := srcAddrData["iil"]; ok {
		_nativeIncomingIntfId := value.(string)
		if _nativeIncomingIntfId != "<none>" {
			var _uiIncomingIntfId string
			util_iprib_get_ui_ifname_from_native_ifname(&_nativeIncomingIntfId, &_uiIncomingIntfId)
			srcEntryStateObj.IncomingInterface = &_uiIncomingIntfId
		}
	}

	if value, ok := srcAddrData["installed"]; ok {
		_installed32 := uint32(value.(float64))
		_installedBool := false
		if _installed32 == 1 {
			_installedBool = true
		}
		srcEntryStateObj.Installed = &_installedBool
	}

	if oilData, ok := srcAddrData["oil"].(map[string]interface{}); ok {
		var nativeOifKey string
		util_iprib_get_native_ifname_from_ui_ifname(&ipv4MrouteStateKey.oifKey, &nativeOifKey)

		for oif := range oilData {
			if (nativeOifKey != "") && (oif != nativeOifKey) {
				continue
			}
			oifData, ok := oilData[oif].(map[string]interface{})
			if !ok {
				continue
			}

			oilInfoEntries := srcEntryStateObj.OilInfoEntries
			if oilInfoEntries == nil {
				var _oilInfoEntries ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State_OilInfoEntries
				srcEntryStateObj.OilInfoEntries = &_oilInfoEntries
				oilInfoEntries = srcEntryStateObj.OilInfoEntries
				ygot.BuildEmptyTree(oilInfoEntries)
			}

			var _uiOifId string
			util_iprib_get_ui_ifname_from_native_ifname(&oif, &_uiOifId)
			OifInfoObj, ok := oilInfoEntries.OifInfo[_uiOifId]
			if !ok {
				OifInfoObj, _ = oilInfoEntries.NewOifInfo(_uiOifId)
				ygot.BuildEmptyTree(OifInfoObj)
			}

			oilInfoStateObj := OifInfoObj.State
			if oilInfoStateObj == nil {
				var _oilInfoStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State_OilInfoEntries_OifInfo_State
				OifInfoObj.State = &_oilInfoStateObj
				oilInfoStateObj = OifInfoObj.State
				ygot.BuildEmptyTree(oilInfoStateObj)
			}
			oilInfoStateObj.OutgoingInterface = &_uiOifId

			if value, ok := oifData["upTimeEpoch"]; ok {
				_uptime := uint64(value.(float64))
				oilInfoStateObj.Uptime = &_uptime
			}
		}
	}

	return true
}

var DbToYang_ipv4_mroute_get_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	operErr := errors.New("Opertational error")
	cmnLog := "GET: xfmr for IP-Mroute (IPv4-Multicast) State"

	aftsObj, niName, _, _, getErr := getIpRoot(inParams)
	if getErr != nil {
		log.Warningf("%s failed !! Error:%s", cmnLog, getErr)
		return operErr
	}

	cmd := "show ip mroute vrf " + niName + " json"
	ipMrouteOutputJson, cmdErr := exec_vtysh_cmd(cmd)
	if cmdErr != nil {
		log.Errorf("%s failed !! VTYSH-cmd : \"%s\" execution failed !! Error:%s", cmnLog, cmd, cmdErr)
		return operErr
	}

	if outError, ok := ipMrouteOutputJson["warning"]; ok {
		log.Errorf("%s failed !! VTYSH-cmd : \"%s\" execution failed !! Error:%s", cmnLog, cmd, outError)
		return operErr
	}

	aftsIpv4McastObj := aftsObj.Ipv4Multicast
	if aftsIpv4McastObj == nil {
		var _aftsIpv4McastObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast
		aftsObj.Ipv4Multicast = &_aftsIpv4McastObj
		aftsIpv4McastObj = aftsObj.Ipv4Multicast
		ygot.BuildEmptyTree(aftsIpv4McastObj)
	}

	pathInfo := NewPathInfo(inParams.uri)
	grpAddrKey := pathInfo.Var("group-address")
	srcAddrKey := pathInfo.Var("source-address")
	oifKey := pathInfo.Var("outgoing-interface")

	log.Info("DbToYang_ipv4_mroute_get_xfmr: ", cmnLog, " ==> URI: ", inParams.uri,
		" niName:", niName, " grpAddrKey:", grpAddrKey, " srcAddrKey:", srcAddrKey)

	var ipMrouteKey _xfmr_ipv4_mroute_state_key
	ipMrouteKey.niName = niName
	ipMrouteKey.oifKey = oifKey

	for grpAddr := range ipMrouteOutputJson {
		if (grpAddrKey != "") && (grpAddr != grpAddrKey) {
			continue
		}
		grpAddrData, ok := ipMrouteOutputJson[grpAddr].(map[string]interface{})
		if !ok {
			continue
		}

		ipv4EntriesObj := aftsIpv4McastObj.Ipv4Entries
		if ipv4EntriesObj == nil {
			var _ipv4EntriesObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast_Ipv4Entries
			aftsIpv4McastObj.Ipv4Entries = &_ipv4EntriesObj
			ipv4EntriesObj = aftsIpv4McastObj.Ipv4Entries
			ygot.BuildEmptyTree(ipv4EntriesObj)
		}

		ipv4EntryObj, ok := ipv4EntriesObj.Ipv4Entry[grpAddr]
		if !ok {
			ipv4EntryObj, _ = ipv4EntriesObj.NewIpv4Entry(grpAddr)
			ygot.BuildEmptyTree(ipv4EntryObj)
		}

		ipv4EntryStateObj := ipv4EntryObj.State
		if ipv4EntryStateObj == nil {
			var _ipv4EntryStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast_Ipv4Entries_Ipv4Entry_State
			ipv4EntryObj.State = &_ipv4EntryStateObj
			ipv4EntryStateObj = ipv4EntryObj.State
			ygot.BuildEmptyTree(ipv4EntryStateObj)
		}

		ipMrouteKey.grpAddr = grpAddr
		_grpAddr := grpAddr
		ipv4EntryStateObj.GroupAddress = &_grpAddr

		for srcAddr := range grpAddrData {
			if (srcAddrKey != "") && (srcAddr != srcAddrKey) {
				continue
			}
			srcAddrData, ok := grpAddrData[srcAddr].(map[string]interface{})
			if !ok {
				continue
			}

			srcEntriesObj := ipv4EntryStateObj.SrcEntries
			if srcEntriesObj == nil {
				var _srcEntriesObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast_Ipv4Entries_Ipv4Entry_State_SrcEntries
				ipv4EntryStateObj.SrcEntries = &_srcEntriesObj
				srcEntriesObj = ipv4EntryStateObj.SrcEntries
				ygot.BuildEmptyTree(srcEntriesObj)
			}

			srcEntryObj, ok := srcEntriesObj.SrcEntry[srcAddr]
			if !ok {
				srcEntryObj, _ = srcEntriesObj.NewSrcEntry(srcAddr)
				ygot.BuildEmptyTree(srcEntryObj)
			}

			srcEntryStateObj := srcEntryObj.State
			if srcEntryStateObj == nil {
				var _srcEntryStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Multicast_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State
				srcEntryObj.State = &_srcEntryStateObj
				srcEntryStateObj = srcEntryObj.State
				ygot.BuildEmptyTree(srcEntryStateObj)
			}

			ipMrouteKey.srcAddr = srcAddr

			fill_ipv4_mroute_state_info(inParams, ipMrouteKey, srcAddrData, srcEntryStateObj)
		}
	}

	return err
}

var Subscribe_ipv4_mroute_get_xfmr SubTreeXfmrSubscribe = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	var err error
	var result XfmrSubscOutParams

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	log.Infof("Subscribe_ipv4_mroute_get_xfmr path:%s; template:%s targetUriPath:%s", pathInfo.Path, pathInfo.Template, targetUriPath)

	result.isVirtualTbl = true
	return result, err
}

func get_rpc_show_ipmroute_sub_cmd_for_summary_(mapData map[string]interface{}) (bool, string, string) {
	_summary, ok := mapData["summary"].(bool)
	if !ok {
		return false, "summary mandatory attribute missing", ""
	}

	if !_summary {
		return false, "summary attribute value should be true", ""
	}

	return true, "", "summary json"
}

func get_rpc_show_ipmroute_sub_cmd_(mapData map[string]interface{}) (bool, string, string) {
	queryType, ok := mapData["query-type"].(string)
	if !ok {
		err := "Mandatory parameter query-type is not present"
		log.Info("In get_rpc_show_ipmroute_sub_cmd_ : ", err)
		return false, err, ""
	}

	log.Info("In get_rpc_show_ipmroute_sub_cmd_ ==> queryType : ", queryType)
	switch queryType {
	case "SUMMARY":
		return get_rpc_show_ipmroute_sub_cmd_for_summary_(mapData)
	default:
		err := "Invalid value in query-type attribute : " + queryType
		log.Info("In get_rpc_show_ipmroute_sub_cmd_ : ", err)
		return false, err, ""
	}
}

var rpc_show_ipmroute RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
	log.Info("In rpc_show_ipmroute")
	var err error
	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Info("Failed to unmarshall given input data")
		return nil, errors.New("RPC show ipmroute, invalid input")
	}

	var result struct {
		Output struct {
			Status string `json:"response"`
		} `json:"sonic-ipmroute-show:output"`
	}

	log.Info("In rpc_show_ipmroute, RPC data:", mapData)

	input := mapData["sonic-ipmroute-show:input"]
	mapData = input.(map[string]interface{})

	vrf_name := "default"
	if value, ok := mapData["vrf-name"].(string); ok {
		vrf_name = value
	}

	af_str := "ip"
	if value, ok := mapData["address-family"].(string); ok {
		if value != "IPV4_UNICAST" {
			dbg_err_str := "show ipmroute RPC execution failed ==> Invalid value in address-family attribute"
			log.Info("In rpc_show_ipmroute : ", dbg_err_str)
			return nil, errors.New(dbg_err_str)
		}
	}

	ok, err_str, subCmd := get_rpc_show_ipmroute_sub_cmd_(mapData)
	if !ok {
		dbg_err_str := "show ipmroute RPC execution failed ==> " + err_str
		log.Info("In rpc_show_ipmroute, ", dbg_err_str)
		return nil, errors.New(dbg_err_str)
	}

	cmd := "show " + af_str + " mroute vrf " + vrf_name + " " + subCmd

	ipmrouteOutput, err := exec_raw_vtysh_cmd(cmd)
	if err != nil {
		dbg_err_str := "FRR execution failed ==> " + err_str
		log.Info("In rpc_show_ipmroute, ", dbg_err_str)
		return nil, errors.New("Internal error!")
	}

	result.Output.Status = ipmrouteOutput
	return json.Marshal(&result)
}

func get_rpc_clear_ipmroute_sub_cmd_for_all_mroutes(mapData map[string]interface{}) (bool, string, string) {
	_allMroutes, ok := mapData["all-mroutes"].(bool)
	if !ok {
		return false, "all-mroutes mandatory attribute missing", ""
	}

	if !_allMroutes {
		return false, "all-mroutes attribute value should be true", ""
	}

	return true, "", ""
}

func get_rpc_clear_ipmroute_sub_cmd_(mapData map[string]interface{}) (bool, string, string) {
	configType, ok := mapData["config-type"].(string)
	if !ok {
		err := "Mandatory parameter config-type is not present"
		log.Info("In get_rpc_clear_ipmroute_sub_cmd_ : ", err)
		return false, err, ""
	}

	log.Info("In get_rpc_clear_ipmroute_sub_cmd_ ==> configType : ", configType)
	switch configType {
	case "ALL-MROUTES":
		return get_rpc_clear_ipmroute_sub_cmd_for_all_mroutes(mapData)
	default:
		err := "Invalid value in config-type attribute : " + configType
		log.Info("In get_rpc_clear_ipmroute_sub_cmd_ : ", err)
		return false, err, ""
	}
}

var rpc_clear_ipmroute RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
	log.Info("In rpc_clear_ipmroute")
	var err error
	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Info("Failed to unmarshall given input data")
		return nil, errors.New("RPC clear ipmroute, invalid input")
	}

	var result struct {
		Output struct {
			Status string `json:"response"`
		} `json:"sonic-ipmroute-clear:output"`
	}

	log.Info("In rpc_clear_ipmroute, RPC data:", mapData)

	input := mapData["sonic-ipmroute-clear:input"]
	mapData = input.(map[string]interface{})

	vrf_name := "default"
	if value, ok := mapData["vrf-name"].(string); ok {
		vrf_name = value
	}

	af_str := "ip"
	if value, ok := mapData["address-family"].(string); ok {
		if value != "IPV4_UNICAST" {
			dbg_err_str := "clear ipmroute RPC execution failed ==> Invalid value in address-family attribute"
			log.Info("In rpc_clear_ipmroute : ", dbg_err_str)
			return nil, errors.New(dbg_err_str)
		}
	}

	ok, err_str, subCmd := get_rpc_clear_ipmroute_sub_cmd_(mapData)
	if !ok {
		dbg_err_str := "clear ipmroute RPC execution failed ==> " + err_str
		log.Info("In rpc_clear_ipmroute, ", dbg_err_str)
		return nil, errors.New(dbg_err_str)
	}

	cmd := "clear " + af_str + " mroute vrf " + vrf_name + " " + subCmd
	cmd = strings.TrimSuffix(cmd, " ")

	ipmrouteOutput, err := exec_raw_vtysh_cmd(cmd)
	if err != nil {
		dbg_err_str := "FRR execution failed ==> " + err_str
		log.Info("In rpc_clear_ipmroute, ", dbg_err_str)
		return nil, errors.New("Internal error!")
	}

	if len(ipmrouteOutput) != 0 {
		result.Output.Status = ipmrouteOutput
	} else {
		result.Output.Status = "Success"
	}

	return json.Marshal(&result)
}
