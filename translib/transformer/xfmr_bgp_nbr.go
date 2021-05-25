package transformer

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

/* NOTE: */
/* The BGP unnumbered nbr can be in native(Ethernet0) or standard (Eth1/1) format,
   for DB access it has to be in native format. Convert wherever needed.
   Also xfmr infra expecting DBDatamap to have this key in user give format
   So make sure returned key is in that format.  */

func init() {
	XlateFuncBind("bgp_nbr_tbl_xfmr", bgp_nbr_tbl_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_tbl_key_xfmr", YangToDb_bgp_nbr_tbl_key_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_tbl_key_xfmr", DbToYang_bgp_nbr_tbl_key_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_address_fld_xfmr", YangToDb_bgp_nbr_address_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_address_fld_xfmr", DbToYang_bgp_nbr_address_fld_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_peer_type_fld_xfmr", YangToDb_bgp_nbr_peer_type_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_peer_type_fld_xfmr", DbToYang_bgp_nbr_peer_type_fld_xfmr)
	XlateFuncBind("bgp_af_nbr_tbl_xfmr", bgp_af_nbr_tbl_xfmr)
	XlateFuncBind("YangToDb_bgp_af_nbr_tbl_key_xfmr", YangToDb_bgp_af_nbr_tbl_key_xfmr)
	XlateFuncBind("DbToYang_bgp_af_nbr_tbl_key_xfmr", DbToYang_bgp_af_nbr_tbl_key_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_asn_fld_xfmr", YangToDb_bgp_nbr_asn_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_asn_fld_xfmr", DbToYang_bgp_nbr_asn_fld_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_afi_safi_name_fld_xfmr", YangToDb_bgp_nbr_afi_safi_name_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_afi_safi_name_fld_xfmr", DbToYang_bgp_nbr_afi_safi_name_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbrs_nbr_state_xfmr", DbToYang_bgp_nbrs_nbr_state_xfmr)
	XlateFuncBind("Subscribe_bgp_nbrs_nbr_state_xfmr", Subscribe_bgp_nbrs_nbr_state_xfmr)
	XlateFuncBind("DbToYang_bgp_nbrs_nbr_af_state_xfmr", DbToYang_bgp_nbrs_nbr_af_state_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_community_type_fld_xfmr", YangToDb_bgp_nbr_community_type_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_community_type_fld_xfmr", DbToYang_bgp_nbr_community_type_fld_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_orf_type_fld_xfmr", YangToDb_bgp_nbr_orf_type_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_orf_type_fld_xfmr", DbToYang_bgp_nbr_orf_type_fld_xfmr)
	XlateFuncBind("YangToDb_bgp_nbr_tx_add_paths_fld_xfmr", YangToDb_bgp_nbr_tx_add_paths_fld_xfmr)
	XlateFuncBind("DbToYang_bgp_nbr_tx_add_paths_fld_xfmr", DbToYang_bgp_nbr_tx_add_paths_fld_xfmr)
	XlateFuncBind("YangToDb_bgp_nbrs_nbr_auth_password_xfmr", YangToDb_bgp_nbrs_nbr_auth_password_xfmr)
	XlateFuncBind("DbToYang_bgp_nbrs_nbr_auth_password_xfmr", DbToYang_bgp_nbrs_nbr_auth_password_xfmr)
	XlateFuncBind("bgp_validate_nbr_af", bgp_validate_nbr_af)
	XlateFuncBind("DbToYangPath_bgp_nbr_path_xfmr", DbToYangPath_bgp_nbr_path_xfmr)
	XlateFuncBind("Subscribe_bgp_nbrs_nbr_auth_password_xfmr", Subscribe_bgp_nbrs_nbr_auth_password_xfmr)
}

func bgp_validate_nbr_af(inParams XfmrParams) bool {
	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _, _ := XfmrRemoveXPATHPredicates(inParams.uri)
	// /openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/afi-safis/afi-safi/
	// Ignore the above prefix of length 125 to save the string compare time
	targetUriPath = targetUriPath[125:]
	afiSafiName := pathInfo.Var("afi-safi-name")
	if log.V(3) {
		log.Info("bgp_validate_nbr_af: VRF ", pathInfo.Var("name"), " URI ",
			inParams.uri, " AFi-SAFI ", afiSafiName, " Target URI ", targetUriPath)
	}
	switch targetUriPath {
	case "ipv4-unicast":
		if afiSafiName != "IPV4_UNICAST" {
			return false
		}
	case "ipv6-unicast":
		if afiSafiName != "IPV6_UNICAST" {
			return false
		}
	case "l2vpn-evpn":
		if afiSafiName != "L2VPN_EVPN" {
			return false
		}
	}
	return true
}

func util_fill_db_datamap_per_bgp_nbr_from_frr_info(inParams XfmrParams, vrf string, nbrAddr string,
	afiSafiType ocbinds.E_OpenconfigBgpTypes_AFI_SAFI_TYPE,
	peerData map[string]interface{}) {
	/* The nbrAddr can be in native(Ethernet0) or standard (Eth1/1) format,
	   for DB access it has to be in native format. Convert wherever needed.
	   Also xfmr infra expecting DBDatamap to have this key in user give format
	   So make sure returned key is in that format.  */
	afiSafiDbType := "ipv4_unicast"
	if afiSafiType == ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST {
		afiSafiDbType = "ipv6_unicast"
	}
	if afiSafiType == ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_L2VPN_EVPN {
		afiSafiDbType = "l2vpn_evpn"
	}

	key := vrf + "|" + nbrAddr + "|" + afiSafiDbType
	nbrAfCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR_AF"}
	nativeNbr := nbrAddr
	util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
	nbrAfEntryKey := db.Key{Comp: []string{vrf, nativeNbr, afiSafiDbType}}
	entryValue, _ := inParams.d.GetEntry(nbrAfCfgTblTs, nbrAfEntryKey)
	(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"][key] = entryValue

	if value, ok := peerData["dynamicPeer"].(bool); ok {
		if !value {
			return
		}
	} else {
		return
	}

	key = vrf + "|" + nbrAddr
	if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"][key]; !ok {
		(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"][key] = db.Value{Field: make(map[string]string)}
	}
}

func util_fill_bgp_nbr_info_per_af_from_frr_info(inParams XfmrParams, vrf string, nbrAddr string,
	afiSafiType ocbinds.E_OpenconfigBgpTypes_AFI_SAFI_TYPE) {
	afiSafiName := "ipv4"
	frrJsonCacheQueryType := BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV4_SUMMARY
	if afiSafiType == ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST {
		afiSafiName = "ipv6"
		frrJsonCacheQueryType = BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV6_SUMMARY
	}
	cmd := "show ip bgp vrf " + vrf + " " + afiSafiName + " summary json"
	bgpFrrJsonCacheKey := bgp_frr_json_cache_query_key_t{niName: vrf, afiSafiName: afiSafiName}
	bgpNeighOutputJson, _ := utl_bgp_exec_vtysh_cmd(cmd, inParams, frrJsonCacheQueryType, bgpFrrJsonCacheKey)

	if _, ok := bgpNeighOutputJson["warning"]; ok {
		return
	}

	ipUcastFrrContainer := "ipv4Unicast"
	if afiSafiType == ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST {
		ipUcastFrrContainer = "ipv6Unicast"
	}

	ipUnicast, ok := bgpNeighOutputJson[ipUcastFrrContainer].(map[string]interface{})
	if !ok {
		return
	}
	peers, ok := ipUnicast["peers"].(map[string]interface{})
	if !ok {
		return
	}

	if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"]; !ok {
		(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"] = make(map[string]db.Value)
	}
	if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"]; !ok {
		(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"] = make(map[string]db.Value)
	}

	if len(nbrAddr) != 0 {
		/* FRR json output the nbr address(for unnumbered case) will be in native format(Ethernet0).
		   So access to that has to be in native format, the nbr address can be native or standard
		   convert to native and access FRR data.*/
		nativeNbr := nbrAddr
		util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
		peerData, ok := peers[nativeNbr].(map[string]interface{})
		if !ok {
			return
		}
		util_fill_db_datamap_per_bgp_nbr_from_frr_info(inParams, vrf, nbrAddr, afiSafiType, peerData)
	} else {
		for peer, peerData := range peers {
			/* FRR json output the nbr address(for unnumbered case) will be in native format(Ethernet0).
			   below function needs it in user give way (can be Ethernet0 or Eth1/1). So convert from
			   native format and pass it */
			util_bgp_get_ui_ifname_from_native_ifname(&peer)
			util_fill_db_datamap_per_bgp_nbr_from_frr_info(inParams, vrf, peer, afiSafiType, peerData.(map[string]interface{}))
		}
	}
}

func util_fill_bgp_nbr_info_for_evpn_from_frr_info(inParams XfmrParams, vrf string, nbrAddr string) {
	cmd := "show bgp vrf all l2vpn evpn summary json"
	evpnSummaryOutputJson, _ := exec_vtysh_cmd(cmd)

	if _, ok := evpnSummaryOutputJson["warning"]; ok {
		return
	}

	evpnVrfSummary, ok := evpnSummaryOutputJson[vrf].(map[string]interface{})
	if !ok {
		return
	}

	peers, ok := evpnVrfSummary["peers"].(map[string]interface{})
	if !ok {
		return
	}

	if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"]; !ok {
		(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"] = make(map[string]db.Value)
	}
	if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"]; !ok {
		(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"] = make(map[string]db.Value)
	}

	if len(nbrAddr) != 0 {
		nativeNbr := nbrAddr
		util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
		peerData, ok := peers[nativeNbr].(map[string]interface{})
		if !ok {
			return
		}
		util_fill_db_datamap_per_bgp_nbr_from_frr_info(inParams, vrf, nbrAddr, ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_L2VPN_EVPN, peerData)
	} else {
		for peer, peerData := range peers {
			util_bgp_get_ui_ifname_from_native_ifname(&peer)
			util_fill_db_datamap_per_bgp_nbr_from_frr_info(inParams, vrf, peer, ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_L2VPN_EVPN, peerData.(map[string]interface{}))
		}
	}
}

func fill_bgp_nbr_details_from_frr_info(inParams XfmrParams, vrf string, nbrAddr string) {
	util_fill_bgp_nbr_info_per_af_from_frr_info(inParams, vrf, nbrAddr, ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
	util_fill_bgp_nbr_info_per_af_from_frr_info(inParams, vrf, nbrAddr, ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
	util_fill_bgp_nbr_info_for_evpn_from_frr_info(inParams, vrf, nbrAddr)
}

var bgp_nbr_tbl_xfmr TableXfmrFunc = func(inParams XfmrParams) ([]string, error) {
	var tblList []string
	if log.V(3) {
		log.Info("bgp_nbr_tbl_xfmr target URI:", inParams.uri)
	}
	pathInfo := NewPathInfo(inParams.uri)

	vrf := pathInfo.Var("name")
	bgpId := pathInfo.Var("identifier")
	protoName := pathInfo.Var("name#2")
	nbrAddr := pathInfo.Var("neighbor-address")

	if len(pathInfo.Vars) < 3 {
		err := errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return tblList, err
	}

	if len(vrf) == 0 {
		err := errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return tblList, err
	}
	if !strings.Contains(bgpId, "BGP") {
		err := errors.New("BGP ID is missing")
		log.Info("BGP ID is missing")
		return tblList, err
	}
	if len(protoName) == 0 {
		err := errors.New("Protocol Name is missing")
		log.Info("Protocol Name is Missing")
		return tblList, err
	}

	if inParams.oper != GET {
		tblList = append(tblList, "BGP_NEIGHBOR")
		return tblList, nil
	}

	tblList = append(tblList, "BGP_NEIGHBOR")
	_, present := inParams.txCache.Load(vrf)

	if inParams.dbDataMap != nil {
		if !present {
			inParams.txCache.Store(vrf, vrf)
		} else {
			if log.V(3) {
				log.Info("bgp_nbr_tbl_xfmr: repetitive table update is avoided for target URI:", inParams.uri)
			}
			return tblList, nil
		}
	}
	/* The nbrAddr can be in native(Ethernet0) or standard (Eth1/1) format,
	   for DB access it has to be in native format. Convert wherever needed.
	   Also xfmr infra expecting DBDatamap to have this key in user give format
	   So make sure returned key is in that format.  */
	if len(nbrAddr) != 0 {
		key := vrf + "|" + nbrAddr
		/* For dynamic BGP nbrs, if isVirtualTbl not set, infra will try to get from config DB and fails
		   with Resource not found. For now for any specific nbr requests, check and set isVirtualTble.
		   From xfmr infra looks like when parent table key check happens the dbDataMap is nil. So for this
		   condition, and if cache is not updated set the virtual table */
		if inParams.dbDataMap == nil && !present {
			reqUriPath, _ := getYangPathFromUri(inParams.requestUri)
			if strings.HasPrefix(reqUriPath, "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor") {
				*inParams.isVirtualTbl = true
				if log.V(3) {
					log.Info("bgp_nbr_tbl_xfmr specific nbr get, set isVirtualTbl to true:", " ReqURI: ", inParams.requestUri)
				}
			}
			return tblList, nil
		}
		if inParams.dbDataMap != nil {
			if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"]; !ok {
				(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"] = make(map[string]db.Value)
			}
			if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"][key]; !ok {
				nbrCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR"}
				nativeNbr := nbrAddr
				util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
				nbrEntryKey := db.Key{Comp: []string{vrf, nativeNbr}}
				entryValue, err := inParams.d.GetEntry(nbrCfgTblTs, nbrEntryKey)
				if err == nil {
					(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"][key] = entryValue
				}
			}

			fill_bgp_nbr_details_from_frr_info(inParams, vrf, nbrAddr)
		}
	} else {
		if inParams.dbDataMap != nil {
			nbrKeys, _ := inParams.d.GetKeysByPattern(&db.TableSpec{Name: "BGP_NEIGHBOR"}, vrf+"|*")
			if len(nbrKeys) > 0 {
				if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"]; !ok {
					(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"] = make(map[string]db.Value)
				}
				for _, nkey := range nbrKeys {

					uiNbr := nkey.Get(1)
					util_bgp_get_ui_ifname_from_native_ifname(&uiNbr)
					key := nkey.Get(0) + "|" + uiNbr
					if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"][key]; !ok {
						nbrCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR"}
						nbrEntryKey := db.Key{Comp: []string{nkey.Get(0), nkey.Get(1)}}
						entryValue, err := inParams.d.GetEntry(nbrCfgTblTs, nbrEntryKey)
						if err == nil {
							(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR"][key] = entryValue
						}
					}
				}
			}

			fill_bgp_nbr_details_from_frr_info(inParams, vrf, "")
		}
	}

	return tblList, nil
}

var YangToDb_bgp_nbr_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err, oerr error
	var vrfName string
	var isLocalIpExist bool

	pathInfo := NewPathInfo(inParams.uri)

	/* Key should contain, <vrf name, protocol name, neighbor name> */

	vrfName = pathInfo.Var("name")
	bgpId := pathInfo.Var("identifier")
	protoName := pathInfo.Var("name#2")
	nbrAddr := pathInfo.Var("neighbor-address")

	if len(pathInfo.Vars) < 3 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return vrfName, err
	}

	if len(vrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return "", err
	}
	if !strings.Contains(bgpId, "BGP") {
		err = errors.New("BGP ID is missing")
		log.Info("BGP ID is missing")
		return "", err
	}
	if len(protoName) == 0 {
		err = errors.New("Protocol Name is missing")
		log.Info("Protocol Name is Missing")
		return "", err
	}
	if len(nbrAddr) == 0 {
		return "", nil
	}
	if (inParams.oper == CREATE) || (inParams.oper == REPLACE) || (inParams.oper == UPDATE) {
		isLocalIpExist, oerr = checkLocalIpExist(inParams.d, nbrAddr)
		if oerr == nil && isLocalIpExist {
			errStr := "Can not configure the local system IP as neighbor"
			err = tlerr.InvalidArgsError{Format: errStr}
			log.Error(errStr)
			return nbrAddr, err
		}
	}

	var pNbrKey string = vrfName + "|" + nbrAddr
	if log.V(3) {
		log.Info("YangToDb_bgp_nbr_tbl_key_xfmr Nbr key:", pNbrKey)
	}
	return pNbrKey, nil
}

var DbToYang_bgp_nbr_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	pathInfo := NewPathInfo(inParams.uri)
	vrfName := pathInfo.Var("name")

	nbrKey := strings.Split(inParams.key, "|")
	if len(nbrKey) < 2 {
		return nil, nil
	}

	if vrfName != nbrKey[0] {
		return nil, nil
	}

	rmap := make(map[string]interface{})

	nbrName := nbrKey[1]

	rmap["neighbor-address"] = nbrName
	return rmap, nil
}

var YangToDb_bgp_nbr_asn_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	var err error
	if inParams.param == nil {
		err = errors.New("No Params")
		return res_map, err
	}

	log.Info("YangToDb_bgp_nbr_asn_fld_xfmr: Xpath ", inParams.uri)
	if inParams.oper == DELETE {
		res_map["asn"] = ""
		return res_map, nil
	}

	pathInfo := NewPathInfo(inParams.uri)
	vrf := pathInfo.Var("name")
	pNbrAddr := pathInfo.Var("neighbor-address")
	if (len(vrf) == 0) || (len(pNbrAddr) == 0) {
		err = errors.New("Missing Params to make key")
		return res_map, err
	}

	nbrCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR"}
	/* Form the key */
	util_bgp_get_native_ifname_from_ui_ifname(&pNbrAddr)
	neigh_key := db.Key{Comp: []string{vrf, pNbrAddr}}

	entryValue, err := inParams.d.GetEntry(nbrCfgTblTs, neigh_key)
	if err == nil {
		neigh_field := entryValue.Field
		if value, ok := neigh_field["peer_type"]; ok {
			err = errors.New("Can't specify  ASN as BGP neighbor as peer type is set to " + value)
			return res_map, err
		}
	}

	asn_no, _ := inParams.param.(*uint32)

	log.Info("YangToDb_bgp_nbr_asn_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " asn : ", *asn_no)

	res_map["asn"] = strconv.FormatUint(uint64(*asn_no), 10)
	return res_map, nil
}

var DbToYang_bgp_nbr_asn_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.V(3).Info("DbToYang_bgp_nbr_asn_fld_xfmr : ", data, "inParams : ", inParams)

	pTbl := data["BGP_NEIGHBOR"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_bgp_nbr_asn_fld_xfmr BGP neighbor not found : ", inParams.key)
		return result, errors.New("BGP neighbor not found : " + inParams.key)
	}
	pGrpKey := pTbl[inParams.key]
	asn, ok := pGrpKey.Field["asn"]

	if ok {
		result["peer-as"], _ = strconv.ParseFloat(asn, 64)
	} else {
		log.Info("asn field not found in DB")
	}
	return result, nil
}

var YangToDb_bgp_nbr_peer_type_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

	res_map := make(map[string]string)

	var err error
	if inParams.param == nil {
		err = errors.New("No Params")
		return res_map, err
	}

	if inParams.oper == DELETE {
		res_map["peer_type"] = ""
		return res_map, nil
	}

	peer_type, _ := inParams.param.(ocbinds.E_OpenconfigBgp_PeerType)
	log.Info("YangToDb_bgp_nbr_peer_type_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " peer-type: ", peer_type)

	pathInfo := NewPathInfo(inParams.uri)

	vrf := pathInfo.Var("name")
	pNbrAddr := pathInfo.Var("neighbor-address")
	if (len(vrf) == 0) || (len(pNbrAddr) == 0) {
		err = errors.New("Missing Params to make key")
		return res_map, err
	}

	nbrCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR"}
	/* Form the key */
	/* DB access convert nbr to native format */
	util_bgp_get_native_ifname_from_ui_ifname(&pNbrAddr)
	neigh_key := db.Key{Comp: []string{vrf, pNbrAddr}}

	entryValue, err := inParams.d.GetEntry(nbrCfgTblTs, neigh_key)
	if err == nil {
		/* Either ASN or peer_type can be configured , not both */
		neigh_field := entryValue.Field
		if value, ok := neigh_field["asn"]; ok {
			err = errors.New("Can't specify  peer type as BGP neighbor as ASN is set to " + value)
			return res_map, err
		}
	}

	if peer_type == ocbinds.OpenconfigBgp_PeerType_INTERNAL {
		res_map["peer_type"] = "internal"
	} else if peer_type == ocbinds.OpenconfigBgp_PeerType_EXTERNAL {
		res_map["peer_type"] = "external"
	} else {
		err = errors.New("Peer Type Missing")
		return res_map, err
	}
	return res_map, nil
}

var DbToYang_bgp_nbr_peer_type_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.V(3).Info("DbToYang_bgp_nbr_peer_type_fld_xfmr : ", data, "inParams : ", inParams)

	pTbl := data["BGP_NEIGHBOR"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_bgp_nbr_peer_type_fld_xfmr BGP neighbor not found : ", inParams.key)
		return result, errors.New("BGP neighbor not found : " + inParams.key)
	}
	pGrpKey := pTbl[inParams.key]
	peer_type, ok := pGrpKey.Field["peer_type"]

	if ok {
		if peer_type == "internal" {
			result["peer-type"] = "INTERNAL"
		} else if peer_type == "external" {
			result["peer-type"] = "EXTERNAL"
		}
	} else {
		log.Info("peer_type field not found in DB")
	}
	return result, nil
}

var YangToDb_bgp_nbr_tx_add_paths_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	var err error
	if inParams.param == nil {
		err = errors.New("No Params")
		return res_map, err
	}

	if inParams.oper == DELETE {
		res_map["tx_add_paths"] = ""
		return res_map, nil
	}

	tx_add_paths_type, _ := inParams.param.(ocbinds.E_OpenconfigBgpExt_TxAddPathsType)
	log.Info("YangToDb_bgp_nbr_tx_add_paths_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " add-paths-type: ", tx_add_paths_type)

	if tx_add_paths_type == ocbinds.OpenconfigBgpExt_TxAddPathsType_TX_ALL_PATHS {
		res_map["tx_add_paths"] = "tx_all_paths"
	} else if tx_add_paths_type == ocbinds.OpenconfigBgpExt_TxAddPathsType_TX_BEST_PATH_PER_AS {
		res_map["tx_add_paths"] = "tx_best_path_per_as"
	} else {
		err = errors.New("Invalid add Paths type Missing")
		return res_map, err
	}

	return res_map, err

}

var DbToYang_bgp_nbr_tx_add_paths_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.V(3).Info("DbToYang_bgp_nbr_tx_add_paths_fld_xfmr: ", data, "inParams : ", inParams)

	pTbl := data["BGP_NEIGHBOR_AF"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_bgp_nbr_tx_add_paths_fld_xfmr BGP neighbor not found : ", inParams.key)
		return result, errors.New("BGP neighbor not found : " + inParams.key)
	}
	pNbrKey := pTbl[inParams.key]
	tx_add_paths_type, ok := pNbrKey.Field["tx_add_paths"]

	if ok {
		if tx_add_paths_type == "tx_all_paths" {
			result["tx-add-paths"] = "TX_ALL_PATHS"
		} else if tx_add_paths_type == "tx_best_path_per_as" {
			result["tx-add-paths"] = "TX_BEST_PATH_PER_AS"
		}
	}
	return result, err
}

var YangToDb_bgp_nbr_address_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_bgp_nbr_address_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	result := make(map[string]interface{})

	entry_key := inParams.key
	nbrAddrKey := strings.Split(entry_key, "|")
	if len(nbrAddrKey) < 2 {
		return result, nil
	}

	nbrAddr := nbrAddrKey[1]

	result["neighbor-address"] = nbrAddr

	return result, err
}

var YangToDb_bgp_nbr_afi_safi_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_bgp_nbr_afi_safi_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	var nbrAfName string
	result := make(map[string]interface{})

	entry_key := inParams.key
	nbrAfKey := strings.Split(entry_key, "|")
	if len(nbrAfKey) < 3 {
		return result, nil
	}

	switch nbrAfKey[2] {
	case "ipv4_unicast":
		nbrAfName = "IPV4_UNICAST"
	case "ipv6_unicast":
		nbrAfName = "IPV6_UNICAST"
	case "l2vpn_evpn":
		nbrAfName = "L2VPN_EVPN"
	default:
		return result, nil
	}
	result["afi-safi-name"] = nbrAfName

	return result, err
}

var bgp_af_nbr_tbl_xfmr TableXfmrFunc = func(inParams XfmrParams) ([]string, error) {
	var err error
	var tblList []string

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
	// /openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/afi-safis/
	// Ignore the above prefix of length 116 to save the string compare time
	targetUriPath = targetUriPath[116:]
	afiSafiName := pathInfo.Var("afi-safi-name")
	if log.V(3) {
		log.Info("bgp_af_nbr_tbl_xfmr: URI ", inParams.uri, " AFI-SAFI ", afiSafiName, " target URI ",
			targetUriPath)
	}

	if len(afiSafiName) != 0 {
		switch targetUriPath {
		case "afi-safi/l2vpn-evpn":
			if !strings.Contains(afiSafiName, "L2VPN_EVPN") {
				if log.V(3) {
					log.Info("bgp_af_nbr_tbl_xfmr : ignored: l2vpn-evpn AF URI ", inParams.uri)
				}
				return tblList, err
			}
		case "afi-safi/ipv4-unicast":
			if !strings.Contains(afiSafiName, "IPV4_UNICAST") {
				if log.V(3) {
					log.Info("bgp_af_nbr_tbl_xfmr : ignored: ipv4-unicast AF URI ", inParams.uri)
				}
				return tblList, err
			}
		case "afi-safi/ipv6-unicast":
			if !strings.Contains(afiSafiName, "IPV6_UNICAST") {
				if log.V(3) {
					log.Info("bgp_af_nbr_tbl_xfmr : ignored: ipv6-unicast AF URI ", inParams.uri)
				}
				return tblList, err
			}
		}
	}
	vrf := pathInfo.Var("name")
	nbrAddr := pathInfo.Var("neighbor-address")

	if len(pathInfo.Vars) < 4 {
		err := errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return tblList, err
	}

	if len(vrf) == 0 {
		err_str := "VRF name is missing"
		err := errors.New(err_str)
		log.Info(err_str)
		return tblList, err
	}
	if len(nbrAddr) == 0 {
		err_str := "Neighbor Address is missing"
		err := errors.New(err_str)
		log.Info(err_str)
		return tblList, err
	}

	if inParams.oper != GET {
		tblList = append(tblList, "BGP_NEIGHBOR_AF")
		return tblList, nil
	}

	tblList = append(tblList, "BGP_NEIGHBOR_AF")
	/* to avoid this dbmap getting called, for same nbr, cache the nbr and check it,
	   if its present in cache, do not do anything */
	_, present := inParams.txCache.Load(nbrAddr)
	if inParams.dbDataMap != nil {
		if !present {
			inParams.txCache.Store(nbrAddr, nbrAddr)
		} else {
			if log.V(3) {
				log.Info("bgp_af_nbr_tbl_xfmr : repetitive table update is avoided for target URI:", inParams.uri)
			}
			return tblList, nil
		}
	}
	/* The nbrAddr can be in native(Ethernet0) or standard (Eth1/1) format,
	   for DB access it has to be in native format. Convert wherever needed.
	   Also xfmr infra expecting DBDatamap to have this key in user give format
	   So make sure returned key is in that format.  */

	if len(afiSafiName) != 0 {
		afiSafiEnum, afiSafiNameDbStr, ok := get_afi_safi_name_enum_dbstr_for_ocstr(afiSafiName)
		if !ok {
			err_str := "AFI-SAFI : " + afiSafiName + " not supported"
			err := errors.New(err_str)
			log.Info(err_str)
			return tblList, err
		}
		/* For dynamic BGP nbrs, if isVirtualTbl not set, infra will try to get from config DB and fails
		   with Resource not found. For now for any specific afi-safi requests, check and set isVirtualTble.
		   From xfmr infra looks like when parent table key check happens the dbDataMap is nil. So for this
		   condition, and if cache is not updated set the virtual table */
		if inParams.dbDataMap == nil && !present {
			reqUriPath, _ := getYangPathFromUri(inParams.requestUri)
			if strings.HasPrefix(reqUriPath, "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/afi-safis/afi-safi") {
				*inParams.isVirtualTbl = true
				if log.V(3) {
					log.Info("bgp_af_nbr_tbl_xfmr specific afi-safi get, set isVirtualTbl to true:", " ReqURI: ", inParams.requestUri)
				}
			}
			return tblList, nil
		}
		if inParams.dbDataMap != nil {
			if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"]; !ok {
				(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"] = make(map[string]db.Value)
			}
			key := vrf + "|" + nbrAddr + "|" + afiSafiNameDbStr
			if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"][key]; !ok {
				nbrAfCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR_AF"}
				nativeNbr := nbrAddr
				util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
				nbrAfEntryKey := db.Key{Comp: []string{vrf, nativeNbr, afiSafiNameDbStr}}
				entryValue, err := inParams.d.GetEntry(nbrAfCfgTblTs, nbrAfEntryKey)
				if err == nil {
					(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"][key] = entryValue
				}
			}
			if strings.Contains(afiSafiName, "L2VPN_EVPN") {
				util_fill_bgp_nbr_info_for_evpn_from_frr_info(inParams, vrf, nbrAddr)
			} else {
				util_fill_bgp_nbr_info_per_af_from_frr_info(inParams, vrf, nbrAddr, afiSafiEnum)
			}
		}
	} else {
		if inParams.dbDataMap != nil {
			nativeNbr := nbrAddr
			util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
			nbrKeys, _ := inParams.d.GetKeysByPattern(&db.TableSpec{Name: "BGP_NEIGHBOR_AF"}, vrf+"|"+nativeNbr+"|*")
			if len(nbrKeys) > 0 {
				if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"]; !ok {
					(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"] = make(map[string]db.Value)
				}
				for _, nkey := range nbrKeys {
					key := nkey.Get(0) + "|" + nbrAddr + "|" + nkey.Get(2)
					if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"][key]; !ok {
						nbrCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR_AF"}
						nbrEntryKey := db.Key{Comp: []string{nkey.Get(0), nkey.Get(1), nkey.Get(2)}}
						entryValue, err := inParams.d.GetEntry(nbrCfgTblTs, nbrEntryKey)
						if err == nil {
							(*inParams.dbDataMap)[db.ConfigDB]["BGP_NEIGHBOR_AF"][key] = entryValue
						}
					}
				}
			}
		}
	}

	return tblList, nil
}

var YangToDb_bgp_af_nbr_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {

	var err error
	var vrfName string

	pathInfo := NewPathInfo(inParams.uri)

	/* Key should contain, <vrf name, protocol name, neighbor name> */

	vrfName = pathInfo.Var("name")
	bgpId := pathInfo.Var("identifier")
	protoName := pathInfo.Var("name#2")
	nbr := pathInfo.Var("neighbor-address")
	afName := pathInfo.Var("afi-safi-name")

	if len(pathInfo.Vars) < 4 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return vrfName, err
	}

	if len(vrfName) == 0 {
		err = errors.New("vrf name is missing")
		log.Info("VRF Name is Missing")
		return vrfName, err
	}
	if !strings.Contains(bgpId, "BGP") {
		err = errors.New("BGP ID is missing")
		log.Info("BGP ID is missing")
		return bgpId, err
	}
	if len(protoName) == 0 {
		err = errors.New("Protocol Name is missing")
		log.Info("Protocol Name is Missing")
		return protoName, err
	}
	if len(nbr) == 0 {
		err = errors.New("Neighbor is missing")
		return nbr, err
	}

	if len(afName) == 0 {
		err = errors.New("AFI SAFI is missing")
		return afName, err
	}

	if strings.Contains(afName, "IPV4_UNICAST") {
		afName = "ipv4_unicast"
	} else if strings.Contains(afName, "IPV6_UNICAST") {
		afName = "ipv6_unicast"
	} else if strings.Contains(afName, "L2VPN_EVPN") {
		afName = "l2vpn_evpn"
	} else if strings.Contains(afName, "*") {
		afName = "*"
		log.Info("Wildcard set  AFI type " + afName)
	} else {
		err = errors.New("Unsupported AFI SAFI")
		log.Info("Unsupported AFI SAFI ", afName)
		return afName, err
	}

	var nbrAfKey string = vrfName + "|" + nbr + "|" + afName
	if log.V(3) {
		log.Info("YangToDb_bgp_af_nbr_tbl_key_xfmr Nbr AF key:", nbrAfKey)
	}
	return nbrAfKey, nil
}

var DbToYang_bgp_af_nbr_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var afName string
	pathInfo := NewPathInfo(inParams.uri)
	vrfName := pathInfo.Var("name")
	nbr := pathInfo.Var("neighbor-address")

	nbrAfKey := strings.Split(inParams.key, "|")
	if len(nbrAfKey) < 3 {
		return nil, nil
	}

	if (vrfName != nbrAfKey[0]) || (nbr != nbrAfKey[1]) {
		return nil, nil
	}

	rmap := make(map[string]interface{})

	switch nbrAfKey[2] {
	case "ipv4_unicast":
		afName = "IPV4_UNICAST"
	case "ipv6_unicast":
		afName = "IPV6_UNICAST"
	case "l2vpn_evpn":
		afName = "L2VPN_EVPN"
	default:
		return rmap, nil
	}

	rmap["afi-safi-name"] = afName

	return rmap, nil
}

type _xfmr_bgp_nbr_state_key struct {
	niName  string
	nbrAddr string
}

func get_spec_nbr_cfg_tbl_entry(cfgDb *db.DB, nbr_key *_xfmr_bgp_nbr_state_key) (map[string]string, error) {
	var err error

	/* For DB access nbr has to be in native(Ethernet0) format, convert it */
	nativeNbr := nbr_key.nbrAddr
	util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
	nbrCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR"}
	nbrEntryKey := db.Key{Comp: []string{nbr_key.niName, nativeNbr}}

	var entryValue db.Value
	if entryValue, err = cfgDb.GetEntry(nbrCfgTblTs, nbrEntryKey); err != nil {
		return nil, err
	}

	return entryValue.Field, err
}

func fill_nbr_state_cmn_info(nbr_key *_xfmr_bgp_nbr_state_key, frrNbrDataValue interface{}, cfgDb *db.DB,
	nbr_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor) error {
	var err error
	nbrState := nbr_obj.State
	nbrState.NeighborAddress = &nbr_key.nbrAddr

	if frrNbrDataValue != nil {
		frrNbrDataJson := frrNbrDataValue.(map[string]interface{})

		if value, ok := frrNbrDataJson["bgpState"]; ok {
			switch value {
			case "Idle":
				nbrState.SessionState = ocbinds.OpenconfigBgp_Bgp_Neighbors_Neighbor_State_SessionState_IDLE
			case "Connect":
				nbrState.SessionState = ocbinds.OpenconfigBgp_Bgp_Neighbors_Neighbor_State_SessionState_CONNECT
			case "Active":
				nbrState.SessionState = ocbinds.OpenconfigBgp_Bgp_Neighbors_Neighbor_State_SessionState_ACTIVE
			case "OpenSent":
				nbrState.SessionState = ocbinds.OpenconfigBgp_Bgp_Neighbors_Neighbor_State_SessionState_OPENSENT
			case "OpenConfirm":
				nbrState.SessionState = ocbinds.OpenconfigBgp_Bgp_Neighbors_Neighbor_State_SessionState_OPENCONFIRM
			case "Established":
				nbrState.SessionState = ocbinds.OpenconfigBgp_Bgp_Neighbors_Neighbor_State_SessionState_ESTABLISHED
			}
		}

		if value, ok := frrNbrDataJson["adminShutDown"]; ok && value == true {
			_enabled, _ := strconv.ParseBool("false")
			nbrState.Enabled = &_enabled
		} else {
			_enabled, _ := strconv.ParseBool("true")
			nbrState.Enabled = &_enabled
		}

		if value, ok := frrNbrDataJson["localAs"]; ok {
			_localAs := uint32(value.(float64))
			nbrState.LocalAs = &_localAs
		}

		if value, ok := frrNbrDataJson["remoteAs"]; ok {
			_peerAs := uint32(value.(float64))
			nbrState.PeerAs = &_peerAs
		}

		if value, ok := frrNbrDataJson["portForeign"]; ok {
			_peerPort := uint16(value.(float64))
			nbrState.PeerPort = &_peerPort
		}

		if value, ok := frrNbrDataJson["bgpTimerUpEstablishedEpoch"]; ok {
			_lastEstablished := uint64(value.(float64))
			nbrState.LastEstablished = &_lastEstablished
		}

		if routerId, ok := frrNbrDataJson["remoteRouterId"]; ok {
			_routerId := routerId.(string)
			nbrState.RemoteRouterId = &_routerId
		}

		if value, ok := frrNbrDataJson["connectionsEstablished"]; ok {
			_establishedTransitions := uint64(value.(float64))
			nbrState.EstablishedTransitions = &_establishedTransitions
		}

		if value, ok := frrNbrDataJson["connectionsDropped"]; ok {
			_connectionsDropped := uint64(value.(float64))
			nbrState.ConnectionsDropped = &_connectionsDropped
		}

		if value, ok := frrNbrDataJson["lastResetTimerMsecs"]; ok {
			_lastResetTimerSec := uint64(value.(float64)) / 1000
			nbrState.LastResetTime = &_lastResetTimerSec
		}

		if resetReason, ok := frrNbrDataJson["lastResetDueTo"]; ok {
			_resetReason := resetReason.(string)
			nbrState.LastResetReason = &_resetReason
		}

		if value, ok := frrNbrDataJson["bgpTimerLastRead"]; ok {
			_lastRead := uint64(value.(float64)) / 1000
			nbrState.LastRead = &_lastRead
		}

		if value, ok := frrNbrDataJson["bgpTimerLastWrite"]; ok {
			_lastWrite := uint64(value.(float64)) / 1000
			nbrState.LastWrite = &_lastWrite
		}

		if statsMap, ok := frrNbrDataJson["messageStats"].(map[string]interface{}); ok {
			var _rcvd_msgs ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_State_Messages_Received
			var _sent_msgs ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_State_Messages_Sent
			var _msgs ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_State_Messages
			var _queues ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_State_Queues
			_msgs.Received = &_rcvd_msgs
			_msgs.Sent = &_sent_msgs
			nbrState.Messages = &_msgs
			nbrState.Queues = &_queues

			if value, ok := statsMap["capabilityRecv"]; ok {
				_capability_rcvd := uint64(value.(float64))
				_rcvd_msgs.Capability = &_capability_rcvd
			}
			if value, ok := statsMap["keepalivesRecv"]; ok {
				_keepalive_rcvd := uint64(value.(float64))
				_rcvd_msgs.Keepalive = &_keepalive_rcvd
			}
			if value, ok := statsMap["notificationsRecv"]; ok {
				_notification_rcvd := uint64(value.(float64))
				_rcvd_msgs.NOTIFICATION = &_notification_rcvd
			}
			if value, ok := statsMap["opensRecv"]; ok {
				_open_rcvd := uint64(value.(float64))
				_rcvd_msgs.Open = &_open_rcvd
			}
			if value, ok := statsMap["routeRefreshRecv"]; ok {
				_routeRefresh_rcvd := uint64(value.(float64))
				_rcvd_msgs.RouteRefresh = &_routeRefresh_rcvd
			}
			if value, ok := statsMap["updatesRecv"]; ok {
				_update_rcvd := uint64(value.(float64))
				_rcvd_msgs.UPDATE = &_update_rcvd
			}

			if value, ok := statsMap["capabilitySent"]; ok {
				_capability_sent := uint64(value.(float64))
				_sent_msgs.Capability = &_capability_sent
			}
			if value, ok := statsMap["keepalivesSent"]; ok {
				_keepalive_sent := uint64(value.(float64))
				_sent_msgs.Keepalive = &_keepalive_sent
			}
			if value, ok := statsMap["notificationsSent"]; ok {
				_notification_sent := uint64(value.(float64))
				_sent_msgs.NOTIFICATION = &_notification_sent
			}
			if value, ok := statsMap["opensSent"]; ok {
				_open_sent := uint64(value.(float64))
				_sent_msgs.Open = &_open_sent
			}
			if value, ok := statsMap["routeRefreshSent"]; ok {
				_routeRefresh_sent := uint64(value.(float64))
				_sent_msgs.RouteRefresh = &_routeRefresh_sent
			}
			if value, ok := statsMap["updatesSent"]; ok {
				_update_sent := uint64(value.(float64))
				_sent_msgs.UPDATE = &_update_sent
			}

			if value, ok := statsMap["depthOutq"]; ok {
				_output := uint32(value.(float64))
				_queues.Output = &_output
			}
			if value, ok := statsMap["depthInq"]; ok {
				_input := uint32(value.(float64))
				_queues.Input = &_input
			}
		}
		nbrState.SupportedCapabilities = nil
		if capabMap, ok := frrNbrDataJson["neighborCapabilities"].(map[string]interface{}); ok {

			if value, ok := capabMap["4byteAs"].(string); ok {
				switch value {
				case "advertisedAndReceived":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ASN32)
				case "advertised":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ASN32_ADVERTISED_ONLY)
				case "received":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ASN32_RECEIVED_ONLY)
				}
			}

			if addPath, ok := capabMap["addPath"].(map[string]interface{}); ok {
				if ipv4UCast, ok := addPath["ipv4Unicast"].(map[string]interface{}); ok {
					if value, ok := ipv4UCast["rxAdvertised"].(bool); ok && value {
						nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ADD_PATHS_ADVERTISED_ONLY)
					}
					if value, ok := ipv4UCast["rxReceived"].(bool); ok && value {
						nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ADD_PATHS_RECEIVED_ONLY)
					}
					if value, ok := ipv4UCast["rxAdvertisedAndReceived"].(bool); ok && value {
						nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ADD_PATHS)
					}
				}
			}

			if value, ok := capabMap["routeRefresh"].(string); ok {
				switch value {
				case "advertisedAndReceivedOldNew":
					fallthrough
				case "advertisedAndReceivedOld":
					fallthrough
				case "advertisedAndReceivedNew":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ROUTE_REFRESH)
				case "advertised":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ROUTE_REFRESH_ADVERTISED_ONLY)
				case "received":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_ROUTE_REFRESH_RECEIVED_ONLY)
				}
			}

			if multi, ok := capabMap["multiprotocolExtensions"].(map[string]interface{}); ok {
				if ipv4UCast, ok := multi["ipv4Unicast"].(map[string]interface{}); ok {
					if value, ok := ipv4UCast["advertised"].(bool); ok && value {
						nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_MPBGP_ADVERTISED_ONLY)
					}
					if value, ok := ipv4UCast["received"].(bool); ok && value {
						nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_MPBGP_RECEIVED_ONLY)
					}
					if value, ok := ipv4UCast["advertisedAndReceived"].(bool); ok && value {
						nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_MPBGP)
					}
				}
			}

			if value, ok := capabMap["gracefulRestartCapability"].(string); ok {
				switch value {
				case "advertisedAndReceived":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_GRACEFUL_RESTART)
				case "advertised":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_GRACEFUL_RESTART_ADVERTISED_ONLY)
				case "received":
					nbrState.SupportedCapabilities = append(nbrState.SupportedCapabilities, ocbinds.OpenconfigBgpTypes_BGP_CAPABILITY_GRACEFUL_RESTART_RECEIVED_ONLY)
				}
			}
		}
	}
	_dynamically_cfred := true

	if cfgDbEntry, cfgdb_get_err := get_spec_nbr_cfg_tbl_entry(cfgDb, nbr_key); cfgdb_get_err == nil {
		if value, ok := cfgDbEntry["peer_group_name"]; ok {
			nbrState.PeerGroup = &value
		}

		if value, ok := cfgDbEntry["admin_status"]; ok {
			_enabled, _ := strconv.ParseBool(value)
			nbrState.Enabled = &_enabled
		}

		if value, ok := cfgDbEntry["shutdown_message"]; ok {
			nbrState.ShutdownMessage = &value
		}

		if value, ok := cfgDbEntry["name"]; ok {
			nbrState.Description = &value
		}

		if value, ok := cfgDbEntry["peer_type"]; ok {
			switch value {
			case "internal":
				nbrState.PeerType = ocbinds.OpenconfigBgp_PeerType_INTERNAL
			case "external":
				nbrState.PeerType = ocbinds.OpenconfigBgp_PeerType_EXTERNAL
			}
		}

		if value, ok := cfgDbEntry["disable_ebgp_connected_route_check"]; ok {
			_disableEbgpConnectedRouteCheck, _ := strconv.ParseBool(value)
			nbrState.DisableEbgpConnectedRouteCheck = &_disableEbgpConnectedRouteCheck
		}

		if value, ok := cfgDbEntry["enforce_first_as"]; ok {
			_enforceFirstAs, _ := strconv.ParseBool(value)
			nbrState.EnforceFirstAs = &_enforceFirstAs
		}

		if value, ok := cfgDbEntry["enforce_multihop"]; ok {
			_enforceMultihop, _ := strconv.ParseBool(value)
			nbrState.EnforceMultihop = &_enforceMultihop
		}

		if value, ok := cfgDbEntry["solo_peer"]; ok {
			_soloPeer, _ := strconv.ParseBool(value)
			nbrState.SoloPeer = &_soloPeer
		}

		if value, ok := cfgDbEntry["ttl_security_hops"]; ok {
			if _ttlSecurityHops_u64, err := strconv.ParseUint(value, 10, 8); err == nil {
				_ttlSecurityHops_u8 := uint8(_ttlSecurityHops_u64)
				nbrState.TtlSecurityHops = &_ttlSecurityHops_u8
			}
		}

		if value, ok := cfgDbEntry["capability_ext_nexthop"]; ok {
			_capabilityExtendedNexthop, _ := strconv.ParseBool(value)
			nbrState.CapabilityExtendedNexthop = &_capabilityExtendedNexthop
		}

		if value, ok := cfgDbEntry["capability_dynamic"]; ok {
			_capabilityDynamic, _ := strconv.ParseBool(value)
			nbrState.CapabilityDynamic = &_capabilityDynamic
		}

		if value, ok := cfgDbEntry["dont_negotiate_capability"]; ok {
			_dontNegotiateCapability, _ := strconv.ParseBool(value)
			nbrState.DontNegotiateCapability = &_dontNegotiateCapability
		}

		if value, ok := cfgDbEntry["override_capability"]; ok {
			_overrideCapability, _ := strconv.ParseBool(value)
			nbrState.OverrideCapability = &_overrideCapability
		}

		if value, ok := cfgDbEntry["strict_capability_match"]; ok {
			_strictCapabilityMatch, _ := strconv.ParseBool(value)
			nbrState.StrictCapabilityMatch = &_strictCapabilityMatch
		}

		if value, ok := cfgDbEntry["local_as_no_prepend"]; ok {
			_localAsNoPrepend, _ := strconv.ParseBool(value)
			nbrState.LocalAsNoPrepend = &_localAsNoPrepend
		}

		if value, ok := cfgDbEntry["local_as_replace_as"]; ok {
			_localAsReplaceAs, _ := strconv.ParseBool(value)
			nbrState.LocalAsReplaceAs = &_localAsReplaceAs
		}

		_dynamically_cfred = false
		nbrState.DynamicallyConfigured = &_dynamically_cfred
	} else {
		nbrState.DynamicallyConfigured = &_dynamically_cfred
	}

	return err
}

func fill_nbr_state_timers_info(nbr_key *_xfmr_bgp_nbr_state_key, frrNbrDataValue interface{}, cfgDb *db.DB,
	nbr_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor) error {
	var err error
	nbrTimersState := nbr_obj.Timers.State
	if frrNbrDataValue != nil {
		frrNbrDataJson := frrNbrDataValue.(map[string]interface{})

		if value, ok := frrNbrDataJson["bgpTimerHoldTimeMsecs"]; ok {
			_neg_hold_time := (value.(float64)) / 1000
			nbrTimersState.NegotiatedHoldTime = &_neg_hold_time
		}

		if value, ok := frrNbrDataJson["bgpTimerKeepAliveIntervalMsecs"]; ok {
			_keepaliveInterval := (value.(float64)) / 1000
			nbrTimersState.KeepaliveInterval = &_keepaliveInterval
		}

		if value, ok := frrNbrDataJson["minBtwnAdvertisementRunsTimerMsecs"]; ok {
			_minimumAdvertisementInterval := (value.(float64)) / 1000
			nbrTimersState.MinimumAdvertisementInterval = &_minimumAdvertisementInterval
		}

		if value, ok := frrNbrDataJson["connectRetryTimer"]; ok {
			_connectRetry := value.(float64)
			nbrTimersState.ConnectRetry = &_connectRetry
		}

		if value, ok := frrNbrDataJson["bgpTimerConfiguredHoldTimeMsecs"]; ok {
			_holdTime := (value.(float64)) / 1000
			nbrTimersState.HoldTime = &_holdTime
		}
	}

	return err
}

func fill_nbr_state_transport_info(nbr_key *_xfmr_bgp_nbr_state_key, frrNbrDataValue interface{}, cfgDb *db.DB,
	nbr_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor) error {
	var err error
	ygot.BuildEmptyTree(nbr_obj.Transport)
	nbrTransportState := nbr_obj.Transport.State
	if frrNbrDataValue != nil {
		frrNbrDataJson := frrNbrDataValue.(map[string]interface{})

		if value, ok := frrNbrDataJson["hostLocal"]; ok {
			_localAddress := string(value.(string))
			nbrTransportState.LocalAddress = &_localAddress
		}
		if value, ok := frrNbrDataJson["portLocal"]; ok {
			_localPort := uint16(value.(float64))
			nbrTransportState.LocalPort = &_localPort
		}
		if value, ok := frrNbrDataJson["hostForeign"]; ok {
			_remoteAddress := string(value.(string))
			nbrTransportState.RemoteAddress = &_remoteAddress
		}
		if value, ok := frrNbrDataJson["portForeign"]; ok {
			_remotePort := uint16(value.(float64))
			nbrTransportState.RemotePort = &_remotePort
		}
	}
	if cfgDbEntry, cfgdb_get_err := get_spec_nbr_cfg_tbl_entry(cfgDb, nbr_key); cfgdb_get_err == nil {
		if value, ok := cfgDbEntry["passive_mode"]; ok {
			_passiveMode, _ := strconv.ParseBool(value)
			nbrTransportState.PassiveMode = &_passiveMode
		}
	}

	return err
}

func fill_nbr_state_info(get_req_uri_type E_bgp_nbr_state_get_req_uri_t, nbr_key *_xfmr_bgp_nbr_state_key, frrNbrDataValue interface{}, cfgDb *db.DB,
	nbr_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor) error {
	switch get_req_uri_type {
	case E_bgp_nbr_state_get_req_uri_nbr_state:
		return fill_nbr_state_cmn_info(nbr_key, frrNbrDataValue, cfgDb, nbr_obj)
	case E_bgp_nbr_state_get_req_uri_nbr_timers_state:
		return fill_nbr_state_timers_info(nbr_key, frrNbrDataValue, cfgDb, nbr_obj)
	case E_bgp_nbr_state_get_req_uri_nbr_transport_state:
		return fill_nbr_state_transport_info(nbr_key, frrNbrDataValue, cfgDb, nbr_obj)
	}

	return errors.New("Opertational error")
}

func get_specific_nbr_state(inParams XfmrParams, get_req_uri_type E_bgp_nbr_state_get_req_uri_t,
	nbr_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor,
	cfgDb *db.DB, nbr_key *_xfmr_bgp_nbr_state_key) error {
	var err error
	nbrKey := nbr_key.nbrAddr
	util_bgp_get_native_ifname_from_ui_ifname(&nbrKey)

	vtysh_cmd := "show ip bgp vrf " + nbr_key.niName + " neighbors " + nbrKey + " json"
	bgpFrrJsonCacheKey := bgp_frr_json_cache_query_key_t{niName: nbr_key.niName}
	nbrMapJson, cmd_err := utl_bgp_exec_vtysh_cmd(vtysh_cmd, inParams, BGP_FRR_JSON_CAHCE_QUERY_TYPE_NBRS, bgpFrrJsonCacheKey)
	if cmd_err != nil {
		log.Errorf("Failed to fetch bgp neighbors state info for niName:%s nbrAddr:%s. Err: %s vtysh_cmd %s \n", nbr_key.niName, nbr_key.nbrAddr, cmd_err, vtysh_cmd)
	}

	if net.ParseIP(nbr_key.nbrAddr) != nil {
		nbrKey = net.ParseIP(nbr_key.nbrAddr).String()
	}

	if frrNbrDataJson, ok := nbrMapJson[nbrKey].(map[string]interface{}); ok {
		err = fill_nbr_state_info(get_req_uri_type, nbr_key, frrNbrDataJson, cfgDb, nbr_obj)
	} else {
		err = fill_nbr_state_info(get_req_uri_type, nbr_key, nil, cfgDb, nbr_obj)
	}

	return err
}

func validate_nbr_state_get(inParams XfmrParams, dbg_log string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor, _xfmr_bgp_nbr_state_key, error) {
	var err error
	oper_err := errors.New("Opertational error")
	var nbr_key _xfmr_bgp_nbr_state_key
	var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp

	bgp_obj, nbr_key.niName, err = getBgpRoot(inParams)
	if err != nil {
		log.Errorf("%s failed !! Error:%s", dbg_log, err)
		return nil, nbr_key, err
	}

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
	nbr_key.nbrAddr = pathInfo.Var("neighbor-address")
	log.Infof("%s : path:%s; template:%s targetUriPath:%s niName:%s nbrAddr:%s",
		dbg_log, pathInfo.Path, pathInfo.Template, targetUriPath, nbr_key.niName, nbr_key.nbrAddr)

	nbrs_obj := bgp_obj.Neighbors
	if nbrs_obj == nil {
		log.Errorf("%s failed !! Error: Neighbors container missing", dbg_log)
		return nil, nbr_key, oper_err
	}

	nbr_obj, ok := nbrs_obj.Neighbor[nbr_key.nbrAddr]
	if !ok {
		nbr_obj, _ = nbrs_obj.NewNeighbor(nbr_key.nbrAddr)
	}
	ygot.BuildEmptyTree(nbr_obj)
	return nbr_obj, nbr_key, err
}

type E_bgp_nbr_state_get_req_uri_t string

const (
	E_bgp_nbr_state_get_req_uri_nbr_state           E_bgp_nbr_state_get_req_uri_t = "GET_REQ_URI_BGP_NBR_STATE"
	E_bgp_nbr_state_get_req_uri_nbr_timers_state    E_bgp_nbr_state_get_req_uri_t = "GET_REQ_URI_BGP_NBR_TIMERS_STATE"
	E_bgp_nbr_state_get_req_uri_nbr_transport_state E_bgp_nbr_state_get_req_uri_t = "GET_REQ_URI_BGP_NBR_TRANSPORT_STATE"
)

var Subscribe_bgp_nbrs_nbr_state_xfmr SubTreeXfmrSubscribe = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	var err error
	var result XfmrSubscOutParams

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	if targetUriPath != "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state/session-state" {
		log.Infof("Subscribe attempted on unsupported path:%s; template:%s targetUriPath:%s",
			pathInfo.Path, pathInfo.Template, targetUriPath)
		return result, err
	}

	vrfName := pathInfo.Var("name")
	nbrAddr := pathInfo.Var("neighbor-address")
	util_bgp_get_native_ifname_from_ui_ifname(&nbrAddr)
	var pNbrKey string = vrfName + "|" + nbrAddr

	result.dbDataMap = make(RedisDbSubscribeMap)
	log.Infof("Subscribe_bgp_nbrs_nbr_state_xfmr path:%s; template:%s targetUriPath:%s key:%s",
		pathInfo.Path, pathInfo.Template, targetUriPath, pNbrKey)

	result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {"BGP_NEIGHBOR": {pNbrKey: {}}}} // tablename & table-idx for the inParams.uri
	result.needCache = true
	result.onChange = OnchangeEnable
	result.nOpts = new(notificationOpts)
	result.nOpts.mInterval = 0
	result.nOpts.pType = OnChange
	return result, err
}

var DbToYang_bgp_nbrs_nbr_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	cmn_log := "GET: xfmr for BGP-nbrs state"
	get_req_uri_type := E_bgp_nbr_state_get_req_uri_nbr_state

	xpath, _, _ := XfmrRemoveXPATHPredicates(inParams.uri)
	switch xpath {
	case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/timers/state":
		cmn_log = "GET: xfmr for BGP-nbrs timers state"
		get_req_uri_type = E_bgp_nbr_state_get_req_uri_nbr_timers_state
	case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/transport/state":
		cmn_log = "GET: xfmr for BGP-nbrs transport state"
		get_req_uri_type = E_bgp_nbr_state_get_req_uri_nbr_transport_state
	}

	nbr_obj, nbr_key, get_err := validate_nbr_state_get(inParams, cmn_log)
	if get_err != nil {
		log.Info("Neighbor state get subtree error: ", get_err)
		return get_err
	}

	err = get_specific_nbr_state(inParams, get_req_uri_type, nbr_obj, inParams.dbs[db.ConfigDB], &nbr_key)
	return err
}

type _xfmr_bgp_nbr_af_state_key struct {
	niName           string
	nbrAddr          string
	afiSafiNameStr   string
	afiSafiNameDbStr string
	afiSafiNameEnum  ocbinds.E_OpenconfigBgpTypes_AFI_SAFI_TYPE
}

func get_afi_safi_name_enum_dbstr_for_ocstr(afiSafiNameStr string) (ocbinds.E_OpenconfigBgpTypes_AFI_SAFI_TYPE, string, bool) {
	switch afiSafiNameStr {
	case "IPV4_UNICAST":
		return ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST, "ipv4_unicast", true
	case "IPV6_UNICAST":
		return ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST, "ipv6_unicast", true
	case "L2VPN_EVPN":
		return ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_L2VPN_EVPN, "l2vpn_evpn", true
	default:
		return ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_UNSET, "", false
	}
}

func validate_nbr_af_state_get(inParams XfmrParams, dbg_log string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_AfiSafis_AfiSafi_State,
	_xfmr_bgp_nbr_af_state_key, error) {
	var err error
	var ok bool
	oper_err := errors.New("Opertational error")
	var nbr_af_key _xfmr_bgp_nbr_af_state_key
	var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp

	bgp_obj, nbr_af_key.niName, err = getBgpRoot(inParams)
	if err != nil {
		log.Errorf("%s failed !! Error:%s", dbg_log, err)
		return nil, nbr_af_key, err
	}

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, err := getYangPathFromUri(pathInfo.Path)
	nbr_af_key.nbrAddr = pathInfo.Var("neighbor-address")
	nbr_af_key.afiSafiNameStr = pathInfo.Var("afi-safi-name")
	nbr_af_key.afiSafiNameEnum, nbr_af_key.afiSafiNameDbStr, ok = get_afi_safi_name_enum_dbstr_for_ocstr(nbr_af_key.afiSafiNameStr)
	if !ok {
		log.Errorf("%s failed !! Error: AFI-SAFI ==> %s not supported", dbg_log, nbr_af_key.afiSafiNameStr)
		return nil, nbr_af_key, oper_err
	}

	log.Infof("%s : path:%s; template:%s targetUriPath:%s niName:%s nbrAddr:%s afiSafiNameStr:%s afiSafiNameEnum:%d afiSafiNameDbStr:%s",
		dbg_log, pathInfo.Path, pathInfo.Template, targetUriPath, nbr_af_key.niName, nbr_af_key.nbrAddr, nbr_af_key.afiSafiNameStr, nbr_af_key.afiSafiNameEnum, nbr_af_key.afiSafiNameDbStr)

	nbrs_obj := bgp_obj.Neighbors
	if nbrs_obj == nil {
		log.Errorf("%s failed !! Error: Neighbors container missing", dbg_log)
		return nil, nbr_af_key, oper_err
	}

	nbr_obj, ok := nbrs_obj.Neighbor[nbr_af_key.nbrAddr]
	if !ok {
		nbr_obj, _ = nbrs_obj.NewNeighbor(nbr_af_key.nbrAddr)
	}
	ygot.BuildEmptyTree(nbr_obj)

	afiSafis_obj := nbr_obj.AfiSafis
	if afiSafis_obj == nil {
		log.Errorf("%s failed !! Error: Neighbors AfiSafis container missing", dbg_log)
		return nil, nbr_af_key, oper_err
	}
	ygot.BuildEmptyTree(afiSafis_obj)

	afiSafi_obj, ok := afiSafis_obj.AfiSafi[nbr_af_key.afiSafiNameEnum]
	if !ok {
		log.Errorf("%s Neighbor AfiSafi object missing, allocate new", dbg_log)
		afiSafi_obj, _ = afiSafis_obj.NewAfiSafi(nbr_af_key.afiSafiNameEnum)
	}

	ygot.BuildEmptyTree(afiSafi_obj)

	afiSafiState_obj := afiSafi_obj.State
	if afiSafiState_obj == nil {
		log.Errorf("%s failed !! Error: Neighbor AfiSafi State object missing", dbg_log)
		return nil, nbr_af_key, oper_err
	}
	ygot.BuildEmptyTree(afiSafiState_obj)

	return afiSafiState_obj, nbr_af_key, err
}

func get_spec_nbr_af_cfg_tbl_entry(cfgDb *db.DB, key *_xfmr_bgp_nbr_af_state_key) (map[string]string, error) {
	var err error

	nativeNbr := key.nbrAddr
	util_bgp_get_native_ifname_from_ui_ifname(&nativeNbr)
	nbrAfCfgTblTs := &db.TableSpec{Name: "BGP_NEIGHBOR_AF"}
	nbrAfEntryKey := db.Key{Comp: []string{key.niName, nativeNbr, key.afiSafiNameDbStr}}

	var entryValue db.Value
	if entryValue, err = cfgDb.GetEntry(nbrAfCfgTblTs, nbrAfEntryKey); err != nil {
		return nil, err
	}

	return entryValue.Field, err
}

var DbToYang_bgp_nbrs_nbr_af_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error

	cmn_log := "GET: xfmr for BGP-nbrs-nbr-af state"

	nbrs_af_state_obj, nbr_af_key, get_err := validate_nbr_af_state_get(inParams, cmn_log)
	if get_err != nil {
		return get_err
	}

	nbrKey := nbr_af_key.nbrAddr
	/* For accessing nbr info from FRR json output, nbr has to to be in native
	   format, convert it. The nbr key in the ygot will be still in user given format */
	util_bgp_get_native_ifname_from_ui_ifname(&nbrKey)
	var afiSafi_cmd string
	var frrJsonCacheQueryType BgpFrrCacheQueryType
	switch nbr_af_key.afiSafiNameEnum {
	case ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST:
		afiSafi_cmd = "ipv4"
		frrJsonCacheQueryType = BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV4_NBRS
	case ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST:
		afiSafi_cmd = "ipv6"
		frrJsonCacheQueryType = BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV6_NBRS
	}

	_enabled := false
	if cfgDbEntry, cfgdb_get_err := get_spec_nbr_af_cfg_tbl_entry(inParams.dbs[db.ConfigDB], &nbr_af_key); cfgdb_get_err == nil {
		nbrs_af_state_obj.AfiSafiName = nbr_af_key.afiSafiNameEnum
		if value, ok := cfgDbEntry["admin_status"]; ok {
			_enabled, _ = strconv.ParseBool(value)
			nbrs_af_state_obj.Enabled = &_enabled
		}

		if value, ok := cfgDbEntry["soft_reconfiguration_in"]; ok {
			_softReconfigurationIn, _ := strconv.ParseBool(value)
			nbrs_af_state_obj.SoftReconfigurationIn = &_softReconfigurationIn
		}

		if value, ok := cfgDbEntry["unsuppress_map_name"]; ok {
			nbrs_af_state_obj.UnsuppressMapName = &value
		}

		if value, ok := cfgDbEntry["weight"]; ok {
			if _weight_u64, err := strconv.ParseUint(value, 10, 32); err == nil {
				_weight_u32 := uint32(_weight_u64)
				nbrs_af_state_obj.Weight = &_weight_u32
			}
		}

		if value, ok := cfgDbEntry["as_override"]; ok {
			_asOverride, _ := strconv.ParseBool(value)
			nbrs_af_state_obj.AsOverride = &_asOverride
		}

		if value, ok := cfgDbEntry["send_community"]; ok {
			switch value {
			case "standard":
				nbrs_af_state_obj.SendCommunity = ocbinds.OpenconfigBgpExt_BgpExtCommunityType_STANDARD
			case "extended":
				nbrs_af_state_obj.SendCommunity = ocbinds.OpenconfigBgpExt_BgpExtCommunityType_EXTENDED
			case "both":
				nbrs_af_state_obj.SendCommunity = ocbinds.OpenconfigBgpExt_BgpExtCommunityType_BOTH
			case "none":
				nbrs_af_state_obj.SendCommunity = ocbinds.OpenconfigBgpExt_BgpExtCommunityType_NONE
			case "large":
				nbrs_af_state_obj.SendCommunity = ocbinds.OpenconfigBgpExt_BgpExtCommunityType_LARGE
			case "all":
				nbrs_af_state_obj.SendCommunity = ocbinds.OpenconfigBgpExt_BgpExtCommunityType_ALL
			}
		}

		if value, ok := cfgDbEntry["rrclient"]; ok {
			_routeReflectorClient, _ := strconv.ParseBool(value)
			nbrs_af_state_obj.RouteReflectorClient = &_routeReflectorClient
		}
	}

	vtysh_cmd := "show ip bgp vrf " + nbr_af_key.niName + " " + afiSafi_cmd + " neighbors " + nbrKey + " json"
	bgpFrrJsonCacheKey := bgp_frr_json_cache_query_key_t{niName: nbr_af_key.niName, afiSafiName: afiSafi_cmd}
	nbrMapJson, nbr_cmd_err := utl_bgp_exec_vtysh_cmd(vtysh_cmd, inParams, frrJsonCacheQueryType, bgpFrrJsonCacheKey)
	if nbr_cmd_err != nil {
		log.Errorf("Failed to fetch bgp neighbors state info for niName:%s nbrAddr:%s afi-safi-name:%s. Err: %s, Cmd: %s\n",
			nbr_af_key.niName, nbr_af_key.nbrAddr, afiSafi_cmd, nbr_cmd_err, vtysh_cmd)
		return nil
	}
	if _, ok := nbrMapJson["bgpNoSuchNeighbor"]; ok {
		return nil
	}

	if net.ParseIP(nbr_af_key.nbrAddr) != nil {
		nbrKey = net.ParseIP(nbr_af_key.nbrAddr).String()
	}

	frrNbrDataJson, ok := nbrMapJson[nbrKey].(map[string]interface{})
	if !ok {
		log.Infof("Data from bgp neighbors state info for niName:%s nbrAddr:%s afi-safi-name:%s. Err: %s vtysh_cmd: %s \n",
			nbr_af_key.niName, nbr_af_key.nbrAddr, afiSafi_cmd, nbr_cmd_err, vtysh_cmd)
		return nil
	}

	_active := false
	var _prefixes ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_AfiSafis_AfiSafi_State_Prefixes

	var _activeRcvdPrefixes, _activeSentPrefixes uint32
	nbrs_af_state_obj.AfiSafiName = nbr_af_key.afiSafiNameEnum
	if AddrFamilyMap, ok := frrNbrDataJson["addressFamilyInfo"].(map[string]interface{}); ok {
		log.Infof("Family dump: %v %d", AddrFamilyMap, nbrs_af_state_obj.AfiSafiName)
		if nbrs_af_state_obj.AfiSafiName == ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST {
			if ipv4UnicastMap, ok := AddrFamilyMap["ipv4Unicast"].(map[string]interface{}); ok {
				_active = true
				_enabled = true
				if value, ok := ipv4UnicastMap["acceptedPrefixCounter"]; ok {
					_activeRcvdPrefixes = uint32(value.(float64))
					log.Info("IPv4 dump recd: %d", _activeRcvdPrefixes)
					_prefixes.Received = &_activeRcvdPrefixes
				}
				if value, ok := ipv4UnicastMap["sentPrefixCounter"]; ok {
					_activeSentPrefixes = uint32(value.(float64))
					_prefixes.Sent = &_activeSentPrefixes
					log.Info("IPv4 dump set: %d", _activeSentPrefixes)
				}
			}
		} else if nbrs_af_state_obj.AfiSafiName == ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST {
			if ipv6UnicastMap, ok := AddrFamilyMap["ipv6Unicast"].(map[string]interface{}); ok {
				_active = true
				_enabled = true
				if value, ok := ipv6UnicastMap["acceptedPrefixCounter"]; ok {
					_activeRcvdPrefixes = uint32(value.(float64))
					_prefixes.Received = &_activeRcvdPrefixes
				}
				if value, ok := ipv6UnicastMap["sentPrefixCounter"]; ok {
					_activeSentPrefixes = uint32(value.(float64))
					_prefixes.Sent = &_activeSentPrefixes
				}
			}
		} else if nbrs_af_state_obj.AfiSafiName == ocbinds.OpenconfigBgpTypes_AFI_SAFI_TYPE_L2VPN_EVPN {
			if l2vpnEvpnMap, ok := AddrFamilyMap["l2VpnEvpn"].(map[string]interface{}); ok {
				_active = true
				_enabled = true
				if value, ok := l2vpnEvpnMap["acceptedPrefixCounter"]; ok {
					_activeRcvdPrefixes = uint32(value.(float64))
					_prefixes.Received = &_activeRcvdPrefixes
				}
				if value, ok := l2vpnEvpnMap["sentPrefixCounter"]; ok {
					_activeSentPrefixes = uint32(value.(float64))
					_prefixes.Sent = &_activeSentPrefixes
				}
			}
		}
	}

	vtysh_cmd = "show ip bgp vrf " + nbr_af_key.niName + " " + afiSafi_cmd + " neighbors " + nbrKey + " received-routes json"
	rcvdRoutesJson, rcvd_cmd_err := exec_vtysh_cmd(vtysh_cmd)
	if rcvd_cmd_err != nil {
		log.Errorf("Failed check to fetch bgp neighbors received-routes state info for niName:%s nbrAddr:%s afi-safi-name:%s. Err: %s\n",
			nbr_af_key.niName, nbr_af_key.nbrAddr, afiSafi_cmd, rcvd_cmd_err)
	}

	if rcvd_cmd_err == nil {
		var _receivedPrePolicy uint32
		if value, ok := rcvdRoutesJson["totalPrefixCounter"]; ok {
			_active = true
			_receivedPrePolicy = uint32(value.(float64))
			_prefixes.ReceivedPrePolicy = &_receivedPrePolicy
		}
	}
	nbrs_af_state_obj.Active = &_active
	nbrs_af_state_obj.Enabled = &_enabled
	nbrs_af_state_obj.Prefixes = &_prefixes

	return err
}

var YangToDb_bgp_nbr_community_type_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	var err error
	if inParams.param == nil {
		err = errors.New("No Params")
		return res_map, err
	}

	if inParams.oper == DELETE {
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

		if _, ok := subOpMap[db.ConfigDB]; !ok {
			subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
		}
		if _, ok := subOpMap[db.ConfigDB]["BGP_NEIGHBOR_AF"]; !ok {
			subOpMap[db.ConfigDB]["BGP_NEIGHBOR_AF"] = make(map[string]db.Value)
		}
		subOpMap[db.ConfigDB]["BGP_NEIGHBOR_AF"][inParams.key] = db.Value{Field: make(map[string]string)}
		subOpMap[db.ConfigDB]["BGP_NEIGHBOR_AF"][inParams.key].Field["send_community"] = "both"

		inParams.subOpDataMap[UPDATE] = &subOpMap
		return res_map, nil
	}
	/* In case of POST operation and field has some default value in the YANG, infra is internally filling the enum
	 * in string format (in this case) and hence setting the field value accordingly. */
	curYgotNodeData, _ := yangNodeForUriGet(inParams.uri, inParams.ygRoot)
	if curYgotNodeData == nil && (inParams.oper == CREATE || inParams.oper == REPLACE) {
		community_type_str, _ := inParams.param.(*string)
		if *community_type_str == "BOTH" {
			res_map["send_community"] = "both"
			return res_map, nil
		}
	}
	/* TEMP FIX:In PATCH case also infra can send default values when body contains the instance/s, curYgotNodeData
	 * is not nil, So check if it not E_OpenconfigBgpExt_BgpExtCommunityType , then it would be string from infra.
	* so convert it */
	if reflect.TypeOf(inParams.param) != reflect.TypeOf(ocbinds.OpenconfigBgpExt_BgpExtCommunityType_BOTH) {
		community_type_str, _ := inParams.param.(*string)
		if *community_type_str == "BOTH" {
			res_map["send_community"] = "both"
			return res_map, nil
		}
	}

	community_type, _ := inParams.param.(ocbinds.E_OpenconfigBgpExt_BgpExtCommunityType)
	log.Info("YangToDb_bgp_nbr_community_type_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri,
		" community_type: ", community_type)

	if community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_STANDARD {
		res_map["send_community"] = "standard"
	} else if community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_EXTENDED {
		res_map["send_community"] = "extended"
	} else if community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_BOTH {
		res_map["send_community"] = "both"
	} else if community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_NONE {
		res_map["send_community"] = "none"
	} else if community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_LARGE {
		res_map["send_community"] = "large"
	} else if community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_ALL {
		res_map["send_community"] = "all"
	} else {
		err = errors.New("send_community  Missing")
		return res_map, err
	}

	return res_map, nil

}

var DbToYang_bgp_nbr_community_type_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.V(3).Info("DbToYang_bgp_nbr_community_type_fld_xfmr : ", data, "inParams : ", inParams)

	pTbl := data["BGP_NEIGHBOR_AF"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_bgp_nbr_community_type_fld_xfmr BGP Peer group not found : ", inParams.key)
		return result, errors.New("BGP neighbor not found : " + inParams.key)
	}
	pGrpKey := pTbl[inParams.key]
	community_type, ok := pGrpKey.Field["send_community"]

	if ok {
		if community_type == "standard" {
			result["send-community"] = "STANDARD"
		} else if community_type == "extended" {
			result["send-community"] = "EXTENDED"
		} else if community_type == "both" {
			result["send-community"] = "BOTH"
		} else if community_type == "none" {
			result["send-community"] = "NONE"
		}
	} else {
		log.Info("send_community not found in DB")
	}
	return result, err
}

var YangToDb_bgp_nbr_orf_type_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	var err error
	if inParams.param == nil {
		err = errors.New("No Params")
		return res_map, err
	}

	if inParams.oper == DELETE {
		res_map["cap_orf"] = ""
		return res_map, nil
	}

	orf_type, _ := inParams.param.(ocbinds.E_OpenconfigBgpExt_BgpOrfType)
	log.Info("YangToDb_bgp_nbr_orf_type_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " orf_type: ", orf_type)

	if orf_type == ocbinds.OpenconfigBgpExt_BgpOrfType_SEND {
		res_map["cap_orf"] = "send"
	} else if orf_type == ocbinds.OpenconfigBgpExt_BgpOrfType_RECEIVE {
		res_map["cap_orf"] = "receive"
	} else if orf_type == ocbinds.OpenconfigBgpExt_BgpOrfType_BOTH {
		res_map["cap_orf"] = "both"
	} else {
		err = errors.New("ORF type Missing")
		return res_map, err
	}

	return res_map, nil

}

var DbToYang_bgp_nbr_orf_type_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.V(3).Info("DbToYang_bgp_nbr_orf_type_fld_xfmr : ", data, "inParams : ", inParams)

	pTbl := data["BGP_NEIGHBOR_AF"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_bgp_nbr_orf_type_fld_xfmr BGP neighbor not found : ", inParams.key)
		return result, errors.New("BGP neighbor not found : " + inParams.key)
	}
	pNbrKey := pTbl[inParams.key]
	orf_type, ok := pNbrKey.Field["cap_orf"]

	if ok {
		if orf_type == "send" {
			result["orf-type"] = "SEND"
		} else if orf_type == "receive" {
			result["orf-type"] = "RECEIVE"
		} else if orf_type == "both" {
			result["orf-type"] = "BOTH"
		}
	}
	return result, err
}

var YangToDb_bgp_nbrs_nbr_auth_password_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	res_map := make(map[string]map[string]db.Value)
	authmap := make(map[string]db.Value)

	var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp

	bgp_obj, niName, err := getBgpRoot(inParams)
	if err != nil {
		log.Errorf("BGP root get failed!")
		return res_map, err
	}

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
	nbrAddr := pathInfo.Var("neighbor-address")
	log.Infof("YangToDb_bgp_nbrs_nbr_auth_password_xfmr VRF:%s nbrAddr:%s URI:%s", niName, nbrAddr, targetUriPath)

	nbrs_obj := bgp_obj.Neighbors
	if nbrs_obj == nil || (nbrs_obj.Neighbor == nil) {
		log.Infof("Neighbors container missing")
		return res_map, err
	}

	nbr_obj, ok := nbrs_obj.Neighbor[nbrAddr]
	if !ok {
		log.Infof("%s Neighbor object missing, add new", nbrAddr)
		return res_map, err
	}
	if (inParams.oper == DELETE) && nbr_obj.AuthPassword == nil {
		return res_map, nil
	}
	entry_key := niName + "|" + nbrAddr
	if nbr_obj.AuthPassword.Config != nil && nbr_obj.AuthPassword.Config.Password != nil && (inParams.oper != DELETE) {
		auth_password := nbr_obj.AuthPassword.Config.Password
		encrypted := nbr_obj.AuthPassword.Config.Encrypted

		encrypted_password := *auth_password
		if encrypted == nil || (encrypted != nil && !*encrypted) {
			cmd := "show bgp encrypt " + *auth_password + " json"
			bgpNeighPasswordJson, cmd_err := exec_vtysh_cmd(cmd)
			if cmd_err != nil {
				log.Errorf("Failed !! Error:%s", cmd_err)
				return res_map, err
			}
			encrypted_password, ok = bgpNeighPasswordJson["Encrypted_string"].(string)
			if !ok {
				return res_map, err
			}
			log.Infof("Neighbor password:%s encrypted:%s", *auth_password, encrypted_password)
		}

		authmap[entry_key] = db.Value{Field: make(map[string]string)}
		authmap[entry_key].Field["auth_password"] = encrypted_password
	} else if inParams.oper == DELETE {
		authmap[entry_key] = db.Value{Field: make(map[string]string)}
		authmap[entry_key].Field["auth_password"] = ""
	}
	res_map["BGP_NEIGHBOR"] = authmap
	return res_map, err
}

var DbToYang_bgp_nbrs_nbr_auth_password_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp

	bgp_obj, niName, err := getBgpRoot(inParams)
	if err != nil {
		log.Errorf("BGP root get failed!")
		return err
	}

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
	nbrAddr := pathInfo.Var("neighbor-address")
	log.Infof("DbToYang_bgp_nbrs_nbr_auth_password_xfmr VRF:%s nbrAddr:%s URI:%s", niName, nbrAddr, targetUriPath)

	nbrs_obj := bgp_obj.Neighbors
	if nbrs_obj == nil {
		log.Errorf("Error: Neighbors container missing")
		return err
	}

	nbr_obj, ok := nbrs_obj.Neighbor[nbrAddr]
	if !ok {
		nbr_obj, _ = nbrs_obj.NewNeighbor(nbrAddr)
	}
	ygot.BuildEmptyTree(nbr_obj)
	var nbr_key _xfmr_bgp_nbr_state_key
	nbr_key.niName = niName
	nbr_key.nbrAddr = nbrAddr
	if cfgDbEntry, cfgdb_get_err := get_spec_nbr_cfg_tbl_entry(inParams.dbs[db.ConfigDB], &nbr_key); cfgdb_get_err == nil {

		if nbr_obj.AuthPassword == nil {
			var auth ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_AuthPassword
			nbr_obj.AuthPassword = &auth
			ygot.BuildEmptyTree(nbr_obj.AuthPassword)
		}

		if nbr_obj.AuthPassword.Config == nil {
			var auth_config ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_AuthPassword_Config
			nbr_obj.AuthPassword.Config = &auth_config
			ygot.BuildEmptyTree(nbr_obj.AuthPassword.Config)
		}

		if nbr_obj.AuthPassword.State == nil {
			var auth_state ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_Neighbors_Neighbor_AuthPassword_State
			nbr_obj.AuthPassword.State = &auth_state
			ygot.BuildEmptyTree(nbr_obj.AuthPassword.State)
		}

		if value, ok := cfgDbEntry["auth_password"]; ok {
			nbr_obj.AuthPassword.Config.Password = &value
			nbr_obj.AuthPassword.State.Password = &value
			encrypted := true
			nbr_obj.AuthPassword.Config.Encrypted = &encrypted
			nbr_obj.AuthPassword.State.Encrypted = &encrypted
		}
	}

	return err
}

var DbToYangPath_bgp_nbr_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) (error) {
	niRoot := "/openconfig-network-instance:network-instances/network-instance"
	bgp_nbr_addr := niRoot + "/protocols/protocol/bgp/neighbors/neighbor"
	bgp_nbr_af := bgp_nbr_addr + "/afi-safis/afi-safi"

	log.Info("DbToYangPath_bgp_nbr_path_xfmr: tbl:",params.tblName, " params: ", params)

	if ((params.tblName != "BGP_NEIGHBOR")&& (params.tblName != "BGP_NEIGHBOR_AF")) {
		oper_err := errors.New("wrong config DB table sent")
		log.Errorf ("BGP neighbor Path-xfmr: table name %s not in BGP neighbor/af view", params.tblKeyComp );
		return oper_err
	} else {
		params.ygPathKeys[niRoot + "/name"]  = params.tblKeyComp[0]
		params.ygPathKeys[niRoot + "/protocols/protocol/identifier"] = "BGP"
		params.ygPathKeys[niRoot + "/protocols/protocol/name"] = "bgp"
		params.ygPathKeys[bgp_nbr_addr + "/neighbor-address"] = params.tblKeyComp[1]
		if (params.tblName == "BGP_NEIGHBOR_AF") {
			afi :=  bgp_afi_convert_to_yang(params.tblKeyComp[2])
			if (afi == "") {
				oper_err := errors.New("Invalid address family")
				log.Errorf ("bgp_nbr_path_xfmr: Unknown address family key %s", params.tblKeyComp[2])
				return oper_err
			}
			params.ygPathKeys[bgp_nbr_af + "/afi-safi-name"] = afi
		}
	}

	log.Info("bgp_nbr_path_xfmr:- params.ygPathKeys: ", params.ygPathKeys)
	return nil
}

var Subscribe_bgp_nbrs_nbr_auth_password_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	var result XfmrSubscOutParams
	var vrfName = "*"
	var nbrAddr = "*"

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
	log.Infof("Subscribe_bgp_nbrs_nbr_auth_password_xfmr path:%s; template:%s targetUriPath:%s",
	pathInfo.Path, pathInfo.Template, targetUriPath)

	if inParams.subscProc == TRANSLATE_SUBSCRIBE {
		if  pathInfo.HasVar("name") {
			vrfName   =  pathInfo.Var("name")
		}
		if  pathInfo.HasVar("neighbor-address") {
			nbrAddr   = pathInfo.Var("neighbor-address")
		}
		util_bgp_get_native_ifname_from_ui_ifname (&nbrAddr)
		var pNbrKey string = vrfName + "|" + nbrAddr

		result.dbDataMap = make(RedisDbSubscribeMap)
		log.Infof("Subscribe_bgp_nbrs_nbr_auth_password_xfmr path:%s; key:%s",
		pathInfo.Path, pNbrKey)

		result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{"BGP_NEIGHBOR":{pNbrKey:{"auth_password":"password"}}}}
		result.onChange = OnchangeEnable
		result.nOpts = new(notificationOpts)
		result.nOpts.pType = OnChange
	} else {
		result.isVirtualTbl = true
	}
	return result, nil
}
