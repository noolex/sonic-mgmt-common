package transformer

import (
    "errors"
    "strconv"
    "strings"
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "net"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
)

func getBgpRoot (inParams XfmrParams) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp, string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    niName := pathInfo.Var("name")
    bgpId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")
    var err error

    if len(pathInfo.Vars) <  3 {
        return nil, "", errors.New("Invalid Key length")
    }

    if len(niName) == 0 {
        return nil, "", errors.New("vrf name is missing")
    }
    if !strings.Contains(bgpId,"BGP") {
        return nil, "", errors.New("BGP ID is missing")
    }
    if len(protoName) == 0 {
        return nil, "", errors.New("Protocol Name is missing")
    }

	deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    netInstsObj := deviceObj.NetworkInstances

    if netInstsObj.NetworkInstance == nil {
        return nil, "", errors.New("Network-instances container missing")
    }

    netInstObj := netInstsObj.NetworkInstance[niName]
    if netInstObj == nil {
        return nil, "", errors.New("Network-instance obj missing")
    }

    if netInstObj.Protocols == nil || len(netInstObj.Protocols.Protocol) == 0 {
        return nil, "", errors.New("Network-instance protocols-container missing or protocol-list empty")
    }

    var protoKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Key
    protoKey.Identifier = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_BGP
    protoKey.Name = protoName
    protoInstObj := netInstObj.Protocols.Protocol[protoKey]
    if protoInstObj == nil {
        return nil, "", errors.New("Network-instance BGP-Protocol obj missing")
    }

    if protoInstObj.Bgp == nil {
        var _bgp_obj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp
        protoInstObj.Bgp = &_bgp_obj
    }

    ygot.BuildEmptyTree (protoInstObj.Bgp)
    return protoInstObj.Bgp, niName, err
}

func util_bgp_get_native_ifname_from_ui_ifname (pIfname *string) {
    if pIfname != nil && net.ParseIP(*pIfname) == nil {
        pNativeIfname := utils.GetNativeNameFromUIName(pIfname)
        if pNativeIfname != nil && len(*pNativeIfname) != 0 {
            *pIfname = *pNativeIfname
        }
    }
}

func util_bgp_get_ui_ifname_from_native_ifname (pIfname *string) {
    if pIfname != nil && net.ParseIP(*pIfname) == nil {
        pUiIfname := utils.GetUINameFromNativeName(pIfname)
        if pUiIfname != nil && len(*pUiIfname) != 0 {
            *pIfname = *pUiIfname
        }
    }
}

type BgpFrrCacheType string
const (
    BGP_FRR_JSON_CACHE BgpFrrCacheType = "BGP_FRR_JSON"
    BGP_FRR_JSON_CACHE_ALL_VRF_SUMMARY BgpFrrCacheType = "BGP_FRR_JSON_ALL_VRF_SUMMARY"
    BGP_FRR_JSON_CACHE_SPECIFIC_VRF_SUMMARY BgpFrrCacheType = "BGP_FRR_JSON_SPECIFIC_VRF_SUMMARY"
    BGP_FRR_JSON_CACHE_ALL_VRF_IPV4_SUMMARY BgpFrrCacheType = "BGP_FRR_JSON_ALL_VRF_IPV4_SUMMARY"
    BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV4_SUMMARY BgpFrrCacheType = "BGP_FRR_JSON_SPECIFIC_VRF_IPV4_SUMMARY"
    BGP_FRR_JSON_CACHE_ALL_VRF_IPV6_SUMMARY BgpFrrCacheType = "BGP_FRR_JSON_ALL_VRF_IPV6_SUMMARY"
    BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV6_SUMMARY BgpFrrCacheType = "BGP_FRR_JSON_SPECIFIC_VRF_IPV6_SUMMARY"
    BGP_FRR_JSON_CACHE_ALL_VRF_NBRS BgpFrrCacheType = "BGP_FRR_JSON_ALL_VRF_NBRS"
    BGP_FRR_JSON_CACHE_SPECIFIC_VRF_NBRS BgpFrrCacheType = "BGP_FRR_JSON_SPECIFIC_VRF_NBRS"
    BGP_FRR_JSON_CACHE_ALL_VRF_IPV4_NBRS BgpFrrCacheType = "BGP_FRR_JSON_ALL_VRF_IPV4_NBRS"
    BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV4_NBRS BgpFrrCacheType = "BGP_FRR_JSON_SPECIFIC_VRF_IPV4_NBRS"
    BGP_FRR_JSON_CACHE_ALL_VRF_IPV6_NBRS BgpFrrCacheType = "BGP_FRR_JSON_ALL_VRF_IPV6_NBRS"
    BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV6_NBRS BgpFrrCacheType = "BGP_FRR_JSON_SPECIFIC_VRF_IPV6_NBRS"
)

type BgpFrrCacheQueryType string
const (
    BGP_FRR_JSON_CACHE_QUERY_TYPE_SUMMARY BgpFrrCacheQueryType = "BGP_FRR_JSON_CACHE_QUERY_SUMMARY"
    BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV4_SUMMARY BgpFrrCacheQueryType = "BGP_FRR_JSON_CACHE_QUERY_IPV4_SUMMARY"
    BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV6_SUMMARY BgpFrrCacheQueryType = "BGP_FRR_JSON_CACHE_QUERY_IPV6_SUMMARY"
    BGP_FRR_JSON_CAHCE_QUERY_TYPE_NBRS BgpFrrCacheQueryType = "BGP_FRR_JSON_CACHE_QUERY_NBRS"
    BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV4_NBRS BgpFrrCacheQueryType = "BGP_FRR_JSON_CACHE_QUERY_IPV4_NBRS"
    BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV6_NBRS BgpFrrCacheQueryType = "BGP_FRR_JSON_CACHE_QUERY_IPV6_NBRS"
)

type bgp_frr_json_cache_query_key_t struct {
    niName string
    afiSafiName string /* ipv4/ipv6 */
}

func utl_bgp_exec_vtysh_cmd (vtyshCmd string, inParams XfmrParams, cmdType BgpFrrCacheQueryType, cmdArgs bgp_frr_json_cache_query_key_t) (map[string]interface{}, error) {
    cache, bgpFrrJsonCachePresent := inParams.txCache.Load(BGP_FRR_JSON_CACHE)
    if bgpFrrJsonCachePresent {
        bgpFrrJsonCache, _ := cache.(map[BgpFrrCacheType]map[string]interface{})
        switch cmdType {
            case BGP_FRR_JSON_CACHE_QUERY_TYPE_SUMMARY:
                if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_SUMMARY] ; ok {return value, nil}
                if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_SUMMARY][cmdArgs.niName].(map[string]interface{}) ; ok {return value, nil}
            case BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV4_SUMMARY:
                if cmdArgs.afiSafiName == "ipv4" {
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV4_SUMMARY] ; ok {return value, nil}
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV4_SUMMARY][cmdArgs.niName].(map[string]interface{}) ; ok {return value, nil}
                }
            case BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV6_SUMMARY:
                if cmdArgs.afiSafiName == "ipv6" {
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV6_SUMMARY] ; ok {return value, nil}
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV6_SUMMARY][cmdArgs.niName].(map[string]interface{}) ; ok {return value, nil}
                }
            case BGP_FRR_JSON_CAHCE_QUERY_TYPE_NBRS:
                if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_NBRS] ; ok {return value, nil}
                if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_NBRS][cmdArgs.niName].(map[string]interface{}) ; ok {return value, nil}
            case BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV4_NBRS:
                if cmdArgs.afiSafiName == "ipv4" {
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV4_NBRS] ; ok {return value, nil}
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV4_NBRS][cmdArgs.niName].(map[string]interface{}) ; ok {return value, nil}
                }
            case BGP_FRR_JSON_CACHE_QUERY_TYPE_IPV6_NBRS:
                if cmdArgs.afiSafiName == "ipv6" {
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV6_NBRS] ; ok {return value, nil}
                    if value, ok := bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV6_NBRS][cmdArgs.niName].(map[string]interface{}) ; ok {return value, nil}
                }
        }
    }
    return exec_vtysh_cmd (vtyshCmd)
}

func utl_bgp_fetch_and_cache_frr_json (inParams *XfmrParams, niName string) {
    bgpFrrJsonCache := make(map[BgpFrrCacheType]map[string]interface{})
    if niName != "" {
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_SUMMARY], _ = exec_vtysh_cmd ("show ip bgp vrf " + niName + " summary json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV4_SUMMARY], _ = exec_vtysh_cmd ("show ip bgp vrf " + niName + " ipv4 summary json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV6_SUMMARY], _ = exec_vtysh_cmd ("show ip bgp vrf " + niName + " ipv6 summary json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_NBRS], _ = exec_vtysh_cmd ("show ip bgp vrf " + niName + " neighbors json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV4_NBRS], _ = exec_vtysh_cmd ("show ip bgp vrf " + niName + " ipv4 neighbors json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_SPECIFIC_VRF_IPV6_NBRS], _ = exec_vtysh_cmd ("show ip bgp vrf " + niName + " ipv6 neighbors json")
    } else {
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_SUMMARY], _ = exec_vtysh_cmd ("show ip bgp vrf all summary json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV4_SUMMARY], _ = exec_vtysh_cmd ("show ip bgp vrf all ipv4 summary json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV6_SUMMARY], _ = exec_vtysh_cmd ("show ip bgp vrf all ipv6 summary json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_NBRS], _ = exec_vtysh_cmd ("show ip bgp vrf all neighbors json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV4_NBRS], _ = exec_vtysh_cmd ("show ip bgp vrf all ipv4 neighbors json")
        bgpFrrJsonCache[BGP_FRR_JSON_CACHE_ALL_VRF_IPV6_NBRS], _ = exec_vtysh_cmd ("show ip bgp vrf all ipv6 neighbors json")
    }
    inParams.txCache.Store(BGP_FRR_JSON_CACHE, bgpFrrJsonCache)
}

func init () {
    XlateFuncBind("bgp_gbl_tbl_xfmr", bgp_gbl_tbl_xfmr)
    XlateFuncBind("YangToDb_bgp_gbl_tbl_key_xfmr", YangToDb_bgp_gbl_tbl_key_xfmr)
    XlateFuncBind("DbToYang_bgp_gbl_tbl_key_xfmr", DbToYang_bgp_gbl_tbl_key_xfmr)
    XlateFuncBind("YangToDb_bgp_local_asn_fld_xfmr", YangToDb_bgp_local_asn_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_local_asn_fld_xfmr", DbToYang_bgp_local_asn_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_gbl_state_xfmr", DbToYang_bgp_gbl_state_xfmr)
    XlateFuncBind("YangToDb_bgp_gbl_afi_safi_field_xfmr", YangToDb_bgp_gbl_afi_safi_field_xfmr)
    XlateFuncBind("DbToYang_bgp_gbl_afi_safi_field_xfmr", DbToYang_bgp_gbl_afi_safi_field_xfmr)
	XlateFuncBind("YangToDb_bgp_dyn_neigh_listen_key_xfmr", YangToDb_bgp_dyn_neigh_listen_key_xfmr)
	XlateFuncBind("DbToYang_bgp_dyn_neigh_listen_key_xfmr", DbToYang_bgp_dyn_neigh_listen_key_xfmr) 
	XlateFuncBind("YangToDb_bgp_gbl_afi_safi_key_xfmr", YangToDb_bgp_gbl_afi_safi_key_xfmr)
	XlateFuncBind("DbToYang_bgp_gbl_afi_safi_key_xfmr", DbToYang_bgp_gbl_afi_safi_key_xfmr) 
	XlateFuncBind("YangToDb_bgp_gbl_afi_safi_addr_key_xfmr", YangToDb_bgp_gbl_afi_safi_addr_key_xfmr)
	XlateFuncBind("DbToYang_bgp_gbl_afi_safi_addr_key_xfmr", DbToYang_bgp_gbl_afi_safi_addr_key_xfmr) 
	XlateFuncBind("YangToDb_bgp_dyn_neigh_listen_field_xfmr", YangToDb_bgp_dyn_neigh_listen_field_xfmr)
	XlateFuncBind("DbToYang_bgp_dyn_neigh_listen_field_xfmr", DbToYang_bgp_dyn_neigh_listen_field_xfmr) 
	XlateFuncBind("YangToDb_bgp_gbl_afi_safi_addr_field_xfmr", YangToDb_bgp_gbl_afi_safi_addr_field_xfmr)
	XlateFuncBind("DbToYang_bgp_gbl_afi_safi_addr_field_xfmr", DbToYang_bgp_gbl_afi_safi_addr_field_xfmr) 
    XlateFuncBind("YangToDb_bgp_global_subtree_xfmr", YangToDb_bgp_global_subtree_xfmr)
    XlateFuncBind("rpc_clear_bgp", rpc_clear_bgp)
    XlateFuncBind("bgp_validate_gbl_af", bgp_validate_gbl_af)
}

func bgp_validate_gbl_af (inParams XfmrParams) bool {
    pathInfo := NewPathInfo(inParams.uri)
    // /openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/global/afi-safis/afi-safi/l2vpn-evpn
    afiSafiName := pathInfo.Var("afi-safi-name")
    if afiSafiName != "L2VPN_EVPN" {
        if log.V(3) {
            log.Info("bgp_validate_gbl_af: ignored - VRF ", pathInfo.Var("name"), " URI ",
                     inParams.uri)
        }
        return false
    }
    return true
}

func bgp_validate_and_set_default_value(inParams *XfmrParams, tblName string, key string, fieldName string, fieldValue string, 
                                        entry db.Value) {
    /* If Default field exists in yangDefValMap, return */
    defValEntry := inParams.yangDefValMap[tblName][key]
    if defValEntry.Has(fieldName) {
        return
    }
    /* If default field exists in dbDataMap table entry, return */
    if entry.IsPopulated() && entry.Has(fieldName) {
        return
    }
    inParams.yangDefValMap[tblName][key].Field[fieldName] = fieldValue
}

var bgp_frr_json_cache_reqd_map = map[string]bool {
    "/openconfig-network-instance:network-instances": true,
    "/openconfig-network-instance:network-instances/network-instance": true,
    "/openconfig-network-instance:network-instances/network-instance/protocols": true,
    "/openconfig-network-instance:network-instances/network-instance/protocols/protocol": true,
    "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp": true,
    "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors": true,
    "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor": true,
}

func bgp_hdl_pre_xfmr (inParams *XfmrParams) {
    if (inParams.oper != GET) {return}

    _ , bgpFrrJsonCachePresent := inParams.txCache.Load(BGP_FRR_JSON_CACHE)
    if !bgpFrrJsonCachePresent && inParams.dbDataMap != nil {
        reqUriXpath,_,_ := XfmrRemoveXPATHPredicates(inParams.requestUri)
        if caching_reqd, found := bgp_frr_json_cache_reqd_map[reqUriXpath]; found && caching_reqd {
            reqUriPathInfo := NewPathInfo(inParams.requestUri)
            _niName := reqUriPathInfo.Var("name")
            _nbrAddr := reqUriPathInfo.Var("neighbor-address")
            if _nbrAddr == "" { /* Ignoring get specific nbr case */
                utl_bgp_fetch_and_cache_frr_json (inParams, _niName)
            }
        }
    }
}

func hdl_post_xfmr_bgp_nbr_del(inParams *XfmrParams, niName string, retDbDataMap *map[string]map[string]db.Value) {
    if log.V(3) {
        log.Info ("In Post-Transformer to fill BGP_NEIGHBOR keys, while handling DELETE-OP for URI : ",
                  inParams.requestUri, " ; VRF : ", niName, " ; Incoming DB-Datamap : ", (*retDbDataMap))
    }

    bgpTblKeys, _ := inParams.d.GetKeysByPattern(&db.TableSpec{Name: "BGP_NEIGHBOR"}, niName+"|*")
    for _, bgpTblKey := range bgpTblKeys {
        if _, ok := (*retDbDataMap)["BGP_NEIGHBOR"]; !ok {
            (*retDbDataMap)["BGP_NEIGHBOR"] = make(map[string]db.Value)
        }

        key := bgpTblKey.Get(0) + "|" + bgpTblKey.Get(1)
        (*retDbDataMap)["BGP_NEIGHBOR"][key] = db.Value{}
    }
    if log.V(3) {
        log.Info ("After Post-Transformer BGP_NEIGHBOR handler ==> retDbDataMap : ", (*retDbDataMap))
    }
}

func hdl_post_xfmr_bgp_nbr_af_del(inParams *XfmrParams, niName string, nbrAddr string, retDbDataMap *map[string]map[string]db.Value) {
    if log.V(3) {
        log.Info ("In Post-Transformer to fill BGP_NEIGHBOR_AF keys, while handling DELETE-OP for URI : ",
                  inParams.requestUri, " ; VRF : ", niName, " ; nbrAddr: ", nbrAddr, " ; Incoming DB-Datamap : ", (*retDbDataMap))
    }

    /* The nbrAddr can be in native(Ethernet0) or standard (Eth1/1) format,
       for DB access it has to be in native format. Convert wherever needed.
       Also xfmr infra expecting DBDatamap to have this key in user give format
       So make sure returned key is in that format.  */
    nativeNbr := nbrAddr
    util_bgp_get_native_ifname_from_ui_ifname (&nativeNbr)
    bgpTblKeys, _ := inParams.d.GetKeysByPattern(&db.TableSpec{Name: "BGP_NEIGHBOR_AF"}, niName+"|"+nativeNbr+"|*")
    for _, bgpTblKey := range bgpTblKeys {
        if _, ok := (*retDbDataMap)["BGP_NEIGHBOR_AF"]; !ok {
            (*retDbDataMap)["BGP_NEIGHBOR_AF"] = make(map[string]db.Value)
        }

        key := bgpTblKey.Get(0) + "|" + nbrAddr + "|" + bgpTblKey.Get(2)
        (*retDbDataMap)["BGP_NEIGHBOR_AF"][key] = db.Value{}
    }
    if log.V(3) {
        log.Info ("After Post-Transformer BGP_NEIGHBOR_AF handler ==> retDbDataMap : ", (*retDbDataMap))
    }
}

func hdl_del_post_xfmr(inParams *XfmrParams, data *map[string]map[string]db.Value) (error) {
    var err error
    xpath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)
    pathInfo := NewPathInfo(inParams.requestUri)
    niName := pathInfo.Var("name")
    if len(niName) == 0 {return err}
    switch xpath {
        case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors": fallthrough
        case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor":
            /* Infra has a limitation to handle this parent level delete when there is a table xfmr function for a neighbor, 
             * so, handle as part of post xfmr function */
            nbrAddr   := pathInfo.Var("neighbor-address")
            if len(nbrAddr) == 0 {
                hdl_post_xfmr_bgp_nbr_del(inParams, niName, data)
                return err
            }
        case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/afi-safis": fallthrough
        case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/afi-safis/afi-safi":
            /* Infra has a limitation to handle this parent level delete when there is a table xfmr function for a neighbor, 
             * so, handle as part of post xfmr function */
            nbrAddr   := pathInfo.Var("neighbor-address")
            afiSafiName := pathInfo.Var("afi-safi-name")
            if len(nbrAddr) != 0 && len(afiSafiName) == 0 {
                hdl_post_xfmr_bgp_nbr_af_del(inParams, niName, nbrAddr, data)
                return err
            }
    }

    if (inParams.subOpDataMap[UPDATE] == nil) {
        return err
    }

    specInfo, ok := xYangSpecMap[xpath]
    if !ok {
       return err
    }
    yangType := yangTypeGet(specInfo.yangEntry)
    if !(yangType == YANG_LEAF) {
        return err
    }
    if log.V(3) {
        log.Info("bgp_hdl_post_xfmr: Yang sub op data map ",
                (*inParams.subOpDataMap[UPDATE])[db.ConfigDB])
    }
    subOpUpdMap := (*inParams.subOpDataMap[UPDATE])[db.ConfigDB]
    bgpNbrTbl := "BGP_NEIGHBOR"
    bgpNbrAfTbl := "BGP_NEIGHBOR_AF"
    if len(subOpUpdMap[bgpNbrTbl]) == 0 && len(subOpUpdMap[bgpNbrAfTbl]) == 0 {
        return err
    }
    subOpDelMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subOpDelMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    inParams.subOpDataMap[DELETE] = &subOpDelMap
    nbrTbls := []string{bgpNbrTbl, bgpNbrAfTbl}
    for _, tbl := range nbrTbls {
        if (len(subOpUpdMap[tbl]) == 0) {
            continue
        }
        subOpDelMap[db.ConfigDB][tbl] = make(map[string]db.Value)
        for key, val := range subOpUpdMap[tbl] {
           (*inParams.subOpDataMap[DELETE])[db.ConfigDB][tbl][key] = val
        }
        subOpUpdMap[tbl] = make(map[string]db.Value)
    }
    if log.V(3) {
        log.Info("bgp_hdl_post_xfmr: Yang UPDATE sub op data map ",
                (*inParams.subOpDataMap[UPDATE])[db.ConfigDB])
        log.Info("bgp_hdl_post_xfmr: Yang DELETE sub op data map ",
                (*inParams.subOpDataMap[DELETE])[db.ConfigDB])
    }
    return err
}

func bgp_hdl_post_xfmr(inParams *XfmrParams, data *map[string]map[string]db.Value) (error) {
    var err error

    if log.V(3) {
        log.Info("bgp_hdl_post_xfmr: Yang default value map ", inParams.yangDefValMap)
        log.Info("bgp_hdl_post_xfmr: Yang DB data map ", data)
    }

    if inParams.oper == DELETE {
        err = hdl_del_post_xfmr(inParams, data)
        return err
    }

    /* To check same listen range already configured in other peer-group */
    if gbl_listen_prefix_map, ok := (*data)["BGP_GLOBALS_LISTEN_PREFIX"]; ok {
        for key := range gbl_listen_prefix_map {
            peer_grp, ok := gbl_listen_prefix_map[key].Field["peer_group"]
            if ok {
                dbSpec := &db.TableSpec{Name: "BGP_GLOBALS_LISTEN_PREFIX"}
                dbEntry, _ := inParams.d.GetEntry(dbSpec, db.Key{Comp: []string{key}})
                peerGrp, ok := dbEntry.Field["peer_group"]
                if ok && peerGrp != peer_grp {
                    errStr := "Same listen range is attached to peer-group " + peerGrp
                    err = tlerr.InvalidArgsError{Format: errStr}
                    log.Error(errStr)
                    return err
                }
            }
        }
    }

    tblName := "BGP_GLOBALS"
    for key := range inParams.yangDefValMap[tblName] {
        entry := (*data)[tblName][key]
        bgp_validate_and_set_default_value(inParams, tblName, key, "always_compare_med", "false", entry)
        bgp_validate_and_set_default_value(inParams, tblName, key, "ignore_as_path_length", "false", entry)
        bgp_validate_and_set_default_value(inParams, tblName, key, "external_compare_router_id", "false", entry)
        bgp_validate_and_set_default_value(inParams, tblName, key, "log_nbr_state_changes", "true", entry)
        bgp_validate_and_set_default_value(inParams, tblName, key, "load_balance_mp_relax", "false", entry)
    }

    /* Dont set the fields with default values for BGP neighbor and neighbor AF tables from infra as it 
     * impacts the configs inheritance from PG when nbr is part of the PG, the default values are expected 
     * to be initialised as part of BGP neighbor creation in bgpcfgd */
    delete (inParams.yangDefValMap, "BGP_NEIGHBOR")
    delete (inParams.yangDefValMap, "BGP_NEIGHBOR_AF")

    tblName = "BGP_PEER_GROUP"
    for key := range inParams.yangDefValMap[tblName] {
        entry := (*data)[tblName][key]
        yang_def_entry := inParams.yangDefValMap[tblName][key]
        /* Dont push the default values of keepalive & holdtime fields as this impacts
         * the global keepalive/holdtime values inheritance */
        if yang_def_entry.Has("keepalive") {
            delete (yang_def_entry.Field, "keepalive")
        }
        if yang_def_entry.Has("holdtime") {
            delete (yang_def_entry.Field, "holdtime")
        }
        bgp_validate_and_set_default_value(inParams, tblName, key, "min_adv_interval", "0", entry)
        bgp_validate_and_set_default_value(inParams, tblName, key, "conn_retry", "30", entry)
        bgp_validate_and_set_default_value(inParams, tblName, key, "passive_mode", "false", entry)
        bgp_validate_and_set_default_value(inParams, tblName, key, "ebgp_multihop", "false", entry)
    }

    /* Remove the invalid default values for BGP address family */
    tbl := inParams.yangDefValMap["BGP_GLOBALS_AF"]
    for key := range tbl {
        entry := tbl[key]
        if !(strings.Contains(key, "ipv4_unicast")) && entry.Has("route_flap_dampen") {
             /* Route flap dampening is supported only for IPv4 AF. */
             delete (entry.Field, "route_flap_dampen")
        }
        if strings.Contains(key, "l2vpn_evpn") {
            if entry.Has("max_ebgp_paths") {
               delete (entry.Field, "max_ebgp_paths")
            }
            if entry.Has("max_ibgp_paths") {
               delete (entry.Field, "max_ibgp_paths")
            }
        } else if (strings.Contains(key, "ipv4_unicast") ||
                   strings.Contains(key, "ipv6_unicast")) {
            if entry.Has("advertise-default-gw") {
               delete (entry.Field, "advertise-default-gw")
            }
        }
    }

    tblName = "BGP_PEER_GROUP_AF"
    tbl = inParams.yangDefValMap[tblName]
    for key := range tbl {
        entry := tbl[key]
        if strings.Contains(key, "l2vpn_evpn") {
            if entry.Has("rrclient") {
               delete (entry.Field, "rrclient")
            }
            if entry.Has("send_community") {
               delete (entry.Field, "send_community")
            }
        } else if (strings.Contains(key, "ipv4_unicast") ||
                   strings.Contains(key, "ipv6_unicast"))  {
            dbMapEntry := (*data)[tblName][key]
            bgp_validate_and_set_default_value(inParams, tblName, key, "send_default_route", "false", dbMapEntry)
            bgp_validate_and_set_default_value(inParams, tblName, key, "max_prefix_warning_only", "false", dbMapEntry)
        }
    }

    if log.V(3) {
        log.Info("bgp_hdl_post_xfmr: updated Yang default value map ", inParams.yangDefValMap)
        log.Info("bgp_hdl_post_xfmr: updated Yang DB data map ", data)
    }
    return err
}

var bgp_gbl_tbl_xfmr TableXfmrFunc = func (inParams XfmrParams)  ([]string, error) {
    var tblList []string

    log.Info("bgp_gbl_tbl_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    vrf := pathInfo.Var("name")
    bgpId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")

    if len(pathInfo.Vars) <  3 {
        err := errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return tblList, err
    }

    if len(vrf) == 0 {
        err_str := "VRF name is missing"
        err := errors.New(err_str); log.Info(err_str)
        return tblList, err
    }
    if !strings.Contains(bgpId,"BGP") {
        err_str := "BGP ID is missing"
        err := errors.New(err_str); log.Info(err_str)
        return tblList, err
    }
    if len(protoName) == 0 {
        err_str := "Protocol Name is Missing"
        err := errors.New(err_str); log.Info(err_str)
        return tblList, err
    }

    tblList = append(tblList, "BGP_GLOBALS")

    return tblList, nil
}


func bgp_global_get_local_asn(d *db.DB , niName string, tblName string) (string, error) {
    var err error

    dbspec := &db.TableSpec { Name: tblName }

    log.Info("bgp_global_get_local_asn", db.Key{Comp: []string{niName}})
    dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{niName}})
    if err != nil {
        return "", err
    }
    asn, ok := dbEntry.Field["local_asn"]
    if ok {
        log.Info("Current ASN ", asn)
    } else {
        log.Info("No ASN assigned")
    }
    return asn, nil;
}


var YangToDb_bgp_local_asn_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    rmap := make(map[string]string)
    var err error
    if inParams.param == nil {
        rmap["local_asn"] = ""
        return rmap, err
    }

    if inParams.oper == DELETE {
        rmap["local_asn"] = ""
        return rmap, nil
    }

    log.Info("YangToDb_bgp_local_asn_fld_xfmr")
    pathInfo := NewPathInfo(inParams.uri)

    niName := pathInfo.Var("name")

    asn, _ := inParams.param.(*uint32)

    curr_asn, err_val := bgp_global_get_local_asn (inParams.d, niName, "BGP_GLOBALS")
    if err_val == nil {
       local_asn64, err_conv := strconv.ParseUint(curr_asn, 10, 32)
       local_asn := uint32(local_asn64)
       if err_conv == nil && local_asn != *asn {
           log.Info("YangToDb_bgp_local_asn_fld_xfmr Local ASN is already present", local_asn, *asn)
           return rmap, tlerr.InvalidArgs("BGP is already running with AS number %s", 
                                          strconv.FormatUint(local_asn64, 10))
       }
    }
    rmap["local_asn"] = strconv.FormatUint(uint64(*asn), 10)
    return rmap, err
}

var DbToYang_bgp_local_asn_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_bgp_local_asn_fld_xfmr: ")

    pTbl := data["BGP_GLOBALS"]
    if _, ok := pTbl[inParams.key]; !ok {
        return result, err
    }
    pGblKey := pTbl[inParams.key]
    curr_asn, ok := pGblKey.Field["local_asn"]
    if ok {
       local_asn64, _:= strconv.ParseUint(curr_asn, 10, 32)
       local_asn := uint32(local_asn64)
       result["as"] = local_asn
    } else {
        log.Info("Local ASN field not found in DB")
    }
    return result, err
}

func get_spec_bgp_glb_cfg_tbl_entry (cfgDb *db.DB, niName string) (map[string]string, error) {
    var err error

    bgpGblTblTs := &db.TableSpec{Name: "BGP_GLOBALS"}
    bgpGblEntryKey := db.Key{Comp: []string{niName}}

    var entryValue db.Value
    if entryValue, err = cfgDb.GetEntry(bgpGblTblTs, bgpGblEntryKey) ; err != nil {
        return nil, err
    }

    return entryValue.Field, err
}

var DbToYang_bgp_gbl_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error
    oper_err := errors.New("Opertational error")
    cmn_log := "GET: xfmr for BGP-Global State"

    //var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp
    bgp_obj, niName, err := getBgpRoot (inParams)
    if err != nil {
        log.Errorf ("%s failed !! Error:%s", cmn_log , err);
        return oper_err
    }

    bgpGbl_obj := bgp_obj.Global
    if bgpGbl_obj == nil {
        log.Errorf("%s failed !! Error: BGP-Global container missing", cmn_log)
        return oper_err
    }
    ygot.BuildEmptyTree (bgpGbl_obj)

    bgpGblState_obj := bgpGbl_obj.State
    if bgpGblState_obj == nil {
        log.Errorf("%s failed !! Error: BGP-Global-State container missing", cmn_log)
        return oper_err
    }
    ygot.BuildEmptyTree (bgpGblState_obj)

    if cfgDbEntry, cfgdb_get_err := get_spec_bgp_glb_cfg_tbl_entry (inParams.dbs[db.ConfigDB], niName) ; cfgdb_get_err == nil {
        if value, ok := cfgDbEntry["local_asn"] ; ok {
            if _local_asn_u64, err := strconv.ParseUint(value, 10, 32) ; err == nil {
                _local_asn_u32 := uint32(_local_asn_u64)
                bgpGblState_obj.As = &_local_asn_u32
            }
        }

        if value, ok := cfgDbEntry["router_id"] ; ok {
            bgpGblState_obj.RouterId = &value
        }

        if value, ok := cfgDbEntry["rr_clnt_to_clnt_reflection"] ; ok {
            _clntToClntReflection, _ := strconv.ParseBool(value)
            bgpGblState_obj.ClntToClntReflection = &_clntToClntReflection
        }

        if value, ok := cfgDbEntry["coalesce_time"] ; ok {
            if _coalesceTime_u64, err := strconv.ParseUint(value, 10, 32) ; err == nil {
                _coalesceTime_u32 := uint32(_coalesceTime_u64)
                bgpGblState_obj.CoalesceTime = &_coalesceTime_u32
            }
        }

        if value, ok := cfgDbEntry["deterministic_med"] ; ok {
            _deterministicMed, _ := strconv.ParseBool(value)
            bgpGblState_obj.DeterministicMed = &_deterministicMed
        }

        if value, ok := cfgDbEntry["disable_ebgp_connected_rt_check"] ; ok {
            _disableEbgpConnectedRouteCheck, _ := strconv.ParseBool(value)
            bgpGblState_obj.DisableEbgpConnectedRouteCheck = &_disableEbgpConnectedRouteCheck
        }

        if value, ok := cfgDbEntry["fast_external_failover"] ; ok {
            _fastExternalFailover, _ := strconv.ParseBool(value)
            bgpGblState_obj.FastExternalFailover = &_fastExternalFailover
        }

        if value, ok := cfgDbEntry["graceful_shutdown"] ; ok {
            _gracefulShutdown, _ := strconv.ParseBool(value)
            bgpGblState_obj.GracefulShutdown = &_gracefulShutdown
        }

        if value, ok := cfgDbEntry["holdtime"] ; ok {
            _holdTime, _ := strconv.ParseFloat(value, 64)
            bgpGblState_obj.HoldTime = &_holdTime
        }

        if value, ok := cfgDbEntry["keepalive"] ; ok {
            _keepaliveInterval, _ := strconv.ParseFloat(value, 64)
            bgpGblState_obj.KeepaliveInterval = &_keepaliveInterval
        }

        if value, ok := cfgDbEntry["max_dynamic_neighbors"] ; ok {
            if _maxDynamicNeighbors_u64, err := strconv.ParseUint(value, 10, 32) ; err == nil {
                _maxDynamicNeighbors_u16 := uint16(_maxDynamicNeighbors_u64)
                bgpGblState_obj.MaxDynamicNeighbors = &_maxDynamicNeighbors_u16
            }
        }

        if value, ok := cfgDbEntry["network_import_check"] ; ok {
            _networkImportCheck, _ := strconv.ParseBool(value)
            bgpGblState_obj.NetworkImportCheck = &_networkImportCheck
        }

        if value, ok := cfgDbEntry["read_quanta"] ; ok {
            if _readQuanta_u64, err := strconv.ParseUint(value, 10, 32) ; err == nil {
                _readQuanta_u8 := uint8(_readQuanta_u64)
                bgpGblState_obj.ReadQuanta = &_readQuanta_u8
            }
        }

        if value, ok := cfgDbEntry["route_map_process_delay"] ; ok {
            if _routeMapProcessDelay_u64, err := strconv.ParseUint(value, 10, 32) ; err == nil {
                _routeMapProcessDelay_u16 := uint16(_routeMapProcessDelay_u64)
                bgpGblState_obj.RouteMapProcessDelay = &_routeMapProcessDelay_u16
            }
        }

        if value, ok := cfgDbEntry["write_quanta"] ; ok {
            if _writeQuanta_u64, err := strconv.ParseUint(value, 10, 32) ; err == nil {
                _writeQuanta_u8 := uint8(_writeQuanta_u64)
                bgpGblState_obj.WriteQuanta = &_writeQuanta_u8
            }
        }
    }

    vtysh_cmd := "show ip bgp vrf " + niName + " summary json"
    bgpFrrJsonCacheKey := bgp_frr_json_cache_query_key_t{niName : niName}
    bgpGblJson, cmd_err := utl_bgp_exec_vtysh_cmd (vtysh_cmd, inParams, BGP_FRR_JSON_CACHE_QUERY_TYPE_SUMMARY, bgpFrrJsonCacheKey)
    if cmd_err != nil {
        log.Errorf("Failed to fetch BGP global info for niName:%s. Err: %s", niName, cmd_err)
        return oper_err
    }

    bgpGblDataJson, ok := bgpGblJson["ipv4Unicast"].(map[string]interface{}); if ok {
        if value, ok := bgpGblDataJson["as"] ; ok {
            _localAs := uint32(value.(float64))
            bgpGblState_obj.As = &_localAs
        }

        if value, ok := bgpGblDataJson["routerId"].(string) ; ok {
            bgpGblState_obj.RouterId = &value
        }
    }

    return err;
}

var YangToDb_bgp_gbl_afi_safi_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    rmap := make(map[string]string)
    var err error

    log.Info("YangToDb_bgp_gbl_afi_safi_field_xfmr")
    rmap["NULL"] = "NULL"

    return rmap, err
}

var DbToYang_bgp_gbl_afi_safi_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error
    entry_key := inParams.key
    log.Info("DbToYang_bgp_gbl_afi_safi_field_xfmr: ", entry_key)

    mpathKey := strings.Split(entry_key, "|")
    if len(mpathKey) < 2 {return rmap, nil}

	afi := ""

	switch mpathKey[1] {
	case "ipv4_unicast":
		afi = "IPV4_UNICAST"
	case "ipv6_unicast":
		afi = "IPV6_UNICAST"
	case "l2vpn_evpn":
		afi = "L2VPN_EVPN"
    default:
        return rmap, nil
	}

    rmap["afi-safi-name"] = afi

    return rmap, err
}

var YangToDb_bgp_dyn_neigh_listen_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    rmap := make(map[string]string)
    var err error

    log.Info("YangToDb_bgp_dyn_neigh_listen_field_xfmr")
    rmap["NULL"] = "NULL"

    return rmap, err
}

var YangToDb_bgp_gbl_afi_safi_addr_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    rmap := make(map[string]string)
    var err error

    log.Info("YangToDb_bgp_gbl_afi_safi_addr_field_xfmr")
    rmap["NULL"] = "NULL"

    return rmap, err
}


var DbToYang_bgp_dyn_neigh_listen_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error

    entry_key := inParams.key
    log.Info("DbToYang_bgp_dyn_neigh_listen_key_xfmr: ", entry_key)

    dynKey := strings.Split(entry_key, "|")
    if len(dynKey) < 2 {return rmap, nil}

    rmap["prefix"] = dynKey[1]

    return rmap, err
}

var DbToYang_bgp_gbl_afi_safi_addr_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error

    entry_key := inParams.key
    log.Info("DbToYang_bgp_gbl_afi_safi_addr_field_xfmr: ", entry_key)

    dynKey := strings.Split(entry_key, "|")
    if len(dynKey) < 3 {return rmap, nil}

    rmap["prefix"] = dynKey[2]

    return rmap, err
}

var YangToDb_bgp_gbl_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    niName := pathInfo.Var("name")
    bgpId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")

    if len(pathInfo.Vars) <  3 {
        return "", errors.New("Invalid Key length")
    }

    if len(niName) == 0 {
        return "", errors.New("vrf name is missing")
    }

    if !strings.Contains(bgpId,"BGP") {
        return "", errors.New("BGP ID is missing")
    }

    if len(protoName) == 0 {
        return "", errors.New("Protocol Name is missing")
    }

    log.V(3).Info("URI VRF ", niName)

    if inParams.oper == DELETE && niName == "default" {
        xpath, _, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)
        switch xpath {
            case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp": fallthrough
            case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/global": fallthrough
            case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/global/config":
                 log.Info ("DELELE op for niName: ", niName, " XPATH: ", xpath)
                 bgpGblTblTs := &db.TableSpec{Name: "BGP_GLOBALS"}
                 if bgpGblTblKeys, err := inParams.d.GetKeys(bgpGblTblTs) ; err == nil {
                     for _, key := range bgpGblTblKeys {
                         /* If "default" VRF is present in keys-list & still list-len is greater than 1,
                          * then don't allow "default" VRF BGP-instance delete.
                          * "default" VRF BGP-instance should be deleted, only after all non-default VRF instances are deleted from the system */
                         if key.Get(0) == niName && len(bgpGblTblKeys) > 1 {
                             return "", tlerr.NotSupported("Delete not allowed, since non-default-VRF BGP-instance present in system")
                         }
                     }
                 }
        }
    }

    return niName, err
}

var DbToYang_bgp_gbl_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error
    entry_key := inParams.key
    log.Info("DbToYang_bgp_gbl_tbl_key: ", entry_key)

    rmap["name"] = entry_key
    return rmap, err
}

var YangToDb_bgp_dyn_neigh_listen_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	log.Info("YangToDb_bgp_dyn_neigh_listen_key_xfmr key: ", inParams.uri)

    pathInfo := NewPathInfo(inParams.uri)

    niName := pathInfo.Var("name")
    bgpId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")
	prefix := pathInfo.Var("prefix")

    if len(pathInfo.Vars) < 4 {
        return "", errors.New("Invalid Key length")
    }

    if len(niName) == 0 {
        return "", errors.New("vrf name is missing")
    }

    if !strings.Contains(bgpId,"BGP") {
        return "", errors.New("BGP ID is missing")
    }

    if len(protoName) == 0 {
        return "", errors.New("Protocol Name is missing")
    }

	key := niName + "|" + prefix

	log.Info("YangToDb_bgp_dyn_neigh_listen_key_xfmr key: ", key)

    return key, nil
}

var DbToYang_bgp_dyn_neigh_listen_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_bgp_dyn_neigh_listen_key_xfmr: ", entry_key)

    dynKey := strings.Split(entry_key, "|")
    if len(dynKey) < 2 {return rmap, nil}

    rmap["prefix"] = dynKey[1]

	log.Info("DbToYang_bgp_dyn_neigh_listen_key_xfmr: rmap:", rmap)
    return rmap, nil
}

var YangToDb_bgp_gbl_afi_safi_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {

    pathInfo := NewPathInfo(inParams.uri)

    niName := pathInfo.Var("name")
    bgpId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")
	afName := pathInfo.Var("afi-safi-name")
	afi := ""
    var err error

    if len(pathInfo.Vars) < 4 {
        return afi, errors.New("Invalid Key length")
    }

    if len(niName) == 0 {
        return afi, errors.New("vrf name is missing")
    }

    if !strings.Contains(bgpId,"BGP") {
        return afi, errors.New("BGP ID is missing")
    }

    if len(protoName) == 0 {
        return afi, errors.New("Protocol Name is missing")
    }

	if strings.Contains(afName, "IPV4_UNICAST") {
		afi = "ipv4_unicast"
	} else if strings.Contains(afName, "IPV6_UNICAST") {
		afi = "ipv6_unicast"
	} else if strings.Contains(afName, "L2VPN_EVPN") {
		afi = "l2vpn_evpn"
	} else {
		log.Info("Unsupported AFI type " + afName)
        return afi, errors.New("Unsupported AFI type " + afName)
	}

    if strings.Contains(afName, "IPV4_UNICAST") {
        afName = "IPV4_UNICAST"
        if strings.Contains(inParams.uri, "ipv6-unicast") ||
           strings.Contains(inParams.uri, "l2vpn-evpn") {
           err = errors.New("IPV4_UNICAST supported only on ipv4-config container")
           log.Info("IPV4_UNICAST supported only on ipv4-config container: ", afName);
           return afName, err
        }
    } else if strings.Contains(afName, "IPV6_UNICAST") {
        afName = "IPV6_UNICAST"
        if strings.Contains(inParams.uri, "ipv4-unicast") ||
           strings.Contains(inParams.uri, "l2vpn-evpn") {
           err = errors.New("IPV6_UNICAST supported only on ipv6-config container")
           log.Info("IPV6_UNICAST supported only on ipv6-config container: ", afName);
           return afName, err
        }
    } else if strings.Contains(afName, "L2VPN_EVPN") {
        afName = "L2VPN_EVPN"
        if strings.Contains(inParams.uri, "ipv6-unicast") ||
           strings.Contains(inParams.uri, "ipv4-unicast") {
           err = errors.New("L2VPN_EVPN supported only on l2vpn-evpn container")
           log.Info("L2VPN_EVPN supported only on l2vpn-evpn container: ", afName);
           return afName, err
        }
    } else  {
	    err = errors.New("Unsupported AFI SAFI")
	    log.Info("Unsupported AFI SAFI ", afName);
	    return afName, err
    }

    key := niName + "|" + afi

    log.Info("YangToDb_bgp_gbl_afi_safi_key_xfmr: AFI key: ", key)

    return key, nil
}

var DbToYang_bgp_gbl_afi_safi_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    pathInfo := NewPathInfo(inParams.uri)
    niName := pathInfo.Var("name")

    mpathKey := strings.Split(inParams.key, "|")
    if len(mpathKey) < 2 {return nil, nil}
    if (mpathKey[0] != niName) {
        if log.V(3) {
           log.Info("Vrf name mismatch: " +  niName + " " + mpathKey[0]);
        }
        return nil, nil
    }

    afi := ""

    switch mpathKey[1] {
        case "ipv4_unicast":
            afi = "IPV4_UNICAST"
	case "ipv6_unicast":
            afi = "IPV6_UNICAST"
	case "l2vpn_evpn":
            afi = "L2VPN_EVPN"
        default:
            return nil, nil
    }

    rmap := make(map[string]interface{})
    rmap["afi-safi-name"] = afi

    if log.V(3) {
        log.Info("DbToYang_bgp_gbl_afi_safi_key_xfmr: key: ", inParams.key, "rmap: ", rmap)
    }
    return rmap, nil
}

var YangToDb_bgp_global_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    log.Info("YangToDb_bgp_global_subtree_xfmr:", inParams.oper)
    if inParams.oper == DELETE {
        return nil, errors.New("Invalid request")
    }
    return nil, err
}

var YangToDb_bgp_gbl_afi_safi_addr_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {

    pathInfo := NewPathInfo(inParams.uri)

    niName := pathInfo.Var("name")
    bgpId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")
    afName := pathInfo.Var("afi-safi-name")
    prefix := pathInfo.Var("prefix")
    afi := ""
    var err error

    if len(pathInfo.Vars) < 5 {
        return afi, errors.New("Invalid Key length")
    }

    if len(niName) == 0 {
        return afi, errors.New("vrf name is missing")
    }

    if !strings.Contains(bgpId,"BGP") {
        return afi, errors.New("BGP ID is missing")
    }

    if len(protoName) == 0 {
        return afi, errors.New("Protocol Name is missing")
    }

	if strings.Contains(afName, "IPV4_UNICAST") {
		afi = "ipv4_unicast"
	} else if strings.Contains(afName, "IPV6_UNICAST") {
		afi = "ipv6_unicast"
	} else if strings.Contains(afName, "L2VPN_EVPN") {
		afi = "l2vpn_evpn"
	} else {
		log.Info("Unsupported AFI type " + afName)
        return afi, errors.New("Unsupported AFI type " + afName)
	}

    if strings.Contains(afName, "IPV4_UNICAST") {
        afName = "IPV4_UNICAST"
        if strings.Contains(inParams.uri, "ipv6-unicast") ||
           strings.Contains(inParams.uri, "l2vpn-evpn") {
		    err = errors.New("IPV4_UNICAST supported only on ipv4-config container")
		    log.Info("IPV4_UNICAST supported only on ipv4-config container: ", afName);
		    return afName, err
        }
    } else if strings.Contains(afName, "IPV6_UNICAST") {
        afName = "IPV6_UNICAST"
        if strings.Contains(inParams.uri, "ipv4-unicast") ||
           strings.Contains(inParams.uri, "l2vpn-evpn") {
		    err = errors.New("IPV6_UNICAST supported only on ipv6-config container")
		    log.Info("IPV6_UNICAST supported only on ipv6-config container: ", afName);
		    return afName, err
        }
    } else if strings.Contains(afName, "L2VPN_EVPN") {
        afName = "L2VPN_EVPN"
        if strings.Contains(inParams.uri, "ipv6-unicast") ||
           strings.Contains(inParams.uri, "ipv4-unicast") {
		    err = errors.New("L2VPN_EVPN supported only on l2vpn-evpn container")
		    log.Info("L2VPN_EVPN supported only on l2vpn-evpn container: ", afName);
		    return afName, err
        }
    } else  {
	    err = errors.New("Unsupported AFI SAFI")
	    log.Info("Unsupported AFI SAFI ", afName);
	    return afName, err
    }

	key := niName + "|" + afi + "|" + prefix

	log.Info("YangToDb_bgp_gbl_afi_safi_addr_key_xfmr AFI key: ", key)

    return key, nil
}

var DbToYang_bgp_gbl_afi_safi_addr_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_bgp_gbl_afi_safi_addr_key_xfmr: ", entry_key)

    mpathKey := strings.Split(entry_key, "|")
    if len(mpathKey) < 3 {return rmap, nil}

    rmap["prefix"] = mpathKey[2]

	log.Info("DbToYang_bgp_gbl_afi_safi_addr_key_xfmr: rmap:", rmap)
    return rmap, nil
}

var rpc_clear_bgp RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_clear_bgp")
    var err error
    var status string
    var clear_all string
    var af_str, vrf_name, all, soft, in, out, ip_address, prefix, peer_group, asn, intf, external, dampening string
    var cmd, cmdbase string
    is_evpn := false
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil, err
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-bgp-clear:output"`
    }

    log.Info("In rpc_clear_bgp ", mapData)

    input := mapData["sonic-bgp-clear:input"]
    mapData = input.(map[string]interface{})

    log.Info("In rpc_clear_bgp", mapData)

    if value, ok := mapData["clear-all"].(bool) ; ok {
        log.Info("In clearall", value)
        if value {
           clear_all = "* "
        }
    }

    log.Info("In clearall", clear_all)
    if value, ok := mapData["vrf-name"].(string) ; ok {
        log.Info("In vrf", value)
        if value != "" {
            vrf_name = "vrf " + value + " "
        }
    }

    if value, ok := mapData["family"].(string) ; ok {
        if value == "IPv4" {
            af_str = "ipv4 "
        } else if value == "IPv6" {
            af_str = "ipv6 "
        } else if value == "EVPN" {
            is_evpn = true
            af_str = "evpn "
        }
    }

    if value, ok := mapData["all"].(bool) ; ok {
        if value {
           all = "* "
        }
    }

    if value, ok := mapData["external"].(bool) ; ok {
        if value {
           external = "external "
        }
    }

    if value, ok := mapData["address"].(string) ; ok {
        if value != "" {
            ip_address = value + " "
        }
    }

    if value, ok := mapData["interface"].(string) ; ok {
        if value != "" {
            util_bgp_get_native_ifname_from_ui_ifname (&value)
            intf = value + " "
        }
    }

    if value, ok := mapData["asn"].(float64) ; ok {
        _asn := uint64(value)
        asn = strconv.FormatUint(_asn, 10)
        asn = asn + " "
    }

    if value, ok := mapData["prefix"].(string) ; ok {
        if value != "" {
            prefix = "prefix " + value + " "
            af_str = ""
            if dampvalue, ok := mapData["dampening"].(bool) ; ok {
               if dampvalue {
                  prefix = value + " "
               }
            }
        }
    }

    if value, ok := mapData["peer-group"].(string) ; ok {
        if value != "" {
            peer_group = "peer-group " + value + " "
        }
    }

    if value, ok := mapData["dampening"].(bool) ; ok {
        if value {
            dampening = "dampening "
        }
    }

    if value, ok := mapData["in"].(bool) ; ok {
        if value {
           in = "in "
        }
    }

    if value, ok := mapData["out"].(bool) ; ok {
        if value {
            out = "out "
        }
    }

    if value, ok := mapData["soft"].(bool) ; ok {
        if value {
            soft = "soft "
        }
    }

    log.Info("In rpc_clear_bgp ", clear_all, vrf_name, af_str, all, ip_address, intf, asn, prefix, peer_group, dampening, in, out, soft)

    if clear_all != "" && dampening == "" {
        cmdbase = "clear bgp "
    } else if is_evpn {
        cmdbase = "clear bgp l2vpn "
    } else {
        cmdbase = "clear ip bgp "
    }

    cmd = cmdbase
    if vrf_name != "" {
        cmd = cmdbase + vrf_name
    }

    if af_str != "" {
        cmd = cmd + af_str
    }

    if dampening != "" {
        cmd = cmd + dampening
    }

    if ip_address != "" {
        cmd = cmd + ip_address
    }

    if intf != "" {
        cmd = cmd + intf
    }

    if prefix != "" {
        cmd = cmd + prefix
    }

    if peer_group != "" {
        cmd = cmd + peer_group
    }

    if external != "" {
        cmd = cmd + external
    }

    if asn != "" {
        cmd = cmd + asn
    }

    if all != "" {
        cmd = cmd + all
    }

    if soft != "" {
        cmd = cmd + soft
    }

    if in != "" {
        cmd = cmd + in
    }

    if out != "" {
        cmd = cmd + out
    }

    cmd = strings.TrimSuffix(cmd, " ")
    exec_vtysh_cmd (cmd)
    status = "Success"
    result.Output.Status = status
    return json.Marshal(&result)
}
