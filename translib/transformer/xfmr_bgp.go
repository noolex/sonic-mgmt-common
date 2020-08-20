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
}

func bgp_hdl_post_xfmr(inParams *XfmrParams, bgpRespMap *map[string]map[string]db.Value) (error) {
    var err error

    if inParams.oper == DELETE {
        return err
    }

    /* Remove the invalid default values for BGP address family */
    for key := range inParams.yangDefValMap["BGP_GLOBALS_AF"] {
        if strings.Contains(key, "l2vpn_evpn") {
            if inParams.yangDefValMap["BGP_GLOBALS_AF"][key].Field["max_ebgp_paths"] != "" {
               delete (inParams.yangDefValMap["BGP_GLOBALS_AF"][key].Field, "max_ebgp_paths")
            }
            if inParams.yangDefValMap["BGP_GLOBALS_AF"][key].Field["max_ibgp_paths"] != "" {
               delete (inParams.yangDefValMap["BGP_GLOBALS_AF"][key].Field, "max_ibgp_paths")
            }
        } else if (strings.Contains(key, "ipv4_unicast") ||
                   strings.Contains(key, "ipv6_unicast")) {
            if inParams.yangDefValMap["BGP_GLOBALS_AF"][key].Field["advertise-default-gw"] != "" {
               delete (inParams.yangDefValMap["BGP_GLOBALS_AF"][key].Field, "advertise-default-gw")
            }
        }
    }

    for key := range inParams.yangDefValMap["BGP_NEIGHBOR_AF"] {
        if strings.Contains(key, "l2vpn_evpn") {
            if inParams.yangDefValMap["BGP_NEIGHBOR_AF"][key].Field["rrclient"] != "" {
               delete (inParams.yangDefValMap["BGP_NEIGHBOR_AF"][key].Field, "rrclient")
            }
            if inParams.yangDefValMap["BGP_NEIGHBOR_AF"][key].Field["send_community"] != "" {
               delete (inParams.yangDefValMap["BGP_NEIGHBOR_AF"][key].Field, "send_community")
            }
        }
    }

    for key := range inParams.yangDefValMap["BGP_PEER_GROUP_AF"] {
        if strings.Contains(key, "l2vpn_evpn") {
            if inParams.yangDefValMap["BGP_PEER_GROUP_AF"][key].Field["rrclient"] != "" {
               delete (inParams.yangDefValMap["BGP_PEER_GROUP_AF"][key].Field, "rrclient")
            }
        }
    }

    return err
}

var bgp_gbl_tbl_xfmr TableXfmrFunc = func (inParams XfmrParams)  ([]string, error) {
    var tblList, nil_tblList []string

    log.Info("bgp_gbl_tbl_xfmr: ", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    vrf := pathInfo.Var("name")
    bgpId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")

    if len(pathInfo.Vars) <  3 {
        err := errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return nil_tblList, err
    }

    if len(vrf) == 0 {
        err_str := "VRF name is missing"
        err := errors.New(err_str); log.Info(err_str)
        return nil_tblList, err
    }
    if !strings.Contains(bgpId,"BGP") {
        err_str := "BGP ID is missing"
        err := errors.New(err_str); log.Info(err_str)
        return nil_tblList, err
    }
    if len(protoName) == 0 {
        err_str := "Protocol Name is Missing"
        err := errors.New(err_str); log.Info(err_str)
        return nil_tblList, err
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
    bgpGblJson, cmd_err := exec_vtysh_cmd (vtysh_cmd)
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

    log.Info("URI VRF ", niName)

    if inParams.oper == DELETE && niName == "default" {
        xpath, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)
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
	
	log.Info("AFI key: ", key)

    return key, nil
}

var DbToYang_bgp_gbl_afi_safi_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_bgp_gbl_afi_safi_key_xfmr: ", entry_key)

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

	log.Info("DbToYang_bgp_gbl_afi_safi_key_xfmr: rmap:", rmap)
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
            if dampvalue, ok := mapData["dampening"].(bool) ; ok {
               if dampvalue {
                  ip_address = value + " "
               }
            }
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

    if !is_evpn {
        cmdbase = "clear ip bgp "
    } else {
        cmdbase = "clear bgp l2vpn "
    }
    if clear_all != "" {
        cmd = cmdbase + clear_all
    } else {
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

    }
    cmd = strings.TrimSuffix(cmd, " ")
    exec_vtysh_cmd (cmd)
    status = "Success"
    result.Output.Status = status
    return json.Marshal(&result)
}
