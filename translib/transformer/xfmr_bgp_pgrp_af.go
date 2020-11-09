package transformer

import (
    "errors"
    "strings"
    "reflect"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    log "github.com/golang/glog"
)


func init () {
    XlateFuncBind("YangToDb_bgp_af_pgrp_tbl_key_xfmr", YangToDb_bgp_af_pgrp_tbl_key_xfmr)
    XlateFuncBind("DbToYang_bgp_af_pgrp_tbl_key_xfmr", DbToYang_bgp_af_pgrp_tbl_key_xfmr)
    XlateFuncBind("YangToDb_bgp_pgrp_afi_safi_name_fld_xfmr", YangToDb_bgp_pgrp_afi_safi_name_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_afi_safi_name_fld_xfmr", DbToYang_bgp_pgrp_afi_safi_name_fld_xfmr)

    XlateFuncBind("YangToDb_bgp_pgrp_community_type_fld_xfmr", YangToDb_bgp_pgrp_community_type_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_community_type_fld_xfmr", DbToYang_bgp_pgrp_community_type_fld_xfmr)
    XlateFuncBind("YangToDb_bgp_pgrp_orf_type_fld_xfmr", YangToDb_bgp_pgrp_orf_type_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_orf_type_fld_xfmr", DbToYang_bgp_pgrp_orf_type_fld_xfmr)
    XlateFuncBind("YangToDb_bgp_pgrp_tx_add_paths_fld_xfmr", YangToDb_bgp_pgrp_tx_add_paths_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_tx_add_paths_fld_xfmr", DbToYang_bgp_pgrp_tx_add_paths_fld_xfmr)
    XlateFuncBind("bgp_validate_pgrp_af", bgp_validate_pgrp_af)
}

func bgp_validate_pgrp_af(inParams XfmrParams) bool {
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath,_,_ := XfmrRemoveXPATHPredicates(inParams.uri)
    // /openconfig-network-instance:network-instances/network-instance/protocols/protocol/bgp/peer-groups/peer-group/afi-safis/afi-safi/
    // Ignore the above prefix of length 129 to save the string compare time
    targetUriPath = targetUriPath[129:]
    afiSafiName := pathInfo.Var("afi-safi-name")
    if log.V(3) {
        log.Info("bgp_util_pgrp_af_validate : VRF ", pathInfo.Var("name"), " URI ",
                 inParams.uri," AFi-SAFI ", afiSafiName, " Target URI ", targetUriPath)
    }
    switch targetUriPath {
        case "ipv4-unicast":
            if afiSafiName != "IPV4_UNICAST" { return false }
        case "ipv6-unicast":
            if afiSafiName != "IPV6_UNICAST" { return false }
        case "l2vpn-evpn":
            if afiSafiName != "L2VPN_EVPN" { return false }
    }
    return true
}

var YangToDb_bgp_pgrp_afi_safi_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_bgp_pgrp_afi_safi_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    entry_key := inParams.key
    pgrpAfKey := strings.Split(entry_key, "|")
    if len(pgrpAfKey) < 3 {return result, nil}

	pgrpAfName := ""

	switch pgrpAfKey[2] {
	case "ipv4_unicast":
		pgrpAfName = "IPV4_UNICAST"
	case "ipv6_unicast":
		pgrpAfName = "IPV6_UNICAST"
	case "l2vpn_evpn":
		pgrpAfName = "L2VPN_EVPN"
	}

    result["afi-safi-name"] = pgrpAfName

    return result, err
}


var YangToDb_bgp_af_pgrp_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var vrfName string

    log.Info("YangToDb_bgp_af_pgrp_tbl_key_xfmr ***", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    /* Key should contain, <vrf name, protocol name, peer group name> */

    vrfName    =  pathInfo.Var("name")
    bgpId      := pathInfo.Var("identifier")
    protoName  := pathInfo.Var("name#2")
    pGrpName   := pathInfo.Var("peer-group-name")
    afName     := pathInfo.Var("afi-safi-name")

    if len(pathInfo.Vars) <  4 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return vrfName, err
    }

    if len(vrfName) == 0 {
        err = errors.New("vrf name is missing");
        log.Info("VRF Name is Missing")
        return vrfName, err
    }
    if !strings.Contains(bgpId,"BGP") {
        err = errors.New("BGP ID is missing");
        log.Info("BGP ID is missing")
        return bgpId, err
    }
    if len(protoName) == 0 {
        err = errors.New("Protocol Name is missing");
        log.Info("Protocol Name is Missing")
        return protoName, err
    }
    if len(pGrpName) == 0 {
        err = errors.New("Peer Group Name is missing")
        log.Info("Peer Group Name is Missing")
        return pGrpName, err
    }

    if len(afName) == 0 {
        err = errors.New("AFI SAFI is missing")
        log.Info("AFI SAFI is Missing")
        return afName, err
    }

    if strings.Contains(afName, "IPV4_UNICAST") {
        afName = "ipv4_unicast"
    } else if strings.Contains(afName, "IPV6_UNICAST") { 
        afName = "ipv6_unicast"
    } else if strings.Contains(afName, "L2VPN_EVPN") {
        afName = "l2vpn_evpn"
    } else  {
	err = errors.New("Unsupported AFI SAFI")
	log.Info("Unsupported AFI SAFI ", afName);
	return afName, err
    }

    log.Info("URI VRF ", vrfName)
    log.Info("URI Peer Group ", pGrpName)
    log.Info("URI AFI SAFI ", afName)

    var afPgrpKey string = vrfName + "|" + pGrpName + "|" + afName

    log.Info("YangToDb_bgp_af_pgrp_tbl_key_xfmr: afPgrpKey:", afPgrpKey)
    return afPgrpKey, nil
}

var DbToYang_bgp_af_pgrp_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_bgp_af_pgrp_tbl_key: ", entry_key)

    afPgrpKey := strings.Split(entry_key, "|")
    if len(afPgrpKey) < 3 {return rmap, nil}

	afName := ""

	switch afPgrpKey[2] {
	case "ipv4_unicast":
		afName = "IPV4_UNICAST"
	case "ipv6_unicast":
		afName = "IPV6_UNICAST"
	case "l2vpn_evpn":
		afName = "L2VPN_EVPN"
	}

    rmap["afi-safi-name"]   = afName

    return rmap, nil
}

var YangToDb_bgp_pgrp_community_type_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    var err error
    if inParams.param == nil {
        err = errors.New("No Params");
        return res_map, err
    }
    
    if inParams.oper == DELETE {
        subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

        if _, ok := subOpMap[db.ConfigDB]; !ok {
            subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        }
        if _, ok := subOpMap[db.ConfigDB]["BGP_PEER_GROUP_AF"]; !ok {
            subOpMap[db.ConfigDB]["BGP_PEER_GROUP_AF"] = make(map[string]db.Value)
        }
        subOpMap[db.ConfigDB]["BGP_PEER_GROUP_AF"][inParams.key] = db.Value{Field: make(map[string]string)}
        subOpMap[db.ConfigDB]["BGP_PEER_GROUP_AF"][inParams.key].Field["send_community"] = "both"

        inParams.subOpDataMap[UPDATE] = &subOpMap
        return res_map, nil
    }
    /* In case of POST operation and field has some default value in the YANG, infra is internally filling the enum 
     * in string format (in this case) and hence setting the field value accordingly. */
    curYgotNodeData, _:= yangNodeForUriGet(inParams.uri, inParams.ygRoot)
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
    log.Info("YangToDb_bgp_pgrp_community_type_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " community_type: ", community_type)

    if (community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_STANDARD) {
        res_map["send_community"] = "standard"
    }  else if (community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_EXTENDED) {
        res_map["send_community"] = "extended"
    }  else if (community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_BOTH) {
        res_map["send_community"] = "both"
    }  else if (community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_NONE) {
        res_map["send_community"] = "none"
    }  else if (community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_LARGE) {
        res_map["send_community"] = "large"
    }  else if (community_type == ocbinds.OpenconfigBgpExt_BgpExtCommunityType_ALL) {
        res_map["send_community"] = "all"
    } else {
        err = errors.New("send_community  Missing");
        return res_map, err
    }

    return res_map, nil

}

var DbToYang_bgp_pgrp_community_type_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_bgp_pgrp_community_type_fld_xfmr : ", data, "inParams : ", inParams)

    pTbl := data["BGP_PEER_GROUP_AF"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_bgp_pgrp_community_type_fld_xfmr BGP Peer group not found : ", inParams.key)
        return result, errors.New("BGP peer group not found : " + inParams.key)
    }
    pGrpKey := pTbl[inParams.key]
    community_type, ok := pGrpKey.Field["send_community"]

    if ok {
        if (community_type == "standard") {
            result["send-community"] = "STANDARD"
        } else if (community_type == "extended") {
            result["send-community"] = "EXTENDED"
        } else if (community_type == "both") {
            result["send-community"] = "BOTH"
        } else if (community_type == "none") {
            result["send-community"] = "NONE"
        } else if (community_type == "large") {
            result["send-community"] = "LARGE"
        } else if (community_type == "all") {
            result["send-community"] = "ALL"
        }
    } else {
        log.Info("send_community not found in DB")
    }
    return result, err
}

var YangToDb_bgp_pgrp_orf_type_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    var err error
    if inParams.param == nil {
        err = errors.New("No Params");
        return res_map, err
    }
    if inParams.oper == DELETE {
        res_map["cap_orf"] = ""
        return res_map, nil
    }

    orf_type, _ := inParams.param.(ocbinds.E_OpenconfigBgpExt_BgpOrfType)
    log.Info("YangToDb_bgp_pgrp_orf_type_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " orf_type: ", orf_type)

    if (orf_type == ocbinds.OpenconfigBgpExt_BgpOrfType_SEND) {
        res_map["cap_orf"] = "send"
    }  else if (orf_type == ocbinds.OpenconfigBgpExt_BgpOrfType_RECEIVE) {
        res_map["cap_orf"] = "receive"
    }  else if (orf_type == ocbinds.OpenconfigBgpExt_BgpOrfType_BOTH) {
        res_map["cap_orf"] = "both"
    } else {
        err = errors.New("ORF type Missing");
        return res_map, err
    }

    return res_map, nil
}

var DbToYang_bgp_pgrp_orf_type_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_bgp_pgrp_orf_type_fld_xfmr : ", data, "inParams : ", inParams)

    pTbl := data["BGP_PEER_GROUP_AF"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_bgp_pgrp_orf_type_fld_xfmr BGP PEER GROUP AF not found : ", inParams.key)
        return result, errors.New("BGP PEER GROUP AF not found : " + inParams.key)
    }
    pGrpKey := pTbl[inParams.key]
    orf_type, ok := pGrpKey.Field["cap_orf"]

    if ok {
        if (orf_type == "send") {
            result["orf-type"] = "SEND"
        } else if (orf_type == "receive") {
            result["orf-type"] = "RECEIVE"
        } else if (orf_type == "both") {
            result["orf-type"] = "BOTH"
        }
    } else {
        log.Info("cap_orf_direction field not found in DB")
    }
    return result, err
}

var YangToDb_bgp_pgrp_tx_add_paths_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    var err error
    if inParams.param == nil {
        err = errors.New("No Params");
        return res_map, err
    }
    if inParams.oper == DELETE {
        res_map["tx_add_paths"] = ""
        return res_map, nil
    }

    tx_add_paths_type, _ := inParams.param.(ocbinds.E_OpenconfigBgpExt_TxAddPathsType)
    log.Info("YangToDb_pgrp_tx_add_paths_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " add-paths-type: ", tx_add_paths_type)

    if (tx_add_paths_type == ocbinds.OpenconfigBgpExt_TxAddPathsType_TX_ALL_PATHS) {
        res_map["tx_add_paths"] = "tx_all_paths"
    }  else if (tx_add_paths_type == ocbinds.OpenconfigBgpExt_TxAddPathsType_TX_BEST_PATH_PER_AS) {
        res_map["tx_add_paths"] = "tx_best_path_per_as"
    } else {
        err = errors.New("Invalid add Paths type Missing");
        return res_map, err
    }

    return res_map, nil

}

var DbToYang_bgp_pgrp_tx_add_paths_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_bgp_pgrp_tx_add_paths_fld_xfmr: ", data, "inParams : ", inParams)

    pTbl := data["BGP_PEER_GROUP_AF"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_bgp_pgrp_tx_add_paths_fld_xfmr BGP peer group not found : ", inParams.key)
        return result, errors.New("BGP neighbor not found : " + inParams.key)
    }
    pNbrKey := pTbl[inParams.key]
    tx_add_paths_type, ok := pNbrKey.Field["tx_add_paths"]

    if ok {
        if (tx_add_paths_type == "tx_all_paths") {
            result["tx-add-paths"] = "TX_ALL_PATHS"
        } else if (tx_add_paths_type == "tx_best_path_per_as") {
            result["tx-add-paths"] = "TX_BEST_PATH_PER_AS"
        }
    } else {
        log.Info("Tx add Paths field not found in DB")
    }
    return result, err
}



