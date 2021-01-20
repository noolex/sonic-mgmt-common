package transformer

import (
    "errors"
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
)


func init () {
    XlateFuncBind("YangToDb_bgp_pgrp_tbl_key_xfmr", YangToDb_bgp_pgrp_tbl_key_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_tbl_key_xfmr", DbToYang_bgp_pgrp_tbl_key_xfmr)
    XlateFuncBind("YangToDb_bgp_pgrp_peer_type_fld_xfmr", YangToDb_bgp_pgrp_peer_type_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_peer_type_fld_xfmr", DbToYang_bgp_pgrp_peer_type_fld_xfmr)
    XlateFuncBind("YangToDb_bgp_pgrp_name_fld_xfmr", YangToDb_bgp_pgrp_name_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_name_fld_xfmr", DbToYang_bgp_pgrp_name_fld_xfmr)
    XlateFuncBind("DbToYang_bgp_peer_group_mbrs_state_xfmr", DbToYang_bgp_peer_group_mbrs_state_xfmr)
    XlateFuncBind("YangToDb_bgp_pgrp_auth_password_xfmr", YangToDb_bgp_pgrp_auth_password_xfmr)
    XlateFuncBind("DbToYang_bgp_pgrp_auth_password_xfmr", DbToYang_bgp_pgrp_auth_password_xfmr)
}

var YangToDb_bgp_pgrp_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_bgp_pgrp_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_bgp_pgrp_name_fld_xfmr : ", data, "inParams : ", inParams)

    entry_key := inParams.key
    peer_group_Key := strings.Split(entry_key, "|")
    if len(peer_group_Key) < 2 {return result, nil}

    peer_group_name:= peer_group_Key[1]
    result["peer-group-name"] = peer_group_name

    return result, err
}

var YangToDb_bgp_pgrp_peer_type_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    var err error
    if inParams.param == nil {
        err = errors.New("No Params");
        return res_map, err
    }
    if inParams.oper == DELETE {
        res_map["peer_type"] = ""
        return res_map, nil
    }

    peer_type, _ := inParams.param.(ocbinds.E_OpenconfigBgp_PeerType)
    log.Info("YangToDb_bgp_pgrp_peer_type_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " peer-type: ", peer_type)

    if (peer_type == ocbinds.OpenconfigBgp_PeerType_INTERNAL) {
        res_map["peer_type"] = "internal"
    }  else if (peer_type == ocbinds.OpenconfigBgp_PeerType_EXTERNAL) {
        res_map["peer_type"] = "external"
    } else {
        err = errors.New("Peer Type Missing");
        return res_map, err
    }

    return res_map, nil

}

var DbToYang_bgp_pgrp_peer_type_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_bgp_pgrp_peer_type_fld_xfmr : ", data, "inParams : ", inParams)

    pTbl := data["BGP_PEER_GROUP"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_bgp_pgrp_peer_type_fld_xfmr BGP peer-groups not found : ", inParams.key)
        return result, errors.New("BGP peer-groups not found : " + inParams.key)
    }
    pGrpKey := pTbl[inParams.key]
    peer_type, ok := pGrpKey.Field["peer_type"]

    if ok {
        if (peer_type == "internal") {
            result["peer-type"] = "INTERNAL" 
        } else if (peer_type == "external") {
            result["peer-type"] = "EXTERNAL"
        }
    } else {
        log.Info("peer_type field not found in DB")
    }
    return result, err
}


var YangToDb_bgp_pgrp_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var vrfName string

    log.Info("YangToDb_bgp_pgrp_tbl_key_xfmr ***", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    /* Key should contain, <vrf name, protocol name, peer group name> */

    vrfName    =  pathInfo.Var("name")
    bgpId      := pathInfo.Var("identifier")
    protoName  := pathInfo.Var("name#2")
    pGrpName   := pathInfo.Var("peer-group-name")

    if len(pathInfo.Vars) <  3 {
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

    var pGrpKey string = vrfName + "|" + pGrpName

    log.Info("YangToDb_bgp_pgrp_tbl_key_xfmr: pGrpKey:", pGrpKey)
    return pGrpKey, nil
}

var DbToYang_bgp_pgrp_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_bgp_pgrp_tbl_key: ", entry_key)

    pgrpKey := strings.Split(entry_key, "|")
    if len(pgrpKey) < 2 {return rmap, nil}

    pgrpName:= pgrpKey[1]

    rmap["peer-group-name"] = pgrpName

    return rmap, nil
}


type _xfmr_bgp_pgrp_state_key struct {
    niName string
    pgrp string
}

func validate_pgrp_state_get (inParams XfmrParams, dbg_log string) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup, _xfmr_bgp_pgrp_state_key, error) {
    var err error
    oper_err := errors.New("Opertational error")
    var pgrp_key _xfmr_bgp_pgrp_state_key
    var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp

    bgp_obj, pgrp_key.niName, err = getBgpRoot (inParams)
    if err != nil {
        log.Errorf ("%s failed !! Error:%s", dbg_log , err);
        return nil, pgrp_key, err
    }

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    pgrp_key.pgrp = pathInfo.Var("peer-group-name")
    log.Info("%s : path:%s; template:%s targetUriPath:%s niName:%s peer group:%s",
              dbg_log, pathInfo.Path, pathInfo.Template, targetUriPath, pgrp_key.niName, pgrp_key.pgrp)

    if pgrp_key.niName == "default" {
       pgrp_key.niName = ""
    }

    pgrps_obj := bgp_obj.PeerGroups
    if pgrps_obj == nil {
        log.Errorf("%s failed !! Error: Peer groups container missing", dbg_log)
        return nil, pgrp_key, oper_err
    }

    pgrp_obj, ok := pgrps_obj.PeerGroup[pgrp_key.pgrp]
    if !ok {
        pgrp_obj,_ = pgrps_obj.NewPeerGroup(pgrp_key.pgrp)
    }
    ygot.BuildEmptyTree(pgrp_obj)
    return pgrp_obj, pgrp_key, err
}

func fill_pgrp_state_info (pgrp_key *_xfmr_bgp_pgrp_state_key, frrPgrpDataValue interface{},
                              pgrp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup) error {
    var err error
    var pMember ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup_MembersState
    pgrp_obj.MembersState = &pMember

    frrPgrpDataJson := frrPgrpDataValue.(map[string]interface{})

    if frrPgrpDataJson == nil {
        log.Info("peer group json Data NIL ")
        return err
    }

    if peerGroupMembers,  ok := frrPgrpDataJson["peerGroupMembers"].(map[string]interface{}) ; ok {
        /* For accessing nbr info from FRR json output, nbr has to to be in native
           format, convert it. The nbr key in the ygot will be still in user given format */
        for pgMem := range peerGroupMembers {
            nativeNbr := pgMem
            util_bgp_get_ui_ifname_from_native_ifname (&pgMem)
            member, ok := pMember.Member[pgMem]
            if !ok {
                member, _ = pMember.NewMember(pgMem)
            }
            if member.State == nil {
                var member_state ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup_MembersState_Member_State
                member.State = &member_state
            }
            ygot.BuildEmptyTree(pgrp_obj)
            member.State.Neighbor = &pgMem
            temp, ok := peerGroupMembers[nativeNbr].(map[string]interface{})
            if  ok {
                if value, ok := temp["peerStatus"].(string); ok {
                    member.State.State = &value
                    log.Infof("peer group member %s status %s", *member.State.Neighbor, value)
                }
                if value, ok := temp["isDynamic"].(bool); ok {
                    member.State.Dynamic = &value
                    log.Infof("peer group member %s Dynamic %d", *member.State.Neighbor, value)
                }
            }
        }
    }

    return err
}

func get_specific_pgrp_state (pgrp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup,
                             pgrp_key *_xfmr_bgp_pgrp_state_key) error {
    var err error
    var vtysh_cmd string
    if pgrp_key.niName == "" {
       vtysh_cmd = "show ip bgp peer-group " + pgrp_key.pgrp + " json"
    } else {
       vtysh_cmd = "show ip bgp vrf " + pgrp_key.niName + " peer-group " + pgrp_key.pgrp + " json"
    }
    pgrpMapJson, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to fetch bgp peer group member state info for niName:%s peer group :%s. Err: %s\n", pgrp_key.niName, pgrp_key.pgrp, cmd_err)
        return cmd_err
    }

    if frrPgrpDataJson, ok := pgrpMapJson[pgrp_key.pgrp].(map[string]interface{}) ; ok {
        err = fill_pgrp_state_info (pgrp_key, frrPgrpDataJson, pgrp_obj)
    }

    return err
}

var DbToYang_bgp_peer_group_mbrs_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error
    cmn_log := "GET: xfmr for BGP Peer Group members state"

    pgrp_obj, pgrp_key, get_err := validate_pgrp_state_get (inParams, cmn_log);
    if get_err != nil {
        log.Info("Peer Group members state get subtree error: ", get_err)
        return get_err
    }

    err = get_specific_pgrp_state (pgrp_obj, &pgrp_key)
    return err;
}

var YangToDb_bgp_pgrp_auth_password_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)
    authmap := make(map[string]db.Value)

    var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp

    bgp_obj, niName, err := getBgpRoot (inParams)
    if err != nil {
        log.Errorf ("BGP root get failed!");
        return res_map, err
    }

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    pgrp := pathInfo.Var("peer-group-name")
    log.Infof("YangToDb_bgp_pgrp_auth_password_xfmr VRF:%s peer group:%s URI:%s", niName, pgrp, targetUriPath)

    pgrps_obj := bgp_obj.PeerGroups
    if pgrps_obj == nil || (pgrps_obj.PeerGroup == nil) {
        log.Errorf("Error: PeerGroups container missing")
        return res_map, err
    }

    pgrp_obj, ok := pgrps_obj.PeerGroup[pgrp]
    if !ok {
        log.Infof("%s Peer group object missing, add new", pgrp)
        return res_map, err
    }
    if (inParams.oper == DELETE) && pgrp_obj.AuthPassword == nil {
        return res_map, nil
    }
    entry_key := niName + "|" + pgrp 
    if pgrp_obj.AuthPassword.Config != nil && pgrp_obj.AuthPassword.Config.Password != nil && (inParams.oper != DELETE){
        auth_password := pgrp_obj.AuthPassword.Config.Password
        encrypted := pgrp_obj.AuthPassword.Config.Encrypted

        encrypted_password := *auth_password
        if encrypted == nil || (encrypted != nil && !*encrypted) {
            cmd := "show bgp encrypt " + *auth_password + " json"
            bgpPgrpPasswordJson, cmd_err := exec_vtysh_cmd (cmd)
            if (cmd_err != nil) {
                log.Errorf ("Failed !! Error:%s", cmd_err);
                return res_map, err
            }
            encrypted_password, ok = bgpPgrpPasswordJson["Encrypted_string"].(string); if !ok {
                return res_map, err
            }
        }
        log.Infof("PeerGroup password:%s encrypted:%s", *auth_password, encrypted_password)
        authmap[entry_key] = db.Value{Field: make(map[string]string)}
        authmap[entry_key].Field["auth_password"] = encrypted_password
    } else if (inParams.oper == DELETE) {
        authmap[entry_key] = db.Value{Field: make(map[string]string)}
        authmap[entry_key].Field["auth_password"] = ""
    }

    res_map["BGP_PEER_GROUP"] = authmap
    return res_map, err
}

var DbToYang_bgp_pgrp_auth_password_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var bgp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp

    bgp_obj, niName, err := getBgpRoot (inParams)
    if err != nil {
        log.Errorf ("BGP root get failed!");
        return err
    }

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    pgrp := pathInfo.Var("peer-group-name")
    log.Infof("DbToYang_bgp_pgrp_auth_password_xfmr VRF:%s Peer group:%s URI:%s", niName, pgrp, targetUriPath)

    pgrps_obj := bgp_obj.PeerGroups
    if pgrps_obj == nil {
        log.Errorf("Error: PeerGroup container missing")
        return err
    }

    pgrp_obj, ok := pgrps_obj.PeerGroup[pgrp]
    if !ok {
        pgrp_obj,_ = pgrps_obj.NewPeerGroup(pgrp)
    }
    ygot.BuildEmptyTree(pgrp_obj)

    
    pgrpCfgTblTs := &db.TableSpec{Name: "BGP_PEER_GROUP"}
    pgrpEntryKey := db.Key{Comp: []string{niName, pgrp}}

    var entryValue db.Value
    if entryValue, err = inParams.dbs[db.ConfigDB].GetEntry(pgrpCfgTblTs, pgrpEntryKey) ; err != nil {
        return err
    }
    if pgrp_obj.AuthPassword == nil {
        var auth ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup_AuthPassword 
        pgrp_obj.AuthPassword = &auth
        ygot.BuildEmptyTree(pgrp_obj.AuthPassword)
    }

    if pgrp_obj.AuthPassword.Config == nil {
        var auth_config ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup_AuthPassword_Config
        pgrp_obj.AuthPassword.Config = &auth_config
        ygot.BuildEmptyTree(pgrp_obj.AuthPassword.Config)
    }

    if pgrp_obj.AuthPassword.State == nil {
        var auth_state ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Bgp_PeerGroups_PeerGroup_AuthPassword_State
        pgrp_obj.AuthPassword.State = &auth_state
        ygot.BuildEmptyTree(pgrp_obj.AuthPassword.State)
    }

    if value, ok := entryValue.Field["auth_password"] ; ok {
        pgrp_obj.AuthPassword.Config.Password = &value
        pgrp_obj.AuthPassword.State.Password = &value
        encrypted := true
        pgrp_obj.AuthPassword.Config.Encrypted = &encrypted
        pgrp_obj.AuthPassword.State.Encrypted = &encrypted
    }

    return err
}


