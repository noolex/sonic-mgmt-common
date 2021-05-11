////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Dell, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "strconv"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    log "github.com/golang/glog"
    "github.com/openconfig/ygot/ygot"
)

func init () {
    XlateFuncBind("DbToYang_lacp_get_xfmr", DbToYang_lacp_get_xfmr)
    XlateFuncBind("Subscribe_lacp_get_xfmr", Subscribe_lacp_get_xfmr)
}

func getLacpRoot (s *ygot.GoStruct) *ocbinds.OpenconfigLacp_Lacp {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Lacp
}

func fillLacpState(inParams XfmrParams, ifKey string, state *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_State) error {

    lagTbl := &db.TableSpec{Name: "LAG_TABLE"}
    stateDb := inParams.dbs[db.StateDB]

    // Fetch the LAG_TABLE entry for a given portchannel from STATE_DB
    dbEntry, err := stateDb.GetEntry(lagTbl, db.Key{Comp: []string{ifKey}})
    if err != nil {
        errStr := "Failed to Get PortChannel details"
        log.Info(errStr)
        return errors.New(errStr)
    }

    if runner_name, ok := dbEntry.Field["setup.runner_name"]; ok {
        if runner_name != "lacp" {
            errStr := "LAG not in LACP mode"
            log.Infof(errStr)
            return tlerr.InvalidArgsError{Format:errStr}
        }
    }

    if val, ok := dbEntry.Field["runner.sys_prio"]; ok {
        sys_prio_tmp,_ := strconv.Atoi(val)
        sys_prio  := uint16(sys_prio_tmp)
        state.SystemPriority = &sys_prio
    }

    var fast_rate bool = false
    if val, ok := dbEntry.Field["runner.fast_rate"]; ok {
        if val == "enabled" {
            fast_rate = true
        }
    }
    if fast_rate {
        state.Interval = ocbinds.OpenconfigLacp_LacpPeriodType_FAST
    } else {
        state.Interval = ocbinds.OpenconfigLacp_LacpPeriodType_SLOW
    }

    val, ok := dbEntry.Field["runner.active"]
    var active bool = false
    if ok {
        if val == "true" {
            active = true
        }
    }
    if active {
        state.LacpMode = ocbinds.OpenconfigLacp_LacpActivityType_ACTIVE
    } else {
        state.LacpMode = ocbinds.OpenconfigLacp_LacpActivityType_PASSIVE
    }

    SystemIdMac :=  dbEntry.Field["team_device.ifinfo.dev_addr"]
    state.SystemIdMac = &SystemIdMac

    return nil
}

func _getSelectedStatus(inParams XfmrParams, lag string, member string, selected *bool) error {
    var memberKey string = lag+":"+member
    lagTblTs := &db.TableSpec{Name: "LAG_MEMBER_TABLE"}
    appDb := inParams.dbs[db.ApplDB]
    dbEntry, err := appDb.GetEntry(lagTblTs, db.Key{Comp: []string{memberKey}})

    if err != nil {
        errStr := "Failed to Get PortChannel Member details"
        log.Info(errStr)
        return errors.New(errStr)
    }

    *selected = false  // Default
    if val, ok := dbEntry.Field["status"]; ok {
        if val == "enabled" {
            *selected = true
        }
    }
    return nil
}

func _fillLacpMemberHelper(inParams XfmrParams, lag string, ifKey string, lacpMemberObj *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members_Member) error {

    lagMemberTbl := &db.TableSpec{Name: "LAG_MEMBER_TABLE"}
    appDb := inParams.dbs[db.StateDB]

    key := lag + "|" + ifKey
    // Fetch the LAG member details from LAG_MEMBER_TABLE of STATE_DB
    dbEntry, err := appDb.GetEntry(lagMemberTbl, db.Key{Comp: []string{key}})
    if err != nil {
        errStr := "Failed to Get PortChannel Member details"
        log.Info(errStr)
        return errors.New(errStr)
    }

    var selected bool = false
    _getSelectedStatus(inParams, lag, ifKey, &selected)
    lacpMemberObj.State.Selected = &selected

    var pport_num uint16 = 0
    if port_num_str, ok := dbEntry.Field["runner.actor_lacpdu_info.port"]; ok {
        port_num,_ := strconv.Atoi(port_num_str)
        pport_num = uint16(port_num)
        lacpMemberObj.State.PortNum = &pport_num
    }

    system_id := dbEntry.Field["runner.actor_lacpdu_info.system"]
    lacpMemberObj.State.SystemId = &system_id

    var ooper_key uint16 = 0
    if oper_key_str, ok := dbEntry.Field["runner.actor_lacpdu_info.key"]; ok {
        oper_key,_ := strconv.Atoi(oper_key_str)
        ooper_key = uint16(oper_key)
        lacpMemberObj.State.OperKey = &ooper_key
    }

    var ppartner_num uint16= 0
    if partner_port_num_str, ok := dbEntry.Field["runner.partner_lacpdu_info.port"]; ok {
        partner_num,_ := strconv.Atoi(partner_port_num_str)
        ppartner_num = uint16(partner_num)
        lacpMemberObj.State.PartnerPortNum = &ppartner_num
    }

    partner_system_id := dbEntry.Field["runner.partner_lacpdu_info.system"]
    lacpMemberObj.State.PartnerId = &partner_system_id

    var ppartner_key uint16= 0
    if partner_oper_key_str, ok := dbEntry.Field["runner.partner_lacpdu_info.key"]; ok {
        partner_key,_ := strconv.Atoi(partner_oper_key_str)
        ppartner_key = uint16(partner_key)
        lacpMemberObj.State.PartnerKey = &ppartner_key
    }

    return nil
}

func fillLacpMember(inParams XfmrParams, lag string, ifMemKey string, lacpMemberObj *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members_Member) error {

    // Call the helper routine to featch all the needed info
    err := _fillLacpMemberHelper(inParams, lag, ifMemKey, lacpMemberObj)
    return err
}

func fillLacpMembers(inParams XfmrParams, lag string, members *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members) error {
    var lacpMemberObj *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members_Member
    var err error

    if members == nil {
        ygot.BuildEmptyTree(members)
    }

    lagMemKeys, err := inParams.dbs[db.StateDB].GetKeysByPattern(&db.TableSpec{Name: "LAG_MEMBER_TABLE"},  lag + "|*")
    if err != nil {
        return err
    }

    for i := range lagMemKeys {
        ifName_str := lagMemKeys[i].Get(1)

        ifName := utils.GetUINameFromNativeName(&ifName_str)

        lacpMemberObj, err = members.NewMember(*ifName)
        if err != nil {
            log.Error("Creation of portchannel member subtree failed")
            return err
        }

        ygot.BuildEmptyTree(lacpMemberObj)
        err = _fillLacpMemberHelper(inParams, lag, *ifName, lacpMemberObj)
    }

    return err
}

func populateLacpData(inParams XfmrParams, ifKey string, state *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_State,
                                    members *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members) error {
    e := fillLacpState(inParams, ifKey, state)
    if e != nil {
        log.Error("Failure in filling LACP state data ")
        return e
    }

    er := fillLacpMembers(inParams, ifKey, members)
    if er != nil {
        log.Error("Failure in filling LACP members data ")
        return er
    }

    return nil
}

func populateLacpMembers(inParams XfmrParams, ifKey string, members *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members) error {

    e := fillLacpMembers(inParams, ifKey, members)
    if e != nil {
        log.Errorf("Failure in filling LACP members data %s\n", e)
        return e
    }

    return nil
}

func populateLacpMember(inParams XfmrParams, ifPoKey string, ifMemKey string, lacpMemberObj *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members_Member) error {

    e := fillLacpMember(inParams, ifPoKey, ifMemKey, lacpMemberObj)
    if e != nil {
        log.Errorf("Failure in filling LACP member data %s\n", e)
        return e
    }

    return nil
}

var DbToYang_lacp_get_xfmr  SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    lacpIntfsObj := getLacpRoot(inParams.ygRoot)
    var members *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members
    var member *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface_Members_Member
    var lacpintfObj *ocbinds.OpenconfigLacp_Lacp_Interfaces_Interface
    var ok bool

    pathInfo := NewPathInfo(inParams.uri)
    ifKey := pathInfo.Var("name")
    ifMemKey := pathInfo.Var("interface")

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Warningf("Get Yang Path from URI failed")
        return err
    }

    log.Infof("Received GET for path: %s; template: %s vars: %v targetUriPath: %s ifKey: %s", pathInfo.Path, pathInfo.Template, pathInfo.Vars, targetUriPath, ifKey)

    if isSubtreeRequest(targetUriPath, "/openconfig-lacp:lacp/interfaces/interface/members/member") {
        if lacpintfObj, ok = lacpIntfsObj.Interfaces.Interface[ifKey]; !ok {
            errStr := "PortChannel Instance doesn't exist"
            log.Info(errStr)
            return errors.New(errStr)
        }

        members = lacpintfObj.Members
        if members != nil && ifMemKey != "" {
            ifName := utils.GetNativeNameFromUIName(&ifMemKey)

            if member, ok = members.Member[ifMemKey]; !ok {
                errStr := "PortChannel Member Instance doesn't exist"
                log.Info(errStr)
                return errors.New(errStr)
            }
            ygot.BuildEmptyTree(member)
            return populateLacpMember(inParams, ifKey, *ifName, member)
        }
    } else if isSubtreeRequest(targetUriPath, "/openconfig-lacp:lacp/interfaces/interface/members") {
        if lacpintfObj, ok = lacpIntfsObj.Interfaces.Interface[ifKey]; !ok {
            errStr := "PortChannel Instance doesn't exist"
            log.Info(errStr)
            return errors.New(errStr)
        }

        members = lacpintfObj.Members
        if members != nil && ifKey != "" {
            return populateLacpMembers(inParams, ifKey, members)
        }
    } else if isSubtreeRequest(targetUriPath, "/openconfig-lacp:lacp/interfaces/interface") {

        /* Request for a specific portchannel */
        if lacpIntfsObj.Interfaces.Interface != nil && len(lacpIntfsObj.Interfaces.Interface) > 0 && ifKey != "" {
            lacpintfObj, ok = lacpIntfsObj.Interfaces.Interface[ifKey]
            if !ok {
                lacpintfObj, _ = lacpIntfsObj.Interfaces.NewInterface(ifKey)
            }
             ygot.BuildEmptyTree(lacpintfObj)

             return populateLacpData(inParams, ifKey, lacpintfObj.State, lacpintfObj.Members)
        }
    } else if isSubtreeRequest(targetUriPath, "/openconfig-lacp:lacp/interfaces") {

        ygot.BuildEmptyTree(lacpIntfsObj)

        keys, err := inParams.dbs[db.ApplDB].GetKeysByPattern(&db.TableSpec{Name: "LAG_TABLE"}, "PortChannel*")
        if err != nil {
            log.Error("App-DB get for list of portchannels failed!")
            return err
        }

        for _, key := range keys {
           ifKey := key.Get(0)

           lacpintfObj, ok = lacpIntfsObj.Interfaces.Interface[ifKey]
           if !ok {
              lacpintfObj, _ = lacpIntfsObj.Interfaces.NewInterface(ifKey)
           }
           ygot.BuildEmptyTree(lacpintfObj)

           populateLacpData(inParams, ifKey, lacpintfObj.State, lacpintfObj.Members)
        }
    } else {
        log.Info("Unsupported Path");
    }

    return nil
}

var Subscribe_lacp_get_xfmr SubTreeXfmrSubscribe = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error)  {

     var err error
     var result XfmrSubscOutParams

     pathInfo := NewPathInfo(inParams.uri)
     targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
     log.Infof("Subscribe_lacp_get_xfmr:%s; template:%s targetUriPath:%s", pathInfo.Path, pathInfo.Template, targetUriPath)

     ifName := pathInfo.Var("name")
     log.Infof("ifName %v ", ifName)
     result.dbDataMap = make(RedisDbMap)

     log.Infof("Subscribe_lacp_get_xfmr path:%s; template:%s targetUriPath:%s key:%s tbl:LAG_TABLE", pathInfo.Path, pathInfo.Template, targetUriPath, ifName)
     result.dbDataMap = RedisDbMap{db.ApplDB:{"LAG_TABLE":{ifName:{}}}}

     return result, err
}

