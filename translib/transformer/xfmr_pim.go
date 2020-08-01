package transformer

import (
    "errors"
    "strings"
    "strconv"
    "encoding/json"
    log "github.com/golang/glog"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init () {
    XlateFuncBind("YangToDb_pim_gbl_tbl_key_xfmr", YangToDb_pim_gbl_tbl_key_xfmr)
    XlateFuncBind("DbToYang_pim_intf_tbl_key_xfmr", DbToYang_pim_intf_tbl_key_xfmr)
    XlateFuncBind("YangToDb_pim_intf_tbl_key_xfmr", YangToDb_pim_intf_tbl_key_xfmr)
    XlateFuncBind("YangToDb_pim_intf_id_fld_xfmr", YangToDb_pim_intf_id_fld_xfmr)
    XlateFuncBind("DbToYang_pim_intf_id_fld_xfmr", DbToYang_pim_intf_id_fld_xfmr)
    XlateFuncBind("YangToDb_pim_intf_mode_fld_xfmr", YangToDb_pim_intf_mode_fld_xfmr)
    XlateFuncBind("DbToYang_pim_intf_mode_fld_xfmr", DbToYang_pim_intf_mode_fld_xfmr)
    XlateFuncBind("DbToYang_pim_intf_state_xfmr", DbToYang_pim_intf_state_xfmr)
    XlateFuncBind("DbToYang_pim_nbrs_state_xfmr", DbToYang_pim_nbrs_state_xfmr)
    XlateFuncBind("DbToYang_pim_tib_state_xfmr", DbToYang_pim_tib_state_xfmr)
    XlateFuncBind("rpc_show_pim", rpc_show_pim)
    XlateFuncBind("rpc_clear_pim", rpc_clear_pim)
}

func pim_exec_vtysh_cmd (vtysh_cmd string) (map[string]interface{}, error) {
    var err error
    operErr := errors.New("Operational error")

    pimOutputJson, cmdErr := exec_vtysh_cmd (vtysh_cmd)
    if (cmdErr != nil) {
        log.Errorf ("PIM: VTYSH-cmd : \"%s\" execution failed with Error:%s", vtysh_cmd, cmdErr);
        return nil, operErr
    }

    if outError, ok := pimOutputJson["warning"] ; ok {
        log.Errorf ("PIM: VTYSH-cmd : \"%s\" execution failed with error-msg ==> %s", vtysh_cmd, outError);
        return nil, operErr
    }

    return pimOutputJson, err
}

func validatePimRoot (inParams XfmrParams) (string, error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    niName := pathInfo.Var("name")
    pimId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")

    if len(pathInfo.Vars) <  3 {
        return "", errors.New("Invalid Key length")
    }

    if len(niName) == 0 {
        return "", errors.New("vrf name is missing")
    }

    if !strings.Contains(pimId,"PIM") {
        return "", errors.New("PIM ID is missing")
    }

    if len(protoName) == 0 {
        return "", errors.New("Protocol Name is missing")
    }

    return niName, err
}

func getPimRoot (inParams XfmrParams) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim, string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    niName := pathInfo.Var("name")
    pimId := pathInfo.Var("identifier")
    protoName := pathInfo.Var("name#2")
    var err error

    if len(pathInfo.Vars) <  3 {
        return nil, "", errors.New("Invalid Key length")
    }

    if len(niName) == 0 {
        return nil, "", errors.New("vrf name is missing")
    }
    if !strings.Contains(pimId,"PIM") {
        return nil, "", errors.New("PIM ID is missing")
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
    protoKey.Identifier = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_PIM
    protoKey.Name = protoName
    protoInstObj := netInstObj.Protocols.Protocol[protoKey]
    if protoInstObj == nil {
        return nil, "", errors.New("Network-instance PIM-Protocol obj missing")
    }

    if protoInstObj.Pim == nil {
        var _pimObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim
        protoInstObj.Pim = &_pimObj
    }

    ygot.BuildEmptyTree (protoInstObj.Pim)
    return protoInstObj.Pim, niName, err
}

func util_pim_get_native_ifname_from_ui_ifname (pUiIfname *string, pNativeIfname *string) {
    if pUiIfname == nil || pNativeIfname == nil {return}
    if len(*pUiIfname) == 0 {return}
    *pNativeIfname = *pUiIfname
    _pNativeIfname := utils.GetNativeNameFromUIName(pUiIfname)
    if _pNativeIfname != nil && len(*_pNativeIfname) != 0 {
        *pNativeIfname = *_pNativeIfname
    }
}

func util_pim_get_ui_ifname_from_native_ifname (pNativeIfname *string, pUiIfname *string) {
    if pUiIfname == nil || pNativeIfname == nil {return}
    if len(*pNativeIfname) == 0 {return}
    *pUiIfname = *pNativeIfname
    _pUiIfname := utils.GetUINameFromNativeName(pNativeIfname)
    if _pUiIfname != nil && len(*_pUiIfname) != 0 {
        *pUiIfname = *_pUiIfname
    }
}

func checkPimCfgExistOnIntf(d *db.DB, ifName string) (bool) {
    pimIntfCfgTblTs := &db.TableSpec{Name: "PIM_INTERFACE"}
    keys, tblErr := d.GetKeysPattern(pimIntfCfgTblTs, db.Key {[]string{"*", "*", ifName}})
    if ((tblErr == nil) && (len(keys) > 0)) {
        log.Info ("checkPimCfgExistOnIntf for ifName:", ifName, " ==> Keys : ",keys)
        return true
    }

    return false
}

var YangToDb_pim_gbl_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    niName, err := validatePimRoot (inParams); if err != nil {
        return "", err
    }

    retKey := (niName + "|" + "ipv4")
    log.Info("YangToDb_pim_gbl_tbl_key_xfmr : URI:", inParams.uri, " VRF:", niName, " Return-Key:", retKey)

    return retKey, err
}

var YangToDb_pim_intf_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    niName, err := validatePimRoot (inParams); if err != nil {
        return "", err
    }

    pathInfo := NewPathInfo(inParams.uri)
    uiIntfId := pathInfo.Var("interface-id")
    if (len(uiIntfId) == 0) {
        return "", errors.New("interface name is missing")
    }

    retKey := (niName + "|" + "ipv4" + "|" + uiIntfId)
    log.Info("YangToDb_pim_intf_tbl_key_xfmr : URI:", inParams.uri, " VRF:", niName, " uiIntfId:", uiIntfId, " Return-Key:", retKey)

    return retKey, err
}

var DbToYang_pim_intf_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    log.Info("DbToYang_pim_intf_tbl_key_xfmr: URI:", inParams.uri, " Key:", inParams.key)

    intfKey := strings.Split(inParams.key, "|")
    if len(intfKey) < 3 {return rmap, nil}

    rmap["interface-id"] = intfKey[2]
    return rmap, nil
}

var YangToDb_pim_intf_id_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    log.Info("YangToDb_pim_intf_id_fld_xfmr : URI:", inParams.uri, " key:", inParams.key)
    res_map := make(map[string]string)
    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_pim_intf_id_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    log.Info("DbToYang_pim_intf_id_fld_xfmr: URI:", inParams.uri, " Key:", inParams.key)

    intfKey := strings.Split(inParams.key, "|")
    if len(intfKey) < 3 {return rmap, nil}

    rmap["interface-id"] = intfKey[2]
    return rmap, nil
}

var YangToDb_pim_intf_mode_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    rmap := make(map[string]string)

    if (inParams.param == nil) || (inParams.oper == DELETE) {
        rmap["mode"] = ""
        return rmap, nil
    }

    inParams_mode := inParams.param.(ocbinds.E_OpenconfigPimTypes_PIM_MODE)
    log.Info("YangToDb_pim_intf_mode_fld_xfmr : URI:", inParams.uri, " Mode:", inParams_mode)

    switch inParams_mode {
        case ocbinds.OpenconfigPimTypes_PIM_MODE_PIM_MODE_SPARSE:
            rmap["mode"] = "sm"
        default:
            return rmap, tlerr.InvalidArgs("Mode not supported")
    }

    return rmap, nil
}

var DbToYang_pim_intf_mode_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    pTbl := data["PIM_INTERFACE"]
    if _, ok := pTbl[inParams.key]; !ok {
        return result, err
    }

    log.Info("DbToYang_pim_intf_mode_fld_xfmr: Key: ",inParams.key)

    pIntfKey := pTbl[inParams.key]
    db_mode, ok := pIntfKey.Field["mode"] ; if ok {
        switch db_mode {
            case "sm":
                result["mode"] = "PIM_MODE_SPARSE"
        }
    }

    return result, err
}

type _xfmr_pim_intf_state_key struct {
    niName string
    intfId string
}

func get_spec_pim_intf_cfg_tbl_entry (cfgDb *db.DB, key *_xfmr_pim_intf_state_key) (map[string]string, error) {
    var err error

    pimIntfCfgTblTs := &db.TableSpec{Name: "PIM_INTERFACE"}
    pimIntfEntryKey := db.Key{Comp: []string{key.niName, "ipv4", key.intfId}}

    var entryValue db.Value
    if entryValue, err = cfgDb.GetEntry(pimIntfCfgTblTs, pimIntfEntryKey) ; err != nil {
        return nil, err
    }

    return entryValue.Field, err
}

func fill_pim_intf_cfg_state_info (inParams XfmrParams, intfKey _xfmr_pim_intf_state_key,
                                   intfStateObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces_Interface_State) bool {
    if cfgDbEntry, cfgDbGetErr := get_spec_pim_intf_cfg_tbl_entry (inParams.dbs[db.ConfigDB], &intfKey) ; cfgDbGetErr == nil {
        if value, ok := cfgDbEntry["bfd-enabled"] ; ok {
            _bfdEnabled, _ := strconv.ParseBool(value)
            intfStateObj.BfdEnabled = &_bfdEnabled
        }

        if value, ok := cfgDbEntry["mode"] ; ok {
            switch value {
                case "sm":
                    intfStateObj.Mode = ocbinds.OpenconfigPimTypes_PIM_MODE_PIM_MODE_SPARSE
            }
        }
    }

    return true
}

func fill_pim_intf_state_info (inParams XfmrParams, intfKey _xfmr_pim_intf_state_key, intfDtlData map[string]interface{},
                               intfStateObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces_Interface_State) bool {
    if value, ok := intfDtlData["state"] ; ok {
        _enabled := false
        switch value {
            case "up":
                _enabled = true
        }
        intfStateObj.Enabled = &_enabled
    }

    if value, ok := intfDtlData["drAddress"] ; ok {
        _drAddress := value.(string)
        intfStateObj.DrAddress = &_drAddress
    }

    if value, ok := intfDtlData["address"] ; ok {
        _localAddress := value.(string)
        intfStateObj.LocalAddress = &_localAddress
    }

    var _nbrsCount uint16
    if value, ok := intfDtlData["neighbors"] ; ok {
        _nbrsCount = uint16(len(value.(map[string]interface{})))
    }
    intfStateObj.NbrsCount = &_nbrsCount

    if value, ok := intfDtlData["drPriority"] ; ok {
        _drPriority := uint32(value.(float64))
        intfStateObj.DrPriority = &_drPriority
    }

    if value, ok := intfDtlData["helloPeriod"] ; ok {
        _helloInterval := uint8(value.(float64))
        intfStateObj.HelloInterval = &_helloInterval
    }

    return true
}

var DbToYang_pim_intf_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error
    operErr := errors.New("Opertational error")
    cmnLog := "GET: xfmr for PIM-Interface-State"

    pimObj, niName, getErr := getPimRoot (inParams)
    if getErr != nil {
        log.Errorf ("%s failed !! Error:%s", cmnLog, getErr);
        return operErr
    }

    pathInfo := NewPathInfo(inParams.uri)
    uiIntfIdKey := pathInfo.Var("interface-id")
    if (uiIntfIdKey == "") {
        log.Errorf ("%s failed !! Mandatory param Interface-id is missing !!", cmnLog)
        return operErr
    }
    var nativeIntfIdKey string
    util_pim_get_native_ifname_from_ui_ifname (&uiIntfIdKey, &nativeIntfIdKey)

    log.Info("DbToYang_pim_intf_state_xfmr: ", cmnLog, " ==> URI: ",inParams.uri, " niName:", niName,
             " uiIntfIdKey:", uiIntfIdKey, " nativeIntfIdKey:", nativeIntfIdKey)

    intfsObj := pimObj.Interfaces ; if intfsObj == nil {
        var _intfsObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces
        pimObj.Interfaces = &_intfsObj
        intfsObj = pimObj.Interfaces
        ygot.BuildEmptyTree(intfsObj)
    }

    cmd := "show ip pim vrf " + niName + " interface detail json"
    pimIntfDtlOutputJson, cmdErr := pim_exec_vtysh_cmd (cmd)
    if (cmdErr != nil) {
        log.Errorf ("%s failed !! Error:%s", cmnLog, cmdErr)
        return operErr
    }

    intfObj, ok := intfsObj.Interface[uiIntfIdKey] ; if !ok {
        intfObj,_ = intfsObj.NewInterface(uiIntfIdKey)
        ygot.BuildEmptyTree(intfObj)
    }

    intfStateObj := intfObj.State ; if intfStateObj == nil {
        var _intfStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces_Interface_State
        intfObj.State = &_intfStateObj
        intfStateObj = intfObj.State
        ygot.BuildEmptyTree(intfStateObj)
    }
    intfStateObj.InterfaceId = &uiIntfIdKey

    var intfKey _xfmr_pim_intf_state_key
    intfKey.niName = niName
    intfKey.intfId = nativeIntfIdKey

    fill_pim_intf_cfg_state_info (inParams, intfKey, intfStateObj)
    for intfId := range pimIntfDtlOutputJson {
        if (nativeIntfIdKey != "" && (intfId != nativeIntfIdKey)) {continue}
        intfDtlData, ok := pimIntfDtlOutputJson[intfId].(map[string]interface{}) ; if !ok {continue}
        fill_pim_intf_state_info (inParams, intfKey, intfDtlData, intfStateObj)
    }

    return err
}

type _xfmr_pim_nbr_state_key struct {
    niName string
    intfId string
    nbrAddr string
}

func fill_pim_nbr_state_info (inParams XfmrParams, nbrKey _xfmr_pim_nbr_state_key, nbrData map[string]interface{}, intfData map[string]interface{},
                              nbrStateObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces_Interface_Neighbors_Neighbor_State) bool {

    nbrStateObj.NeighborAddress = &nbrKey.nbrAddr

    if value, ok := intfData["drAddress"] ; ok {
        _drAddress := value.(string)
        nbrStateObj.DrAddress = &_drAddress
    }

    if value, ok := nbrData["drPriority"] ; ok {
        _drPriority := uint32(value.(float64))
        nbrStateObj.DrPriority = &_drPriority
    }

    if value, ok := nbrData["upTimeEpoch"] ; ok {
        _neighborEstablished := uint64(value.(float64))
        nbrStateObj.NeighborEstablished = &_neighborEstablished
    }

    if value, ok := nbrData["holdTimeEpoch"] ; ok {
        _neighborExpires := uint64(value.(float64))
        nbrStateObj.NeighborExpires = &_neighborExpires
    }

    intfKey := _xfmr_pim_intf_state_key {niName:nbrKey.niName, intfId:nbrKey.intfId}
    if cfgDbEntry, cfgDbGetErr := get_spec_pim_intf_cfg_tbl_entry (inParams.dbs[db.ConfigDB], &intfKey) ; cfgDbGetErr == nil {
        if value, ok := cfgDbEntry["mode"] ; ok {
            switch value {
                case "sm":
                    nbrStateObj.Mode = ocbinds.OpenconfigPimTypes_PIM_MODE_PIM_MODE_SPARSE
            }
        }
    }

    return true
}

var DbToYang_pim_nbrs_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error
    operErr := errors.New("Opertational error")
    cmnLog := "GET: xfmr for PIM-Neighbors-State"

    pimObj, niName, getErr := getPimRoot (inParams)
    if getErr != nil {
        log.Errorf ("%s failed !! Error:%s", cmnLog, getErr);
        return operErr
    }

    pathInfo := NewPathInfo(inParams.uri)
    uiIntfIdKey := pathInfo.Var("interface-id")
    if (uiIntfIdKey == "") {
        log.Errorf ("%s failed !! Mandatory param Interface-id is missing !!", cmnLog)
        return operErr
    }
    var nativeIntfIdKey string
    util_pim_get_native_ifname_from_ui_ifname (&uiIntfIdKey, &nativeIntfIdKey)
    nbrAddrKey := pathInfo.Var("neighbor-address")

    log.Info("DbToYang_pim_nbrs_state_xfmr: ", cmnLog, " ==> URI: ",inParams.uri, " niName:", niName,
             " uiIntfIdKey:", uiIntfIdKey, " nativeIntfIdKey:", nativeIntfIdKey, " nbrAddrKey:", nbrAddrKey)

    cmd := "show ip pim vrf " + niName + " interface " + nativeIntfIdKey + " json"
    pimIntfOutputJson, cmdErr := pim_exec_vtysh_cmd (cmd)
    if (cmdErr != nil) {
        log.Errorf ("%s failed !! Error:%s", cmnLog, cmdErr);
        return operErr
    }
    intfData, ok := pimIntfOutputJson[nativeIntfIdKey].(map[string]interface{}) ; if !ok {
        log.Errorf ("%s failed !! Failed to fetch PIM-interface:%s specific details from FRR !!", cmnLog, nativeIntfIdKey);
        return operErr
    }

    cmd = "show ip pim vrf " + niName + " neighbor json"
    pimNbrOutputJson, cmdErr := pim_exec_vtysh_cmd (cmd)
    if (cmdErr != nil) {
        log.Errorf ("%s failed !! Error:%s", cmnLog, cmdErr);
        return operErr
    }

    intfsObj := pimObj.Interfaces ; if intfsObj == nil {
        var _intfsObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces
        pimObj.Interfaces = &_intfsObj
        intfsObj = pimObj.Interfaces
        ygot.BuildEmptyTree(intfsObj)
    }

    var nbrKey _xfmr_pim_nbr_state_key
    nbrKey.niName = niName
    nbrKey.intfId = nativeIntfIdKey

    for intfId := range pimNbrOutputJson {
        if (intfId != nativeIntfIdKey) {continue}
        intfNbrData, ok := pimNbrOutputJson[intfId].(map[string]interface{}) ; if !ok {continue}

        for nbrAddr := range intfNbrData {
            nbrData, ok := intfNbrData[nbrAddr].(map[string]interface{}) ; if !ok {continue}
            if ((nbrAddrKey != "") && (nbrAddr != nbrAddrKey)) {continue}

            var _uiIntfId string
            util_pim_get_ui_ifname_from_native_ifname (&intfId, &_uiIntfId)
            intfObj, ok := intfsObj.Interface[_uiIntfId] ; if !ok {
                intfObj,_ = intfsObj.NewInterface(_uiIntfId)
                ygot.BuildEmptyTree(intfObj)
            }

            nbrsObj := intfObj.Neighbors ; if nbrsObj == nil {
                var _nbrsObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces_Interface_Neighbors
                intfObj.Neighbors = &_nbrsObj
                nbrsObj = intfObj.Neighbors
                ygot.BuildEmptyTree(nbrsObj)
            }

            nbrObj, ok := nbrsObj.Neighbor[nbrAddr] ; if !ok {
                nbrObj,_ = nbrsObj.NewNeighbor(nbrAddr)
                ygot.BuildEmptyTree(nbrObj)
            }

            nbrStateObj := nbrObj.State ; if nbrStateObj == nil {
                var _nbrStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces_Interface_Neighbors_Neighbor_State
                nbrObj.State = &_nbrStateObj
                nbrStateObj = nbrObj.State
                ygot.BuildEmptyTree(nbrStateObj)
            }

            nbrKey.nbrAddr = nbrAddr

            fill_pim_nbr_state_info (inParams, nbrKey, nbrData, intfData, nbrStateObj)
        }
    }

    return err
}

type _xfmr_pim_tib_state_key struct {
    niName string
    grpAddr string
    srcAddr string
    routeType ocbinds.E_OpenconfigPimExt_RouteType
    oifKey string
}

func fill_pim_tib_mroute_state_info (inParams XfmrParams, tibKey _xfmr_pim_tib_state_key, srcAddrData map[string]interface{},
                                     srcEntryStateObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State) bool {
    srcEntryStateObj.SourceAddress = &tibKey.srcAddr
    srcEntryStateObj.RouteType = tibKey.routeType

    if value, ok := srcAddrData["upTimeEpoch"] ; ok {
        _uptime := uint64(value.(float64))
        srcEntryStateObj.Uptime = &_uptime
    }

    if value, ok := srcAddrData["expireEpoch"] ; ok {
        _expiry := uint64(value.(float64))
        srcEntryStateObj.Expiry = &_expiry
    }

    if value, ok := srcAddrData["flags"] ; ok {
        _flags := value.(string)
        srcEntryStateObj.Flags = &_flags
    }

    if iilData, ok := srcAddrData["iil"].(map[string]interface{}) ; ok {
        for iif := range iilData {
            iifData, ok := iilData[iif].(map[string]interface{}) ; if !ok {continue}

            var _uiIncomingIntfId string
            util_pim_get_ui_ifname_from_native_ifname (&iif, &_uiIncomingIntfId)
            srcEntryStateObj.IncomingInterface = &_uiIncomingIntfId

            rpfInfoObj := srcEntryStateObj.RpfInfo ; if rpfInfoObj == nil {
                var _rpfInfoObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State_RpfInfo
                srcEntryStateObj.RpfInfo = &_rpfInfoObj
                rpfInfoObj = srcEntryStateObj.RpfInfo
                ygot.BuildEmptyTree(rpfInfoObj)
            }

            rpfInfoStateObj := rpfInfoObj.State ; if rpfInfoStateObj == nil {
                var _rpfInfoStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State_RpfInfo_State
                rpfInfoObj.State = &_rpfInfoStateObj
                rpfInfoStateObj = rpfInfoObj.State
                ygot.BuildEmptyTree(rpfInfoStateObj)
            }

            if value, ok := iifData["RPF Neighbor"] ; ok {
                _rpfNeighborAddress := value.(string)
                rpfInfoStateObj.RpfNeighborAddress = &_rpfNeighborAddress
            }

            if value, ok := iifData["RPF Metric"] ; ok {
                _metric := uint32(value.(float64))
                rpfInfoStateObj.Metric = &_metric
            }

            if value, ok := iifData["RPF Preference"] ; ok {
                _preference := uint32(value.(float64))
                rpfInfoStateObj.Preference = &_preference
            }

            if oilData, ok := iifData["oil"].(map[string]interface{}) ; ok {
                var nativeOifKey string
                util_pim_get_native_ifname_from_ui_ifname (&tibKey.oifKey, &nativeOifKey)

                for oif := range oilData {
                    if ((nativeOifKey != "") && (oif != nativeOifKey)) {continue}
                    oifData, ok := oilData[oif].(map[string]interface{}) ; if !ok {continue}

                    oilInfoEntries := srcEntryStateObj.OilInfoEntries ; if oilInfoEntries == nil {
                        var _oilInfoEntries ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State_OilInfoEntries
                        srcEntryStateObj.OilInfoEntries = &_oilInfoEntries
                        oilInfoEntries = srcEntryStateObj.OilInfoEntries
                        ygot.BuildEmptyTree(oilInfoEntries)
                    }

                    var _uiOifId string
                    util_pim_get_ui_ifname_from_native_ifname (&oif, &_uiOifId)
                    OifInfoObj, ok := oilInfoEntries.OilInfoEntry[_uiOifId] ; if !ok {
                        OifInfoObj,_ = oilInfoEntries.NewOilInfoEntry(_uiOifId)
                        ygot.BuildEmptyTree(OifInfoObj)
                    }

                    oilInfoStateObj := OifInfoObj.State ; if oilInfoStateObj == nil {
                        var _oilInfoStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State_OilInfoEntries_OilInfoEntry_State
                        OifInfoObj.State = &_oilInfoStateObj
                        oilInfoStateObj = OifInfoObj.State
                        ygot.BuildEmptyTree(oilInfoStateObj)
                    }
                    oilInfoStateObj.OutgoingInterface = &_uiOifId

                    if value, ok := oifData["upTimeEpoch"] ; ok {
                        _uptime := uint64(value.(float64))
                        oilInfoStateObj.Uptime = &_uptime
                    }

                    if value, ok := oifData["expireEpoch"] ; ok {
                        _expiry := uint64(value.(float64))
                        oilInfoStateObj.Expiry = &_expiry
                    }
                }
            }
        }
	}

    return true
}

var DbToYang_pim_tib_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error
    operErr := errors.New("Opertational error")
    cmnLog := "GET: xfmr for PIM-TIB-State"

    pimObj, niName, getErr := getPimRoot (inParams)
    if getErr != nil {
        log.Errorf ("%s failed !! Error:%s", cmnLog, getErr);
        return operErr
    }

    pathInfo := NewPathInfo(inParams.uri)
    grpAddrKey := pathInfo.Var("group-address")
    srcAddrKey := pathInfo.Var("source-address")
    routeTypeKey := pathInfo.Var("route-type")
    oifKey := pathInfo.Var("outgoing-interface")

    log.Info("DbToYang_pim_tib_state_xfmr: ", cmnLog, " ==> URI: ",inParams.uri, " niName:", niName,
             " grpAddrKey:", grpAddrKey, " srcAddrKey:", srcAddrKey, " routeTypeKey:", routeTypeKey, " oifKey:",oifKey)

    if routeTypeKey != "" && routeTypeKey != "SG" {
        log.Errorf ("%s failed !! route-type attribute value(current:%v) other than \"SG\" is not supported !!", cmnLog, routeTypeKey)
        return operErr
    }

    cmd := "show ip pim vrf " + niName + " topology json"
    pimTibOutputJson, cmdErr := pim_exec_vtysh_cmd (cmd)
    if (cmdErr != nil) {
        log.Errorf ("%s failed !! Error:%s", cmnLog, cmdErr);
        return operErr
    }

    gblObj := pimObj.Global ; if gblObj == nil {
        var _gblObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global
        pimObj.Global = &_gblObj
        gblObj = pimObj.Global
        ygot.BuildEmptyTree(gblObj)
    }

    tibObj := gblObj.Tib ; if tibObj == nil {
        var _tibObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib
        gblObj.Tib = &_tibObj
        tibObj = gblObj.Tib
        ygot.BuildEmptyTree(tibObj)
    }

    var tibKey _xfmr_pim_tib_state_key
    tibKey.niName = niName
    tibKey.routeType = ocbinds.OpenconfigPimExt_RouteType_SG
    tibKey.oifKey = oifKey

    for grpAddr := range pimTibOutputJson {
        if ((grpAddrKey != "") && (grpAddr != grpAddrKey)) {continue}
        grpAddrData, ok := pimTibOutputJson[grpAddr].(map[string]interface{}) ; if !ok {continue}

        ipv4EntriesObj := tibObj.Ipv4Entries ; if ipv4EntriesObj == nil {
            var _ipv4EntriesObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries
            tibObj.Ipv4Entries = &_ipv4EntriesObj
            ipv4EntriesObj = tibObj.Ipv4Entries
            ygot.BuildEmptyTree(ipv4EntriesObj)
        }

        ipv4EntryObj, ok := ipv4EntriesObj.Ipv4Entry[grpAddr] ; if !ok {
            ipv4EntryObj,_ = ipv4EntriesObj.NewIpv4Entry(grpAddr)
            ygot.BuildEmptyTree(ipv4EntryObj)
        }

        ipv4EntryStateObj := ipv4EntryObj.State ; if ipv4EntryStateObj == nil {
            var _ipv4EntryStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State
            ipv4EntryObj.State = &_ipv4EntryStateObj
            ipv4EntryStateObj = ipv4EntryObj.State
            ygot.BuildEmptyTree(ipv4EntryStateObj)
        }

        tibKey.grpAddr = grpAddr
        _grpAddr := grpAddr
        ipv4EntryStateObj.GroupAddress = &_grpAddr

        for srcAddr := range grpAddrData {
            if ((srcAddrKey != "") && (srcAddr != srcAddrKey)) {continue}
            srcAddrData, ok := grpAddrData[srcAddr].(map[string]interface{}) ; if !ok {continue}

            srcEntriesObj := ipv4EntryStateObj.SrcEntries ; if srcEntriesObj == nil {
                var _srcEntriesObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries
                ipv4EntryStateObj.SrcEntries = &_srcEntriesObj
                srcEntriesObj = ipv4EntryStateObj.SrcEntries
                ygot.BuildEmptyTree(srcEntriesObj)
            }

            key := ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_Key{
                SourceAddress: srcAddr,
                RouteType: tibKey.routeType,
            }

            srcEntryObj, ok := srcEntriesObj.SrcEntry[key] ; if !ok {
                srcEntryObj,_ = srcEntriesObj.NewSrcEntry(key.SourceAddress, key.RouteType)
                ygot.BuildEmptyTree(srcEntryObj)
            }

            srcEntryStateObj := srcEntryObj.State ; if srcEntryStateObj == nil {
                var _srcEntryStateObj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Global_Tib_Ipv4Entries_Ipv4Entry_State_SrcEntries_SrcEntry_State
                srcEntryObj.State = &_srcEntryStateObj
                srcEntryStateObj = srcEntryObj.State
                ygot.BuildEmptyTree(srcEntryStateObj)
            }

            tibKey.srcAddr = srcAddr

            fill_pim_tib_mroute_state_info (inParams, tibKey, srcAddrData, srcEntryStateObj)
        }
    }

    return err
}

func get_rpc_show_pim_sub_cmd_for_rpf_ (mapData map[string]interface{}) (bool, string, string) {
    _rpf, ok := mapData["rpf"].(bool) ; if !ok {
        return false, "rpf mandatory attribute missing", ""
    }

    if !_rpf {
        return false, "rpf attribute value should be true", ""
    }

    return true, "", "rpf json"
}

func get_rpc_show_pim_sub_cmd_ (mapData map[string]interface{}) (bool, string, string) {
    queryType, ok := mapData["query-type"].(string) ; if !ok {
        err := "Mandatory parameter query-type is not present"
        log.Info ("In get_rpc_show_pim_sub_cmd_ : ", err)
        return false, err, ""
    }

    log.Info("In get_rpc_show_pim_sub_cmd_ ==> queryType : ", queryType)
    switch queryType {
        case "RPF":
            return get_rpc_show_pim_sub_cmd_for_rpf_ (mapData)
        default:
            err := "Invalid value in query-type attribute : " + queryType
            log.Info ("In get_rpc_show_pim_sub_cmd_ : ", err)
            return false, err, ""
    }
}

var rpc_show_pim RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_show_pim")
    var err error
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil, errors.New("RPC show ip pim, invalid input")
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-pim-show:output"`
    }

    log.Info("In rpc_show_pim, RPC data:", mapData)

    input := mapData["sonic-pim-show:input"]
    mapData = input.(map[string]interface{})

    vrf_name := "default"
    if value, ok := mapData["vrf-name"].(string) ; ok {
        vrf_name = value
    }

    af_str := "ip"
    if value, ok := mapData["address-family"].(string) ; ok {
        if value != "IPV4_UNICAST" {
            dbg_err_str := "show ip pim RPC execution failed ==> Invalid value in address-family attribute"
            log.Info("In rpc_show_pim : ", dbg_err_str)
            return nil, errors.New(dbg_err_str)
        }
    }

    ok, err_str, subCmd := get_rpc_show_pim_sub_cmd_ (mapData) ; if !ok {
        dbg_err_str := "show ip pim RPC execution failed ==> " + err_str
        log.Info("In rpc_show_pim, ", dbg_err_str)
        return nil, errors.New(dbg_err_str)
    }

    cmd := "show " + af_str + " pim vrf " + vrf_name + " " + subCmd

    pimOutput, err := exec_raw_vtysh_cmd(cmd)
    if err != nil {
        dbg_err_str := "FRR execution failed ==> " + err_str
        log.Info("In rpc_show_pim, ", dbg_err_str)
        return nil, errors.New("Internal error!")
    }

    result.Output.Status = pimOutput
    return json.Marshal(&result)
}

func get_rpc_clear_pim_sub_cmd_for_all_interfaces (mapData map[string]interface{}) (bool, string, string) {
    _allInterfaces, ok := mapData["all-interfaces"].(bool) ; if !ok {
        return false, "all-interfaces mandatory attribute missing", ""
    }

    if !_allInterfaces {
        return false, "all-interfaces attribute value should be true", ""
    }

    return true, "", "interfaces"
}

func get_rpc_clear_pim_sub_cmd_for_all_oil (mapData map[string]interface{}) (bool, string, string) {
    _allOil, ok := mapData["all-oil"].(bool) ; if !ok {
        return false, "all-oil mandatory attribute missing", ""
    }

    if !_allOil {
        return false, "all-oil attribute value should be true", ""
    }

    return true, "", "oil"
}

func get_rpc_clear_pim_sub_cmd_ (mapData map[string]interface{}) (bool, string, string) {
    configType, ok := mapData["config-type"].(string) ; if !ok {
        err := "Mandatory parameter config-type is not present"
        log.Info ("In get_rpc_clear_pim_sub_cmd_ : ", err)
        return false, err, ""
    }

    log.Info("In get_rpc_clear_pim_sub_cmd_ ==> configType : ", configType)
    switch configType {
        case "ALL-INTERFACES":
            return get_rpc_clear_pim_sub_cmd_for_all_interfaces (mapData)
        case "ALL-OIL":
            return get_rpc_clear_pim_sub_cmd_for_all_oil (mapData)
        default:
            err := "Invalid value in config-type attribute : " + configType
            log.Info ("In get_rpc_clear_pim_sub_cmd_ : ", err)
            return false, err, ""
    }
}

var rpc_clear_pim RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_clear_pim")
    var err error
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil, errors.New("RPC clear pim, invalid input")
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-pim-clear:output"`
    }

    log.Info("In rpc_clear_pim, RPC data:", mapData)

    input := mapData["sonic-pim-clear:input"]
    mapData = input.(map[string]interface{})

    vrf_name := "default"
    if value, ok := mapData["vrf-name"].(string) ; ok {
        vrf_name = value
    }

    af_str := "ip"
    if value, ok := mapData["address-family"].(string) ; ok {
        if value != "IPV4_UNICAST" {
            dbg_err_str := "clear pim RPC execution failed ==> Invalid value in address-family attribute"
            log.Info("In rpc_clear_pim : ", dbg_err_str)
            return nil, errors.New(dbg_err_str)
        }
    }

    ok, err_str, subCmd := get_rpc_clear_pim_sub_cmd_ (mapData) ; if !ok {
        dbg_err_str := "clear pim RPC execution failed ==> " + err_str
        log.Info("In rpc_clear_pim, ", dbg_err_str)
        return nil, errors.New(dbg_err_str)
    }

    cmd := "clear " + af_str + " pim vrf " + vrf_name + " " + subCmd
    cmd = strings.TrimSuffix(cmd, " ")

    pimOutput, err := exec_raw_vtysh_cmd(cmd)
    if err != nil {
        dbg_err_str := "FRR execution failed ==> " + err_str
        log.Info("In rpc_clear_pim, ", dbg_err_str)
        return nil, errors.New("Internal error!")
    }

    if len(pimOutput) != 0 {
        result.Output.Status = pimOutput
    } else {
        result.Output.Status = "Success"
    }

    return json.Marshal(&result)
}

func hdl_post_xfmr_pim_globals_del_ (inParams *XfmrParams, niName string, retDbDataMap *map[string]map[string]db.Value) {
    log.Info ("In PIM Post-Transformer to fill PIM_GLOBALS keys, while handling DELETE-OP for URI : ",
              inParams.requestUri, " ; VRF : ", niName, " ; Incoming DB-Datamap : ", (*retDbDataMap))

    gblTblKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:"PIM_GLOBALS"})

    matchingKeyFound := false
    for _, gblTblKey := range gblTblKeys {
        if gblTblKey.Len() < 2 {continue}
        if !((gblTblKey.Get(0) == niName) && (gblTblKey.Get(1) == "ipv4")) {continue}
        matchingKeyFound = true

        if _, ok := (*retDbDataMap)["PIM_GLOBALS"]; !ok {
            (*retDbDataMap)["PIM_GLOBALS"] = make(map[string]db.Value)
        }

        key := gblTblKey.Get(0) + "|" + gblTblKey.Get(1)
        (*retDbDataMap)["PIM_GLOBALS"][key] = db.Value{}
    }

    if !matchingKeyFound {
        if _, ok := (*retDbDataMap)["PIM_GLOBALS"]; ok && len((*retDbDataMap)["PIM_GLOBALS"]) == 0 {
            delete ((*retDbDataMap), "PIM_GLOBALS")
        }
    }

    log.Info ("After PIM Post-Transformer PIM_GLOBALS handler ==> retDbDataMap : ", (*retDbDataMap))
}

func hdl_post_xfmr_pim_intfs_del_ (inParams *XfmrParams, niName string, retDbDataMap *map[string]map[string]db.Value) {
    log.Info ("In PIM Post-Transformer to fill PIM_INTERFACE keys, while handling DELETE-OP for URI : ",
              inParams.requestUri, " ; VRF : ", niName, " ; Incoming DB-Datamap : ", (*retDbDataMap))

    intfTblKeys, _ := inParams.d.GetKeys(&db.TableSpec{Name:"PIM_INTERFACE"})

    matchingKeyFound := false
    for _, intfTblKey := range intfTblKeys {
        if intfTblKey.Len() < 3 {continue}
        if !((intfTblKey.Get(0) == niName) && (intfTblKey.Get(1) == "ipv4")) {continue}
        matchingKeyFound = true

        if _, ok := (*retDbDataMap)["PIM_INTERFACE"]; !ok {
            (*retDbDataMap)["PIM_INTERFACE"] = make(map[string]db.Value)
        }

        key := intfTblKey.Get(0) + "|" + intfTblKey.Get(1) + "|" + intfTblKey.Get(2)
        (*retDbDataMap)["PIM_INTERFACE"][key] = db.Value{}
    }

    if !matchingKeyFound {
        if _, ok := (*retDbDataMap)["PIM_INTERFACE"]; ok && len((*retDbDataMap)["PIM_INTERFACE"]) == 0 {
            delete ((*retDbDataMap), "PIM_INTERFACE")
        }
    }

    log.Info ("After PIM Post-Transformer PIM_INTERFACE handler ==> retDbDataMap : ", (*retDbDataMap))
}

func pim_hdl_post_xfmr (inParams *XfmrParams, retDbDataMap *map[string]map[string]db.Value) (error) {
    var err error

    if inParams.oper == DELETE {
        xpath, _ := XfmrRemoveXPATHPredicates(inParams.requestUri)
        pathInfo := NewPathInfo(inParams.requestUri)
        niName := pathInfo.Var("name")
        if len(niName) == 0 {return err}
        uiIntfId := pathInfo.Var("interface-id")

        switch xpath {
            case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/pim":
                hdl_post_xfmr_pim_globals_del_ (inParams, niName, retDbDataMap)
                hdl_post_xfmr_pim_intfs_del_ (inParams, niName, retDbDataMap)

            case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/pim/global":
                hdl_post_xfmr_pim_globals_del_ (inParams, niName, retDbDataMap)

            case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/pim/interfaces": fallthrough
            case "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/pim/interfaces/interface":
                if len(uiIntfId) == 0 {
                    /* Handle only all interfaces delete case. Specific interface delete will be handled in usual way, by infra-code */
                    hdl_post_xfmr_pim_intfs_del_ (inParams, niName, retDbDataMap)
                }
        }
    }

    return err
}
