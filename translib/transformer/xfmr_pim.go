package transformer

import (
    "errors"
    "strings"
    "strconv"
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
    XlateFuncBind("YangToDb_pim_intf_mode_fld_xfmr", YangToDb_pim_intf_mode_fld_xfmr)
    XlateFuncBind("DbToYang_pim_intf_mode_fld_xfmr", DbToYang_pim_intf_mode_fld_xfmr)
    XlateFuncBind("DbToYang_pim_intf_state_xfmr", DbToYang_pim_intf_state_xfmr)
    XlateFuncBind("DbToYang_pim_nbrs_state_xfmr", DbToYang_pim_nbrs_state_xfmr)
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

var YangToDb_pim_gbl_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    niName, err := validatePimRoot (inParams); if err != nil {
        return "", err
    }

    log.Info("YangToDb_pim_gbl_tbl_key_xfmr : URI:", inParams.uri, " VRF:", niName)

    return (niName + "|" + "ipv4"), err
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

    log.Info("YangToDb_pim_intf_tbl_key_xfmr : URI:", inParams.uri, " VRF:", niName, " uiIntfId:", uiIntfId)

    return (niName + "|" + "ipv4" + "|" + uiIntfId), err
}

var DbToYang_pim_intf_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    log.Info("DbToYang_pim_intf_tbl_key_xfmr: Key:", inParams.key)

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

        if value, ok := cfgDbEntry["dr-priority"] ; ok {
            if _drPriorityU64, err := strconv.ParseUint(value, 10, 32) ; err == nil {
                _drPriorityU32 := uint32(_drPriorityU64)
                intfStateObj.DrPriority = &_drPriorityU32
            }
        }

        if value, ok := cfgDbEntry["hello-interval"] ; ok {
            if _helloIntervalU64, err := strconv.ParseUint(value, 10, 8) ; err == nil {
                _helloIntervalU8 := uint8(_helloIntervalU64)
                intfStateObj.HelloInterval = &_helloIntervalU8
            }
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

func fill_pim_intf_state_info (inParams XfmrParams, intfKey _xfmr_pim_intf_state_key, intfData map[string]interface{},
                               intfStateObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Pim_Interfaces_Interface_State) bool {
    if value, ok := intfData["state"] ; ok {
        _enabled := false
        switch value {
            case "up":
                _enabled = true
        }
        intfStateObj.Enabled = &_enabled
    }

    if value, ok := intfData["pimDesignatedRouter"] ; ok {
        _drAddress := value.(string)
        intfStateObj.DrAddress = &_drAddress
    }

    if value, ok := intfData["address"] ; ok {
        _localAddress := value.(string)
        intfStateObj.LocalAddress = &_localAddress
    }

    if value, ok := intfData["pimNeighbors"] ; ok {
        _nbrsCount := uint16(value.(float64))
        intfStateObj.NbrsCount = &_nbrsCount
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

    cmd := "show ip pim vrf " + niName + " interface json"
    pimIntfOutputJson, cmdErr := pim_exec_vtysh_cmd (cmd)
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
    for intfId := range pimIntfOutputJson {
        if (nativeIntfIdKey != "" && (intfId != nativeIntfIdKey)) {continue}
        intfData, ok := pimIntfOutputJson[intfId].(map[string]interface{}) ; if !ok {continue}
        fill_pim_intf_state_info (inParams, intfKey, intfData, intfStateObj)
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

    if value, ok := nbrData["upTime"] ; ok {
        _neighborEstablished := value.(string)
        nbrStateObj.NeighborEstablished = &_neighborEstablished
    }

    if value, ok := nbrData["holdTime"] ; ok {
        _neighborExpires := value.(string)
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
