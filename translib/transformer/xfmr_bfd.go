package transformer

import (
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "strings"
    "encoding/json"
    "strconv"
    "os/exec"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
)

func init () {
    XlateFuncBind("DbToYang_bfd_shop_state_xfmr", DbToYang_bfd_shop_state_xfmr)
    XlateFuncBind("DbToYang_bfd_mhop_state_xfmr", DbToYang_bfd_mhop_state_xfmr)
    XlateFuncBind("YangToDb_bfd_shop_remoteaddr_fld_xfmr", YangToDb_bfd_shop_remoteaddr_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_shop_vrf_fld_xfmr", YangToDb_bfd_shop_vrf_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_shop_interface_fld_xfmr", YangToDb_bfd_shop_interface_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_shop_localaddr_fld_xfmr", YangToDb_bfd_shop_localaddr_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_shop_remoteaddr_fld_xfmr", DbToYang_bfd_shop_remoteaddr_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_shop_vrf_fld_xfmr", DbToYang_bfd_shop_vrf_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_shop_interface_fld_xfmr", DbToYang_bfd_shop_interface_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_shop_localaddr_fld_xfmr", DbToYang_bfd_shop_localaddr_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_mhop_remoteaddr_fld_xfmr", YangToDb_bfd_mhop_remoteaddr_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_mhop_vrf_fld_xfmr", YangToDb_bfd_mhop_vrf_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_mhop_interface_fld_xfmr", YangToDb_bfd_mhop_interface_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_mhop_localaddr_fld_xfmr", YangToDb_bfd_mhop_localaddr_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_mhop_remoteaddr_fld_xfmr", DbToYang_bfd_mhop_remoteaddr_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_mhop_vrf_fld_xfmr", DbToYang_bfd_mhop_vrf_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_mhop_interface_fld_xfmr", DbToYang_bfd_mhop_interface_fld_xfmr)
    XlateFuncBind("DbToYang_bfd_mhop_localaddr_fld_xfmr", DbToYang_bfd_mhop_localaddr_fld_xfmr)
    XlateFuncBind("YangToDb_bfd_shop_tbl_key_xfmr", YangToDb_bfd_shop_tbl_key_xfmr)
    XlateFuncBind("YangToDb_bfd_mhop_tbl_key_xfmr", YangToDb_bfd_mhop_tbl_key_xfmr)
    XlateFuncBind("DbToYang_bfd_shop_tbl_key_xfmr", DbToYang_bfd_shop_tbl_key_xfmr)
    XlateFuncBind("DbToYang_bfd_mhop_tbl_key_xfmr", DbToYang_bfd_mhop_tbl_key_xfmr)
    XlateFuncBind("bfd_shop_session_tbl_xfmr", bfd_shop_session_tbl_xfmr)
    XlateFuncBind("bfd_mhop_session_tbl_xfmr", bfd_mhop_session_tbl_xfmr)
    XlateFuncBind("rpc_clear_bfd", rpc_clear_bfd)
}

var bfd_table_key_transformer = func(inParams XfmrParams) (string, error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    bfdPeer        := pathInfo.Var("remote-address")
    bfdInterface   := pathInfo.Var("interface")
    bfdVrf         := pathInfo.Var("vrf")
    bfdLocalAddr   := pathInfo.Var("local-address")

    if len(pathInfo.Vars) <  4 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return "", err
    }

    if len(bfdPeer) == 0 {
        err = errors.New("BFD Peer Addr is missing");
        log.Info("BFD Peer Addr is missing")
        return "", err
    }

    if len(bfdInterface) == 0 {
        err = errors.New("BFD interface is missing");
        log.Info("BFD interface is missing")
        return "", err
    }

    if len(bfdVrf) == 0 {
        err = errors.New("BFD Peer Vrf is missing");
        log.Info("BFD Peer Vrf is missing")
        return "", err
    }

    if len(bfdLocalAddr) == 0 {
        err = errors.New("BFD localaddr is missing");
        log.Info("BFD localaddr is missing")
        return "", err
    }

    log.Info("URI Peer", bfdPeer)
    log.Info("URI Interface", bfdInterface)
	log.Info("URI VRF", bfdVrf)
    log.Info("URI Localaddr", bfdLocalAddr)

    TableKey := bfdPeer + "|" + bfdInterface + "|" + bfdVrf + "|" + bfdLocalAddr

    log.Info("bfd_table_key_transformer: TableKey - ", TableKey)
    return TableKey, nil
}

var YangToDb_bfd_shop_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {

    log.Info("YangToDb_bfd_shop_tbl_key_xfmr: ", inParams.uri)

    return bfd_table_key_transformer(inParams)
}

var YangToDb_bfd_mhop_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {

    log.Info("YangToDb_bfd_mhop_tbl_key_xfmr: ", inParams.uri)

    return bfd_table_key_transformer(inParams)
}

var YangToDb_bfd_shop_remoteaddr_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_shop_remoteaddr_fld_xfmr: ", inParams.key)

    return res_map, err
}

var YangToDb_bfd_shop_vrf_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_shop_vrf_fld_xfmr: ", inParams.key)

    return res_map, err
}

var YangToDb_bfd_shop_interface_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_shop_interface_fld_xfmr: ", inParams.key)

    return res_map, err
}

var YangToDb_bfd_shop_localaddr_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_shop_localaddr_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_bfd_shop_remoteaddr_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["remote-address"]     = TableKeys[0]
    }

    log.Info("DbToYang_bfd_shop_remoteaddr_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_shop_vrf_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["vrf"]     = TableKeys[1]
    }

    log.Info("DbToYang_bfd_shop_vrf_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_shop_interface_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["interface"]     = TableKeys[2]
    }

    log.Info("DbToYang_bfd_shop_interface_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_shop_localaddr_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["local-address"]     = TableKeys[3]
    }

    log.Info("DbToYang_bfd_shop_localaddr_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var YangToDb_bfd_mhop_remoteaddr_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_mhop_remoteaddr_fld_xfmr: ", inParams.key)

    return res_map, err
}

var YangToDb_bfd_mhop_vrf_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_mhop_vrf_fld_xfmr: ", inParams.key)

    return res_map, err
}

var YangToDb_bfd_mhop_interface_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_mhop_interface_fld_xfmr: ", inParams.key)

    return res_map, err
}

var YangToDb_bfd_mhop_localaddr_fld_xfmr = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    log.Info("YangToDb_bfd_mhop_localaddr_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_bfd_mhop_remoteaddr_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["remote-address"]     = TableKeys[0]
    }

    log.Info("DbToYang_bfd_mhop_remoteaddr_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_mhop_vrf_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["vrf"]     = TableKeys[1]
    }

    log.Info("DbToYang_bfd_mhop_vrf_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_mhop_interface_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["interface"]     = TableKeys[2]
    }

    log.Info("DbToYang_bfd_mhop_interface_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_mhop_localaddr_fld_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    TableKeys := strings.Split(inParams.key, "|")

    if len(TableKeys) >= 4 {
       res_map["local-address"]     = TableKeys[3]
    }

    log.Info("DbToYang_bfd_mhop_localaddr_fld_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_shop_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_bfd_shop_tbl_key_xfmr: entry key - ", entry_key)

    TableKeys := strings.Split(entry_key, "|")

    if len(TableKeys) >= 4 {
       res_map["remote-address"]     = TableKeys[0]
	   res_map["interface"]      = TableKeys[1]
	   res_map["vrf"]            = TableKeys[2]
	   res_map["local-address"]  = TableKeys[3]
    }

    log.Info("DbToYang_bfd_shop_tbl_key_xfmr: res_map - ", res_map)
    return res_map, nil
}

var DbToYang_bfd_mhop_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_bfd_mhop_tbl_key_xfmr: entry key - ", entry_key)

    TableKeys := strings.Split(entry_key, "|")

    if len(TableKeys) >= 4 {
       res_map["remote-address"]     = TableKeys[0]
	   res_map["interface"]      = TableKeys[1]
	   res_map["vrf"]            = TableKeys[2]
	   res_map["local-address"]  = TableKeys[3]
    }

    log.Info("DbToYang_bfd_mhop_tbl_key_xfmr: res_map - ", res_map)
    return res_map, nil
}

func bfd_get_shop_root (inParams XfmrParams, dbg_log string) (*ocbinds.OpenconfigBfd_Bfd_BfdShopSessions, error) {
    var err error
    var bfd_obj *ocbinds.OpenconfigBfd_Bfd

    log.Info("bfd_get_shop_root")
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    bfd_obj = deviceObj.Bfd

    if bfd_obj == nil {
        log.Info("bfd_get_shop_root22")
        return nil, errors.New("BFD container missing")
    }

    if bfd_obj.BfdShopSessions == nil {
        ygot.BuildEmptyTree (bfd_obj)
    }

    return bfd_obj.BfdShopSessions, err
}

func bfd_get_mhop_root (inParams XfmrParams, dbg_log string) (*ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions, error) {
    var err error
    var bfd_obj *ocbinds.OpenconfigBfd_Bfd

    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    bfd_obj = deviceObj.Bfd

    if bfd_obj == nil {
        log.Info("bfd_get_shop_root22")
        return nil, errors.New("BFD container missing")
    }

    if bfd_obj.BfdMhopSessions == nil {
        ygot.BuildEmptyTree (bfd_obj)
    }

    return bfd_obj.BfdMhopSessions, err
}

func exec_vtysh_cmd_array (vtysh_cmd string) ([]interface{}, error) {
    var err error
    oper_err := errors.New("Operational error")

    log.Infof("Going to execute vtysh cmd ==> \"%s\"", vtysh_cmd)

    cmd := exec.Command("/usr/bin/docker", "exec", "bgp", "vtysh", "-c", vtysh_cmd)
    out_stream, err := cmd.StdoutPipe()
    if err != nil {
        log.Errorf("Can't get stdout pipe: %s\n", err)
        return nil, oper_err
    }

    err = cmd.Start()
    if err != nil {
        log.Errorf("cmd.Start() failed with %s\n", err)
        return nil, oper_err
    }

    var outputJson []interface{}
    err = json.NewDecoder(out_stream).Decode(&outputJson)
    if err != nil {
        log.Errorf("Not able to decode vtysh json output as array of objects: %s\n", err)
        return nil, oper_err
    }

    err = cmd.Wait()
    if err != nil {
        log.Errorf("Command execution completion failed with %s\n", err)
        return nil, oper_err
    }

    log.Infof("Successfully executed vtysh-cmd ==> \"%s\"", vtysh_cmd)

    if outputJson == nil {
        log.Errorf("VTYSH output empty !!!")
        return nil, oper_err
    }

    return outputJson, err
}

var DbToYang_bfd_shop_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var bfdshop_key ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop_Key
    var vtysh_cmd string
    var err error

    log.Info("DbToYang_bfd_shop_state_xfmr")

    bfdMapJson := make(map[string]interface{})
    bfdCounterMapJson := make(map[string]interface{})

    cmn_log := "GET: xfmr for BFD peers state"
    pathInfo := NewPathInfo(inParams.uri)
    log.Errorf("pathInfo", pathInfo)

    bfd_obj, get_err := bfd_get_shop_root (inParams, cmn_log);
    if get_err != nil {
        return get_err
    }

    bfdshop_key.RemoteAddress = pathInfo.Var("remote-address")
    bfdshop_key.Vrf = pathInfo.Var("vrf")
    bfdshop_key.Interface = pathInfo.Var("interface")
    bfdshop_key.LocalAddress = pathInfo.Var("local-address")

    if (bfdshop_key.Interface != "null") {
        bfdshop_key.Interface = *utils.GetNativeNameFromUIName(&(bfdshop_key.Interface))
    }

    if (bfdshop_key.LocalAddress == "null") {
        vtysh_cmd = "show bfd vrf " + bfdshop_key.Vrf + " peer " + bfdshop_key.RemoteAddress + " interface " + bfdshop_key.Interface + " json"
    } else {
        vtysh_cmd = "show bfd vrf " + bfdshop_key.Vrf + " peer " + bfdshop_key.RemoteAddress + " interface " + bfdshop_key.Interface + " local-address " + bfdshop_key.LocalAddress + " json"
    }

    output_peer, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to fetch shop bfd peers:, err")
        return cmd_err;
    }

    if (bfdshop_key.LocalAddress == "null") {
        vtysh_cmd = "show bfd vrf " + bfdshop_key.Vrf + " peer " + bfdshop_key.RemoteAddress + " interface " + bfdshop_key.Interface + " counters" + " json"
    } else {
        vtysh_cmd = "show bfd vrf " + bfdshop_key.Vrf + " peer " + bfdshop_key.RemoteAddress + " interface " + bfdshop_key.Interface + " local-address " + bfdshop_key.LocalAddress + " counters" + " json"
    }

    output_counter, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to fetch shop bfd peers counters array:, err")
        return cmd_err;
    }

    log.Info(output_peer)
    bfdMapJson["output"] = output_peer

    log.Info(output_counter)
    bfdCounterMapJson["output"] = output_counter

    if sessions, ok := bfdMapJson["output"].(map[string]interface{}) ; ok {
        log.Info(sessions)
        if counters, ok := bfdCounterMapJson["output"].(map[string]interface{}) ; ok {
            log.Info(counters)
            fill_bfd_shop_data (bfd_obj, sessions, counters, &bfdshop_key)
        }
    }

    return err;
}

var DbToYang_bfd_mhop_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var bfdmhop_key ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions_MultiHop_Key
    var err error
    var vtysh_cmd string

    log.Info("DbToYang_bfd_mhop_state_xfmr")

    bfdMapJson := make(map[string]interface{})
    bfdCounterMapJson := make(map[string]interface{})

    cmn_log := "GET: xfmr for BFD peers state"

    bfd_obj, get_err := bfd_get_mhop_root (inParams, cmn_log);
    if get_err != nil {
        return get_err
    }

    pathInfo := NewPathInfo(inParams.uri)

    bfdmhop_key.RemoteAddress = pathInfo.Var("remote-address")
    bfdmhop_key.Interface = pathInfo.Var("interface")
    bfdmhop_key.Vrf = pathInfo.Var("vrf")
    bfdmhop_key.LocalAddress = pathInfo.Var("local-address")

    if (bfdmhop_key.Interface != "null") {
        bfdmhop_key.Interface = *utils.GetNativeNameFromUIName(&(bfdmhop_key.Interface))
    }

    if (bfdmhop_key.LocalAddress == "null") {
        vtysh_cmd = "show bfd vrf " + bfdmhop_key.Vrf + " peer " + bfdmhop_key.RemoteAddress + " multihop " + " local-address " + bfdmhop_key.LocalAddress + " json"
    } else {
        vtysh_cmd = "show bfd vrf " + bfdmhop_key.Vrf + " peer " + bfdmhop_key.RemoteAddress + " multihop " + " local-address " + bfdmhop_key.LocalAddress + " interface " + bfdmhop_key.Interface + " json"
    }

    output_peer, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to fetch shop bfd peers array:, err")
        return cmd_err;
    }

    if (bfdmhop_key.LocalAddress == "null") {
        vtysh_cmd = "show bfd vrf " + bfdmhop_key.Vrf + " peer " + bfdmhop_key.RemoteAddress + " multihop " + " local-address " + bfdmhop_key.LocalAddress + " counters" + " json"
    } else {
        vtysh_cmd = "show bfd vrf " + bfdmhop_key.Vrf + " peer " + bfdmhop_key.RemoteAddress + " multihop " + " local-address " + bfdmhop_key.LocalAddress + " interface " + bfdmhop_key.Interface + " counters" + " json"
    }

    output_counter, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
        log.Errorf("Failed to fetch shop bfd peers counters array:, err")
        return cmd_err;
    }

    log.Info(output_peer)
    bfdMapJson["output"] = output_peer

    log.Info(output_counter)
    bfdCounterMapJson["output"] = output_counter

    if sessions, ok := bfdMapJson["output"].(map[string]interface{}) ; ok {
        log.Info(sessions)
        if counters, ok := bfdCounterMapJson["output"].(map[string]interface{}) ; ok {
            log.Info(counters)
            fill_bfd_mhop_data (bfd_obj, sessions, counters, &bfdmhop_key)
        }
    }

    return err;
}

func fill_bfd_shop_data (bfd_obj *ocbinds.OpenconfigBfd_Bfd_BfdShopSessions, session_data map[string]interface{}, counter_data map[string]interface{}, bfdshop_Input_key *ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop_Key) bool {
    var err error
    var bfdshop_obj *ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop
    var bfdshop_obj_state *ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop_State
    var bfdshopkey ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop_Key
    var bfdshop_tempkey ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop_Key
    var bfdasyncstats *ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop_State_Async
    var bfdechocstats *ocbinds.OpenconfigBfd_Bfd_BfdShopSessions_SingleHop_State_Echo

    log.Info("fill_bfd_shop_data")

    if (nil != bfdshop_Input_key) {
        bfdshop_tempkey = *bfdshop_Input_key
        bfdshop_obj = bfd_obj.SingleHop[bfdshop_tempkey]
        if (nil == bfdshop_obj) {
            if value, ok := session_data["peer"].(string) ; ok {
                bfdshopkey.RemoteAddress = value
            }

            if value, ok := session_data["interface"].(string) ; ok {
               bfdshopkey.Interface = *utils.GetUINameFromNativeName(&value)
            }

            if value, ok := session_data["vrf"].(string) ; ok {
                bfdshopkey.Vrf = value
            } 

            if value, ok := session_data["local"].(string) ; ok {
                bfdshopkey.LocalAddress = value
            } else {
                bfdshopkey.LocalAddress = "null"
            }

            bfdshop_obj, err = bfd_obj.NewSingleHop (bfdshopkey.RemoteAddress, bfdshopkey.Interface, bfdshopkey.Vrf, bfdshopkey.LocalAddress)
            if (err != nil) {
                log.Info("New Shop node created")
                return false;
            }
        }
    }
 
    ygot.BuildEmptyTree(bfdshop_obj)
    ygot.BuildEmptyTree(bfdshop_obj.State)
    bfdshop_obj_state = bfdshop_obj.State;

    if value, ok := session_data["status"].(string) ; ok {
        if value == "down" {
            bfdshop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_DOWN
        } else if value == "up" {
            bfdshop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_UP
        } else if value == "shutdown" {
            bfdshop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_ADMIN_DOWN
        } else if value == "init" {
            bfdshop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_INIT
        } else {
            bfdshop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_UNSET
        }

    }

    /*if value, ok := session_data["remote-status"].(ocbinds.E_OpenconfigBfd_BfdSessionState) ; ok {
        bfdshop_obj_state.RemoteSessionState = value
    }*/

    if bfdshop_obj_state.SessionState != ocbinds.OpenconfigBfd_BfdSessionState_UP { 
        if value, ok := session_data["downtime"].(float64) ; ok {
            value64 := uint64(value)
            bfdshop_obj_state.LastFailureTime = &value64
        }   
    }

    if value, ok := session_data["id"].(float64) ; ok {
        s := strconv.FormatFloat(value, 'f', -1, 64)
        bfdshop_obj_state.LocalDiscriminator = &s
    }

    if value, ok := session_data["remote-id"].(float64) ; ok {
        s := strconv.FormatFloat(value, 'f', -1, 64)
        bfdshop_obj_state.RemoteDiscriminator = &s
    }
    
    if value, ok := session_data["diagnostic"].(string) ; ok {
        if value == "ok" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_UNSET
        } else if value == "control detection time expired" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_DETECTION_TIMEOUT
        } else if value == "echo function failed" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ECHO_FAILED
        } else if value == "neighbor signaled session down" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NEIGHBOR_SIGNALED_DOWN
        } else if value == "forwarding plane reset" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_FORWARDING_RESET
        } else if value == "path down" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_PATH_DOWN
        } else if value == "concatenated path down" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_CONCATENATED_PATH_DOWN
        } else if value == "administratively down" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ADMIN_DOWN
        } else if value == "reverse concatenated path down" {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_REVERSE_CONCATENATED_PATH_DOWN
        } else {
            bfdshop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NO_DIAGNOSTIC
        }

    }

    if value, ok := session_data["remote-diagnostic"].(string) ; ok {
        if value == "ok" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_UNSET
        } else if value == "control detection time expired" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_DETECTION_TIMEOUT
        } else if value == "echo function failed" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ECHO_FAILED
        } else if value == "neighbor signaled session down" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NEIGHBOR_SIGNALED_DOWN
        } else if value == "forwarding plane reset" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_FORWARDING_RESET
        } else if value == "path down" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_PATH_DOWN
        } else if value == "concatenated path down" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_CONCATENATED_PATH_DOWN
        } else if value == "administratively down" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ADMIN_DOWN
        } else if value == "reverse concatenated path down" {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_REVERSE_CONCATENATED_PATH_DOWN
        } else {
            bfdshop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NO_DIAGNOSTIC
        }
    }

    if value, ok := session_data["remote-receive-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdshop_obj_state.RemoteMinimumReceiveInterval = &value32
    }

    /*if value, ok := session_data[""].(bool) ; ok {
        bfdshop_obj_state.DemandModeRequested = &value
    }

    if value, ok := session_data[""].(bool) ; ok {
        bfdshop_obj_state.RemoteAuthenticationEnabled = &value
    }

    if value, ok := session_data[""].(bool) ; ok {
        bfdshop_obj_state.RemoteControlPlaneIndependent = &value
    }*/

    if value, ok := session_data["peer_type"].(string) ; ok {
        if value == "configured" {
            bfdshop_obj_state.SessionType = ocbinds.OpenconfigBfdExt_BfdSessionType_CONFIGURED
        } else {
            bfdshop_obj_state.SessionType = ocbinds.OpenconfigBfdExt_BfdSessionType_DYNAMIC
        }
    }

    if value, ok := session_data["remote-detect-multiplier"].(float64) ; ok {
        value32 := uint32(value)
        bfdshop_obj_state.RemoteMultiplier = &value32
    }

    if value, ok := session_data["detect-multiplier"].(float64) ; ok {
        value8 := uint8(value)
        bfdshop_obj_state.DetectionMultiplier = &value8
    }

    if value, ok := session_data["transmit-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdshop_obj_state.DesiredMinimumTxInterval = &value32
    }

    if value, ok := session_data["receive-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdshop_obj_state.RequiredMinimumReceive = &value32
    }

    if value, ok := session_data["remote-transmit-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdshop_obj_state.RemoteDesiredTransmissionInterval = &value32
    }

    if value, ok := session_data["remote-echo-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdshop_obj_state.RemoteEchoReceiveInterval = &value32
    }

    if value, ok := session_data["echo-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdshop_obj_state.DesiredMinimumEchoReceive = &value32
    }

    /*if value, ok := session_data[""].(uint64) ; ok {
        bfdshop_obj_state.LastUpTime = &value
    }*/

    if bfdshop_obj_state.SessionState == ocbinds.OpenconfigBfd_BfdSessionState_UP {
        if value, ok := session_data["uptime"].(float64) ; ok {
            value64 := uint64(value)
            bfdshop_obj_state.LastUpTime = &value64
        }
    }

    bfdasyncstats = bfdshop_obj_state.Async
    bfdechocstats = bfdshop_obj_state.Echo

    /*if value, ok := counter_data[""].(uint64) ; ok {
        bfdasyncstats.LastPacketReceived = &value
    }

    if value, ok := counter_data[""].(uint64) ; ok {
        bfdasyncstats.LastPacketTransmitted = &value
    }*/

    if value, ok := counter_data["control-packet-input"].(float64) ; ok {
        value64 := uint64(value)
        bfdasyncstats.ReceivedPackets = &value64
    }

    if value, ok := counter_data["control-packet-output"].(float64) ; ok {
        value64 := uint64(value)
        bfdasyncstats.TransmittedPackets = &value64
    }

    if value, ok := counter_data["session-up"].(float64) ; ok {
        value64 := uint64(value)
        bfdasyncstats.UpTransitions = &value64
    }

    if value, ok := counter_data["session-down"].(float64) ; ok {
        value64 := uint64(value)
        bfdshop_obj_state.FailureTransitions = &value64
    }

    /*if value, ok := counter_data[""].(bool) ; ok {
        bfdechocstats.Active = &value
    }

    if value, ok := counter_data[""].(uint64) ; ok {
        bfdechocstats.LastPacketReceived = &value
    }

    if value, ok := counter_data[""].(uint64) ; ok {
        bfdechocstats.LastPacketTransmitted = &value
    }*/

    if value, ok := counter_data["echo-packet-input"].(float64) ; ok {
        value64 := uint64(value)
        bfdechocstats.ReceivedPackets = &value64
    }

    if value, ok := counter_data["echo-packet-output"].(float64) ; ok {
        value64 := uint64(value)
        bfdechocstats.TransmittedPackets = &value64
    }

    /*if value, ok := counter_data[""].(uint64) ; ok {
        bfdechocstats.UpTransitions = &value
    }*/

    return true;
}



func fill_bfd_mhop_data (bfd_obj *ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions, session_data map[string]interface{}, counter_data map[string]interface{}, bfdmhop_Input_key *ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions_MultiHop_Key) bool {
    var err error
    var bfdmhop_obj *ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions_MultiHop
    var bfdmhop_obj_state *ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions_MultiHop_State
    var bfdmhopkey ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions_MultiHop_Key
    var bfdmhop_tempkey ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions_MultiHop_Key
    var bfdasyncstats *ocbinds.OpenconfigBfd_Bfd_BfdMhopSessions_MultiHop_State_Async

    log.Info("fill_bfd_mhop_data")

    if (nil != bfdmhop_Input_key) {
        bfdmhop_tempkey = *bfdmhop_Input_key
        bfdmhop_obj = bfd_obj.MultiHop[bfdmhop_tempkey]
        if (nil == bfdmhop_obj) {
            if value, ok := session_data["peer"].(string) ; ok {
                bfdmhopkey.RemoteAddress = value
            }

            if value, ok := session_data["interface"].(string) ; ok {
                bfdmhopkey.Interface = *utils.GetUINameFromNativeName(&value)
            } else {
                 bfdmhopkey.Interface = "null"
            }

            if value, ok := session_data["vrf"].(string) ; ok {
                bfdmhopkey.Vrf = value
            }

            if value, ok := session_data["local"].(string) ; ok {
                bfdmhopkey.LocalAddress = value
            }

            bfdmhop_obj, err = bfd_obj.NewMultiHop(bfdmhopkey.RemoteAddress, bfdmhopkey.Interface, bfdmhopkey.Vrf, bfdmhopkey.LocalAddress)
            if err != nil {return false}
        }
    }

    ygot.BuildEmptyTree(bfdmhop_obj)
    ygot.BuildEmptyTree(bfdmhop_obj.State)

    bfdmhop_obj_state = bfdmhop_obj.State;

    if value, ok := session_data["status"].(string) ; ok {
        if value == "down" {
            bfdmhop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_DOWN
        } else if value == "up" {
            bfdmhop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_UP
        } else if value == "shutdown" {
            bfdmhop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_ADMIN_DOWN
        } else if value == "init" {
            bfdmhop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_INIT
        } else {
            bfdmhop_obj_state.SessionState = ocbinds.OpenconfigBfd_BfdSessionState_UNSET
        }
    }

    /*if value, ok := session_data["remote-status"].(ocbinds.E_OpenconfigBfd_BfdSessionState) ; ok {
        bfdmhop_obj_state.RemoteSessionState = value
    }*/

    if bfdmhop_obj_state.SessionState != ocbinds.OpenconfigBfd_BfdSessionState_UP {
        if value, ok := session_data["downtime"].(float64) ; ok {
            value64 := uint64(value)
            bfdmhop_obj_state.LastFailureTime = &value64
        }   
    }
    if value, ok := session_data["id"].(float64) ; ok {
        s := strconv.FormatFloat(value, 'f', -1, 64)
        bfdmhop_obj_state.LocalDiscriminator = &s
    }

    if value, ok := session_data["remote-id"].(float64) ; ok {
        s := strconv.FormatFloat(value, 'f', -1, 64)
        bfdmhop_obj_state.RemoteDiscriminator = &s
    }

    if value, ok := session_data["diagnostic"].(string) ; ok {
        if value == "ok" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_UNSET
        } else if value == "control detection time expired" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_DETECTION_TIMEOUT
        } else if value == "echo function failed" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ECHO_FAILED
        } else if value == "neighbor signaled session down" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NEIGHBOR_SIGNALED_DOWN
        } else if value == "forwarding plane reset" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_FORWARDING_RESET
        } else if value == "path down" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_PATH_DOWN
        } else if value == "concatenated path down" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_CONCATENATED_PATH_DOWN
        } else if value == "administratively down" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ADMIN_DOWN
        } else if value == "reverse concatenated path down" {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_REVERSE_CONCATENATED_PATH_DOWN
        } else {
            bfdmhop_obj_state.LocalDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NO_DIAGNOSTIC
        }

    }

    if value, ok := session_data["remote-diagnostic"].(string) ; ok {
        if value == "ok" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_UNSET
        } else if value == "control detection time expired" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_DETECTION_TIMEOUT
        } else if value == "echo function failed" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ECHO_FAILED
        } else if value == "neighbor signaled session down" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NEIGHBOR_SIGNALED_DOWN
        } else if value == "forwarding plane reset" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_FORWARDING_RESET
        } else if value == "path down" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_PATH_DOWN
        } else if value == "concatenated path down" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_CONCATENATED_PATH_DOWN
        } else if value == "administratively down" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_ADMIN_DOWN
        } else if value == "reverse concatenated path down" {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_REVERSE_CONCATENATED_PATH_DOWN
        } else {
            bfdmhop_obj_state.RemoteDiagnosticCode = ocbinds.OpenconfigBfd_BfdExtDiagnosticCode_NO_DIAGNOSTIC
        }
    }

    if value, ok := session_data["remote-receive-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdmhop_obj_state.RemoteMinimumReceiveInterval = &value32
    }

    /*if value, ok := session_data[""].(bool) ; ok {
        bfdmhop_obj_state.DemandModeRequested = &value
    }

    if value, ok := session_data[""].(bool) ; ok {
        bfdmhop_obj_state.RemoteAuthenticationEnabled = &value
    }

    if value, ok := session_data[""].(bool) ; ok {
        bfdmhop_obj_state.RemoteControlPlaneIndependent = &value
    }

    if value, ok := session_data[""].(ocbinds.E_OpenconfigBfdExt_BfdSessionType) ; ok {
        bfdmhop_obj_state.SessionType = value
    }*/

    if value, ok := session_data["remote-detect-multiplier"].(float64) ; ok {
        value32 := uint32(value)
        bfdmhop_obj_state.RemoteMultiplier = &value32
    }

    if value, ok := session_data["detect-multiplier"].(float64) ; ok {
        value8 := uint8(value)
        bfdmhop_obj_state.DetectionMultiplier = &value8
    }

    if value, ok := session_data["peer_type"].(string) ; ok {
        if value == "configured" {
            bfdmhop_obj_state.SessionType = ocbinds.OpenconfigBfdExt_BfdSessionType_CONFIGURED
        } else {
            bfdmhop_obj_state.SessionType = ocbinds.OpenconfigBfdExt_BfdSessionType_DYNAMIC
        }
    }

    if value, ok := session_data["transmit-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdmhop_obj_state.DesiredMinimumTxInterval = &value32
    }

    if value, ok := session_data["receive-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdmhop_obj_state.RequiredMinimumReceive = &value32
    }

    if value, ok := session_data["remote-transmit-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdmhop_obj_state.RemoteDesiredTransmissionInterval = &value32
    }

    if value, ok := session_data["remote-echo-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdmhop_obj_state.RemoteEchoReceiveInterval = &value32
    }

    /*if value, ok := session_data["echo-interval"].(float64) ; ok {
        value32 := uint32(value)
        bfdmhop_obj_state.MinimumEchoInterval = &value32
    }*/

    if bfdmhop_obj_state.SessionState == ocbinds.OpenconfigBfd_BfdSessionState_UP {
        if value, ok := session_data["uptime"].(float64) ; ok {
            value64 := uint64(value)
            bfdmhop_obj_state.LastUpTime = &value64
        }
    }

    bfdasyncstats = bfdmhop_obj_state.Async
    //bfdechocstats = bfdmhop_obj_state.Echo

    /*if value, ok := counter_data[""].(uint64) ; ok {
        bfdasyncstats.LastPacketReceived = &value
    }

    if value, ok := counter_data[""].(uint64) ; ok {
        bfdasyncstats.LastPacketTransmitted = &value
    }*/

    if value, ok := counter_data["control-packet-input"].(float64) ; ok {
        value64 := uint64(value)
        bfdasyncstats.ReceivedPackets = &value64
    }

    if value, ok := counter_data["control-packet-output"].(float64) ; ok {
        value64 := uint64(value)
        bfdasyncstats.TransmittedPackets = &value64
    }

    if value, ok := counter_data["session-up"].(float64) ; ok {
        value64 := uint64(value)
        bfdasyncstats.UpTransitions = &value64
    }

    if value, ok := counter_data["session-down"].(float64) ; ok {
        value64 := uint64(value)
        bfdmhop_obj_state.FailureTransitions = &value64
    }

    /*if value, ok := counter_data[""].(bool) ; ok {
        bfdechocstats.Active = &value
    }

    if value, ok := counter_data[""].(uint64) ; ok {
        bfdechocstats.LastPacketReceived = &value
    }

    if value, ok := counter_data[""].(uint64) ; ok {
        bfdechocstats.LastPacketTransmitted = &value
    }

    if value, ok := counter_data["echo-packet-input"].(float64) ; ok {
        value64 := uint64(value)
        bfdechocstats.ReceivedPackets = &value64
    }

    if value, ok := counter_data["echo-packet-output"].(float64) ; ok {
        value64 := uint64(value)
        bfdechocstats.TransmittedPackets = &value64
    }

    if value, ok := counter_data[""].(uint64) ; ok {
        bfdechocstats.UpTransitions = &value
    }*/

    return true;
}

var bfd_mhop_session_tbl_xfmr TableXfmrFunc = func (inParams XfmrParams)  ([]string, error) {
    var tblList []string
    var err error
    var key string
    var output_peer []interface{}

    bfdMapJson := make(map[string]interface{})

    tblList = append(tblList, "BFD_PEER_MULTI_HOP")

    if (inParams.dbDataMap != nil) {
        if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_MULTI_HOP"]; !ok {
                    (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_MULTI_HOP"] = make(map[string]db.Value)
        }
    } else {
        return tblList,nil
    }

    vtysh_cmd := "show bfd peers json"
    output_peer, err = exec_vtysh_cmd_array (vtysh_cmd)
    if err != nil {
        log.Errorf("Failed to fetch bfd peers array:, err")
            return tblList,nil
    }

    log.Info(output_peer)
    bfdMapJson["output"] = output_peer

    sessions, _ := bfdMapJson["output"].([]interface{})

    for _, session := range sessions {
        session_data, _ := session.(map[string]interface{})
        log.Info(session_data)

        if value, ok := session_data["multihop"].(bool) ; ok {
            if value {

                key = ""

                if value, ok := session_data["peer"].(string) ; ok {
                    key = key + value
                }

                if value, ok := session_data["interface"].(string) ; ok {
                    key = key + "|" + *utils.GetUINameFromNativeName(&value)
                } else {
                    key = key + "|" + "null"
                }

                if value, ok := session_data["vrf"].(string) ; ok {
                    key = key + "|" + value
                }

                if value, ok := session_data["local"].(string) ; ok {
                    key = key + "|" + value
                } else {
                    key = key + "|" + "null"
                }

                log.Info(key)

                if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_MULTI_HOP"][key]; !ok {
                            (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_MULTI_HOP"][key] = db.Value{Field: make(map[string]string)}
                }
            }
        }
    }

    return tblList, nil
}

var bfd_shop_session_tbl_xfmr TableXfmrFunc = func (inParams XfmrParams)  ([]string, error) {
    var tblList []string
    var err error
    var key string
    var output_peer []interface{}

    bfdMapJson := make(map[string]interface{})

    tblList = append(tblList, "BFD_PEER_SINGLE_HOP")

    if (inParams.dbDataMap != nil) {
        if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_SINGLE_HOP"]; !ok {
                    (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_SINGLE_HOP"] = make(map[string]db.Value)
        }

    } else {
        return tblList,nil
    }

    vtysh_cmd := "show bfd peers json"
    output_peer, err = exec_vtysh_cmd_array (vtysh_cmd)
    if err != nil {
        log.Errorf("Failed to fetch bfd peers array:, err")
            return tblList,nil
    }

    log.Info(output_peer)
    bfdMapJson["output"] = output_peer

    sessions, _ := bfdMapJson["output"].([]interface{})

    for _, session := range sessions {
        session_data, _ := session.(map[string]interface{})

        if value, ok := session_data["multihop"].(bool) ; ok {
            if !value {

                key = ""

                if value, ok := session_data["peer"].(string) ; ok {
                    key = key + value
                }

                if value, ok := session_data["interface"].(string) ; ok {
                    key = key + "|" + *utils.GetUINameFromNativeName(&value)
                } else {
                    key = key + "|" + "null"
                }

                if value, ok := session_data["vrf"].(string) ; ok {
                    key = key + "|" + value
                }

                if value, ok := session_data["local"].(string) ; ok {
                    key = key + "|" + value
                } else {
                    key = key + "|" + "null"
                }

                log.Info(key)

                if _, ok := (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_SINGLE_HOP"][key]; !ok {
                            (*inParams.dbDataMap)[db.ConfigDB]["BFD_PEER_SINGLE_HOP"][key] = db.Value{Field: make(map[string]string)}
                }
            }
        }
    }

    return tblList, nil
}

var rpc_clear_bfd RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    log.Info("In rpc_clear_bfd")
    var err error
    var status string
    var remoteaddr, vrf_name, localaddr, intfname, multi_hop string
    var cmd string
    var mapData map[string]interface{}

    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        return nil, err
    }

    var result struct {
        Output struct {
              Status string `json:"response"`
        } `json:"sonic-bfd-clear:output"`
    }

    log.Info("In rpc_clear_bfd", mapData)

    input := mapData["sonic-bfd-clear:input"]
    mapData = input.(map[string]interface{})

    log.Info("In rpc_clear_bfd", mapData)

    if value, ok := mapData["remote-address"].(string) ; ok {
        if value != "" {
            remoteaddr = value + " "
        }
    }

    if value, ok := mapData["vrf"].(string) ; ok {
        log.Info("In vrf", value)
        if value != "" {
            vrf_name = value + " "
        }
    }

    if value, ok := mapData["interface"].(string) ; ok {
        if value != "" {
            intfname = value + " "
        }
    }

    if value, ok := mapData["local-address"].(string) ; ok {
        if value != "" {
            localaddr = value + " "
        }
    }

    if value, ok := mapData["multihop"].(string) ; ok {
        if value != "" {
            multi_hop = "multihop "
        }
    }

    log.Info("In rpc_clear_bfd", remoteaddr, vrf_name, intfname, localaddr, multi_hop)

    cmd = cmd + "clear bfd peer " + remoteaddr

    if vrf_name != "" {
        cmd = cmd + "vrf " + vrf_name
    }

    if multi_hop != "" {
        cmd = cmd + multi_hop
    }

    if intfname != "" {
        cmd = cmd + "interface " + intfname
    }

    if localaddr != "" {
        cmd = cmd + "local-address " + localaddr
    }

    cmd = cmd + "counters"

    cmd = strings.TrimSuffix(cmd, " ")
    exec_vtysh_cmd (cmd)
    status = "Success"
    result.Output.Status = status
    return json.Marshal(&result)
}
