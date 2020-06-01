package transformer

import (
    "errors"
    "strings"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init () {
    XlateFuncBind("YangToDb_pim_gbl_tbl_key_xfmr", YangToDb_pim_gbl_tbl_key_xfmr)
    XlateFuncBind("YangToDb_pim_intf_tbl_key_xfmr", YangToDb_pim_intf_tbl_key_xfmr)
    XlateFuncBind("YangToDb_pim_intf_mode_fld_xfmr", YangToDb_pim_intf_mode_fld_xfmr)
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
    intf := pathInfo.Var("interface-id")
    if (len(intf) == 0) {
        return "", errors.New("interface name is missing")
    }

    log.Info("YangToDb_pim_intf_tbl_key_xfmr : URI:", inParams.uri, " VRF:", niName, " Interface:", intf)

    return (niName + "|" + "ipv4" + "|" + intf), err
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
