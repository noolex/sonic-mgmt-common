package custom_validation

import (
        "strings"
        log "github.com/golang/glog"
        "net"
)

// ValidateMgmtIntfGwAddr check gw addr should be in the same subnet as mgmt intf IP
func (t *CustomValidation) ValidateMgmtIntfGwAddr(vc *CustValidationCtxt) CVLErrorInfo {

        log.Info("ValidateMgmtIntfGwAddr op:", vc.CurCfg.VOp, " key:", vc.CurCfg.Key, " data:", vc.CurCfg.Data, "vc.ReqData: ", vc.ReqData, "vc.SessCache", vc.SessCache)

        // If delete op or gw not configured, return success
        if (vc.YNodeVal == "") || (vc.CurCfg.VOp == OP_DELETE) {
                return CVLErrorInfo{ErrCode: CVL_SUCCESS}
        }

        key := vc.CurCfg.Key
        key_split := strings.Split(key, "|")
        ip_prefix := key_split[2]

        gw_addr := vc.YNodeVal

        log.Info("ValidateMgmtIntfGwAddr, mgmt ip: ", ip_prefix, " gw addr:", gw_addr)

        _, ipnet, _ := net.ParseCIDR(ip_prefix)
        gw := net.ParseIP(gw_addr)

        if ipnet.Contains(gw) {
                log.Info("ValidateMgmtIntfGwAddr, gw addr validation pass")
                return CVLErrorInfo{ErrCode: CVL_SUCCESS}
        } else {
                errStr := "Gateway address not in the same subnet as mgmt IP"
                log.Error(errStr)

                return CVLErrorInfo {
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: vc.CurCfg.Key,
                    CVLErrDetails: errStr,
                    ConstraintErrMsg: errStr,
                }
        }
}
