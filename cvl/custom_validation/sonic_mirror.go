package custom_validation

import (
    log "github.com/golang/glog"
    "reflect"
    "strings"
    util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
 )

//ValidateDstIp validates whether dst_ip is configured in any other session
func (t *CustomValidation) ValidateDstIp(vc *CustValidationCtxt) CVLErrorInfo {
    if (vc.CurCfg.VOp == OP_DELETE) {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }
    keys, err := vc.RClient.Keys("MIRROR_SESSION|*").Result()
    if err == nil {
        for _, key := range keys {
            /* for each mirror session */
            if key == vc.CurCfg.Key {
                log.Info("ValidateDstIp: Skip current session ", key)
                continue
            }

            entry, err := vc.RClient.HGet(key, "dst_ip").Result()
            if (err == nil) && (entry == vc.YNodeVal) {
                log.Error("ValidateDstIp: ", vc.YNodeVal, " already configured: ")
                errStr := "Destination IP already configured in other mirror session"
                return CVLErrorInfo{
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: "MIRROR_SESSION",
                    CVLErrDetails : errStr,
                    ConstraintErrMsg : errStr,
                }
            }
        }
    }

    log.Info("ValidateDstIp ", vc.YNodeVal, " success")
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//ValidateSrcPort validates all soruce port validations
func (t *CustomValidation) ValidateSrcPort(vc *CustValidationCtxt) CVLErrorInfo {

    if (vc.CurCfg.VOp == OP_DELETE) {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }
    keys, err := vc.RClient.Keys("MIRROR_SESSION|*").Result()
    if err == nil {
        for _, key := range keys {
            /* for each mirror session */
            if key == vc.CurCfg.Key {
                log.Info("ValidateSrcPort: Skip current session ", key)
                continue
            }

            entry, err := vc.RClient.HGet(key, "dst_port").Result()
            if (err == nil) && (entry == vc.YNodeVal) {
                log.Error("ValidateSrcPort: ", vc.YNodeVal, " already configured in ", key)
                errStr := "Source port already configured as destination in other mirror session"
                return CVLErrorInfo{
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: "MIRROR_SESSION",
                    CVLErrDetails : errStr,
                    ConstraintErrMsg : errStr,
                }
            }
        }
    }
    log.Info("ValidateSrcPort ", vc.YNodeVal, " success")
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//ValidateDstPort validates whether destination port has any VLAN configuration
func (t *CustomValidation) ValidateDstPort(vc *CustValidationCtxt) CVLErrorInfo {

    if (vc.CurCfg.VOp == OP_DELETE) {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    /* check if input passed is found in ConfigDB VLAN_MEMBER|* */
    tableKeys, err:= vc.RClient.Keys("VLAN_MEMBER|*|" + vc.YNodeVal).Result()
    if (err != nil) || (vc.SessCache == nil) {
        log.Error("Error reading VLAN_MEMBER Table")
        errStr := "Destination port validation failure"
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "VLAN_MEMBER",
            CVLErrDetails : errStr,
            ConstraintErrMsg : errStr,
        }
    }

    s := reflect.ValueOf(tableKeys)
    if (s.Len() > 0) {
        log.Error("ValidateDstPortVlanMember: ", vc.YNodeVal, " has vlans configuration: ", s.Len())
        errStr := "Destination port has VLAN config"
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "VLAN_MEMBER",
            CVLErrDetails : errStr,
            ConstraintErrMsg : errStr,
        }
    }

    log.Info("ValidateDstPortVlanMember: ", vc.YNodeVal, " has no vlan configuration: ", s.Len())

    // Verify if port is already member of any portchannel
    pomemberKeys, _ := vc.RClient.Keys("PORTCHANNEL_MEMBER|*|" + vc.YNodeVal).Result()
    if len(pomemberKeys) > 0 {
        log.Error("ValidateDstPortVlanMember: ", vc.YNodeVal, " has vlans configuration: ", s.Len())
        errStr := "Destination port is part of portchannel"
        return CVLErrorInfo {
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "VLAN_MEMBER",
            CVLErrDetails : errStr,
            ConstraintErrMsg : errStr,
        }
    }

    keys, err := vc.RClient.Keys("MIRROR_SESSION|*").Result()
    if err == nil {
        for _, key := range keys {
            /* for each mirror session */
            if key == vc.CurCfg.Key {
                log.Info("ValidateDstIp: Skip current session ", key)
                continue
            }

            entry, err := vc.RClient.HGet(key, "src_port").Result()
            if (err == nil) && (entry == vc.YNodeVal) {
                log.Error("ValidateDstPort: ", vc.YNodeVal, " already configured in ", key)
                errStr := "Destination port already configured as source in other mirror session"
                return CVLErrorInfo{
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: "MIRROR_SESSION",
                    CVLErrDetails : errStr,
                    ConstraintErrMsg : errStr,
                }
            }
        }
    }

    /* Disabling LLDP validation until FT scripts are taken care 
    // check if LLDP is disabled on port
    lldpData, err1 := vc.RClient.HGetAll("LLDP_PORT|" + vc.YNodeVal).Result() 
    // By default LLDP is enabled
    if err1 != nil {
        log.Error("ValidateDstPort has LLDP enabled: ", vc.YNodeVal)
        errStr := "Destination port has LLDP enabled"
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "LLDP_PORT",
            CVLErrDetails : errStr,
            ConstraintErrMsg : errStr,
        }
    }

    if lldpData["enabled"] != "false" {
        log.Error("ValidateDstPort: ", vc.YNodeVal, " has LLDP: ", lldpData["enabled"])
        errStr := "Destination port has LLDP enabled"
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "LLDP_PORT",
            CVLErrDetails : errStr,
            ConstraintErrMsg : errStr,
        }
    }

    log.Info("ValidateDstPort: ", vc.YNodeVal, "has LLDP: ", lldpData["enabled"])
    */
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//ValidateMirrorSessions validates whether mirror sessions are available and session is not active.
func (t *CustomValidation) ValidateMirrorSessions(vc *CustValidationCtxt) CVLErrorInfo {

    if (vc.CurCfg.VOp == OP_DELETE) {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    stateDBClient := util.NewDbClient("STATE_DB")
    defer func() {
        if (stateDBClient != nil) {
            stateDBClient.Close()
        }
    }()

    if (stateDBClient != nil) {
        key := "MIRROR_SESSION_TABLE|mirror_capability"
        available_count, err := stateDBClient.HGet(key, "available_count").Result()

        if (err == nil) {
            if (available_count == "0") {
                log.Error("ValidateMirrorSessions: Exceed max active sessions.", available_count)
                errStr := "Maximum sessions already configured"
                return CVLErrorInfo{
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: "MIRROR_SESSION_TABLE",
                    CVLErrDetails : errStr,
                    ConstraintErrMsg : errStr,
                }
            }
        }
        log.Info("ValidateMirrorSessions: available_sessions ", available_count)
        keys := strings.Split(vc.CurCfg.Key, "|")
        session_status, err := stateDBClient.HGet("MIRROR_SESSION_TABLE|" + keys[1], "status").Result()
        if (err == nil) {
            if (session_status == "active") {
                log.Error("ValidateMirrorSessions: Session ", keys[1] ," already active. Update not supported ", session_status)
                errStr := "Mirror session is already active. Update not supported"
                return CVLErrorInfo{
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: "MIRROR_SESSION_TABLE",
                    CVLErrDetails : errStr,
                    ConstraintErrMsg : errStr,
                }
            }
        }
        log.Error("ValidateMirrorSessions: Session ", keys[1] ," is not active. ")
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
