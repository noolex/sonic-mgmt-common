package custom_validation

import (
    //"net"
    util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
    "strings"
    log "github.com/golang/glog"

 )

//ValidateDpbConfigs Purpose: Check correct for correct agent_id
//vc : Custom Validation Context
//Returns -  CVL Error object
func (t *CustomValidation) ValidateDpbConfigs(
       vc *CustValidationCtxt) CVLErrorInfo {

       log.Info("DpbValidateInterfaceConfigs operation: ", vc.CurCfg.VOp, 
                " Key: ", vc.CurCfg.Key, " Data: ", vc.CurCfg.Data,
                " Req Data: ", vc.ReqData)

       log.Info("DpbValidateInterfaceConfigs YNodeVal: ", vc.YNodeVal)

       /* check if input passed is found in ConfigDB PORT|* */
       tableKeys, err:= vc.RClient.Keys("PORT|*").Result()

       if (err != nil) || (vc.SessCache == nil) {
               log.Info("DpbValidateInterfaceConfigs PORT is empty or invalid argument")
               errStr := "ConfigDB PORT list is empty"
               return CVLErrorInfo{
                       ErrCode: CVL_SEMANTIC_ERROR,
                       TableName: "PORT",
                       CVLErrDetails : errStr,
                       ConstraintErrMsg : errStr,
               }
       }
       found := false
       for _, dbKey := range tableKeys {
               tmp := strings.Replace(dbKey, "PORT|", "", 1)
               if (tmp == vc.YNodeVal) {
                    log.Info("DpbValidateInterfaceConfigs dbKey ", tmp)
                    found = true
               }
       }
       if !found {
            errStr := "Interface not found"
            return CVLErrorInfo{
                       ErrCode: CVL_SEMANTIC_ERROR,
                       TableName: "PORT",
                       CVLErrDetails : errStr,
                       ConstraintErrMsg : errStr,
            }
       }

    return CVLErrorInfo{ErrCode: CVL_SUCCESS}

}


//ValidateDpbStatus Purpose: Check if DPB is in progress
//vc : Custom Validation Context
//Returns -  CVL Error object
func (t *CustomValidation) ValidateDpbStatus(
       vc *CustValidationCtxt) CVLErrorInfo {

    key := strings.Replace(vc.CurCfg.Key, "PORT|", "BREAKOUT_PORTS|", 1)
    log.Info("ValidateDpbStatus: ", vc.CurCfg.VOp, 
                " Key: ", vc.CurCfg.Key, " Data: ", vc.CurCfg.Data,
                " Req Data: ", vc.ReqData)
    entry, err := vc.RClient.HGetAll(key).Result()
    if (err == nil && len(entry) > 0 && len(entry["master"]) > 0) {
        key = "PORT_BREAKOUT|" + entry["master"]
    } else {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }
    log.Info("Master port for ", key, " is ", entry["master"])
    _, ok := vc.CurCfg.Data["lanes"]
    if (vc.CurCfg.VOp == OP_CREATE) && (!ok) {
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "PORT",
            Keys: strings.Split(vc.CurCfg.Key, "|"),
            ConstraintErrMsg: "Port does not exist",
            CVLErrDetails: "Config Validation Error",
            ErrAppTag:  "invalid-port",
        }
    }

    /* Check STATE_DB if port state of the port s getting deleted is OK */
    rclient := util.NewDbClient("STATE_DB")
    defer func() {
        if (rclient != nil) {
            rclient.Close()
        }
    }()

    if (rclient == nil) {
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "BREAKOUT_PORTS",
            Keys: strings.Split(vc.CurCfg.Key, "|"),
            ConstraintErrMsg: "Failed to connect to STATE_DB",
            CVLErrDetails: "Config Validation Error",
            ErrAppTag:  "capability-unsupported",
        }
    }

    entry, err1 := rclient.HGetAll(key).Result()
    log.Info("[DPB-CVL] STATE_DB DPB key ", key, " Entry: ", entry, " ", err1)
    if ((err1 == nil) && (len(entry) > 0) && (len(entry["status"]) > 0) && (entry["status"] == "InProgress")) {
        util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "STATE_DB DPB table has entry. DPB in-progress")
        return CVLErrorInfo{
                ErrCode: CVL_SEMANTIC_ERROR,
                TableName: "BREAKOUT_CFG",
                Keys: strings.Split(vc.CurCfg.Key, ":"),
                ConstraintErrMsg: "Port breakout is in progress. Try later.",
                CVLErrDetails: "Config Validation Error",
                ErrAppTag:  "operation-inprogress",
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

