package custom_validation

import (
    "net"
    util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
    //util "cvl/internal/util"
    "strings"
    "fmt"
    log "github.com/golang/glog"

 )

//Purpose: Check correct for correct agent_id
//vc : Custom Validation Context
//Returns -  CVL Error object
func (t *CustomValidation) ValidateDpbConfigs(
       vc *CustValidationCtxt) CVLErrorInfo {

       log.Info("DpbValidateInterfaceConfigs operation: ", vc.CurCfg.VOp, 
                " Key: ", vc.CurCfg.Key, " Data: ", vc.CurCfg.Data,
                " Req Data: ", vc.ReqData)
       if (vc.CurCfg.VOp == OP_DELETE) {
               return CVLErrorInfo{ErrCode: CVL_SUCCESS}
       }

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

       for _, dbKey := range tableKeys {
               tmp := strings.Replace(dbKey, "PORT|", "", 1)
               log.Info("DpbValidateInterfaceConfigs dbKey ", tmp)
               if (tmp == vc.YNodeVal) {
                       return CVLErrorInfo{ErrCode: CVL_SUCCESS}
               }
       }
       /* check if input passed is found in list of network interfaces (includes, network_if, mgmt_if, and loopback) */
       ifaces, err2 := net.Interfaces()
       if err2 != nil {
               log.Info("DpbValidateInterfaceConfigs Error getting network interfaces")
               errStr := "Error getting network interfaces"
               return CVLErrorInfo{
                       ErrCode: CVL_SEMANTIC_ERROR,
                       TableName: "PORT",
                       CVLErrDetails : errStr,
                       ConstraintErrMsg : errStr,
               }
       }

       found := false
       for _, i := range ifaces {
               if (i.Name == vc.YNodeVal) {
                       log.Info("DpbValidateInterfaceConfigs i.Name ", i.Name)
                        found = true
                       return CVLErrorInfo{ErrCode: CVL_SUCCESS}
               }
       }
       if found == false {
            errStr := "Interface not found"
            return CVLErrorInfo{
                       ErrCode: CVL_SEMANTIC_ERROR,
                       TableName: "PORT",
                       CVLErrDetails : errStr,
                       ConstraintErrMsg : errStr,
            }
       } else {
            return CVLErrorInfo{ErrCode: CVL_SUCCESS}
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
            TableName: "PORT_TABLE",
            Keys: strings.Split(vc.CurCfg.Key, "|"),
            ConstraintErrMsg: fmt.Sprintf("Failed to connect to STATE_DB"),
            CVLErrDetails: "Config Validation Error",
            ErrAppTag:  "capability-unsupported",
        }
    }

    for idx := 0; idx < len(vc.ReqData); idx++ {
        if (vc.ReqData[idx].VOp == OP_DELETE) &&
            (strings.HasPrefix(vc.ReqData[idx].Key, "PORT|")) {
            key := strings.Replace(vc.ReqData[idx].Key, "PORT|", "PORT_TABLE:", 1)

            port_state, err := rclient.HGetAll(key).Result()
            if (err != nil) {
                util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "PORT_TABLE is empty or invalid argument")
                return CVLErrorInfo{
                    ErrCode: CVL_SEMANTIC_ERROR,
                    TableName: "PORT_TABLE",
                    Keys: strings.Split(vc.CurCfg.Key, ":"),
                    ConstraintErrMsg: fmt.Sprintf("Another breakout is in progress"),
                    CVLErrDetails: "Config Validation Error",
                    ErrAppTag:  "capability-unsupported",
                }
            } else {
                _, err := port_state["state"]
                if (!err) {
                    util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "PORT_TABLE is empty or invalid argument")
                    return CVLErrorInfo{
                        ErrCode: CVL_SEMANTIC_ERROR,
                        TableName: "PORT_TABLE",
                        Keys: strings.Split(vc.CurCfg.Key, ":"),
                        ConstraintErrMsg: fmt.Sprintf("Another breakout is in progress"),
                        CVLErrDetails: "Config Validation Error",
                        ErrAppTag:  "capability-unsupported",
                    }
                }
            }
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

