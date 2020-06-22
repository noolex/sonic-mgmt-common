package custom_validation

import (
    "fmt"
    util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
    "strings"
	"encoding/json"
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

func (t *CustomValidation) CheckDpbInProgressForPortConfig (vc *CustValidationCtxt) CVLErrorInfo {
	/* Check STATE_DB if any DPB in progress */
	rclient := util.NewDbClient("STATE_DB")
	defer func() {
		if (rclient != nil) {
			rclient.Close()
		}
	}()

	predicate := "return (h['status'] ~= nil and h['status'] == 'InProgress')"
	entries, dbErr := util.FILTER_ENTRIES_LUASCRIPT.Run(rclient, []string{}, "PORT_BREAKOUT|*", "ifname", predicate, "status").Result()
	if dbErr != nil {
		return CVLErrorInfo {
			ErrCode: CVL_FAILURE,
			TableName: "PORT_BREAKOUT",
			ConstraintErrMsg: "Failed to retrieve Port breakout status from Db",
			CVLErrDetails: "Data retrievel Error",
			ErrAppTag:  "dpb-progress-status",
		}
	}
	entriesJson := string(entries.(string))

	var v interface{}
	b := []byte(entriesJson)
	if err := json.Unmarshal(b, &v); err != nil {
		log.Errorf("[DPB-CVL] DPB progress status retrieval failed")
		return CVLErrorInfo{
			ErrCode: CVL_INTERNAL_UNKNOWN,
			TableName: "PORT_BREAKOUT",
			ConstraintErrMsg: "Failed to retrieve Port breakout status from Db",
			CVLErrDetails: "Data retrievel Error",
			ErrAppTag:  "dpb-progress-status",
		}
	}

	var entriesMap map[string]interface{} = v.(map[string]interface{})
	if len(entriesMap) == 0 {
		// No DPB operation in progress
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	} else if len(entriesMap) > 1 {
		// Assumption that there can be only one Port breakout in progress
		return CVLErrorInfo {
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "PORT_BREAKOUT",
			ConstraintErrMsg: "Multiple Ports breakout is in progress",
			CVLErrDetails: "Config Validation Semantic Error",
			ErrAppTag:  "operation-inprogress",
		}
	}

	var brkIntfName string
	for key := range entriesMap["PORT_BREAKOUT"].(map[string]interface{}) {
		brkIntfName = key
		util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "CheckDpbInProgressForPortConfig: DPB in progress for interface: %s", brkIntfName)
	}

	// Skipping DELETE op as DELETE is already taken care during cascade delete
	// Skipping if InProgress interface name is blank
	if vc.CurCfg.VOp == OP_DELETE || len(brkIntfName) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	// For create and update operations, if node is key leaf or non-key leaf,
	// it's value is populated. For leaf-list value may not be populated.
	yangNodeVal := vc.YNodeVal
	yangNodeName := vc.YNodeName
	redisKey := vc.CurCfg.Key
	node := vc.YCur
	rediskeyList := strings.SplitN(redisKey, "|", 2)
	tableName := rediskeyList[0]
	tableKey := rediskeyList[1]

	// Determine if node is a leaf-list node
	var isNodeLeafList bool
	for nodeLeaf := node.FirstChild; nodeLeaf != nil; nodeLeaf = nodeLeaf.NextSibling {
		if (yangNodeName != nodeLeaf.Data) {
			continue
		}
		if (len(nodeLeaf.Attr) > 0) && (nodeLeaf.Attr[0].Name.Local == "leaf-list") {
			isNodeLeafList = true
		}
	}
	util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "CheckDpbInProgressForPortConfig: DPB check on table: %v|%v for node: %v[%v], isleaflist:%t\n", tableName, tableKey, yangNodeName, yangNodeVal, isNodeLeafList)

	if len(yangNodeVal) > 0 {
		// If port name is available from context(vc) and equals to DPB in progress port
		if yangNodeVal == brkIntfName {
			log.Infof("[DPB-CVL] Operation failed on: %v|%v for node: %v[%v] as DPB in progress\n", tableName, tableKey, yangNodeName, yangNodeVal)
			return CVLErrorInfo {
				ErrCode: CVL_SEMANTIC_ERROR,
				TableName: tableName,
				Keys: strings.Split(tableKey, "|"),
				ConstraintErrMsg: fmt.Sprintf("Breakout of port %s in progress", brkIntfName),
				CVLErrDetails: "Config Validation Semantic Error",
				ErrAppTag:  "operation-inprogress",
			}
		} else {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	} else if len(yangNodeVal) == 0 {
		// If port name from context(vc) is blank, check if it is leaf-list. So get from curCfg Data
		if isNodeLeafList && len(vc.CurCfg.Data) > 0 {
			util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "CheckDpbInProgressForPortConfig: Checking leaf-list: %v", vc.CurCfg.Data)
			fldVal, exists := vc.CurCfg.Data[yangNodeName]
			if !exists {
				fldVal, exists = vc.CurCfg.Data[yangNodeName + "@"]
			}
			if exists && strings.Contains(fldVal, brkIntfName) {
				return CVLErrorInfo {
					ErrCode: CVL_SEMANTIC_ERROR,
					TableName: tableName,
					Keys: strings.Split(tableKey, "|"),
					ConstraintErrMsg: fmt.Sprintf("Breakout of port %s in progress", brkIntfName),
					CVLErrDetails: "Config Validation Semantic Error",
					ErrAppTag:  "operation-inprogress",
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
