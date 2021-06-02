package custom_validation

import (
	"strings"

	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
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
	tableKeys, err := vc.RClient.Keys("PORT|*").Result()

	if (err != nil) || (vc.SessCache == nil) {
		log.Info("DpbValidateInterfaceConfigs PORT is empty or invalid argument")
		errStr := "ConfigDB PORT list is empty"
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        "PORT",
			CVLErrDetails:    errStr,
			ConstraintErrMsg: errStr,
		}
	}
	found := false
	for _, dbKey := range tableKeys {
		tmp := strings.Replace(dbKey, "PORT|", "", 1)
		if tmp == vc.YNodeVal {
			log.Info("DpbValidateInterfaceConfigs dbKey ", tmp)
			found = true
		}
	}
	if !found {
		errStr := "Interface not found"
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        "PORT",
			CVLErrDetails:    errStr,
			ConstraintErrMsg: errStr,
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
	if err == nil && len(entry) > 0 && len(entry["master"]) > 0 {
		key = "PORT_BREAKOUT|" + entry["master"]
	} else {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	log.Info("Master port for ", key, " is ", entry["master"])
	_, ok := vc.CurCfg.Data["lanes"]
	if (vc.CurCfg.VOp == OP_CREATE) && (!ok) {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        "PORT",
			Keys:             strings.Split(vc.CurCfg.Key, "|"),
			ConstraintErrMsg: "Port does not exist",
			CVLErrDetails:    "Config Validation Error",
			ErrAppTag:        "invalid-port",
		}
	}

	/* Check STATE_DB if port state of the port s getting deleted is OK */
	rclient := util.NewDbClient("STATE_DB")
	defer func() {
		if rclient != nil {
			rclient.Close()
		}
	}()

	if rclient == nil {
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        "BREAKOUT_PORTS",
			Keys:             strings.Split(vc.CurCfg.Key, "|"),
			ConstraintErrMsg: "Failed to connect to STATE_DB",
			CVLErrDetails:    "Config Validation Error",
			ErrAppTag:        "capability-unsupported",
		}
	}

	entry, err1 := rclient.HGetAll(key).Result()
	log.Info("[DPB-CVL] STATE_DB DPB key ", key, " Entry: ", entry, " ", err1)
	if (err1 == nil) && (len(entry) > 0) && (len(entry["status"]) > 0) && (entry["status"] == "InProgress") {
		util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "STATE_DB DPB table has entry. DPB in-progress")
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        "BREAKOUT_CFG",
			Keys:             strings.Split(vc.CurCfg.Key, ":"),
			ConstraintErrMsg: "Port breakout is in progress. Try later.",
			CVLErrDetails:    "Config Validation Error",
			ErrAppTag:        "breakout-in-progress",
		}
	}
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) CheckDpbInProgressForPortConfig(vc *CustValidationCtxt) CVLErrorInfo {
	// Skipping DELETE op as DELETE is already taken care during cascade delete
	if vc.CurCfg.VOp == OP_DELETE {
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
		if yangNodeName != nodeLeaf.Data {
			continue
		}
		if (len(nodeLeaf.Attr) > 0) && (nodeLeaf.Attr[0].Name.Local == "leaf-list") {
			isNodeLeafList = true
		}
	}
	util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "CheckDpbInProgressForPortConfig: DPB check on table: %v|%v for node: %v[%v], isleaflist:%t\n", tableName, tableKey, yangNodeName, yangNodeVal, isNodeLeafList)

	var intfNameToCheck string
	// Determine the interface name on which operation is happening
	if len(yangNodeVal) > 0 {
		intfNameToCheck = yangNodeVal
	} else {
		// If port name from context(vc) is blank, check if it is leaf-list. So get from curCfg Data
		if isNodeLeafList && len(vc.CurCfg.Data) > 0 {
			correctNodeName := yangNodeName
			fldVal, exists := vc.CurCfg.Data[yangNodeName]
			if !exists {
				fldVal, exists = vc.CurCfg.Data[yangNodeName+"@"]
				if exists {
					correctNodeName = yangNodeName + "@"
				}
			}
			util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "CheckDpbInProgressForPortConfig: leaf-list data from Request: %v", fldVal)
			if exists && (len(fldVal) > 0) {
				// On adding or deleting element to leaf-list, always generates UPDATE request
				// and yangNodeVal may be empty. So to determine the correct interface on which
				// operation is going, we need to query all elements of leaf-list from DB and
				// compare with leaf-list received in CurCfg.Data.
				tblData, _ := vc.RClient.HGetAll(redisKey).Result()
				dbNodeVal := tblData[correctNodeName]
				util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "CheckDpbInProgressForPortConfig: leaf-list data from DB: %v", dbNodeVal)

				// Data in DB is not present, means new element getting added
				if len(dbNodeVal) == 0 {
					intfNameToCheck = fldVal
				} else {
					elemFromDb := strings.Split(dbNodeVal, ",")
					elemfromReq := strings.Split(fldVal, ",")
					// Adding interface to leaf-list have entry in request but not in DB
					// Deleting interface from leaf-list have entry in DB but not in request
					// So their difference will provide the interface under operation
					elems := util.GetDifference(elemFromDb, elemfromReq)
					if len(elems) > 0 {
						// Only 1 interface under operation, so assuming that length is 1
						intfNameToCheck = elems[0]
					}
				}
			}
		}
	}
	util.CVL_LEVEL_LOG(util.INFO, "CheckDpbInProgressForPortConfig: operation in progress for interface: %s", intfNameToCheck)

	// Skipping if interface name could not be determined
	if len(intfNameToCheck) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	// Some yang nodes have union type and so value can be PortChannel or Vlan also
	// Check if the interface is from PORT table. Otherwise return success
	portTblKey, _ := vc.RClient.Keys("PORT|" + intfNameToCheck).Result()
	if len(portTblKey) == 0 {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	// Get Master port information from BREAKOUT_PORTS table in config Db.
	mpdata, _ := vc.RClient.HGetAll("BREAKOUT_PORTS|" + intfNameToCheck).Result()
	// If entry does not exists in BREAKOUT_PORTS it means breakout didn't happended
	// so consider intfNameToCheck as master port
	masterPortName, exists := mpdata["master"]
	if !exists {
		masterPortName = intfNameToCheck
	}
	util.CVL_LEVEL_LOG(util.INFO, "CheckDpbInProgressForPortConfig: DPB status check for Master port: %s", masterPortName)

	/* Check STATE_DB if any DPB in progress */
	rclient := util.NewDbClient("STATE_DB")
	defer func() {
		if rclient != nil {
			rclient.Close()
		}
	}()

	statusData, dbErr := rclient.HGetAll("PORT_BREAKOUT|" + masterPortName).Result()
	if dbErr != nil {
		return CVLErrorInfo{
			ErrCode:          CVL_FAILURE,
			TableName:        "PORT_BREAKOUT",
			ConstraintErrMsg: "Failed to retrieve Port breakout status",
			CVLErrDetails:    "Data retrievel Error",
			ErrAppTag:        "dpb-progress-status",
		}
	}

	dpbStatus, exists := statusData["status"]
	if !exists || len(dpbStatus) == 0 {
		// DPB status is not in STATE_DB. No DPB in process
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	// if DPB status is InProgress, return error
	if dpbStatus == "InProgress" {
		util.CVL_LEVEL_LOG(util.WARNING, "[DPB-CVL] Operation failed on: %v|%v for node: %v[%v] as breakout of %s in progress\n", tableName, tableKey, yangNodeName, yangNodeVal, masterPortName)
		return CVLErrorInfo{
			ErrCode:          CVL_SEMANTIC_ERROR,
			TableName:        tableName,
			Keys:             strings.Split(tableKey, "|"),
			ConstraintErrMsg: "Breakout of port in progress",
			CVLErrDetails:    "Config Validation Semantic Error",
			ErrAppTag:        "breakout-in-progress",
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
