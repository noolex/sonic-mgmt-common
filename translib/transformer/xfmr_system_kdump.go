package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "strconv"
    "fmt"
    "encoding/json"
    log "github.com/golang/glog"
    ygot "github.com/openconfig/ygot/ygot"
)

func init () {
    XlateFuncBind("DbToYang_oc_kdump_status_xfmr", DbToYang_oc_kdump_status_xfmr)
    XlateFuncBind("DbToYang_oc_kdump_config_xfmr", DbToYang_oc_kdump_config_xfmr)
    XlateFuncBind("YangToDb_oc_kdump_config_xfmr", YangToDb_oc_kdump_config_xfmr)

}

/*App specific constants */
const (
    KDUMP_STATUS_ADMIN_MODE         = "enable"
    KDUMP_STATUS_OPER_STATE         = "current-state"
    KDUMP_STATUS_MEMORY             = "memory"
    KDUMP_STATUS_MEMORY_ALLOC       = "allocated-memory"
    KDUMP_STATUS_NUM_DUMPS          = "max-dumps"
    KDUMP_RECORDS_LIST              = "kdump-record"
    KDUMP_RECORDS_KEY               = "id"
    KDUMP_RECORDS_CRASH_LOG_FILENAME = "vmcore-diagnostic-message-file"
    KDUMP_RECORDS_CRASH_LOG         = "vmcore-diagnostic-message"
    KDUMP_RECORDS_VMCORE            = "vmcore"
)

/* App specific type definitions */

type kdumpStatusCache struct {
    kdumpStatusMap map[string]string
    kdumpRecordMap map[string]map[string]string
}

/* App specific utilities */

/* Initialise kdump status cache Data structure */

func kdumpCacheInit(statusCache *kdumpStatusCache) {
    statusCache.kdumpStatusMap = make(map[string]string)
    statusCache.kdumpRecordMap = make(map[string]map[string]string)
}

/* Get ygot root object */

func getKdumpRoot (s *ygot.GoStruct) (*ocbinds.OpenconfigSystem_System_Kdump) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.System.Kdump
}

/* Wrapper to call host service to perform kdump operations */

func kdumpAction(action string, options [2]string) (string, error) {
	var output string
        var result HostResult
	// result.Body is of type []interface{}, since any data may be returned by
	// the host server. The application is responsible for performing
	// type assertions to get the correct data.
        if (action == "status" || action == "getconfig") {
	    result = HostQuery("KDUMP." + action)
        } else {
	    result = HostQuery("KDUMP." + action, options)
        }
	if result.Err != nil {
		return output, result.Err
	}
	if (action == "status" || action == "getconfig") {
		// KDUMP.status returns an exit code and the stdout of the command
		// We only care about the stdout (which is at [1] in the slice)
		output, _ = result.Body[0].(string)
        }
        return output, nil
}

/* Function to populate kdump status data structure with the status info from host service */

func getKdumpStatusFromHost(statusCache * kdumpStatusCache, hostData map[string] interface{}) {

    temp := hostData
    for attr,val := range temp {
	switch attr {
	    case KDUMP_STATUS_ADMIN_MODE:
		statusCache.kdumpStatusMap[KDUMP_STATUS_ADMIN_MODE] = fmt.Sprintf("%t",val)
	    case KDUMP_STATUS_OPER_STATE:
    		statusCache.kdumpStatusMap[KDUMP_STATUS_OPER_STATE] = fmt.Sprintf("%v",val)
	    case KDUMP_STATUS_MEMORY:
    		statusCache.kdumpStatusMap[KDUMP_STATUS_MEMORY] = fmt.Sprintf("%v",val)
	    case KDUMP_STATUS_MEMORY_ALLOC:
    		statusCache.kdumpStatusMap[KDUMP_STATUS_MEMORY_ALLOC] = fmt.Sprintf("%v",val)
	    case KDUMP_STATUS_NUM_DUMPS:
    		statusCache.kdumpStatusMap[KDUMP_STATUS_NUM_DUMPS] = fmt.Sprint(val)
	    default:
		log.Info("Invalid attr:",attr)
	}
   }
}

/* Function to populate kdump records data structure with info from host service */

func getKdumpRecord(recordId string, dataMap map[string]interface{}, statusCache *kdumpStatusCache) {
    statusCache.kdumpRecordMap[recordId] = make(map[string]string)
    for attr,val := range dataMap {
	switch attr {
	    case KDUMP_RECORDS_KEY:
    		statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_KEY] = recordId
            case KDUMP_RECORDS_CRASH_LOG_FILENAME:
    		statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_CRASH_LOG_FILENAME] = fmt.Sprintf("%v",val)
            case KDUMP_RECORDS_CRASH_LOG:
    		statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_CRASH_LOG] = fmt.Sprintf("%v",val)
            case KDUMP_RECORDS_VMCORE:
    		statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_VMCORE] = fmt.Sprintf("%v",val)
            case KDUMP_RECORDS_LIST:
	    default:
    		log.Info("Invalid attr:",attr)
	}
    }
}

/* Populate kdump status ygot tree */

func populateKdumpStatusYgotTree(statusObj *ocbinds.OpenconfigSystem_System_Kdump_State, statusCache *kdumpStatusCache) {

    if value,present := statusCache.kdumpStatusMap[KDUMP_STATUS_ADMIN_MODE]; present {
        admin := new(bool)
        *admin,_ =  strconv.ParseBool(value)
        statusObj.Enable =  admin
    }
    if value,present :=statusCache.kdumpStatusMap[KDUMP_STATUS_OPER_STATE]; present {
        if value == "Ready after Reboot" {
            statusObj.CurrentState = ocbinds.OpenconfigKdump_KdumpCurrentState_KDUMP_READY_AFTER_REBOOT;
        } else if value == "Ready" {
            statusObj.CurrentState = ocbinds.OpenconfigKdump_KdumpCurrentState_KDUMP_READY;
        } else {
            statusObj.CurrentState = ocbinds.OpenconfigKdump_KdumpCurrentState_KDUMP_DISABLED;
        }
    }
    if value,present := statusCache.kdumpStatusMap[KDUMP_STATUS_MEMORY]; present {
        mem := value
        statusObj.Memory = &mem
    }
    if value,present := statusCache.kdumpStatusMap[KDUMP_STATUS_NUM_DUMPS]; present {
        numd := new(uint64)
        num8 := new(uint8)
        *numd,_ =  strconv.ParseUint(value, 10, 64)
        *num8 = uint8 (*numd)
        statusObj.MaxDumps =  num8
    }
    if value,present := statusCache.kdumpStatusMap[KDUMP_STATUS_MEMORY_ALLOC]; present {
        numd := new(uint64)
        *numd,_ =  strconv.ParseUint(value, 10, 64)
        statusObj.AllocatedMemory = numd
    }
}

/* Populate kdump records ygot tree */

func populateKdumpRecordYgotTree(recordId string, recordObj *ocbinds.OpenconfigSystem_System_Kdump_State_KdumpRecord, statusCache *kdumpStatusCache) {
    if value,present := statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_KEY]; present {
        rkey := value
        recordObj.Id = &rkey
    }
    if value,present := statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_CRASH_LOG_FILENAME]; present {
        logFile := value
        recordObj.VmcoreDiagnosticMessageFile = &logFile
    }
    if value,present := statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_CRASH_LOG]; present {
        log := value
        recordObj.VmcoreDiagnosticMessage = &log
    }
    if value,present := statusCache.kdumpRecordMap[recordId][KDUMP_RECORDS_VMCORE]; present {
        vmc := value
        recordObj.Vmcore = &vmc
    }
}

/* Get status info from db */

func getKdumpStatusInfofromDb( statusObj *ocbinds.OpenconfigSystem_System_Kdump_State, statusCache *kdumpStatusCache ) (error) {

    log.Info("Entered kdump status info from db")
    act:= "status"
    var args [2]string
    mess, err:= kdumpAction(act, args)
    if err != nil {
	log.Error("Error from sonic host service:",err)
        return err
    }
    
    var hostData map[string] interface{}
    err = json.Unmarshal([]byte (mess),&hostData)
    if err != nil {
	log.Error("kdump json unmarshal error:",err)
        return err
    }

    getKdumpStatusFromHost(statusCache,hostData)
    populateKdumpStatusYgotTree(statusObj, statusCache)
    if kdumpRecordsList, present := hostData[KDUMP_RECORDS_LIST]; present {
	    for record, dataMap := range kdumpRecordsList.(map[string]interface{}) {
                kdumpRecordList, err :=statusObj.NewKdumpRecord(record)
	        if err != nil {
                    log.Error("Creation of kdumprecords subtree failed!")
                    return err
                }
                ygot.BuildEmptyTree(kdumpRecordList)
                getKdumpRecord(record, dataMap.(map[string]interface{}), statusCache)
                populateKdumpRecordYgotTree(record, kdumpRecordList, statusCache)
            }
        }
    return nil;
}

/* Wrapper to kdump status related function calls */

func getKdumpStatus(kdumpObj *ocbinds.OpenconfigSystem_System_Kdump) (error) {

    if kdumpObj.State == nil {
	ygot.BuildEmptyTree(kdumpObj)
    }
    statusObj := kdumpObj.State
    ygot.BuildEmptyTree(statusObj)
    var statusCache kdumpStatusCache
    kdumpCacheInit(&statusCache)
    err :=  getKdumpStatusInfofromDb(statusObj, &statusCache)
    return err
}

/* Transformer specific functions */

var DbToYang_oc_kdump_status_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {

    kdumpObj := getKdumpRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Error("Failed to retrieve TARGET URI PATH")
        return err
    }
    log.Info("TARGET URI PATH KDUMP:", targetUriPath)
    if targetUriPath == "/openconfig-system:system/openconfig-system-ext:kdump/state" {
	log.Info("TARGET URI PATH KDUMP:", targetUriPath)
        log.Info("TableXfmrFunc - Uri KDUMP: ", inParams.uri);
        err =  getKdumpStatus(kdumpObj)
	return err
    } else {
	return nil
    }
}

var DbToYang_oc_kdump_config_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    kdumpObj := getKdumpRoot(inParams.ygRoot)
    log.Info("TableXfmrFunc - Uri KDUMP: ", inParams.uri);
    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Error("Failed to retrieve TARGET URI PATH")
        return err
    }
    log.Info("TARGET URI PATH KDUMP:", targetUriPath)

    act:= "getconfig"
    var args [2]string
    mess, err := kdumpAction(act, args)
    if err != nil {
        log.Error("Error from host service:",err)
        return err
    }

    var hostData map[string] interface{}
    err = json.Unmarshal([]byte (mess),&hostData)
    if err != nil {
        log.Error("kdump json unmarshal error:",err)
        return err
    }

    if kdumpObj.Config == nil {
	ygot.BuildEmptyTree(kdumpObj)
    }
    configObj := kdumpObj.Config
    ygot.BuildEmptyTree(configObj)

    for attr,val := range hostData {
        switch attr {
            case KDUMP_STATUS_ADMIN_MODE:
                var mode_str = fmt.Sprintf("%t",val)
                mode := new(bool)
                *mode,_ =  strconv.ParseBool(mode_str)
                configObj.Enable = mode
            case KDUMP_STATUS_MEMORY:
                var mem_str = fmt.Sprintf("%v",val)
                mem := mem_str
                configObj.Memory = &mem
            case KDUMP_STATUS_NUM_DUMPS:
                var numd_str = fmt.Sprint(val)
                numd := new(uint64)
                num8 := new(uint8)
                *numd,_ =  strconv.ParseUint(numd_str, 10, 64)
                *num8 = uint8(*numd)
                configObj.MaxDumps = num8
            default:
                log.Error("Invalid attr:",attr)
        }
   }
   return err;

}

var YangToDb_oc_kdump_config_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {
    var err error
    var args [2]string
    var action string
    log.Info("TableXfmrFunc - Uri KDUMP: ", inParams.uri);

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Error("Failed to retrieve TARGET URI PATH")
        return nil,err
    }

    log.Info("TARGET URI PATH KDUMP:", targetUriPath)

    kdumpObj := getKdumpRoot(inParams.ygRoot)
    if kdumpObj.Config.Enable != nil {
        if (* kdumpObj.Config.Enable) {
            args[0] = "enable"
        } else {
            args[0] = "disable"
        }
        _, err = kdumpAction("configure", args)
    }

    if kdumpObj.Config.Memory != nil {
        args[0] = "memory"
        if inParams.oper == DELETE {
            action = "reset"
        } else {
            action = "configure"
            args[1] = * kdumpObj.Config.Memory
        }
        _, err = kdumpAction(action, args)
    }

    if kdumpObj.Config.MaxDumps != nil {
        var num64 uint64
        var num8 uint8
        args[0] = "num_dumps"
        if inParams.oper == DELETE {
            action = "reset"
        } else {
            action = "configure"
            num8 = * kdumpObj.Config.MaxDumps
            num64 = uint64(num8)
            args[1] = strconv.FormatUint(num64, 10)
        }
        _, err = kdumpAction(action, args)
    }

    return nil,err;
}
