package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "strconv"
    "fmt"
    "strings"
    "encoding/json"
    log "github.com/golang/glog"
    ygot "github.com/openconfig/ygot/ygot"
)

func init () {
    XlateFuncBind("DbToYang_oc_systemd_coredump_status_xfmr", DbToYang_oc_systemd_coredump_status_xfmr)
    XlateFuncBind("DbToYang_oc_systemd_coredump_records_xfmr", DbToYang_oc_systemd_coredump_records_xfmr)
    XlateFuncBind("DbToYang_oc_systemd_coredump_config_xfmr", DbToYang_oc_systemd_coredump_config_xfmr)
    XlateFuncBind("YangToDb_oc_systemd_coredump_config_xfmr", YangToDb_oc_systemd_coredump_config_xfmr)

}

/*App specific constants */
const (
    COREDUMP_STATUS_ADMIN_MODE    = "enable"
    COREDUMP_RECORDS_LIST         = "core-file-record"
    CORE_FILE_RECORD_TIMESTAMP    = "timestamp"
    CORE_FILE_RECORD_EXE          = "executable"
    CORE_FILE_RECORD_STORAGE      = "core-file"
    CORE_FILE_RECORD_PID          = "pid"
    CORE_FILE_RECORD_UID          = "uid"
    CORE_FILE_RECORD_GID          = "gid"
    CORE_FILE_RECORD_SIGNAL       = "signal"
    CORE_FILE_RECORD_CMD_LINE     = "command-line"
    CORE_FILE_RECORD_BOOT_ID      = "boot-identifier"
    CORE_FILE_RECORD_MACHINE_ID   = "machine-identifier"
    CORE_FILE_RECORD_MESSAGE      = "crash-message"
    CORE_FILE_RECORD_CORE_PRESENT = "core-file-present"
)

/* App specific type definitions */

type coredumpStatusCache struct {
    coredumpStatusMap map[string]string
}

type coredumpRecordsCache struct {
    coreFileRecordMap map[string]map[string]string
}

/* App specific utilities */

/* Initialise coredump status cache Data structure */

func coredumpCacheInit(statusCache *coredumpStatusCache) {
    statusCache.coredumpStatusMap = make(map[string]string)
}

func coredumpCacheRecordsInit(statusCache *coredumpRecordsCache) {
    statusCache.coreFileRecordMap = make(map[string]map[string]string)
}

/* Get ygot root object */

func getCoredumpRoot (s *ygot.GoStruct) (*ocbinds.OpenconfigSystem_System_SystemdCoredump) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.System.SystemdCoredump
}

/* Wrapper to call host service to perform coredump info retrieve operations */

func coredumpAction(action string, options [2]string) (string, error) {
	var output string
        var result HostResult
	// result.Body is of type []interface{}, since any data may be returned by
	// the host server. The application is responsible for performing
	// type assertions to get the correct data.
        if (action == "status" || action == "getconfig" || action == "records") {
	    result = HostQuery("coredumpctl." + action)
        } else {
	    result = HostQuery("coredumpctl." + action, options)
        }
	if result.Err != nil {
		return output, result.Err
	}
	if (action == "status" || action == "getconfig" || action == "records") {
		// coredumpctl.status returns an exit code and the stdout of the command
		// We only care about the stdout (which is at [1] in the slice)
		output, _ = result.Body[0].(string)
        }
        return output, nil
}

/* Function to populate coredump status data structure with the status info from host service */

func getCoredumpStatusFromHost(statusCache * coredumpStatusCache, hostData map[string] interface{}) {

    temp := hostData
    for attr,val := range temp {
	switch attr {
	    case COREDUMP_STATUS_ADMIN_MODE:
		statusCache.coredumpStatusMap[COREDUMP_STATUS_ADMIN_MODE] = fmt.Sprintf("%t",val)
            case COREDUMP_RECORDS_LIST:
	    default:
		log.Info("Invalid attr:",attr)
	}
   }
}

/* Function to populate core file records data structure with info from host service */

func getCoreFileRecord(recordKey string, dataMap map[string]interface{}, statusCache *coredumpRecordsCache) {
    statusCache.coreFileRecordMap[recordKey] = make(map[string]string)
    for attr,val := range dataMap {
	switch attr {
	    case CORE_FILE_RECORD_TIMESTAMP:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_TIMESTAMP] = recordKey
            case CORE_FILE_RECORD_EXE:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_EXE] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_STORAGE:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_STORAGE] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_PID:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_PID] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_UID:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_UID] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_GID:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_GID] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_SIGNAL:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_SIGNAL] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_CMD_LINE:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_CMD_LINE] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_BOOT_ID:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_BOOT_ID] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_MACHINE_ID:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_MACHINE_ID] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_MESSAGE:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_MESSAGE] = fmt.Sprintf("%v",val)
            case CORE_FILE_RECORD_CORE_PRESENT:
    		statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_CORE_PRESENT] = fmt.Sprintf("%t",val)
	    default:
    		log.Info("Invalid attr:",attr)
	}
    }
}

/* Populate coredump status ygot tree */

func populateCoredumpStatusYgotTree(statusObj *ocbinds.OpenconfigSystem_System_SystemdCoredump_State, statusCache *coredumpStatusCache) {
    if value,present := statusCache.coredumpStatusMap[COREDUMP_STATUS_ADMIN_MODE]; present {
        admin := new(bool)
        *admin,_ =  strconv.ParseBool(value)
        statusObj.Enable =  admin
    }
}

/* Populate core file records ygot tree */

func populateCoreFileRecordYgotTree(recordKey string, recordObj *ocbinds.OpenconfigSystem_System_SystemdCoredump_CoreFileRecords_CoreFileRecord_State, statusCache *coredumpRecordsCache) {
    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_TIMESTAMP]; present {
        numd := new(uint64)
        *numd,_ =  strconv.ParseUint(value, 10, 64)
        recordObj.Timestamp = numd
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_EXE]; present {
        exe := value
        recordObj.Executable = &exe
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_STORAGE]; present {
        core_file := value
        recordObj.CoreFile = &core_file
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_PID]; present {
        numd := new(uint64)
        *numd,_ =  strconv.ParseUint(value, 10, 64)
        recordObj.Pid = numd
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_UID]; present {
        numd := new(uint64)
        num32 := new(uint32)
        *numd,_ =  strconv.ParseUint(value, 10, 64)
        *num32 = uint32 (*numd)
        recordObj.Uid =  num32
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_GID]; present {
        numd := new(uint64)
        num32 := new(uint32)
        *numd,_ =  strconv.ParseUint(value, 10, 64)
        *num32 = uint32 (*numd)
        recordObj.Gid =  num32
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_SIGNAL]; present {
        numd := new(uint64)
        num32 := new(uint32)
        *numd,_ =  strconv.ParseUint(value, 10, 64)
        *num32 = uint32 (*numd)
        recordObj.Signal =  num32
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_CMD_LINE]; present {
        cmd_line := value
        recordObj.CommandLine = &cmd_line
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_BOOT_ID]; present {
        boot_id := value
        recordObj.BootIdentifier = &boot_id
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_MACHINE_ID]; present {
        machine_id := value
        recordObj.MachineIdentifier = &machine_id
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_MESSAGE]; present {
        crash_msg := value
        recordObj.CrashMessage = &crash_msg
    }

    if value,present := statusCache.coreFileRecordMap[recordKey][CORE_FILE_RECORD_CORE_PRESENT]; present {
        pres := new(bool)
        *pres,_ =  strconv.ParseBool(value)
        recordObj.CoreFilePresent =  pres
    }
}

/* Get status info from db */

func getCoredumpStatusInfofromDb( statusObj *ocbinds.OpenconfigSystem_System_SystemdCoredump_State, statusCache *coredumpStatusCache ) (error) {

    log.Info("Entered coredump status info from db")
    act:= "status"
    var args [2]string
    mess, err:= coredumpAction(act, args)
    if err != nil {
	log.Error("Error from sonic host service:",err)
        return err
    }
    
    var hostData map[string] interface{}
    err = json.Unmarshal([]byte (mess),&hostData)
    if err != nil {
	log.Error("coredump json unmarshal error:",err)
        return err
    }

    getCoredumpStatusFromHost(statusCache,hostData)
    populateCoredumpStatusYgotTree(statusObj, statusCache)
    return nil;
}

/* Get records info from db */

func getCoredumpRecordsInfofromDb( recordsObj *ocbinds.OpenconfigSystem_System_SystemdCoredump_CoreFileRecords, statusCache *coredumpRecordsCache ) (error) {

    log.Info("Entered coredump records info from db")
    act:= "records"
    var args [2]string
    mess, err:= coredumpAction(act, args)
    if err != nil {
        log.Error("Error from sonic host service:",err)
        return err
    }

    var hostData map[string] interface{}
    err = json.Unmarshal([]byte (mess),&hostData)
    if err != nil {
        log.Error("coredump json unmarshal error:",err)
        return err
    }

    if coreFileRecordsList, present := hostData[COREDUMP_RECORDS_LIST]; present {
            for recordKey, dataMap := range coreFileRecordsList.(map[string]interface{}) {
                record,err := strconv.ParseUint(recordKey, 10, 64)
                if err != nil {
                    log.Error("Failed to interpret record key. Creation of corefile records subtree failed.", err)
                    return err
                }
                coreFileRecordList, err := recordsObj.NewCoreFileRecord(record)
                if err != nil {
                    log.Error("Creation of corefile records subtree failed.!", err)
                    return err
                }
                ygot.BuildEmptyTree(coreFileRecordList)
                if coreFileRecordList.State == nil {
                    ygot.BuildEmptyTree(coreFileRecordList.State)
                }
                getCoreFileRecord(recordKey, dataMap.(map[string]interface{}), statusCache)
                populateCoreFileRecordYgotTree(recordKey, coreFileRecordList.State, statusCache)
            }
        }
    return nil;
}

/* Wrapper to coredump status related function calls */

func getCoredumpStatus(coredumpObj *ocbinds.OpenconfigSystem_System_SystemdCoredump) (error) {

    if coredumpObj.State == nil {
	ygot.BuildEmptyTree(coredumpObj)
    }
    statusObj := coredumpObj.State
    ygot.BuildEmptyTree(statusObj)
    var statusCache coredumpStatusCache
    coredumpCacheInit(&statusCache)
    err :=  getCoredumpStatusInfofromDb(statusObj, &statusCache)
    return err
}

/* Transformer specific functions */

var DbToYang_oc_systemd_coredump_records_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {

    coredumpObj := getCoredumpRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Error("Failed to retrieve TARGET URI PATH:", err)
        return err
    }
    log.Info("TARGET URI PATH systemd-coredump:", targetUriPath)
    if strings.Contains(targetUriPath, "/openconfig-system:system/openconfig-system-ext:systemd-coredump/core-file-records") {
        log.Info("TARGET URI PATH systemd-coredump:", targetUriPath)
        log.Info("TableXfmrFunc - Uri systemd-coredump: ", inParams.uri);

        if coredumpObj.CoreFileRecords == nil {
            ygot.BuildEmptyTree(coredumpObj)
        }
        recordsObj := coredumpObj.CoreFileRecords
        var statusCache coredumpRecordsCache
        coredumpCacheRecordsInit(&statusCache)
        return getCoredumpRecordsInfofromDb(recordsObj, &statusCache)
    } else {
        return nil
    }
}

var DbToYang_oc_systemd_coredump_status_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {

    coredumpObj := getCoredumpRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Error("Failed to retrieve TARGET URI PATH:", err)
        return err
    }
    log.Info("TARGET URI PATH systemd-coredump:", targetUriPath)
    if strings.Contains(targetUriPath, "/openconfig-system:system/openconfig-system-ext:systemd-coredump/state") {
	log.Info("TARGET URI PATH systemd-coredump:", targetUriPath)
        log.Info("TableXfmrFunc - Uri systemd-coredump: ", inParams.uri);
        err =  getCoredumpStatus(coredumpObj)
	return err
    } else {
	return nil
    }
}

var DbToYang_oc_systemd_coredump_config_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    coredumpObj := getCoredumpRoot(inParams.ygRoot)
    log.Info("TableXfmrFunc - Uri systemd-coredump: ", inParams.uri);
    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Error("Failed to retrieve TARGET URI PATH:",err)
        return err
    }
    log.Info("TARGET URI PATH systemd-coredump:", targetUriPath)

    act:= "getconfig"
    var args [2]string
    mess, err := coredumpAction(act, args)
    if err != nil {
        log.Error("Error from host service:",err)
        return err
    }

    var hostData map[string] interface{}
    err = json.Unmarshal([]byte (mess),&hostData)
    if err != nil {
        log.Error("coredumpctl json unmarshal error:",err)
        return err
    }

    if coredumpObj.Config == nil {
	ygot.BuildEmptyTree(coredumpObj)
    }
    configObj := coredumpObj.Config
    ygot.BuildEmptyTree(configObj)

    for attr,val := range hostData {
        switch attr {
            case COREDUMP_STATUS_ADMIN_MODE:
                var mode_str = fmt.Sprintf("%t",val)
                mode := new(bool)
                *mode,_ =  strconv.ParseBool(mode_str)
                configObj.Enable = mode
            default:
                log.Error("Invalid attr:",attr)
        }
   }
   return err;

}

var YangToDb_oc_systemd_coredump_config_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {
    var err error
    var args [2]string
    log.Info("TableXfmrFunc - Uri systemd-coredump: ", inParams.uri);

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        log.Error("Failed to retrieve TARGET URI PATH:", err)
        return nil,err
    }

    log.Info("TARGET URI PATH systemd-coredump:", targetUriPath)

    coredumpObj := getCoredumpRoot(inParams.ygRoot)
    if coredumpObj.Config.Enable != nil {
        if (* coredumpObj.Config.Enable) {
            args[0] = "enable"
        } else {
            args[0] = "disable"
        }
        if inParams.oper == DELETE {
            args[0] = "enable"
        }
        _, err = coredumpAction("configure", args)
    }
    return nil,err;
}
