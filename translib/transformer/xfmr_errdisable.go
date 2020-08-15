package transformer

import (
	log "github.com/golang/glog"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init() {
	XlateFuncBind("YangToDb_errdisable_global_key_xfmr", YangToDb_errdisable_global_key_xfmr)
	XlateFuncBind("YangToDb_errdisable_cause_xfmr", YangToDb_errdisable_cause_xfmr)
	XlateFuncBind("DbToYang_errdisable_cause_xfmr", DbToYang_errdisable_cause_xfmr)
}

func getDbEntry(dbCl *db.DB, tblName string, key string) (db.Value, error) {
    var err error
	var ERRDISABLE_TABLE_TS *db.TableSpec = &db.TableSpec{Name: tblName}

    log.Info("Checking Config DB for ErrDisable Table >>", tblName, "|", key)

    errdisableData, err := configDbPtr.GetTable(ERRDISABLE_TABLE_TS)
    if err != nil {
        log.Error("GetTable failed")
        return db.Value{Field: make(map[string]string)}, err
    }

    entry, err := errdisableData.GetEntry(db.Key{Comp: []string{key}})
    if err != nil {
        log.Error("GetEntry failed")
        return db.Value{Field: make(map[string]string)}, err
    }

    log.Info("getEntry : ",entry)
    return entry, nil
}

func getAllCauseStatus(dbCl *db.DB, tblName string, key string) ([]string, error) {
	var cause []string
    entry, err := getDbEntry(dbCl, tblName, key)
    if err != nil {
        return cause, err
    }

    if entry.Field["udld"] == "enabled" {
        enumName, _ := ygot.EnumName(ocbinds.OpenconfigErrdisableTypes_ERRDISABLE_RECOVERY_CAUSE_UDLD)
        cause = append(cause, enumName)
    }

    if entry.Field["bpduguard"] == "enabled" {
        enumName, _ := ygot.EnumName(ocbinds.OpenconfigErrdisableTypes_ERRDISABLE_RECOVERY_CAUSE_BPDUGUARD)
        cause = append(cause, enumName)
    }
    return cause, err
}

var YangToDb_errdisable_global_key_xfmr = func(inParams XfmrParams) (string, error) {
	log.Info("YangToDb_errdisable_global_key_xfmr: ", inParams.ygRoot, inParams.uri)
	return "RECOVERY", nil
}

func getErrDisableRoot (s *ygot.GoStruct) *ocbinds.OpenconfigErrdisableExt_Errdisable {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Errdisable

}

var YangToDb_errdisable_cause_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    var is_enabled string
	var cause []ocbinds.E_OpenconfigErrdisableTypes_ERRDISABLE_RECOVERY_CAUSE

    errdisableObj := getErrDisableRoot(inParams.ygRoot)
    cause = errdisableObj.Config.Cause

    if inParams.oper == DELETE {
        is_enabled = "disabled"
        subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

        if _, ok := subOpMap[db.ConfigDB]; !ok {
            subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        }
        if _, ok := subOpMap[db.ConfigDB]["ERRDISABLE"]; !ok {
            subOpMap[db.ConfigDB]["ERRDISABLE"] = make(map[string]db.Value)
        }
        subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"] = db.Value{Field: make(map[string]string)}

        errdisable_entry, err := getDbEntry(inParams.dbs[db.ConfigDB], "ERRDISABLE", "RECOVERY")
        if err != nil {
            log.Error("getEntry FAiled")
            return res_map, err
        }
        if val, ok := errdisable_entry.Field["interval"]; ok {
            subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"].Field["interval"] = val
        }
        if val, ok := errdisable_entry.Field["udld"]; ok {
            subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"].Field["udld"] = val
        }
        if val, ok := errdisable_entry.Field["bpduguard"]; ok {
            subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"].Field["bpduguard"] = val
        }

        if len(cause) == 0 {
            subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"].Field["udld"] = is_enabled
            subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"].Field["bpduguard"] = is_enabled
        } else {
            for i := 0; i < len(cause); i++ {
                switch t_cause := cause[i]; t_cause {
                case ocbinds.OpenconfigErrdisableTypes_ERRDISABLE_RECOVERY_CAUSE_UDLD:
                    subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"].Field["udld"] = is_enabled
                case ocbinds.OpenconfigErrdisableTypes_ERRDISABLE_RECOVERY_CAUSE_BPDUGUARD:
                    subOpMap[db.ConfigDB]["ERRDISABLE"]["RECOVERY"].Field["bpduguard"] = is_enabled
                default:
                    log.Error(" Invalid Cause : ", cause)
                    err = errors.New("Invalid cause")
                    return res_map, err
                }
            }
        }
        inParams.subOpDataMap[UPDATE] = &subOpMap
    } else {
        is_enabled = "enabled"
        for i := 0; i < len(cause); i++ {
            switch t_cause := cause[i]; t_cause {
            case ocbinds.OpenconfigErrdisableTypes_ERRDISABLE_RECOVERY_CAUSE_UDLD:
                res_map["udld"] = is_enabled
            case ocbinds.OpenconfigErrdisableTypes_ERRDISABLE_RECOVERY_CAUSE_BPDUGUARD:
                res_map["bpduguard"] = is_enabled
            default:
                log.Error(" Invalid Cause : ", cause)
                err = errors.New("Invalid cause")
                return res_map, err
            }
        }
    }

    log.Info("YangToDb_errdisable_udld_is_enabled_xfmr: res_map:", res_map)
    return res_map, nil
}


func DbToYang_errdisable_cause_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    item_exist := false
    res_map := make(map[string]interface{})
    cause_list,err := getAllCauseStatus(inParams.dbs[db.ConfigDB], "ERRDISABLE", "RECOVERY")
    if err != nil {
        return nil, tlerr.NotFound("Resource Not Found")
    }
    pathInfo := NewPathInfo(inParams.uri)
    cause := pathInfo.Var("cause")
    if len(cause) != 0 {
        for _, item := range cause_list {
            if cause == item {
                item_exist = true
                break
            }
        }
        if !item_exist {
            return nil, tlerr.NotFound("Resource Not Found")
        }
        //if item exist we should return empty as per guidance from DELL.
    } else {
        res_map["cause"] = cause_list
    }

    log.Info("DbToYang_errdisable_cause_xfmr : res_map : ", res_map)
    return res_map, nil
}


