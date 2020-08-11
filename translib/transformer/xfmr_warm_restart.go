//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Dell, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer

import (
	log "github.com/golang/glog"
        "strconv"
        "strings"
	"errors"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("YangToDb_wmr_config_en_key_xfmr", YangToDb_wmr_config_en_key_xfmr)
	XlateFuncBind("DbToYang_wmr_config_en_key_xfmr", DbToYang_wmr_config_en_key_xfmr)
	XlateFuncBind("YangToDb_wmr_config_eoiu_key_xfmr", YangToDb_wmr_config_eoiu_key_xfmr)
	XlateFuncBind("DbToYang_wmr_config_eoiu_key_xfmr", DbToYang_wmr_config_eoiu_key_xfmr)
	XlateFuncBind("YangToDb_wmr_module_key_xfmr", YangToDb_wmr_module_key_xfmr)
	XlateFuncBind("DbToYang_wmr_module_key_xfmr", DbToYang_wmr_module_key_xfmr)
	XlateFuncBind("YangToDb_wmr_timer_key_xfmr", YangToDb_wmr_timer_key_xfmr)
	XlateFuncBind("DbToYang_wmr_timer_key_xfmr", DbToYang_wmr_timer_key_xfmr)
	XlateFuncBind("YangToDb_wmr_timer_value_field_xfmr", YangToDb_wmr_timer_value_field_xfmr)
	XlateFuncBind("DbToYang_wmr_timer_value_field_xfmr", DbToYang_wmr_timer_value_field_xfmr)
	XlateFuncBind("DbToYang_wrm_status_subtree_xfmr", DbToYang_wrm_status_subtree_xfmr)
	XlateFuncBind("DbToYang_wmr_timer_submodule_field_xfmr", DbToYang_wmr_timer_submodule_field_xfmr)
	XlateFuncBind("YangToDb_wmr_timer_submodule_field_xfmr", YangToDb_wmr_timer_submodule_field_xfmr)
	XlateFuncBind("DbToYang_wmr_module_field_xfmr", DbToYang_wmr_module_field_xfmr)
	XlateFuncBind("YangToDb_wmr_module_field_xfmr", YangToDb_wmr_module_field_xfmr)
}

//Currently supported module

var ocToDBmodules = map[string]string {
    "BGP"   : "bgp" ,
    "TEAMD" : "teamd",
    "SWSS"  : "swss",
}

var dbToOCmodules = map[string]string {

    "bgp"   :  "BGP" ,
    "teamd" :  "TEAMD" ,
    "swss"  :  "SWSS" ,
}

var modulesToSubmodules = map[string]string {
    "bgp"   :  "BGP" ,
    "teamd" :  "TEAMSYNCD" ,
    "swss"  :  "NEIGHSYNCD" ,
}

var subModulesToModules = map[string]string {
    "BGP"        : "bgp" ,
    "TEAMSYNCD"  : "teamd" ,
    "NEIGHSYNCD" : "swss" ,
}

var subModuleToTimers = map[string]string {
    "BGP"        : "bgp_timer" ,
    "TEAMSYNCD"  : "teamsyncd_timer" ,
    "NEIGHSYNCD" : "neighsyncd_timer" ,
}

func getOCModuleName (modname string) (string,bool) {
    value, ret := dbToOCmodules[modname]
    return  value, ret
}

func getDBModuleName (modname string) (string,bool) {
    value, ret := ocToDBmodules[modname]
    return  value, ret
}

func getSubModuleFromModule (modname string) (string,bool) {
    value, ret := modulesToSubmodules[modname]
    return  value, ret
}

func getModuleFromSubmodule (subModname string) (string,bool) {
     value, ret := subModulesToModules[subModname]
    return  value, ret
}

func getFieldFromSubModule (subModname string) (string,bool) {
     value, ret := subModuleToTimers[subModname]
    return  value, ret
}

/* Key transformer  Handler function for enable/disable system*/

var YangToDb_wmr_config_en_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var module string
    var err error

    module = "system"
    log.V(3).Info("YangToDb_wmr_config_en_key_xfmr - return module ", module)
    return module, err
}

var DbToYang_wmr_config_en_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    rmap := make(map[string]interface{})
    var err error

    log.V(3).Info("DbToYang_wmr_config_en_key_xfmr rmap ", rmap)
    return rmap, err
}

/* Handler function for enable/disable BGP EOIU */

var YangToDb_wmr_config_eoiu_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var module string
    var err error

    module = "bgp"
     log.V(3).Info("YangToDb_wmr_config_eoiu_key_xfmr - return module ", module)
    return module, err
}

var DbToYang_wmr_config_eoiu_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error

    log.V(3).Info("DbToYang_wmr_config_eoiu_key_xfmr rmap ", rmap)
    return rmap, err
}

/* Handler function for enable/disable module */

var YangToDb_wmr_module_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    modname := pathInfo.Var("module")
    dbModulename , isOk := getDBModuleName(modname)

    if !isOk {
        log.Error("YangToDb_wmr_module_key_xfmr Unknown submodule ", modname)
        return "", err
    }
    log.V(3).Info("YangToDb_wmr_module_key_xfmr - return module ", modname)
    return dbModulename, err
}

var DbToYang_wmr_module_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    rmap := make(map[string]interface{})
    var err error

    moduleName , isOk := getOCModuleName(inParams.key)

    if !isOk {
        log.Error("DbToYang_wmr_module__key_xfmr Unknown submodule ", inParams.key)
        return rmap, err
    }
    rmap["module"] = moduleName
    log.V(3).Info("DbToYang_wmr_module_key_xfmr rmap ", rmap)
    return rmap, err
}

/* Handler function for key transformer for timer value for submodule */

var YangToDb_wmr_timer_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    subMod := pathInfo.Var("submodule")
    moduleName, ok := getModuleFromSubmodule(subMod)

    if (!ok) {
        return "", err
    }

    log.V(3).Info("YangToDb_wmr_timer_key_xfmr - return submodule ", moduleName)
    return moduleName, err
}

var DbToYang_wmr_timer_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    rmap := make(map[string]interface{})
    var err error
    subModule, ok := getSubModuleFromModule(inParams.key)

    if (!ok) {
        return rmap, err
    }
    rmap["submodule"] = subModule
    log.V(3).Info("DbToYang_wmr_timer_key_xfmr rmap ", rmap)
    return rmap, err
}

/* Handler function for setting timer value for submodule */

var YangToDb_wmr_timer_value_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var value uint32 = 0
    pathInfo := NewPathInfo(inParams.uri)
    submod := pathInfo.Var("submodule")

    pvalue, ok := inParams.param.(*uint32)
    if (!ok) {
       log.Error("Invalid Param for ",submod)
       value = 0
    } else {
       value = *pvalue
    }
    field, isOk := getFieldFromSubModule(submod)

    if (!isOk) {
        log.Error("Unknown submodule ", submod)
        return res_map, errors.New("Invalid submodule")
    }
    res_map[field] = strconv.FormatUint(uint64(value), 10)
    log.V(3).Info("YangToDb_wmr_timer_value_field_xfmr - return  ",res_map);
    return res_map, nil
}


var DbToYang_wmr_timer_value_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    pathInfo := NewPathInfo(inParams.uri)
    submod:= pathInfo.Var("submodule")
    field, isOk := getFieldFromSubModule(submod)

    if (!isOk) {
        log.Error("Unknown submodule ", submod)
        return rmap, errors.New("Invalid submodule")
    }

    data := (*inParams.dbDataMap)[inParams.curDb]
    tbl := data["WARM_RESTART"]
    str1, ok := tbl[inParams.key]
    if (ok) {
        res_val, isOk := str1.Field[field]
        if (isOk) {
             value, _ := strconv.ParseInt(res_val, 10, 16)
                 rmap["value"] = value
        }
    }
    log.V(3).Info("DbToYang_wmr_timer_value_field_xfmr return:",rmap);
    return rmap, nil
}


var DbToYang_wrm_status_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var submodulesList ocbinds.OpenconfigWarmRestart_WarmRestart_Status
    var keys []db.Key
    var err error
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    warmInstsObj := deviceObj.WarmRestart
    ygot.BuildEmptyTree(warmInstsObj)

    tblName := "WARM_RESTART_TABLE"
    dbspec := &db.TableSpec { Name: tblName }

    if keys, err = inParams.d.GetKeys(&db.TableSpec{Name:tblName} ); err != nil {
        return errors.New("Operational Error at status_subtree_xfmr")
    }
    warmInstsObj.Status = &submodulesList
    for _, key := range keys {
        dbEntry, dbErr := inParams.d.GetEntry(dbspec, key)
        if dbErr != nil {
            log.Error("DB GetEntry failed for key : ", key)
            continue
        }

        submod := key.Comp[0]
        countValStr := dbEntry.Field["restore_count"]
        cntVal16, _ := strconv.ParseUint(countValStr, 10, 16)
        stateFld := dbEntry.Field["state"]

        var submodule ocbinds.OpenconfigWarmRestart_WarmRestart_Status_Submodules
        var stateCon  ocbinds.OpenconfigWarmRestart_WarmRestart_Status_Submodules_State
        stateCon.Submodule = &submod
        cntVal := uint16(cntVal16)
        stateCon.RestoreCount = &cntVal
        stateCon.State = &stateFld
        submodule.State = &stateCon
        submodulesList.Submodules = append(submodulesList.Submodules,&submodule)
    }

    log.V(3).Info("submodulesList",submodulesList)
    return err
}

var YangToDb_wmr_module_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_wmr_module_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_wmr_module_field_xfmr: ", data, "inParams : ", inParams)

    entry_key := inParams.key
    key := strings.Split(entry_key, "|")
    modName := key[0]
    ocModName, ok := getOCModuleName(modName)
    if !ok {
       return result, err
    }
    result["module"] = ocModName

    return result, err
}

var YangToDb_wmr_timer_submodule_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_wmr_timer_submodule_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_wmr_timer_submodule_field_xfmr: ", data, "inParams : ", inParams)

    entry_key := inParams.key
    key := strings.Split(entry_key, "|")
    modName := key[0]
    subModule, ok := getSubModuleFromModule(modName)
    if (!ok) {
        return result, err
    }

    result["submodule"] = subModule

    return result, err
}


