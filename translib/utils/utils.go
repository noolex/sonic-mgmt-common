////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////


package utils

import (
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/cvl"
    "sync"
    "strings"
    "fmt"
    log "github.com/golang/glog"
)

// Maintaining aliasMode based on the following flag
var aliasMode bool = false

// Interface Name to Alias Map
var ifNameAliasMap *sync.Map
// Alias to Interface Name Map
var aliasIfNameMap *sync.Map

func init() {
    portNotifSubscribe();
    populateAliasDS()
    devMetaNotifSubscribe();
}

func getDBOptions(dbNo db.DBNum, isWriteDisabled bool) db.Options {
    var opt db.Options

    switch dbNo {
    case db.ApplDB, db.CountersDB, db.AsicDB:
        opt = getDBOptionsWithSeparator(dbNo, "", ":", ":", isWriteDisabled)
    case db.FlexCounterDB, db.LogLevelDB, db.ConfigDB, db.StateDB, db.ErrorDB, db.UserDB:
        opt = getDBOptionsWithSeparator(dbNo, "", "|", "|", isWriteDisabled)
    }

    return opt
}

func getDBOptionsWithSeparator(dbNo db.DBNum, initIndicator string, tableSeparator string, keySeparator string, isWriteDisabled bool) db.Options {
    return (db.Options{
        DBNo:               dbNo,
        InitIndicator:      initIndicator,
        TableNameSeparator: tableSeparator,
        KeySeparator:       keySeparator,
        IsWriteDisabled:    isWriteDisabled,
    })
}

func updateCacheForPort(portKey *db.Key, d *db.DB) {
    portName := portKey.Get(0)
    portEntry, err := d.GetEntry(&db.TableSpec{Name:"PORT"}, *portKey)
    if err != nil {
        log.Errorf("Retrieval of entry for port: %s failed from port table", portName)
        return
    }
    if !portEntry.IsPopulated() {
        log.Errorf("PortEntry populated for port: %s failed", portName)
        return
    }
    aliasName, ok := portEntry.Field["alias"]
    if !ok {
        // don't return error, keep populating data structures
        log.Infof("Alias field not present for port: %s", portName)
        return
    }
    existingAliasName, ok := ifNameAliasMap.Load(portName)
    if ok {
        log.Errorf("Alias name : %s already present for %s, updating with new alias name : %s", existingAliasName.(string), portName, aliasName)
    }
    ifNameAliasMap.Store(portName, aliasName)

    existingIfName, ok := aliasIfNameMap.Load(aliasName)
    if ok {
        log.Errorf("Port name : %s already present for %s, updating with new port name : %s", existingIfName.(string), aliasName, portName)
    }
    aliasIfNameMap.Store(aliasName, portName)
    log.Infof("alias cache updated %s <==> %s", portName, aliasName)
}

func portNotifHandler(d *db.DB, skey *db.SKey, key *db.Key, event db.SEvent) error {
    log.V(3).Info("***handler: d: ", d, " skey: ", *skey, " key: ", *key,
           " event: ", event)
    switch event {
    case db.SEventHSet, db.SEventHDel:
        updateCacheForPort(key, d)
    }
    return nil
}

func dbNotifSubscribe(ts db.TableSpec, key db.Key, handler db.HFunc) error {

    var skeys []*db.SKey = make([]*db.SKey, 1)
    skeys[0] = & (db.SKey { 
        Ts: &ts,
        Key: &key,
        SEMap: map[db.SEvent]bool {
            db.SEventHSet:  true,
            db.SEventHDel:  true,
            db.SEventDel:   true,
        },
    })

    _,e := db.SubscribeDB(db.Options {
        DBNo              : db.ConfigDB,
        InitIndicator     : "CONFIG_DB_INITIALIZED",
        TableNameSeparator: "|",
        KeySeparator      : "|",
    }, skeys, handler)

    return e
}

func portNotifSubscribe() {
    var akey db.Key
    tsa := db.TableSpec { Name: "PORT" }

    ca := make([]string, 1)
    ca[0] = "*"
    akey = db.Key { Comp: ca}

    e := dbNotifSubscribe(tsa, akey, portNotifHandler)
    if e != nil {
        log.Info("dbNotifSubscribe() returns error : ", e)
    }

    log.Info("PORT table subscribe done....");
}

func devMetaNotifHandler(d *db.DB, skey *db.SKey, key *db.Key, event db.SEvent) error {
    log.V(3).Info("***handler: d: ", d, " skey: ", *skey, " key: ", *key,
           " event: ", event)
    switch event {
    case db.SEventHSet, db.SEventHDel:
        updateAliasFromDB(key, d)
    }

    return nil
}

func updateAliasFromDB(key *db.Key, d *db.DB) {
    key0 := key.Get(0)
    entry, err := d.GetEntry(&db.TableSpec{Name:"DEVICE_METADATA"}, *key)
    if err != nil {
        log.Errorf("Retrieval of entry for %s failed from port table", key0)
        return
    }
    aliasVal, ok := entry.Field["intf_naming_mode"]
    if !ok {
        // don't return error, keep populating data structures
        aliasMode = false
        log.Infof("intf_naming_mode not present, disabling alias mode")
        return
    }
    aliasMode = (aliasVal == "standard")
    log.Infof("aliasMode set to %v", aliasMode);
}

func devMetaNotifSubscribe() {
    var akey db.Key
    tsa := db.TableSpec { Name: "DEVICE_METADATA" }

    ca := make([]string, 1)
    ca[0] = "*"
    akey = db.Key { Comp: ca}

    e := dbNotifSubscribe(tsa, akey, devMetaNotifHandler)
    if e != nil {
        log.Info("dbNotifSubscribe() returns error : ", e)
    }

    log.Info("DEVICE_METADATA table subscribe done....");
}

func populateAliasDS() error {
    var err error

    ifNameAliasMap = new(sync.Map)
    aliasIfNameMap = new(sync.Map)

    d, err := db.NewDB(getDBOptions(db.ConfigDB, false))
    if err != nil {
        log.Error("Instantiation of config-db failed!")
        return err
    }
    portTbl, err := d.GetTable(&db.TableSpec{Name: "PORT"})
    if err != nil {
        log.Error("Get PORT table failed")
        return err
    }
    portKeys, err := portTbl.GetKeys()
    if err != nil {
        log.Error("Retrieval of keys from PORT table failed!")
        return err
    }
    for _, portKey := range portKeys {
        updateCacheForPort(&portKey, d)
    }

    updateAliasFromDB(&db.Key{Comp: []string{"localhost"}}, d)

    return err
}

func IsAliasModeEnabled() bool {
    return  aliasMode
}

func GetAliasMode() bool {
    return aliasMode
}

func SetAliasMode(enableMode bool) {
    aliasMode = enableMode
}

// GetNativeNameFromUIName returns physical interface name for alias-name
func GetNativeNameFromUIName(uiName *string) *string {
	if !IsAliasModeEnabled() {
		return uiName
	}

	parts := strings.Split(*uiName, ",")
	converted := make([]string, len(parts))
	for idx, part := range parts {
		ifName, ok := aliasIfNameMap.Load(*uiName)
		if ok {
			converted[idx] = ifName.(string)
		} else {
			converted[idx] = part
		}
	}
	ret := strings.Join(converted, ",")
	log.Infof("%s => %s", *uiName, ret)

	return &ret
}

// GetUINameFromNativeName returns alias-name for physical interface Name
func GetUINameFromNativeName(ifName *string) *string {
	if !IsAliasModeEnabled() {
		return ifName
	}

	parts := strings.Split(*ifName, ",")
	converted := make([]string, len(parts))
	for idx, part := range parts {
		aliasName, ok := ifNameAliasMap.Load(part)
		if ok {
			converted[idx] = aliasName.(string)
		} else {
			converted[idx] = part
		}
	}
	ret := strings.Join(converted, ",")
	log.Infof("%s => %s", *ifName, ret)

	return &ret
}

func IsValidAliasName(ifName *string) bool {
    _, ok := aliasIfNameMap.Load(*ifName)
    return ok
}

// SortAsPerTblDeps - sort transformer result table list based on dependencies (using CVL API) tables to be used for CRUD operations
func SortAsPerTblDeps(tblLst []string) ([]string, error) {
        var resultTblLst []string
        var err error
        logStr := "Failure in CVL API to sort table list as per dependencies."

        cvSess, cvlRetSess := cvl.ValidationSessOpen()
        if cvlRetSess != cvl.CVL_SUCCESS {

                log.Errorf("Failure in creating CVL validation session object required to use CVl API(sort table list as per dependencies) - %v", cvlRetSess)
                err = fmt.Errorf("%v", logStr)
                return resultTblLst, err
        }
        cvlSortDepTblList, cvlRetDepTbl := cvSess.SortDepTables(tblLst)
        if cvlRetDepTbl != cvl.CVL_SUCCESS {
                log.Warningf("Failure in cvlSess.SortDepTables: %v", cvlRetDepTbl)
                cvl.ValidationSessClose(cvSess)
                err = fmt.Errorf("%v", logStr)
                return resultTblLst, err
        }
        log.Info("cvlSortDepTblList = ", cvlSortDepTblList)
        resultTblLst = cvlSortDepTblList

        cvl.ValidationSessClose(cvSess)
        return resultTblLst, err

}

// RemoveElement - Remove a specific string from a list of strings
func RemoveElement(sl []string, str string) []string {
    for i := 0; i < len(sl); i++ {
        if sl[i] == str {
            sl = append(sl[:i], sl[i+1:]...)
            i--
            break
        }
    }
    return sl
}
