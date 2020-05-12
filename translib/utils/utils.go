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
    "os"
    "sync"
    "github.com/Azure/sonic-mgmt-common/translib/db"

    log "github.com/golang/glog"
)

// Maintaining aliasMode based on the following flag
var aliasMode bool = false

// Interface Name to Alias Map
var ifNameAliasMap *sync.Map
// Alias to Interface Name Map
var aliasIfNameMap *sync.Map

func init() {
    retrieveAliasMode()
    populateAliasDS()
}

func getDBOptions(dbNo db.DBNum, isWriteDisabled bool) db.Options {
    var opt db.Options

    switch dbNo {
    case db.ApplDB, db.CountersDB, db.AsicDB:
        opt = getDBOptionsWithSeparator(dbNo, "", ":", ":", isWriteDisabled)
        break
    case db.FlexCounterDB, db.LogLevelDB, db.ConfigDB, db.StateDB, db.ErrorDB, db.UserDB:
        opt = getDBOptionsWithSeparator(dbNo, "", "|", "|", isWriteDisabled)
        break
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
    log.Info("***handler: d: ", d, " skey: ", *skey, " key: ", *key,
           " event: ", event)
    switch event {
    case db.SEventHSet, db.SEventHDel:
        updateCacheForPort(key, d)
    }
    return nil
}


func portNotifSubscribe() {
    var akey db.Key
    tsa := db.TableSpec { Name: "PORT" }

    ca := make([]string, 1, 1)
    ca[0] = "*"
    akey = db.Key { Comp: ca}

    var skeys []*db.SKey = make([]*db.SKey, 1)
    skeys[0] = & (db.SKey { Ts: &tsa, Key: &akey,

    SEMap: map[db.SEvent]bool {
        db.SEventHSet:  true,
        db.SEventHDel:  true,
        db.SEventDel:   true,
    }})

    _,e := db.SubscribeDB(db.Options {
        DBNo              : db.ConfigDB,
        InitIndicator     : "CONFIG_DB_INITIALIZED",
        TableNameSeparator: "|",
        KeySeparator      : "|",
    }, skeys, portNotifHandler)

    if e != nil {
        log.Info("Subscribe() returns error e: ", e)
    }

    log.Info("PORT table subscribe done....");
}

func populateAliasDS() error {
    var err error

    portNotifSubscribe()

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
    return err
}

func retrieveAliasModeFromEnv() {
    alsMode, ok := os.LookupEnv("SONIC_CLI_IFACE_MODE")
    if !ok {
        aliasMode = false
        return
    }
    log.Info("Alias Mode (String) = ", alsMode)

    switch alsMode {
    case "default":
        aliasMode = false
    case "alias":
        aliasMode = true
    default:
        log.Errorf("Not supported Interface mode %s received!", alsMode)
    }
    log.Info("Alias Mode = ", aliasMode)
}

func retrieveAliasMode() {
    var Key string = "localhost"
    TblTs := &db.TableSpec{Name: "DEVICE_METADATA"}

    cfgDb, err := db.NewDB(getDBOptions(db.ConfigDB, false))
    if err != nil {
        log.Error("Instantiation of Config DB failed!")
    }

    dbEntry, err := cfgDb.GetEntry(TblTs, db.Key{Comp: []string{Key}})

    if err != nil {
        errStr := "Failed to Get DEVICE METADATA details"
        log.Info(errStr)
    }
    aliasMode = false
    if val, ok := dbEntry.Field["aliasMode"].(bool); ok {
        if val == true {
            aliasMode = val
        }
    }
    log.Info("Alias Mode = ", aliasMode)
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

// Retrieve physical interface name from alias-name
func GetInterfaceNameFromAlias(aliasName *string) *string {
    if !IsAliasModeEnabled() {
        return aliasName
    }
    ifName, ok := aliasIfNameMap.Load(*aliasName)
    if ok {
        name := ifName.(string)
        return &name
    }
    return aliasName
}

// Retrieve alias-name from physical interface Name
func GetAliasNameFromIfName(ifName *string) *string {
    if !IsAliasModeEnabled() {
        return ifName
    }
    aliasName, ok := ifNameAliasMap.Load(*ifName)
    if ok {
        alias := aliasName.(string)
        return &alias
    }
    return ifName
}

func IsValidAliasName(ifName *string) bool {
    _, ok := aliasIfNameMap.Load(*ifName)
    return ok
}

