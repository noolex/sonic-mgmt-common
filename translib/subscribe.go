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

/*
Package translib defines the functions to be used by the subscribe 

handler to subscribe for a key space notification. It also has

functions to handle the key space notification from redis and

call the appropriate app module to handle them.

*/

package translib

import (
	"sync"
	"time"
	"bytes"
	"strconv"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	log "github.com/golang/glog"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/Workiva/go-datastructures/queue"
)

//Subscribe mutex for all the subscribe operations on the maps to be thread safe
var sMutex = &sync.Mutex{}

//lint:file-ignore U1000 temporarily ignore all "unused var" errors.
// Fields in the new structs are getting flagged as unused.

// notificationAppInfo contains the details for monitoring db notifications
// for a given path. App moodules provide these details for each subscribe
// path. One notificationAppInfo object must inclue details for one db table.
// One subscribe path can map to multiple notificationAppInfo.
type notificationAppInfo struct   {
	// table name
	table *db.TableSpec

	// key string without table name prefix. Can include wildcards.
	// Like - "ACL1|RULE_101" or "ACL1|*".
	key *db.Key

	// dbFieldYangPathMap is the mapping of db entry field to the yang
	// field (leaf/leaf-list) for the input path.
	dbFieldYangPathMap map[string]string

	// database index
	dbno db.DBNum

	// path indicates the yang path to which the key maps to.
	// When the input path maps to multiple db tables, the path field
	// identifies the yang segments for each db table.
	path *gnmi.Path

	// isOnChangeSupported indicates if on-change notification is
	// supported for the input path. Table and key mappings should
	// be filled even if on-change is not supported.
	isOnChangeSupported bool

	// mInterval indicates the minimum sample interval supported for
	// the input path. Can be set to 0 (default value) to indicate
	// system default interval.
	mInterval int

	// pType indicates the preferred notification type for the input
	// path. Used when gNMI client subscribes with "TARGET_DEFINED" mode.
	pType NotificationType
}

type notificationSubAppInfo struct {
	ntfAppInfoTrgt  []notificationAppInfo
	ntfAppInfoTrgtChlds []notificationAppInfo
}

// dbKeyInfo represents one db key.
type dbKeyInfo struct {
    // table name
    table db.TableSpec

    // key string without table name prefix.
    key db.Key

    // database index
    dbno db.DBNum

    // path template for the db key. Can include wild cards.
    path gnmi.Path
}

// subscribePathResponse defines response data structure of processSubscribe
// function.
type subscribePathResponse struct {
    // path indicates the yang path to which the db key maps to.
    path gnmi.Path
}


type notificationInfo struct{
	table               db.TableSpec
	key					db.Key
	dbno				db.DBNum
	needCache			bool
	path				string
	app				   *appInterface
	appInfo			   *appInfo
	cache			  []byte
	sKey			   *db.SKey
	dbs [db.MaxDB]	   *db.DB //used to perform get operations
}

type subscribeInfo struct{
	syncDone			bool
	q				   *queue.PriorityQueue
	nInfoArr		 []*notificationInfo
	stop				chan struct{}
	sDBs			 []*db.DB //Subscription DB should be used only for keyspace notification unsubscription
}

var nMap map[*db.SKey]*notificationInfo
var sMap map[*notificationInfo]*subscribeInfo
var stopMap map[chan struct{}]*subscribeInfo
var cleanupMap map[*db.DB]*subscribeInfo

func init() {
	nMap = make(map[*db.SKey]*notificationInfo)
	sMap = make(map[*notificationInfo]*subscribeInfo)
	stopMap	= make(map[chan struct{}]*subscribeInfo)
	cleanupMap	= make(map[*db.DB]*subscribeInfo)
}

func startDBSubscribe(opt db.Options, nInfoList []*notificationInfo, sInfo *subscribeInfo) error {
	var sKeyList []*db.SKey

	for _, nInfo := range nInfoList {
		sKey := &db.SKey{ Ts: &nInfo.table, Key: &nInfo.key}
		sKeyList = append(sKeyList, sKey)
		nInfo.sKey = sKey
		nMap[sKey] = nInfo
		sMap[nInfo] = sInfo
	}

	sDB, err := db.SubscribeDB(opt, sKeyList, notificationHandler)

	if err == nil {
		sInfo.sDBs = append(sInfo.sDBs, sDB)
		cleanupMap[sDB] = sInfo
	} else {
		for i, nInfo := range nInfoList {
			delete(nMap, sKeyList[i])
			delete(sMap, nInfo)
		}
	}

	return err
}

func notificationHandler(d *db.DB, sKey *db.SKey, key *db.Key, event db.SEvent) error {
    log.Info("notificationHandler: d: ", d, " sKey: ", *sKey, " key: ", *key,
        " event: ", event)
	switch event {
	case db.SEventHSet, db.SEventHDel, db.SEventDel:
		sMutex.Lock()
		defer sMutex.Unlock()

		if sKey != nil {
			if nInfo, ok := nMap[sKey]; (ok && nInfo != nil) {
				if sInfo, ok := sMap[nInfo]; (ok && sInfo != nil) {
					var chgdFields []string
					isChanged := isDbEntryChanged(d, *key, nInfo, &chgdFields, (event == db.SEventDel))
					log.Infof("notificationHandler: Changed Fields: %v", chgdFields)

					if isChanged {
						updateCache(nInfo) // Will be removed later on final integration
						sendNotification(sInfo, nInfo, false)
					}
				} else {
					log.Info("sInfo not in map", sInfo)
				}
			} else {
				log.Info("nInfo not in map", nInfo)
			}
		}
	case db.SEventClose:
	case db.SEventErr:
		if sInfo, ok := cleanupMap[d]; (ok && sInfo != nil) {
			nInfo := sInfo.nInfoArr[0]
			if nInfo != nil {
				sendNotification(sInfo, nInfo, true)
			}
		}
	}

    return nil
}

func updateCache(nInfo *notificationInfo) error {
	var err error

	json, err1 := getJson (nInfo)

	if err1 == nil {
		nInfo.cache = json
	} else {
		log.Error("Failed to get the Json for the path = ", nInfo.path)
		log.Error("Error returned = ", err1)

		nInfo.cache = []byte("{}")
	}

	return err
}

func isCacheChanged(nInfo *notificationInfo) bool {
	json, err := getJson (nInfo)

    if err != nil {
		json = []byte("{}")
	}

    if bytes.Equal(nInfo.cache, json) {
		log.Info("Cache is same as DB")
		return false
	} else {
		log.Info("Cache is NOT same as DB")
		nInfo.cache = json
		return true
	}

	return false
}

func isDbEntryChanged(subscrDb *db.DB, key db.Key, nInfo *notificationInfo, chgdFields *[]string, entryDeleted bool) bool {
	var dbEntry db.Value

	// Retrieve Db entry from redis using DB instance where pubsub is registered
	// for onChange only if entry is NOT deleted.
	if !entryDeleted {
		dbEntry, _ = subscrDb.GetEntry(&nInfo.table, key)
	}
	// Db instance in nInfo maintains cache. Compare modified dbEntry with cache
	// and retrieve modified fields. Also merge changes in cache
	*chgdFields = nInfo.dbs[subscrDb.Opts.DBNo].DiffAndMergeOnChangeCache(dbEntry, &nInfo.table, key, entryDeleted)

	return (entryDeleted || len(*chgdFields) > 0)
}

func startSubscribe(sInfo *subscribeInfo, dbNotificationMap map[db.DBNum][]*notificationInfo) error {
	var err error

    sMutex.Lock()
	defer sMutex.Unlock()

	stopMap[sInfo.stop] = sInfo

    for dbno, nInfoArr := range dbNotificationMap {
		isWriteDisabled := true
        opt := getDBOptions(dbno, isWriteDisabled)
        err = startDBSubscribe(opt, nInfoArr, sInfo)

		if err != nil {
			cleanup (sInfo.stop)
			return err
		}

        sInfo.nInfoArr = append(sInfo.nInfoArr, nInfoArr...)
    }

    for i, nInfo := range sInfo.nInfoArr {
        err = updateCache(nInfo)

		if err != nil {
			cleanup (sInfo.stop)
            return err
        }

		if i == len(sInfo.nInfoArr)-1 {
			sInfo.syncDone = true
		}

		sendNotification(sInfo, nInfo, false)
    }
	//printAllMaps()

	go stophandler(sInfo.stop)

	return err
}

func getJson (nInfo *notificationInfo) ([]byte, error) {
    var payload []byte

	app := nInfo.app
	path := nInfo.path
	appInfo := nInfo.appInfo

    err := appInitialize(app, appInfo, path, nil, nil, GET)

    if  err != nil {
        return payload, err
    }

	dbs := nInfo.dbs

    err = (*app).translateGet (dbs)

    if err != nil {
        return payload, err
    }

    resp, err := (*app).processGet(dbs)

    if err == nil {
        payload = resp.Payload
    }

    return payload, err
}

func sendNotification(sInfo *subscribeInfo, nInfo *notificationInfo, isTerminated bool){
	log.Info("Sending notification for sInfo = ", sInfo)
	log.Info("payload = ", string(nInfo.cache))
	log.Info("isTerminated", strconv.FormatBool(isTerminated))
	sInfo.q.Put(&SubscribeResponse{
			Path:nInfo.path,
			Payload:nInfo.cache,
			Timestamp:    time.Now().UnixNano(),
			SyncComplete: sInfo.syncDone,
			IsTerminated: isTerminated,
	})
}

func stophandler(stop chan struct{}) {
	for {
		stopSig := <-stop
		log.Info("stop channel signalled", stopSig)
		sMutex.Lock()
		defer sMutex.Unlock()

		cleanup (stop)

		return
	}
}

func cleanup(stop chan struct{}) {
	if sInfo,ok := stopMap[stop]; ok {

		for _, sDB := range sInfo.sDBs {
			sDB.UnsubscribeDB()
		}

		for _, nInfo := range sInfo.nInfoArr {
			delete(nMap, nInfo.sKey)
			delete(sMap, nInfo)
		}

		delete(stopMap, stop)
	}
	//printAllMaps()
}

/*
//Debugging functions
func printnMap() {
	log.Info("Printing the contents of nMap")
	for sKey, nInfo := range nMap {
		log.Info("sKey = ", sKey)
		log.Info("nInfo = ", nInfo)
	}
}

func printStopMap() {
	log.Info("Printing the contents of stopMap")
	for stop, sInfo := range stopMap {
		log.Info("stop = ", stop)
		log.Info("sInfo = ", sInfo)
	}
}

func printsMap() {
	log.Info("Printing the contents of sMap")
	for sInfo, nInfo := range sMap {
		log.Info("nInfo = ", nInfo)
		log.Info("sKey = ", sInfo)
	}
}

func printAllMaps() {
	printnMap()
	printsMap()
	printStopMap()
}*/
