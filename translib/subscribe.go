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
	"fmt"
	"sync"
	"time"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/path"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Workiva/go-datastructures/queue"
	log "github.com/golang/glog"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
)

//Subscribe mutex for all the subscribe operations on the maps to be thread safe
var sMutex = &sync.Mutex{}

// notificationAppInfo contains the details for monitoring db notifications
// for a given path. App modules provide these details for each subscribe
// path. One notificationAppInfo object must inclue details for one db table.
// One subscribe path can map to multiple notificationAppInfo.
type notificationAppInfo struct {
	// table name
	table *db.TableSpec

	// key string without table name prefix. Can include wildcards.
	// Like - "ACL1|RULE_101" or "ACL1|*".
	key *db.Key

	// dbFieldYangPathMap is the mapping of db entry field to the yang
	// field (leaf/leaf-list) for the input path.
	dbFldYgPathInfoList []*dbFldYgPathInfo

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

	// opaque data can be used to store context information to assist
	// future key-to-path translations. This is an optional data item.
	// Apps can store any context information based on their logic.
	// Translib passes this back to the processSubscribe function.
	opaque interface{}
}

type dbFldYgPathInfo struct {
	rltvPath       string
	dbFldYgPathMap map[string]string //db field to leaf / rel. path to leaf
}

type notificationSubAppInfo struct {
	ntfAppInfoTrgt      []notificationAppInfo
	ntfAppInfoTrgtChlds []notificationAppInfo
}

// dbKeyInfo represents one db key.
type dbKeyInfo struct {
	// table name
	table *db.TableSpec

	// key string without table name prefix.
	key *db.Key

	// database index
	dbno db.DBNum

	// path template for the db key. Can include wild cards.
	path *gnmi.Path

	// List of all DB objects. Apps should only use these DB objects
	// to query db if they need additional data for translation.
	dbs [db.MaxDB]*db.DB

	// App specific opaque data -- can be used to pass context data
	// between translateSubscribe and processSubscribe.
	opaque interface{}
}

// subscribePathResponse defines response data structure of processSubscribe
// function.
type subscribePathResponse struct {
	// path indicates the yang path to which the db key maps to.
	path *gnmi.Path
}

type notificationInfo struct {
	table   *db.TableSpec
	key     *db.Key
	dbno    db.DBNum
	fields  []*dbFldYgPathInfo // map of db field to yang fields map
	path    *gnmi.Path         // Path to which the db key maps to
	app     *appInterface
	appInfo *appInfo
	sInfo   *subscribeInfo
	opaque  interface{} // App specific opaque data
}

type subscribeInfo struct {
	id       uint64 // Subscribe request id
	syncDone bool
	q        *queue.PriorityQueue
	nInfoArr []*notificationInfo
	stop     chan struct{}
	sDBs     []*db.DB         //Subscription DB should be used only for keyspace notification unsubscription
	dbs      [db.MaxDB]*db.DB //used to perform get operations
}

// notificationEvent holds data about translib notification.
type notificationEvent struct {
	id    string            // Unique id for logging
	event db.SEvent         // DB notification type, if any
	key   *db.Key           // DB key, if any
	db    *db.DB            // DB object on which this event was received
	nInfo *notificationInfo // Registration data
}

// subscribeCounter counts number of Subscribe calls.
var subscribeCounter Counter

// dbNotificationCounter counts number of db notification processed.
// Used to derive notificationID
var dbNotificationCounter Counter

var stopMap map[chan struct{}]*subscribeInfo
var cleanupMap map[*db.DB]*subscribeInfo

func init() {
	stopMap = make(map[chan struct{}]*subscribeInfo)
	cleanupMap = make(map[*db.DB]*subscribeInfo)
}

func startDBSubscribe(opt db.Options, nInfoList []*notificationInfo, sInfo *subscribeInfo) error {
	var sKeyList []*db.SKey

	for _, nInfo := range nInfoList {
		sKey := &db.SKey{
			Ts:     nInfo.table,
			Key:    nInfo.key,
			Opaque: nInfo,
		}
		sKeyList = append(sKeyList, sKey)

		//
		d := sInfo.dbs[nInfo.dbno]
		d.RegisterTableForOnChangeCaching(nInfo.table)
	}

	sDB, err := db.SubscribeDB(opt, sKeyList, notificationHandler)

	if err == nil {
		sInfo.sDBs = append(sInfo.sDBs, sDB)
		cleanupMap[sDB] = sInfo
	}

	return err
}

func notificationHandler(d *db.DB, sKey *db.SKey, key *db.Key, event db.SEvent) error {
	nid := dbNotificationCounter.Next()
	log.Infof("[%d] notificationHandler: d=%p, sKey=%v, key=%v, event=%v",
		nid, d, sKey, key, event)

	switch event {
	case db.SEventHSet, db.SEventHDel, db.SEventDel:
		// TODO revisit mutex usage
		sMutex.Lock()
		defer sMutex.Unlock()

		if sKey != nil {
			if nInfo, ok := sKey.Opaque.(*notificationInfo); ok {
				n := notificationEvent{
					id:    fmt.Sprintf("%d:%d", nInfo.sInfo.id, nid),
					event: event,
					key:   key,
					db:    d,
					nInfo: nInfo,
				}
				n.process()
			} else {
				log.Warningf("[%d] notificationHandler: SKey corrupted; nil opaque. %v", nid, *sKey)
			}
		}
	case db.SEventClose:
	case db.SEventErr:
		if sInfo, ok := cleanupMap[d]; ok && sInfo != nil {
			nInfo := sInfo.nInfoArr[0]
			if nInfo != nil {
				sendSyncNotification(sInfo, true)
			}
		}
	}

	return nil
}

type subscribeContext struct {
	sInfo    *subscribeInfo
	dbNInfos map[db.DBNum][]*notificationInfo
	tgtInfos []*notificationInfo

	app     *appInterface
	appInfo *appInfo
}

func (sc *subscribeContext) add(nAppSubInfo *notificationSubAppInfo) {
	if sc.dbNInfos == nil {
		sc.dbNInfos = make(map[db.DBNum][]*notificationInfo)
	}

	for _, nAppInfo := range nAppSubInfo.ntfAppInfoTrgt {
		nInfo := sc.addNInfo(&nAppInfo)
		sc.tgtInfos = append(sc.tgtInfos, nInfo)
	}

	for _, nAppInfo := range nAppSubInfo.ntfAppInfoTrgtChlds {
		sc.addNInfo(&nAppInfo)
	}
}

func (sc *subscribeContext) addNInfo(nAppInfo *notificationAppInfo) *notificationInfo {
	d := nAppInfo.dbno
	nInfo := &notificationInfo{
		dbno:    d,
		table:   nAppInfo.table,
		key:     nAppInfo.key,
		fields:  nAppInfo.dbFldYgPathInfoList,
		path:    nAppInfo.path,
		app:     sc.app,
		appInfo: sc.appInfo,
		sInfo:   sc.sInfo,
		opaque:  nAppInfo.opaque,
	}

	// Make sure field prefix path has a leading and trailing "/".
	// Helps preparing full path later by joining parts
	for _, pi := range nAppInfo.dbFldYgPathInfoList {
		if len(pi.rltvPath) != 0 && pi.rltvPath[0] != '/' {
			pi.rltvPath = "/" + pi.rltvPath
		}
	}

	sc.dbNInfos[d] = append(sc.dbNInfos[d], nInfo)
	return nInfo
}

func (sc *subscribeContext) startSubscribe() error {
	var err error

	sMutex.Lock()
	defer sMutex.Unlock()

	sInfo := sc.sInfo

	stopMap[sInfo.stop] = sInfo

	for dbno, nInfoArr := range sc.dbNInfos {
		isWriteDisabled := true
		opt := getDBOptions(dbno, isWriteDisabled)
		err = startDBSubscribe(opt, nInfoArr, sInfo)

		if err != nil {
			log.Warningf("[%d] db subscribe failed -- %v", sInfo.id, err)
			cleanup(sInfo.stop)
			return err
		}

		sInfo.nInfoArr = append(sInfo.nInfoArr, nInfoArr...)
	}

	for _, nInfo := range sc.tgtInfos {
		err := sendInitialUpdate(sInfo, nInfo)
		if err != nil {
			log.Warningf("[%d] init sync failed -- %v", sInfo.id, err)
			cleanup(sInfo.stop)
			return err
		}
	}

	sInfo.syncDone = true
	sendSyncNotification(sInfo, false)

	go stophandler(sInfo.stop)

	return err
}

// sendInitialUpdate sends the initial sync updates to the caller.
// Performs following steps:
//  1) Scan all keys for the table
//  2) Map each key to yang path
//  3) Get value for each path and send the notification message
func sendInitialUpdate(sInfo *subscribeInfo, nInfo *notificationInfo) error {
	db := sInfo.dbs[int(nInfo.dbno)]
	ne := notificationEvent{
		id:    fmt.Sprintf("%d:0", sInfo.id),
		nInfo: nInfo,
	}

	keys, err := db.GetKeysPattern(nInfo.table, *nInfo.key)
	if err != nil {
		return err
	}

	for _, k := range keys {
		ne.key = &k
		ne.sendNotification(nInfo, nil)
	}

	return nil
}

func sendSyncNotification(sInfo *subscribeInfo, isTerminated bool) {
	log.Infof("[%d] Sending syncDone=%v, isTerminated=%v",
		sInfo.id, sInfo.syncDone, isTerminated)
	sInfo.q.Put(&SubscribeResponse{
		Timestamp:    time.Now().UnixNano(),
		SyncComplete: sInfo.syncDone,
		IsTerminated: isTerminated,
	})
}

// process translates db notification into SubscribeResponse and
// pushes to the caller.
func (ne *notificationEvent) process() {
	modFields, err := ne.findModifiedFields()
	if err != nil {
		log.Warningf("[%s] error finding modified fields: %v", ne.id, err)
		return
	}
	if len(modFields) == 0 {
		log.Infof("[%s] no fields updated", ne.id)
		return
	}

	ne.sendNotification(ne.nInfo, modFields)
}

// findModifiedFields determines db fields changed since last notification
func (ne *notificationEvent) findModifiedFields() ([]string, error) {
	nInfo := ne.nInfo
	entryDeleted := true
	var dbEntry db.Value

	// Retrieve Db entry from redis using DB instance where pubsub is registered
	// for onChange only if entry is NOT deleted.
	// TODO this can fail if db caching is enabled in the system.
	// TODO move this functionality inside DiffAndMergeOnChangeCache itself
	if ne.event != db.SEventDel {
		dbEntry, _ = ne.db.GetEntry(nInfo.table, *ne.key)
		entryDeleted = false
	}

	// Db instance in nInfo maintains cache. Compare modified dbEntry with cache
	// and retrieve modified fields. Also merge changes in cache
	chgFields := nInfo.sInfo.dbs[nInfo.dbno].DiffAndMergeOnChangeCache(dbEntry, nInfo.table, *ne.key, entryDeleted)

	log.V(3).Infof("[%s] findModifiedFields: changed db fields: %v", ne.id, chgFields)
	log.V(3).Infof("[%s] findModifiedFields: monitored fields: %v", ne.id, nInfo.fields)

	var modFields []string
	for _, f := range chgFields {
		for _, nDbFldInfo := range nInfo.fields {
			if _, ok := nDbFldInfo.dbFldYgPathMap[f]; ok {
				modFields = append(modFields, f)
				break
			}
		}
	}

	log.V(3).Infof("[%s] findModifiedFields returns %v", ne.id, modFields)

	return modFields, nil
}

func (ne *notificationEvent) getValue(path string) ([]byte, error) {
	var payload []byte

	nInfo := ne.nInfo
	app := nInfo.app
	appInfo := nInfo.appInfo
	dbs := nInfo.sInfo.dbs

	err := appInitialize(app, appInfo, path, nil, nil, GET)

	if err != nil {
		return payload, err
	}

	err = (*app).translateGet(dbs)

	if err != nil {
		return payload, err
	}

	resp, err := (*app).processGet(dbs, TRANSLIB_FMT_IETF_JSON)

	if err == nil {
		payload = resp.Payload
	}

	return payload, err
}

func (ne *notificationEvent) dbkeyToYangPath(nInfo *notificationInfo) (*gnmi.Path, error) {
	in := dbKeyInfo{
		dbno:   nInfo.dbno,
		table:  nInfo.table,
		key:    ne.key,
		dbs:    nInfo.sInfo.dbs,
		opaque: nInfo.opaque,
		path:   path.Clone(nInfo.path),
	}

	log.Infof("[%s] Call processSubscribe with dbno=%d, table=%s, key=%v",
		ne.id, in.dbno, in.table.Name, in.key)
	if log.V(3) {
		log.Infof("[%s] Path template: %s", ne.id, path.String(in.path))
	}

	out, err := (*nInfo.app).processSubscribe(in)
	if err != nil {
		return nil, fmt.Errorf("processSubscribe err=%v", err)
	}
	if log.V(3) {
		log.Infof("[%s] processSubscribe returned: %s", ne.id, path.String(out.path))
	}

	// TODO check if response path is valid and does not include wildcards

	return out.path, nil
}

func (ne *notificationEvent) sendNotification(nInfo *notificationInfo, fields []string) {
	prefix := nInfo.path
	if path.HasWildcardKey(prefix) {
		var err error
		prefix, err = ne.dbkeyToYangPath(nInfo)
		if err != nil {
			log.Warningf("[%s] skip notification -- %v", ne.id, err)
			return
		}
	}

	paths := make([]string, 0, len(fields))
	sInfo := nInfo.sInfo
	prefixStr, err := ygot.PathToString(prefix)
	if err != nil {
		log.Warningf("[%s] skip notification -- %v", ne.id, err)
		return
	}

	for _, f := range fields {
		for _, nDbFldInfo := range nInfo.fields {
			if suffix, ok := nDbFldInfo.dbFldYgPathMap[f]; ok {
				paths = append(paths, prefixStr+nDbFldInfo.rltvPath+"/"+suffix)
				break
			}
		}
	}

	// Load whole container/list if fields are not specified.
	// Used for initial sync messages
	if len(fields) == 0 {
		paths = append(paths, prefixStr)
	}

	for _, p := range paths {
		data, err := ne.getValue(p)
		if _, ok := err.(tlerr.NotFoundError); ok && sInfo.syncDone {
			// Ignore "not found" errors before after sync done
			err = nil
		}

		if err == nil {
			// TODO combine all values into single payload.
			log.Infof("[%s] Sending SubscribeResponse for path %s", ne.id, p)
			log.V(1).Infof("[%s] data = %s", ne.id, data)

			sInfo.q.Put(&SubscribeResponse{
				Path:         p,
				Payload:      data,
				Timestamp:    time.Now().UnixNano(), // TODO
				SyncComplete: sInfo.syncDone,
			})
		} else {
			log.Warningf("[%s] skip notification -- %v", ne.id, err)
		}
	}
}

func stophandler(stop chan struct{}) {
	for {
		stopSig := <-stop
		log.Info("stop channel signalled", stopSig)
		sMutex.Lock()
		defer sMutex.Unlock()

		cleanup(stop)

		return
	}
}

func cleanup(stop chan struct{}) {
	if sInfo, ok := stopMap[stop]; ok {
		log.Infof("[s%d] stopping..", sInfo.id)

		for _, sDB := range sInfo.sDBs {
			sDB.UnsubscribeDB()
		}

		closeAllDbs(sInfo.dbs[:])

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
