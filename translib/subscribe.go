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
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/path"
	"github.com/Workiva/go-datastructures/queue"
	log "github.com/golang/glog"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
)

//Subscribe mutex for all the subscribe operations on the maps to be thread safe
var sMutex = &sync.Mutex{}

// notificationInfo flags
const (
	niLeafPath Bits = 1 << iota
	niWildcardPath
	niPartial
)

type notificationInfo struct {
	flags   Bits
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

func (sc *subscribeContext) add(subscribePath string, nAppSubInfo *translateSubResponse) {
	if sc.dbNInfos == nil {
		sc.dbNInfos = make(map[db.DBNum][]*notificationInfo)
	}

	log.Infof("Subscribe path \"%s\" mapped to %d primary and %d subtree notificationAppInfos",
		subscribePath, len(nAppSubInfo.ntfAppInfoTrgt), len(nAppSubInfo.ntfAppInfoTrgtChlds))

	for i, nAppInfo := range nAppSubInfo.ntfAppInfoTrgt {
		log.Infof("pri[%d] = %v", i, nAppInfo)
		nInfo := sc.addNInfo(nAppInfo)
		sc.tgtInfos = append(sc.tgtInfos, nInfo)
	}

	for i, nAppInfo := range nAppSubInfo.ntfAppInfoTrgtChlds {
		log.Infof("sub[%d] = %v", i, nAppInfo)
		sc.addNInfo(nAppInfo)
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

	if nAppInfo.isLeafPath() {
		nInfo.flags.Set(niLeafPath)
	}
	if nAppInfo.isPartial {
		nInfo.flags.Set(niPartial)
	}
	if path.HasWildcardKey(nAppInfo.path) {
		nInfo.flags.Set(niWildcardPath)
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

	topNode := []*yangNodeInfo{new(yangNodeInfo)}
	for _, k := range keys {
		ne.key = &k
		ne.sendNotification(nInfo, topNode)
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
func (ne *notificationEvent) findModifiedFields() ([]*yangNodeInfo, error) {
	nInfo := ne.nInfo

	// Db instance in nInfo maintains cache. Compare modified dbEntry with cache
	// and retrieve modified fields. Also merge changes in cache
	d := nInfo.sInfo.dbs[nInfo.dbno]
	entryDiff, err := d.DiffAndMergeOnChangeCache(nInfo.table, *ne.key, (ne.event == db.SEventDel))
	if err != nil {
		return nil, err
	}

	var modFields []*yangNodeInfo

	// When a new db entry is created, the notification infra can fetch full
	// content of target path.
	if entryDiff.EntryCreated {
		log.Infof("[%s] Entry created;", ne.id)
		modFields = append(modFields, &yangNodeInfo{})
		return modFields, nil
	}

	// Treat entry delete as update when 'partial' flag is set
	if entryDiff.EntryDeleted && nInfo.flags.Has(niPartial) {
		log.Infof("[%s] Entry deleted; but treating it as update", ne.id)
		modFields = ne.createYangPathInfos(nInfo, entryDiff.DeletedFields, false)
		if len(modFields) == 0 {
			log.Infof("[%s] empty entry; use target path", ne.id)
			modFields = append(modFields, &yangNodeInfo{})
		}
		return modFields, nil
	}

	// When entry is deleted, mark the whole target path as deleted if the
	if entryDiff.EntryDeleted {
		log.Infof("[%s] Entry deleted;", ne.id)
		modFields = append(modFields, &yangNodeInfo{deleted: true})
		return modFields, nil
	}

	// Collect yang leaf info for updated fields
	for _, f := range entryDiff.UpdatedFields {
		for _, nDbFldInfo := range nInfo.fields {
			if leaf, ok := nDbFldInfo.dbFldYgPathMap[f]; ok {
				log.Infof("[%s] Field %s modified; path=%s/%s", ne.id, f, nDbFldInfo.rltvPath, leaf)
				modFields = append(modFields, &yangNodeInfo{
					parentPrefix: nDbFldInfo.rltvPath,
					leafName:     leaf,
				})
			}
		}
	}

	// Collect yang leaf info for deleted fields
	for _, f := range entryDiff.DeletedFields {
		for _, nDbFldInfo := range nInfo.fields {
			if leaf, ok := nDbFldInfo.dbFldYgPathMap[f]; ok {
				log.Infof("[%s] Field %s deleted; path=%s/%s", ne.id, f, nDbFldInfo.rltvPath, leaf)
				modFields = append(modFields, &yangNodeInfo{
					parentPrefix: nDbFldInfo.rltvPath,
					leafName:     leaf,
					deleted:      true,
				})
			}
		}
	}

	log.V(3).Infof("[%s] findModifiedFields returns %v", ne.id, modFields)

	return modFields, err
}

func (ne *notificationEvent) createYangPathInfos(nInfo *notificationInfo, fields []string, isDelete bool) []*yangNodeInfo {
	var yInfos []*yangNodeInfo
	var opStr string
	if isDelete {
		opStr = "delete "
	}

	for _, f := range fields {
		for _, nDbFldInfo := range nInfo.fields {
			if leaf, ok := nDbFldInfo.dbFldYgPathMap[f]; ok {
				log.Infof("[%s] %sfield=%s, path=%s/%s", ne.id, opStr, f, nDbFldInfo.rltvPath, leaf)
				yInfos = append(yInfos, &yangNodeInfo{
					parentPrefix: nDbFldInfo.rltvPath,
					leafName:     leaf,
					deleted:      isDelete,
				})
			}
		}
	}

	return yInfos
}

func (ne *notificationEvent) getValue(path string) (ygot.ValidatedGoStruct, error) {
	var payload ygot.ValidatedGoStruct

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

	resp, err := (*app).processGet(dbs, TRANSLIB_FMT_YGOT)

	if err == nil {
		if resp.ValueTree != nil {
			payload = *resp.ValueTree
		} else {
			err = fmt.Errorf("nil value")
		}
	}

	return payload, err
}

func (ne *notificationEvent) dbkeyToYangPath(nInfo *notificationInfo) *gnmi.Path {
	in := processSubRequest{
		ctxID:  ne.id,
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

	out, err := (*nInfo.app).processSubscribe(&in)
	if err != nil {
		log.Warningf("[%s] processSubscribe returned err: %v", ne.id, err)
		return nil
	}

	if out.path == nil {
		log.Warningf("[%s] processSubscribe returned nil path", ne.id)
		return nil
	}

	if !path.Matches(out.path, nInfo.path) {
		log.Warningf("[%s] processSubscribe returned: %s", ne.id, path.String(out.path))
		log.Warningf("[%s] Expected path template   : %s", ne.id, path.String(nInfo.path))
		return nil
	}

	// Trim the output path if it is longer than nInfo.path
	if tLen := path.Len(nInfo.path); path.Len(out.path) > tLen {
		out.path = path.SubPath(out.path, 0, tLen)
	}

	if path.HasWildcardKey(out.path) {
		log.Warningf("[%s] processSubscribe did not resolve all wildcards: \"%s\"",
			ne.id, path.String(out.path))
		return nil
	}

	if log.V(3) {
		log.Infof("[%s] processSubscribe returned: %s", ne.id, path.String(out.path))
	}

	return out.path
}

func (ne *notificationEvent) sendNotification(nInfo *notificationInfo, fields []*yangNodeInfo) {
	prefix := nInfo.path
	if nInfo.flags.Has(niWildcardPath) {
		prefix = ne.dbkeyToYangPath(nInfo)
		if prefix == nil {
			log.Warningf("[%s] skip notification", ne.id)
			return
		}
	}

	sInfo := nInfo.sInfo
	prefixStr, err := ygot.PathToString(prefix)
	if err != nil {
		log.Warningf("[%s] skip notification -- %v", ne.id, err)
		return
	}

	resp := &SubscribeResponse{
		Path:      prefixStr,
		Timestamp: time.Now().UnixNano(),
	}

	log.Infof("[%s] preparing SubscribeResponse for %s", ne.id, prefixStr)
	var numUpdate uint32

	for _, lv := range fields {
		leafPath := lv.getPath()

		// Blindly treat DB delete as yang delete.. Will it work always??
		// Probably need an option for apps to customize this behavior.
		if lv.deleted {
			log.V(3).Infof("[%s] %s deleted", ne.id, leafPath)
			resp.Delete = append(resp.Delete, leafPath)
			continue
		}

		data, err := ne.getValue(prefixStr + leafPath)

		if sInfo.syncDone && isNotFoundError(err) {
			log.V(3).Infof("[%s] %s not found", ne.id, leafPath)
			resp.Delete = append(resp.Delete, leafPath)
			continue
		}
		if err != nil {
			log.Warningf("[%s] skip notification -- %v", ne.id, err)
			continue
		}

		log.V(3).Infof("[%s] %s = %v", ne.id, leafPath, data)
		lv.valueTree = data
		numUpdate++
	}

	switch {
	case numUpdate == 0:
		// No updates; retain resp.Path=prefixStr and resp.Update=nil
	case numUpdate == 1 && len(resp.Delete) == 0:
		// There is only one update and no deletes. Overwrite the resp.Path
		// to the parent node (because processGet returns GoStruct for the parent)
		lv, _ := nextYangNodeForUpdate(fields, 0)
		n := path.Len(prefix)
		if nInfo.flags.Has(niLeafPath) {
			pp := path.SubPath(prefix, 0, n-1)
			resp.Path, err = ygot.PathToString(pp)
		} else if !lv.isTargetNode(nInfo) {
			resp.Path = prefixStr + lv.parentPrefix
		} else {
			// Optimization for init sync/entry create of non-leaf target -- use the
			// GoStruct of the target node and retain full target path in resp.Path.
			// This longer prefix will produce more compact notification message.
			pp := path.SubPath(prefix, 0, n-1)
			cp := path.SubPath(prefix, n-1, n)
			lv.valueTree, err = getYgotAtPath(lv.valueTree, pp, cp)
		}

		resp.Update = lv.valueTree
		log.Infof("[%s] Single update case; Path=\"%s\", Update=%T",
			ne.id, resp.Path, resp.Update)

	default:
		// There are > 1 updates or 1 update with few delete paths. Hence retain resp.Path
		// as prefixStr itself. Coalesce the values by merging them into a new data tree.
		tmpRoot := new(ocbinds.Device)
		resp.Update, err = mergeYgotAtPath(tmpRoot, prefix, nil)
		if err != nil {
			break
		}

		log.Infof("[%s] Coalesce %d updates; Path=\"%s\", Update=%T",
			ne.id, numUpdate, resp.Path, resp.Update)
		lv, i := nextYangNodeForUpdate(fields, 0)
		for lv != nil && err == nil {
			_, err = mergeYgotAtPathStr(tmpRoot, prefixStr+lv.parentPrefix, lv.valueTree)
			lv, i = nextYangNodeForUpdate(fields, i+1)
		}
	}

	if err != nil {
		log.Warningf("[%s] skip notification -- %v", ne.id, err)
		return
	}

	log.Infof("[%s] Sending %d updates and %d deletes", ne.id, numUpdate, len(resp.Delete))
	sInfo.q.Put(resp)
}

func nextYangNodeForUpdate(nodes []*yangNodeInfo, indx int) (*yangNodeInfo, int) {
	for n := len(nodes); indx < n; indx++ {
		if nodes[indx].valueTree != nil {
			return nodes[indx], indx
		}
	}
	return nil, -1
}

// yangNodeInfo holds path and value for a yang leaf
type yangNodeInfo struct {
	parentPrefix string
	leafName     string
	deleted      bool
	valueTree    ygot.ValidatedGoStruct
}

func (lv *yangNodeInfo) getPath() string {
	if len(lv.leafName) == 0 {
		return lv.parentPrefix
	}
	return lv.parentPrefix + "/" + lv.leafName
}

// isTargetLeaf checks if this yang node is the target path of the notificationInfo.
func (lv *yangNodeInfo) isTargetNode(nInfo *notificationInfo) bool {
	return len(lv.parentPrefix) == 0 && len(lv.leafName) == 0
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
