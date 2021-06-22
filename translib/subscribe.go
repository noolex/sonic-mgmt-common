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
	"strings"
	"sync"
	"time"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/path"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
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
	niOnChangeSupported
	niKeyFields // some db fields mapped to yang keys
)

type notificationInfo struct {
	flags   Bits
	table   *db.TableSpec
	key     *db.Key
	dbno    db.DBNum
	fields  []*dbFldYgPathInfo // map of db field to yang fields map
	path    *gnmi.Path         // Path to which the db key maps to
	appInfo *appInfo
	sInfo   *subscribeInfo
	opaque  interface{} // App specific opaque data
}

// subscribeInfo holds the client data of Subscribe or Stream request.
// Should not be reused across multiple API calls.
type subscribeInfo struct {
	id       uint64 // Subscribe request id
	syncDone bool
	termDone bool // Terminate message has been sent
	q        *queue.PriorityQueue
	stop     chan struct{}
	sDBs     []*db.DB         //Subscription DB should be used only for keyspace notification unsubscription
	dbs      [db.MaxDB]*db.DB //used to perform get operations
}

// SubscribeSession is used to share session data between subscription
// related APIs - IsSubscribeSupported, Subscribe and Stream.
type SubscribeSession struct {
	ID       string
	pathData map[string]*translatedSubData
}

// translatedSubData holds translated subscription data for a path.
type translatedSubData struct {
	targetInfos []*notificationInfo
	childInfos  []*notificationInfo
}

// notificationGroup is the grouping of notificationInfo by the key pattern.
type notificationGroup struct {
	nInfos map[string][]*notificationInfo
	//TODO move dbno, TS, key from notificationInfo to here
}

// notificationEvent holds data about translib notification.
type notificationEvent struct {
	id    string             // Unique id for logging
	event db.SEvent          // DB notification type, if any
	key   *db.Key            // DB key, if any
	entry *db.Value          // DB entry
	db    *db.DB             // DB object on which this event was received
	nGrup *notificationGroup // Target notificationGroup for the event
	sInfo *subscribeInfo

	// Meta info for processSubscribe calls
	forceProcessSub bool
	keyGroupComps   []int
	appCache        map[*appInfo]appInterface
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

func startDBSubscribe(opt db.Options, nGroups map[db.TableSpec]*notificationGroup, sInfo *subscribeInfo) error {
	var sKeyList []*db.SKey
	d := sInfo.dbs[int(opt.DBNo)]

	for tSpec, nGroup := range nGroups {
		skeys := nGroup.toSKeys()
		if len(skeys) == 0 {
			continue // should not happen
		}

		log.Infof("[%v] nGroup=%p:%v", sInfo.id, nGroup, nGroup.toString())

		sKeyList = append(sKeyList, skeys...)

		d.RegisterTableForOnChangeCaching(&tSpec)
	}

	sDB, err := db.SubscribeDB(opt, sKeyList, notificationHandler)

	if err == nil {
		sInfo.sDBs = append(sInfo.sDBs, sDB)
		cleanupMap[sDB] = sInfo
	}

	return err
}

func notificationHandler(d *db.DB, sKey *db.SKey, key *db.Key, event db.SEvent) error {
	nid := fmt.Sprintf("ne%d", dbNotificationCounter.Next())
	log.Infof("[%v] notificationHandler: d=%v, table=%v, kayPattern=%v, key=%v, event=%v",
		nid, dbInfo(d), tableInfo(sKey.Ts), keyInfo(sKey.Key), keyInfo(key), event)

	sMutex.Lock()
	defer sMutex.Unlock()

	switch event {
	case db.SEventHSet, db.SEventHDel, db.SEventDel:

		if sKey != nil {
			if nGrup, ok := sKey.Opaque.(*notificationGroup); ok {
				n := notificationEvent{
					id:    nid,
					event: event,
					key:   key,
					db:    d,
					nGrup: nGrup,
				}
				n.process()
			} else {
				log.Warningf("[%v] notificationHandler: SKey corrupted; nil opaque. %v", nid, *sKey)
			}
		}

	case db.SEventClose:
		// Close event would have been triggered due to unsubscribe on stop request
		delete(cleanupMap, d)

	case db.SEventErr:
		// Unexpected error in db layer.. Terminate the subscribe request.
		if sInfo, ok := cleanupMap[d]; ok && sInfo != nil && !sInfo.termDone {
			sendSyncNotification(sInfo, true)
			sInfo.termDone = true
		}
		delete(cleanupMap, d)
	}

	return nil
}

type subscribeContext struct {
	id      uint64 // context id
	dbs     [db.MaxDB]*db.DB
	version Version
	mode    NotificationType
	session *SubscribeSession
	sInfo   *subscribeInfo

	dbNInfos map[db.DBNum]map[db.TableSpec]*notificationGroup
	tgtInfos []*notificationInfo
}

func (sc *subscribeContext) newNInfo(nAppInfo *notificationAppInfo, aInfo *appInfo) *notificationInfo {
	nInfo := &notificationInfo{
		dbno:    nAppInfo.dbno,
		table:   nAppInfo.table,
		key:     nAppInfo.key,
		fields:  nAppInfo.dbFldYgPathInfoList,
		path:    nAppInfo.path,
		appInfo: aInfo,
		sInfo:   sc.sInfo,
		opaque:  nAppInfo.opaque,
	}

	// Make sure field prefix path has a leading and trailing "/".
	// Helps preparing full path later by joining parts
	for _, pi := range nInfo.fields {
		if len(pi.rltvPath) != 0 && pi.rltvPath[0] != '/' {
			pi.rltvPath = "/" + pi.rltvPath
		}
		// Look for fields mapped to yang key - formatted as "{xyz}"
		for _, leaf := range pi.dbFldYgPathMap {
			if len(leaf) != 0 && leaf[0] == '{' {
				nInfo.flags.Set(niKeyFields)
			}
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
	if nAppInfo.isOnChangeSupported {
		nInfo.flags.Set(niOnChangeSupported)
	}

	return nInfo
}

func (sc *subscribeContext) addToNGroup(nInfo *notificationInfo) {
	d := nInfo.dbno
	tKey := *nInfo.table
	nGrp := sc.dbNInfos[d][tKey]
	if nGrp == nil {
		nGrp = new(notificationGroup)
		if tMap := sc.dbNInfos[d]; tMap != nil {
			tMap[tKey] = nGrp
		} else {
			sc.dbNInfos[d] = map[db.TableSpec]*notificationGroup{tKey: nGrp}
		}
	}

	nGrp.add(nInfo)
	nInfo.sInfo = sc.sInfo
}

// saveTranslatedData saves the translatedSubData into the SubscribeSession
func (sc *subscribeContext) saveTranslatedData(path string, trData *translatedSubData) {
	if sc.session == nil || trData == nil {
		return
	}
	if sc.session.pathData == nil {
		sc.session.pathData = make(map[string]*translatedSubData)
	}
	log.Infof("[%v] set trData %p in session for \"%s\"", sc.id, trData, path)
	sc.session.pathData[path] = trData
}

func (sc *subscribeContext) translateAndAddPath(path string) error {
	var trData *translatedSubData
	var err error

	if sc.session != nil {
		trData = sc.session.pathData[path]
		log.Infof("[%v] found trData %p from session for '%s'", sc.id, trData, path)
	}
	if trData == nil {
		_, trData, err = sc.translatePath(path)
	}
	if err != nil {
		return err
	}

	sc.tgtInfos = append(sc.tgtInfos, trData.targetInfos...)

	// Group nInfo by table and key pattern for OnChange.
	// Required for registering db subscriptions.
	if sc.mode == OnChange {
		if sc.dbNInfos == nil {
			sc.dbNInfos = make(map[db.DBNum]map[db.TableSpec]*notificationGroup)
		}
		for _, nInfo := range trData.targetInfos {
			sc.addToNGroup(nInfo)
		}
		for _, nInfo := range trData.childInfos {
			sc.addToNGroup(nInfo)
		}
	}

	return nil
}

func (sc *subscribeContext) translatePath(path string) (*translateSubResponse, *translatedSubData, error) {
	sid := sc.id
	app, appInfo, err := getAppModule(path, sc.version)
	if err != nil {
		return nil, nil, err
	}

	nAppInfos, err := (*app).translateSubscribe(
		&translateSubRequest{
			ctxID: sid,
			path:  path,
			mode:  sc.mode,
			dbs:   sc.dbs,
		})

	if err != nil {
		log.Warningf("[%v] translateSubscribe failed for \"%s\"; err=%v", sid, path, err)
		return nAppInfos, nil, err
	}
	if nAppInfos == nil {
		log.Warningf("%T.translateSubscribe returned nil for path: %s", *app, path)
		return nAppInfos, nil, fmt.Errorf("Error processing path: %s", path)
	}

	targetLen := len(nAppInfos.ntfAppInfoTrgt)
	childLen := len(nAppInfos.ntfAppInfoTrgtChlds)
	subData := &translatedSubData{
		targetInfos: make([]*notificationInfo, targetLen),
		childInfos:  make([]*notificationInfo, childLen),
	}

	log.Infof("[%v] Path \"%s\" mapped to %d target and %d child notificationAppInfos",
		sid, path, targetLen, childLen)

	for i, nAppInfo := range nAppInfos.ntfAppInfoTrgt {
		log.Infof("[%v] targetInfo[%d] = %v", sid, i, nAppInfo)
		subData.targetInfos[i] = sc.newNInfo(nAppInfo, appInfo)
	}

	for i, nAppInfo := range nAppInfos.ntfAppInfoTrgtChlds {
		log.Infof("[%v] childInfo[%d] = %v", sid, i, nAppInfo)
		subData.childInfos[i] = sc.newNInfo(nAppInfo, appInfo)
	}

	return nAppInfos, subData, err
}

func (sc *subscribeContext) startSubscribe() error {
	var err error

	sMutex.Lock()
	defer sMutex.Unlock()

	sInfo := sc.sInfo

	stopMap[sInfo.stop] = sInfo

	for dbno, nGroups := range sc.dbNInfos {
		isWriteDisabled := true
		opt := getDBOptions(dbno, isWriteDisabled)
		err = startDBSubscribe(opt, nGroups, sInfo)

		if err != nil {
			log.Warningf("[%d] db subscribe failed -- %v", sInfo.id, err)
			cleanup(sInfo.stop)
			return err
		}
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

// add a notificationInfo to the notificationGroup
func (ng *notificationGroup) add(nInfo *notificationInfo) {
	keyStr := strings.Join(nInfo.key.Comp, "/")
	if ng.nInfos == nil {
		ng.nInfos = map[string][]*notificationInfo{keyStr: {nInfo}}
	} else {
		ng.nInfos[keyStr] = append(ng.nInfos[keyStr], nInfo)
	}
}

// toSKeys prepares DB subscribe keys for the notificationGroup
func (ng *notificationGroup) toSKeys() []*db.SKey {
	skeys := make([]*db.SKey, 0, len(ng.nInfos))
	for _, nInfoList := range ng.nInfos {
		// notificationInfo are already segregated by key patterns. So we can
		// just use 1st entry from this sub-group for getting table and key patterns.
		// TODO avoid redundant registrations of matching patterns (like "PORT|Eth1" and "PORT|*")
		nInfo := nInfoList[0]
		skeys = append(skeys, &db.SKey{
			Ts:     nInfo.table,
			Key:    nInfo.key,
			Opaque: ng,
		})
	}
	return skeys
}

func (ng *notificationGroup) toString() string {
	var nInfo *notificationInfo
	comps := make([][]string, 0, len(ng.nInfos))
	for _, nInfoList := range ng.nInfos {
		nInfo = nInfoList[0]
		comps = append(comps, nInfo.key.Comp)
	}
	return fmt.Sprintf("{dbno=%d, table=%s, patterns=%v}", nInfo.dbno, nInfo.table.Name, comps)
}

// sendInitialUpdate sends the initial sync updates to the caller.
// Performs following steps:
//  1) Scan all keys for the table
//  2) Map each key to yang path
//  3) Get value for each path and send the notification message
func sendInitialUpdate(sInfo *subscribeInfo, nInfo *notificationInfo) error {
	ne := notificationEvent{
		id:    fmt.Sprintf("%d:0", sInfo.id),
		sInfo: sInfo,
	}

	topNode := []*yangNodeInfo{new(yangNodeInfo)}

	if nInfo.table == nil { // non-db case
		if nInfo.flags.Has(niWildcardPath) {
			p := path.String(nInfo.path)
			log.Warningf("[%s] Wildcard not supported for non-db path \"%s\"", ne.id, p)
			return tlerr.NotSupportedErr("", p, "Unsupported wildcard path")
		}

		ne.sendNotification(nInfo, topNode)
		return nil
	}

	// DB path.. iterate over keys and generate notification for each.

	opts := db.ScanCursorOpts{}
	d := sInfo.dbs[int(nInfo.dbno)]
	cursor, err := d.NewScanCursor(nInfo.table, *nInfo.key, &opts)
	if err != nil {
		log.Errorf("[%s] Failed to create db cursor for %d/%s/%v; err=%v",
			ne.id, nInfo.dbno, nInfo.table.Name, nInfo.key, err)
		return err
	}

	defer cursor.DeleteScanCursor()
	var ddup map[string]bool
	var keys []db.Key

	if nInfo.key.IsPattern() && !nInfo.flags.Has(niWildcardPath) {
		log.Infof("[%s] db key is a glob pattern. Forcing processSubscribe..", ne.id)
		ne.forceProcessSub = true
	}

	for done := false; !done; {
		keys, done, err = cursor.GetNextKeys(&opts)
		if err != nil {
			log.Infof("[%s] Failed to read db cursor for %d/%s/%v; err=%v",
				ne.id, nInfo.dbno, nInfo.table.Name, nInfo.key, err)
			return err
		}

		for _, k := range keys {
			ne.key = &k
			if ddk := ne.getDdupKey(); len(ddk) != 0 && ddup[ddk] {
				log.Infof("[%s] skip init sync for key %v; another key with matching comps %v has been processed",
					ne.id, k.Comp, ne.keyGroupComps)
				continue
			}

			if v, err := d.GetEntry(nInfo.table, k); err != nil {
				log.Infof("[%v] Table %s key %v not found; skip initial sync",
					ne.id, nInfo.table.Name, k.Comp)
				continue
			} else {
				ne.entry = &v
			}

			ne.sendNotification(nInfo, topNode)

			if ddk := ne.getDdupKey(); len(ddk) != 0 {
				if ddup == nil {
					ddup = make(map[string]bool)
				}
				ddup[ddk] = true
			}
		}
	}

	return nil
}

func sendSyncNotification(sInfo *subscribeInfo, isTerminated bool) {
	log.Infof("[%v] Sending SubscribeResponse{syncDone=%v, isTerminated=%v}",
		sInfo.id, sInfo.syncDone, isTerminated)
	sInfo.q.Put(&SubscribeResponse{
		Timestamp:    time.Now().UnixNano(),
		SyncComplete: sInfo.syncDone,
		IsTerminated: isTerminated,
	})
}

func (ne *notificationEvent) getDdupKey() string {
	if len(ne.keyGroupComps) == 0 {
		return ""
	}

	kLen := ne.key.Len()
	uniq := make([]string, len(ne.keyGroupComps))
	for i, v := range ne.keyGroupComps {
		if v < 0 || v >= kLen {
			log.Warningf("[%s] app returned invalid component index %d; key=%v",
				ne.id, i, ne.key.Comp)
			return ""
		}
		uniq[i] = ne.key.Get(v)
	}

	return strings.Join(uniq, "|")
}

// process translates db notification into SubscribeResponse and
// pushes to the caller.
func (ne *notificationEvent) process() {
	dbDiff, err := ne.DiffAndMergeOnChangeCache()
	if err != nil {
		log.Warningf("[%s] error finding modified db fields: %v", ne.id, err)
		return
	}

	// Find all key patterns that match current key
	for _, nInfos := range ne.nGrup.nInfos {
		keyPattern := nInfos[0].key
		if !ne.key.Matches(keyPattern) {
			log.V(3).Infof("[%s] Key %v does not match pattern %v",
				ne.id, ne.key.Comp, keyPattern.Comp)
			continue
		}

		log.Infof("[%s] Key %v matches registered pattern %v; has %d nInfos",
			ne.id, ne.key.Comp, keyPattern.Comp, len(nInfos))

		for _, nInfo := range nInfos {
			ne.sInfo = nInfo.sInfo
			log.Infof("[%s] processing path: %s", ne.id, path.String(nInfo.path))

			yInfos := ne.findModifiedFields(nInfo, dbDiff)
			changed := false
			if len(yInfos.old) != 0 {
				changed = true
				ne.entry = &dbDiff.oldValue
				ne.sendNotification(nInfo, yInfos.old)
			}
			if len(yInfos.new) != 0 {
				changed = true
				ne.entry = &dbDiff.newValue
				ne.sendNotification(nInfo, yInfos.new)
			}
			if !changed {
				log.Infof("[%s] no fields updated", ne.id)
			}
		}
	}
}

type onchangeCacheDiff struct {
	oldValue      db.Value
	newValue      db.Value
	EntryCreated  bool
	EntryDeleted  bool
	CreatedFields []string
	UpdatedFields []string
	DeletedFields []string
}

func (c *onchangeCacheDiff) String() string {
	return fmt.Sprintf(
		"{EntryCreated=%t, EntryDeleted=%t, CreatedFields=%v, UpdatedFields=%v, DeletedFields=%v}",
		c.EntryCreated, c.EntryDeleted, c.CreatedFields, c.UpdatedFields, c.DeletedFields)
}

// DiffAndMergeOnChangeCache Compare modified entry with cached entry and
// return modified fields. Also update the cache with changes.
func (ne *notificationEvent) DiffAndMergeOnChangeCache() (*onchangeCacheDiff, error) {
	// Randomly pick one nInfo from the notificationGroup for db diff. Should
	// not access key, path or path related data here.
	var nInfo *notificationInfo
	for _, n := range ne.nGrup.nInfos {
		nInfo = n[0]
		break
	}

	ts := nInfo.table
	d := nInfo.sInfo.dbs[nInfo.dbno]
	key := ne.key
	entryDeleted := (ne.event == db.SEventDel)

	cachedEntry, val, e := d.OnChangeCacheUpdate(ts, *key)

	cacheEntryDiff := &onchangeCacheDiff{
		oldValue: cachedEntry,
		newValue: val,
	}

	exists := !((e != nil) || (len(cachedEntry.Field) == 0))
	if exists { // Already exists in cache

		if entryDeleted {
			// Entry deleted.
			cacheEntryDiff.EntryDeleted = true
			return cacheEntryDiff, nil
		}

		for fldName := range cachedEntry.Field {
			if fldName == "NULL" {
				continue
			}
			if _, fldOk := val.Field[fldName]; !fldOk {
				cacheEntryDiff.DeletedFields = append(
					cacheEntryDiff.DeletedFields, strings.TrimSuffix(fldName, "@"))
			}
		}

		for nf, nv := range val.Field {
			if nf == "NULL" {
				continue
			}
			if cv, exists := cachedEntry.Field[nf]; !exists {
				cacheEntryDiff.CreatedFields = append(
					cacheEntryDiff.CreatedFields, strings.TrimSuffix(nf, "@"))
			} else if cv != nv {
				cacheEntryDiff.UpdatedFields = append(
					cacheEntryDiff.UpdatedFields, strings.TrimSuffix(nf, "@"))
			}
		}

	} else if !entryDeleted {
		// Not exists in cache
		cacheEntryDiff.EntryCreated = true
	}

	log.Infof("[%s] DiffAndMergeOnChangeCache: %v", ne.id, cacheEntryDiff)

	return cacheEntryDiff, nil
}

func (ne *notificationEvent) getFieldNames(v db.Value) []string {
	var fields []string
	for f := range v.Field {
		if f != "NULL" {
			fields = append(fields, strings.TrimSuffix(f, "@"))
		}
	}
	return fields
}

// findModifiedFields determines db fields changed since last notification
func (ne *notificationEvent) findModifiedFields(nInfo *notificationInfo, entryDiff *onchangeCacheDiff) yangNodeInfoSet {
	var yInfos yangNodeInfoSet
	targetPathCreate := entryDiff.EntryCreated
	targetPathDelete := entryDiff.EntryDeleted

	if nInfo.flags.Has(niKeyFields) && !targetPathCreate && !targetPathDelete {
		targetPathCreate, targetPathDelete = ne.processKeyFields(nInfo, entryDiff)
	}

	// When a new db entry is created, the notification infra can fetch full
	// content of target path.
	if targetPathCreate {
		log.Infof("[%s] Entry created;", ne.id)
		yInfos.new = append(yInfos.new, &yangNodeInfo{})
	}

	// Treat entry delete as update when 'partial' flag is set
	if entryDiff.EntryDeleted && nInfo.flags.Has(niPartial) {
		delFields := ne.getFieldNames(entryDiff.oldValue)
		yInfos.old = ne.createYangPathInfos(nInfo, delFields, "update")
		if len(yInfos.old) != 0 {
			log.Infof("[%s] Entry deleted; but treating it as update", ne.id)
			return yInfos
		}
	}

	// When entry is deleted, mark the whole target path as deleted
	if targetPathDelete {
		log.Infof("[%s] Entry deleted;", ne.id)
		yInfos.old = append(yInfos.old, &yangNodeInfo{deleted: true})
	}

	if targetPathCreate || targetPathDelete {
		log.V(3).Infof("[%s] findModifiedFields returns %v", ne.id, yInfos)
		return yInfos
	}

	// Collect yang leaf info for updated fields
	if len(entryDiff.UpdatedFields) != 0 {
		yInfos.new = ne.createYangPathInfos(nInfo, entryDiff.UpdatedFields, "update")
	}

	// Collect yang leaf info for created fields
	if len(entryDiff.CreatedFields) != 0 {
		yy := ne.createYangPathInfos(nInfo, entryDiff.CreatedFields, "create")
		if len(yy) != 0 {
			yInfos.new = append(yInfos.new, yy...)
		}
	}

	// Collect yang leaf info for deleted fields
	if len(entryDiff.DeletedFields) != 0 {
		yy := ne.createYangPathInfos(nInfo, entryDiff.DeletedFields, "delete")
		if len(yy) != 0 {
			yInfos.new = append(yInfos.new, yy...)
		}
	}

	log.V(3).Infof("[%s] findModifiedFields returns %v", ne.id, yInfos)
	return yInfos
}

func (ne *notificationEvent) processKeyFields(nInfo *notificationInfo, entryDiff *onchangeCacheDiff) (keyCreate, keyDelete bool) {
	keyFields := map[string]bool{}
	for _, nDbFldInfo := range nInfo.fields {
		for field, leaf := range nDbFldInfo.dbFldYgPathMap {
			if len(leaf) != 0 && leaf[0] == '{' {
				keyFields[field] = true
			}
		}
	}
	for _, f := range entryDiff.DeletedFields {
		if keyFields[f] {
			log.Infof("[%s] deleted field %s is mapped to yang key; treat as path delete", ne.id, f)
			keyDelete = true
			break
		}
	}
	for _, f := range entryDiff.CreatedFields {
		if keyFields[f] {
			log.Infof("[%s] created field %s is mapped to yang key; treat as path create", ne.id, f)
			keyCreate = true
			break
		}
	}
	for _, f := range entryDiff.UpdatedFields {
		if keyFields[f] {
			log.Infof("[%s] updated field %s is mapped to yang key; treat as path delete+create", ne.id, f)
			keyDelete = true
			keyCreate = true
			break
		}
	}
	return
}

func (ne *notificationEvent) createYangPathInfos(nInfo *notificationInfo, fields []string, action string) []*yangNodeInfo {
	var yInfos []*yangNodeInfo
	isDelete := (action == "delete")

	for _, f := range fields {
		for _, nDbFldInfo := range nInfo.fields {
			if leaf, ok := nDbFldInfo.dbFldYgPathMap[f]; ok {
				log.Infof("[%s] %s field=%s, path=%s/%s", ne.id, action, f, nDbFldInfo.rltvPath, leaf)
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

func (ne *notificationEvent) getApp(nInfo *notificationInfo) appInterface {
	if app := ne.appCache[nInfo.appInfo]; app != nil {
		return app
	}

	app, _ := getAppInterface(nInfo.appInfo.appType)
	if ne.appCache == nil {
		ne.appCache = map[*appInfo]appInterface{nInfo.appInfo: app}
	} else {
		ne.appCache[nInfo.appInfo] = app
	}
	return app
}

func (ne *notificationEvent) getValue(nInfo *notificationInfo, path string) (ygot.ValidatedGoStruct, error) {
	var payload ygot.ValidatedGoStruct
	app := ne.getApp(nInfo)
	appInfo := nInfo.appInfo
	dbs := ne.sInfo.dbs

	err := appInitialize(&app, appInfo, path, nil, nil, GET)

	if err != nil {
		return payload, err
	}

	err = app.translateGet(dbs)

	if err != nil {
		return payload, err
	}

	resp, err := app.processGet(dbs, TRANSLIB_FMT_YGOT)

	if err == nil {
		if resp.ValueTree == nil {
			err = tlerr.NotFound("app returned nil")
		} else if isEmptyYgotStruct(*resp.ValueTree) {
			err = tlerr.NotFound("app returned empty %T", *resp.ValueTree)
		} else {
			payload = *resp.ValueTree
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
		entry:  ne.entry,
		dbs:    ne.sInfo.dbs,
		opaque: nInfo.opaque,
		path:   path.Clone(nInfo.path),
	}

	log.Infof("[%s] Call processSubscribe with dbno=%d, table=%s, key=%v",
		ne.id, in.dbno, tableInfo(in.table), keyInfo(in.key))

	app := ne.getApp(nInfo)
	out, err := app.processSubscribe(&in)
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

	if log.V(1) {
		log.Infof("[%s] processSubscribe returned: %v", ne.id, out)
	}

	ne.keyGroupComps = out.keyGroupComps
	return out.path
}

func (ne *notificationEvent) sendNotification(nInfo *notificationInfo, fields []*yangNodeInfo) {
	var prefix *gnmi.Path
	if nInfo.flags.Has(niWildcardPath) || ne.forceProcessSub {
		prefix = ne.dbkeyToYangPath(nInfo)
		if prefix == nil {
			log.Warningf("[%s] skip notification", ne.id)
			return
		}
	} else {
		prefix = path.Clone(nInfo.path)
	}

	sInfo := ne.sInfo
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
	var updatePaths []string

	for _, lv := range fields {
		leafPath := lv.getPath()

		if lv.deleted {
			log.V(3).Infof("[%s] %s deleted", ne.id, leafPath)
			resp.Delete = append(resp.Delete, leafPath)
			continue
		}

		data, err := ne.getValue(nInfo, prefixStr+leafPath)

		if sInfo.syncDone && isNotFoundError(err) {
			log.V(3).Infof("[%s] %s not found (%v)", ne.id, leafPath, err)
			resp.Delete = append(resp.Delete, leafPath)
			continue
		}
		if err != nil {
			log.Warningf("[%s] skip notification -- %v", ne.id, err)
			continue
		}

		log.V(3).Infof("[%s] %s = %T", ne.id, leafPath, data)
		lv.valueTree = data
		updatePaths = append(updatePaths, leafPath)
	}

	numUpdate := len(updatePaths)
	numDelete := len(resp.Delete)
	log.Infof("[%v][%v] Found %d updates and %d deletes", ne.id, sInfo.id, numUpdate, numDelete)
	if numUpdate == 0 && numDelete == 0 {
		return
	}

	switch {
	case numUpdate == 0:
		// No updates; retain resp.Path=prefixStr and resp.Update=nil
	case numUpdate == 1 && numDelete == 0:
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
			cp := path.SubPath(prefix, n-1, n)
			lv.valueTree, err = getYgotAtPath(lv.valueTree, cp)
		}

		resp.Update = lv.valueTree
		log.Infof("[%s] Single update case; %T", ne.id, resp.Update)

	default:
		// There are > 1 updates or 1 update with few delete paths. Hence retain resp.Path
		// as prefixStr itself. Coalesce the values by merging them into a new data tree.
		tmpRoot := new(ocbinds.Device)
		resp.Update, err = mergeYgotAtPath(tmpRoot, prefix, nil)
		if err != nil {
			break
		}

		log.Infof("[%s] Coalesce %d updates into %T", ne.id, numUpdate, resp.Update)
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

	log.Infof("[%v][%v] Sending SubscribeResponse{Path=\"%s\", Update=%v, Delete=%v}",
		ne.id, sInfo.id, resp.Path, sliceValue(updatePaths), sliceValue(resp.Delete))
	sInfo.q.Put(resp)
}

func sliceValue(s []string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}

func nextYangNodeForUpdate(nodes []*yangNodeInfo, indx int) (*yangNodeInfo, int) {
	for n := len(nodes); indx < n; indx++ {
		if nodes[indx].valueTree != nil {
			return nodes[indx], indx
		}
	}
	return nil, -1
}

// yangNodeInfoSet contains yangNodeInfo mappings for old and new db entries.
// Old mappings usually include db entry delete operations. New mappings
// include entry create or update operations (including field delete).
type yangNodeInfoSet struct {
	old []*yangNodeInfo
	new []*yangNodeInfo
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

		sInfo.sDBs = nil
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
