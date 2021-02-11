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
	termDone bool // Terminate message has been sent
	q        *queue.PriorityQueue
	stop     chan struct{}
	sDBs     []*db.DB         //Subscription DB should be used only for keyspace notification unsubscription
	dbs      [db.MaxDB]*db.DB //used to perform get operations
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
	db    *db.DB             // DB object on which this event was received
	nGrup *notificationGroup // Target notificationGroup for the event
	nInfo *notificationInfo  // Current notificationInfo

	// Meta info for processSubscribe calls
	forceProcessSub bool
	keyGroupComps   []int
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
	log.Infof("[%v] notificationHandler: d=%p, sKey=%v, key=%v, event=%v",
		nid, d, sKey, key, event)

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
	sInfo    *subscribeInfo
	dbNInfos map[db.DBNum]map[db.TableSpec]*notificationGroup
	tgtInfos []*notificationInfo

	app     *appInterface
	appInfo *appInfo
}

func (sc *subscribeContext) add(subscribePath string, nAppSubInfo *translateSubResponse) {
	sid := sc.sInfo.id
	if sc.dbNInfos == nil {
		sc.dbNInfos = make(map[db.DBNum]map[db.TableSpec]*notificationGroup)
	}

	log.Infof("[%v] Subscribe path \"%s\" mapped to %d primary and %d subtree notificationAppInfos",
		sid, subscribePath, len(nAppSubInfo.ntfAppInfoTrgt), len(nAppSubInfo.ntfAppInfoTrgtChlds))

	for i, nAppInfo := range nAppSubInfo.ntfAppInfoTrgt {
		log.Infof("[%v] pri[%d] = %v", sid, i, nAppInfo)
		nInfo := sc.addNInfo(nAppInfo)
		sc.tgtInfos = append(sc.tgtInfos, nInfo)
	}

	for i, nAppInfo := range nAppSubInfo.ntfAppInfoTrgtChlds {
		log.Infof("[%v] sub[%d] = %v", sid, i, nAppInfo)
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

	// Group nInfo by table and key pattern
	tKey := *nAppInfo.table
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
	return nInfo
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
		ng.nInfos = map[string][]*notificationInfo{keyStr: []*notificationInfo{nInfo}}
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

	if nInfo.key.IsPattern() && !nInfo.flags.Has(niWildcardPath) {
		log.Infof("[%s] db key is a glob pattern. Forcing processSubscribe..", ne.id)
		ne.forceProcessSub = true
	}

	var ddup map[string]bool
	topNode := []*yangNodeInfo{new(yangNodeInfo)}

	for _, k := range keys {
		ne.key = &k
		if ddk := ne.getDdupKey(); len(ddk) != 0 && ddup[ddk] {
			log.Infof("[%s] skip init sync for key %v; another key with matching comps %v has been processed",
				ne.id, k, ne.keyGroupComps)
			continue
		}

		ne.sendNotification(nInfo, topNode)

		if ddk := ne.getDdupKey(); len(ddk) != 0 {
			if ddup == nil {
				ddup = make(map[string]bool)
			}
			ddup[ddk] = true
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
				ne.id, i, ne.key)
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
			log.V(3).Infof("[%s] Key %v does not match pattern %v", ne.id, ne.key, keyPattern)
			continue
		}

		log.Infof("[%s] Key %v matches registered pattern %v; has %d nInfos",
			ne.id, ne.key, keyPattern, len(nInfos))

		for _, nInfo := range nInfos {
			ne.nInfo = nInfo
			log.Infof("[%s] processing path: %s", ne.id, path.String(nInfo.path))

			modFields := ne.findModifiedFields(nInfo, dbDiff)
			if len(modFields) == 0 {
				log.Infof("[%s] no fields updated", ne.id)
				continue
			}

			ne.sendNotification(nInfo, modFields)
		}
	}
}

type onchangeCacheDiff struct {
	UpdatedEntry  *db.Value
	EntryCreated  bool
	EntryDeleted  bool
	UpdatedFields []string
	DeletedFields []string
}

func (c *onchangeCacheDiff) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s[%t], ", "EntryCreated", c.EntryCreated)
	fmt.Fprintf(&b, "%s[%t], ", "EntryDeleted", c.EntryDeleted)
	fmt.Fprintf(&b, "%s->%v, ", "UpdatedFields", c.UpdatedFields)
	fmt.Fprintf(&b, "%s->%v, ", "DeletedFields", c.DeletedFields)
	if c.UpdatedEntry != nil {
		fmt.Fprintf(&b, "Entry->")
		for k, v := range c.UpdatedEntry.Field {
			fmt.Fprintf(&b, "%s[%s]  ", k, v)
		}
	}

	return b.String()
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

	cacheEntryDiff := &onchangeCacheDiff{}

	cachedEntry, val, e := d.OnChangeCacheUpdate(ts, *key)

	exists := !((e != nil) || (len(cachedEntry.Field) == 0))
	if exists { // Already exists in cache

		if entryDeleted {
			// Entry deleted.
			cacheEntryDiff.EntryDeleted = true
			for fldName := range cachedEntry.Field {
				cacheEntryDiff.DeletedFields = append(
					cacheEntryDiff.DeletedFields, fldName)
			}
			return cacheEntryDiff, nil
		}

		cacheEntryDiff.UpdatedEntry = &val

		for fldName := range cachedEntry.Field {
			if fldName == "NULL" {
				continue
			}
			if _, fldOk := val.Field[fldName]; !fldOk {
				cacheEntryDiff.DeletedFields = append(
					cacheEntryDiff.DeletedFields, fldName)
				cachedEntry.Remove(fldName)
			}
		}

		for nf, nv := range val.Field {
			if nf == "NULL" {
				continue
			}
			if cachedEntry.Field[nf] != nv {
				cacheEntryDiff.UpdatedFields = append(
					cacheEntryDiff.UpdatedFields, nf)
				cachedEntry.Set(nf, nv)
			}
		}

	} else if !entryDeleted {
		// Not exists in cache
		cacheEntryDiff.EntryCreated = true
		cacheEntryDiff.UpdatedEntry = &val
	}

	log.Infof("[%s] DiffAndMergeOnChangeCache: %v", ne.id, cacheEntryDiff)

	return cacheEntryDiff, nil
}

// findModifiedFields determines db fields changed since last notification
func (ne *notificationEvent) findModifiedFields(nInfo *notificationInfo, entryDiff *onchangeCacheDiff) []*yangNodeInfo {
	var modFields []*yangNodeInfo

	// When a new db entry is created, the notification infra can fetch full
	// content of target path.
	if entryDiff.EntryCreated {
		log.Infof("[%s] Entry created;", ne.id)
		modFields = append(modFields, &yangNodeInfo{})
		return modFields
	}

	// Treat entry delete as update when 'partial' flag is set
	if entryDiff.EntryDeleted && nInfo.flags.Has(niPartial) {
		log.Infof("[%s] Entry deleted; but treating it as update", ne.id)
		modFields = ne.createYangPathInfos(nInfo, entryDiff.DeletedFields, false)
		if len(modFields) == 0 {
			log.Infof("[%s] empty entry; use target path", ne.id)
			modFields = append(modFields, &yangNodeInfo{})
		}
		return modFields
	}

	// When entry is deleted, mark the whole target path as deleted if the
	if entryDiff.EntryDeleted {
		log.Infof("[%s] Entry deleted;", ne.id)
		modFields = append(modFields, &yangNodeInfo{deleted: true})
		return modFields
	}

	// Collect yang leaf info for updated fields
	if len(entryDiff.UpdatedFields) != 0 {
		modFields = ne.createYangPathInfos(nInfo, entryDiff.UpdatedFields, false)
	}

	// Collect yang leaf info for deleted fields
	if len(entryDiff.DeletedFields) != 0 {
		modFields = append(modFields,
			ne.createYangPathInfos(nInfo, entryDiff.DeletedFields, true)...)
	}

	log.V(3).Infof("[%s] findModifiedFields returns %v", ne.id, modFields)

	return modFields
}

func (ne *notificationEvent) createYangPathInfos(nInfo *notificationInfo, fields []string, isDelete bool) []*yangNodeInfo {
	var yInfos []*yangNodeInfo
	var opStr string
	if isDelete {
		opStr = "delete "
	}

	for _, f := range fields {
		f = strings.TrimSuffix(f, "@") // Apps do not fill @ suffix for array fields
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
		if resp.ValueTree == nil {
			err = fmt.Errorf("nil value")
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
		dbs:    nInfo.sInfo.dbs,
		opaque: nInfo.opaque,
		path:   path.Clone(nInfo.path),
	}

	log.Infof("[%s] Call processSubscribe with dbno=%d, table=%s, key=%v",
		ne.id, in.dbno, in.table.Name, in.key)

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

	if log.V(1) {
		log.Infof("[%s] processSubscribe returned: %v", ne.id, out)
	}

	ne.keyGroupComps = out.keyGroupComps
	return out.path
}

func (ne *notificationEvent) sendNotification(nInfo *notificationInfo, fields []*yangNodeInfo) {
	prefix := nInfo.path
	if nInfo.flags.Has(niWildcardPath) || ne.forceProcessSub {
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
	var updatePaths []string

	for _, lv := range fields {
		leafPath := lv.getPath()

		if lv.deleted {
			log.V(3).Infof("[%s] %s deleted", ne.id, leafPath)
			resp.Delete = append(resp.Delete, leafPath)
			continue
		}

		data, err := ne.getValue(prefixStr + leafPath)

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

	log.Infof("[%v][%v] Found %d updates and %d deletes", ne.id, sInfo.id, numUpdate, len(resp.Delete))
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
