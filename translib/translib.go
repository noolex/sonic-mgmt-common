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
Package translib implements APIs like Create, Get, Subscribe etc.

to be consumed by the north bound management server implementations

This package take care of translating the incoming requests to

Redis ABNF format and persisting them in the Redis DB.

It can also translate the ABNF format to YANG specific JSON IETF format

This package can also talk to non-DB clients.
*/

package translib

import (
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Workiva/go-datastructures/queue"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

//Write lock for all write operations to be synchronized
var writeMutex = &sync.Mutex{}

//minimum global interval for subscribe in secs
var minSubsInterval = 20
var maxSubsInterval = 600

type ErrSource int

const (
	ProtoErr ErrSource = iota
	AppErr
)

const (
	TRANSLIB_FMT_IETF_JSON = iota
	TRANSLIB_FMT_YGOT
)

type TranslibFmtType int

type UserRoles struct {
	Name  string
	Roles []string
}

type SetRequest struct {
	Path             string
	Payload          []byte
	User             UserRoles
	AuthEnabled      bool
	ClientVersion    Version
	DeleteEmptyEntry bool
}

type SetResponse struct {
	ErrSrc ErrSource
	Err    error
}

type GetRequest struct {
	Path          string
	FmtType       TranslibFmtType
	User          UserRoles
	AuthEnabled   bool
	ClientVersion Version

	// Depth limits the depth of data subtree in the response
	// payload. Default value 0 indicates there is no limit.
	Depth uint
}

type GetResponse struct {
	Payload   []byte
	ValueTree *ygot.ValidatedGoStruct
	ErrSrc    ErrSource
}

type ActionRequest struct {
	Path          string
	Payload       []byte
	User          UserRoles
	AuthEnabled   bool
	ClientVersion Version
}

type ActionResponse struct {
	Payload []byte
	ErrSrc  ErrSource
}

type BulkRequest struct {
	DeleteRequest  []SetRequest
	ReplaceRequest []SetRequest
	UpdateRequest  []SetRequest
	CreateRequest  []SetRequest
	User           UserRoles
	AuthEnabled    bool
	ClientVersion  Version
}

type BulkResponse struct {
	DeleteResponse  []SetResponse
	ReplaceResponse []SetResponse
	UpdateResponse  []SetResponse
	CreateResponse  []SetResponse
}

// SubscribeRequest holds the request data for Subscribe and Stream APIs.
type SubscribeRequest struct {
	Paths         []string
	Q             *queue.PriorityQueue
	Stop          chan struct{}
	User          UserRoles
	AuthEnabled   bool
	ClientVersion Version
	Session       *SubscribeSession
}

type SubscribeResponse struct {
	Path         string
	Update       ygot.ValidatedGoStruct // updated values
	Delete       []string               // deleted paths - relative to Path
	Timestamp    int64
	SyncComplete bool
	IsTerminated bool
}

type NotificationType int

const (
	Sample NotificationType = iota
	OnChange
)

type IsSubscribeRequest struct {
	Paths         []string
	User          UserRoles
	AuthEnabled   bool
	ClientVersion Version
	Session       *SubscribeSession
}

type IsSubscribeResponse struct {
	Path                string
	IsOnChangeSupported bool
	MinInterval         int
	Err                 error
	PreferredType       NotificationType
}

type ModelData struct {
	Name string
	Org  string
	Ver  string
}

// Counter is a monotonically increasing unsigned integer.
type Counter uint64

//initializes logging and app modules
func init() {
	log.Flush()
}

//Create - Creates entries in the redis DB pertaining to the path and payload
func Create(req SetRequest) (SetResponse, error) {
	var keys []db.WatchKeys
	var resp SetResponse
	path := req.Path
	payload := req.Payload
	if !isAuthorizedForSet(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Create Operation",
			Path:   path,
		}
	}

	log.Info("Create request received with path =", path)
	log.Info("Create request received with payload =", string(payload))

	app, appInfo, err := getAppModule(path, req.ClientVersion)

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	err = appInitialize(app, appInfo, path, &payload, nil, CREATE)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	writeMutex.Lock()
	defer writeMutex.Unlock()

	isWriteDisabled := false
	d, err := db.NewDB(getDBOptions(db.ConfigDB, isWriteDisabled))

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	defer d.DeleteDB()

	keys, err = (*app).translateCreate(d)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.StartTx(keys, appInfo.tablesToWatch)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	resp, err = (*app).processCreate(d)

	if err != nil {
		d.AbortTx()
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.CommitTx()

	if err != nil {
		resp.ErrSrc = AppErr
	}

	return resp, err
}

//Update - Updates entries in the redis DB pertaining to the path and payload
func Update(req SetRequest) (SetResponse, error) {
	var keys []db.WatchKeys
	var resp SetResponse
	path := req.Path
	payload := req.Payload
	if !isAuthorizedForSet(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Update Operation",
			Path:   path,
		}
	}

	log.Info("Update request received with path =", path)
	log.Info("Update request received with payload =", string(payload))

	app, appInfo, err := getAppModule(path, req.ClientVersion)

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	err = appInitialize(app, appInfo, path, &payload, nil, UPDATE)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	writeMutex.Lock()
	defer writeMutex.Unlock()

	isWriteDisabled := false
	d, err := db.NewDB(getDBOptions(db.ConfigDB, isWriteDisabled))

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	defer d.DeleteDB()

	keys, err = (*app).translateUpdate(d)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.StartTx(keys, appInfo.tablesToWatch)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	resp, err = (*app).processUpdate(d)

	if err != nil {
		d.AbortTx()
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.CommitTx()

	if err != nil {
		resp.ErrSrc = AppErr
	}

	return resp, err
}

//Replace - Replaces entries in the redis DB pertaining to the path and payload
func Replace(req SetRequest) (SetResponse, error) {
	var err error
	var keys []db.WatchKeys
	var resp SetResponse
	path := req.Path
	payload := req.Payload
	if !isAuthorizedForSet(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Replace Operation",
			Path:   path,
		}
	}

	log.Info("Replace request received with path =", path)
	log.Info("Replace request received with payload =", string(payload))

	app, appInfo, err := getAppModule(path, req.ClientVersion)

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	err = appInitialize(app, appInfo, path, &payload, nil, REPLACE)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	writeMutex.Lock()
	defer writeMutex.Unlock()

	isWriteDisabled := false
	d, err := db.NewDB(getDBOptions(db.ConfigDB, isWriteDisabled))

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	defer d.DeleteDB()

	keys, err = (*app).translateReplace(d)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.StartTx(keys, appInfo.tablesToWatch)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	resp, err = (*app).processReplace(d)

	if err != nil {
		d.AbortTx()
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.CommitTx()

	if err != nil {
		resp.ErrSrc = AppErr
	}

	return resp, err
}

//Delete - Deletes entries in the redis DB pertaining to the path
func Delete(req SetRequest) (SetResponse, error) {
	var err error
	var keys []db.WatchKeys
	var resp SetResponse
	path := req.Path
	if !isAuthorizedForSet(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Delete Operation",
			Path:   path,
		}
	}

	log.Info("Delete request received with path =", path)

	app, appInfo, err := getAppModule(path, req.ClientVersion)

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	opts := appOptions{deleteEmptyEntry: req.DeleteEmptyEntry}
	err = appInitialize(app, appInfo, path, nil, &opts, DELETE)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	writeMutex.Lock()
	defer writeMutex.Unlock()

	isWriteDisabled := false
	d, err := db.NewDB(getDBOptions(db.ConfigDB, isWriteDisabled))

	if err != nil {
		resp.ErrSrc = ProtoErr
		return resp, err
	}

	defer d.DeleteDB()

	keys, err = (*app).translateDelete(d)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.StartTx(keys, appInfo.tablesToWatch)

	if err != nil {
		resp.ErrSrc = AppErr
		return resp, err
	}

	resp, err = (*app).processDelete(d)

	if err != nil {
		d.AbortTx()
		resp.ErrSrc = AppErr
		return resp, err
	}

	err = d.CommitTx()

	if err != nil {
		resp.ErrSrc = AppErr
	}

	return resp, err
}

//Get - Gets data from the redis DB and converts it to northbound format
func Get(req GetRequest) (GetResponse, error) {
	var payload []byte
	var resp GetResponse
	path := req.Path
	if !isAuthorizedForGet(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Get Operation",
			Path:   path,
		}
	}

	log.Info("Received Get request for path = ", path)

	app, appInfo, err := getAppModule(path, req.ClientVersion)

	if err != nil {
		resp = GetResponse{Payload: payload, ErrSrc: ProtoErr}
		return resp, err
	}

	opts := appOptions{depth: req.Depth}
	err = appInitialize(app, appInfo, path, nil, &opts, GET)

	if err != nil {
		resp = GetResponse{Payload: payload, ErrSrc: AppErr}
		return resp, err
	}

	isGetCase := true
	isEnableCache := true
	isSubscribeCase := false
	dbs, err := getAllDbsC(isGetCase, isEnableCache, isSubscribeCase)

	if err != nil {
		resp = GetResponse{Payload: payload, ErrSrc: ProtoErr}
		return resp, err
	}

	defer closeAllDbs(dbs[:])

	err = (*app).translateGet(dbs)

	if err != nil {
		resp = GetResponse{Payload: payload, ErrSrc: AppErr}
		return resp, err
	}
	resp, err = (*app).processGet(dbs, req.FmtType)
	// if the size of byte array equals or greater than 10 MB, then free the memory
	if len(resp.Payload) >= 10000000 {
		log.Info("Calling FreeOSMemory..")
		debug.FreeOSMemory()
	}
	return resp, err
}

func Action(req ActionRequest) (ActionResponse, error) {
	var payload []byte
	var resp ActionResponse
	path := req.Path
	if !isAuthorizedForAction(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Action Operation",
			Path:   path,
		}
	}

	log.Info("Received Action request for path = ", path)

	app, appInfo, err := getAppModule(path, req.ClientVersion)

	if err != nil {
		resp = ActionResponse{Payload: payload, ErrSrc: ProtoErr}
		return resp, err
	}

	aInfo := *appInfo

	aInfo.isNative = true

	err = appInitialize(app, &aInfo, path, &req.Payload, nil, GET)

	if err != nil {
		resp = ActionResponse{Payload: payload, ErrSrc: AppErr}
		return resp, err
	}

	writeMutex.Lock()
	defer writeMutex.Unlock()

	isGetCase := false
	dbs, err := getAllDbs(isGetCase)

	if err != nil {
		resp = ActionResponse{Payload: payload, ErrSrc: ProtoErr}
		return resp, err
	}

	defer closeAllDbs(dbs[:])

	err = (*app).translateAction(dbs)

	if err != nil {
		resp = ActionResponse{Payload: payload, ErrSrc: AppErr}
		return resp, err
	}

	resp, err = (*app).processAction(dbs)
	// if the size of byte array equals or greater than 10 MB, then free the memory
	if len(resp.Payload) >= 10000000 {
		log.Info("Calling FreeOSMemory..")
		debug.FreeOSMemory()
	}
	return resp, err
}

func Bulk(req BulkRequest) (BulkResponse, error) {
	var err error
	var keys []db.WatchKeys
	var errSrc ErrSource

	delResp := make([]SetResponse, len(req.DeleteRequest))
	replaceResp := make([]SetResponse, len(req.ReplaceRequest))
	updateResp := make([]SetResponse, len(req.UpdateRequest))
	createResp := make([]SetResponse, len(req.CreateRequest))

	resp := BulkResponse{DeleteResponse: delResp,
		ReplaceResponse: replaceResp,
		UpdateResponse:  updateResp,
		CreateResponse:  createResp}

	if !isAuthorizedForBulk(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Action Operation",
		}
	}

	writeMutex.Lock()
	defer writeMutex.Unlock()

	isWriteDisabled := false
	d, err := db.NewDB(getDBOptions(db.ConfigDB, isWriteDisabled))

	if err != nil {
		return resp, err
	}

	defer d.DeleteDB()

	//Start the transaction without any keys or tables to watch will be added later using AppendWatchTx
	err = d.StartTx(nil, nil)

	if err != nil {
		return resp, err
	}

	for i := range req.DeleteRequest {
		path := req.DeleteRequest[i].Path
		opts := appOptions{deleteEmptyEntry: req.DeleteRequest[i].DeleteEmptyEntry}

		log.Info("Delete request received with path =", path)

		app, appInfo, err := getAppModule(path, req.DeleteRequest[i].ClientVersion)

		if err != nil {
			errSrc = ProtoErr
			goto BulkDeleteError
		}

		err = appInitialize(app, appInfo, path, nil, &opts, DELETE)

		if err != nil {
			errSrc = AppErr
			goto BulkDeleteError
		}

		keys, err = (*app).translateDelete(d)

		if err != nil {
			errSrc = AppErr
			goto BulkDeleteError
		}

		err = d.AppendWatchTx(keys, appInfo.tablesToWatch)

		if err != nil {
			errSrc = AppErr
			goto BulkDeleteError
		}

		resp.DeleteResponse[i], err = (*app).processDelete(d)

		if err != nil {
			errSrc = AppErr
		}

	BulkDeleteError:

		if err != nil {
			d.AbortTx()
			resp.DeleteResponse[i].ErrSrc = errSrc
			resp.DeleteResponse[i].Err = err
			return resp, err
		}
	}

	for i := range req.ReplaceRequest {
		path := req.ReplaceRequest[i].Path
		payload := req.ReplaceRequest[i].Payload

		log.Info("Replace request received with path =", path)

		app, appInfo, err := getAppModule(path, req.ReplaceRequest[i].ClientVersion)

		if err != nil {
			errSrc = ProtoErr
			goto BulkReplaceError
		}

		log.Info("Bulk replace request received with path =", path)
		log.Info("Bulk replace request received with payload =", string(payload))

		err = appInitialize(app, appInfo, path, &payload, nil, REPLACE)

		if err != nil {
			errSrc = AppErr
			goto BulkReplaceError
		}

		keys, err = (*app).translateReplace(d)

		if err != nil {
			errSrc = AppErr
			goto BulkReplaceError
		}

		err = d.AppendWatchTx(keys, appInfo.tablesToWatch)

		if err != nil {
			errSrc = AppErr
			goto BulkReplaceError
		}

		resp.ReplaceResponse[i], err = (*app).processReplace(d)

		if err != nil {
			errSrc = AppErr
		}

	BulkReplaceError:

		if err != nil {
			d.AbortTx()
			resp.ReplaceResponse[i].ErrSrc = errSrc
			resp.ReplaceResponse[i].Err = err
			return resp, err
		}
	}

	for i := range req.UpdateRequest {
		path := req.UpdateRequest[i].Path
		payload := req.UpdateRequest[i].Payload

		log.Info("Update request received with path =", path)

		app, appInfo, err := getAppModule(path, req.UpdateRequest[i].ClientVersion)

		if err != nil {
			errSrc = ProtoErr
			goto BulkUpdateError
		}

		err = appInitialize(app, appInfo, path, &payload, nil, UPDATE)

		if err != nil {
			errSrc = AppErr
			goto BulkUpdateError
		}

		keys, err = (*app).translateUpdate(d)

		if err != nil {
			errSrc = AppErr
			goto BulkUpdateError
		}

		err = d.AppendWatchTx(keys, appInfo.tablesToWatch)

		if err != nil {
			errSrc = AppErr
			goto BulkUpdateError
		}

		resp.UpdateResponse[i], err = (*app).processUpdate(d)

		if err != nil {
			errSrc = AppErr
		}

	BulkUpdateError:

		if err != nil {
			d.AbortTx()
			resp.UpdateResponse[i].ErrSrc = errSrc
			resp.UpdateResponse[i].Err = err
			return resp, err
		}
	}

	for i := range req.CreateRequest {
		path := req.CreateRequest[i].Path
		payload := req.CreateRequest[i].Payload

		log.Info("Create request received with path =", path)

		app, appInfo, err := getAppModule(path, req.CreateRequest[i].ClientVersion)

		if err != nil {
			errSrc = ProtoErr
			goto BulkCreateError
		}

		err = appInitialize(app, appInfo, path, &payload, nil, CREATE)

		if err != nil {
			errSrc = AppErr
			goto BulkCreateError
		}

		keys, err = (*app).translateCreate(d)

		if err != nil {
			errSrc = AppErr
			goto BulkCreateError
		}

		err = d.AppendWatchTx(keys, appInfo.tablesToWatch)

		if err != nil {
			errSrc = AppErr
			goto BulkCreateError
		}

		resp.CreateResponse[i], err = (*app).processCreate(d)

		if err != nil {
			errSrc = AppErr
		}

	BulkCreateError:

		if err != nil {
			d.AbortTx()
			resp.CreateResponse[i].ErrSrc = errSrc
			resp.CreateResponse[i].Err = err
			return resp, err
		}
	}

	err = d.CommitTx()

	return resp, err
}

// NewSubscribeSession creates a new SubscribeSession. Caller
// MUST close the session object through CloseSubscribeSession
// call at the end.
func NewSubscribeSession() *SubscribeSession {
	return &SubscribeSession{
		ID: fmt.Sprintf("%d", subscribeCounter.Next()),
	}
}

// CloseSubscribeSession closes a SubscribeSession and release
// any resources it held. API client MUST close the sessions it
// creates; and not reuse the session after closing.
func CloseSubscribeSession(ss *SubscribeSession) {
	// nothing for now!
}

//Subscribe - Subscribes to the paths requested and sends notifications when the data changes in DB
func Subscribe(req SubscribeRequest) error {
	paths := req.Paths
	q := req.Q
	stop := req.Stop

	if !isAuthorizedForSubscribe(req) {
		return tlerr.AuthorizationError{
			Format: "User is unauthorized for Action Operation",
		}
	}

	isGetCase := true
	isEnableCache := false
	isSubscribeCase := true
	dbs, err := getAllDbsC(isGetCase, isEnableCache, isSubscribeCase)

	if err != nil {
		return err
	}

	sInfo := &subscribeInfo{
		id:   subscribeCounter.Next(),
		q:    q,
		stop: stop,
		dbs:  dbs,
	}

	sCtx := subscribeContext{
		sInfo:   sInfo,
		dbs:     dbs,
		mode:    OnChange,
		version: req.ClientVersion,
		session: req.Session,
	}

	for _, path := range paths {
		err = sCtx.translateAndAddPath(path)
		if err != nil {
			closeAllDbs(dbs[:])
			return err
		}
	}

	// Start db subscription and exit. DB objects will be
	// closed automatically when the subscription ends.
	err = sCtx.startSubscribe()

	return err
}

// Stream function streams the value for requested paths through a queue.
// Unlike Get, this function can return smaller chunks of response separately.
// Individual chunks are packed in a SubscribeResponse object and pushed to the req.Q.
// Pushes a SubscribeResponse with SyncComplete=true after data are pushed.
// Function will block until all values are returned. This can be used for
// handling "Sample" subscriptions (NotificationType.Sample).
// Client should be authorized to perform "subscribe" operation.
func Stream(req SubscribeRequest) error {

	if !isAuthorizedForSubscribe(req) {
		return tlerr.AuthorizationError{
			Format: "User is unauthorized for Action Operation",
		}
	}

	sid := subscribeCounter.Next()
	log.Infof("[%v] Stream request rcvd for paths %v", sid, req.Paths)

	dbs, err := getAllDbs(true)
	if err != nil {
		return err
	}
	defer closeAllDbs(dbs[:])

	sc := subscribeContext{
		id:      sid,
		dbs:     dbs,
		version: req.ClientVersion,
		session: req.Session,
	}

	for _, path := range req.Paths {
		err := sc.translateAndAddPath(path)
		if err != nil {
			return err
		}
	}

	sInfo := &subscribeInfo{
		id:  sid,
		q:   req.Q,
		dbs: dbs,
	}

	for _, nInfo := range sc.tgtInfos {
		err = sendInitialUpdate(sInfo, nInfo)
		if err != nil {
			return err
		}
	}

	// Push a SyncComplete message at the end
	sInfo.syncDone = true
	sendSyncNotification(sInfo, false)
	return nil
}

//IsSubscribeSupported - Check if subscribe is supported on the given paths
func IsSubscribeSupported(req IsSubscribeRequest) ([]*IsSubscribeResponse, error) {

	reqID := subscribeCounter.Next()
	paths := req.Paths
	resp := make([]*IsSubscribeResponse, len(paths))

	for i := range resp {
		resp[i] = &IsSubscribeResponse{Path: paths[i],
			IsOnChangeSupported: true,
			MinInterval:         minSubsInterval,
			PreferredType:       OnChange,
			Err:                 nil}
	}

	if !isAuthorizedForIsSubscribe(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Action Operation",
		}
	}

	log.Info("IsSubscribeSupported:", paths)

	isGetCase := true
	dbs, err := getAllDbs(isGetCase)

	if err != nil {
		return resp, err
	}

	defer closeAllDbs(dbs[:])

	sc := subscribeContext{
		id:      reqID,
		dbs:     dbs,
		version: req.ClientVersion,
		session: req.Session,
	}

	for i, path := range paths {
		nAppInfos, trData, errApp := sc.translatePath(path)

		r := resp[i]

		if nAppInfos != nil {
			collectNotificationPreferences(nAppInfos.ntfAppInfoTrgt, r)
			collectNotificationPreferences(nAppInfos.ntfAppInfoTrgtChlds, r)
		}
		if trData != nil {
			sc.saveTranslatedData(path, trData)
		}

		log.Infof("IsSubscribeResponse[%d]: onChg=%v, pref=%v, minInt=%d, err=%v",
			i, r.IsOnChangeSupported, r.PreferredType, r.MinInterval, errApp)

		if errApp != nil {
			resp[i].Err = errApp
			err = errApp
		}
	}

	return resp, err
}

// collectNotificationPreferences computes overall notification preferences (is on-change
// supported, min sample interval, preferred mode etc) by combining individual table preferences
// from the notificationAppInfo array. Writes them to the IsSubscribeResponse object 'resp'.
func collectNotificationPreferences(nAppInfos []*notificationAppInfo, resp *IsSubscribeResponse) {
	if len(nAppInfos) == 0 {
		return
	}

	for _, nInfo := range nAppInfos {
		if !nInfo.isOnChangeSupported || nInfo.isNonDB() {
			resp.IsOnChangeSupported = false
			resp.PreferredType = Sample
		}
		if nInfo.pType == Sample {
			resp.PreferredType = Sample
		}
		if nInfo.mInterval > resp.MinInterval {
			resp.MinInterval = nInfo.mInterval
		}
	}

	if resp.MinInterval > maxSubsInterval {
		resp.MinInterval = maxSubsInterval
	}
}

//GetModels - Gets all the models supported by Translib
func GetModels() ([]ModelData, error) {
	var err error

	return getModels(), err
}

//Creates DB connection with all the redis DBs. Cache Disabled
func getAllDbs(isGetCase bool) ([db.MaxDB]*db.DB, error) {
	return getAllDbsC(isGetCase, false, false)
}

//Creates DB connection with all the redis DBs.
//Allow Per Connection cache enabling, if configured to do so.
//Allow OnChange cache enabling.
//Per Connection cache and OnChange cache are mutually exclusive.
func getAllDbsC(isGetCase bool, isEnableCache bool, isEnableOnChange bool) ([db.MaxDB]*db.DB, error) {
	var dbs [db.MaxDB]*db.DB
	var err error
	var isWriteDisabled bool

	if isGetCase {
		isWriteDisabled = true
	} else {
		isWriteDisabled = false
	}

	//Create Application DB connection
	dbs[db.ApplDB], err = db.NewDB(getDBOptionsC(db.ApplDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create ASIC DB connection
	dbs[db.AsicDB], err = db.NewDB(getDBOptionsC(db.AsicDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create Counter DB connection
	dbs[db.CountersDB], err = db.NewDB(getDBOptionsC(db.CountersDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create Log Level DB connection
	dbs[db.LogLevelDB], err = db.NewDB(getDBOptionsC(db.LogLevelDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	isWriteDisabled = true

	//Create Config DB connection
	dbs[db.ConfigDB], err = db.NewDB(getDBOptionsC(db.ConfigDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	if isGetCase {
		isWriteDisabled = true
	} else {
		isWriteDisabled = false
	}

	//Create Flex Counter DB connection
	dbs[db.FlexCounterDB], err = db.NewDB(getDBOptionsC(db.FlexCounterDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create State DB connection
	dbs[db.StateDB], err = db.NewDB(getDBOptionsC(db.StateDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create Error DB connection
	dbs[db.ErrorDB], err = db.NewDB(getDBOptionsC(db.ErrorDB, isWriteDisabled, isEnableCache, isEnableOnChange))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	return dbs, err
}

//Closes the dbs, and nils out the arr.
func closeAllDbs(dbs []*db.DB) {
	for dbsi, d := range dbs {
		if d != nil {
			d.DeleteDB()
			dbs[dbsi] = nil
		}
	}
}

// Compare - Implement Compare method for priority queue for SubscribeResponse struct
func (val SubscribeResponse) Compare(other queue.Item) int {
	o := other.(*SubscribeResponse)
	if val.Timestamp > o.Timestamp {
		return 1
	} else if val.Timestamp == o.Timestamp {
		return 0
	}
	return -1
}

func getDBOptions(dbNo db.DBNum, isWriteDisabled bool) db.Options {
	return getDBOptionsC(dbNo, isWriteDisabled, false, false)
}

func getDBOptionsC(dbNo db.DBNum, isWriteDisabled bool, isEnableCache bool, isEnableOnChange bool) db.Options {
	var opt db.Options

	switch dbNo {
	case db.ApplDB, db.CountersDB, db.AsicDB, db.FlexCounterDB, db.LogLevelDB, db.ErrorDB:
		opt = getDBOptionsWithSeparator(dbNo, "", ":", ":", isWriteDisabled)
	case db.ConfigDB, db.StateDB, db.SnmpDB:
		opt = getDBOptionsWithSeparator(dbNo, "", "|", "|", isWriteDisabled)
	}
	opt.IsCacheEnabled = isEnableCache
	opt.IsEnableOnChange = isEnableOnChange

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

func getAppModule(path string, clientVer Version) (*appInterface, *appInfo, error) {
	var app appInterface

	aInfo, err := getAppModuleInfo(path)

	if err != nil {
		return nil, aInfo, err
	}

	if err := validateClientVersion(clientVer, path, aInfo); err != nil {
		return nil, aInfo, err
	}

	app, err = getAppInterface(aInfo.appType)

	if err != nil {
		return nil, aInfo, err
	}

	return &app, aInfo, err
}

func appInitialize(app *appInterface, appInfo *appInfo, path string, payload *[]byte, opts *appOptions, opCode int) error {
	var err error
	var input []byte

	if payload != nil {
		input = *payload
	}

	if appInfo.isNative {
		log.Info("Native MSFT format")
		data := appData{path: path, payload: input}
		data.setOptions(opts)
		(*app).initialize(data)
	} else {
		ygotStruct, ygotTarget, err := getRequestBinder(&path, payload, opCode, &(appInfo.ygotRootType)).unMarshall()
		if err != nil {
			log.Info("Error in request binding: ", err)
			return err
		}

		data := appData{path: path, payload: input, ygotRoot: ygotStruct, ygotTarget: ygotTarget}
		data.setOptions(opts)
		(*app).initialize(data)
	}

	return err
}

func (data *appData) setOptions(opts *appOptions) {
	if opts != nil {
		data.appOptions = *opts
	}
}

func (nt NotificationType) String() string {
	switch nt {
	case Sample:
		return "Sample"
	case OnChange:
		return "OnChange"
	default:
		return fmt.Sprintf("NotificationType(%d)", nt)
	}
}

// Next increments the counter and returns the new value
func (c *Counter) Next() uint64 {
	return atomic.AddUint64((*uint64)(c), 1)
}
