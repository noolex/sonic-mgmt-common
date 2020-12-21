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
	FillValueTree bool
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

type SubscribeRequest struct {
	Paths         []string
	Q             *queue.PriorityQueue
	Stop          chan struct{}
	User          UserRoles
	AuthEnabled   bool
	ClientVersion Version
}

type SubscribeResponse struct {
	Path         string
	Payload      []byte
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
	dbs, err := getAllDbs(isGetCase)

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
	resp, err = (*app).processGet(dbs, req.FillValueTree)
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

//Subscribe - Subscribes to the paths requested and sends notifications when the data changes in DB
func Subscribe(req SubscribeRequest) ([]*IsSubscribeResponse, error) {
	var err error
	var sErr error

	paths := req.Paths
	q := req.Q
	stop := req.Stop

	dbNotificationMap := make(map[db.DBNum][]*notificationInfo)

	resp := make([]*IsSubscribeResponse, len(paths))

	for i := range resp {
		resp[i] = &IsSubscribeResponse{Path: paths[i],
			IsOnChangeSupported: false,
			MinInterval:         minSubsInterval,
			PreferredType:       Sample,
			Err:                 nil}
	}

	if !isAuthorizedForSubscribe(req) {
		return resp, tlerr.AuthorizationError{
			Format: "User is unauthorized for Action Operation",
		}
	}

	isGetCase := true
	dbs, err := getAllDbs(isGetCase)

	if err != nil {
		return resp, err
	}

	// Enable onChange cache support on all DBs
	enableOnChangeCaching(dbs[:])

	sInfo := &subscribeInfo{syncDone: false,
		id:   subscribeCounter.Next(),
		q:    q,
		stop: stop,
		dbs:  dbs,
	}

	for i, path := range paths {

		app, appInfo, err := getAppModule(path, req.ClientVersion)

		if err != nil {

			if sErr == nil {
				sErr = err
			}

			resp[i].Err = err
			continue
		}

		nAppSubInfo, errApp := (*app).translateSubscribe(dbs, path)

		collectNotificationPreferences(nAppSubInfo.ntfAppInfoTrgt, resp[i])
		collectNotificationPreferences(nAppSubInfo.ntfAppInfoTrgtChlds, resp[i])

		if errApp != nil {
			resp[i].Err = errApp

			if sErr == nil {
				sErr = errApp
			}

			continue
		} else {
			if len(nAppSubInfo.ntfAppInfoTrgt) == 0 && len(nAppSubInfo.ntfAppInfoTrgtChlds) == 0 {
				sErr = tlerr.NotSupportedError{
					Format: "Subscribe not supported", Path: path}
				resp[i].Err = sErr
				continue
			}
		}

		// Prepare notificationInfo for notificationAppInfo for target.
		for _, nOpts := range nAppSubInfo.ntfAppInfoTrgt {
			nInfo := &notificationInfo{
				table:   nOpts.table,
				key:     nOpts.key,
				dbno:    nOpts.dbno,
				fields:  nOpts.dbFieldYangPathMap,
				path:    nOpts.path,
				app:     app,
				appInfo: appInfo,
				sInfo:   sInfo,
			}
			dbNotificationMap[nInfo.dbno] = append(dbNotificationMap[nInfo.dbno], nInfo)

			// Enable on-change cache.. Hope it handles duplicate registrations
			sInfo.dbs[nInfo.dbno].RegisterTableForOnChangeCaching(nInfo.table)
		}

		// Prepare notificationInfo for notificationAppInfo for child nodes.
		for _, nOpts := range nAppSubInfo.ntfAppInfoTrgtChlds {
			nInfo := &notificationInfo{
				table:   nOpts.table,
				key:     nOpts.key,
				dbno:    nOpts.dbno,
				fields:  nOpts.dbFieldYangPathMap,
				path:    nOpts.path,
				app:     app,
				appInfo: appInfo,
				sInfo:   sInfo,
			}
			dbNotificationMap[nInfo.dbno] = append(dbNotificationMap[nInfo.dbno], nInfo)

			// Register table for caching
			sInfo.dbs[nInfo.dbno].RegisterTableForOnChangeCaching(nInfo.table)
		}
	}

	// Close the db pointers only on error. Otherwise keep them
	// open till subscription is active.
	if sErr != nil {
		closeAllDbs(dbs[:])
	} else {
		log.V(1).Info("dbNotificationMap =", dbNotificationMap)
		sErr = startSubscribe(sInfo, dbNotificationMap)
	}

	return resp, sErr
}

//IsSubscribeSupported - Check if subscribe is supported on the given paths
func IsSubscribeSupported(req IsSubscribeRequest) ([]*IsSubscribeResponse, error) {

	paths := req.Paths
	resp := make([]*IsSubscribeResponse, len(paths))

	for i := range resp {
		resp[i] = &IsSubscribeResponse{Path: paths[i],
			IsOnChangeSupported: false,
			MinInterval:         minSubsInterval,
			PreferredType:       Sample,
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

	for i, path := range paths {

		app, _, err := getAppModule(path, req.ClientVersion)

		if err != nil {
			resp[i].Err = err
			continue
		}

		nAppInfos, errApp := (*app).translateSubscribe(dbs, path)

		r := resp[i]
		collectNotificationPreferences(nAppInfos.ntfAppInfoTrgt, r)
		collectNotificationPreferences(nAppInfos.ntfAppInfoTrgtChlds, r)

		log.Infof("IsSubscribeResponse[%d]: onChg=%v, pref=%v, minInt=%d, err=%v",
			i, r.IsOnChangeSupported, r.PreferredType, r.MinInterval, errApp)

		if errApp != nil {
			resp[i].Err = errApp
			err = errApp

			continue
		}
	}

	return resp, err
}

// collectNotificationPreferences computes overall notification preferences (is on-change
// supported, min sample interval, preferred mode etc) by combining individual table preferences
// from the notificationAppInfo array. Writes them to the IsSubscribeResponse object 'resp'.
func collectNotificationPreferences(nAppInfos []notificationAppInfo, resp *IsSubscribeResponse) {
	if len(nAppInfos) == 0 {
		return
	}

	resp.IsOnChangeSupported = true
	resp.PreferredType = OnChange
	resp.MinInterval = minSubsInterval

	for _, nInfo := range nAppInfos {
		if !nInfo.isOnChangeSupported || nInfo.dbno == db.CountersDB {
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

//Creates connection will all the redis DBs. To be used for get request
func getAllDbs(isGetCase bool) ([db.MaxDB]*db.DB, error) {
	var dbs [db.MaxDB]*db.DB
	var err error
	var isWriteDisabled bool

	if isGetCase {
		isWriteDisabled = true
	} else {
		isWriteDisabled = false
	}

	//Create Application DB connection
	dbs[db.ApplDB], err = db.NewDB(getDBOptions(db.ApplDB, isWriteDisabled))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create ASIC DB connection
	dbs[db.AsicDB], err = db.NewDB(getDBOptions(db.AsicDB, isWriteDisabled))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create Counter DB connection
	dbs[db.CountersDB], err = db.NewDB(getDBOptions(db.CountersDB, isWriteDisabled))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create Log Level DB connection
	dbs[db.LogLevelDB], err = db.NewDB(getDBOptions(db.LogLevelDB, isWriteDisabled))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	isWriteDisabled = true

	//Create Config DB connection
	dbs[db.ConfigDB], err = db.NewDB(getDBOptions(db.ConfigDB, isWriteDisabled))

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
	dbs[db.FlexCounterDB], err = db.NewDB(getDBOptions(db.FlexCounterDB, isWriteDisabled))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create State DB connection
	dbs[db.StateDB], err = db.NewDB(getDBOptions(db.StateDB, isWriteDisabled))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create Error DB connection
	dbs[db.ErrorDB], err = db.NewDB(getDBOptions(db.ErrorDB, isWriteDisabled))

	if err != nil {
		closeAllDbs(dbs[:])
		return dbs, err
	}

	//Create User DB connection
	dbs[db.UserDB], err = db.NewDB(getDBOptions(db.UserDB, isWriteDisabled))

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

// Enable onChangeCaching on DB instance
func enableOnChangeCaching(dbs []*db.DB) {
	for _, d := range dbs {
		if d != nil {
			d.Opts.OnChangeCacheEnabled = true
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
