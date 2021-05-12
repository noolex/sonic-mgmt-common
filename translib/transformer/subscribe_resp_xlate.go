////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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

package transformer

import (
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	log "github.com/golang/glog"
	"github.com/openconfig/gnmi/proto/gnmi"
	"strings"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"sync"
	"github.com/openconfig/ygot/ygot"
	"reflect"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"fmt"
)

type subscribeNotfRespXlator struct {
	ntfXlateReq   *subscribeNotfXlateReq
	dbYgXlateList []*DbYgXlateInfo
	KeyGroupComps []int // set by path transformer
}

type subscribeNotfXlateReq struct {
	path     *gnmi.Path
	dbNum    db.DBNum
	table    *db.TableSpec
	key      *db.Key
	entry    *db.Value
	dbs      [db.MaxDB]*db.DB
	opaque   interface{}
	reqLogId string
}

type DbYgXlateInfo struct {
	pathIdx     int
	ygXpathInfo *yangXpathInfo
	tableName   string
	dbKey       string
	uriPath     string
	xlateReq    *subscribeNotfXlateReq
}

func GetSubscribeNotfRespXlator(ctxID interface{}, gPath *gnmi.Path, dbNum db.DBNum, table *db.TableSpec, key *db.Key,
entry *db.Value, dbs [db.MaxDB]*db.DB, opaque interface{}) (*subscribeNotfRespXlator, error) {
	reqLogId := "subNotfReq Id:[" + fmt.Sprintf("%v", ctxID) + "] : "

	log.Infof(reqLogId + "GetSubscribeNotfRespXlator: table: %v, key: %v, " +
		"dbno: %v, path: %v", table, key, dbNum, gPath)

	if opaque == nil || (reflect.ValueOf(opaque).Kind() == reflect.Ptr && reflect.ValueOf(opaque).IsNil()) {
		opaque = new(sync.Map)
	}

	xlateReq := subscribeNotfXlateReq{gPath, dbNum, table, key, entry, dbs, opaque, reqLogId}
	return &subscribeNotfRespXlator{ntfXlateReq: &xlateReq}, nil
}

func (respXlator *subscribeNotfRespXlator) Translate() (*gnmi.Path, error) {
	ntfXlateReq := respXlator.ntfXlateReq

	log.Info(ntfXlateReq.reqLogId + "subscribeNotfRespXlator:Translate: path: ", ntfXlateReq.path)

	pathElem := respXlator.ntfXlateReq.path.Elem

	for idx := len(pathElem) - 1; idx >= 0; idx-- {

		ygPath := respXlator.getYangListPath(idx)
		log.Info("subscribeNotfRespXlator:Translate: ygPath: ", ygPath)
		if log.V(dbLgLvl) {
			log.Info(ntfXlateReq.reqLogId + "subscribeNotfRespXlator:Translate:ygPath: ", ygPath)
		}

		ygXpathInfo, err := respXlator.getYangXpathInfo(ygPath)
		if err != nil {
			return nil, err
		}

		if log.V(dbLgLvl) {
			log.Info(ntfXlateReq.reqLogId + "subscribeNotfRespXlator:Translate: ygXpathInfo: ", ygXpathInfo)
		}

		// for subtree, path transformr can be present at any node level
		if (len(pathElem[idx].Key) == 0 || !respXlator.hasPathWildCard(idx)) && len(ygXpathInfo.xfmrPath) == 0 {
			continue
		}

		if len(ygXpathInfo.xfmrPath) > 0 {
			if err := respXlator.handlePathTransformer(ygXpathInfo, idx); err != nil {
				return nil, err
			} else {
				if err := respXlator.processDbToYangKeyXfmrList(); err != nil {
					return nil, err
				} else {
					log.Error(ntfXlateReq.reqLogId + "subscribeNotfRespXlator: translated path: ", *respXlator.ntfXlateReq.path)
					return respXlator.ntfXlateReq.path, nil
				}
			}
		} else if ygXpathInfo.virtualTbl != nil && (*ygXpathInfo.virtualTbl) {
			log.Error(ntfXlateReq.reqLogId + "Translate: virtual table is set to true and path transformer not found list node path: ", *respXlator.ntfXlateReq.path)
			return nil, tlerr.InternalError{Format: ntfXlateReq.reqLogId + "virtual table is set to true and path transformer not found list node path", Path: ygPath}
		} else if len(ygXpathInfo.xfmrFunc) == 0 && len(ygXpathInfo.xfmrKey) > 0 {
			dbYgXlateInfo := &DbYgXlateInfo{pathIdx: idx, ygXpathInfo: ygXpathInfo, xlateReq: respXlator.ntfXlateReq}
			dbYgXlateInfo.setUriPath()
			respXlator.dbYgXlateList = append(respXlator.dbYgXlateList, dbYgXlateInfo)
			// since there is no path transformer defined in the path, processing the collected db to yang key xfmrs
			if err := respXlator.processDbToYangKeyXfmrList(); err != nil {
				log.Error(ntfXlateReq.reqLogId + "Translate: Error in processDbToYangKeyXfmrList for the path: ", *respXlator.ntfXlateReq.path)
				return nil, err
			}
		} else {
			if len(ygXpathInfo.xfmrFunc) > 0 {
				log.Warning(ntfXlateReq.reqLogId + "Translate: Could not find the path transformer for the xpath: ", ygPath)
			} else {
				log.Warning(ntfXlateReq.reqLogId + "Translate: Could not find the DbToYangKey transformer for the xpath: ", ygPath)
			}
			log.Warning(ntfXlateReq.reqLogId + "Translate: Attempting direct conversion - to convert the db key to yang key directly for the path: ", ygPath)
			log.Infof(ntfXlateReq.reqLogId + "Translate: key comp: %v, pathElem key: %v", respXlator.ntfXlateReq.key.Comp, pathElem[idx].Key)

			if len(respXlator.ntfXlateReq.key.Comp) == len(pathElem[idx].Key) {
				dbKeyIdx := 0
				for kn := range pathElem[idx].Key {
					pathElem[idx].Key[kn] = respXlator.ntfXlateReq.key.Comp[dbKeyIdx]
					dbKeyIdx++
				}
			} else {
				log.Error(ntfXlateReq.reqLogId + "Translate: Could not find the path transformer or DbToYangKey transformer for the ygXpathListInfo: ", ygPath)
				return nil, tlerr.InternalError{Format: ntfXlateReq.reqLogId + "Could not find the path transformer or DbToYangKey transformer", Path: ygPath}
			}
		}
	}

	log.Info(ntfXlateReq.reqLogId + "subscribeNotfRespXlator: translated path: ", *respXlator.ntfXlateReq.path)
	return respXlator.ntfXlateReq.path, nil
}

func (respXlator *subscribeNotfRespXlator) handlePathTransformer(ygXpathInfo *yangXpathInfo, pathIdx int) (error) {
	var currPath gnmi.Path
	pathElems := respXlator.ntfXlateReq.path.Elem
	ygSchemPath := "/" + pathElems[0].Name
	currPath.Elem = append(currPath.Elem, pathElems[0])

	for idx := 1; idx <= pathIdx; idx++ {
		ygSchemPath = ygSchemPath + "/" + pathElems[idx].Name
		currPath.Elem = append(currPath.Elem, pathElems[idx])
	}

	inParam := XfmrDbToYgPathParams{
		yangPath:      &currPath,
		subscribePath: respXlator.ntfXlateReq.path,
		ygSchemaPath:  ygSchemPath,
		tblName:       respXlator.ntfXlateReq.table.Name,
		tblKeyComp:    respXlator.ntfXlateReq.key.Comp,
		tblEntry:      respXlator.ntfXlateReq.entry,
		dbNum:         respXlator.ntfXlateReq.dbNum,
		dbs:           respXlator.ntfXlateReq.dbs,
		db:            respXlator.ntfXlateReq.dbs[respXlator.ntfXlateReq.dbNum],
		ygPathKeys:    make(map[string]string),
		keyGroup:      &respXlator.KeyGroupComps,
	}

	if err := respXlator.xfmrPathHandlerFunc("DbToYangPath_" + ygXpathInfo.xfmrPath, inParam); err != nil {
		log.Errorf(respXlator.ntfXlateReq.reqLogId + "Error in path transformer callback : %v for the gnmi path: %v, and the error: %v", ygXpathInfo.xfmrPath, respXlator.ntfXlateReq.path, err)
		return err
	}

	log.Info(respXlator.ntfXlateReq.reqLogId + "handlePathTransformer: uriPathKeysMap: ", inParam.ygPathKeys)
	ygpath := "/" + respXlator.ntfXlateReq.path.Elem[0].Name

	for idx := 1; idx <= pathIdx; idx++ {
		ygpath = ygpath + "/" + respXlator.ntfXlateReq.path.Elem[idx].Name

		if log.V(dbLgLvl) {
			log.Info(respXlator.ntfXlateReq.reqLogId + "handlePathTransformer: yang map keys: yang path:", ygpath)
		}

		for keyName, keyVal := range respXlator.ntfXlateReq.path.Elem[idx].Key {
			if keyVal != "*" {
				continue
			}
			if log.V(dbLgLvl) {
				log.Info(respXlator.ntfXlateReq.reqLogId + "handlePathTransformer: yang map keys: yang key path:", ygpath + "/" + keyName)
			}
			if ygKeyVal, ok := inParam.ygPathKeys[ygpath + "/" + keyName]; ok {
				respXlator.ntfXlateReq.path.Elem[idx].Key[keyName] = ygKeyVal
			} else {
				log.Errorf(respXlator.ntfXlateReq.reqLogId + "Error: path transformer callback (%v) response yang key map does not have " +
					"the yang key value for the yang key: %v ", ygXpathInfo.xfmrPath, ygpath + "/" + keyName)
				return tlerr.InternalError{Format: respXlator.ntfXlateReq.reqLogId + "Error in processsing the transformer callback map keys", Path: inParam.yangPath.String()}
			}
		}
	}

	return nil
}

func (respXlator *subscribeNotfRespXlator) xfmrPathHandlerFunc(xfmrPathFunc string, inParam XfmrDbToYgPathParams) (error) {

	log.Infof(respXlator.ntfXlateReq.reqLogId + "Received inParam %v, Path transformer function name %v", inParam, xfmrPathFunc)

	if retVals, err := XlateFuncCall(xfmrPathFunc, inParam); err != nil {
		return err
	} else {
		if retVals == nil || len(retVals) != PATH_XFMR_RET_ARGS {
			log.Errorf(respXlator.ntfXlateReq.reqLogId + "Error: incorrect return type in the transformer call back function (\"%v\") for the yang path %v", xfmrPathFunc, inParam.yangPath.String())
			return tlerr.InternalError{Format: "incorrect return type in the transformer call back function", Path: inParam.yangPath.String()}
		} else if retVals[PATH_XFMR_RET_ERR_INDX].Interface() != nil {
			if err = retVals[PATH_XFMR_RET_ERR_INDX].Interface().(error); err != nil {
				log.Errorf(respXlator.ntfXlateReq.reqLogId + "Path Transformer function(\"%v\") returned error - %v.", xfmrPathFunc, err)
				return err
			}
		}
	}

	return nil
}

func (respXlator *subscribeNotfRespXlator) processDbToYangKeyXfmrList() (error) {
	for idx := (len(respXlator.dbYgXlateList) - 1); idx >= 0; idx -- {
		respXlator.dbYgXlateList[idx].handleDbToYangKeyXlate()
	}
	return nil
}

func (respXlator *subscribeNotfRespXlator) hasPathWildCard(idx int) bool {
	for _, kv := range respXlator.ntfXlateReq.path.Elem[idx].Key {
		if kv == "*" {
			continue
		}
		return false
	}
	return true
}

func (respXlator *subscribeNotfRespXlator) getYangListPath(listIdx int) (string) {
	ygPathTmp := ""
	for idx := 0; idx <= listIdx; idx++ {
		pathName := respXlator.ntfXlateReq.path.Elem[idx].Name
		if idx > 0 {
			pathNames := strings.Split(respXlator.ntfXlateReq.path.Elem[idx].Name, ":")
			if len(pathNames) > 1 {
				pathName = pathNames[1]
			}
		}
		ygPathTmp = ygPathTmp + "/" + pathName
	}
	log.Infof(respXlator.ntfXlateReq.reqLogId + "getYangListPath: listIdx: %v, ygPathTmp: %v ", listIdx, ygPathTmp)
	return ygPathTmp
}

func (dbYgXlateInfo *DbYgXlateInfo) setUriPath() {
	for idx := 0; idx <= dbYgXlateInfo.pathIdx; idx++ {
		dbYgXlateInfo.uriPath = dbYgXlateInfo.uriPath + "/" + dbYgXlateInfo.xlateReq.path.Elem[idx].Name
		for kn, kv := range dbYgXlateInfo.xlateReq.path.Elem[idx].Key {
			// not including the wildcard in the path; since it will be sent to db to yang key xfmr
			if kv == "*" {
				continue
			}
			dbYgXlateInfo.uriPath = dbYgXlateInfo.uriPath + "[" + kn + "=" + kv + "]"
		}
	}
}

func (respXlator *subscribeNotfRespXlator) getYangXpathInfo(ygPath string) (*yangXpathInfo, error) {
	ygXpathListInfo, ok := xYangSpecMap[ygPath]

	if !ok || ygXpathListInfo == nil {
		log.Error(respXlator.ntfXlateReq.reqLogId + "ygXpathInfo data not found in the xYangSpecMap for xpath : ", ygPath)
		return nil, tlerr.InternalError{Format: respXlator.ntfXlateReq.reqLogId + "Error in processing the subscribe path", Path: ygPath}
	} else if ygXpathListInfo.yangEntry == nil {
		return nil, tlerr.NotSupportedError{Format: respXlator.ntfXlateReq.reqLogId + "Subscribe not supported", Path: ygPath}
	}
	return ygXpathListInfo, nil
}

func (dbYgXlateInfo *DbYgXlateInfo) handleDbToYangKeyXlate() (error) {

	if dbYgXlateInfo.ygXpathInfo.tableName != nil && *dbYgXlateInfo.ygXpathInfo.tableName != "NONE" {
		dbYgXlateInfo.tableName = *dbYgXlateInfo.ygXpathInfo.tableName
	} else if dbYgXlateInfo.ygXpathInfo.xfmrTbl != nil {
		log.Info(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: Going to call the table transformer => ", *dbYgXlateInfo.ygXpathInfo.xfmrTbl)
		tblLst, err := dbYgXlateInfo.handleTableXfmrCallback()
		if err != nil {
			log.Error(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: Error in handling the table transformer" +
				" callaback:", *dbYgXlateInfo.ygXpathInfo.tableName)
			return err
		}
		if len(tblLst) == 0 {
			log.Error(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: Error: No tables are returned by the table " +
				"transformer: for the path:", dbYgXlateInfo.uriPath)
			return tlerr.NotSupportedError{Format: dbYgXlateInfo.xlateReq.reqLogId + "More than one table found for the list" +
				" URI from the table transformer", Path: dbYgXlateInfo.uriPath}
		} else {
			// taking the first table, since number of keys should be same between the tables returned by table transformer
			dbYgXlateInfo.tableName = tblLst[0]
			log.Info(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: Found table from the table transformer: table name: ", dbYgXlateInfo.tableName)
		}
	} else {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "Error in handling the table transformer callaback:", *dbYgXlateInfo.ygXpathInfo.tableName)
		return tlerr.NotSupportedError{Format: dbYgXlateInfo.xlateReq.reqLogId + "Could not find the table information for the path", Path: dbYgXlateInfo.uriPath}
	}

	ygDbInfo, err := dbYgXlateInfo.getDbYangNode()
	if err != nil {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: xDbSpecMap does not have the dbInfo entry for the table:", dbYgXlateInfo.tableName)
		return err
	}

	dbIdx := ygDbInfo.dbIndex
	delim := ygDbInfo.delim
	if len(delim) == 0 && dbIdx < db.MaxDB {
		delim = dbYgXlateInfo.xlateReq.dbs[dbIdx].Opts.KeySeparator
	}

	for _, listName := range ygDbInfo.listName {
		if listName != dbYgXlateInfo.tableName + "_LIST" {
			log.Warning(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: sonic yang model list name does not" +
				" match with the table name, list name: ", listName)
			continue
		}
		dbYgListInfo, err := dbYgXlateInfo.getDbYangListInfo(listName)
		if err != nil {
			log.Error(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: Error in getDbYangListNode: ", err)
			return err
		}
		ygDbListNode := dbYgListInfo.dbEntry
		if ygDbListNode.IsList() {
			keyList := strings.Fields(ygDbListNode.Key)
			log.Info("keyList: ", keyList)
			if len(keyList) > dbYgXlateInfo.xlateReq.key.Len() {
				return tlerr.NotSupportedError{Format: dbYgXlateInfo.xlateReq.reqLogId + "Could not convert the db key to yang path," +
					" since parent db table key is not part of child table db key", Path: dbYgXlateInfo.uriPath}
			}
			dbTableKey := dbYgXlateInfo.xlateReq.key.Comp[0]
			for idx := 1; idx < len(keyList); idx++ {
				if len(dbYgListInfo.delim) > 0 {
					delim = dbYgListInfo.delim
				} else if dbYgListInfo.dbIndex < db.MaxDB {
					delim = dbYgXlateInfo.xlateReq.dbs[dbYgListInfo.dbIndex].Opts.KeySeparator
				} else if len(delim) == 0 && ygDbInfo.dbEntry.Config != yang.TSFalse {
					delim = "|"
				}
				if len(delim) == 0 {
					log.Error(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXlate: Key-delim or db-name annotation is missing" +
						" from the sonic yang model container: ", ygDbInfo.dbEntry.Name)
					return tlerr.NotSupportedError{Format: dbYgXlateInfo.xlateReq.reqLogId + "Could not form db key, since key-delim or " +
						"db-name annotation is missing from the sonic yang model container", Path: ygDbInfo.dbEntry.Name}
				}
				dbTableKey = dbTableKey + delim + dbYgXlateInfo.xlateReq.key.Comp[idx]
			}
			log.Info("dbTableKey: ", dbTableKey)
			dbYgXlateInfo.dbKey = dbTableKey
			return dbYgXlateInfo.handleDbToYangKeyXfmr()
		}
	}

	return nil
}

func (dbYgXlateInfo *DbYgXlateInfo) handleDbToYangKeyXfmr() (error) {
	dbDataMap := make(RedisDbMap)
	for i := db.ApplDB; i < db.MaxDB; i++ {
		dbDataMap[i] = make(map[string]map[string]db.Value)
	}
	inParams := formXfmrInputRequest(dbYgXlateInfo.xlateReq.dbs[dbYgXlateInfo.xlateReq.dbNum], dbYgXlateInfo.xlateReq.dbs, dbYgXlateInfo.xlateReq.dbNum,
		nil, dbYgXlateInfo.uriPath, dbYgXlateInfo.uriPath, GET, dbYgXlateInfo.dbKey, &dbDataMap, nil, nil, dbYgXlateInfo.xlateReq.opaque)

	inParams.table = dbYgXlateInfo.tableName
	rmap, err := keyXfmrHandlerFunc(inParams, dbYgXlateInfo.ygXpathInfo.xfmrKey)
	if err != nil {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXfmr: error in keyXfmrHandlerFunc ", err)
		return err
	}

	log.Info(dbYgXlateInfo.xlateReq.reqLogId + "handleDbToYangKeyXfmr: res map: ", rmap)
	for k, v := range rmap {
		//Assuming that always the string to be passed as the value in the DbtoYang key transformer response map
		dbYgXlateInfo.xlateReq.path.Elem[dbYgXlateInfo.pathIdx].Key[k] = fmt.Sprintf("%v", v)
	}

	return nil
}

func (dbYgXlateInfo *DbYgXlateInfo) getDbYangListInfo(listName string) (*dbInfo, error) {
	dbListkey := dbYgXlateInfo.tableName + "/" + listName
	log.Info("getDbYangListInfo: dbListkey: ", dbListkey)
	dbListInfo, ok := xDbSpecMap[dbListkey]
	if !ok {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "getDbYangListInfo: xDbSpecMap does not have the dbInfo entry for the table:", dbYgXlateInfo.tableName)
		return nil, tlerr.InternalError{Format: dbYgXlateInfo.xlateReq.reqLogId + "xDbSpecMap does not have the dbInfo entry for the table " + dbYgXlateInfo.tableName, Path: dbYgXlateInfo.uriPath}
	}
	if dbListInfo.dbEntry == nil {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "dbInfo has nil value for its yangEntry field for the table:", dbYgXlateInfo.tableName)
		return nil, tlerr.InternalError{Format: dbYgXlateInfo.xlateReq.reqLogId + "dbInfo has nil value for its yangEntry field for the table " + dbYgXlateInfo.tableName, Path: dbYgXlateInfo.uriPath}
	}
	if dbListInfo.dbEntry.IsList() {
		return dbListInfo, nil
	} else {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "dbInfo is not a Db yang LIST node", *dbListInfo)
		return nil, tlerr.InternalError{Format: dbYgXlateInfo.xlateReq.reqLogId + "dbListInfo is not a Db yang LIST node for the listName " + listName}
	}
	return nil, nil
}

func (dbYgXlateInfo *DbYgXlateInfo) getDbYangNode() (*dbInfo, error) {
	if dbInfo, ok := xDbSpecMap[dbYgXlateInfo.tableName]; !ok || dbInfo == nil {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "xDbSpecMap does not have the dbInfo entry for the table:", dbYgXlateInfo.tableName)
		return nil, tlerr.InternalError{Format: dbYgXlateInfo.xlateReq.reqLogId + "xDbSpecMap does not have the dbInfo entry for the table " + dbYgXlateInfo.tableName, Path: dbYgXlateInfo.uriPath}
	} else if dbInfo.dbEntry == nil {
		log.Error(dbYgXlateInfo.xlateReq.reqLogId + "dbInfo has nil value for its yangEntry field for the table:", dbYgXlateInfo.tableName)
		return nil, tlerr.InternalError{Format: dbYgXlateInfo.xlateReq.reqLogId + "dbInfo has nil value for its yangEntry field for the table " + dbYgXlateInfo.tableName, Path: dbYgXlateInfo.uriPath}
	} else {
		return dbInfo, nil
	}
}

func (dbYgXlateInfo *DbYgXlateInfo) handleTableXfmrCallback() ([]string, error) {
	ygXpathInfo := dbYgXlateInfo.ygXpathInfo
	uriPath := dbYgXlateInfo.uriPath

	log.Info(dbYgXlateInfo.xlateReq.reqLogId + "handleTableXfmrCallback: ", uriPath)
	var dbs [db.MaxDB]*db.DB
	txCache := new(sync.Map)
	currDbNum := db.DBNum(ygXpathInfo.dbIndex)
	xfmrDbTblKeyCache := make(map[string]tblKeyCache)
	dbDataMap := make(RedisDbMap)
	for i := db.ApplDB; i < db.MaxDB; i++ {
		dbDataMap[i] = make(map[string]map[string]db.Value)
	}
	//gPathChild, gPathErr := ygot.StringToPath(reqUripath, ygot.StructuredPath, ygot.StringSlicePath)
	//if gPathErr != nil {
	//	log.Error("Error in uri to path conversion: ", gPathErr)
	//	return notificationListInfo, gPathErr
	//}

	deviceObj := ocbinds.Device{}
	//if _, _, errYg := ytypes.GetOrCreateNode(ocbSch.RootSchema(), &deviceObj, gPathChild); errYg != nil {
	//	log.Error("Error in unmarshalling the uri into ygot object ==> ", errYg)
	//	return notificationListInfo, errYg
	//}
	rootIntf := reflect.ValueOf(&deviceObj).Interface()
	ygotObj := rootIntf.(ygot.GoStruct)
	inParams := formXfmrInputRequest(dbs[ygXpathInfo.dbIndex], dbs, currDbNum, &ygotObj, uriPath,
		uriPath, SUBSCRIBE, "", &dbDataMap, nil, nil, txCache)
	tblList, tblXfmrErr := xfmrTblHandlerFunc(*ygXpathInfo.xfmrTbl, inParams, xfmrDbTblKeyCache)
	if tblXfmrErr != nil {
		log.Errorf(dbYgXlateInfo.xlateReq.reqLogId + "handleTableXfmrCallback: table transformer callback returns error: %v for the callback %v", tblXfmrErr, *ygXpathInfo.xfmrTbl)
	} else if inParams.isVirtualTbl != nil && *inParams.isVirtualTbl {
		log.Info(dbYgXlateInfo.xlateReq.reqLogId + "handleTableXfmrCallback: virtualTbl is SET to TRUE for this table transformer callback: ", *ygXpathInfo.xfmrTbl)
	} else {
		log.Infof(dbYgXlateInfo.xlateReq.reqLogId + "handleTableXfmrCallback: table list %v returned by table transformer callback: %v ", tblList, *ygXpathInfo.xfmrTbl)
		return tblList, nil
	}

	return nil, nil
}
