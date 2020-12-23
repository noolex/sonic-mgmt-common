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
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/openconfig/ygot/ygot"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"strings"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"reflect"
	"fmt"
)

type subscribeReqXlator struct {
	subReq          *subscribeReq
	subReqXlateInfo *XfmrSubscribeReqXlateInfo
	pathXlator      *subscribePathXlator
}

/*
minInterval - aggregating the min interval
 */

type subscribeReq struct {
	reqUri               string
	ygPath               string
	isTrgtDfnd           bool
	isTrgtPathWldcrd     bool
	gPath                *gnmipb.Path
	txCache              interface{}
	dbs                  [db.MaxDB]*db.DB
	tblKeyCache          map[string]tblKeyCache
	isOnchange           bool
	xlateNodeType        xlateNodeType
	chldNodeMaxMinIntrvl int
}

type subscribePathXlator struct {
	gPath           *gnmipb.Path
	pathXlateInfo   *XfmrSubscribePathXlateInfo
	ygListXpathInfo *yangXpathInfo
	uriPath         string
	subReq          *subscribeReq
}

type xlateNodeType int

const (
	TARGET_NODE xlateNodeType = 1 + iota
	CHILD_NODE
)

type dbTableKeyInfo struct {
	Table          *db.TableSpec // table to be subscribed
	Key            *db.Key       // specific key entry of the table to be subscribed
	DbNum          db.DBNum      // database index
	DbFldYgMapList []*DbFldYgPathInfo
}

type DbFldYgPathInfo struct {
	RltvPath       string
	DbFldYgPathMap map[string]string //db field to leaf / rel. path to leaf
}

type XfmrSubscribePathXlateInfo struct {
	Path           *gnmipb.Path // subscribe path
	ygXpathInfo    *yangXpathInfo
	DbKeyXlateInfo []*dbTableKeyInfo
	MinInterval    int          // min interval
	NeedCache      bool
	PType          NotificationType
	OnChange       bool
}

type XfmrSubscribeReqXlateInfo struct {
	TrgtPathInfo  *XfmrSubscribePathXlateInfo
	ChldPathsInfo []*XfmrSubscribePathXlateInfo
}

func (reqXlator *subscribeReqXlator) getSubscribePathXlator(gPath *gnmipb.Path, uriPath string, ygXpathInfo *yangXpathInfo) (*subscribePathXlator, error) {
	var err error
	reqXlator.pathXlator.gPath = gPath
	reqXlator.pathXlator.pathXlateInfo = &(XfmrSubscribePathXlateInfo{Path: gPath, ygXpathInfo: ygXpathInfo})
	reqXlator.pathXlator.uriPath = uriPath
	reqXlator.pathXlator.ygListXpathInfo = nil
	if reqXlator.subReq.xlateNodeType == TARGET_NODE {
		if err = reqXlator.pathXlator.setTrgtListYgXpathInfo(); err != nil {
			log.Error("Error in setting the YgXpathInfo of the last LIST node in the path and the error is :", err)
			return nil, err
		}
	}
	return reqXlator.pathXlator, err
}

func (pathXltr *subscribePathXlator) setTrgtListYgXpathInfo() (error) {
	log.Info("Entering into the setTrgtListYgXpathInfo: ygPath: ", pathXltr.subReq.ygPath)

	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	ygPathTmp := pathXltr.subReq.ygPath

	for ygXpathInfo != nil && !ygXpathInfo.yangEntry.IsList() {
		tIdx := strings.LastIndex(ygPathTmp, "/")
		// -1: not found, and 0: first character in the path
		if tIdx > 0 {
			ygPathTmp = ygPathTmp[0:tIdx]
		} else {
			break
		}
		log.Info("xPathTmp: ", ygPathTmp)
		if ygXpathInfoTmp, ok := xYangSpecMap[ygPathTmp]; !ok || ygXpathInfoTmp == nil {
			log.Error("xYangSpecMap does not have the yangXpathInfo for the path:", ygPathTmp)
			return tlerr.InternalError{Format: "xYangSpecMap does not have the yangXpathInfo", Path: ygPathTmp}
		} else if ygXpathInfo.yangEntry == nil {
			log.Error("yangXpathInfo has nil value for its yangEntry field for the path:", ygPathTmp)
			return tlerr.InternalError{Format: "yangXpathInfo has nil value for its yangEntry field", Path: ygPathTmp}
		} else {
			ygXpathInfo = ygXpathInfoTmp
		}
	}
	if ygXpathInfo != nil && ygXpathInfo.yangEntry.IsList() {
		pathXltr.ygListXpathInfo = ygXpathInfo
	}
	return nil
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) addPathXlateInfo(tblSpec *db.TableSpec, dbKey *db.Key, dBNum db.DBNum) {
	dbTblIfo := dbTableKeyInfo{Table: tblSpec, Key: dbKey, DbNum: dBNum}
	pathXlateInfo.DbKeyXlateInfo = append(pathXlateInfo.DbKeyXlateInfo, &dbTblIfo)
}

func GetSubscribeReqXlator(reqUri string, isOnchange bool, dbs [db.MaxDB]*db.DB, txCache interface{}) (*subscribeReqXlator, error) {

	log.Info("Entering into the GetSubscribeReqXlator: for the reqUri: ", reqUri)
	subReq := subscribeReq{reqUri: reqUri, dbs:dbs, txCache: txCache, isTrgtPathWldcrd: true}
	subReq.tblKeyCache = make(map[string]tblKeyCache)
	subReq.isOnchange = isOnchange
	subReq.xlateNodeType = TARGET_NODE
	subReq.chldNodeMaxMinIntrvl = 0
	var err error

	if subReq.ygPath, _, err = XfmrRemoveXPATHPredicates(reqUri); err != nil {
		log.Error("Got error from the XfmrRemoveXPATHPredicates function: ", err)
		return nil, err
	}

	if subReq.gPath, err = ygot.StringToPath(reqUri, ygot.StructuredPath, ygot.StringSlicePath); err != nil {
		log.Error("Error in converting the URI into GNMI path for the URI: ", reqUri)
		return nil, tlerr.InternalError{Format: "Error in converting the URI into GNMI path", Path: reqUri}
	}

	for _, pathElem := range subReq.gPath.Elem {
		for _, kv := range pathElem.Key {
			log.Info("list node: kv: ", kv)
			if kv == "*" {
				continue
			}
			subReq.isTrgtPathWldcrd = false
			break
		}
	}

	subReqXlator := subscribeReqXlator{subReq: &subReq}
	subReqXlator.subReqXlateInfo = new(XfmrSubscribeReqXlateInfo)
	subReqXlator.pathXlator = &subscribePathXlator{subReq: &subReq}

	return &subReqXlator, nil
}

func (reqXlator *subscribeReqXlator) Translate() (error) {

	log.Info("Entering into the Translate: reqXlator: ", *reqXlator)

	var err error

	ygXpathInfoTrgt, ok := xYangSpecMap[reqXlator.subReq.ygPath]

	if !ok || ygXpathInfoTrgt == nil {
		log.Errorf("Translate: ygXpathInfo data not found in the xYangSpecMap for xpath : %v", reqXlator.subReq.ygPath)
		return tlerr.InternalError{Format: "Error in processing the subscribe path", Path: reqXlator.subReq.reqUri}
	} else if ygXpathInfoTrgt.yangEntry == nil {
		log.Errorf("Translate: yangEntry is nil in the ygXpathInfo for the path: %v", reqXlator.subReq.ygPath)
		return tlerr.NotSupportedError{Format: "Subscribe not supported", Path: reqXlator.subReq.reqUri}
	}

	isSubscribe := true
	if ygXpathInfoTrgt.subscribeOnChg == XFMR_DISABLE {
		if reqXlator.subReq.isTrgtDfnd {
			if ygXpathInfoTrgt.subscribePref == nil || *ygXpathInfoTrgt.subscribePref == "onchange" {
				isSubscribe = false
			}
		} else if reqXlator.subReq.isOnchange {
			isSubscribe = false
		}
	}

	if !isSubscribe {
		log.Errorf("Subscribe not supported; on change disabled for the given subscribe path:: %v", reqXlator.subReq.reqUri)
		return tlerr.NotSupportedError{Format: "Subscribe not supported; on change disabled for the given subscribe path: ", Path: reqXlator.subReq.reqUri}
	}

	if reqXlator.subReq.isTrgtDfnd {
		// by default the preference is on change
		if ygXpathInfoTrgt.subscribePref == nil || *ygXpathInfoTrgt.subscribePref == "onchange" {
			reqXlator.subReq.isOnchange = true
		}
	}

	if err = reqXlator.translateTargetNodePath(ygXpathInfoTrgt); err == nil {
		if reqXlator.subReq.isTrgtDfnd {
			if ygXpathInfoTrgt.subscribePref != nil && *ygXpathInfoTrgt.subscribePref != "onchange" {
				reqXlator.subReqXlateInfo.TrgtPathInfo.MinInterval = ygXpathInfoTrgt.subscribeMinIntvl
				reqXlator.subReqXlateInfo.TrgtPathInfo.PType = Sample
				reqXlator.subReq.isOnchange = false
			} else {
				reqXlator.subReqXlateInfo.TrgtPathInfo.PType = OnChange
				reqXlator.subReq.isOnchange = true
			}
		} else if !reqXlator.subReq.isTrgtDfnd {
			reqXlator.subReqXlateInfo.TrgtPathInfo.OnChange = true
		}

		if err = reqXlator.translateChildNodePaths(ygXpathInfoTrgt); err != nil {
			log.Errorf("Error in translating the child node for the subscribe path: %v", err)
			return err
		}

		if !reqXlator.subReq.isOnchange {
			// sampling
			if reqXlator.subReqXlateInfo.TrgtPathInfo.MinInterval < reqXlator.subReq.chldNodeMaxMinIntrvl {
				reqXlator.subReqXlateInfo.TrgtPathInfo.MinInterval = reqXlator.subReq.chldNodeMaxMinIntrvl
			}
		}

	} else {
		log.Errorf("Error in translating the target node subscribe path: %v", err)
	}

	return err
}

func (reqXlator *subscribeReqXlator) translateTargetNodePath(trgtYgxPath *yangXpathInfo) (error) {
	if trgtPathXlator, err := reqXlator.getSubscribePathXlator(reqXlator.subReq.gPath, reqXlator.subReq.reqUri, trgtYgxPath); err != nil {
		log.Error("Error in getSubscribePathXlator: error: ", err)
		return err
	} else {
		if err = trgtPathXlator.translatePath(); err != nil {
			log.Error("Error: in translateTargetNodePath: error: ", err)
			return err
		}
		reqXlator.subReqXlateInfo.TrgtPathInfo = trgtPathXlator.pathXlateInfo
	}
	return nil
}

func (pathXltr *subscribePathXlator) handleSubtreeNodeXlate() (error) {
	log.Info("Entering into the handleSubtreeNodeXlate: reqUri: ", pathXltr.uriPath)
	//subtree subscribe transformer
	// call the subscribe subtree transformer
	subInParam := XfmrSubscInParams{pathXltr.uriPath, pathXltr.subReq.dbs, make(RedisDbMap), TRANSLATE_SUBSCRIBE}
	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	subOutPram, subErr := xfmrSubscSubtreeHandler(subInParam, ygXpathInfo.xfmrFunc)
	log.Info("handleSubtreeNodeXlate: subOutPram: ", subOutPram)
	if subErr != nil {
		log.Error("Got error form the Subscribe transformer callback ", subErr)
		return subErr
	}

	//TODO: Need to see how this subOutPram.onChange is going to be set to false, since the default value is itself false
	//if len(subOutPram.dbDataMap) == 0 || (pathXltr.subReq.isOnchange && subOutPram.onChange == false) {
	//		log.Error("Onchange subscription is not supported; onChange flag set to false and dbDataMap is empty from the Subscribe transformer callback: ", ygXpathInfo.xfmrFunc)
	//		return nil, tlerr.InternalError{Format: "Onchange subscription is not supported; onChange flag set to false and dbDataMap is empty from the Subscribe transformer callback", Path: *pathXltr.uriPath}
	//}

	if pathXltr.subReq.isOnchange || pathXltr.subReq.xlateNodeType == TARGET_NODE {
		for dbNum, tblKeyInfo := range subOutPram.dbDataMap {
			log.Info("handleSubtreeNodeXlate: dbNum: ", dbNum)
			for tblName, tblFieldInfo := range tblKeyInfo {
				log.Info("handleSubtreeNodeXlate: tblName: ", tblName)
				tblSpec := &db.TableSpec{Name: tblName}
				for dBKey, tblField := range tblFieldInfo {
					log.Info("handleSubtreeNodeXlate: tYgXpathInfo.delim: ", ygXpathInfo.delim)
					keyComp := strings.Split(dBKey, ygXpathInfo.delim)
					log.Info("handleSubtreeNodeXlate: tblField: ", tblField)
					pathXltr.pathXlateInfo.addPathXlateInfo(tblSpec, &db.Key{keyComp}, dbNum)
				}
			}
		}
	} else if subOutPram.nOpts != nil && pathXltr.subReq.chldNodeMaxMinIntrvl < subOutPram.nOpts.mInterval {
		pathXltr.subReq.chldNodeMaxMinIntrvl = subOutPram.nOpts.mInterval
	}
	// subscribe - call subsribe transformer
	// if one of the subscriber onchange is disable then throw error saying subscription not supported
	// fill the tableNames

	return nil
}

func (pathXltr *subscribePathXlator) translatePath() (error) {
	log.Info("subscribePathXlator: translatePath - printing xpathInfo..")
	ygXpathInfoTrgt := pathXltr.pathXlateInfo.ygXpathInfo

	//debugPrintXPathInfo(ygXpathInfoTrgt)
	log.Info("Entering into the processTrgtNodePath: ygXpathInfoTrgt: ", ygXpathInfoTrgt)

	if len(ygXpathInfoTrgt.xfmrFunc) > 0 {
		if err := pathXltr.handleSubtreeNodeXlate(); err != nil {
			return err
		}
	} else {
		if pathXltr.subReq.isOnchange || pathXltr.subReq.xlateNodeType == TARGET_NODE {
			if err := pathXltr.handleNonSubtreeNodeXlate(); err != nil {
				return err
			}
		} else if pathXltr.subReq.chldNodeMaxMinIntrvl < ygXpathInfoTrgt.subscribeMinIntvl {
			pathXltr.subReq.chldNodeMaxMinIntrvl = ygXpathInfoTrgt.subscribeMinIntvl
		}
	}
	return nil
}

func (pathXltr *subscribePathXlator) handleYangToDbKeyXfmr() (string, error) {
	log.Info("Entering into the handleYangToDbKeyXfmr.. pathXltr.uriPath: ", pathXltr.uriPath)

	log.Info("handleYangToDbKeyXfmr: isTrgtPathWldcrd: ", pathXltr.subReq.isTrgtPathWldcrd)
	// call the yang to db key transformer
	if !pathXltr.subReq.isTrgtPathWldcrd && pathXltr.ygListXpathInfo != nil {
		ygXpathInfo := pathXltr.ygListXpathInfo
		log.Info("handleYangToDbKeyXfmr: key transformer name:", ygXpathInfo.xfmrKey)
		currDbNum := db.DBNum(ygXpathInfo.dbIndex)
		ygotRoot, err := pathXltr.unMarshallYgotObj(pathXltr.pathXlateInfo.Path)
		if err != nil {
			return "", err
		}
		inParams := formXfmrInputRequest(pathXltr.subReq.dbs[ygXpathInfo.dbIndex], pathXltr.subReq.dbs, currDbNum, ygotRoot, pathXltr.uriPath,
			pathXltr.subReq.reqUri, SUBSCRIBE, "", nil, nil, nil, pathXltr.subReq.txCache)
		if dBTblKey, errKey := keyXfmrHandler(inParams, ygXpathInfo.xfmrKey); errKey == nil {
			return dBTblKey, nil
		} else {
			log.Error("handleYangToDbKeyXfmr: keyXfmrHandler callback error:", errKey)
			return dBTblKey, errKey
		}
	}

	if pathXltr.ygListXpathInfo == nil {
		log.Info("handleYangToDbKeyXfmr: ygListXpathInfo is nil for the uripath: ", pathXltr.uriPath)
	}
	return "", nil
}

func (pathXltr *subscribePathXlator) handleNonSubtreeNodeXlate() (error) {
	log.Info("Entering into the handleNonSubtreeNodeXlate:", pathXltr.uriPath)
	var err error
	var tblNames []string
	var keyComp []string

	if dBTblKey, err := pathXltr.handleYangToDbKeyXfmr(); err != nil {
		return err
	} else if len(dBTblKey) > 0 {
		keyComp = strings.Split(dBTblKey, pathXltr.ygListXpathInfo.delim)
	}

	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	if pTblName := pathXltr.getXpathInfoTableName(); pTblName != nil {
		tblNames = append(tblNames, *pTblName)
	} else if ygXpathInfo.xfmrTbl != nil && len(*ygXpathInfo.xfmrTbl) > 0 {
		if tblNames, err = pathXltr.handleTableXfmrCallback(); err != nil {
			return err
		}
	}

	var dbKey *db.Key

	if len(keyComp) > 0 {
		log.Info("handleNonSubtreeNodeXlate: keyComp: ", keyComp)
		dbKey = &db.Key{keyComp}
	}

	for _, tblName := range tblNames {
		log.Info("handleNonSubtreeNodeXlate: Adding tablename: ", tblName)
		pathXltr.pathXlateInfo.addPathXlateInfo(&db.TableSpec{Name: tblName}, dbKey, ygXpathInfo.dbIndex)
	}

	return nil
}

func (pathXltr *subscribePathXlator) handleTableXfmrCallback() ([]string, error) {
	log.Info("Entering into the handleTableXfmrCallback:", pathXltr.uriPath)
	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo

	currDbNum := db.DBNum(ygXpathInfo.dbIndex)
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
	//	log.Error("Error in unmarshalling the uri into ygot object: ", errYg)
	//	return notificationListInfo, errYg
	//}
	rootIntf := reflect.ValueOf(&deviceObj).Interface()
	ygotObj := rootIntf.(ygot.GoStruct)
	inParams := formXfmrInputRequest(pathXltr.subReq.dbs[ygXpathInfo.dbIndex], pathXltr.subReq.dbs, currDbNum, &ygotObj, pathXltr.uriPath,
		pathXltr.subReq.reqUri, SUBSCRIBE, "", &dbDataMap, nil, nil, pathXltr.subReq.txCache)
	tblList, tblXfmrErr := xfmrTblHandlerFunc(*ygXpathInfo.xfmrTbl, inParams, pathXltr.subReq.tblKeyCache)
	if tblXfmrErr != nil {
		log.Error("handleTableXfmrCallback: table transformer callback returns error: ", tblXfmrErr)
		log.Info("handleTableXfmrCallback: table transformer callback: ", *ygXpathInfo.xfmrTbl)
		//TODO: commenting out the return error statement for now, this has to be uncommented in the future
		//return nil, tblXfmrErr
	} else if inParams.isVirtualTbl != nil && *inParams.isVirtualTbl {
		log.Info("handleTableXfmrCallback: isVirtualTbl is set to true for the table transformer callback: ", *ygXpathInfo.xfmrTbl)
	} else {
		return tblList, nil
	}

	return nil, nil
}

func (pathXltr *subscribePathXlator) getXpathInfoTableName() (*string) {
	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	if ygXpathInfo.tableName != nil && *ygXpathInfo.tableName != "NONE" {
		return ygXpathInfo.tableName
	}
	return nil
}

func (reqXlator *subscribeReqXlator) translateChildNodePaths(ygXpathInfo *yangXpathInfo) (error) {
	log.Info("Entering the processTrgtNodeChildPathsXlate method..")
	var err error
	ygNode := ygXpathInfo.yangEntry

	if (!ygNode.IsList() && !ygNode.IsContainer()) {
		return nil
	}

	rltvUriPath := ""
	reqXlator.subReq.xlateNodeType = CHILD_NODE

	trgtXpathNode := &(ygXpathNode{relUriPath: rltvUriPath, ygXpathInfo: ygXpathInfo})
	trgtXpathNode.pathXlateInfo = reqXlator.subReqXlateInfo.TrgtPathInfo

	if err = reqXlator.collectChldYgXPathInfo(ygNode, reqXlator.subReq.ygPath, rltvUriPath, ygXpathInfo, trgtXpathNode); err != nil {
		log.Error("translateChildNodePaths: Error in collectChldYgXPathInfo; error: ", err)
		return err
	}

	if err := reqXlator.subReqXlateInfo.TrgtPathInfo.addDbFldYgPathMap("", trgtXpathNode); err != nil {
		log.Error("translateChildNodePaths: Error in addDbFldYgPathMap; error: ", err)
		return err
	}

	if err = reqXlator.traverseYgXpathAndTranslate(trgtXpathNode, "", reqXlator.subReqXlateInfo.TrgtPathInfo); err != nil {
		log.Error("translateChildNodePaths: Error in traverseYgXpathAndTranslate; error: ", err)
	}

	return err
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) isDbTablePresentInParent(parentDbKeyXlateInfo []*dbTableKeyInfo) (bool) {
	if len(parentDbKeyXlateInfo) == 0 {
		return false
	}
	for _, dbXlateInfo := range pathXlateInfo.DbKeyXlateInfo {
		isPresent := false
		for _, parentDbInfo := range parentDbKeyXlateInfo {
			if parentDbInfo.DbNum != dbXlateInfo.DbNum {
				continue
			}
			if parentDbInfo.Table.Name != dbXlateInfo.Table.Name {
				continue
			}
			isPresent = true
			break
		}
		if !isPresent {
			return false
		}
	}
	return true
}
//parentDbKeyXlateInfo []*dbTableKeyInfo
func (reqXlator *subscribeReqXlator) traverseYgXpathAndTranslate(ygXpNode *ygXpathNode, parentRelUri string, parentPathXlateInfo *XfmrSubscribePathXlateInfo) (error) {
	var err error

	for _, chldNode := range ygXpNode.chldNodes {

		log.Info("next child node relPath Path: ", chldNode.relUriPath)
		log.Info("next child node xpathObj: ", chldNode.ygXpathInfo)

		var pathXlateInfo *XfmrSubscribePathXlateInfo
		relUri := parentRelUri

		if chldNode.isParentTbl {
			pathXlateInfo = parentPathXlateInfo
			log.Info("traverseYgXpathAndTranslate: isParentTbl: true")
			pathXlateInfo.copyDbFldYgPathMap(relUri, chldNode)
		} else {
			var gPathCurr *gnmipb.Path
			if gPathCurr, err = reqXlator.uriToAbsolutePath(chldNode.relUriPath); err != nil {
				return err
			}

			uriPath := reqXlator.subReq.reqUri + chldNode.relUriPath
			log.Info("next child node URI Path: ", uriPath)

			pathXlator, err := reqXlator.getSubscribePathXlator(gPathCurr, uriPath, chldNode.ygXpathInfo)
			if err != nil {
				log.Error("traverseYgXpathAndTranslate: Error in getSubscribePathXlator: ", err)
				return err
			}

			if err = pathXlator.translatePath(); err != nil {
				log.Error("traverseYgXpathAndTranslate: Error in translate(): ", err)
				return err
			} else {
				chldNode.pathXlateInfo = pathXlator.pathXlateInfo
			}

			if chldNode.pathXlateInfo.isDbTablePresentInParent(parentPathXlateInfo.DbKeyXlateInfo) {
				pathXlateInfo = parentPathXlateInfo
				// copy the dbFldYgPathMap from chlNode
				log.Info("traverseYgXpathAndTranslate: inside isDbTablePresentInParent..")
				parentPathXlateInfo.copyDbFldYgPathMap(relUri, chldNode)

			} else {
				pathXlateInfo = chldNode.pathXlateInfo
				relUri = chldNode.relUriPath
				chldNode.pathXlateInfo.addDbFldYgPathMap("", chldNode)

				if !chldNode.ygXpathInfo.yangEntry.IsList() && len(parentPathXlateInfo.DbKeyXlateInfo) > 0 {
					// other than list node, that is for the container / leaf / leaf-list node
					// the db key entry of the parent list node's table db key will be used as the table
					// key for the container/leaf/leaf-list node's table
					// this is needed to subscribe to the table for the particular key entry
					// TODO: Do we need to add support to handle if the container table key is different
					// than it parent table key, if so then the feature team needs to write the
					// yang to db key transformer for the given path and its associated table
					for _, dbKeyInfo := range chldNode.pathXlateInfo.DbKeyXlateInfo {
						if dbKeyInfo.Key == nil {
							// since the yang key is same for the all mapped tables, so assigning
							// the first key.. which will be same for all the tables
							dbKeyInfo.Key = parentPathXlateInfo.DbKeyXlateInfo[0].Key
						}
					}
				} else if len(chldNode.pathXlateInfo.DbKeyXlateInfo) == 0 {
					// for list node and the length of DbKeyXlateInfo is 0
					log.Error("traverseYgXpathAndTranslate: Db table information is not found for the list node for the uri path : ", uriPath)
					//debugPrintXPathInfo(chldNode.ygXpathInfo)
					return tlerr.InternalError{Format: "traverseYgXpathAndTranslate: Db table information is not found for the list node for the uri path", Path: uriPath}
				}

				reqXlator.subReqXlateInfo.ChldPathsInfo = append(reqXlator.subReqXlateInfo.ChldPathsInfo, chldNode.pathXlateInfo)
			}
		}

		if err = reqXlator.traverseYgXpathAndTranslate(chldNode, relUri, pathXlateInfo); err != nil {
			return err
		}
	}
	return err
}

func (reqXlator *subscribeReqXlator) debugTrvsalCtxt(ygEntry *yang.Entry, ygPath string, rltvUriPath string, ygXpathInfo *yangXpathInfo) {
	log.Info("debugTrvsalCtxt ygPath: ", ygPath)
	log.Info("debugTrvsalCtxt rltvUriPath: ", rltvUriPath)
	log.Info("debugTrvsalCtxt ygXpathInfo: ", ygXpathInfo)
	log.Info("debugTrvsalCtxt ygEntry: ", ygEntry)
}

type ygXpathNode struct {
	relUriPath        string
	ygXpathInfo       *yangXpathInfo
	chldNodes         []*ygXpathNode
	dbFldYgPathMap    map[string]string
	dbTblFldYgPathMap map[string]map[string]string
	pathXlateInfo     *XfmrSubscribePathXlateInfo
	isParentTbl       bool
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) copyDbFldYgPathMap(parentRelUri string, ygXpNode *ygXpathNode) (error) {
	log.Info("copyDbFldYgPathMap: parentRelUri: ", parentRelUri)
	log.Info("copyDbFldYgPathMap: ygXpNode.relUriPath: ", ygXpNode.relUriPath)
	if sIdx := strings.Index(ygXpNode.relUriPath, parentRelUri); sIdx == -1 {
		log.Error("copyDbFldYgPathMap: Not able to get the relative path of the node for the path: ", ygXpNode.relUriPath)
		return tlerr.InternalError{Format: "Not able to get the relative path of the node", Path: ygXpNode.relUriPath}
	} else {
		log.Info("copyDbFldYgPathMap: sIdx: ", sIdx)
		relPath := string(ygXpNode.relUriPath[sIdx + len(parentRelUri):])
		log.Info("copyDbFldYgPathMap: relPath: ", relPath)
		return pathXlateInfo.addDbFldYgPathMap(relPath, ygXpNode)
	}
	return nil
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) addDbFldYgPathMap(relPath string, ygXpNode *ygXpathNode) (error) {
	if len(pathXlateInfo.DbKeyXlateInfo) == 1 {
		log.Info("addDbFldYgPathMap: single table:", ygXpNode.relUriPath)
		dbKeyInfo := pathXlateInfo.DbKeyXlateInfo[0]
		dbFldInfo := DbFldYgPathInfo{relPath, make(map[string]string)}
		dbFldInfo.DbFldYgPathMap = ygXpNode.dbFldYgPathMap
		dbKeyInfo.DbFldYgMapList = append(dbKeyInfo.DbFldYgMapList, &dbFldInfo)
	} else {
		log.Info("addDbFldYgPathMap: multi table:", ygXpNode.relUriPath)
		for _, dbKeyInfo := range pathXlateInfo.DbKeyXlateInfo {
			if dbFldYgMap, ok := ygXpNode.dbTblFldYgPathMap[dbKeyInfo.Table.Name]; ok {
				dbFldInfo := DbFldYgPathInfo{relPath, make(map[string]string)}
				dbFldInfo.DbFldYgPathMap = dbFldYgMap
				dbKeyInfo.DbFldYgMapList = append(dbKeyInfo.DbFldYgMapList, &dbFldInfo)
			} else {
				log.Error("addDbFldYgPathMap: Not able to find the table for the db field:", ygXpNode.relUriPath)
				return tlerr.InternalError{Format: "Not able to find the table for the db field", Path: ygXpNode.relUriPath}
			}
		}
	}
	return nil
}

func (ygXpNode *ygXpathNode) addDbFldNames(ygNodeName string, dbFldNames []string) (error) {
	for _, dbTblFldName := range dbFldNames {
		tblField := strings.Split(dbTblFldName, ":")
		if len(tblField) > 1 {
			if _, ok := ygXpNode.dbTblFldYgPathMap[tblField[0]]; !ok {
				ygXpNode.dbTblFldYgPathMap[tblField[0]] = make(map[string]string)
				ygXpNode.dbTblFldYgPathMap[tblField[0]][tblField[1]] = ygNodeName
			} else {
				ygXpNode.dbTblFldYgPathMap[tblField[0]][tblField[1]] = ygNodeName
			}
		} else {
			log.Error("addDbFldNames: Table name is missing in the composite-db-fields annoation for the leaf node path:", ygXpNode.relUriPath + "/" + ygNodeName)
			return tlerr.InternalError{Format: "Table name is missing in the composite-db-fields annoation for the leaf node path", Path: ygXpNode.relUriPath + "/" + ygNodeName}
		}
	}
	return nil
}

func (ygXpNode *ygXpathNode) addDbFldName(ygNodeName string, dbFldName string) {
	ygXpNode.dbFldYgPathMap[dbFldName] = ygNodeName
}

func (ygXpNode *ygXpathNode) addChildNode(rltUri string, ygXpathInfo *yangXpathInfo) (*ygXpathNode) {
	chldNode := ygXpathNode{relUriPath: rltUri, ygXpathInfo: ygXpathInfo}
	chldNode.dbFldYgPathMap = make(map[string]string)
	ygXpNode.chldNodes = append(ygXpNode.chldNodes, &chldNode)
	return &chldNode
}

func (reqXlator *subscribeReqXlator) collectChldYgXPathInfo(ygEntry *yang.Entry, ygPath string,
rltvUriPath string, ygXpathInfo *yangXpathInfo, ygXpNode *ygXpathNode) (error) {

	log.Info("Entering into the collectChldYgXPathInfo..")

	reqXlator.debugTrvsalCtxt(ygEntry, ygPath, rltvUriPath, ygXpathInfo)

	for _, childYgEntry := range ygEntry.Dir {
		log.Info("collectChldYgXPathInfo: node name:", childYgEntry.Name)
		childYgPath := ygPath + "/" + childYgEntry.Name
		log.Info("collectChldYgXPathInfo: childYgPath:", childYgPath)

		if chYgXpathInfo, ok := xYangSpecMap[childYgPath]; ok {
			rltvChldUriPath := rltvUriPath
			if chYgXpathInfo.nameWithMod != nil {
				rltvChldUriPath = rltvChldUriPath + "/" + *(chYgXpathInfo.nameWithMod)
			} else {
				rltvChldUriPath = rltvChldUriPath + "/" + childYgEntry.Name
			}

			if childYgEntry.IsList() {
				log.Info("collectChldYgXPathInfo: childYgEntry.Key: ", childYgEntry.Key)
				keyElemNames := strings.Fields(childYgEntry.Key)
				for _, keName := range keyElemNames {
					rltvChldUriPath = rltvChldUriPath + "[" + keName + "=*]"
				}
				log.Info("chldUri uri path for list node with keys: ", rltvChldUriPath)
			}

			//if (chYgXpathInfo.dbIndex == db.CountersDB) {
			//	log.Warning("CountersDB mapped in the path => ", childYgPath)
			//	return tlerr.NotSupportedError{Format: "Subscribe not supported; one of its child path is mapped to COUNTERS DB", Path: childYgPath}
			//} else if chYgXpathInfo.subscribeOnChg == XFMR_DISABLE {
			//	log.Warning("Subscribe not supported; one of the child path's on_change subscription is disabled => ", childYgPath)
			//	return tlerr.NotSupportedError{Format: "Subscribe not supported; one of the child path's on_change subscription is disabled", Path: childYgPath}
			//} else if isTrgtDefnd && chYgXpathInfo.subscribePref != nil && *chYgXpathInfo.subscribePref != "onchange" {
			//	log.Warning("Subscribe not supported; one of the child path's subscription preference is NOT on_change => ", childYgPath)
			//	return tlerr.NotSupportedError{Format: "Subscribe not supported; one of the child path's subscription preference is not on_change", Path: childYgPath}
			//}

			tblName := ""
			if ((chYgXpathInfo.tableName != nil && *chYgXpathInfo.tableName != "NONE") && (ygXpathInfo.tableName == nil ||
				*ygXpathInfo.tableName != *chYgXpathInfo.tableName)) {
				tblName = *chYgXpathInfo.tableName
			}

			if childYgEntry.IsLeaf() || childYgEntry.IsLeafList() {
				if tblName != "" {
					log.Infof("adding table name %v for the leaf node for the path %v ", tblName, childYgPath)
					ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else if len(chYgXpathInfo.fieldName) > 0 {
					log.Infof("adding field name %v for the leaf node for the path %v ", chYgXpathInfo.fieldName, childYgEntry.Name)
					ygXpNode.addDbFldName(childYgEntry.Name, chYgXpathInfo.fieldName)
				} else if len(chYgXpathInfo.compositeFields) > 0 {
					log.Infof("adding composite field names %v for the leaf node for the path %v ", chYgXpathInfo.compositeFields, childYgEntry.Name)
					if err := ygXpNode.addDbFldNames(childYgEntry.Name, chYgXpathInfo.compositeFields); err != nil {
						return err
					}
				}// else {
				//	log.Error("collectChldYgXPathInfo: No db field name mapping for the yang leaf-name: ", childYgPath)
				//	if len(chYgXpathInfo.xfmrField) > 0 {
				//		log.Error("collectChldYgXPathInfo: Please add the field-name annotation, since the yang node has the field transformer: ", chYgXpathInfo.xfmrField)
				//	}
				//	return tlerr.InternalError{Format: "No Db field name mapping for the yang node", Path: childYgPath}
				//}
			} else if (childYgEntry.IsList() || childYgEntry.IsContainer()) {
				chldNode := ygXpNode
				if len(chYgXpathInfo.xfmrFunc) > 0 {
					log.Infof("adding subtree xfmr func %v for the path %v ", chYgXpathInfo.xfmrFunc, childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else if tblName != "" {
					log.Infof("adding table name %v for the path %v ", tblName, childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else if (chYgXpathInfo.xfmrTbl != nil) {
					log.Infof("adding table transformer %v for the path %v ", *chYgXpathInfo.xfmrTbl, childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else {
					if childYgEntry.IsList() {
						log.Error("No table related information for the LIST yang node path: ", childYgPath)
						return tlerr.InternalError{Format: "No yangXpathInfo found for the LIST / Container yang node path", Path: childYgPath}
					}
					log.Infof("Adding ygXpNode for the container with no tables mapped and the path %v", childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
					chldNode.isParentTbl = true
				}
				if err := reqXlator.collectChldYgXPathInfo(childYgEntry, childYgPath, rltvChldUriPath, chYgXpathInfo, chldNode); err != nil {
					log.Infof("Error in collecting the ygXpath Info for the yang path: %v and the error: %v", childYgPath, err)
					return err
				}
			}
		} else if childYgEntry.IsList() || childYgEntry.IsContainer() {
			log.Error("No yangXpathInfo found for the LIST / Container yang node path: ", childYgPath)
			return tlerr.InternalError{Format: "No yangXpathInfo found for the LIST / Container yang node path", Path: childYgPath}
		} else {
			log.Warning("No yangXpathInfo found for the leaf / leaf-list node yang node path: ", childYgPath)
		}
	}

	return nil
}

func (pathXltr *subscribePathXlator) unMarshallYgotObj(gPath *gnmipb.Path) (*ygot.GoStruct, error) {
	//for _, p := range gPathChild.Elem {
	//	pathSlice := strings.Split(p.Name, ":")
	//	p.Name = pathSlice[len(pathSlice)-1]
	//}
	deviceObj := ocbinds.Device{}
	//if _, _, errYg := ytypes.GetOrCreateNode(ocbSch.RootSchema(), &deviceObj, gPath); errYg != nil {
	//	log.Error("Error in unmarshalling the uri into ygot object:", errYg)
	//	return nil, errYg
	//}
	rootIntf := reflect.ValueOf(&deviceObj).Interface()
	ygotObj := rootIntf.(ygot.GoStruct)
	return &ygotObj, nil
}

func (reqXlator *subscribeReqXlator) GetSubscribeReqXlateInfo() (*XfmrSubscribeReqXlateInfo) {
	return reqXlator.subReqXlateInfo
}

func (reqXlator *subscribeReqXlator) uriToAbsolutePath(rltvUri string) (*gnmipb.Path, error) {
	log.Info("Entering into uriToAbsolutePath: rltvUri: ", rltvUri)
	if gRelPath, err := ygot.StringToPath(rltvUri, ygot.StructuredPath, ygot.StringSlicePath); err != nil {
		log.Error("Error in converting the URI into GNMI path for the URI: ", rltvUri)
		return nil, tlerr.InternalError{Format: "Error in converting the URI into GNMI path", Path: rltvUri}
	} else {
		gPath := gnmipb.Path{}
		gPath.Elem = append(gPath.Elem, reqXlator.subReq.gPath.Elem...)
		gPath.Elem = append(gPath.Elem, gRelPath.Elem...)
		return &gPath, nil
	}
}

//TODO: remove the fmt.Print and modify it into formatted string and print using log.
func debugPrintXPathInfo(xpathInfo *yangXpathInfo) {
	fmt.Printf("    yangDataType: %v\r\n", xpathInfo.yangDataType)
	fmt.Println("      fieldName: ", xpathInfo.fieldName)
	if xpathInfo.nameWithMod != nil {
		fmt.Printf("    nameWithMod : %v\r\n", *xpathInfo.nameWithMod)
	} else {
		fmt.Println("      nameWithMod: ", xpathInfo.nameWithMod)
	}
	fmt.Printf("    hasChildSubTree : %v\r\n", xpathInfo.hasChildSubTree)
	fmt.Printf("    hasNonTerminalNode : %v\r\n", xpathInfo.hasNonTerminalNode)
	fmt.Printf("    subscribeOnChg     : %v\r\n", xpathInfo.subscribeOnChg)
	fmt.Printf("    subscribeMinIntvl  : %v\r\n", xpathInfo.subscribeMinIntvl)
	if xpathInfo.subscribePref != nil {
		fmt.Printf("    subscribePref      : %v\r\n", *xpathInfo.subscribePref)
	} else {
		fmt.Printf("    subscribePref      : %v\r\n", xpathInfo.subscribePref)
	}
	fmt.Printf("    tableName: ")
	if xpathInfo.tableName != nil {
		fmt.Printf("%v", *xpathInfo.tableName)
	} else {
		fmt.Printf("%v", xpathInfo.tableName)
	}
	fmt.Printf("\r\n    virtualTbl: ")
	if xpathInfo.virtualTbl != nil {
		fmt.Printf("%v", *xpathInfo.virtualTbl)
	} else {
		fmt.Printf("%v", xpathInfo.virtualTbl)
	}
	fmt.Printf("\r\n    xfmrTbl  : ")
	if xpathInfo.xfmrTbl != nil {
		fmt.Printf("%v", *xpathInfo.xfmrTbl)
	} else {
		fmt.Printf("%v", xpathInfo.xfmrTbl)
	}
	fmt.Printf("\r\n    keyName  : ")
	if xpathInfo.keyName != nil {
		fmt.Printf("%v", *xpathInfo.keyName)
	} else {
		fmt.Printf("%v", xpathInfo.keyName)
	}
	if len(xpathInfo.childTable) > 0 {
		fmt.Printf("\r\n    childTbl : %v", xpathInfo.childTable)
	}
	if len(xpathInfo.fieldName) > 0 {
		fmt.Printf("\r\n    FieldName: %v", xpathInfo.fieldName)
	}
	fmt.Printf("\r\n    keyLevel : %v", xpathInfo.keyLevel)
	if len(xpathInfo.xfmrKey) > 0 {
		fmt.Printf("\r\n    xfmrKeyFn: %v", xpathInfo.xfmrKey)
	}
	if len(xpathInfo.xfmrFunc) > 0 {
		fmt.Printf("\r\n    xfmrFunc : %v", xpathInfo.xfmrFunc)
	}
	if len(xpathInfo.xfmrField) > 0 {
		fmt.Printf("\r\n    xfmrField :%v", xpathInfo.xfmrField)
	}
	if xpathInfo.xfmrPath != nil {
		fmt.Printf("\r\n    xfmrPath :%v", *xpathInfo.xfmrPath)
	}
	fmt.Printf("\r\n    dbIndex  : %v", xpathInfo.dbIndex)

	fmt.Printf("\r\n    yangEntry: ")
	if xpathInfo.yangEntry != nil {
		fmt.Printf("%v", *xpathInfo.yangEntry)
	} else {
		fmt.Printf("%v", xpathInfo.yangEntry)
	}
	fmt.Printf("\r\n    dbEntry: ")
	if xpathInfo.dbEntry != nil {
		fmt.Printf("%v", *xpathInfo.dbEntry)
	} else {
		fmt.Printf("%v", xpathInfo.dbEntry)
	}
	fmt.Printf("\r\n    keyXpath: %d\r\n", xpathInfo.keyXpath)
	for i, kd := range xpathInfo.keyXpath {
		fmt.Printf("        %d : xpathInfo. %#v\r\n", i, kd)
	}
	fmt.Printf("\r\n    isKey   : %v\r\n", xpathInfo.isKey)
	fmt.Println("      delim: ", xpathInfo.delim)
}