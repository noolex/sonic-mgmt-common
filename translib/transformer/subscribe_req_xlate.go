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
	xlateNodeType   xlateNodeType
	subReqXlateInfo *XfmrSubscribeReqXlateInfo
}

type subscribeReq struct {
	reqUri           *string
	ygPath           *string
	isTrgtDfnd       bool
	isTrgtPathWldcrd bool
	gPath            *gnmipb.Path
	txCache          interface{}
	dbs              [db.MaxDB]*db.DB
	tblKeyCache      map[string]tblKeyCache
}

type subscribePathXlator struct {
	gPath           *gnmipb.Path
	pathXlateInfo   *XfmrSubscribePathXlateInfo
	ygListXpathInfo *yangXpathInfo
	uriPath         *string
	subReq          *subscribeReq
}

type xlateNodeType int

const (
	TARGET_NODE xlateNodeType = 1 + iota
	CHILD_NODE
)

type dbTableKeyInfo struct {
	Table *db.TableSpec // table to be subscribed
	Key   *db.Key       // specific key entry of the table to be subscribed
	DbNum db.DBNum      // database index
}

type XfmrSubscribePathXlateInfo struct {
	Path           *gnmipb.Path      // subscribe path
	ygXpathInfo    *yangXpathInfo
	DbKeyXlateInfo []*dbTableKeyInfo
	MinInterval    int               // min interval
	NeedCache      bool
	PType          NotificationType
	OnChange       bool
	DbFldYgPathMap map[string]string //db field to leaf / rel. path to leaf
}

type XfmrSubscribeReqXlateInfo struct {
	TrgtPathInfo  *XfmrSubscribePathXlateInfo
	ChldPathsInfo []*XfmrSubscribePathXlateInfo
}

func (reqXlator *subscribeReqXlator) getSubscribePathXlator(gPath *gnmipb.Path, uriPath *string, ygXpathInfo *yangXpathInfo) (*subscribePathXlator, error) {
	var err error
	pathXltr := subscribePathXlator{gPath: gPath, pathXlateInfo: &(XfmrSubscribePathXlateInfo{Path: gPath, ygXpathInfo: ygXpathInfo})}
	pathXltr.uriPath = uriPath
	pathXltr.subReq = reqXlator.subReq
	if reqXlator.xlateNodeType == TARGET_NODE {
		if err = (&pathXltr).setTrgtListYgXpathInfo(); err != nil {
			log.Error("Error in setting the YgXpathInfo of the last LIST node in the path and the error is :", err)
			return nil, err
		}
	}
	return &(pathXltr), err
}

func (pathXltr *subscribePathXlator) setTrgtListYgXpathInfo() (error) {
	log.Info("Entering into the setTrgtListYgXpathInfo: ygPath ==> ", *pathXltr.subReq.ygPath)

	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	ygPathTmp := *pathXltr.subReq.ygPath

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
	dbTblIfo := dbTableKeyInfo{tblSpec, dbKey, dBNum}
	pathXlateInfo.DbKeyXlateInfo = append(pathXlateInfo.DbKeyXlateInfo, &dbTblIfo)
}

func GetSubscribeReqXlator(reqUri *string, dbs [db.MaxDB]*db.DB, txCache interface{}) (*subscribeReqXlator, error) {

	log.Info("Entering into the GetSubscribeReqXlator: for the reqUri ==> ", *reqUri)
	subReq := subscribeReq{reqUri: reqUri, dbs:dbs, txCache: txCache, gPath: nil, ygPath: nil, isTrgtPathWldcrd: true, isTrgtDfnd: false}
	subReq.tblKeyCache = make(map[string]tblKeyCache)

	if ygPath, _, err := XfmrRemoveXPATHPredicates(*reqUri); err != nil {
		log.Error("Got error from the XfmrRemoveXPATHPredicates function: ", err)
		return nil, err
	} else {
		subReq.ygPath = &ygPath
	}

	var err error
	if subReq.gPath, err = ygot.StringToPath(*reqUri, ygot.StructuredPath, ygot.StringSlicePath); err != nil {
		log.Error("Error in converting the URI into GNMI path for the URI: ", *reqUri)
		return nil, tlerr.InternalError{Format: "Error in converting the URI into GNMI path", Path: *reqUri}
	}

	for _, pathElem := range subReq.gPath.Elem {
		for _, kv := range pathElem.Key {
			log.Info("list node: kv ==> ", kv)
			if kv == "*" {
				continue
			}
			subReq.isTrgtPathWldcrd = false
			break
		}
	}

	subReqXlator := subscribeReqXlator{subReq: &subReq, xlateNodeType: TARGET_NODE}

	return &subReqXlator, nil
}

func (reqXlator *subscribeReqXlator) Translate() (error) {

	log.Info("Entering into the Translate: reqXlator: ==> ", reqXlator)

	var err error

	ygXpathInfoTrgt, ok := xYangSpecMap[*reqXlator.subReq.ygPath]

	if !ok || ygXpathInfoTrgt == nil {
		log.Errorf("ygXpathInfo data not found in the xYangSpecMap for xpath : %v", *reqXlator.subReq.ygPath)
		return tlerr.InternalError{Format: "Error in processing the subscribe path", Path: *reqXlator.subReq.reqUri}
	} else if ygXpathInfoTrgt.yangEntry == nil {
		return tlerr.NotSupportedError{Format: "Subscribe not supported", Path: *reqXlator.subReq.reqUri}
	}

	// to keep all the translated info
	reqXlator.subReqXlateInfo = new(XfmrSubscribeReqXlateInfo)

	if err = reqXlator.translateTargetNodePath(ygXpathInfoTrgt); err == nil {
		err = reqXlator.translateChildNodePaths(ygXpathInfoTrgt)
	} else {
		log.Errorf("Error in translating the target node subscribe path: %v", err)
	}

	return err
}

func (reqXlator *subscribeReqXlator) translateTargetNodePath(trgtYgxPath *yangXpathInfo) (error) {
	if trgtPathXlator, err := reqXlator.getSubscribePathXlator(reqXlator.subReq.gPath, reqXlator.subReq.reqUri, trgtYgxPath); err != nil {
		log.Error("Error in getSubscribePathXlator: error => ", err)
		return err
	} else {
		if err = trgtPathXlator.translatePath(); err != nil {
			log.Error("Error: in translateTargetNodePath: error => ", err)
		} else {
			reqXlator.subReqXlateInfo.TrgtPathInfo = trgtPathXlator.pathXlateInfo
		}
		return err
	}
}

func (pathXltr *subscribePathXlator) handleSubtreeNodeXlate() (error) {
	log.Info("Entering into the handleSubtreeNodeXlate: reqUri: ", *pathXltr.uriPath)
	//subtree subscribe transformer
	// call the subscribe subtree transformer
	subInParam := XfmrSubscInParams{*pathXltr.uriPath, pathXltr.subReq.dbs, make(RedisDbMap), TRANSLATE_SUBSCRIBE}
	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	subOutPram, subErr := xfmrSubscSubtreeHandler(subInParam, ygXpathInfo.xfmrFunc)
	log.Info("handleSubtreeNodeXlate: subOutPram: ", subOutPram)
	if subErr != nil {
		log.Error("Got error form the Subscribe transformer callback ", subErr)
		return subErr
	}
	//TODO: Need to see how this subOutPram.onChange is going to be set to false, since the default value is itself false
	//if subOutPram.onChange == false && len(subOutPram.dbDataMap) == 0 {
	//	log.Error("Onchange subscription is not supported; onChange flag set to false and dbDataMap is empty from the Subscribe transformer callback")
	//	errSub := errors.New("Onchange flag set to false thru' subscriber transformer and subscription is not supported for this path "+uPath)
	//	return nil, errSub
	//}
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
	// subscribe - call subsribe transformer
	// if one of the subscriber onchange is disable then throw error saying subscription not supported
	// fill the tableNames

	return nil
}

func (pathXltr *subscribePathXlator) translatePath() (error) {
	log.Info("subscribePathXlator: translatePath - printing xpathInfo..")
	ygXpathInfoTrgt := pathXltr.pathXlateInfo.ygXpathInfo

	debugPrintXPathInfo(ygXpathInfoTrgt)
	log.Info("Entering into the processTrgtNodePath: ygXpathInfoTrgt: ", ygXpathInfoTrgt)

	if len(ygXpathInfoTrgt.xfmrFunc) > 0 {
		if err := pathXltr.handleSubtreeNodeXlate(); err != nil {
			return err
		}
	} else {
		if err := pathXltr.handleNonSubtreeNodeXlate(); err != nil {
			return err
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
		inParams := formXfmrInputRequest(pathXltr.subReq.dbs[ygXpathInfo.dbIndex], pathXltr.subReq.dbs, currDbNum, ygotRoot, *pathXltr.uriPath,
			*pathXltr.subReq.reqUri, SUBSCRIBE, "", nil, nil, nil, pathXltr.subReq.txCache)
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
	log.Info("Entering into the handleTableXfmrCallback:", *pathXltr.uriPath)
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
	//	log.Error("Error in unmarshalling the uri into ygot object ==> ", errYg)
	//	return notificationListInfo, errYg
	//}
	rootIntf := reflect.ValueOf(&deviceObj).Interface()
	ygotObj := rootIntf.(ygot.GoStruct)
	inParams := formXfmrInputRequest(pathXltr.subReq.dbs[ygXpathInfo.dbIndex], pathXltr.subReq.dbs, currDbNum, &ygotObj, *pathXltr.uriPath,
		*pathXltr.subReq.reqUri, SUBSCRIBE, "", &dbDataMap, nil, nil, pathXltr.subReq.txCache)
	tblList, tblXfmrErr := xfmrTblHandlerFunc(*ygXpathInfo.xfmrTbl, inParams, pathXltr.subReq.tblKeyCache)
	if tblXfmrErr != nil {
		log.Error("handleTableXfmrCallback: table transformer callback returns error: ", tblXfmrErr)
		log.Info("handleTableXfmrCallback: table transformer callback: ", *ygXpathInfo.xfmrTbl)
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

	reqXlator.xlateNodeType = CHILD_NODE

	rltvUriPath := ""
	trgtXpathNode := &(ygXpathNode{relUriPath: &rltvUriPath, ygXpathInfo: ygXpathInfo})
	if err = reqXlator.collectChldYgXPathInfo(ygNode, reqXlator.subReq.ygPath, &rltvUriPath, ygXpathInfo, trgtXpathNode); err != nil {
		log.Info("Error in collectChldYgXPathInfo; error: ", err)
		return err
	}

	var dbKey *db.Key
	if len(reqXlator.subReqXlateInfo.TrgtPathInfo.DbKeyXlateInfo) > 0 {
		dbKey = reqXlator.subReqXlateInfo.TrgtPathInfo.DbKeyXlateInfo[0].Key
	}
	if err = reqXlator.traverseYgXpathAndTranslate(trgtXpathNode, dbKey); err != nil {
		log.Info("Error in traverseYgXpathAndTranslate; error: ", err)
	}
	return err
}

func (reqXlator *subscribeReqXlator) traverseYgXpathAndTranslate(ygXpNode *ygXpathNode, parentListDbKey *db.Key) (error) {
	var err error
	for _, chldNode := range ygXpNode.chldNodes {
		log.Info("next child node relPath Path: ", *chldNode.relUriPath)
		log.Info("next child node xpathObj: ", chldNode.ygXpathInfo)
		var gPathCurr *gnmipb.Path
		if gPathCurr, err = reqXlator.uriToAbsolutePath(chldNode.relUriPath); err != nil {
			return err
		}

		uriPath := *reqXlator.subReq.reqUri + *chldNode.relUriPath
		log.Info("next child node URI Path: ", uriPath)

		pathXlator, err := reqXlator.getSubscribePathXlator(gPathCurr, &uriPath, chldNode.ygXpathInfo)
		if err != nil {
			log.Info("traverseYgXpathAndTranslate: Error in getSubscribePathXlator: ", err)
		}

		if err = pathXlator.translatePath(); err != nil {
			log.Info("traverseYgXpathAndTranslate: Error in translate(): ", err)
			return err
		}

		dbKey := parentListDbKey
		pathXlateInfo := pathXlator.pathXlateInfo
		if chldNode.ygXpathInfo.yangEntry.IsList() && len(pathXlateInfo.DbKeyXlateInfo) > 0 {
			dbKey = pathXlator.pathXlateInfo.DbKeyXlateInfo[0].Key
		} else {
			for _, dbKeyInfo := range pathXlateInfo.DbKeyXlateInfo {
				if dbKeyInfo.Key == nil {
					// assigning the list node db key to its child container table key
					dbKeyInfo.Key = dbKey
				}
			}
		}
		reqXlator.subReqXlateInfo.ChldPathsInfo = append(reqXlator.subReqXlateInfo.ChldPathsInfo, pathXlateInfo)
		if err = reqXlator.traverseYgXpathAndTranslate(chldNode, dbKey); err != nil {
			return err
		}
	}
	return err
}

func (reqXlator *subscribeReqXlator) debugTrvsalCtxt(ygEntry *yang.Entry, ygPath *string, rltvUriPath *string, ygXpathInfo *yangXpathInfo) {
	log.Info("debugTrvsalCtxt ygPath: ", *ygPath)
	log.Info("debugTrvsalCtxt rltvUriPath: ", *rltvUriPath)
	log.Info("debugTrvsalCtxt ygXpathInfo: ", ygXpathInfo)
	log.Info("debugTrvsalCtxt ygEntry: ", ygEntry)
}

type ygXpathNode struct {
	relUriPath  *string
	ygXpathInfo *yangXpathInfo
	chldNodes   []*ygXpathNode
}

func (ygXpNode *ygXpathNode) addChildNode(rltUri *string, ygXpathInfo *yangXpathInfo) (*ygXpathNode) {
	chldNode := ygXpathNode{relUriPath: rltUri, ygXpathInfo: ygXpathInfo}
	ygXpNode.chldNodes = append(ygXpNode.chldNodes, &chldNode)
	return &chldNode
}

func (reqXlator *subscribeReqXlator) collectChldYgXPathInfo(ygEntry *yang.Entry, ygPath *string,
rltvUriPath *string, ygXpathInfo *yangXpathInfo, ygXpNode *ygXpathNode) (error) {

	log.Info("Entering into the collectChldYgXPathInfo..")

	reqXlator.debugTrvsalCtxt(ygEntry, ygPath, rltvUriPath, ygXpathInfo)

	for _, childYgEntry := range ygEntry.Dir {
		log.Info("collectChldYgXPathInfo: node name:", childYgEntry.Name)
		childYgPath := *ygPath + "/" + childYgEntry.Name
		log.Info("collectChldYgXPathInfo: childYgPath:", childYgPath)

		if chYgXpathInfo, ok := xYangSpecMap[childYgPath]; ok {
			rltvChldUriPath := *rltvUriPath
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

			if (childYgEntry.IsLeaf() || childYgEntry.IsLeafList()) && tblName != "" {
				log.Info("adding table name %v for the leaf node for the path %v ", tblName, childYgPath)
				ygXpNode.addChildNode(&rltvChldUriPath, chYgXpathInfo)
			} else if (childYgEntry.IsList() || childYgEntry.IsContainer()) {
				chldNode := ygXpNode
				if len(chYgXpathInfo.xfmrFunc) > 0 {
					log.Info("adding subtree xfmr func %v for the path %v ", chYgXpathInfo.xfmrFunc, childYgPath)
					chldNode = ygXpNode.addChildNode(&rltvChldUriPath, chYgXpathInfo)
				} else if tblName != "" {
					log.Info("adding table name %v for the path %v ", tblName, childYgPath)
					chldNode = ygXpNode.addChildNode(&rltvChldUriPath, chYgXpathInfo)
				} else if (chYgXpathInfo.xfmrTbl != nil) {
					log.Info("adding table transformer %v for the path %v ", *chYgXpathInfo.xfmrTbl, childYgPath)
					chldNode = ygXpNode.addChildNode(&rltvChldUriPath, chYgXpathInfo)
				}
				if childYgEntry.IsList() {
					log.Warning("No table related information for the LIST yang node path: ", childYgPath)
				}
				if err := reqXlator.collectChldYgXPathInfo(childYgEntry, &childYgPath, &rltvChldUriPath, chYgXpathInfo, chldNode); err != nil {
					return err
				}
			}
		} else if childYgEntry.IsList() || childYgEntry.IsContainer() {
			log.Error("No yangXpathInfo found for the LIST / Container yang node path: ", childYgPath)
			return tlerr.InternalError{Format: "No yangXpathInfo found for the LIST / Container yang node path", Path: childYgPath}
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

func (reqXlator *subscribeReqXlator) uriToAbsolutePath(rltvUri *string) (*gnmipb.Path, error) {
	log.Info("Entering into uriToAbsolutePath: rltvUri: ", *rltvUri)
	if gRelPath, err := ygot.StringToPath(*rltvUri, ygot.StructuredPath, ygot.StringSlicePath); err != nil {
		log.Error("Error in converting the URI into GNMI path for the URI: ", *rltvUri)
		return nil, tlerr.InternalError{Format: "Error in converting the URI into GNMI path", Path: *rltvUri}
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