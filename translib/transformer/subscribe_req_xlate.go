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
	pathXlator      *subscribePathXlator
}

type subscribeReq struct {
	reqLogId             string
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
	subReqXlateInfo *XfmrSubscribeReqXlateInfo
}

type subscribePathXlator struct {
	gPath           *gnmipb.Path
	pathXlateInfo   *XfmrSubscribePathXlateInfo
	ygTrgtXpathInfo *yangXpathInfo
	uriPath         string
	subReq          *subscribeReq
	parentXlateInfo *XfmrSubscribePathXlateInfo
	xpathYgNode     *ygXpathNode
}

//TODO: log level will be changed to 5 later
var dbLgLvl log.Level = 2 // debug log level

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
	IsPartial      bool // db entry has only partial value of the path (eg: leaf-list mapped to a table)
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
	OnChange       OnchangeMode
	TrgtNodeChld   bool // to indicate the immediate child level pathXlate info of the target node
	reqLogId       string
}

type XfmrSubscribeReqXlateInfo struct {
	TrgtPathInfo  *XfmrSubscribePathXlateInfo
	ChldPathsInfo []*XfmrSubscribePathXlateInfo
	ygXpathTrgtList *yangXpathInfo
}

func (reqXlator *subscribeReqXlator) getSubscribePathXlator(gPath *gnmipb.Path, uriPath string, ygXpathInfo *yangXpathInfo,
parentXlateInfo *XfmrSubscribePathXlateInfo, xpathYgNode *ygXpathNode) (*subscribePathXlator, error) {
	var err error
	reqXlator.pathXlator.gPath = gPath
	reqXlator.pathXlator.pathXlateInfo = &(XfmrSubscribePathXlateInfo{Path: gPath, ygXpathInfo: ygXpathInfo, reqLogId: reqXlator.subReq.reqLogId})
	reqXlator.pathXlator.uriPath = uriPath
	reqXlator.pathXlator.ygTrgtXpathInfo = ygXpathInfo
	reqXlator.pathXlator.parentXlateInfo = parentXlateInfo
	reqXlator.pathXlator.xpathYgNode = xpathYgNode
	if reqXlator.subReq.xlateNodeType == TARGET_NODE {
		if err = reqXlator.pathXlator.setTrgtYgXpathInfo(); err != nil {
			log.Error(reqXlator.subReq.reqLogId+"Error in setting the YgXpathInfo of the last LIST node in the path and the error is :", err)
			return nil, err
		}
	}
	return reqXlator.pathXlator, err
}

func (pathXltr *subscribePathXlator) setTrgtYgXpathInfo() (error) {
	log.Info("Entering into the setTrgtListYgXpathInfo: ygPath: ", pathXltr.subReq.ygPath)

	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	ygPathTmp := pathXltr.subReq.ygPath

	for ygXpathInfo != nil && len(ygXpathInfo.xfmrKey) == 0 {
		tIdx := strings.LastIndex(ygPathTmp, "/")
		// -1: not found, and 0: first character in the path
		if tIdx > 0 {
			ygPathTmp = ygPathTmp[0:tIdx]
		} else {
			break
		}
		if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"xPathTmp: ", ygPathTmp) }
		if ygXpathInfoTmp, ok := xYangSpecMap[ygPathTmp]; !ok || ygXpathInfoTmp == nil {
			log.Error(pathXltr.subReq.reqLogId+"xYangSpecMap does not have the yangXpathInfo for the path:", ygPathTmp)
			return tlerr.InternalError{Format: "xYangSpecMap does not have the yangXpathInfo", Path: ygPathTmp}
		} else if ygXpathInfo.yangEntry == nil {
			log.Error(pathXltr.subReq.reqLogId+"yangXpathInfo has nil value for its yangEntry field for the path:", ygPathTmp)
			return tlerr.InternalError{Format: "yangXpathInfo has nil value for its yangEntry field", Path: ygPathTmp}
		} else {
			ygXpathInfo = ygXpathInfoTmp
		}
	}
	if ygXpathInfo != nil {
		pathXltr.ygTrgtXpathInfo = ygXpathInfo
	}
	return nil
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) addPathXlateInfo(tblSpec *db.TableSpec, dbKey *db.Key, dBNum db.DBNum) (*dbTableKeyInfo) {
	dbTblIfo := dbTableKeyInfo{Table: tblSpec, Key: dbKey, DbNum: dBNum}
	pathXlateInfo.DbKeyXlateInfo = append(pathXlateInfo.DbKeyXlateInfo, &dbTblIfo)
	return &dbTblIfo
}

func GetSubscribeReqXlator(subReqId interface{}, reqUri string, isOnchange bool, dbs [db.MaxDB]*db.DB, txCache interface{}) (*subscribeReqXlator, error) {
	reqIdLogStr := "subReq Id:["+fmt.Sprintf("%v",subReqId)+"] : "
	log.Infof(reqIdLogStr + "GetSubscribeReqXlator: for the reqUri: %v; isOnchange: %v; txCache: %v", reqUri, isOnchange, txCache)
	subReq := subscribeReq{reqLogId: reqIdLogStr, reqUri: reqUri, dbs:dbs, txCache: txCache, isTrgtPathWldcrd: true}
	subReq.tblKeyCache = make(map[string]tblKeyCache)
	subReq.isOnchange = isOnchange
	subReq.xlateNodeType = TARGET_NODE
	subReq.chldNodeMaxMinIntrvl = 0
	var err error

	if subReq.ygPath, _, err = XfmrRemoveXPATHPredicates(reqUri); err != nil {
		log.Error(subReq.reqLogId + "Got error from the XfmrRemoveXPATHPredicates function: ", err)
		return nil, err
	}

	if subReq.gPath, err = ygot.StringToPath(reqUri, ygot.StructuredPath, ygot.StringSlicePath); err != nil {
		log.Error(subReq.reqLogId + "Error in converting the URI into GNMI path for the URI: ", reqUri)
		return nil, tlerr.InternalError{Format: "Error in converting the URI into GNMI path", Path: reqUri}
	}

	subReqXlator := subscribeReqXlator{subReq: &subReq}
	subReqXlator.subReq.subReqXlateInfo = new(XfmrSubscribeReqXlateInfo)
	subReqXlator.pathXlator = &subscribePathXlator{subReq: &subReq}
	return &subReqXlator, nil
}

func (reqXlator *subscribeReqXlator) processSubscribePath () (error) {
	log.Info(reqXlator.subReq.reqLogId+"processSubscribePath: path: ", reqXlator.subReq.reqUri)
	pathElems := reqXlator.subReq.gPath.Elem
	pathIdx := len(pathElems) - 1
	ygXpathInfoTmp := reqXlator.subReq.subReqXlateInfo.ygXpathTrgtList
	ygPathTmp := reqXlator.subReq.ygPath
	for {
		if ygXpathInfoTmp.yangEntry.Parent != nil && ygXpathInfoTmp.nameWithMod != nil {
			if log.V(dbLgLvl) { log.Infof("parent node name space: %v and curr. node name space: %v", ygXpathInfoTmp.yangEntry.Parent.Namespace().Name,
				ygXpathInfoTmp.yangEntry.Namespace().Name) }
			if (strings.HasSuffix(*ygXpathInfoTmp.nameWithMod, ":"+pathElems[pathIdx].Name) &&
				ygXpathInfoTmp.yangEntry.Parent.Namespace().Name != ygXpathInfoTmp.yangEntry.Namespace().Name) {
				log.Infof(reqXlator.subReq.reqLogId+"module prefix is missing in the path: adding the same: mod prefix: %v, " +
					"input path name: %v", *ygXpathInfoTmp.nameWithMod, pathElems[pathIdx].Name)
				pathElems[pathIdx].Name = *ygXpathInfoTmp.nameWithMod
			}
		}

		if ygXpathInfoTmp.yangEntry.IsList() && len(pathElems[pathIdx].Key) == 0 {
			for _, listKey := range strings.Fields(ygXpathInfoTmp.yangEntry.Key) {
				pathElems[pathIdx].Key[listKey] = "*"
			}
			if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"processSubscribePath: list node doesn not have keys in the input path;" +
				" added wildcard to the list node path: ", reqXlator.subReq.ygPath) }
		} else if reqXlator.subReq.isTrgtPathWldcrd {
			for _, kv := range pathElems[pathIdx].Key {
				if kv == "*" { continue }
				reqXlator.subReq.isTrgtPathWldcrd = false
			}
		}

		tIdx := strings.LastIndex(ygPathTmp, "/")
		if tIdx > 0 {
			ygPathTmp = ygPathTmp[0:tIdx]
			pathIdx--
			if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"processSubscribePath: xPathTmp: ", ygPathTmp) }
			var ok bool
			if ygXpathInfoTmp, ok = xYangSpecMap[ygPathTmp]; !ok || ygXpathInfoTmp == nil || ygXpathInfoTmp.yangEntry == nil {
				log.Error(reqXlator.subReq.reqLogId+"processSubscribePath: xYangSpecMap does not have the yangXpathInfo for the path:", ygPathTmp)
				return tlerr.InternalError{Format: "xYangSpecMap does not have the yangXpathInfo", Path: ygPathTmp}
			}
		} else {
			break
		}
	}
	return nil
}

func (reqXlator *subscribeReqXlator) Translate() (error) {
	var err error
	if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"Translate: reqXlator: ", *reqXlator.subReq) }

	ygXpathInfoTrgt, ok := xYangSpecMap[reqXlator.subReq.ygPath]

	if !ok || ygXpathInfoTrgt == nil {
		log.Errorf(reqXlator.subReq.reqLogId+"Translate: ygXpathInfo data not found in the xYangSpecMap for xpath : %v", reqXlator.subReq.ygPath)
		return tlerr.InternalError{Format: "Error in processing the subscribe path", Path: reqXlator.subReq.reqUri}
	} else if ygXpathInfoTrgt.yangEntry == nil {
		log.Errorf(reqXlator.subReq.reqLogId+"Translate: yangEntry is nil in the ygXpathInfo for the path: %v", reqXlator.subReq.ygPath)
		return tlerr.NotSupportedError{Format: "Subscribe not supported", Path: reqXlator.subReq.reqUri}
	} else {
		reqXlator.subReq.subReqXlateInfo.ygXpathTrgtList = ygXpathInfoTrgt
		reqXlator.processSubscribePath()
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
		log.Errorf(reqXlator.subReq.reqLogId+"Subscribe not supported; on change disabled for the given subscribe path:: %v", reqXlator.subReq.reqUri)
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
				reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.MinInterval = ygXpathInfoTrgt.subscribeMinIntvl
				reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.PType = Sample
				reqXlator.subReq.isOnchange = false
			} else {
				reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.PType = OnChange
				reqXlator.subReq.isOnchange = true
			}
		} else if !reqXlator.subReq.isTrgtDfnd {
			reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.OnChange = OnchangeEnable
		}

		if err = reqXlator.translateChildNodePaths(ygXpathInfoTrgt); err != nil {
			log.Errorf(reqXlator.subReq.reqLogId+"Error in translating the child node for the subscribe path: %v", err)
			return err
		}

		if !reqXlator.subReq.isOnchange {
			// sampling
			if reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.MinInterval < reqXlator.subReq.chldNodeMaxMinIntrvl {
				reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.MinInterval = reqXlator.subReq.chldNodeMaxMinIntrvl
			}
		}

	} else {
		log.Errorf(reqXlator.subReq.reqLogId+"Error in translating the target node subscribe path: %v", err)
	}

	return err
}

func (reqXlator *subscribeReqXlator) translateTargetNodePath(trgtYgxPath *yangXpathInfo) (error) {
	if trgtPathXlator, err := reqXlator.getSubscribePathXlator(reqXlator.subReq.gPath, reqXlator.subReq.reqUri, trgtYgxPath, nil, nil); err != nil {
		log.Error(reqXlator.subReq.reqLogId+"Error in getSubscribePathXlator: error: ", err)
		return err
	} else {
		if err = trgtPathXlator.translatePath(); err != nil {
			log.Error(reqXlator.subReq.reqLogId+"Error: in translateTargetNodePath: error: ", err)
			return err
		}
		reqXlator.subReq.subReqXlateInfo.TrgtPathInfo = trgtPathXlator.pathXlateInfo
	}
	return nil
}

func (pathXltr *subscribePathXlator) handleSubtreeNodeXlate() (error) {
	log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: reqUri: ", pathXltr.uriPath)

	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo

	uriSubtree := pathXltr.uriPath

	if ygXpathInfo.yangEntry.IsLeaf() || ygXpathInfo.yangEntry.IsLeafList() {
		idxS := strings.LastIndex(uriSubtree, "/")
		uriSubtree = uriSubtree[:idxS]
		if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: trimmed uriSubtree: ", uriSubtree) }
	}

	if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: handleSubtreeNodeXlate: uriSubtree: ", uriSubtree) }

	subInParam := XfmrSubscInParams{uriSubtree, pathXltr.subReq.dbs, make(RedisDbMap), TRANSLATE_SUBSCRIBE}
	subOutPram, subErr := xfmrSubscSubtreeHandler(subInParam, ygXpathInfo.xfmrFunc)

	if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: subOutPram:  ", subOutPram) }
	if subErr != nil {
		log.Error(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: Got error form the Subscribe transformer callback ", subErr)
		return subErr
	}

	var ntfType NotificationType

	if ygXpathInfo.subscribePref != nil && *ygXpathInfo.subscribePref == "onchange" {
		ntfType = OnChange
	}

	if subOutPram.nOpts != nil {
		ntfType = NotificationType(subOutPram.nOpts.pType)
	}

	if !subOutPram.isVirtualTbl &&
		(subOutPram.onChange == OnchangeDisable || (pathXltr.subReq.isTrgtDfnd && ntfType != OnChange))  {
		log.Error(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: Onchange subscription is not supported; onChange flag set to" +
			" false in the XfmrSubscOutParams for the Subscribe transformer callback: ", ygXpathInfo.xfmrFunc)
		return tlerr.InternalError{Format: "Onchange subscription is not supported; onChange flag set to false in the" +
			" XfmrSubscOutParams for the Subscribe transformer callback", Path: pathXltr.uriPath}
	} else {
		if subOutPram.onChange == OnchangeDefault {
			if pathXltr.pathXlateInfo.ygXpathInfo.subscribeOnChg != XFMR_DISABLE {
				pathXltr.pathXlateInfo.OnChange = OnchangeEnable
			} else {
				pathXltr.pathXlateInfo.OnChange = OnchangeDisable
			}
		} else if subOutPram.onChange == OnchangeEnable {
			pathXltr.pathXlateInfo.OnChange = OnchangeEnable
		}

		if pathXltr.subReq.isTrgtDfnd {
			pathXltr.pathXlateInfo.PType = ntfType
		}
	}

	if pathXltr.subReq.isOnchange || pathXltr.subReq.xlateNodeType == TARGET_NODE || !subOutPram.isVirtualTbl {
		isTrgtNodeLeaf := (ygXpathInfo.yangEntry.IsLeaf() || ygXpathInfo.yangEntry.IsLeafList())
		isLeafTblFound := false
		ygLeafNodeSecDbMap := make (map[string]bool) // yang leaf/leaf-list node name as key
		for dbNum, tblKeyInfo := range subOutPram.secDbDataMap {
			if isLeafTblFound { break } // do not process any more entry if the target node is leaf and it is processed
			if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: secDbDataMap: dbNum: ", dbNum) }
			for tblName, tblFieldInfo := range tblKeyInfo {
				if isLeafTblFound { break } // do not process any more entry if the target node is leaf and it is processed
				if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: secDbDataMap: tblName: ", tblName) }
				tblSpec := &db.TableSpec{Name: tblName}
				for dBKey, nodeIntf := range tblFieldInfo {
					if isLeafTblFound { break } // do not process any more entry if the target node is leaf and it is processed
					dbFldYgNameMap := make(map[string]string) // map of yang leaf/leaf-list name as key and db table field name as value
					switch intfVal := nodeIntf.(type) {
						case string:
							// yang leaf/leaf-list node mapped to db table key, not db table field
							// because of this, the db field is empty, and keeping yang name as db field name in this map.
							dbFldYgNameMap[intfVal] = intfVal
						case map[string]string:
							dbFldYgNameMap = intfVal
						default:
							log.Errorf(pathXltr.subReq.reqLogId+"Error: Onchange subscription: handleSubtreeNodeXlate: Incorrect type recieved from the Subscribe " +
								"transformer callback: %v and the type is %v ", ygXpathInfo.xfmrFunc, intfVal)
							return tlerr.InternalError{Format: "Onchange subscription: Incorrect type recieved from the Subscribe transformer callback", Path: pathXltr.uriPath}
					}
					ygLeafNodePathPrefix := pathXltr.subReq.ygPath // default target node path
					if pathXltr.xpathYgNode != nil { ygLeafNodePathPrefix = pathXltr.xpathYgNode.ygPath }

					keyComp := strings.Split(dBKey, pathXltr.subReq.dbs[dbNum].Opts.KeySeparator)
					if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: secDbDataMap: keyComp: ", keyComp) }

					for dbField, yangNodeName := range dbFldYgNameMap {
						if isLeafTblFound { break } // do not process any more entry if the target node is leaf and it is processed
						ygLeafNodePath := ygLeafNodePathPrefix
						if isTrgtNodeLeaf {
							if yangNodeName != ygXpathInfo.yangEntry.Name { continue }
							isLeafTblFound = true // only if the subscribe path target is leaf/leaf-list
						} else {
							ygLeafNodePath = ygLeafNodePathPrefix + "/" + yangNodeName
						}

						if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: ygLeafNodePath: ", ygLeafNodePath) }
						yangNodeNameWithMod := yangNodeName

						var ygLeafXpathInfo *yangXpathInfo
						var okLeaf bool

						if ygLeafXpathInfo, okLeaf = xYangSpecMap[ygLeafNodePath]; okLeaf && ygLeafXpathInfo.nameWithMod != nil {
							yangNodeNameWithMod = *(ygLeafXpathInfo.nameWithMod)
						} else if ygLeafXpathInfo == nil {
							log.Error(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: XpathInfo not found for the leaf path: ", ygLeafNodePath)
							return tlerr.InternalError{Format: "XpathInfo not found for the leaf path", Path: ygLeafNodePath}
						}

						if log.V(dbLgLvl) { log.Infof(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: secDbDataMap: uripath: %v; " +
							"KeySeparator: %v ", pathXltr.uriPath + "/" + yangNodeNameWithMod, pathXltr.subReq.dbs[dbNum].Opts.KeySeparator) }

						if leafPath, err := ygot.StringToPath(pathXltr.uriPath + "/" + yangNodeNameWithMod, ygot.StructuredPath, ygot.StringSlicePath); err != nil {
							log.Error(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: error in StringToPath: err: ", err)
							return err
						} else {
							if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate:secDbDataMap: leafPath", leafPath) }
							ygLeafNodeSecDbMap[yangNodeName] = true
							if isLeafTblFound { // target node
								if pathXltr.subReq.isTrgtDfnd {
									pathXltr.pathXlateInfo.PType = ntfType
								}
								dbTblInfo := pathXltr.pathXlateInfo.addPathXlateInfo(tblSpec, &db.Key{keyComp}, dbNum)
								if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate:secDbDataMap: path is leaf / leaf-list", pathXltr.uriPath) }
								dbYgPath := DbFldYgPathInfo{"", make(map[string]string)}
								dbYgPath.DbFldYgPathMap[dbField] = ""
								dbTblInfo.DbFldYgMapList = append(dbTblInfo.DbFldYgMapList, &dbYgPath)
								if ygXpathInfo.yangEntry.IsLeafList() {
									dbTblInfo.IsPartial = true
								}
								if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: secDbDataMap: target node: leaf: " +
									"Adding special entry for leaf node mapped to table for the uri path: ", pathXltr.uriPath + "/" + yangNodeNameWithMod) }
							} else {
								leafPathXlateInfo := &XfmrSubscribePathXlateInfo {Path: leafPath, PType: ntfType, OnChange: pathXltr.pathXlateInfo.OnChange}
								dbTblInfo := leafPathXlateInfo.addPathXlateInfo(tblSpec, &db.Key{keyComp}, dbNum)
								if ygLeafXpathInfo.yangEntry != nil && ygLeafXpathInfo.yangEntry.IsLeafList() {
									dbTblInfo.IsPartial = true
								}
								if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate:secDbDataMap: mapped to leaf / leaf-list", pathXltr.uriPath) }
								dbYgPath := DbFldYgPathInfo{"", make(map[string]string)}
								dbYgPath.DbFldYgPathMap[dbField] = ""
								dbTblInfo.DbFldYgMapList = append(dbTblInfo.DbFldYgMapList, &dbYgPath)
								if pathXltr.subReq.isTrgtDfnd { leafPathXlateInfo.PType = ntfType }
								if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: secDbDataMap: target node: container: " +
									"Adding special entry for leaf node mapped to table for the uri path: ", pathXltr.uriPath + "/" + yangNodeNameWithMod) }
								pathXltr.subReq.subReqXlateInfo.ChldPathsInfo = append(pathXltr.subReq.subReqXlateInfo.ChldPathsInfo, leafPathXlateInfo)
							}
						}
					}
				}
			}
		}

		if !isLeafTblFound {
			for dbNum, tblKeyInfo := range subOutPram.dbDataMap {
				if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate:  dbNum: ", dbNum) }
				for tblName, tblFieldInfo := range tblKeyInfo {
					if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: tblName: ", tblName) }
					tblSpec := &db.TableSpec{Name: tblName}
					for dBKey, tblFld := range tblFieldInfo {
						if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: pathXltr.subReq.dbs[dbNum].Opts.KeySeparator: ", pathXltr.subReq.dbs[dbNum].Opts.KeySeparator) }
						keyComp := strings.Split(dBKey, pathXltr.subReq.dbs[dbNum].Opts.KeySeparator)
						if log.V(dbLgLvl) { log.Infof(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: keyComp: %v ; tblFld %v", keyComp, tblFld) }
						dbTblInfo := pathXltr.pathXlateInfo.addPathXlateInfo(tblSpec, &db.Key{keyComp}, dbNum)
						dbYgPath := DbFldYgPathInfo {"", make(map[string]string)}
						yangNodes := make(map[string]bool)
						// copy the leaf nodes form the secDbMap to skip those.
						for ygNameSecDbMap := range ygLeafNodeSecDbMap { yangNodes[ygNameSecDbMap] =  true }
						for dbFld, ygNodeName := range tblFld {
							if !isTrgtNodeLeaf {
								dbYgPath.DbFldYgPathMap[dbFld] = ygNodeName
								yangNodes[ygNodeName] = true
							} else if ygNodeName == ygXpathInfo.yangEntry.Name {  // for the target node - leaf / leaf-list
								if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate:dbDataMap: path is leaf / leaf-list", pathXltr.uriPath) }
								dbYgPath.DbFldYgPathMap[dbFld] = ""
								dbTblInfo.DbFldYgMapList = append(dbTblInfo.DbFldYgMapList, &dbYgPath)
								yangNodes[ygNodeName] = true
								break
							}
						}
						// to add the db field which are same as yang leaf/leaf-list nodes
						if !isTrgtNodeLeaf {
							for ygNodeName, ygLeafEntry := range ygXpathInfo.yangEntry.Dir {
								if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: traversing yang node: ", ygNodeName) }
								if !(yangNodes[ygNodeName]) && (ygLeafEntry.IsLeaf() || ygLeafEntry.IsLeafList()) {
									if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: adding default leaf node: ", ygNodeName) }
									dbYgPath.DbFldYgPathMap[ygNodeName] = ygNodeName
								}
							}
							dbTblInfo.DbFldYgMapList = append(dbTblInfo.DbFldYgMapList, &dbYgPath)
							if log.V(dbLgLvl) { log.Infof(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate:Db field and yang node mapping: " +
								"dbYgPath: %v and for the ygpath: %v", dbYgPath, pathXltr.uriPath) }
							if pathXltr.xpathYgNode != nil {
								// only one db key entry per table for the given subscribe path, so dbTblFldYgPathMap or dbFldYgPathMap won't get overridden
								if len(subOutPram.dbDataMap) > 1 {
									pathXltr.xpathYgNode.dbTblFldYgPathMap[tblName] = dbYgPath.DbFldYgPathMap
								} else {
									pathXltr.xpathYgNode.dbFldYgPathMap = dbYgPath.DbFldYgPathMap
								}
							}
						} else if !(yangNodes[ygXpathInfo.yangEntry.Name]) { // for the target node - leaf / leaf-list
							if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleSubtreeNodeXlate: target: LEAF: adding default leaf node: ", ygXpathInfo.yangEntry.Name) }
							dbYgPath.DbFldYgPathMap[ygXpathInfo.yangEntry.Name] = ""
							dbTblInfo.DbFldYgMapList = append(dbTblInfo.DbFldYgMapList, &dbYgPath)
						}
					}
				}
			}
		}
	} else if pathXltr.pathXlateInfo.OnChange == OnchangeDisable && (subOutPram.nOpts != nil && pathXltr.subReq.chldNodeMaxMinIntrvl < subOutPram.nOpts.mInterval) {
		pathXltr.subReq.chldNodeMaxMinIntrvl = subOutPram.nOpts.mInterval
	}

	return nil
}

func (pathXltr *subscribePathXlator) addDbFldYangMapInfo() (error) {
	if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"subscribePathXlator: addDbFldYangMapInfo: target subscribe path is leaf/leaf-list node: ", pathXltr.uriPath) }
	fieldName := pathXltr.getDbFieldName()
	if len(pathXltr.pathXlateInfo.ygXpathInfo.compositeFields) > 0 {
		if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"subscribePathXlator: addDbFldYangMapInfo: adding composite db field names in the dbFldYgPath map: ", pathXltr.pathXlateInfo.ygXpathInfo.compositeFields) }
		for _, dbTblFldName := range pathXltr.pathXlateInfo.ygXpathInfo.compositeFields {
			tblField := strings.Split(dbTblFldName, ":")
			if len(tblField) > 1 {
				tblName := strings.TrimSpace(tblField[0])
				var dbKeyInfo *dbTableKeyInfo
				for _, dbKeyInfo = range pathXltr.pathXlateInfo.DbKeyXlateInfo {
					if dbKeyInfo.Table.Name == tblName {
						dbFldYgPath := DbFldYgPathInfo{DbFldYgPathMap: make(map[string]string)}
						dbFldYgPath.DbFldYgPathMap[strings.TrimSpace(tblField[1])] = ""
						dbKeyInfo.DbFldYgMapList = append(dbKeyInfo.DbFldYgMapList, &dbFldYgPath)
						if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"subscribePathXlator: addDbFldYangMapInfo: target subscribe leaf/leaf-list path dbygpathmap list for composite field names: ", dbKeyInfo.DbFldYgMapList) }
						break
					}
				}
				if len(dbKeyInfo.DbFldYgMapList) == 0 {
					log.Errorf(pathXltr.subReq.reqLogId+"subscribePathXlator: addDbFldYangMapInfo: Table name %v is not mapped to this path:", tblName, pathXltr.uriPath)
					intfStrArr := []interface{}{tblName}
					return tlerr.InternalError{Format: "Table name %v is not mapped for the leaf node path", Path: pathXltr.uriPath, Args: intfStrArr}
				}
			} else {
				log.Error(pathXltr.subReq.reqLogId+"subscribePathXlator: addDbFldYangMapInfo: Table name is missing in the composite-db-fields annoation for the leaf node path:", pathXltr.uriPath)
				return tlerr.InternalError{Format: "Table name is missing in the composite-db-fields annoation for the leaf node path", Path: pathXltr.uriPath}
			}
		}
	} else if len(fieldName) > 0 {
		if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"subscribePathXlator: addDbFldYangMapInfo: adding db field name in the dbFldYgPath map: ", fieldName) }
		dbFldYgPath := DbFldYgPathInfo{DbFldYgPathMap: make(map[string]string)}
		dbFldYgPath.DbFldYgPathMap[fieldName] = ""
		for _, dbKeyInfo := range pathXltr.pathXlateInfo.DbKeyXlateInfo {
			dbKeyInfo.DbFldYgMapList = append(dbKeyInfo.DbFldYgMapList, &dbFldYgPath)
			if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"subscribePathXlator: addDbFldYangMapInfo: target subscribe leaf/leaf-list path dbygpathmap list: ", dbKeyInfo.DbFldYgMapList) }
		}
	}

	return nil
}

func (pathXltr *subscribePathXlator) translatePath() (error) {
	ygXpathInfoTrgt := pathXltr.pathXlateInfo.ygXpathInfo

	log.Infof(pathXltr.subReq.reqLogId+"translatePath: path: %v; ygXpathInfoTrgt: %v", pathXltr.uriPath, ygXpathInfoTrgt)

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
	log.Infof(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr.. pathXltr.uriPath: %v; " +
		"isTrgtPathWldcrd: %v", pathXltr.uriPath, pathXltr.subReq.isTrgtPathWldcrd)

	if pathXltr.ygTrgtXpathInfo == nil {
		log.Error(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: yangXpathInfo is nil in the xYangSpecMap for the path: ", pathXltr.uriPath)
		return "", tlerr.InternalError {Format: pathXltr.subReq.reqLogId+"yangXpathInfo is nil in the xYangSpecMap for the path", Path: pathXltr.uriPath}
	}

	if len(pathXltr.ygTrgtXpathInfo.xfmrKey) > 0 {
		ygXpathInfo := pathXltr.ygTrgtXpathInfo
		log.Info(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: key transformer name:", ygXpathInfo.xfmrKey)

		ygotRoot, err := pathXltr.unMarshallYgotObj(pathXltr.pathXlateInfo.Path)
		if err != nil {
			log.Error(pathXltr.subReq.reqLogId+"Error: unMarshallYgotObj error: ", err)
			return "", err
		}

		currDbNum := db.DBNum(ygXpathInfo.dbIndex)
		inParams := formXfmrInputRequest(pathXltr.subReq.dbs[ygXpathInfo.dbIndex], pathXltr.subReq.dbs, currDbNum, ygotRoot, pathXltr.uriPath,
			pathXltr.subReq.reqUri, SUBSCRIBE, "", nil, nil, nil, pathXltr.subReq.txCache)
		if dBTblKey, errKey := keyXfmrHandler(inParams, ygXpathInfo.xfmrKey); errKey == nil {
			log.Infof(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: key transformer: %v; dBTblKey: %v", ygXpathInfo.xfmrKey, dBTblKey)
			return dBTblKey, nil
		} else {
			log.Error(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: keyXfmrHandler callback error:", errKey)
			return dBTblKey, errKey
		}
	} else {
		log.Infof(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: default db key translation uri path: %v; " +
			"ygListXpathInfo.dbIndex: %v ", pathXltr.uriPath, pathXltr.ygTrgtXpathInfo.dbIndex)

		dbKey := "*"
		isKeyEmpty := true

		keyDelm := pathXltr.subReq.dbs[pathXltr.ygTrgtXpathInfo.dbIndex].Opts.KeySeparator
		log.Info(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: keyDelm: ", keyDelm)

		pathElems := pathXltr.gPath.Elem
		ygPath := "/"+pathElems[0].Name

		for idx := 1; idx < len(pathElems); idx++ {
			ygNames := strings.Split(pathElems[idx].Name, ":")
			if len(ygNames) == 1 {
				ygPath = ygPath + "/" + ygNames[0]
			} else {
				ygPath = ygPath + "/" + ygNames[1]
			}
			log.Info(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: ygPath: ", ygPath)
			if len(pathElems[idx].Key) > 0 {
				if ygXpathInfo, ok := xYangSpecMap[ygPath]; ok {
					if ygXpathInfo.virtualTbl == nil || !(*ygXpathInfo.virtualTbl) {
						for _, kv := range pathElems[idx].Key {
							if isKeyEmpty { dbKey = kv; isKeyEmpty = false; continue }
							dbKey = dbKey + keyDelm + kv
						}
					}
				} else {
					log.Warning(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: xpathinfo not found for the ygpath: ", ygPath)
				}
			}
		}
		log.Info(pathXltr.subReq.reqLogId+"handleYangToDbKeyXfmr: default translation: dbKey: ", dbKey)
		return dbKey, nil
	}
}

func (pathXltr *subscribePathXlator) handleNonSubtreeNodeXlate() (error) {
	log.Info(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: uriPath: ", pathXltr.uriPath)
	var keyComp []string
	tblNameMap := make(map[string]bool)

	ygXpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	if pTblName := pathXltr.getXpathInfoTableName(); pTblName != nil {
		log.Infof(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: mapped table name: %v for the path: %v", *pTblName, pathXltr.uriPath)
		tblNameMap[*pTblName] = true
	} else if ygXpathInfo.xfmrTbl != nil && len(*ygXpathInfo.xfmrTbl) > 0 {
		if tblNames, err := pathXltr.handleTableXfmrCallback(); err != nil {
			log.Error(pathXltr.subReq.reqLogId+"Error: handleNonSubtreeNodeXlate: error in handleTableXfmrCallback: ", err)
			return err
		} else {
			log.Infof(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: table transfoerm: tblNames: %v for the path: %v", tblNames, pathXltr.uriPath)
			for _, tblName := range tblNames {
				tblNameMap[tblName] = true
			}
		}
	}

	tblCnt := 0
	if pathXltr.parentXlateInfo != nil {
		for _, dbTblKeyInfo := range pathXltr.parentXlateInfo.DbKeyXlateInfo {
			if dbTblKeyInfo.DbNum == ygXpathInfo.dbIndex && tblNameMap[dbTblKeyInfo.Table.Name] { tblCnt++; break }
		}
	}

	if tblCnt == len(tblNameMap) {
		log.Infof(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: tables are actually mapped its parent node; table count: %v for the path $v", tblCnt, pathXltr.uriPath)
		return nil
	}

	if dBTblKey, err := pathXltr.handleYangToDbKeyXfmr(); err != nil {
		return err
	} else if len(dBTblKey) > 0 {
		log.Infof(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: dBTblKey: %v for the path %v", dBTblKey, pathXltr.uriPath)
		keyComp = strings.Split(dBTblKey, pathXltr.subReq.dbs[pathXltr.ygTrgtXpathInfo.dbIndex].Opts.KeySeparator)
	}

	var dbKey *db.Key

	if len(keyComp) > 0 {
		if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: keyComp: ", keyComp) }
		dbKey = &db.Key{keyComp}
	}

	for tblName := range tblNameMap {
		if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: Adding tablename: ", tblName) }
		pathXltr.pathXlateInfo.addPathXlateInfo(&db.TableSpec{Name: tblName}, dbKey, ygXpathInfo.dbIndex)
	}

	if pathXltr.subReq.xlateNodeType == TARGET_NODE && (pathXltr.pathXlateInfo.ygXpathInfo.yangEntry.IsLeafList() ||
		pathXltr.pathXlateInfo.ygXpathInfo.yangEntry.IsLeaf()) {
		log.Info(pathXltr.subReq.reqLogId+"handleNonSubtreeNodeXlate: leaf/leaf-list target node for the path: ", pathXltr.uriPath)
		if err := pathXltr.addDbFldYangMapInfo(); err != nil { return err }
	}

	return nil
}

func (pathXltr *subscribePathXlator) handleTableXfmrCallback() ([]string, error) {
	if log.V(dbLgLvl) { log.Info(pathXltr.subReq.reqLogId+"handleTableXfmrCallback:", pathXltr.uriPath) }
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
		log.Errorf(pathXltr.subReq.reqLogId+"handleTableXfmrCallback: table transformer callback returns error: %v and table transformer callback: %v", tblXfmrErr, *ygXpathInfo.xfmrTbl)
		return nil, tblXfmrErr
	} else if inParams.isVirtualTbl != nil && *inParams.isVirtualTbl {
		log.Info(pathXltr.subReq.reqLogId+"handleTableXfmrCallback: isVirtualTbl is set to true for the table transformer callback: ", *ygXpathInfo.xfmrTbl)
	} else {
		log.Infof(pathXltr.subReq.reqLogId+"handleTableXfmrCallback: table names from table transformer callback: %v for the transformer name: %v", tblList, *ygXpathInfo.xfmrTbl)
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
	var err error
	ygNode := ygXpathInfo.yangEntry

	log.Infof(reqXlator.subReq.reqLogId+"translateChildNodePaths: ygXpathInfo.yangEntry: %v for the request uri path: %v", ygNode, reqXlator.subReq.reqUri)

	if (!ygNode.IsList() && !ygNode.IsContainer()) {
		return nil
	}

	rltvUriPath := ""
	reqXlator.subReq.xlateNodeType = CHILD_NODE

	trgtXpathNode := &(ygXpathNode{relUriPath: rltvUriPath, ygXpathInfo: ygXpathInfo, dbFldYgPathMap: make(map[string]string),
		dbTblFldYgPathMap: make(map[string]map[string]string)})

	if ygXpathInfo.yangEntry.IsList() {
		trgtXpathNode.listKeyMap = make(map[string]bool)
		if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"collectChldYgXPathInfo: ygXpathInfo.yangEntry.Key: ", ygXpathInfo.yangEntry.Key) }
		keyElemNames := strings.Fields(ygXpathInfo.yangEntry.Key)
		for _, keyName := range keyElemNames {
			trgtXpathNode.listKeyMap[keyName] = true
		}
	}

	trgtXpathNode.pathXlateInfo = reqXlator.subReq.subReqXlateInfo.TrgtPathInfo

	if err = reqXlator.collectChldYgXPathInfo(ygNode, reqXlator.subReq.ygPath, rltvUriPath, ygXpathInfo, trgtXpathNode); err != nil {
		log.Error(reqXlator.subReq.reqLogId+"translateChildNodePaths: Error in collectChldYgXPathInfo; error: ", err)
		return err
	}

	if err := reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.addDbFldYgPathMap("", trgtXpathNode); err != nil {
		log.Error(reqXlator.subReq.reqLogId+"translateChildNodePaths: Error in addDbFldYgPathMap; error: ", err)
		return err
	}

	if err = reqXlator.traverseYgXpathAndTranslate(trgtXpathNode, "", reqXlator.subReq.subReqXlateInfo.TrgtPathInfo); err != nil {
		log.Error(reqXlator.subReq.reqLogId+"translateChildNodePaths: Error in traverseYgXpathAndTranslate; error: ", err)
	}

	return err
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) isDbTablePresentInParent(parentDbKeyXlateInfo []*dbTableKeyInfo) (bool) {
	log.Info(pathXlateInfo.reqLogId+"isDbTablePresentInParent: path: ", pathXlateInfo.Path)
	if len(parentDbKeyXlateInfo) == 0 {
		log.Info(pathXlateInfo.reqLogId+"isDbTablePresentInParent: parentDbKeyXlateInfo is empty for the path: ", pathXlateInfo.Path)
		return false
	}
	if log.V(dbLgLvl) { log.Info(pathXlateInfo.reqLogId+"isDbTablePresentInParent: pathXlateInfo.DbKeyXlateInfo: ", pathXlateInfo.DbKeyXlateInfo) }
	for _, dbXlateInfo := range pathXlateInfo.DbKeyXlateInfo {
		isPresent := false
		for _, parentDbInfo := range parentDbKeyXlateInfo {
			if log.V(dbLgLvl) { log.Infof(pathXlateInfo.reqLogId+"isDbTablePresentInParent: parentDbInfo: %v for the path: %v", parentDbInfo, pathXlateInfo.Path) }
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

func (reqXlator *subscribeReqXlator) traverseYgXpathAndTranslate(ygXpNode *ygXpathNode, parentRelUri string, parentPathXlateInfo *XfmrSubscribePathXlateInfo) (error) {
	log.Infof(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: ygXpNode path:%v; parentRelUri: %v; parentPathXlateInfo path: %v ", ygXpNode.ygPath, parentRelUri, parentPathXlateInfo.Path)
	var err error

	if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: parentPathXlateInfo: ", *parentPathXlateInfo) }

	for _, chldNode := range ygXpNode.chldNodes {

		log.Infof(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: child path: %v; isParentTbl: %v; relUriPath: %v ", chldNode.ygPath, chldNode.isParentTbl, chldNode.relUriPath)

		var pathXlateInfo *XfmrSubscribePathXlateInfo
		relUri := parentRelUri

		if chldNode.isParentTbl {
			pathXlateInfo = parentPathXlateInfo
			if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: isParentTbl: true") }
			if len(chldNode.dbFldYgPathMap) > 0 || len(chldNode.dbTblFldYgPathMap) > 0 {
				pathXlateInfo.copyDbFldYgPathMap(relUri, chldNode)
			} else {
				if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: isParentTbl: no db field yang map found for the path: ", reqXlator.subReq.reqUri + chldNode.relUriPath) }
			}
		} else {
			var gPathCurr *gnmipb.Path
			if gPathCurr, err = reqXlator.uriToAbsolutePath(chldNode.relUriPath); err != nil {
				return err
			}

			uriPath := reqXlator.subReq.reqUri + chldNode.relUriPath
			if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"next child node URI Path: ", uriPath) }

			pathXlator, err := reqXlator.getSubscribePathXlator(gPathCurr, uriPath, chldNode.ygXpathInfo, parentPathXlateInfo, chldNode)
			if err != nil {
				log.Errorf(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: Error in getSubscribePathXlator: %v for the path: %v", err, uriPath)
				return err
			}

			if err = pathXlator.translatePath(); err != nil {
				log.Errorf(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: Error in translatePath: %v for the path %v", err, uriPath)
				return err
			} else {
				chldNode.pathXlateInfo = pathXlator.pathXlateInfo
			}

			if chldNode.pathXlateInfo.isDbTablePresentInParent(parentPathXlateInfo.DbKeyXlateInfo) {
				pathXlateInfo = parentPathXlateInfo
				log.Infof(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: isDbTablePresentInParent is true for the path: %v for the parent path: %v", uriPath, parentPathXlateInfo.Path)
				parentPathXlateInfo.copyDbFldYgPathMap(relUri, chldNode)
			} else {
				pathXlateInfo = chldNode.pathXlateInfo
				relUri = chldNode.relUriPath

				if len(chldNode.ygXpathInfo.xfmrFunc) == 0 { // only for non sub tree - for subtree, got added by handleSubtreeNodeXlate
					if err := chldNode.pathXlateInfo.addDbFldYgPathMap("", chldNode); err != nil {
						log.Errorf(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: Error in addDbFldYgPathMap: error: %v and path is %v ", err, uriPath)
						return err
					}
				}

				if !chldNode.ygXpathInfo.yangEntry.IsList() && len(parentPathXlateInfo.DbKeyXlateInfo) > 0 {
					// other than list node, that is for the container / leaf / leaf-list node
					// the db key entry of the parent list node's table db key will be used as the table
					// key for the container/leaf/leaf-list node's table
					// this is needed to subscribe to the table for the particular key entry
					// if we need to add support to handle if the container table key is different
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
					log.Warning(reqXlator.subReq.reqLogId+"traverseYgXpathAndTranslate: Db table information is not found for the list node for the uri path : ", uriPath)
				}
				if len(reqXlator.subReq.subReqXlateInfo.TrgtPathInfo.DbKeyXlateInfo) == 0 &&
					(!parentPathXlateInfo.TrgtNodeChld && len(chldNode.pathXlateInfo.DbKeyXlateInfo) > 0) {
					log.Info("traverseYgXpathAndTranslate: target info path is empty; setting TrgtNodeChld flag to true for the path: ", chldNode.pathXlateInfo.Path)
					chldNode.pathXlateInfo.TrgtNodeChld = true
				}
				reqXlator.subReq.subReqXlateInfo.ChldPathsInfo = append(reqXlator.subReq.subReqXlateInfo.ChldPathsInfo, chldNode.pathXlateInfo)
			}
		}

		if err = reqXlator.traverseYgXpathAndTranslate(chldNode, relUri, pathXlateInfo); err != nil {
			return err
		}
	}
	return err
}

func (reqXlator *subscribeReqXlator) debugTrvsalCtxt(ygEntry *yang.Entry, ygPath string, rltvUriPath string, ygXpathInfo *yangXpathInfo) {
	if log.V(dbLgLvl) { log.Infof(reqXlator.subReq.reqLogId+"debugTrvsalCtxt ygPath: %v; rltvUriPath: %v; ygXpathInfo: %v; ygEntry: %v", ygPath, rltvUriPath, *ygXpathInfo, ygEntry) }
}

type ygXpathNode struct {
	relUriPath        string
	ygXpathInfo       *yangXpathInfo
	chldNodes         []*ygXpathNode
	dbFldYgPathMap    map[string]string
	dbTblFldYgPathMap map[string]map[string]string
	pathXlateInfo     *XfmrSubscribePathXlateInfo
	isParentTbl       bool
	listKeyMap        map[string]bool
	ygPath            string
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) copyDbFldYgPathMap(parentRelUri string, ygXpNode *ygXpathNode) (error) {
	log.Infof(pathXlateInfo.reqLogId+"copyDbFldYgPathMap: parentRelUri: %v; ygXpNode.relUriPath: %v", parentRelUri, ygXpNode.relUriPath)

	if sIdx := strings.Index(ygXpNode.relUriPath, parentRelUri); sIdx == -1 {
		log.Error(pathXlateInfo.reqLogId+"copyDbFldYgPathMap: Not able to get the relative path of the node for the relUriPath: ", ygXpNode.relUriPath)
		return tlerr.InternalError{Format: "Not able to get the relative path of the node", Path: ygXpNode.relUriPath}
	} else {
		if log.V(dbLgLvl) { log.Info(pathXlateInfo.reqLogId+"copyDbFldYgPathMap: sIdx: ", sIdx) }
		relPath := string(ygXpNode.relUriPath[sIdx + len(parentRelUri):])
		log.Info(pathXlateInfo.reqLogId+"copyDbFldYgPathMap: relPath: ", relPath)
		return pathXlateInfo.addDbFldYgPathMap(relPath, ygXpNode)
	}

	return nil
}

func (pathXlateInfo *XfmrSubscribePathXlateInfo) addDbFldYgPathMap(relPath string, ygXpNode *ygXpathNode) (error) {

	if len(pathXlateInfo.DbKeyXlateInfo) == 0 && len(ygXpNode.dbFldYgPathMap) > 0 {
		log.Error(pathXlateInfo.reqLogId+"addDbFldYgPathMap: pathXlateInfo.DbKeyXlateInfo is empty for the path ", ygXpNode.ygPath)
		return tlerr.InternalError{Format: "DbKeyXlateInfo is empty: ", Path: ygXpNode.ygPath}
	} else if len(ygXpNode.dbTblFldYgPathMap) > 0 { // multi table field mapped to same yang node
		for _, dbKeyInfo := range pathXlateInfo.DbKeyXlateInfo {
			if dbFldYgMap, ok := ygXpNode.dbTblFldYgPathMap[dbKeyInfo.Table.Name]; ok {
				dbFldInfo := DbFldYgPathInfo{relPath, make(map[string]string)}
				dbFldInfo.DbFldYgPathMap = dbFldYgMap
				dbKeyInfo.DbFldYgMapList = append(dbKeyInfo.DbFldYgMapList, &dbFldInfo)
				log.Infof(pathXlateInfo.reqLogId+"addDbFldYgPathMap: multi table field nodes: dbFldInfo: %v for the table name: %v", dbFldInfo, dbKeyInfo.Table.Name)
			} else {
				log.Errorf(pathXlateInfo.reqLogId+"addDbFldYgPathMap: Not able to find the table %v for the db field path map for the node: %v", dbKeyInfo.Table.Name, ygXpNode.ygPath)
				return tlerr.InternalError{Format: "Not able to find the table for the db field", Path: ygXpNode.ygPath}
			}
		}
	} else if len(ygXpNode.dbFldYgPathMap) > 0 {
		if log.V(dbLgLvl) { log.Info(pathXlateInfo.reqLogId+"addDbFldYgPathMap: adding the direct leaf nodes: ygXpNode.dbFldYgPathMap: ", ygXpNode.dbFldYgPathMap) }
		dbFldYgPathInfo := &DbFldYgPathInfo{relPath, ygXpNode.dbFldYgPathMap}

		for _, dbKeyInfo := range pathXlateInfo.DbKeyXlateInfo {
			if log.V(dbLgLvl) { log.Info(pathXlateInfo.reqLogId+"addDbFldYgPathMap: adding the direct leaf node to the table : ", dbKeyInfo.Table.Name) }
			dbKeyInfo.DbFldYgMapList = append(dbKeyInfo.DbFldYgMapList, dbFldYgPathInfo)
		}
	}

	return nil
}

func (ygXpNode *ygXpathNode) addDbFldNames(ygNodeName string, dbFldNames []string) (error) {
	for _, dbTblFldName := range dbFldNames {
		tblField := strings.Split(dbTblFldName, ":")
		if len(tblField) > 1 {
			tblName := strings.TrimSpace(tblField[0])
			if _, ok := ygXpNode.dbTblFldYgPathMap[tblName]; !ok {
				ygXpNode.dbTblFldYgPathMap[tblName] = make(map[string]string)
				ygXpNode.dbTblFldYgPathMap[tblName][strings.TrimSpace(tblField[1])] = ygNodeName
			} else {
				ygXpNode.dbTblFldYgPathMap[tblName][strings.TrimSpace(tblField[1])] = ygNodeName
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

func (pathXltr *subscribePathXlator) getDbFieldName() (string) {
	xpathInfo := pathXltr.pathXlateInfo.ygXpathInfo
	log.Infof(pathXltr.subReq.reqLogId+"getDbFieldName: fieldName: %v; xpathInfo.yangEntry: %v", xpathInfo.fieldName, xpathInfo.yangEntry)
	if xpathInfo.yangEntry.IsLeafList() || xpathInfo.yangEntry.IsLeaf() {
		fldName := xpathInfo.fieldName
		if len(fldName) == 0 {
			fldName = xpathInfo.yangEntry.Name
		}
		log.Info(pathXltr.subReq.reqLogId+"getDbFieldName: fldName: ", fldName)
		return fldName
	}
	return ""
}

func (reqXlator *subscribeReqXlator) collectChldYgXPathInfo(ygEntry *yang.Entry, ygPath string,
rltvUriPath string, ygXpathInfo *yangXpathInfo, ygXpNode *ygXpathNode) (error) {

	log.Infof(reqXlator.subReq.reqLogId+"collectChldYgXPathInfo: ygEntry: %v, ygPath: %v, rltvUriPath: %v; table name: %v;" +
		" parent node path: %v", ygEntry, ygPath, rltvUriPath, ygXpathInfo.tableName, ygXpNode.ygPath)

	reqXlator.debugTrvsalCtxt(ygEntry, ygPath, rltvUriPath, ygXpathInfo)

	for _, childYgEntry := range ygEntry.Dir {
		childYgPath := ygPath + "/" + childYgEntry.Name
		log.Info(reqXlator.subReq.reqLogId+"collectChldYgXPathInfo: childYgPath:", childYgPath)

		if chYgXpathInfo, ok := xYangSpecMap[childYgPath]; ok {
			rltvChldUriPath := rltvUriPath

			if chYgXpathInfo.nameWithMod != nil {
				rltvChldUriPath = rltvChldUriPath + "/" + *(chYgXpathInfo.nameWithMod)
			} else {
				rltvChldUriPath = rltvChldUriPath + "/" + childYgEntry.Name
			}

			var keyListMap map[string]bool

			if childYgEntry.IsList() {
				keyListMap = make (map[string]bool)
				if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"collectChldYgXPathInfo: childYgEntry.Key: ", childYgEntry.Key) }
				keyElemNames := strings.Fields(childYgEntry.Key)

				for _, keyName := range keyElemNames {
					rltvChldUriPath = rltvChldUriPath + "[" + keyName + "=*]"
					keyListMap[keyName] = true
				}

				log.Infof(reqXlator.subReq.reqLogId+"collectChldYgXPathInfo: keyListMap: %v, for the path: %v ", keyListMap, childYgPath)
			}

			if (chYgXpathInfo.dbIndex == db.CountersDB && chYgXpathInfo.subscribeOnChg != XFMR_ENABLE) {
				log.Warning(reqXlator.subReq.reqLogId+"CountersDB mapped in the path: ", childYgPath)
				return tlerr.NotSupportedError{Format: "Subscribe not supported; one of its child path is mapped to COUNTERS DB and its not enabled explicitly", Path: childYgPath}
			} else if chYgXpathInfo.subscribeOnChg == XFMR_DISABLE {
				log.Warning(reqXlator.subReq.reqLogId+"Subscribe not supported; one of the child path's on_change subscription is disabled: ", childYgPath)
				if log.V(dbLgLvl) { debugPrintXPathInfo(chYgXpathInfo) }
				return tlerr.NotSupportedError{Format: "Subscribe not supported; one of the child path's on_change subscription is disabled", Path: childYgPath}
			} else if reqXlator.subReq.isTrgtDfnd && chYgXpathInfo.subscribePref != nil && *chYgXpathInfo.subscribePref != "onchange" {
				log.Warning(reqXlator.subReq.reqLogId+"Subscribe not supported; one of the child path's subscription preference is NOT on_change: ", childYgPath)
				return tlerr.NotSupportedError{Format: "Subscribe not supported; one of the child path's subscription preference is not on_change", Path: childYgPath}
			}

			tblName := ""
			if (chYgXpathInfo.tableName != nil && *chYgXpathInfo.tableName != "NONE") && (chYgXpathInfo.virtualTbl == nil || !*chYgXpathInfo.virtualTbl) {
				if ygXpathInfo.tableName == nil || *ygXpathInfo.tableName != *chYgXpathInfo.tableName {
					tblName = *chYgXpathInfo.tableName
				}
			}

			if childYgEntry.IsLeaf() || childYgEntry.IsLeafList() {
				if ygXpNode.ygXpathInfo.yangEntry.IsList() {
					if _, ok := ygXpNode.listKeyMap[chYgXpathInfo.yangEntry.Name]; ok {
						// for key leaf - there is no need to collect the info
						if log.V(dbLgLvl) { log.Info(reqXlator.subReq.reqLogId+"List key leaf node.. not collecting the info.. key leaf name: ", chYgXpathInfo.yangEntry.Name) }
						continue
					}
				}
				if tblName != "" {
					log.Infof(reqXlator.subReq.reqLogId+"adding child ygXpNode for the table name %v for the leaf node for the path %v ", tblName, childYgPath)
					ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else if len(chYgXpathInfo.compositeFields) > 0 && len(chYgXpathInfo.xfmrFunc) == 0 {
					log.Infof(reqXlator.subReq.reqLogId+"adding composite field names %v for the leaf node for the path %v ", chYgXpathInfo.compositeFields, childYgPath)
					if err := ygXpNode.addDbFldNames(childYgEntry.Name, chYgXpathInfo.compositeFields); err != nil {
						return err
					}
				} else if len(chYgXpathInfo.fieldName) > 0 && len(chYgXpathInfo.xfmrFunc) == 0 {
					log.Infof(reqXlator.subReq.reqLogId+"adding field name %v for the leaf node for the path %v ", chYgXpathInfo.fieldName, childYgPath)
					ygXpNode.addDbFldName(childYgEntry.Name, chYgXpathInfo.fieldName)
				} else if len(chYgXpathInfo.xfmrFunc) == 0 {
					log.Warning(reqXlator.subReq.reqLogId+"collectChldYgXPathInfo: Adding yang node namae as db field name by default since there is no db field name mapping for the yang leaf-name: ", childYgPath)
					ygXpNode.addDbFldName(childYgEntry.Name, childYgEntry.Name)
				}
			} else if (childYgEntry.IsList() || childYgEntry.IsContainer()) {
				chldNode := ygXpNode
				isVirtualTbl := (chYgXpathInfo.virtualTbl != nil && *chYgXpathInfo.virtualTbl)

				if len(chYgXpathInfo.xfmrFunc) > 0 {
					log.Infof(reqXlator.subReq.reqLogId+"adding subtree xfmr func %v for the path %v ", chYgXpathInfo.xfmrFunc, childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else if tblName != "" {
					log.Infof(reqXlator.subReq.reqLogId+"adding table name %v for the path %v ", tblName, childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else if (chYgXpathInfo.xfmrTbl != nil && !isVirtualTbl) {
					log.Infof(reqXlator.subReq.reqLogId+"adding table transformer %v for the path %v ", *chYgXpathInfo.xfmrTbl, childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
				} else {
					if childYgEntry.IsList() && !isVirtualTbl {
						log.Error(reqXlator.subReq.reqLogId+"No table related information for the LIST yang node path: ", childYgPath)
						return tlerr.InternalError{Format: "No yangXpathInfo found for the LIST / Container yang node path", Path: childYgPath}
					}
					log.Info(reqXlator.subReq.reqLogId+"Adding ygXpNode for the list node(with virtual table) / container with no tables mapped and the path: ", childYgPath)
					chldNode = ygXpNode.addChildNode(rltvChldUriPath, chYgXpathInfo)
					chldNode.isParentTbl = true
				}

				if childYgEntry.IsList() {
					chldNode.listKeyMap = keyListMap
				}

				chldNode.ygPath = childYgPath
				if err := reqXlator.collectChldYgXPathInfo(childYgEntry, childYgPath, rltvChldUriPath, chYgXpathInfo, chldNode); err != nil {
					log.Errorf(reqXlator.subReq.reqLogId+"Error in collecting the ygXpath Info for the yang path: %v and the error: %v", childYgPath, err)
					return err
				}
			}
		} else if childYgEntry.IsList() || childYgEntry.IsContainer() {
			log.Error(reqXlator.subReq.reqLogId+"No yangXpathInfo found for the LIST / Container yang node path: ", childYgPath)
			return tlerr.InternalError{Format: "No yangXpathInfo found for the LIST / Container yang node path", Path: childYgPath}
		} else {
			log.Warning(reqXlator.subReq.reqLogId+"No yangXpathInfo found for the leaf / leaf-list node yang node path: ", childYgPath)
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
	return reqXlator.subReq.subReqXlateInfo
}

func (reqXlator *subscribeReqXlator) uriToAbsolutePath(rltvUri string) (*gnmipb.Path, error) {
	log.Info(reqXlator.subReq.reqLogId+"uriToAbsolutePath: rltvUri: ", rltvUri)
	if gRelPath, err := ygot.StringToPath(rltvUri, ygot.StructuredPath, ygot.StringSlicePath); err != nil {
		log.Error(reqXlator.subReq.reqLogId+"Error in converting the URI into GNMI path for the URI: ", rltvUri)
		return nil, tlerr.InternalError{Format: "Error in converting the URI into GNMI path", Path: rltvUri}
	} else {
		gPath := gnmipb.Path{}
		gPath.Elem = append(gPath.Elem, reqXlator.subReq.gPath.Elem...)
		gPath.Elem = append(gPath.Elem, gRelPath.Elem...)
		log.Info(reqXlator.subReq.reqLogId+"uriToAbsolutePath: gPath: ", gPath)
		return &gPath, nil
	}
}

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
	if len(xpathInfo.xfmrPath) > 0 {
		fmt.Printf("\r\n    xfmrPath :%v", xpathInfo.xfmrPath)
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
