////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Dell, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
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
    "fmt"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "strings"
    "encoding/json"
    "strconv"
    "errors"
    "sync"
    "github.com/openconfig/goyang/pkg/yang"

    log "github.com/golang/glog"
)

type typeMapOfInterface map[string]interface{}

var mapCopyMutex = &sync.Mutex{}

func DbValToInt(dbFldVal string, base int, size int, isUint bool) (interface{}, error) {
	var res interface{}
	var err error
	if isUint {
		if res, err = strconv.ParseUint(dbFldVal, base, size); err != nil {
			log.Warningf("Non Yint%v type for yang leaf-list item %v", size, dbFldVal)
		}
	} else {
		if res, err = strconv.ParseInt(dbFldVal, base, size); err != nil {
			log.Warningf("Non Yint %v type for yang leaf-list item %v", size, dbFldVal)
		}
	}
	return res, err
}

func getLeafrefRefdYangType(yngTerminalNdDtType yang.TypeKind, fldXpath string) (yang.TypeKind) {
	if yngTerminalNdDtType == yang.Yleafref {
		var entry *yang.Entry
		var path string
		if _, ok := xDbSpecMap[fldXpath]; ok {
			path = xDbSpecMap[fldXpath].dbEntry.Type.Path
			entry = xDbSpecMap[fldXpath].dbEntry
		} else if _, ok := xYangSpecMap[fldXpath]; ok {
			path = xYangSpecMap[fldXpath].yangEntry.Type.Path
			entry = xYangSpecMap[fldXpath].yangEntry
		}
		path = stripAugmentedModuleNames(path)
		path = path[1:]
		xfmrLogInfoAll("Received path %v for FieldXpath %v", path, fldXpath)
		if strings.Contains(path, "..") {
			if entry != nil && len(path) > 0 {
				// Referenced path within same yang file
				xpath, err := XfmrRemoveXPATHPredicates(path)
				if  err != nil {
					log.Warningf("error in XfmrRemoveXPATHPredicates %v", path)
					return yngTerminalNdDtType
				}
				xpath = xpath[1:]
				pathList := strings.Split(xpath, "/")
				for _, x := range pathList {
					if x == ".." {
						entry = entry.Parent
					} else {
						if _,ok := entry.Dir[x]; ok {
							entry = entry.Dir[x]
						}
					}
				}
				if entry != nil && entry.Type != nil {
					yngTerminalNdDtType = entry.Type.Kind
					xfmrLogInfoAll("yangLeaf datatype %v", yngTerminalNdDtType)
					if yngTerminalNdDtType == yang.Yleafref {
						leafPath := getXpathFromYangEntry(entry)
						xfmrLogInfoAll("getLeafrefRefdYangType: xpath for leafref type:%v",leafPath)
						return getLeafrefRefdYangType(yngTerminalNdDtType, leafPath)
					}
				}
			}
		} else if len(path) > 0 {
			// Referenced path in a different yang file
			xpath, err := XfmrRemoveXPATHPredicates(path)
			if  err != nil {
				log.Warningf("error in XfmrRemoveXPATHPredicates %v", xpath)
				return yngTerminalNdDtType
			}
			// Form xpath based on sonic or non sonic yang path
			if strings.Contains(xpath, "sonic") {
				pathList := strings.Split(xpath, "/")
				xpath = pathList[SONIC_TABLE_INDEX]+ "/" + pathList[SONIC_FIELD_INDEX]
				if _, ok := xDbSpecMap[xpath]; ok {
					yngTerminalNdDtType = xDbSpecMap[xpath].dbEntry.Type.Kind
				}

			} else {
				xpath = replacePrefixWithModuleName(xpath)
				if _, ok := xYangSpecMap[xpath]; ok {
					yngTerminalNdDtType = xYangSpecMap[xpath].dbEntry.Type.Kind
				}
			}

		}
		xfmrLogInfoAll("yangLeaf datatype %v", yngTerminalNdDtType)
	}
	return yngTerminalNdDtType
}

func DbToYangType(yngTerminalNdDtType yang.TypeKind, fldXpath string, dbFldVal string) (interface{}, interface{}, error) {
	xfmrLogInfoAll("Received FieldXpath %v, yngTerminalNdDtType %v and Db field value %v to be converted to yang data-type.", fldXpath, yngTerminalNdDtType, dbFldVal)
	var res interface{}
	var resPtr interface{}
	var err error
	const INTBASE = 10

	if yngTerminalNdDtType == yang.Yleafref {
		yngTerminalNdDtType = getLeafrefRefdYangType(yngTerminalNdDtType, fldXpath)
	}

	switch yngTerminalNdDtType {
        case yang.Ynone:
                log.Warning("Yang node data-type is non base yang type")
		//TODO - enhance to handle non base data types depending on future use case
		err = errors.New("Yang node data-type is non base yang type")
        case yang.Yint8:
                res, err = DbValToInt(dbFldVal, INTBASE, 8, false)
		var resInt8 int8 = int8(res.(int64))
		resPtr = &resInt8
        case yang.Yint16:
                res, err = DbValToInt(dbFldVal, INTBASE, 16, false)
		var resInt16 int16 = int16(res.(int64))
		resPtr = &resInt16
        case yang.Yint32:
                res, err = DbValToInt(dbFldVal, INTBASE, 32, false)
		var resInt32 int32 = int32(res.(int64))
		resPtr = &resInt32
        case yang.Yuint8:
                res, err = DbValToInt(dbFldVal, INTBASE, 8, true)
		var resUint8 uint8 = uint8(res.(uint64))
		resPtr = &resUint8
        case yang.Yuint16:
                res, err = DbValToInt(dbFldVal, INTBASE, 16, true)
		var resUint16 uint16 = uint16(res.(uint64))
		resPtr = &resUint16
        case yang.Yuint32:
                res, err = DbValToInt(dbFldVal, INTBASE, 32, true)
		var resUint32 uint32 = uint32(res.(uint64))
		resPtr = &resUint32
        case yang.Ybool:
		if res, err = strconv.ParseBool(dbFldVal); err != nil {
			log.Warningf("Non Bool type for yang leaf-list item %v", dbFldVal)
		}
		var resBool bool = res.(bool)
		resPtr = &resBool
        case yang.Ybinary, yang.Ydecimal64, yang.Yenum, yang.Yidentityref, yang.Yint64, yang.Yuint64, yang.Ystring, yang.Yunion, yang.Yleafref:
                // TODO - handle the union type
                // Make sure to encode as string, expected by util_types.go: ytypes.yangToJSONType
                xfmrLogInfoAll("Yenum/Ystring/Yunion(having all members as strings) type for yangXpath %v", fldXpath)
                res = dbFldVal
		var resString string = res.(string)
		resPtr = &resString
	case yang.Yempty:
		logStr := fmt.Sprintf("Yang data type for xpath %v is Yempty.", fldXpath)
		log.Error(logStr)
		err = errors.New(logStr)
        default:
		logStr := fmt.Sprintf("Unrecognized/Unhandled yang-data type(%v) for xpath %v.", fldXpath, yang.TypeKindToName[yngTerminalNdDtType])
                log.Error(logStr)
                err = errors.New(logStr)
        }
	return res, resPtr, err
}

/*convert leaf-list in Db to leaf-list in yang*/
func processLfLstDbToYang(fieldXpath string, dbFldVal string, yngTerminalNdDtType yang.TypeKind) []interface{} {
	valLst := strings.Split(dbFldVal, ",")
	var resLst []interface{}
	const INTBASE = 10

	xfmrLogInfoAll("xpath: %v, dbFldVal: %v", fieldXpath, dbFldVal)
	switch  yngTerminalNdDtType {
	case yang.Ybinary, yang.Ydecimal64, yang.Yenum, yang.Yidentityref, yang.Yint64, yang.Yuint64, yang.Ystring, yang.Yunion:
                // TODO - handle the union type.OC yang should have field xfmr.sonic-yang?
                // Make sure to encode as string, expected by util_types.go: ytypes.yangToJSONType:
		xfmrLogInfoAll("DB leaf-list and Yang leaf-list are of same data-type")
		for _, fldVal := range valLst {
			resLst = append(resLst, fldVal)
		}
	default:
		for _, fldVal := range valLst {
			resVal, _, err := DbToYangType(yngTerminalNdDtType, fieldXpath, fldVal)
			if err == nil {
				resLst = append(resLst, resVal)
			}
		}
	}
	return resLst
}

func sonicDbToYangTerminalNodeFill(field string, inParamsForGet xlateFromDbParams) {
	resField := field
	value := ""

	if inParamsForGet.dbDataMap != nil {
		tblInstFields, dbDataExists := (*inParamsForGet.dbDataMap)[inParamsForGet.curDb][inParamsForGet.tbl][inParamsForGet.tblKey]
		if dbDataExists {
			fieldVal, valueExists := tblInstFields.Field[field]
			if !valueExists {
				return
			}
			value = fieldVal
		} else {
			return
		}
	}

	if strings.HasSuffix(field, "@") {
		fldVals := strings.Split(field, "@")
		resField = fldVals[0]
	}
	fieldXpath := inParamsForGet.tbl + "/" + resField
	xDbSpecMapEntry, ok := xDbSpecMap[fieldXpath]
	if !ok {
		log.Warningf("No entry found in xDbSpecMap for xpath %v", fieldXpath)
		return
	}
	if xDbSpecMapEntry.dbEntry == nil {
		log.Warningf("Yang entry is nil in xDbSpecMap for xpath %v", fieldXpath)
		return
	}

	yangType := yangTypeGet(xDbSpecMapEntry.dbEntry)
	yngTerminalNdDtType := xDbSpecMapEntry.dbEntry.Type.Kind
	if yangType ==  YANG_LEAF_LIST {
		/* this should never happen but just adding for safetty */
		if !strings.HasSuffix(field, "@") {
			log.Warningf("Leaf-list in Sonic yang should also be a leaf-list in DB, its not for xpath %v", fieldXpath)
			return
		}
		resLst := processLfLstDbToYang(fieldXpath, value, yngTerminalNdDtType)
		inParamsForGet.resultMap[resField] = resLst
	} else { /* yangType is leaf - there are only 2 types of yang terminal node leaf and leaf-list */
		resVal, _, err := DbToYangType(yngTerminalNdDtType, fieldXpath, value)
		if err != nil {
			log.Warningf("Failure in converting Db value type to yang type for xpath", fieldXpath)
		} else {
			inParamsForGet.resultMap[resField] = resVal
		}
	}
	return
}

func sonicDbToYangListFill(inParamsForGet xlateFromDbParams) []typeMapOfInterface {
	var mapSlice []typeMapOfInterface
	dbDataMap := inParamsForGet.dbDataMap
	table := inParamsForGet.tbl
	dbIdx := inParamsForGet.curDb
	xpath := inParamsForGet.xpath
	dbTblData := (*dbDataMap)[dbIdx][table]

	for keyStr, _ := range dbTblData {
		curMap := make(map[string]interface{})
		linParamsForGet := formXlateFromDbParams(inParamsForGet.dbs[dbIdx], inParamsForGet.dbs, dbIdx, inParamsForGet.ygRoot, inParamsForGet.uri, inParamsForGet.requestUri, xpath, inParamsForGet.oper, table, keyStr, dbDataMap, inParamsForGet.txCache, curMap, inParamsForGet.validate)
		sonicDbToYangDataFill(linParamsForGet)
		curMap = linParamsForGet.resultMap
		dbDataMap = linParamsForGet.dbDataMap
		inParamsForGet.dbDataMap = dbDataMap
		dbSpecData, ok := xDbSpecMap[table]
		if ok && dbSpecData.keyName == nil {
			yangKeys := yangKeyFromEntryGet(xDbSpecMap[xpath].dbEntry)
			sonicKeyDataAdd(dbIdx, yangKeys, table, keyStr, curMap)
		}
		if curMap != nil && len(curMap) > 0 {
			mapSlice = append(mapSlice, curMap)
		}
	}
	return mapSlice
}

func sonicDbToYangDataFill(inParamsForGet xlateFromDbParams) {
	xpath := inParamsForGet.xpath
	uri := inParamsForGet.uri
	table := inParamsForGet.tbl
	key := inParamsForGet.tblKey
	resultMap := inParamsForGet.resultMap
	dbDataMap := inParamsForGet.dbDataMap
	dbIdx := inParamsForGet.curDb
	yangNode, ok := xDbSpecMap[xpath]

	if ok  && yangNode.dbEntry != nil {
		xpathPrefix := table
		if len(table) > 0 { xpathPrefix += "/" }

		for yangChldName := range yangNode.dbEntry.Dir {
			chldXpath := xpathPrefix+yangChldName
			if xDbSpecMap[chldXpath] != nil && xDbSpecMap[chldXpath].dbEntry != nil {
				chldYangType := yangTypeGet(xDbSpecMap[chldXpath].dbEntry)

				if  chldYangType == YANG_LEAF || chldYangType == YANG_LEAF_LIST {
					xfmrLogInfoAll("tbl(%v), k(%v), yc(%v)", table, key, yangChldName)
					fldName := yangChldName
					if chldYangType == YANG_LEAF_LIST  {
						fldName = fldName + "@"
					}
				        curUri := inParamsForGet.uri + "/" + yangChldName
					linParamsForGet := formXlateFromDbParams(nil, inParamsForGet.dbs, dbIdx, inParamsForGet.ygRoot, curUri, inParamsForGet.requestUri, curUri, inParamsForGet.oper, table, key, dbDataMap, inParamsForGet.txCache, resultMap, inParamsForGet.validate)
                                        sonicDbToYangTerminalNodeFill(fldName, linParamsForGet)
					resultMap = linParamsForGet.resultMap
					inParamsForGet.resultMap = resultMap
				} else if chldYangType == YANG_CONTAINER {
					curMap := make(map[string]interface{})
					curUri := xpath + "/" + yangChldName
					// container can have a static key, so extract key for current container
					_, curKey, curTable := sonicXpathKeyExtract(curUri)
					// use table-name as xpath from now on
					d := inParamsForGet.dbs[xDbSpecMap[curTable].dbIndex]
					linParamsForGet := formXlateFromDbParams(d, inParamsForGet.dbs, xDbSpecMap[curTable].dbIndex, inParamsForGet.ygRoot, curUri, inParamsForGet.requestUri, curTable, inParamsForGet.oper, curTable, curKey, dbDataMap, inParamsForGet.txCache, curMap, inParamsForGet.validate)
					sonicDbToYangDataFill(linParamsForGet)
					curMap = linParamsForGet.resultMap
					dbDataMap = linParamsForGet.dbDataMap
					if len(curMap) > 0 {
						resultMap[yangChldName] = curMap
					} else {
						xfmrLogInfoAll("Empty container for xpath(%v)", curUri)
					}
					inParamsForGet.dbDataMap = linParamsForGet.dbDataMap
					inParamsForGet.resultMap = resultMap
				} else if chldYangType == YANG_LIST {
					pathList := strings.Split(uri, "/")
					// Skip the list entries if the uri has specific list query
					if len(pathList) > SONIC_TABLE_INDEX+1 && !strings.Contains(uri,yangChldName) {
						xfmrLogInfoAll("Skipping yangChldName: %v, pathList:%v, len:%v", yangChldName, pathList, len(pathList))
					} else {
						var mapSlice []typeMapOfInterface
						curUri := xpath + "/" + yangChldName
						inParamsForGet.uri = curUri
						inParamsForGet.xpath = curUri
						mapSlice = sonicDbToYangListFill(inParamsForGet)
						dbDataMap = inParamsForGet.dbDataMap
						if len(key) > 0 && len(mapSlice) == 1 {// Single instance query. Don't return array of maps
							for k, val := range mapSlice[0] {
								resultMap[k] = val
							}

						} else if len(mapSlice) > 0 {
							resultMap[yangChldName] = mapSlice
						} else {
							xfmrLogInfoAll("Empty list for xpath(%v)", curUri)
						}
						inParamsForGet.resultMap = resultMap
					}
				} else if chldYangType == YANG_CHOICE || chldYangType == YANG_CASE {
					curUri := table + "/" + yangChldName
					inParamsForGet.uri = curUri
					inParamsForGet.xpath = curUri
					inParamsForGet.curDb = xDbSpecMap[table].dbIndex
					sonicDbToYangDataFill(inParamsForGet)
					dbDataMap = inParamsForGet.dbDataMap
					resultMap = inParamsForGet.resultMap
				} else {
					xfmrLogInfoAll("Not handled case %v", chldXpath)
				}
			} else {
				xfmrLogInfoAll("Yang entry not found for %v", chldXpath)
			}
		}
	}
	return
}

/* Traverse db map and create json for cvl yang */
func directDbToYangJsonCreate(inParamsForGet xlateFromDbParams) (string, error, bool) {
	var err error
	uri := inParamsForGet.uri
	dbDataMap := inParamsForGet.dbDataMap
	resultMap := inParamsForGet.resultMap
	xpath, key, table := sonicXpathKeyExtract(uri)
	inParamsForGet.xpath = xpath
	inParamsForGet.tbl = table
	inParamsForGet.tblKey = key

	if len(xpath) > 0 {
		var dbNode *dbInfo

		if len(table) > 0 {
			tokens:= strings.Split(xpath, "/")
			if tokens[SONIC_TABLE_INDEX] == table {
				fieldName := tokens[len(tokens)-1]
				dbSpecField := table + "/" + fieldName
				_, ok := xDbSpecMap[dbSpecField]
				if ok && (xDbSpecMap[dbSpecField].fieldType == YANG_LEAF || xDbSpecMap[dbSpecField].fieldType == YANG_LEAF_LIST) {
					dbNode = xDbSpecMap[dbSpecField]
					xpath = dbSpecField
					inParamsForGet.xpath = xpath
				} else {
					dbNode = xDbSpecMap[table]
				}
			}
		} else {
			dbNode, _ = xDbSpecMap[xpath]
		}

		if dbNode != nil && dbNode.dbEntry != nil {
			cdb   := db.ConfigDB
			yangType := yangTypeGet(dbNode.dbEntry)
			if len(table) > 0 {
				cdb = xDbSpecMap[table].dbIndex
			}
			inParamsForGet.curDb = cdb

			if yangType == YANG_LEAF || yangType == YANG_LEAF_LIST {
				fldName := xDbSpecMap[xpath].dbEntry.Name
				if yangType == YANG_LEAF_LIST  {
					fldName = fldName + "@"
				}
				linParamsForGet := formXlateFromDbParams(nil, inParamsForGet.dbs, cdb, inParamsForGet.ygRoot, xpath, inParamsForGet.requestUri, uri, inParamsForGet.oper, table, key, dbDataMap, inParamsForGet.txCache, resultMap, inParamsForGet.validate)
				sonicDbToYangTerminalNodeFill(fldName, linParamsForGet)
				resultMap = linParamsForGet.resultMap
			} else if yangType == YANG_CONTAINER {
				if len(table) > 0 {
					xpath = table
					inParamsForGet.xpath = xpath
				}
				sonicDbToYangDataFill(inParamsForGet)
				resultMap = inParamsForGet.resultMap
			} else if yangType == YANG_LIST {
				mapSlice := sonicDbToYangListFill(inParamsForGet)
				if len(key) > 0 && len(mapSlice) == 1 {// Single instance query. Don't return array of maps
                                                for k, val := range mapSlice[0] {
                                                        resultMap[k] = val
                                                }

                                } else if len(mapSlice) > 0 {
					pathl := strings.Split(xpath, "/")
					lname := pathl[len(pathl) - 1]
					resultMap[lname] = mapSlice
				}
			}
		}
	}

	jsonMapData, _ := json.Marshal(resultMap)
	isEmptyPayload := isJsonDataEmpty(string(jsonMapData))
	jsonData := fmt.Sprintf("%v", string(jsonMapData))
        if isEmptyPayload {
		errStr := fmt.Sprintf("No data available")
		log.Error(errStr)
		//err = tlerr.NotFound("Resource not found")
        }
        return jsonData, err, isEmptyPayload
}

func tableNameAndKeyFromDbMapGet(dbDataMap map[string]map[string]db.Value) (string, string, error) {
    tableName := ""
    tableKey  := ""
    for tn, tblData := range dbDataMap {
        tableName = tn
        for kname, _ := range tblData {
            tableKey = kname
        }
    }
    return tableName, tableKey, nil
}

func fillDbDataMapForTbl(uri string, xpath string, tblName string, tblKey string, cdb db.DBNum, dbs [db.MaxDB]*db.DB) (map[db.DBNum]map[string]map[string]db.Value, error) {
	var err error
	dbresult  := make(RedisDbMap)
	dbresult[cdb] = make(map[string]map[string]db.Value)
	dbFormat := KeySpec{}
	dbFormat.Ts.Name = tblName
	dbFormat.DbNum = cdb
	if tblKey != "" {
		if tblSpecInfo, ok := xDbSpecMap[tblName]; ok && tblSpecInfo.hasXfmrFn == true {
			/* key from uri should be converted into redis-db key, to read data */
			tblKey, err = dbKeyValueXfmrHandler(CREATE, cdb, tblName, tblKey)
			if err != nil {
				log.Errorf("Value-xfmr for table(%v) & key(%v) failed.", tblName, tblKey)
				return nil, err
			}
		}

		dbFormat.Key.Comp = append(dbFormat.Key.Comp, tblKey)
	}
	err = TraverseDb(dbs, dbFormat, &dbresult, nil)
	if err != nil {
		log.Errorf("TraverseDb() failure for tbl(DB num) %v(%v) for xpath %v", tblName, cdb, xpath)
		return nil, err
	}
	if _, ok := dbresult[cdb]; !ok {
		logStr := fmt.Sprintf("TraverseDb() did not populate Db data for tbl(DB num) %v(%v) for xpath %v", tblName, cdb, xpath)
		err = fmt.Errorf("%v", logStr)
		return nil, err
	}
	return dbresult, err

}

// Assumption: All tables are from the same DB
func dbDataFromTblXfmrGet(tbl string, inParams XfmrParams, dbDataMap *map[db.DBNum]map[string]map[string]db.Value) error {
    // skip the query if the table is already visited
    if _,ok := (*dbDataMap)[inParams.curDb][tbl]; ok {
       if len(inParams.key) > 0 {
          if  _,ok = (*dbDataMap)[inParams.curDb][tbl][inParams.key]; ok {
             return nil
          }
       } else {
          return nil
       }
    }
    xpath, _ := XfmrRemoveXPATHPredicates(inParams.uri)
    curDbDataMap, err := fillDbDataMapForTbl(inParams.uri, xpath, tbl, inParams.key, inParams.curDb, inParams.dbs)
    if err == nil {
        mapCopy((*dbDataMap)[inParams.curDb], curDbDataMap[inParams.curDb])
    }
    return nil
}

func yangListDataFill(inParamsForGet xlateFromDbParams, isFirstCall bool) error {
	var tblList []string
	dbs := inParamsForGet.dbs
	ygRoot := inParamsForGet.ygRoot
	uri := inParamsForGet.uri
	requestUri := inParamsForGet.requestUri
	dbDataMap := inParamsForGet.dbDataMap
	txCache := inParamsForGet.txCache
	cdb := inParamsForGet.curDb
	resultMap := inParamsForGet.resultMap
	xpath := inParamsForGet.xpath
	tbl := inParamsForGet.tbl
	tblKey := inParamsForGet.tblKey


	_, ok := xYangSpecMap[xpath]
	if ok {
	if xYangSpecMap[xpath].xfmrTbl != nil {
		xfmrTblFunc := *xYangSpecMap[xpath].xfmrTbl
		if len(xfmrTblFunc) > 0 {
			inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, uri, requestUri, GET, tblKey, dbDataMap, nil, nil, txCache)
			tblList, _   = xfmrTblHandlerFunc(xfmrTblFunc, inParams)
			inParamsForGet.dbDataMap = dbDataMap
			inParamsForGet.ygRoot = ygRoot
			if len(tblList) != 0 {
				for _, curTbl := range tblList {
					dbDataFromTblXfmrGet(curTbl, inParams, dbDataMap)
					inParamsForGet.dbDataMap = dbDataMap
					inParamsForGet.ygRoot = ygRoot
				}
			}
		}
		if tbl != "" {
			if !contains(tblList, tbl) {
				tblList = append(tblList, tbl)
			}
		}
	} else if tbl != "" && xYangSpecMap[xpath].xfmrTbl == nil {
		tblList = append(tblList, tbl)
	} else if tbl == "" && xYangSpecMap[xpath].xfmrTbl == nil {
		// Handling for case: Parent list is not associated with a tableName but has children containers/lists having tableNames.
		if tblKey != "" {
			var mapSlice []typeMapOfInterface
			instMap, err := yangListInstanceDataFill(inParamsForGet, isFirstCall)
			dbDataMap = inParamsForGet.dbDataMap
			ygRoot = inParamsForGet.ygRoot
			if err != nil {
				log.Infof("Error(%v) returned for %v", err, uri)
			} else if ((instMap != nil)  && (len(instMap) > 0)) {
				mapSlice = append(mapSlice, instMap)
			}

			if len(mapSlice) > 0 {
				listInstanceGet := false
				// Check if it is a list instance level Get
				if ((strings.HasSuffix(uri, "]")) || (strings.HasSuffix(uri, "]/"))) {
					listInstanceGet = true
					for k, v := range mapSlice[0] {
						resultMap[k] = v
					}
				}
				if !listInstanceGet {
					resultMap[xYangSpecMap[xpath].yangEntry.Name] = mapSlice
				}
				inParamsForGet.resultMap = resultMap
			}
		}
	}
	}

	for _, tbl = range(tblList) {
		inParamsForGet.tbl = tbl

		tblData, ok := (*dbDataMap)[cdb][tbl]

		if ok {
			var mapSlice []typeMapOfInterface
			for dbKey, _ := range tblData {
				inParamsForGet.tblKey = dbKey
				instMap, err := yangListInstanceDataFill(inParamsForGet, isFirstCall)
				dbDataMap = inParamsForGet.dbDataMap
				ygRoot = inParamsForGet.ygRoot
				if err != nil {
					log.Infof("Error(%v) returned for %v", err, uri)
				} else if ((instMap != nil)  && (len(instMap) > 0)) {
					mapSlice = append(mapSlice, instMap)
				}
			}

			if len(mapSlice) > 0 {
				listInstanceGet := false
				/*Check if it is a list instance level Get*/
				if ((strings.HasSuffix(uri, "]")) || (strings.HasSuffix(uri, "]/"))) {
					listInstanceGet = true
					for k, v := range mapSlice[0] {
						resultMap[k] = v
					}
				}
				if !listInstanceGet {
					if _, specOk := xYangSpecMap[xpath]; specOk {
					if _, ok := resultMap[xYangSpecMap[xpath].yangEntry.Name]; ok {
						mlen := len(resultMap[xYangSpecMap[xpath].yangEntry.Name].([]typeMapOfInterface))
						for i := 0; i < mlen; i++ {
							mapSlice = append(mapSlice, resultMap[xYangSpecMap[xpath].yangEntry.Name].([]typeMapOfInterface)[i])
						}
					}
					resultMap[xYangSpecMap[xpath].yangEntry.Name] = mapSlice
					inParamsForGet.resultMap = resultMap
					}
				}
			} else {
				xfmrLogInfoAll("Empty slice for (\"%v\").\r\n", uri)
			}
		}
	}// end of tblList for

	return nil
}

func yangListInstanceDataFill(inParamsForGet xlateFromDbParams, isFirstCall bool) (typeMapOfInterface,error) {

	var err error
	curMap := make(map[string]interface{})
	err = nil
	dbs := inParamsForGet.dbs
	ygRoot := inParamsForGet.ygRoot
	uri := inParamsForGet.uri
	requestUri := inParamsForGet.requestUri
	dbDataMap := inParamsForGet.dbDataMap
	txCache := inParamsForGet.txCache
	cdb := inParamsForGet.curDb
	xpath := inParamsForGet.xpath
	tbl := inParamsForGet.tbl
	dbKey := inParamsForGet.tblKey

	curKeyMap, curUri, err := dbKeyToYangDataConvert(uri, requestUri, xpath, tbl, dbDataMap, dbKey, dbs[cdb].Opts.KeySeparator, txCache)
        if ((err != nil) || (curKeyMap == nil) || (len(curKeyMap) == 0)) {
                xfmrLogInfoAll("Skip filling list instance for uri %v since no yang  key found corresponding to db-key %v", uri, dbKey)
               return curMap, err
        }
	parentXpath := parentXpathGet(xpath)
	_, ok := xYangSpecMap[xpath]
	if ok && len(xYangSpecMap[xpath].xfmrFunc) > 0 {
		if isFirstCall || (!isFirstCall && (len(xYangSpecMap[parentXpath].xfmrFunc) == 0) ||
			(len(xYangSpecMap[parentXpath].xfmrFunc) > 0 && (xYangSpecMap[parentXpath].xfmrFunc != xYangSpecMap[xpath].xfmrFunc))) {
			xfmrLogInfoAll("Parent subtree already handled cur uri: %v", xpath)
			inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, curUri, requestUri, GET, dbKey, dbDataMap, nil, nil, txCache)
			err := xfmrHandlerFunc(inParams)
			inParamsForGet.ygRoot = ygRoot
			inParamsForGet.dbDataMap = dbDataMap
			if err != nil {
				xfmrLogInfoAll("Error returned by %v: %v", xYangSpecMap[xpath].xfmrFunc, err)
			}
		}
		if xYangSpecMap[xpath].hasChildSubTree == true {
			linParamsForGet := formXlateFromDbParams(dbs[cdb], dbs, cdb, ygRoot, curUri, requestUri, xpath, inParamsForGet.oper, tbl, dbKey, dbDataMap, inParamsForGet.txCache, curMap, inParamsForGet.validate)
			yangDataFill(linParamsForGet)
			curMap = linParamsForGet.resultMap
			dbDataMap = linParamsForGet.dbDataMap
			ygRoot = linParamsForGet.ygRoot
			inParamsForGet.dbDataMap = dbDataMap
			inParamsForGet.ygRoot = ygRoot
		}
	} else {
		_, keyFromCurUri, _, _ := xpathKeyExtract(dbs[cdb], ygRoot, GET, curUri, requestUri, nil, txCache)
		inParamsForGet.ygRoot = ygRoot
		if dbKey == keyFromCurUri || keyFromCurUri == "" {
			if dbKey == keyFromCurUri {
				for k, kv := range curKeyMap {
					curMap[k] = kv
				}
			}
			curXpath, _ := XfmrRemoveXPATHPredicates(curUri)
			linParamsForGet := formXlateFromDbParams(dbs[cdb], dbs, cdb, ygRoot, curUri, requestUri, curXpath, inParamsForGet.oper, tbl, dbKey, dbDataMap, inParamsForGet.txCache, curMap, inParamsForGet.validate)
			yangDataFill(linParamsForGet)
			curMap = linParamsForGet.resultMap
			dbDataMap = linParamsForGet.dbDataMap
			ygRoot = linParamsForGet.ygRoot
			inParamsForGet.dbDataMap = dbDataMap
			inParamsForGet.ygRoot = ygRoot
		}
	}
	return curMap, err
}

func terminalNodeProcess(inParamsForGet xlateFromDbParams) (map[string]interface{}, error) {
	xfmrLogInfoAll("Received xpath - %v, uri - %v, table - %v, table key - %v", inParamsForGet.xpath, inParamsForGet.uri, inParamsForGet.tbl, inParamsForGet.tblKey)
	var err error
	resFldValMap := make(map[string]interface{})
	xpath := inParamsForGet.xpath
	dbs := inParamsForGet.dbs
	ygRoot := inParamsForGet.ygRoot
	uri := inParamsForGet.uri
	tbl := inParamsForGet.tbl
	tblKey := inParamsForGet.tblKey
	requestUri := inParamsForGet.requestUri
	dbDataMap := inParamsForGet.dbDataMap
	txCache := inParamsForGet.txCache

	_, ok := xYangSpecMap[xpath]
	if !ok || xYangSpecMap[xpath].yangEntry == nil {
		logStr := fmt.Sprintf("No yang entry found for xpath %v.", xpath)
		err = fmt.Errorf("%v", logStr)
		return resFldValMap, err
	}

	cdb := xYangSpecMap[xpath].dbIndex
	if len(xYangSpecMap[xpath].xfmrField) > 0 {
		inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, uri, requestUri, GET, tblKey, dbDataMap, nil, nil, txCache)
		fldValMap, err := leafXfmrHandlerFunc(inParams)
		inParamsForGet.ygRoot = ygRoot
		inParamsForGet.dbDataMap = dbDataMap
		if err != nil {
			logStr := fmt.Sprintf("%Failed to get data from overloaded function for %v -v.", uri, err)
			err = fmt.Errorf("%v", logStr)
			return resFldValMap, err
		}
		if fldValMap != nil {
		    for lf, val := range fldValMap {
			resFldValMap[lf] = val
		    }
	        }
	} else {
		dbFldName := xYangSpecMap[xpath].fieldName
		if dbFldName == XFMR_NONE_STRING {
			return resFldValMap, err
		}
		/* if there is no transformer extension/annotation then it means leaf-list in yang is also leaflist in db */
		if len(dbFldName) > 0  && !xYangSpecMap[xpath].isKey {
			yangType := yangTypeGet(xYangSpecMap[xpath].yangEntry)
			yngTerminalNdDtType := xYangSpecMap[xpath].yangEntry.Type.Kind
			if yangType ==  YANG_LEAF_LIST {
				dbFldName += "@"
				val, ok := (*dbDataMap)[cdb][tbl][tblKey].Field[dbFldName]
				if ok {
					resLst := processLfLstDbToYang(xpath, val, yngTerminalNdDtType)
					resFldValMap[xYangSpecMap[xpath].yangEntry.Name] = resLst
				}
			} else {
				val, ok := (*dbDataMap)[cdb][tbl][tblKey].Field[dbFldName]
				if ok {
					resVal, _, err := DbToYangType(yngTerminalNdDtType, xpath, val)
					if err != nil {
						log.Error("Failure in converting Db value type to yang type for field", xpath)
					} else {
						resFldValMap[xYangSpecMap[xpath].yangEntry.Name] = resVal
					}
				}
			}
		}
	}
	return resFldValMap, err
}

func mergeMaps(mapIntfs ...map[string]interface{}) map[string]interface{} {
    resultMap := make(map[string]interface{})
    for _, mapIntf := range mapIntfs {
        for f, v := range mapIntf {
            resultMap[f] = v
        }
    }
    return resultMap
}

func yangDataFill(inParamsForGet xlateFromDbParams) error {
	var err error
	validate := inParamsForGet.validate
	isValid := validate
	dbs := inParamsForGet.dbs
	ygRoot := inParamsForGet.ygRoot
	uri := inParamsForGet.uri
	requestUri := inParamsForGet.requestUri
	dbDataMap := inParamsForGet.dbDataMap
	txCache := inParamsForGet.txCache
	cdb := inParamsForGet.curDb
	resultMap := inParamsForGet.resultMap
	xpath := inParamsForGet.xpath
	tblKey := inParamsForGet.tblKey
	var chldUri string

	yangNode, ok := xYangSpecMap[xpath]

	if ok  && yangNode.yangEntry != nil {
		for yangChldName := range yangNode.yangEntry.Dir {
			chldXpath := xpath+"/"+yangChldName
			if xYangSpecMap[chldXpath] != nil && xYangSpecMap[chldXpath].nameWithMod != nil {
				chldUri   = uri+"/"+ *(xYangSpecMap[chldXpath].nameWithMod)
			} else {
				chldUri   = uri+"/"+yangChldName
			}
			inParamsForGet.xpath = chldXpath
			inParamsForGet.uri = chldUri
			if xYangSpecMap[chldXpath] != nil && xYangSpecMap[chldXpath].yangEntry != nil {
				cdb = xYangSpecMap[chldXpath].dbIndex
				inParamsForGet.curDb = cdb
				if len(xYangSpecMap[chldXpath].validateFunc) > 0 && !validate {
					_, key, _, _ := xpathKeyExtract(dbs[cdb], ygRoot, GET, chldUri, requestUri, nil, txCache)
					inParamsForGet.ygRoot = ygRoot
					// TODO - handle non CONFIG-DB
					inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, chldUri, requestUri, GET, key, dbDataMap, nil, nil, txCache)
					res := validateHandlerFunc(inParams)
					if res != true {
						continue
					} else {
						isValid = res
					}
					inParamsForGet.validate = isValid
					inParamsForGet.dbDataMap = dbDataMap
					inParamsForGet.ygRoot = ygRoot
				}
				chldYangType := xYangSpecMap[chldXpath].yangDataType
				if  chldYangType == YANG_LEAF || chldYangType == YANG_LEAF_LIST {
					if len(xYangSpecMap[xpath].xfmrFunc) > 0 {
						continue
					}
					fldValMap, err := terminalNodeProcess(inParamsForGet)
					dbDataMap = inParamsForGet.dbDataMap
					ygRoot = inParamsForGet.ygRoot
					if err != nil {
						xfmrLogInfoAll("Failed to get data(\"%v\").", chldUri)
					}
					for lf, val := range fldValMap {
						resultMap[lf] = val
					}
					inParamsForGet.resultMap = resultMap
				} else if chldYangType == YANG_CONTAINER {
					_, tblKey, chtbl, _ := xpathKeyExtract(dbs[cdb], ygRoot, GET, chldUri, requestUri, nil, txCache)
					inParamsForGet.ygRoot = ygRoot
					if _, ok := (*dbDataMap)[cdb][chtbl]; !ok && len(chtbl) > 0 {
						curDbDataMap, err := fillDbDataMapForTbl(chldUri, chldXpath, chtbl, "", cdb, dbs)
						if err == nil {
							mapCopy((*dbDataMap)[cdb], curDbDataMap[cdb])
							inParamsForGet.dbDataMap = dbDataMap
						}
					}
					cname := xYangSpecMap[chldXpath].yangEntry.Name
					if xYangSpecMap[chldXpath].xfmrTbl != nil {
						xfmrTblFunc := *xYangSpecMap[chldXpath].xfmrTbl
						if len(xfmrTblFunc) > 0 {
							inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, chldUri, requestUri, GET, tblKey, dbDataMap, nil, nil, txCache)
							tblList, _ := xfmrTblHandlerFunc(xfmrTblFunc, inParams)
							inParamsForGet.dbDataMap = dbDataMap
							inParamsForGet.ygRoot = ygRoot
							if len(tblList) > 1 {
								log.Warningf("Table transformer returned more than one table for container %v", chldXpath)
							}
							if len(tblList) == 0 {
								continue
							}
							dbDataFromTblXfmrGet(tblList[0], inParams, dbDataMap)
							inParamsForGet.dbDataMap = dbDataMap
							inParamsForGet.ygRoot = ygRoot
							chtbl = tblList[0]
						}
					}
					if len(xYangSpecMap[chldXpath].xfmrFunc) > 0 {
						if (len(xYangSpecMap[xpath].xfmrFunc) == 0) ||
						(len(xYangSpecMap[xpath].xfmrFunc) > 0   &&
						(xYangSpecMap[xpath].xfmrFunc != xYangSpecMap[chldXpath].xfmrFunc)) {
							inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, chldUri, requestUri, GET, "", dbDataMap, nil, nil, txCache)
							err := xfmrHandlerFunc(inParams)
							inParamsForGet.dbDataMap = dbDataMap
							inParamsForGet.ygRoot = ygRoot
							if err != nil {
								xfmrLogInfoAll("Error returned by %v: %v", xYangSpecMap[xpath].xfmrFunc, err)
							}
						}
						if xYangSpecMap[chldXpath].hasChildSubTree == false {
							continue
						}
					}
					cmap2 := make(map[string]interface{})
					linParamsForGet := formXlateFromDbParams(dbs[cdb], dbs, cdb, ygRoot, chldUri, requestUri, chldXpath, inParamsForGet.oper, chtbl, tblKey, dbDataMap, inParamsForGet.txCache, cmap2, inParamsForGet.validate)
					err  = yangDataFill(linParamsForGet)
					cmap2 = linParamsForGet.resultMap
					dbDataMap = linParamsForGet.dbDataMap
					ygRoot = linParamsForGet.ygRoot
					if err != nil && len(cmap2) == 0 {
						xfmrLogInfoAll("Empty container.(\"%v\").\r\n", chldUri)
					} else {
						if len(cmap2) > 0 {
							resultMap[cname] = cmap2
						}
						inParamsForGet.resultMap = resultMap
					}
					inParamsForGet.dbDataMap = dbDataMap
					inParamsForGet.ygRoot = ygRoot
				} else if chldYangType ==  YANG_LIST {
					_, tblKey, _, _ = xpathKeyExtract(dbs[cdb], ygRoot, GET, chldUri, requestUri, nil, txCache)
					inParamsForGet.ygRoot = ygRoot
					cdb = xYangSpecMap[chldXpath].dbIndex
					inParamsForGet.curDb = cdb
					if len(xYangSpecMap[chldXpath].xfmrFunc) > 0 {
						if (len(xYangSpecMap[xpath].xfmrFunc) == 0) ||
						   (len(xYangSpecMap[xpath].xfmrFunc) > 0   &&
						   (xYangSpecMap[xpath].xfmrFunc != xYangSpecMap[chldXpath].xfmrFunc)) {
							   inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, chldUri, requestUri, GET, "", dbDataMap, nil, nil, txCache)
							   err := xfmrHandlerFunc(inParams)
							   if err != nil {
								   xfmrLogInfoAll("Error returned by %v: %v", xYangSpecMap[chldXpath].xfmrFunc, err)
							   }
							   inParamsForGet.dbDataMap = dbDataMap
							   inParamsForGet.ygRoot = ygRoot
						}
						if xYangSpecMap[chldXpath].hasChildSubTree == false {
							continue
						}
					}
					ynode, ok := xYangSpecMap[chldXpath]
					lTblName := ""
					if ok && ynode.tableName != nil {
						lTblName = *ynode.tableName
					}
					if _, ok := (*dbDataMap)[cdb][lTblName]; !ok && len(lTblName) > 0 {
						curDbDataMap, err := fillDbDataMapForTbl(chldUri, chldXpath, lTblName, "", cdb, dbs)
						if err == nil {
							mapCopy((*dbDataMap)[cdb], curDbDataMap[cdb])
							inParamsForGet.dbDataMap = dbDataMap
						}
					}
					linParamsForGet := formXlateFromDbParams(dbs[cdb], dbs, cdb, ygRoot, chldUri, requestUri, chldXpath, inParamsForGet.oper, lTblName, tblKey, dbDataMap, inParamsForGet.txCache, resultMap, inParamsForGet.validate)
					yangListDataFill(linParamsForGet, false)
					resultMap = linParamsForGet.resultMap
					dbDataMap = linParamsForGet.dbDataMap
					ygRoot = linParamsForGet.ygRoot
					inParamsForGet.dbDataMap = dbDataMap
					inParamsForGet.resultMap = resultMap
					inParamsForGet.ygRoot = ygRoot

				} else if chldYangType == "choice" || chldYangType == "case" {
					yangDataFill(inParamsForGet)
					resultMap = inParamsForGet.resultMap
					dbDataMap = inParamsForGet.dbDataMap
				} else {
					return err
				}
			}
		}
	}
	return err
}

/* Traverse linear db-map data and add to nested json data */
func dbDataToYangJsonCreate(inParamsForGet xlateFromDbParams) (string, error, bool) {
	var err error
	jsonData := ""
	resultMap := make(map[string]interface{})
        d := inParamsForGet.d
        dbs := inParamsForGet.dbs
        ygRoot := inParamsForGet.ygRoot
        uri := inParamsForGet.uri
        requestUri := inParamsForGet.requestUri
        dbDataMap := inParamsForGet.dbDataMap
        txCache := inParamsForGet.txCache
	cdb := inParamsForGet.curDb
	inParamsForGet.resultMap = resultMap

	if isSonicYang(uri) {
		return directDbToYangJsonCreate(inParamsForGet)
	} else {
		reqXpath, keyName, tableName, _ := xpathKeyExtract(d, ygRoot, GET, uri, requestUri, nil, txCache)
		inParamsForGet.xpath = reqXpath
		inParamsForGet.tbl = tableName
		inParamsForGet.tblKey = keyName
		inParamsForGet.ygRoot = ygRoot
		yangNode, ok := xYangSpecMap[reqXpath]
		if ok {
			yangType := yangTypeGet(yangNode.yangEntry)
			validateHandlerFlag := false
			tableXfmrFlag := false
			IsValidate := false
			if len(xYangSpecMap[reqXpath].validateFunc) > 0 {
				inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, uri, requestUri, GET, keyName, dbDataMap, nil, nil, txCache)
				res := validateHandlerFunc(inParams)
				inParamsForGet.dbDataMap = dbDataMap
				inParamsForGet.ygRoot = ygRoot
				if !res {
					validateHandlerFlag = true
					/* cannot immediately return from here since reXpath yangtype decides the return type */
				} else {
					IsValidate = res
				}
			}
			inParamsForGet.validate = IsValidate
			isList := false
			switch yangType {
			case YANG_LIST:
				isList = true
			case YANG_LEAF, YANG_LEAF_LIST, YANG_CONTAINER:
				isList = false
			default:
				xfmrLogInfo("Unknown yang object type for path %v", reqXpath)
				isList = true //do not want non-list processing to happen
			}
			/*If yangtype is a list separate code path is to be taken in case of table transformer
			since that code path already handles the calling of table transformer and subsequent processing
			*/
			if (!validateHandlerFlag) && (!isList) {
				if xYangSpecMap[reqXpath].xfmrTbl != nil {
					xfmrTblFunc := *xYangSpecMap[reqXpath].xfmrTbl
					if len(xfmrTblFunc) > 0 {
						inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, uri, requestUri, GET, keyName, dbDataMap, nil, nil, txCache)
						tblList, _ := xfmrTblHandlerFunc(xfmrTblFunc, inParams)
						inParamsForGet.dbDataMap = dbDataMap
						inParamsForGet.ygRoot = ygRoot
						if len(tblList) > 1 {
							log.Warningf("Table transformer returned more than one table for container %v", reqXpath)
						}
						if len(tblList) == 0 {
							log.Warningf("Table transformer returned no table for conatiner %v", reqXpath)
							tableXfmrFlag = true
						}
						if !tableXfmrFlag {
                                                      for _, tbl := range tblList {
                                                               dbDataFromTblXfmrGet(tbl, inParams, dbDataMap)
							       inParamsForGet.dbDataMap = dbDataMap
							       inParamsForGet.ygRoot = ygRoot
                                                      }

						}
					} else {
						log.Warningf("empty table transformer function name for xpath - %v", reqXpath)
						tableXfmrFlag = true
					}
				}
			}

			for {
				if yangType ==  YANG_LEAF || yangType == YANG_LEAF_LIST {
					yangName := xYangSpecMap[reqXpath].yangEntry.Name
					if validateHandlerFlag || tableXfmrFlag {
						resultMap[yangName] = ""
						break
					}
					if len(xYangSpecMap[reqXpath].xfmrFunc) > 0 {
						inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, uri, requestUri, GET, "", dbDataMap, nil, nil, txCache)
						err := xfmrHandlerFunc(inParams)
						if err != nil {
							xfmrLogInfo("Error returned by %v: %v", xYangSpecMap[reqXpath].xfmrFunc, err)
						}
						inParamsForGet.dbDataMap = dbDataMap
						inParamsForGet.ygRoot = ygRoot
					} else {
						tbl, key, _ := tableNameAndKeyFromDbMapGet((*dbDataMap)[cdb])
						inParamsForGet.tbl = tbl
						inParamsForGet.tblKey = key
						fldValMap, err := terminalNodeProcess(inParamsForGet)
						if err != nil {
							xfmrLogInfo("Empty terminal node (\"%v\").", uri)
						}
						dbDataMap = inParamsForGet.dbDataMap
						ygRoot = inParamsForGet.ygRoot
						resultMap = fldValMap
					}
					break

				} else if yangType == YANG_CONTAINER {
					cmap  := make(map[string]interface{})
					resultMap = cmap
					if validateHandlerFlag || tableXfmrFlag {
						break
					}
					if len(xYangSpecMap[reqXpath].xfmrFunc) > 0 {
						inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, uri, requestUri, GET, "", dbDataMap, nil, nil, txCache)
						err := xfmrHandlerFunc(inParams)
						if err != nil {
							xfmrLogInfo("Error returned by %v: %v", xYangSpecMap[reqXpath].xfmrFunc, err)
						}
						inParamsForGet.dbDataMap = dbDataMap
						inParamsForGet.ygRoot = ygRoot
						if xYangSpecMap[reqXpath].hasChildSubTree == false {
							break
						}
					}
					inParamsForGet.resultMap = make(map[string]interface{})
					err = yangDataFill(inParamsForGet)
					if err != nil {
						xfmrLogInfo("Empty container(\"%v\").\r\n", uri)
					}
					dbDataMap = inParamsForGet.dbDataMap
					ygRoot = inParamsForGet.ygRoot
					resultMap = inParamsForGet.resultMap
					break
				} else if yangType == YANG_LIST {
					isFirstCall := true
					if len(xYangSpecMap[reqXpath].xfmrFunc) > 0 {
						inParams := formXfmrInputRequest(dbs[cdb], dbs, cdb, ygRoot, uri, requestUri, GET, "", dbDataMap, nil, nil, txCache)
						err := xfmrHandlerFunc(inParams)
						if err != nil {
							xfmrLogInfo("Error returned by %v: %v", xYangSpecMap[reqXpath].xfmrFunc, err)
						}
						isFirstCall = false
						inParamsForGet.dbDataMap = dbDataMap
						inParamsForGet.ygRoot = ygRoot
						if xYangSpecMap[reqXpath].hasChildSubTree == false {
							break
						}
					}
					inParamsForGet.resultMap = make(map[string]interface{})
					err = yangListDataFill(inParamsForGet, isFirstCall)
					if err != nil {
						xfmrLogInfo("yangListDataFill failed for list case(\"%v\").\r\n", uri)
					}
					dbDataMap = inParamsForGet.dbDataMap
					ygRoot = inParamsForGet.ygRoot
					resultMap = inParamsForGet.resultMap
					break
				} else {
					log.Warningf("Unknown yang object type for path %v", reqXpath)
					break
				}
			} //end of for
		}
	}

	jsonMapData, _ := json.Marshal(resultMap)
	isEmptyPayload := isJsonDataEmpty(string(jsonMapData))
	jsonData        = fmt.Sprintf("%v", string(jsonMapData))

	return jsonData, nil, isEmptyPayload
}
