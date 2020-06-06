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
	"errors"
	"github.com/Azure/sonic-mgmt-common/translib/db"
)

func tblKeyDataGet(xlateParams xlateToParams, dbDataMap *map[db.DBNum]map[string]map[string]db.Value, cdb db.DBNum) ([]string, error) {
	var err error
	var dbs [db.MaxDB]*db.DB
	var tblList []string
	dbs[cdb] = xlateParams.d

	xfmrLogInfoAll("Get table data for  (\"%v\")", xlateParams.uri)
	if (xYangSpecMap[xlateParams.xpath].tableName != nil) && (len(*xYangSpecMap[xlateParams.xpath].tableName) > 0) {
		tblList = append(tblList, *xYangSpecMap[xlateParams.xpath].tableName)
	} else if xYangSpecMap[xlateParams.xpath].xfmrTbl != nil {
		xfmrTblFunc := *xYangSpecMap[xlateParams.xpath].xfmrTbl
		if len(xfmrTblFunc) > 0 {
			inParams := formXfmrInputRequest(xlateParams.d, dbs, cdb, xlateParams.ygRoot, xlateParams.uri, xlateParams.requestUri, xlateParams.oper, xlateParams.keyName, dbDataMap, nil, nil, xlateParams.txCache)
			tblList, err = xfmrTblHandlerFunc(xfmrTblFunc, inParams)
			if err != nil {
				return tblList, err
			}
		}
	}
	tbl := xlateParams.tableName
	if tbl != "" {
		if !contains(tblList, tbl) {
			tblList = append(tblList, tbl)
		}
	}
	return tblList, err
}

func subTreeXfmrDelDataGet(xlateParams xlateToParams, dbDataMap *map[db.DBNum]map[string]map[string]db.Value, cdb db.DBNum, spec *yangXpathInfo, chldSpec *yangXpathInfo, subTreeResMap *map[string]map[string]db.Value) error {
	var dbs [db.MaxDB]*db.DB
	dbs[cdb]   = xlateParams.d

	xfmrLogInfoAll("Handle subtree for  (\"%v\")", xlateParams.uri)
	if (len(chldSpec.xfmrFunc) > 0) {
		if ((len(spec.xfmrFunc) == 0) || ((len(spec.xfmrFunc) > 0) &&
		(spec.xfmrFunc != chldSpec.xfmrFunc))) {
			inParams := formXfmrInputRequest(xlateParams.d, dbs, cdb, xlateParams.ygRoot, xlateParams.uri, xlateParams.requestUri, xlateParams.oper, "",
			                                 dbDataMap, xlateParams.subOpDataMap, nil, xlateParams.txCache)
			retMap, err := xfmrHandler(inParams, chldSpec.xfmrFunc)
			if err != nil {
				xfmrLogInfoAll("Error returned by %v: %v", chldSpec.xfmrFunc, err)
				return err
			}
			mapCopy(*subTreeResMap, retMap)
                        if xlateParams.pCascadeDelTbl != nil && len(*inParams.pCascadeDelTbl) > 0 {
                            for _, tblNm :=  range *inParams.pCascadeDelTbl {
                                if !contains(*xlateParams.pCascadeDelTbl, tblNm) {
                                    *xlateParams.pCascadeDelTbl = append(*xlateParams.pCascadeDelTbl, tblNm)
                                }
                            }
                        }
		}
	}
	return nil
}

func yangListDelData(xlateParams xlateToParams, dbDataMap *map[db.DBNum]map[string]map[string]db.Value, subTreeResMap *map[string]map[string]db.Value) error {
	var err error
	var dbs [db.MaxDB]*db.DB

	spec, ok := xYangSpecMap[xlateParams.xpath]
	if ok && (spec.dbIndex == db.ConfigDB) {
		var tblList []string
		cdb       := spec.dbIndex
		dbs[cdb]   = xlateParams.d
		dbOpts    := getDBOptions(cdb)
		separator := dbOpts.KeySeparator

		_, keyName, tbl, err := xpathKeyExtract(xlateParams.d, xlateParams.ygRoot, xlateParams.oper, xlateParams.uri, xlateParams.requestUri, xlateParams.subOpDataMap, xlateParams.txCache)
		if err != nil {
			return err
		}

		xlateParams.tableName = tbl
		xlateParams.keyName = keyName
		tblList, err = tblKeyDataGet(xlateParams, dbDataMap, cdb)
		if err != nil {
			return err
		}

		xfmrLogInfoAll("tblList(%v), tbl(%v), key(%v)  for uri (\"%v\")", tblList, tbl,  keyName, xlateParams.uri)
		for _, tbl := range(tblList) {
			curDbDataMap, ferr := fillDbDataMapForTbl(xlateParams.uri, xlateParams.xpath, tbl, keyName, cdb, dbs)
			if ((ferr == nil) && len(curDbDataMap) > 0) {
				mapCopy((*dbDataMap)[cdb], curDbDataMap[cdb])
			}
		}

		for _, tbl := range(tblList) {
			tblData, ok := (*dbDataMap)[cdb][tbl]
			if ok {
				for dbKey, _ := range tblData {
					_, curUri, kerr := dbKeyToYangDataConvert(xlateParams.uri, xlateParams.requestUri, xlateParams.xpath, tbl, dbDataMap, dbKey, separator, xlateParams.txCache)
					if kerr != nil {
						continue
					}
					for yangChldName := range spec.yangEntry.Dir {
						chldXpath    := xlateParams.xpath+"/"+yangChldName
						chldUri      := curUri+"/"+yangChldName
						chldSpec, ok := xYangSpecMap[chldXpath]
						if (ok && (chldSpec.dbIndex == db.ConfigDB) && chldSpec.hasChildSubTree &&
						(chldSpec.yangEntry != nil)) {
							chldYangType := chldSpec.yangDataType
							curXlateParams := xlateParams
							curXlateParams.uri = chldUri
							curXlateParams.xpath = chldXpath
							curXlateParams.tableName = ""
							curXlateParams.keyName = ""

							if ((chldYangType == YANG_CONTAINER || chldYangType == YANG_LIST) &&
							    (len(chldSpec.xfmrFunc) > 0)) {
								err = subTreeXfmrDelDataGet(curXlateParams, dbDataMap, cdb, spec, chldSpec, subTreeResMap)
								if err != nil {
									return err
								}
							}
							if chldSpec.hasChildSubTree == true {
								if chldYangType == YANG_CONTAINER {
									err = yangContainerDelData(curXlateParams, dbDataMap, subTreeResMap)
									if err != nil {
										return err
									}
								} else if chldYangType == YANG_LIST {
									err = yangListDelData(curXlateParams, dbDataMap, subTreeResMap)
									if err != nil {
										return err
									}
								}
							}
						}
					}
				}
			}
        }

    }
	return err
}

func yangContainerDelData(xlateParams xlateToParams, dbDataMap *map[db.DBNum]map[string]map[string]db.Value, subTreeResMap *map[string]map[string]db.Value) error {
	var err error
	var dbs [db.MaxDB]*db.DB
	spec, _ := xYangSpecMap[xlateParams.xpath]
	cdb     := spec.dbIndex
	dbs[cdb] = xlateParams.d

	xfmrLogInfoAll("Parse container for subtree-xfmr(\"%v\")", xlateParams.uri)
	for yangChldName := range spec.yangEntry.Dir {
		chldXpath    := xlateParams.xpath+"/"+yangChldName
		chldUri      := xlateParams.uri+"/"+yangChldName
		chldSpec, ok := xYangSpecMap[chldXpath]
		if (ok && (chldSpec.dbIndex == db.ConfigDB) && (chldSpec.yangEntry != nil)) {
			chldYangType := chldSpec.yangDataType
			curXlateParams := xlateParams
			curXlateParams.uri = chldUri
			curXlateParams.xpath = chldXpath

			if ((chldYangType == YANG_CONTAINER || chldYangType == YANG_LIST) && (len(chldSpec.xfmrFunc) > 0)) {
				err = subTreeXfmrDelDataGet(curXlateParams, dbDataMap, cdb, spec, chldSpec, subTreeResMap)
				if err != nil {
					return err
				}
			}
			if xYangSpecMap[chldXpath].hasChildSubTree == true {
				if chldYangType == YANG_CONTAINER {
					err = yangContainerDelData(curXlateParams, dbDataMap, subTreeResMap)
					if err != nil {
						return err
					}
				} else if chldYangType == YANG_LIST {
					err = yangListDelData(curXlateParams, dbDataMap, subTreeResMap)
					if err != nil {
						return err
					}
				}
			}
		}
	}
	return err
}

func allChildTblGetToDelete(xlateParams xlateToParams) (map[string]map[string]db.Value, error) {
	var err error
	subTreeResMap := make(map[string]map[string]db.Value)
	xpath, _ := XfmrRemoveXPATHPredicates(xlateParams.requestUri)
	spec, ok := xYangSpecMap[xpath]

	if !ok {
		errStr := "Xpath not found in spec-map:" + xpath
		return subTreeResMap, errors.New(errStr)
	}

	dbDataMap := make(RedisDbMap)
	for i := db.ApplDB; i < db.MaxDB; i++ {
		dbDataMap[i] = make(map[string]map[string]db.Value)
	}

	xfmrLogInfoAll("Req-uri (\"%v\") has subtree-xfmr", xlateParams.requestUri)
	if ok && spec.yangEntry != nil {
		xlateParams.uri = xlateParams.requestUri
		xlateParams.xpath = xpath
		if (spec.yangDataType == YANG_LIST) {
			err = yangListDelData(xlateParams, &dbDataMap, &subTreeResMap)
			return subTreeResMap, err
		} else if (spec.yangDataType == YANG_CONTAINER) {
			err = yangContainerDelData(xlateParams, &dbDataMap, &subTreeResMap)
		}
	}
	return subTreeResMap, err
}

/* Get the db table, key and field name for the incoming delete request */
func dbMapDelete(d *db.DB, ygRoot *ygot.GoStruct, oper int, uri string, requestUri string, jsonData interface{}, resultMap map[int]map[db.DBNum]map[string]map[string]db.Value, txCache interface{}, skipOrdTbl *bool) error {
	var err error
	var result = make(map[string]map[string]db.Value)
	subOpDataMap := make(map[int]*RedisDbMap)
	var xfmrErr error
	*skipOrdTbl = false
	var cascadeDelTbl []string

	for i := 0; i < MAXOPER; i++ {
		resultMap[i] = make(map[db.DBNum]map[string]map[string]db.Value)
	}

	if isSonicYang(uri) {
		*skipOrdTbl = true
		xpathPrefix, keyName, tableName := sonicXpathKeyExtract(uri)
		xfmrLogInfo("Delete req: uri(\"%v\"), key(\"%v\"), xpathPrefix(\"%v\"), tableName(\"%v\").", uri, keyName, xpathPrefix, tableName)
		resultMap[oper][db.ConfigDB] = result
		xlateToData := formXlateToDbParam(d, ygRoot, oper, uri, requestUri, xpathPrefix, keyName, jsonData, resultMap, result, txCache, nil, subOpDataMap, &cascadeDelTbl, &xfmrErr, "","",tableName)
		err = sonicYangReqToDbMapDelete(xlateToData)
	} else {
		xpathPrefix, keyName, tableName, err := xpathKeyExtract(d, ygRoot, oper, uri, requestUri, subOpDataMap, txCache)
		if err != nil {
			return err
		}
		xfmrLogInfo("Delete req: uri(\"%v\"), key(\"%v\"), xpathPrefix(\"%v\"), tableName(\"%v\").", uri, keyName, xpathPrefix, tableName)
		spec, ok := xYangSpecMap[xpathPrefix]
		if ok {
			specYangType := yangTypeGet(spec.yangEntry)
			moduleNm := "/" + strings.Split(uri, "/")[1]
			xfmrLogInfo("Module name for uri %s is %s", uri, moduleNm)
			if spec.cascadeDel == XFMR_ENABLE && tableName != "" && tableName != XFMR_NONE_STRING {
				if !contains(cascadeDelTbl, tableName) {
					cascadeDelTbl = append(cascadeDelTbl, tableName)
				}
			}
			curXlateParams := formXlateToDbParam(d, ygRoot, oper, uri, requestUri, xpathPrefix, keyName, jsonData, resultMap, result, txCache, nil, subOpDataMap, &cascadeDelTbl, &xfmrErr, "", "", tableName)
			if len(spec.xfmrFunc) > 0 {
				var dbs [db.MaxDB]*db.DB
				cdb := spec.dbIndex
				inParams := formXfmrInputRequest(d, dbs, cdb, ygRoot, uri, requestUri, oper, "", nil, subOpDataMap, nil, txCache)
				stRetData, err := xfmrHandler(inParams, spec.xfmrFunc)
				if err == nil {
					mapCopy(result, stRetData)
				} else {
					return err
				}
				if inParams.pCascadeDelTbl != nil && len(*inParams.pCascadeDelTbl) > 0 {
					for _, tblNm :=  range *inParams.pCascadeDelTbl {
						if !contains(cascadeDelTbl, tblNm) {
							cascadeDelTbl = append(cascadeDelTbl, tblNm)
						}
					}
				}
			} else if len(tableName) > 0 {
				result[tableName] = make(map[string]db.Value)
				if len(keyName) > 0 {
					result[tableName][keyName] = db.Value{Field: make(map[string]string)}
					xpath := xpathPrefix
					uriItemList := strings.Split(strings.TrimSuffix(uri, "/"), "/")
					uriItemListLen := len(uriItemList)
					var terminalNode, luri string
					if uriItemListLen > 0 {
						terminalNode = uriItemList[uriItemListLen-1]
						luri = strings.Join(uriItemList[:uriItemListLen-1], "/") //strip off the leaf/leaf-list for mapFillDataUtil takes uri without it

					}
					if specYangType == YANG_LEAF {
						_, ok := xYangSpecMap[xpath]
						if ok && len(xYangSpecMap[xpath].defVal) > 0 {
							// Do not fill def value if leaf does not map to any redis field
							dbSpecXpath := tableName + "/" + xYangSpecMap[xpath].fieldName
							_, mapped := xDbSpecMap[dbSpecXpath]
							if mapped || len(xYangSpecMap[xpath].xfmrField) > 0 {
								curXlateParams.uri = luri
								curXlateParams.name = spec.fieldName
								curXlateParams.value = xYangSpecMap[xpath].defVal
								err = mapFillDataUtil(curXlateParams)
								if xfmrErr != nil {
									return xfmrErr
								}
								if err != nil {
									return err
								}
								if len(subOpDataMap) > 0 && subOpDataMap[UPDATE] != nil {
									subOperMap := subOpDataMap[UPDATE]
									mapCopy((*subOperMap)[db.ConfigDB], result)
								} else {
									var redisMap = new(RedisDbMap)
									var dbresult = make(RedisDbMap)
									for i := db.ApplDB; i < db.MaxDB; i++ {
										dbresult[i] = make(map[string]map[string]db.Value)
									}
									redisMap = &dbresult
									(*redisMap)[db.ConfigDB] = result
									subOpDataMap[UPDATE]     = redisMap
								}
							}
							result = make(map[string]map[string]db.Value)
						} else {
							curXlateParams.uri = luri
							curXlateParams.name = spec.fieldName
							err = mapFillDataUtil(curXlateParams)
							if xfmrErr != nil {
								return xfmrErr
							}
							if err != nil {
								return err
							}
						}
					} else if specYangType == YANG_LEAF_LIST {
						var fieldVal []interface{}
						if strings.Contains(terminalNode, "[") {
							terminalNodeData := strings.TrimSuffix(strings.SplitN(terminalNode, "[", 2)[1], "]")
							terminalNodeDataLst := strings.SplitN(terminalNodeData, "=", 2)
							terminalNodeVal := terminalNodeDataLst[1]
							fieldVal = append(fieldVal, terminalNodeVal)
						}
						curXlateParams.uri = luri
						curXlateParams.name = spec.yangEntry.Name
						curXlateParams.value = fieldVal
						err = mapFillDataUtil(curXlateParams)

						if xfmrErr != nil {
							return xfmrErr
						}
						if err != nil {
							return err
						}
					} else if (spec.hasChildSubTree == true) {
						if (spec.tblOwner != nil) && (*spec.tblOwner == false) {
							err = tableFieldsForUriGet(uri, spec, result)
							if err != nil {
								return err
							}
						}
						xfmrLogInfoAll("Uri(\"%v\") has child subtree-xfmr", uri)
						curResult, cerr := allChildTblGetToDelete(curXlateParams)
						if cerr != nil {
							err = cerr
						} else {
							mapCopy(result, curResult)
						}
					} else if (spec.tblOwner != nil) && (*spec.tblOwner == false) {
						err = tableFieldsForUriGet(uri, spec, result)
						if err != nil {
							return err
						}
					}
				} else if (spec.hasChildSubTree == true) {
					xfmrLogInfoAll("Uri(\"%v\") has child subtree-xfmr", uri)
					curResult, cerr := allChildTblGetToDelete(curXlateParams)
					if cerr != nil {
						err = cerr
					} else {
						mapCopy(result, curResult)
					}
				}
			} else if len(spec.childTable) > 0 {
				if (spec.hasChildSubTree == true) {
					xfmrLogInfoAll("Uri(\"%v\") has child subtree-xfmr", uri)
					result, err = allChildTblGetToDelete(curXlateParams)
				}
				chResult := make(map[string]map[string]db.Value)
				for _, child := range spec.childTable {
					chResult[child] = make(map[string]db.Value)
				}
				log.Infof("Before Merge result: %v  result with  child tables: %v", result, chResult)
				mapCopy(result, chResult)
				log.Infof("Merged result tables with child tables: %v", result)

			} else {
				if (spec.hasChildSubTree == true) {
					xfmrLogInfoAll("Uri(\"%v\") has child subtree-xfmr", uri)
					result, err = allChildTblGetToDelete(curXlateParams)
				}
			}
			if err != nil {
				return err
			}

			_, ok := xYangSpecMap[moduleNm]
			if ok && len(xYangSpecMap[moduleNm].xfmrPost) > 0 {
				xfmrLogInfo("Invoke post transformer: %v", xYangSpecMap[moduleNm].xfmrPost)
				var dbs [db.MaxDB]*db.DB
				var dbresult = make(RedisDbMap)
				dbresult[db.ConfigDB] = result
				inParams := formXfmrInputRequest(d, dbs, db.ConfigDB, ygRoot, uri, requestUri, oper, "", &dbresult, subOpDataMap, nil, txCache)
				result, err = postXfmrHandlerFunc(xYangSpecMap[moduleNm].xfmrPost, inParams)
				if err != nil {
					return err
				}
				if inParams.skipOrdTblChk != nil {
					*skipOrdTbl = *(inParams.skipOrdTblChk)
					xfmrLogInfo("skipOrdTbl flag: %v", *skipOrdTbl)
				}
				if inParams.pCascadeDelTbl != nil && len(*inParams.pCascadeDelTbl) > 0 {
					for _, tblNm :=  range *inParams.pCascadeDelTbl {
						if !contains(cascadeDelTbl, tblNm) {
							cascadeDelTbl = append(cascadeDelTbl, tblNm)
						}
					}
				}
			}

			if len(result) > 0 {
				resultMap[oper][db.ConfigDB] = result
			}

			if len(subOpDataMap) > 0 {
				for op, data := range subOpDataMap {
					if len(*data) > 0 {
						for dbType, dbData := range (*data) {
							if len(dbData) > 0 {
								if _, ok := resultMap[op][dbType]; !ok {
									resultMap[op][dbType] = make(map[string]map[string]db.Value)
								}
								mapCopy(resultMap[op][dbType], (*subOpDataMap[op])[dbType])
							}
						}
					}
				}

			}
			/* for container/list delete req , it should go through, even if there are any leaf default-yang-values */
		}
	}

	err = dbDataXfmrHandler(resultMap)
	if err != nil {
		log.Errorf("Failed in dbdata-xfmr for %v", resultMap)
		return err
	}
	if (len(cascadeDelTbl) > 0) {
		cdErr := handleCascadeDelete(d, resultMap, cascadeDelTbl)
		if cdErr != nil {
			xfmrLogInfo("Cascade Delete Failed for cascadeDelTbl (%v), Error: (%v)", cascadeDelTbl, cdErr)
			return cdErr
		}
	}

	printDbData(resultMap, nil, "/tmp/yangToDbDataDel.txt")
	xfmrLogInfo("Delete req: uri(\"%v\") resultMap(\"%v\").", uri, resultMap)
	return err
}

func sonicYangReqToDbMapDelete(xlateParams xlateToParams) error {
	var err error
	if (xlateParams.tableName != "") {
		// Specific table entry case
		xlateParams.result[xlateParams.tableName] = make(map[string]db.Value)
		if (xlateParams.keyName != "") {
			// Specific key case
			var dbVal db.Value
			tokens:= strings.Split(xlateParams.xpath, "/")
			if tokens[SONIC_TABLE_INDEX] == xlateParams.tableName {
				fieldName := ""
				if len(tokens) > SONIC_FIELD_INDEX {
					fieldName = tokens[SONIC_FIELD_INDEX]
				}

				if fieldName != "" {
					dbSpecField := xlateParams.tableName + "/" + fieldName
					_, ok := xDbSpecMap[dbSpecField]
					if ok {
						yangType := xDbSpecMap[dbSpecField].fieldType
						// terminal node case
						if yangType == YANG_LEAF_LIST {
							dbVal.Field = make(map[string]string)
							//check if it is a specific item in leaf-list delete
							uriItemList := strings.Split(strings.TrimSuffix(xlateParams.requestUri, "/"), "/")
							uriItemListLen := len(uriItemList)
							var terminalNode string
							if uriItemListLen > 0 {
								terminalNode = uriItemList[uriItemListLen-1]
								dbFldVal := ""
								if strings.Contains(terminalNode, "[") {
									terminalNodeData := strings.TrimSuffix(strings.SplitN(terminalNode, "[", 2)[1], "]")
									terminalNodeDataLst := strings.SplitN(terminalNodeData, "=", 2)
									terminalNodeVal := terminalNodeDataLst[1]
									dbFldVal, err = unmarshalJsonToDbData(xDbSpecMap[dbSpecField].dbEntry, dbSpecField, fieldName, terminalNodeVal)
									if err != nil {
										log.Errorf("Failed to unmashal Json to DbData: path(\"%v\") error (\"%v\").", dbSpecField, err)
										return err
									}
								}
								fieldName = fieldName + "@"
								dbVal.Field[fieldName] = dbFldVal
							}
						}
						if yangType == YANG_LEAF {
							dbVal.Field = make(map[string]string)
							dbVal.Field[fieldName] = ""
						}
					}
				}
			}
			xlateParams.result[xlateParams.tableName][xlateParams.keyName] = dbVal
		} else {
			// Get all keys
		}
	} else {
		// Get all table entries
		// If table name not available in xpath get top container name
		_, ok := xDbSpecMap[xlateParams.xpath]
		if ok && xDbSpecMap[xlateParams.xpath] != nil {
			dbInfo := xDbSpecMap[xlateParams.xpath]
			if dbInfo.fieldType == "container" {
				for dir, _ := range dbInfo.dbEntry.Dir {
					if dbInfo.dbEntry.Dir[dir].Config != yang.TSFalse {
						xlateParams.result[dir] = make(map[string]db.Value)
					}
				}
			}
		}
	}
	return nil
}

func tableFieldsForUriGet(uri string, spec *yangXpathInfo, result map[string]map[string]db.Value) error {
	return nil
}
