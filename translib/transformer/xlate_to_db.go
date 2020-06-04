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
    "github.com/openconfig/ygot/ygot"
    "os"
    "reflect"
    "strings"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/openconfig/ygot/ytypes"
    "github.com/openconfig/goyang/pkg/yang"
    log "github.com/golang/glog"
)

var ocbSch, _ = ocbinds.Schema()

/* Fill redis-db map with field & value info */
func dataToDBMapAdd(tableName string, dbKey string, result map[string]map[string]db.Value, field string, value string) {
    _, ok := result[tableName]
    if !ok {
        result[tableName] = make(map[string]db.Value)
    }

    _, ok = result[tableName][dbKey]
    if !ok {
        result[tableName][dbKey] = db.Value{Field: make(map[string]string)}
    }

	if field == XFMR_NONE_STRING {
		if len(result[tableName][dbKey].Field) == 0 {
			result[tableName][dbKey].Field["NULL"] = "NULL"
		}
		return
	}

    result[tableName][dbKey].Field[field] = value
    return
}

/*use when single table name is expected*/
func tblNameFromTblXfmrGet(xfmrTblFunc string, inParams XfmrParams) (string, error){
	var err error
	var tblList []string
	tblList, err = xfmrTblHandlerFunc(xfmrTblFunc, inParams)
	if err != nil {
		return "", err
	}
	if len(tblList) != 1 {
		xfmrLogInfoAll("Uri (\"%v\") translates to 0 or multiple tables instead of single table - %v", inParams.uri, tblList)
		return "", err
	}
	return tblList[0], err
}

/* Fill the redis-db map with data */
func mapFillData(xlateParams xlateToParams) error {
	var dbs [db.MaxDB]*db.DB
	var err error
    xpath := xlateParams.xpath + "/" + xlateParams.name
    xpathInfo, ok := xYangSpecMap[xpath]
    xfmrLogInfoAll("name: \"%v\", xpathPrefix(\"%v\").", xlateParams.name, xlateParams.xpath)

    if !ok || xpathInfo == nil {
        log.Errorf("Yang path(\"%v\") not found.", xpath)
	return nil
    }

    if xpathInfo.tableName == nil && xpathInfo.xfmrTbl == nil{
        log.Errorf("Table for yang-path(\"%v\") not found.", xpath)
	return nil
    }

    if xpathInfo.tableName != nil && *xpathInfo.tableName == XFMR_NONE_STRING {
        log.Errorf("Table for yang-path(\"%v\") NONE.", xpath)
	return nil
    }

    if len(xlateParams.keyName) == 0 {
        log.Errorf("Table key for yang path(\"%v\") not found.", xpath)
	return nil
    }

    tableName := ""
    if xpathInfo.xfmrTbl != nil {
	    inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, xlateParams.uri, xlateParams.requestUri, xlateParams.oper, "", nil, xlateParams.subOpDataMap, "", xlateParams.txCache)
	    // expecting only one table name from tbl-xfmr
	    tableName, err = tblNameFromTblXfmrGet(*xYangSpecMap[xpath].xfmrTbl, inParams)
	    if err != nil {
		    if xlateParams.xfmrErr != nil && *xlateParams.xfmrErr == nil {
			    *xlateParams.xfmrErr = err
		    }
		    return err
	    }
	    if tableName == "" {
		    log.Warningf("No table name found for uri (\"%v\")", xlateParams.uri)
		    return err
	    }
	    // tblXpathMap used for default value processing for a given request
	    if tblUriMapVal, tblUriMapOk := xlateParams.tblXpathMap[tableName]; !tblUriMapOk {
		    tblUriMapVal = map[string]bool{xlateParams.uri: true}
		    xlateParams.tblXpathMap[tableName] = tblUriMapVal
	    } else {
		    if tblUriMapVal == nil {
			    tblUriMapVal = map[string]bool{xlateParams.uri: true}
		    } else {
			    tblUriMapVal[xlateParams.uri] = true
		    }
		    xlateParams.tblXpathMap[tableName] = tblUriMapVal
	    }
    } else {
	    tableName = *xpathInfo.tableName
    }

	curXlateParams := xlateParams
	curXlateParams.tableName = tableName
	curXlateParams.xpath = xpath
	err = mapFillDataUtil(curXlateParams)
	return err
}

func mapFillDataUtil(xlateParams xlateToParams) error {
	var dbs [db.MaxDB]*db.DB

	xpathInfo, ok := xYangSpecMap[xlateParams.xpath]
	if !ok {
		errStr := fmt.Sprintf("Invalid yang-path(\"%v\").", xlateParams.xpath)
		return tlerr.InternalError{Format: errStr}
	}

	if len(xpathInfo.xfmrField) > 0 {
		xlateParams.uri = xlateParams.uri + "/" + xlateParams.name

		/* field transformer present */
		xfmrLogInfoAll("Transformer function(\"%v\") invoked for yang path(\"%v\"). uri: %v", xpathInfo.xfmrField, xlateParams.xpath, xlateParams.uri)
		curYgotNodeData, nodeErr := yangNodeForUriGet(xlateParams.uri, xlateParams.ygRoot)
		if nodeErr != nil {
			return nil
		}
		inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, xlateParams.uri, xlateParams.requestUri, xlateParams.oper, xlateParams.keyName, nil, xlateParams.subOpDataMap, curYgotNodeData, xlateParams.txCache)
		retData, err := leafXfmrHandler(inParams, xpathInfo.xfmrField)
		if err != nil {
			if xlateParams.xfmrErr != nil && *xlateParams.xfmrErr == nil {
				*xlateParams.xfmrErr = err
			}
			return err
		}
		if retData != nil {
			xfmrLogInfoAll("Transformer function : %v Xpath : %v retData: %v", xpathInfo.xfmrField, xlateParams.xpath, retData)
			for f, v := range retData {
				dataToDBMapAdd(xlateParams.tableName, xlateParams.keyName, xlateParams.result, f, v)
			}
		}
		return nil
	}

	if len(xpathInfo.fieldName) == 0 {
		xfmrLogInfoAll("Field for yang-path(\"%v\") not found in DB.", xlateParams.xpath)
		errStr := fmt.Sprintf("Field for yang-path(\"%v\") not found in DB.", xlateParams.xpath)
		return tlerr.InternalError{Format: errStr}
	}
	fieldName := xpathInfo.fieldName
	valueStr := ""

        fieldXpath := xlateParams.tableName + "/" + fieldName
        _, ok = xDbSpecMap[fieldXpath]
        if !ok {
                logStr := fmt.Sprintf("Failed to find the xDbSpecMap: xpath(\"%v\").", fieldXpath)
                log.Error(logStr)
                return nil
        }

	if xpathInfo.yangEntry.IsLeafList() {
		/* Both yang side and Db side('@' suffix field) the data type is leaf-list */
		xfmrLogInfoAll("Yang type and Db type is Leaflist for field  = %v", xlateParams.xpath)
		fieldName += "@"
		if reflect.ValueOf(xlateParams.value).Kind() != reflect.Slice {
			logStr := fmt.Sprintf("Value for yang xpath %v which is a leaf-list should be a slice", xlateParams.xpath)
			log.Error(logStr)
			return nil
		}
		valData := reflect.ValueOf(xlateParams.value)
		for fidx := 0; fidx < valData.Len(); fidx++ {
			if fidx > 0 {
				valueStr += ","
			}

                        // SNC-3626 - string conversion based on the primitive type
                        fVal, err := unmarshalJsonToDbData(xDbSpecMap[fieldXpath].dbEntry, fieldXpath, fieldName, valData.Index(fidx).Interface())
                        if err == nil {
			      if ((strings.Contains(fVal, ":")) && (strings.HasPrefix(fVal, OC_MDL_PFX) || strings.HasPrefix(fVal, IETF_MDL_PFX) || strings.HasPrefix(fVal, IANA_MDL_PFX))) {
				      // identity-ref/enum has module prefix
				      fVal = strings.SplitN(fVal, ":", 2)[1]
			      }
			      valueStr = valueStr + fVal
                        } else {
                              logStr := fmt.Sprintf("Failed to unmarshal Json to DbData: table(\"%v\") field(\"%v\") value(\"%v\").", xlateParams.tableName, fieldName, valData.Index(fidx).Interface())
                              log.Error(logStr)
                              return nil
                        }
		}
		xfmrLogInfoAll("leaf-list value after conversion to DB format %v  :  %v", fieldName, valueStr)

	} else { // xpath is a leaf

                // SNC-3626 - string conversion based on the primitive type
                fVal, err := unmarshalJsonToDbData(xDbSpecMap[fieldXpath].dbEntry, fieldXpath, fieldName, xlateParams.value)
                if err == nil {
                      valueStr = fVal
                } else {
                      logStr := fmt.Sprintf("Failed to unmarshal Json to DbData: table(\"%v\") field(\"%v\") value(\"%v\").", xlateParams.tableName, fieldName, xlateParams.value)
                      log.Error(logStr)
                      return nil
                }

		if ((strings.Contains(valueStr, ":")) && (strings.HasPrefix(valueStr, OC_MDL_PFX) || strings.HasPrefix(valueStr, IETF_MDL_PFX) || strings.HasPrefix(valueStr, IANA_MDL_PFX))) {
			// identity-ref/enum might has module prefix
			valueStr = strings.SplitN(valueStr, ":", 2)[1]
		}
	}

	dataToDBMapAdd(xlateParams.tableName, xlateParams.keyName, xlateParams.result, fieldName, valueStr)
	xfmrLogInfoAll("TblName: \"%v\", key: \"%v\", field: \"%v\", valueStr: \"%v\".", xlateParams.tableName, xlateParams.keyName,
	fieldName, valueStr)
	return nil
}

func sonicYangReqToDbMapCreate(xlateParams xlateToParams) error {
    if reflect.ValueOf(xlateParams.jsonData).Kind() == reflect.Map {
        data := reflect.ValueOf(xlateParams.jsonData)
        for _, key := range data.MapKeys() {
            _, ok := xDbSpecMap[key.String()]
            if ok {
                directDbMapData("", key.String(), data.MapIndex(key).Interface(), xlateParams.result)
            } else {
		curXlateParams := xlateParams
		curXlateParams.jsonData = data.MapIndex(key).Interface()
                sonicYangReqToDbMapCreate(curXlateParams)
            }
        }
    }
    return nil
}

func dbMapDataFill(uri string, tableName string, keyName string, d map[string]interface{}, result map[string]map[string]db.Value) {
	result[tableName][keyName] = db.Value{Field: make(map[string]string)}
	for field, value := range d {
		fieldXpath := tableName + "/" + field
		if _, fieldOk := xDbSpecMap[fieldXpath]; (fieldOk  && (xDbSpecMap[fieldXpath].dbEntry != nil)) {
			xfmrLogInfoAll("Found non-nil yang entry in xDbSpecMap for field xpath = %v", fieldXpath)
			if xDbSpecMap[fieldXpath].dbEntry.IsLeafList() {
				xfmrLogInfoAll("Yang type is Leaflist for field  = %v", field)
				field += "@"
				fieldDt := reflect.ValueOf(value)
				fieldValue := ""
				for fidx := 0; fidx < fieldDt.Len(); fidx++ {
					if fidx > 0 {
						fieldValue += ","
					}
					fVal, err := unmarshalJsonToDbData(xDbSpecMap[fieldXpath].dbEntry, fieldXpath, field, fieldDt.Index(fidx).Interface())
					if err != nil {
						log.Errorf("Failed to unmashal Json to DbData: path(\"%v\") error (\"%v\").", fieldXpath, err)
					} else {
						fieldValue = fieldValue + fVal
					}
				}
				result[tableName][keyName].Field[field] = fieldValue
				continue
			}
			dbval, err := unmarshalJsonToDbData(xDbSpecMap[fieldXpath].dbEntry, fieldXpath, field, value)
			if err != nil {
				log.Errorf("Failed to unmashal Json to DbData: path(\"%v\") error (\"%v\").", fieldXpath, err)
			} else {
				result[tableName][keyName].Field[field] = dbval
			}
		} else {
			// should ideally never happen , just adding for safety
			xfmrLogInfoAll("Did not find entry in xDbSpecMap for field xpath = %v", fieldXpath)
		}
	}
	return
}

func dbMapListDataFill(uri string, tableName string, dbEntry *yang.Entry, jsonData interface{}, result map[string]map[string]db.Value) {
	data := reflect.ValueOf(jsonData)
	tblKeyName := strings.Split(dbEntry.Key, " ")
	for idx := 0; idx < data.Len(); idx++ {
		keyName := ""
		d := data.Index(idx).Interface().(map[string]interface{})
		for i, k := range tblKeyName {
			if i > 0 {
				keyName += "|"
			}
			fieldXpath := tableName + "/" + k
			val, err := unmarshalJsonToDbData(dbEntry.Dir[k], fieldXpath, k, d[k])
			if err != nil {
				log.Errorf("Failed to unmashal Json to DbData: path(\"%v\") error (\"%v\").", fieldXpath, err)
			} else {
				keyName += val
			}
			delete(d, k)
		}
		dbMapDataFill(uri, tableName, keyName, d, result)
	}
	return
}

func directDbMapData(uri string, tableName string, jsonData interface{}, result map[string]map[string]db.Value) bool {
	_, ok := xDbSpecMap[tableName]
	if ok && xDbSpecMap[tableName].dbEntry != nil {
		data := reflect.ValueOf(jsonData).Interface().(map[string]interface{})
		key  := ""
		dbSpecData := xDbSpecMap[tableName]
		result[tableName] = make(map[string]db.Value)

		if dbSpecData.keyName != nil {
			key = *dbSpecData.keyName
			xfmrLogInfoAll("Fill data for container uri(%v), key(%v)", uri, key)
			dbMapDataFill(uri, tableName, key, data, result)
			return true
		}

		for k, v := range data {
			xpath := tableName + "/" + k
			curDbSpecData, ok := xDbSpecMap[xpath]
			if ok && curDbSpecData.dbEntry != nil {
				eType := yangTypeGet(curDbSpecData.dbEntry)
				switch eType {
				case "list":
					xfmrLogInfoAll("Fill data for list uri(%v)", uri)
					dbMapListDataFill(uri, tableName, curDbSpecData.dbEntry, v, result)
				default:
					xfmrLogInfoAll("Invalid node type for uri(%v)", uri)
				}
			}
		}
	}
	return true
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
					uriItemList := splitUri(strings.TrimSuffix(uri, "/"))
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
						xfmrLogInfoAll("Uri(\"%v\") has child subtree-xfmr", uri)
						curResult, cerr := allChildTblGetToDelete(curXlateParams)
						if cerr != nil {
							err = cerr
						} else {
							mapCopy(result, curResult)
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

    printDbData(resultMap, "/tmp/yangToDbDataDel.txt")
	xfmrLogInfo("Delete req: uri(\"%v\") resultMap(\"%v\").", uri, resultMap)
	return err
}

func sonicYangReqToDbMapDelete(xlateParams xlateToParams) error {
	var err error
    if (xlateParams.tableName != "") {
        // Specific table entry case
        xlateParams.result[xlateParams.tableName] = make(map[string]db.Value)
		if tblSpecInfo, ok := xDbSpecMap[xlateParams.tableName]; ok && (tblSpecInfo.cascadeDel == XFMR_ENABLE) {
			*xlateParams.pCascadeDelTbl = append(*xlateParams.pCascadeDelTbl, xlateParams.tableName)
		}
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
					     uriItemList := splitUri(strings.TrimSuffix(xlateParams.requestUri, "/"))
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
                    if tblSpecInfo, ok := xDbSpecMap[dir]; ok && tblSpecInfo.cascadeDel == XFMR_ENABLE {
                        *xlateParams.pCascadeDelTbl = append(*xlateParams.pCascadeDelTbl, dir)
                    }
                    if dbInfo.dbEntry.Dir[dir].Config != yang.TSFalse {
                       xlateParams.result[dir] = make(map[string]db.Value)
                    }
                }
            }
        }
    }
    return nil
}

/* Get the data from incoming update/replace request, create map and fill with dbValue(ie. field:value to write into redis-db */
func dbMapUpdate(d *db.DB, ygRoot *ygot.GoStruct, oper int, path string, requestUri string, jsonData interface{}, result map[int]map[db.DBNum]map[string]map[string]db.Value, txCache interface{}) error {
    xfmrLogInfo("Update/replace req: path(\"%v\").", path)
    var err error
    err = dbMapCreate(d, ygRoot, oper, path, requestUri, jsonData, result, txCache)
    xfmrLogInfo("Update/replace req: path(\"%v\") result(\"%v\").", path, result)
    printDbData(result, "/tmp/yangToDbDataUpRe.txt")
    return err
}

func dbMapDefaultFieldValFill(xlateParams xlateToParams, tblUriList []string) error {
	tblData := xlateParams.result[xlateParams.tableName]
	var dbs [db.MaxDB]*db.DB
	tblName := xlateParams.tableName
	dbKey := xlateParams.keyName
	for _, tblUri := range tblUriList {
		xfmrLogInfoAll("Processing uri %v for default value filling(Table - %v, dbKey - %v)", tblUri, tblName, dbKey)
		yangXpath, prdErr := XfmrRemoveXPATHPredicates(tblUri)
		if prdErr != nil {
			continue
		}
		yangNode, ok := xYangSpecMap[yangXpath]
		if ok {
			for childName  := range yangNode.yangEntry.Dir {
				childXpath := yangXpath + "/" + childName
				childNode, ok := xYangSpecMap[childXpath]
				if ok {
					if (len(childNode.xfmrFunc) > 0) {
						xfmrLogInfoAll("Skip default filling since a subtree Xfmr found for path - %v", childXpath)
						continue
					}
					if childNode.yangDataType == YANG_LIST || childNode.yangDataType == YANG_CONTAINER {
						var tblList []string
						tblList = append(tblList, childXpath)
						err := dbMapDefaultFieldValFill(xlateParams, tblList)
						if err != nil {
							return err
						}
					}
					if (childNode.tableName != nil && *childNode.tableName == tblName) || (childNode.xfmrTbl != nil) {
						if childNode.xfmrTbl != nil {
							if len(*childNode.xfmrTbl) > 0 {
								inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, tblUri, xlateParams.requestUri, xlateParams.oper, "", nil, xlateParams.subOpDataMap, "", xlateParams.txCache)
								chldTblNm, _ := tblNameFromTblXfmrGet(*childNode.xfmrTbl, inParams)
								xfmrLogInfoAll("Table transformer %v for xpath %v returned table %v", *childNode.xfmrTbl, childXpath, chldTblNm)
								if chldTblNm != tblName {
									continue
								}

							}
						}
						_, ok := tblData[dbKey].Field[childName]
						if !ok && len(childNode.defVal) > 0  && len(childNode.fieldName) > 0 {
							xfmrLogInfoAll("Update(\"%v\") default: tbl[\"%v\"]key[\"%v\"]fld[\"%v\"] = val(\"%v\").",
							childXpath, tblName, dbKey, childNode.fieldName, childNode.defVal)
							if len(childNode.xfmrField) > 0 {
								childYangType := childNode.yangEntry.Type.Kind
								_, defValPtr, err := DbToYangType(childYangType, childXpath, childNode.defVal)
								if err == nil && defValPtr != nil {
									inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, childXpath, xlateParams.requestUri, xlateParams.oper, "", nil, xlateParams.subOpDataMap, defValPtr, xlateParams.txCache)
									retData, err := leafXfmrHandler(inParams, childNode.xfmrField)
									if err != nil {
										return err
									}
									if retData != nil {
										xfmrLogInfoAll("Transformer function : %v Xpath: %v retData: %v", childNode.xfmrField, childXpath, retData)
										for f, v := range retData {
											// Fill default value only if value is not available in result Map
											// else we overwrite the value filled in resultMap with default value
											_, ok := xlateParams.result[tblName][dbKey].Field[f]
											if !ok {
												dataToDBMapAdd(tblName, dbKey, xlateParams.result, f, v)
											}
										}
									}

								} else {
									xfmrLogInfoAll("Failed to update(\"%v\") default: tbl[\"%v\"]key[\"%v\"]fld[\"%v\"] = val(\"%v\").",
									childXpath, tblName, dbKey, childNode.fieldName, childNode.defVal)
								}
							} else {
								var xfmrErr error
								if _, ok := xDbSpecMap[tblName+"/"+childNode.fieldName]; ok {
									// Fill default value only if value is not available in result Map
									// else we overwrite the value filled in resultMap with default value
									_, ok = xlateParams.result[tblName][dbKey].Field[childNode.fieldName]
									if !ok {
										curXlateParams := formXlateToDbParam(xlateParams.d, xlateParams.ygRoot, xlateParams.oper, xlateParams.uri, xlateParams.requestUri, childXpath, dbKey, xlateParams.jsonData, xlateParams.resultMap, xlateParams.result, xlateParams.txCache, xlateParams.tblXpathMap, xlateParams.subOpDataMap, xlateParams.pCascadeDelTbl, &xfmrErr, childName, childNode.defVal, tblName)
										err := mapFillDataUtil(curXlateParams)
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
	}
	return nil
}

func dbMapDefaultValFill(xlateParams xlateToParams) error {
	for tbl, tblData := range xlateParams.result {
		for dbKey, _ := range tblData {
			var yxpathList []string //contains all uris(with keys) that were traversed for a table while processing the incoming request
			if tblUriMapVal, ok := xlateParams.tblXpathMap[tbl]; ok {
				for tblUri, _ := range tblUriMapVal {
					yxpathList = append(yxpathList, tblUri)
				}
			}
			curXlateParams := xlateParams
			curXlateParams.tableName = tbl
			curXlateParams.keyName = dbKey
			err := dbMapDefaultFieldValFill(curXlateParams, yxpathList)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

/* Get the data from incoming create request, create map and fill with dbValue(ie. field:value to write into redis-db */
func dbMapCreate(d *db.DB, ygRoot *ygot.GoStruct, oper int, uri string, requestUri string, jsonData interface{}, resultMap map[int]RedisDbMap, txCache interface{}) error {
	var err error
	tblXpathMap := make(map[string]map[string]bool)
	var result = make(map[string]map[string]db.Value)
	subOpDataMap := make(map[int]*RedisDbMap)
        var cascadeDelTbl []string
	root := xpathRootNameGet(uri)
	var xfmrErr error

	xlateToData := formXlateToDbParam(d, ygRoot, oper, root, uri, "", "", jsonData, resultMap, result, txCache, tblXpathMap, subOpDataMap, &cascadeDelTbl, &xfmrErr, "", "", "")

	if isSonicYang(uri) {
		err = sonicYangReqToDbMapCreate(xlateToData)
		resultMap[oper] = make(RedisDbMap)
		resultMap[oper][db.ConfigDB] = result
	} else {
		err = yangReqToDbMapCreate(xlateToData)
		if xfmrErr != nil {
			return xfmrErr
		}
		if err != nil {
			return err
		}
	}
	if err == nil {
		if !isSonicYang(uri) {
			xpath, _ := XfmrRemoveXPATHPredicates(uri)
			yangNode, ok := xYangSpecMap[xpath]
			if ok && yangNode.yangDataType != YANG_LEAF && yangNode.yangDataType != YANG_LEAF_LIST &&
			   (oper == CREATE || oper == REPLACE) {
				xfmrLogInfo("Fill default value for %v, oper(%v)\r\n", uri, oper)
				curXlateToParams := formXlateToDbParam(d, ygRoot, oper, uri, requestUri, xpath, "", jsonData, resultMap, result, txCache, tblXpathMap, subOpDataMap, &cascadeDelTbl, &xfmrErr, "", "", "")
				err = dbMapDefaultValFill(curXlateToParams)
				if err != nil {
					return err
				}
			}

			if ok && oper == REPLACE {
				if yangNode.yangDataType == YANG_LEAF {
					xfmrLogInfo("Change leaf oper to UPDATE for %v, oper(%v)\r\n", uri, oper)
					resultMap[UPDATE] = make(RedisDbMap)
					resultMap[UPDATE][db.ConfigDB] = result
					result = make(map[string]map[string]db.Value)
				} else if yangNode.yangDataType == YANG_LEAF_LIST {
					xfmrLogInfo("Change leaflist oper to UPDATE for %v, oper(%v)\r\n", uri, oper)
					delMap := make(map[string]map[string]db.Value)
					resultMap[DELETE] = make(RedisDbMap)
					tblSchemaCopy(delMap, result)
					resultMap[DELETE][db.ConfigDB] = delMap
					resultMap[UPDATE] = make(RedisDbMap)
					resultMap[UPDATE][db.ConfigDB] = result
					result = make(map[string]map[string]db.Value)
				}
			}

			moduleNm := "/" + strings.Split(uri, "/")[1]
			xfmrLogInfo("Module name for uri %s is %s", uri, moduleNm)
			if _, ok := xYangSpecMap[moduleNm]; ok {
				if xYangSpecMap[moduleNm].yangDataType == "container" && len(xYangSpecMap[moduleNm].xfmrPost) > 0 {
					xfmrLogInfo("Invoke post transformer: %v, result map: %v ", xYangSpecMap[moduleNm].xfmrPost, result)
					var dbDataMap = make(RedisDbMap)
					dbDataMap[db.ConfigDB] = result
					var dbs [db.MaxDB]*db.DB
					inParams := formXfmrInputRequest(d, dbs, db.ConfigDB, ygRoot, uri, requestUri, oper, "", &dbDataMap, subOpDataMap, nil, txCache)
					result, err = postXfmrHandlerFunc(xYangSpecMap[moduleNm].xfmrPost, inParams)
					if err != nil {
						return err
					}
                                        if inParams.pCascadeDelTbl != nil && len(*inParams.pCascadeDelTbl) > 0 {
                                            for _, tblNm :=  range *inParams.pCascadeDelTbl {
                                            if !contains(cascadeDelTbl, tblNm) {
                                                cascadeDelTbl = append(cascadeDelTbl, tblNm)
                                            }
                                        }
                                    }
				}
			} else {
				log.Errorf("No Entry exists for module %s in xYangSpecMap. Unable to process post xfmr (\"%v\") uri(\"%v\") error (\"%v\").", oper, uri, err)
			}
                        if len(result) > 0 || len(subOpDataMap) > 0 {
                                  resultMap[oper] = make(RedisDbMap)
                                  resultMap[oper][db.ConfigDB] = result
                                  for op, redisMapPtr := range subOpDataMap {
                                         if redisMapPtr != nil {
                                                 if _,ok := resultMap[op]; !ok {
                                                       resultMap[op] = make(RedisDbMap)
                                               }
                                               for dbNum, dbMap := range *redisMapPtr {
                                                       if _,ok := resultMap[op][dbNum]; !ok {
                                                               resultMap[op][dbNum] = make(map[string]map[string]db.Value)
                                                       }
                                                       mapCopy(resultMap[op][dbNum],dbMap)
                                               }
                                         }
                                  }
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
			xfmrLogInfo("Cascade Delete Failed for cascadeDelTbl (%v), Error (%v).", cascadeDelTbl, cdErr)
			return cdErr
		    }
                }

		printDbData(resultMap, "/tmp/yangToDbDataCreate.txt")
	} else {
		log.Errorf("DBMapCreate req failed for oper (\"%v\") uri(\"%v\") error (\"%v\").", oper, uri, err)
	}
	return err
}

func yangNodeForUriGet(uri string, ygRoot *ygot.GoStruct) (interface{}, error) {
	path, err := ygot.StringToPath(uri, ygot.StructuredPath, ygot.StringSlicePath)
	if path == nil || err != nil {
		log.Warningf("For uri %v - StringToPath failure", uri)
		errStr := fmt.Sprintf("Ygot stringTopath failed for uri(%v)", uri)
		return nil, tlerr.InternalError{Format: errStr}
	}

	for _, p := range path.Elem {
		pathSlice := strings.Split(p.Name, ":")
		p.Name = pathSlice[len(pathSlice)-1]
		if len(p.Key) > 0 {
			for ekey, ent := range p.Key {
				// SNC-2126: check the occurrence of ":"
				if ((strings.Contains(ent, ":")) && (strings.HasPrefix(ent, OC_MDL_PFX) || strings.HasPrefix(ent, IETF_MDL_PFX) || strings.HasPrefix(ent, IANA_MDL_PFX))) {
					// identity-ref/enum has module prefix
					eslice := strings.SplitN(ent, ":", 2)
					// TODO - exclude the prexix by checking enum type
					p.Key[ekey] = eslice[len(eslice)-1]
				} else {
					p.Key[ekey] = ent
				}
			}
		}
	}
	schRoot := ocbSch.RootSchema()
	node, nErr := ytypes.GetNode(schRoot, (*ygRoot).(*ocbinds.Device), path)
	if nErr != nil {
		log.Warningf("For uri %v - GetNode failure - %v", uri, nErr)
		errStr := fmt.Sprintf("%v", nErr)
		return nil, tlerr.InternalError{Format: errStr}
	}
	if ((node == nil) || (len(node) == 0) || (node[0].Data == nil)) {
		log.Warningf("GetNode returned nil for uri %v", uri)
		errStr := "GetNode returned nil for the given uri."
		return nil, tlerr.InternalError{Format: errStr}
	}
	xfmrLogInfoAll("GetNode data: %v", node[0].Data)
	return node[0].Data, nil
}

func yangReqToDbMapCreate(xlateParams xlateToParams) error {
	xfmrLogInfoAll("key(\"%v\"), xpathPrefix(\"%v\").", xlateParams.keyName, xlateParams.xpath)
	var dbs [db.MaxDB]*db.DB
	var retErr error

	if reflect.ValueOf(xlateParams.jsonData).Kind() == reflect.Slice {
		xfmrLogInfoAll("slice data: key(\"%v\"), xpathPrefix(\"%v\").", xlateParams.keyName, xlateParams.xpath)
		jData := reflect.ValueOf(xlateParams.jsonData)
		dataMap := make([]interface{}, jData.Len())
		for idx := 0; idx < jData.Len(); idx++ {
			dataMap[idx] = jData.Index(idx).Interface()
		}
		for _, data := range dataMap {
			curKey := ""
			curUri, _ := uriWithKeyCreate(xlateParams.uri, xlateParams.xpath, data)
			_, ok := xYangSpecMap[xlateParams.xpath]
			if ok && len(xYangSpecMap[xlateParams.xpath].xfmrKey) > 0 {
				/* key transformer present */
				curYgotNode, nodeErr := yangNodeForUriGet(curUri, xlateParams.ygRoot)
				if nodeErr != nil {
					curYgotNode = nil
				}
				inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, curUri, xlateParams.requestUri, xlateParams.oper, "", nil, xlateParams.subOpDataMap, curYgotNode, xlateParams.txCache)

				ktRetData, err := keyXfmrHandler(inParams, xYangSpecMap[xlateParams.xpath].xfmrKey)
				//if key transformer is called without key values in curUri ignore the error
				if err != nil  && strings.HasSuffix(curUri, "]") {
					if xlateParams.xfmrErr != nil && *xlateParams.xfmrErr == nil {
						*xlateParams.xfmrErr = err
					}
					return nil
				}
				curKey = ktRetData
			} else if ok && xYangSpecMap[xlateParams.xpath].keyName != nil {
				curKey = *xYangSpecMap[xlateParams.xpath].keyName
			} else {
				curKey = keyCreate(xlateParams.keyName, xlateParams.xpath, data, xlateParams.d.Opts.KeySeparator)
			}
			curXlateParams := formXlateToDbParam(xlateParams.d, xlateParams.ygRoot, xlateParams.oper, curUri, xlateParams.requestUri, xlateParams.xpath, curKey, data, xlateParams.resultMap, xlateParams.result, xlateParams.txCache, xlateParams.tblXpathMap, xlateParams.subOpDataMap, xlateParams.pCascadeDelTbl, xlateParams.xfmrErr, "", "", "")
			retErr = yangReqToDbMapCreate(curXlateParams)
		}
	} else {
		if reflect.ValueOf(xlateParams.jsonData).Kind() == reflect.Map {
			jData := reflect.ValueOf(xlateParams.jsonData)
			for _, key := range jData.MapKeys() {
				typeOfValue := reflect.TypeOf(jData.MapIndex(key).Interface()).Kind()

				xfmrLogInfoAll("slice/map data: key(\"%v\"), xpathPrefix(\"%v\").", xlateParams.keyName, xlateParams.xpath)
				xpath    := xlateParams.uri
				curUri   := xlateParams.uri
				curKey   := xlateParams.keyName
				pathAttr := key.String()
				if len(xlateParams.xpath) > 0 {
					if strings.Contains(pathAttr, ":") {
						pathAttr = strings.Split(pathAttr, ":")[1]
					}
					xpath  = xlateParams.xpath + "/" + pathAttr
					curUri = xlateParams.uri + "/" + pathAttr
				}
				_, ok := xYangSpecMap[xpath]
				xfmrLogInfoAll("slice/map data: curKey(\"%v\"), xpath(\"%v\"), curUri(\"%v\").",
				curKey, xpath, curUri)
				if ok && xYangSpecMap[xpath] != nil && len(xYangSpecMap[xpath].xfmrKey) > 0 {
					specYangType := yangTypeGet(xYangSpecMap[xpath].yangEntry)
					curYgotNode, nodeErr := yangNodeForUriGet(curUri, xlateParams.ygRoot)
					if nodeErr != nil {
						curYgotNode = nil
					}
					inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, curUri, xlateParams.requestUri, xlateParams.oper, "", nil, xlateParams.subOpDataMap, curYgotNode, xlateParams.txCache)
					ktRetData, err := keyXfmrHandler(inParams, xYangSpecMap[xpath].xfmrKey)
					if ((err != nil) && (specYangType != YANG_LIST || strings.HasSuffix(curUri, "]"))) {
						if xlateParams.xfmrErr != nil && *xlateParams.xfmrErr == nil {
							*xlateParams.xfmrErr = err
						}
						return nil
					}
					curKey = ktRetData
				} else if ok && xYangSpecMap[xpath].keyName != nil {
					curKey = *xYangSpecMap[xpath].keyName
				}

				if ok && (typeOfValue == reflect.Map || typeOfValue == reflect.Slice) && xYangSpecMap[xpath].yangDataType != "leaf-list" {
					// Call subtree only if start processing for the requestUri. Skip for parent uri traversal
					curXpath, _ := XfmrRemoveXPATHPredicates(curUri)
					reqXpath, _ := XfmrRemoveXPATHPredicates(xlateParams.requestUri)
					xfmrLogInfoAll("CurUri: %v, requestUri: %v\r\n", curUri, xlateParams.requestUri)
					xfmrLogInfoAll("curxpath: %v, requestxpath: %v\r\n", curXpath, reqXpath)
					if strings.HasPrefix(curXpath, reqXpath) {
						if xYangSpecMap[xpath] != nil && len(xYangSpecMap[xpath].xfmrFunc) > 0 &&
                        (xYangSpecMap[xlateParams.xpath] != xYangSpecMap[xpath]) {
							/* subtree transformer present */
							curYgotNode, nodeErr := yangNodeForUriGet(curUri, xlateParams.ygRoot)
							if nodeErr != nil {
								curYgotNode = nil
							}
							inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, curUri, xlateParams.requestUri, xlateParams.oper, "", nil, xlateParams.subOpDataMap, curYgotNode, xlateParams.txCache)
							stRetData, err := xfmrHandler(inParams, xYangSpecMap[xpath].xfmrFunc)
							if err != nil {
								if xlateParams.xfmrErr != nil && *xlateParams.xfmrErr == nil {
									*xlateParams.xfmrErr = err
                                                                }
								return nil
							}
							if stRetData != nil {
								mapCopy(xlateParams.result, stRetData)
							}
                                                        if xlateParams.pCascadeDelTbl != nil && len(*inParams.pCascadeDelTbl) > 0 {
                                                            for _, tblNm :=  range *inParams.pCascadeDelTbl {
                                                                if !contains(*xlateParams.pCascadeDelTbl, tblNm) {
                                                                    *xlateParams.pCascadeDelTbl = append(*xlateParams.pCascadeDelTbl, tblNm)
                                                                }
                                                            }
                                                        }
						}
					}
					curXlateParams := formXlateToDbParam(xlateParams.d, xlateParams.ygRoot, xlateParams.oper, curUri, xlateParams.requestUri, xpath, curKey, jData.MapIndex(key).Interface(), xlateParams.resultMap, xlateParams.result, xlateParams.txCache, xlateParams.tblXpathMap, xlateParams.subOpDataMap, xlateParams.pCascadeDelTbl, xlateParams.xfmrErr, "", "", "")
					retErr = yangReqToDbMapCreate(curXlateParams)
				} else {
					pathAttr := key.String()
					if strings.Contains(pathAttr, ":") {
						pathAttr = strings.Split(pathAttr, ":")[1]
					}
					xpath := xlateParams.xpath + "/" + pathAttr
					xfmrLogInfoAll("LEAF Case: xpath: %v, xpathPrefix: %v, pathAttr: %v", xpath, xlateParams.xpath, pathAttr)
					/* skip processing for list key-leaf outside of config container(OC yang) directly under the list.
					   Inside full-spec isKey is set to true for list key-leaf dierctly under the list(outside of config container) 
					   For ietf yang(eg.ietf-ptp) list key-leaf might have a field transformer.
					 */
					 _, ok := xYangSpecMap[xpath]
					if ok && ((!xYangSpecMap[xpath].isKey) || (len(xYangSpecMap[xpath].xfmrField) > 0)) {
						if len(xYangSpecMap[xpath].xfmrFunc) == 0 {
							value := jData.MapIndex(key).Interface()
							xfmrLogInfoAll("data field: key(\"%v\"), value(\"%v\").", key, value)
							curXlateParams := formXlateToDbParam(xlateParams.d, xlateParams.ygRoot, xlateParams.oper, xlateParams.uri, xlateParams.requestUri, xlateParams.xpath, curKey, xlateParams.jsonData, xlateParams.resultMap, xlateParams.result, xlateParams.txCache, xlateParams.tblXpathMap, xlateParams.subOpDataMap, xlateParams.pCascadeDelTbl, xlateParams.xfmrErr, pathAttr, value, "")
							retErr = mapFillData(curXlateParams)
							if retErr != nil {
								log.Errorf("Failed constructing data for db write: key(\"%v\"), value(\"%v\"), path(\"%v\").",
								pathAttr, value, xlateParams.xpath)
								return retErr
							}
						} else {
							xfmrLogInfoAll("write: key(\"%v\"), xpath(\"%v\"), uri(%v).",key, xpath, xlateParams.uri)
							curYgotNode, nodeErr := yangNodeForUriGet(xlateParams.uri, xlateParams.ygRoot)
							if nodeErr != nil {
								curYgotNode = nil
							}
							inParams := formXfmrInputRequest(xlateParams.d, dbs, db.MaxDB, xlateParams.ygRoot, xlateParams.uri, xlateParams.requestUri, xlateParams.oper, curKey, nil, xlateParams.subOpDataMap, curYgotNode, xlateParams.txCache)
							stRetData, err := xfmrHandler(inParams, xYangSpecMap[xpath].xfmrFunc)
							if err != nil {
								if xlateParams.xfmrErr != nil && *xlateParams.xfmrErr == nil {
                                                                        *xlateParams.xfmrErr = err
                                                                }
								return nil
							}
							if stRetData != nil {
                                                                mapCopy(xlateParams.result, stRetData)
							}
                                                        if xlateParams.pCascadeDelTbl != nil && len(*inParams.pCascadeDelTbl) > 0 {
                                                            for _, tblNm :=  range *inParams.pCascadeDelTbl {
                                                                if !contains(*xlateParams.pCascadeDelTbl, tblNm) {
                                                                    *xlateParams.pCascadeDelTbl = append(*xlateParams.pCascadeDelTbl, tblNm)
                                                                }
                                                            }
                                                        }
						}
					}
				}
			}
		}
	}

	return retErr
}

/* Debug function to print the map data into file */
func printDbData(resMap map[int]map[db.DBNum]map[string]map[string]db.Value, fileName string) {
	fp, err := os.Create(fileName)
	if err != nil {
		return
	}
	defer fp.Close()
	for oper, dbRes := range resMap {
		fmt.Fprintf(fp, "-----------------------------------------------------------------\r\n")
		fmt.Fprintf(fp, "Oper Type : %v\r\n", oper)
		for d, dbMap := range dbRes {
			fmt.Fprintf(fp, "DB num : %v\r\n", d)
			for k, v := range dbMap {
				fmt.Fprintf(fp, "table name : %v\r\n", k)
				for ik, iv := range v {
					fmt.Fprintf(fp, "  key : %v\r\n", ik)
					for k, d := range iv.Field {
						fmt.Fprintf(fp, "    %v :%v\r\n", k, d)
					}
				}
			}
		}
	}
	fmt.Fprintf(fp, "-----------------------------------------------------------------\r\n")
	return
}
