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
	var chldUri string

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
					_, curUri, kerr := dbKeyToYangDataConvert(xlateParams.uri, xlateParams.requestUri, xlateParams.xpath, dbKey, separator, xlateParams.txCache)
					if kerr != nil {
						continue
					}
					for yangChldName := range spec.yangEntry.Dir {
						chldXpath    := xlateParams.xpath+"/"+yangChldName
						chldSpec, ok := xYangSpecMap[chldXpath]
						if (ok && (chldSpec.dbIndex == db.ConfigDB) && chldSpec.hasChildSubTree &&
						(chldSpec.yangEntry != nil)) {
							if chldSpec.nameWithMod != nil {
								chldUri   = curUri +"/"+ *chldSpec.nameWithMod
							} else {
								chldUri   = curUri +"/"+yangChldName
							}
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
	var chldUri string
	spec, _ := xYangSpecMap[xlateParams.xpath]
	cdb     := spec.dbIndex
	dbs[cdb] = xlateParams.d

	xfmrLogInfoAll("Parse container for subtree-xfmr(\"%v\")", xlateParams.uri)
	for yangChldName := range spec.yangEntry.Dir {
		chldXpath    := xlateParams.xpath+"/"+yangChldName
		chldSpec, ok := xYangSpecMap[chldXpath]
		if (ok && (chldSpec.dbIndex == db.ConfigDB) && (chldSpec.yangEntry != nil)) {
			if chldSpec.nameWithMod != nil {
				chldUri = xlateParams.uri + "/" + *chldSpec.nameWithMod
			} else {
				chldUri = xlateParams.uri+"/"+yangChldName
			}
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

