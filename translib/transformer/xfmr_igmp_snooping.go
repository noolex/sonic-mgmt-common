////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom, Inc.                                             //
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
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
)

//config db tables
var (
	CFG_L2MC_TABLE_TS               *db.TableSpec = &db.TableSpec{Name: CFG_L2MC_TABLE}
	CFG_L2MC_MROUTER_TABLE_TS       *db.TableSpec = &db.TableSpec{Name: CFG_L2MC_MROUTER_TABLE}
	CFG_L2MC_STATIC_GROUP_TABLE_TS  *db.TableSpec = &db.TableSpec{Name: CFG_L2MC_STATIC_GROUP_TABLE}
	CFG_L2MC_STATIC_MEMBER_TABLE_TS *db.TableSpec = &db.TableSpec{Name: CFG_L2MC_STATIC_MEMBER_TABLE}
)

//app db tables
var (
	APP_L2MC_MROUTER_TABLE_TS *db.TableSpec = &db.TableSpec{Name: APP_L2MC_MROUTER_TABLE}
	APP_L2MC_MEMBER_TABLE_TS  *db.TableSpec = &db.TableSpec{Name: APP_L2MC_MEMBER_TABLE}
)

var L2MC_TABLE_DEFAULT_FIELDS_MAP = map[string]string{
	"enabled":                    "true",
	"version":                    "2",
	"query-interval":             "125",
	"last-member-query-interval": "1000",
	"query-max-response-time":    "10",
}

const (
	CFG_L2MC_TABLE               = "CFG_L2MC_TABLE"
	CFG_L2MC_MROUTER_TABLE       = "CFG_L2MC_MROUTER_TABLE"
	CFG_L2MC_STATIC_GROUP_TABLE  = "CFG_L2MC_STATIC_GROUP_TABLE"
	CFG_L2MC_STATIC_MEMBER_TABLE = "CFG_L2MC_STATIC_MEMBER_TABLE"
	APP_L2MC_MROUTER_TABLE       = "APP_L2MC_MROUTER_TABLE"
	APP_L2MC_MEMBER_TABLE        = "APP_L2MC_MEMBER_TABLE"
)

func init() {
	XlateFuncBind("YangToDb_igmp_snooping_subtree_xfmr", YangToDb_igmp_snooping_subtree_xfmr)
	XlateFuncBind("DbToYang_igmp_snooping_subtree_xfmr", DbToYang_igmp_snooping_subtree_xfmr)
        XlateFuncBind("Subscribe_igmp_snooping_subtree_xfmr", Subscribe_igmp_snooping_subtree_xfmr)
	XlateFuncBind("DbToYangPath_igmp_snooping_path_xfmr", DbToYangPath_igmp_snooping_path_xfmr)
}

type reqProcessor struct {
	uri           *string
	uriPath       *gnmipb.Path
	opcode        int
	rootObj       *ocbinds.Device
	targetObj     interface{}
	db            *db.DB
	dbs           [db.MaxDB]*db.DB
	igmpsObj      *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping
	intfConfigObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping_Interfaces_Interface_Config
	intfStateObj  *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping_Interfaces_Interface_State
	intfStaticObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping_Interfaces_Interface_Staticgrps
	targetNode    *yang.Entry
}

func getYangNode(path *gnmipb.Path) (*yang.Entry, error) {
	pathStr, err := ygot.PathToSchemaPath(path)

	if err != nil {
		return nil, errors.New("path to schema path conversion failed")
	}

	fmt.Println("tmpStr pathStr ==> ", pathStr)

	pathStr = pathStr[1:]

	fmt.Println("tmpStr pathStr ==> ", pathStr)

	ygNode := ocbinds.SchemaTree["Device"].Find(pathStr)

	fmt.Println("translate == ygNode => ", ygNode)

	return ygNode, err
}

func getUriPath(uri string) (*gnmipb.Path, error) {
	uriPath := strings.Replace(uri, "openconfig-network-instance-deviation:", "", -1)
	path, err := ygot.StringToPath(uriPath, ygot.StructuredPath, ygot.StringSlicePath)
	if err != nil {
		return nil, errors.New("URI to path conversion failed")
	}
	for _, p := range path.Elem {
		pathSlice := strings.Split(p.Name, ":")
		p.Name = pathSlice[len(pathSlice)-1]
	}
	return path, nil
}

func (reqP *reqProcessor) setIGMPSnoopingObjFromReq() error {

	igmpsPath := &gnmipb.Path{}

	var pathList []*gnmipb.PathElem = reqP.uriPath.Elem

	for i := 0; i < len(pathList); i++ {
		igmpsPath.Elem = append(igmpsPath.Elem, pathList[i])
		if pathList[i].Name == "igmp-snooping" {
			break
		}
	}

	log.Info("igmpsPath => ", igmpsPath)

	if reqP.opcode == 1 { // GET case - we create the target node if not exist in the device object - its an workaround since tranformer is giving nil object
		if ygNode, _, errYg := ytypes.GetOrCreateNode(ocbinds.SchemaTree["Device"], reqP.rootObj, igmpsPath); errYg == nil && ygNode != nil {
			reqP.igmpsObj = ygNode.(*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping)
		} else {
			return tlerr.InvalidArgs("Invalid URI in the request")
		}
	} else {
		if targetNodeList, errTmp := ytypes.GetNode(ocbinds.SchemaTree["Device"], reqP.rootObj, igmpsPath); errTmp != nil || len(targetNodeList) == 0 {
			return tlerr.InvalidArgs("Invalid URI in the request")
		} else {
			reqP.igmpsObj = targetNodeList[0].Data.(*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping)
		}
	}

	fmt.Println("igmpSnoopingObj ==> ", reqP.igmpsObj)

	return nil
}

func (reqP *reqProcessor) handleDeleteReq(inParams XfmrParams) (*map[string]map[string]db.Value, error) {
	var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)

	var igmpsTblMap map[string]db.Value = make(map[string]db.Value)
	var igmpsMrouterTblMap map[string]db.Value = make(map[string]db.Value)
	var igmpsMcastGroupTblMap map[string]db.Value = make(map[string]db.Value)
	var igmpsMcastGroupMemTblMap map[string]db.Value = make(map[string]db.Value)
    var oif_list []string

	igmpsObj := reqP.igmpsObj

	if igmpsObj == nil || igmpsObj.Interfaces == nil || len(igmpsObj.Interfaces.Interface) == 0 {
		res_map[CFG_L2MC_TABLE] = igmpsTblMap
		res_map[CFG_L2MC_MROUTER_TABLE] = igmpsMrouterTblMap
		res_map[CFG_L2MC_STATIC_GROUP_TABLE] = igmpsMcastGroupTblMap
		res_map[CFG_L2MC_STATIC_MEMBER_TABLE] = igmpsMcastGroupMemTblMap
	} else {
		if len(igmpsObj.Interfaces.Interface) == 1 {
			for igmpsKey, igmpsVal := range igmpsObj.Interfaces.Interface {
				if igmpsVal.Config == nil && igmpsVal.Staticgrps == nil {
					igmpsTblMap[igmpsKey] = db.Value{Field: make(map[string]string)}
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					var mRouterDbTbl db.Table
					var err error
					if mRouterDbTbl, err = reqP.db.GetTable(CFG_L2MC_MROUTER_TABLE_TS); err != nil {
						fmt.Println("DB error in GetEntry => ", err)
					}

					mrouterKeys, _ := mRouterDbTbl.GetKeys()

					for j := range mrouterKeys {
						_, err := mRouterDbTbl.GetEntry(mrouterKeys[j])
						if err != nil {
							fmt.Println("mRouterDbTbl.GetEntry fails => ", err)
							continue
						}
						if igmpsKey != mrouterKeys[j].Comp[0] {
							continue
						}
                        mrtrIfName := *(utils.GetNativeNameFromUIName(&mrouterKeys[j].Comp[1]))
                        log.Infof("handleDeleteReq Deleting Mrouter interface:%v mrIfName:%v", mrouterKeys[j].Comp[1], mrtrIfName)
						igmpsMrouterKey := igmpsKey + "|" + mrtrIfName
						igmpsMrouterTblMap[igmpsMrouterKey] = db.Value{Field: make(map[string]string)}
					}
					if len(igmpsMrouterTblMap) > 0 {
						res_map[CFG_L2MC_MROUTER_TABLE] = igmpsMrouterTblMap
					}

					// -- static group table
					var staticGrpDbTbl db.Table
					if staticGrpDbTbl, err = reqP.db.GetTable(CFG_L2MC_STATIC_MEMBER_TABLE_TS); err != nil {
						fmt.Println("DB error in GetEntry => ", err)
					}

					staticGrpKeys, _ := staticGrpDbTbl.GetKeys()

					for k := range staticGrpKeys {
						_, err := staticGrpDbTbl.GetEntry(staticGrpKeys[k])
						if err != nil {
							fmt.Println("staticGrpDbTbl memeber - GetEntry fails => ", err)
							continue
						}
						if igmpsKey != staticGrpKeys[k].Comp[0] {
							continue
						}

                        sgrpIfName := *(utils.GetNativeNameFromUIName(&staticGrpKeys[k].Comp[3]))
                        log.Infof("handleDeleteReq sgrp interface:%v <=> sgrpIfName:%v", staticGrpKeys[k].Comp[3], sgrpIfName)

						igmpsGrpMemKey := igmpsKey + "|" + staticGrpKeys[k].Comp[1] + "|" + staticGrpKeys[k].Comp[2] + "|" + sgrpIfName
						igmpsMcastGroupMemTblMap[igmpsGrpMemKey] = db.Value{Field: make(map[string]string)}
					}

					if len(igmpsMcastGroupMemTblMap) > 0 {
						res_map[CFG_L2MC_STATIC_MEMBER_TABLE] = igmpsMcastGroupMemTblMap
					}

					if staticGrpDbTbl, err = reqP.db.GetTable(CFG_L2MC_STATIC_GROUP_TABLE_TS); err != nil {
						fmt.Println("handleDeleteReq - DB error in CFG_L2MC_STATIC_GROUP_TABLE_TS - GetTable => ", err)
						return nil, err
					}

					staticGrpKeys, _ = staticGrpDbTbl.GetKeys()
					// fetch all group entries from the db and delete the entries matches with the given grpKey
					for k := range staticGrpKeys {
						_, err := staticGrpDbTbl.GetEntry(staticGrpKeys[k])
						if err != nil {
							fmt.Println("staticGrpDbTbl.GetEntry fails => ", err)
						}

						if igmpsKey != staticGrpKeys[k].Comp[0] {
							continue
						}

						igmpsGrpKey := igmpsKey + "|" + staticGrpKeys[k].Comp[1] + "|" + staticGrpKeys[k].Comp[2]
						igmpsMcastGroupTblMap[igmpsGrpKey] = db.Value{Field: make(map[string]string)}
					}

					if len(igmpsMcastGroupTblMap) > 0 {
						res_map[CFG_L2MC_STATIC_GROUP_TABLE] = igmpsMcastGroupTblMap
					}
					break
				}

				dbV := db.Value{Field: make(map[string]string)}

				if reqP.targetNode.Name == "version" {
					dbV.Field["version"] = ""
					igmpsTblMap[igmpsKey] = dbV
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					fmt.Println("handleDeleteReq version res_map ==> ", res_map)
				} else if reqP.targetNode.Name == "fast-leave" {
					dbV.Field["fast-leave"] = "false"
					igmpsTblMap[igmpsKey] = dbV
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					fmt.Println("handleDeleteReq fast-leave res_map ==> ", res_map)
				} else if reqP.targetNode.Name == "querier" {
					dbV.Field["querier"] = ""
					igmpsTblMap[igmpsKey] = dbV
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					fmt.Println("handleDeleteReq querier res_map ==> ", res_map)
				} else if reqP.targetNode.Name == "query-interval" {
					dbV.Field["query-interval"] = ""
					igmpsTblMap[igmpsKey] = dbV
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					fmt.Println("handleDeleteReq query-interval res_map ==> ", res_map)
				} else if reqP.targetNode.Name == "query-max-response-time" {
					dbV.Field["query-max-response-time"] = ""
					igmpsTblMap[igmpsKey] = dbV
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					fmt.Println("handleDeleteReq query-max-response-time res_map ==> ", res_map)
				} else if reqP.targetNode.Name == "last-member-query-interval" {
					dbV.Field["last-member-query-interval"] = ""
					igmpsTblMap[igmpsKey] = dbV
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					fmt.Println("handleDeleteReq last-member-query-interval res_map ==> ", res_map)
				} else if reqP.targetNode.Name == "enabled" {
					dbV.Field["enabled"] = ""
					igmpsTblMap[igmpsKey] = dbV
					res_map[CFG_L2MC_TABLE] = igmpsTblMap
					fmt.Println("handleDeleteReq enabled res_map ==> ", res_map)
				} else if igmpsVal.Config != nil && len(igmpsVal.Config.MrouterInterface) == 0 && reqP.isConfigTargetNode("mrouter-interface") {
					res_map[CFG_L2MC_MROUTER_TABLE] = igmpsMrouterTblMap
				} else if igmpsVal.Config != nil && len(igmpsVal.Config.MrouterInterface) == 1 {
                    fmt.Println("handleDeleteReq Del MrouterInterface ==> ")
					for _, mrVal := range igmpsVal.Config.MrouterInterface {
                        mrIfName := *(utils.GetNativeNameFromUIName(&mrVal))
                        log.Infof("Mrouter mrval:%v mrIfName:%v", mrVal, mrIfName)
						igmpsMrouterKey := igmpsKey + "|" + mrIfName
						igmpsMrouterTblMap[igmpsMrouterKey] = db.Value{Field: make(map[string]string)}
					}
					res_map[CFG_L2MC_MROUTER_TABLE] = igmpsMrouterTblMap
				} else if len(igmpsVal.Staticgrps.StaticMulticastGroup) == 0 && reqP.isConfigTargetNode("staticgrps") {
					res_map[CFG_L2MC_STATIC_GROUP_TABLE] = igmpsMcastGroupTblMap
					res_map[CFG_L2MC_STATIC_MEMBER_TABLE] = igmpsMcastGroupMemTblMap
				} else if len(igmpsVal.Staticgrps.StaticMulticastGroup) == 1 {
					for grpKey, grpObj := range igmpsVal.Staticgrps.StaticMulticastGroup {
						if grpObj.Config == nil || len(grpObj.Config.OutgoingInterface) == 0 {
							var err error
							var staticGrpDbTbl db.Table
							if staticGrpDbTbl, err = reqP.db.GetTable(CFG_L2MC_STATIC_GROUP_TABLE_TS); err != nil {
								fmt.Println("DB error in GetEntry => ", err)
								return nil, err
							}

							staticGrpKeys, _ := staticGrpDbTbl.GetKeys()
							// fetch all group entries from the db and delete the entries matches with the given grpKey
							for k := range staticGrpKeys {
								if staticGrpKeys[k].Comp[1] == grpKey.Group {
									igmpsGrpKey := igmpsKey + "|" + grpKey.Group + "|" + "0.0.0.0"
									igmpsMcastGroupTblMap[igmpsGrpKey] = db.Value{Field: make(map[string]string)}

									staticGrpDbV, err := staticGrpDbTbl.GetEntry(staticGrpKeys[k])
									if err != nil {
										return nil, err
									}
									outIntfs := staticGrpDbV.GetList("out-intf")
									for _, intf := range outIntfs {
                                        sgIfName := *(utils.GetNativeNameFromUIName(&intf))
                                        log.Infof("handleDeleteReq - Static grp intf:%v <==> sgIfName:%v", intf, sgIfName)
										igmpsGrpMemKey := igmpsKey + "|" + grpKey.Group + "|" + "0.0.0.0" + "|" + sgIfName
										igmpsMcastGroupMemTblMap[igmpsGrpMemKey] = db.Value{Field: make(map[string]string)}
									}
									break
								}
							}
						} else {
							dbV := db.Value{Field: make(map[string]string)}
                            for _, oIf := range grpObj.Config.OutgoingInterface {
                                    oIfName := *(utils.GetNativeNameFromUIName(&oIf))
                                        oif_list = append(oif_list, oIfName)
                            }
							dbV.SetList("out-intf", oif_list)
							igmpsGrpKey := igmpsKey + "|" + grpKey.Group + "|" + "0.0.0.0"
							igmpsMcastGroupTblMap[igmpsGrpKey] = dbV
							for _, outIntf := range grpObj.Config.OutgoingInterface {
                                sgIfName := *(utils.GetNativeNameFromUIName(&outIntf))
                                log.Infof("handleDeleteReq --> Static grp intf:%v <==> sgIfName:%v", outIntf, sgIfName)
								igmpsGrpMemKey := igmpsKey + "|" + grpKey.Group + "|" + "0.0.0.0" + "|" + sgIfName
								igmpsMcastGroupMemTblMap[igmpsGrpMemKey] = db.Value{Field: make(map[string]string)}
							}
						}
					}
					if len(igmpsMcastGroupTblMap) > 0 {
						res_map[CFG_L2MC_STATIC_GROUP_TABLE] = igmpsMcastGroupTblMap
					}
					if len(igmpsMcastGroupMemTblMap) > 0 {
						res_map[CFG_L2MC_STATIC_MEMBER_TABLE] = igmpsMcastGroupMemTblMap
					}
				}
			}
		}
	}

	/* fmt.Println(" handleDeleteReq ============> res_map")
	pretty.Print(res_map) */

	return &res_map, nil
}

// handle create/replace/update request
func (reqP *reqProcessor) handleCRUReq(inParams XfmrParams) (*map[string]map[string]db.Value, error) {

	fmt.Println(" handleCRUReq entering ============> ")

	var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)
	var igmpsTblMap map[string]db.Value = make(map[string]db.Value)
	var igmpsMrouterTblMap map[string]db.Value = make(map[string]db.Value)
	var igmpsMcastGroupTblMap map[string]db.Value = make(map[string]db.Value)
	var igmpsMcastGroupMemTblMap map[string]db.Value = make(map[string]db.Value)
    var oif_list []string
	igmpsObj := reqP.igmpsObj
    var enabled bool

	for igmpsKey, igmpsVal := range igmpsObj.Interfaces.Interface {

		if igmpsVal.Config == nil {
			fmt.Println(" handleCRUReq ============> igmpsVal.Config is NULL")
			continue
		}

		dbV := db.Value{Field: make(map[string]string)}

		if igmpsVal.Config.Version != nil {
			dbV.Field["version"] = strconv.Itoa(int(*igmpsVal.Config.Version))
			fmt.Println(" handleCRUReq ============> setting version => ", strconv.Itoa(int(*igmpsVal.Config.Version)))
		}

		if igmpsVal.Config.FastLeave != nil {
			dbV.Field["fast-leave"] = strconv.FormatBool(*igmpsVal.Config.FastLeave)
			fmt.Println(" handleCRUReq ============> setting fast-leave => ", strconv.FormatBool(*igmpsVal.Config.FastLeave))
		}

		if igmpsVal.Config.QueryInterval != nil {
			dbV.Field["query-interval"] = strconv.Itoa(int(*igmpsVal.Config.QueryInterval))
			fmt.Println(" handleCRUReq ============> setting query-interval => ", strconv.Itoa(int(*igmpsVal.Config.QueryInterval)))
		}

		if igmpsVal.Config.QueryMaxResponseTime != nil {
			dbV.Field["query-max-response-time"] = strconv.Itoa(int(*igmpsVal.Config.QueryMaxResponseTime))
			fmt.Println(" handleCRUReq ============> setting query-max-response-time => ", strconv.Itoa(int(*igmpsVal.Config.QueryMaxResponseTime)))
		}

		if igmpsVal.Config.LastMemberQueryInterval != nil {
			dbV.Field["last-member-query-interval"] = strconv.Itoa(int(*igmpsVal.Config.LastMemberQueryInterval))
			fmt.Println(" handleCRUReq ============> setting last-member-query-interval => ", strconv.Itoa(int(*igmpsVal.Config.LastMemberQueryInterval)))
		}

		if igmpsVal.Config.Querier != nil {
			dbV.Field["querier"] = strconv.FormatBool(*igmpsVal.Config.Querier)
			fmt.Println(" handleCRUReq ============> setting querier => ", strconv.FormatBool(*igmpsVal.Config.Querier))
		}

		if igmpsVal.Config.Enabled != nil {
			dbV.Field["enabled"] = strconv.FormatBool(*igmpsVal.Config.Enabled)
			fmt.Println(" handleCRUReq ============> setting snooping-enable => ", strconv.FormatBool(*igmpsVal.Config.Enabled))
		}

		if len(dbV.Field) > 0 {
            if igmpsVal.Config.Enabled != nil {
                enabled = *igmpsVal.Config.Enabled
                if enabled {
                    igmpsTblMap[igmpsKey] = dbV
                    res_map[CFG_L2MC_TABLE] = igmpsTblMap
                } else {
                    subOpMap:= make(map[db.DBNum]map[string]map[string]db.Value)
                    submap_del := make(map[string]map[string]db.Value)
                    submap_del[CFG_L2MC_TABLE] = make(map[string]db.Value)
                    submap_del[CFG_L2MC_TABLE][igmpsKey] = db.Value{}
                    subOpMap[db.ConfigDB] = submap_del
                    inParams.subOpDataMap[DELETE] = &subOpMap
                    log.Infof(" handleCRUReq ============> Initiating DELETE key:%s val:%s",igmpsKey,igmpsVal)
                }
            } else {
                igmpsTblMap[igmpsKey] = dbV
                res_map[CFG_L2MC_TABLE] = igmpsTblMap
            }
		}

		fmt.Println(" handleCRUReq ============> igmpsVal", igmpsVal)
		fmt.Println(" handleCRUReq ============> igmpsVal.config", igmpsVal.Config)
		if len(igmpsVal.Config.MrouterInterface) > 0 {

			fmt.Println(" handleCRUReq ============> setting igmpsVal.Config.MrouterInterface")

			for _, mrVal := range igmpsVal.Config.MrouterInterface {
                mrIfName := *(utils.GetNativeNameFromUIName(&mrVal))
				igmpsMrouterKey := igmpsKey + "|" + mrIfName
				dbV := db.Value{Field: make(map[string]string)}
				dbV.Field["NULL"] = "NULL" // to represent empty value
				igmpsMrouterTblMap[igmpsMrouterKey] = dbV
                log.Infof("Mrouter mrval:%v mrIfName:%v", mrVal, mrIfName)
				fmt.Println(" handleCRUReq ============> setting igmpsMrouterKey => ", igmpsMrouterKey)
			}

			if len(igmpsMrouterTblMap) > 0 {
				fmt.Println(" handleCRUReq ============> setting CFG_L2MC_MROUTER_TABLE igmpsMrouterTblMap => ", igmpsMrouterTblMap)
				res_map[CFG_L2MC_MROUTER_TABLE] = igmpsMrouterTblMap
			}
		}

		if igmpsVal.Staticgrps != nil && len(igmpsVal.Staticgrps.StaticMulticastGroup) > 0 {

			fmt.Println(" handleCRUReq ============> setting igmpsVal.Config.StaticMulticastGroup")

			for grpKey, grpObj := range igmpsVal.Staticgrps.StaticMulticastGroup {
				if len(grpObj.Config.OutgoingInterface) > 0 {
					igmpsGrpKey := igmpsKey + "|" + grpKey.Group + "|" + "0.0.0.0"
					dbV := db.Value{Field: make(map[string]string)}
					dbV.Field["NULL"] = "NULL" // since deleting the field "out-intf" from the db removes the key also, to avoid that insert the dummy field/value as NULL/NULL
					
                    for _, oIf := range grpObj.Config.OutgoingInterface {
                        oIfName := *(utils.GetNativeNameFromUIName(&oIf))
                        oif_list = append(oif_list, oIfName)
                    }
                    //dbV.SetList("out-intf", grpObj.Config.OutgoingInterface)
                    dbV.SetList("out-intf", oif_list)
					igmpsMcastGroupTblMap[igmpsGrpKey] = dbV
                    
					for _, outIntf := range grpObj.Config.OutgoingInterface {
                        sgIfName := *(utils.GetNativeNameFromUIName(&outIntf))
						igmpsGrpMemKey := igmpsKey + "|" + grpKey.Group + "|" + "0.0.0.0" + "|" + sgIfName
						dbV := db.Value{Field: make(map[string]string)}
						dbV.Field["NULL"] = "NULL" // to represent empty value
						igmpsMcastGroupMemTblMap[igmpsGrpMemKey] = dbV
                        log.Infof("handleCRUReq ============> OIF outIntf:%v => sgIfName:%v", outIntf, sgIfName)
						fmt.Println(" handleCRUReq ============> setting igmpsVal.Config.StaticMulticastGroup igmpsGrpMemKey => ", igmpsGrpMemKey)
					}

				} else {
					igmpsGrpKey := igmpsKey + "|" + grpKey.Group + "|" + "0.0.0.0"
					dbV := db.Value{Field: make(map[string]string)}
					dbV.Field["NULL"] = "NULL" // to represent empty value
					igmpsMcastGroupTblMap[igmpsGrpKey] = dbV
					fmt.Println(" handleCRUReq ============> setting igmpsVal.Config.StaticMulticastGroup igmpsGrpKey => ", igmpsGrpKey)
				}
			}

			if len(igmpsMcastGroupTblMap) > 0 {
				fmt.Println(" handleCRUReq ============> setting CFG_L2MC_STATIC_GROUP_TABLE igmpsMcastGroupTblMap => ", igmpsMcastGroupTblMap)
				res_map[CFG_L2MC_STATIC_GROUP_TABLE] = igmpsMcastGroupTblMap
			}

			if len(igmpsMcastGroupMemTblMap) > 0 {
				fmt.Println(" handleCRUReq ============> setting CFG_L2MC_STATIC_MEMBER_TABLE igmpsMcastGroupMemTblMap => ", igmpsMcastGroupMemTblMap)
				res_map[CFG_L2MC_STATIC_MEMBER_TABLE] = igmpsMcastGroupMemTblMap
			}
		}
	}

	/* fmt.Println(" handleCRUReq ============> printing  res_map ")
	pretty.Print(res_map) */

	return &res_map, nil
}

func (reqP *reqProcessor) translateToDb(inParams XfmrParams) (*map[string]map[string]db.Value, error) {
	//DELETE
	if reqP.opcode == 5 {
		// get the target node
		var err error
		if reqP.targetNode, err = getYangNode(reqP.uriPath); err != nil {
			return nil, tlerr.InvalidArgs("Invalid request: %s", *reqP.uri)
		}

		fmt.Println("translateToDb param reqP.targetNode.Name ==> ", reqP.targetNode.Name)

		res_map, err := reqP.handleDeleteReq(inParams)

		if err != nil {
			return nil, tlerr.InvalidArgs("Invlaid IGMP Snooing delete: %s", *reqP.uri)
		}

		return res_map, err

	} else if reqP.igmpsObj != nil && reqP.igmpsObj.Interfaces != nil {
		res_map, err := reqP.handleCRUReq(inParams)
		if err != nil {
			return nil, tlerr.InvalidArgs("Invlaid IGMP Snooing request: %s", *reqP.uri)
		}
		return res_map, err
	} else {
		return nil, tlerr.InvalidArgs("IGMP Snooing object not found in the request: %s", *reqP.uri)
	}
}

var YangToDb_igmp_snooping_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

	fmt.Println("YangToDb_igmp_snooping_subtree_xfmr entering => ", inParams)

	path, err := getUriPath(inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)
	niName := pathInfo.Var("name")
	protoId := pathInfo.Var("identifier")
	if !strings.Contains(protoId, "IGMP_SNOOPING") {
		return nil, errors.New("IGMP Proto ID is missing")
	}

	if err != nil {
		return nil, err
	} else if niName != "default" {
		fmt.Println("YangToDb_igmp_snooping_subtree_xfmr - called with incorrect network-instance - name => ", niName, " and returning error..")
		return nil, tlerr.NotFound("Resource Not Found")
	}

	reqP := &reqProcessor{&inParams.uri, path, inParams.oper, (*inParams.ygRoot).(*ocbinds.Device), inParams.param, inParams.d, inParams.dbs, nil, nil, nil, nil, nil}

	fmt.Println("YangToDb_igmp_snooping_subtree_xfmr => translateToDb == reqP.uri => ", *reqP.uri)

	if err := reqP.setIGMPSnoopingObjFromReq(); err != nil {
		return nil, err
	}

	/* fmt.Println("YangToDb_igmp_snooping_subtree_xfmr ==> printing IGMPSnooping object request ==> ")
	pretty.Print(*reqP.igmpsObj) */

	res_map, err := reqP.translateToDb(inParams)

	if err == nil {
		return *res_map, nil
	} else {
		return nil, err
	}
}

var DbToYang_igmp_snooping_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    log.Info("DbToYang_igmp_snooping_subtree_xfmr entering => uri:", inParams.uri)

	path, err := getUriPath(inParams.uri)

	pathInfo := NewPathInfo(inParams.uri)
	niName := pathInfo.Var("name")
	protoId := pathInfo.Var("identifier")
	if !strings.Contains(protoId, "IGMP_SNOOPING") {
		return errors.New("IGMP Proto ID is missing")
	}

	if err != nil {
		return err
	} else if niName != "default" {
		//fmt.Println("DbToYang_igmp_snooping_subtree_xfmr - called with incorrect network-instance - name => ", niName, " and returning error..")
		return tlerr.NotFound("Resource Not Found")
	}

	reqP := &reqProcessor{&inParams.uri, path, inParams.oper, (*inParams.ygRoot).(*ocbinds.Device), inParams.param, inParams.d, inParams.dbs, nil, nil, nil, nil, nil}

	//fmt.Println("DbToYang_igmp_snooping_subtree_xfmr => translateToDb == reqP.uri => ", *reqP.uri)

	if err := reqP.setIGMPSnoopingObjFromReq(); err != nil {
		return err
	}

	// get the target node
	reqP.targetNode, err = getYangNode(reqP.uriPath)
	if err != nil {
		return tlerr.InvalidArgs("Invalid request - error: %v", err)
	}
    return reqP.translateToYgotObj()
}

func (reqP *reqProcessor) unMarshalStaticGrpObj() error {
	if reqP.intfStaticObj != nil && len(reqP.intfStaticObj.StaticMulticastGroup) > 0 {
		for grpKey, staticGrpObj := range reqP.intfStaticObj.StaticMulticastGroup {
			fmt.Println("unMarshalStaticGrpConfigObj - grpey => ", grpKey.Group)
			fmt.Println("unMarshalStaticGrpConfigObj - grpKey => ", grpKey.SourceAddr)
			fmt.Println("unMarshalStaticGrpConfig - grpObj => ", staticGrpObj)
			var err error
            var isOif bool = false
            var isConfOif bool = false
			var staticGrpDbTbl db.Table
			var srcAddr string
			if staticGrpDbTbl, err = reqP.db.GetTable(CFG_L2MC_STATIC_MEMBER_TABLE_TS); err != nil {
				fmt.Println("DB error in GetEntry => ", err)
			}
			staticGrpKeys, _ := staticGrpDbTbl.GetKeys()

			for k := range staticGrpKeys {
				_, err := staticGrpDbTbl.GetEntry(staticGrpKeys[k])
				if err != nil {
					return err
				}

				if *reqP.intfConfigObj.Name != staticGrpKeys[k].Comp[0] || grpKey.Group != staticGrpKeys[k].Comp[1] {
					continue
				}
                oIfName := *(utils.GetUINameFromNativeName(&staticGrpKeys[k].Comp[3]))
                log.Infof("unMarshalStaticGrpConfigObj:2 -  comp-oif:%v oIfName:%v", staticGrpKeys[k].Comp[3], oIfName)
				if staticGrpObj.Config != nil {
                fmt.Println("unMarshalStaticGrpConfigObj:2 - current OIF ", staticGrpObj.Config.OutgoingInterface)

                if len(staticGrpObj.Config.OutgoingInterface) > 0 {
                   _, found := Find(staticGrpObj.Config.OutgoingInterface, oIfName)
                   if (found) {
                       isConfOif = true
                   }
                   fmt.Println("unMarshalStaticGrpConfObj:2.- Printing Conf-OIF ", isConfOif,staticGrpObj.Config.OutgoingInterface)
                }
                if reqP.targetNode.Name == "group" {
					staticGrpObj.Config.Group = &grpKey.Group
				} else if reqP.targetNode.Name == "outgoing-interface" {
					if len(staticGrpObj.Config.OutgoingInterface) == 0 {

						staticGrpObj.Config.OutgoingInterface = append(staticGrpObj.Config.OutgoingInterface, oIfName)
					} else if oIfName == staticGrpObj.Config.OutgoingInterface[0] {
						if !isConfOif {
                            staticGrpObj.Config.OutgoingInterface = append(staticGrpObj.Config.OutgoingInterface, oIfName)
                        }
					}
				} else {
					srcAddr = "0.0.0.0"
					staticGrpObj.Config.Group = &grpKey.Group
					staticGrpObj.Config.SourceAddr = &srcAddr
                    if !isConfOif {
                        staticGrpObj.Config.OutgoingInterface = append(staticGrpObj.Config.OutgoingInterface, oIfName)
                    }
				}
			}
			}

			// StateObj
			if staticGrpObj.State != nil {
			intfKeys := reflect.ValueOf(reqP.igmpsObj.Interfaces.Interface).MapKeys()
			fmt.Println("unMarshalStaticGrpStateObj - TargetNode =>", reqP.targetNode)
			if reqP.targetNode.Name == "outgoing-interface" && len(staticGrpObj.State.OutgoingInterface) > 0 {
				portIntfName := staticGrpObj.State.OutgoingInterface[0]
				_, err := reqP.dbs[0].GetEntry(APP_L2MC_MEMBER_TABLE_TS, db.Key{[]string{intfKeys[0].Interface().(string), grpKey.SourceAddr, grpKey.Group, portIntfName}})
				if err != nil {
					return err
				}
				staticGrpObj.State.OutgoingInterface = append(staticGrpObj.State.OutgoingInterface, portIntfName)
			} else {
				if staticGrpDbTbl, err = reqP.dbs[0].GetTable(APP_L2MC_MEMBER_TABLE_TS); err != nil {
					fmt.Println("DB error in GetEntry => ", err)
				}
				staticGrpKeys, _ := staticGrpDbTbl.GetKeys()

				for k := range staticGrpKeys {
					_, err := staticGrpDbTbl.GetEntry(staticGrpKeys[k])
					if err != nil {
						return err
					}

					if intfKeys[0].Interface().(string) != staticGrpKeys[k].Comp[0] || grpKey.SourceAddr != staticGrpKeys[k].Comp[1] || grpKey.Group != staticGrpKeys[k].Comp[2] {
						continue
					}

                    grpIfName := *(utils.GetUINameFromNativeName(&staticGrpKeys[k].Comp[3]))
                    log.Infof("unMarshalStaticGrpStateObj:2 -  comp-oif:%v oIfName:%v", staticGrpKeys[k].Comp[3], grpIfName)
                    if len(staticGrpObj.State.OutgoingInterface) > 0 {
                        _, found := Find(staticGrpObj.State.OutgoingInterface, grpIfName)
                        if (found) {
                            isOif = true
                        }
                    }
					staticGrpObj.State.Group = &grpKey.Group
					staticGrpObj.State.SourceAddr = &grpKey.SourceAddr

                    if !isOif {
                        fmt.Println("unMarshalStaticGrpStateObj:2.Adding new OIF ", grpIfName)
                        staticGrpObj.State.OutgoingInterface = append(staticGrpObj.State.OutgoingInterface, grpIfName)
                    }
                    fmt.Println("unMarshalStaticGrpStateObj:2.State - Printing State-OIF ", isOif,staticGrpObj.State.OutgoingInterface)
					break
				}
			}
			break
		}
			}
	} else if reqP.isConfigTargetNode("staticgrps") {
		var staticGrpDbTbl db.Table
		var err error
		var srcAddr string

		if staticGrpDbTbl, err = reqP.db.GetTable(CFG_L2MC_STATIC_MEMBER_TABLE_TS); err != nil {
			fmt.Println("DB error in GetEntry => ", err)
		}

		staticGrpKeys, _ := staticGrpDbTbl.GetKeys()
		for k := range staticGrpKeys {
			_, err := staticGrpDbTbl.GetEntry(staticGrpKeys[k])
			if err != nil {
				return err
			}
			if *reqP.intfConfigObj.Name != staticGrpKeys[k].Comp[0] {
				continue
			}
			staticGrpKey := ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping_Interfaces_Interface_Staticgrps_StaticMulticastGroup_Key{staticGrpKeys[k].Comp[1], "0.0.0.0"}
			staticGrpObj := reqP.intfStaticObj.StaticMulticastGroup[staticGrpKey]

			if staticGrpObj == nil {
				staticGrpObj, err = reqP.intfStaticObj.NewStaticMulticastGroup(staticGrpKeys[k].Comp[1], "0.0.0.0")
				if err != nil {
					return err
				}
			}
    
            oIfName := *(utils.GetUINameFromNativeName(&staticGrpKeys[k].Comp[3]))
            log.Infof("unMarshalStaticGrpConfigObj:1 -  comp-oif:%v oIfName:%v", staticGrpKeys[k].Comp[3], oIfName)

			srcAddr = "0.0.0.0"
			ygot.BuildEmptyTree(staticGrpObj)
			staticGrpObj.Config.OutgoingInterface = append(staticGrpObj.Config.OutgoingInterface, oIfName)
			staticGrpObj.Config.Group = &staticGrpKeys[k].Comp[1]
			staticGrpObj.Config.SourceAddr = &srcAddr
            fmt.Println("unMarshalStaticGrpConfigObj:1.1 - Printing Config-OIF ", staticGrpObj.Config.OutgoingInterface)
			fmt.Println("unMarshalStaticGrpConfigObj - printing staticGrpObj => ", *staticGrpObj)
		}

        //StateObj
        if staticGrpDbTbl, err = reqP.dbs[0].GetTable(APP_L2MC_MEMBER_TABLE_TS); err != nil {
            fmt.Println("DB error in GetEntry => ", err) 
        }

        /* fmt.Println("unMarshalStaticGrpStateObj - printing db staticGrpDbTbl data")
        pretty.Print(staticGrpDbTbl) */

		staticGrpKeys, _ = staticGrpDbTbl.GetKeys()
		for k := range staticGrpKeys {
			_, err := staticGrpDbTbl.GetEntry(staticGrpKeys[k])
			if err != nil {
				return err
			}

			if *reqP.intfConfigObj.Name != staticGrpKeys[k].Comp[0] {
				continue
			}
			staticGrpKey := ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping_Interfaces_Interface_Staticgrps_StaticMulticastGroup_Key{staticGrpKeys[k].Comp[2], staticGrpKeys[k].Comp[1]}
			staticGrpObj := reqP.intfStaticObj.StaticMulticastGroup[staticGrpKey]
			if staticGrpObj == nil {
				staticGrpObj, err = reqP.intfStaticObj.NewStaticMulticastGroup(staticGrpKeys[k].Comp[2], staticGrpKeys[k].Comp[1])
				if err != nil {
					return err
				}
			}
            ygot.BuildEmptyTree(staticGrpObj)

            grpIfName := *(utils.GetUINameFromNativeName(&staticGrpKeys[k].Comp[3]))
            log.Infof("unMarshalStaticGrpStateObj:1 -  comp-oif:%v oIfName:%v", staticGrpKeys[k].Comp[3], grpIfName)

			staticGrpObj.State.Group = &staticGrpKeys[k].Comp[2]
			staticGrpObj.State.SourceAddr = &staticGrpKeys[k].Comp[1]
                    fmt.Println("unMarshalStaticGrpStateObj:1.Prev State - Appending State-OIF 1 ", staticGrpObj.State.OutgoingInterface)
			staticGrpObj.State.OutgoingInterface = append(staticGrpObj.State.OutgoingInterface, grpIfName)
			fmt.Println("unMarshalStaticGrpStateObj - printing staticGrpObj => ", *staticGrpObj)
		}
	}
	return nil
}

func (reqP *reqProcessor) unMarshalMrouterState() error {
	if !reqP.isStateTargetNode("mrouter-interface") {
		return nil
	}

	var mRouterDbTbl db.Table
	var err error
	if mRouterDbTbl, err = reqP.dbs[0].GetTable(APP_L2MC_MROUTER_TABLE_TS); err != nil {
		fmt.Println("DB error in GetEntry => ", err)
	}

	mrouterKeys, _ := mRouterDbTbl.GetKeys()
	for j := range mrouterKeys {
		_, err := mRouterDbTbl.GetEntry(mrouterKeys[j])
		if err != nil {
			return err
		}

		if *reqP.intfStateObj.Name != mrouterKeys[j].Comp[0] {
			continue
		}
        mrIfName := *(utils.GetUINameFromNativeName(&mrouterKeys[j].Comp[1]))
        log.Infof("Mrouter mrcomp:%v mrIfName:%v", mrouterKeys[j].Comp[1], mrIfName)
		reqP.intfStateObj.MrouterInterface = append(reqP.intfStateObj.MrouterInterface, mrIfName)
	}

	return nil
}

func (reqP *reqProcessor) unMarshalMrouterConfig() error {
	if !reqP.isConfigTargetNode("mrouter-interface") {
		return nil
	}

	var mRouterDbTbl db.Table
	var err error
	if mRouterDbTbl, err = reqP.db.GetTable(CFG_L2MC_MROUTER_TABLE_TS); err != nil {
		fmt.Println("DB error in GetEntry => ", err)
	}
	mrouterKeys, _ := mRouterDbTbl.GetKeys()

	for j := range mrouterKeys {
		_, err := mRouterDbTbl.GetEntry(mrouterKeys[j])
		if err != nil {
			return err
		}
		if *reqP.intfConfigObj.Name != mrouterKeys[j].Comp[0] {
			continue
		}
        mrIfName := *(utils.GetUINameFromNativeName(&mrouterKeys[j].Comp[1]))
        log.Infof("Mrouter mrcomp:%v mrIfName:%v", mrouterKeys[j].Comp[1], mrIfName)
		reqP.intfConfigObj.MrouterInterface = append(reqP.intfConfigObj.MrouterInterface, mrIfName)
	}

	return nil
}

func (reqP *reqProcessor) unMarshalIGMPSnoopingIntfConfigObjInst(dbV *db.Value) {
	isAllFields := reqP.isConfigTargetNode("")
	if reqP.targetNode.Name == "version" || isAllFields {
		if fv, ok := dbV.Field["version"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint8(intV)
			reqP.intfConfigObj.Version = &tmp
		}
	}
	if reqP.targetNode.Name == "fast-leave" || isAllFields {
		if fv, ok := dbV.Field["fast-leave"]; ok {
			tmp, _ := strconv.ParseBool(fv)
			reqP.intfConfigObj.FastLeave = &tmp
		}
	}
	if reqP.targetNode.Name == "query-interval" || isAllFields {
		if fv, ok := dbV.Field["query-interval"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint16(intV)
			reqP.intfConfigObj.QueryInterval = &tmp
		}
	}
	if reqP.targetNode.Name == "last-member-query-interval" || isAllFields {
		if fv, ok := dbV.Field["last-member-query-interval"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint32(intV)
			reqP.intfConfigObj.LastMemberQueryInterval = &tmp
		}
	}
	if reqP.targetNode.Name == "query-max-response-time" || isAllFields {
		if fv, ok := dbV.Field["query-max-response-time"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint16(intV)
			reqP.intfConfigObj.QueryMaxResponseTime = &tmp
		}
	}
	if reqP.targetNode.Name == "enabled" || isAllFields {
		if fv, ok := dbV.Field["enabled"]; ok {
			tmp, _ := strconv.ParseBool(fv)
			reqP.intfConfigObj.Enabled = &tmp
		}
	}
	if reqP.targetNode.Name == "querier" || isAllFields {
		if fv, ok := dbV.Field["querier"]; ok {
			tmp, _ := strconv.ParseBool(fv)
			reqP.intfConfigObj.Querier = &tmp
		}
	}
}

func (reqP *reqProcessor) unMarshalIGMPSnoopingIntfStateObjInst(dbV *db.Value) {
	isAllFields := reqP.isStateTargetNode("")
	if reqP.targetNode.Name == "version" || isAllFields {
		if fv, ok := dbV.Field["version"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint8(intV)
			reqP.intfStateObj.Version = &tmp
		}
	}
	if reqP.targetNode.Name == "fast-leave" || isAllFields {
		if fv, ok := dbV.Field["fast-leave"]; ok {
			tmp, _ := strconv.ParseBool(fv)
			reqP.intfStateObj.FastLeave = &tmp
		}
	}
	if reqP.targetNode.Name == "query-interval" || isAllFields {
		if fv, ok := dbV.Field["query-interval"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint16(intV)
			reqP.intfStateObj.QueryInterval = &tmp
		}
	}
	if reqP.targetNode.Name == "last-member-query-interval" || isAllFields {
		if fv, ok := dbV.Field["last-member-query-interval"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint32(intV)
			reqP.intfStateObj.LastMemberQueryInterval = &tmp
		}
	}
	if reqP.targetNode.Name == "query-max-response-time" || isAllFields {
		if fv, ok := dbV.Field["query-max-response-time"]; ok {
			intV, _ := strconv.ParseInt(fv, 10, 64)
			tmp := uint16(intV)
			reqP.intfStateObj.QueryMaxResponseTime = &tmp
		}
	}
	if reqP.targetNode.Name == "enabled" || isAllFields {
		if fv, ok := dbV.Field["enabled"]; ok {
			tmp, _ := strconv.ParseBool(fv)
			reqP.intfStateObj.Enabled = &tmp
		}
	}
	if reqP.targetNode.Name == "querier" || isAllFields {
		if fv, ok := dbV.Field["querier"]; ok {
			tmp, _ := strconv.ParseBool(fv)
			reqP.intfStateObj.Querier = &tmp
		}
	}
}

func (reqP *reqProcessor) unMarshalIGMPSnoopingIntf(objType int) error {
	var l2McDbTbl db.Table
	var dbErr error
	if l2McDbTbl, dbErr = reqP.db.GetTable(CFG_L2MC_TABLE_TS); dbErr != nil {
		fmt.Println("DB error in GetEntry => ", dbErr)
	}

	/* fmt.Println("translateToYgotObj - printing db data")
	pretty.Print(l2McDbTbl) */

	l2McKeys, _ := l2McDbTbl.GetKeys()

	for i := range l2McKeys {
		dbV, err := l2McDbTbl.GetEntry(l2McKeys[i])
		if err != nil {
			return err
		}
		intfName := l2McKeys[i].Comp[0]
		intfObj, err := reqP.igmpsObj.Interfaces.NewInterface(intfName)
		if err != nil {
			return err
		}
		ygot.BuildEmptyTree(intfObj)
		reqP.intfStaticObj = intfObj.Staticgrps

		if objType == 1 {
			intfObj.Config.Name = intfObj.Name
			reqP.intfConfigObj = intfObj.Config

			reqP.unMarshalIGMPSnoopingIntfConfigObjInst(&dbV)

			if err := reqP.unMarshalMrouterConfig(); err != nil {
				return err
			}
			if err := reqP.unMarshalStaticGrpObj(); err != nil {
				return err
			}
		} else if objType == 2 {
			//state
			intfObj.State.Name = intfObj.Name
			reqP.intfStateObj = intfObj.State

			reqP.unMarshalIGMPSnoopingIntfStateObjInst(&dbV)

			if err := reqP.unMarshalMrouterState(); err != nil {
				return err
			}

			if err := reqP.unMarshalStaticGrpObj(); err != nil {
				return err
			}
		} else if objType == 3 {
			//config
			intfObj.Config.Name = intfObj.Name
			reqP.intfConfigObj = intfObj.Config

			reqP.unMarshalIGMPSnoopingIntfConfigObjInst(&dbV)

			if err := reqP.unMarshalMrouterConfig(); err != nil {
				return err
			}
			if err := reqP.unMarshalStaticGrpObj(); err != nil {
				return err
			}
			//state
			intfObj.State.Name = intfObj.Name
			reqP.intfStateObj = intfObj.State

			reqP.unMarshalIGMPSnoopingIntfStateObjInst(&dbV)

			if err := reqP.unMarshalMrouterState(); err != nil {
				return err
			}

			if err := reqP.unMarshalStaticGrpObj(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (reqP *reqProcessor) isConfigTargetNode(nodeName string) bool {
	if reqP.targetNode.Name == "igmp-snooping" || reqP.targetNode.Name == "interfaces" || reqP.targetNode.Name == "interface" || reqP.targetNode.Name == "config" || nodeName == reqP.targetNode.Name {
		return true
	}
	return false
}

func (reqP *reqProcessor) isStateTargetNode(nodeName string) bool {
	if reqP.targetNode.Name == "igmp-snooping" || reqP.targetNode.Name == "interfaces" || reqP.targetNode.Name == "interface" || reqP.targetNode.Name == "state" || nodeName == reqP.targetNode.Name {
		return true
	}
	return false
}

func (reqP *reqProcessor) translateToYgotObj() error {
	log.Info("translateToYgotObj entering => ")

	var err error

	fmt.Println("translateToYgotObj param reqP.targetNode.Name test ==> ", reqP.targetNode.Name)

	if reqP.igmpsObj == nil {
		reqP.igmpsObj = &(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_IgmpSnooping{nil})
	}

	if reqP.targetNode.Name == "igmp-snooping" || reqP.targetNode.Name == "interfaces" || len(reqP.igmpsObj.Interfaces.Interface) == 0 {
		ygot.BuildEmptyTree(reqP.igmpsObj)
		reqP.unMarshalIGMPSnoopingIntf(3)
	} else if len(reqP.igmpsObj.Interfaces.Interface) == 1 {
		intfKeys := reflect.ValueOf(reqP.igmpsObj.Interfaces.Interface).MapKeys()
		intfObj := reqP.igmpsObj.Interfaces.Interface[intfKeys[0].Interface().(string)]

		var objType int
		if intfObj.Config != nil {
			objType = 1
		} else if intfObj.State != nil {
			objType = 2
		} else {
			objType = 3
		}

		ygot.BuildEmptyTree(intfObj)
		reqP.intfStaticObj = intfObj.Staticgrps
		if objType == 1 || objType == 3 {
			intfObj.Config.Name = intfObj.Name
			reqP.intfConfigObj = intfObj.Config
			dbV, err := reqP.db.GetEntry(CFG_L2MC_TABLE_TS, db.Key{[]string{intfKeys[0].Interface().(string)}})
			if err != nil {
				fmt.Println("db.GetEntry - CFG_L2MC_TABLE_TS - fails ==> ", err)
			}
			reqP.unMarshalIGMPSnoopingIntfConfigObjInst(&dbV)

			if err = reqP.unMarshalMrouterConfig(); err != nil {
				fmt.Println("unMarshalMrouterConfig - fails ==> ", err)
			}

			if err = reqP.unMarshalStaticGrpObj(); err != nil {
				fmt.Println("unMarshalStaticGrpConfigObj - fails ==> ", err)
			}
		}

		if objType == 2 || objType == 3 {
			// state obj
			//state
			intfObj.State.Name = intfObj.Name
			reqP.intfStateObj = intfObj.State

			dbV, err := reqP.dbs[4].GetEntry(CFG_L2MC_TABLE_TS, db.Key{[]string{*intfObj.Name}})
			if err != nil {
				fmt.Println("db.GetEntry - CFG_L2MC_TABLE_TS - fails ==> ", err)
			}

			reqP.unMarshalIGMPSnoopingIntfStateObjInst(&dbV)

			if err := reqP.unMarshalMrouterState(); err != nil {
				fmt.Println("unMarshalMrouterState - fails ==> ", err)
			}

			if err := reqP.unMarshalStaticGrpObj(); err != nil {
				fmt.Println("unMarshalStaticGrpStateObj - fails ==> ", err)
			}
		}
	}

	/* fmt.Println("translateToYgotObj printing ygot object after unmarshalled ==> ")
	pretty.Print(reqP.igmpsObj) */

	return err
}


//var Subscribe_igmp_snooping_subtree_xfmr SubTreeXfmrSubscribe = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
//
//    var err error
//    var result XfmrSubscOutParams
//    pathInfo := NewPathInfo(inParams.uri)
//    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
//
//    log.Infof("Subscribe_igmp_snooping_subtree_xfmr:- URI:%s pathinfo:%s ", inParams.uri, pathInfo.Path)
//    log.Infof("Subscribe_igmp_snooping_subtree_xfmr:- Target URI path:%s", targetUriPath)
//
//    result.isVirtualTbl = true
//    return result, err
//}

var Subscribe_igmp_snooping_subtree_xfmr SubTreeXfmrSubscribe = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	var err error
	var result XfmrSubscOutParams

	log.Info("Subscribe_igmp_snooping_subtree_xfmr: inParams.subscProc: ",inParams.subscProc)

	pathInfo := NewPathInfo(inParams.uri)
	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	log.Infof("Subscribe_igmp_snooping_subtree_xfmr:- URI: %s ;; pathinfo: %s ", inParams.uri, pathInfo.Path)
	log.Infof("Subscribe_igmp_snooping_subtree_xfmr:- Target URI path: %s", targetUriPath)

	if inParams.subscProc == TRANSLATE_SUBSCRIBE {
		// to handle the TRANSLATE_SUBSCRIBE
		igmpSnoopingPath := "/openconfig-network-instance:network-instances/network-instance/protocols/protocol/openconfig-network-instance-deviation:igmp-snooping"
		igmpSnoopingIntfPath := igmpSnoopingPath + "/interfaces/interface"

		if targetUriPath == igmpSnoopingIntfPath || targetUriPath == igmpSnoopingPath {
			result.isVirtualTbl = true
			log.Info("Subscribe_igmp_snooping_subtree_xfmr:- result.isVirtualTbl: ", result.isVirtualTbl)
			return result, err
		}

		result.onChange = OnchangeEnable
		result.nOpts = &notificationOpts{}
		result.nOpts.pType = OnChange
		result.isVirtualTbl = false

		niName := pathInfo.Var("name")
		if niName == "" {
			niName = "*"
		}

		intfName := pathInfo.Var("name#3")
		mrouterIntf := pathInfo.Var("mrouter-interface") // for leaf-list node value
		staticGrpName := pathInfo.Var("group")
		staticSrcAddr := pathInfo.Var("source-addr")
		outgoingIntf := pathInfo.Var("outgoing-interface") // for leaf-list node value

		igmpSnpItfKey := ""
		mrouterKey := ""

		if intfName == "" {
			intfName = "*"
		}

		if mrouterIntf == "" {
			mrouterIntf = "*"
		} else {
			mrouterIntf = *(utils.GetNativeNameFromUIName(&mrouterIntf))
		}

		if outgoingIntf == "" {
			outgoingIntf = "*"
		} else {
			outgoingIntf = *(utils.GetNativeNameFromUIName(&outgoingIntf))
		}

		if staticGrpName == "" {
			staticGrpName = "*"
		}

		if staticSrcAddr == "" {
			staticSrcAddr = "*"
		}

		igmpIntfConfPath := igmpSnoopingPath + "/interfaces/interface/config"
		igmpIntfStatePath := igmpSnoopingPath + "/interfaces/interface/state"
		staticGrpConfPath := igmpSnoopingPath + "/interfaces/interface/staticgrps/static-multicast-group/config"
		staticGrpStatePath := igmpSnoopingPath + "/interfaces/interface/staticgrps/static-multicast-group/state"

		if niName == "default" || niName == "*" {
			igmpSnpItfKey = intfName
			mrouterKey = intfName + "|" + mrouterIntf
			staticGrpKey := intfName + "|" + staticGrpName + "|" + staticSrcAddr
			mrouterAppDbKey := intfName + ":" + mrouterIntf

			if targetUriPath == igmpIntfConfPath {
				result.dbDataMap = RedisDbMap{db.ConfigDB:{"CFG_L2MC_TABLE":     {igmpSnpItfKey:{}}}}
				result.secDbDataMap = RedisDbYgNodeMap{db.ConfigDB:{"CFG_L2MC_MROUTER_TABLE": {mrouterKey:"mrouter-interface"}}}
			} else if targetUriPath == igmpIntfStatePath {
				result.dbDataMap = RedisDbMap{db.ConfigDB:{"CFG_L2MC_TABLE":     {igmpSnpItfKey:{}}}}
				result.secDbDataMap = RedisDbYgNodeMap{db.ApplDB:{"APP_L2MC_MROUTER_TABLE":{mrouterAppDbKey :"mrouter-interface"}}}
			} else if targetUriPath == staticGrpConfPath {
				if outgoingIntf == "*" {
					result.dbDataMap = RedisDbMap{db.ConfigDB:{"CFG_L2MC_STATIC_GROUP_TABLE": {staticGrpKey:{}}}}
				} else {
					configOutgoingIntfKey := intfName + "|" + staticGrpName + "|" + staticSrcAddr + "|" + outgoingIntf
					result.dbDataMap = RedisDbMap{db.ConfigDB:{"CFG_L2MC_STATIC_MEMBER_TABLE": {configOutgoingIntfKey:{}}}}
				}
			} else if targetUriPath == staticGrpStatePath {
				staticGrpAppDbKey := intfName + ":" + staticSrcAddr + ":" + staticGrpName + ":" + outgoingIntf
				result.dbDataMap = RedisDbMap{db.ApplDB:{"APP_L2MC_MEMBER_TABLE":     {staticGrpAppDbKey :{}}}}
			}
		}

		log.Info("Subscribe_igmp_snooping_subtree_xfmr: result dbDataMap: ", result.dbDataMap)
		log.Info("Subscribe_igmp_snooping_subtree_xfmr: result secDbDataMap: ", result.secDbDataMap)

		return result, err
	} else {
		result.isVirtualTbl = true
		log.Info("Subscribe_igmp_snooping_subtree_xfmr:- result.isVirtualTbl: ", result.isVirtualTbl)
		return result, err
	}
}

var DbToYangPath_igmp_snooping_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) (error) {
	niRoot := "/openconfig-network-instance:network-instances/network-instance"
	igmpsIf := niRoot + "/protocols/protocol/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
	smGroup := igmpsIf + "/staticgrps/static-multicast-group"

	log.Info("DbToYangPath_igmp_snooping_path_xfmr: params: ", params)

	params.ygPathKeys[niRoot + "/name"] = "default"
	params.ygPathKeys[niRoot + "/protocols/protocol/identifier"] = "IGMP_SNOOPING"
	params.ygPathKeys[niRoot + "/protocols/protocol/name"] = "IGMP-SNOOPING"

	if params.tblName == "CFG_L2MC_TABLE" || params.tblName == "CFG_L2MC_MROUTER_TABLE" ||
		params.tblName == "APP_L2MC_MROUTER_TABLE" || params.tblName == "CFG_L2MC_STATIC_GROUP_TABLE" ||
		params.tblName == "APP_L2MC_MEMBER_TABLE" || params.tblName == "CFG_L2MC_STATIC_MEMBER_TABLE" {
		params.ygPathKeys[igmpsIf + "/name"] = params.tblKeyComp[0]
	}

	if params.tblName == "CFG_L2MC_STATIC_GROUP_TABLE" {
		if len(params.tblKeyComp) == 3 {
			params.ygPathKeys[smGroup + "/group"] = params.tblKeyComp[1]
			params.ygPathKeys[smGroup + "/source-addr"] = params.tblKeyComp[2]
		}
	} else if params.tblName == "CFG_L2MC_STATIC_MEMBER_TABLE" {
		if len(params.tblKeyComp) == 4 {
			params.ygPathKeys[smGroup + "/group"] = params.tblKeyComp[1]
			params.ygPathKeys[smGroup + "/source-addr"] = params.tblKeyComp[2]
		}
	} else if params.tblName == "APP_L2MC_MEMBER_TABLE" {
		if len(params.tblKeyComp) == 4 {
			params.ygPathKeys[smGroup + "/source-addr"] = params.tblKeyComp[1]
			params.ygPathKeys[smGroup + "/group"] = params.tblKeyComp[2]
		}
	}

	log.Info("DbToYangPath_igmp_snooping_path_xfmr:- params.ygPathKeys: ", params.ygPathKeys)

	return nil
}
