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

package translib

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/kylelemons/godebug/pretty"
	ygot "github.com/openconfig/ygot/ygot"
)

const (
	SONIC_CLASS_MATCH_TYPE_ACL    = "ACL"
	SONIC_CLASS_MATCH_TYPE_FIELDS = "FIELDS"
	SONIC_POLICY_TYPE_QOS         = "QOS"
	SONIC_POLICY_TYPE_FORWARDING  = "FORWARDING"
	SONIC_POLICY_TYPE_MONITORING  = "MONITORING"
	SONIC_PACKET_ACTION_DROP      = "DROP"
	CFG_CLASSIFIER_TABLE          = "CLASSIFIER_TABLE"
	CFG_POLICY_TABLE              = "POLICY_TABLE"
	CFG_POLICY_SECTIONS_TABLE     = "POLICY_SECTIONS_TABLE"
	CFG_POLICY_BINDING_TABLE      = "POLICY_BINDING_TABLE"
	APP_POLICER_TABLE             = "POLICER_TABLE"
	PBF_GROUP_TABLE               = "PBF_GROUP_TABLE"
	FBS_COUNTERS_TABLE            = "FBS_COUNTERS"
	LAST_FBS_COUNTERS_TABLE       = "LAST_FBS_COUNTERS"
	POLICER_COUNTERS_TABLE        = "POLICER_COUNTERS"
	LAST_POLICER_COUNTERS_TABLE   = "LAST_POLICER_COUNTERS"

//	OPENCONFIG_ACL_TYPE_IPV4      = "ACL_IPV4"
//	OPENCONFIG_ACL_TYPE_IPV6      = "ACL_IPV6"
//	OPENCONFIG_ACL_TYPE_L2        = "ACL_L2"
)

type FbsFwdCountersEntry struct {
	Active         bool   `path:"active" module:"openconfig-fbs-ext"`
	MatchedOctets  uint64 `path:"matched-octets" module:"openconfig-fbs-ext"`
	MatchedPackets uint64 `path:"matched-packets" module:"openconfig-fbs-ext"`
}

type FbsFlowForwardingStateEntry struct {
	IntfName        *string `path:"intf-name" module:"openconfig-fbs-ext"`
	Priority        *uint16 `path:"priority" module:"openconfig-fbs-ext"`
	IpAddress       *string `path:"ip-address" module:"openconfig-fbs-ext"`
	NetworkInstance *string `path:"network-instance" module:"openconfig-fbs-ext"`
	Discard         *bool   `path:"discard" module:"openconfig-fbs-ext"`

	fbsFlowState FbsFwdCountersEntry //MatchedOctets,MatchedPackets, Active
}

type FbsPolicerStateEntry struct {
	Cbs uint64 `path:"cbs" module:"openconfig-fbs-ext"`
	Pbs uint64 `path:"pbs" module:"openconfig-fbs-ext"`
	Cir uint64 `path:"cir" module:"openconfig-fbs-ext"`
	Pir uint64 `path:"pir" module:"openconfig-fbs-ext"`
}

type FbsFlowQosStateEntry struct {
	ConformingOctets uint64 `path:"conforming-octets" module:"openconfig-fbs-ext"`
	ConformingPkts   uint64 `path:"conforming-pkts" module:"openconfig-fbs-ext"`
	ExceedingOctets  uint64 `path:"exceeding-octets" module:"openconfig-fbs-ext"`
	ExceedingPkts    uint64 `path:"exceeding-pkts" module:"openconfig-fbs-ext"`
	ViolatingOctets  uint64 `path:"violating-octets" module:"openconfig-fbs-ext"`
	ViolatingPkts    uint64 `path:"violating-pkts" module:"openconfig-fbs-ext"`
	Active           bool   `path:"active" module:"openconfig-fbs-ext"`

	policerState FbsPolicerStateEntry //MatchedOctets,MatchedPackets, Active
	fbsFlowState FbsFwdCountersEntry  //MatchedOctets,MatchedPackets, Active
}

var classTblTs *db.TableSpec = &db.TableSpec{Name: CFG_CLASSIFIER_TABLE}
var policyTblTs *db.TableSpec = &db.TableSpec{Name: CFG_POLICY_TABLE}
var policySectionTblTs *db.TableSpec = &db.TableSpec{Name: CFG_POLICY_SECTIONS_TABLE}
var policerTblTs *db.TableSpec = &db.TableSpec{Name: APP_POLICER_TABLE}
var policyBindingTblTs *db.TableSpec = &db.TableSpec{Name: CFG_POLICY_BINDING_TABLE}
var pbfGrpTblTs *db.TableSpec = &db.TableSpec{Name: PBF_GROUP_TABLE}
var fbsCntrTblTs *db.TableSpec = &db.TableSpec{Name: FBS_COUNTERS_TABLE}
var lastFbsCntrTblTs *db.TableSpec = &db.TableSpec{Name: LAST_FBS_COUNTERS_TABLE}
var policerCtrTbl *db.TableSpec = &db.TableSpec{Name: POLICER_COUNTERS_TABLE}
var lastPolicerCtrTbl *db.TableSpec = &db.TableSpec{Name: LAST_POLICER_COUNTERS_TABLE}

type FbsApp struct {
	pathInfo   *PathInfo
	ygotRoot   *ygot.GoStruct
	ygotTarget *interface{}

	classMapTable      map[string]*db.Value
	policyMapTable     map[string]*db.Value
	policySectionTable map[string]*db.Value
	policyBindingTable map[string]*db.Value

	classMapCache      map[string]db.Value
	policyMapCache     map[string]db.Value
	policySectionCache map[string]db.Value
	policyBindingCache map[string]db.Value
}

var fbsAppInfo appInfo = appInfo{appType: reflect.TypeOf(FbsApp{}),
	ygotRootType:  reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs{}),
	isNative:      false,
	tablesToWatch: []*db.TableSpec{classTblTs, policyTblTs, policySectionTblTs, policyBindingTblTs}}

// init registers FBS App with the URI
func init() {
	err := register("/openconfig-fbs-ext:fbs", &fbsAppInfo)

	if err != nil {
		log.Fatal("Register FBS app module with App interface failed with error=", err)
	} else {
		log.Info("Register done.")
	}

	err = addModel(&ModelData{Name: "openconfig-lst-ext",
		Org: "OpenConfig working group",
		Ver: "0.1.0"})
	if err != nil {
		log.Fatal("Adding model data to appinterface failed with error=", err)
	}
}

func (app *FbsApp) initialize(data appData) {
	pathInfo := NewPathInfo(data.path)
	*app = FbsApp{pathInfo: pathInfo, ygotRoot: data.ygotRoot, ygotTarget: data.ygotTarget}

	app.classMapTable = make(map[string]*db.Value)
	app.policyMapTable = make(map[string]*db.Value)
	app.policySectionTable = make(map[string]*db.Value)
	app.policyBindingTable = make(map[string]*db.Value)

	app.classMapCache = make(map[string]db.Value)
	app.policyMapCache = make(map[string]db.Value)
	app.policySectionCache = make(map[string]db.Value)
	app.policyBindingCache = make(map[string]db.Value)

	log.Infof("FbsApp:: Path:%v", app.pathInfo.Path)
	log.Infof("FbsApp:: Template:%v", app.pathInfo.Template)
	log.Infof("FbsApp:: URIArgs:%v", app.pathInfo.Vars)
	pretty.Print(app.getAppRootObject())
}

func (app *FbsApp) getAppRootObject() *ocbinds.OpenconfigFbsExt_Fbs {
	deviceObj := (*app.ygotRoot).(*ocbinds.Device)
	return deviceObj.Fbs
}

func (app *FbsApp) translateCreate(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	log.Info("CREATE")
	err = app.translateCU(d, CREATE)

	return keys, err
}

func (app *FbsApp) translateUpdate(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	log.Info("UPDATE")
	err = app.translateCU(d, UPDATE)

	return keys, err
}

func (app *FbsApp) translateReplace(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	log.Info("REPLACE")
	err = app.translateRep(d)

	return keys, err
}

func (app *FbsApp) translateDelete(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	log.Info("DELETE")
	err = app.translateDel(d)

	return keys, err
}

func (app *FbsApp) translateGet(dbs [db.MaxDB]*db.DB) error {
	var err error

	return err
}

func (app *FbsApp) translateSubscribe(dbs [db.MaxDB]*db.DB, path string) ([]notificationAppInfo, error) {
	notSupported := tlerr.NotSupportedError{Format: "Subscribe not supported", Path: path}

	return nil, notSupported
}

func (app *FbsApp) translateAction(dbs [db.MaxDB]*db.DB) error {
	err := errors.New("Not supported")
	return err
}

func (app *FbsApp) processCreate(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCRUD(d, CREATE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *FbsApp) processUpdate(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCRUD(d, UPDATE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *FbsApp) processReplace(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCRUD(d, REPLACE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *FbsApp) processDelete(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCRUD(d, DELETE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *FbsApp) processGet(dbs [db.MaxDB]*db.DB) (GetResponse, error) {
	var err error
	var payload []byte

	err = app.processFbsGet(dbs)
	if err != nil {
		return GetResponse{Payload: payload, ErrSrc: AppErr}, err
	}

	payload, err = generateGetResponsePayload(app.pathInfo.Path, (*app.ygotRoot).(*ocbinds.Device), app.ygotTarget)
	if err != nil {
		return GetResponse{Payload: payload, ErrSrc: AppErr}, err
	}

	return GetResponse{Payload: payload}, err
}

func (app *FbsApp) processAction(dbs [db.MaxDB]*db.DB) (ActionResponse, error) {
	var resp ActionResponse
	err := errors.New("Not implemented")

	return resp, err
}

func (app *FbsApp) processSubscribe(param dbKeyInfo) (subscribePathResponse, error) {
	var resp subscribePathResponse
	return resp, tlerr.New("Not implemented")
}

/*
 * Translation functions to convert from Openconfig format to DB format
 */

// translateCU translates the incoming payload for Create and Update cases
func (app *FbsApp) translateCU(d *db.DB, opcode int) error {
	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers") {
		return app.translateCUClassifier(d, opcode)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/policies") {
		return app.translateCUPolicy(d, opcode)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces") {
		return app.translateCUInterface(d, opcode)
	} else {
		err := app.translateCUInterface(d, opcode)
		if err == nil {
			err = app.translateCUPolicy(d, opcode)
		}
		if err == nil {
			app.translateCUClassifier(d, opcode)
		}
		return err
	}
}

// translateRep translates the incoming payload for Replace case
func (app *FbsApp) translateRep(d *db.DB) error {
	// For replace operation, translate using delete first. Since translate delete will
	// Only build the items to be deleted in memory, update can be called on top of that
	// to add new contents from the payload. Finally the updated value will be written
	// to the DB
	dummy := []byte{}
	ygotStruct, ygotTarget, err := getRequestBinder(&app.pathInfo.Path, &dummy, DELETE, &(fbsAppInfo.ygotRootType)).unMarshall()
	if err != nil {
		log.Error(err)
		return nil
	}

	delAppData := appData{path: app.pathInfo.Path, payload: []byte{}, ygotRoot: ygotStruct, ygotTarget: ygotTarget}

	var delData FbsApp
	delData.initialize(delAppData)
	err = delData.translateDel(d)
	if err != nil {
		log.Error(err)
		return err
	}

	// Copy over the data
	app.classMapTable = delData.classMapTable
	app.policyMapTable = delData.policyMapTable
	app.policySectionTable = delData.policySectionTable
	app.policyBindingTable = delData.policyBindingTable

	app.classMapCache = delData.classMapCache
	app.policyMapCache = delData.policyMapCache
	app.policySectionCache = delData.policySectionCache
	app.policyBindingCache = delData.policyBindingCache

	err = app.translateCU(d, UPDATE)
	return err
}

// translateDel translates the incoming payload for Delete case
func (app *FbsApp) translateDel(d *db.DB) error {
	var err error

	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers") {
		err = app.translateDelClassifier(d)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/policies") {
		err = app.translateDelPolicy(d)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces") {
		err = app.translateDelInterface(d)
	} else {
		err = app.translateDelInterface(d)
		if err == nil {
			err = app.translateDelPolicy(d)
		}
		if err == nil {
			app.translateDelClassifier(d)
		}
	}

	// Handle cascaded delete. Going through the dependent config find and delete all references
	if err == nil {
		for className, classData := range app.classMapTable {
			if classData == nil {
				log.Infof("classifier %v is scheduled for delete. Find and delete its references", className)
				sectionKeys, err := d.GetKeysPattern(policySectionTblTs, db.Key{[]string{"*", className}})
				if err != nil {
					return err
				}

				for _, sectionKey := range sectionKeys {
					log.Infof("Section %v will be deleted due to cascaded delete", sectionKey)
					app.policySectionTable[sectionKey.Get(0)+"|"+sectionKey.Get(1)] = nil
				}
			}
		}
		for policyName, policyData := range app.policyMapTable {
			if policyData == nil {
				log.Infof("Policy %v is scheduled for delete. Find and delete its references", policyName)
				sectionKeys, err := d.GetKeysPattern(policySectionTblTs, db.Key{[]string{policyName, "*"}})
				if err != nil {
					return err
				}

				for _, sectionKey := range sectionKeys {
					log.Infof("Section %v will be deleted due to cascaded delete", sectionKey)
					app.policySectionTable[sectionKey.Get(0)+"|"+sectionKey.Get(1)] = nil
				}

				policyBindingTable, err := d.GetTable(policyBindingTblTs)
				if err != nil {
					return nil
				}
				policyBindKeys, _ := policyBindingTable.GetKeys()
				for _, policyBindKey := range policyBindKeys {
					bindingData, _ := policyBindingTable.GetEntry(policyBindKey)
					isModified := false
					for key, value := range bindingData.Field {
						if value == policyName {
							delete(bindingData.Field, key)
							isModified = true
						}
					}
					if len(bindingData.Field) == 0 {
						app.policyBindingTable[policyBindKey.Get(0)] = nil
					} else if isModified {
						app.policyBindingCache[policyBindKey.Get(0)] = bindingData
						app.policyBindingTable[policyBindKey.Get(0)] = &bindingData
					}
				}
			}
		}
	}

	return err
}

func (app *FbsApp) translateCUClassifier(d *db.DB, opcode int) error {
	fbsObj := app.getAppRootObject()

	if nil == fbsObj.Classifiers || len(fbsObj.Classifiers.Classifier) == 0 {
		log.Info("No classifiers data to translate")
		return nil
	}

	log.Info("Translating Classifiers")
	// for Create request, if the URI is pointing to level below classifier, validation is needed to make sure
	// It does not exist. for URI below classifier make sure the classifier exists.
	classSpecific := isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers/classifier{}")
	for className, classVal := range fbsObj.Classifiers.Classifier {
		log.Infof("Classifier CU: Class %v", className)

		dbV := db.Value{Field: make(map[string]string)}
		oldDbV, found := app.classMapTable[className]
		if !found {
			log.Infof("Classifier %v does not exist in the processed data", className)
			oldDbV, err := app.getClassifierEntryFromDB(d, className)
			if err != nil {
				log.Info(err)
				if isNotFoundError(err) {
					if classSpecific && opcode == CREATE {
						return tlerr.NotFound("Classifier %v not found", className)
					} else {
						log.Info("Not class specific request. Proceed")
					}
					// Not class specific request. Ignore the error as we need to create it
				} else {
					return err
				}
			} else {
				log.Infof("Classifer %v exists in processed data", className)
				if !classSpecific && opcode == CREATE {
					return tlerr.AlreadyExists("Classifier %v already exists", className)
				}
				dbV = oldDbV
			}
		} else if oldDbV == nil {
			log.Infof("Classifier %v is marked for delete", className)
			dbV = db.Value{Field: make(map[string]string)}
		} else {
			log.Infof("Classifier %v exists in the processed data. Update it", className)
			dbV = *oldDbV
		}

		var matchType string
		if classVal.Config != nil {
			matchType = getClassMatchTypeDbStrFromOcEnum(classVal.Config.MatchType)
			if matchType != "" {
				dbV.Field["MATCH_TYPE"] = matchType
			}

			if classVal.Config.Description != nil {
				dbV.Field["DESCRIPTION"] = *classVal.Config.Description
			}
		}
		log.Infof("Classifier:%v matchType:%v ", classVal, matchType)

		if classVal.MatchAcl != nil && classVal.MatchAcl.Config != nil {
			if classVal.MatchAcl.Config.AclName != nil {
				ocAclName := *classVal.MatchAcl.Config.AclName
				dbV.Field["ACL_NAME"] = ocAclName
			}

			ocAclType := classVal.MatchAcl.Config.AclType
			if ocAclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4 {
				dbV.Field["ACL_TYPE"] = "L3"
			} else if ocAclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV6 {
				dbV.Field["ACL_TYPE"] = "L3V6"
			} else if ocAclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2 {
				dbV.Field["ACL_TYPE"] = "L2"
			}
		} else if classVal.MatchHdrFields != nil {

			//Fill L2 Fields - START
			if classVal.MatchHdrFields.L2 != nil && classVal.MatchHdrFields.L2.Config != nil {
				if classVal.MatchHdrFields.L2.Config.DestinationMac != nil {
					ocMacStr := *(classVal.MatchHdrFields.L2.Config.DestinationMac)
					if classVal.MatchHdrFields.L2.Config.DestinationMacMask != nil {
						ocMacStr = ocMacStr + "/" + *(classVal.MatchHdrFields.L2.Config.DestinationMacMask)
					}
					log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
					dbV.Field["DST_MAC"] = ocMacStr
				}

				if classVal.MatchHdrFields.L2.Config.SourceMac != nil {
					ocMacStr := *(classVal.MatchHdrFields.L2.Config.SourceMac)
					if classVal.MatchHdrFields.L2.Config.SourceMacMask != nil {
						ocMacStr = ocMacStr + "/" + *(classVal.MatchHdrFields.L2.Config.SourceMacMask)
					}
					dbV.Field["SRC_MAC"] = ocMacStr
				}

				if classVal.MatchHdrFields.L2.Config.Dei != nil {
					dbV.Field["DEI"] = strconv.Itoa(int(*(classVal.MatchHdrFields.L2.Config.Dei)))
				}

				if classVal.MatchHdrFields.L2.Config.Pcp != nil {
					dbV.Field["PCP"] = strconv.Itoa(int(*(classVal.MatchHdrFields.L2.Config.Pcp)))
				}

				if classVal.MatchHdrFields.L2.Config.Vlanid != nil {
					dbV.Field["VLAN"] = strconv.Itoa(int(*classVal.MatchHdrFields.L2.Config.Vlanid))
				}

				if classVal.MatchHdrFields.L2.Config.Ethertype != nil {
					ethertypeType := reflect.TypeOf(classVal.MatchHdrFields.L2.Config.Ethertype).Elem()
					var b bytes.Buffer
					switch ethertypeType {
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE{}):
						v := classVal.MatchHdrFields.L2.Config.Ethertype.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE)
						fmt.Fprintf(&b, "0x%x", ETHERTYPE_MAP[v.E_OpenconfigPacketMatchTypes_ETHERTYPE])
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_Uint16{}):
						v := classVal.MatchHdrFields.L2.Config.Ethertype.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_Uint16)
						fmt.Fprintf(&b, "0x%x", v.Uint16)
					}
					dbV.Field["ETHER_TYPE"] = b.String()
				}
			}
			//Fill L2 Fields - END

			if classVal.MatchHdrFields.Ip != nil && classVal.MatchHdrFields.Ip.Config != nil {
				if classVal.MatchHdrFields.Ip.Config.Dscp != nil {
					dbV.Field["DSCP"] = strconv.Itoa(int(*classVal.MatchHdrFields.Ip.Config.Dscp))
				}
				if classVal.MatchHdrFields.Ip.Config.Protocol != nil {
					ipProtocolType := reflect.TypeOf(classVal.MatchHdrFields.Ip.Config.Protocol).Elem()
					var dbIpProto string
					switch ipProtocolType {
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
						v := classVal.MatchHdrFields.Ip.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
						dbIpProto = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_Uint8{}):
						v := classVal.MatchHdrFields.Ip.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_Uint8)
						dbIpProto = strconv.FormatInt(int64(v.Uint8), 10)
					}
					dbV.Field["IP_PROTOCOL"] = dbIpProto
				}
			}

			//Fill IPV4/Ipv6 Fields - START
			if classVal.MatchHdrFields.Ipv4 != nil && classVal.MatchHdrFields.Ipv4.Config != nil {
				if classVal.MatchHdrFields.Ipv4.Config.SourceAddress != nil {
					dbV.Field["SRC_IP"] = *(classVal.MatchHdrFields.Ipv4.Config.SourceAddress)
				}

				if classVal.MatchHdrFields.Ipv4.Config.DestinationAddress != nil {
					dbV.Field["DST_IP"] = *(classVal.MatchHdrFields.Ipv4.Config.DestinationAddress)
				}
			}

			if classVal.MatchHdrFields.Ipv6 != nil && classVal.MatchHdrFields.Ipv6.Config != nil {
				if classVal.MatchHdrFields.Ipv6.Config.SourceAddress != nil {
					dbV.Field["SRC_IPV6"] = *(classVal.MatchHdrFields.Ipv6.Config.SourceAddress)
				}
				if classVal.MatchHdrFields.Ipv6.Config.DestinationAddress != nil {
					dbV.Field["DST_IPV6"] = *(classVal.MatchHdrFields.Ipv6.Config.DestinationAddress)
				}
			}
			//Fill IPV4/Ipv6 Fields - END

			//Fill Transport Fields - START
			if classVal.MatchHdrFields.Transport != nil && classVal.MatchHdrFields.Transport.Config != nil {
				if classVal.MatchHdrFields.Transport.Config.SourcePort != nil {
					srcPortType := reflect.TypeOf(classVal.MatchHdrFields.Transport.Config.SourcePort).Elem()
					switch srcPortType {
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort{}):
						v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort)

						dbV.Field["L4_SRC_PORT"] = v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort.ΛMap()["E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort"][int64(v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort)].Name
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_String{}):
						v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_String)
						dbV.Field["L4_SRC_PORT_RANGE"] = strings.Replace(v.String, "..", "-", 1)
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_Uint16{}):
						v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_Uint16)
						dbV.Field["L4_SRC_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
					}

				}
				if classVal.MatchHdrFields.Transport.Config.DestinationPort != nil {
					dstPortType := reflect.TypeOf(classVal.MatchHdrFields.Transport.Config.DestinationPort).Elem()
					switch dstPortType {
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort{}):
						v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort)

						dbV.Field["L4_DST_PORT"] = v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort.ΛMap()["E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort"][int64(v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort)].Name
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_String{}):
						v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_String)
						dbV.Field["L4_DST_PORT_RANGE"] = strings.Replace(v.String, "..", "-", 1)
					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_Uint16{}):
						v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_Uint16)
						dbV.Field["L4_DST_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
					}
				}
				if classVal.MatchHdrFields.Transport.Config.TcpFlags != nil && len(classVal.MatchHdrFields.Transport.Config.TcpFlags) > 0 {
					log.Infof("Classifier CRUD: TCP_Flags:%v", classVal.MatchHdrFields.Transport.Config.TcpFlags)
					dbV.Field["TCP_FLAGS"] = convertOCTcpFlagsToDbFormat(classVal.MatchHdrFields.Transport.Config.TcpFlags)
					//Fill Transport Fields - END
				}
			}
		} // Hdr fields end

		app.classMapTable[className] = &dbV
	} // Classifier loop end

	return nil
}

func (app *FbsApp) translateCUPolicy(d *db.DB, opcode int) error {
	fbsObj := app.getAppRootObject()

	if fbsObj.Policies == nil || len(fbsObj.Policies.Policy) == 0 {
		log.Info("No policy input for translation")
		return nil
	}

	log.Info("Translating policy")
	policySpecific := isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{}")
	sectionSpecific := isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{}/sections/section{}")

	for policyName, policyVal := range fbsObj.Policies.Policy {
		log.Infof("Policy:%v", policyName)

		policyDbV := db.Value{Field: make(map[string]string)}
		oldPolicyDbV, found := app.policyMapTable[policyName]
		if !found {
			log.Infof("Policy %v does not exist in the processed data", policyName)
			oldPolicyDbV, err := app.getPolicyEntryFromDB(d, policyName)
			if err != nil {
				log.Info(err)
				if isNotFoundError(err) {
					if policySpecific && opcode == CREATE {
						return tlerr.NotFound("Policy %v not found", policyName)
					}
					// Not policy specific request. Ignore the error as we need to create it
				} else {
					return err
				}
			} else {
				log.Infof("Policy %v exists in processed data", policyName)
				if !policySpecific && opcode == CREATE {
					return tlerr.AlreadyExists("Policy %v already exists", policyName)
				}
				policyDbV = oldPolicyDbV
			}
		} else if oldPolicyDbV == nil {
			log.Infof("Policy %v is marked for delete", policyName)
			policyDbV = db.Value{Field: make(map[string]string)}
		} else {
			log.Infof("Policy %v exists in the processed data. Update it", policyName)
			policyDbV = *oldPolicyDbV
		}

		if policyVal.Config != nil {
			ocpolicyType, _ := getPolicyTypeDbStrFromOcEnum(policyVal.Config.Type)
			if ocpolicyType != "" {
				policyDbV.Field["TYPE"] = ocpolicyType
			}

			if policyVal.Config.Description != nil {
				policyDbV.Field["DESCRIPTION"] = *policyVal.Config.Description
			}
		}

		if policyVal.Sections != nil && len(policyVal.Sections.Section) > 0 {
			for className, policySectionVal := range policyVal.Sections.Section {
				log.Infof("Policy:%v Class:%v", policyName, className)

				sectionDbKeyStr := policyName + "|" + className

				sectionDbV := db.Value{Field: make(map[string]string)}
				oldSectionDbV, found := app.policySectionTable[sectionDbKeyStr]
				if !found {
					log.Infof("Section %v does not exist in the processed data", sectionDbKeyStr)
					oldSectionDbV, err := app.getSectionEntryFromDB(d, sectionDbKeyStr)
					if err != nil {
						log.Info(err)
						if isNotFoundError(err) {
							if sectionSpecific && opcode == CREATE {
								return tlerr.NotFound("Section %v not found", sectionDbKeyStr)
							}
							// Not section specific request. Ignore the error as we need to create it
						} else {
							return err
						}
					} else {
						log.Infof("Section %v exists in processed data", sectionDbKeyStr)
						if !sectionSpecific && opcode == CREATE {
							return tlerr.AlreadyExists("Section %v already exists", sectionDbKeyStr)
						}
						sectionDbV = oldSectionDbV
					}
				} else if oldSectionDbV == nil {
					log.Infof("Section %v is marked for delete", sectionDbKeyStr)
					sectionDbV = db.Value{Field: make(map[string]string)}
				} else {
					log.Infof("Policy %v exists in the processed data. Update it", policyName)
					sectionDbV = *oldSectionDbV
				}

				if policySectionVal.Config != nil {
					if policySectionVal.Config.Priority != nil {
						priority := strconv.FormatInt(int64(*(policySectionVal.Config.Priority)), 10)
						sectionDbV.Field["PRIORITY"] = priority
					}
					if policySectionVal.Config.Description != nil {
						sectionDbV.Field["DESCRIPTION"] = *policySectionVal.Config.Description
					}
				}

				if policySectionVal.Monitoring != nil {
					log.Infof("Processing Monitoring")
					if policySectionVal.Monitoring.MirrorSessions != nil && len(policySectionVal.Monitoring.MirrorSessions.MirrorSession) > 0 {
						if len(policySectionVal.Monitoring.MirrorSessions.MirrorSession) > 1 {
							return tlerr.NotSupported("Maximum 1 mirror session supported")
						}
						for _, mirrorSessionVal := range policySectionVal.Monitoring.MirrorSessions.MirrorSession {
							if mirrorSessionVal.Config != nil {
								sectionDbV.Field["SET_MIRROR_SESSION"] = *(mirrorSessionVal.Config.SessionName)
							}
						}
					}
				} else if policySectionVal.Forwarding != nil {
					log.Infof("Processing Forwarding")
					if policySectionVal.Forwarding.Config != nil {
						if *(policySectionVal.Forwarding.Config.Discard) {
							sectionDbV.Field["DEFAULT_PACKET_ACTION"] = SONIC_PACKET_ACTION_DROP
						}
					}

					if policySectionVal.Forwarding.EgressInterfaces != nil && len(policySectionVal.Forwarding.EgressInterfaces.EgressInterface) > 0 {
						log.Infof("Processing Egress interfaces")
						egressIfs := sectionDbV.GetList("SET_INTERFACE")
						for uiIfName, egressIfVal := range policySectionVal.Forwarding.EgressInterfaces.EgressInterface {
							egressIfName := *(utils.GetNativeNameFromUIName(&uiIfName))
							if egressIfVal.Config != nil {
								if egressIfVal.Config.Priority != nil {
									egressIfs = append(egressIfs, egressIfName+"|"+strconv.FormatInt(int64(*egressIfVal.Config.Priority), 10))
								} else {
									egressIfs = append(egressIfs, egressIfName+"|")
								}
							}
						}
						if len(egressIfs) > 0 {
							sectionDbV.SetList("SET_INTERFACE", pruneEgressWithHighestPriority(egressIfs))
						}
					} //EgressInterfaces - END

					if policySectionVal.Forwarding.NextHops != nil && len(policySectionVal.Forwarding.NextHops.NextHop) > 0 {
						log.Infof("Processing Nexthops")
						v4NextHops := sectionDbV.GetList("SET_IP_NEXTHOP")
						v6NextHops := sectionDbV.GetList("SET_IPV6_NEXTHOP")
						for nhopKey, nhopPtr := range policySectionVal.Forwarding.NextHops.NextHop {
							var vrf string
							vrfType := reflect.TypeOf(nhopKey.NetworkInstance).Elem()
							switch vrfType {
							case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union_E_OpenconfigFbsExt_NEXT_HOP_NETWORK_INSTANCE{}):
								vrf = ""
							case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union_String{}):
								vrf = nhopKey.NetworkInstance.(*ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union_String).String
							}
							// WA for Ygot bug
							if vrf == "INTERFACE_NETWORK_INSTANCE" || vrf == "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE" {
								vrf = ""
							}
							nhopsDbStr := nhopKey.IpAddress + "|" + vrf
							if nhopPtr.Config.Priority != nil {
								nhopsDbStr = nhopsDbStr + "|" + strconv.FormatInt(int64(*nhopPtr.Config.Priority), 10)
							} else {
								nhopsDbStr = nhopsDbStr + "|"
							}
							if isV4Address(nhopKey.IpAddress) {
								v4NextHops = append(v4NextHops, nhopsDbStr)
							} else {
								v6NextHops = append(v6NextHops, nhopsDbStr)
							}
						}
						if len(v4NextHops) > 0 {
							sectionDbV.SetList("SET_IP_NEXTHOP", pruneEgressWithHighestPriority(v4NextHops))
						}
						if len(v6NextHops) > 0 {
							sectionDbV.SetList("SET_IPV6_NEXTHOP", pruneEgressWithHighestPriority(v6NextHops))
						}
					} //Nexthops - END
				} else if policySectionVal.Qos != nil { //QOS - START
					if policySectionVal.Qos.Policer != nil {
						if policySectionVal.Qos.Policer.Config != nil {
							if policySectionVal.Qos.Policer.Config.Cir != nil {
								sectionDbV.Field["SET_POLICER_CIR"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Cir), 10)
							}
							if policySectionVal.Qos.Policer.Config.Pir != nil {
								sectionDbV.Field["SET_POLICER_PIR"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Pir), 10)
							}
							if policySectionVal.Qos.Policer.Config.Cbs != nil {
								sectionDbV.Field["SET_POLICER_CBS"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Cbs), 10)
							}
							if policySectionVal.Qos.Policer.Config.Pbs != nil {
								sectionDbV.Field["SET_POLICER_PBS"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Pbs), 10)
							}
						}
					}

					if policySectionVal.Qos.Queuing != nil {
						if policySectionVal.Qos.Queuing.Config != nil {
							sectionDbV.Field["SET_TC"] = strconv.Itoa(int(*policySectionVal.Qos.Queuing.Config.OutputQueueIndex))
						}
					}

					if policySectionVal.Qos.Remark != nil {
						if policySectionVal.Qos.Remark.Config != nil {
							if policySectionVal.Qos.Remark.Config.SetDscp != nil {
								sectionDbV.Field["SET_DSCP"] = strconv.Itoa(int(*policySectionVal.Qos.Remark.Config.SetDscp))
							}
							if policySectionVal.Qos.Remark.Config.SetDot1P != nil {
								sectionDbV.Field["SET_PCP"] = strconv.Itoa(int(*policySectionVal.Qos.Remark.Config.SetDot1P))
							}
						}
					}
				} //Qos - END

				log.Infof("Section %v Data %v", sectionDbKeyStr, sectionDbV.Field)
				app.policySectionTable[sectionDbKeyStr] = &sectionDbV
			} //policySections forloop - END
		} //policySection check
		log.Infof("Policy %v Data %v ", policyVal, policyDbV)
		app.policyMapTable[policyName] = &policyDbV
	} //policies for loop

	return nil
}

func (app *FbsApp) translateCUInterface(d *db.DB, opcode int) error {
	var err error
	fbsObj := app.getAppRootObject()

	log.Info("Translating interfaces")
	if fbsObj.Interfaces != nil && len(fbsObj.Interfaces.Interface) > 0 {
		for ifId, ifVal := range fbsObj.Interfaces.Interface {

			if nil == ifVal.InterfaceRef || nil == ifVal.InterfaceRef.Config || nil == ifVal.InterfaceRef.Config.Interface {
				goto SkipIntfCheck
			}

			if nil != ifVal.InterfaceRef.Config.Subinterface {
				return tlerr.NotSupported("SubInterface not supported")
			}

			if ifId != *ifVal.InterfaceRef.Config.Interface {
				return tlerr.NotSupported("Different ID %s and Interface name %s not supported", ifId, *ifVal.InterfaceRef.Config.Interface)
			}

		SkipIntfCheck:
			polBindDbV := db.Value{Field: make(map[string]string)}
			nativeName := *utils.GetNativeNameFromUIName(&ifId)
			oldPolBindDbV, found := app.policyBindingTable[nativeName]
			if found {
				if nil != oldPolBindDbV {
					polBindDbV = *oldPolBindDbV
				}
			} else {
				polBindDbV, err = app.getPolicyBindingEntryFromDB(d, nativeName)
				if err != nil {
					if !isNotFoundError(err) {
						return err
					} else {
						polBindDbV = db.Value{Field: make(map[string]string)}
					}
				}
			}

			if ifVal.IngressPolicies != nil {
				if ifVal.IngressPolicies.Forwarding != nil {
					if ifVal.IngressPolicies.Forwarding.Config != nil {
						if oldPolicy, found := polBindDbV.Field["INGRESS_FORWARDING_POLICY"]; found && opcode == CREATE {
							if oldPolicy != *ifVal.IngressPolicies.Forwarding.Config.PolicyName {
								return tlerr.AlreadyExistsErr("different-policy-already-applied", "", "%v policy already applied", oldPolicy)
							} else {
								return tlerr.AlreadyExistsErr("same-policy-already-applied", "", "%v policy already applied", oldPolicy)
							}
						}
						polBindDbV.Field["INGRESS_FORWARDING_POLICY"] = *(ifVal.IngressPolicies.Forwarding.Config.PolicyName)
					}
				}
				if ifVal.IngressPolicies.Monitoring != nil {
					if ifVal.IngressPolicies.Monitoring.Config != nil {
						if oldPolicy, found := polBindDbV.Field["INGRESS_MONITORING_POLICY"]; found && opcode == CREATE {
							if oldPolicy != *ifVal.IngressPolicies.Monitoring.Config.PolicyName {
								return tlerr.AlreadyExistsErr("different-policy-already-applied", "", "%v policy already applied", oldPolicy)
							} else {
								return tlerr.AlreadyExistsErr("same-policy-already-applied", "", "%v policy already applied", oldPolicy)
							}
						}
						polBindDbV.Field["INGRESS_MONITORING_POLICY"] = *(ifVal.IngressPolicies.Monitoring.Config.PolicyName)
					}
				}
				if ifVal.IngressPolicies.Qos != nil {
					if ifVal.IngressPolicies.Qos.Config != nil {
						if oldPolicy, found := polBindDbV.Field["INGRESS_QOS_POLICY"]; found && opcode == CREATE {
							if oldPolicy != *ifVal.IngressPolicies.Qos.Config.PolicyName {
								return tlerr.AlreadyExistsErr("different-policy-already-applied", "", "%v policy already applied", oldPolicy)
							} else {
								return tlerr.AlreadyExistsErr("same-policy-already-applied", "", "%v policy already applied", oldPolicy)
							}
						}
						polBindDbV.Field["INGRESS_QOS_POLICY"] = *(ifVal.IngressPolicies.Qos.Config.PolicyName)
					}
				}
			}

			if ifVal.EgressPolicies != nil {
				if ifVal.EgressPolicies.Qos != nil {
					if ifVal.EgressPolicies.Qos.Config != nil {
						if oldPolicy, found := polBindDbV.Field["EGRESS_QOS_POLICY"]; found && opcode == CREATE {
							if oldPolicy != *ifVal.EgressPolicies.Qos.Config.PolicyName {
								return tlerr.AlreadyExistsErr("different-policy-already-applied", "", "%v policy already applied", oldPolicy)
							} else {
								return tlerr.AlreadyExistsErr("same-policy-already-applied", "", "%v policy already applied", oldPolicy)
							}
						}
						polBindDbV.Field["EGRESS_QOS_POLICY"] = *(ifVal.EgressPolicies.Qos.Config.PolicyName)
					}
				}
			}

			log.Infof("Intf:%v %v Data %v", ifId, nativeName, polBindDbV)
			app.policyBindingTable[nativeName] = &polBindDbV
		} //Fbs Interfaces forloop - END
	}

	return nil
}

func (app *FbsApp) translateDelClassifier(d *db.DB) error {
	fbsObj := app.getAppRootObject()

	if fbsObj.Classifiers == nil || len(fbsObj.Classifiers.Classifier) == 0 {
		log.Info("Delete All classifiers")
		keys, err := d.GetKeys(classTblTs)
		if err != nil {
			return err
		}
		for _, key := range keys {
			app.classMapTable[key.Get(0)] = nil
		}
		return nil
	}

	targetNode, err := getTargetNodeYangSchema(app.pathInfo.Path, (*app.ygotRoot).(*ocbinds.Device))
	if err != nil {
		log.Info(err)
		return err
	}

	for classKey, classVal := range fbsObj.Classifiers.Classifier {
		log.Infof("Classifier %v DELETE operation; classVal ", classKey)

		var existingVal db.Value
		existingVal, err := app.getClassifierEntryFromDB(d, classKey)
		if nil != err {
			if isNotFoundError(err) {
				log.Infof("Classifier %v not present", classKey)
				continue
			}
			return err
		}

		if classVal.Config != nil { //class config level delete
			if targetNode.Name == "match-type" {
				return tlerr.InvalidArgs("Classifier match type delete not allowed")
			} else if targetNode.Name == "description" {
				delete(existingVal.Field, "DESCRIPTION")
			} else {
				return tlerr.NotSupported("Delete not supported for this URI")
			}
			app.classMapTable[classKey] = &existingVal
		} else if classVal.MatchAcl != nil { //class  matchacl delete
			delete(existingVal.Field, "ACL_NAME")
			delete(existingVal.Field, "ACL_TYPE")
			app.classMapTable[classKey] = &existingVal
		} else if classVal.MatchHdrFields != nil { //class matchHdrFields delete
			delL2Flds := targetNode.Name == "match-hdr-fields"
			delIpFlds := targetNode.Name == "match-hdr-fields"
			delIpv4Flds := targetNode.Name == "match-hdr-fields"
			delIpv6Flds := targetNode.Name == "match-hdr-fields"
			delTransFlds := targetNode.Name == "match-hdr-fields"

			if classVal.MatchHdrFields.L2 != nil { //class L2 matchhdrfields
				if classVal.MatchHdrFields.L2.Config != nil { //class L2 matchhdrfields config
					if targetNode.Name == "source-mac" {
						delete(existingVal.Field, "SRC_MAC")
					} else if targetNode.Name == "source-mac-mask" {
						oldValue, found := existingVal.Field["SRC_MAC"]
						if found {
							existingVal.Field["SRC_MAC"] = strings.Split(oldValue, "/")[0]
						} else {
							delete(existingVal.Field, "SRC_MAC")
						}
					} else if targetNode.Name == "destination-mac" {
						delete(existingVal.Field, "DST_MAC")
					} else if targetNode.Name == "destination-mac-mask" {
						oldValue, found := existingVal.Field["DST_MAC"]
						if found {
							existingVal.Field["DST_MAC"] = strings.Split(oldValue, "/")[0]
						} else {
							delete(existingVal.Field, "DST_MAC")
						}
					} else if targetNode.Name == "ethertype" {
						delete(existingVal.Field, "ETHER_TYPE")
					} else if targetNode.Name == "pcp" {
						delete(existingVal.Field, "PCP")
					} else if targetNode.Name == "dei" {
						delete(existingVal.Field, "DEI")
					} else if targetNode.Name == "vlanid" {
						delete(existingVal.Field, "VLAN")
					} else {
						delL2Flds = true
					}
				} else {
					delL2Flds = true
				}
			} else if classVal.MatchHdrFields.Ip != nil {
				if classVal.MatchHdrFields.Ip.Config != nil {
					if targetNode.Name == "dscp" {
						delete(existingVal.Field, "DSCP")
					} else if targetNode.Name == "protocol" {
						delete(existingVal.Field, "IP_PROTOCOL")
					} else {
						delIpFlds = true
					}
				} else {
					delIpFlds = true
				}
			} else if classVal.MatchHdrFields.Ipv4 != nil { //class Ipv4 matchhdrfields
				if classVal.MatchHdrFields.Ipv4.Config != nil { //class Ipv4 matchhdrfields config
					if targetNode.Name == "source-address" {
						delete(existingVal.Field, "SRC_IP")
					} else if targetNode.Name == "destination-address" {
						delete(existingVal.Field, "DST_IP")
					} else {
						delIpv4Flds = true
					}
				} else {
					delIpv4Flds = true
				}
			} else if classVal.MatchHdrFields.Ipv6 != nil { //class Ipv6 matchhdrfields
				if classVal.MatchHdrFields.Ipv6.Config != nil { //class Ipv4 matchhdrfields config
					if targetNode.Name == "source-address" {
						delete(existingVal.Field, "SRC_IPV6")
					} else if targetNode.Name == "destination-address" {
						delete(existingVal.Field, "DST_IPV6")
					} else {
						delIpv6Flds = true
					}
				} else {
					delIpv6Flds = true
				}
			} else if classVal.MatchHdrFields.Transport != nil { //class Ipv6 matchhdrfields
				if classVal.MatchHdrFields.Transport.Config != nil { //class Ipv4 matchhdrfields config
					if targetNode.Name == "source-port" {
						delete(existingVal.Field, "L4_SRC_PORT")
						delete(existingVal.Field, "L4_SRC_PORT_RANGE")
					} else if targetNode.Name == "destination-port" {
						delete(existingVal.Field, "L4_DST_PORT")
						delete(existingVal.Field, "L4_DST_PORT_RANGE")
					} else if targetNode.Name == "tcp-flags" {
						if len(classVal.MatchHdrFields.Transport.Config.TcpFlags) > 0 {
							log.Info("Delete specific flag")
							existing, found := existingVal.Field["TCP_FLAGS"]
							if found {
								var newTcpFlags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS
								for _, flag := range getTransportConfigTcpFlags(existing) {
									if flag != classVal.MatchHdrFields.Transport.Config.TcpFlags[0] {
										newTcpFlags = append(newTcpFlags, flag)
									}
								}
								if len(newTcpFlags) > 0 {
									existingVal.Field["TCP_FLAGS"] = convertOCTcpFlagsToDbFormat(newTcpFlags)
								} else {
									delete(existingVal.Field, "TCP_FLAGS")
								}
							}
						} else {
							log.Info("Delete all flag")
							delete(existingVal.Field, "TCP_FLAGS")
						}
					} else if targetNode.Name == "icmp-code" {
						delete(existingVal.Field, "ICMP_CODE")
					} else if targetNode.Name == "icmp-type" {
						delete(existingVal.Field, "ICMP_TYPE")
					} else {
						delTransFlds = true
					}
				} else {
					delTransFlds = true
				}
			} //transport
			if delL2Flds {
				delete(existingVal.Field, "SRC_MAC")
				delete(existingVal.Field, "DST_MAC")
				delete(existingVal.Field, "ETHER_TYPE")
				delete(existingVal.Field, "PCP")
				delete(existingVal.Field, "DEI")
				delete(existingVal.Field, "VLAN")
			}
			if delIpFlds {
				delete(existingVal.Field, "DSCP")
				delete(existingVal.Field, "IP_PROTOCOL")
			}
			if delIpv4Flds {
				delete(existingVal.Field, "SRC_IP")
				delete(existingVal.Field, "DST_IP")
			}
			if delIpv6Flds {
				delete(existingVal.Field, "SRC_IPV6")
				delete(existingVal.Field, "DST_IPV6")
			}
			if delTransFlds {
				delete(existingVal.Field, "L4_SRC_PORT")
				delete(existingVal.Field, "L4_SRC_PORT_RANGE")
				delete(existingVal.Field, "L4_DST_PORT")
				delete(existingVal.Field, "L4_DST_PORT_RANGE")
				delete(existingVal.Field, "TCP_FLAGS")
				delete(existingVal.Field, "ICMP_CODE")
				delete(existingVal.Field, "ICMP_TYPE")
			}
			app.classMapTable[classKey] = &existingVal
		} else { //matchhdrfields
			app.classMapTable[classKey] = nil
		}
	} //classifiers forloop

	return nil
}

func (app *FbsApp) translateDelPolicy(d *db.DB) error {
	fbsObj := app.getAppRootObject()

	if fbsObj.Policies == nil || len(fbsObj.Policies.Policy) == 0 {
		log.Info("Delete all policies")
		keys, err := d.GetKeys(policyTblTs)
		if err != nil {
			return err
		}
		for _, key := range keys {
			app.policyMapTable[key.Get(0)] = nil
		}
		return nil
	}

	targetNode, _ := getTargetNodeYangSchema(app.pathInfo.Path, (*app.ygotRoot).(*ocbinds.Device))

	for policyKey, policyVal := range fbsObj.Policies.Policy {
		log.Infof("DELETE Policy:%v related", policyKey)

		if policyVal.Config != nil { //policy config level delete
			existingEntry, err := app.getPolicyEntryFromDB(d, policyKey)
			if err != nil {
				if isNotFoundError(err) {
					log.Infof("Policy %v not present", policyKey)
					continue
				}
				return err
			}

			if targetNode.Name == "type" {
				return tlerr.NotSupported("Type delete not allowed")
			} else if targetNode.Name == "description" {
				delete(existingEntry.Field, "DESCRIPTION")
			} else {
				return tlerr.NotSupported("Delete not supported for this URI")
			}
			app.policyMapTable[policyKey] = &existingEntry
		} else if policyVal.Sections != nil { //policy Sections
			if len(policyVal.Sections.Section) > 0 { //policy section
				for className, policySectionVal := range policyVal.Sections.Section {
					sectionDbKeyStr := policyKey + "|" + className
					log.Infof("DELETE Section:%v related", sectionDbKeyStr)

					sectionDbV, err := app.getSectionEntryFromDB(d, sectionDbKeyStr)
					if err != nil {
						if isNotFoundError(err) {
							log.Infof("Section %v not present", sectionDbKeyStr)
							continue
						}
						return err
					}

					if policySectionVal.Config != nil { //policy section config
						if targetNode.Name == "priority" {
							return tlerr.NotSupported("Priority delete not allowed")
						} else if targetNode.Name == "description" {
							delete(sectionDbV.Field, "DESCRIPTION")
						} else {
							return tlerr.NotSupported("Delete not supported for this URI")
						}
						app.policySectionTable[sectionDbKeyStr] = &sectionDbV
					} else if policySectionVal.Qos != nil { //policy section Qos
						delRemark := false
						delPolicer := false
						delQueue := false
						if policySectionVal.Qos.Remark != nil { //policy section Qos Remark
							if policySectionVal.Qos.Remark.Config != nil { //policy section Qos Remark
								if targetNode.Name == "set-dscp" {
									delete(sectionDbV.Field, "SET_DSCP")
								} else if targetNode.Name == "set-dot1p" {
									delete(sectionDbV.Field, "SET_PCP")
								} else {
									delRemark = true
								}
							} else { //qos remark config
								delRemark = true
							}
						} else if policySectionVal.Qos.Policer != nil { //policer
							if policySectionVal.Qos.Policer.Config != nil { //policer config
								if targetNode.Name == "cir" {
									delete(sectionDbV.Field, "SET_POLICER_CIR")
								} else if targetNode.Name == "pir" {
									delete(sectionDbV.Field, "SET_POLICER_PIR")
								} else if targetNode.Name == "bc" {
									delete(sectionDbV.Field, "SET_POLICER_CBS")
								} else if targetNode.Name == "be" {
									delete(sectionDbV.Field, "SET_POLICER_PBS")
								} else {
									delPolicer = true
								}
							} else {
								delPolicer = true
							}
						} else if policySectionVal.Qos.Queuing != nil { //queuing
							if policySectionVal.Qos.Queuing.Config != nil { //queuing config
								if targetNode.Name == "output-queue-index" {
									delete(sectionDbV.Field, "SET_TC")
								} else {
									delQueue = true
								}
							} else {
								delRemark = true
							}
						} else {
							delRemark = true
							delPolicer = true
							delQueue = true
						}

						if delRemark {
							delete(sectionDbV.Field, "SET_DSCP")
							delete(sectionDbV.Field, "SET_PCP")
						}
						if delPolicer {
							delete(sectionDbV.Field, "SET_POLICER_CIR")
							delete(sectionDbV.Field, "SET_POLICER_PIR")
							delete(sectionDbV.Field, "SET_POLICER_CBS")
							delete(sectionDbV.Field, "SET_POLICER_PBS")
						}
						if delQueue {
							delete(sectionDbV.Field, "SET_TC")
						}
						app.policySectionTable[sectionDbKeyStr] = &sectionDbV
					} else if policySectionVal.Monitoring != nil { //monitoring
						// TODO Handle specific session delete
						if policySectionVal.Monitoring.MirrorSessions != nil && len(policySectionVal.Monitoring.MirrorSessions.MirrorSession) > 0 {
							for _, mirrorSessionVal := range policySectionVal.Monitoring.MirrorSessions.MirrorSession {
								if mirrorSessionVal.Config != nil {
									delete(sectionDbV.Field, "SET_MIRROR_SESSION")
								}
							}
						} else {
							delete(sectionDbV.Field, "SET_MIRROR_SESSION")
						}
						app.policySectionTable[sectionDbKeyStr] = &sectionDbV
					} else if policySectionVal.Forwarding != nil { //forwarding
						if policySectionVal.Forwarding.Config != nil {
							// As of now only 1 leaf exists. Just delete it blindly
							delete(sectionDbV.Field, "DEFAULT_PACKET_ACTION")
						} else if policySectionVal.Forwarding.EgressInterfaces != nil {
							if len(policySectionVal.Forwarding.EgressInterfaces.EgressInterface) > 0 {
								egressIfs := sectionDbV.GetList("SET_INTERFACE")
								for egressIfName, egressIfVal := range policySectionVal.Forwarding.EgressInterfaces.EgressInterface {
									var delKey string
									var exact bool
									nativeName := *utils.GetNativeNameFromUIName(&egressIfName)
									if (egressIfVal.Config != nil) && (egressIfVal.Config.Priority != nil) {
										delKey = nativeName + "|" + strconv.FormatInt(int64(*egressIfVal.Config.Priority), 10)
										exact = true
									} else {
										delKey = nativeName + "|"
										exact = false
									}
									for _, intf := range egressIfs {
										if exact && intf == delKey {
											egressIfs = removeElement(egressIfs, delKey)
											break
										} else if !exact && strings.HasPrefix(intf, delKey) {
											egressIfs = removeElement(egressIfs, intf)
											break
										}
									}
								}
								if len(egressIfs) > 0 {
									sectionDbV.Field["SET_INTERFACE@"] = strings.Join(egressIfs, ",")
								} else {
									delete(sectionDbV.Field, "SET_INTERFACE@")
								}
							} else {
								delete(sectionDbV.Field, "SET_INTERFACE@")
							}
						} else if policySectionVal.Forwarding.NextHops != nil {
							if len(policySectionVal.Forwarding.NextHops.NextHop) > 0 {
								v4NextHops := sectionDbV.GetList("SET_IP_NEXTHOP")
								v6NextHops := sectionDbV.GetList("SET_IPV6_NEXTHOP")
								for nhopKey, nhopPtr := range policySectionVal.Forwarding.NextHops.NextHop {
									var vrf string
									vrfType := reflect.TypeOf(nhopKey.NetworkInstance).Elem()
									switch vrfType {
									case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union_E_OpenconfigFbsExt_NEXT_HOP_NETWORK_INSTANCE{}):
										vrf = ""
									case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union_String{}):
										vrf = nhopKey.NetworkInstance.(*ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union_String).String
									}
									// WA for Ygot bug
									if vrf == "INTERFACE_NETWORK_INSTANCE" || vrf == "openconfig-fbs-ext:INTERFACE_NETWORK_INSTANCE" {
										vrf = ""
									}
									nhopsDbStr := nhopKey.IpAddress + "|" + vrf
									isIpv4 := isV4Address(nhopKey.IpAddress)
									exact := false
									if nhopPtr.Config != nil && nhopPtr.Config.Priority != nil {
										nhopsDbStr = nhopsDbStr + "|" + strconv.FormatInt(int64(*nhopPtr.Config.Priority), 10)
										exact = true
									} else {
										nhopsDbStr = nhopsDbStr + "|"
									}
									log.Infof("NextHop to delete is %v Exact %v", nhopsDbStr, exact)
									if isIpv4 {
										for _, entry := range v4NextHops {
											if exact && entry == nhopsDbStr {
												v4NextHops = removeElement(v4NextHops, entry)
												break
											} else if !exact && strings.HasPrefix(entry, nhopsDbStr) {
												v4NextHops = removeElement(v4NextHops, entry)
												break
											}
										}
									} else {
										for _, entry := range v6NextHops {
											if exact && entry == nhopsDbStr {
												v6NextHops = removeElement(v6NextHops, entry)
												break
											} else if !exact && strings.HasPrefix(entry, nhopsDbStr) {
												v6NextHops = removeElement(v6NextHops, entry)
												break
											}
										}
									}
								}
								if len(v4NextHops) > 0 {
									sectionDbV.Field["SET_IP_NEXTHOP@"] = strings.Join(v4NextHops, ",")
								} else {
									delete(sectionDbV.Field, "SET_IP_NEXTHOP@")
								}
								if len(v6NextHops) > 0 {
									sectionDbV.Field["SET_IPV6_NEXTHOP@"] = strings.Join(v6NextHops, ",")
								} else {
									delete(sectionDbV.Field, "SET_IPV6_NEXTHOP@")
								}
							} else {
								delete(sectionDbV.Field, "SET_IP_NEXTHOP@")
								delete(sectionDbV.Field, "SET_IPV6_NEXTHOP@")
							} // Nexthops END
						} else {
							delete(sectionDbV.Field, "DEFAULT_PACKET_ACTION")
							delete(sectionDbV.Field, "SET_INTERFACE@")
							delete(sectionDbV.Field, "SET_IP_NEXTHOP@")
							delete(sectionDbV.Field, "SET_IPV6_NEXTHOP@")
						}
						app.policySectionTable[sectionDbKeyStr] = &sectionDbV
					} else { //Forwarding
						log.Infof("Delete section %v", sectionDbKeyStr)
						app.policySectionTable[sectionDbKeyStr] = nil
					}
				} // END section loop
			} else {
				keys, err := d.GetKeysPattern(policySectionTblTs, db.Key{[]string{policyKey, "*"}})
				if err != nil {
					if isNotFoundError(err) {
						log.Infof("No sections present for policy %v", policyKey)
						continue
					}
					return err
				}
				for _, key := range keys {
					app.policySectionTable[key.Get(0)+"|"+key.Get(1)] = nil
				}
			}
		} else {
			log.Infof("Delete policy %v", policyKey)
			app.policyMapTable[policyKey] = nil
		}
	} //policies for loop

	return nil
}

func (app *FbsApp) translateDelInterface(d *db.DB) error {
	fbsObj := app.getAppRootObject()

	if fbsObj == nil || fbsObj.Interfaces == nil || len(fbsObj.Interfaces.Interface) == 0 {
		log.Info("Delete all interface bindings")
		keys, err := d.GetKeys(policyBindingTblTs)
		if err != nil {
			return err
		}
		for _, key := range keys {
			app.policyBindingTable[key.Get(0)] = nil
		}
		return nil
	}

	for intfName, intfPtr := range fbsObj.Interfaces.Interface {
		if intfPtr.Config != nil || intfPtr.InterfaceRef != nil {
			return tlerr.NotSupported("Delete of this URI is not supported")
		}
		nativeName := *utils.GetNativeNameFromUIName(&intfName)
		dbV, err := app.getPolicyBindingEntryFromDB(d, nativeName)
		if err != nil {
			if isNotFoundError(err) {
				log.Infof("No bindings present for %v:%v", intfName, nativeName)
				err = nil
				continue
			}
		}
		if intfPtr.IngressPolicies != nil {
			if intfPtr.IngressPolicies.Qos != nil {
				delete(dbV.Field, "INGRESS_QOS_POLICY")
			} else if intfPtr.IngressPolicies.Monitoring != nil {
				delete(dbV.Field, "INGRESS_MONITORING_POLICY")
			} else if intfPtr.IngressPolicies.Forwarding != nil {
				delete(dbV.Field, "INGRESS_FORWARDING_POLICY")
			} else {
				delete(dbV.Field, "INGRESS_QOS_POLICY")
				delete(dbV.Field, "INGRESS_MONITORING_POLICY")
				delete(dbV.Field, "INGRESS_FORWARDING_POLICY")
			}
		} else if intfPtr.EgressPolicies != nil {
			if intfPtr.EgressPolicies.Qos != nil {
				delete(dbV.Field, "EGRESS_QOS_POLICY")
			} else {
				delete(dbV.Field, "EGRESS_QOS_POLICY")
			}
		} else {
			log.Infof("Delete all bindings for interface %v", nativeName)
			app.policyBindingTable[nativeName] = nil
			continue
		}

		if len(dbV.Field) > 0 {
			app.policyBindingTable[nativeName] = &dbV
		} else {
			app.policyBindingTable[nativeName] = nil
		}
	}

	return nil
}

// processCRUD flushes the in memory contents to the DB
// It uses the following method
// If the value is nil it will be deleted.
// If the value is not nil but is present in cache it will be updated
// if the value is not nil but is not present in cache it will be created
// Dependent tables will be applied first, followed by independent.
// Order is Binding, Section, Policy, Classifier
func (app *FbsApp) processCRUD(d *db.DB, opcode int) error {
	var err error

	if opcode == DELETE {
		err = app.processOperation(d, false, 1<<DELETE)
	} else if opcode == CREATE || opcode == UPDATE {
		err = app.processOperation(d, false, 1<<CREATE|1<<UPDATE)
	} else {
		// Replace needs to be staged.
		// Step 1 is to delete all in order used by delete
		err = app.processOperation(d, true, 1<<DELETE)
		// Step 2 is to create in the order used by create
		if err == nil {
			err = app.processOperation(d, true, 1<<CREATE|1<<UPDATE)
		}
	}

	return err
}

func (app *FbsApp) processFbsGet(dbs [db.MaxDB]*db.DB) error {
	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers") {
		return app.processClassifiersGet(dbs)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/policies") {
		return app.processPoliciesGet(dbs)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces") {
		return app.processInterfacesGet(dbs)
	} else {
		root := app.getAppRootObject()
		ygot.BuildEmptyTree(root)

		err := app.processClassifiersGet(dbs)
		if err == nil {
			err = app.processPoliciesGet(dbs)
		}
		if err == nil {
			app.processInterfacesGet(dbs)
		}
		return err
	}
}

func (app *FbsApp) processClassifiersGet(dbs [db.MaxDB]*db.DB) error {
	var err error

	fbsObj := app.getAppRootObject()

	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers/classifier{}") { //class level request
		className := app.pathInfo.Var("class-name")
		classObj := fbsObj.Classifiers.Classifier[className]
		log.Infof("Class %v", className)

		err = app.fillFbsClassDetails(dbs, className, classObj)
	} else { //top level get
		log.Infof("Get all classifiers")

		classKeys, err := dbs[db.ConfigDB].GetKeys(classTblTs)
		if err != nil {
			return err
		}

		for _, key := range classKeys {
			className := key.Get(0)
			log.Infof("Classifier get %v", className)
			classObj, _ := fbsObj.Classifiers.NewClassifier(className)
			err = app.fillFbsClassDetails(dbs, className, classObj)
			if err != nil {
				return err
			}
		}
	}

	return err
}

func (app *FbsApp) processPoliciesGet(dbs [db.MaxDB]*db.DB) error {
	fbsObj := app.getAppRootObject()

	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{}") { //policy level request
		policyName := app.pathInfo.Var("policy-name")
		log.Infof("Get for specific policy %v", policyName)
		policyObj := fbsObj.Policies.Policy[policyName]

		err := app.fillFbsPolicyDetails(dbs, policyName, policyObj)
		if err != nil {
			return err
		}
	} else { //top level get
		log.Infof("Policy top level get")

		PolicyTbl, err := dbs[db.ConfigDB].GetTable(policyTblTs)
		if err != nil {
			log.Error(err)
			return err
		}

		policyKeys, _ := PolicyTbl.GetKeys()
		for _, key := range policyKeys {
			policyName := key.Get(0)
			log.Infof("Policy Name %v", policyName)
			policyObj, _ := fbsObj.Policies.NewPolicy(policyName)
			err = app.fillFbsPolicyDetails(dbs, policyName, policyObj)
			if err != nil {
				return err
			}
		}

		return nil
	}

	return nil
}

func (app *FbsApp) processInterfacesGet(dbs [db.MaxDB]*db.DB) error {
	var err error
	fbsObj := app.getAppRootObject()
	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{}") { //inerface level request
		interfaceId := app.pathInfo.Var("id")
		log.Infof("Interface Get InterfaceId:%v", interfaceId)

		interfaceObj := fbsObj.Interfaces.Interface[interfaceId]
		err = app.fillFbsInterfaceDetails(dbs, interfaceId, interfaceObj)
		if err != nil {
			return err
		}
	} else { //top level get
		log.Infof("fbs Interface Get;top level Get")

		interfaceKeys, err := dbs[db.ConfigDB].GetKeys(policyBindingTblTs)
		if err != nil {
			log.Errorf("Couldn't get Policy Binding table keys. Err %v", err)
			return err
		}

		for _, key := range interfaceKeys {
			interfaceId := key.Get(0)
			uiIfName := *utils.GetUINameFromNativeName(&interfaceId)
			log.Infof("Key:%v interfaceId:%v:%v", key, interfaceId, uiIfName)
			interfaceObj, _ := fbsObj.Interfaces.NewInterface(uiIfName)
			err = app.fillFbsInterfaceDetails(dbs, uiIfName, interfaceObj)
			if err != nil {
				return err
			}
		}
	}

	return err
}

/*
 * Helper Functions
 */
func isV4Address(str string) bool {
	ip := net.ParseIP(str)
	return ip != nil && strings.Contains(str, ".")
}

func getClassMatchTypeOCEnumFromDbStr(val string) (ocbinds.E_OpenconfigFbsExt_MATCH_TYPE, error) {
	switch val {
	case SONIC_CLASS_MATCH_TYPE_ACL, "openconfig-fbs-ext:MATCH_ACL":
		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_ACL, nil
	case SONIC_CLASS_MATCH_TYPE_FIELDS, "openconfig-fbs-ext:MATCH_FIELDS":
		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_FIELDS, nil
	default:
		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_UNSET,
			tlerr.NotSupported("FBS Class Match Type '%s' not supported", val)
	}
}

func getClassMatchTypeDbStrFromOcEnum(ocMatchType ocbinds.E_OpenconfigFbsExt_MATCH_TYPE) string {
	if ocMatchType == ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_ACL {
		return SONIC_CLASS_MATCH_TYPE_ACL
	} else if ocMatchType == ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_FIELDS {
		return SONIC_CLASS_MATCH_TYPE_FIELDS
	}

	return ""
}

func getPolicyTypeOCEnumFromDbStr(val string) (ocbinds.E_OpenconfigFbsExt_POLICY_TYPE, error) {
	switch val {
	case SONIC_POLICY_TYPE_QOS, "openconfig-fbs-ext:QOS":
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_QOS, nil
	case SONIC_POLICY_TYPE_FORWARDING, "openconfig-fbs-ext:FORWARDING":
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_FORWARDING, nil
	case SONIC_POLICY_TYPE_MONITORING, "openconfig-fbs-ext:MONITORING":
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_MONITORING, nil
	default:
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_UNSET,
			tlerr.NotSupported("FBS Policy Type '%s' not supported", val)
	}
}

func getPolicyTypeDbStrFromOcEnum(ocPolicyType ocbinds.E_OpenconfigFbsExt_POLICY_TYPE) (string, error) {
	if ocPolicyType == ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_QOS {
		return SONIC_POLICY_TYPE_QOS, nil
	} else if ocPolicyType == ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_MONITORING {
		return SONIC_POLICY_TYPE_MONITORING, nil
	} else if ocPolicyType == ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_FORWARDING {
		return SONIC_POLICY_TYPE_FORWARDING, nil
	}

	return "", nil
}

func (app *FbsApp) getClassifierEntryFromDB(d *db.DB, className string) (db.Value, error) {
	if val, found := app.classMapCache[className]; found {
		log.Infof("Return from cache %v", val)
		return val, nil
	}

	dbVal, err := d.GetEntry(classTblTs, db.Key{[]string{className}})
	if nil != err {
		log.Info(err)
		return dbVal, err
	}

	app.classMapCache[className] = dbVal
	log.Infof("Return from DB %v", dbVal)

	return dbVal, err
}

func (app *FbsApp) getPolicyEntryFromDB(d *db.DB, policyName string) (db.Value, error) {
	if val, found := app.policyMapCache[policyName]; found {
		log.Infof("Return from cache %v", val)
		return val, nil
	}

	dbVal, err := d.GetEntry(policyTblTs, db.Key{[]string{policyName}})
	if nil != err {
		return dbVal, err
	}

	app.policyMapCache[policyName] = dbVal
	log.Infof("Return from DB %v", dbVal)

	return dbVal, err
}

func (app *FbsApp) getSectionEntryFromDB(d *db.DB, sectionName string) (db.Value, error) {
	if val, found := app.policySectionCache[sectionName]; found {
		log.Infof("Return from cache %v", val)
		return val, nil
	}

	dbVal, err := d.GetEntry(policySectionTblTs, db.Key{[]string{sectionName}})
	if nil != err {
		return dbVal, err
	}

	app.policySectionCache[sectionName] = dbVal
	log.Infof("Return from DB %v", dbVal)

	return dbVal, err
}

func (app *FbsApp) getPolicyBindingEntryFromDB(d *db.DB, intfName string) (db.Value, error) {
	if val, found := app.classMapCache[intfName]; found {
		log.Infof("Return from cache %v", val)
		return val, nil
	}

	dbVal, err := d.GetEntry(policyBindingTblTs, db.Key{[]string{intfName}})
	if nil != err {
		return dbVal, err
	}

	app.policyBindingCache[intfName] = dbVal
	log.Infof("Return from DB %v", dbVal)

	return dbVal, err
}

func (app *FbsApp) fillFbsClassDetails(dbs [db.MaxDB]*db.DB, className string, classData *ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier) error {

	classTblVal, err := app.getClassifierEntryFromDB(dbs[db.ConfigDB], className)
	if err != nil {
		return err
	}

	ygot.BuildEmptyTree(classData)

	classData.ClassName = &className
	matchType := classTblVal.Get("MATCH_TYPE")

	log.Infof("className:%v and MatchType:%v", className, matchType)

	classData.Config.Name = &className
	classData.State.Name = classData.Config.Name
	classData.Config.MatchType, _ = getClassMatchTypeOCEnumFromDbStr(matchType)
	classData.State.MatchType = classData.Config.MatchType

	if strVal, found := classTblVal.Field["DESCRIPTION"]; found {
		classData.Config.Description = &strVal
		classData.State.Description = &strVal
	}

	if matchType == SONIC_CLASS_MATCH_TYPE_ACL {
		aclNameInDb := classTblVal.Get("ACL_NAME")
		if aclTypeInDb, found := classTblVal.Field["ACL_TYPE"]; found {
			aclType := ocbinds.OpenconfigAcl_ACL_TYPE_UNSET
			if aclTypeInDb == "L2" {
				aclType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2
			} else if aclTypeInDb == "L3" {
				aclType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4
			} else if aclTypeInDb == "L3V6" {
				aclType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4
			}
			classData.MatchAcl.Config.AclName = &aclNameInDb
			classData.MatchAcl.Config.AclType = aclType

			classData.MatchAcl.State.AclName = classData.MatchAcl.Config.AclName
			classData.MatchAcl.State.AclType = classData.MatchAcl.Config.AclType
		}
	} else if matchType == SONIC_CLASS_MATCH_TYPE_FIELDS {
		matchAll := true
		ygot.BuildEmptyTree(classData.MatchHdrFields)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Config)
		ygot.BuildEmptyTree(classData.MatchHdrFields.State)
		classData.MatchHdrFields.Config.MatchAll = &matchAll
		classData.MatchHdrFields.State.MatchAll = classData.MatchHdrFields.Config.MatchAll

		//Fill L2 Fields - START
		ygot.BuildEmptyTree(classData.MatchHdrFields.L2)
		ygot.BuildEmptyTree(classData.MatchHdrFields.L2.Config)
		ygot.BuildEmptyTree(classData.MatchHdrFields.L2.State)
		l2Filled := false
		if strVal, found := classTblVal.Field["DST_MAC"]; found {
			splitStr := strings.Split(strVal, "/")
			classData.MatchHdrFields.L2.Config.DestinationMac = &splitStr[0]
			classData.MatchHdrFields.L2.State.DestinationMac = &splitStr[0]
			if len(splitStr) == 2 {
				classData.MatchHdrFields.L2.Config.DestinationMacMask = &splitStr[1]
				classData.MatchHdrFields.L2.State.DestinationMacMask = &splitStr[1]
			}
			l2Filled = found
		}
		if strVal, found := classTblVal.Field["SRC_MAC"]; found {
			splitStr := strings.Split(strVal, "/")
			classData.MatchHdrFields.L2.Config.SourceMac = &splitStr[0]
			classData.MatchHdrFields.L2.State.SourceMac = &splitStr[0]
			if len(splitStr) == 2 {
				classData.MatchHdrFields.L2.Config.SourceMacMask = &splitStr[1]
				classData.MatchHdrFields.L2.State.SourceMacMask = &splitStr[1]
			}
			l2Filled = found
		}
		if strVal, found := classTblVal.Field["DEI"]; found {
			dei, _ := strconv.Atoi(strVal)
			ocDei := uint8(dei)
			classData.MatchHdrFields.L2.Config.Dei = &ocDei
			classData.MatchHdrFields.L2.State.Dei = &ocDei
			l2Filled = found
		}
		if strVal, found := classTblVal.Field["PCP"]; found {
			pcp, _ := strconv.Atoi(strVal)
			ocPcp := uint8(pcp)
			classData.MatchHdrFields.L2.Config.Pcp = &ocPcp
			classData.MatchHdrFields.L2.State.Pcp = &ocPcp
			l2Filled = found
		}
		if strVal, found := classTblVal.Field["VLAN"]; found {
			vlan, _ := strconv.Atoi(strVal)
			ocVlan := uint16(vlan)
			classData.MatchHdrFields.L2.Config.Vlanid = &ocVlan
			classData.MatchHdrFields.L2.State.Vlanid = &ocVlan
			l2Filled = found
		}
		if strVal, found := classTblVal.Field["ETHER_TYPE"]; found {
			ethType, _ := strconv.ParseUint(strings.Replace(strVal, "0x", "", -1), 16, 32)
			ocEtype := getL2EtherType(ethType)
			classData.MatchHdrFields.L2.Config.Ethertype, _ = classData.MatchHdrFields.L2.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union(ocEtype)
			classData.MatchHdrFields.L2.State.Ethertype, _ = classData.MatchHdrFields.L2.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_State_Ethertype_Union(ocEtype)
			l2Filled = found
		}
		if !l2Filled {
			classData.MatchHdrFields.L2 = nil
		}
		//Fill L2 Fields - END

		// Fill IP Common fields
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ip)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ip.Config)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ip.State)
		ipFilled := false
		if strVal, found := classTblVal.Field["DSCP"]; found {
			dscp, _ := strconv.Atoi(strVal)
			ocDscp := uint8(dscp)
			classData.MatchHdrFields.Ip.Config.Dscp = &ocDscp
			classData.MatchHdrFields.Ip.State.Dscp = classData.MatchHdrFields.Ip.Config.Dscp
			ipFilled = found
		}
		if strVal, found := classTblVal.Field["IP_PROTOCOL"]; found {
			ipProto, _ := strconv.ParseInt(strVal, 10, 64)
			ipProtoVal := getIpProtocol(ipProto)
			classData.MatchHdrFields.Ip.Config.Protocol, _ = classData.MatchHdrFields.Ip.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union(ipProtoVal)
			classData.MatchHdrFields.Ip.State.Protocol, _ = classData.MatchHdrFields.Ip.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_State_Protocol_Union(ipProtoVal)
			ipFilled = found
		}
		if !ipFilled {
			classData.MatchHdrFields.Ip = nil
		}

		//Fill IPV4 Fields - START
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv4)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv4.Config)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv4.State)
		ipv4Filled := false
		if strVal, found := classTblVal.Field["SRC_IP"]; found {
			classData.MatchHdrFields.Ipv4.Config.SourceAddress = &strVal
			classData.MatchHdrFields.Ipv4.State.SourceAddress = &strVal
			ipv4Filled = found
		}
		if strVal, found := classTblVal.Field["DST_IP"]; found {
			classData.MatchHdrFields.Ipv4.Config.DestinationAddress = &strVal
			classData.MatchHdrFields.Ipv4.State.DestinationAddress = &strVal
			ipv4Filled = found
		}
		if !ipv4Filled {
			classData.MatchHdrFields.Ipv4 = nil
		}
		//Fill IPV4 Fields - END

		//Fill IPV6 Fields - START
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv6)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv6.Config)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv6.State)
		ipv6Filled := false
		if strVal, found := classTblVal.Field["SRC_IPV6"]; found {
			classData.MatchHdrFields.Ipv6.Config.SourceAddress = &strVal
			classData.MatchHdrFields.Ipv6.State.SourceAddress = &strVal
			ipv6Filled = found
		}
		if strVal, found := classTblVal.Field["DST_IPV6"]; found {
			classData.MatchHdrFields.Ipv6.Config.DestinationAddress = &strVal
			classData.MatchHdrFields.Ipv6.State.DestinationAddress = &strVal
			ipv6Filled = found
		}
		if !ipv6Filled {
			classData.MatchHdrFields.Ipv6 = nil
		}
		//Fill IPV6 Fields - END

		//Fill Transport Fields - START
		ygot.BuildEmptyTree(classData.MatchHdrFields.Transport)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Transport.Config)
		ygot.BuildEmptyTree(classData.MatchHdrFields.Transport.State)
		transportFilled := false
		if strVal, found := classTblVal.Field["L4_SRC_PORT"]; found {
			srcPort := getTransportSrcDestPorts(strVal, "src")
			classData.MatchHdrFields.Transport.Config.SourcePort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union(srcPort)
			classData.MatchHdrFields.Transport.State.SourcePort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_SourcePort_Union(srcPort)
			transportFilled = found
		}
		if strVal, found := classTblVal.Field["L4_DST_PORT"]; found {
			dstPort := getTransportSrcDestPorts(strVal, "dest")
			classData.MatchHdrFields.Transport.Config.DestinationPort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union(dstPort)
			classData.MatchHdrFields.Transport.State.DestinationPort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_DestinationPort_Union(dstPort)
			transportFilled = found
		}
		if strVal, found := classTblVal.Field["L4_SRC_PORT_RANGE"]; found {
			srcPortRange := strings.Replace(strVal, "-", "..", 1)
			classData.MatchHdrFields.Transport.Config.SourcePort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union(srcPortRange)
			classData.MatchHdrFields.Transport.State.SourcePort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_SourcePort_Union(srcPortRange)
			transportFilled = found
		}
		if strVal, found := classTblVal.Field["L4_DST_PORT_RANGE"]; found {
			dstPortRange := strings.Replace(strVal, "-", "..", 1)
			classData.MatchHdrFields.Transport.Config.DestinationPort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union(dstPortRange)
			classData.MatchHdrFields.Transport.State.DestinationPort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_DestinationPort_Union(dstPortRange)
			transportFilled = found
		}
		if strVal, found := classTblVal.Field["TCP_FLAGS"]; found {
			classData.MatchHdrFields.Transport.Config.TcpFlags = getTransportConfigTcpFlags(strVal)
			classData.MatchHdrFields.Transport.State.TcpFlags = classData.MatchHdrFields.Transport.Config.TcpFlags
			transportFilled = found
		}
		if !transportFilled {
			classData.MatchHdrFields.Transport = nil
		}
		//Fill Transport Fields - END
	}

	pretty.Print(classData)

	return nil
}

func (app *FbsApp) fillFbsPolicyDetails(dbs [db.MaxDB]*db.DB, policyName string, policyData *ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy) error {
	policyTblVal, err := app.getPolicyEntryFromDB(dbs[db.ConfigDB], policyName)
	if err != nil {
		return err
	}

	ygot.BuildEmptyTree(policyData)

	policyData.PolicyName = &policyName
	policyType := policyTblVal.Get("TYPE")

	policyData.Config.Name = &policyName
	log.Infof("policyName:%v and type:%v", policyName, policyType)

	policyData.Config.Type, _ = getPolicyTypeOCEnumFromDbStr(policyType)
	policyData.State.Type = policyData.Config.Type
	policyData.State.Name = policyData.Config.Name

	if policyData.Sections == nil || len(policyData.Sections.Section) == 0 {
		ygot.BuildEmptyTree(policyData.Sections)

		policySectionKeys, err := dbs[db.ConfigDB].GetKeysPattern(policySectionTblTs, db.Key{[]string{policyName, "*"}})
		if err != nil {
			return err
		}

		for _, key := range policySectionKeys {
			className := key.Get(1)
			log.Infof("Key:%v policyName:%v className:%v ", key, policyName, className)
			policyData.Sections.NewSection(className)
		}
	}

	for className, sectionPtr := range policyData.Sections.Section {
		err := app.fillFbsPolicySectionDetails(dbs, policyName, className, sectionPtr)
		if err != nil {
			return err
		}
	}

	return nil
}

func (app *FbsApp) fillFbsPolicySectionDetails(dbs [db.MaxDB]*db.DB, policyName string, className string, policySectionData *ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section) error {
	log.Infof("Policy:%v Class:%v", policyName, className)

	policySectionTblVal, err := app.getSectionEntryFromDB(dbs[db.ConfigDB], policyName+"|"+className)
	if err != nil {
		log.Error(err)
		return err
	}

	//Fill PolicySectionDetails
	ygot.BuildEmptyTree(policySectionData)
	policySectionData.Class = &className
	policySectionData.Config.Name = &className
	policySectionData.State.Name = &className
	if strVal, found := policySectionTblVal.Field["PRIORITY"]; found {
		priority, _ := strconv.Atoi(strVal)
		ocPriority := uint16(priority)
		policySectionData.Config.Priority = &ocPriority
		policySectionData.State.Priority = &ocPriority
	}

	//Forwarding START
	//forwarding Config
	if strVal, found := policySectionTblVal.Field["DEFAULT_PACKET_ACTION"]; found {
		ygot.BuildEmptyTree(policySectionData.Forwarding)
		dropFlag := false
		if strVal == SONIC_PACKET_ACTION_DROP {
			dropFlag = true
		}
		policySectionData.Forwarding.Config.Discard = &dropFlag
		policySectionData.Forwarding.State.Discard = &dropFlag
	}

	//forwarding EgressInterfaces
	if intfs := policySectionTblVal.GetList("SET_INTERFACE"); len(intfs) > 0 {
		ygot.BuildEmptyTree(policySectionData.Forwarding)
		ygot.BuildEmptyTree(policySectionData.Forwarding.EgressInterfaces)
		for i := range intfs {
			intfSplits := strings.Split(intfs[i], "|")
			egressIfName := *(utils.GetUINameFromNativeName(&intfSplits[0]))
			egressIfData, _ := policySectionData.Forwarding.EgressInterfaces.NewEgressInterface(egressIfName)
			ygot.BuildEmptyTree(egressIfData)
			egressIfData.IntfName = &egressIfName
			egressIfData.Config.IntfName = &egressIfName
			egressIfData.State.IntfName = &egressIfName
			if len(intfSplits[1]) > 0 {
				prio, _ := strconv.Atoi(intfSplits[1])
				ocPriority := uint16(prio)
				egressIfData.Config.Priority = &ocPriority
				egressIfData.State.Priority = &ocPriority
			}
		}
	}

	//forwarding NextHops
	var ipNhops []string
	if ipNhops = policySectionTblVal.GetList("SET_IP_NEXTHOP"); len(ipNhops) == 0 {
		ipNhops = policySectionTblVal.GetList("SET_IPV6_NEXTHOP")
	}
	if len(ipNhops) > 0 {
		ygot.BuildEmptyTree(policySectionData.Forwarding)
		ygot.BuildEmptyTree(policySectionData.Forwarding.NextHops)
		for i := range ipNhops {
			nhopSplits := strings.Split(ipNhops[i], "|")
			nhopIp := nhopSplits[0]
			vrf := nhopSplits[1]

			var temp ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config
			var vrfUnion ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union
			if vrf != "" {
				vrfUnion, _ = temp.To_OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union(vrf)
			} else {
				vrfUnion, _ = temp.To_OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_Config_NetworkInstance_Union(ocbinds.OpenconfigFbsExt_NEXT_HOP_NETWORK_INSTANCE_INTERFACE_NETWORK_INSTANCE)
			}

			nhopData, _ := policySectionData.Forwarding.NextHops.NewNextHop(nhopIp, vrfUnion)
			ygot.BuildEmptyTree(nhopData)
			nhopData.IpAddress = &nhopIp
			nhopData.NetworkInstance = vrfUnion

			nhopData.Config.IpAddress = &nhopIp
			nhopData.Config.NetworkInstance = vrfUnion
			nhopData.State.IpAddress = &nhopIp
			if vrf != "" {
				nhopData.State.NetworkInstance, _ = nhopData.State.To_OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_State_NetworkInstance_Union(vrf)
			} else {
				nhopData.State.NetworkInstance, _ = nhopData.State.To_OpenconfigFbsExt_Fbs_Policies_Policy_Sections_Section_Forwarding_NextHops_NextHop_State_NetworkInstance_Union(ocbinds.OpenconfigFbsExt_NEXT_HOP_NETWORK_INSTANCE_INTERFACE_NETWORK_INSTANCE)
			}

			if len(nhopSplits[2]) > 0 {
				prio, _ := strconv.Atoi(nhopSplits[2])
				ocPrio := uint16(prio)
				nhopData.Config.Priority = &ocPrio
				nhopData.State.Priority = &ocPrio
			}
		}
	}
	//Forwarding - END

	//Monitoring - START
	if strVal, found := policySectionTblVal.Field["SET_MIRROR_SESSION"]; found {
		ygot.BuildEmptyTree(policySectionData.Monitoring)
		mirrorData, _ := policySectionData.Monitoring.MirrorSessions.NewMirrorSession(strVal)
		ygot.BuildEmptyTree(mirrorData)
		mirrorData.Config.SessionName = &strVal
		mirrorData.State.SessionName = &strVal
	}
	//Monitoring - END

	//QOS - START
	log.Infof("Policy GET  className:%v ", className)
	if strVal, found := policySectionTblVal.Field["SET_POLICER_CIR"]; found {
		ygot.BuildEmptyTree(policySectionData.Qos)
		ygot.BuildEmptyTree(policySectionData.Qos.Policer)
		val, _ := strconv.ParseUint(strVal, 10, 64)
		policySectionData.Qos.Policer.Config.Cir = &val
		policySectionData.Qos.Policer.State.Cir = &val
	}
	if strVal, found := policySectionTblVal.Field["SET_POLICER_CBS"]; found {
		val, _ := strconv.ParseUint(strVal, 10, 64)
		policySectionData.Qos.Policer.Config.Cbs = &val
		policySectionData.Qos.Policer.State.Cbs = &val
	}
	if strVal, found := policySectionTblVal.Field["SET_POLICER_PIR"]; found {
		val, _ := strconv.ParseUint(strVal, 10, 64)
		policySectionData.Qos.Policer.Config.Pir = &val
		policySectionData.Qos.Policer.State.Pir = &val
	}
	if strVal, found := policySectionTblVal.Field["SET_POLICER_PBS"]; found {
		val, _ := strconv.ParseUint(strVal, 10, 64)
		policySectionData.Qos.Policer.Config.Pbs = &val
		policySectionData.Qos.Policer.State.Pbs = &val
	}
	if strVal, found := policySectionTblVal.Field["SET_PCP"]; found {
		ygot.BuildEmptyTree(policySectionData.Qos)
		ygot.BuildEmptyTree(policySectionData.Qos.Remark)
		val, _ := strconv.ParseUint(strVal, 10, 8)
		val8 := uint8(val)
		policySectionData.Qos.Remark.Config.SetDot1P = &val8
		policySectionData.Qos.Remark.State.SetDot1P = &val8
	}
	if strVal, found := policySectionTblVal.Field["SET_DSCP"]; found {
		ygot.BuildEmptyTree(policySectionData.Qos)
		ygot.BuildEmptyTree(policySectionData.Qos.Remark)
		val, _ := strconv.ParseUint(strVal, 10, 8)
		val8 := uint8(val)
		policySectionData.Qos.Remark.Config.SetDscp = &val8
		policySectionData.Qos.Remark.State.SetDscp = &val8
	}
	if strVal, found := policySectionTblVal.Field["SET_TC"]; found {
		ygot.BuildEmptyTree(policySectionData.Qos)
		ygot.BuildEmptyTree(policySectionData.Qos.Queuing)
		val, _ := strconv.ParseUint(strVal, 10, 8)
		val8 := uint8(val)
		policySectionData.Qos.Queuing.Config.OutputQueueIndex = &val8
		policySectionData.Qos.Queuing.State.OutputQueueIndex = &val8
	}
	//QOS - END

	return nil
}

func (app *FbsApp) fillFbsInterfaceDetails(dbs [db.MaxDB]*db.DB, uiIfName string, policyBindData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface) error {
	nativeIfName := *utils.GetNativeNameFromUIName(&uiIfName)
	log.Infof("fbs Interface Get;Interface level request; nativeIfName:%v uiIfName:%v ", nativeIfName, uiIfName)

	policyBindTblVal, err := app.getPolicyBindingEntryFromDB(dbs[db.ConfigDB], nativeIfName)
	if err != nil {
		return err
	}

	ygot.BuildEmptyTree(policyBindData)

	policyBindData.Config.Id = &uiIfName
	policyBindData.State.Id = &uiIfName
	ygot.BuildEmptyTree(policyBindData.InterfaceRef)
	policyBindData.InterfaceRef.Config.Interface = &uiIfName
	policyBindData.InterfaceRef.State.Interface = &uiIfName

	// find out specific type requested if any. This will help optimize DB access and the response times
	policyTypes := []string{}
	policyDirs := []string{}
	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{}/ingress-policies") {
		policyDirs = append(policyDirs, "INGRESS")
		if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{}/ingress-policies/qos") {
			policyTypes = append(policyTypes, SONIC_POLICY_TYPE_QOS)
		} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{}/ingress-policies/monitoring") {
			policyTypes = append(policyTypes, SONIC_POLICY_TYPE_MONITORING)
		} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{}/ingress-policies/forwarding") {
			policyTypes = append(policyTypes, SONIC_POLICY_TYPE_FORWARDING)
		} else {
			policyTypes = []string{SONIC_POLICY_TYPE_FORWARDING, SONIC_POLICY_TYPE_MONITORING, SONIC_POLICY_TYPE_QOS}
		}
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{}/egress-policies") {
		policyDirs = append(policyDirs, "EGRESS")
		policyTypes = []string{SONIC_POLICY_TYPE_QOS}
	} else {
		policyDirs = append(policyDirs, "INGRESS")
		policyDirs = append(policyDirs, "EGRESS")
		policyTypes = []string{SONIC_POLICY_TYPE_FORWARDING, SONIC_POLICY_TYPE_MONITORING, SONIC_POLICY_TYPE_QOS}
	}

	log.Infof("Intf:%v Types:%v Dirs:%v", nativeIfName, policyTypes, policyDirs)
	for _, policyType := range policyTypes {
		for _, bindDir := range policyDirs {
			dbFieldKey := bindDir + "_" + policyType + "_POLICY"
			if str_val, found := policyBindTblVal.Field[dbFieldKey]; found {
				if bindDir == "INGRESS" {
					ygot.BuildEmptyTree(policyBindData.IngressPolicies)
					if policyType == SONIC_POLICY_TYPE_FORWARDING {
						ygot.BuildEmptyTree(policyBindData.IngressPolicies.Forwarding)
						policyBindData.IngressPolicies.Forwarding.Config.PolicyName = &str_val
						policyBindData.IngressPolicies.Forwarding.State.PolicyName = &str_val
						err := app.fillFbsIngressIfPolicyFwdSections(dbs, nativeIfName, str_val, policyBindData.IngressPolicies.Forwarding.Sections)
						if err != nil {
							log.Infof("fbs interface Get failed err:%v ; uiIfName:%v, dbFieldKey:%v ", err, uiIfName, dbFieldKey)
							return err
						}

					} else if policyType == SONIC_POLICY_TYPE_MONITORING {
						ygot.BuildEmptyTree(policyBindData.IngressPolicies.Monitoring)
						policyBindData.IngressPolicies.Monitoring.Config.PolicyName = &str_val
						policyBindData.IngressPolicies.Monitoring.State.PolicyName = &str_val
						app.fillFbsIngressIfPolicyMonSections(dbs, nativeIfName, str_val, policyBindData.IngressPolicies.Monitoring.Sections)
						if err != nil {
							log.Infof("fbs interface Get failed err:%v ; uiIfName:%v, dbFieldKey:%v ", err, uiIfName, dbFieldKey)
							return err
						}
					} else if policyType == SONIC_POLICY_TYPE_QOS {
						ygot.BuildEmptyTree(policyBindData.IngressPolicies.Qos)
						policyBindData.IngressPolicies.Qos.Config.PolicyName = &str_val
						policyBindData.IngressPolicies.Qos.State.PolicyName = &str_val
						app.fillFbsIngressIfPolicyQosSections(dbs, nativeIfName, str_val, policyBindData.IngressPolicies.Qos.Sections)
						if err != nil {
							log.Infof("fbs interface Get failed err:%v ; uiIfName:%v, dbFieldKey:%v ", err, uiIfName, dbFieldKey)
							return err
						}
					}
				} else {
					ygot.BuildEmptyTree(policyBindData.EgressPolicies)
					if policyType == SONIC_POLICY_TYPE_QOS {
						ygot.BuildEmptyTree(policyBindData.EgressPolicies.Qos)
						policyBindData.EgressPolicies.Qos.Config.PolicyName = &str_val
						policyBindData.EgressPolicies.Qos.State.PolicyName = &str_val
						app.fillFbsEgressIfPolicyQosSections(dbs, nativeIfName, str_val, policyBindData.EgressPolicies.Qos.Sections)
						if err != nil {
							log.Infof("fbs interface Get failed err:%v ; uiIfName:%v, dbFieldKey:%v ", err, uiIfName, dbFieldKey)
							return err
						}
					}
				}
			}
		}
	}

	return nil
}

func get_counter_diff(currentVal db.Value, lastVal db.Value, field string) uint64 {
	current, _ := strconv.ParseUint(currentVal.Field[field], 10, 64)
	last, _ := strconv.ParseUint(lastVal.Field[field], 10, 64)

	if current < last {
		return math.MaxUint64 - last + current
	} else {
		return current - last
	}
}

func (app *FbsApp) fillPolicySectionCounters(dbs [db.MaxDB]*db.DB, polPbfKey db.Key, fbsFlowState *FbsFwdCountersEntry) error {
	countersDbPtr := dbs[db.CountersDB]
	fbsCtrVal, err := countersDbPtr.GetEntry(fbsCntrTblTs, polPbfKey)
	lastFbsCtrVal, err2 := countersDbPtr.GetEntry(lastFbsCntrTblTs, polPbfKey)
	activeFlag := false
	if err == nil && err2 == nil {
		count := get_counter_diff(fbsCtrVal, lastFbsCtrVal, "Packets")
		fbsFlowState.MatchedPackets = count
		count = get_counter_diff(fbsCtrVal, lastFbsCtrVal, "Bytes")
		fbsFlowState.MatchedOctets = count
		activeFlag = true
		fbsFlowState.Active = activeFlag
	} else {
		fbsFlowState.Active = activeFlag
	}

	log.Infof("fbsCtrVal:%v err:%v err2:%v ", fbsCtrVal, err, err2)
	return err
}

func (app *FbsApp) fillFbsForwardingStateEntry(dbs [db.MaxDB]*db.DB, polPbfKey db.Key, fwdState *FbsFlowForwardingStateEntry) (err error) {
	stateDbPtr := dbs[db.StateDB]
	pbfKey := db.Key{Comp: []string{strings.Join(polPbfKey.Comp, ":")}}
	val, err := stateDbPtr.GetEntry(pbfGrpTblTs, pbfKey)
	if err == nil {
		selected := val.Field["CONFIGURED_SELECTED"]
		log.Infof("Key:%v Selected:%v", pbfKey, selected)
		if selected == "DROP" {
			discard := true
			fwdState.Discard = &discard
		} else if selected != "FORWARD" {
			parts := strings.Split(selected, "|")
			if len(parts) == 3 {
				fwdState.IpAddress = &parts[0]
				fwdState.NetworkInstance = &parts[1]
				if parts[2] != "" {
					prio, _ := strconv.ParseInt(parts[2], 10, 32)
					prio_int := uint16(prio)
					fwdState.Priority = &prio_int
				}
			} else {
				fwdState.IntfName = &parts[0]
				if parts[1] != "" {
					prio, _ := strconv.ParseInt(parts[1], 10, 32)
					prio_int := uint16(prio)
					fwdState.Priority = &prio_int
				}
			}
		}
	}

	err = app.fillPolicySectionCounters(dbs, polPbfKey, &fwdState.fbsFlowState)
	return err
}

func (app *FbsApp) fillFbsPolicerStateEntry(dbs [db.MaxDB]*db.DB, polPbfKey db.Key, qosState *FbsPolicerStateEntry) (err error) {
	appDbPtr := dbs[db.ApplDB]
	var policerTblVal db.Value
	policerTblVal, err = appDbPtr.GetEntry(policerTblTs, polPbfKey)
	log.Infof("Key:%v Val:%v Err:%v", polPbfKey, policerTblVal, err)
	if err == nil {
		if str_val, found := policerTblVal.Field["CIR"]; found {
			val, _ := strconv.ParseUint(str_val, 10, 64)
			qosState.Cir = val
		}

		if str_val, found := policerTblVal.Field["PIR"]; found {
			val, _ := strconv.ParseUint(str_val, 10, 64)
			qosState.Pir = val
		}

		if str_val, found := policerTblVal.Field["CBS"]; found {
			val, _ := strconv.ParseUint(str_val, 10, 64)
			qosState.Cbs = val
		}

		if str_val, found := policerTblVal.Field["PBS"]; found {
			val, _ := strconv.ParseUint(str_val, 10, 64)
			qosState.Pbs = val
		}
	}

	return err
}

func (app *FbsApp) fillFbsQosStateEntry(dbs [db.MaxDB]*db.DB, polPbfKey db.Key, qosState *FbsFlowQosStateEntry) (err error) {

	countersDbPtr := dbs[db.CountersDB]
	polCntVal, err := countersDbPtr.GetEntry(policerCtrTbl, polPbfKey)
	lastPolCntVal, err2 := countersDbPtr.GetEntry(lastPolicerCtrTbl, polPbfKey)

	log.Infof("Key:%v Value:%v Last:%v Err:%v Err2:%v", polPbfKey, polCntVal, lastPolCntVal, err, err2)
	if err == nil && err2 == nil {
		count := get_counter_diff(polCntVal, lastPolCntVal, "GreenPackets")
		qosState.ConformingPkts = count

		count = get_counter_diff(polCntVal, lastPolCntVal, "GreenBytes")
		qosState.ConformingOctets = count

		count = get_counter_diff(polCntVal, lastPolCntVal, "YellowPackets")
		qosState.ExceedingPkts = count

		count = get_counter_diff(polCntVal, lastPolCntVal, "YellowBytes")
		qosState.ExceedingOctets = count

		count = get_counter_diff(polCntVal, lastPolCntVal, "RedPackets")
		qosState.ViolatingPkts = count

		count = get_counter_diff(polCntVal, lastPolCntVal, "RedBytes")
		qosState.ViolatingOctets = count

		qosState.Active = true
	} else {
		qosState.Active = false
	}

	err = app.fillFbsPolicerStateEntry(dbs, polPbfKey, &qosState.policerState)
	if err != nil {
		err = app.fillPolicySectionCounters(dbs, polPbfKey, &qosState.fbsFlowState)
	}

	return err
}

func (app *FbsApp) fillFbsIngressIfPolicyFwdSections(dbs [db.MaxDB]*db.DB, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Forwarding_Sections) error {
	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
	ygot.BuildEmptyTree(policySectionsData)

	if len(policySectionsData.Section) == 0 {
		policySectionKeys, err := dbs[db.ConfigDB].GetKeysPattern(policySectionTblTs, asKey(policyName, "*"))
		if err != nil {
			log.Infof("fillFbsIngressIfPolicyFwdSections err:%v ; policyName:%v ", err, policyName)
			return err
		}
		for _, key := range policySectionKeys {
			policySectionsData.NewSection(key.Get(1))
		}
	}

	bindDir := "INGRESS"

	for className, policySectionData := range policySectionsData.Section {
		log.Infof("IntfPolicysection className:%v", className)
		//Fill PolicySectionDetails
		ygot.BuildEmptyTree(policySectionData)

		ygotClassName := className
		policySectionData.ClassName = &ygotClassName
		policySectionData.State.ClassName = &ygotClassName
		log.Infof("Policy Get;policyName:%v className:%v ", policyName, ygotClassName)

		//fill forwarding selected egress interface and select nexhop details
		var fwdState FbsFlowForwardingStateEntry
		polPbfKey := asKey(policyName, className, nativeIfName, bindDir)
		err := app.fillFbsForwardingStateEntry(dbs, polPbfKey, &fwdState)
		if err != nil {
			log.Infof("fbs forwarding flow state get failed err:%v ; polPbfKey:%v ", err, polPbfKey)
			return err
		}

		if fwdState.IntfName != nil {
			ygot.BuildEmptyTree(policySectionData.EgressInterface)
			policySectionData.EgressInterface.State.IntfName = fwdState.IntfName
			policySectionData.EgressInterface.State.Priority = fwdState.Priority
		}
		if fwdState.IpAddress != nil {
			ygot.BuildEmptyTree(policySectionData.NextHop)
			policySectionData.NextHop.State.IpAddress = fwdState.IpAddress
			if fwdState.NetworkInstance != nil {
				policySectionData.NextHop.State.NetworkInstance, _ = policySectionData.NextHop.State.To_OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Forwarding_Sections_Section_NextHop_State_NetworkInstance_Union(*fwdState.NetworkInstance)
			} else {
				policySectionData.NextHop.State.NetworkInstance, _ = policySectionData.NextHop.State.To_OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Forwarding_Sections_Section_NextHop_State_NetworkInstance_Union(ocbinds.OpenconfigFbsExt_NEXT_HOP_NETWORK_INSTANCE_INTERFACE_NETWORK_INSTANCE)
			}
			policySectionData.NextHop.State.Priority = fwdState.Priority
		}
		policySectionData.State.Discard = fwdState.Discard
		policySectionData.State.Active = &fwdState.fbsFlowState.Active
		policySectionData.State.MatchedOctets = &fwdState.fbsFlowState.MatchedOctets
		policySectionData.State.MatchedPackets = &fwdState.fbsFlowState.MatchedPackets
		pretty.Print(policySectionData)
	}

	return nil
}

func (app *FbsApp) fillFbsIngressIfPolicyMonSections(dbs [db.MaxDB]*db.DB, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Monitoring_Sections) error {
	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
	ygot.BuildEmptyTree(policySectionsData)

	if len(policySectionsData.Section) == 0 {
		policySectionKeys, err := dbs[db.ConfigDB].GetKeysPattern(policySectionTblTs, asKey(policyName, "*"))
		if err != nil {
			log.Infof("fillFbsIngressIfPolicyMonSections failed err:%v ; policyName:%v ", err, policyName)
			return err
		}
		for _, key := range policySectionKeys {
			policySectionsData.NewSection(key.Get(1))
		}
	}

	bindDir := "INGRESS"

	for className, policySectionData := range policySectionsData.Section {
		log.Infof("IntfPolicysection className:%v", className)
		//Fill PolicySectionDetails
		ygot.BuildEmptyTree(policySectionData)

		ygotClassName := className
		policySectionData.ClassName = &ygotClassName
		policySectionData.State.ClassName = &ygotClassName
		log.Infof("Policy Get;policyName:%v className:%v ", policyName, ygotClassName)

		var fbsFlowState FbsFwdCountersEntry
		polPbfKey := asKey(policyName, className, nativeIfName, bindDir)
		err := app.fillPolicySectionCounters(dbs, polPbfKey, &fbsFlowState)
		if nil != err {
			log.Infof("fillPolicySectionCounters failed err:%v ; polPbfKey:%v ", err, polPbfKey)
			return err
		}

		policySectionData.State.Active = &fbsFlowState.Active
		policySectionData.State.MatchedOctets = &fbsFlowState.MatchedOctets
		policySectionData.State.MatchedPackets = &fbsFlowState.MatchedPackets

		pretty.Print(policySectionData)
	}

	return nil
}

func (app *FbsApp) fillFbsIngressIfPolicyQosSections(dbs [db.MaxDB]*db.DB, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Qos_Sections) error {
	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
	ygot.BuildEmptyTree(policySectionsData)

	if len(policySectionsData.Section) == 0 {
		policySectionKeys, err := dbs[db.ConfigDB].GetKeysPattern(policySectionTblTs, asKey(policyName, "*"))
		if err != nil {
			log.Infof("fillFbsIngressIfPolicyQosSections failed err:%v ; policyName:%v ", err, policyName)
			return err
		}
		for _, key := range policySectionKeys {
			policySectionsData.NewSection(key.Get(1))
		}
	}

	bindDir := "INGRESS"

	for className, policySectionData := range policySectionsData.Section {
		log.Infof("IntfPolicysection className:%v", className)
		//Fill PolicySectionDetails
		ygot.BuildEmptyTree(policySectionData)

		ygotClassName := className
		policySectionData.ClassName = &ygotClassName
		policySectionData.State.ClassName = &ygotClassName
		log.Infof("Policy Get;policyName:%v className:%v ", policyName, ygotClassName)

		var qosState FbsFlowQosStateEntry
		polPbfKey := asKey(policyName, className, nativeIfName, bindDir)
		err := app.fillFbsQosStateEntry(dbs, polPbfKey, &qosState)
		if err != nil {
			activeFlag := false
			log.Infof("policer State not active ; polPbfKey:%v ", polPbfKey)
			policySectionData.State.Active = &activeFlag
		} else {
			policySectionData.State.Active = &qosState.Active
			policySectionData.State.Cir = &(qosState.policerState.Cir)
			policySectionData.State.Pir = &(qosState.policerState.Pir)
			policySectionData.State.Cbs = &(qosState.policerState.Cbs)
			policySectionData.State.Pbs = &(qosState.policerState.Pbs)

			policySectionData.State.ConformingOctets = &(qosState.ConformingOctets)
			policySectionData.State.ConformingPkts = &(qosState.ConformingPkts)
			policySectionData.State.ExceedingOctets = &(qosState.ExceedingOctets)
			policySectionData.State.ExceedingPkts = &(qosState.ExceedingPkts)
			policySectionData.State.ViolatingOctets = &(qosState.ViolatingOctets)
			policySectionData.State.ViolatingPkts = &(qosState.ViolatingPkts)
		}

		var fbsFlowState FbsFwdCountersEntry
		err = app.fillPolicySectionCounters(dbs, polPbfKey, &fbsFlowState)
		if nil != err {
			log.Infof("fillPolicySectionCounters failed err:%v; polPbfKey:%v ", err, polPbfKey)
			return err
		}

		policySectionData.State.Active = &fbsFlowState.Active
		policySectionData.State.MatchedOctets = &fbsFlowState.MatchedOctets
		policySectionData.State.MatchedPackets = &fbsFlowState.MatchedPackets

		pretty.Print(policySectionData)
	}

	return nil
}

func (app *FbsApp) fillFbsEgressIfPolicyQosSections(dbs [db.MaxDB]*db.DB, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_EgressPolicies_Qos_Sections) error {
	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
	ygot.BuildEmptyTree(policySectionsData)

	if len(policySectionsData.Section) == 0 {
		policySectionKeys, err := dbs[db.ConfigDB].GetKeysPattern(policySectionTblTs, asKey(policyName, "*"))
		if err != nil {
			log.Infof("fillFbsEgressIfPolicyQosSections failed err:%v ; policyName:%v ", err, policyName)
			return err
		}
		for _, key := range policySectionKeys {
			policySectionsData.NewSection(key.Get(1))
		}
	}

	bindDir := "EGRESS"

	for className, policySectionData := range policySectionsData.Section {
		log.Infof("IntfPolicysection className:%v", className)
		//Fill PolicySectionDetails
		ygot.BuildEmptyTree(policySectionData)

		ygotClassName := className
		policySectionData.ClassName = &ygotClassName
		policySectionData.State.ClassName = &ygotClassName
		log.Infof("Policy Get;policyName:%v className:%v ", policyName, ygotClassName)

		var qosState FbsFlowQosStateEntry
		polPbfKey := asKey(policyName, className, nativeIfName, bindDir)
		err := app.fillFbsQosStateEntry(dbs, polPbfKey, &qosState)
		if err != nil {
			activeFlag := false
			policySectionData.State.Active = &activeFlag
			log.Infof("policer State not active ; polPbfKey:%v ", polPbfKey)
		} else {
			policySectionData.State.Active = &qosState.Active
			policySectionData.State.Cir = &(qosState.policerState.Cir)
			policySectionData.State.Pir = &(qosState.policerState.Pir)
			policySectionData.State.Cbs = &(qosState.policerState.Cbs)
			policySectionData.State.Pbs = &(qosState.policerState.Pbs)

			policySectionData.State.ConformingOctets = &(qosState.ConformingOctets)
			policySectionData.State.ConformingPkts = &(qosState.ConformingPkts)
			policySectionData.State.ExceedingOctets = &(qosState.ExceedingOctets)
			policySectionData.State.ExceedingPkts = &(qosState.ExceedingPkts)
			policySectionData.State.ViolatingOctets = &(qosState.ViolatingOctets)
			policySectionData.State.ViolatingPkts = &(qosState.ViolatingPkts)
		}

		var fbsFlowState FbsFwdCountersEntry
		err = app.fillPolicySectionCounters(dbs, polPbfKey, &fbsFlowState)
		if nil != err {
			log.Infof("fillPolicySectionCounters failed err:%v; polPbfKey:%v ", err, polPbfKey)
			return err
		}

		policySectionData.State.Active = &fbsFlowState.Active
		policySectionData.State.MatchedOctets = &fbsFlowState.MatchedOctets
		policySectionData.State.MatchedPackets = &fbsFlowState.MatchedPackets

		pretty.Print(policySectionData)
	}

	return nil
}

func (app *FbsApp) processOperation(d *db.DB, filter bool, opcodeBmp int) error {
	log.Infof("Filter:%v OpcodeBmp:%v", filter, opcodeBmp)
	var err error

	if opcodeBmp&(1<<DELETE) != 0 {
		err = applyTableData(d, policyBindingTblTs, app.policyBindingTable, app.policyBindingCache, filter, opcodeBmp)
		if err == nil {
			err = applyTableData(d, policySectionTblTs, app.policySectionTable, app.policySectionCache, filter, opcodeBmp)
		}
		if err == nil {
			err = applyTableData(d, policyTblTs, app.policyMapTable, app.policyMapCache, filter, opcodeBmp)
		}
		if err == nil {
			err = applyTableData(d, classTblTs, app.classMapTable, app.classMapCache, filter, opcodeBmp)
		}
	} else if opcodeBmp&(1<<CREATE) != 0 || opcodeBmp&(1<<UPDATE) != 0 {
		err = applyTableData(d, classTblTs, app.classMapTable, app.classMapCache, filter, opcodeBmp)
		if err == nil {
			err = applyTableData(d, policyTblTs, app.policyMapTable, app.policyMapCache, filter, opcodeBmp)
		}
		if err == nil {
			err = applyTableData(d, policySectionTblTs, app.policySectionTable, app.policySectionCache, filter, opcodeBmp)
		}
		if err == nil {
			err = applyTableData(d, policyBindingTblTs, app.policyBindingTable, app.policyBindingCache, filter, opcodeBmp)
		}
	}

	return err
}

func applyTableData(d *db.DB, tableTs *db.TableSpec, tableData map[string]*db.Value, cacheTableData map[string]db.Value, filter bool, opcodeBmp int) error {
	tblJson, _ := json.Marshal(tableData)
	cacheJson, _ := json.Marshal(cacheTableData)
	log.Infof("Table:%v Cache:%v", string(tblJson), string(cacheJson))

	for key, keyData := range tableData {
		dbKey := asKey(key)
		if keyData == nil {
			log.Infof("Delete Table:%v Key:%v", tableTs.Name, dbKey)
			if filter && (opcodeBmp&(1<<DELETE)) == 0 {
				log.Infof("Skip as per input arg filter:%v opcodeBmp:%x", filter, opcodeBmp)
				continue
			}
			err := d.DeleteEntry(tableTs, dbKey)
			if err != nil {
				log.Error(err)
				return err
			}
		} else if _, found := cacheTableData[key]; found {
			log.Infof("Modify Table:%v Key:%v Value:%v", tableTs.Name, dbKey, *keyData)
			if filter && (opcodeBmp&(1<<UPDATE)) == 0 {
				log.Infof("Skip as per input arg filter:%v opcodeBmp:%x", filter, opcodeBmp)
				continue
			}
			err := d.SetEntry(tableTs, dbKey, *keyData)
			if err != nil {
				log.Error(err)
				return err
			}
		} else {
			log.Infof("Set Table:%v Key:%v Value:%v", tableTs.Name, dbKey, *keyData)
			if filter && (opcodeBmp&(1<<CREATE)) == 0 {
				log.Infof("Skip as per input arg filter:%v opcodeBmp:%x", filter, opcodeBmp)
				continue
			}
			err := d.CreateEntry(tableTs, dbKey, *keyData)
			if err != nil {
				log.Error(err)
				return err
			}
		}
		delete(tableData, key)
	}

	return nil
}

func pruneEgressWithHighestPriority(egress []string) []string {
	log.Info(egress)

	egressMap := make(map[string]uint16)

	for _, egr := range egress {
		key := egr[:strings.LastIndex(egr, "|")]
		prioStr := egr[strings.LastIndex(egr, "|")+1:]
		if prioStr == "" {
			egressMap[key] = 0
		} else {
			prio, _ := strconv.ParseUint(prioStr, 10, 16)
			egressMap[key] = uint16(prio)
		}
	}

	retVal := []string{}
	for key, val := range egressMap {
		var valStr string
		if val == 0 {
			valStr = ""
		} else {
			valStr = strconv.FormatUint(uint64(val), 10)
		}
		retVal = append(retVal, key+"|"+valStr)
	}

	log.Info(retVal)
	return retVal
}
