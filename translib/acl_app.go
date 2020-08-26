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
	"errors"
	"fmt"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/util"
	"github.com/openconfig/ygot/ygot"
	"reflect"
	"strconv"
	"strings"
)

const (
	TABLE_SEPARATOR                  = "|"
	KEY_SEPARATOR                    = "|"
	ACL_TABLE                        = "ACL_TABLE"
	RULE_TABLE                       = "ACL_RULE"
	ACL_COUNTERS                     = "ACL_COUNTERS"
	LAST_ACL_COUNTERS                = "LAST_ACL_COUNTERS"
	HARDWARE                         = "HARDWARE"
	ACL_FIELD_TYPE                   = "type"
	ACL_FIELD_STAGE                  = "stage"
	ACL_FIELD_PORTS                  = "ports"
	ACL_STAGE_INGRESS                = "INGRESS"
	ACL_STAGE_EGRESS                 = "EGRESS"
	ACL_DESCRIPTION                  = "policy_desc"
	SONIC_ACL_TYPE_L2                = "L2"
	SONIC_ACL_TYPE_IPV4              = "L3"
	SONIC_ACL_TYPE_IPV6              = "L3V6"
	OPENCONFIG_ACL_TYPE_IPV4         = "ACL_IPV4"
	OPENCONFIG_ACL_TYPE_IPV6         = "ACL_IPV6"
	OPENCONFIG_ACL_TYPE_L2           = "ACL_L2"
	OC_ACL_APP_MODULE_NAME           = "/openconfig-acl:acl"
	OC_ACL_YANG_PATH_PREFIX          = "/device/acl"
	ACL_RULE_FIELD_IP_PROTOCOL       = "IP_PROTOCOL"
	ACL_RULE_FIELD_SRC_IP            = "SRC_IP"
	ACL_RULE_FIELD_DST_IP            = "DST_IP"
	ACL_RULE_FIELD_SRC_IPV6          = "SRC_IPV6"
	ACL_RULE_FIELD_DST_IPV6          = "DST_IPV6"
	ACL_RULE_FIELD_DSCP              = "DSCP"
	ACL_RULE_FIELD_L4_SRC_PORT       = "L4_SRC_PORT"
	ACL_RULE_FIELD_L4_SRC_PORT_RANGE = "L4_SRC_PORT_RANGE"
	ACL_RULE_FIELD_L4_DST_PORT       = "L4_DST_PORT"
	ACL_RULE_FIELD_L4_DST_PORT_RANGE = "L4_DST_PORT_RANGE"
	ACL_RULE_FIELD_TCP_FLAGS         = "TCP_FLAGS"
	ACL_RULE_FIELD_SRC_MAC           = "SRC_MAC"
	ACL_RULE_FIELD_DST_MAC           = "DST_MAC"
	ACL_RULE_FIELD_ETHER_TYPE        = "ETHER_TYPE"
	ACL_RULE_FIELD_PCP               = "PCP"
	ACL_RULE_FIELD_DEI               = "DEI"
	ACL_RULE_ICMP_TYPE               = "ICMP_TYPE"
	ACL_RULE_ICMP_CODE               = "ICMP_CODE"
	ACL_RULE_FIELD_VLANID            = "VLAN"
	ACL_RULE_FIELD_DESCRIPTION       = "DESCRIPTION"
	ACL_RULE_PACKET_ACTION           = "PACKET_ACTION"
	ACL_CTRL_PLANE_PORT              = "CtrlPlane"
	ACL_GLOBAL_PORT                  = "Switch"

	MIN_PRIORITY = 1
	MAX_PRIORITY = 65536 // Seq num range is 1-65535. these are converted into prio 65535-1
)

var IP_PROTOCOL_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]uint8{
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_ICMP: 1,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_IGMP: 2,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_TCP:  6,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_UDP:  17,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_RSVP: 46,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_GRE:  47,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_AUTH: 51,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_PIM:  103,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_L2TP: 115,
}

var ETHERTYPE_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_ETHERTYPE]uint32{
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_LLDP: 0x88CC,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_VLAN: 0x8100,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ROCE: 0x8915,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ARP:  0x0806,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV4: 0x0800,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV6: 0x86DD,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_MPLS: 0x8847,
}

type AclApp struct {
	pathInfo   *PathInfo
	ygotRoot   *ygot.GoStruct
	ygotTarget *interface{}

	aclTs          *db.TableSpec
	ruleTs         *db.TableSpec
	counterTs      *db.TableSpec
	lastCounterTs  *db.TableSpec
	hardwareTs     *db.TableSpec
	aclBindStateTs *db.TableSpec

	aclTableMap         map[string]db.Value
	ruleTableMap        map[string]map[string]db.Value
	hardwareAclTableMap map[string]db.Value
	aclInterfacesMap    map[string][]string // Key=ACL Name, Value=Interfaces List
}

func init() {

	err := register("/openconfig-acl:acl",
		&appInfo{appType: reflect.TypeOf(AclApp{}),
			ygotRootType:  reflect.TypeOf(ocbinds.OpenconfigAcl_Acl{}),
			isNative:      false,
			tablesToWatch: []*db.TableSpec{&db.TableSpec{Name: ACL_TABLE}, &db.TableSpec{Name: RULE_TABLE}}})

	if err != nil {
		log.Fatal("Register ACL app module with App Interface failed with error=", err)
	}

	err = addModel(&ModelData{Name: "openconfig-acl",
		Org: "OpenConfig working group",
		Ver: "1.0.2"})
	if err != nil {
		log.Fatal("Adding model data to appinterface failed with error=", err)
	}
}

func (app *AclApp) initialize(data appData) {
	log.Info("initialize:acl:path =", data.path)
	pathInfo := NewPathInfo(data.path)
	*app = AclApp{pathInfo: pathInfo, ygotRoot: data.ygotRoot, ygotTarget: data.ygotTarget}

	app.aclTs = &db.TableSpec{Name: ACL_TABLE}
	app.ruleTs = &db.TableSpec{Name: RULE_TABLE}
	app.counterTs = &db.TableSpec{Name: ACL_COUNTERS}
	app.lastCounterTs = &db.TableSpec{Name: LAST_ACL_COUNTERS}
	app.hardwareTs = &db.TableSpec{Name: HARDWARE, NoDelete: true}
	app.aclBindStateTs = &db.TableSpec{Name: "ACL_BINDING_TABLE", NoDelete: true}

	app.aclTableMap = make(map[string]db.Value)
	app.ruleTableMap = make(map[string]map[string]db.Value)
	app.hardwareAclTableMap = make(map[string]db.Value)
}

func (app *AclApp) getAppRootObject() *ocbinds.OpenconfigAcl_Acl {
	deviceObj := (*app.ygotRoot).(*ocbinds.Device)
	return deviceObj.Acl
}

func (app *AclApp) translateCreate(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys
	log.Info("translateCreate:acl:path =", app.pathInfo.Template)

	keys, err = app.translateCRUCommon(d, CREATE)
	return keys, err
}

func (app *AclApp) translateUpdate(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys
	log.Info("translateUpdate:acl:path =", app.pathInfo.Template)

	keys, err = app.translateCRUCommon(d, UPDATE)
	return keys, err
}

func (app *AclApp) translateReplace(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys
	log.Info("translateReplace:acl:path =", app.pathInfo.Template)

	keys, err = app.translateCRUCommon(d, REPLACE)
	return keys, err
}

func (app *AclApp) translateDelete(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys
	log.Info("translateDelete:acl:path =", app.pathInfo.Template)

	return keys, err
}

func (app *AclApp) translateGet(dbs [db.MaxDB]*db.DB) error {
	var err error
	log.Info("translateGet:acl:path =", app.pathInfo.Template)
	return err
}

func (app *AclApp) translateAction(dbs [db.MaxDB]*db.DB) error {
	err := errors.New("Not supported")
	return err
}

func (app *AclApp) translateSubscribe(dbs [db.MaxDB]*db.DB, path string) (*notificationOpts, *notificationInfo, error) {
	pathInfo := NewPathInfo(path)
	notifInfo := notificationInfo{dbno: db.ConfigDB}
	notifOpts := notificationOpts{isOnChangeSupported: true}
	notSupported := tlerr.NotSupportedError{
		Format: "Subscribe not supported", Path: path}

	if isSubtreeRequest(pathInfo.Template, "/openconfig-acl:acl/acl-sets") {
		// Subscribing to top level ACL record is not supported. It requires listening
		// to 2 tables (ACL and ACL_RULE); TransLib does not support it yet
		if pathInfo.HasSuffix("/acl-sets") ||
			pathInfo.HasSuffix("/acl-set") ||
			pathInfo.HasSuffix("/acl-set{}{}") {
			log.Errorf("Subscribe not supported for top level ACL %s", pathInfo.Template)
			return nil, nil, notSupported
		}

		t, err := getAclTypeOCEnumFromName(pathInfo.Var(ACL_FIELD_TYPE))
		if err != nil {
			return nil, nil, err
		}

		aclkey := convertOCAclnameTypeToInternal(pathInfo.Var("name"), t)

		if strings.Contains(pathInfo.Template, "/acl-entry{}") {
			// Subscribe for one rule
			rulekey := "RULE_" + pathInfo.Var("sequence-id")
			notifInfo.table = db.TableSpec{Name: RULE_TABLE}
			notifInfo.key = asKey(aclkey, rulekey)
			notifInfo.needCache = !pathInfo.HasSuffix("/acl-entry{}")

		} else if pathInfo.HasSuffix("/acl-entries") || pathInfo.HasSuffix("/acl-entry") {
			// Subscribe for all rules of an ACL
			notifInfo.table = db.TableSpec{Name: RULE_TABLE}
			notifInfo.key = asKey(aclkey, "*")

		} else {
			// Subscibe for ACL fields only
			notifInfo.table = db.TableSpec{Name: ACL_TABLE}
			notifInfo.key = asKey(aclkey)
			notifInfo.needCache = true
		}
	} else if isSubtreeRequest(pathInfo.Template, "/openconfig-acl:acl/interfaces") {
		// Right now interface binding config is maintained within ACL
		// table itself. Multiple ACLs can be bound to one intf; one
		// inname can occur in multiple ACL entries. So we cannot map
		// interface binding xpaths to specific ACL table entry keys.
		// For now subscribe for full ACL table!!
		notifInfo.table = db.TableSpec{Name: ACL_TABLE}
		notifInfo.key = asKey("*")
		notifInfo.needCache = true

	} else {
		log.Errorf("Unknown path %s", pathInfo.Template)
		return nil, nil, notSupported
	}

	return &notifOpts, &notifInfo, nil
}

func (app *AclApp) processCreate(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCommon(d, CREATE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *AclApp) processUpdate(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCommon(d, UPDATE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *AclApp) processReplace(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCommon(d, REPLACE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *AclApp) processDelete(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCommon(d, DELETE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *AclApp) processGet(dbs [db.MaxDB]*db.DB) (GetResponse, error) {
	var err error
	var payload []byte

	err = app.processAclGet(dbs)
	if err != nil {
		return GetResponse{Payload: payload, ErrSrc: AppErr}, err
	}

	payload, err = generateGetResponsePayload(app.pathInfo.Path, (*app.ygotRoot).(*ocbinds.Device), app.ygotTarget)
	if err != nil {
		return GetResponse{Payload: payload, ErrSrc: AppErr}, err
	}

	return GetResponse{Payload: payload}, err
}

func (app *AclApp) processAction(dbs [db.MaxDB]*db.DB) (ActionResponse, error) {
	var resp ActionResponse
	err := errors.New("Not implemented")

	return resp, err
}

func uniquePorts(ports []string) []string {
	temp := make(map[string]bool)
	for _, port := range ports {
		temp[port] = true
	}

	i := 0
	ret := make([]string, len(temp))
	for key := range temp {
		ret[i] = key
		i++
	}

	return ret
}

func (app *AclApp) translateCRUCommon(d *db.DB, opcode int) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys
	log.Info("translateCRUCommon:acl:path =", app.pathInfo.Template)

	// First level check if the URI itself contains unsupported paths. Second check will be done
	// later from the payload
	if strings.Contains(app.pathInfo.Template, "input-interface") {
		return nil, tlerr.NotSupported("input-interface not supported")
	}

	app.convertOCCountermodeToInternal()
	app.convertOCAclsToInternal()
	err = app.convertOCAclRulesToInternal()
	if err == nil {
		err = app.convertOCAclInterfaceBindingsToInternal()
	}
	if err == nil {
		app.convertOCAclGlobalBindingsToInternal()
		app.convertOCAclControlPlaneBindingsToInternal()
	}
	if err == nil {
		for aclName, ports := range app.aclInterfacesMap {
			aclData := app.aclTableMap[aclName]
			portList := aclData.GetList(ACL_FIELD_PORTS)
			portList = append(portList, ports...)
			portList = uniquePorts(portList)
			aclData.SetList(ACL_FIELD_PORTS, portList)
			app.aclTableMap[aclName] = aclData
			log.Info(aclData)
		}
	}

	return keys, err
}

func (app *AclApp) processAclGet(dbs [db.MaxDB]*db.DB) error {

	var err error

	d := dbs[db.ConfigDB]
	acl := app.getAppRootObject()

	log.Infof("processAclGet--Path Received: %s", app.pathInfo.Template)

	err = app.convertDBAclCounterToInternal(dbs)
	if nil != err {
		log.Error("Unable to get counter mode")
		return err
	}

	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/config") ||
		isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/state") {
		ygot.BuildEmptyTree(acl)
		app.convertInternalToOCAclCounter(dbs, acl)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/acl-sets") {
		if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/acl-sets/acl-set{}{}") {
			for aclSetKey := range acl.AclSets.AclSet {
				aclSet := acl.AclSets.AclSet[aclSetKey]
				aclKey := app.getAclKeyByCheckingDbForNameWithoutType(d, aclSetKey.Name, aclSetKey.Type)

				if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/acl-sets/acl-set{}{}/acl-entries/acl-entry{}") {
					// Subtree of one Rule
					for seqId := range aclSet.AclEntries.AclEntry {
						entrySet := aclSet.AclEntries.AclEntry[seqId]
						ruleKeyStr := app.getAclRuleByCheckingDbForNameWithoutRule(d, aclKey, strconv.FormatInt(int64(seqId), 10))
						err = app.convertDBAclRulesToInternal(dbs, aclKey, ruleKeyStr, db.Key{})
						ygot.BuildEmptyTree(entrySet)
						app.convertInternalToOCAclRule(aclKey, aclSetKey.Type, ruleKeyStr, nil, entrySet)
					}
				} else {
					err = app.convertDBAclToInternal(dbs, db.Key{Comp: []string{aclKey}})
					if err != nil {
						return err
					}
					ygot.BuildEmptyTree(aclSet)
					app.convertInternalToOCAcl(aclKey, acl.AclSets, aclSet)
				}
			}
		} else {
			// Get all Acls and their rules
			err = app.processCommonToplevelGetPath(dbs, acl, false)
		}
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/interfaces") {
		err = app.getOCInterfaceSubtree(dbs, acl.Interfaces)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:global") {
		err = app.getAclBindingInfoForSwitch(dbs)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:control-plane") {
		err = app.getAclBindingInfoForControlPlane(dbs)
	} else {
		err = app.processCommonToplevelGetPath(dbs, acl, true)
	}

	return err
}

func (app *AclApp) processCommon(d *db.DB, opcode int) error {
	var err error
	acl := app.getAppRootObject()

	targetUriPath, _ := getYangPathFromUri(app.pathInfo.Path)
	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/config") {
		switch opcode {
		case CREATE:
		case DELETE:
			err = tlerr.NotSupported("Create or Delete on %s is not supported", app.pathInfo.Template)
		case REPLACE:
		case UPDATE:
			if len(app.hardwareAclTableMap) > 0 {
				err = app.setAclCounterDataInConfigDb(d, app.hardwareAclTableMap)
			} else {
				err = tlerr.InvalidArgs("No data to set")
			}
		}
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/acl-sets") {
		if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/acl-sets/acl-set{}{}") {
			for aclSetKey := range acl.AclSets.AclSet {
				aclSet := acl.AclSets.AclSet[aclSetKey]
				aclKey := convertOCAclnameTypeToInternal(aclSetKey.Name, aclSetKey.Type)

				if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/acl-sets/acl-set{}{}/acl-entries/acl-entry{}") {
					// Subtree of one Rule
					for seqId := range aclSet.AclEntries.AclEntry {
						ruleKey := "RULE_" + strconv.Itoa(int(seqId))
						entrySet := aclSet.AclEntries.AclEntry[seqId]

						ruleNodeYangPath := getYangPathFromYgotStruct(entrySet, OC_ACL_YANG_PATH_PREFIX, OC_ACL_APP_MODULE_NAME)
						isRuleNodeSubtree := len(targetUriPath) > len(ruleNodeYangPath)
						switch opcode {
						case CREATE:
							if isRuleNodeSubtree {
								err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, false)
							} else if *app.ygotTarget == entrySet {
								err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, true)
							} else {
								log.Errorf("processCommon: Given CREATE path %s not handled", targetUriPath)
							}
						case REPLACE:
							err = d.SetEntry(app.ruleTs, db.Key{Comp: []string{aclKey, ruleKey}}, app.ruleTableMap[aclKey][ruleKey])
						case UPDATE:
							err = d.ModEntry(app.ruleTs, db.Key{Comp: []string{aclKey, ruleKey}}, app.ruleTableMap[aclKey][ruleKey])
						case DELETE:
							if *app.ygotTarget == entrySet {
								err = d.DeleteEntry(app.ruleTs, db.Key{Comp: []string{aclKey, ruleKey}})
							} else if isRuleNodeSubtree {
								err = app.handleRuleFieldsDeletion(d, aclKey, ruleKey)
								if err != nil {
									return err
								}
								//err = d.SetEntry(app.ruleTs, db.Key{Comp: []string{aclKey, ruleKey}}, app.ruleTableMap[aclKey][ruleKey])
							} else {
								log.Errorf("processCommon: Given DELETE path %s not handled", targetUriPath)
							}
						}
					}
				} else {
					isAclEntriesSubtree := isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/acl-sets/acl-set{}{}/acl-entries")
					switch opcode {
					case CREATE:
						if *app.ygotTarget == aclSet {
							err = app.setAclDataInConfigDb(d, app.aclTableMap, true)
							if err != nil {
								return err
							}
							err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, true)
						} else if isAclEntriesSubtree {
							err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, true)
						} else {
							err = d.SetEntry(app.aclTs, db.Key{Comp: []string{aclKey}}, app.aclTableMap[aclKey])
						}
					case REPLACE:
						if *app.ygotTarget == aclSet || isAclEntriesSubtree {
							err = d.DeleteKeys(app.ruleTs, db.Key{Comp: []string{aclKey + TABLE_SEPARATOR + "*"}})
							if err != nil {
								return err
							}
							err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, true)
							if err != nil {
								return err
							}
						}
						if !isAclEntriesSubtree {
							err = d.ModEntry(app.aclTs, db.Key{Comp: []string{aclKey}}, app.aclTableMap[aclKey])
						}
					case UPDATE:
						if !isAclEntriesSubtree {
							err = app.setAclDataInConfigDb(d, app.aclTableMap, false)
							//err = d.ModEntry(app.aclTs, db.Key{Comp: []string{aclKey}}, app.aclTableMap[aclKey])
							if err != nil {
								return err
							}
						}
						if *app.ygotTarget == aclSet || isAclEntriesSubtree {
							err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, false)
						}
					case DELETE:
						if *app.ygotTarget == aclSet {
							err = d.DeleteKeys(app.ruleTs, db.Key{Comp: []string{aclKey + TABLE_SEPARATOR + "*"}})
							if err != nil {
								return err
							}
							err = d.DeleteEntry(app.aclTs, db.Key{Comp: []string{aclKey}})
						} else if isAclEntriesSubtree {
							err = d.DeleteKeys(app.ruleTs, db.Key{Comp: []string{aclKey + TABLE_SEPARATOR + "RULE_*"}})
						} else {
							nodeInfo, err := getTargetNodeYangSchema(app.pathInfo.Path, (*app.ygotRoot).(*ocbinds.Device))
							if err != nil {
								return err
							}
							if nodeInfo != nil && nodeInfo.IsLeaf() && nodeInfo.Name == "description" {
								err = d.DeleteEntryFields(app.aclTs, asKey(aclKey), createEmptyDbValue(ACL_DESCRIPTION))
								if nil != err {
									log.Error(err)
								}
							}
							//err = d.SetEntry(app.aclTs, db.Key{Comp: []string{aclKey}}, app.aclTableMap[aclKey])
						}
					}
				}
			}
		} else {
			// All Acls and their rules
			err = app.processCommonToplevelPath(d, acl, opcode, false)
		}
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/interfaces") ||
		isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:global") ||
		isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:control-plane") {
		switch opcode {
		case CREATE, REPLACE, UPDATE:
			err = app.setAclBindDataInConfigDb(d, opcode)
		case DELETE:
			err = app.handleBindingsDeletion(d)
		}
	} else {
		err = app.processCommonToplevelPath(d, acl, opcode, true)
	}

	return err
}

func (app *AclApp) processCommonToplevelGetPath(dbs [db.MaxDB]*db.DB, acl *ocbinds.OpenconfigAcl_Acl, isTopmostPath bool) error {

	var err error
	ygot.BuildEmptyTree(acl)

	err = app.convertDBAclToInternal(dbs, db.Key{})
	if err != nil {
		return err
	}
	app.convertInternalToOCAcl("", acl.AclSets, nil)
	if isTopmostPath {
		err = app.getAllBindingsInfo(dbs, false)
		if nil == err {
			err = app.convertDBAclCounterToInternal(dbs)
			if nil == err {
				app.convertInternalToOCAclCounter(dbs, acl)
			}
		}
	}

	return err
}

func (app *AclApp) processCommonToplevelPath(d *db.DB, acl *ocbinds.OpenconfigAcl_Acl, opcode int, isTopmostPath bool) error {
	var err error
	switch opcode {
	case CREATE:
		err = app.setAclCounterDataInConfigDb(d, app.hardwareAclTableMap)
		if err == nil {
			err = app.setAclDataInConfigDb(d, app.aclTableMap, true)
		}
		if err == nil {
			err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, true)
		}
	case REPLACE:
		err = d.DeleteTable(app.aclTs)
		if err == nil {
			err = d.DeleteTable(app.ruleTs)
		}
		if err == nil {
			err = app.setAclCounterDataInConfigDb(d, app.hardwareAclTableMap)
		}
		if err == nil {
			err = app.setAclDataInConfigDb(d, app.aclTableMap, true)
		}
		if err == nil {
			err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, true)
		}
	case UPDATE:
		err = app.setAclCounterDataInConfigDb(d, app.hardwareAclTableMap)
		if err == nil {
			err = app.setAclDataInConfigDb(d, app.aclTableMap, false)
		}
		if err == nil {
			err = app.setAclRuleDataInConfigDb(d, app.ruleTableMap, false)
		}
	case DELETE:
		err = d.DeleteTable(app.ruleTs)
		if err == nil {
			err = d.DeleteTable(app.aclTs)
		}
	}
	return err
}

/***********    These are Translation Helper Function   ***********/
func (app *AclApp) getAclCounterMode(dbs [db.MaxDB]*db.DB) ocbinds.E_OpenconfigAcl_ACL_COUNTER_CAPABILITY {
	aclHw, found := app.hardwareAclTableMap["ACCESS_LIST"]
	if found {
		ctrType := aclHw.Field["COUNTER_MODE"]
		if strings.EqualFold(ctrType, "per-rule") {
			return ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_AGGREGATE_ONLY
		} else if strings.EqualFold(ctrType, "per-interface-rule") {
			return ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_INTERFACE_ONLY
		}
	} else {
		data, err := dbs[db.ConfigDB].GetEntry(app.hardwareTs, db.Key{Comp: []string{"ACCESS_LIST"}})
		if nil == err {
			app.hardwareAclTableMap["ACCESS_LIST"] = data
			return app.getAclCounterMode(dbs)
		}
	}

	return ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_AGGREGATE_ONLY
}

func (app *AclApp) convertDBAclCounterToInternal(dbs [db.MaxDB]*db.DB) error {
	dbCl := dbs[db.ConfigDB]
	data, err := dbCl.GetEntry(app.hardwareTs, db.Key{Comp: []string{"ACCESS_LIST"}})
	if nil == err {
		app.hardwareAclTableMap["ACCESS_LIST"] = data
	}

	return err
}

func (app *AclApp) convertInternalToOCAclCounter(dbs [db.MaxDB]*db.DB, acl *ocbinds.OpenconfigAcl_Acl) {
	acl.Config.CounterCapability = app.getAclCounterMode(dbs)
	acl.State.CounterCapability = acl.Config.CounterCapability
}

func (app *AclApp) convertDBAclRulesToInternal(dbs [db.MaxDB]*db.DB, aclName string, ruleName string, ruleKey db.Key) error {
	dbCl := dbs[db.ConfigDB]
	dbCo := dbs[db.CountersDB]

	var err error
	if len(ruleName) > 0 {
		aclData, acl_err := dbCl.GetEntry(app.aclTs, db.Key{Comp: []string{aclName}})
		if acl_err != nil {
			log.Info("Configdb getentry failed for acl ", aclName)
			return acl_err
		}
		ruleKey.Comp = []string{aclName, ruleName, strings.ToUpper(aclData.Get(ACL_FIELD_STAGE))}
	}
	if ruleKey.Len() > 1 {
		ruleName := ruleKey.Get(1)
		ruleData, err := dbCl.GetEntry(app.ruleTs, db.Key{Comp: []string{ruleKey.Get(0), ruleKey.Get(1)}})
		if err != nil {
			log.Info("Configdb getentry failed for rule ", ruleName)
			return err
		}
		if app.ruleTableMap[aclName] == nil {
			app.ruleTableMap[aclName] = make(map[string]db.Value)
		}
		if app.getAclCounterMode(dbs) == ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_AGGREGATE_ONLY {
			counterData, cErr := dbCo.GetEntry(app.counterTs, ruleKey)
			if cErr == nil && len(counterData.Field) > 0 {
				lastCounterData, lastCntErr := dbCo.GetEntry(app.lastCounterTs, ruleKey)
				if lastCntErr == nil && len(lastCounterData.Field) > 0 {
					for k, v := range counterData.Field {
						val, _ := strconv.ParseUint(v, 10, 64)
						lastVal, _ := strconv.ParseUint(lastCounterData.Field[k], 10, 64)
						log.Infof("Key:%v Field:%v Val:%v LastVal:%v", ruleKey, k, val, lastVal)
						ruleData.Field[k] = strconv.FormatUint(val-lastVal, 10)
					}
				}
			} else {
				log.Infof("No counter available for %v", ruleKey)
			}
		} else {
			log.Infof("ACL Counter is not aggregate. Will not populate per rule counters")
		}
		app.ruleTableMap[aclName][ruleName] = ruleData
	} else {
		aclData, acl_err := dbCl.GetEntry(app.aclTs, db.Key{Comp: []string{aclName}})
		if acl_err != nil {
			log.Info("Configdb getentry failed for acl ", aclName)
			return acl_err
		}

		ruleKeys, err := dbCl.GetKeys(app.ruleTs)
		if err != nil {
			return err
		}
		for i := range ruleKeys {
			if aclName == ruleKeys[i].Get(0) {
				app.convertDBAclRulesToInternal(dbs, aclName, "", db.Key{Comp: []string{ruleKeys[i].Get(0),
					ruleKeys[i].Get(1), strings.ToUpper(aclData.Get(ACL_FIELD_STAGE))}})
			}
		}
	}

	return err
}

func (app *AclApp) convertDBAclToInternal(dbs [db.MaxDB]*db.DB, aclkey db.Key) error {
	var err error
	dbCl := dbs[db.ConfigDB]

	if aclkey.Len() > 0 {
		// Get one particular ACL
		entry, err := dbCl.GetEntry(app.aclTs, aclkey)
		if err != nil {
			return err
		}
		if entry.IsPopulated() {
			app.aclTableMap[aclkey.Get(0)] = entry
			app.ruleTableMap[aclkey.Get(0)] = make(map[string]db.Value)
			err = app.convertDBAclRulesToInternal(dbs, aclkey.Get(0), "", db.Key{})
			if err != nil {
				return err
			}
		} else {
			return tlerr.NotFound("Acl %s is not configured", aclkey.Get(0))
		}
	} else {
		// Get all ACLs
		tbl, err := dbCl.GetTable(app.aclTs)
		if err != nil {
			return err
		}
		keys, _ := tbl.GetKeys()
		for i := range keys {
			app.convertDBAclToInternal(dbs, keys[i])
		}
	}
	return err
}

func (app *AclApp) convertInternalToOCAcl(aclName string, aclSets *ocbinds.OpenconfigAcl_Acl_AclSets, aclSet *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet) {
	if len(aclName) > 0 {
		aclData := app.aclTableMap[aclName]
		if aclSet != nil {
			aclSet.Config.Name = aclSet.Name
			aclSet.Config.Type = aclSet.Type
			aclSet.State.Name = aclSet.Name
			aclSet.State.Type = aclSet.Type

			for k := range aclData.Field {
				if ACL_DESCRIPTION == k {
					descr := aclData.Get(k)
					aclSet.Config.Description = &descr
					aclSet.State.Description = &descr
				} else if k == "ports@" {
					continue
				}
			}
			app.convertInternalToOCAclRule(aclName, aclSet.Type, "", aclSet, nil)
		}
	} else {
		for acln := range app.aclTableMap {
			acldata := app.aclTableMap[acln]
			aclNameStr, aclType := convertInternalAclnameTypeToOC(acln, acldata.Get(ACL_FIELD_TYPE))
			if aclType != ocbinds.OpenconfigAcl_ACL_TYPE_UNSET {
				aclSetPtr, aclErr := aclSets.NewAclSet(aclNameStr, aclType)
				if aclErr != nil {
					fmt.Println("Error handling: ", aclErr)
				}
				ygot.BuildEmptyTree(aclSetPtr)
				app.convertInternalToOCAcl(acln, nil, aclSetPtr)
			}
		}
	}
}

func (app *AclApp) convertInternalToOCAclRule(aclName string, aclType ocbinds.E_OpenconfigAcl_ACL_TYPE, ruleName string, aclSet *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet, entrySet *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) {
	if len(ruleName) > 0 {
		//ruleName := "RULE_" + strconv.FormatInt(int64(seqId), 10)
		app.convertInternalToOCAclRuleProperties(app.ruleTableMap[aclName][ruleName], aclType, nil, entrySet)
	} else {
		for ruleName := range app.ruleTableMap[aclName] {
			app.convertInternalToOCAclRuleProperties(app.ruleTableMap[aclName][ruleName], aclType, aclSet, nil)
		}
	}
}

func (app *AclApp) convertInternalToOCAclRuleProperties(ruleData db.Value, aclType ocbinds.E_OpenconfigAcl_ACL_TYPE, aclSet *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet, entrySet *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) {
	priority, _ := strconv.ParseInt(ruleData.Get("PRIORITY"), 10, 32)
	seqId := uint32(MAX_PRIORITY - priority)

	if entrySet == nil {
		if aclSet != nil {
			entrySet_, _ := aclSet.AclEntries.NewAclEntry(seqId)
			entrySet = entrySet_
			ygot.BuildEmptyTree(entrySet)
		}
	}

	entrySet.Config.SequenceId = &seqId
	entrySet.State.SequenceId = &seqId

	ygot.BuildEmptyTree(entrySet.Transport)
	ygot.BuildEmptyTree(entrySet.Actions)

	for ruleKey := range ruleData.Field {
		if ACL_RULE_FIELD_L4_SRC_PORT == ruleKey || ACL_RULE_FIELD_L4_SRC_PORT_RANGE == ruleKey {
			port := ruleData.Get(ruleKey)
			srcPort := getTransportSrcDestPorts(port, "src")
			entrySet.Transport.Config.SourcePort, _ = entrySet.Transport.Config.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_Union(srcPort)
			entrySet.Transport.State.SourcePort, _ = entrySet.Transport.State.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_State_SourcePort_Union(srcPort)
		} else if ACL_RULE_FIELD_L4_DST_PORT == ruleKey || ACL_RULE_FIELD_L4_DST_PORT_RANGE == ruleKey {
			port := ruleData.Get(ruleKey)
			destPort := getTransportSrcDestPorts(port, "dest")
			entrySet.Transport.Config.DestinationPort, _ = entrySet.Transport.Config.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_Union(destPort)
			entrySet.Transport.State.DestinationPort, _ = entrySet.Transport.State.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_State_DestinationPort_Union(destPort)
		} else if ACL_RULE_FIELD_TCP_FLAGS == ruleKey {
			tcpFlags := ruleData.Get(ruleKey)
			entrySet.Transport.Config.TcpFlags = getTransportConfigTcpFlags(tcpFlags)
			entrySet.Transport.State.TcpFlags = getTransportConfigTcpFlags(tcpFlags)
		} else if ACL_RULE_PACKET_ACTION == ruleKey {
			if strings.ToUpper(ruleData.Get(ruleKey)) == "FORWARD" {
				entrySet.Actions.Config.ForwardingAction = ocbinds.OpenconfigAcl_FORWARDING_ACTION_ACCEPT
				entrySet.Actions.State.ForwardingAction = ocbinds.OpenconfigAcl_FORWARDING_ACTION_ACCEPT
			} else if strings.ToUpper(ruleData.Get(ruleKey)) == "DO_NOT_NAT" {
				entrySet.Actions.Config.ForwardingAction = ocbinds.OpenconfigAcl_FORWARDING_ACTION_DO_NOT_NAT
				entrySet.Actions.State.ForwardingAction = ocbinds.OpenconfigAcl_FORWARDING_ACTION_DO_NOT_NAT
			} else {
				entrySet.Actions.Config.ForwardingAction = ocbinds.OpenconfigAcl_FORWARDING_ACTION_DROP
				entrySet.Actions.State.ForwardingAction = ocbinds.OpenconfigAcl_FORWARDING_ACTION_DROP
			}
		} else if ACL_RULE_ICMP_TYPE == ruleKey {
			data, _ := strconv.ParseUint(ruleData.Get(ruleKey), 10, 8)
			dataInt := uint8(data)
			entrySet.Transport.Config.IcmpType = &dataInt
			entrySet.Transport.State.IcmpType = &dataInt
		} else if ACL_RULE_ICMP_CODE == ruleKey {
			data, _ := strconv.ParseUint(ruleData.Get(ruleKey), 10, 8)
			dataInt := uint8(data)
			entrySet.Transport.Config.IcmpCode = &dataInt
			entrySet.Transport.State.IcmpCode = &dataInt
		} else if ruleKey == "Packets" {
			pkts, _ := strconv.ParseUint(ruleData.Get(ruleKey), 10, 64)
			entrySet.State.MatchedPackets = &pkts
			log.Info("Packets count ", pkts, " found in  COUNTER db for rulekey ", ruleKey)
		} else if ruleKey == "Bytes" {
			bytes, _ := strconv.ParseUint(ruleData.Get(ruleKey), 10, 64)
			entrySet.State.MatchedOctets = &bytes
		} else if ACL_RULE_FIELD_DESCRIPTION == ruleKey {
			ruleDescr := ruleData.Get(ACL_RULE_FIELD_DESCRIPTION)
			entrySet.Config.Description = &ruleDescr
			entrySet.State.Description = &ruleDescr
		} else if ACL_RULE_FIELD_VLANID == ruleKey {
			vlanIdData, _ := strconv.ParseInt(ruleData.Get(ACL_RULE_FIELD_VLANID), 10, 16)
			vlanId := uint16(vlanIdData)
			ygot.BuildEmptyTree(entrySet.L2)
			entrySet.L2.Config.Vlanid = &vlanId
			entrySet.L2.State.Vlanid = &vlanId
		}
	}

	if aclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4 {
		ygot.BuildEmptyTree(entrySet.Ipv4)
		for ruleKey := range ruleData.Field {
			if ACL_RULE_FIELD_IP_PROTOCOL == ruleKey {
				ipProto, _ := strconv.ParseInt(ruleData.Get(ruleKey), 10, 64)
				protocolVal := getIpProtocol(ipProto)
				entrySet.Ipv4.Config.Protocol, _ = entrySet.Ipv4.Config.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4_Config_Protocol_Union(protocolVal)
				entrySet.Ipv4.State.Protocol, _ = entrySet.Ipv4.State.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4_State_Protocol_Union(protocolVal)
			} else if ACL_RULE_FIELD_DSCP == ruleKey {
				var dscp uint8
				dscpData, _ := strconv.ParseInt(ruleData.Get(ruleKey), 10, 64)
				dscp = uint8(dscpData)
				entrySet.Ipv4.Config.Dscp = &dscp
				entrySet.Ipv4.State.Dscp = &dscp
			} else if ACL_RULE_FIELD_SRC_IP == ruleKey {
				addr := ruleData.Get(ruleKey)
				entrySet.Ipv4.Config.SourceAddress = &addr
				entrySet.Ipv4.State.SourceAddress = &addr
			} else if ACL_RULE_FIELD_DST_IP == ruleKey {
				addr := ruleData.Get(ruleKey)
				entrySet.Ipv4.Config.DestinationAddress = &addr
				entrySet.Ipv4.State.DestinationAddress = &addr
			}
		}
	} else if aclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV6 {
		ygot.BuildEmptyTree(entrySet.Ipv6)
		for ruleKey := range ruleData.Field {
			if ACL_RULE_FIELD_IP_PROTOCOL == ruleKey {
				ipProto, _ := strconv.ParseInt(ruleData.Get(ruleKey), 10, 64)
				protocolVal := getIpProtocol(ipProto)
				entrySet.Ipv6.Config.Protocol, _ = entrySet.Ipv6.Config.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6_Config_Protocol_Union(protocolVal)
				entrySet.Ipv6.State.Protocol, _ = entrySet.Ipv6.State.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6_State_Protocol_Union(protocolVal)
			} else if ACL_RULE_FIELD_DSCP == ruleKey {
				var dscp uint8
				dscpData, _ := strconv.ParseInt(ruleData.Get(ruleKey), 10, 64)
				dscp = uint8(dscpData)
				entrySet.Ipv6.Config.Dscp = &dscp
				entrySet.Ipv6.State.Dscp = &dscp
			} else if ACL_RULE_FIELD_SRC_IPV6 == ruleKey {
				addr := ruleData.Get(ruleKey)
				entrySet.Ipv6.Config.SourceAddress = &addr
				entrySet.Ipv6.State.SourceAddress = &addr
			} else if ACL_RULE_FIELD_DST_IPV6 == ruleKey {
				addr := ruleData.Get(ruleKey)
				entrySet.Ipv6.Config.DestinationAddress = &addr
				entrySet.Ipv6.State.DestinationAddress = &addr
			}
		}
	} else if aclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2 {
		if nil == entrySet.L2 {
			ygot.BuildEmptyTree(entrySet.L2)
		}
		for ruleKey := range ruleData.Field {
			if ACL_RULE_FIELD_ETHER_TYPE == ruleKey {
				ethType, _ := strconv.ParseUint(strings.Replace(ruleData.Get(ruleKey), "0x", "", -1), 16, 32)
				ethertype := getL2EtherType(ethType)
				entrySet.L2.Config.Ethertype, _ = entrySet.L2.Config.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2_Config_Ethertype_Union(ethertype)
				entrySet.L2.State.Ethertype, _ = entrySet.L2.State.To_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2_State_Ethertype_Union(ethertype)
			} else if ACL_RULE_FIELD_SRC_MAC == ruleKey {
				parts := strings.Split(ruleData.Get(ruleKey), "/")
				entrySet.L2.Config.SourceMac = &parts[0]
				entrySet.L2.State.SourceMac = &parts[0]
				if len(parts) > 1 {
					entrySet.L2.Config.SourceMacMask = &parts[1]
					entrySet.L2.State.SourceMacMask = &parts[1]
				}
			} else if ACL_RULE_FIELD_DST_MAC == ruleKey {
				parts := strings.Split(ruleData.Get(ruleKey), "/")
				entrySet.L2.Config.DestinationMac = &parts[0]
				entrySet.L2.State.DestinationMac = &parts[0]
				if len(parts) > 1 {
					entrySet.L2.Config.DestinationMacMask = &parts[1]
					entrySet.L2.State.DestinationMacMask = &parts[1]
				}
			} else if ACL_RULE_FIELD_PCP == ruleKey {
				parts := strings.Split(ruleData.Get(ruleKey), "/")
				pcp, _ := strconv.ParseUint(parts[0], 10, 8)
				pcpRes := uint8(pcp)
				entrySet.L2.Config.Pcp = &pcpRes
				entrySet.L2.State.Pcp = &pcpRes
				if len(parts) > 1 {
					pcpMask, _ := strconv.ParseUint(parts[1], 10, 8)
					pcpMaskRes := uint8(pcpMask)
					entrySet.L2.Config.PcpMask = &pcpMaskRes
					entrySet.L2.State.PcpMask = &pcpMaskRes
				}
			} else if ACL_RULE_FIELD_DEI == ruleKey {
				dei, _ := strconv.ParseUint(ruleData.Get(ruleKey), 10, 8)
				deiRes := uint8(dei)
				entrySet.L2.Config.Dei = &deiRes
				entrySet.L2.State.Dei = &deiRes
			}
		}
	}
}

func (app *AclApp) getAllAclTablesFromDB(cdb *db.DB) error {
	if len(app.aclTableMap) == 0 {
		aclKeys, err := cdb.GetKeys(app.aclTs)
		if err != nil {
			return err
		}

		for i := range aclKeys {
			aclEntry, err := cdb.GetEntry(app.aclTs, aclKeys[i])
			if err != nil {
				return err
			}
			app.aclTableMap[(aclKeys[i]).Get(0)] = aclEntry
		}
	}

	return nil
}

func (app *AclApp) getAllBindingsInfo(dbs [db.MaxDB]*db.DB, intfOnly bool) error {
	acl := app.getAppRootObject()

	if !intfOnly {
		if err := app.getAclBindingInfoForControlPlane(dbs); err != nil {
			return err
		}

		if err := app.getAclBindingInfoForSwitch(dbs); err != nil {
			return err
		}
	}

	err := app.getOCInterfaceSubtree(dbs, acl.Interfaces)
	return err
}

func (app *AclApp) getOCInterfaceSubtree(dbs [db.MaxDB]*db.DB, intfSt *ocbinds.OpenconfigAcl_Acl_Interfaces) error {
	trustIntf := false
	// At this stage we can assume that the Interfaces is already present. If the Get is done at
	// Root level, the caller of this should have populated this
	if nil == intfSt.Interface || (nil != intfSt.Interface && len(intfSt.Interface) == 0) {
		log.Info("Get request for all interfaces")
		// Check and create cache
		app.getAllAclTablesFromDB(dbs[db.ConfigDB])

		var interfaces []string
		for aclName := range app.aclTableMap {
			aclData := app.aclTableMap[aclName]
			if len(aclData.GetList(ACL_FIELD_PORTS)) > 0 {
				aclIntfs := aclData.GetList(ACL_FIELD_PORTS)
				if len(aclIntfs) > 0 {
					interfaces = uniquePorts(append(interfaces, aclIntfs...))
				}
			}
		}

		// No interface bindings present. Return. This is general Query ie No interface specified
		// by the user. We should return no error
		if len(interfaces) == 0 {
			return nil
		}

		trustIntf = true
		// For each binding present, create Ygot tree to process next level.
		ygot.BuildEmptyTree(intfSt)
		for _, intfId := range interfaces {
			if intfId == ACL_GLOBAL_PORT || intfId == ACL_CTRL_PLANE_PORT {
				continue
			}
			ptr, _ := intfSt.NewInterface(*utils.GetUINameFromNativeName(&intfId))
			ygot.BuildEmptyTree(ptr)
		}
	} else {
		log.Info("Get request for specific interface")
	}

	// For each interface present, Process it. The interface present could be created as part of
	// of the URI or created above
	for ifName, ocIntfPtr := range intfSt.Interface {
		if !trustIntf {
			// TODO. Check if the Interface is created.
			if *app.ygotTarget == ocIntfPtr {
				ygot.BuildEmptyTree(ocIntfPtr)
			}
		}

		log.Infof("Processing get request for %s", *ocIntfPtr.Id)
		// When the Target is Interface{}/xxgressAclSets No need to full Interface related structs
		if nil != ocIntfPtr.Config {
			ocIntfPtr.Config.Id = ocIntfPtr.Id
		}
		if nil != ocIntfPtr.State {
			ocIntfPtr.State.Id = ocIntfPtr.Id
		}
		if nil != ocIntfPtr.InterfaceRef {
			if nil == ocIntfPtr.InterfaceRef.Config {
				ygot.BuildEmptyTree(ocIntfPtr.InterfaceRef)
			}
			ocIntfPtr.InterfaceRef.Config.Interface = ocIntfPtr.Id
			ocIntfPtr.InterfaceRef.State.Interface = ocIntfPtr.Id
		}

		nativeName := *utils.GetNativeNameFromUIName(&ifName)
		inFound, err := app.getOCIntfSubtreeIntfDataForStage(dbs, nativeName, "Ingress", ocIntfPtr)
		if err != nil {
			return err
		}

		outFound, err := app.getOCIntfSubtreeIntfDataForStage(dbs, nativeName, "Egress", ocIntfPtr)
		if err != nil {
			return err
		}

		// Return error if no bindings found. This condition should be hit only when a specific query was made
		// For all higher queries, this API will be called only when there is data present
		if !inFound && !outFound {
			log.Infof("Requested ACL binding not found for %s", *ocIntfPtr.Id)
			return tlerr.NotFound("Requested ACL binding not found for %s", *ocIntfPtr.Id)
		}
	}

	return nil
}

func (app *AclApp) getOCIntfSubtreeIntfDataForStage(dbs [db.MaxDB]*db.DB, intfId string, stage string,
	ocIntfPtr interface{}) (bool, error) {

	trustAcls := false
	found := false
	intfValPtr := reflect.ValueOf(ocIntfPtr)
	intfValElem := intfValPtr.Elem()

	aclSets := intfValElem.FieldByName(stage + "AclSets")
	if !aclSets.IsNil() {
		aclSet := aclSets.Elem().FieldByName(stage + "AclSet")
		if aclSet.IsNil() || (!aclSet.IsNil() && aclSet.Len() == 0) {
			log.Infof("Get all %s ACLs for %s", stage, intfId)

			// Check if any ACL is applied
			app.getAllAclTablesFromDB(dbs[db.ConfigDB])

			bindInfo := getAclNamesBoundToInterface(app.aclTableMap, intfId, strings.ToUpper(stage))
			for aclType, aclName := range bindInfo {
				trustAcls = true
				log.Infof("Port:%s ACLName:%s ACLType:%s %s", intfId, aclName, aclType, stage)
				aclOrigName, aclOrigType := convertInternalAclnameTypeToOC(aclName, aclType)
				aclSet := aclSets.MethodByName("New" + stage + "AclSet").Call([]reflect.Value{reflect.ValueOf(aclOrigName), reflect.ValueOf(aclOrigType)})
				ygot.BuildEmptyTree(aclSet[0].Interface().(ygot.ValidatedGoStruct))
				found = true
			}
		} else {
			log.Info("Get for specific ACL")
		}
	}

	if aclSets.IsNil() {
		return false, nil
	}

	aclSetMap := aclSets.Elem().FieldByName(stage + "AclSet")
	aclSetMapIter := aclSetMap.MapRange()
	for aclSetMapIter.Next() {
		found = true
		aclSetKey := aclSetMapIter.Key()
		aclSetPtr := aclSetMapIter.Value()

		if !trustAcls {
			if reflect.TypeOf(*app.ygotTarget) == aclSetPtr.Type() {
				ygot.BuildEmptyTree(aclSetPtr.Interface().(ygot.ValidatedGoStruct))
			}
		}

		aclSetName := aclSetKey.FieldByName("SetName")
		aclSetType := aclSetKey.FieldByName("Type")
		err := app.getOCIntfAclSetData(dbs, intfId, strings.ToUpper(stage), aclSetName.String(),
			aclSetType.Interface().(ocbinds.E_OpenconfigAcl_ACL_TYPE), aclSetPtr)
		if err != nil {
			return true, err
		}
	}

	return found, nil
}

func (app *AclApp) getOCIntfAclSetData(dbs [db.MaxDB]*db.DB, intfId string, stage string, aclName string,
	aclType ocbinds.E_OpenconfigAcl_ACL_TYPE, aclSet reflect.Value) error {

	log.Infof("ACL:%s Type:%v Intf:%s Stage:%s", aclName, aclType, intfId, stage)

	// The Names will be in Openconfig format. The name could be internally filled or filled from request.
	// Validate and return error always.
	aclDbName := app.getAclKeyByCheckingDbForNameWithoutType(dbs[db.ConfigDB], aclName, aclType)

	var aclData db.Value
	if len(app.aclTableMap) > 0 {
		var found bool
		aclData, found = app.aclTableMap[aclDbName]
		if !found {
			log.Infof("ACL:%s Type:%v not found", aclDbName, aclType)
			return tlerr.NotFound("ACL:%s:%v not found", aclName, aclType)
		}
	} else {
		var err error
		aclData, err = dbs[db.ConfigDB].GetEntry(app.aclTs, db.Key{Comp: []string{aclDbName}})
		if err != nil {
			return err
		}
		app.aclTableMap[aclDbName] = aclData
	}

	aclDbStage := ACL_STAGE_INGRESS
	if aclData.Has(ACL_FIELD_STAGE) {
		aclDbStage = aclData.Get(ACL_FIELD_STAGE)
	}

	if aclDbStage != stage {
		log.Infof("ACL:%s Stage:%s Required %s", aclDbName, aclDbStage, stage)
		return tlerr.NotFound("requested binding not found for %s and %s at %s", aclName, intfId, stage)
	}
	if !contains(aclData.GetList(ACL_FIELD_PORTS), intfId) {
		log.Infof("ACL:%s Stage:%s not bound to %s", aclDbName, aclDbStage, intfId)
		return tlerr.NotFound("requested binding not found for %s and %s at %s", aclName, intfId, stage)
	}

	aclSetCfg := aclSet.Elem().FieldByName("Config")
	if !aclSetCfg.IsNil() {
		aclSetCfg.Elem().FieldByName("SetName").Set(aclSet.Elem().FieldByName("SetName"))
		aclSetCfg.Elem().FieldByName("Type").Set(aclSet.Elem().FieldByName("Type"))
	}

	aclSetState := aclSet.Elem().FieldByName("State")
	if !aclSetState.IsNil() {
		aclSetState.Elem().FieldByName("SetName").Set(aclSet.Elem().FieldByName("SetName"))
		aclSetState.Elem().FieldByName("Type").Set(aclSet.Elem().FieldByName("Type"))
	}

	// At this stage we have verified that the ACL binding exists. Starts filling the actual data
	// Check if the data was requested for a specific Entry else find all the rules
	aclEntries := aclSet.Elem().FieldByName("AclEntries")
	if aclEntries.IsNil() {
		log.Info("ACL Entries not requested")
		return nil
	}

	var trustEntry = false
	aclEntry := aclEntries.Elem().FieldByName("AclEntry")
	if aclEntry.IsNil() || aclEntry.Len() == 0 {
		log.Infof("Get all entries for ACLs %s Intf %s Stage %s", aclName, intfId, stage)

		// We only need sequence number under interface subtree. No need to pull the rule content
		if _, ok := app.ruleTableMap[aclDbName]; !ok {
			log.Infof("Get rules for ACL %s", aclDbName)
			ruleKeys, _ := dbs[db.ConfigDB].GetKeysPattern(app.ruleTs, db.Key{Comp: []string{aclDbName, "*"}})
			for i := range ruleKeys {
				trustEntry = true
				seqId, _ := strconv.ParseUint(strings.Replace(ruleKeys[i].Get(1), "RULE_", "", 1), 10, 16)
				seqId32 := uint32(seqId)
				entry := aclEntries.MethodByName("NewAclEntry").Call([]reflect.Value{reflect.ValueOf(seqId32)})
				ygot.BuildEmptyTree(entry[0].Interface().(ygot.ValidatedGoStruct))
			}
		} else {
			log.Infof("Using rules from the DB")
			for ruleName := range app.ruleTableMap[aclDbName] {
				trustEntry = true
				seqId, _ := strconv.ParseUint(strings.Replace(ruleName, "RULE_", "", 1), 10, 16)
				seqId32 := uint32(seqId)
				entry := aclEntries.MethodByName("NewAclEntry").Call([]reflect.Value{reflect.ValueOf(seqId32)})
				ygot.BuildEmptyTree(entry[0].Interface().(ygot.ValidatedGoStruct))
			}
		}
	}

	//aclEntry is a reflected value of Map
	aclEntry = aclEntries.Elem().FieldByName("AclEntry")
	aclEntryIter := aclEntry.MapRange()
	for aclEntryIter.Next() {
		aclEntryKey := aclEntryIter.Key()
		aclEntryPtr := aclEntryIter.Value()

		if !trustEntry {
			if reflect.TypeOf(*app.ygotTarget) == aclEntryPtr.Type() {
				ygot.BuildEmptyTree(aclEntryPtr.Interface().(ygot.ValidatedGoStruct))
			}
		}

		// The Rule cant be trusted but we dont have to validate it with ConfigDB. CounterDB can
		// be used for the same at the same time we can get the counter values also
		ruleName := "RULE_" + strconv.Itoa(int(aclEntryKey.Uint()))
		err := app.getOCIntfAclSetAclEntryData(dbs, uint16(aclEntryKey.Uint()), aclDbName, ruleName, intfId,
			stage, aclEntryPtr)
		if nil != err {
			return err
		}
	}

	return nil
}

func (app *AclApp) getOCIntfAclSetAclEntryData(dbs [db.MaxDB]*db.DB,
	seqId uint16,
	aclKey string,
	rulekey string,
	intfId string,
	direction string,
	entrySet reflect.Value) error {

	var packets uint64 = 0
	var bytes uint64 = 0

	entrySetState := entrySet.Elem().FieldByName("State")
	if entrySetState.IsNil() {
		_, err := dbs[db.ConfigDB].GetEntry(app.ruleTs, db.Key{Comp: []string{aclKey, rulekey}})
		if nil != err {
			return err
		}
	} else {
		if app.getAclCounterMode(dbs) == ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_INTERFACE_ONLY {
			cntKey := db.Key{Comp: []string{aclKey, rulekey, intfId, direction}}
			data, err := dbs[db.CountersDB].GetEntry(app.counterTs, cntKey)
			if nil != err {
				return err
			}

			lastCtrKey := db.Key{Comp: []string{aclKey, rulekey, intfId, direction}}
			lastData, err := dbs[db.CountersDB].GetEntry(app.lastCounterTs, lastCtrKey)
			if nil == err {
				lastPkts, _ := strconv.ParseUint(lastData.Field["Packets"], 10, 64)
				packets, _ = strconv.ParseUint(data.Field["Packets"], 10, 64)
				log.Infof("Key:%v Packets Last:%v Current:%v", cntKey, lastPkts, packets)
				packets = packets - lastPkts
				lastBytes, _ := strconv.ParseUint(lastData.Field["Bytes"], 10, 64)
				bytes, _ = strconv.ParseUint(data.Field["Bytes"], 10, 64)
				log.Infof("Key:%v Bytes Last:%v Current:%v", cntKey, lastBytes, bytes)
				bytes = bytes - lastBytes
			}
		}
	}

	entrySetState.Elem().FieldByName("SequenceId").Set(entrySet.Elem().FieldByName("SequenceId"))
	entrySetState.Elem().FieldByName("MatchedPackets").Set(reflect.ValueOf(&packets))
	entrySetState.Elem().FieldByName("MatchedOctets").Set(reflect.ValueOf(&bytes))

	return nil
}

func (app *AclApp) getAclBindingInfoForControlPlane(dbs [db.MaxDB]*db.DB) error {
	acl := app.getAppRootObject()

	log.Info("Get binding data for Control Plane ACLs")
	if (acl.ControlPlane.IngressAclSets == nil) || (acl.ControlPlane.IngressAclSets != nil && len(acl.ControlPlane.IngressAclSets.IngressAclSet) == 0) {
		log.Info("Get All Control Plane ACLs")
		err := app.getAllAclTablesFromDB(dbs[db.ConfigDB])
		if err != nil {
			return err
		}

		if acl.ControlPlane.IngressAclSets == nil {
			ygot.BuildEmptyTree(acl.ControlPlane)
		}

		bindInfo := getAclNamesBoundToInterface(app.aclTableMap, ACL_CTRL_PLANE_PORT, ACL_STAGE_INGRESS)
		if len(bindInfo) == 0 {
			return nil
		}

		for aclType, aclName := range bindInfo {
			log.Infof("CtrlPlane ACLName:%s ACLType:%s", aclName, aclType)
			aclOrigName, aclOrigType := convertInternalAclnameTypeToOC(aclName, aclType)
			ingressAclSet, err := acl.ControlPlane.IngressAclSets.NewIngressAclSet(aclOrigName, aclOrigType)
			if err != nil {
				log.Error(err)
				return err
			}
			ygot.BuildEmptyTree(ingressAclSet)
			ingressAclSet.Config.SetName = &aclOrigName
			ingressAclSet.State.SetName = &aclOrigName
			ingressAclSet.Config.Type = aclOrigType
			ingressAclSet.State.Type = aclOrigType
		}
	} else {
		for ingressAclSetKey := range acl.ControlPlane.IngressAclSets.IngressAclSet {
			if strings.Contains(ingressAclSetKey.SetName, " ") {
				return tlerr.InvalidArgs("ACL name should not have any spaces. Requested %s", ingressAclSetKey.SetName)
			}
			aclName := ingressAclSetKey.SetName
			aclKey := app.getAclKeyByCheckingDbForNameWithoutType(dbs[db.ConfigDB], aclName, ingressAclSetKey.Type)
			aclData, _ := dbs[db.ConfigDB].GetEntry(app.aclTs, db.Key{Comp: []string{aclKey}})
			if aclData.Has(ACL_FIELD_STAGE) && aclData.Get(ACL_FIELD_STAGE) == ACL_STAGE_EGRESS {
				log.Infof("ACL:%s Stage:%s Required %s", aclName, aclData.Get(ACL_FIELD_STAGE), ACL_STAGE_INGRESS)
				return tlerr.NotFound("requested binding not found for %s", ingressAclSetKey.SetName)
			}
			if !contains(aclData.GetList(ACL_FIELD_PORTS), ACL_CTRL_PLANE_PORT) {
				log.Infof("ACL:%s Stage:%s not bound to %s", aclName, aclData.Get(ACL_FIELD_STAGE), ACL_CTRL_PLANE_PORT)
				return tlerr.NotFound("requested binding not found for %s and %s at %s", ingressAclSetKey.SetName, ACL_CTRL_PLANE_PORT, ACL_STAGE_INGRESS)
			}

			ingressAclSet := acl.ControlPlane.IngressAclSets.IngressAclSet[ingressAclSetKey]
			ygot.BuildEmptyTree(ingressAclSet)
			ingressAclSet.Config.SetName = &ingressAclSetKey.SetName
			ingressAclSet.State.SetName = &ingressAclSetKey.SetName
			ingressAclSet.Config.Type = ingressAclSetKey.Type
			ingressAclSet.State.Type = ingressAclSetKey.Type
		}
	}

	return nil
}

func (app *AclApp) getAclBindingInfoForSwitch(dbs [db.MaxDB]*db.DB) error {
	acl := app.getAppRootObject()

	log.Info("Get binding data for Global ACLs")
	if nil == acl.Global {
		log.Info("Get All Global ACL")
		ygot.BuildEmptyTree(acl.Global)
	}

	inFound, err := app.getOCIntfSubtreeIntfDataForStage(dbs, "Switch", "Ingress", acl.Global)
	if err != nil {
		return err
	}

	outFound, err := app.getOCIntfSubtreeIntfDataForStage(dbs, "Switch", "Egress", acl.Global)
	if err != nil {
		return err
	}

	// Return error if no bindings found. This condition should be hit only when a specific query was made
	// For all higher queries, this API will be called only when there is data present
	if !inFound && !outFound {
		if *app.ygotTarget == acl || (acl != nil && *app.ygotTarget == acl.Global) {
			// Generic Get request at top level. Return success if no data found.
			// For specific queries only return error.
			return nil
		}

		log.Info("Requested ACL binding not found for Switch")
		return tlerr.NotFound("Requested ACL binding not found for Switch")
	}

	return nil
}

func (app *AclApp) findAndDeleteAclBindings(d *db.DB, intfIn string, stage string, aclname string,
	acltype ocbinds.E_OpenconfigAcl_ACL_TYPE) error {

	intf := *utils.GetNativeNameFromUIName(&intfIn)
	log.Infof("Delete ACL bindings ACL:%s Stage:%s Type:%v Intf:%v", aclname, stage, acltype, intf)

	aclKeys, _ := d.GetKeys(app.aclTs)
	for i := range aclKeys {
		aclEntry, _ := d.GetEntry(app.aclTs, aclKeys[i])
		dbaclname, dbacltype := convertInternalAclnameTypeToOC(aclKeys[i].Get(0), aclEntry.Get(ACL_FIELD_TYPE))

		if aclname != "" && aclname != dbaclname {
			log.Infof("Skipping ACL %s. Name mismatch %v:%v", aclKeys[i].Get(0), aclname, dbaclname)
			continue
		}

		if acltype != ocbinds.OpenconfigAcl_ACL_TYPE_UNSET && acltype != dbacltype {
			log.Infof("Skipping ACL %s Type %v. Type mismatch", dbaclname, acltype)
			continue
		}

		ports := aclEntry.GetList(ACL_FIELD_PORTS)
		if len(ports) > 0 {
			if intf != "" {
				remove := false
				if contains(ports, intf) {
					if stage != "" {
						if strings.EqualFold(aclEntry.Get(ACL_FIELD_STAGE), stage) {
							remove = true
						} else {
							log.Infof("Skipping ACL %s. Stage mismatch", aclKeys[i].Get(0))
						}
					} else {
						remove = true
					}

					if remove {
						ports = removeElement(ports, intf)
						aclEntry.SetList(ACL_FIELD_PORTS, ports)
						if len(ports) == 0 {
							aclEntry.Remove(ACL_FIELD_STAGE)
						}
						err := d.SetEntry(app.aclTs, aclKeys[i], aclEntry)
						if err != nil {
							return err
						}

						if aclname != "" && acltype != ocbinds.OpenconfigAcl_ACL_TYPE_UNSET && stage != "" && intf != "" {
							break
						}
					}
				} else {
					log.Infof("Skipping ACL %s. Not bound to required port", aclKeys[i].Get(0))
				}
			} else {
				aclEntry.Remove(ACL_FIELD_STAGE)
				aclEntry.SetList(ACL_FIELD_PORTS, []string{})
				err := d.SetEntry(app.aclTs, aclKeys[i], aclEntry)
				if err != nil {
					return err
				}
			}
		} else {
			log.Infof("Skipping ACL %s. No ports", aclKeys[i].Get(0))
		}
	}

	return nil
}

func (app *AclApp) handleBindingsDeletion(d *db.DB) error {
	intf := ""
	stage := ""
	aclname := ""
	var acltype ocbinds.E_OpenconfigAcl_ACL_TYPE = ocbinds.OpenconfigAcl_ACL_TYPE_UNSET

	acl := app.getAppRootObject()
	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/interfaces/interface{}") {
		for intf = range acl.Interfaces.Interface {
			if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/interfaces/interface{}/ingress-acl-sets") {
				stage = ACL_STAGE_INGRESS
				if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/interfaces/interface{}/ingress-acl-sets/ingress-acl-set{}{}") {
					for aclReq := range acl.Interfaces.Interface[intf].IngressAclSets.IngressAclSet {
						aclname = aclReq.SetName
						acltype = aclReq.Type
						err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
						if err != nil {
							return err
						}
					}
				} else {
					err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
					if err != nil {
						return err
					}
				}
			} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/interfaces/interface{}/egress-acl-sets") {
				stage = ACL_STAGE_EGRESS
				if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/interfaces/interface{}/egress-acl-sets/egress-acl-set{}{}") {
					for aclReq := range acl.Interfaces.Interface[intf].EgressAclSets.EgressAclSet {
						aclname = aclReq.SetName
						acltype = aclReq.Type
						err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
						if err != nil {
							return err
						}
					}
				} else {
					err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
					if err != nil {
						return err
					}
				}
			} else {
				err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
				if err != nil {
					return err
				}
			}
		}
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:global") {
		intf = ACL_GLOBAL_PORT
		if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:global/ingress-acl-sets") {
			stage = ACL_STAGE_INGRESS
			if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:global/ingress-acl-sets/ingress-acl-set{}{}") {
				for aclReq := range acl.Global.IngressAclSets.IngressAclSet {
					aclname = aclReq.SetName
					acltype = aclReq.Type
					err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
					if err != nil {
						return err
					}
				}
			} else {
				err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
				if err != nil {
					return err
				}
			}
		} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:global/egress-acl-sets") {
			stage = ACL_STAGE_EGRESS
			if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:global/egress-acl-sets/egress-acl-set{}{}") {
				for aclReq := range acl.Global.EgressAclSets.EgressAclSet {
					aclname = aclReq.SetName
					acltype = aclReq.Type
					err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
					if err != nil {
						return err
					}
				}
			} else {
				err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
				if err != nil {
					return err
				}
			}
		}
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:control-plane") {
		intf = ACL_CTRL_PLANE_PORT
		if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:control-plane/ingress-acl-sets") {
			stage = ACL_STAGE_INGRESS
			if isSubtreeRequest(app.pathInfo.Template, "/openconfig-acl:acl/openconfig-acl-ext:control-plane/ingress-acl-sets/ingress-acl-set{}{}") {
				for aclReq := range acl.ControlPlane.IngressAclSets.IngressAclSet {
					aclname = aclReq.SetName
					acltype = aclReq.Type
					err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
					if err != nil {
						return err
					}
				}
			} else {
				err := app.findAndDeleteAclBindings(d, intf, stage, aclname, acltype)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

/********************   CREATE related    *******************************/
func (app *AclApp) convertOCCountermodeToInternal() {
	acl := app.getAppRootObject()
	if acl != nil {
		app.hardwareAclTableMap = make(map[string]db.Value)
		if acl.Config != nil {
			app.hardwareAclTableMap["ACCESS_LIST"] = db.Value{Field: map[string]string{}}
			if acl.Config.CounterCapability == ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_UNSET {
				app.hardwareAclTableMap["ACCESS_LIST"].Field["COUNTER_MODE"] = "per-rule"
			} else if acl.Config.CounterCapability == ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_AGGREGATE_ONLY {
				app.hardwareAclTableMap["ACCESS_LIST"].Field["COUNTER_MODE"] = "per-rule"
			} else if acl.Config.CounterCapability == ocbinds.OpenconfigAcl_ACL_COUNTER_CAPABILITY_INTERFACE_ONLY {
				app.hardwareAclTableMap["ACCESS_LIST"].Field["COUNTER_MODE"] = "per-interface-rule"
			} else {
				log.Error("Unknown/Unsupported counter mode requested")
			}
		}
	}
}

func convertOCAclTypeToInternal(aclType ocbinds.E_OpenconfigAcl_ACL_TYPE) string {
	var ret string = ""

	if aclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4 {
		ret = SONIC_ACL_TYPE_IPV4
	} else if aclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV6 {
		ret = SONIC_ACL_TYPE_IPV6
	} else if aclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2 {
		ret = SONIC_ACL_TYPE_L2
	} else {
		log.Errorf("Unknown type %v", aclType)
	}

	return ret
}

func (app *AclApp) convertOCAclsToInternal() {
	acl := app.getAppRootObject()
	if acl != nil {
		app.aclTableMap = make(map[string]db.Value)
		if acl.AclSets != nil && len(acl.AclSets.AclSet) > 0 {
			for aclSetKey := range acl.AclSets.AclSet {
				aclSet := acl.AclSets.AclSet[aclSetKey]
				aclKey := convertOCAclnameTypeToInternal(aclSetKey.Name, aclSetKey.Type)
				app.aclTableMap[aclKey] = db.Value{Field: map[string]string{}}

				if aclSet.Config != nil {
					app.aclTableMap[aclKey].Field[ACL_FIELD_TYPE] = convertOCAclTypeToInternal(aclSetKey.Type)

					if aclSet.Config.Description != nil {
						app.aclTableMap[aclKey].Field[ACL_DESCRIPTION] = *aclSet.Config.Description
					}
				}
			}
		}
	}
}

func (app *AclApp) convertOCAclRulesToInternal() error {
	acl := app.getAppRootObject()
	if acl != nil {
		app.ruleTableMap = make(map[string]map[string]db.Value)
		if acl.AclSets != nil && len(acl.AclSets.AclSet) > 0 {
			for aclSetKey := range acl.AclSets.AclSet {
				aclSet := acl.AclSets.AclSet[aclSetKey]
				aclKey := convertOCAclnameTypeToInternal(aclSetKey.Name, aclSetKey.Type)
				app.ruleTableMap[aclKey] = make(map[string]db.Value)

				if aclSet.AclEntries != nil {
					for seqId := range aclSet.AclEntries.AclEntry {
						entrySet := aclSet.AclEntries.AclEntry[seqId]
						ruleName := "RULE_" + strconv.Itoa(int(seqId))
						app.ruleTableMap[aclKey][ruleName] = db.Value{Field: map[string]string{}}
						err := convertOCAclRuleToInternalAclRule(app.ruleTableMap[aclKey][ruleName], seqId, aclKey, aclSet.Type, entrySet)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	return nil
}

func (app *AclApp) convertOCAclInterfaceBindingsToInternal() error {
	aclObj := app.getAppRootObject()

	app.aclInterfacesMap = make(map[string][]string)
	if aclObj.Interfaces != nil && len(aclObj.Interfaces.Interface) > 0 {
		// Below code assumes that an ACL can be either INGRESS or EGRESS but not both.
		for intfId, intf := range aclObj.Interfaces.Interface {

			if nil == intf.InterfaceRef || nil == intf.InterfaceRef.Config ||
				nil == intf.InterfaceRef.Config.Interface {
				goto SkipIntfCheck
			}

			if intfId != *intf.InterfaceRef.Config.Interface {
				return tlerr.NotSupported("Different ID %s and Interface name %s not supported", intfId, *intf.InterfaceRef.Config.Interface)
			}

		SkipIntfCheck:

			if intf.IngressAclSets != nil && len(intf.IngressAclSets.IngressAclSet) > 0 {
				for inAclKey := range intf.IngressAclSets.IngressAclSet {
					aclName := convertOCAclnameTypeToInternal(inAclKey.SetName, inAclKey.Type)
					app.aclInterfacesMap[aclName] = append(app.aclInterfacesMap[aclName], *utils.GetNativeNameFromUIName(intf.Id))
					if len(app.aclTableMap) == 0 {
						app.aclTableMap[aclName] = db.Value{Field: map[string]string{}}
					}
					app.aclTableMap[aclName].Field[ACL_FIELD_STAGE] = ACL_STAGE_INGRESS
					app.aclTableMap[aclName].Field[ACL_FIELD_TYPE] = convertOCAclTypeToInternal(inAclKey.Type)
				}
			}

			if intf.EgressAclSets != nil && len(intf.EgressAclSets.EgressAclSet) > 0 {
				for outAclKey := range intf.EgressAclSets.EgressAclSet {
					aclName := convertOCAclnameTypeToInternal(outAclKey.SetName, outAclKey.Type)
					app.aclInterfacesMap[aclName] = append(app.aclInterfacesMap[aclName], *utils.GetNativeNameFromUIName(intf.Id))
					if len(app.aclTableMap) == 0 {
						app.aclTableMap[aclName] = db.Value{Field: map[string]string{}}
					}
					app.aclTableMap[aclName].Field[ACL_FIELD_STAGE] = ACL_STAGE_EGRESS
					app.aclTableMap[aclName].Field[ACL_FIELD_TYPE] = convertOCAclTypeToInternal(outAclKey.Type)
				}
			}
		}
	}

	return nil
}

func (app *AclApp) convertOCAclGlobalBindingsToInternal() {
	aclObj := app.getAppRootObject()

	// NOTE:: Below code assumes that an ACL can be either INGRESS or EGRESS but not both.
	if aclObj.Global != nil {
		if aclObj.Global.IngressAclSets != nil && len(aclObj.Global.IngressAclSets.IngressAclSet) > 0 {
			for inAclKey := range aclObj.Global.IngressAclSets.IngressAclSet {
				aclName := convertOCAclnameTypeToInternal(inAclKey.SetName, inAclKey.Type)
				app.aclInterfacesMap[aclName] = append(app.aclInterfacesMap[aclName], ACL_GLOBAL_PORT)
				if len(app.aclTableMap) == 0 {
					app.aclTableMap[aclName] = db.Value{Field: map[string]string{}}
				}
				app.aclTableMap[aclName].Field[ACL_FIELD_STAGE] = ACL_STAGE_INGRESS
				app.aclTableMap[aclName].Field[ACL_FIELD_TYPE] = convertOCAclTypeToInternal(inAclKey.Type)
				log.Infof("ACL:%v Globally apply at Ingress", aclName)
			}
		}
		if aclObj.Global.EgressAclSets != nil && len(aclObj.Global.EgressAclSets.EgressAclSet) > 0 {
			for outAclKey := range aclObj.Global.EgressAclSets.EgressAclSet {
				aclName := convertOCAclnameTypeToInternal(outAclKey.SetName, outAclKey.Type)
				app.aclInterfacesMap[aclName] = append(app.aclInterfacesMap[aclName], ACL_GLOBAL_PORT)
				if len(app.aclTableMap) == 0 {
					app.aclTableMap[aclName] = db.Value{Field: map[string]string{}}
				}
				app.aclTableMap[aclName].Field[ACL_FIELD_STAGE] = ACL_STAGE_EGRESS
				app.aclTableMap[aclName].Field[ACL_FIELD_TYPE] = convertOCAclTypeToInternal(outAclKey.Type)
				log.Infof("ACL:%v Globally apply at Egress", aclName)
			}
		}
	}
}

func (app *AclApp) convertOCAclControlPlaneBindingsToInternal() {
	aclObj := app.getAppRootObject()

	if aclObj.ControlPlane != nil && aclObj.ControlPlane.IngressAclSets != nil && len(aclObj.ControlPlane.IngressAclSets.IngressAclSet) > 0 {
		for inAclKey := range aclObj.ControlPlane.IngressAclSets.IngressAclSet {
			aclName := convertOCAclnameTypeToInternal(inAclKey.SetName, inAclKey.Type)
			app.aclInterfacesMap[aclName] = append(app.aclInterfacesMap[aclName], ACL_CTRL_PLANE_PORT)
			if len(app.aclTableMap) == 0 {
				app.aclTableMap[aclName] = db.Value{Field: map[string]string{}}
			}
			app.aclTableMap[aclName].Field[ACL_FIELD_STAGE] = ACL_STAGE_INGRESS
			app.aclTableMap[aclName].Field[ACL_FIELD_TYPE] = convertOCAclTypeToInternal(inAclKey.Type)
			log.Infof("ACL:%v CtrlPlane apply at Ingress", aclName)
		}
	}
}

func convertOCAclRuleToInternalAclRule(ruleData db.Value, seqId uint32, aclName string, aclType ocbinds.E_OpenconfigAcl_ACL_TYPE, rule *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) error {
	ruleIndex := seqId
	ruleData.Field["PRIORITY"] = strconv.FormatInt(int64(MAX_PRIORITY-ruleIndex), 10)
	if rule.Config != nil && rule.Config.Description != nil {
		ruleData.Field[ACL_RULE_FIELD_DESCRIPTION] = *rule.Config.Description
	}

	convertOCToInternalIPv4(ruleData, aclName, ruleIndex, rule)
	convertOCToInternalIPv6(ruleData, aclName, ruleIndex, rule)
	convertOCToInternalL2(ruleData, aclName, ruleIndex, rule)
	convertOCToInternalTransport(ruleData, aclName, aclType, ruleIndex, rule)
	err := convertOCToInternalInputAction(ruleData, aclName, ruleIndex, rule)

	return err
}

func convertOCToInternalL2(ruleData db.Value, aclName string, ruleIndex uint32, rule *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) {
	if rule.L2 == nil {
		return
	}

	if rule.L2.Config.Ethertype != nil && util.IsTypeStructPtr(reflect.TypeOf(rule.L2.Config.Ethertype)) {
		ethertypeType := reflect.TypeOf(rule.L2.Config.Ethertype).Elem()
		var b bytes.Buffer
		switch ethertypeType {
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE{}):
			v := (rule.L2.Config.Ethertype).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE)
			//ruleData[ACL_RULE_FIELD_ETHER_TYPE] = v.E_OpenconfigPacketMatchTypes_ETHERTYPE.ΛMap()["E_OpenconfigPacketMatchTypes_ETHERTYPE"][int64(v.E_OpenconfigPacketMatchTypes_ETHERTYPE)].Name
			fmt.Fprintf(&b, "0x%x", ETHERTYPE_MAP[v.E_OpenconfigPacketMatchTypes_ETHERTYPE])
			ruleData.Field[ACL_RULE_FIELD_ETHER_TYPE] = b.String()
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2_Config_Ethertype_Union_Uint16{}):
			v := (rule.L2.Config.Ethertype).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2_Config_Ethertype_Union_Uint16)
			fmt.Fprintf(&b, "0x%x", v.Uint16)
			ruleData.Field[ACL_RULE_FIELD_ETHER_TYPE] = b.String()
		}
	}

	if rule.L2.Config.SourceMac != nil && rule.L2.Config.SourceMacMask != nil {
		ruleData.Field[ACL_RULE_FIELD_SRC_MAC] = *rule.L2.Config.SourceMac + "/" + *rule.L2.Config.SourceMacMask
	} else if rule.L2.Config.SourceMac != nil {
		ruleData.Field[ACL_RULE_FIELD_SRC_MAC] = *rule.L2.Config.SourceMac
	}

	if rule.L2.Config.DestinationMac != nil && rule.L2.Config.DestinationMacMask != nil {
		ruleData.Field[ACL_RULE_FIELD_DST_MAC] = *rule.L2.Config.DestinationMac + "/" + *rule.L2.Config.DestinationMacMask
	} else if rule.L2.Config.DestinationMac != nil {
		ruleData.Field[ACL_RULE_FIELD_DST_MAC] = *rule.L2.Config.DestinationMac
	}

	if rule.L2.Config.Pcp != nil && rule.L2.Config.PcpMask != nil {
		ruleData.Field[ACL_RULE_FIELD_PCP] = strconv.FormatUint(uint64(*rule.L2.Config.Pcp), 10) + "/" + strconv.FormatUint(uint64(*rule.L2.Config.PcpMask), 10)
	} else if rule.L2.Config.Pcp != nil {
		ruleData.Field[ACL_RULE_FIELD_PCP] = strconv.FormatUint(uint64(*rule.L2.Config.Pcp), 10)
	}

	if rule.L2.Config.Dei != nil {
		ruleData.Field[ACL_RULE_FIELD_DEI] = strconv.FormatUint(uint64(*rule.L2.Config.Dei), 10)
	}

	if rule.L2.Config.Vlanid != nil {
		ruleData.Field[ACL_RULE_FIELD_VLANID] = strconv.FormatUint(uint64(*rule.L2.Config.Vlanid), 10)
	}
}

func convertOCToInternalIPv4(ruleData db.Value, aclName string, ruleIndex uint32, rule *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) {
	if rule.Ipv4 == nil {
		return
	}

	if rule.Ipv4.Config.Protocol != nil && util.IsTypeStructPtr(reflect.TypeOf(rule.Ipv4.Config.Protocol)) {
		protocolType := reflect.TypeOf(rule.Ipv4.Config.Protocol).Elem()
		switch protocolType {
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
			v := (rule.Ipv4.Config.Protocol).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
			//ruleData[ACL_RULE_FIELD_IP_PROTOCOL] = v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL.ΛMap()["E_OpenconfigPacketMatchTypes_IP_PROTOCOL"][int64(v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL)].Name
			ruleData.Field[ACL_RULE_FIELD_IP_PROTOCOL] = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4_Config_Protocol_Union_Uint8{}):
			v := (rule.Ipv4.Config.Protocol).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4_Config_Protocol_Union_Uint8)
			ruleData.Field[ACL_RULE_FIELD_IP_PROTOCOL] = strconv.FormatInt(int64(v.Uint8), 10)
		}
	}

	if rule.Ipv4.Config.Dscp != nil {
		ruleData.Field[ACL_RULE_FIELD_DSCP] = strconv.FormatInt(int64(*rule.Ipv4.Config.Dscp), 10)
	}
	if rule.Ipv4.Config.SourceAddress != nil {
		ruleData.Field[ACL_RULE_FIELD_SRC_IP] = *rule.Ipv4.Config.SourceAddress
	}
	if rule.Ipv4.Config.DestinationAddress != nil {
		ruleData.Field[ACL_RULE_FIELD_DST_IP] = *rule.Ipv4.Config.DestinationAddress
	}
}

func convertOCToInternalIPv6(ruleData db.Value, aclName string, ruleIndex uint32, rule *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) {
	if rule.Ipv6 == nil {
		return
	}

	if rule.Ipv6.Config.Protocol != nil && util.IsTypeStructPtr(reflect.TypeOf(rule.Ipv6.Config.Protocol)) {
		protocolType := reflect.TypeOf(rule.Ipv6.Config.Protocol).Elem()
		switch protocolType {
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
			v := (rule.Ipv6.Config.Protocol).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
			//ruleData[ACL_RULE_FIELD_IP_PROTOCOL] = v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL.ΛMap()["E_OpenconfigPacketMatchTypes_IP_PROTOCOL"][int64(v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL)].Name
			ruleData.Field[ACL_RULE_FIELD_IP_PROTOCOL] = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6_Config_Protocol_Union_Uint8{}):
			v := (rule.Ipv6.Config.Protocol).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6_Config_Protocol_Union_Uint8)
			ruleData.Field[ACL_RULE_FIELD_IP_PROTOCOL] = strconv.FormatInt(int64(v.Uint8), 10)
		}
	}

	if rule.Ipv6.Config.Dscp != nil {
		ruleData.Field[ACL_RULE_FIELD_DSCP] = strconv.FormatInt(int64(*rule.Ipv6.Config.Dscp), 10)
	}
	if rule.Ipv6.Config.SourceAddress != nil {
		ruleData.Field[ACL_RULE_FIELD_SRC_IPV6] = *rule.Ipv6.Config.SourceAddress
	}
	if rule.Ipv6.Config.DestinationAddress != nil {
		ruleData.Field[ACL_RULE_FIELD_DST_IPV6] = *rule.Ipv6.Config.DestinationAddress
	}
}

func convertOCToInternalTransport(ruleData db.Value, aclName string, aclType ocbinds.E_OpenconfigAcl_ACL_TYPE, ruleIndex uint32, rule *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) {
	if rule.Transport == nil {
		return
	}

	if rule.Transport.Config.SourcePort != nil && util.IsTypeStructPtr(reflect.TypeOf(rule.Transport.Config.SourcePort)) {
		sourceportType := reflect.TypeOf(rule.Transport.Config.SourcePort).Elem()
		switch sourceportType {
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort{}):
			v := (rule.Transport.Config.SourcePort).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort)
			ruleData.Field[ACL_RULE_FIELD_L4_SRC_PORT] = v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort.ΛMap()["E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort"][int64(v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort)].Name
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_Union_String{}):
			v := (rule.Transport.Config.SourcePort).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_Union_String)
			ruleData.Field[ACL_RULE_FIELD_L4_SRC_PORT_RANGE] = strings.Replace(v.String, "..", "-", 1)
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_Union_Uint16{}):
			v := (rule.Transport.Config.SourcePort).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_Union_Uint16)
			ruleData.Field[ACL_RULE_FIELD_L4_SRC_PORT] = strconv.FormatInt(int64(v.Uint16), 10)
		}
	}

	if rule.Transport.Config.DestinationPort != nil && util.IsTypeStructPtr(reflect.TypeOf(rule.Transport.Config.DestinationPort)) {
		destportType := reflect.TypeOf(rule.Transport.Config.DestinationPort).Elem()
		switch destportType {
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort{}):
			v := (rule.Transport.Config.DestinationPort).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort)
			ruleData.Field[ACL_RULE_FIELD_L4_DST_PORT] = v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort.ΛMap()["E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort"][int64(v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort)].Name
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_Union_String{}):
			v := (rule.Transport.Config.DestinationPort).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_Union_String)
			ruleData.Field[ACL_RULE_FIELD_L4_DST_PORT_RANGE] = strings.Replace(v.String, "..", "-", 1)
		case reflect.TypeOf(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_Union_Uint16{}):
			v := (rule.Transport.Config.DestinationPort).(*ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_Union_Uint16)
			ruleData.Field[ACL_RULE_FIELD_L4_DST_PORT] = strconv.FormatInt(int64(v.Uint16), 10)
		}
	}

	if len(rule.Transport.Config.TcpFlags) > 0 {
		ruleData.Field[ACL_RULE_FIELD_TCP_FLAGS] = convertOCTcpFlagsToDbFormat(rule.Transport.Config.TcpFlags)
	}

	if rule.Transport.Config.IcmpType != nil {
		ruleData.Field[ACL_RULE_ICMP_TYPE] = strconv.FormatUint(uint64(*rule.Transport.Config.IcmpType), 10)
	}
	if rule.Transport.Config.IcmpCode != nil {
		ruleData.Field[ACL_RULE_ICMP_CODE] = strconv.FormatUint(uint64(*rule.Transport.Config.IcmpCode), 10)
	}
}

func convertOCToInternalInputAction(ruleData db.Value, aclName string, ruleIndex uint32, rule *ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry) error {
	if rule.Actions != nil && rule.Actions.Config != nil {
		switch rule.Actions.Config.ForwardingAction {
		case ocbinds.OpenconfigAcl_FORWARDING_ACTION_ACCEPT:
			ruleData.Field[ACL_RULE_PACKET_ACTION] = "FORWARD"
		case ocbinds.OpenconfigAcl_FORWARDING_ACTION_DROP:
			ruleData.Field[ACL_RULE_PACKET_ACTION] = "DROP"
		case ocbinds.OpenconfigAcl_FORWARDING_ACTION_DO_NOT_NAT:
			ruleData.Field[ACL_RULE_PACKET_ACTION] = "DO_NOT_NAT"
		default:
			return tlerr.NotSupported("input-interface not supported")
		}
	}

	return nil
}

func (app *AclApp) handleRuleFieldsDeletion(d *db.DB, aclKey string, ruleKey string) error {
	var err error

	ruleEntry, err := d.GetEntry(app.ruleTs, asKey(aclKey, ruleKey))
	if err != nil {
		return err
	}
	nodeInfo, err := getTargetNodeYangSchema(app.pathInfo.Path, (*app.ygotRoot).(*ocbinds.Device))
	if err != nil {
		return err
	}
	if nodeInfo.IsLeaf() {
		switch nodeInfo.Name {
		case "description":
			(&ruleEntry).Remove(ACL_RULE_FIELD_DESCRIPTION)
		// L2
		case "ethertype":
			(&ruleEntry).Remove(ACL_RULE_FIELD_ETHER_TYPE)
		case "source-mac":
			(&ruleEntry).Remove(ACL_RULE_FIELD_SRC_MAC)
		case "source-mac-mask":
			src_mac := ruleEntry.Get(ACL_RULE_FIELD_SRC_MAC)
			if src_mac != "" {
				parts := strings.Split(src_mac, "/")
				if len(parts) > 1 {
					ruleEntry.Set(ACL_RULE_FIELD_SRC_MAC, parts[0])
				}
			}
		case "destination-mac":
			(&ruleEntry).Remove(ACL_RULE_FIELD_DST_MAC)
		case "destination-mac-mask":
			dst_mac := ruleEntry.Get(ACL_RULE_FIELD_DST_MAC)
			if dst_mac != "" {
				parts := strings.Split(dst_mac, "/")
				if len(parts) > 1 {
					ruleEntry.Set(ACL_RULE_FIELD_DST_MAC, parts[0])
				}
			}
		case "pcp":
			(&ruleEntry).Remove(ACL_RULE_FIELD_PCP)
		case "pcp-mask":
			pcp_val := ruleEntry.Get(ACL_RULE_FIELD_PCP)
			if pcp_val != "" {
				parts := strings.Split(pcp_val, "/")
				if len(parts) > 1 {
					ruleEntry.Set(ACL_RULE_FIELD_PCP, parts[0])
				}
			}
		case "dei":
			(&ruleEntry).Remove(ACL_RULE_FIELD_DEI)
		case "vlanid":
			(&ruleEntry).Remove(ACL_RULE_FIELD_VLANID)
		// IPv4/IPv6
		case "source-address":
			if strings.Contains(app.pathInfo.Path, "ipv4/config") {
				(&ruleEntry).Remove(ACL_RULE_FIELD_SRC_IP)
			} else if strings.Contains(app.pathInfo.Path, "ipv6/config") {
				(&ruleEntry).Remove(ACL_RULE_FIELD_SRC_IPV6)
			}
		case "destination-address":
			if strings.Contains(app.pathInfo.Path, "ipv4/config") {
				(&ruleEntry).Remove(ACL_RULE_FIELD_DST_IP)
			} else if strings.Contains(app.pathInfo.Path, "ipv6/config") {
				(&ruleEntry).Remove(ACL_RULE_FIELD_DST_IPV6)
			}
		case "dscp":
			(&ruleEntry).Remove(ACL_RULE_FIELD_DSCP)
		case "protocol":
			(&ruleEntry).Remove(ACL_RULE_FIELD_IP_PROTOCOL)
		// transport
		case "source-port":
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_SRC_PORT)
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_SRC_PORT_RANGE)
		case "destination-port":
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_DST_PORT)
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_DST_PORT_RANGE)
		case "icmp-type":
			(&ruleEntry).Remove(ACL_RULE_ICMP_TYPE)
		case "icmp-code":
			(&ruleEntry).Remove(ACL_RULE_ICMP_CODE)
		// actions
		case "forwarding-action":
			(&ruleEntry).Remove(ACL_RULE_PACKET_ACTION)
		//input-interface
		case "interface":
			return tlerr.NotSupported("input-interface not supported")
		}
	} else if nodeInfo.IsContainer() {
		targetType := reflect.TypeOf(*app.ygotTarget)
		switch targetType.Elem().Name() {
		case "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2", "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_L2_Config":
			(&ruleEntry).Remove(ACL_RULE_FIELD_ETHER_TYPE)
			(&ruleEntry).Remove(ACL_RULE_FIELD_SRC_MAC)
			(&ruleEntry).Remove(ACL_RULE_FIELD_DST_MAC)
			(&ruleEntry).Remove(ACL_RULE_FIELD_PCP)
			(&ruleEntry).Remove(ACL_RULE_FIELD_DEI)
			(&ruleEntry).Remove(ACL_RULE_FIELD_VLANID)
		case "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4", "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv4_Config":
			(&ruleEntry).Remove(ACL_RULE_FIELD_IP_PROTOCOL)
			(&ruleEntry).Remove(ACL_RULE_FIELD_SRC_IP)
			(&ruleEntry).Remove(ACL_RULE_FIELD_DST_IP)
			(&ruleEntry).Remove(ACL_RULE_FIELD_DSCP)
		case "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6", "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Ipv6_Config":
			(&ruleEntry).Remove(ACL_RULE_FIELD_IP_PROTOCOL)
			(&ruleEntry).Remove(ACL_RULE_FIELD_SRC_IPV6)
			(&ruleEntry).Remove(ACL_RULE_FIELD_DST_IPV6)
			(&ruleEntry).Remove(ACL_RULE_FIELD_DSCP)
		case "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport", "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config":
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_SRC_PORT)
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_SRC_PORT_RANGE)
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_DST_PORT)
			(&ruleEntry).Remove(ACL_RULE_FIELD_L4_DST_PORT_RANGE)
			(&ruleEntry).Remove(ACL_RULE_FIELD_TCP_FLAGS)
			(&ruleEntry).Remove(ACL_RULE_ICMP_TYPE)
			(&ruleEntry).Remove(ACL_RULE_ICMP_CODE)
		case "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_InputInterface", "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_InputInterface_InterfaceRef", "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_InputInterface_InterfaceRef_Config":
			return tlerr.NotSupported("input-interface not supported")
		case "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Actions", "OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Actions_Config":
			(&ruleEntry).Remove(ACL_RULE_PACKET_ACTION)
		}
	} else if nodeInfo.IsLeafList() {
		switch nodeInfo.Name {
		case "tcp-flags":
			(&ruleEntry).Remove(ACL_RULE_FIELD_TCP_FLAGS)
		}
	} else {
		log.Error("This yang type is not handled currently")
	}
	err = d.SetEntry(app.ruleTs, asKey(aclKey, ruleKey), ruleEntry)

	return err
}

func (app *AclApp) setAclCounterDataInConfigDb(d *db.DB, hwAclData map[string]db.Value) error {
	err := d.ModEntry(app.hardwareTs, db.Key{Comp: []string{"ACCESS_LIST"}}, app.hardwareAclTableMap["ACCESS_LIST"])
	return err
}

func (app *AclApp) setAclDataInConfigDb(d *db.DB, aclData map[string]db.Value, createFlag bool) error {
	var err error
	for key := range aclData {
		log.Infof("ACL:%s Data:%v", key, aclData)
		existingEntry, err := d.GetEntry(app.aclTs, db.Key{Comp: []string{key}})
		// If Create ACL request comes and ACL already exists, throw error
		if createFlag && existingEntry.IsPopulated() {
			aclName, _ := convertInternalAclnameTypeToOC(key, existingEntry.Get(ACL_FIELD_TYPE))
			return tlerr.AlreadyExists("Acl %s already exists", aclName)
		}
		if createFlag || (!createFlag && err != nil && !existingEntry.IsPopulated()) {
			err := d.CreateEntry(app.aclTs, db.Key{Comp: []string{key}}, aclData[key])
			if err != nil {
				return err
			}
		} else {
			if existingEntry.IsPopulated() {
				val := aclData[key]
				if existingEntry.Has(ACL_FIELD_STAGE) && val.Has(ACL_FIELD_STAGE) {
					if existingEntry.Get(ACL_FIELD_STAGE) != val.Get(ACL_FIELD_STAGE) {
						return tlerr.NotSupported("ACL binding at both ingress and egress stage not supported")
					}
				} else if !val.Has(ACL_FIELD_STAGE) && existingEntry.Has(ACL_FIELD_STAGE) {
					val.Set(ACL_FIELD_STAGE, existingEntry.Get(ACL_FIELD_STAGE))
				}

				ports := append(val.GetList(ACL_FIELD_PORTS), existingEntry.GetList(ACL_FIELD_PORTS)...)
				val.SetList(ACL_FIELD_PORTS, ports)

				err := d.ModEntry(app.aclTs, db.Key{Comp: []string{key}}, val)
				if err != nil {
					return err
				}
			}
		}
	}

	return err
}

func (app *AclApp) setAclRuleDataInConfigDb(d *db.DB, ruleData map[string]map[string]db.Value, createFlag bool) error {
	var err error

	for aclName := range ruleData {
		for ruleName := range ruleData[aclName] {
			existingRuleEntry, err := d.GetEntry(app.ruleTs, db.Key{Comp: []string{aclName, ruleName}})
			// If Create Rule request comes and Rule already exists, throw error
			if createFlag && existingRuleEntry.IsPopulated() {
				seqId, _ := strconv.ParseUint(strings.Replace(ruleName, "RULE_", "", 1), 10, 16)
				return tlerr.AlreadyExists("Rule with sequence number %v already exists", seqId)
			}
			if createFlag || (!createFlag && err != nil && !existingRuleEntry.IsPopulated()) {
				err := d.CreateEntry(app.ruleTs, db.Key{Comp: []string{aclName, ruleName}}, ruleData[aclName][ruleName])
				if err != nil {
					return err
				}
			} else {
				if existingRuleEntry.IsPopulated() {
					err := d.ModEntry(app.ruleTs, db.Key{Comp: []string{aclName, ruleName}}, ruleData[aclName][ruleName])
					if err != nil {
						return err
					}
				}
			}
		}
	}

	return err
}

func getAclNamesBoundToInterface(cache map[string]db.Value, intf string, stage string) map[string]string {
	bindInfo := make(map[string]string)

	for aclName, aclData := range cache {
		if aclData.Get(ACL_FIELD_STAGE) == stage {
			ports := aclData.GetList(ACL_FIELD_PORTS)
			if contains(ports, intf) {
				bindInfo[aclData.Get(ACL_FIELD_TYPE)] = aclName
				if len(bindInfo) == 3 {
					break
				}
			}
		}
	}

	return bindInfo
}

func getAclnameBoundToInterfaceByType(cache map[string]db.Value, intf string, stage string, aclType string) (string, bool) {
	log.Infof("Input is Intf:%s Stage:%s Type:%s", intf, stage, aclType)
	for aclName, aclData := range cache {
		log.Infof("ACL:%v Data:%v", aclName, aclData)
		if aclData.Get(ACL_FIELD_STAGE) == stage && aclData.Get(ACL_FIELD_TYPE) == aclType {
			ports := aclData.GetList(ACL_FIELD_PORTS)
			if contains(ports, intf) {
				return aclName, true
			}
		}
	}

	return "", false
}

func (app *AclApp) setAclBindDataInConfigDb(d *db.DB, opcode int) error {
	var err error

	aclCache := make(map[string]db.Value)
	deleteAclData := make(map[string]db.Value)

	aclKeys, err := d.GetKeys(app.aclTs)
	if err != nil {
		return err
	}

	for i := range aclKeys {
		log.Infof("Get ACL %s from DB", aclKeys[i].Get(0))
		aclCache[aclKeys[i].Get(0)], err = d.GetEntry(app.aclTs, aclKeys[i])
		if err != nil {
			return err
		}
	}

	for aclKey, aclInfo := range app.aclTableMap {
		// Get ACL info from DB
		dbAcl := aclCache[aclKey]

		// Check if new binding request doesnt change the ACL stage if it has other bindings
		dbAclIntfs := dbAcl.GetList(ACL_FIELD_PORTS)
		dbAclDirec := dbAcl.Get(ACL_FIELD_STAGE)
		newIntfs := aclInfo.GetList(ACL_FIELD_PORTS)
		newDirec := aclInfo.Get(ACL_FIELD_STAGE)
		log.Infof("Check for conflicts for ACL:%s Stage:%s Ports:%v", aclKey, newDirec, newIntfs)
		if len(dbAclIntfs) > 0 {
			if (len(dbAclDirec) > 0) && (len(newDirec) > 0) && (dbAclDirec != newDirec) {
				log.Errorf("ACL %s already has %s binding on ports %v. %s binding on %v not allowed",
					aclKey, dbAclDirec, dbAclIntfs, newDirec, newIntfs)
				return tlerr.InvalidArgs("Acl %s direction of %s not allowed when it is already configured as %s",
					aclKey, newDirec, dbAclDirec)
			}
		}

		// Check if the new binding ends up applying 2 ACLs to the same interface.
		// For create return error. For update and replace operation remove the old interface
		// bindings if it already exists
		for _, intf := range newIntfs {
			existingAclName, found := getAclnameBoundToInterfaceByType(aclCache, intf, newDirec, aclInfo.Get(ACL_FIELD_TYPE))
			if !found {
				continue
			}

			if CREATE == opcode {
				if found {
					log.Errorf("Intf %s has ACL %s at %s already. Cant create new ACL %s binding", intf,
						existingAclName, dbAclDirec, aclKey)
					return tlerr.AlreadyExists("ACL binding on %s at %s already exists.", intf, newDirec)
				}
			} else if REPLACE == opcode || UPDATE == opcode {
				log.Infof("Intf %s ACL binding update requested from %s => %s", intf, existingAclName, aclKey)

				var oldBindingAcl db.Value
				var ok bool
				if oldBindingAcl, ok = deleteAclData[existingAclName]; !ok {
					oldBindingAcl = aclCache[existingAclName]
				}

				oldBindList := oldBindingAcl.GetList(ACL_FIELD_PORTS)
				newBindList := removeElement(oldBindList, intf)
				if len(newBindList) > 0 {
					log.Infof("ACL %s bind list changed from %v => %v", existingAclName, oldBindList, newBindList)
					oldBindingAcl.SetList(ACL_FIELD_PORTS, newBindList)
				} else {
					oldBindingAcl.Remove("ports@")
					oldBindingAcl.Remove(ACL_FIELD_STAGE)
				}
				deleteAclData[existingAclName] = oldBindingAcl
			}
		}
	}

	// At this stage deleteAclData contains new Port List for any port deletes that might have happended
	// When the same Interface is updated/replaced with a different ACL name. Now merge the new binding
	// With whats present in DB.
	for aclKey, aclInfo := range app.aclTableMap {
		var dbAcl db.Value
		var err error
		var ok bool
		if dbAcl, ok = deleteAclData[aclKey]; !ok {
			dbAcl, err = d.GetEntry(app.aclTs, db.Key{Comp: []string{aclKey}})
			if err != nil {
				return err
			}
		}

		dbAclIntfs := dbAcl.GetList(ACL_FIELD_PORTS)
		newIntfs := aclInfo.GetList(ACL_FIELD_PORTS)
		for _, ifId := range newIntfs {
			if !contains(dbAclIntfs, ifId) {
				dbAclIntfs = append(dbAclIntfs, ifId)
			}
		}
		dbAcl.SetList(ACL_FIELD_PORTS, dbAclIntfs)
		if len(dbAcl.Get(ACL_FIELD_STAGE)) == 0 {
			dbAcl.Set(ACL_FIELD_STAGE, aclInfo.Get(ACL_FIELD_STAGE))
		}
		app.aclTableMap[aclKey] = dbAcl
	}

	// Now that we have a delete ACL Binding list and new binding List, apply delete first and then new
	for aclKey, aclInfo := range deleteAclData {
		err = d.SetEntry(app.aclTs, db.Key{Comp: []string{aclKey}}, aclInfo)
		if err != nil {
			return err
		}
	}
	for aclKey, aclInfo := range app.aclTableMap {
		err = d.SetEntry(app.aclTs, db.Key{Comp: []string{aclKey}}, aclInfo)
		if err != nil {
			return err
		}
	}

	return err
}

func (app *AclApp) getAclKeyByCheckingDbForNameWithoutType(d *db.DB, aclname string, acltype ocbinds.E_OpenconfigAcl_ACL_TYPE) string {
	//	var aclKey string
	//	aclT := acltype.ΛMap()["E_OpenconfigAcl_ACL_TYPE"][int64(acltype)].Name
	//	aclKey = aclname + "_" + aclT
	//
	//	// For ACLs created by Config json directly, ACL name may not appended with its type
	//	patternKeys, err := d.GetKeysByPattern(app.aclTs, aclname+"*")
	//	if err != nil {
	//		return aclKey
	//	}
	//	for i := range patternKeys {
	//		// Find entry which does not ends with Acl type and its name matches with name given in url
	//		patternKeyFromDb := patternKeys[i].Get(0)
	//		if !strings.HasSuffix(patternKeyFromDb, aclT) && patternKeyFromDb == aclname {
	//			aclKey = aclname
	//			log.Infof("getAclKeyByCheckingDbForNameWithoutType: Modified aclKey to: %s", aclKey)
	//		}
	//	}
	//
	//	return aclKey
	return aclname
}

func (app *AclApp) getAclRuleByCheckingDbForNameWithoutRule(d *db.DB, aclname string, ruleId string) string {
	var ruleKey string

	ruleKey = "RULE_" + ruleId
	//For Rules created by Config json directly, Rule name may not prefixed with "RULE_"
	patternKeys, err := d.GetKeysByPattern(app.ruleTs, aclname+"|"+"*"+ruleId)
	if err != nil {
		return ruleKey
	}
	for i := range patternKeys {
		// Find entry which does not starts with "RULE_" and its name matches with rule name given in url
		patternKeyFromDb := patternKeys[i].Get(1)
		if !strings.HasPrefix(patternKeyFromDb, "RULE_") && patternKeyFromDb == ruleId {
			ruleKey = ruleId
			log.Infof("getAclRuleByCheckingDbForNameWithoutRule: Modified ruleKey to: %s", ruleKey)
		}
	}

	return ruleKey
}

func getIpProtocol(proto int64) interface{} {
	for k, v := range IP_PROTOCOL_MAP {
		if uint8(proto) == v {
			return k
		}
	}

	return uint8(proto)
}

func getTransportSrcDestPorts(portVal string, portType string) interface{} {
	if strings.Contains(portVal, "-") {
		return strings.Replace(portVal, "-", "..", 1)
	} else if len(portVal) > 0 {
		portNum, err := strconv.Atoi(portVal)
		if err == nil {
			return uint16(portNum)
		}
	} else {
		if portType == "src" {
			return ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_ANY
		} else if portType == "dest" {
			return ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_ANY
		}
	}

	return nil
}

func convertOCTcpFlagsToDbFormat(flags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS) string {
	var tcpFlags uint32 = 0x00
	var tcpFlagsMask uint32 = 0x00
	for _, flag := range flags {
		switch flag {
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN:
			tcpFlags |= 0x01
			tcpFlagsMask |= 0x1
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_FIN:
			tcpFlagsMask |= 0x1
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN:
			tcpFlags |= 0x02
			tcpFlagsMask |= 0x2
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_SYN:
			tcpFlagsMask |= 0x2
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST:
			tcpFlags |= 0x04
			tcpFlagsMask |= 0x4
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_RST:
			tcpFlagsMask |= 0x4
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH:
			tcpFlags |= 0x08
			tcpFlagsMask |= 0x8
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_PSH:
			tcpFlagsMask |= 0x8
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK:
			tcpFlags |= 0x10
			tcpFlagsMask |= 0x10
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ACK:
			tcpFlagsMask |= 0x10
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG:
			tcpFlags |= 0x20
			tcpFlagsMask |= 0x20
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_URG:
			tcpFlagsMask |= 0x20
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE:
			tcpFlags |= 0x40
			tcpFlagsMask |= 0x40
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ECE:
			tcpFlagsMask |= 0x40
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR:
			tcpFlags |= 0x80
			tcpFlagsMask |= 0x80
		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_CWR:
			tcpFlagsMask |= 0x80
		}
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "0x%x/0x%x", tcpFlags, tcpFlagsMask)

	return b.String()
}

func getTransportConfigTcpFlags(tcpFlags string) []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS {
	var flags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS
	flagParts := strings.Split(tcpFlags, "/")
	valueStr := flagParts[0]
	maskStr := flagParts[1]
	flagValue, _ := strconv.ParseUint(valueStr, 0, 8)
	flagMask, _ := strconv.ParseUint(maskStr, 0, 8)
	for i := 0; i < 8; i++ {
		mask := uint64(1 << i)
		if (flagValue&mask) > 0 || (flagMask&mask) > 0 {
			switch mask {
			case 0x01:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_FIN)
				}
			case 0x02:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_SYN)
				}
			case 0x04:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_RST)
				}
			case 0x08:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_PSH)
				}
			case 0x10:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ACK)
				}
			case 0x20:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_URG)
				}
			case 0x40:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ECE)
				}
			case 0x80:
				if (flagValue & mask) > 0 {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR)
				} else {
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_CWR)
				}
			default:
			}
		}
	}
	return flags
}

func getL2EtherType(etherType uint64) interface{} {
	for k, v := range ETHERTYPE_MAP {
		if uint32(etherType) == v {
			return k
		}
	}

	return uint16(etherType)
}

func convertInternalAclnameTypeToOC(aclKey string, aclType string) (string, ocbinds.E_OpenconfigAcl_ACL_TYPE) {
	var aclOrigName string = aclKey
	var aclOrigType ocbinds.E_OpenconfigAcl_ACL_TYPE

	if SONIC_ACL_TYPE_IPV4 == aclType {
		//aclOrigName = strings.Replace(aclKey, "_" + OPENCONFIG_ACL_TYPE_IPV4, "", 1)
		aclOrigType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4
	} else if SONIC_ACL_TYPE_IPV6 == aclType {
		//aclOrigName = strings.Replace(aclKey, "_" + OPENCONFIG_ACL_TYPE_IPV6, "", 1)
		aclOrigType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV6
	} else if SONIC_ACL_TYPE_L2 == aclType {
		//aclOrigName = strings.Replace(aclKey, "_" + OPENCONFIG_ACL_TYPE_L2, "", 1)
		aclOrigType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2
	}

	return aclOrigName, aclOrigType
}

// getAclTypeOCEnumFromName returns the ACL_FIELD_TYPE enum from name
func getAclTypeOCEnumFromName(val string) (ocbinds.E_OpenconfigAcl_ACL_TYPE, error) {
	switch val {
	case "ACL_IPV4", "openconfig-acl:ACL_IPV4":
		return ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4, nil
	case "ACL_IPV6", "openconfig-acl:ACL_IPV6":
		return ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV6, nil
	case "ACL_L2", "openconfig-acl:ACL_L2":
		return ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2, nil
	default:
		return ocbinds.OpenconfigAcl_ACL_TYPE_UNSET,
			tlerr.NotSupported("ACL Type '%s' not supported", val)
	}
}

func convertOCAclnameTypeToInternal(aclname string, acltype ocbinds.E_OpenconfigAcl_ACL_TYPE) string {
	//	aclT := acltype.ΛMap()["E_OpenconfigAcl_ACL_TYPE"][int64(acltype)].Name
	//	return aclname + "_" + aclT
	return aclname
}
