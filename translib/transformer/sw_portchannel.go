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
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("YangToDb_lag_min_links_xfmr", YangToDb_lag_min_links_xfmr)
	XlateFuncBind("DbToYang_lag_min_links_xfmr", DbToYang_lag_min_links_xfmr)
	XlateFuncBind("YangToDb_lag_fallback_xfmr", YangToDb_lag_fallback_xfmr)
	XlateFuncBind("DbToYang_lag_fallback_xfmr", DbToYang_lag_fallback_xfmr)
	XlateFuncBind("YangToDb_lag_fast_rate_xfmr", YangToDb_lag_fast_rate_xfmr)
	XlateFuncBind("DbToYang_lag_fast_rate_xfmr", DbToYang_lag_fast_rate_xfmr)
	XlateFuncBind("DbToYang_intf_lag_state_xfmr", DbToYang_intf_lag_state_xfmr)
	XlateFuncBind("YangToDb_lag_type_xfmr", YangToDb_lag_type_xfmr)
	XlateFuncBind("DbToYang_lag_type_xfmr", DbToYang_lag_type_xfmr)
	XlateFuncBind("YangToDb_lag_graceful_shutdown_xfmr", YangToDb_lag_graceful_shutdown_xfmr)
	XlateFuncBind("DbToYang_lag_graceful_shutdown_xfmr", DbToYang_lag_graceful_shutdown_xfmr)
}

const (
	LAG_TYPE                      = "lag-type"
	PORTCHANNEL_TABLE             = "PORTCHANNEL"
	DEFAULT_PORTCHANNEL_MIN_LINKS = "1"
)

var LAG_TYPE_MAP = map[string]string{
	strconv.FormatInt(int64(ocbinds.OpenconfigIfAggregate_AggregationType_LACP), 10):   "false",
	strconv.FormatInt(int64(ocbinds.OpenconfigIfAggregate_AggregationType_STATIC), 10): "true",
}

func uint16Conv(sval string) (uint16, error) {
	v, err := strconv.ParseUint(sval, 10, 16)
	if err != nil {
		errStr := "Conversion of string: " + "sval" + " to int failed"
		if log.V(3) {
			log.Error(errStr)
		}
		return 0, errors.New(errStr)
	}
	return uint16(v), nil
}

/* Validate whether LAG exists in DB */
func validatePortChannel(d *db.DB, lagName string) error {

	intfType, _, ierr := getIntfTypeByName(lagName)
	if ierr != nil || intfType != IntfTypePortChannel {
		return tlerr.InvalidArgsError{Format: "Invalid PortChannel: " + lagName}
	}

	err := validateIntfExists(d, PORTCHANNEL_TABLE, lagName)
	if err != nil {
		errStr := "PortChannel: " + lagName + " does not exist"
		return tlerr.InvalidArgsError{Format: errStr}
	}

	return nil
}

func get_min_links(d *db.DB, lagName *string, links *uint16) error {
	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	curr, err := d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.portTN}, db.Key{Comp: []string{*lagName}})
	if err != nil {
		errStr := "Failed to Get PortChannel details"
		log.Info(errStr)
		return errors.New(errStr)
	}
	if val, ok := curr.Field["min_links"]; ok {
		*links, err = uint16Conv(val)
		if err != nil {
			return err
		}
	} else {
		log.Info("Minlinks set to 0 (dafault value)")
		*links = 0
	}
	log.Infof("Got min links from DB : %d\n", *links)
	return nil
}

func get_lag_type(d *db.DB, lagName *string, mode *string) error {
	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	curr, err := d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.portTN}, db.Key{Comp: []string{*lagName}})
	if err != nil {
		errStr := "Failed to Get PortChannel details"
		log.Info(errStr)
		return errors.New(errStr)
	}
	if val, ok := curr.Field["static"]; ok {
		*mode = val
		log.Infof("Mode from DB: %s\n", *mode)
	} else {
		*mode = "false"
		log.Infof("Default LACP Mode: %s\n", *mode)
	}
	return nil
}

func get_fallback(d *db.DB, lagName *string, fallback *string) error {
	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	curr, err := d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.portTN}, db.Key{Comp: []string{*lagName}})
	if err != nil {
		errStr := "Failed to Get PortChannel details"
		log.Info(errStr)
		return errors.New(errStr)
	}
	if val, ok := curr.Field["fallback"]; ok {
		*fallback = val
		log.Infof("Fallback option read from DB: %s\n", *fallback)
	} else {
		*fallback = "false"
		log.Infof("Default Fallback option: %s\n", *fallback)
	}
	return nil
}

func get_fast_rate(d *db.DB, lagName *string, fastRate *string) error {
	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	curr, err := d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.portTN}, db.Key{Comp: []string{*lagName}})
	if err != nil {
		errStr := "Failed to Get PortChannel details"
		log.Info(errStr)
		return errors.New(errStr)
	}
	if val, ok := curr.Field["fast-rate"]; ok {
		*fastRate = val
		log.Infof("Fast Rate option read from DB: %s\n", *fastRate)
	} else {
		*fastRate = "false"
		log.Infof("Default Fast Rate option: %s\n", *fastRate)
	}
	return nil
}

/* Validate physical interface configured as member of PortChannel */
func validateIntfAssociatedWithPortChannel(d *db.DB, ifName *string) error {
	var err error
	if len(*ifName) == 0 {
		return errors.New("Interface name is empty!")
	}
	lagKeys, err := d.GetKeysByPattern(&db.TableSpec{Name: PORTCHANNEL_MEMBER_TN}, "*"+*ifName)

	if err == nil && len(lagKeys) != 0 {
		intfNameAlias := utils.GetUINameFromNativeName(ifName)
		errStr := *intfNameAlias + " is already associated with " + lagKeys[0].Get(0)
		log.Error(errStr)
		return tlerr.InvalidArgsError{Format: errStr}
	}
	return err
}

// YangToDb_lag_min_links_xfmr is a Yang to DB translation overloaded method for handle min-links config
var YangToDb_lag_min_links_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	if log.V(3) {
		log.Info("Entering YangToDb_lag_min_links_xfmr")
	}
	res_map := make(map[string]string)
	var err error

	pathInfo := NewPathInfo(inParams.uri)
	ifKey := pathInfo.Var("name")

	log.Infof("Received Min links config for path: %s; template: %s vars: %v ifKey: %s", pathInfo.Path, pathInfo.Template, pathInfo.Vars, ifKey)

	if inParams.param == nil {
		if log.V(3) {
			log.Info("YangToDb_lag_min_links_xfmr Error: No Params")
		}
		return res_map, err
	}

	var links uint16
	err = get_min_links(inParams.d, &ifKey, &links)

	if err == nil && links != *(inParams.param.(*uint16)) {
		errStr := "Cannot reconfigure min links for an existing PortChannel: " + ifKey
		log.Info(errStr)
		err = tlerr.InvalidArgsError{Format: errStr}
		return res_map, err
	}

	minLinks, _ := inParams.param.(*uint16)
	res_map["min_links"] = strconv.Itoa(int(*minLinks))
	return res_map, nil
}

var DbToYang_lag_min_links_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	if log.V(3) {
		log.Info("Entering DbToYang_lag_min_links_xfmr")
	}
	var err error
	result := make(map[string]interface{})

	err = validatePortChannel(inParams.d, inParams.key)
	if err != nil {
		log.Infof("DbToYang_lag_min_links_xfmr Error: %v ", err)
		return result, err
	}
	data := (*inParams.dbDataMap)[inParams.curDb]
	links, ok := data[PORTCHANNEL_TABLE][inParams.key].Field["min_links"]
	if ok {
		linksUint16, err := uint16Conv(links)
		if err != nil {
			return result, err
		}
		result["min-links"] = linksUint16
	} else {
		if log.V(3) {
			log.Info("min-links set to 0 (dafault value)")
		}
		result["min-links"] = 0
	}

	return result, err
}

func can_configure_fallback(inParams XfmrParams) error {
	device := (*inParams.ygRoot).(*ocbinds.Device)
	user_config_json, e := ygot.EmitJSON(device, &ygot.EmitJSONConfig{
		Format: ygot.RFC7951,
		Indent: "  ",
		RFC7951Config: &ygot.RFC7951JSONConfig{
			AppendModuleName: true,
		}})

	if e != nil {
		log.Infof("EmitJSON error: %v", e)
		return e
	}

	type intf struct {
		IntfS map[string]interface{} `json:"openconfig-interfaces:interfaces"`
	}
	var res intf
	e = json.Unmarshal([]byte(user_config_json), &res)
	if e != nil {
		log.Infof("UnMarshall Error %v\n", e)
		return e
	}

	i := res.IntfS["interface"].([]interface{})
	po_map := i[0].(map[string]interface{})

	pathInfo := NewPathInfo(inParams.uri)
	ifKey := pathInfo.Var("name")

	var static string = "false"
	if agg, ok := po_map["openconfig-if-aggregate:aggregation"]; ok {
		a := agg.(map[string]interface{})
		agg_conf := a["config"].(map[string]interface{})
		if lag_type, k := agg_conf["lag-type"]; k {
			if lag_type == "STATIC" {
				// User Input Static LAG
				static = "true"
			} else {
				// Read LAG Type from DB
				var mode string
				e = get_lag_type(inParams.d, &ifKey, &mode)
				if e == nil && mode == "true" {
					static = "true"
				}
			}
		}
	}

	if static == "true" {
		errStr := "Fallback is not supported for Static LAGs"
		return tlerr.InvalidArgsError{Format: errStr}
	}

	// LACP LAG: Check for fallback re-configuration
	var fallback string
	e = get_fallback(inParams.d, &ifKey, &fallback)
	if e == nil && fallback == "false" {
		errStr := "Fallback option cannot be configured for an already existing PortChannel: " + ifKey
		return tlerr.InvalidArgsError{Format: errStr}
	}

	return nil
}

func can_configure_fast_rate(inParams XfmrParams) error {

	pathInfo := NewPathInfo(inParams.uri)
	ifKey := pathInfo.Var("name")

	var static string = "false"
	// Read LAG Type from DB
	var mode string
	e := get_lag_type(inParams.d, &ifKey, &mode)
	if e == nil && mode == "true" {
		static = "true"
	}

	if static == "true" {
		errStr := "Fast Rate interval configuration is not applicable for Static LAG"
		return tlerr.InvalidArgsError{Format: errStr}
	}

	// LACP LAG: Check for fast_rate interval re-configuration
	var fastRate string
	e = get_fast_rate(inParams.d, &ifKey, &fastRate)
	if e == nil && fastRate == "false" {
		errStr := "Fast Rate option cannot be configured for an already existing PortChannel: " + ifKey
		return tlerr.InvalidArgsError{Format: errStr}
	}

	return nil
}

// YangToDb_lag_fast_rate_xfmr is a Yang to DB translation overloaded method for handle fast_rate config
var YangToDb_lag_fast_rate_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	if log.V(3) {
		log.Info("Entering YangToDb_lag_fast_rate_xfmr")
	}
	res_map := make(map[string]string)
	var err error

	if inParams.param == nil {
		if log.V(3) {
			log.Info("YangToDb_lag_fast_rate_xfmr Error: No Params")
		}
		return res_map, err
	}

	err = can_configure_fast_rate(inParams)
	if err != nil {
		return res_map, err
	}

	fastRate, _ := inParams.param.(*bool)
	res_map["fast_rate"] = strconv.FormatBool(*fastRate)
	return res_map, nil
}

// YangToDb_lag_fallback_xfmr is a Yang to DB translation overloaded method for handle fallback config
var YangToDb_lag_fallback_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	if log.V(3) {
		log.Info("Entering YangToDb_lag_fallback_xfmr")
	}
	res_map := make(map[string]string)
	var err error

	if inParams.param == nil {
		if log.V(3) {
			log.Info("YangToDb_lag_fallback_xfmr Error: No Params")
		}
		return res_map, err
	}

	err = can_configure_fallback(inParams)
	if err != nil {
		return res_map, err
	}

	fallback, _ := inParams.param.(*bool)
	res_map["fallback"] = strconv.FormatBool(*fallback)
	return res_map, nil
}

var DbToYang_lag_fallback_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	if log.V(3) {
		log.Info("Entering DbToYang_lag_fallback_xfmr")
	}
	var err error
	result := make(map[string]interface{})

	err = validatePortChannel(inParams.d, inParams.key)
	if err != nil {
		log.Infof("DbToYang_lag_fallback_xfmr Error: %v ", err)
		return result, err
	}

	data := (*inParams.dbDataMap)[inParams.curDb]

	fallback, ok := data[PORTCHANNEL_TABLE][inParams.key].Field["fallback"]
	if ok {
		result["fallback"], _ = strconv.ParseBool(fallback)
	} else {
		if log.V(3) {
			log.Info("fallback set to false (default value)")
		}
		result["fallback"] = false
	}
	return result, err
}

var DbToYang_lag_fast_rate_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	if log.V(3) {
		log.Info("Entering DbToYang_lag_fast_rate_xfmr")
	}
	var err error
	result := make(map[string]interface{})

	err = validatePortChannel(inParams.d, inParams.key)
	if err != nil {
		log.Infof("DbToYang_lag_fast_rate_xfmr Error: %v ", err)
		return result, err
	}

	data := (*inParams.dbDataMap)[inParams.curDb]

	fastRate, ok := data[PORTCHANNEL_TABLE][inParams.key].Field["fast_rate"]
	if ok {
		result["fast-rate"], _ = strconv.ParseBool(fastRate)
	}
	return result, err
}

func getLagStateAttr(attr *string, ifName *string, lagInfoMap map[string]db.Value,
	oc_val *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Aggregation_State) error {
	lagEntries, ok := lagInfoMap[*ifName]
	if !ok {
		errStr := "Cannot find info for Interface: " + *ifName
		return errors.New(errStr)
	}
	switch *attr {
	case "mode":
		oc_val.LagType = ocbinds.OpenconfigIfAggregate_AggregationType_LACP

		lag_type, ok := lagEntries.Field["static"]
		if ok {
			if lag_type == "true" {
				oc_val.LagType = ocbinds.OpenconfigIfAggregate_AggregationType_STATIC
			}
		}
	case "min-links":
		links, _ := strconv.Atoi(lagEntries.Field["min-links"])
		minlinks := uint16(links)
		oc_val.MinLinks = &minlinks
	case "fallback":
		fallbackVal, _ := strconv.ParseBool(lagEntries.Field["fallback"])
		oc_val.Fallback = &fallbackVal
	case "fast-rate":
		fastRateVal, _ := strconv.ParseBool(lagEntries.Field["fast-rate"])
		oc_val.FastRate = &fastRateVal
	case "member":
		lagMembers := strings.Split(lagEntries.Field["member@"], ",")
		oc_val.Member = lagMembers
	}
	return nil
}

func getLagState(ifName *string, lagInfoMap map[string]db.Value,
	oc_val *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Aggregation_State) error {
	log.V(3).Info("getLagState() called")
	lagEntries, ok := lagInfoMap[*ifName]
	if !ok {
		errStr := "Cannot find info for Interface: " + *ifName
		return errors.New(errStr)
	}
	links, _ := strconv.Atoi(lagEntries.Field["min-links"])
	minlinks := uint16(links)
	oc_val.MinLinks = &minlinks
	fallbackVal, _ := strconv.ParseBool(lagEntries.Field["fallback"])
	oc_val.Fallback = &fallbackVal
	fastRateVal, _ := strconv.ParseBool(lagEntries.Field["fast-rate"])
	oc_val.FastRate = &fastRateVal

	oc_val.LagType = ocbinds.OpenconfigIfAggregate_AggregationType_LACP
	lag_type, ok := lagEntries.Field["static"]
	if ok {
		if lag_type == "true" {
			oc_val.LagType = ocbinds.OpenconfigIfAggregate_AggregationType_STATIC
		}
	}

	lagMembers := strings.Split(lagEntries.Field["member@"], ",")
	oc_val.Member = lagMembers
	return nil
}

/* Get PortChannel Info */
func fillLagInfoForIntf(inParams XfmrParams, d *db.DB, ifName *string, lagInfoMap map[string]db.Value) error {
	var err error
	var lagMemKeys []db.Key
	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	/* Get members list */
	ts := db.TableSpec{Name: PORTCHANNEL_MEMBER_TN + d.Opts.KeySeparator + *ifName}
	lagMemKeys, err = d.GetKeys(&ts)
	if err != nil {
		return err
	}
	log.Info("lag-member-table keys", lagMemKeys)

	var lagMembers []string
	var memberPortsStr strings.Builder
	for i := range lagMemKeys {
		ethName := lagMemKeys[i].Get(1)
		lagMembers = append(lagMembers, ethName)
		memberPortsStr.WriteString(ethName + ",")
	}
	lagInfoMap[*ifName] = db.Value{Field: make(map[string]string)}
	lagInfoMap[*ifName].Field["member@"] = strings.Join(lagMembers, ",")
	/* Get MinLinks value */
	curr, err := d.GetEntry(&db.TableSpec{Name: intTbl.cfgDb.portTN}, db.Key{Comp: []string{*ifName}})
	if err != nil {
		errStr := "Failed to Get PortChannel details"
		return errors.New(errStr)
	}
	var links int
	if val, ok := curr.Field["min_links"]; ok {
		min_links, err := strconv.Atoi(val)
		if err != nil {
			errStr := "Conversion of string to int failed"
			return errors.New(errStr)
		}
		links = min_links
	} else {
		log.V(3).Info("Minlinks set to 0 (dafault value)")
		links = 0
	}
	lagInfoMap[*ifName].Field["min-links"] = strconv.Itoa(links)
	/* Get fallback value */

	lagTbl := &db.TableSpec{Name: "LAG_TABLE"}
	appDb := inParams.dbs[db.ApplDB]
	dbEntry, err := appDb.GetEntry(lagTbl, db.Key{Comp: []string{*ifName}})
	if err != nil {
		errStr := "Failed to get PortChannel APP_DB entry"
		log.Info(errStr)
		return errors.New(errStr)
	}

	var fallbackVal string
	if val, ok := dbEntry.Field["fallback_operational"]; ok {
		fallbackVal = val
	} else {
		log.V(3).Info("Fallback set to False, default value")
		fallbackVal = "false"
	}
	lagInfoMap[*ifName].Field["fallback"] = fallbackVal

	/* Get fast rate value */
	var fastRateVal string
	if val, ok := curr.Field["fast_rate"]; ok {
		fastRateVal = val
	} else {
		if log.V(3) {
			log.Info("fast_rate set to false (default value)")
		}
		fastRateVal = "false"
	}

	lagInfoMap[*ifName].Field["fast-rate"] = fastRateVal

	/*Get Static Value*/
	if v, k := curr.Field["static"]; k {
		lagInfoMap[*ifName].Field["static"] = v
	} else {
		log.V(3).Info("Mode set to LACP, default value")
		lagInfoMap[*ifName].Field["static"] = "false"
	}
	log.Infof("Updated the lag-info-map for Interface: %s", *ifName)

	return err
}

// DbToYang_intf_lag_state_xfmr is a DB to Yang translation overloaded method for PortChannel GET operation
var DbToYang_intf_lag_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error

	intfsObj := getIntfsRoot(inParams.ygRoot)
	if intfsObj == nil || intfsObj.Interface == nil {
		errStr := "Failed to Get root object!"
		log.Errorf(errStr)
		return errors.New(errStr)
	}
	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("name")
	if _, ok := intfsObj.Interface[ifName]; !ok {
		obj, _ := intfsObj.NewInterface(ifName)
		ygot.BuildEmptyTree(obj)
	}
	intfObj := intfsObj.Interface[ifName]
	if intfObj.Aggregation == nil {
		ygot.BuildEmptyTree(intfObj)
	}
	if intfObj.Aggregation.State == nil {
		ygot.BuildEmptyTree(intfObj.Aggregation)
	}
	intfType, _, err := getIntfTypeByName(ifName)
	if intfType != IntfTypePortChannel || err != nil {
		intfTypeStr := strconv.Itoa(int(intfType))
		errStr := "TableXfmrFunc - Invalid interface type: " + intfTypeStr
		log.Warning(errStr)
		return errors.New(errStr)
	}
	/*Validate given PortChannel exists */
	err = validatePortChannel(inParams.d, ifName)
	if err != nil {
		return err
	}

	targetUriPath, _ := getYangPathFromUri(inParams.uri)
	log.Info("targetUriPath is ", targetUriPath)
	lagInfoMap := make(map[string]db.Value)
	ocAggregationStateVal := intfObj.Aggregation.State
	err = fillLagInfoForIntf(inParams, inParams.d, &ifName, lagInfoMap)
	if err != nil {
		log.Errorf("Failed to get info: %s failed!", ifName)
		return err
	}
	log.Info("Succesfully completed DB map population!", lagInfoMap)
	switch targetUriPath {
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/min-links":
		log.Info("Get is for min-links")
		attr := "min-links"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/lag-type":
		log.Info("Get is for lag type")
		attr := "mode"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/openconfig-interfaces-ext:fallback":
		log.Info("Get is for fallback")
		attr := "fallback"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/openconfig-interfaces-ext:fast-rate":

		links, _ := strconv.Atoi(DEFAULT_PORTCHANNEL_MIN_LINKS)
		minlinks := uint16(links)
		ocAggregationStateVal.MinLinks = &minlinks

		log.Info("Get is for fast rate")
		attr := "fast-rate"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state/member":
		log.Info("Get is for member")
		attr := "member"
		err = getLagStateAttr(&attr, &ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	case "/openconfig-interfaces:interfaces/interface/aggregation/state":
		fallthrough
	case "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation/state":
		log.Info("Get is for State Container!")
		err = getLagState(&ifName, lagInfoMap, ocAggregationStateVal)
		if err != nil {
			return err
		}
	default:
		log.Infof(targetUriPath + " - Not an supported Get attribute")
	}
	return err
}

/* Function to delete PortChannel and all its member ports */
func deleteLagIntfAndMembers(inParams *XfmrParams, lagName *string) error {
	log.Info("Inside deleteLagIntfAndMembers")
	var err error

	subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
	resMap := make(map[string]map[string]db.Value)
	lagMap := make(map[string]db.Value)
	lagMemberMap := make(map[string]db.Value)
	lagIntfMap := make(map[string]db.Value)
	lagMap[*lagName] = db.Value{Field: map[string]string{}}

	intTbl := IntfTypeTblMap[IntfTypePortChannel]
	subOpMap[db.ConfigDB] = resMap
	inParams.subOpDataMap[DELETE] = &subOpMap
	/* Validate given PortChannel exists */
	intfType, _, ierr := getIntfTypeByName(*lagName)
	if ierr != nil || intfType != IntfTypePortChannel {
		return tlerr.InvalidArgsError{Format: "Invalid PortChannel: " + *lagName}
	}

	entry, err := inParams.d.GetEntry(&db.TableSpec{Name: PORTCHANNEL_TABLE}, db.Key{Comp: []string{*lagName}})
	if err != nil || !entry.IsPopulated() {
		// Not returning error from here since mgmt infra will return "Resource not found" error in case of non existence entries
		return nil
	}

	/* Restrict deletion if iface configured as member-port of any existing Vlan */
	err = validateIntfAssociatedWithExistingVlan(inParams.d, lagName)
	if err != nil {
		return err
	}

	/* Validate L3 Configuration only operation is not Delete */
	if inParams.oper != DELETE {
		err = validateL3ConfigExists(inParams.d, lagName)
		if err != nil {
			return err
		}
	}

	/* Handle PORTCHANNEL_MEMBER TABLE */
	var flag bool = false
	ts := db.TableSpec{Name: intTbl.cfgDb.memberTN + inParams.d.Opts.KeySeparator + *lagName}
	lagKeys, err := inParams.d.GetKeys(&ts)
	if err == nil {
		for key := range lagKeys {
			flag = true
			log.Info("Member port", lagKeys[key].Get(1))
			memberKey := *lagName + "|" + lagKeys[key].Get(1)
			lagMemberMap[memberKey] = db.Value{Field: map[string]string{}}
		}
		if flag {
			resMap["PORTCHANNEL_MEMBER"] = lagMemberMap
		}
	}

	/* Handle PORTCHANNEL_INTERFACE TABLE */
	processIntfTableRemoval(inParams.d, *lagName, PORTCHANNEL_INTERFACE_TN, lagIntfMap)
	if len(lagIntfMap) != 0 {
		resMap[PORTCHANNEL_INTERFACE_TN] = lagIntfMap
	}

	/* Handle PORTCHANNEL TABLE */
	resMap["PORTCHANNEL"] = lagMap
	subOpMap[db.ConfigDB] = resMap
	log.Info("subOpMap: ", subOpMap)
	inParams.subOpDataMap[DELETE] = &subOpMap
	return nil
}

var YangToDb_lag_type_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	result := make(map[string]string)
	var err error

	if inParams.param == nil {
		return result, err
	}

	pathInfo := NewPathInfo(inParams.uri)
	ifKey := pathInfo.Var("name")

	log.Infof("Received Mode configuration for path: %s; template: %s vars: %v ifKey: %s", pathInfo.Path, pathInfo.Template, pathInfo.Vars, ifKey)

	var mode string
	err = get_lag_type(inParams.d, &ifKey, &mode)

	t, _ := inParams.param.(ocbinds.E_OpenconfigIfAggregate_AggregationType)
	user_mode := findInMap(LAG_TYPE_MAP, strconv.FormatInt(int64(t), 10))

	if err == nil && mode != user_mode {
		errStr := "Cannot configure Mode for an existing PortChannel: " + ifKey
		err = tlerr.InvalidArgsError{Format: errStr}
		return result, err
	}

	log.Info("YangToDb_lag_type_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " type: ", t)
	result["static"] = user_mode
	return result, nil

}

var DbToYang_lag_type_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	err = validatePortChannel(inParams.d, inParams.key)
	if err != nil {
		log.Infof("DbToYang_lag_type_xfmr Error: %v ", err)
		return result, err
	}

	data := (*inParams.dbDataMap)[inParams.curDb]
	var agg_type ocbinds.E_OpenconfigIfAggregate_AggregationType
	agg_type = ocbinds.OpenconfigIfAggregate_AggregationType_LACP

	lag_type, ok := data[PORTCHANNEL_TABLE][inParams.key].Field["static"]
	if ok {
		if lag_type == "true" {
			agg_type = ocbinds.OpenconfigIfAggregate_AggregationType_STATIC
		}
	}
	result[LAG_TYPE] = ocbinds.E_OpenconfigIfAggregate_AggregationType.ΛMap(agg_type)["E_OpenconfigIfAggregate_AggregationType"][int64(agg_type)].Name
	log.Infof("Lag Type returned from Field Xfmr: %v\n", result)
	return result, err
}

/* Function to update MTU of PortChannel member ports */
func updateMemberPortsMtu(inParams *XfmrParams, lagName *string, mtuValStr *string) error {
	log.Info("Inside updateLagIntfAndMembersMtu")
	var err error
	resMap := make(map[string]string)
	intPortChannelTbl := IntfTypeTblMap[IntfTypePortChannel]

	/* Validate given PortChannel exits */
	err = validatePortChannel(inParams.d, *lagName)
	if err != nil {
		return err
	}
	ts := db.TableSpec{Name: intPortChannelTbl.cfgDb.memberTN + inParams.d.Opts.KeySeparator + *lagName}
	lagKeys, err := inParams.d.GetKeys(&ts)
	if err == nil {
		subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
		intfMap := make(map[string]map[string]db.Value)
		intTbl := IntfTypeTblMap[IntfTypeEthernet]
		resMap["mtu"] = *mtuValStr
		intfMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)

		for key := range lagKeys {
			portName := lagKeys[key].Get(1)
			intfMap[intTbl.cfgDb.portTN][portName] = db.Value{Field: resMap}
			log.Info("Member port ", portName, " updated with mtu ", *mtuValStr)
		}

		subOpMap[db.ConfigDB] = intfMap
		inParams.subOpDataMap[UPDATE] = &subOpMap
	}
	return err
}

// YangToDb_lag_graceful_shutdown_xfmr is a Yang to DB translation graceful_shutdown config
var YangToDb_lag_graceful_shutdown_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	if log.V(3) {
		log.Info("Entering YangToDb_lag_graceful_shutdown_xfmr")
	}
	res_map := make(map[string]string)
	var err error

	if inParams.param == nil {
		if log.V(3) {
			log.Info("YangToDb_lag_graceful_shutdown_xfmr Error: No Params")
		}
		return res_map, err
	}

	err = validatePortChannel(inParams.d, inParams.key)
	if err != nil {
		log.Infof("YangToDb_lag_graceful_shutdown_xfmr Error: %v ", err)
		return res_map, err
	}

	gshutmode_str, _ := inParams.param.(*string)
	if *gshutmode_str != "enable" && *gshutmode_str != "disable" {
		log.Info("Invalid input")
		return res_map, err
	}
	res_map["graceful_shutdown_mode"] = *gshutmode_str
	return res_map, nil
}

// DbToYang_lag_graceful_shutdown_xfmr is a DB to Yang translation overloaded method for graceful_shutdown_mode GET config
var DbToYang_lag_graceful_shutdown_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	if log.V(3) {
		log.Info("Entering DbToYang_lag_graceful_shutdown_xfmr")
	}

	var err error
	result := make(map[string]interface{})

	err = validatePortChannel(inParams.d, inParams.key)
	if err != nil {
		log.Infof("DbToYang_lag_graceful_shutdown_xfmr Error: %v ", err)
		return result, err
	}

	data := (*inParams.dbDataMap)[inParams.curDb]

	gshutmode, ok := data[PORTCHANNEL_TABLE][inParams.key].Field["graceful_shutdown_mode"]
	if ok {
		result["graceful-shutdown-mode"] = gshutmode
	} else {
		if log.V(3) {
			log.Info("DbToYang_lag_graceful_shutdown_xfmr: graceful_shutdown_mode set to default")
		}
		result["graceful-shutdown-mode"] = ""
	}
	return result, err
}
