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
	"errors"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	CFG_INTF_TRACKING_TABLE             = "INTF_TRACKING"
	STATE_INTF_TRACKING_TABLE           = "INTF_TRACKING_TABLE"
	TABLE_AND_KEY_SEPARATOR             = "|"
	INTF_TRACK_FIELD_NAME               = "name"
	INTF_TRACK_FIELD_DESCRIPTION        = "description"
	INTF_TRACK_FIELD_UPSTREAM           = "upstream@"
	INTF_TRACK_FIELD_DOWNSTREAM         = "downstream@"
	INTF_TRACK_FIELD_TIMEOUT            = "timeout"
	INTF_TRACK_FIELD_THRESHOLD_TYPE     = "threshold_type"
	INTF_TRACK_FIELD_THRESHOLD_UP       = "threshold_up"
	INTF_TRACK_FIELD_THRESHOLD_DOWN     = "threshold_down"
	INTF_TRACK_FIELD_DOWNSTREAM_STATUS  = "downstream_status@"
	INTF_TRACK_VALUE_ALL_MCLAG          = "all-mclag"
	INTF_TRACK_FIELD_BRINGUP_START_TIME = "bringup_start_time"
)

type LstApp struct {
	pathInfo   *PathInfo
	ygotRoot   *ygot.GoStruct
	ygotTarget *interface{}

	intfTrackCfgTs *db.TableSpec
	intfTrackStTs  *db.TableSpec

	intfTrackCfgTblMap      map[string]db.Value // Contains the data to be set ie request
	intfUpstreamCfgTblMap   map[string][]string // Contains Interface->Upstreams map
	intfDownstreamCfgTblMap map[string]string   // Contains Interface->Downstream map
	deleteGroups            []string            // Groups to be deleted

	intfTrackCfgTblCache map[string]db.Value // Contains the data retrived from the DB
}

func init() {
	err := register("/openconfig-lst-ext:lst",
		&appInfo{appType: reflect.TypeOf(LstApp{}),
			ygotRootType:  reflect.TypeOf(ocbinds.OpenconfigLstExt_Lst{}),
			isNative:      false,
			tablesToWatch: []*db.TableSpec{&db.TableSpec{Name: CFG_INTF_TRACKING_TABLE}}})

	if err != nil {
		log.Fatal("Register LST app module with App interface failed with error=", err)
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

func (app *LstApp) initialize(data appData) {
	pathInfo := NewPathInfo(data.path)
	*app = LstApp{pathInfo: pathInfo, ygotRoot: data.ygotRoot, ygotTarget: data.ygotTarget}

	app.intfTrackCfgTs = &db.TableSpec{Name: CFG_INTF_TRACKING_TABLE, NoDelete: true}
	app.intfTrackStTs = &db.TableSpec{Name: STATE_INTF_TRACKING_TABLE, NoDelete: true}

	app.intfTrackCfgTblMap = make(map[string]db.Value)
	app.intfUpstreamCfgTblMap = make(map[string][]string)
	app.intfDownstreamCfgTblMap = make(map[string]string)
	app.intfTrackCfgTblCache = make(map[string]db.Value)

	log.Infof("LSTApp:: Path:%v", app.pathInfo.Path)
	log.Infof("LSTApp:: Template:%v", app.pathInfo.Template)
	log.Infof("LSTApp:: URIArgs:%v", app.pathInfo.Vars)
}

func (app *LstApp) getAppRootObject() *ocbinds.OpenconfigLstExt_Lst {
	deviceObj := (*app.ygotRoot).(*ocbinds.Device)
	return deviceObj.Lst
}

func (app *LstApp) translateCreate(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	err = app.translateOcToIntCRUCommon(d, CREATE)

	return keys, err
}

func (app *LstApp) translateUpdate(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	err = app.translateOcToIntCRUCommon(d, UPDATE)

	return keys, err
}

func (app *LstApp) translateReplace(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	err = app.translateOcToIntCRUCommon(d, REPLACE)

	return keys, err
}

func (app *LstApp) translateDelete(d *db.DB) ([]db.WatchKeys, error) {
	var err error
	var keys []db.WatchKeys

	return keys, err
}

func (app *LstApp) translateGet(dbs [db.MaxDB]*db.DB) error {
	var err error

	return err
}

func (app *LstApp) translateSubscribe(dbs [db.MaxDB]*db.DB, path string) ([]notificationAppInfo, error) {
	notSupported := tlerr.NotSupportedError{Format: "Subscribe not supported", Path: path}

	return nil, notSupported
}

func (app *LstApp) translateAction(dbs [db.MaxDB]*db.DB) error {
	err := errors.New("Not supported")
	return err
}

func (app *LstApp) processCreate(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCRUCommon(d, CREATE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *LstApp) processUpdate(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCRUCommon(d, UPDATE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *LstApp) processReplace(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if err = app.processCRUCommon(d, REPLACE); err != nil {
		log.Error(err)
		resp = SetResponse{ErrSrc: AppErr}
	}

	return resp, err
}

func (app *LstApp) processDelete(d *db.DB) (SetResponse, error) {
	var err error
	var resp SetResponse

	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/") {
		err = app.processDeleteGroupData(d)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/interfaces") {
		err = app.processDeleteInterfaceData(d)
	} else {
		name := app.pathInfo.Var("name")
		err = app.deleteGroupsByName(d, name)
	}

	if nil == err {
		err = app.applyData(d)
	}

	return resp, err
}

func (app *LstApp) processGet(dbs [db.MaxDB]*db.DB) (GetResponse, error) {
	var err error
	var payload []byte

	err = app.processLstGet(dbs)
	if err != nil {
		return GetResponse{Payload: payload, ErrSrc: AppErr}, err
	}

	payload, err = generateGetResponsePayload(app.pathInfo.Path, (*app.ygotRoot).(*ocbinds.Device), app.ygotTarget)
	if err != nil {
		return GetResponse{Payload: payload, ErrSrc: AppErr}, err
	}

	return GetResponse{Payload: payload}, err
}

func (app *LstApp) processAction(dbs [db.MaxDB]*db.DB) (ActionResponse, error) {
	var resp ActionResponse
	err := errors.New("Not implemented")

	return resp, err
}

func (app *LstApp) processSubscribe(param dbKeyInfo) (subscribePathResponse, error) {
	var resp subscribePathResponse
	return resp, tlerr.New("Not implemented")
}

/*
 * Translation to convert from Openconfig Format to Internal format
 */
func (app *LstApp) translateOcToIntCRUCommon(d *db.DB, opcode int) error {

	root := app.getAppRootObject()

	// Process Groups first
	if nil != root.LstGroups && len(root.LstGroups.LstGroup) > 0 {
		for name, grpPtr := range root.LstGroups.LstGroup {

			data, found := app.intfTrackCfgTblMap[name]
			if !found {
				data.Field = make(map[string]string)
			}
			if nil != grpPtr.Config {
				if grpPtr.Config.AllMclagsDownstream != nil {
					dsList := data.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
					if *grpPtr.Config.AllMclagsDownstream {
						dsList = append(dsList, INTF_TRACK_VALUE_ALL_MCLAG)
					} else {
						dsList = append(dsList, "")
					}
					data.SetList(INTF_TRACK_FIELD_DOWNSTREAM, dsList)
				}

				if grpPtr.Config.Description != nil {
					data.Set(INTF_TRACK_FIELD_DESCRIPTION, *grpPtr.Config.Description)
				}

				if grpPtr.Config.Timeout != nil {
					data.Set(INTF_TRACK_FIELD_TIMEOUT, strconv.FormatUint(uint64(*grpPtr.Config.Timeout), 10))
				}

				if grpPtr.Config.ThresholdType != ocbinds.OpenconfigLstExt_THRESHOLD_TYPE_UNSET {
					if grpPtr.Config.ThresholdType == ocbinds.OpenconfigLstExt_THRESHOLD_TYPE_ONLINE_PERCENTAGE {
						data.Set(INTF_TRACK_FIELD_THRESHOLD_TYPE, "ONLINE_PERCENTAGE")
					}
				}

				if grpPtr.Config.ThresholdUp != nil {
					data.Set(INTF_TRACK_FIELD_THRESHOLD_UP, strconv.FormatFloat(*grpPtr.Config.ThresholdUp, 'f', 2, 64))
				}

				if grpPtr.Config.ThresholdDown != nil {
					data.Set(INTF_TRACK_FIELD_THRESHOLD_DOWN, strconv.FormatFloat(*grpPtr.Config.ThresholdDown, 'f', 2, 64))
				}
			} else {
				data.Set(INTF_TRACK_FIELD_TIMEOUT, "60")
			}

			app.intfTrackCfgTblMap[name] = data
		}
	}

	// Next process Interfaces
	if nil != root.Interfaces && len(root.Interfaces.Interface) > 0 {
		for id, intfPtr := range root.Interfaces.Interface {
			if nil == intfPtr.InterfaceRef || nil == intfPtr.InterfaceRef.Config ||
				nil == intfPtr.InterfaceRef.Config.Interface {
				goto SkipIntfCheck
			}

			if nil != intfPtr.InterfaceRef.Config.Subinterface {
				return tlerr.NotSupported("SubInterface not supported")
			}

			if id != *intfPtr.InterfaceRef.Config.Interface {
				return tlerr.NotSupported("Different ID %s and Interface name %s not supported", id, *intfPtr.InterfaceRef.Config.Interface)
			}

		SkipIntfCheck:
			if nil != intfPtr.UpstreamGroups && nil != intfPtr.DownstreamGroup {
				return tlerr.InvalidArgs("Interface %s has both upstream and downstream groups", id)
			}
			if nil != intfPtr.UpstreamGroups {
				if !isInterfaceNameValid(id, false) {
					return tlerr.InvalidArgs("Interface %s is invalid for upstream", id)
				}
				for upstr := range intfPtr.UpstreamGroups.UpstreamGroup {
					// Check group is part of request
					ifName := *utils.GetNativeNameFromUIName(&id)
					upstreams := app.intfUpstreamCfgTblMap[ifName]
					upstreams = append(upstreams, upstr)
					app.intfUpstreamCfgTblMap[ifName] = upstreams
				}
			}

			if nil != intfPtr.DownstreamGroup && nil != intfPtr.DownstreamGroup.Config &&
				nil != intfPtr.DownstreamGroup.Config.GroupName {
				if !isInterfaceNameValid(id, true) {
					return tlerr.InvalidArgs("Interface %s is invalid for downstream", id)
				}
				ifName := *utils.GetNativeNameFromUIName(&id)
				app.intfDownstreamCfgTblMap[ifName] = *intfPtr.DownstreamGroup.Config.GroupName
			}
		}

		// TODO Check with State DB if any port is common in configured upstream and operational downstream
	}

	log.Infof("Group data:%v", app.intfTrackCfgTblMap)
	log.Infof("Upstream data:%v", app.intfUpstreamCfgTblMap)
	log.Infof("Downstream data:%v", app.intfDownstreamCfgTblMap)
	log.Infof("Scheduled delete:%v", app.deleteGroups)

	return nil
}

func (app *LstApp) processCRUCommon(d *db.DB, opcode int) error {
	var err error

	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/lst-groups") {
		err = app.processCRUCommonGroups(d, opcode)
	} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/interfaces") {
		err = app.processCRUCommonInterfaces(d, opcode)
	} else {
		err = app.processCRUCommonRoot(d, opcode)
	}
	if err == nil {
		err = app.applyData(d)
	}

	return err
}

func (app *LstApp) processCRUCommonGroups(d *db.DB, opcode int) error {
	log.Infof("Opcode:%v", opcode)
	log.Info(app.intfTrackCfgTblMap)

	if opcode == CREATE {
		if app.pathInfo.Template != "/openconfig-lst-ext:lst/lst-groups/lst-group{}" {
			// Check if Group is already created
			for name := range app.intfTrackCfgTblMap {
				_, err := app.getGroupDatafromDB(d, name)
				if nil == err {
					return tlerr.AlreadyExists("%s group already exists", name)
				} else if !isNotFoundError(err) {
					return err
				}
			}
		}
	} else if opcode == UPDATE {
		// Update is always merge the requested data with data from DB
		// Pull the data from DB and merge it
		for name, grpReqData := range app.intfTrackCfgTblMap {
			grpDbData, err := app.getGroupDatafromDB(d, name)
			if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/lst-groups/lst-group{}") {
				if nil != err {
					return err
				}
			} else if nil != err && !isNotFoundError(err) {
				return err
			} else if isNotFoundError(err) {
				grpDbData.Field = make(map[string]string)
			}

			for field, val := range grpReqData.Field {
				if field == INTF_TRACK_FIELD_DOWNSTREAM {
					lst := grpDbData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
					if val == "" {
						lst = removeElement(lst, INTF_TRACK_VALUE_ALL_MCLAG)
					} else {
						lst = uniqueElements(append(lst, val))
					}
					grpDbData.SetList(INTF_TRACK_FIELD_DOWNSTREAM, lst)
				} else {
					grpDbData.Set(field, val)
				}
			}
			app.intfTrackCfgTblMap[name] = grpDbData
		}
	} else { // REPLACE
		if app.pathInfo.Template == "/openconfig-lst-ext:lst" ||
			app.pathInfo.Template == "/openconfig-lst-ext:lst/lst-groups" ||
			app.pathInfo.Template == "/openconfig-lst-ext:lst/lst-groups/lst-group" {

			// Delete all groups which are not part of the request.
			keys, err := d.GetKeys(app.intfTrackCfgTs)
			if err != nil {
				return err
			}
			for _, k := range keys {
				app.deleteGroups = append(app.deleteGroups, k.Comp[0])
			}
			for name := range app.intfTrackCfgTblMap {
				if contains(app.deleteGroups, name) {
					app.deleteGroups = removeElement(app.deleteGroups, name)
				}
			}
		} else if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/lst-groups/lst-group{}") {
			// Group specific replace.
			for name, grpReqData := range app.intfTrackCfgTblMap {
				grpDbData, err := app.getGroupDatafromDB(d, name)
				if nil != err {
					return err
				}
				if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/") {
					log.Info("Specific field replace")
					// Request is only for these specific fields
					for field, val := range grpReqData.Field {
						if field == INTF_TRACK_FIELD_DOWNSTREAM {
							lst := grpDbData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
							if val == "" {
								lst = removeElement(lst, INTF_TRACK_VALUE_ALL_MCLAG)
							} else {
								lst = uniqueElements(append(lst, val))
							}
							grpDbData.SetList(INTF_TRACK_FIELD_DOWNSTREAM, lst)
						} else {
							grpDbData.Set(field, val)
						}
					}
					app.intfTrackCfgTblMap[name] = grpDbData
				} else {
					log.Info("Replace group config")
					// Request is for full group replace. Preserve the upstream and downstream which is set by Interface subtree
					upstr := grpDbData.GetList(INTF_TRACK_FIELD_UPSTREAM)
					if len(upstr) > 0 {
						grpReqData.SetList(INTF_TRACK_FIELD_UPSTREAM, upstr)
					}

					dbDwnstr := grpDbData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
					dwstr := grpReqData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
					if len(dwstr) == 0 && contains(dbDwnstr, INTF_TRACK_VALUE_ALL_MCLAG) {
						dbDwnstr = removeElement(dbDwnstr, INTF_TRACK_VALUE_ALL_MCLAG)
						grpReqData.SetList(INTF_TRACK_FIELD_UPSTREAM, dbDwnstr)
					}
					// Everything as came with request.
					app.intfTrackCfgTblMap[name] = grpReqData
				}
			}
		} else {
			return tlerr.New("Unknown/Unhandled URI")
		}
	}

	return nil
}

func (app *LstApp) processCRUCommonInterfaces(d *db.DB, opcode int) error {
	// Do pre-processing for REPLACE first
	if REPLACE == opcode {
		// For the following URIs, delete all existing upstream and downstream interfaces
		app.processDeleteInterfaceData(d)
	}

	err := app.processUpstreamInterfaces(d, opcode)
	if nil != err {
		return err
	}
	err = app.processDownstreamInterfaces(d, opcode)
	if nil != err {
		return err
	}

	return nil
}

func (app *LstApp) processUpstreamInterfaces(d *db.DB, opcode int) error {
	for intf, groups := range app.intfUpstreamCfgTblMap {
		for _, group := range groups {
			if contains(app.deleteGroups, group) {
				log.Infof("Group %s is scheduled for delete", group)
				return tlerr.InvalidArgs("Group %s will be deleted in the request. Cant be used as upstream group for %s", group, intf)
			}

			grpData, found := app.intfTrackCfgTblMap[group]
			if !found {
				var err error
				grpData, err = app.getGroupDatafromDB(d, group)
				if err != nil {
					log.Error(err)
					return err
				}
			}

			lst := grpData.GetList(INTF_TRACK_FIELD_UPSTREAM)
			if opcode == CREATE && contains(lst, intf) {
				return tlerr.AlreadyExists("Intf:%s is already part of upstream interfaces for group %s", intf, group)
			}

			lst = uniqueElements(append(lst, intf))
			grpData.SetList(INTF_TRACK_FIELD_UPSTREAM, lst)
			app.intfTrackCfgTblMap[group] = grpData
		}
	}

	return nil
}

func (app *LstApp) processDownstreamInterfaces(d *db.DB, opcode int) error {
	for intf, group := range app.intfDownstreamCfgTblMap {
		if contains(app.deleteGroups, group) {
			log.Infof("Group %s is scheduled for delete", group)
			return tlerr.InvalidArgs("Group %s will be deleted in the request. Cant be used as downstream group for %s", group, intf)
		}

		grpData, found := app.intfTrackCfgTblMap[group]
		if !found {
			var err error
			grpData, err = app.getGroupDatafromDB(d, group)
			if err != nil {
				log.Error(err)
				return err
			}
		}
		lst := grpData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
		if opcode == CREATE && contains(lst, intf) {
			return tlerr.AlreadyExists("Intf:%s is already part of downstream interfaces for group %s", intf, group)
		}

		// Each interface can be downstream for 1 group
		keys, err := d.GetKeys(app.intfTrackCfgTs)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.Comp[0] == group {
				continue
			}
			if contains(app.deleteGroups, k.Comp[0]) {
				continue
			}

			tmpGrpData, _ := app.getGroupDatafromDB(d, k.Comp[0])
			dlst := tmpGrpData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
			if contains(dlst, intf) {
				return tlerr.AlreadyExists("%s is already downstream for group %s", intf, k.Comp[0])
			}
		}

		lst = uniqueElements(append(lst, intf))
		grpData.SetList(INTF_TRACK_FIELD_DOWNSTREAM, lst)
		app.intfTrackCfgTblMap[group] = grpData
	}

	return nil
}

func (app *LstApp) processCRUCommonRoot(d *db.DB, opcode int) error {
	root := app.getAppRootObject()

	if root.LstGroups != nil {
		// Payload contains groups. Process & Validate
		err := app.processCRUCommonGroups(d, opcode)
		if err != nil {
			return nil
		}
	}

	if root.Interfaces != nil {
		err := app.processCRUCommonInterfaces(d, opcode)
		if err != nil {
			return nil
		}
	}

	return nil
}

func (app *LstApp) removeGroupInterface(d *db.DB, group string, field string, intf string) error {
	log.Infof("Grp:%s Intf:%s Field:%s", group, intf, field)

	var groups []string
	if group == "" {
		keys, err := d.GetKeys(app.intfTrackCfgTs)
		if err != nil {
			return err
		}
		for _, k := range keys {
			groups = append(groups, k.Comp[0])
		}
	} else {
		groups = append(groups, group)
	}
	log.Infof("Applicable Groups:%v", groups)

	for _, group := range groups {
		grpData, found := app.intfTrackCfgTblMap[group]
		if !found {
			var err error
			grpData, err = app.getGroupDatafromDB(d, group)
			if isNotFoundError(err) {
				continue
			} else if nil != err {
				return err
			}
		}

		if grpData.Has(field) {
			if field == INTF_TRACK_FIELD_DOWNSTREAM {
				lst := grpData.GetList(field)
				if intf == "" {
					if contains(lst, INTF_TRACK_VALUE_ALL_MCLAG) {
						grpData.SetList(field, []string{INTF_TRACK_VALUE_ALL_MCLAG})
					} else {
						grpData.Remove(field)
					}
				} else {
					lst = removeElement(lst, intf)
					if len(lst) > 0 {
						grpData.SetList(field, lst)
					} else {
						grpData.Remove(field)
					}
				}
			} else {
				lst := grpData.GetList(field)
				if intf == "" {
					grpData.Remove(field)
				} else {
					lst = removeElement(lst, intf)
					if len(lst) > 0 {
						grpData.SetList(field, lst)
					} else {
						grpData.Remove(field)
					}
				}
			}
			// Finally update the new value
			app.intfTrackCfgTblMap[group] = grpData
		} else {
			log.Infof("Group %s doesnt have %s", group, field)
		}
	}

	return nil
}

func (app *LstApp) processDeleteGroupData(d *db.DB) error {
	grpname := app.pathInfo.Var("name")
	grpData, err := app.getGroupDatafromDB(d, grpname)
	if err != nil {
		if isNotFoundError(err) {
			return nil
		}

		return err
	}

	mod := true
	switch app.pathInfo.Template {
	case "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/description":
		grpData.Remove(INTF_TRACK_FIELD_DESCRIPTION)
		mod = true
	case "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/timeout":
		grpData.Set(INTF_TRACK_FIELD_TIMEOUT, "60")
		mod = true
	case "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/all-mclags-downstream":
		dsList := grpData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
		if contains(dsList, INTF_TRACK_VALUE_ALL_MCLAG) {
			grpData.SetList(INTF_TRACK_FIELD_DOWNSTREAM, removeElement(dsList, INTF_TRACK_VALUE_ALL_MCLAG))
			mod = true
		}
	case "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/threshold-type":
		grpData.Remove(INTF_TRACK_FIELD_THRESHOLD_TYPE)
		grpData.Remove(INTF_TRACK_FIELD_THRESHOLD_UP)
		grpData.Remove(INTF_TRACK_FIELD_THRESHOLD_DOWN)
		mod = true
	case "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/threshold-up":
		grpData.Remove(INTF_TRACK_FIELD_THRESHOLD_UP)
		mod = true
	case "/openconfig-lst-ext:lst/lst-groups/lst-group{}/config/threshold-down":
		grpData.Remove(INTF_TRACK_FIELD_THRESHOLD_DOWN)
		mod = true
	default:
		return tlerr.NotSupported("")
	}

	if mod {
		app.intfTrackCfgTblMap[grpname] = grpData
	}

	return nil
}

func (app *LstApp) processDeleteInterfaceData(d *db.DB) error {
	intf := app.pathInfo.Var("id")
	if intf != "" && !isInterfaceNameValid(intf, false) {
		return tlerr.InvalidArgs("%s intf name invalid", intf)
	}

	if isSubtreeRequest(app.pathInfo.Template, "/openconfig-lst-ext:lst/interfaces/interface{}/upstream-groups") {
		err := app.removeGroupInterface(d, app.pathInfo.Var("group-name"), INTF_TRACK_FIELD_UPSTREAM, app.pathInfo.Var("id"))
		if nil != err {
			return err
		}
	} else if app.pathInfo.Template == "/openconfig-lst-ext:lst/interfaces/interface{}/downstream-group" {
		if !isInterfaceNameValid(intf, true) {
			return tlerr.InvalidArgs("%s intf name invalid", intf)
		}
		err := app.removeGroupInterface(d, "", INTF_TRACK_FIELD_DOWNSTREAM, app.pathInfo.Var("id"))
		if nil != err {
			return err
		}
	} else {
		err := app.removeGroupInterface(d, "", INTF_TRACK_FIELD_UPSTREAM, intf)
		if nil != err {
			return err
		}
		err = app.removeGroupInterface(d, "", INTF_TRACK_FIELD_DOWNSTREAM, intf)
		if nil != err {
			return err
		}
	}

	return nil
}

func (app *LstApp) deleteGroupsByName(d *db.DB, name string) error {
	if name == "" {
		keys, err := d.GetKeys(app.intfTrackCfgTs)
		if err != nil {
			return err
		}

		for _, k := range keys {
			app.deleteGroups = append(app.deleteGroups, k.Comp[0])
		}
	} else {
		app.deleteGroups = append(app.deleteGroups, name)
	}

	return nil
}

func (app *LstApp) applyData(d *db.DB) error {
	for _, name := range app.deleteGroups {
		err := d.DeleteEntry(app.intfTrackCfgTs, db.Key{Comp: []string{name}})
		if err != nil {
			return nil
		}
	}

	for name, grpData := range app.intfTrackCfgTblMap {
		grpData.Field["NULL"] = "NULL"
		if _, found := app.intfTrackCfgTblCache[name]; !found {
			err := d.CreateEntry(app.intfTrackCfgTs, db.Key{Comp: []string{name}}, grpData)
			if err != nil {
				return err
			}
		} else {
			err := d.SetEntry(app.intfTrackCfgTs, db.Key{Comp: []string{name}}, grpData)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func isInterfaceNameValid(intf string, isDown bool) bool {
	if isDown {
		return strings.HasPrefix(intf, "Eth") || strings.HasPrefix(intf, "PortChannel")
	} else {
		return strings.HasPrefix(intf, "Eth") || strings.HasPrefix(intf, "PortChannel") || strings.HasPrefix(intf, "Vlan")
	}
}

/*
 * Translation to convert from Internal format to Openconfig format
 */
func (app *LstApp) processLstGet(dbs [db.MaxDB]*db.DB) error {
	root := app.getAppRootObject()

	if *app.ygotTarget == root {
		ygot.BuildEmptyTree(root)
	}

	if nil != root.LstGroups {
		if nil == root.LstGroups.LstGroup || len(root.LstGroups.LstGroup) == 0 {
			keys, err := dbs[db.ConfigDB].GetKeys(app.intfTrackCfgTs)
			if err != nil {
				return err
			}

			for _, k := range keys {
				ptr, err := root.LstGroups.NewLstGroup(k.Comp[0])
				if err != nil {
					return err
				}
				ygot.BuildEmptyTree(ptr)
			}
		}
		for _, grpPtr := range root.LstGroups.LstGroup {
			err := app.processLstGroupsGet(dbs, grpPtr)
			if nil != err {
				return err
			}
		}
	}

	if nil != root.Interfaces {
		keys, err := dbs[db.ConfigDB].GetKeys(app.intfTrackCfgTs)
		if err != nil {
			return err
		}

		all_intf := []string{}
		for _, k := range keys {
			grpData, err := app.getGroupDatafromDB(dbs[db.ConfigDB], k.Comp[0])
			if err != nil {
				return err
			}

			/* Convert to UI names */
			upPorts := []string{}
			for _, upIntf := range grpData.GetList(INTF_TRACK_FIELD_UPSTREAM) {
				uiName := *utils.GetUINameFromNativeName(&upIntf)
				upPorts = append(upPorts, uiName)
				app.intfUpstreamCfgTblMap[uiName] = append(app.intfUpstreamCfgTblMap[uiName], k.Comp[0])
			}
			grpData.SetList(INTF_TRACK_FIELD_UPSTREAM, upPorts)

			downPorts := []string{}
			for _, downIntf := range grpData.GetList(INTF_TRACK_FIELD_DOWNSTREAM) {
				uiName := *utils.GetUINameFromNativeName(&downIntf)
				downPorts = append(downPorts, uiName)
			}
			grpData.SetList(INTF_TRACK_FIELD_DOWNSTREAM, downPorts)

			/* Convert State DB to UI names */
			grpStateData, stErr := dbs[db.StateDB].GetEntry(app.intfTrackStTs, k)
			if stErr != nil {
				return stErr
			}

			upPorts = []string{}
			for _, upIntf := range grpStateData.GetList(INTF_TRACK_FIELD_UPSTREAM) {
				uiName := *utils.GetUINameFromNativeName(&upIntf)
				upPorts = append(upPorts, uiName)
			}
			grpStateData.SetList(INTF_TRACK_FIELD_UPSTREAM, upPorts)

			downPorts = []string{}
			for _, downIntf := range grpStateData.GetList(INTF_TRACK_FIELD_DOWNSTREAM) {
				uiName := *utils.GetUINameFromNativeName(&downIntf)
				downPorts = append(downPorts, uiName)
				app.intfDownstreamCfgTblMap[uiName] = k.Comp[0]
			}
			grpStateData.SetList(INTF_TRACK_FIELD_DOWNSTREAM, downPorts)

			app.intfTrackCfgTblMap[k.Comp[0]] = grpStateData
			all_intf = append(all_intf, grpData.GetList(INTF_TRACK_FIELD_UPSTREAM)...)
			all_intf = append(all_intf, grpStateData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)...)

			log.Infof("Upstream:%v", app.intfUpstreamCfgTblMap)
			log.Infof("Downstream:%v", app.intfDownstreamCfgTblMap)
		}

		if nil == root.Interfaces.Interface || len(root.Interfaces.Interface) == 0 {
			all_intf = uniqueElements(all_intf)

			for _, intf := range all_intf {
				intfPtr, err := root.Interfaces.NewInterface(intf)
				if nil != err {
					return err
				}

				ygot.BuildEmptyTree(intfPtr)
				if _, found := app.intfUpstreamCfgTblMap[intf]; !found {
					log.Infof("Intf:%s is not upstream", intf)
					intfPtr.UpstreamGroups = nil
				}
				if _, found := app.intfDownstreamCfgTblMap[intf]; !found {
					log.Infof("Intf:%s is not downstream", intf)
					intfPtr.DownstreamGroup = nil
				}
			}
		}

		for _, intfPtr := range root.Interfaces.Interface {
			err := app.processLstInterfaceGet(dbs, intfPtr)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (app *LstApp) processLstGroupsGet(dbs [db.MaxDB]*db.DB, grpPtr *ocbinds.OpenconfigLstExt_Lst_LstGroups_LstGroup) error {
	grpData, err := app.getGroupDatafromDB(dbs[db.ConfigDB], *grpPtr.Name)
	if err != nil {
		return err
	}

	if nil == grpPtr.Config || nil == grpPtr.State {
		ygot.BuildEmptyTree(grpPtr)
	}

	grpPtr.Config.Name = grpPtr.Name
	grpPtr.State.Name = grpPtr.Name
	grpPtr.Config.Type = ocbinds.OpenconfigLstExt_GROUP_TYPE_GROUP_L3
	grpPtr.State.Type = ocbinds.OpenconfigLstExt_GROUP_TYPE_GROUP_L3

	dwnStr := grpData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
	all_mclag := contains(dwnStr, INTF_TRACK_VALUE_ALL_MCLAG)
	if all_mclag {
		grpPtr.Config.AllMclagsDownstream = &all_mclag
		grpPtr.State.AllMclagsDownstream = &all_mclag
	}

	descr := grpData.Get(INTF_TRACK_FIELD_DESCRIPTION)
	if descr != "" {
		grpPtr.Config.Description = &descr
		grpPtr.State.Description = &descr
	}

	tmout := grpData.Get(INTF_TRACK_FIELD_TIMEOUT)
	var tmout_16 uint16 = 0
	if tmout != "" {
		tmout_64, _ := strconv.ParseUint(tmout, 10, 16)
		tmout_16 = uint16(tmout_64)
		grpPtr.Config.Timeout = &tmout_16
		grpPtr.State.Timeout = &tmout_16
	}

	thr_type := grpData.Get(INTF_TRACK_FIELD_THRESHOLD_TYPE)
	if thr_type == "ONLINE_PERCENTAGE" {
		grpPtr.Config.ThresholdType = ocbinds.OpenconfigLstExt_THRESHOLD_TYPE_ONLINE_PERCENTAGE
		grpPtr.State.ThresholdType = ocbinds.OpenconfigLstExt_THRESHOLD_TYPE_ONLINE_PERCENTAGE
	}

	thr_up := grpData.Get(INTF_TRACK_FIELD_THRESHOLD_UP)
	if thr_up != "" {
		thr_up_64, _ := strconv.ParseFloat(thr_up, 64)
		grpPtr.Config.ThresholdUp = &thr_up_64
		grpPtr.State.ThresholdUp = &thr_up_64
	}

	thr_down := grpData.Get(INTF_TRACK_FIELD_THRESHOLD_DOWN)
	if thr_down != "" {
		thr_down_64, _ := strconv.ParseFloat(thr_down, 64)
		grpPtr.Config.ThresholdDown = &thr_down_64
		grpPtr.State.ThresholdDown = &thr_down_64
	}

	grpStateData, stErr := dbs[db.StateDB].GetEntry(app.intfTrackStTs, db.Key{Comp: []string{*grpPtr.Name}})
	if stErr == nil {
		epoch_str := grpStateData.Get(INTF_TRACK_FIELD_BRINGUP_START_TIME)
		epoch, _ := strconv.ParseInt(epoch_str, 10, 64)
		if epoch != 0 {
			now := time.Now()
			secs := now.Unix()
			diff := uint16(secs - epoch)
			if diff < tmout_16 {
				diff = tmout_16 - diff
			} else {
				diff = 0
			}
			grpPtr.State.BringupRemainingTime = &diff
		}
	}

	return nil
}

func (app *LstApp) processLstInterfaceGet(dbs [db.MaxDB]*db.DB, intfPtr *ocbinds.OpenconfigLstExt_Lst_Interfaces_Interface) error {
	_, upFound := app.intfUpstreamCfgTblMap[*intfPtr.Id]
	_, downFound := app.intfDownstreamCfgTblMap[*intfPtr.Id]
	if !upFound && !downFound {
		return tlerr.NotFound("Intf %s is not associated with any groups", *intfPtr.Id)
	}

	ygot.BuildEmptyTree(intfPtr)

	ygot.BuildEmptyTree(intfPtr.Config)
	intfPtr.Config.Id = intfPtr.Id

	ygot.BuildEmptyTree(intfPtr.State)
	intfPtr.State.Id = intfPtr.Id

	ygot.BuildEmptyTree(intfPtr.InterfaceRef)
	ygot.BuildEmptyTree(intfPtr.InterfaceRef.Config)
	ygot.BuildEmptyTree(intfPtr.InterfaceRef.State)
	intfPtr.InterfaceRef.Config.Interface = intfPtr.Id
	intfPtr.InterfaceRef.State.Interface = intfPtr.Id

	if upFound {
		err := app.processLstInterfaceUpstreamGet(dbs, *intfPtr.Id, intfPtr.UpstreamGroups)
		if err != nil {
			return err
		}
	} else {
		intfPtr.UpstreamGroups = nil
	}

	if downFound {
		err := app.processLstInterfaceDownstreamGet(dbs, *intfPtr.Id, intfPtr.DownstreamGroup)
		if err != nil {
			return err
		}
	} else {
		intfPtr.DownstreamGroup = nil
	}

	return nil
}

func (app *LstApp) processLstInterfaceUpstreamGet(dbs [db.MaxDB]*db.DB, intf string,
	upIntfPtr *ocbinds.OpenconfigLstExt_Lst_Interfaces_Interface_UpstreamGroups) error {

	log.Infof("Filling upstream info for %v", intf)

	if nil == upIntfPtr.UpstreamGroup || len(upIntfPtr.UpstreamGroup) == 0 {
		upGrps, found := app.intfUpstreamCfgTblMap[intf]
		if !found {
			return tlerr.NotFound("Intf %s is not configured as upstream for any groups", intf)
		}

		log.Infof("Groups are %v", upGrps)
		for _, upgrp := range upGrps {
			upGrpPtr, err := upIntfPtr.NewUpstreamGroup(upgrp)
			if nil != err {
				log.Error(err)
				return err
			}

			ygot.BuildEmptyTree(upGrpPtr)
		}
	}

	for grpName, grpPtr := range upIntfPtr.UpstreamGroup {
		if !contains(app.intfUpstreamCfgTblMap[intf], grpName) {
			return tlerr.NotFound("Intf %s is not configured as upstream of %s", intf, grpName)
		}
		ygot.BuildEmptyTree(grpPtr)
		ygot.BuildEmptyTree(grpPtr.Config)
		ygot.BuildEmptyTree(grpPtr.State)
		grpPtr.Config.GroupName = grpPtr.GroupName
		grpPtr.State.GroupName = grpPtr.GroupName
	}

	return nil
}

func (app *LstApp) processLstInterfaceDownstreamGet(dbs [db.MaxDB]*db.DB, intf string,
	downIntfPtr *ocbinds.OpenconfigLstExt_Lst_Interfaces_Interface_DownstreamGroup) error {

	log.Infof("Filling Downstream info for %v", intf)

	grpName, found := app.intfDownstreamCfgTblMap[intf]
	if !found {
		return tlerr.NotFound("Intf %s is not configured as downstream of any groups", intf)
	}

	cfgGrpData := app.intfTrackCfgTblCache[grpName]
	cfgDownPorts := cfgGrpData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)

	ygot.BuildEmptyTree(downIntfPtr)
	if contains(cfgDownPorts, intf) {
		downIntfPtr.Config.GroupName = &grpName
	} else {
		log.Infof("Intf %v not present in config %v. Populate only state info", &intf, cfgDownPorts)
	}
	downIntfPtr.State.GroupName = &grpName

	grpStateData := app.intfTrackCfgTblMap[grpName]

	dsPorts := grpStateData.GetList(INTF_TRACK_FIELD_DOWNSTREAM)
	dsStatus := grpStateData.GetList(INTF_TRACK_FIELD_DOWNSTREAM_STATUS)

	portIdx, _ := indexOf(dsPorts, intf)
	status := dsStatus[portIdx]

	disabled := status == "Disabled"
	downIntfPtr.State.Disabled = &disabled

	return nil
}

/*
 * All other helpers
 */
func (app *LstApp) getGroupDatafromDB(d *db.DB, name string) (db.Value, error) {
	log.Infof("Get data from DB for Group %s", name)

	if cacheData, found := app.intfTrackCfgTblCache[name]; found {
		log.Infof("return data from cache %v", cacheData)
		return cacheData, nil
	}

	dbGrp, err := d.GetEntry(app.intfTrackCfgTs, db.Key{Comp: []string{name}})
	if err != nil {
		log.Error(err)
		return dbGrp, err
	}

	log.Infof("Group:%s Data:%v", name, dbGrp)
	app.intfTrackCfgTblCache[name] = dbGrp

	return dbGrp, nil
}
