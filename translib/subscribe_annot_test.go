////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2021 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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

// +build subscribe_annot

package translib

import (
	"testing"

	"github.com/Azure/sonic-mgmt-common/translib/db"
)

// tamSwitchConfigNInfo returns mappings for /tam/switch/config
func tamSwitchConfigNInfo(subpath string) *notificationAppInfo {
	nInfo := &notificationAppInfo{
		dbno:                db.ConfigDB,
		table:               &db.TableSpec{Name: "TAM_SWITCH_TABLE"},
		key:                 db.NewKey("global"),
		isOnChangeSupported: true,
		mInterval:           20,
		pType:               OnChange,
	}
	switch subpath {
	case "*":
		nInfo.setFields(`{"":{"switch-id": "switch-id", "enterprise-id": "enterprise-id"}}`)
	default:
		nInfo.setFields(`{"":{"` + subpath + `": ""}}`)
	}
	return nInfo
}

// tamSwitchStateNInfo returns mappings for /tam/switch/state
func tamSwitchStateNInfo(subpath string) *notificationAppInfo {
	nInfo := &notificationAppInfo{
		dbno:                db.ApplDB,
		table:               &db.TableSpec{Name: "TAM_APPL_SWITCH_TABLE"},
		key:                 db.NewKey("global"),
		isOnChangeSupported: false,
		mInterval:           20,
		pType:               Sample,
	}
	switch subpath {
	case "*":
		nInfo.setFields(`{"":{"switch-id": "switch-id", "enterprise-id": "enterprise-id",
			"op-switch-id": "op-switch-id", "op-enterprise-id": "op-enterprise-id"}}`)
	default:
		nInfo.setFields(`{"":{"` + subpath + `": ""}}`)
	}
	return nInfo
}

// ON_CHANGE for /tam/switch

func TestSubscribeOnChange_tam_switch(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch", OnChange)
	tv.VerifyCount(translErr, 0)
}

func TestSubscribeOnChange_tam_switch_config(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/config", OnChange)
	tv.VerifyCount(1, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/config", tamSwitchConfigNInfo("*"))
}

func TestSubscribeOnChange_tam_switch_config_id(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/config/switch-id", OnChange)
	tv.VerifyCount(1, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/config/switch-id", tamSwitchConfigNInfo("switch-id"))
}

func TestSubscribeOnChange_tam_switch_state(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/state", OnChange)
	tv.VerifyCount(translErr, 0)
}

func TestSubscribeOnChange_tam_switch_state_id(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/state/switch-id", OnChange)
	tv.VerifyCount(translErr, 0)
}

// SAMPLE for /tam/switch

func TestSubscribeSample_tam_switch(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch", Sample)
	tv.VerifyCount(2, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/config", tamSwitchConfigNInfo("*"))
	tv.VerifyTarget("/openconfig-tam:tam/switch/state", tamSwitchStateNInfo("*"))
}

func TestSubscribeSample_tam_switch_config(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/config", Sample)
	tv.VerifyCount(1, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/config", tamSwitchConfigNInfo("*"))
}

func TestSubscribeSample_tam_switch_state(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/state", Sample)
	tv.VerifyCount(1, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/state", tamSwitchStateNInfo("*"))
}

// TARGET_DEFINED for /tam/switch

func TestSubscribeTrgtDef_tam_switch(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch", TargetDefined)
	tv.VerifyCount(2, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/config", tamSwitchConfigNInfo("*"))
	tv.VerifyTarget("/openconfig-tam:tam/switch/state", tamSwitchStateNInfo("*"))
}

func TestSubscribeTrgtDef_tam_switch_config(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/config", TargetDefined)
	tv.VerifyCount(2, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/config", tamSwitchConfigNInfo("*"))
}

func TestSubscribeTrgtDef_tam_switch_state(t *testing.T) {
	tv := testTranslateSubscribe(t, "/openconfig-tam:tam/switch/state", TargetDefined)
	tv.VerifyCount(1, 0)
	tv.VerifyTarget("/openconfig-tam:tam/switch/state", tamSwitchStateNInfo("*"))
}
