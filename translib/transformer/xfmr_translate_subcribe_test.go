//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Dell, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	. "github.com/Azure/sonic-mgmt-common/translib/transformer"
)

func Test_TranslateSubscribe_OCYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Translate Subscribe OC yang ++++++++++++")
	var xfmrTrSubInfo XfmrTranslateSubscribeInfo
	xfmrTrSubInfo.DbDataMap = make(RedisDbMap)
	for i := db.ApplDB; i < db.MaxDB; i++ {
		xfmrTrSubInfo.DbDataMap[i] = make(map[string]map[string]db.Value)
	}
	/*Static case interface state mtu*/
	xfmrTrSubInfo.DbDataMap = nil
	xfmrTrSubInfo.MinInterval = 0
	xfmrTrSubInfo.NeedCache = true
	xfmrTrSubInfo.PType = Sample
	xfmrTrSubInfo.OnChange = false
	path := "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/state/mtu"
	t.Run("Static case on change disable(interface state mtu)", translateSubscribeRequest(path, xfmrTrSubInfo, false, nil))
	time.Sleep(1 * time.Second)
	/*********************************/

	/*Static case interface config mtu*/
	//expErr := tlerr.NotSupportedError("Subscribe not supported.")
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/config/mtu"
	xfmrTrSubInfo.DbDataMap = nil
	xfmrTrSubInfo.MinInterval = 0
	xfmrTrSubInfo.NeedCache = true
	xfmrTrSubInfo.PType = Sample
	xfmrTrSubInfo.OnChange = false
	t.Run("Static case on change disable(interface config mtu)", translateSubscribeRequest(path, xfmrTrSubInfo, false, nil))
	time.Sleep(1 * time.Second)
	/********************************/

	/* Static case interface subinterfaces */
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/subinterfaces"
	expErr := tlerr.NotSupportedError{Format: "Subscribe not supported", Path: path}
	t.Run("Static case on change disable(interface subinterfaces)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/******************/

	/*Static case interface state oper-status, native format key*/
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/state/oper-status"
	xfmrTrSubInfo.DbDataMap = make(RedisDbMap)
	xfmrTrSubInfo.DbDataMap[0] = map[string]map[string]db.Value{"PORT_TABLE": map[string]db.Value{"Ethernet4": {}}}
	xfmrTrSubInfo.MinInterval = 0
	xfmrTrSubInfo.NeedCache = true
	xfmrTrSubInfo.PType = OnChange
	xfmrTrSubInfo.OnChange = true
	t.Run("Static case on change enable(interface state oper-status)", translateSubscribeRequest(path, xfmrTrSubInfo, false, nil))
	time.Sleep(1 * time.Second)
	/*****************************/

	/*Static case interface state oper-status, non-native/alias format key*/
	path = "/openconfig-interfaces:interfaces/interface[name=Eth1/4]/state/oper-status"
	xfmrTrSubInfo.DbDataMap = make(RedisDbMap)
	xfmrTrSubInfo.DbDataMap[0] = map[string]map[string]db.Value{"PORT_TABLE": map[string]db.Value{"Ethernet4": {}}}
	xfmrTrSubInfo.MinInterval = 0
	xfmrTrSubInfo.NeedCache = true
	xfmrTrSubInfo.PType = OnChange
	xfmrTrSubInfo.OnChange = true
	url := "/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST[name=localhost]/intf_naming_mode"
	url_body_json := "{\"sonic-device-metadata:intf_naming_mode\": \"standard\"}"
	t.Run("Enable Alias mode", processSetRequest(url, url_body_json, "PATCH", false))
	time.Sleep(2 * time.Second)
	t.Run("Static case on change enable(non-native key interface state oper-status)", translateSubscribeRequest(path, xfmrTrSubInfo, false, nil))
	time.Sleep(1 * time.Second)
	url = "/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST[name=localhost]/intf_naming_mode"
	t.Run("Disable Alias mode", processDeleteRequest(url, false))
	/*****************************/

	/*Static case interface  key-leaf*/
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/name"
	xfmrTrSubInfo.DbDataMap = nil
	xfmrTrSubInfo.PType = Sample
	xfmrTrSubInfo.OnChange = false
	t.Run("Static case on change disable(interface list key-leaf)", translateSubscribeRequest(path, xfmrTrSubInfo, false))
	time.Sleep(1 * time.Second)
	/*******************************/

	/*Static case interface  list with key*/
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]"
	expErr = tlerr.NotSupportedError{Format: "Subscribe not supported", Path: path}
	t.Run("Static case on change not supported(interface list level with key)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/***********************************/

	/*Static case interface  list without key*/
	path = "/openconfig-interfaces:interfaces/interface"
	expErr = tlerr.NotSupportedError{Format: "Subscribe not supported", Path: path}
	t.Run("Static case on change not supported (interface list level without key)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/****************************/

	/*Static case interface  top-level container*/
	path = "/openconfig-interfaces:interfaces"
	expErr = tlerr.NotSupportedError{Format: "Subscribe not supported", Path: path}
	t.Run("Static case on change not supported (interface top-level container)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/********************/

	/*Subtree case onChange disabled bgp/neigbors/neighbor/state/established-transitions*/
	path = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=bgp]/bgp/neighbors/neighbor[neighbor-address=Eth1/1]/state/established-transitions"
	xfmrTrSubInfo.DbDataMap = nil
	xfmrTrSubInfo.MinInterval = 0
	xfmrTrSubInfo.OnChange = false
	t.Run("Subtree case on change disable(bgp/neigbors/neighbor/state/established-transitions)", translateSubscribeRequest(path, xfmrTrSubInfo, false, nil))
	time.Sleep(1 * time.Second)
	/*****************************/

	/*Subtree case bgp/neigbors/neighbor/state/session-state, non-native/alias format key*/
	path = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=bgp]/bgp/neighbors/neighbor[neighbor-address=Eth1/1]/state/session-state"
	xfmrTrSubInfo.DbDataMap = make(RedisDbMap)
	xfmrTrSubInfo.DbDataMap[6] = map[string]map[string]db.Value{"BGP_NEIGHBOR": map[string]db.Value{"default|Ethernet0": {}}}
	xfmrTrSubInfo.MinInterval = 0
	xfmrTrSubInfo.NeedCache = true
	xfmrTrSubInfo.PType = OnChange
	xfmrTrSubInfo.OnChange = true
	url = "/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST[name=localhost]/intf_naming_mode"
	url_body_json = "{\"sonic-device-metadata:intf_naming_mode\": \"standard\"}"
	t.Run("Enable Alias mode", processSetRequest(url, url_body_json, "PATCH", false))
	time.Sleep(2 * time.Second)
	t.Run("Subtree case on change enable(bgp/neigbors/neighbor/state/session-state)", translateSubscribeRequest(path, xfmrTrSubInfo, false, nil))
	time.Sleep(1 * time.Second)
	url = "/sonic-device-metadata:sonic-device-metadata/DEVICE_METADATA/DEVICE_METADATA_LIST[name=localhost]/intf_naming_mode"
	t.Run("Disable Alias mode", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)

	/*****************************/

	fmt.Println("+++++++++++++ Done!!! Performing  Translate Subscribe OC yang ++++++++++++")

}
