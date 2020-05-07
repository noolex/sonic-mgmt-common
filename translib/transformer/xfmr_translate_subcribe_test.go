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

	/* Static case interface state */
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/state"
	expErr := tlerr.NotSupportedError{Format:"Subscribe not supported", Path : path}
	t.Run("Static case on change disable(interface state)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/******************/

	/*Static case interface state oper-status*/
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/state/oper-status"
	xfmrTrSubInfo.DbDataMap = make(RedisDbMap)
	xfmrTrSubInfo.DbDataMap[0] = map[string]map[string]db.Value{"PORT_TABLE": map[string]db.Value{"Ethernet4":{}}}
	xfmrTrSubInfo.MinInterval = 0
	xfmrTrSubInfo.NeedCache = true
	xfmrTrSubInfo.PType = OnChange
	xfmrTrSubInfo.OnChange = true
	t.Run("Static case on change enable(interface state oper-status)", translateSubscribeRequest(path, xfmrTrSubInfo, false, nil))
	time.Sleep(1 * time.Second)
	/*****************************/

	/*Static case interface  key-leaf*/
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/name"
	expErr = tlerr.NotSupportedError{Format:"Subscribe not supported", Path : path}
	t.Run("Static case on change disable(interface list key-leaf)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/*******************************/

	/*Static case interface  list with key*/
	path = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]"
	expErr = tlerr.NotSupportedError{Format:"Subscribe not supported", Path : path}
	t.Run("Static case on change not supported(interface list level with key)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/***********************************/

	/*Static case interface  list without key*/
	path = "/openconfig-interfaces:interfaces/interface"
	expErr = tlerr.NotSupportedError{Format:"Subscribe not supported", Path : path}
	t.Run("Static case on change not supported (interface list level without key)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/****************************/

	/*Static case interface  top-level container*/
	path = "/openconfig-interfaces:interfaces"
        expErr = tlerr.NotSupportedError{Format:"Subscribe not supported", Path : path}
	t.Run("Static case on change not supported (interface top-level container)", translateSubscribeRequest(path, xfmrTrSubInfo, true, expErr))
	time.Sleep(1 * time.Second)
	/********************/

    fmt.Println("+++++++++++++ Done!!! Performing  Translate Subscribe OC yang ++++++++++++")

}

