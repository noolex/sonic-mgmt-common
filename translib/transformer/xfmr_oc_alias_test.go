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
)



/* Alias Leaf Cases */
func Test_OC_Alias_Leaf_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]/config/mtu"

        fmt.Println("++++++++++++++  UPDATE Test_OC_Alias_Leaf  +++++++++++++")

        patch_payload := "{ \"openconfig-interfaces:mtu\": 1600}"
        patch_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"1600","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("UPDATE on Alias Leaf", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Alias Leaf", verifyDbResult(rclient, "PORT|Ethernet80", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_Leaf_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]/config/mtu"

        fmt.Println("++++++++++++++  Replace Test_OC_Alias_Leaf  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"openconfig-interfaces:mtu\": 2400}"
        put_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("Replace on Alias Leaf", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Alias Leaf", verifyDbResult(rclient, "PORT|Ethernet80", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_Leaf_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]/config/mtu"

        fmt.Println("++++++++++++++  DELETE Test_OC_Alias_Leaf  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        delete_expected_map := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("DELETE on Alias Leaf", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Alias Leaf", verifyDbResult(rclient, "PORT|Ethernet80", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_Leaf_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]/config/mtu"

        fmt.Println("++++++++++++++  Get Test_OC_Alias_Leaf  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-interfaces:mtu\": 1600}"

        t.Run("GET on Alias Leaf", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

/* Alias List Cases */
func Test_OC_Alias_List_Create(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]"

        fmt.Println("++++++++++++++  CREATE Test_OC_Alias_List  +++++++++++++")

        post_payload := "{ \"openconfig-interfaces:interface\": [ { \"name\": \"Eth1/21\", \"config\": { \"mtu\": 1600 } } ]}"
        post_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"1600","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("CREATE on Alias List", processSetRequest(url, post_payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify create on Alias List", verifyDbResult(rclient, "PORT|Ethernet80", post_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_List_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]"

        fmt.Println("++++++++++++++  UPDATE Test_OC_Alias_List  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        patch_payload := "{ \"openconfig-interfaces:interface\": [ { \"name\": \"Eth1/21\", \"config\": { \"mtu\": 2400 } } ]}"
        patch_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("UPDATE on Alias List", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Alias List", verifyDbResult(rclient, "PORT|Ethernet80", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_List_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]"

        fmt.Println("++++++++++++++  Replace Test_OC_Alias_List  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"openconfig-interfaces:interface\": [ { \"name\": \"Eth1/21\", \"config\": { \"mtu\": 2400 } } ]}"
        put_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("Replace on Alias List", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Alias List", verifyDbResult(rclient, "PORT|Ethernet80", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_List_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]"

        fmt.Println("++++++++++++++  Get Test_OC_Alias_List  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-interfaces:interface\":[{\"config\":{\"enabled\":false,\"mtu\":1600,\"name\":\"Ethernet80\",\"type\":\"iana-if-type:ethernetCsmacd\"},\"name\":\"Ethernet80\",\"openconfig-if-ethernet:ethernet\":{\"state\":{\"counters\":{\"in-oversize-frames\":\"0\",\"openconfig-if-ethernet-ext:in-distribution\":{\"in-frames-128-255-octets\":\"0\"},\"openconfig-interfaces-ext:out-oversize-frames\":\"0\"},\"port-speed\":\"openconfig-if-ethernet:SPEED_40GB\"}},\"state\":{\"admin-status\":\"DOWN\",\"counters\":{\"in-broadcast-pkts\":\"0\",\"in-discards\":\"0\",\"in-errors\":\"0\",\"in-multicast-pkts\":\"0\",\"in-octets\":\"0\",\"in-pkts\":\"0\",\"in-unicast-pkts\":\"0\",\"last-clear\":\"0\",\"out-broadcast-pkts\":\"0\",\"out-discards\":\"0\",\"out-errors\":\"0\",\"out-multicast-pkts\":\"0\",\"out-octets\":\"0\",\"out-pkts\":\"0\",\"out-unicast-pkts\":\"0\"},\"description\":\"\",\"enabled\":false,\"mtu\":1600,\"name\":\"Ethernet80\",\"oper-status\":\"DOWN\"},\"subinterfaces\":{\"subinterface\":[{\"index\":0,\"openconfig-if-ip:ipv6\":{\"config\":{\"enabled\":false},\"state\":{\"enabled\":false}}}]}}]}"

        t.Run("GET on Alias List", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

/* Alias Container Cases*/
func Test_OC_Alias_Container_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]/config"

        fmt.Println("++++++++++++++  UPDATE Test_OC_Alias_Container  +++++++++++++")

        patch_payload := "{ \"openconfig-interfaces:config\": { \"mtu\": 1600 }}"
        patch_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"1600","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("UPDATE on Alias Container", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Alias Container", verifyDbResult(rclient, "PORT|Ethernet80", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_Container_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]/config"

        fmt.Println("++++++++++++++  Replace Test_OC_Alias_Container  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"openconfig-interfaces:config\": { \"mtu\": 2400 }}"
        put_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("Replace on Alias Container", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Alias Container", verifyDbResult(rclient, "PORT|Ethernet80", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_OC_Alias_Container_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Eth1/21]/config"

        fmt.Println("++++++++++++++  Get Test_OC_Alias_Container  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-interfaces:config\":{\"enabled\":true,\"mtu\":2400,\"name\":\"Ethernet80\",\"type\":\"iana-if-type:ethernetCsmacd\"}}"

        t.Run("GET on Alias Container", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

