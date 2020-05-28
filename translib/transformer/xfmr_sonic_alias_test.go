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
func Test_Sonic_Alias_Leaf_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=Eth1/21]/mtu"

        fmt.Println("++++++++++++++  UPDATE Test_Sonic_Alias_Leaf  +++++++++++++")

        patch_payload := "{ \"sonic-port:mtu\": 1600}"
        patch_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"1600","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("UPDATE on Alias Leaf", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Alias Leaf", verifyDbResult(rclient, "PORT|Ethernet80", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Sonic_Alias_Leaf_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=Eth1/21]/mtu"

        fmt.Println("++++++++++++++  Replace Test_Sonic_Alias_Leaf  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"sonic-port:mtu\": 2400}"
        put_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("Replace on Alias Leaf", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Alias Leaf", verifyDbResult(rclient, "PORT|Ethernet80", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Sonic_Alias_Leaf_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=Eth1/21]/mtu"

        fmt.Println("++++++++++++++  DELETE Test_Sonic_Alias_Leaf  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        delete_expected_map := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("DELETE on Alias Leaf", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Alias Leaf", verifyDbResult(rclient, "PORT|Ethernet80", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Sonic_Alias_Leaf_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=Eth1/21]/mtu"

        fmt.Println("++++++++++++++  Get Test_Sonic_Alias_Leaf  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{ \"sonic-port:mtu\": 1600}"

        t.Run("GET on Alias Leaf", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

/* Alias List Cases */
func Test_Sonic_Alias_List_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=Eth1/21]"

        fmt.Println("++++++++++++++  UPDATE Test_Sonic_Alias_List  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        patch_payload := "{ \"sonic-port:PORT_LIST\": [ { \"ifname\": \"Eth1/21\", \"mtu\": 2400 } ]}"
        patch_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("UPDATE on Alias List", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Alias List", verifyDbResult(rclient, "PORT|Ethernet80", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Sonic_Alias_List_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=Eth1/21]"

        fmt.Println("++++++++++++++  Replace Test_Sonic_Alias_List  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"sonic-port:PORT_LIST\": [ { \"ifname\": \"Eth1/21\", \"mtu\": 2400 } ]}"
        put_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("Replace on Alias List", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Alias List", verifyDbResult(rclient, "PORT|Ethernet80", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Sonic_Alias_List_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST[ifname=Eth1/21]"

        fmt.Println("++++++++++++++  Get Test_Sonic_Alias_List  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"sonic-port:PORT_LIST\":[{\"admin_status\":\"up\",\"ifname\":\"Ethernet80\",\"mtu\":1600}]}"

        t.Run("GET on Alias List", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

/* Alias Container Cases*/
func Test_Sonic_Alias_Container_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST"

        fmt.Println("++++++++++++++  UPDATE Test_Sonic_Alias_Container  +++++++++++++")

        patch_payload := "{ \"sonic-port:PORT_LIST\": [ { \"ifname\": \"Ethernet80\", \"mtu\": 1600 } ]}"
        patch_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"1600","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("UPDATE on Alias Container", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Alias Container", verifyDbResult(rclient, "PORT|Ethernet80", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Sonic_Alias_Container_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST"

        fmt.Println("++++++++++++++  Replace Test_Sonic_Alias_Container  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"sonic-port:PORT_LIST\": [ { \"ifname\": \"Ethernet80\", \"mtu\": 2400 } ]}"
        put_expected := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"index":"20","lanes":"109,110,111,112","mtu":"2400","alias":"fortyGigE0/80","admin_status":"down","speed":"40000"}}}

        t.Run("Replace on Alias Container", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Alias Container", verifyDbResult(rclient, "PORT|Ethernet80", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Sonic_Alias_Container_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":""}}
        prereq := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet80":map[string]interface{}{"mtu":"1600"}}}
        url := "/sonic-port:sonic-port/PORT/PORT_LIST"

        fmt.Println("++++++++++++++  Get Test_Sonic_Alias_Container  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"sonic-port:PORT_LIST\":[{\"admin_status\":\"up\",\"ifname\":\"Ethernet0\",\"mtu\":3600},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/100\",\"ifname\":\"Ethernet100\",\"index\":25,\"lanes\":\"121,122,123,124\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/104\",\"ifname\":\"Ethernet104\",\"index\":26,\"lanes\":\"81,82,83,84\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/108\",\"ifname\":\"Ethernet108\",\"index\":27,\"lanes\":\"85,86,87,88\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/112\",\"ifname\":\"Ethernet112\",\"index\":28,\"lanes\":\"93,94,95,96\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/116\",\"ifname\":\"Ethernet116\",\"index\":29,\"lanes\":\"89,90,91,92\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/12\",\"ifname\":\"Ethernet12\",\"index\":3,\"lanes\":\"37,38,39,40\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/120\",\"ifname\":\"Ethernet120\",\"index\":30,\"lanes\":\"101,102,103,104\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/124\",\"ifname\":\"Ethernet124\",\"index\":31,\"lanes\":\"97,98,99,100\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/16\",\"ifname\":\"Ethernet16\",\"index\":4,\"lanes\":\"45,46,47,48\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/20\",\"ifname\":\"Ethernet20\",\"index\":5,\"lanes\":\"41,42,43,44\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/24\",\"ifname\":\"Ethernet24\",\"index\":6,\"lanes\":\"1,2,3,4\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/28\",\"ifname\":\"Ethernet28\",\"index\":7,\"lanes\":\"5,6,7,8\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/32\",\"ifname\":\"Ethernet32\",\"index\":8,\"lanes\":\"13,14,15,16\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/36\",\"ifname\":\"Ethernet36\",\"index\":9,\"lanes\":\"9,10,11,12\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/4\",\"ifname\":\"Ethernet4\",\"index\":1,\"lanes\":\"29,30,31,32\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/40\",\"ifname\":\"Ethernet40\",\"index\":10,\"lanes\":\"17,18,19,20\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/44\",\"ifname\":\"Ethernet44\",\"index\":11,\"lanes\":\"21,22,23,24\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/48\",\"ifname\":\"Ethernet48\",\"index\":12,\"lanes\":\"53,54,55,56\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/52\",\"ifname\":\"Ethernet52\",\"index\":13,\"lanes\":\"49,50,51,52\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/56\",\"ifname\":\"Ethernet56\",\"index\":14,\"lanes\":\"57,58,59,60\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/60\",\"ifname\":\"Ethernet60\",\"index\":15,\"lanes\":\"61,62,63,64\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/64\",\"ifname\":\"Ethernet64\",\"index\":16,\"lanes\":\"69,70,71,72\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/68\",\"ifname\":\"Ethernet68\",\"index\":17,\"lanes\":\"65,66,67,68\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/72\",\"ifname\":\"Ethernet72\",\"index\":18,\"lanes\":\"73,74,75,76\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/76\",\"ifname\":\"Ethernet76\",\"index\":19,\"lanes\":\"77,78,79,80\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/8\",\"ifname\":\"Ethernet8\",\"index\":2,\"lanes\":\"33,34,35,36\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"up\",\"ifname\":\"Ethernet80\",\"mtu\":1600},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/84\",\"ifname\":\"Ethernet84\",\"index\":21,\"lanes\":\"105,106,107,108\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/88\",\"ifname\":\"Ethernet88\",\"index\":22,\"lanes\":\"113,114,115,116\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/92\",\"ifname\":\"Ethernet92\",\"index\":23,\"lanes\":\"117,118,119,120\",\"mtu\":9100,\"speed\":\"40000\"},{\"admin_status\":\"down\",\"alias\":\"fortyGigE0/96\",\"ifname\":\"Ethernet96\",\"index\":24,\"lanes\":\"125,126,127,128\",\"mtu\":9100,\"speed\":\"40000\"}]}"

        t.Run("GET on Alias Container", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

