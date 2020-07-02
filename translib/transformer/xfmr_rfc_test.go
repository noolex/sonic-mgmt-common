//////////////////////////////////////////////////////////////////////
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
        "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

/***********************************************************************************************************************/
/***************************    RFC COMPLIANCE TEST - POST OPERATION   *************************************************/
/***********************************************************************************************************************/

func Test_Rfc_Post_Operation(t *testing.T) {

        // Post(create) on container, parent table present

        cleanuptbl1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  Post(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system-ext:source-address\": \"1.1.1.1\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret1\", \"openconfig-system-ext:timeout\": 10, \"openconfig-system-ext:retransmit-attempts\": 10}"
        expected := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL", "auth_type":"mschap", "passkey":"secret1","timeout":"10"}}}
        t.Run("RFC - POST on container(create)", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(create) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Post(update) on container, parent table present, overriding timeout:10 with timeout:20

        prereq1 = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret1","src_ip":"1.1.1.1","timeout":"10"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  Post(update) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload = "{ \"openconfig-system-ext:source-address\": \"1.1.1.1\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret1\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10}"
        expected = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret1","src_ip":"1.1.1.1","timeout":"20"}}}
        t.Run("RFC - POST on container(update)", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(update) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Post(create) on list instance, parent table present

        cleanuptbl2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":""}}
	prereq1 = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

	fmt.Println("++++++++++++++  POST(create) - uri: list instance, message-body: leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        payload = "{\"openconfig-system:config\":{\"timeout\":40}}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL", "timeout":"40"}}}
        t.Run("RFC - POST(create) on list instance", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(create) on list instance", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Post(update) on list instance, parent table present, overriding "timeout":"40" with "timeout":"30""

        prereq2 = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL", "timeout":"40"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  POST(Update) - uri: list instance, message-body: leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        payload = "{\"openconfig-system:config\":{\"timeout\":30}}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL", "timeout":"30"}}}
        t.Run("RFC - POST(Update) on list instance", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(Update) on list instance", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


/*
        // Post(create) on container, parent table pressent, default value 

        cleanuptbl1 = map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"default":""}}
        prereq1 = map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}}}
        prereq2 = map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"default":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  POST - uri: container, default value   +++++++++++++")
        url = ""
        payload = ""
        expected = 
        t.Run("RFC - POST(create) on container, default value", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(create) on container, default value", verifyDbResult(rclient, "", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Post(create) on list instance, parent table present, default value

         // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  POST - uri: list instance, default value   +++++++++++++")
        url = ""
        payload = ""
        expected =
        t.Run("RFC - POST(create) on list instance, default value", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(create) on list, default value", verifyDbResult(rclient, "", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
*/
}

func Test_Rfc_Put_Operation(t *testing.T) {

        // Put(create) on container, parent table present

        cleanuptbl1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PUT(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","timeout":"20"}}}
        t.Run("RFC - PUT(create) on container", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Put(modify) on container, parent table present, overriding timeout:10 with timeout:20

        prereq1 = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"10"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PUT(modify) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload = "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}
        t.Run("RFC - PUT(modify) on container", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Put(create) on list, parent table present

        cleanuptbl2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":""}}
	prereq1 = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PUT(create) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":40}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}
        t.Run("RFC - PUT(create) on list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on list", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Put(modify) on list, parent table and subscribe subtree present, overriding "timeout":"40" with "timeout":"30"

        prereq2 = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PUT(modify) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":30}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"30"}}}
        t.Run("RFC - PUT(modify) on list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on list", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Put(create) on list instance, parent table present

        prereq2 = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PUT(create) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":40}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}
        t.Run("RFC - PUT(create) on list instance", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on list instance", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Put(modify) on list instance, parent table and subscribe subtree present, overriding overriding "timeout":"40" with "timeout":"30"

        prereq2 = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PUT(modify) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":30}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"30"}}} 
        t.Run("RFC - PUT(modify) on list instance", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on list instance", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)

        // Put(create) on leaf, parent table present

        cleanuptbl1 = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":""}}
        prereq1 = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"NULL":"NULL"}}}

        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PUT(create) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PUT(create) on leaf", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on leaf", verifyDbResult(rclient, "ROUTE_MAP_SET|MAP1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Put(modify) on leaf, parent table present, overriding set_local_pref:8 with set_local_pref:7

        prereq1 = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"set_local_pref":"8"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PUT(modify) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PUT(modify) on leaf", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on leaf", verifyDbResult(rclient, "ROUTE_MAP_SET|MAP1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Put(create) on leaf-list, parent table present

        cleanuptbl1 = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq1 = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PUT(create) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL","include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PUT(create) on leaf-list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Put(modify) on leaf-list, parent table present, overriding "include@": "1.2.3.5.*,1.3.6.*" with "include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"

        prereq1 =  map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PUT(modify) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PUT(modify) on leaf-list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


   /*     // Put on container, parent table present, default value fill

        cleanuptbl1 = map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"default":""}}
        prereq1 = map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 = map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"default":map[string]interface{}{"":""}}}

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl1)
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PUT - uri: container, default value fill  +++++++++++++")
        url = ""
        payload = ""
        expected =
        t.Run("RFC - PUT on container, default value fill", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT on container, default value fill", verifyDbResult(rclient, "BGP_GLOBALS|default", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1) */
}

func Test_Rfc_Patch_Operation(t *testing.T) {

        // Patch(create) on container  

        cleanuptbl1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

	fmt.Println("++++++++++++++  PATCH(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL","auth_type":"mschap", "passkey":"secret4","timeout":"20"}}}
        t.Run("RFC - PATCH(create) on container", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Patch(merge) on container, overriding timeout:10 with timeout:20

        prereq1 = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"10"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PATCH(merge) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload = "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}
        t.Run("RFC - PATCH(merge) on container", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Patch(create) on list, parent table present

        cleanuptbl2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":""}}
        prereq1 = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PATCH(create) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":40}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}
        t.Run("RFC - PATCH(create) on list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on list", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Patch(merge) on list, parent table and subscribe subtree present, overriding "timeout":"40" with "timeout":"30"

        prereq2 = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PATCH(merge) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":30}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"30"}}}
        t.Run("RFC - PATCH(merge) on list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on list", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Patch(create) on list instance, parent table present       

        prereq2 = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PATCH(create) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":40}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}
        t.Run("RFC - PATCH(create) on list instance", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on list instance", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Patch(merge) on list instance, parent table and subscribe subtree present, overriding "timeout":"40" with "timeout":"30"

        prereq2 = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PATCH(merge) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        payload = "{\"openconfig-system:server\":[{\"address\":\"1.1.1.1\",\"config\":{\"timeout\":30}}]}"
        expected = map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"30"}}}
        t.Run("RFC - PATCH(merge) on list instance", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on list instance", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Patch(create) on leaf, parent table present

        cleanuptbl1 = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":""}}
        prereq1 = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1|1":map[string]interface{}{"NULL":"NULL"}}}

        loadConfigDB(rclient, prereq1)

	fmt.Println("++++++++++++++  PATCH(create) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PATCH(create) on leaf", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on leaf", verifyDbResult(rclient, "ROUTE_MAP_SET|MAP1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Patch(merge) on leaf, parent table present, overriding set_local_pref:8 with set_local_pref:7

        prereq1 = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"set_local_pref":"8"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PATCH(merge) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PATCH(merge) on leaf", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on leaf", verifyDbResult(rclient, "ROUTE_MAP_SET|MAP1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Patch(create) on leaf-list, parent table present

        cleanuptbl1 = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq1 = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

	fmt.Println("++++++++++++++  PATCH(create) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL","include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PATCH(create) on leaf-list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Patch(merge) on leaf-list, parent table present, overriding "include@": "1.2.3.5.*,1.3.6.*" with "include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"

        prereq1 =  map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  PATCH(merge) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PATCH(merge) on leaf-list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


       /*     // Patch on container, parent table present, default value fill

        cleanuptbl1 = map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"default":""}}
        prereq1 = map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 = map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"default":map[string]interface{}{"":""}}}

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl1)
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  PATCH - uri: container, default value fill  +++++++++++++")
        url = ""
        payload = ""
        expected =
        t.Run("RFC - PATCH on container, default value fill", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH on container, default value fill", verifyDbResult(rclient, "BGP_GLOBALS|default", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1) */
}

func Test_Rfc_Delete_Operation(t *testing.T) {

	// Delete on container, data present in DB

        cleanuptbl1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

	fmt.Println("++++++++++++++  DELETE uri container, data present in DB  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        expected := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"src_ip":"4.4.4.4"}}}
        t.Run("RFC - Delete on container, data present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on container, data present in DB", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)


        // Delete on list, data present in DB

        cleanuptbl2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":""}}
        prereq1 = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"1.1.1.1":map[string]interface{}{"timeout":"40"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

	fmt.Println("++++++++++++++  DELETE uri list, data present in DB  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server"
        expected = make(map[string]interface{})
        t.Run("RFC - Delete on list, data present in DB",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list, data present in DB", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Delete on list instance, data present in DB

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

	fmt.Println("++++++++++++++  DELETE uri list instance, data present in DB  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        t.Run("RFC - Delete on list instance, data present in DB",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list instance, data present in DB", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Delete on leaf,  data present in DB, last leaf in container

        cleanuptbl1 = map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq1 = map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"4"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

        fmt.Println("++++++++++++++  DELETE uri leaf, data present in DB  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"
        expected = map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}
        t.Run("RFC - Delete on leaf, data present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf, data present in DB", verifyDbResult(rclient, "RADIUS|global", expected, false))

        unloadConfigDB(rclient, cleanuptbl1)


        // Delete on leaf-list, data present in DB

        cleanuptbl1 = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq1 = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.4.*,1.3.4.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

	fmt.Println("++++++++++++++  DELETE uri leaf-list, data present in DB  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL"}}}
        t.Run("RFC - Delete on leaf-list, data present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list, data present in DB", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))

        unloadConfigDB(rclient, cleanuptbl1)


        // Delete on leaf-list instance, data present in DB

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)

	fmt.Println("++++++++++++++  DELETE uri leaf-list instance, data present in DB  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.3.4.*]"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL","include@": "1.2.3.4.*"}}}
        t.Run("RFC - Delete on leaf-list instance, data present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list instance, data present in DB", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))

        unloadConfigDB(rclient, cleanuptbl1)
}

func Test_Rfc_Delete_Negative_Cases(t *testing.T) {


        // Delete on container, data not present in DB

        cleanuptbl := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  DELETE uri container, data not present in DB  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        t.Run("RFC - Delete on container, data not present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on container, data not present in DB", verifyDbResult(rclient, "TACPLUS|global", prereq, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Delete on list, data present not in DB

        cleanuptbl = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  DELETE uri list, data not present in DB  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server"
        t.Run("RFC - Delete on list, data not present in DB",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list, data not present in DB", verifyDbResult(rclient, "TACPLUS|global", prereq, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Delete on list instance, data not present in DB

        cleanuptbl1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        cleanuptbl2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"2.2.2.2":""}}
        prereq1 := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"TACPLUS_SERVER":map[string]interface{}{"2.2.2.2":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  DELETE uri list instance, data not present in DB +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/servers/server[address=1.1.1.1]"
        expected := make(map[string]interface{})
        t.Run("RFC - Delete on list instance, data not present in DB",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list instance, data not present in DB", verifyDbResult(rclient, "TACPLUS_SERVER|1.1.1.1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Delete on leaf, data not present in DB

        cleanuptbl = map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq = map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  DELETE uri leaf, data not present in DB +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"
        t.Run("RFC - Delete on leaf, data not present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf, data not present in DB", verifyDbResult(rclient, "RADIUS|global", prereq, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Delete on leaf-list, data not present in DB

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  DELETE uri leaf-list, data not present in DB +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        t.Run("RFC - Delete on leaf-list, data not present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list, data not present in DB", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", prereq, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Delete on leaf-list instance, data not present in DB

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  DELETE uri leaf-list instance, data not present in DB +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.3.4.*]"
        t.Run("RFC - Delete on leaf-list instance", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list instance", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", prereq, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Rfc_Get_Operation(t *testing.T) {

        // Get on OC nonexistent container 

        cleanuptbl := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  GET with uri OC container(nonexistent)  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        expected := "{}"
        t.Run("Verify Get on OC container(nonexistent)", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on Sonic nonexistent container

        fmt.Println("++++++++++++++  GET with uri Sonic container(nonexistent)  +++++++++++++")
        url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW"
        expected = "{}"
        t.Run("Verify Get on Sonic container(nonexistent)", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on OC list, no instances exist

	fmt.Println("++++++++++++++  GET with uri OC list, but no instances exist +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view"
        expected = "{}"
        t.Run("Verify Get on OC list no instances exist", processGetRequest(url, expected, false))


        // Get on Sonic list, no instances exist

        fmt.Println("++++++++++++++  GET with uri Sonic list, but no instances exist +++++++++++++")
        url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW/SNMP_SERVER_VIEW_LIST"
        expected = "{}"
        t.Run("Verify Get on Sonic list no instances exist", processGetRequest(url, expected, false))


        // Get on OC leaf-list, no instances exist      

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"exclude@":"1.2.3.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  GET with uri OC leaf-list, but no instances exist +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        expected = "{}"
        t.Run("Verify Get on OC leaf-list no instances exist", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on OC leaf-list, instance exists

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@":"1.2.3.*, 1.6.7.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  GET with uri OC leaf-list, but instances exists +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[1.2.3.*]"
        expected = "{\"ietf-snmp:include\":[\"1.2.3.*\"]}"
        t.Run("Verify Get on OC leaf-list instances exists", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on Sonic leaf-list, no instances exist

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"exclude@":"1.2.3.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  GET with uri Sonic leaf-list, but no instances exist +++++++++++++")
        url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW/SNMP_SERVER_VIEW_LIST=TestVacmView1/include"
        expected = "{}"
        t.Run("Verify Get on Sonic leaf-list no instances exist", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on Sonic leaf-list, instances exist

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@":"1.2.3.*, 1.6.7.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  GET with uri Sonic leaf-list, but  instances exists +++++++++++++")
        url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW/SNMP_SERVER_VIEW_LIST=TestVacmView1/include[1.2.3.*]"
        expected = "{\"sonic-snmp:include\":[\"1.2.3.*\"]}"
        t.Run("Verify Get on Sonic leaf-list  instances exists", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on list instance that does not map to any real table in DB, and yang children have data in DB 

        cleanuptbl1 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4":""}}
        cleanuptbl2 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4|*":""}}
        prereq1 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4||1.2.3.4/16":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        fmt.Println("++++++++++++++  Get on list instance that does not map to any real table in DB, and yang children have data in DB +++++++++++++")
        url = "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/subinterfaces/subinterface[index=0]"
        expected = "{\"openconfig-interfaces:subinterface\":[{\"index\":0,\"openconfig-if-ip:ipv4\":{\"addresses\":{\"address\":[{\"config\":{\"ip\":\"1.2.3.4\",\"prefix-length\":16},\"ip\":\"1.2.3.4\",\"state\":{\"ip\":\"1.2.3.4\",\"prefix-length\":16}}]}},\"openconfig-if-ip:ipv6\":{\"config\":{\"enabled\":false},\"state\":{\"enabled\":false}}}]}"
        t.Run("Verify Get on list instance that does not map to any real table in DB, and yang children have data in DB", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)


        // Get on a leaf/field, parent list instance exists but field exists in DB (OC YANG)  

        // Get on a leaf/field, parent list instance exists but field exist in DB (Sonic YANG)  

}

