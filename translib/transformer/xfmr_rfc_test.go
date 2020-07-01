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

        cleanuptbl := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  Post(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system-ext:source-address\": \"1.1.1.1\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret1\", \"openconfig-system-ext:timeout\": 10, \"openconfig-system-ext:retransmit-attempts\": 10}"
        expected := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL", "auth_type":"mschap", "passkey":"secret1","timeout":"10"}}}
        t.Run("RFC - POST on container(create)", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(create) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Post(update) on container, parent table present, overriding timeout:10 with timeout:20

        prereq = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret1","src_ip":"1.1.1.1","timeout":"10"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  Post(update) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload = "{ \"openconfig-system-ext:source-address\": \"1.1.1.1\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret1\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10}"
        expected = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret1","src_ip":"1.1.1.1","timeout":"20"}}}
        t.Run("RFC - POST on container(update)", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(update) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Post(create) on list instance, parent table present

        cleanuptbl = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":""}}
        vrf_prereq := map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}}}
        prereq = map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  POST(create) - uri: list instance, message-body: leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}"
        expected = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}}}
        t.Run("RFC - POST(create) on list instance", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(create) on list instance", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Post(update) on list instance, parent table present, overriding "last-member-query-interval":"1000" with "last-member-query-interval\":2000}}"
        prereq = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"1000","enabled":"true"}}} 

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  POST(Update) - uri: list instance, message-body: leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}"
        expected = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}}}
        t.Run("RFC - POST(Update) on list instance", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST(Update) on list instance", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Post on container, default value fill

        cleanuptbl = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":""}}

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl)

        fmt.Println("++++++++++++++  POST - uri: container, default value fill  +++++++++++++")
        url = "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"
        payload = "{\"mtu\":3000,\"loopback-mode\":true,\"description\":\"test-descp1\",\"openconfig-vlan:tpid\":\"TPID_0X8100\"}"
        expected = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":map[string]interface{}{"mtu":"3000", "admin_status":"up","description":"test-descp1"}}}
        t.Run("RFC - POST on container, default value fill", processSetRequest(url, payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify POST on container, default value fill", verifyDbResult(rclient, "PORT|Ethernet32", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)

}

func Test_Rfc_Post_Negative_Cases(t *testing.T) {


        // Post on list instance, child data resources given for target 

        cleanuptbl := map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":""}}
        vrf_prereq := map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}}}
        prereq := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  POST - uri: list instance, child data resources given for target  +++++++++++++")
        url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload := "{ \"openconfig-network-instance-deviation:interfaces\": { \"interface\": [ { \"config\": { \"enabled\": true, \"last-member-query-interval\": 1000, \"name\": \"Vlan1\", \"version\": 3 }, \"name\": \"Vlan1\" } ] }}"
        expected_err :=  tlerr.InvalidArgsError{Format:"Entry not found"} 
        t.Run("RFC - POST on list instance, child data resources given for target", processSetRequest(url, payload, "POST", true, expected_err))
        unloadConfigDB(rclient, cleanuptbl)


        // Post(404 error) on container, parent table not present

        fmt.Println("++++++++++++++  Post(404 error) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload = "{ \"openconfig-system-ext:source-address\": \"1.1.1.1\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret1\", \"openconfig-system-ext:timeout\": 10, \"openconfig-syster-ext:retransmit-attempts\": 10}"
        t.Run("RFC - POST(404 error) on container", processSetRequest(url, payload, "POST", true, expected_err))


        // Post(404 error) on list instance, parent table not present
        fmt.Println("++++++++++++++  POST(404 error) - uri: list instance, message-body: leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=Vrfvrf]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}"
        t.Run("RFC - POST(404 error) on list instance", processSetRequest(url, payload, "POST", false))


        // Post(404 error) on list instance, list instance nonexistent

        prereq = map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":""}}
        unloadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  POST with uri: list instance, but the list instance not existent, return 404 +++++++++++++")
        url = "/openconfig-interfaces:interfaces/interface[name=Vlan1]/subinterfaces/subinterface[index=0]"
        payload = "{\"openconfig-interfaces:config\":{\"index\":0},\"openconfig-if-ip:ipv4\":{\"openconfig-interfaces-ext:sag-ipv4\":{\"config\":{\"static-anycast-gateway\":[\"1.1.1.1/1\"]}}}}"
        t.Run("RFC -  POST(no list instance) on list instance", processSetRequest(url, payload, "POST", true, expected_err))
}

func Test_Rfc_Put_Operation(t *testing.T) {

        // Put(create) on container, parent table present

        cleanuptbl := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}
        t.Run("RFC - PUT on container(create)", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(modify) on container, parent table present, overriding timeout:10 with timeout:20

        prereq = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"10"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(modify) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload = "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}
        t.Run("RFC - PUT on container(modify)", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(create) on list, parent table present

        cleanuptbl = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":""}}
        vrf_prereq := map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}}}
        prereq = map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(create) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PUT(create) on list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on list", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(modify) on list, parent table and subscribe subtree present, overriding last-member-query-interval:1000 overriding last-member-query-interval:2000

        prereq = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"1000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(modify) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PUT(modify) on list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on list", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(create) on list instance, parent table present

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)

        fmt.Println("++++++++++++++  PUT(create) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PUT(create) on list instance", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on list instance", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(modify) on list instance, parent table and subscribe subtree present, overriding last-member-query-interval:1000 overriding last-member-query-interval:2000

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(modify) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PUT(modify) on list instance", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on list instance", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(create) on leaf, parent table present

        cleanuptbl = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":""}}
        prereq = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"NULL":"NULL"}}}

        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(create) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PUT(create) on leaf", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on leaf", verifyDbResult(rclient, "ROUTE_MAP|MAP1|1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(modify) on leaf, parent table present, overriding set_local_pref:8 with set_local_pref:7

        prereq = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"8"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(modify) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PUT(modify) on leaf", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on leaf", verifyDbResult(rclient, "ROUTE_MAP|MAP1|1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(create) on leaf-list, parent table present

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(create) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PUT(create) on leaf-list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(create) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put(modify) on leaf-list, parent table present, overriding "include@": "1.2.3.5.*,1.3.6.*" with "include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"

        prereq =  map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT(modify) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PUT(modify) on leaf-list", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT(modify) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Put on container, default value fill

        cleanuptbl = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":""}}
        prereq = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":map[string]interface{}{"mtu":"3500", "admin_status":"down","description":"desc-1"}}}

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PUT - uri: container, default value fill  +++++++++++++")
        url = "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"
        payload = "{\"openconfig-interfaces:config\":{\"name\":\"Ethernet32\",\"mtu\":3700,\"loopback-mode\":true,\"description\":\"desc-2\",\"openconfig-vlan:tpid\":\"TPID_0X8100\", \"enabled\":false}}"
        expected = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":map[string]interface{}{"mtu":"3700","admin_status":"down","description":"desc-2"}}}
        t.Run("RFC - PUT on container, default value fill", processSetRequest(url, payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PUT on container, default value fill", verifyDbResult(rclient, "PORT|Ethernet32", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Rfc_Put_Negative_Cases(t *testing.T) {

        // Put(404 error) on container parent table not present

        fmt.Println("++++++++++++++  PUT(404 error) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected_err :=  tlerr.InvalidArgsError{Format:"Entry not found"}
        t.Run("RFC - PUT on container(404 error)", processSetRequest(url, payload, "PUT", true, expected_err))


        // Put(404 error) on list, parent table not present

        fmt.Println("++++++++++++++  PUT(404 error) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=Vrfvrf]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        t.Run("RFC - PUT(404 error) on list", processSetRequest(url, payload, "PUT", true, expected_err))


       // Put(404 error) on list instance, parent table not present

        fmt.Println("++++++++++++++  PUT(404 error) uri: list instance, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=Vrfvrf]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        t.Run("RFC - PUT(404 error) on list instance", processSetRequest(url, payload, "PUT", true, expected_err))


        // Put(404 error) on leaf, parent table not present

        fmt.Println("++++++++++++++  PATCH(404 error) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        t.Run("RFC - PUT(404 error) on leaf", processSetRequest(url, payload, "PUT", true, expected_err))


        // Put(404 error) on leaf-list, parent table not present

        fmt.Println("++++++++++++++  PUT(404 error) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        t.Run("RFC - PUT(404 error) on leaf-list", processSetRequest(url, payload, "PUT", true, expected_err))

}

func Test_Rfc_Patch_Operation(t *testing.T) {

        // Patch(create) on container  

        cleanuptbl := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  PATCH(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}
        t.Run("RFC - PATCH on container(create)", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(merge) on container, overriding timeout:10 with timeout:20

        prereq = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"10"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PATCH(merge) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload = "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected = map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}
        t.Run("RFC - PATCH on container(merge)", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(create) on list, parent table present

        cleanuptbl = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":""}}
        vrf_prereq := map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}}}
        prereq = map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PATCH(create) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PATCH(create) on list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on list", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(merge) on list, parent table and subscribe subtree present, overriding last-member-query-interval:1000 overriding last-member-query-interval:2000

        prereq = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"1000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PATCH(merge) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PATCH(merge) on list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on list", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(create) on list instance, parent table present       

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)

        fmt.Println("++++++++++++++  PATCH(create) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PATCH(create) on list instance", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on list instance", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(merge) on list instance, parent table and subscribe subtree present, overriding last-member-query-interval:1000 overriding last-member-query-interval:2000

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PATCH(merge) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        expected =  map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"2000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        t.Run("RFC - PATCH(merge) on list instance", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on list instance", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(create) on leaf, parent table present

        cleanuptbl = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":""}}
        prereq = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"NULL":"NULL"}}}

        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  PATCH(create) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PATCH(create) on leaf", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on leaf", verifyDbResult(rclient, "ROUTE_MAP|MAP1|1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(merge) on leaf, parent table present, overriding set_local_pref:8 with set_local_pref:7

        prereq = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"8"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PATCH(merge) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        expected = map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"7"}}}
        t.Run("RFC - PATCH(merge) on leaf", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on leaf", verifyDbResult(rclient, "ROUTE_MAP|MAP1|1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(create) on leaf-list, parent table present

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  PATCH(create) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PATCH(create) on leaf-list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(create) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch(merge) on leaf-list, parent table present, overriding "include@": "1.2.3.5.*,1.3.6.*" with "include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"

        prereq =  map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PATCH(merge) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        expected = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
        t.Run("RFC - PATCH(merge) on leaf-list", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH(merge) on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Patch on container, default value fill

        cleanuptbl = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":""}}
        prereq = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":map[string]interface{}{"mtu":"9100", "admin_status":"down","description":"desc-1"}}} 

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl)
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  PATCH - uri: container, default value fill  +++++++++++++")
        url = "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"
        payload = "{\"openconfig-interfaces:config\":{\"name\":\"Ethernet32\",\"mtu\":3700,\"loopback-mode\":true,\"enabled\":true,\"description\":\"desc-2\",\"openconfig-vlan:tpid\":\"TPID_0X8100\"}}"
        expected = map[string]interface{}{"PORT":map[string]interface{}{"Ethernet32":map[string]interface{}{"mtu":"3700","admin_status":"up","description":"desc-2"}}}
        t.Run("RFC - PATCH on container, default value fill", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH on container, default value fill", verifyDbResult(rclient, "PORT|Ethernet32", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Rfc_Patch_Negative_Cases(t *testing.T) {

        // Patch(404 error) on container parent table not present

        fmt.Println("++++++++++++++  PATCH(404 error) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"4.4.4.4\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20, \"openconfig-system-ext:retransmit-attempts\": 10 }}"
        expected_err :=  tlerr.InvalidArgsError{Format:"Entry not found"}
        t.Run("RFC - PATCH on container(404 error)", processSetRequest(url, payload, "PATCH", true, expected_err))


        // Patch(404 error) on list, parent table not present

        fmt.Println("++++++++++++++  PATCH(404 error) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=Vrfvrf]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        t.Run("RFC - PATCH(404 error) on list", processSetRequest(url, payload, "PATCH", true, expected_err))


       // Patch(404 error) on list instance, parent table not present

        fmt.Println("++++++++++++++  PATCH(404 error) uri: list instance, message-body: list, instance, leaf and leaf-list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=Vrfvrf]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        payload = "{\"openconfig-network-instance-deviation:interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"version\":3,\"last-member-query-interval\":2000}}]}"
        t.Run("RFC - PATCH(404 error) on list instance", processSetRequest(url, payload, "PATCH", true, expected_err))


        // Patch(404 error) on leaf, parent table not present

        fmt.Println("++++++++++++++  PATCH(404 error) uri: leaf, message-body: leaf  +++++++++++++")
        url = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"
        payload = "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        t.Run("RFC - PATCH(404 error) on leaf", processSetRequest(url, payload, "PATCH", true, expected_err))


        // Patch(404 error) on leaf-list, parent table not present

        fmt.Println("++++++++++++++  PATCH(404 error) uri: leaf-list, message-body: leaf-list  +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        payload = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
        t.Run("RFC - PATCH(404 error) on leaf-list", processSetRequest(url, payload, "PATCH", true, expected_err))
}

func Test_Rfc_Delete_Operation(t *testing.T) {

	// Delete on container, data present in DB

        cleanuptbl := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"auth_type":"mschap", "passkey":"secret4","src_ip":"4.4.4.4","timeout":"20"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  DELETE uri container  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        expected := make(map[string]interface{})
        t.Run("RFC - Delete on container", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on container", verifyDbResult(rclient, "TACPLUS|global", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Delete on list, data present in DB

        cleanuptbl = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":""}}
        vrf_prereq := map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}}}
        prereq = map[string]interface{}{"CFG_L2MC_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"version":"3", "last-member-query-interval":"1000","enabled":"true"}},"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  DELETE uri list  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        t.Run("RFC - Delete on list",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Delete on list instance, data present in DB

        // Setup - Prerequisite
        loadConfigDB(rclient, vrf_prereq)
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  DELETE uri list instance +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        t.Run("RFC - Delete on list instance",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list instance", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Delete on leaf instance, data present in DB

        cleanuptbl = map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq = map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"4"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  DELETE uri leaf +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"
        t.Run("RFC - Delete on leaf", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf", verifyDbResult(rclient, "RADIUS|global", expected, false))

        unloadConfigDB(rclient, cleanuptbl)


        // Delete on leaf-list, data present in DB

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":""}
        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.4.*,1.3.4.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  DELETE uri leaf-list +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        t.Run("RFC - Delete on leaf-list", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))

        unloadConfigDB(rclient, cleanuptbl)


        // Delete on leaf-list instance, data present in DB

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  DELETE uri leaf-list instance +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.3.4.*]"
        t.Run("RFC - Delete on leaf-list instance", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list instance", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Rfc_Delete_Negative_Cases(t *testing.T) {

        /* expected return code - 404(Not Found) */

        // Delete on leaf-list instance, data not present in DB

        prereq := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":""}}

        // Setup - Prerequisite
        unloadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  DELETE with uri: list instance not existent +++++++++++++")
        url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1"
        expected_err :=  tlerr.InvalidArgsError{Format:"Entry not found"}
        t.Run("RFC - Delete on list",  processDeleteRequest(url, true, expected_err))
        time.Sleep(1 * time.Second)


	/* expected return code - 204(No Content), note we don't return 404 below cases. */

        // Delete on container, data not present in DB

        fmt.Println("++++++++++++++  DELETE uri container, data not present in DB  +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        expected := make(map[string]interface{})
        t.Run("RFC - Delete on container, data not present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on container, data not present in DB", verifyDbResult(rclient, "TACPLUS|global", expected, false))


        // Delete on list, data present not in DB

        fmt.Println("++++++++++++++  DELETE uri list, data not present in DB  +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface"
        t.Run("RFC - Delete on list, data not present in DB",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list, data not present in DB", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))


        // Delete on list instance, data not present in DB

        fmt.Println("++++++++++++++  DELETE uri list instance, data not present in DB +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        t.Run("RFC - Delete on list instance, data not present in DB",  processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify Delete on list instance, data not present in DB", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", expected, false))


        // Delete on leaf, data not present in DB

        fmt.Println("++++++++++++++  DELETE uri leaf, data not present in DB +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"
        t.Run("RFC - Delete on leaf, data not present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf, data not present in DB", verifyDbResult(rclient, "RADIUS|global", expected, false))


        // Delete on leaf-list, data not present in DB

        fmt.Println("++++++++++++++  DELETE uri leaf-list, data not present in DB +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        t.Run("RFC - Delete on leaf-list, data not present in DB", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list, data not present in DB", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))


        // Delete on leaf-list instance, data not present in DB

        fmt.Println("++++++++++++++  DELETE uri leaf-list instance, data not present in DB +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.3.4.*]"
        t.Run("RFC - Delete on leaf-list instance", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify Delete on leaf-list instance", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected, false))
}

func Test_Rfc_Get_Operation(t *testing.T) {


        // Get on nonexistent container 

        cleanuptbl := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"TACPLUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  GET with uri container(nonexistent)  +++++++++++++")
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"
        expected := "{}"
        t.Run("Verify Get on container(nonexistent), no data", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on list, no instances exist

	fmt.Println("++++++++++++++  GET with uri list, but no instances exist +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group"
        expected = "{}"
        t.Run("Verify Get on list no instances exist", processGetRequest(url, expected, false))


        // Get on leaf-list, no instances exist      

        prereq = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  GET with uri leaf-list, but no instances exist +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        expected = "{}"
        t.Run("Verify Get on leaf-list no instances exist", processGetRequest(url, expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on list, dummy table in DB

        fmt.Println("++++++++++++++  GET with uri list, dummy table in DB +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
        expected = "{\"openconfig-nat:instance\":[{\"config\":{\"enable\": false,\"tcp-timeout\": 86400,\"timeout\": 600,\"udp-timeout\": 300},\"id\": 0,\"state\": {\"enable\": false,\"tcp-timeout\": 86400,\"timeout\": 600,\"udp-timeout\": 300}}]}"
        t.Run("Verify Get on list, dummy table in DB ", processGetRequest(url, expected, false))
}

func Test_Rfc_Get_Negative_Cases(t *testing.T) {

        // Get on list instance, parent list instance nonexistent        

        cleanuptbl := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":""}}
        prereq := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}

        loadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  GET with uri list instance: parent list instance nonexistent +++++++++++++")
        url := "/openconfig-network-instance:network-instances/network-instance[name=Vrfvrf]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        json_expected := "{}"
        expected_err :=  tlerr.InvalidArgsError{Format:"Entry not found"}
        t.Run("Verify Get on list instance parent list instance nonexistent", processGetRequest(url, json_expected, true, expected_err))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on list instance, child list instance nonexistent

        prereq = map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}}}

        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  GET with uri list instance: child list instance nonexistent +++++++++++++")
        url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=Vlan1]"
        json_expected = "{}"
        expected_err =  tlerr.InvalidArgsError{Format:"Entry not found"}
        t.Run("Verify Get on list instance child list instance nonexistent", processGetRequest(url, json_expected, true, expected_err))


        loadConfigDB(rclient, cleanuptbl)


        // Get on container, parent list instance nonexistent

        fmt.Println("++++++++++++++  GET with uri container: parent list instance nonexistent +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config"
        json_expected = "{}"
        expected_err =  tlerr.InvalidArgsError{Format:"Entry not found"}
        t.Run("Verify Get on container parent list instance nonexistent", processGetRequest(url, json_expected, true, expected_err))


        // Get on leaf-list instance, leaf-list instance nonexistent

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq =  map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"include@": "1.2.3.5.*,1.3.6.*"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  GET with uri leaf-list, leaf-list instance nonexistent +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.3.4.*]"
        json_expected = "{}"
        t.Run("Verify Get on leaf-list instance nonexistent", processGetRequest(url, json_expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on leaf-list instance, leaf-list field nonexistent

        cleanuptbl = map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":""}}
        prereq =  map[string]interface{}{"SNMP_SERVER_VIEW":map[string]interface{}{"TestVacmView1":map[string]interface{}{"NULL": "NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  GET with uri leaf-list, leaf-list field nonexistent +++++++++++++")
        url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.3.4.*]"
        json_expected = "{}"
        t.Run("Verify Get on leaf-list, leaf-list field nonexistent ", processGetRequest(url, json_expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)


        // Get on leaf, leaf field nonexistent
        cleanuptbl = map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq = map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        fmt.Println("++++++++++++++  GET with uri leaf, leaf field nonexistent +++++++++++++")
        url = "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"
        json_expected = "{}"
        t.Run("Verify Get on leaf, leaf field nonexistent", processGetRequest(url, json_expected, false))
        // Teardown
        unloadConfigDB(rclient, cleanuptbl)
}
