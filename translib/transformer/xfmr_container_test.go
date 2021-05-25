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
	//	db "github.com/Azure/sonic-mgmt-common/translib/db"
)

/***********************************************************************************************************************/
/***************************CONTAINER TABLE TRANSFORMER CRUD AND GET *************************************************/
/***********************************************************************************************************************/

func Test_Container_Table_Xfmr_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": ""}}
	prereq := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": map[string]interface{}{"NULL": "NULL"}}}
	url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"

	fmt.Println("++++++++++++++  CREATE Test_Container_Table_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	// Payload
	post_payload := "{ \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret1\", \"openconfig-system-ext:timeout\": 10}"
	post_expected := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": map[string]interface{}{"NULL": "NULL", "auth_type": "mschap", "passkey": "secret1", "timeout": "10"}}}

	t.Run("CREATE on Container table transformer mapping", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with table transformer", verifyDbResult(rclient, "TACPLUS|global", post_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)

}

func Test_Container_Table_Xfmr_Replace(t *testing.T) {

	cleanuptbl := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": ""}}
	prereq := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": map[string]interface{}{"auth_type": "mschap", "passkey": "secret1", "timeout": "10"}}}
	url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"

	fmt.Println("++++++++++++++  REPLACE Test_Container_Table_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	put_payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:auth-type\": \"mschap\", \"openconfig-system-ext:secret-key\": \"secret4\", \"openconfig-system-ext:timeout\": 20}}"
	put_expected := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": map[string]interface{}{"auth_type": "mschap", "passkey": "secret4", "timeout": "20"}}}

	t.Run("REPLACE on Container table transformer mapping", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with table transformer", verifyDbResult(rclient, "TACPLUS|global", put_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Table_Xfmr_Update(t *testing.T) {

	cleanuptbl := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": ""}}
	prereq := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": map[string]interface{}{"auth_type": "mschap", "passkey": "secret4", "timeout": "20"}}}
	url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"

	fmt.Println("++++++++++++++  UPDATE Test_Container_Table_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	patch_payload := "{ \"openconfig-system:config\": { \"name\": \"TACACS\", \"openconfig-system-ext:source-address\": \"3.3.3.3\", \"openconfig-system-ext:auth-type\": \"pap\", \"openconfig-system-ext:secret-key\": \"secret2\", \"openconfig-system-ext:timeout\": 30}}"
	patch_expected := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": map[string]interface{}{"auth_type": "pap", "passkey": "secret2", "timeout": "30"}}}

	t.Run("UPDATE on Container table transformer mapping", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with table transformer", verifyDbResult(rclient, "TACPLUS|global", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Table_Xfmr_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"DNS": map[string]interface{}{"global": ""}}
	prereq := map[string]interface{}{"DNS": map[string]interface{}{"global": map[string]interface{}{"NULL": "NULL"}}}
	url := "/openconfig-system:system/dns/config"

	fmt.Println("++++++++++++++  DELETE Test_Container_Table_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected := make(map[string]interface{})

	t.Run("DELETE on Container table transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with table transformer", verifyDbResult(rclient, "DNS|global", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Table_Xfmr_Get(t *testing.T) {

	cleanuptbl := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": ""}}
	prereq := map[string]interface{}{"TACPLUS": map[string]interface{}{"global": map[string]interface{}{"auth_type": "mschap", "passkey": "secret4", "src_ip": "4.4.4.4", "timeout": "20"}}}
	url := "/openconfig-system:system/aaa/server-groups/server-group[name=TACACS]/config"

	fmt.Println("++++++++++++++  GET Test_Container_Table_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-system:config\":{\"openconfig-system-ext:auth-type\":\"mschap\",\"openconfig-system-ext:secret-key\":\"secret4\",\"openconfig-system-ext:source-address\":\"4.4.4.4\",\"openconfig-system-ext:timeout\":20}}"

	t.Run("GET on Container table transformer mapping", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

/***********************************************************************************************************************/
/***************************CONTAINER SUBTREE TRANSFORMER CRUD AND GET *************************************************/
/***********************************************************************************************************************/

func Test_Container_Subtree_Xfmr_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": ""}}
	vrf_prereq := map[string]interface{}{"VRF": map[string]interface{}{"default": map[string]interface{}{"NULL": "NULL"}}}
	prereq := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}

	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping"

	fmt.Println("++++++++++++++  CREATE Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	loadConfigDB(rclient, vrf_prereq)
	loadConfigDB(rclient, prereq)

	post_payload := "{ \"openconfig-network-instance-deviation:interfaces\": { \"interface\": [ { \"config\": { \"enabled\": true, \"last-member-query-interval\": 1000, \"name\": \"Vlan1\", \"version\": 3 }, \"name\": \"Vlan1\" } ] }}"
	post_expected := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"version": "3", "last-member-query-interval": "1000", "enabled": "true"}}}

	t.Run("CREATE on Container Subtree transformer mapping", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with Subtree transformer", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", post_expected, false))
	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Subtree_Xfmr_Replace(t *testing.T) {

	cleanuptbl := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": ""}}
	vrf_prereq := map[string]interface{}{"VRF": map[string]interface{}{"default": map[string]interface{}{"NULL": "NULL"}}}
	prereq := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"version": "3", "last-member-query-interval": "1000", "enabled": "true"}}, "VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}
	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping"

	fmt.Println("++++++++++++++  REPLACE Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, vrf_prereq)
	loadConfigDB(rclient, prereq)

	put_payload := "{\"openconfig-network-instance-deviation:igmp-snooping\":{\"interfaces\":{\"interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"last-member-query-interval\":2000}}]}}}"
	put_expected := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"last-member-query-interval": "2000", "enabled": "true"}}}

	t.Run("REPLACE on Container Subtree transformer mapping", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with subtree transformer", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", put_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Subtree_Xfmr_Update(t *testing.T) {

	cleanuptbl1 := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": ""}}
	cleanuptbl2 := map[string]interface{}{"SAG": map[string]interface{}{"Vlan1|IPv4": ""}}
	cleanuptbl3 := map[string]interface{}{"VLAN_INTERFACE": map[string]interface{}{"Vlan1": ""}}
	prereq1 := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}
	prereq2 := map[string]interface{}{"VLAN_INTERFACE": map[string]interface{}{"Vlan1": map[string]interface{}{"NULL": "NULL"}}}
	prereq3 := map[string]interface{}{"SAG": map[string]interface{}{"Vlan1|IPv4": map[string]interface{}{"gwip@": "10.10.10.10/16"}}}

	url := "/openconfig-interfaces:interfaces/interface[name=Vlan1]/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/openconfig-interfaces-ext:sag-ipv4"

	fmt.Println("++++++++++++++  UPDATE Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq1)
	loadConfigDB(rclient, prereq2)
	loadConfigDB(rclient, prereq3)

	patch_payload := "{\"openconfig-interfaces-ext:sag-ipv4\":{\"config\":{\"static-anycast-gateway\":[\"20.20.20.20/16\"]}}}"
	patch_expected := map[string]interface{}{"SAG": map[string]interface{}{"Vlan1|IPv4": map[string]interface{}{"gwip@": "10.10.10.10/16,20.20.20.20/16"}}}

	t.Run("UPDATE on Container Subtree transformer mapping", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with subtree transformer", verifyDbResult(rclient, "SAG|Vlan1|IPv4", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl1)
	unloadConfigDB(rclient, cleanuptbl2)
	unloadConfigDB(rclient, cleanuptbl3)
}

func Test_Container_Subtree_Xfmr_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": ""}}
	vrf_prereq := map[string]interface{}{"VRF": map[string]interface{}{"default": map[string]interface{}{"NULL": "NULL"}}}
	prereq := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"version": "3", "last-member-query-interval": "1000", "enabled": "true"}}, "VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}
	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping"

	fmt.Println("++++++++++++++  DELETE Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, vrf_prereq)
	loadConfigDB(rclient, prereq)

	delete_expected := make(map[string]interface{})

	t.Run("DELETE on Container subtree transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with subtree transformer", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Subtree_Xfmr_Get(t *testing.T) {

	cleanuptbl := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": ""}}
	vrf_prereq := map[string]interface{}{"VRF": map[string]interface{}{"default": map[string]interface{}{"NULL": "NULL"}}}
	prereq := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"version": "3", "last-member-query-interval": "2000", "enabled": "true"}}, "VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}
	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping"

	fmt.Println("++++++++++++++  GET Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, vrf_prereq)
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-network-instance-deviation:igmp-snooping\":{\"interfaces\":{\"interface\":[{\"config\":{\"enabled\":true,\"last-member-query-interval\":2000,\"name\":\"Vlan1\",\"version\":3},\"name\":\"Vlan1\",\"state\":{\"enabled\":true,\"last-member-query-interval\":2000,\"name\":\"Vlan1\",\"version\":3}}]}}}"

	t.Run("GET on Container subtree transformer mapping", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

/***********************************************************************************************************************/
/***************************CONTAINER TABLE NAME AND KEY TRANSFORMER CRUD AND GET *************************************************/
/***********************************************************************************************************************/

func Test_Container_TableName_KeyXfmr_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": ""}}
	//prereq := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
	url := "/openconfig-nat:nat/instances/instance[id=1]/config"

	fmt.Println("++++++++++++++  CREATE Test_Container_TableName_KeyXfmr  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	//loadConfigDB(rclient, prereq)

	post_payload := "{\"openconfig-nat:enable\":true,\"openconfig-nat:timeout\":456,\"openconfig-nat:tcp-timeout\":567,\"openconfig-nat:udp-timeout\":333}"
	post_expected := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": map[string]interface{}{"nat_udp_timeout": "333", "admin_mode": "enabled", "nat_tcp_timeout": "567", "nat_timeout": "456"}}}

	t.Run("CREATE on Container with TableName and Key transformer mapping", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with TableName and Key transformer", verifyDbResult(rclient, "NAT_GLOBAL|Values", post_expected, false))
	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_TableName_KeyXfmr_Replace(t *testing.T) {

	cleanuptbl := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": ""}}
	prereq := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": map[string]interface{}{"nat_udp_timeout": "333", "admin_mode": "enabled", "nat_tcp_timeout": "567", "nat_timeout": "456"}}}
	url := "/openconfig-nat:nat/instances/instance[id=1]/config"

	fmt.Println("++++++++++++++  REPLACE Test_Container_TableName_KeyXfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	put_payload := "{ \"openconfig-nat:config\": { \"enable\": true, \"tcp-timeout\": 770, \"udp-timeout\": 180 }}"
	put_expected := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": map[string]interface{}{"nat_udp_timeout": "180", "admin_mode": "enabled", "nat_tcp_timeout": "770"}}}

	t.Run("REPLACE on Container with TableName and Keytransformer mapping", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with TableName and Key transformer", verifyDbResult(rclient, "NAT_GLOBAL|Values", put_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_TableName_KeyXfmr_Update(t *testing.T) {

	cleanuptbl := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": ""}}
	prereq := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": map[string]interface{}{"nat_udp_timeout": "180", "admin_mode": "enabled", "nat_tcp_timeout": "770"}}}
	url := "/openconfig-nat:nat/instances/instance[id=1]/config"

	fmt.Println("++++++++++++++  UPDATE Test_Container_TableName_KeyXfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	patch_payload := "{\"openconfig-nat:config\":{\"enable\":false,\"timeout\":720,\"tcp-timeout\":580,\"udp-timeout\":280}}"
	patch_expected := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": map[string]interface{}{"nat_udp_timeout": "280", "admin_mode": "disabled", "nat_tcp_timeout": "580", "nat_timeout": "720"}}}

	t.Run("UPDATE on Container with TableName and Key transformer mapping", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with TableName and Key transformer", verifyDbResult(rclient, "NAT_GLOBAL|Values", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_TableName_KeyXfmr_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": ""}}
	prereq := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": map[string]interface{}{"nat_udp_timeout": "280", "admin_mode": "disabled", "nat_tcp_timeout": "580", "nat_timeout": "720"}}}
	url := "/openconfig-nat:nat/instances/instance[id=1]/config"

	fmt.Println("++++++++++++++  DELETE Test_Container_TableName_KeyXfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected := make(map[string]interface{})

	t.Run("DELETE on Container with TableName and Key transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with TableName and Key transformer", verifyDbResult(rclient, "NAT_GLOBAL|Values", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_TableName_KeyXfmr_Get(t *testing.T) {

	cleanuptbl := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": ""}}
	prereq := map[string]interface{}{"NAT_GLOBAL": map[string]interface{}{"Values": map[string]interface{}{"nat_udp_timeout": "333", "admin_mode": "enabled", "nat_tcp_timeout": "567", "nat_timeout": "456"}}}
	url := "/openconfig-nat:nat/instances/instance[id=1]/config"

	fmt.Println("++++++++++++++  GET Test_Container_TableName_KeyXfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-nat:config\":{\"enable\":true,\"tcp-timeout\":567,\"timeout\":456,\"udp-timeout\":333}}"

	t.Run("GET on Container with TableName and Key transformer mapping", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

/***********************************************************************************************************************/
/***************************CONTAINER INHERITED SUBTREE TRANSFORMER CRUD AND GET *************************************************/
/***********************************************************************************************************************/

func Test_Container_Inherited_Subtree_Xfmr_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": ""}, "VLAN": map[string]interface{}{"Vlan1": ""}}
	vrf_prereq := map[string]interface{}{"VRF": map[string]interface{}{"default": map[string]interface{}{"NULL": "NULL"}}}
	prereq := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}

	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces"

	fmt.Println("++++++++++++++  CREATE Test_Container_Inherited Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	loadConfigDB(rclient, vrf_prereq)
	loadConfigDB(rclient, prereq)

	post_payload := "{\"openconfig-network-instance-deviation:interface\":[{\"config\":{\"enabled\": true,\"last-member-query-interval\":1000,\"name\":\"Vlan1\",\"version\":3},\"name\":\"Vlan1\"}]}"
	post_expected := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"version": "3", "last-member-query-interval": "1000", "enabled": "true"}}}

	t.Run("CREATE on Container with Inherited Subtree transformer mapping", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with inherited subtree transformer", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", post_expected, false))
	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Inherited_Subtree_Xfmr_Replace(t *testing.T) {

	cleanuptbl := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": ""}, "VLAN": map[string]interface{}{"Vlan1": ""}}
	vrf_prereq := map[string]interface{}{"VRF": map[string]interface{}{"default": map[string]interface{}{"NULL": "NULL"}}}
	prereq := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"version": "3", "last-member-query-interval": "1000", "enabled": "true"}}, "VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}
	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/openconfig-network-instance-deviation:igmp-snooping/interfaces"

	fmt.Println("++++++++++++++  REPLACE Test_Container_Inherited_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, vrf_prereq)
	loadConfigDB(rclient, prereq)

	put_payload := "{\"openconfig-network-instance-deviation:interfaces\":{\"interface\":[{\"name\":\"Vlan1\",\"config\":{\"name\":\"Vlan1\",\"enabled\":true,\"last-member-query-interval\":2000}}]}}"
	put_expected := map[string]interface{}{"CFG_L2MC_TABLE": map[string]interface{}{"Vlan1": map[string]interface{}{"enabled": "true", "last-member-query-interval": "2000"}}}

	t.Run("REPLACE on Container with inherited subtree transformer mapping", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with inherited subtree transformer", verifyDbResult(rclient, "CFG_L2MC_TABLE|Vlan1", put_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Inherited_Subtree_Xfmr_Update(t *testing.T) {

	cleanuptbl1 := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": ""}}
	cleanuptbl2 := map[string]interface{}{"SAG": map[string]interface{}{"Vlan1|IPv4": ""}}
	cleanuptbl3 := map[string]interface{}{"VLAN_INTERFACE": map[string]interface{}{"Vlan1": ""}}
	prereq1 := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}
	prereq2 := map[string]interface{}{"VLAN_INTERFACE": map[string]interface{}{"Vlan1": map[string]interface{}{"NULL": "NULL"}}}
	prereq3 := map[string]interface{}{"SAG": map[string]interface{}{"Vlan1|IPv4": map[string]interface{}{"gwip@": "10.10.10.10/16"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Vlan1]/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/openconfig-interfaces-ext:sag-ipv4/config"

	fmt.Println("++++++++++++++  UPDATE Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq1)
	loadConfigDB(rclient, prereq2)
	loadConfigDB(rclient, prereq3)

	patch_payload := "{\"openconfig-interfaces-ext:config\":{\"static-anycast-gateway\":[\"20.20.20.20/16\"]}}"
	patch_expected := map[string]interface{}{"SAG": map[string]interface{}{"Vlan1|IPv4": map[string]interface{}{"gwip@": "10.10.10.10/16,20.20.20.20/16"}}}

	t.Run("UPDATE on Container Subtree transformer mapping", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with subtree transformer", verifyDbResult(rclient, "SAG|Vlan1|IPv4", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl1)
	unloadConfigDB(rclient, cleanuptbl2)
	unloadConfigDB(rclient, cleanuptbl3)

}

func Test_Container_Inherited_Subtree_Xfmr_TableOrderCheck_Update(t *testing.T) {

	cleanuptbl := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": ""}, "VLAN_MEMBER": map[string]interface{}{"Vlan1|Ethernet36": ""}}
	prereq := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet36]/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config"

	fmt.Println("++++++++++++++  UPDATE Test_Container_Inherited_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	patch_payload := "{ \"openconfig-vlan:config\": { \"access-vlan\": 1 }}"
	patch_expected_vlan := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1", "members@": "Ethernet36"}}}
	patch_expected_vlanmember := map[string]interface{}{"VLAN_MEMBER": map[string]interface{}{"Vlan1|Ethernet36": map[string]interface{}{"tagging_mode": "untagged"}}}

	t.Run("UPDATE on Container with inherited subtree transformer mapping", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify VLAN table update on container with inherited subtree transformer", verifyDbResult(rclient, "VLAN|Vlan1", patch_expected_vlan, false))
	t.Run("Verify VLAN MEMBER update on container with inherited subtree transformer", verifyDbResult(rclient, "VLAN_MEMBER|Vlan1|Ethernet36", patch_expected_vlanmember, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Inherited_Subtree_Xfmr_TableOrderCheck_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": ""}, "VLAN_MEMBER": map[string]interface{}{"Vlan1|Ethernet36": ""}}
	prereq := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}, "VLAN_MEMBER": map[string]interface{}{"Vlan1|Ethernet36": map[string]interface{}{"tagging_mode": "untagged"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet36]/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config"

	fmt.Println("++++++++++++++  DELETE Test_Container_Inherited_Subtree_TableOrderCheck_KeyXfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected_vlanmember := make(map[string]interface{})
	delete_expected_vlan := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}}

	t.Run("DELETE on Container with inherited subtree transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify vlan member delete on container with inherited subtree transformer", verifyDbResult(rclient, "VLAN_MEMBER|Vlan1|Ethernet36", delete_expected_vlanmember, false))
	t.Run("Verify vlan table update on container with inherited subtree transformer", verifyDbResult(rclient, "VLAN|Vlan1", delete_expected_vlan, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Inherited_Subtree_Xfmr_Get(t *testing.T) {

	cleanuptbl := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": ""}, "VLAN_MEMBER": map[string]interface{}{"Vlan1|Ethernet36": ""}}
	prereq := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}, "VLAN_MEMBER": map[string]interface{}{"Vlan1|Ethernet36": map[string]interface{}{"tagging_mode": "untagged"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet36]/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config"

	fmt.Println("++++++++++++++  GET Test_Inherited_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-vlan:config\":{\"access-vlan\":1,\"interface-mode\":\"ACCESS\"}}"

	t.Run("GET on Container with inherited subtree transformer mapping", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

/***********************************************************************************************************************/
/************************************ CONTAINER DB NAME ANNOTATION GET *************************************************/
/***********************************************************************************************************************/

func Test_Container_DB_Name_Annotation_Get(t *testing.T) {

	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet36]/state"

	fmt.Println("++++++++++++++  GET Test_Container_DB_Name_Annotation  +++++++++++++")

	// Setup - Prerequisite
	// None as we cannot write to non config DBs

	get_expected := "{\"openconfig-interfaces:state\":{\"admin-status\":\"DOWN\",\"counters\":{\"in-broadcast-pkts\":\"0\",\"in-discards\":\"0\",\"in-errors\":\"0\",\"in-multicast-pkts\":\"0\",\"in-octets\":\"0\",\"in-pkts\":\"0\",\"in-unicast-pkts\":\"0\",\"last-clear\":\"0\",\"openconfig-interfaces-ext:in-bits-per-second\":\"0\",\"openconfig-interfaces-ext:in-octets-per-second\":\"0\",\"openconfig-interfaces-ext:in-pkts-per-second\":\"0\",\"openconfig-interfaces-ext:in-utilization\":0,\"openconfig-interfaces-ext:out-bits-per-second\":\"0\",\"openconfig-interfaces-ext:out-octets-per-second\":\"0\",\"openconfig-interfaces-ext:out-pkts-per-second\":\"0\",\"out-broadcast-pkts\":\"0\",\"out-discards\":\"0\",\"out-errors\":\"0\",\"out-multicast-pkts\":\"0\",\"out-octets\":\"0\",\"out-pkts\":\"0\",\"out-unicast-pkts\":\"0\"},\"description\":\"\",\"enabled\":false,\"mtu\":9100,\"name\":\"Ethernet36\",\"openconfig-interfaces-ext:rate-interval\":10,\"oper-status\":\"DOWN\"}}"

	t.Run("GET on Container with DB Name annotation", processGetRequest(url, get_expected, false))

	// No Teardown for non config DB
}

func Test_Container_DB_Name_Annotation_Subtree_Get(t *testing.T) {

	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/state/counters"

	fmt.Println("++++++++++++++  GET Test_Container_DB_Name_Annotation  +++++++++++++")

	// Setup - Prerequisite
	// None as we cannot write to non config DBs

	get_expected := "{\"openconfig-interfaces:counters\": {\"in-broadcast-pkts\": \"0\",\"in-discards\": \"0\",\"in-errors\": \"0\",\"in-multicast-pkts\": \"0\",\"in-octets\": \"0\",\"in-pkts\": \"0\",\"in-unicast-pkts\": \"0\",\"last-clear\": \"0\",\"openconfig-interfaces-ext:in-bits-per-second\": \"0\",\"openconfig-interfaces-ext:in-octets-per-second\": \"0\",\"openconfig-interfaces-ext:in-pkts-per-second\": \"0\",\"openconfig-interfaces-ext:in-utilization\": 0,\"openconfig-interfaces-ext:out-bits-per-second\": \"0\",\"openconfig-interfaces-ext:out-octets-per-second\": \"0\",\"openconfig-interfaces-ext:out-pkts-per-second\": \"0\",\"out-broadcast-pkts\": \"0\",\"out-discards\": \"0\",\"out-errors\": \"0\",\"out-multicast-pkts\": \"0\",\"out-octets\": \"0\",\"out-pkts\": \"0\",\"out-unicast-pkts\": \"0\"}}"

	t.Run("GET on Container with DB Name annotation", processGetRequest(url, get_expected, false))

	// No Teardown for non config DB
}

/*func Test_Container_DB_Name_Annotation_Sonic_Get(t *testing.T) {

	cleanuptbl := map[string]interface{}{"INTF_TABLE":map[string]interface{}{"Vlan1":"","Ethernet4":"","Ethernet4:1.2.3.4/16":""}}
	prereq := map[string]interface{}{"INTF_TABLE":map[string]interface{}{"Vlan1":map[string]interface{}{"NULL":"NULL"},"Ethernet4":map[string]interface{}{"NULL":"NULL"},"Ethernet4:1.2.3.4/16":map[string]interface{}{"scope":"global","family":"IPV4"}}}
        url := "/sonic-interface/INTF_TABLE"

        fmt.Println("++++++++++++++  GET Test_DB_Name_Annotation_Sonic +++++++++++++")

        // Setup - Prerequisite
        unloadDB(int(db.ApplDB), cleanuptbl)
        loadDB(int(db.ApplDB), prereq)

        //get_expected := "{\"sonic-interface:INTF_TABLE\":{\"INTF_TABLE_IPADDR_LIST\":[{\"ifName\":\"Ethernet4\",\"ipPrefix\":\"1.2.3.4/16\"}],\"INTF_TABLE_LIST\":[{\"ifName\":\"Ethernet4\"},{\"ifName\":\"Vlan1\"}]}}"
        get_expected := "{\"sonic-interface:INTF_TABLE\":{\"INTF_TABLE_LIST\":[{\"ifName\":\"Vlan1\"}]}}"

        t.Run("GET on Container with inherited subtree transformer mapping", processGetRequest(url, get_expected, false))

        // Teardown
        unloadDB(int(db.ApplDB), cleanuptbl)
}
*/

/***********************************************************************************************************************/
/*************************** CONTAINER NESTED SUBTREE TRANSFORMER CRUD AND GET *****************************************/
/***********************************************************************************************************************/

func Test_Container_Nested_Subtree_Xfmr_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"INTERFACE": map[string]interface{}{"Etherner4": "", "Ethernet|1.2.3.4/16": ""}}
	//prereq := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4"

	fmt.Println("++++++++++++++  CREATE Test_Container_Nested Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	//loadConfigDB(rclient, prereq)

	post_payload := "{\"openconfig-if-ip:addresses\":{\"address\":[{\"ip\":\"1.2.3.4\",\"config\":{\"ip\":\"1.2.3.4\",\"prefix-length\":16}}]},\"openconfig-if-ip:neighbors\":{\"neighbor\":[{\"ip\":\"2.3.4.5\",\"config\":{\"ip\":\"2.3.4.5\",\"link-layer-address\":\"22:33:44:55:66:77\"}}]}}"
	post_expected_1 := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": map[string]interface{}{"NULL": "NULL"}}}
	post_expected_2 := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4|1.2.3.4/16": map[string]interface{}{"NULL": "NULL"}}}

	t.Run("CREATE on Container Subtree transformer mapping", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with Nested Subtree transformer", verifyDbResult(rclient, "INTERFACE|Ethernet4", post_expected_1, false))
	t.Run("Verify create on container with Nested Subtree transformer", verifyDbResult(rclient, "INTERFACE|Ethernet4|1.2.3.4/16", post_expected_2, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Nested_Subtree_Xfmr_SubOpMap_OperationOrder_Replace(t *testing.T) {

	cleanuptbl := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": "", "Ethernet4|1.2.3.5/8": ""}}
	prereq := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": map[string]interface{}{"NULL": "NULL"}, "Ethernet4|1.2.3.4/16": map[string]interface{}{"NULL": "NULL"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4"

	fmt.Println("++++++++++++++  REPLACE Test_Container_Nested_Subtree_Xfmr_SubOpMap_OperationOrder  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	put_payload := "{\"openconfig-if-ip:ipv4\":{\"addresses\":{\"address\":[{\"ip\":\"1.2.3.5\",\"config\":{\"ip\":\"1.2.3.5\",\"prefix-length\":8}}]}}}"
	put_expected1 := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4|1.2.3.5/8": map[string]interface{}{"NULL": "NULL"}}}
	put_expected2 := make(map[string]interface{})

	t.Run("REPLACE on Container with Nested Subtree, SubopMap and Operation Order ", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with nested subtree SubopMap and Operation order", verifyDbResult(rclient, "INTERFACE|Ethernet4|1.2.3.5/8", put_expected1, false))
	t.Run("Verify replace on container with nested subtree subopMap and Operation Order", verifyDbResult(rclient, "INTERFACE|Ethernet4|1.2.3.4/16", put_expected2, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Nested_Subtree_Xfmr_SubOpMap_OperationOrder_Update(t *testing.T) {

	cleanuptbl := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": "", "Ethernet4|1.2.3.5/8": "", "Ethernet4|11.2.3.6/24": ""}}
	prereq := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": map[string]interface{}{"NULL": "NULL"}, "Ethernet4|1.2.3.5/8": map[string]interface{}{"NULL": "NULL"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4"

	fmt.Println("++++++++++++++  UPDATE Test_Container_Nested_Subtree_Xfmr_SubOpMap_OperationOrder  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	patch_payload := "{\"openconfig-if-ip:ipv4\":{\"addresses\":{\"address\":[{\"ip\":\"11.2.3.6\",\"config\":{\"ip\":\"11.2.3.6\",\"prefix-length\":24}}]}}}"
	patch_expected := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4|11.2.3.6/24": map[string]interface{}{"NULL": "NULL"}}}

	t.Run("UPDATE on Container Subtree transformer mapping", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with nested subtree, SubOpMAp and OperOrder", verifyDbResult(rclient, "INTERFACE|Ethernet4|11.2.3.6/24", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Nested_Subtree_Xfmr_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": "", "Ethernet4|1.2.3.5/8": ""}}
	prereq := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": map[string]interface{}{"NULL": "NULL"}, "Ethernet4|1.2.3.4/16": map[string]interface{}{"NULL": "NULL"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses"

	fmt.Println("++++++++++++++  DELETE Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected := make(map[string]interface{})

	t.Run("DELETE on Container subtree transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify delete on container with nested subtree transformer", verifyDbResult(rclient, "INTERFACE|Ethernet4", delete_expected, false))
	t.Run("Verify delete on container with nested subtree transformer", verifyDbResult(rclient, "INTERFACE|Ethernet4|1.2.3.4/16", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Nested_Subtree_Xfmr_Get(t *testing.T) {

	//cleanuptbl := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4":"", "Ethernet4|*":""}}
	cleanuptbl := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": "", "Ethernet4|1.2.3.5/8": "", "Ethernet4|11.2.3.6/24": ""}}
	prereq := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet4": map[string]interface{}{"NULL": "NULL"}, "Ethernet4|1.2.3.4/16": map[string]interface{}{"NULL": "NULL"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet4]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4"

	fmt.Println("++++++++++++++  GET Test_Container_Subtree_Xfmr  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-if-ip:ipv4\": {\"addresses\": {\"address\": [{\"config\": {\"ip\": \"1.2.3.4\",\"openconfig-interfaces-ext:secondary\": false,\"prefix-length\": 16},\"ip\": \"1.2.3.4\",\"state\": {\"ip\": \"1.2.3.4\",\"openconfig-interfaces-ext:secondary\": false,\"prefix-length\": 16}}]},\"openconfig-ospfv2-ext:ospfv2\": {\"if-addresses\":[{\"address\": \"Ethernet4\"},{\"address\": \"Ethernet4|1.2.3.4/16\"}]}}}"

	t.Run("GET on Container Nested subtree transformer mapping", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

/***********************************************************************************************************************/
/*************************** CONTAINER TABLE ORDER CHECK CRUD AND GET **************************************************/
/***********************************************************************************************************************/

func Test_Container_Table_Order_Check_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": ""}, "ACL_RULE": map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1": ""}}
	url := "/sonic-acl:sonic-acl"

	fmt.Println("++++++++++++++  CREATE Test_Container_Table_order_Check  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)

	post_payload := "{\"sonic-acl:ACL_TABLE\":{\"ACL_TABLE_LIST\":[{\"aclname\":\"MyACL1_ACL_IPV4\",\"policy_desc\":\"Description for MyACL1\", \"type\":\"L3\" } ] },\"sonic-acl:ACL_RULE\": { \"ACL_RULE_LIST\": [ { \"aclname\": \"MyACL1_ACL_IPV4\", \"rulename\": \"RULE_1\", \"PRIORITY\": 65534,  \"DESCRIPTION\": \"Description for MyACL1\", \"PACKET_ACTION\": \"FORWARD\", \"IP_TYPE\": \"IPV4\", \"IP_PROTOCOL\": 6, \"SRC_IP\": \"10.1.1.1/32\", \"DST_IP\": \"20.2.2.2/32\" }]}}"

	/*"{\"sonic-acl:ACL_TABLE\":{\"ACL_TABLE_LIST\":[{\"aclname\":\"MyACL1_ACL_IPV4\",\"policy_desc\":\"Description for MyACL1\"}]},\"sonic-acl:ACL_RULE\":{\"ACL_RULE_LIST\":[{\"aclname\":\"MyACL1_ACL_IPV4\",\"rulename\":\"RULE_1\",\"PRIORITY\": 65534,\"RULE_DESCRIPTION\":\"Description for MyACL1\",\"PACKET_ACTION\":\"FORWARD\",\"IP_TYPE\":\"IPV4\",\"IP_PROTOCOL\":6,\"SRC_IP\":\"10.1.1.1/32\",\"DST_IP\":\"20.2.2.2/32\"}]}}"*/
	post_expected_1 := map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{"type": "L3", "policy_desc": "Description for MyACL1"}}}
	post_expected_2 := map[string]interface{}{"ACL_RULE": map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1": map[string]interface{}{"PRIORITY": "65534", "SRC_IP": "10.1.1.1/32", "DST_IP": "20.2.2.2/32", "IP_TYPE": "IPV4", "DESCRIPTION": "Description for MyACL1", "IP_PROTOCOL": "6", "PACKET_ACTION": "FORWARD"}}}

	t.Run("CREATE on Container for table order check", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container for Table Order check", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", post_expected_1, false))
	t.Run("Verify create on container for Table Order check", verifyDbResult(rclient, "ACL_RULE|MyACL1_ACL_IPV4|RULE_1", post_expected_2, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Table_Order_Check_Replace(t *testing.T) {

	cleanuptbl := map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": ""}, "ACL_RULE": map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1": ""}}
	prereq := map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{"policy_desc": "Description for MyACL1"}}, "ACL_RULE": map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1": map[string]interface{}{"PRIORITY": "65534", "SRC_IP": "10.1.1.1/32", "DST_IP": "20.2.2.2/32", "IP_TYPE": "IPV4", "RULE_DESCRIPTION": "Description for MyACL1", "IP_PROTOCOL": "6", "PACKET_ACTION": "FORWARD"}}}
	url := "/sonic-acl:sonic-acl"

	fmt.Println("++++++++++++++  REPLACE Test_Container_Table_order_check +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	put_payload := "{\"sonic-acl:sonic-acl\":{\"ACL_TABLE\":{\"ACL_TABLE_LIST\":[{\"aclname\":\"MyACL1_ACL_IPV4\",\"policy_desc\":\"Updated MyACL1\",\"type\":\"L3\"}]},\"ACL_RULE\":{\"ACL_RULE_LIST\":[{\"aclname\":\"MyACL1_ACL_IPV4\",\"rulename\":\"RULE_1\",\"IP_TYPE\":\"IPV4\",\"IP_PROTOCOL\":6,\"SRC_IP\":\"10.1.1.1/32\",\"DST_IP\":\"20.5.5.5/16\"}]}}}"
	put_expected_1 := map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{"policy_desc": "Updated MyACL1", "type": "L3"}}}
	put_expected_2 := map[string]interface{}{"ACL_RULE": map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1": map[string]interface{}{"SRC_IP": "10.1.1.1/32", "DST_IP": "20.5.5.5/16", "IP_TYPE": "IPV4", "IP_PROTOCOL": "6"}}}

	t.Run("REPLACE on Container Table order check", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container for Table Order check", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", put_expected_1, false))
	t.Run("Verify replace on container for Table Order check", verifyDbResult(rclient, "ACL_RULE|MyACL1_ACL_IPV4|RULE_1", put_expected_2, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

/***********************************************************************************************************************/
/*************************** CONTAINER USER DEFINED TABLE ORDER CHECK DELETE *******************************************/
/***********************************************************************************************************************/

func Test_Container_UserDefined_TableOrder_Delete(t *testing.T) {

	prereq := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan1": map[string]interface{}{"vlanid": "1"}}, "VRF": map[string]interface{}{"default": map[string]interface{}{"enabled": "true"}}, "BGP_GLOBALS": map[string]interface{}{"default": map[string]interface{}{"local_asn": "200"}}, "BGP_PEER_GROUP": map[string]interface{}{"default|test": map[string]interface{}{"NULL": "NULL"}}, "BGP_NEIGHBOR": map[string]interface{}{"default|1.1.1.1": map[string]interface{}{"NULL": "NULL", "asn": "100"}, "default|Vlan1": map[string]interface{}{"NULL": "NULL"}}}
	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/config"

	fmt.Println("++++++++++++++  DELETE Test_Container_UserDefined_TableOrder  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected1 := map[string]interface{}{"BGP_GLOBALS": map[string]interface{}{"default": map[string]interface{}{"NULL": "NULL"}}}
	delete_expected2 := map[string]interface{}{"BGP_NEIGHBOR": map[string]interface{}{"default|Vlan1": map[string]interface{}{"NULL": "NULL"}}}
	//   delete_expected3 := map[string]interface{}{"BGP_NEIGHBOR":map[string]interface{}{"default|1.1.1.1":map[string]interface{}{"NULL":"NULL"}}}
	delete_expected4 := map[string]interface{}{"BGP_NEIGHBOR": map[string]interface{}{"default|test": map[string]interface{}{"NULL": "NULL"}}}

	t.Run("DELETE on Container subtree transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify delete on container with user defined table order", verifyDbResult(rclient, "BGP_GLOBALS|default", delete_expected1, false))
	t.Run("Verify delete on container with user defined table order", verifyDbResult(rclient, "BGP_NEIGHBOR|default|Vlan1", delete_expected2, false))
	//	t.Run("Verify delete on container with user defined table order", verifyDbResult(rclient, "BGP_NEIGHBOR|default|1.1.1.1", delete_expected3, false))
	t.Run("Verify delete on container with user defined table order", verifyDbResult(rclient, "BGP_PEER_GROUP|default|test", delete_expected4, false))

	// Teardown
	unloadConfigDB(rclient, prereq)
}

/***********************************************************************************************************************/
/*************************** CONTAINER SUBOP MAP HANDLING CRUD and GET *************************************************/
/***********************************************************************************************************************/

/*
func Test_Container_SubOpMap_Create(t *testing.T) {

        cleanuptbl := map[string]interface{}{"SSH_SERVER_VRF":map[string]interface{}{"mgmt":""}}
        prereq := map[string]interface{}{"SSH_SERVER_VRF":map[string]interface{}{"mgmt":map[string]interface{}{"NULL":"NULL"}}}
        url := "/openconfig-network-instance:network-instances/network-instance[name=mgmt]"

        fmt.Println("++++++++++++++  CREATE Test_Container_SubOpMap  +++++++++++++")

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl)
        loadConfigDB(rclient, prereq)

        post_payload := "{\"openconfig-network-instance:config\":{\"name\":\"mgmt\",\"type\":\"L2P2P\",\"enabled\":true,\"description\":\"test mgmt vrf\",\"mtu\":2500}}"
        post_expected := map[string]interface{}{"SSH_SERVER_VRF":map[string]interface{}{"mgmt":map[string]interface{}{"port":"22"}}}

        t.Run("CREATE on Container with SubOper Map merging", processSetRequest(url, post_payload, "POST", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify create on container for Table Order check", verifyDbResult(rclient, "SSH_SERVER_VRF|mgmt", post_expected, false))

	// Teardown
        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_SubOperMap_Delete1(t *testing.T) {

	prereq := map[string]interface{}{"VRF":map[string]interface{}{"default":map[string]interface{}{"enabled":"true"}},"BGP_GLOBALS":map[string]interface{}{"default":map[string]interface{}{"local_asn":"200"}},"BGP_NEIGHBOR":map[string]interface{}{"default|1.2.3.4":map[string]interface{}{"NULL":"NULL"}},"BGP_NEIGHBOR_AF":map[string]interface{}{"default|1.2.3.4|ipv4_unicast":map[string]interface{}{"send_community":"standard"}}}
	url := "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=1.2.3.4]/afi-safis/afi-safi[afi-safi-name=IPV4_UNICAST]/config/openconfig-bgp-ext:send-community"

        fmt.Println("++++++++++++++  DELETE Test_Container_SubOperMap  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	delete_expected_update := map[string]interface{}{"BGP_NEIGHBOR_AF":map[string]interface{}{"default|1.2.3.4|ipv4_unicast":map[string]interface{}{"send_community":"both"}}}

        t.Run("DELETE on Container subtree transformer mapping", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on container with SubOperMap handling", verifyDbResult(rclient, "BGP_NEIGHBOR_AF|default|1.2.3.4|ipv4_unicast", delete_expected_update, false))

	// Teardown
        unloadConfigDB(rclient, prereq)
}
*/
func Test_Container_SubOperMap_Delete2(t *testing.T) {

	prereq := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan2": map[string]interface{}{"vlanid": "2", "members@": "Ethernet32"}}, "VLAN_MEMBER": map[string]interface{}{"Vlan2|Ethernet32": map[string]interface{}{"tagging_mode": "untagged"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Vlan2]"

	fmt.Println("++++++++++++++  DELETE Test_Container_SubOperMap  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected := make(map[string]interface{})

	t.Run("DELETE on Container subtree transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify delete on container with SubOperMap handling", verifyDbResult(rclient, "VLAN|Vlan2", delete_expected, false))
	t.Run("Verify delete on container with SubOperMap handling", verifyDbResult(rclient, "VLAN_MEMBER|Vlan2|Ethernet32", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, prereq)
}

/***********************************************************************************************************************/
/*************************** CONTAINER ONE TO ONE MAPPING SONIC CRUD and GET *************************************************/
/***********************************************************************************************************************/

func Test_Container_OneToOne_Mapping_Sonic_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": ""}}
	url := "/sonic-sflow:sonic-sflow/SFLOW_COLLECTOR"

	fmt.Println("++++++++++++++  CREATE  Test_Container_OneToOne_Mapping_Sonic  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)

	post_payload := "{\"sonic-sflow:SFLOW_COLLECTOR_LIST\":[{\"collector_name\":\"test\",\"collector_ip\":\"1.2.3.4\",\"collector_port\":50}]}"
	post_expected := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": map[string]interface{}{"collector_ip": "1.2.3.4", "collector_port": "50"}}}

	t.Run("CREATE on Container with OneonOne Sonic mapping", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with Subtree transformer", verifyDbResult(rclient, "SFLOW_COLLECTOR|test", post_expected, false))
	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_OneToOne_Mapping_Sonic_Replace(t *testing.T) {

	cleanuptbl := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": ""}}
	prereq := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": map[string]interface{}{"collector_ip": "1.2.3.4", "collector_port": "50"}}}
	url := "/sonic-sflow:sonic-sflow/SFLOW_COLLECTOR"

	fmt.Println("++++++++++++++  REPLACE Test_Container_OneToOne_Mapping_Sonic +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	put_payload := "{\"sonic-sflow:SFLOW_COLLECTOR\":{\"SFLOW_COLLECTOR_LIST\":[{\"collector_name\":\"test\",\"collector_ip\":\"2.3.4.5\"}]}}"
	put_expected := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": map[string]interface{}{"collector_ip": "2.3.4.5"}}}

	t.Run("REPLACE on Container with OneonOne Sonic mapping", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with OneonOne Sonic mapping", verifyDbResult(rclient, "SFLOW_COLLECTOR|test", put_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_OneToOne_Mapping_Sonic_Update(t *testing.T) {

	cleanuptbl := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": ""}}
	prereq := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": map[string]interface{}{"collector_ip": "2.3.4.5"}}}
	url := "/sonic-sflow:sonic-sflow/SFLOW_COLLECTOR"

	fmt.Println("++++++++++++++  UPDATE Test_Container_OneToOne_Mapping_Sonic  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	patch_payload := "{\"sonic-sflow:SFLOW_COLLECTOR\":{\"SFLOW_COLLECTOR_LIST\":[{\"collector_name\":\"test\",\"collector_ip\":\"2.3.4.5\",\"collector_port\":45}]}}"
	patch_expected := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": map[string]interface{}{"collector_ip": "2.3.4.5", "collector_port": "45"}}}

	t.Run("UPDATE on Container Subtree transformer mapping", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with subtree transformer", verifyDbResult(rclient, "SFLOW_COLLECTOR|test", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_OneToOne_Mapping_Sonic_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": ""}}
	prereq := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": map[string]interface{}{"collector_ip": "2.3.4.5", "collector_port": "45"}}}
	url := "/sonic-sflow:sonic-sflow/SFLOW_COLLECTOR"

	fmt.Println("++++++++++++++  DELETE Test_Container_OneToOne_Mapping_Sonic  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected := make(map[string]interface{})

	t.Run("DELETE on Container subtree transformer mapping", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with subtree transformer", verifyDbResult(rclient, "SFLOW_COLLECTOR|test", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_OneToOne_Mapping_Sonic_Get(t *testing.T) {

	cleanuptbl := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": ""}}
	prereq := map[string]interface{}{"SFLOW_COLLECTOR": map[string]interface{}{"test": map[string]interface{}{"collector_ip": "2.3.4.5", "collector_port": "45"}}}
	url := "/sonic-sflow:sonic-sflow/SFLOW_COLLECTOR"

	fmt.Println("++++++++++++++  GET Test_Container_OneToOne_Mapping_Sonic  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	get_expected := "{\"sonic-sflow:SFLOW_COLLECTOR\":{\"SFLOW_COLLECTOR_LIST\":[{\"collector_ip\":\"2.3.4.5\",\"collector_name\":\"test\",\"collector_port\":45}]}}"

	t.Run("GET on Container subtree transformer mapping", processGetRequest(url, get_expected, false))

	unloadConfigDB(rclient, cleanuptbl)
}

/***********************************************************************************************************************/
/*********************CONTAINER DEFAULT VALUE FILLING AND NO MAPPING TO REDIS CRUD AND GET *****************************/
/***********************************************************************************************************************/

func Test_Container_Default_Value_Fill_NoMappingToRedis_Create(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"NULL": "NULL"}}}

	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"

	fmt.Println("++++++++++++++  CREATE Test_Container_Default_Value_Fill_NoMappingToRedis  +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	loadConfigDB(rclient, prereq)

	post_payload := "{\"mtu\":3000,\"loopback-mode\":true,\"description\":\"test-descp1\",\"openconfig-vlan:tpid\":\"TPID_0X8100\"}"
	post_expected := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "3000", "NULL": "NULL", "description": "test-descp1"}}}

	t.Run("CREATE on Container Default Value Fill & NoMappingToRedis", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with Default Value Fill & NoMappingToRedis", verifyDbResult(rclient, "PORT|Ethernet32", post_expected, false))
	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Default_Value_Fill_NoMappingToRedis_Replace1(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "3500", "admin_status": "down", "description": "desc-1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"

	fmt.Println("++++++++++++++  REPLACE Test_Container_Default_Value_Fill_NoMappingToRedis 1 +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	loadConfigDB(rclient, prereq)

	put_payload := "{\"openconfig-interfaces:config\":{\"name\":\"Ethernet32\",\"mtu\":3700,\"loopback-mode\":true,\"description\":\"desc-2\",\"openconfig-vlan:tpid\":\"TPID_0X8100\", \"enabled\":false}}"
	put_expected := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "3700", "admin_status": "down", "description": "desc-2"}}}

	t.Run("REPLACE on Container with Default_Value_Fill_NoMappingToRedis 1", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with Default_Value_Fill_NoMappingToRedis 1", verifyDbResult(rclient, "PORT|Ethernet32", put_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Default_Value_Fill_NoMappingToRedis_Replace2(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "3500", "admin_status": "down", "description": "desc-1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"

	fmt.Println("++++++++++++++  REPLACE Test_Container_Default_Value_Fill_NoMappingToRedis 2 +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	loadConfigDB(rclient, prereq)

	put_payload := "{\"openconfig-interfaces:config\":{\"name\":\"Ethernet32\",\"mtu\":3700,\"loopback-mode\":true,\"description\":\"desc-2\",\"openconfig-vlan:tpid\":\"TPID_0X8100\"}}"
	put_expected := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "3700", "admin_status": "up", "description": "desc-2"}}}

	t.Run("REPLACE on Container with Default_Value_Fill_NoMappingToRedis 2", processSetRequest(url, put_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with Default_Value_Fill_NoMappingToRedis 2", verifyDbResult(rclient, "PORT|Ethernet32", put_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Container_Default_Value_Fill_NoMappingToRedis_Update(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "9100", "admin_status": "down", "description": "desc-1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"

	fmt.Println("++++++++++++++  UPDATE Test_Container_Default_Value_Fill_NoMappingToRedis_Update  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	patch_payload := "{\"openconfig-interfaces:config\":{\"name\":\"Ethernet32\",\"mtu\":3700,\"loopback-mode\":true,\"enabled\":true,\"description\":\"desc-2\",\"openconfig-vlan:tpid\":\"TPID_0X8100\"}}"
	patch_expected := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "3700", "admin_status": "up", "description": "desc-2"}}}

	t.Run("UPDATE on with Default_Value_Fill_NoMappingToRedis", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with Default_Value_Fill_NoMappingToRedis", verifyDbResult(rclient, "PORT|Ethernet32", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Default_Value_Fill_ValueXfmr_Update(t *testing.T) {
	cleanuptbl := map[string]interface{}{"VLAN_SUB_INTERFACE": map[string]interface{}{"Eth0.23": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet0": map[string]interface{}{"mtu": "9100", "admin_status": "down", "description": "desc-1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces"

	fmt.Println("++++++++++++++  UPDATE/CREATE Test_Default_Value_Fill_ValueXfmr  +++++++++++++")
	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	patch_payload := "{\"openconfig-interfaces:subinterfaces\":{\"subinterface\":[{\"index\":23,\"config\":{\"index\":23}}]}}"
	patch_expected := map[string]interface{}{"VLAN_SUB_INTERFACE": map[string]interface{}{"Eth0.23": map[string]interface{}{"admin_status": "up", "parent": "Ethernet0"}}}

	t.Run("UPDATE on with Default_Value_Fill_ValueXfmr", processSetRequest(url, patch_payload, "PATCH", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify update on container with Default_Value_Fill_ValueXfmr", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.23", patch_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Default_And_Aux_Value_Fill_ValueXfmr_Replace(t *testing.T) {
	cleanuptbl := map[string]interface{}{"VLAN_SUB_INTERFACE": map[string]interface{}{"Eth0.23": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet0": map[string]interface{}{"mtu": "9100", "admin_status": "down", "description": "desc-1"}},
		"VLAN_SUB_INTERFACE": map[string]interface{}{"Eth0.23": map[string]interface{}{"mtu": "9100", "admin_status": "down", "parent": "Ethernet0", "description": "subintf-desc"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=23]/config"

	fmt.Println("++++++++++++++  REPLACE Test_Default_And_Aux_Value_Fill_ValueXfmr  +++++++++++++")
	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	replace_payload := "{\"config\":{\"index\":23,\"mtu\":9200}}"
	replace_expected := map[string]interface{}{"VLAN_SUB_INTERFACE": map[string]interface{}{"Eth0.23": map[string]interface{}{"admin_status": "up", "parent": "Ethernet0", "mtu": 9200}}}

	t.Run("REPLACE on with Default_And_Aux_Value_Fill_ValueXfmr", processSetRequest(url, replace_payload, "PUT", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify replace on container with Default_iand_Aux_Value_Fill_ValueXfmr", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.23", replace_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Default_Value_Fill_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "9100", "admin_status": "down", "description": "desc-1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config/enabled"

	fmt.Println("++++++++++++++  DELETE Test_NoMappingToRedis  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "9100", "admin_status": "up", "description": "desc-1"}}}

	t.Run("DELETE on NoMappingToRedis entry", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify delete entry with NoMappingToRedis", verifyDbResult(rclient, "PORT|Ethernet32", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_NoMappingToRedis_Delete(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "9100", "admin_status": "down", "description": "desc-1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config/loopback-mode"

	fmt.Println("++++++++++++++  DELETE Test_NoMappingToRedis  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	delete_expected := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "9100", "admin_status": "down", "description": "desc-1"}}}

	t.Run("DELETE on NoMappingToRedis entry", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify delete entry with NoMappingToRedis", verifyDbResult(rclient, "PORT|Ethernet32", delete_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Default_Value_Fill_Get_NoMappingToRedis(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "9100", "admin_status": "down", "description": "desc-1"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"

	fmt.Println("++++++++++++++  GET Test_Default_Value_Fill_NoMappingToRedis  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-interfaces:config\":{\"description\":\"desc-1\",\"enabled\":false,\"mtu\":9100,\"name\":\"Ethernet32\",\"type\":\"iana-if-type:ethernetCsmacd\"}}"

	t.Run("GET on Container with Default Value Fill and NoMappingToRedis", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_Ygot_Merge_Xfmr_Infra_Get(t *testing.T) {

	cleanuptbl := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": ""}}
	prereq := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{"mtu": "9100", "admin_status": "up"}}}
	url := "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/config"

	fmt.Println("++++++++++++++  Get Test_Ygot_Merge_Xfmr_Infra  +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-interfaces:config\":{\"enabled\":true,\"mtu\":9100,\"name\":\"Ethernet32\",\"type\":\"iana-if-type:ethernetCsmacd\"}}"

	t.Run("GET on Ygot Merge Xfmr Infra", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)

}

func Test_PyLdWithPathKeyVal_Create(t *testing.T) {
	cleanuptbl := map[string]interface{}{"DIALOUT_SENSOR_GROUP": map[string]interface{}{"sg1": ""},
		"DIALOUT_SENSOR_PATH": map[string]interface{}{"sg1|/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config": ""}}
	prereq := map[string]interface{}{"DIALOUT_SENSOR_GROUP": map[string]interface{}{"sg1": map[string]interface{}{"NULL": "NULL"}}}

	url := "/openconfig-telemetry:telemetry-system/sensor-groups"

	fmt.Println("++++++++++++++  CREATE Test_PyLdWithPathKeyVal_Create +++++++++++++")

	// Setup - Prerequisite
	unloadConfigDB(rclient, cleanuptbl)
	loadConfigDB(rclient, prereq)

	post_payload := "{\"openconfig-telemetry:sensor-group\":[{\"sensor-group-id\":\"sg1\",\"config\":{\"sensor-group-id\":\"sg1\"},\"sensor-paths\":{\"sensor-path\":[{\"path\":\"/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config\",\"config\":{\"path\":\"/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config\"}}]}}]}"
	post_expected := map[string]interface{}{"DIALOUT_SENSOR_PATH": map[string]interface{}{"sg1|/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config": map[string]interface{}{"NULL": "NULL"}}}

	t.Run("CREATE on Container with payload having path in key value", processSetRequest(url, post_payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("Verify create on container with payload having path in key value", verifyDbResult(rclient, "DIALOUT_SENSOR_PATH|sg1|/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config", post_expected, false))
	// Teardown
	unloadConfigDB(rclient, cleanuptbl)
}

func Test_PyLdWithPathKeyVal_Get(t *testing.T) {
	cleanuptbl := map[string]interface{}{"DIALOUT_SENSOR_GROUP": map[string]interface{}{"sg1": ""},
		"DIALOUT_SENSOR_PATH": map[string]interface{}{"sg1|/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config": ""}}
	prereq := map[string]interface{}{"DIALOUT_SENSOR_GROUP": map[string]interface{}{"sg1": map[string]interface{}{"NULL": "NULL"}},
		"DIALOUT_SENSOR_PATH": map[string]interface{}{"sg1|/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config": map[string]interface{}{"NULL": "NULL"}}}

	url := "/openconfig-telemetry:telemetry-system/sensor-groups"

	fmt.Println("++++++++++++++  Get Test_PyLdWithPathKeyVal +++++++++++++")

	// Setup - Prerequisite
	loadConfigDB(rclient, prereq)

	get_expected := "{\"openconfig-telemetry:sensor-groups\":{\"sensor-group\":[{\"config\":{\"sensor-group-id\":\"sg1\"},\"sensor-group-id\":\"sg1\",\"sensor-paths\":{\"sensor-path\":[{\"config\":{\"path\":\"/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config\"},\"path\":\"/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config\",\"state\":{\"path\":\"/openconfig-interfaces:interfaces/interface[name=Ethernet0]/config\"}}]},\"state\":{\"sensor-group-id\":\"sg1\"}}]}}"

	t.Run("GET on container having path as key value element", processGetRequest(url, get_expected, false))

	// Teardown
	unloadConfigDB(rclient, cleanuptbl)

}

/* test leafref datatype resolution for leafref with absoulte path and having leafref to leafref reference */
// TODO: Enable when ip-helper/interface-ref yang is added to modela/yang
/*
func Test_OC_Leafref_Resolve_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"UDP_BROADCAST_FORWARDING":map[string]interface{}{"Ports":""}}
        prereq := map[string]interface{}{"UDP_BROADCAST_FORWARDING":map[string]interface{}{"Ports":map[string]interface{}{"interface":"Ethernet0", "subinterface":"10", "include_ports@", "69,53,37,137,138,49"}}}
        url := "/openconfig-ip-helper:ip-helper/interface-ref"

        fmt.Println("++++++++++++++  Get Test_OC_Leafref_Resolve  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-ip-helper:interface-ref\":{\"config\":{\"interface\":\"Ethernet0\",\"subinterface\":10}}}"

        t.Run("GET OC Leafref Resolve", processGetRequest(url, get_expected, false))

        // Teardown
        unloadConfigDB(rclient, cleanuptbl)

}

*/
/*
// TODO: Enable when VLAN_SUB_INTERFACE_REF table is added to sonic-interface yang
func Test_Sonic_Leafref_Resolve_Get(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"VLAN_SUB_INTERFACE_REF":map[string]interface{}{"Eth0.6":""}}
        cleanuptbl2 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.6":""}}
        cleanuptbl3 := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet0":""}}
        prereq1 := map[string]interface{}{"VLAN_SUB_INTERFACE_REF":map[string]interface{}{"Eth0.6":map[string]interface{}{"subintfidx":"6", "parent":"Ethernet0"}}}
	prereq2 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.6":map[string]interface{}{"index":"6", "admin_status":"up","vrf_name":"Vrf1","ifName":"Ethernet0"}}}
	prereq3 := map[string]interface{}{"PORT":map[string]interface{}{"Ethernet0":map[string]interface{}{"admin_status":"up", "index":"1", "alias":"Eth1/1/1", "lanes":"49,50,51,52","speed":"100000"}}}
        url := "/sonic-interface:sonic-interface/VLAN_SUB_INTERFACE_REF"

        fmt.Println("++++++++++++++  Get Test_Sonic_Leafref_Resolve  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)
        loadConfigDB(rclient, prereq3)

        get_expected := "{\"sonic-interface:VLAN_SUB_INTERFACE_REF\":{\"VLAN_SUB_INTERFACE_REF_LIST\":[{\"parent\":\"Ethernet0\",\"subifid\":\"Ethernet0.6\"}]}}"

        t.Run("GET Sonic Leafref Resolve", processGetRequest(url, get_expected, false))

        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
        unloadConfigDB(rclient, cleanuptbl3)

}

// TODO: Enable when VLAN_SUB_INTERFACE_IPADDR_LIST/id is changed to leafref in sonic-interface yang
func Test_Sonic_Leafref_WithinTable_Resolve_Get(t *testing.T) {

	cleanuptbl1 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20|20.1.1.1/24":""}}
        cleanuptbl2 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20":""}}
	prereq1 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20|20.1.1.1/24":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20":map[string]interface{}{"NULL":"NULL"}}}
        url := "/sonic-interface:sonic-interface/VLAN_SUB_INTERFACE"

        fmt.Println("++++++++++++++  Get Test_Sonic_Leafref_Resolve_Within_Same_Table  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        get_expected := "{\"sonic-interface:VLAN_SUB_INTERFACE\":{\"VLAN_SUB_INTERFACE_IPADDR_LIST\":[{\"id\":\"Ethernet0.20\",\"ip_prefix\":\"20.1.1.1/24\"}],\"VLAN_SUB_INTERFACE_LIST\":[{\"id\":\"Ethernet0.20\"}]}}"

        t.Run("GET Sonic Leafref Resolve", processGetRequest(url, get_expected, false))

        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)

}

// TODO: Enable when VLAN_SUB_INTERFACE_IPADDR_LIST/id is changed to leafref in sonic-interface yang
func Test_Leafref_WithinSonicTable_Resolve_Patch(t *testing.T) {

	cleanuptbl1 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20|0.1.1.1/24":""}}
        cleanuptbl2 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20":""}}
	expected1 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20":map[string]interface{}{"NULL":"NULL"}}}
	expected2 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.20|0.1.1.1/24":map[string]interface{}{"NULL":"NULL"}}}
        url := "/openconfig-interfaces:interfaces/interface=Ethernet0/subinterfaces/subinterface=20/openconfig-if-ip:ipv4/addresses"

        fmt.Println("++++++++++++++  Patch Test_Leafref_Resolve_Within_Same_Sonic_Table  +++++++++++++")

        // Setup - Prerequisite
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)

	payload := "{\"openconfig-if-ip:addresses\": {\"address\": [{\"ip\": \"20.1.1.1\", \"openconfig-if-ip:config\": {\"ip\": \"20.1.1.1\", \"prefix-length\": 24}}]}}"

	t.Run("RFC - PATCH on container for sonic table with leafref within same table", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("RFC - Verify PATCH on container for sonic table with leafref within same table", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.20", expected1, false))
        t.Run("RFC - Verify PATCH on container for sonic table with leafref within same table", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.20|20.1.1.1/24", expected2, false))

        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)

}

*/
/*
//Enable when new leafref relation has been introduced to VLAN_SUB_INTERFACE/VLAN_SUB_INTERFACE_LIST/id in sonic-interface.yang
func Test_Delete_WithinSonicDBKey_Ordering_Patch(t *testing.T) {

	cleanuptbl1 := map[string]interface{}{"VLAN_SUB_INTERFACE":map[string]interface{}{"Eth0.10|1010::1/64":"", "Eth0.10|10.10.1.1/24":"", "Eth0.10|10.10.2.1/24":"", "Eth0.10":""}}
	cleanuptbl2 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet0|10.0.0.1/24":"", "Ethernet0|10::1/64":"", "Ethernet0":""}}

        prereq1 := map[string]interface{}{"VLAN_SUB_INTERFACE_REF":map[string]interface{}{"Eth0.10":map[string]interface{}{"parent":"Ethernet0"},"Eth0.10|1010::1/64":map[string]interface{}{"NULL":"NULL"},"Eth0.10|10.10.1.1/24":map[string]interface{}{"NULL":"NULL"},"Eth0.10|10.10.2.1/24":map[string]interface{}{"NULL":"NULL"}}}
	prereq2 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet0":map[string]interface{}{"NULL":"NULL"},"Ethernet0|10::1/64":map[string]interface{}{"NULL":"NULL"},"Ethernet0|10.0.0.1/24":map[string]interface{}{"NULL":"NULL"}}}


        url := "/openconfig-platform:components"

	delete_expected := make(map[string]interface{})

        fmt.Println("++++++++++++++  Patch Verify SubOpMap Delete ordering for sonic DbKeys  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        payload := "{\"openconfig-platform:components\": {\"component\": [{\"name\": \"1/1\", \"port\": {\"openconfig-platform-port:breakout-mode\": {\"config\": {\"num-channels\": 4, \"channel-speed\": \"SPEED_25GB\"}}}}]}}"

        t.Run("Patch Verify SubOpMap Delete ordering for sonic DbKeys", processSetRequest(url, payload, "PATCH", false))
        time.Sleep(1 * time.Second)

        t.Run("Verify SubOpMap Delete ordering for sonic DbKeys", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.10|1010::1/64", delete_expected, false))
        t.Run("Verify SubOpMap Delete ordering for sonic DbKeys", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.10|10.10.1.1/24", delete_expected, false))
        t.Run("Verify SubOpMap Delete ordering for sonic DbKeys", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.10|10.10.2.1/24", delete_expected, false))
        t.Run("Verify SubOpMap Delete ordering for sonic DbKeys", verifyDbResult(rclient, "VLAN_SUB_INTERFACE|Eth0.10", delete_expected, false))

        t.Run("Verify SubOpMap Delete ordering for sonic DbKeys", verifyDbResult(rclient, "INTERFACE|Ethernet0|10.0.0.1/24", delete_expected, false))
        t.Run("Verify SubOpMap Delete ordering for sonic DbKeys", verifyDbResult(rclient, "INTERFACE|Ethernet0|10::1/64", delete_expected, false))
        t.Run("Verify SubOpMap Delete ordering for sonic DbKeys", verifyDbResult(rclient, "INTERFACE|Ethernet0", delete_expected, false))

        // Teardown
        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)

}
*/
