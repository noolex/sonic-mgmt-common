///////////////////////////////////////////////////////////////////////////
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


func Test_Leaf_Field_Name_UINT8_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"retransmit":"4"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/openconfig-aaa-radius-ext:radius/config/retransmit-attempts"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Field_Name_UINT8  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

	patch_payload := "{\"openconfig-aaa-radius-ext:retransmit-attempts\":5}"
        patch_expected := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"retransmit":"5"}}}

        t.Run("UPDATE on Leaf Field Name UINT8", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Leaf Field Name UINT8", verifyDbResult(rclient, "RADIUS|global", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT8_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"retransmit":"5"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/openconfig-aaa-radius-ext:radius/config/retransmit-attempts"

        fmt.Println("++++++++++++++  Replace Test_Leaf_Field_Name_UINT8  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{\"openconfig-aaa-radius-ext:retransmit-attempts\":6}"
        put_expected := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"retransmit":"6"}}}

        t.Run("Replace on Leaf Field Name UINT8", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Leaf Field Name UINT8", verifyDbResult(rclient, "RADIUS|global", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT8_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"retransmit":"5"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/openconfig-aaa-radius-ext:radius/config/retransmit-attempts"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Field_Name_UINT8  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        delete_expected_map := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"NULL":"NULL"}}}

        t.Run("DELETE on Leaf Field Name UINT8", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Leaf Field Name UINT8", verifyDbResult(rclient, "RADIUS|global", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT8_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"retransmit":"5"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/openconfig-aaa-radius-ext:radius/config/retransmit-attempts"

        fmt.Println("++++++++++++++  Get Test_Leaf_Field_Name_UINT8  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-aaa-radius-ext:retransmit-attempts\":5}"

        t.Run("GET on Leaf Field Name UINT8", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT16_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"7"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Field_Name_UINT16  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        patch_payload := "{ \"openconfig-system-ext:timeout\": 8}"
        patch_expected := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"8"}}}

        t.Run("UPDATE on Leaf Field Name UINT16", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Leaf Field Name UINT16", verifyDbResult(rclient, "RADIUS|global", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT16_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"8"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"

        fmt.Println("++++++++++++++  Replace Test_Leaf_Field_Name_UINT16  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"openconfig-system-ext:timeout\": 4}"
        put_expected := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"4"}}}

        t.Run("Replace on Leaf Field Name UINT16", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Leaf Field Name UINT16", verifyDbResult(rclient, "RADIUS|global", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT16_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"4"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Field_Name_UINT16  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        delete_expected_map := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"5"}}}
	/* delete on a leaf having  yang default resets the leaf value to default */
        t.Run("DELETE on Leaf Field Name UINT16 and has default value", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Leaf Field Name UINT16 and has default value", verifyDbResult(rclient, "RADIUS|global", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT16_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"RADIUS":map[string]interface{}{"global":""}}
        prereq := map[string]interface{}{"RADIUS":map[string]interface{}{"global":map[string]interface{}{"timeout":"4"}}}
        url := "/openconfig-system:system/aaa/server-groups/server-group[name=RADIUS]/config/openconfig-system-ext:timeout"

        fmt.Println("++++++++++++++  Get Test_Leaf_Field_Name_UINT16  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-system-ext:timeout\":4}"

        t.Run("GET on Leaf Field Name UINT16", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_UINT32_Update(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":""}}
        cleanuptbl2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":""}}
        prereq1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"NULL":"NULL"}}}

        url := "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Field_Name_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        patch_payload := "{ \"openconfig-bgp-policy:set-local-pref\": 7}"
        patch_expected := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"NULL":"NULL","set_local_pref":"7"}}}

        t.Run("UPDATE on Leaf Field Name UINT32", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Leaf Field Name UINT32", verifyDbResult(rclient, "ROUTE_MAP|MAP1|1", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}

func Test_Leaf_Field_Name_UINT32_Replace(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":""}}
        cleanuptbl2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":""}}
        prereq1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"7"}}}
        prereq2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"NULL":"NULL"}}}
        url := "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"

        fmt.Println("++++++++++++++  Replace Test_Leaf_Field_Name_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        put_payload := "{ \"openconfig-bgp-policy:set-local-pref\": 9}"
        put_expected := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"9"}}}
        t.Run("Replace on Leaf Field Name UINT32", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Leaf Field Name UINT32", verifyDbResult(rclient, "ROUTE_MAP|MAP1|1", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}

func Test_Leaf_Field_Name_UINT32_Delete(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":""}}
        cleanuptbl2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":""}}
        prereq1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"9"}}}
        prereq2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"NULL":"NULL"}}}
        url := "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Field_Name_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        delete_expected_map := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"NULL":"NULL"}}}

        t.Run("DELETE on Leaf Field Name UINT32", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Leaf Field Name UINT32", verifyDbResult(rclient, "ROUTE_MAP|MAP1|1", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}

func Test_Leaf_Field_Name_UINT32_Get(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":""}}
        cleanuptbl2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":""}}
        prereq1 := map[string]interface{}{"ROUTE_MAP":map[string]interface{}{"MAP1|1":map[string]interface{}{"set_local_pref":"9"}}}
        prereq2 := map[string]interface{}{"ROUTE_MAP_SET":map[string]interface{}{"MAP1":map[string]interface{}{"NULL":"NULL"}}}
        url := "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition[name=MAP1]/statements/statement[name=1]/actions/openconfig-bgp-policy:bgp-actions/config/set-local-pref"

        fmt.Println("++++++++++++++  Get Test_Leaf_Field_Name_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        get_expected := "{\"openconfig-bgp-policy:set-local-pref\": 9}"

        t.Run("GET on Leaf Field Name UINT32", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}

// Test_Leaf_Field_Name_Boolean also covers leaf field name default value and data type conversion cases 
func Test_Leaf_Field_Name_Boolean_Update(t *testing.T) {

        prereq1 := map[string]interface{}{"VRF":map[string]interface{}{"Vrf12":map[string]interface{}{"NULL":"NULL"}}}
	prereq2 := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":map[string]interface{}{"NULL":"NULL"}}}
	cleanuptbl := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":""}}

        url := "/openconfig-network-instance:network-instances/network-instance[name=Vrf12]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/route-selection-options/config/always-compare-med"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Field_Name_Boolean  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        patch_payload := "{ \"openconfig-network-instance:always-compare-med\": true}"
        patch_expected := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":map[string]interface{}{"NULL":"NULL","always_compare_med":"true"}}}

        t.Run("UPDATE on Leaf Field Name Boolean", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Leaf Field Name Boolean", verifyDbResult(rclient, "BGP_GLOBALS|Vrf12", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_Boolean_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":""}}
        prereq1 := map[string]interface{}{"VRF":map[string]interface{}{"Vrf12":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":map[string]interface{}{"always_compare_med":"true"}}}
        url := "/openconfig-network-instance:network-instances/network-instance[name=Vrf12]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/route-selection-options/config/always-compare-med"

        fmt.Println("++++++++++++++  Replace Test_Leaf_Field_Name_Boolean  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        put_payload := "{ \"openconfig-network-instance:always-compare-med\": false}"
        put_expected := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":map[string]interface{}{"always_compare_med":"false"}}}

        t.Run("Replace on Leaf Field Name Boolean", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Leaf Field Name Boolean", verifyDbResult(rclient, "BGP_GLOBALS|Vrf12", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_Boolean_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":""}}
        prereq1 := map[string]interface{}{"VRF":map[string]interface{}{"Vrf12":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":map[string]interface{}{"always_compare_med":"true"}}}
        url := "/openconfig-network-instance:network-instances/network-instance[name=Vrf12]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/route-selection-options/config/always-compare-med"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Field_Name_Boolean  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        delete_expected_map := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":map[string]interface{}{"always_compare_med":"false"}}}

        t.Run("DELETE on Leaf Field Name Boolean", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Leaf Field Name Boolean", verifyDbResult(rclient, "BGP_GLOBALS|Vrf12", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Name_Boolean_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":""}}
        prereq1 := map[string]interface{}{"VRF":map[string]interface{}{"Vrf12":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"BGP_GLOBALS":map[string]interface{}{"Vrf12":map[string]interface{}{"always_compare_med":"false"}}}
        url := "/openconfig-network-instance:network-instances/network-instance[name=Vrf12]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/route-selection-options/config/always-compare-med"

        fmt.Println("++++++++++++++  Get Test_Leaf_Field_Name_Boolean  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        get_expected := "{\"openconfig-network-instance:always-compare-med\": false}"

        t.Run("GET on Leaf Field Name Boolean", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

// Test_Leaf_Field_Xfmr also covers leaf table transformer case 
func Test_Leaf_Field_Xfmr_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":""}}
        prereq := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":map[string]interface{}{"NULL":"NULL"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=PortChannel1]/config/mtu"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Field_Xfmr  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        patch_payload := "{ \"openconfig-interfaces:mtu\": 1500}"
        patch_expected := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":map[string]interface{}{"NULL":"NULL","mtu":"1500"}}}

        t.Run("UPDATE on Leaf Field Xfmr", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Leaf Field Xfmr", verifyDbResult(rclient, "PORTCHANNEL|PortChannel1", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Xfmr_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":""}}
        prereq := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":map[string]interface{}{"mtu":"1500"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=PortChannel1]/config/mtu"

        fmt.Println("++++++++++++++  Replace Test_Leaf_Field_Xfmr  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"openconfig-interfaces:mtu\": 1600}"
        put_expected := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":map[string]interface{}{"mtu":"1600"}}}

        t.Run("Replace on Leaf Field Xfmr", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Leaf Field Xfmr", verifyDbResult(rclient, "PORTCHANNEL|PortChannel1", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Xfmr_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":""}}
        prereq := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":map[string]interface{}{"mtu":"1500"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=PortChannel1]/config/mtu"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Field_Xfmr  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        delete_expected_map := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":map[string]interface{}{"NULL":"NULL","mtu":"9100"}}}

        t.Run("DELETE on Leaf Field Xfmr", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Leaf Field Xfmr", verifyDbResult(rclient, "PORTCHANNEL|PortChannel1", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Field_Xfmr_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":""}}
        prereq := map[string]interface{}{"PORTCHANNEL":map[string]interface{}{"PortChannel1":map[string]interface{}{"mtu":"1500"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=PortChannel1]/config/mtu"

        fmt.Println("++++++++++++++  Get Test_Leaf_Field_Xfmr  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-interfaces:mtu\": 1500}"

        t.Run("GET on Leaf Field Xfmr", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_UINT32_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":""}}
        prereq := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":map[string]interface{}{"NULL":"NULL"}}}
        url := "/sonic-sflow:sonic-sflow/SFLOW_SESSION/SFLOW_SESSION_LIST[ifname=Ethernet0]/sample_rate"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Sonic_Yang_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        patch_payload := "{ \"sonic-sflow:sample_rate\": 512}"
        patch_expected := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":map[string]interface{}{"NULL":"NULL","sample_rate":"512"}}}

        t.Run("UPDATE on Leaf Sonic Yang UINT32", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Leaf Sonic Yang UINT32", verifyDbResult(rclient, "SFLOW_SESSION|Ethernet0", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_UINT32_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":""}}
        prereq := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":map[string]interface{}{"sample_rate":"512"}}}
        url := "/sonic-sflow:sonic-sflow/SFLOW_SESSION/SFLOW_SESSION_LIST[ifname=Ethernet0]/sample_rate"

        fmt.Println("++++++++++++++  Replace Test_Leaf_Sonic_Yang_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"sonic-sflow:sample_rate\": 256}"
        put_expected := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":map[string]interface{}{"sample_rate":"256"}}}

        t.Run("Replace on Leaf Sonic Yang UINT32", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Leaf Sonic Yang UINT32", verifyDbResult(rclient, "SFLOW_SESSION|Ethernet0", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_UINT32_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":""}}
        prereq := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":map[string]interface{}{"sample_rate":"256"}}}
        url := "/sonic-sflow:sonic-sflow/SFLOW_SESSION/SFLOW_SESSION_LIST[ifname=Ethernet0]/sample_rate"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Sonic_Yang_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        delete_expected_map := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":map[string]interface{}{"NULL":"NULL"}}}

        t.Run("DELETE on Leaf Sonic Yang UINT32", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Leaf Sonic Yang UINT32", verifyDbResult(rclient, "SFLOW_SESSION|Ethernet0", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_UINT32_Get(t *testing.T) {

        cleanuptbl := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":""}}
        prereq := map[string]interface{}{"SFLOW_SESSION":map[string]interface{}{"Ethernet0":map[string]interface{}{"sample_rate":"256"}}}
        url := "/sonic-sflow:sonic-sflow/SFLOW_SESSION/SFLOW_SESSION_LIST[ifname=Ethernet0]/sample_rate"

        fmt.Println("++++++++++++++  Get Test_Leaf_Sonic_Yang_UINT32  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"sonic-sflow:sample_rate\": 256}"

        t.Run("GET on Leaf Sonic Yang UINT32", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_Choice_Case_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"MyACL1_ACL_IPV4":""},"ACL_RULE":map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1":""}}

        prereq := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"MyACL1_ACL_IPV4":map[string]interface{}{"policy_desc":"Description for MyACL1","type":"L3"}},"ACL_RULE":map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1":map[string]interface{}{"PRIORITY":"65534","SRC_IP":"10.1.1.1/32","DST_IP":"20.2.2.2/32","IP_TYPE":"IPV4","RULE_DESCRIPTION":"Description for MyACL1","IP_PROTOCOL":"6","PACKET_ACTION":"FORWARD"}}}

        url := "/sonic-acl:sonic-acl/ACL_RULE/ACL_RULE_LIST[aclname=MyACL1_ACL_IPV4][rulename=RULE_1]/SRC_IP"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Sonic_Yang_Choice_Case  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        patch_payload := "{ \"sonic-acl:SRC_IP\": \"1.1.1.1/1\"}"
        patch_expected := map[string]interface{}{"ACL_RULE":map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1":map[string]interface{}{"PRIORITY":"65534","SRC_IP":"1.1.1.1/1","DST_IP":"20.2.2.2/32","IP_TYPE":"IPV4","RULE_DESCRIPTION":"Description for MyACL1","IP_PROTOCOL":"6","PACKET_ACTION":"FORWARD"}}}

        t.Run("UPDATE on Leaf Sonic Yang Choice Case", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify update on Leaf Sonic Yang Choice Case", verifyDbResult(rclient, "ACL_RULE|MyACL1_ACL_IPV4|RULE_1", patch_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_Choice_Case_Replace(t *testing.T) {

        cleanuptbl := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"MyACL1_ACL_IPV4":""},"ACL_RULE":map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1":""}}

        prereq := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"MyACL1_ACL_IPV4":map[string]interface{}{"policy_desc":"Description for MyACL1","type":"L3"}},"ACL_RULE":map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1":map[string]interface{}{"PRIORITY":"65534","SRC_IP":"10.1.1.1/32","DST_IP":"20.2.2.2/32","IP_TYPE":"IPV4","RULE_DESCRIPTION":"Description for MyACL1","IP_PROTOCOL":"6","PACKET_ACTION":"FORWARD"}}}

        url := "/sonic-acl:sonic-acl/ACL_RULE/ACL_RULE_LIST[aclname=MyACL1_ACL_IPV4][rulename=RULE_1]/SRC_IP"

        fmt.Println("++++++++++++++  REPLACE Test_Leaf_Sonic_Yang_Choice_Case  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        put_payload := "{ \"sonic-acl:SRC_IP\": \"1.1.1.1/1\"}"
        //put_actual := map[string]interface{}{"ACL_RULE":map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1":map[string]interface{}{"SRC_IP":"1.1.1.1/1"}}}
        put_expected := map[string]interface{}{"ACL_RULE":map[string]interface{}{"MyACL1_ACL_IPV4|RULE_1":map[string]interface{}{"PRIORITY":"65534","SRC_IP":"1.1.1.1/1","DST_IP":"20.2.2.2/32","IP_TYPE":"IPV4","RULE_DESCRIPTION":"Description for MyACL1","IP_PROTOCOL":"6","PACKET_ACTION":"FORWARD"}}}

	// Update on leaf not handled for SONIC Yet TODO 
        t.Run("REPLACE on Leaf Sonic Yang Choice Case", processSetRequest(url, put_payload, "PUT", false))
        time.Sleep(1 * time.Second)
        t.Run("Verify replace on Leaf Sonic Yang Choice Case", verifyDbResult(rclient, "ACL_RULE|MyACL1_ACL_IPV4|RULE_1", put_expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_Choice_Case_Delete(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"acl1":""}}
        cleanuptbl2 := map[string]interface{}{"ACL_RULE":map[string]interface{}{"acl1|rule1":""}}
        prereq1 := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"acl1":map[string]interface{}{"ports@":"Ethernet0","stage":"INGRESS","type":"MIRROR","policy_desc":"descr"}}}
        prereq2 := map[string]interface{}{"ACL_RULE":map[string]interface{}{"acl1|rule1":map[string]interface{}{"DST_IP":"2.2.2.2/2","SRC_IP":"1.1.1.1/1"}}}
        url := "/sonic-acl:sonic-acl/ACL_RULE/ACL_RULE_LIST[aclname=acl1][rulename=rule1]/SRC_IP"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Sonic_Yang_Choice_Case  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        delete_expected_map := map[string]interface{}{"ACL_RULE":map[string]interface{}{"acl1|rule1":map[string]interface{}{"DST_IP":"2.2.2.2/2"}}}

        t.Run("DELETE on Leaf Sonic Yang Choice Case", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete on Leaf Sonic Yang Choice Case", verifyDbResult(rclient, "ACL_RULE|acl1|rule1", delete_expected_map, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}

func Test_Leaf_Sonic_Yang_Choice_Case_Get(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"acl1":""}}
        cleanuptbl2 := map[string]interface{}{"ACL_RULE":map[string]interface{}{"acl1|rule1":""}}
        prereq1 := map[string]interface{}{"ACL_TABLE":map[string]interface{}{"acl1":map[string]interface{}{"ports@":"Ethernet0","stage":"INGRESS","type":"MIRROR","policy_desc":"descr"}}}
        prereq2 := map[string]interface{}{"ACL_RULE":map[string]interface{}{"acl1|rule1":map[string]interface{}{"DST_IP":"2.2.2.2/2","SRC_IP":"1.1.1.1/1"}}}
        url := "/sonic-acl:sonic-acl/ACL_RULE/ACL_RULE_LIST[aclname=acl1][rulename=rule1]/SRC_IP"

        fmt.Println("++++++++++++++  Get Test_Leaf_Sonic_Yang_Choice_Case  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        get_expected := "{\"sonic-acl:SRC_IP\": \"1.1.1.1/1\"}"

        t.Run("GET on Leaf Sonic Yang Choice Case", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}

func Test_Leaf_Sonic_Yang_List_With_Multi_Key_Update(t *testing.T) {

        cleanuptbl := map[string]interface{}{"THRESHOLD_TABLE":map[string]interface{}{"queue|unicast|Ethernet0|7":""}}
        prereq := map[string]interface{}{"THRESHOLD_TABLE":map[string]interface{}{"queue|unicast|Ethernet0|7":map[string]interface{}{"threshold":7}}}
        url := "/sonic-threshold:sonic-threshold/THRESHOLD_TABLE/THRESHOLD_TABLE_LIST[buffer=queue][threshold_buffer_type=unicast][interface_name=Ethernet0][buffer_index_per_port=7]/threshold"

        fmt.Println("++++++++++++++  UPDATE Test_Leaf_Sonic_Yang_List_Multi_Key  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)
	patch_payload := "{ \"sonic-threshold:threshold\":  5 }"
        expected := map[string]interface{}{"THRESHOLD_TABLE":map[string]interface{}{"queue|unicast|Ethernet0|7":map[string]interface{}{"threshold":"5"}}}

        t.Run("UPDATE on Leaf Sonic Yang with multi Key list", processSetRequest(url, patch_payload, "PATCH", false))
        time.Sleep(1 * time.Second)
        t.Run("UPDATE on Leaf Sonic Yang with MultiKey List", verifyDbResult(rclient, "THRESHOLD_TABLE|queue|unicast|Ethernet0|7", expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Sonic_Yang_List_With_Multi_Key_Delete(t *testing.T) {

        cleanuptbl := map[string]interface{}{"THRESHOLD_TABLE":map[string]interface{}{"queue|unicast|Ethernet0|7":""}}
        prereq := map[string]interface{}{"THRESHOLD_TABLE":map[string]interface{}{"queue|unicast|Ethernet0|7":map[string]interface{}{"threshold":"5"}}}
        url := "/sonic-threshold:sonic-threshold/THRESHOLD_TABLE/THRESHOLD_TABLE_LIST[buffer=queue][threshold_buffer_type=unicast][interface_name=Ethernet0][buffer_index_per_port=7]/threshold"

        fmt.Println("++++++++++++++  DELETE Test_Leaf_Sonic_Yang_List_Multi_Key  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        expected := map[string]interface{}{"THRESHOLD_TABLE":map[string]interface{}{"queue|unicast|Ethernet0|7":map[string]interface{}{"NULL":"NULL"}}}

        t.Run("DELETE on Leaf Sonic Yang with MultiKey List", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("DELETE on Leaf Sonic Yang with MultiKey List", verifyDbResult(rclient, "THRESHOLD_TABLE|queue|unicast|Ethernet0|7", expected, false))

        unloadConfigDB(rclient, cleanuptbl)
}

func Test_Leaf_Add_Null_Field(t *testing.T) {

	cleanuptbl1 := map[string]interface{}{"LOOPBACK_INTERFACE":map[string]interface{}{"Loopback1":""}}
        cleanuptbl2 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4":""}}
        prereq1 := map[string]interface{}{"LOOPBACK_INTERFACE":map[string]interface{}{"Loopback1":map[string]interface{}{"NULL":"NULL"}}}
        prereq2 := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4":map[string]interface{}{"unnumbered":"Loopback1"}}}
        url := "/sonic-interface:sonic-interface/INTERFACE/INTERFACE_LIST[portname=Ethernet4]/unnumbered"

        fmt.Println("++++++++++++++  ADD a NULL field when a last field gets deleted  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

        delete_expected := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet4":map[string]interface{}{"NULL":"NULL"}}}

        t.Run("DELETE a last field on a given entry", processDeleteRequest(url, false))
        time.Sleep(1 * time.Second)
        t.Run("Verify delete entry", verifyDbResult(rclient, "INTERFACE|Ethernet4", delete_expected, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}

