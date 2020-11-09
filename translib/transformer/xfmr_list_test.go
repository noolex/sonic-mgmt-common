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
)

/*func Test_List_Custom_DB_Update_Get(t *testing.T) {

        cleanuptbl1 := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":""}}
        cleanuptbl2 := map[string]interface{}{"SAG":map[string]interface{}{"Vlan1|IPv4":""}}
        prereq1 := map[string]interface{}{"VLAN":map[string]interface{}{"Vlan1":map[string]interface{}{"vlanid":"1"}}}
        prereq2 := map[string]interface{}{"SAG":map[string]interface{}{"Vlan1|IPv4":map[string]interface{}{"gwip@":"1.1.1.1/1"}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Vlan1]/subinterfaces/subinterface[index=0]"

        fmt.Println("++++++++++++++  Get Test_List_Custom_DB_Update  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq1)
        loadConfigDB(rclient, prereq2)

//        get_expected := "{\"openconfig-interfaces:subinterface\":[{\"index\":0,\"openconfig-if-ip:ipv4\":{\"openconfig-interfaces-ext:sag-ipv4\":{\"state\":{\"static-anycast-gateway\":[\"1.1.1.1/1\"]}}}}]}"

	 get_expected := "{\"openconfig-interfaces:subinterface\":[{\"index\":0,\"openconfig-if-ip:ipv4\":{\"openconfig-interfaces-ext:sag-ipv4\":{\"config\":{\"static-anycast-gateway\":[\"1.1.1.1/1\"]}}},\"openconfig-if-ip:ipv6\":{\"config\":{\"enabled\":false},\"state\":{\"enabled\":false}}}]}"

        t.Run("GET on List Custom DB Update", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, cleanuptbl1)
        unloadConfigDB(rclient, cleanuptbl2)
}
*/
func Test_List_Ygot_Merge_Xfmr_Infra_Subtree_Xfmr_Get(t *testing.T) {

        url := "/openconfig-interfaces:interfaces/interface[name=Ethernet0]"

        fmt.Println("++++++++++++++  Get Test_List_Ygot_Merge_Xfmr_Infra_Subtree_Xfmr  +++++++++++++")

        get_expected := "{\"openconfig-interfaces:interface\":[{\"config\":{\"description\":\"\",\"enabled\":false,\"mtu\":9100,\"name\":\"Ethernet0\",\"type\":\"iana-if-type:ethernetCsmacd\"},\"name\":\"Ethernet0\",\"openconfig-if-ethernet:ethernet\":{\"config\":{\"port-speed\":\"openconfig-if-ethernet:SPEED_40GB\"},\"state\":{\"counters\":{\"in-fragment-frames\":\"0\",\"in-jabber-frames\":\"0\",\"in-oversize-frames\":\"0\",\"in-undersize-frames\":\"0\",\"openconfig-if-ethernet-ext2:eth-in-distribution\":{\"in-frames-1024-1518-octets\":\"0\",\"in-frames-128-255-octets\":\"0\",\"in-frames-1519-2047-octets\":\"0\",\"in-frames-2048-4095-octets\":\"0\",\"in-frames-256-511-octets\":\"0\",\"in-frames-4096-9216-octets\":\"0\",\"in-frames-512-1023-octets\":\"0\",\"in-frames-64-octets\":\"0\",\"in-frames-65-127-octets\":\"0\",\"in-frames-9217-16383-octets\":\"0\"},\"openconfig-if-ethernet-ext2:eth-out-distribution\":{\"out-frames-1024-1518-octets\":\"0\",\"out-frames-128-255-octets\":\"0\",\"out-frames-1519-2047-octets\":\"0\",\"out-frames-2048-4095-octets\":\"0\",\"out-frames-256-511-octets\":\"0\",\"out-frames-4096-9216-octets\":\"0\",\"out-frames-512-1023-octets\":\"0\",\"out-frames-64-octets\":\"0\",\"out-frames-65-127-octets\":\"0\",\"out-frames-9217-16383-octets\":\"0\"},\"openconfig-interfaces-ext:out-oversize-frames\":\"0\"},\"openconfig-if-ethernet-ext2:port-unreliable-los\":\"openconfig-if-ethernet-ext2:UNRELIABLE_LOS_MODE_OFF\",\"port-speed\":\"openconfig-if-ethernet:SPEED_40GB\"}},\"state\":{\"admin-status\":\"DOWN\",\"counters\":{\"in-broadcast-pkts\":\"0\",\"in-discards\":\"0\",\"in-errors\":\"0\",\"in-multicast-pkts\":\"0\",\"in-octets\":\"0\",\"in-pkts\":\"0\",\"in-unicast-pkts\":\"0\",\"last-clear\":\"0\",\"openconfig-interfaces-ext:in-bits-per-second\":\"0\",\"openconfig-interfaces-ext:in-octets-per-second\":\"0\",\"openconfig-interfaces-ext:in-pkts-per-second\":\"0\",\"openconfig-interfaces-ext:in-utilization\":0,\"openconfig-interfaces-ext:out-bits-per-second\":\"0\",\"openconfig-interfaces-ext:out-octets-per-second\":\"0\",\"openconfig-interfaces-ext:out-pkts-per-second\":\"0\",\"out-broadcast-pkts\":\"0\",\"out-discards\":\"0\",\"out-errors\":\"0\",\"out-multicast-pkts\":\"0\",\"out-octets\":\"0\",\"out-pkts\":\"0\",\"out-unicast-pkts\":\"0\"},\"description\":\"\",\"enabled\":false,\"mtu\":9100,\"name\":\"Ethernet0\",\"openconfig-interfaces-ext:rate-interval\":10,\"oper-status\":\"DOWN\"},\"subinterfaces\":{\"subinterface\":[{\"index\":0,\"openconfig-if-ip:ipv4\": {\"openconfig-ospfv2-ext:ospfv2\": {\"if-addresses\":[{\"address\": \"Ethernet4|1.2.3.4/16\"}]}},\"openconfig-if-ip:ipv6\":{\"config\":{\"enabled\":false},\"state\":{\"enabled\":false}}}]}}]}"

        t.Run("GET on List Ygot Merge Xfmr Infra Subtree Xfmr", processGetRequest(url, get_expected, false))

}

func Test_List_Ygot_Merge_None_Get(t *testing.T) {

        prereq := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet0":map[string]interface{}{"1.1.1.1/0":""}}}
        url := "/openconfig-interfaces:interfaces/interface[name=Ethernet0]/subinterfaces/subinterface[index=0]/openconfig-if-ip:ipv4/addresses/address[ip=1.1.1.1]"

        fmt.Println("++++++++++++++  Get Test_List_Ygot_Merge_None  +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"openconfig-if-ip:address\":[{\"ip\":\"1.1.1.1\"}]}"

        t.Run("GET on List Ygot Merge None", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, prereq)
}


func Test_List_Sonic_Key_Split_Get(t *testing.T) {

        prereq := map[string]interface{}{"INTERFACE":map[string]interface{}{"Ethernet0|10.11.12.13/16":map[string]interface{}{"NULL":"NULL"}}}
        url := "/sonic-interface:sonic-interface/INTERFACE/INTERFACE_IPADDR_LIST[portname=Ethernet0][ip_prefix=10.11.12.13/16]/"

        fmt.Println("++++++++++++++  GET Test_List_Sonic_Key_Split +++++++++++++")

        // Setup - Prerequisite
        loadConfigDB(rclient, prereq)

        get_expected := "{\"sonic-interface:INTERFACE_IPADDR_LIST\":[{\"ip_prefix\":\"10.11.12.13/16\",\"portname\":\"Ethernet0\"}]}"

        t.Run("GET on List for Sonic Yang with / in key", processGetRequest(url, get_expected, false))

        unloadConfigDB(rclient, prereq)
}

