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

package translib

import (
	"reflect"
	"testing"

	"strings"

	"github.com/openconfig/ygot/ygot"
)

func TestNewPathValidator(t *testing.T) {
	pathValdtor := NewPathValidator(&(AppendModulePrefix{}), &(AddWildcardKeys{}))
	if pathValdtor != nil {
		t.Log("reflect.ValueOf(pathValdtor.rootObj).Type().Name() ==> ", reflect.ValueOf(pathValdtor.rootObj).Type().Name())
		if reflect.ValueOf(pathValdtor.rootObj).Type().Name() != "ocbinds.Device" || pathValdtor.hasIgnoreKeyValidationOption() ||
			!pathValdtor.hasAppendModulePrefixOption() || !pathValdtor.hasAddWildcardKeyOption() {
			t.Error("Error in creating the NewPathValidator")
		}
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		tid     int
		path    string
		resPath string
	}{{
		tid:     1, // validate path and key value
		path:    "/openconfig-acl:acl/acl-sets/acl-set[name=Sample][type=ACL_IPV4]/state/description",
		resPath: "/openconfig-acl:acl/acl-sets/acl-set[name=Sample][type=ACL_IPV4]/state/description",
	}, {
		tid: 2, // fill key name and value as wild card for missing keys
		path: "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/" +
			"openconfig-network-instance-deviation:igmp-snooping/interfaces/interface/config",
		resPath: "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/" +
			"openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[name=*]/config",
	}, {
		tid: 3, // append module prefix
		path: "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/" +
			"igmp-snooping/interfaces",
		resPath: "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/" +
			"openconfig-network-instance-deviation:igmp-snooping/interfaces",
	}, {
		tid: 4, // negative - invalid key name
		path: "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/" +
			"openconfig-network-instance-deviation:igmp-snooping/interfaces/interface[namexx=*]/config",
		resPath: "",
	}, {
		tid: 5, // negative - invalid module prefix
		path: "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/" +
			"openconfig-network-instance-deviationxx:igmp-snooping/interfaces",
		resPath: "",
	}, {
		tid: 6, // negative - invalid path
		path: "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=IGMP_SNOOPING][name=IGMP-SNOOPING]/" +
			"openconfig-network-instance-deviation:igmp-snooping/interfacesxx",
		resPath: "",
	}}

	pathValdtor := NewPathValidator(&(AppendModulePrefix{}), &(AddWildcardKeys{}))
	for _, tt := range tests {
		if gPath, err := ygot.StringToPath(tt.path, ygot.StructuredPath); err != nil {
			t.Error("Error in uri to path conversion: ", err)
			break
		} else {
			pathValdtor.init(gPath)
			if err := pathValdtor.validatePath(); err != nil && tt.tid < 4 {
				t.Errorf("Testcase %v failed; error: %v", tt.tid, err)
			} else {
				if tt.tid < 4 {
					if resPath, err := ygot.PathToString(gPath); resPath != tt.resPath {
						t.Errorf("Testcase %v failed; error: %v; result path: %v", tt.tid, err, resPath)
					}
				} else if tt.tid == 4 && err.Error() != "Invalid key name: map[namexx:*] in the list node path: interface" {
					t.Logf("Testcase %v failed; error: %v", tt.tid, err)
				} else if tt.tid == 5 && err.Error() != "Invalid yang module prefix in the path node openconfig-network-instance-deviationxx:igmp-snooping" {
					t.Logf("Testcase %v failed; error: %v", tt.tid, err)
				} else if tt.tid == 6 && !strings.HasPrefix(err.Error(), "Node interfacesxx not found in the given gnmi path elem") {
					t.Logf("Testcase %v failed; error: %v", tt.tid, err)
				}
			}
		}
	}
}

func BenchmarkValidatePath1(b *testing.B) {
	pathValdtor := NewPathValidator(&(AppendModulePrefix{}), &(AddWildcardKeys{}))
	if gPath, err := ygot.StringToPath("/openconfig-tam:tam/flowgroups/flowgroup[name=*]/config/priority", ygot.StructuredPath); err != nil {
		b.Error("Error in uri to path conversion: ", err)
	} else {
		for i := 0; i < b.N; i++ {
			pathValdtor.Validate(gPath)
		}
	}
}

func BenchmarkValidatePath2(b *testing.B) {
	pathValdtor := NewPathValidator(&(AppendModulePrefix{}), &(AddWildcardKeys{}))
	if gPath, err := ygot.StringToPath("/openconfig-interfaces:interfaces/interface[name=*]/subinterfaces/subinterface[index=*]/openconfig-if-ip:ipv6/addresses/address[ip=*]/state", ygot.StructuredPath); err != nil {
		b.Error("Error in uri to path conversion: ", err)
	} else {
		for i := 0; i < b.N; i++ {
			pathValdtor.Validate(gPath)
		}
	}
}

func BenchmarkValidatePath3(b *testing.B) {
	pathValdtor := NewPathValidator(&(AppendModulePrefix{}), &(AddWildcardKeys{}))
	if gPath, err := ygot.StringToPath("/openconfig-network-instance:network-instances/network-instance[name=*]/protocols/protocol[identifier=*][name=*]"+
		"/ospfv2/areas/area[identifier=*]/lsdb/lsa-types/lsa-type[type=*]/lsas/lsa-ext[link-state-id=*][advertising-router=*]"+
		"/opaque-lsa/extended-prefix/tlvs/tlv/sid-label-binding/tlvs/tlv/ero-path/segments/segment/unnumbered-hop/state/router-id", ygot.StructuredPath); err != nil {
		b.Error("Error in uri to path conversion: ", err)
	} else {
		for i := 0; i < b.N; i++ {
			pathValdtor.Validate(gPath)
		}
	}
}
