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
	"testing"

	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/openconfig/ygot/ygot"
)

func BenchmarkGetAppModule(b *testing.B) {
	var v Version
	path := "/benchmark/common_app/creation"
	for i := 0; i < b.N; i++ {
		getAppModule(path, v)
	}
}

func Test_isEmptyStruct_EmptyObj(t *testing.T) {
	v := &ocbinds.OpenconfigAcl_Acl_AclSets_AclSet{}
	if !isEmptyYgotStruct(v) {
		t.FailNow()
	}
}

func Test_isEmptyStruct_DirectAttr(t *testing.T) {
	x := &ocbinds.OpenconfigAcl_Acl_AclSets_AclSet{
		Name: ygot.String("Foo"),
	}
	if isEmptyYgotStruct(x) {
		t.FailNow()
	}
}

func Test_isEmptyStruct_NestedAttr(t *testing.T) {
	x := new(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet)
	ygot.BuildEmptyTree(x)
	x.Config.Description = ygot.String("Hello, world!")
	if isEmptyYgotStruct(x) {
		t.FailNow()
	}
}

func Test_isEmptyStruct_EmptyContainers(t *testing.T) {
	x := new(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet)
	ygot.BuildEmptyTree(x)
	if !isEmptyYgotStruct(x) {
		t.FailNow()
	}
}

func Test_isEmptyStruct_EmptyTree(t *testing.T) {
	x := new(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry)
	ygot.BuildEmptyTree(x)
	if !isEmptyYgotStruct(x) {
		t.FailNow()
	}
}

func Test_isEmptyStruct_NDeepAttr(t *testing.T) {
	x := new(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry)
	ygot.BuildEmptyTree(x)
	x.Ipv4.Config.SourceAddress = ygot.String("1.2.3.4/32")
	if isEmptyYgotStruct(x) {
		t.FailNow()
	}
}

func Test_isEmptyStruct_NDeepLeafList(t *testing.T) {
	x := new(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry)
	ygot.BuildEmptyTree(x)
	x.Transport.Config.TcpFlags = []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS{ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK}
	if isEmptyYgotStruct(x) {
		t.FailNow()
	}
}

func Test_isEmptyStruct_NDeepList(t *testing.T) {
	x := new(ocbinds.OpenconfigAcl_Acl_AclSets_AclSet)
	ygot.BuildEmptyTree(x)
	x.AclEntries.NewAclEntry(10)
	if isEmptyYgotStruct(x) {
		t.FailNow()
	}
}
