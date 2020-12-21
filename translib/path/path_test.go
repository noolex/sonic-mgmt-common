////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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

package path

import (
	"testing"

	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
)

func TestHasWildcardKey(t *testing.T) {
	t.Run("no_key", testKeyWC("/X/Y/Z", false))
	t.Run("no_wc1", testKeyWC("/X[a=1]/Y/Z", false))
	t.Run("no_wc2", testKeyWC("/X[a=1][b=2]/Y[c=3]/Z", false))
	t.Run("only_wc", testKeyWC("/X[a=*]/Y/Z", true))
	t.Run("one_wc", testKeyWC("/X[a=*]/Y/Z", true))
	t.Run("end_wc", testKeyWC("/X/Y/Z[a=*]", true))
	t.Run("multi", testKeyWC("/X[a=*][b=*]/Y/Z", true))
	t.Run("mixed", testKeyWC("/X[a=1][b=2]/Y[c=3][d=*]/Z", true))
}

func testKeyWC(path string, exp bool) func(*testing.T) {
	return func(t *testing.T) {
		p, err := ygot.StringToStructuredPath(path)
		if err != nil {
			t.Fatalf("Invalid path: \"%v\". err=%v", path, err)
		}

		if HasWildcardKey(p) != exp {
			t.Fatalf("Wildcard key check failed for \"%s\"", path)
		}
	}
}

func TestToString(t *testing.T) {
	path := "/AA/BB/CC"
	p, _ := ygot.StringToStructuredPath(path)

	pstr := String(p)
	if pstr != path {
		t.Fatalf("ToString failed; input=\"%s\", output=\"%s\"", path, pstr)
	}
}

func TestToString_invalid(t *testing.T) {
	path := &gnmi.Path{
		Elem: []*gnmi.PathElem{
			&gnmi.PathElem{Name: "AA"},
			&gnmi.PathElem{Name: ""},
		},
	}

	pstr := String(path)
	t.Logf("pstr = \"%s\"", pstr)
	if pstr == "" {
		t.Fatalf("ToString failed; input=\"%v\"", path)
	}
}
