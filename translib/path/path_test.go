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

func parsePath(t *testing.T, path string) *gnmi.Path {
	p, err := ygot.StringToStructuredPath(path)
	if err != nil {
		t.Fatalf("Invalid path: \"%v\". err=%v", path, err)
	}
	return p
}

func testKeyWC(path string, exp bool) func(*testing.T) {
	return func(t *testing.T) {
		p := parsePath(t, path)
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

func TestMatches(t *testing.T) {
	t.Run("nokeys", testMatch("/AA/BB/CC", "/AA/BB/CC", true))
	t.Run("shorter", testMatch("/AA/BB", "/AA/BB/CC", false))
	t.Run("longer", testMatch("/AA/BB/CC/DD", "/AA/BB/CC", true))
	t.Run("1keys", testMatch("/AA[one=1]/BB", "/AA[one=1]/BB", true))
	t.Run("nkeys", testMatch("/AA[one=1][two=2]/BB[x=y]", "/AA[two=2][one=1]/BB[x=y]", true))
	t.Run("longkey", testMatch("/AA[one=1]/BB/CC[x=y]", "/AA[one=1]/BB", true))
	t.Run("lesskey", testMatch("/AA/BB[one=1][two=2]", "/AA/BB[one=1]", false))
	t.Run("xtrakey", testMatch("/AA/BB[one=1][two=2]", "/AA/BB[one=1][two=2][x=y]", false))
	t.Run("1wcard", testMatch("/AA/BB[one=1][two=2]", "/AA/BB[one=*][two=2]", true))
	t.Run("2wcard", testMatch("/AA/BB[one=1][two=2]", "/AA/BB[one=*][two=*]", true))
	t.Run("wcard_lesskey", testMatch("/AA/BB[one=1]", "/AA/BB[one=*][two=*]", false))
	t.Run("wcard_nomatch", testMatch("/AA/BB[one=1][two=2]", "/AA/BB[one=x][two=*]", false))
	t.Run("wcard_path", testMatch("/AA/BB[one=*]", "/AA/BB[one=x]", false))
}

func testMatch(path, template string, exp bool) func(*testing.T) {
	return func(t *testing.T) {
		pp := parsePath(t, path)
		tp := parsePath(t, template)
		if Matches(pp, tp) != exp {
			t.Fatalf("Matches(\"%s\", \"%s\") != %v", path, template, exp)
		}
	}
}

func TestSubPath(t *testing.T) {
	t.Run("first1", testSubPath("/AA/BB/CC", 0, 1, "/AA"))
	t.Run("midle1", testSubPath("/AA/BB/CC", 1, 2, "/BB"))
	t.Run("last1", testSubPath("/AA/BB/CC", 2, 3, "/CC"))
	t.Run("first2", testSubPath("/AA/BB/CC", 0, 2, "/AA/BB"))
	t.Run("midle2", testSubPath("/AA/BB[x=y]/CC/DD", 1, 3, "/BB[x=y]/CC"))
	t.Run("last2", testSubPath("/AA/BB/CC", 1, 3, "/BB/CC"))
	t.Run("all", testSubPath("/AA/BB/CC", 0, 3, "/AA/BB/CC"))
	t.Run("none", testSubPath("/AA/BB/CC", 0, 0, "/"))
}

func testSubPath(path string, si, ei int, exp string) func(*testing.T) {
	return func(t *testing.T) {
		p := parsePath(t, path)
		s := String(SubPath(p, si, ei))
		if s != exp {
			t.Errorf("SubPath(\"%s\", %d, %d) != \"%s\"", path, si, ei, exp)
			t.Errorf("Found \"%s\"", s)
		}
	}
}
