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

package db

import "testing"

func TestIsPattern(t *testing.T) {
	t.Run("none1", testNotPattern("aaa"))
	t.Run("none5", testNotPattern("aaa", "bbb", "ccc", "ddd", "eee"))
	t.Run("* frst", testPattern("*aa", "bbb"))
	t.Run("* last", testPattern("aa*", "bbb"))
	t.Run("* midl", testPattern("a*a", "bbb"))
	t.Run("* frst", testPattern("aaa", "*bb"))
	t.Run("* last", testPattern("aaa", "bb*"))
	t.Run("* midl", testPattern("aaa", "b*b"))
	t.Run("? frst", testPattern("aaa", "?bb"))
	t.Run("? last", testPattern("aaa", "bb?"))
	t.Run("? midl", testPattern("a?a", "bbb"))
	t.Run("\\* frst", testNotPattern("\\*aa", "bbb"))
	t.Run("\\* last", testNotPattern("aaa", "bb\\*"))
	t.Run("\\* midl", testNotPattern("a\\*a", "bbb"))
	t.Run("\\? frst", testNotPattern("aaa", "\\?bb"))
	t.Run("\\? last", testNotPattern("aa\\?", "bbb"))
	t.Run("\\? midl", testNotPattern("aaa", "b\\?b"))
	t.Run("**", testPattern("aaa", "b**b"))
	t.Run("??", testPattern("a**a", "bbb"))
	t.Run("\\**", testPattern("aa\\**", "bbb"))
	t.Run("\\??", testPattern("aaa", "b\\??b"))
	t.Run("class", testNotPattern("a[bcd]e"))
	t.Run("range", testNotPattern("a[b-d]e"))
	// TODO have * and ? inside character class :)
}

func testPattern(comp ...string) func(*testing.T) {
	return func(t *testing.T) {
		k := NewKey(comp...)
		if !k.IsPattern() {
			t.Fatalf("IsPattern() did not detect pattern in %v", k)
		}
	}
}

func testNotPattern(comp ...string) func(*testing.T) {
	return func(t *testing.T) {
		k := NewKey(comp...)
		if k.IsPattern() {
			t.Fatalf("IsPattern() wrongly detected pattern in %v", k)
		}
	}
}
