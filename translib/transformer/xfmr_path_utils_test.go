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

package transformer_test

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Azure/sonic-mgmt-common/translib/transformer"
)

func TestSplitPath(t *testing.T) {
	t.Run("oneword", testSplitPath("one"))
	t.Run("L-slash", testSplitPath("/one"))
	t.Run("R-slash", testSplitPath("one/"))
	t.Run("LR-slash", testSplitPath("/one/"))
	t.Run("multi", testSplitPath("/one/two/three"))
	t.Run("1-key", testSplitPath("/one/two[aa=1]/three"))
	t.Run("n-key", testSplitPath("/one/two[aa=1][bb=2]/three[cc=3]"))
	t.Run("escaped", testSplitPath(`/one/two[aa=\\\]][bb=[hello world\]123]`))
	t.Run("special", testSplitPath(`/one/two[aa=$ missing! #@%/.]`))
	t.Run("special", testSplitPath(`/one/two[aa=//]/three`))
}

func testSplitPath(path string) func(*testing.T) {
	return func(t *testing.T) {
		x := transformer.SplitPath(path)
		y := splitUri_old(path)
		if !reflect.DeepEqual(x, y) {
			t.Fatalf("TestSplitPath failed.\n path=\"%s\"\n expected={%s}\n actual={%s}",
				path, strings.Join(y, "}{"), strings.Join(x, "}{"))
		}
	}
}

func splitUri_old(uri string) []string {
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	rgp := regexp.MustCompile(`\/\w*(\-*\:*\w*)*(\[([^\[\]]*)\])*`)
	pathList := rgp.FindAllString(uri, -1)
	for i, kname := range pathList {
		//xfmrLogInfoAll("uri path elems: %v", kname)
		if strings.HasPrefix(kname, "/") {
			pathList[i] = kname[1:]
		}
	}
	return pathList
}
