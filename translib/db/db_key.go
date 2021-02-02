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

import "fmt"

// Key is the db key components without table name prefix.
// (Eg: { Comp : [] string { "acl1", "rule1" } } ).
type Key struct {
	Comp []string
}

// NewKey returns a Key object with given key components
func NewKey(comps ...string) *Key {
	return &Key{Comp: comps}
}

func (k Key) String() string {
	return fmt.Sprintf("{Comp: %v}", k.Comp)
}

// Len returns number of components in the Key
func (k *Key) Len() int {
	return len(k.Comp)
}

// Get returns the key component at given index
func (k *Key) Get(index int) string {
	return k.Comp[index]
}

// IsPattern checks if the key has redis glob-style pattern.
// Supports only '*' and '?' wildcards.
func (k *Key) IsPattern() bool {
	for _, s := range k.Comp {
		n := len(s)
		for i := 0; i < n; i++ {
			switch s[i] {
			case '\\':
				i++
			case '*', '?':
				return true
			}
		}
	}
	return false
}
