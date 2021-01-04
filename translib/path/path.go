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

// Package path defines utilities to operate on translib path.
// TRanslib uses gnmi path syntax.
package path

import (
	"fmt"

	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
)

// HasWildcardKey checks if a gnmi.Path contains any wildcard key value ("*").
func HasWildcardKey(p *gnmi.Path) bool {
	for _, e := range p.Elem {
		for _, v := range e.Key {
			if v == "*" {
				return true
			}
		}
	}

	return false
}

// Len returns number of elements in a gnmi.Path
func Len(path *gnmi.Path) int {
	return len(path.Elem)
}

// IsEmpty checks if gnmi path is nil or empty
func IsEmpty(path *gnmi.Path) bool {
	return path == nil || len(path.Elem) == 0
}

// Clone returns a clone of given gnmi.Path.
func Clone(path *gnmi.Path) *gnmi.Path {
	newElem := make([]*gnmi.PathElem, len(path.Elem))
	for i, ele := range path.Elem {
		newElem[i] = cloneElem(ele)
	}
	return &gnmi.Path{Elem: newElem}
}

func cloneElem(pe *gnmi.PathElem) *gnmi.PathElem {
	clone := &gnmi.PathElem{Name: pe.Name}
	if pe.Key != nil {
		clone.Key = make(map[string]string)
		for k, v := range pe.Key {
			clone.Key[k] = v
		}
	}
	return clone
}

// String returns gnmi.Path as a string. Returns empty string
// if the path is not valid.
func String(path *gnmi.Path) string {
	s, err := ygot.PathToString(path)
	if err != nil {
		s = fmt.Sprintf("%v", path)
	}
	return s
}

// SubPath creates a new gnmi.Path having path elements from
// given start and end indices.
func SubPath(path *gnmi.Path, startIndex, endIndex int) *gnmi.Path {
	newElem := make([]*gnmi.PathElem, endIndex-startIndex)
	copy(newElem, path.Elem[startIndex:endIndex])
	return &gnmi.Path{Elem: newElem}
}

// AppendElems appends one or more path elements to a gnmi.Path
func AppendElems(path *gnmi.Path, elems ...string) {
	for _, ele := range elems {
		pe := &gnmi.PathElem{Name: ele}
		path.Elem = append(path.Elem, pe)
	}
}

// MergeElemsAt merges new path elements at given path position.
// Returns number of elements merged.
func MergeElemsAt(path *gnmi.Path, index int, elems ...string) int {
	size := len(path.Elem)
	for i, ele := range elems {
		if index >= size {
			newElem := &gnmi.PathElem{Name: ele}
			path.Elem = append(path.Elem, newElem)
		} else if elems[i] != path.Elem[index].Name {
			return i
		} else {
			index++
		}
	}

	return len(elems)
}

// GetElemAt returns the path element name at given index.
// Returns empty string if index is not valid.
func GetElemAt(path *gnmi.Path, index int) string {
	if index < len(path.Elem) {
		return path.Elem[index].Name
	}
	return ""
}

// SetKeyAt adds/updates a key value to the path element at given index.
func SetKeyAt(path *gnmi.Path, index int, name, value string) {
	SetKey(path.Elem[index], name, value)
}

// SetKey adds/updates a key value to the path element.
func SetKey(elem *gnmi.PathElem, name, value string) {
	if elem.Key == nil {
		elem.Key = map[string]string{name: value}
	} else {
		elem.Key[name] = value
	}
}

// Matches checks if the path matches a template. Path must satisfy
// following conditions for a match:
// 1) Should be of equal length or longer than template.
// 2) Element names at each position should match.
// 3) Keys at each postion should match -- should have same set of key
// 	  names with same values. Wildcard value in the template matches
//	  any value of corresponding key in the path. But wildcard value
// 	  in the path can only match with a wildcard value in template.
//
// Examples:
// "AA/BB/CC" matches "AA/BB"
// "AA/BB[x=1][y=1]" matches "AA/BB[x=1][y=*]"
// "AA/BB[x=1][y=*]" matches "AA/BB[x=1][y=*]"
// "AA/BB[x=1]" does not match "AA/BB[x=1][y=*]"
// "AA/BB[x=*]" does not match "AA/BB[x=1]"
func Matches(path *gnmi.Path, template *gnmi.Path) bool {
	if len(path.Elem) < len(template.Elem) {
		return false
	}

	for i, t := range template.Elem {
		p := path.Elem[i]
		if t.Name != p.Name {
			return false
		}
		if len(t.Key) != len(p.Key) {
			return false
		}
		for k, tv := range t.Key {
			if pv, ok := p.Key[k]; ok {
				if tv != "*" && tv != pv {
					return false
				}
			} else {
				return false
			}
		}
	}

	return true
}
