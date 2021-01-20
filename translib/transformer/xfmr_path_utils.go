///////////////////////////////////////////////////////////////////////
//
// Copyright 2019 Broadcom. All rights reserved.
// The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
//
///////////////////////////////////////////////////////////////////////

package transformer

import (
	"bytes"
	"fmt"
	"strings"
)

// PathInfo structure contains parsed path information.
type PathInfo struct {
	Path     string
	Template string
	Vars     map[string]string
}

// HasVar checks if the PathInfo contains given variable.
func (p *PathInfo) HasVar(name string) bool {
   _, exists := p.Vars[name]
   return exists
}

// Var returns the string value for a path variable. Returns
// empty string if no such variable exists.
func (p *PathInfo) Var(name string) string {
	return p.Vars[name]
}

// NewPathInfo parses given path string into a PathInfo structure.
func NewPathInfo(path string) *PathInfo {
	var info PathInfo
	info.Path = path
	info.Vars = make(map[string]string)

	//TODO optimize using regexp
	var template strings.Builder
	r := strings.NewReader(path)

	for r.Len() > 0 {
		c, _ := r.ReadByte()
		if c != '[' {
			template.WriteByte(c)
			continue
		}

		name := readUntil(r, '=')
		value := readUntil(r, ']')
               // Handle duplicate parameter names by suffixing "#N" to it.
               // N is the number of occurance of that parameter name.
               if info.HasVar(name) {
                   namePrefix := name
                   for k := 2; info.HasVar(name); k++ {
                       name = fmt.Sprintf("%s#%d", namePrefix, k)
                   }
               }

		if len(name) != 0 {
			fmt.Fprintf(&template, "{}")
			info.Vars[name] = value
		}
	}

	info.Template = template.String()

	return &info
}

func readUntil(r *strings.Reader, delim byte) string {
        var buff strings.Builder
        var escaped bool

        for {
                c, err := r.ReadByte()
                if err != nil || (c == delim && !escaped) {
                        break
                } else if c == '\\' && !escaped {
                        escaped = true
                } else {
                        escaped = false
                        buff.WriteByte(c)
                }
        }

        return buff.String()
}

// SplitPath splits the ygot path into parts.
func SplitPath(path string) []string {
	var parts []string
	var start int
	var inEscape, inKey bool

	path = strings.TrimPrefix(path, "/")

	for i, c := range path {
		switch {
		case inEscape:
			inEscape = false
		case c == '\'':
			inEscape = true
		case c == '[':
			inKey = true
		case c == ']':
			inKey = false
		case c == '/' && !inEscape && !inKey:
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}

	parts = append(parts, path[start:])
	return parts
}

func RemoveXPATHPredicates(s string) (string, error) {
	var b bytes.Buffer
	for i := 0; i < len(s); {
		ss := s[i:]
		si, ei := strings.Index(ss, "["), strings.Index(ss, "]")
		switch {
		case si == -1 && ei == -1:
			// This substring didn't contain a [] pair, therefore write it
			// to the buffer.
			b.WriteString(ss)
			// Move to the last character of the substring.
			i += len(ss)
		case si == -1 || ei == -1:
			// This substring contained a mismatched pair of []s.
			return "", fmt.Errorf("Mismatched brackets within substring %s of %s, [ pos: %d, ] pos: %d", ss, s, si, ei)
		case si > ei:
			// This substring contained a ] before a [.
			return "", fmt.Errorf("Incorrect ordering of [] within substring %s of %s, [ pos: %d, ] pos: %d", ss, s, si, ei)
		default:
			// This substring contained a matched set of []s.
			b.WriteString(ss[0:si])
			i += ei + 1
		}
	}

	return b.String(), nil
}
