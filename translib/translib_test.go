////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()

	fmt.Println("Cleanup before tests..")
	invokeCleanupFuncs(true)

	ret := m.Run()

	fmt.Println("Cleanup after tests..")
	invokeCleanupFuncs(false)

	os.Exit(ret)
}

// CleanupFunc is the callback function for the cleanup tasks to be performed
// before and after tests. Should be registered via addCleanupFunc.
type CleanupFunc func() error

var cleanupFuncs map[string]CleanupFunc

// addCleanupFunc registers a cleanup function.
// These functions are invoked at the beginning and end of TestMain.
func addCleanupFunc(f CleanupFunc) {
	if f == nil {
		return
	}
	if cleanupFuncs == nil {
		cleanupFuncs = map[string]CleanupFunc{}
	}
	name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	cleanupFuncs[name] = f
}

func invokeCleanupFuncs(exitOnError bool) {
	for name, f := range cleanupFuncs {
		if err := f(); err != nil {
			fmt.Printf("%s failed; err=%v\n", name, err)
			if exitOnError {
				os.Exit(-1)
			}
		}
	}
}

// assert fails the test if the condition is false.
func assert(tb testing.TB, condition bool, msg string, v ...interface{}) {
	if !condition {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: "+msg+"\033[39m\n\n", append([]interface{}{filepath.Base(file), line}, v...)...)
		tb.FailNow()
	}
}

// ok fails the test if an err is not nil.
func ok(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		tb.FailNow()
	}
}

// equals fails the test if exp is not equal to act.
func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

func BenchmarkGetAppModule(b *testing.B) {
	var v Version
	path := "/benchmark/common_app/creation"
	for i := 0; i < b.N; i++ {
		getAppModule(path, v)
	}
}
