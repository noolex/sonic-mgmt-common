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

import (
	// "fmt"
	// "strconv"

	"errors"
	// "strings"
	// "sync"
	// "reflect"

	// "github.com/Azure/sonic-mgmt-common/cvl"
	// "github.com/go-redis/redis/v7"
	"github.com/golang/glog"
	// "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

////////////////////////////////////////////////////////////////////////////////
//  Exported Types                                                            //
////////////////////////////////////////////////////////////////////////////////

type dbOnChangeReg struct {
	CacheTables   map[string]bool // Only cache these tables.
}

////////////////////////////////////////////////////////////////////////////////
//  Exported Functions                                                        //
////////////////////////////////////////////////////////////////////////////////

func (d *DB) RegisterTableForOnChangeCaching(ts *TableSpec) error {
	var e error
	if glog.V(1) {
		glog.Info("RegisterTableForOnChange: ts:", ts)
	}
	if d.Opts.IsEnableOnChange {
		d.onCReg.CacheTables[ts.Name] = true
	} else {
		glog.Error("RegisterTableForOnChange: OnChange disabled")
		e = errors.New("OnChange disabled")
	}
	return e
}

func (d *DB) OnChangeCacheUpdate(ts *TableSpec, key Key) (Value, Value, error) {
	var e error
	if glog.V(3) {
		glog.Info("OnChangeCacheUpdate: Begin: ", "ts: ", ts, " key: ", key)
	}

	if !d.Opts.IsEnableOnChange {
		glog.Error("OnChangeCacheUpdate: OnChange disabled")
		e = errors.New("OnChange disabled")
		return Value{}, Value{}, e
	}

	var valueOrig Value
	if _, ok := d.cache.Tables[ts.Name] ; ok {
			valueOrig = d.cache.Tables[ts.Name].entry[d.key2redis(ts, key)]
	}

	// Get New Value from the DB
	value, e := d.getEntry(ts,key,true)

	if e != nil {
		if glog.V(1) {
			glog.Info("OnChangeCacheUpdate: Delete ts:", ts, " key: ", key)
		}
		if _, ok := d.cache.Tables[ts.Name] ; ok {
			delete(d.cache.Tables[ts.Name].entry,d.key2redis(ts, key))
		}
		e = nil
	}

	return valueOrig, value, e
}



////////////////////////////////////////////////////////////////////////////////
//  Internal Functions                                                        //
////////////////////////////////////////////////////////////////////////////////

func init() {
}

func (reg *dbOnChangeReg) isCacheTable(name string) bool {
	return reg.CacheTables[name]
}

