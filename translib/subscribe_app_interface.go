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
	"fmt"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/path"
	"github.com/openconfig/gnmi/proto/gnmi"
)

/**
 *This file contains type definitions to be used by app modules to
 * handle subscribe requests.
 */

// translateSubRequest is the input for translateSubscribe callback
type translateSubRequest struct {
	ctxID interface{}      // request id for logging
	path  string           // subscribe path
	dbs   [db.MaxDB]*db.DB // DB objects for querying, if needed
}

// translateSubResponse is the output returned by app modules
// from translateSubscribe callback.
type translateSubResponse struct {
	// ntfAppInfoTrgt includes the notificationAppInfo mappings for top
	// level tables corresponding to the subscribe path. At least one
	// such mapping should be present.
	ntfAppInfoTrgt []*notificationAppInfo

	// ntfAppInfoTrgtChlds includes notificationAppInfo mappings for the
	// dependent tables of the entries in ntfAppInfoTrgt. Should be nil
	// if there are no dependent tables.
	ntfAppInfoTrgtChlds []*notificationAppInfo
}

// notificationAppInfo contains the details for monitoring db notifications
// for a given path. App modules provide these details for each subscribe
// path. One notificationAppInfo object must inclue details for one db table.
// One subscribe path can map to multiple notificationAppInfo.
type notificationAppInfo struct {
	// database index for the DB key represented by this notificationAppInfo.
	// Should be db.MaxDB for non-DB data provider cases.
	dbno db.DBNum

	// table name. Should be nil for non-DB case.
	table *db.TableSpec

	// key components without table name prefix. Can include wildcards.
	// Should be nil for non-DB case.
	key *db.Key

	// path to which the key maps to. Can include wildcard keys.
	// Should match request path -- should not point to any node outside
	// the yang segment of request path.
	path *gnmi.Path

	// dbFieldYangPathMap is the mapping of db entry field to the yang
	// field (leaf/leaf-list) for the input path.
	dbFldYgPathInfoList []*dbFldYgPathInfo

	// isOnChangeSupported indicates if on-change notification is
	// supported for the input path. Table and key mappings should
	// be filled even if on-change is not supported.
	isOnChangeSupported bool

	// mInterval indicates the minimum sample interval supported for
	// the input path. Can be set to 0 (default value) to indicate
	// system default interval.
	mInterval int

	// pType indicates the preferred notification type for the input
	// path. Used when gNMI client subscribes with "TARGET_DEFINED" mode.
	pType NotificationType

	// opaque data can be used to store context information to assist
	// future key-to-path translations. This is an optional data item.
	// Apps can store any context information based on their logic.
	// Translib passes this back to the processSubscribe function when
	// it detects changes to the DB entry for current key or key pattern.
	opaque interface{}
}

type dbFldYgPathInfo struct {
	rltvPath       string
	dbFldYgPathMap map[string]string //db field to leaf / rel. path to leaf
}

// processSubRequest is the input for app module's processSubscribe function.
// It includes a path template (with wildcards) and one db key that needs to
// be mapped to the path.
type processSubRequest struct {
	ctxID interface{} // context id for logging
	path  *gnmi.Path  // path template to be filled -- contains wildcards

	// DB entry info to be used for filling the path template
	dbno  db.DBNum
	table *db.TableSpec
	key   *db.Key

	// List of all DB objects. Apps should only use these DB objects
	// to query db if they need additional data for translation.
	dbs [db.MaxDB]*db.DB

	// App specific opaque data -- can be used to pass context data
	// between translateSubscribe and processSubscribe.
	opaque interface{}
}

// processSubResponse is the output data structure of processSubscribe
// function. Includes the path with wildcards resolved. Translib validates
// if this path matches the template in processSubRequest.
type processSubResponse struct {
	// path with wildcards resolved
	path *gnmi.Path
}

func (ni *notificationAppInfo) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "{path='%s'", path.String(ni.path))
	fmt.Fprintf(&b, ", db=%s, ts=%v, key=%v", ni.dbno, ni.table, ni.key)
	fmt.Fprintf(&b, ", fields={")
	for i, fi := range ni.dbFldYgPathInfoList {
		if i != 0 {
			fmt.Fprintf(&b, ", ")
		}
		fmt.Fprintf(&b, "%s=%v", fi.rltvPath, fi.dbFldYgPathMap)
	}
	fmt.Fprintf(&b, "}}")
	return b.String()
}

// isNonDB returns true if the notificationAppInfo ni is a non-DB mapping.
func (ni *notificationAppInfo) isNonDB() bool {
	return ni.dbno == db.MaxDB || ni.table == nil || ni.key == nil
}
