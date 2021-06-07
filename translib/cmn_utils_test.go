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
	"fmt"
	"testing"

	db "github.com/Azure/sonic-mgmt-common/translib/db"
)

func processGetRequest(url string, expectedRespJson string, errorCase bool) func(*testing.T) {
	return func(t *testing.T) {
		response, err := Get(GetRequest{Path: url, User: UserRoles{Name: "admin", Roles: []string{"admin"}}})
		if err != nil && !errorCase {
			t.Errorf("Error %v received for Url: %s", err, url)
		}

		respJson := response.Payload
		if string(respJson) != expectedRespJson {
			t.Errorf("Response for Url: %s received is not expected:\n%s", url, string(respJson))
		}
	}
}

func processSetRequest(url string, jsonPayload string, oper string, errorCase bool) func(*testing.T) {
	return func(t *testing.T) {
		var err error
		switch oper {
		case "POST":
			_, err = Create(SetRequest{Path: url, Payload: []byte(jsonPayload)})
		case "PATCH":
			_, err = Update(SetRequest{Path: url, Payload: []byte(jsonPayload)})
		case "PUT":
			_, err = Replace(SetRequest{Path: url, Payload: []byte(jsonPayload)})
		default:
			t.Errorf("Operation not supported")
		}
		if err != nil && !errorCase {
			t.Errorf("Error %v received for Url: %s", err, url)
		}
	}
}

func processDeleteRequest(url string) func(*testing.T) {
	return func(t *testing.T) {
		_, err := Delete(SetRequest{Path: url})
		if err != nil {
			t.Errorf("Error %v received for Url: %s", err, url)
		}
	}
}

func getConfigDb() *db.DB {
	configDb, _ := db.NewDB(db.Options{
		DBNo:               db.ConfigDB,
		InitIndicator:      "CONFIG_DB_INITIALIZED",
		TableNameSeparator: "|",
		KeySeparator:       "|",
	})

	return configDb
}

var emptyJson string = "{}"

// getNPorts returns random N eth port names from PORT table.
func getNPorts(n int) ([]string, error) {
	d := getConfigDb()
	defer d.DeleteDB()

	keys, err := d.GetKeys(&db.TableSpec{Name: "PORT"})
	if err != nil {
		return nil, err
	}
	if len(keys) < n {
		return nil, fmt.Errorf("Not enough PORT entries; %d requested, %d present", n, len(keys))
	}
	ports := make([]string, n)
	for i := 0; i < n; i++ {
		ports[i] = keys[i].Get(0)
	}
	return ports, nil
}
