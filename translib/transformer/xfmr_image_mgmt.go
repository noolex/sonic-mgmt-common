////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Dell, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
)

func init() {
	XlateFuncBind("rpc_image_install", rpc_image_install)
	XlateFuncBind("rpc_image_remove", rpc_image_remove)
	XlateFuncBind("rpc_image_default", rpc_image_default)
	XlateFuncBind("YangToDb_image_table_key_xfmr", YangToDb_image_table_key_xfmr)
	XlateFuncBind("DbToYang_image_table_key_xfmr", DbToYang_image_table_key_xfmr)
	XlateFuncBind("YangToDb_image_global_key_xfmr", YangToDb_image_global_key_xfmr)
	XlateFuncBind("DbToYang_image_global_key_xfmr", DbToYang_image_global_key_xfmr)
}

var YangToDb_image_table_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {

	var err error
	pathInfo := NewPathInfo(inParams.uri)

	iName := pathInfo.Var("image-name")
	log.Infof("YangToDb_image_table_key_xfmr img-name %s, uri: %s", iName, inParams.uri)
	if len(iName) == 0 {
		return "", errors.New("image name is missing")
	}

	return iName, err
}

var DbToYang_image_table_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	var err error
	log.Infof("DbToYang_image_table_key_xfmr uri: %s, key %s", inParams.uri, inParams.key)
	rmap["image-name"] = inParams.key
	return rmap, err
}

var YangToDb_image_global_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error
	pathInfo := NewPathInfo(inParams.uri)

	key := pathInfo.Var("global-key")
	log.Infof("YangToDb_image_table_key_xfmr uri: %s , key %s ", inParams.uri, key)
	if len(key) == 0 {
		return "", errors.New("Global key missing.")
	}

	if key != "CONFIG" {
		return "", errors.New("Invalid global key.")
	}
	return "config", err
}

var DbToYang_image_global_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	var err error
	log.Info("DbToYang_image_global_key_xfmr root, uri: ", inParams.uri)
	rmap["global-key"] = "CONFIG"
	return rmap, err
}

var rpc_image_install RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
	return image_mgmt_operation("install", body)
}

var rpc_image_remove RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
	return image_mgmt_operation("remove", body)
}

var rpc_image_default RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
	return image_mgmt_operation("set_default", body)
}

func image_mgmt_operation(command string, body []byte) ([]byte, error) {

	var query_result HostResult
	var result struct {
		Output struct {
			Status        int32  `json:"status"`
			Status_detail string `json:"status-detail"`
		} `json:"sonic-image-management:output"`
	}

	var mapData map[string]interface{}

	err := json.Unmarshal(body, &mapData)
	var imagename string

	if err == nil || command == "remove" {

		input, image_present := mapData["sonic-image-management:input"]
		if image_present {
			mapData, image_present = input.(map[string]interface{})
			if image_present {
				var v interface{}
				v, image_present = mapData["imagename"]
				if image_present {
					imagename = v.(string)

				}
			}
		}
		err = nil

		log.Info("image_present:", image_present, "image:", imagename)
		if command == "remove" && !image_present {
			command = "cleanup"
		}
		if command != "cleanup" && !image_present {
			log.Error("Config input not provided.")
			err = errors.New("Image name not provided.")
		}

		if err == nil {
			var options []string

			if command == "install" {
				if strings.HasPrefix(imagename, "file://") {
					imagename = strings.TrimPrefix(imagename, "file:")
				} else if !strings.HasPrefix(imagename, "http:") &&
					!strings.HasPrefix(imagename, "https:") {
					errStr := "Invalid image url " + imagename
					err = errors.New(errStr)
				}

				if err == nil {

					/* Check if mgmt VRF configured */
					d, err1 := db.NewDB(getDBOptions(db.ConfigDB))

					if err1 != nil {
						log.Infof("image_mgmt_operation, unable to get configDB, error %v", err1)
					}

					defer d.DeleteDB()

					if err1 == nil {
						var MGMT_VRF_TABLE string = "MGMT_VRF_CONFIG"

						mgmtVrfTable := &db.TableSpec{Name: MGMT_VRF_TABLE}
						key := db.Key{Comp: []string{"vrf_global"}}

						dbEntry, err1 := d.GetEntry(mgmtVrfTable, key)
						if err1 != nil {
							log.Info("image_mgmt_operation, mgmt vrf not found")
						}

						if err1 == nil {
							mgmtVrfconfiguredStr := (&dbEntry).Get("mgmtVrfEnabled")

							if mgmtVrfconfiguredStr == "true" {
								options = append(options, "-mgmt")
							}
						}
					}
				}
			}

			if err == nil {
				options = append(options, command)
				if command == "install" || command == "remove" || command == "cleanup" {
					options = append(options, "-y")
				}

				if len(imagename) > 0 {
					options = append(options, imagename)
				}
				log.Info("Command:", options)
				query_result = HostQuery("image_mgmt.action", options)
			}
		}
	}

	result.Output.Status = 1
	if err != nil {
		result.Output.Status_detail = err.Error()
	} else if query_result.Err != nil {
		result.Output.Status_detail = "Internal SONiC Hostservice communication failure."
	} else if query_result.Body[0].(int32) == 1 {
		result.Output.Status_detail = fmt.Sprintf("Invalid image URL %s.", imagename)
	} else if query_result.Body[0].(int32) != 0 {
		result.Output.Status_detail = "Command Failed."
	} else {
		result.Output.Status = 0
		result.Output.Status_detail = "SUCCESS"
	}

	json_m, _ := json.Marshal(&result)

	if result.Output.Status > 0 {
		err = tlerr.InvalidArgsError{Format: result.Output.Status_detail}
	}
	return json_m, err
}
