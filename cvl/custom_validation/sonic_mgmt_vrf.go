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

package custom_validation

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	"github.com/go-redis/redis/v7"
)

func (t *CustomValidation) ValidateBeforeMgmtVrfDelete(ctx *CustValidationCtxt) CVLErrorInfo {
	cfg := ctx.CurCfg
	err := CVLErrorInfo{ErrCode: CVL_SUCCESS}

	// Mgmt vrf can be disabled in following ways:
	// 1) delete of MGMT_VRF_CONFIG entry
	// 2) delete mgmtVrfEnabled field in MGMT_VRF_CONFIG entry
	// 3) update mgmtVrfEnabled to false in MGMT_VRF_CONFIG entry
	var mgmtVrfDelete bool
	if v, ok := cfg.Data["mgmtVrfEnabled"]; ok {
		mgmtVrfDelete = (cfg.VOp == OP_DELETE) || (cfg.VOp == OP_UPDATE && v != "true")
	} else {
		mgmtVrfDelete = (cfg.VOp == OP_DELETE && len(cfg.Data) == 0)
	}

	if mgmtVrfDelete {
		if err.ErrCode == CVL_SUCCESS {
			err = verifyMgmtVrfNotReferred("SYSLOG_SERVER|*", "ipaddress", "vrf_name", "-1", ctx)
		}
		if err.ErrCode == CVL_SUCCESS {
			err = verifyMgmtVrfNotReferred("STATIC_ROUTE|*", "vrf_name|prefix", "vrf_name", "1", ctx)
		}
                if err.ErrCode == CVL_SUCCESS {
                        err = verifyMgmtVrfNotReferred("NTP|*", "global", "vrf", "1", ctx)
                }
	}

	return err
}

func verifyMgmtVrfNotReferred(keyPattern, keyNames, field, count string, ctx *CustValidationCtxt) CVLErrorInfo {
	tableName := strings.SplitN(keyPattern, "|", 2)[0]
	var data map[string]interface{}
	var predicate interface{}
	if len(field) != 0 {
		predicate = fmt.Sprintf("return (k['%[1]s'] == 'mgmt' or h['%[1]s'] == 'mgmt')", field)
	}

	// Find rows referring to mgmt vrf using lua script. It returns nil or a string
	// containing data json -- "{ table: { key : { field: value, ... }}}"
	resp, err := util.FILTER_ENTRIES_LUASCRIPT.Run(
		ctx.RClient, nil, keyPattern, keyNames, predicate, keyNames, count).Result()
	util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "verifyMgmtVrfNotReferred: %s rows = %v", tableName, resp)
	if err == nil {
		err = json.Unmarshal([]byte(resp.(string)), &data)
	} else if err == redis.Nil {
		err = nil // lua script returned nil, which is good
	}

	// DB error or json error
	if err != nil {
		return CVLErrorInfo{
			ErrCode:          CVL_FAILURE,
			TableName:        tableName,
			Msg:              err.Error(),
			ConstraintErrMsg: "Database access error",
			ErrAppTag:        "database-error",
		}
	}

	if rows, ok := data[tableName].(map[string]interface{}); ok && len(rows) != 0 {
		var errKeys []string
		for rowKey := range rows {
			key := fmt.Sprintf("%s|%s", tableName, rowKey)
			//TODO check if data is not deleted in this transaction
			errKeys = append(errKeys, key)
		}

		if len(errKeys) != 0 {
			cfgKeys := strings.Split(ctx.CurCfg.Key, "|")
			return CVLErrorInfo{
				ErrCode:          CVL_SEMANTIC_ERROR,
				TableName:        cfgKeys[0],
				Keys:             cfgKeys,
				Msg:              fmt.Sprintf("Management VRF referred by %v, field=%s", errKeys, field),
				ConstraintErrMsg: "Management VRF in use",
				ErrAppTag:        "instance-in-use",
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
