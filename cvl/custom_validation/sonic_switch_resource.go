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

package custom_validation

import (
    util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
)

func(t * CustomValidation) IsDropMonitorSupported(vc * CustValidationCtxt) CVLErrorInfo {
    stateDBClient := util.NewDbClient("STATE_DB")
    defer func() {
        if (stateDBClient != nil) {
            stateDBClient.Close()
        }
    }()

    var status string
    status = "UNSUPPORTED"
    if (stateDBClient != nil) {
        key := "TAM_STATE_FEATURES_TABLE|DROPMONITOR"
        status, _ = stateDBClient.HGet(key, "op-status").Result()
    }

    if ((status == "UNSUPPORTED") || (status == "INSUFFICIENT_RESOURCES")) {
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            ConstraintErrMsg: "Dropmonitor feature is not supported, operation not allowed",
            CVLErrDetails : "Operation not allowed",
            ErrAppTag : "operation-not-allowed",
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

