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
	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
    "strings"
    "strconv"
)

const QMIN = 0
const QMAX = 7
const CPU_QMAX = 47

func (t *CustomValidation) ValidateQindexPattern(
	vc *CustValidationCtxt) CVLErrorInfo {

	util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateQindexPattern operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateQindexPattern key: %v", vc.CurCfg.Key)
	keys := strings.Split(vc.CurCfg.Key, "|")
    if len(keys) != 3 {
        err_str := "Invalid Key"
        return CVLErrorInfo{
            ErrCode:          CVL_SEMANTIC_ERROR,
            TableName:        keys[0],
            Keys:             keys,
            ConstraintErrMsg: err_str,
            ErrAppTag:        "key-invalid",
        }
    }

    var qmin, qmax int
    if strings.Contains(keys[2], "-") {
	   qrange := strings.Split(keys[2], "-")
       qmin, _ = strconv.Atoi(qrange[0])
       qmax, _ = strconv.Atoi(qrange[1])
    } else {
      qmin, _ = strconv.Atoi(keys[2])
      qmax, _ = strconv.Atoi(keys[2])
    }

    if ((qmin < QMIN) ||
        (keys[1] == "CPU" && qmax > CPU_QMAX) ||
        (keys[1] != "CPU" && qmax > QMAX)) {
        err_str := "Invalid Q-index"
        return CVLErrorInfo{
            ErrCode:          CVL_SEMANTIC_ERROR,
            TableName:        keys[0],
            Keys:             keys,
            ConstraintErrMsg: err_str,
            ErrAppTag:        "qindex-invalid",
        }
    }

    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
