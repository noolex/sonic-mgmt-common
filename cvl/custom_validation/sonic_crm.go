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
	"fmt"
	"strconv"
	"strings"
	//log "github.com/golang/glog"
)

func (t *CustomValidation) ValidateCrmThreshold(vc *CustValidationCtxt) CVLErrorInfo {

	if vc.CurCfg.VOp == OP_DELETE {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	//Allow empty value
	if vc.YNodeVal == "" {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	tok := strings.Split(vc.YNodeName, "_")
	key := ""
	for idx := 0; idx < len(tok)-2; idx++ {
		key += tok[idx] + "_"
	}

	hi, hasHI := vc.CurCfg.Data[key+"high_threshold"]
	if !hasHI {
		xx, err := vc.RClient.HMGet(vc.CurCfg.Key, key+"high_threshold").Result()
		if (err == nil) && (xx != nil) {
			hi = fmt.Sprintf("%v", xx)
			hi = hi[1 : len(hi)-1]
		} else {
			hi = ""
		}
	}
	if hi == "" {
		hi = "0"
	}

	lo, hasLO := vc.CurCfg.Data[key+"low_threshold"]
	if !hasLO {
		xx, err := vc.RClient.HMGet(vc.CurCfg.Key, key+"low_threshold").Result()
		if (err == nil) && (xx != nil) {
			lo = fmt.Sprintf("%v", xx)
			lo = lo[1 : len(lo)-1]
		} else {
			lo = ""
		}
	}
	if lo == "" {
		lo = "0"
	}

	tt, hasTT := vc.CurCfg.Data[key+"threshold_type"]
	if !hasTT {
		xx, err := vc.RClient.HMGet(vc.CurCfg.Key, key+"threshold_type").Result()
		if (err == nil) && (xx != nil) {
			tt = fmt.Sprintf("%v", xx)
			tt = tt[1 : len(tt)-1]
		} else {
			tt = ""
		}
	}
	if tt == "" {
		tt = "percentage"
	}

	loValue, _ := strconv.Atoi(lo)
	hiValue, _ := strconv.Atoi(hi)

	//log.Infof("+++ ValidateCrmThreshold: %v: %v: %v,%v", key, tt, loValue, hiValue)

	if (loValue < 0) || (hiValue < 0) {
		return CVLErrorInfo{
			ErrCode:       CVL_SYNTAX_INVALID_INPUT_DATA,
			CVLErrDetails: "negative threshold",
			ErrAppTag:     "threshold-invalid",
		}
	}

	if (tt == "percentage") && ((loValue > 100) || (hiValue > 100)) {
		return CVLErrorInfo{
			ErrCode:       CVL_SYNTAX_INVALID_INPUT_DATA,
			CVLErrDetails: "invalid threshold for percentage type",
			ErrAppTag:     "threshold-invalid",
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
