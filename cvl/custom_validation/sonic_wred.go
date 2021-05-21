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
	"strconv"
	"strings"

	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
)

func (t *CustomValidation) ValidateAtLeastOneColorEnabled(
	vc *CustValidationCtxt) CVLErrorInfo {
	var color_attributes = []string{
		"wred_green_enable",
		"wred_yellow_enable",
		"wred_red_enable",
	}

	util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "ValidateAtLeastOneColorEnabled operation: %v", vc.CurCfg.VOp)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled key: %v", vc.CurCfg.Key)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled YNodeName: %v", vc.YNodeName)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled YNodeVal: %v", vc.YNodeVal)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled YCur: %v", vc.YCur)
	util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled Data: %v", vc.CurCfg.Data)

	var color_attr_present bool = false
	for _, attrib := range color_attributes {
		if _, ok := vc.CurCfg.Data[attrib]; ok {
			color_attr_present = true
			break
		}
	}

	if !color_attr_present {
		util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled no color attr present, Skip validate")
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	var disable_all_color bool = true
	var color_enable bool = false

	entry, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
	for _, attrib := range color_attributes {
		color_enable = false
		if err == nil {
			/* check if WRED_PROFILE attribute is present */
			if enable, found_field := entry[attrib]; found_field {
				color_enable, _ = strconv.ParseBool(enable)
			}
		}

		if val, ok := vc.CurCfg.Data[attrib]; ok {
			if vc.CurCfg.VOp != OP_DELETE {
				color_enable, _ = strconv.ParseBool(val)
			} else {
				color_enable = false
			}
		}
		if color_enable {
			disable_all_color = false
			break
		}
	}

	if !disable_all_color {
		util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled one color enable, Skip validate")
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	util.CVL_LEVEL_LOG(util.INFO, "ValidateAtLeastOneColorEnabled, Check profile attached to queue")
	/* get all QUEUE entries */
	keys, err := vc.RClient.Keys("QUEUE|*").Result()
	if err == nil {
		for _, key := range keys {
			/* for each QUEUE entry found */
			entry, err := vc.RClient.HGetAll(key).Result()
			if err == nil {
				/* check if wred_profile attribute is present */
				if wred_profile_name, found_field := entry["wred_profile"]; found_field {
					/* if wred_profile matches name */
					wred_name := strings.Trim(wred_profile_name, "[]")
					wred_name = strings.TrimPrefix(wred_name, "WRED_PROFILE|")
					if strings.Split(vc.CurCfg.Key, "|")[1] == wred_name {
						err_str := "Atleast one of the colors(GREEN/YELLOW/RED) must be present in WRED policy"
						return CVLErrorInfo{
							ErrCode:          CVL_SEMANTIC_ERROR,
							TableName:        keys[0],
							Keys:             keys,
							ConstraintErrMsg: err_str,
							ErrAppTag:        "del-not-allowed",
						}
					}
				}
			}
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
