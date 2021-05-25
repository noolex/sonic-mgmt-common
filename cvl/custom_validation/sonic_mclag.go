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

package custom_validation

import (
	"strconv"
	"strings"

	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	log "github.com/golang/glog"
)

//ValidateMclagMac Check whether mclag mac is valid mac or not
//Purpose: Check correct mclag mac provided for config is valid mac
//vc : Custom Validation Context
//Returns -  CVL Error object
func (t *CustomValidation) ValidateMclagMac(vc *CustValidationCtxt) CVLErrorInfo {
	var valid bool = true
	mac := vc.YNodeVal

	log.Info("In MCLAG Mac custom validation:", mac)
	if mac != "" {
		if mac == "00:00:00:00:00:00" {
			valid = false
		} else if strings.EqualFold(mac, "ff:ff:ff:ff:ff:ff") { //broadcast mac
			valid = false
		} else { //multicast mac
			macSplit := strings.Split(mac, ":")
			macHi, err := strconv.ParseUint(macSplit[0], 16, 8)
			if err != nil {
				valid = false
			} else if macHi&0x01 == 0x01 {
				valid = false
			} else {
				valid = true
			}
		}
	}

	if !valid {
		errStr := "MCLAG MAC not valid, it shouldn't be zero, multicast, or broadcast"
		util.CVL_LEVEL_LOG(util.ERROR, "%s", errStr)
		return CVLErrorInfo{
			ErrCode:          CVL_SYNTAX_INVALID_INPUT_DATA,
			TableName:        "MCLAG_DOMAIN",
			CVLErrDetails:    errStr,
			ConstraintErrMsg: errStr,
		}
	}
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
