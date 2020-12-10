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
        "strings"
        "fmt"
        util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
    )

func (t *CustomValidation) ValidateL3vniConfiguration(vc *CustValidationCtxt) CVLErrorInfo {
    
    if (vc.CurCfg.VOp != OP_DELETE) {
         return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }

    keys := "VRF|" + vc.YNodeVal
    vrfData, err := vc.RClient.HGetAll(keys).Result()

    if (err != nil) {
        util.CVL_LEVEL_LOG(util.TRACE_SEMANTIC, "Given VRF not found or invalid argument")
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            TableName: "BGP_GLOBALS",
            Keys: strings.Split(vc.CurCfg.Key, "|"),
            ConstraintErrMsg: fmt.Sprintf("Failed to get all fields of VRF %s", vc.YNodeVal),
            CVLErrDetails: "DB Access Error",
        }
    }

    vni, hasVni := vrfData["vni"]

    if (hasVni && vni != "0") {
        error_str := fmt.Sprintf("Please unconfigure l3vni %s from vrf %s", vni, vc.YNodeVal)
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            Msg: error_str,
            ConstraintErrMsg: error_str,
        }
    }

    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

func (t *CustomValidation) ValidateStrictAndOverRideCapability (vc *CustValidationCtxt) CVLErrorInfo {

    if ((vc.CurCfg.Data["strict_capability_match"] == "true") && (vc.CurCfg.Data["override_capability"] == "true")) {
        return CVLErrorInfo{
            ErrCode: CVL_SEMANTIC_ERROR,
            ConstraintErrMsg: "Can't set override-capability and strict-capability-match at the same time" ,
        }
    } else {
        neighData, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
        if (err == nil) {
            strictCap, hasStrict := neighData["strict_capability_match"]
            if (hasStrict && strictCap == "true") {
                if (vc.CurCfg.Data["override_capability"] == "true"){
                    return CVLErrorInfo{
                        ErrCode: CVL_SEMANTIC_ERROR,
                        ConstraintErrMsg: "Can't set override-capability and strict-capability-match at the same time",
                    }
                }
            }
            overCap, hasOver := neighData["override_capability"]
            if (hasOver && overCap == "true") {
                if (vc.CurCfg.Data["strict_capability_match"] == "true"){
                    return CVLErrorInfo{
                        ErrCode: CVL_SEMANTIC_ERROR,
                        ConstraintErrMsg: "Can't set override-capability and strict-capability-match at the same time" ,
                    }
                }
            }
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

