////////////////////////////////////////////////////////////////////////////////
//                                                                  //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                //
//                                                                  //
//  Licensed under the Apache License, Version 2.0 (the "License");    //
//  you may not use this file except in compliance with the License.      //
//  You may obtain a copy of the License at                        //
//                                                                  //
//     http://www.apache.org/licenses/LICENSE-2.0                    //
//                                                                  //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,    //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                  //
//                                                                  //
////////////////////////////////////////////////////////////////////////////////

package custom_validation

import (
	"strings"

	"github.com/go-redis/redis/v7"
	log "github.com/golang/glog"
)

func (t *CustomValidation) ValidateSymmHashCfg(vc *CustValidationCtxt) CVLErrorInfo {

	log.Info("ValidateSymmHashCfg Operation: ", vc.CurCfg.VOp)
	log.Info("ValidateSymmHashCfg Key: ", vc.CurCfg.Key)
	log.Info("ValidateSymmHashCfg Data: ", vc.CurCfg.Data)

	/* Allow table delete but validate specifc field delete */
	if (vc.CurCfg.VOp == OP_DELETE) && (len(vc.CurCfg.Data) == 0) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	keys := strings.Split(vc.CurCfg.Key, "|")
	if len(keys) < 2 {
		return CVLErrorInfo{
			ErrCode:          CVL_ERROR,
			TableName:        vc.CurCfg.Key,
			ConstraintErrMsg: "Invalid key",
		}
	}
	attrs, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
	if err != nil && err != redis.Nil {
		return CVLErrorInfo{
			ErrCode:          CVL_ERROR,
			TableName:        vc.CurCfg.Key,
			ConstraintErrMsg: "Failed to read ECMP Table",
		}
	}
	ip := keys[1] // ipv4,ipv6
	/* Check if symmetric hashing is enabled*/
	var symmHashFldName string
	var isSymmHashEnabled bool
	if ip == "ipv4" {
		symmHashFldName = "ipv4_symmetric"
	} else {
		symmHashFldName = "ipv6_symmetric"
	}
	fvs := make(map[string]string)
	/* Fetch the existing config */
	if err != redis.Nil && len(attrs) != 0 {
		for dfn, dfv := range attrs {
			fvs[dfn] = dfv
			if dfn == symmHashFldName && dfv == "true" {
				isSymmHashEnabled = true
			}
		}
	}
	/* Update the config map with requested config*/
	var f, v string
	for f, v = range vc.CurCfg.Data {
		if v == "" {
			if vc.CurCfg.VOp == OP_DELETE {
				v = "false"
			} else {
				log.Info("ValidateSymmHashCfg: Config failed...")
				return CVLErrorInfo{
					ErrCode:          CVL_ERROR,
					TableName:        vc.CurCfg.Key,
					Field:            f,
					Value:            v,
					ConstraintErrMsg: "Unexpected config request",
				}
			}
		}
		fvs[f] = v
	}
	var sip, dip, srcp, dstp, symm string
	var ok bool
	if ip == "ipv4" {
		srcp, ok = fvs["ipv4_l4_src_port"]
		if !ok {
			srcp = "false"
		}
		dstp, ok = fvs["ipv4_l4_dst_port"]
		if !ok {
			dstp = "false"
		}
		sip, ok = fvs["ipv4_src_ip"]
		if !ok {
			sip = "false"
		}
		dip, ok = fvs["ipv4_dst_ip"]
		if !ok {
			dip = "false"
		}
		symm, ok = fvs["ipv4_symmetric"]
		if !ok {
			symm = "false"
		}
	} else {
		srcp, ok = fvs["ipv6_l4_src_port"]
		if !ok {
			srcp = "false"
		}
		dstp, ok = fvs["ipv6_l4_dst_port"]
		if !ok {
			dstp = "false"
		}
		sip, ok = fvs["ipv6_src_ip"]
		if !ok {
			sip = "false"
		}
		dip, ok = fvs["ipv6_dst_ip"]
		if !ok {
			dip = "false"
		}
		symm, ok = fvs["ipv6_symmetric"]
		if !ok {
			symm = "false"
		}
	}
	/* Verify the updated config map satisfies all constraints*/
	if symm == "true" {
		var err_str string
		if sip == "false" && dip == "false" && srcp == "false" && dstp == "false" {
			err_str = "Configure required ECMP parameters before enabling symmetric hashing"
		} else if sip != dip {
			if isSymmHashEnabled {
				err_str = "Cannot modify this parameter as symmetric hashing is enabled"
			} else {
				err_str = "Symmetric hash requires both Src-IP and Dst-ip to be enabled or disabled"
			}
		} else if srcp != dstp {
			if isSymmHashEnabled {
				err_str = "Cannot modify this parameter as symmetric hashing is enabled"
			} else {
				err_str = "Symmetric hash requires both L4-Src-Port and L4-Dst-Port to be enabled or disabled"
			}
		} else {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
		return CVLErrorInfo{
			ErrCode:          CVL_ERROR,
			TableName:        vc.CurCfg.Key,
			ConstraintErrMsg: err_str,
		}
	}
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
