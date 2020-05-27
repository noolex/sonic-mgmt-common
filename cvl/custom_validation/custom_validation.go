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
	"github.com/go-redis/redis/v7"
	"strings"
	log "github.com/golang/glog"
	"net"
	"reflect"
	"os"
	"bufio"
	)

func (t *CustomValidation) ValidateSflowAgentId(
	vc *CustValidationCtxt) CVLErrorInfo {

	log.Info("ValidateSflowAgentId operation: ", vc.CurCfg.VOp)
	if (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	log.Info("ValidateSflowAgentId YNodeVal: ", vc.YNodeVal)
	/*  allow empty or deleted agent_id */
	if vc.YNodeVal == "" {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	/* check if input passed is found in ConfigDB PORT|* */
	tableKeys, err:= vc.RClient.Keys("PORT|*").Result()

	if (err != nil) || (vc.SessCache == nil) {
		log.Info("ValidateSflowAgentId PORT is empty or invalid argument")
		errStr := "ConfigDB PORT list is empty"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "SFLOW",
			CVLErrDetails : errStr,
			ConstraintErrMsg : errStr,
		}
	}

	for _, dbKey := range tableKeys {
		tmp := strings.Replace(dbKey, "PORT|", "", 1)
		log.Info("ValidateSflowAgentId dbKey ", tmp)
		if (tmp == vc.YNodeVal) {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	/* check if input passed is found in list of network interfaces (includes, network_if, mgmt_if, and loopback) */
	ifaces, err2 := net.Interfaces()
	if err2 != nil {
		log.Info("ValidateSflowAgentId Error getting network interfaces")
		errStr := "Error getting network interfaces"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "SFLOW",
			CVLErrDetails : errStr,
			ConstraintErrMsg : errStr,
		}
	}
	for _, i := range ifaces {
		log.Info("ValidateSflowAgentId i.Name ", i.Name)
		if (i.Name == vc.YNodeVal) {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	errStr := "Invalid interface name"
	return CVLErrorInfo{
		ErrCode: CVL_SEMANTIC_ERROR,
		TableName: "SFLOW",
		CVLErrDetails : errStr,
		ConstraintErrMsg : errStr,
	}
}

func (t *CustomValidation) ValidatePtpUnderlyingInterface(
	vc *CustValidationCtxt) CVLErrorInfo {

	log.Info("ValidatePtpUnderlyingInterface operation: ", vc.CurCfg.VOp)
	if (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	log.Info("ValidatePtpUnderlyingInterface YNodeVal: ", vc.YNodeVal)

	/* check if input passed is found in ConfigDB PORT|* */
	tableKeys, err:= vc.RClient.Keys("PORT|*").Result()

	if (err != nil) || (vc.SessCache == nil) {
		log.Info("ValidatePtpUnderlyingInterface PORT is empty or invalid argument")
		errStr := "ConfigDB PORT list is empty"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "SFLOW",
			CVLErrDetails : errStr,
			ConstraintErrMsg : errStr,
		}
	}

	for _, dbKey := range tableKeys {
		tmp := strings.Replace(dbKey, "PORT|", "", 1)
		log.Info("ValidatePtpUnderlyingInterface dbKey ", tmp)
		if (tmp == vc.YNodeVal) {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	/* check if input passed is found in list of network interfaces (includes, network_if, mgmt_if, and loopback) */
	ifaces, err2 := net.Interfaces()
	if err2 != nil {
		log.Info("ValidatePtpUnderlyingInterface Error getting network interfaces")
		errStr := "Error getting network interfaces"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "SFLOW",
			CVLErrDetails : errStr,
			ConstraintErrMsg : errStr,
		}
	}
	for _, i := range ifaces {
		log.Info("ValidatePtpUnderlyingInterface i.Name ", i.Name)
		if (i.Name == vc.YNodeVal) {
			return CVLErrorInfo{ErrCode: CVL_SUCCESS}
		}
	}

	errStr := "Invalid interface name"
	return CVLErrorInfo{
		ErrCode: CVL_SEMANTIC_ERROR,
		TableName: "SFLOW",
		CVLErrDetails : errStr,
		ConstraintErrMsg : errStr,
	}
}

func (t *CustomValidation) ValidatePtp(
	vc *CustValidationCtxt) CVLErrorInfo {
		
	log.Info("ValidatePtp operation: ", vc.CurCfg.VOp)

	/* validate software build version */
	file, err := os.Open("/etc/sonic/sonic_branding.yml")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "product_name") {
				log.Info("ValidatePtp : ", scanner.Text())
				if !strings.Contains(scanner.Text(), "Enterprise Advanced") &&
					!strings.Contains(scanner.Text(), "Cloud Advanced") {
					errStr := "This object is not supported in this build"
					return CVLErrorInfo{
						ErrCode: CVL_SEMANTIC_ERROR,
						TableName: "PTP_CLOCK",
						CVLErrDetails : errStr,
						ConstraintErrMsg : errStr,
					}
				}
			}
		}
	}

	/* validate platform */
	ls := redis.NewScript(`return redis.call('HGETALL', "DEVICE_METADATA|localhost")`)

	var nokey []string
	redisEntries, err := ls.Run(vc.RClient, nokey).Result()
	if err != nil {
		errStr := "Cannot retrieve platform information"
		return CVLErrorInfo{
			ErrCode: CVL_SEMANTIC_ERROR,
			TableName: "PTP_CLOCK",
			CVLErrDetails : errStr,
			ConstraintErrMsg : errStr,
		}
	}

	s := reflect.ValueOf(redisEntries)
	log.Info("ValidatePtp length(redisEntries) : ", s.Len())
	for i := 0; i < s.Len(); i+=2 {
		log.Info("ValidatePtp index(", i, ") : ", s.Index(i).Interface().(string))
		if  s.Index(i).Interface().(string) == "platform" {
			platform := s.Index(i+1).Interface().(string)
			log.Info("ValidatePtp platform : ", platform)

			if !strings.Contains(platform, "x86_64-accton_as7712_32x") &&
				!strings.Contains(platform, "x86_64-accton_as5712_54x") {
				errStr := "This object is not supported in this platform"
				return CVLErrorInfo{
					ErrCode: CVL_SEMANTIC_ERROR,
					TableName: "PTP_CLOCK",
					CVLErrDetails : errStr,
					ConstraintErrMsg : errStr,
				}
			}
			break
		}
	}

	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

