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

//Path : /sonic-sflow/SFLOW/SFLOW_LIST/agent_id
//Purpose: Check correct for correct agent_id
//vc : Custom Validation Context
//Returns -  CVL Error object
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

//Path : /sonic-ptp/PTP_PORT/PTP_PORT_LIST/underlying-interface
//Purpose: Check correct for correct agent_id
//vc : Custom Validation Context
//Returns -  CVL Error object
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

//Path : /sonic-ptp/PTP_CLOCK
//Purpose: Check correct platform
//Returns -  CVL Error object
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
		if "platform" == s.Index(i).Interface().(string) {
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

func getNexthopAttrList(vc *CustValidationCtxt) (string, []string, error) {
    keys := strings.Split(vc.CurCfg.Key, "|")
    if len(keys) < 2 || keys[0] != "STATIC_ROUTE" {
        return "", nil, fmt.Errorf("Invalid key format: %s", vc.CurCfg.Key)
    }
    prefix := keys[len(keys) - 1]
    if len(vc.YNodeVal) == 0 {
        return prefix, []string{}, nil
    }
    if vc.SessCache.Data == nil {
        vc.SessCache.Data = make(map[string]int)
    }
    nhNumMap, ok := vc.SessCache.Data.(map[string]int)
    if !ok {
        return "", nil, fmt.Errorf("Invalid data type in session cache")
    }
    vals := strings.Split(vc.YNodeVal, ",")
    num, ok := nhNumMap[prefix]
    if !ok {
        attrs, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
	    if err != nil && err != redis.Nil {
            return "", nil, fmt.Errorf("Failed to read NH attribute from DB, key: %s", vc.CurCfg.Key)
        }
	    if err == redis.Nil || len(attrs) == 0 {
            nhNumMap[prefix] = len(vals)
        } else {
            for _, fldVal := range attrs {
                nhNumMap[prefix] = len(strings.Split(fldVal, ","))
                break
            }
        }
        num = nhNumMap[prefix]
    }
    if num != len(vals) {
        return "", nil, fmt.Errorf("Given attr number %d is not aligned to existing NH number %d",
                                   len(vals), num)
    }

    return prefix, vals, nil
}

func checkTableKeyExists(db *redis.Client, tableList []string, key string) bool {
    for _, table := range tableList {
        fullKey := fmt.Sprintf("%s|%s", table, key)
        attrs, err := db.HGetAll(fullKey).Result()
        if err == nil && attrs != nil && len(attrs) > 0 {
            return true
        }
    }
    return false
}

//Path : /sonic-static-route/STATIC_ROUTE/nexthop
// Purpose: To check if every item in comma separated list is valid IP address
// Returns -  CVL Error object
func (t *CustomValidation) ValidateNexthopGateway(
	vc *CustValidationCtxt) CVLErrorInfo {
    prefix, gwIpList, err := getNexthopAttrList(vc)
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: err.Error()}
    }
    if len(gwIpList) == 0 {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }
    pfxIpStr := strings.Split(prefix, "/")[0]
    pfxIp := net.ParseIP(pfxIpStr)
    if pfxIp == nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: "Invalid static route IP prefix"}
    }
    pfxIpv4 := pfxIp.To4() != nil
    for _, gwIP := range gwIpList {
        ip := net.ParseIP(gwIP)
        if ip == nil {
            errMsg := fmt.Sprintf("Invalid gateway IP format %s", gwIP)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
        gwIpv4 := ip.To4() != nil
        if gwIpv4 != pfxIpv4 {
            errMsg := fmt.Sprintf("Address family of NH gateway %s not same as prefix %s", gwIP, pfxIpStr)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//Path : /sonic-static-route/STATIC_ROUTE/ifname
// Purpose: To check if every item in comma separated list is an active interface name
// Returns -  CVL Error object
func (t *CustomValidation) ValidateNexthopInterface(
	vc *CustValidationCtxt) CVLErrorInfo {
    _, intfList, err := getNexthopAttrList(vc)
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: err.Error()}
    }
    var tableList = []string{"PORT", "PORTCHANNEL", "VLAN", "LOOPBACK_INTERFACE"}
    for _, ifName := range intfList {
        if len(ifName) == 0 {
            continue
        }
        if found := checkTableKeyExists(vc.RClient, tableList, ifName); !found {
            errMsg := fmt.Sprintf("Interface %s not found in config DB", ifName)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
    }
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//Path : /sonic-static-route/STATIC_ROUTE/nexthop-vrf
// Purpose: To check if every item in comma separated list is an active VRF name
// Returns -  CVL Error object
func (t *CustomValidation) ValidateNexthopVrf(
	vc *CustValidationCtxt) CVLErrorInfo {
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    _, vrfList, err := getNexthopAttrList(vc)
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: err.Error()}
    }
    var tableList = []string{"VRF"}
    for _, vrfName := range vrfList {
        if len(vrfName) == 0 {
            continue
        }
        if found := checkTableKeyExists(vc.RClient, tableList, vrfName); !found {
            errMsg := fmt.Sprintf("VRF %s not found in config DB", vrfName)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
    }
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
