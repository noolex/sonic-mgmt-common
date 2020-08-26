////////////////////////////////////////////////////////////////////////////////
//		                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.		                                         //
//		                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");	   //
//  you may not use this file except in compliance with the License.	  //
//  You may obtain a copy of the License at		                   //
//		                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0		             //
//		                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,	 //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.		                            //
//		                                                            //
////////////////////////////////////////////////////////////////////////////////

package custom_validation

import (
	"github.com/go-redis/redis/v7"
	"strings"
	log "github.com/golang/glog"
	"fmt"
	util "github.com/Azure/sonic-mgmt-common/cvl/internal/util"
	)

type slaMap struct {
	slaTcpMap map[string]string //ip_sla_id->tcp_dst_port map
}


//ValidateTcpPort Validate DstIp Tcp Port mappings
//
func (t *CustomValidation) ValidateTcpPort(vc *CustValidationCtxt) CVLErrorInfo {
	if (vc.CurCfg.VOp == OP_DELETE) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}
	pSlaMap := &slaMap{}
	pSlaMap.slaTcpMap = make(map[string]string)
	vc.SessCache.Data = pSlaMap
	var ipSlaId string

	tcpPort, hasTcpPort := vc.CurCfg.Data["tcp_dst_port"]
	if !hasTcpPort  {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	keyArr := strings.Split(vc.CurCfg.Key, "|")
	if (len(keyArr) > 1) {
		ipSlaId = keyArr[1]
		keyArr = keyArr[1:]
	}

	tableKeys, err:= vc.RClient.Keys("IP_SLA|*").Result()

	if (err != nil) || (vc.SessCache == nil) {
		return CVLErrorInfo{ErrCode: CVL_SUCCESS}
	}

	mCmd := map[string]*redis.SliceCmd{}
	pipe := vc.RClient.Pipeline()
	for _, dbKey := range tableKeys {
		    mCmd[dbKey] = pipe.HMGet(dbKey, "tcp_dst_port")
	}

	_, err = pipe.Exec()
	if err != nil {
		util.TRACE_LEVEL_LOG(util.TRACE_SEMANTIC, "Failed to retreive data from Db")
	}
	pipe.Close()
	for dbKey, val := range mCmd {
		res, err := val.Result()
		if (err != nil) || (len(res) != 1) || (res[0] == nil) || (res[0] == "") {
			continue
		}

	       keySlaComp := strings.Split(dbKey, "|") //IP_SLA|ip_sla_id
	       keySlaDb := keySlaComp[1]
		if (ipSlaId == keySlaDb) {

			tcpPortInDb := res[0]
			if (tcpPortInDb != tcpPort) { // if ip_sla_id matches  and if tcp dst port is different in db
				log.Info("Error: Mismatch with existing db tcp dst port value: ",tcpPortInDb)
				return CVLErrorInfo{
					ErrCode: CVL_SEMANTIC_ERROR,
					TableName: "IP_SLA",
					Keys: keyArr,
					ErrAppTag:  "tcp-port-configured-different",
					ConstraintErrMsg:  fmt.Sprintf("Tcp Destination Port %s already configured", tcpPortInDb),
				}
			}

			break;
		}
	}
	log.Info("ValidateTcpPort: Retruning Success")
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
