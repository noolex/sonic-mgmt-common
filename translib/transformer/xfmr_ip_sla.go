////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
    log "github.com/golang/glog"
        "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "strconv"
)

func init() {
    XlateFuncBind("YangToDb_ip_sla_id_fld_xfmr", YangToDb_ip_sla_id_fld_xfmr)
    XlateFuncBind("DbToYang_ip_sla_id_fld_xfmr", DbToYang_ip_sla_id_fld_xfmr)
    XlateFuncBind("DbToYang_ip_sla_state_xfmr", DbToYang_ip_sla_state_xfmr)
}

var YangToDb_ip_sla_id_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_ip_sla_id_fld_xfmr: ", inParams.key)

    return res_map, err
}

var DbToYang_ip_sla_id_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    log.Info("DbToYang_ip_sla_id_fld_xfmr: ", inParams.key)
    result["ip-sla-id"], _ = strconv.ParseUint(inParams.key, 10, 32)

    return result, err
}

var DbToYang_ip_sla_state_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("DbToYang_ip_sla_state_xfmr - targetUriPath: ", targetUriPath)
    
    var ipSlaObj *ocbinds.OpenconfigIpSla_IpSlas_IpSla
    
    log.Info("DbToYang_ip_sla_state_xfmr 1- ipSlaTblTs: ", ipSlaObj)
    // FRR fetch code

    return err
}


