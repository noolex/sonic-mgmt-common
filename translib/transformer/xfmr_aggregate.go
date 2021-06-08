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

package transformer

import (
	log "github.com/golang/glog"
)

func init() {
	XlateFuncBind("YangToDb_portchannel_global_key_xfmr", YangToDb_portchannel_global_key_xfmr)
}

var YangToDb_portchannel_global_key_xfmr = func(inParams XfmrParams) (string, error) {

	log.Info("YangToDb_portchannel_global_key_xfmr: ", inParams.ygRoot, inParams.uri)
	return "GLOBAL", nil
}
