////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Dell, Inc.                                                 //
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
       )

func init() {
	XlateFuncBind("YangToDb_swresource_name_fld_xfmr", YangToDb_swresource_name_fld_xfmr)
        XlateFuncBind("DbToYang_swresource_name_xfmr", DbToYang_swresource_name_fld_xfmr)
}

var YangToDb_swresource_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
                 res_map := make(map[string]string)
		 var err error
		 log.Info("YangToDb_swresource_name_fld_xfmr: ", inParams.key)

		 return res_map, err
}


var DbToYang_swresource_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
      var err error
      result := make(map[string]interface{})
      log.Info("DbToYang_swresource_name_fld_xfmr: ", inParams.key)
      result["name"] = inParams.key

      return result, err
}
