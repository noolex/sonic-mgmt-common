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

const (
	YANG_MODULE    = "module"
	YANG_LIST      = "list"
	YANG_CONTAINER = "container"
	YANG_LEAF      = "leaf"
	YANG_LEAF_LIST = "leaf-list"
	YANG_CHOICE    = "choice"
	YANG_CASE      = "case"

	YANG_ANNOT_DB_NAME       = "db-name"
	YANG_ANNOT_TABLE_NAME    = "table-name"
	YANG_ANNOT_FIELD_NAME    = "field-name"
	YANG_ANNOT_KEY_DELIM     = "key-delimiter"
	YANG_ANNOT_TABLE_XFMR    = "table-transformer"
	YANG_ANNOT_FIELD_XFMR    = "field-transformer"
	YANG_ANNOT_KEY_XFMR      = "key-transformer"
	YANG_ANNOT_POST_XFMR     = "post-transformer"
	YANG_ANNOT_SUBTREE_XFMR  = "subtree-transformer"
	YANG_ANNOT_VALIDATE_FUNC = "get-validate"

	REDIS_DB_TYPE_APPLN       = "APPL_DB"
	REDIS_DB_TYPE_ASIC        = "ASIC_DB"
	REDIS_DB_TYPE_CONFIG      = "CONFIG_DB"
	REDIS_DB_TYPE_COUNTER     = "COUNTERS_DB"
	REDIS_DB_TYPE_LOG_LVL     = "LOGLEVEL_DB"
	REDIS_DB_TYPE_STATE       = "STATE_DB"
	REDIS_DB_TYPE_FLX_COUNTER = "FLEX_COUNTER_DB"

	XPATH_SEP_FWD_SLASH         = "/"
	XFMR_EMPTY_STRING           = ""
	XFMR_NONE_STRING            = "NONE"
	SONIC_TABLE_INDEX           = 2
	SONIC_LIST_INDEX            = 3
	SONIC_FIELD_INDEX           = 4
	SONIC_MDL_PFX               = "sonic"
	OC_MDL_PFX                  = "openconfig-"
	IETF_MDL_PFX                = "ietf-"
	IANA_MDL_PFX                = "iana-"
	YTDB_KEY_XFMR_RET_ARGS      = 2
	YTDB_KEY_XFMR_RET_VAL_INDX  = 0
	YTDB_KEY_XFMR_RET_ERR_INDX  = 1
	YTDB_SBT_XFMR_RET_ARGS      = 2
	YTDB_SBT_XFMR_RET_VAL_INDX  = 0
	YTDB_SBT_XFMR_RET_ERR_INDX  = 1
	YTDB_FLD_XFMR_RET_ARGS      = 2
	YTDB_FLD_XFMR_RET_VAL_INDX  = 0
	YTDB_FLD_XFMR_RET_ERR_INDX  = 1
	DBTY_KEY_XFMR_RET_ARGS      = 2
	DBTY_KEY_XFMR_RET_VAL_INDX  = 0
	DBTY_KEY_XFMR_RET_ERR_INDX  = 1
	DBTY_FLD_XFMR_RET_ARGS      = 2
	DBTY_FLD_XFMR_RET_VAL_INDX  = 0
	DBTY_FLD_XFMR_RET_ERR_INDX  = 1
	SUBSC_SBT_XFMR_RET_ARGS     = 2
	SUBSC_SBT_XFMR_RET_VAL_INDX = 0
	SUBSC_SBT_XFMR_RET_ERR_INDX = 1
	DBTY_SBT_XFMR_RET_ERR_INDX  = 0
	TBL_XFMR_RET_ARGS           = 2
	TBL_XFMR_RET_VAL_INDX       = 0
	TBL_XFMR_RET_ERR_INDX       = 1
	POST_XFMR_RET_ARGS          = 2
	POST_XFMR_RET_VAL_INDX      = 0
	POST_XFMR_RET_ERR_INDX      = 1
	PRE_XFMR_RET_ARGS           = 1
	PRE_XFMR_RET_ERR_INDX       = 0
	PATH_XFMR_RET_ARGS          = 1
	PATH_XFMR_RET_ERR_INDX      = 0

	XFMR_INVALID        = -1
	XFMR_DISABLE        = 0
	XFMR_ENABLE         = 1
	XFMR_DEFAULT_ENABLE = 2
)
