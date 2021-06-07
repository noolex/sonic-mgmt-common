package transformer

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
)

const (
	SONIC_PREFIX_SET_MODE_IPV4 = "IPv4"
	SONIC_PREFIX_SET_MODE_IPV6 = "IPv6"
	SONIC_MATCH_SET_ACTION_ANY = "ANY"
	SONIC_MATCH_SET_ACTION_ALL = "ALL"
)

var PREFIX_SET_MODE_MAP = map[string]string{
	strconv.FormatInt(int64(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_PrefixSets_PrefixSet_Config_Mode_IPV4), 10): SONIC_PREFIX_SET_MODE_IPV4,
	strconv.FormatInt(int64(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_PrefixSets_PrefixSet_Config_Mode_IPV6), 10): SONIC_PREFIX_SET_MODE_IPV6,
}

var MATCH_SET_ACTION_MAP = map[string]string{
	strconv.FormatInt(int64(ocbinds.OpenconfigRoutingPolicy_MatchSetOptionsType_ALL), 10): SONIC_MATCH_SET_ACTION_ALL,
	strconv.FormatInt(int64(ocbinds.OpenconfigRoutingPolicy_MatchSetOptionsType_ANY), 10): SONIC_MATCH_SET_ACTION_ANY,
}

func init() {
	XlateFuncBind("YangToDb_prefix_set_name_fld_xfmr", YangToDb_prefix_set_name_fld_xfmr)
	XlateFuncBind("DbToYang_prefix_set_name_fld_xfmr", DbToYang_prefix_set_name_fld_xfmr)
	XlateFuncBind("YangToDb_prefix_set_mode_fld_xfmr", YangToDb_prefix_set_mode_fld_xfmr)
	XlateFuncBind("DbToYang_prefix_set_mode_fld_xfmr", DbToYang_prefix_set_mode_fld_xfmr)
	XlateFuncBind("YangToDb_prefix_key_xfmr", YangToDb_prefix_key_xfmr)
	XlateFuncBind("DbToYang_prefix_key_xfmr", DbToYang_prefix_key_xfmr)
	XlateFuncBind("YangToDb_prefix_action_fld_xfmr", YangToDb_defined_sets_action_fld_xfmr)
	XlateFuncBind("DbToYang_prefix_action_fld_xfmr", DbToYang_prefix_action_fld_xfmr)
	XlateFuncBind("YangToDb_community_action_fld_xfmr", YangToDb_defined_sets_action_fld_xfmr)
	XlateFuncBind("DbToYang_community_action_fld_xfmr", DbToYang_community_action_fld_xfmr)
	XlateFuncBind("YangToDb_ext_community_action_fld_xfmr", YangToDb_defined_sets_action_fld_xfmr)
	XlateFuncBind("DbToYang_ext_community_action_fld_xfmr", DbToYang_ext_community_action_fld_xfmr)
	XlateFuncBind("YangToDb_as_path_action_fld_xfmr", YangToDb_defined_sets_action_fld_xfmr)
	XlateFuncBind("DbToYang_as_path_action_fld_xfmr", DbToYang_as_path_action_fld_xfmr)
	XlateFuncBind("YangToDb_prefix_seq_no_fld_xfmr", YangToDb_prefix_seq_no_fld_xfmr)
	XlateFuncBind("DbToYang_prefix_seq_no_fld_xfmr", DbToYang_prefix_seq_no_fld_xfmr)
	XlateFuncBind("YangToDb_prefix_ip_prefix_fld_xfmr", YangToDb_prefix_ip_prefix_fld_xfmr)
	XlateFuncBind("DbToYang_prefix_ip_prefix_fld_xfmr", DbToYang_prefix_ip_prefix_fld_xfmr)
	XlateFuncBind("YangToDb_prefix_masklength_range_fld_xfmr", YangToDb_prefix_masklength_range_fld_xfmr)
	XlateFuncBind("DbToYang_prefix_masklength_range_fld_xfmr", DbToYang_prefix_masklength_range_fld_xfmr)

	XlateFuncBind("YangToDb_community_set_name_fld_xfmr", YangToDb_community_set_name_fld_xfmr)
	XlateFuncBind("DbToYang_community_set_name_fld_xfmr", DbToYang_community_set_name_fld_xfmr)
	XlateFuncBind("YangToDb_community_match_set_options_fld_xfmr", YangToDb_community_match_set_options_fld_xfmr)
	XlateFuncBind("DbToYang_community_match_set_options_fld_xfmr", DbToYang_community_match_set_options_fld_xfmr)
	XlateFuncBind("YangToDb_community_member_fld_xfmr", YangToDb_community_member_fld_xfmr)
	XlateFuncBind("DbToYang_community_member_fld_xfmr", DbToYang_community_member_fld_xfmr)

	XlateFuncBind("YangToDb_ext_community_set_name_fld_xfmr", YangToDb_ext_community_set_name_fld_xfmr)
	XlateFuncBind("DbToYang_ext_community_set_name_fld_xfmr", DbToYang_ext_community_set_name_fld_xfmr)
	XlateFuncBind("YangToDb_ext_community_match_set_options_fld_xfmr", YangToDb_ext_community_match_set_options_fld_xfmr)
	XlateFuncBind("DbToYang_ext_community_match_set_options_fld_xfmr", DbToYang_ext_community_match_set_options_fld_xfmr)
	XlateFuncBind("YangToDb_ext_community_member_fld_xfmr", YangToDb_ext_community_member_fld_xfmr)
	XlateFuncBind("DbToYang_ext_community_member_fld_xfmr", DbToYang_ext_community_member_fld_xfmr)

	XlateFuncBind("YangToDb_as_path_set_name_fld_xfmr", YangToDb_as_path_set_name_fld_xfmr)
	XlateFuncBind("DbToYang_as_path_set_name_fld_xfmr", DbToYang_as_path_set_name_fld_xfmr)
}

var YangToDb_defined_sets_action_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

	res_map := make(map[string]string)
	var err error
	if inParams.param == nil {
		return res_map, err
	}
	if inParams.oper == DELETE {
		res_map["action"] = ""
		return res_map, nil
	}

	action, _ := inParams.param.(ocbinds.E_OpenconfigRoutingPolicyExt_RoutingPolicyExtActionType)
	log.Info("YangToDb_defined_sets_action_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " route-operation: ", action)
	if action == ocbinds.OpenconfigRoutingPolicyExt_RoutingPolicyExtActionType_PERMIT {
		res_map["action"] = "permit"
	} else if action == ocbinds.OpenconfigRoutingPolicyExt_RoutingPolicyExtActionType_DENY {
		res_map["action"] = "deny"
	}
	return res_map, err
}

var DbToYang_prefix_action_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_prefix_action_fld_xfmr", data, "inParams : ", inParams)

	pTbl := data["PREFIX"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_prefix_action_fld_xfmr table not found : ", inParams.key)
		return result, errors.New("Prefix table not found : " + inParams.key)
	}
	niInst := pTbl[inParams.key]
	route_operation, ok := niInst.Field["action"]
	if ok {
		if route_operation == "permit" {
			result["action"] = "PERMIT"
		} else {
			result["action"] = "DENY"
		}
	} else {
		log.Info("DbToYang_prefix_action_fld_xfmr field not found in DB")
	}
	return result, err
}

var DbToYang_community_action_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_community_action_fld_xfmr", data, "inParams : ", inParams)

	pTbl := data["COMMUNITY_SET"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_community_action_fld_xfmr table not found : ", inParams.key)
		return result, errors.New("Community table not found : " + inParams.key)
	}
	niInst := pTbl[inParams.key]
	route_operation, ok := niInst.Field["action"]
	if ok {
		if route_operation == "permit" {
			result["action"] = "PERMIT"
		} else {
			result["action"] = "DENY"
		}
	} else {
		log.Info("DbToYang_community_action_fld_xfmr field not found in DB")
	}
	return result, err
}

var DbToYang_ext_community_action_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ext_community_action_fld_xfmr", data, "inParams : ", inParams)

	pTbl := data["EXTENDED_COMMUNITY_SET"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_ext_community_action_fld_xfmr table not found : ", inParams.key)
		return result, errors.New("Extended community table not found : " + inParams.key)
	}
	niInst := pTbl[inParams.key]
	route_operation, ok := niInst.Field["action"]
	if ok {
		if route_operation == "permit" {
			result["action"] = "PERMIT"
		} else {
			result["action"] = "DENY"
		}
	} else {
		log.Info("DbToYang_ext_community_action_fld_xfmr field not found in DB")
	}
	return result, err
}

var DbToYang_as_path_action_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_as_path_action_fld_xfmr", data, "inParams : ", inParams)

	pTbl := data["AS_PATH_SET"]
	if _, ok := pTbl[inParams.key]; !ok {
		log.Info("DbToYang_as_path_action_fld_xfmr table not found : ", inParams.key)
		return result, errors.New("AS-PATH table not found : " + inParams.key)
	}
	niInst := pTbl[inParams.key]
	route_operation, ok := niInst.Field["action"]
	if ok {
		if route_operation == "permit" {
			result["action"] = "PERMIT"
		} else {
			result["action"] = "DENY"
		}
	} else {
		log.Info("DbToYang_as_path_action_fld_xfmr field not found in DB")
	}
	return result, err
}

var YangToDb_prefix_set_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	log.Info("YangToDb_prefix_cfg_set_name_fld_xfmr: ", inParams.key)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_prefix_set_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	var err error
	log.Info("DbToYang_prefix_set_name_fld_xfmr: ", inParams.key)
	key := inParams.key
	log.Info("DbToYang_prefix_set_name_fld_xfmr: ", key)
	setTblKey := strings.Split(key, "|")
	setName := setTblKey[0]

	res_map["name"] = setName
	log.Info("prefix-set/config/name  ", res_map)
	return res_map, err
}

func prefix_all_keys_get(d *db.DB, dbSpec *db.TableSpec) ([]db.Key, error) {

	var keys []db.Key

	prefixTable, err := d.GetTable(dbSpec)
	if err != nil {
		return keys, err
	}

	keys, err = prefixTable.GetKeys()
	log.Info("prefix_all_keys_get: Found %d PREFIX table keys", len(keys))
	return keys, err
}

func prefixes_exits_by_set_name(d *db.DB, setName string, tblName string) bool {
	keys, _ := prefix_all_keys_get(d, &db.TableSpec{Name: tblName})
	for _, key := range keys {
		if len(key.Comp) < 3 {
			continue
		}
		if key.Get(0) == setName {
			log.Info("prefixes_exits_by_set_name: Found PREFIX table key set ", key.Get(0), "prefix ", key.Get(1), "mask ", key.Get(2))
			return true
		}
	}
	return false
}

func prefix_set_mode_get_by_set_name(d *db.DB, setName string, tblName string) (string, error) {
	var err error

	dbspec := &db.TableSpec{Name: tblName}

	log.Info("prefix_set_mode_get_by_set_name  ", db.Key{Comp: []string{setName}})
	dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{setName}})
	if err != nil {
		log.Info("No Entry found e = ", err)
		return "", err
	}
	mode, ok := dbEntry.Field["mode"]
	if ok {
		log.Info("Previous Mode ", mode)
	} else {
		log.Info("New Table, No previous mode ", mode)
	}
	return mode, nil
}

var YangToDb_prefix_set_mode_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	if inParams.param == nil {
		res_map["mode"] = ""
		return res_map, err
	}
	if inParams.oper == DELETE {
		res_map["mode"] = ""
		return res_map, nil
	}

	pathInfo := NewPathInfo(inParams.uri)
	/* Key should contain, <name> */
	setName := pathInfo.Var("name")
	if len(setName) == 0 {
		err = errors.New("set name is missing")
		log.Info("Set Name is Missing")
		return res_map, err
	}
	is_prefixes_exits := prefixes_exits_by_set_name(inParams.d, setName, "PREFIX")
	log.Info("YangToDb_prefix_set_mode_fld_xfmr: setName ", setName, "is_prefixes_exits ", is_prefixes_exits)

	mode, _ := inParams.param.(ocbinds.E_OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_PrefixSets_PrefixSet_Config_Mode)
	log.Info("YangToDb_prefix_set_mode_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " Mode: ", mode)
	new_mode := findInMap(PREFIX_SET_MODE_MAP, strconv.FormatInt(int64(mode), 10))

	prev_mode, _ := prefix_set_mode_get_by_set_name(inParams.d, setName, "PREFIX_SET")

	log.Info("YangToDb_prefix_set_mode_fld_xfmr: prev_mode ", prev_mode, "new mode ", res_map["mode"], "is_prefixes_exits ", is_prefixes_exits)
	if is_prefixes_exits && (prev_mode != new_mode) {
		err = errors.New("Prefixes Configured already, Mode Change not supported")
		log.Error("Prefixes Configured already, Mode Change not supported")
		return res_map, err
	}
	res_map["mode"] = new_mode
	return res_map, err
}

var DbToYang_prefix_set_mode_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_prefix_set_mode_fld_xfmr: Input", data, inParams.ygRoot)
	mode, ok := data["PREFIX_SET"][inParams.key].Field["mode"]
	if ok {
		oc_mode := findInMap(PREFIX_SET_MODE_MAP, mode)
		n, err := strconv.ParseInt(oc_mode, 10, 64)
		result["mode"] = ocbinds.E_OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_PrefixSets_PrefixSet_Config_Mode(n).ΛMap()["E_OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_PrefixSets_PrefixSet_Config_Mode"][n].Name
		log.Info("DbToYang_prefix_set_mode_fld_xfmr ", result)
		return result, err
	}
	return result, err
}

var YangToDb_prefix_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var err error
	var setName string
	var seqNo string
	var ipPrefix string
	var masklenrange string
	var prefixTblKey string

	log.Info("YangToDb_prefix_key_xfmr: ", inParams.ygRoot, inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	if (inParams.oper == DELETE) && (len(pathInfo.Vars) == 1) {
		setName = pathInfo.Var("name")
		if len(setName) == 0 {
			err = errors.New("YangToDb_prefix_key_xfmr: Prefix set name is missing")
			log.Error("YangToDb_prefix_key_xfmr: Prefix set name is Missing")
			return setName, err
		}
		// TODO - This Case will not come for CLI, Riht now return dummy key to avoid DB flush
		//   return prefix_del_by_set_name (inParams.d, setName, "PREFIX")
		return "NULL", nil
	} else {
		if len(pathInfo.Vars) < 4 {
			err = errors.New("Invalid xpath, key attributes not found")
			log.Info("YangToDb_prefix_key_xfmr: Prefix keys are Missing, numKeys ", len(pathInfo.Vars))
			return prefixTblKey, err
		}
		setName = pathInfo.Var("name")
		seqNo = pathInfo.Var("sequence-number")
		ipPrefix = pathInfo.Var("ip-prefix")
		masklenrange = pathInfo.Var("masklength-range")

		if len(setName) == 0 {
			err = errors.New("YangToDb_prefix_key_xfmr: Prefix set name is missing")
			log.Info("YangToDb_prefix_key_xfmr: Prefix set name is Missing")
			return setName, err
		}

		if len(seqNo) == 0 {
			err = errors.New("sequence-number is missing")
			log.Info("YangToDb_prefix_key_xfmr: sequence-number is Missing")
			return ipPrefix, err
		}

		if len(ipPrefix) == 0 {
			err = errors.New("YangToDb_prefix_key_xfmr: ipPrefix is missing")
			log.Info("YangToDb_prefix_key_xfmr: ipPrefix is Missing")
			return ipPrefix, err
		}

		if len(masklenrange) == 0 {
			err = errors.New("YangToDb_prefix_key_xfmr: masklenrange is missing")
			log.Info("YangToDb_prefix_key_xfmr: masklength-range is Missing")
			return masklenrange, err
		}

		log.Info("YangToDb_prefix_key_xfmr: PrefixSetName: ", setName, " Sequence-number: ", seqNo,
			" IP-Prefix: ", ipPrefix, " MaskLenRange: ", masklenrange)

		if masklenrange != "exact" {
			prefix_mask := strings.Split(ipPrefix, "/")
			length, _ := strconv.Atoi(prefix_mask[1])

			m_range := strings.Split(masklenrange, "..")
			ge, _ := strconv.Atoi(m_range[0])
			le, _ := strconv.Atoi(m_range[1])

			log.Infof("YangToDb_prefix_key_xfmr: mask length %d ge %d le %d", length, ge, le)

			if (length > ge) || (ge > le) {
				err = errors.New("Invalid range, valid range is len < ge-value <= le-value")
				log.Error("YangToDb_prefix_key_xfmr: Invalid maskrange, make len < ge-value <= ge-value")
				return ipPrefix, err
			}
		}
		prefixTblKey = setName + "|" + seqNo + "|" + ipPrefix + "|" + masklenrange
	}
	log.Info("YangToDb_prefix_key_xfmr: prefixTblKey: ", prefixTblKey)

	return prefixTblKey, nil
}

var DbToYang_prefix_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	key := inParams.key

	log.Info("DbToYang_prefix_key_xfmr: ", key)

	prefixTblKey := strings.Split(key, "|")
	seqNo := prefixTblKey[1]
	ipPrefix := prefixTblKey[2]
	masklenrange := prefixTblKey[3]

	if _seqno_u64, err := strconv.ParseUint(seqNo, 10, 32); err == nil {
		rmap["sequence-number"] = uint32(_seqno_u64)
	}
	rmap["ip-prefix"] = ipPrefix
	rmap["masklength-range"] = masklenrange

	log.Info("DbToYang_prefix_key_xfmr: sequence-number: ", seqNo, " ipPrefix ", ipPrefix, "masklength-range ", masklenrange)

	return rmap, nil
}

var YangToDb_prefix_seq_no_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	log.Info("YangToDb_prefix_seq_no_fld_xfmr: ", inParams.key)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_prefix_seq_no_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	var err error
	log.Info("DbToYang_prefix_seq_no_fld_xfmr: ", inParams.key)
	key := inParams.key
	prefixKey := strings.Split(key, "|")
	seqNo := prefixKey[1]

	if _seqno_u64, err := strconv.ParseUint(seqNo, 10, 32); err == nil {
		res_map["sequence-number"] = uint32(_seqno_u64)
	}
	log.Info("prefix-set/prefix/config/sequence-number ", res_map)
	return res_map, err
}

var YangToDb_prefix_ip_prefix_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	log.Info("YangToDb_prefix_ip_prefix_fld_xfmr: ", inParams.key)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_prefix_ip_prefix_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	var err error
	log.Info("DbToYang_prefix_ip_prefix_fld_xfmr: ", inParams.key)
	key := inParams.key
	prefixKey := strings.Split(key, "|")
	ip_prefix := prefixKey[2]

	res_map["ip-prefix"] = ip_prefix
	log.Info("prefix-set/prefix/config/ip-prefix ", res_map)
	return res_map, err
}

var YangToDb_prefix_masklength_range_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	log.Info("YangToDb_prefix_masklength_range_fld_xfmr: ", inParams.key)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_prefix_masklength_range_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	var err error
	log.Info("DbToYang_prefix_masklength_range_fld_xfmr: ", inParams.key)
	key := inParams.key
	prefixKey := strings.Split(key, "|")
	mask := prefixKey[3]

	res_map["masklength-range"] = mask
	log.Info("prefix-set/prefix/config/masklength-range ", res_map)
	return res_map, err
}

var YangToDb_community_set_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	log.Info("YangToDb_community_set_name_fld_xfmr: ", inParams.key)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_community_set_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	var err error
	log.Info("DbToYang_community_set_name_fld_xfmr: ", inParams.key)
	key := inParams.key
	log.Info("DbToYang_community_set_name_fld_xfmr: ", key)
	setTblKey := strings.Split(key, "|")
	setName := setTblKey[0]

	res_map["community-set-name"] = setName
	log.Info("config/name  ", res_map)
	return res_map, err
}

func community_set_match_options_get_by_set_name(d *db.DB, setName string, tblName string) (string, error) {
	var err error

	dbspec := &db.TableSpec{Name: tblName}

	log.Info("community_set_match_options_get_by_set_name: key  ", db.Key{Comp: []string{setName}})
	dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{setName}})
	if err != nil {
		log.Info("No Entry found e = ", err)
		return "", err
	}
	match_action, ok := dbEntry.Field["match_action"]
	if ok {
		log.Info("Previous Match options ", match_action)
	} else {
		log.Info("New Table, No previous match option ", match_action)
	}
	return match_action, nil
}

var YangToDb_community_match_set_options_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	if inParams.param == nil {
		res_map["match_action"] = ""
		return res_map, err
	}
	if inParams.oper == DELETE {
		res_map["match_action"] = ""
		return res_map, nil
	}

	log.Info("YangToDb_community_match_set_options_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri)

	pathInfo := NewPathInfo(inParams.uri)
	if len(pathInfo.Vars) < 1 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return res_map, err
	}

	setName := pathInfo.Var("community-set-name")
	log.Info("YangToDb_community_match_set_options_fld_xfmr: setName ", setName)
	if len(setName) == 0 {
		err = errors.New("set name is missing")
		log.Info("Set Name is Missing")
		return res_map, err
	}

	prev_match_action, _ := community_set_match_options_get_by_set_name(inParams.d, setName, "COMMUNITY_SET")

	match_opt, _ := inParams.param.(ocbinds.E_OpenconfigRoutingPolicy_MatchSetOptionsType)
	new_match_action := findInMap(MATCH_SET_ACTION_MAP, strconv.FormatInt(int64(match_opt), 10))
	log.Info("YangToDb_community_match_set_options_fld_xfmr: New match Opt: ", new_match_action)
	if len(prev_match_action) > 0 {
		if prev_match_action != new_match_action {
			log.Error("YangToDb_community_match_set_options_fld_xfmr: Match option difference, Error previous", prev_match_action, " new ", new_match_action)
			err = errors.New("Match option difference")
			return nil, err
		} else {
			prev_match_action = new_match_action
		}
	}

	res_map["match_action"] = new_match_action

	return res_map, err
}

var DbToYang_community_match_set_options_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	log.Info("DbToYang_community_match_set_options_fld_xfmr", inParams.ygRoot)
	data := (*inParams.dbDataMap)[inParams.curDb]
	opt, ok := data["COMMUNITY_SET"][inParams.key].Field["match_action"]
	if ok {
		match_opt := findInMap(MATCH_SET_ACTION_MAP, opt)
		n, err := strconv.ParseInt(match_opt, 10, 64)
		result["match-set-options"] = ocbinds.E_OpenconfigRoutingPolicy_MatchSetOptionsType(n).ΛMap()["E_OpenconfigRoutingPolicy_MatchSetOptionsType"][n].Name
		log.Info("DbToYang_community_match_set_options_fld_xfmr ", result["match-set-options"])
		return result, err
	}
	return result, err
}

func community_set_type_get_by_set_name(d *db.DB, setName string, tblName string) (string, error) {
	var err error

	dbspec := &db.TableSpec{Name: tblName}

	log.Info("community_set_type_get_by_set_name: key  ", db.Key{Comp: []string{setName}})
	dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{setName}})
	if err != nil {
		log.Info("No Entry found e = ", err)
		return "", err
	}
	prev_type, ok := dbEntry.Field["set_type"]
	if ok {
		log.Info("Previous type ", prev_type)
	} else {
		log.Info("New Table, No previous type ", prev_type)
	}
	return prev_type, nil
}

func community_set_is_community_members_exits(d *db.DB, setName string, tblName string, fieldName string) (bool, error) {
	var err error
	var community_list string

	dbspec := &db.TableSpec{Name: tblName}

	log.Info("community_set_is_community_members_exits: key  ", db.Key{Comp: []string{setName}})
	dbEntry, err := d.GetEntry(dbspec, db.Key{Comp: []string{setName}})
	if err != nil {
		log.Info("No Entry found e = ", err)
		return false, err
	}

	community_list, ok := dbEntry.Field[fieldName]
	if ok {
		if len(community_list) > 0 {
			log.Info("community_set_is_community_members_exits: Comminuty members eixts")
			return true, nil
		}
	} else {
		log.Info("community_set_is_community_members_exits: No Comminuty members eixts ")
	}

	return false, nil
}

var YangToDb_community_member_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var community_list string
	var new_type string
	var prev_type string

	log.Info("YangToDb_community_member_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, "inParams : ", inParams)
	if inParams.param == nil {
		res_map["community_member@"] = ""
		return res_map, errors.New("Invalid Inputs")
	}

	pathInfo := NewPathInfo(inParams.uri)
	if len(pathInfo.Vars) < 1 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return res_map, err
	}

	setName := pathInfo.Var("community-set-name")
	log.Info("YangToDb_community_member_fld_xfmr: setName ", setName)
	if len(setName) == 0 {
		err = errors.New("set name is missing")
		log.Info("Set Name is Missing")
		return res_map, err
	}
	is_member_exits, _ := community_set_is_community_members_exits(inParams.d, setName, "COMMUNITY_SET", "community_member@")
	if is_member_exits {
		prev_type, _ = community_set_type_get_by_set_name(inParams.d, setName, "COMMUNITY_SET")

		log.Info("YangToDb_community_member_fld_xfmr: prev_type ", prev_type)
	}
	members := inParams.param.([]ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySets_CommunitySet_Config_CommunityMember_Union)

	for _, member := range members {

		memberType := reflect.TypeOf(member).Elem()
		log.Info("YangToDb_community_member_fld_xfmr: member - ", member, " memberType: ", memberType)
		var b bytes.Buffer
		switch memberType {

		case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySets_CommunitySet_Config_CommunityMember_Union_E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY{}):
			v := (member).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySets_CommunitySet_Config_CommunityMember_Union_E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY)
			switch v.E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY {
			case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NOPEER:
				community_list += "no-peer" + ","
			case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_ADVERTISE:
				community_list += "no-advertise" + ","
			case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT:
				community_list += "no-export" + ","
			case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT_SUBCONFED:
				community_list += "local-AS" + ","
			}
			new_type = "STANDARD"
		case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySets_CommunitySet_Config_CommunityMember_Union_Uint32{}):
			v := (member).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySets_CommunitySet_Config_CommunityMember_Union_Uint32)
			fmt.Fprintf(&b, "%d", v.Uint32)
			community_list += b.String() + ","
			new_type = "STANDARD"
		case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySets_CommunitySet_Config_CommunityMember_Union_String{}):
			v := (member).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_DefinedSets_BgpDefinedSets_CommunitySets_CommunitySet_Config_CommunityMember_Union_String)

			has_regex := strings.HasPrefix(v.String, "REGEX:")
			if has_regex {
				new_type = "EXPANDED"
			} else {
				new_type = "STANDARD"
			}
			community_list += strings.TrimPrefix(v.String, "REGEX:") + ","
		}

		log.Info("YangToDb_community_member_fld_xfmr: new_type: ", new_type, " prev_type ", prev_type)
		if (len(prev_type) > 0) && (prev_type != new_type) {
			log.Error("YangToDb_community_member_fld_xfmr: Type Difference Error, previous", prev_type, " newType: ", new_type)
			if inParams.oper == DELETE {
				return res_map, tlerr.InvalidArgs("Can't find community-list")
			}
			err = errors.New("Type difference, Quit Operation")
			return res_map, err
		} else {
			prev_type = new_type
		}
	}

	res_map["community_member@"] = strings.TrimSuffix(community_list, ",")

	if (inParams.oper != DELETE) && (prev_type != "") {
		res_map["set_type"] = prev_type
	}

	log.Info("YangToDb_community_member_fld_xfmr: ", res_map["community_member@"], " type ", res_map["set_type"])
	return res_map, err
}

var DbToYang_community_member_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var result_community string
	data := (*inParams.dbDataMap)[inParams.curDb]

	log.Info("DbToYang_community_member_fld_xfmr", data, inParams.ygRoot, inParams.key)

	set_type := data["COMMUNITY_SET"][inParams.key].Field["set_type"]

	log.Info("DbToYang_community_member_fld_xfmr: type ", set_type)
	var Communities []interface{}

	community_list, ok := data["COMMUNITY_SET"][inParams.key].Field["community_member@"]
	if ok {
		log.Info("DbToYang_community_member_fld_xfmr: DB Memebers ", community_list)
		for _, community := range strings.Split(community_list, ",") {
			if set_type == "EXPANDED" {
				result_community = "REGEX:"
			} else {
				result_community = ""
			}

			if community == "local-AS" {
				result_community += "NO_EXPORT_SUBCONFED"
			} else if community == "no-advertise" {
				result_community += "NO_ADVERTISE"
			} else if community == "no-export" {
				result_community += "NO_EXPORT"
			} else if community == "no-peer" {
				result_community += "NOPEER"
			} else {
				result_community += community
			}
			log.Info("DbToYang_community_member_fld_xfmr: result_community ", result_community)
			Communities = append(Communities, result_community)
		}
	}
	result["community-member"] = Communities
	log.Info("DbToYang_community_member_fld_xfmr: Comminuty Memebers ", result["community-member"])
	return result, err
}

var YangToDb_ext_community_set_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	log.Info("YangToDb_ext_community_set_name_fld_xfmr: ", inParams.key)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_ext_community_set_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	var err error
	log.Info("DbToYang_ext_community_set_name_fld_xfmr: ", inParams.key)
	key := inParams.key
	log.Info("DbToYang_ext_community_set_name_fld_xfmr: ", key)
	setTblKey := strings.Split(key, "|")
	setName := setTblKey[0]

	res_map["ext-community-set-name"] = setName
	log.Info("config/name  ", res_map)
	return res_map, err
}

var YangToDb_ext_community_match_set_options_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	if inParams.param == nil {
		res_map["match_action"] = ""
		return res_map, err
	}
	if inParams.oper == DELETE {
		res_map["match_action"] = ""
		return res_map, nil
	}

	log.Info("YangToDb_ext_community_match_set_options_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri)

	pathInfo := NewPathInfo(inParams.uri)
	if len(pathInfo.Vars) < 1 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return res_map, err
	}

	setName := pathInfo.Var("ext-community-set-name")
	log.Info("YangToDb_ext_community_match_set_options_fld_xfmr: setName ", setName)
	if len(setName) == 0 {
		err = errors.New("set name is missing")
		log.Info("Set Name is Missing")
		return res_map, err
	}

	prev_match_action, _ := community_set_match_options_get_by_set_name(inParams.d, setName, "EXTENDED_COMMUNITY_SET")

	match_opt, _ := inParams.param.(ocbinds.E_OpenconfigRoutingPolicy_MatchSetOptionsType)
	new_match_action := findInMap(MATCH_SET_ACTION_MAP, strconv.FormatInt(int64(match_opt), 10))
	log.Info("YangToDb_ext_community_match_set_options_fld_xfmr: New match Opt: ", new_match_action)
	if len(prev_match_action) > 0 {
		if prev_match_action != new_match_action {
			log.Error("YangToDb_ext_community_match_set_options_fld_xfmr: Match option difference, Error previous", prev_match_action, " new ", new_match_action)
			err = errors.New("Match option difference")
			return nil, err
		} else {
			prev_match_action = new_match_action
		}
	}

	res_map["match_action"] = new_match_action

	return res_map, err
}

var DbToYang_ext_community_match_set_options_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	log.Info("DbToYang_ext_community_match_set_options_fld_xfmr", inParams.ygRoot)
	data := (*inParams.dbDataMap)[inParams.curDb]
	opt, ok := data["EXTENDED_COMMUNITY_SET"][inParams.key].Field["match_action"]
	if ok {
		match_opt := findInMap(MATCH_SET_ACTION_MAP, opt)
		n, err := strconv.ParseInt(match_opt, 10, 64)
		result["match-set-options"] = ocbinds.E_OpenconfigRoutingPolicy_MatchSetOptionsType(n).ΛMap()["E_OpenconfigRoutingPolicy_MatchSetOptionsType"][n].Name
		log.Info("DbToYang_ext_community_match_set_options_fld_xfmr ", result["match-set-options"])
		return result, err
	}
	return result, err
}

var YangToDb_ext_community_member_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var community_list string
	var new_type string
	var prev_type string

	log.Info("YangToDb_ext_community_member_fld_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, "inParams : ", inParams)
	if inParams.param == nil {
		res_map["community_member@"] = ""
		return res_map, errors.New("Invalid Inputs")
	}

	pathInfo := NewPathInfo(inParams.uri)
	if len(pathInfo.Vars) < 1 {
		err = errors.New("Invalid Key length")
		log.Info("Invalid Key length", len(pathInfo.Vars))
		return res_map, err
	}

	setName := pathInfo.Var("ext-community-set-name")
	log.Info("YangToDb_ext_community_member_fld_xfmr: setName ", setName)
	if len(setName) == 0 {
		err = errors.New("set name is missing")
		log.Info("Set Name is Missing")
		return res_map, err
	}
	is_member_exits, _ := community_set_is_community_members_exits(inParams.d, setName, "EXTENDED_COMMUNITY_SET", "community_member@")
	if is_member_exits {
		prev_type, _ = community_set_type_get_by_set_name(inParams.d, setName, "EXTENDED_COMMUNITY_SET")

		log.Info("YangToDb_ext_community_member_fld_xfmr: prev_type ", prev_type)
	}

	members := inParams.param.([]string)

	log.Info("YangToDb_ext_community_member_fld_xfmr: members", members)
	for _, member := range members {

		has_regex := strings.HasPrefix(member, "REGEX:")
		if has_regex {
			new_type = "EXPANDED"
		} else {
			new_type = "STANDARD"
		}
		member = strings.TrimPrefix(member, "REGEX:")

		has_rt := strings.HasPrefix(member, "route-target")
		has_ro := strings.HasPrefix(member, "route-origin")
		if (new_type == "STANDARD") && !has_rt && !has_ro {
			err = errors.New("Community member is not of type route-target or route-origin")
			log.Error("Community member is not of type route-target or route-origin")
			return res_map, err
		}
		community_list += member + ","
		log.Info("YangToDb_ext_community_member_fld_xfmr: new_type: ", new_type, " prev_type ", prev_type)
		if (len(prev_type) > 0) && (prev_type != new_type) {
			log.Error("YangToDb_ext_community_member_fld_xfmr: Type Difference Error, previous", prev_type, " newType: ", new_type)
			if inParams.oper == DELETE {
				return res_map, tlerr.InvalidArgs("Can't find extcommunity-list")
			}
			err = errors.New("Type difference, Quit Operation")
			return res_map, err
		} else {
			prev_type = new_type
		}
	}
	res_map["community_member@"] = strings.TrimSuffix(community_list, ",")

	if (inParams.oper != DELETE) && (prev_type != "") {
		res_map["set_type"] = prev_type
	}

	log.Info("YangToDb_ext_community_member_fld_xfmr: ", res_map["community_member@"], " type ", res_map["set_type"])
	return res_map, err
}

var DbToYang_ext_community_member_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var result_community string
	data := (*inParams.dbDataMap)[inParams.curDb]

	log.Info("DbToYang_ext_community_member_fld_xfmr", data, inParams.ygRoot, inParams.key)

	set_type := data["EXTENDED_COMMUNITY_SET"][inParams.key].Field["set_type"]

	log.Info("DbToYang_ext_community_member_fld_xfmr: type ", set_type)
	var Communities []interface{}

	community_list, ok := data["EXTENDED_COMMUNITY_SET"][inParams.key].Field["community_member@"]
	if ok {
		log.Info("DbToYang_ext_community_member_fld_xfmr: DB Memebers ", community_list)
		for _, community := range strings.Split(community_list, ",") {
			if set_type == "EXPANDED" {
				result_community = "REGEX:"
			} else {
				result_community = ""
			}
			result_community += community
			log.Info("DbToYang_ext_community_member_fld_xfmr: result_community ", result_community)
			Communities = append(Communities, result_community)
		}
	}
	result["ext-community-member"] = Communities
	log.Info("DbToYang_ext_community_member_fld_xfmr: Comminuty Memebers ", result["community-member"])
	return result, err
}

var YangToDb_as_path_set_name_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)

	log.Info("YangToDb_as_path_set_name_fld_xfmr: ", inParams.key)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_as_path_set_name_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	var err error
	key := inParams.key
	log.Info("DbToYang_as_path_set_name_fld_xfmr: ", key)
	setTblKey := strings.Split(key, "|")
	setName := setTblKey[0]

	res_map["as-path-set-name"] = setName
	log.Info("config/name  ", res_map)
	return res_map, err
}
