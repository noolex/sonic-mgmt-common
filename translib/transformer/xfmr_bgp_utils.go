package transformer

import (
	"strconv"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	log "github.com/golang/glog"
)

func hdl_validate_values_post_xfmr(inParams *XfmrParams) error {

	var retVal error
	retVal = validate_neighbor_post_xfmr(inParams)
	if retVal != nil {
		return retVal
	}
	retVal = validate_peer_group_post_xfmr(inParams)
	if retVal != nil {
		return retVal
	}
	return nil
}

func validate_neighbor_post_xfmr(inParams *XfmrParams) error {
	var retVal error
	retVal = validate_prefix_limit_post_xfmr(inParams, "BGP_NEIGHBOR_AF")
	if retVal != nil {
		return retVal
	}

	retVal = validate_multihop_ttlSecurity_value_post_xfmr(inParams, "BGP_NEIGHBOR", "ebgp_multihop_ttl", "ttl_security_hops")
	if retVal != nil {
		return retVal
	}

	return nil
}

func validate_peer_group_post_xfmr(inParams *XfmrParams) error {

	var retVal error
	retVal = validate_prefix_limit_post_xfmr(inParams, "BGP_PEER_GROUP_AF")
	if retVal != nil {
		return retVal
	}

	retVal = validate_multihop_ttlSecurity_value_post_xfmr(inParams, "BGP_PEER_GROUP", "ebgp_multihop_ttl", "ttl_security_hops")
	if retVal != nil {
		return retVal
	}
	return nil
}

func validate_multihop_ttlSecurity_value_post_xfmr(inParams *XfmrParams, tableName string, fieldName1 string, fieldName2 string) error {
	var field1 int64
	var field2 int64

	if dataMapDB, ok := (*inParams.dbDataMap)[db.ConfigDB][tableName]; ok {
		for key := range dataMapDB {
			fieldVal1, ok1 := dataMapDB[key].Field[fieldName1]
			fieldVal2, ok2 := dataMapDB[key].Field[fieldName2]
			if (ok1) && (ok2) {
				field1, _ = strconv.ParseInt(fieldVal1, 10, 16)
				field2, _ = strconv.ParseInt(fieldVal2, 10, 16)
				if (field1 > 0) && (field2 > 0) {
					errStr := fieldName1 + " and " + fieldName2 + " cannot co-exist"
					log.Error(errStr)
					return tlerr.InvalidArgsError{Format: errStr}
				}
			} else {
				tblSpec := &db.TableSpec{Name: tableName}
				dbEntry, dbErr := inParams.d.GetEntry(tblSpec, db.Key{Comp: []string{key}})
				if dbErr == nil {
					if (!ok1) && (ok2) {
						_, ok := dbEntry.Field[fieldName1]
						if ok {
							errStr := fieldName2 + " is not supported with " + fieldName1
							log.Error(errStr)
							return tlerr.InvalidArgsError{Format: errStr}
						}
					} else if (ok1) && (!ok2) {
						_, ok := dbEntry.Field[fieldName2]
						if ok {
							errStr := fieldName1 + " is not supported with " + fieldName2
							log.Error(errStr)
							return tlerr.InvalidArgsError{Format: errStr}
						}
					}
				}
			}
		}
	}
	return nil
}

func validate_prefix_limit_post_xfmr(inParams *XfmrParams, tableName string) error {

	if dataMapDB, ok := (*inParams.dbDataMap)[db.ConfigDB][tableName]; ok {
		for key := range dataMapDB {
			warn_str, warnOk := dataMapDB[key].Field["max_prefix_warning_only"]
			_, restartOk := dataMapDB[key].Field["max_prefix_restart_interval"]
			if (warnOk) && (restartOk) {
				if warn_str == "true" {
					errStr := "prevent-teardown and restart-timer are mutually exclusive"
					log.Error(errStr)
					return tlerr.InvalidArgsError{Format: errStr}
				}
			} else if (!warnOk) && (restartOk) {
				tblSpec := &db.TableSpec{Name: tableName}
				dbEntry, dbErr := inParams.d.GetEntry(tblSpec, db.Key{Comp: []string{key}})
				if dbErr == nil {
					warningOnly, ok := dbEntry.Field["max_prefix_warning_only"]
					if ok && warningOnly == "true" {
						//warning_only exists. Return error
						errStr := "restart-timer is not supported with prevent-teardown"
						log.Error(errStr)
						return tlerr.InvalidArgsError{Format: errStr}
					}
				}
			} else if (warnOk) && (!restartOk) {
				tblSpec := &db.TableSpec{Name: tableName}
				dbEntry, dbErr := inParams.d.GetEntry(tblSpec, db.Key{Comp: []string{key}})
				if dbErr == nil {
					_, ok := dbEntry.Field["max_prefix_restart_interval"]
					if ok {
						//restart interval exists. Return error
						errStr := "prevent-teardown is not supported with restart-timer"
						log.Error(errStr)
						return tlerr.InvalidArgsError{Format: errStr}
					}
				}
			}
		}
	}
	return nil
}
