package transformer

import (
    "strings"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/db"
)
func init () {
    XlateFuncBind("YangToDb_qos_queue_key_xfmr", YangToDb_qos_queue_key_xfmr)
    XlateFuncBind("DbToYang_qos_queue_key_xfmr", DbToYang_qos_queue_key_xfmr)
    XlateFuncBind("YangToDb_qos_queue_wred_profile_fld_xfmr", YangToDb_qos_queue_wred_profile_fld_xfmr)
    XlateFuncBind("DbToYang_qos_queue_wred_profile_fld_xfmr", DbToYang_qos_queue_wred_profile_fld_xfmr)

}

var YangToDb_qos_queue_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var entry_key string
    log.Info("YangToDb_qos_queue_key_xfmr: ", inParams.ygRoot, inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    qname := pathInfo.Var("name")

    log.Info("YangToDb: qname: ", qname)

    qKey := strings.Replace(strings.Replace(qname, " ", "_", -1), "-", "_", -1)
    entry_key = strings.Replace(qKey, ":", "|", -1)

    log.Info("YangToDb_qos_queue_key_xfmr - entry_key : ", entry_key)

    return entry_key, nil
}

var DbToYang_qos_queue_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_qos_queue_key_xfmr: ", entry_key)

    rmap["name"] = strings.Replace(entry_key, "|", ":", 1)
    return rmap, nil
}

var YangToDb_qos_queue_wred_profile_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error
    log.Info("YangToDb_qos_queue_wred_profile_fld_xfmr - inParams ", inParams)


    pathInfo := NewPathInfo(inParams.uri)

    q_name := pathInfo.Var("name")

    qosObj := getQosRoot(inParams.ygRoot)
    if qosObj == nil {
        return res_map, err
    }

	queueObj, ok := qosObj.Queues.Queue[q_name]
	if !ok {
		return res_map, err
	}

	wred_name := *(queueObj.Wred.Config.WredProfile)

	if wred_name == "" {
        log.Error("wred name is Missing")
        return res_map, err
	}

    log.Info("YangToDb_qos_queue_wred_profile_fld_xfmr - WRED ", wred_name)

    res_map["wred_profile"] = StringToDbLeafref(wred_name, "WRED_PROFILE")
    return res_map, err
}

var DbToYang_qos_queue_wred_profile_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("Entering DbToYang_qos_queue_wred_profile_fld_xfmr ", inParams)
    res_map := make(map[string]interface{})

    pathInfo := NewPathInfo(inParams.uri)

    q_name := pathInfo.Var("name")
	log.Info("q_name: ", q_name)

    dbSpec := &db.TableSpec{Name: "QUEUE"}

	s := strings.Split(q_name, ":")
    key := db.Key{Comp: []string{s[0], s[1]}}
    qCfg, _ := inParams.d.GetEntry(dbSpec, key)

    log.Info("current entry: ", qCfg)
    value, ok := qCfg.Field["wred_profile"]

    if ok {
        log.Info("wred profile = ", value)
        res_map["wred-profile"] = DbLeafrefToString(value,  "WRED_PROFILE")
    }
    return res_map, nil

}


