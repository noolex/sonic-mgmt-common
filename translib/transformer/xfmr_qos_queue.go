package transformer

import (
    "strings"
    log "github.com/golang/glog"
)
func init () {
    XlateFuncBind("YangToDb_qos_queue_key_xfmr", YangToDb_qos_queue_key_xfmr)
    XlateFuncBind("DbToYang_qos_queue_key_xfmr", DbToYang_qos_queue_key_xfmr)

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


