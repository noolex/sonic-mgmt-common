package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/db"
)

func init() {
    XlateFuncBind("network_instance_post_xfmr", network_instance_post_xfmr)
}

var network_instance_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    retDbDataMap := (*inParams.dbDataMap)[inParams.curDb]

    err = ospfv2_config_post_xfmr(&inParams, &retDbDataMap)

    return retDbDataMap, err
}
