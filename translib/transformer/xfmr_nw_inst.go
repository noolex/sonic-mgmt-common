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

    if ospfv2Err := ospfv2_config_post_xfmr (&inParams, &retDbDataMap) ; ospfv2Err != nil {err = ospfv2Err}
    if pimErr := pim_hdl_post_xfmr (&inParams, &retDbDataMap) ; pimErr != nil {err = pimErr}

    return retDbDataMap, err
}
