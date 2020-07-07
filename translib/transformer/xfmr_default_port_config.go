package transformer

import (
    "github.com/Azure/sonic-mgmt-common/cvl"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    log "github.com/golang/glog"
    "encoding/json"
    "fmt"
)

/* Transformer specific functions */
func init () {
    XlateFuncBind("rpc_default_port_config", rpc_default_port_config)
    parsePlatformJsonFile()
}

var rpc_default_port_config RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
       log.Infof("UnMarshall Error %v\n", err)
       return nil, err
    }

    input := mapData["sonic-config-mgmt:input"]
    mapData = input.(map[string]interface{})
    input = mapData["ifname"]
    input_str := fmt.Sprintf("%v", input)
    sonicName := utils.GetNativeNameFromUIName(&input_str)
    input_str = *sonicName

    var exec struct {
        Output struct {
            DepKeys []string `json:"keys"`
        } `json:"sonic-port-breakout:output"`
    }

    cvSess, _ := cvl.ValidationSessOpen()
    depConfigs := cvSess.GetDepDataForDelete(fmt.Sprintf("PORT|%v", input_str))
    for _, dep := range depConfigs {
        for key, depc := range dep.Entry {
            log.Info(dep.RefKey, " / ", key, "  entry: ", depc)
        }
    }

    result, err := json.Marshal(&exec)
    cvl.ValidationSessClose(cvSess)
    return result, err
}
