package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "strings"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
)

/* Transformer specific functions */
func init () {
    XlateFuncBind("YangToDb_port_group_config_xfmr", YangToDb_port_group_config_xfmr)
    XlateFuncBind("DbToYang_port_group_config_xfmr", DbToYang_port_group_config_xfmr)
    XlateFuncBind("DbToYang_port_group_state_xfmr", DbToYang_port_group_state_xfmr)
    parsePlatformDefJsonFile()
    parsePlatformJsonFile()
}

func getPgRoot (s *ygot.GoStruct) (*ocbinds.OpenconfigPortGroup_PortGroups) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.PortGroups
}

var DbToYang_port_group_state_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {

    pgObj := getPgRoot(inParams.ygRoot)
    if pgObj == nil {
        log.Info("DbToYang_port_group_config_xfmr: Empty component.")
        return tlerr.NotSupported("Port group is not supported")
    }
    log.Info("Port-group obj ", pgObj)
    err := getPgData(pgObj)
    log.Info("Port-groups ", pgObj.PortGroup)
    return err

}

var DbToYang_port_group_config_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    log.Warningf("PG  %v", inParams)
    return nil;
}
var YangToDb_port_group_config_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {
    var err error
    pgMap := make(map[string]map[string]db.Value)
    log.Info(" PG KEY: ", inParams.key, "OPER: ", inParams.oper);
    // Due to some reasons infra is not giving key for DELETE
    if len(inParams.key) == 0 {
        pathInfo := NewPathInfo(inParams.uri)
        inParams.key = pathInfo.Var("id")
        log.Info("Updated PG KEY: ", inParams.key);
    }
    err = nil

    pgObj := getPgRoot(inParams.ygRoot)
    if pgObj == nil {
        log.Info("DbToYang_port_group_config_xfmr: Empty component.")
        return pgMap, tlerr.NotSupported("Port group is not supported")
    }
    port_speed := strings.ReplaceAll(ocSpeedMap[pgObj.PortGroup[inParams.key].Config.Speed], "G", "000")
    ports, err := getPortGroupMembersAfterSpeedCheck(inParams.key, &port_speed)
    if (err == nil) {
        if (len(ports) > 0) {
            m := make(map[string]string)
            data := db.Value{Field: m}
            data.Set("speed", port_speed)
            pgMap["PORT"] = make (map[string]db.Value)
            for _, ifName := range ports {
                pgMap["PORT"][ifName] = data
            }
        } else {
            log.Info("Could not get the member ports for ", inParams.key)
            err = tlerr.InvalidArgs("Invalid port-group")
        }
    }
    log.Info("Port-group map ==>", pgMap)
    if inParams.oper == DELETE {
        portMap := make(map[db.DBNum]map[string]map[string]db.Value)
        portMap[db.ConfigDB] = pgMap
        inParams.subOpDataMap[UPDATE] = &portMap
        return make(map[string]map[string]db.Value), err
    } else {
        return pgMap, err
    }
}
