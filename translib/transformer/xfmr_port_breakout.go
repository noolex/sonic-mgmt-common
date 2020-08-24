package transformer

import (
    "strconv"
    "github.com/Azure/sonic-mgmt-common/cvl"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "strings"
    "sort"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "encoding/json"
    "fmt"
    "reflect"
)

var ocSpeedMap = map[ocbinds.E_OpenconfigIfEthernet_ETHERNET_SPEED] string {
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_1GB: "1G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_5GB: "5G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_10GB: "10G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_25GB: "25G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_40GB: "40G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_50GB: "50G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_100GB: "100G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_200GB: "200G",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_400GB: "400G",
}

/* Transformer specific functions */

func init () {
    XlateFuncBind("YangToDb_port_breakout_config_xfmr", YangToDb_port_breakout_config_xfmr)
    XlateFuncBind("DbToYang_port_breakout_config_xfmr", DbToYang_port_breakout_config_xfmr)
    XlateFuncBind("DbToYang_port_breakout_state_xfmr", DbToYang_port_breakout_state_xfmr)
    XlateFuncBind("rpc_breakout_dependencies", rpc_breakout_dependencies)
    XlateFuncBind("rpc_breakout_capabilities", rpc_breakout_capabilities)
    parsePlatformDefJsonFile()
    parsePlatformJsonFile()
}


func getDpbRoot (s *ygot.GoStruct) (map[string]*ocbinds.OpenconfigPlatform_Components_Component) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Components.Component

}


var DbToYang_port_breakout_state_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var members []string

    pathInfo := NewPathInfo(inParams.uri)
    platObj := getDpbRoot(inParams.ygRoot)
    if platObj == nil || len(platObj) < 1 {
        log.Info("DbToYang_port_breakout_config_xfmr: Empty component.")
        return tlerr.NotSupported("Dynamic port breakout is not supported")
    }
    ifName := getIfName(pathInfo.Var("name"))
    if len(ifName) <=0 {
        log.Info("YangToDb_port_breakout_config_xfmr : ifName is empty")
        return tlerr.InvalidArgs("Invalid port")
    }
    statusExist := false
    entry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:"PORT_BREAKOUT"}, db.Key{Comp: []string{ifName}})
    if dbErr != nil {
            log.Info("Failed to read DB entry, PORT_BREAKOUT|", ifName)
    } else {
        status := entry.Get("status")
        log.Info("DPB STATUS:", status, " dbs: ", inParams.dbs[db.ConfigDB])
        statusExist = true
        platObj[pathInfo.Var("name")].Port.BreakoutMode.State.Status = &status
    }
    configDb := inParams.dbs[db.ConfigDB]
    if configDb == nil {
        configDb, _ = db.NewDB(getDBOptions(db.ConfigDB))
    }
    brkout_mode := ""
    entry, dbErr = configDb.GetEntry(&db.TableSpec{Name:"BREAKOUT_CFG"}, db.Key{Comp: []string{ifName}})
    if dbErr == nil {
        brkout_mode = entry.Get("brkout_mode")
    }

    ports, err := getPorts(ifName, brkout_mode)
    for _, member := range ports {
        members = append(members, member.name)
    }
    if len(brkout_mode) > 0 {
        sort.SliceStable(members, func(i, j int) bool {
            first,_ := strconv.Atoi(strings.ReplaceAll(members[i], "Ethernet", ""))
            second,_ := strconv.Atoi(strings.ReplaceAll(members[j], "Ethernet", ""))
            return first  < second
        })
        for j, name := range members {
            members[j] = *(utils.GetUINameFromNativeName(&name))
        }
        if !statusExist {
            status := "Completed"
            platObj[pathInfo.Var("name")].Port.BreakoutMode.State.Status = &status
            log.Info("DPB only members for ", ifName)
        }
    } else if statusExist {
        members = append(members, ifName)
        log.Info("DPB mode is default for ", ifName)
    } else {
        log.Info("No port breakout configurations for ", ifName)
        return tlerr.NotFound("No port breakout configurations")
    }

    platObj[pathInfo.Var("name")].Port.BreakoutMode.State.Members = members
    return err;

}

var DbToYang_port_breakout_config_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    pathInfo := NewPathInfo(inParams.uri)

    log.Info("DPB PATH:", pathInfo.Path)
    log.Warningf("DPB  %v", inParams)
    platObj := getDpbRoot(inParams.ygRoot)
    if platObj == nil || len(platObj) < 1 {
        log.Info("DbToYang_port_breakout_config_xfmr: Empty component.")
        return tlerr.NotSupported("Dynamic port breakout is not supported")
    }
    port := pathInfo.Var("name")
    ifName := getIfName(pathInfo.Var("name"))
    if len(ifName) <=0 {
        log.Info("YangToDb_port_breakout_config_xfmr : ifName is empty")
        return tlerr.InvalidArgs("Invalid port")
    }
    entry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:"BREAKOUT_CFG"}, db.Key{Comp: []string{ifName}})
    if dbErr != nil {
            log.Info("Failed to read DB entry, BREAKOUT_CFG|", ifName)
            return tlerr.NotFound("No port breakout configurations")
    }
    splitted_mode := strings.Split(entry.Get("brkout_mode"), "x")
    log.Info(" Splitted breakout mode: ", splitted_mode)
    channels, err := strconv.ParseUint(splitted_mode[0], 10, 8)
    if err != nil {
        return err
    }
    dpb_channels := uint8(channels)
    if _, ok := platObj[pathInfo.Var("name")]; !ok {
        return tlerr.NotSupported("Breakout not supported on %s", port)
    }
    platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.NumChannels = &dpb_channels

    for oc_speed, speed := range ocSpeedMap {
        if speed == splitted_mode[1] {
            platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.ChannelSpeed = oc_speed
        }
    }

    log.Info("OUT param ", *platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.NumChannels,
                "x", ocSpeedMap[platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.ChannelSpeed])


    return err;

}
func updateDpbPorts(ifName string, delPorts []portProp, addPorts[]portProp) map[string]db.Value {

    portsMap := make(map[string]db.Value)
    for _, port := range delPorts {
        fv := make(map[string]string)
        fvpairs := db.Value{Field: fv}
        fvpairs.Set("master", ifName)
        portsMap[port.name] = fvpairs
    }
    for _, port := range addPorts {
        fv := make(map[string]string)
        fvpairs := db.Value{Field: fv}
        fvpairs.Set("master", ifName)
        portsMap[port.name] = fvpairs
    }
    log.Info("BREAKOUT_PORTS = ", portsMap)
    return portsMap
}

/* Breakout action, shutdown, remove dependent configs , remove ports, add ports */
func breakout_action (ifName string, from_mode string, to_mode string, inParams XfmrParams) error {
        var err error
        if to_mode == from_mode {
            log.Info("DPB no config change")
            err = tlerr.InvalidArgs("No change in port breakout mode")
        } else {

            curr_ports, err1 := getPorts(ifName, from_mode)
            err = err1
            if err == nil {
                ports, err2 := getPorts(ifName, to_mode)
                err = err2
                if err == nil {
                    isEqual := reflect.DeepEqual(curr_ports,ports)
                    if isEqual {
                         log.Info("No change in port breakout mode")
                         return nil
                    }
                    //2. Remove ports
                    delMap := removePorts(curr_ports)
                    inParams.subOpDataMap[DELETE] = &delMap
                    log.Info("PORTS TO BE DELETED: ", curr_ports)
                    //3. Add ports
                    addMap := addPorts(ports)
                    inParams.subOpDataMap[CREATE] = &addMap
                    //4. Update the lane set and port map
                    portMap := make(map[db.DBNum]map[string]map[string]db.Value)
                    portMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                    portMap[db.ConfigDB]["BREAKOUT_PORTS"] = updateDpbPorts(ifName, curr_ports, ports)
                    portMap[db.ConfigDB]["BREAKOUT_CFG"] = getLaneSet(ifName)
                    inParams.subOpDataMap[UPDATE] = &portMap
                    log.Info("PORTS TO BE ADDED: ", ports)
                    *inParams.pCascadeDelTbl = append(*inParams.pCascadeDelTbl, "PORT")
                }
            }
        }
        return err
}

var YangToDb_port_breakout_config_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {
    var err error
    dpbMap := make(map[string]map[string]db.Value)
    log.Warningf("DPB  %v", inParams)
    log.Info(" DPB KEY: ", inParams.key);

    if len(inParams.key) > 0 {
        return dpbMap, nil
    }

    platObj := getDpbRoot(inParams.ygRoot)
    if platObj == nil || len(platObj) < 1 {
        log.Info("YangToDb_port_breakout_config_xfmr: Empty component.")
        return dpbMap, tlerr.NotSupported("Dynamic port breakout is not supported")
    }
    pathInfo := NewPathInfo(inParams.uri)
    ifName := getIfName(pathInfo.Var("name"))
    log.Warning("DPB  Path:", pathInfo)
    log.Warning("DPB  ifName : ", ifName)
    log.Warning("DPB  Platform Object : ", platObj[pathInfo.Var("name")])

    if len(ifName) <=0 {
        log.Info("YangToDb_port_breakout_config_xfmr : ifName is empty")
        return dpbMap, tlerr.InvalidArgs("Invalid port")
    }

    tblName := "BREAKOUT_CFG"

    entry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})
    if dbErr != nil {
        log.Info("Failed to read DB entry, " + tblName + " " + ifName)
    } else {
        log.Info("Read DB entry, " + tblName + " " + ifName)
    }

    if inParams.oper == DELETE {
        log.Info("DEL breakout config " + tblName + " " + ifName)
        if !entry.Has("brkout_mode") {
            log.Info("Port breakout config not present, " + tblName + " " + ifName)
        }
        if _, ok := dpbMap[tblName]; !ok {
            dpbMap[tblName] = make (map[string]db.Value)
        }
        m := make(map[string]string)
        data := db.Value{Field: m}
        data.Set("brkout_mode", "")
        dpbMap[tblName][ifName] = data
        dpb_entry, err1 := inParams.d.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})
        //Delete only when current config is non-default
        if err1 == nil {
            log.Info("CURRENT: ", dpb_entry)
            ports, err2 := getPorts(ifName, dpb_entry.Get("brkout_mode"))
            if err2 == nil {
                log.Info("PORTS TO BE DELETED: ", ports)
            }
            err = breakout_action(ifName, dpb_entry.Get("brkout_mode"), "", inParams)
        }   else    {
            log.Info("DPB no config change")
            err = tlerr.InvalidArgs("No change in port breakout mode")
        }

    } else {
        m := make(map[string]string)
        data := db.Value{Field: m}
        log.Info("IN param ", *platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.NumChannels, "x",
                    ocSpeedMap[platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.ChannelSpeed])
        brkout_mode := fmt.Sprint(*platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.NumChannels) +
                    "x" + ocSpeedMap[platObj[pathInfo.Var("name")].Port.BreakoutMode.Config.ChannelSpeed]
        log.Info("inParams.oper: ", inParams.oper)
        log.Info("inParams: ", inParams)
        data.Set("brkout_mode", brkout_mode)
        data.Set("port", pathInfo.Var("name"))
        if _, ok := dpbMap[tblName]; !ok {
            dpbMap[tblName] = make (map[string]db.Value)
        } else {
            dpbMap[tblName] = make (map[string]db.Value)
        }

        dpb_entry, _ := inParams.d.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})
        log.Info("CURRENT: ", dpb_entry)
        err = breakout_action(ifName, dpb_entry.Get("brkout_mode"), brkout_mode, inParams)
        if err == nil {
            dpbMap[tblName][ifName] = data
            log.Info("Breakout success for  ", ifName)
        } else {
            log.Info("Breakout failed for  ", ifName)
        }
    }
    log.Info("DPB map ==>", dpbMap)
    return dpbMap, err
}

var rpc_breakout_capabilities RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {

    log.Info("DPB Capabilities RPC")
    var exec struct {
        Output struct {
            Caps []portCaps `json:"caps,omitempty"`
        } `json:"sonic-port-breakout:output"`
    }
    exec.Output.Caps = getCapabilities()
    result, err := json.Marshal(&exec)
    return result, err

}

var rpc_breakout_dependencies RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var input map[string]interface{}
    var depConfigs []cvl.CVLDepDataForDelete
    err = json.Unmarshal(body, &input)
    if err != nil {
       log.Infof("UnMarshall Error %v\n", err)
       return nil, err
    }

    key := input["sonic-port-breakout:input"].(map[string]interface{})
    log.Info("KEY : ", key)

    var exec struct {
        Output struct {
            DepKeys []string `json:"keys"`
        } `json:"sonic-port-breakout:output"`
    }

    cvSess, _ := cvl.ValidationSessOpen()
    ifName := getIfName(fmt.Sprintf("%v",key["ifname"]))
    if len(ifName) < 1 {
        return nil, tlerr.InvalidArgs("Invalid port")
    }
    entry, dbErr := dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:"BREAKOUT_CFG"}, db.Key{Comp: []string{ifName}})

    if dbErr != nil {
        log.Info("BREAKOUT_CFG|", ifName, " does not exist")
        log.Info("Dependent configs for ", ifName)
        depConfigs = cvSess.GetDepDataForDelete(fmt.Sprintf("PORT|%v", ifName))
    } else {
        portprops,_ := getPorts(ifName, entry.Get("brkout_mode"))
        for i := len(portprops)-1; i >= 0; i-- {
            depConfigs = append(depConfigs, cvSess.GetDepDataForDelete(fmt.Sprintf("PORT|%v", portprops[i].name))...)
            log.Info("Dependent configs for ", portprops[i].name)
        }
    }

    for i, dep := range depConfigs {
            for key, depc := range dep.Entry {
                exec.Output.DepKeys = append(exec.Output.DepKeys , key)
                log.Info("Dep-",i," : ", dep.RefKey, "/", key, "entry: ", depc)
            }
    }

    result, err := json.Marshal(&exec)
    log.Info("RPC Result: ", result)
    cvl.ValidationSessClose(cvSess)
    return result, err

}
