package transformer

import (
    "strconv"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "strings"
    "sort"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    log "github.com/golang/glog"
    "io/ioutil"
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
)

const (
    PLATFORM_JSON = "/usr/share/sonic/hwsku/platform.json"
    PLATFORM_DEF_JSON = "/usr/share/sonic/hwsku/platform-def.json"
)


type portProp struct {
    name string
    index string
    lanes string
    alias string
    valid_speeds string
    speed string
}

type portCaps struct {
    Port string     `json:"port,omitempty"`
    Name string     `json:"name,omitempty"`
    Modes string    `json:"modes,omitempty"`
    DefMode string `json:"defmode,omitempty"`
}

var platConfigStr map[string]map[string]string
var platDefStr map[string]map[string]map[string]string

/* Functions */

func init () {
    parsePlatformJsonFile();
}


func decodePortParams(port_i string, mode string, subport int, entry map[string]string) (portProp, error) {
    var port_config portProp
    var dpb_index string
    var dpb_lanes string

    // Check if mode is supported.
    supported_modes := strings.Split(entry["breakout_modes"], ",")
    for _, mode_iter := range supported_modes {
        if strings.Contains(mode_iter, mode[2:])  && (strings.Compare(mode_iter[0:1], mode[0:1])==0) {
            log.Info("[DEBUG] Matched mode: ", mode_iter)
            pos := strings.Index(mode_iter, "G")
            if pos != -1 {
                speed,_ := strconv.Atoi(mode_iter[2:pos])
                port_config.valid_speeds = strconv.Itoa(speed*1000)
            } else {
                log.Error("MODES: ", mode_iter)
            }
            pos = strings.Index(mode_iter, "[")
            epos := strings.Index(mode_iter, "]")
            if pos != -1 && epos != -1 {
                speed,_ := strconv.Atoi(mode_iter[pos+1:epos-1])
                port_config.valid_speeds = port_config.valid_speeds + ", " + strconv.Itoa(speed*1000)
            }
        }
    }

    if len(port_config.valid_speeds) < 1 {
        log.Error("Invalid or unsupported breakout mode")
        return port_config, tlerr.InvalidArgs("Invalid or unsupported breakout mode %s", mode)
    }

    lane_speed_map := map[string][]int{"1x100G":{4, 100000}, "1x40G":{4, 40000},"1x400G":{8, 400000},
                        "2x50G":{2, 50000}, "4x25G":{1, 25000}, "4x10G":{1, 10000}, "2x200G":{4, 200000},
                        "2x100G":{4, 100000}, "4x100G":{2, 100000}, "4x50G":{2, 50000}}
    indeces := strings.Split(entry["index"], ",")
    lanes := strings.Split(entry["lanes"], ",")
    lane_speed, ok := lane_speed_map[mode]
    if !ok {
        log.Error("Invalid or unsupported breakout mode", mode)
        return port_config, tlerr.InvalidArgs("Invalid or unsupported breakout mode %s", mode)
    }
    start_lane := subport*lane_speed[0]
    end_lane := start_lane + lane_speed[0]
    if len(lanes) < end_lane {
        log.Error("Invalid or unsupported breakout mode - lane count mismatch", len(lanes), " < ", end_lane)
        return port_config, tlerr.InvalidArgs("Invalid or unsupported breakout mode")
    }

    dpb_index = indeces[subport]
    dpb_lanes = lanes[start_lane]
    for i := start_lane + 1; i < end_lane; i++ {
        dpb_lanes = dpb_lanes + "," + lanes[i]
    }
    base_port,_ := strconv.Atoi(strings.TrimLeft(port_i, "Ethern"))
    port_config.name = "Ethernet"+strconv.Itoa(base_port+(lane_speed[0]*subport))
    port_config.alias = strings.TrimSpace(strings.Split(entry["alias_at_lanes"], ",")[subport])
    port_config.index = dpb_index
    port_config.lanes = dpb_lanes
    port_config.speed = strconv.Itoa(lane_speed_map[mode][1])
    if strings.HasPrefix(mode, "1x") {
        pos := strings.LastIndex(port_config.alias, "/")
        if pos != -1 {
           port_config.alias =  port_config.alias[0:pos]
        }
    }
    log.Info("port_config: ", port_config)
    return port_config, nil
}

func getPorts (port_i string, mode string) ([]portProp, error) {
    var err error
    var ports []portProp

    // This error will get updated in success case.
    err = tlerr.InvalidArgs("Invalid or unsupported breakout mode %s", mode)
    if entry, ok := platConfigStr[port_i]; ok {
        // Default mode. DELETE/"no breakout" case
        if len(mode) == 0 {
            mode =  entry["default_brkout_mode"]
            if len(mode) == 0 {
                err = tlerr.InvalidArgs("Invalid default breakout mode")
                return ports, err
            }
            if strings.Contains(mode, "[") {
                mode =  mode[0:strings.Index(mode, "[")]
            }
            log.Info("Default to ", mode)
        }
        count,_ := strconv.Atoi(string(mode[0]))
        ports = make([]portProp, count)
        for i := 0; i < count; i++ {
            ports[i], err = decodePortParams(port_i, mode, i, entry )
        }
    } else {
            log.Info("Invalid interface/master port - ", mode)
            err = tlerr.NotSupported("Breakout not supported on %s", port_i)
    }

    return ports, err
}

func getCapabilities () ([]portCaps) {
    var caps []portCaps
    offset := 0
    for _, entry := range  platConfigStr {
        indeces := strings.Split(entry["index"], ",")
        if indeces[0] == "0" {
            offset = 1;
            log.Info("Zero based SFP index")
        }
    }
    for name, entry := range  platConfigStr {
        if len(strings.Split(entry["breakout_modes"], ",")) >1 {
            indeces := strings.Split(entry["index"], ",")
            index,_ := strconv.Atoi(indeces[0])
            port := "1/" + strconv.Itoa(index + offset)
            modes := strings.ReplaceAll(strings.Trim(entry["breakout_modes"]," "), ",", ", ")
            name = *(utils.GetUINameFromNativeName(&name))
            if strings.Count(name,"/") > strings.Count(port, "/") {
                name = name[0:strings.LastIndex(name, "/")]
            }
            caps = append(caps, portCaps {
                        Name: name,
                        Modes: modes,
                        DefMode: entry["default_brkout_mode"],
                        Port: port,
                    })
        }
    }
    sort.SliceStable(caps, func(i, j int) bool {
            first,_ := strconv.Atoi(strings.ReplaceAll(caps[i].Port, "/", ""))
            second,_ := strconv.Atoi(strings.ReplaceAll(caps[j].Port, "/", ""))
            return first  < second
        })
    return caps
}

func getValidSpeeds(port_i string) ([]string, error) {
    var valid_speeds []string
    if len(platConfigStr) < 1 {
        parsePlatformJsonFile()
    }
    if entry, ok := platConfigStr[port_i]; ok {
        // Get the valid speed from default breakout mode.
        mode :=  entry["default_brkout_mode"]
        log.Info("[DEBUG] Default mode: ", mode)
        pos := strings.Index(mode, "G")
        if pos != -1 {
            speed,_ := strconv.Atoi(mode[2:pos])
            valid_speeds = append(valid_speeds, strconv.Itoa(speed*1000))
        } else {
            log.Error("Invalid mode: ", mode)
        }
        pos = strings.Index(mode, "[")
        epos := strings.Index(mode, "]")
        if pos != -1 && epos != -1 {
            speed,_ := strconv.Atoi(mode[pos+1:epos-1])
            valid_speeds = append(valid_speeds, strconv.Itoa(speed*1000))
        }
    }
    if len(valid_speeds) < 1 {
        log.Error("Could not get valid speeds from default breakout mode")
        return valid_speeds, tlerr.InvalidArgs("Unable to determine valid speeds")
    }
    return valid_speeds, nil
}

// getDefaultBreakoutModeSpeed - Returns default speed of a port or error 
func getDefaultBreakoutModeSpeed(port_i string) (string, error) {
    var err error
    var mode string
    var default_speed string

    mode, err = getDefaultBreakoutMode(port_i)
    if err == nil {
        pos := strings.Index(mode, "G")
        if pos != -1 {
            speed, err := strconv.Atoi(mode[2:pos])
            if err == nil {
                default_speed = strconv.Itoa(speed*1000)
            }
        } else {
            err = tlerr.InvalidArgs("Unable to determine default port speed")
        }
    }
    return default_speed, err
}

// getDefaultBreakoutMode - Returns default breakout mode of a port
func getDefaultBreakoutMode(port_i string) (string, error) {
    var def_breakout_mode string
    var err error
    if len(platConfigStr) < 1 {
        if parsePlatformJsonFile() != nil {
            err = tlerr.InvalidArgs("Dynamic breakout mode is not supported for this platform")
            return def_breakout_mode, err
        }
    }
    err = nil
    if entry, ok := platConfigStr[port_i]; ok {
        // Get the valid speed from default breakout mode.
        if mode, ok := entry["default_brkout_mode"]; ok {
            def_breakout_mode = strings.Split(mode, "[")[0]
        } else {
            err = tlerr.InvalidArgs("Default breakout mode not found in the platform JSON file")
        }
    } else {
        err = tlerr.InvalidArgs("Port information not found in the platform JSON file")
    }
    return def_breakout_mode, err
}

func parsePlatformJsonFile () (error) {

    file, err := ioutil.ReadFile(PLATFORM_JSON)

    if nil != err {
        log.Error("Dynamic port breakout not supported");
        return err
    }

    platConfigStr = make(map[string]map[string]string)
    err = json.Unmarshal([]byte(file), &platConfigStr)
    return err
}

func parsePlatformDefJsonFile () (error) {

    file, err := ioutil.ReadFile(PLATFORM_DEF_JSON)

    if nil != err {
        log.Info("Platform specific properties not supported");
        return err
    }

    platDefStr = make(map[string]map[string]map[string]string)
    err = json.Unmarshal([]byte(file), &platDefStr)
    log.Info(platDefStr)
    return err
}

func getPgData (pgObj *ocbinds.OpenconfigPortGroup_PortGroups) (error) {

    var speedMap = map[string] ocbinds.E_OpenconfigIfEthernet_ETHERNET_SPEED {
        "1000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_1GB,
        "10000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_10GB,
        "25000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_25GB,
        "40000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_40GB,
        "50000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_50GB,
        "100000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_100GB,
        "200000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_200GB,
        "400000": ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_400GB,
    }

    if len(platDefStr) < 1 {
        log.Info("Platform does not support port-group");
        return tlerr.NotSupported("Platform does not support port-group")
    }

    if pgs, ok := platDefStr["port-group"]; ok {
        for id, pg := range pgs {
            var entry ocbinds.OpenconfigPortGroup_PortGroups_PortGroup_State
            var pgInstance *ocbinds.OpenconfigPortGroup_PortGroups_PortGroup
            entry.Id = &id
            ifRange := strings.Split(pg["members"],"-")
            entry.MemberIfStart = utils.GetUINameFromNativeName(&ifRange[0])
            ifRange[1] = "Ethernet" + ifRange[1]
            entry.MemberIfEnd = utils.GetUINameFromNativeName(&ifRange[1])
            vspeeds := strings.Split(strings.TrimSpace(pg["valid_speeds"]),",")
            var val_speeds []ocbinds.E_OpenconfigIfEthernet_ETHERNET_SPEED
            for _, spd := range vspeeds{
                val_speeds = append(val_speeds, speedMap[spd])
            }
            entry.Speed = val_speeds[0]
            entry.ValidSpeeds = val_speeds
            if _, ok := pgObj.PortGroup[id]; ok {
                pgInstance = pgObj.PortGroup[id]
                pgInstance.State = &entry
                log.Info("Entry ", id, " ", entry)
            }
        }
    }

    log.Info("PG Data: ", pgObj.PortGroup)
    return nil
}

func isPortGroupMember(ifName string) (bool) {
    if len(platDefStr) < 1 {
        parsePlatformDefJsonFile()
        if len(platDefStr) < 1 {
            return false
        }
    }
    if pgs, ok := platDefStr["port-group"]; ok {
        for id, pg := range pgs {
            memRange := strings.Split(strings.TrimLeft(pg["members"], "Ethern"), "-")
            ifNum,_ := strconv.Atoi(strings.TrimLeft(ifName, "Ethern"))
            startNum,_ := strconv.Atoi(memRange[0])
            endNum,_ := strconv.Atoi(memRange[1])
            log.Info("PG ", id, pg["members"], " ", pg["valid_speeds"], " ==> ",
                        startNum, " - ", ifNum, " - ", endNum)
            if (ifNum >= startNum) && (ifNum <= endNum) {
                return true
            }
        }
    }
    return false
}

func getPortGroupMembersAfterSpeedCheck(pgid string, speed *string) ([]string, error) {
   var  members []string

    if len(platDefStr) < 1 {
        parsePlatformDefJsonFile()
        if len(platDefStr) < 1 {
            return members, tlerr.NotSupported("Port-group is not supported")
        }
    }
    if pgs, ok := platDefStr["port-group"]; ok {
        for id, pg := range pgs {
            if id == pgid {
                vspeeds := strings.Split(strings.Trim(strings.TrimSpace(pg["valid_speeds"]), "[]"),",")
                isSpeedValid := false
                for _, spd := range vspeeds {
                    if *speed == spd {
                        isSpeedValid = true
                        break
                    } else if *speed == "" {
                        *speed = vspeeds[0]
                        isSpeedValid = true
                        log.Info("Setting default speed to ", *speed)
                        break
                    }
                }
                if !isSpeedValid {
                    log.Info("speed ", *speed, " is not supported for PG#", pgid)
                    return members, tlerr.NotSupported("Speed not supported")
                }
                memRange := strings.Split(strings.TrimLeft(pg["members"], "Ethern"), "-")
                startNum,_ := strconv.Atoi(memRange[0])
                endNum,_ := strconv.Atoi(memRange[1])
                log.Info("PG ", id, pg["members"], " ", pg["valid_speeds"], " ==> ",
                            startNum, " - ", endNum)
                for i := startNum; i <= endNum; i++ {
                    members = append(members, "Ethernet"+strconv.Itoa(i))
                }
            }
        }
    } else {
        return members, tlerr.NotSupported("Port-group is not supported")
    }
    return members, nil
}


func removePorts (ports_i []portProp) (map[db.DBNum]map[string]map[string]db.Value) {
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    delMap := make(map[string]map[string]db.Value)
    entryMap := make(map[string]db.Value)

    // Delete in reverse order, so that master port gets deleted last.
    for i := len(ports_i)-1; i >= 0; i-- {
        // Field value map is null to indicate entire entry delete.
        entryMap[ports_i[i].name] = db.Value{}
    }
    delMap["PORT"] = entryMap
    log.Info("DPB: DELETE Map", delMap)
    subOpMap[db.ConfigDB] = delMap
    return subOpMap;
}

func getLaneSet(ifName string) (map[string]db.Value) {
    var brkoutMap map[string]db.Value
    entry, ok := platConfigStr[ifName]
    if ok {
        brkoutMap = make(map[string]db.Value)
        fv := make(map[string]string)
        fvpairs := db.Value{Field: fv}
        fvpairs.Set("lanes", entry["lanes"])
        brkoutMap[ifName] = fvpairs
    }
    log.Info("DPB: UPDATE Lanes Map", brkoutMap)
    return brkoutMap;
}

func addPorts ( ports []portProp) (map[db.DBNum]map[string]map[string]db.Value) {
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    addMap := make(map[string]map[string]db.Value)
    entryMap := make(map[string]db.Value)

    for i := 0; i < len(ports); i++ {
        m := make(map[string]string)
        value := db.Value{Field: m}
        value.Set("admin_status", "down")
        value.Set("mtu", "9100")
        value.Set("index",ports[i].index)
        value.Set("lanes", ports[i].lanes)
        value.Set("alias", ports[i].alias)
        value.Set("speed", ports[i].speed)
        value.Set("valid_speeds", ports[i].valid_speeds)
        entryMap[ports[i].name] = value
    }

    addMap["PORT"] = entryMap
    log.Info("DPB: CREATE Map", addMap)
    subOpMap[db.ConfigDB] = addMap
    return subOpMap;
}

func getIfName(port_i string) (string) {
    offset := 0
    var ifName string
    for _, entry := range  platConfigStr {
        indeces := strings.Split(entry["index"], ",")
        if indeces[0] == "0" {
            offset = 1;
            log.Info("Zero based SFP index")
        }
    }
    for key, entry := range  platConfigStr {
        if len(strings.Split(entry["breakout_modes"], ",")) >1 {
            indeces := strings.Split(entry["index"], ",")
            index,_ := strconv.Atoi(indeces[0])
            port := "1/" + strconv.Itoa(index + offset)
            if (port == port_i) {
                ifName = key
                log.Info(port, " ", key)
            }
        }
    }
    return ifName
}
