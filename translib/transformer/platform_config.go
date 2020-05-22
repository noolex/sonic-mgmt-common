package transformer

import (
    "strconv"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "strings"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "io/ioutil"
    "encoding/json"
)

const (
    PLATFORM_JSON = "/usr/share/sonic/hwsku/platform.json"
)


type portProp struct {
    name string
    index string
    lanes string
    alias string
    valid_speeds string
    speed string
    oid string
}

var platConfigStr map[string]map[string]string

/* Functions */

func init () {
    parsePlatformJsonFile();
}


func getPlatRoot (s *ygot.GoStruct) *ocbinds.OpenconfigPlatform_Components {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Components
}


func decodePortParams(port_i string, mode string, subport int, entry map[string]string) (portProp, error) {
    var port_config portProp
    var dpb_index string
    var dpb_lanes string

    // Check if mode is supported.
    supported_modes := strings.Split(entry["breakout_modes"], ",")
    for _, mode_iter := range supported_modes {
        if strings.Contains(mode_iter, mode[2:len(mode)]) {
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
    dpb_index = indeces[subport]
    dpb_lanes = lanes[start_lane]
    for i := start_lane + 1; i < end_lane; i++ {
        dpb_lanes = dpb_lanes + "," + lanes[i]
    }
    base_port,_ := strconv.Atoi(strings.TrimLeft(port_i, "Ethernet"))
    port_config.name = "Ethernet"+strconv.Itoa(base_port+(lane_speed[0]*subport))
    port_config.alias = strings.Split(entry["alias_at_lanes"], ",")[subport]
    port_config.index = dpb_index
    port_config.lanes = dpb_lanes
    port_config.speed = strconv.Itoa(lane_speed_map[mode][1])
    if strings.HasPrefix(mode, "1x") {
        pos := strings.Index(port_config.alias, ":")
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

        entry, ok := platConfigStr[ports[i].name]
        if ok {
            brkoutMap := make(map[string]db.Value)
            fv := make(map[string]string)
            fvpairs := db.Value{Field: fv}
            fvpairs.Set("lanes", entry["lanes"])
            brkoutMap[ports[i].name] = fvpairs
            addMap["BREAKOUT_CFG"] = brkoutMap
        }
    }

    addMap["PORT"] = entryMap
    log.Info("DPB: CREATE Map", addMap)
    subOpMap[db.ConfigDB] = addMap
    return subOpMap;
}


