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
    "errors"
    "reflect"
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

type portGroup struct {
    memberIfStart string
    memberIfEnd string
    validPortSpeeds map[string]string
}
var portGroups map[string]portGroup

var platConfigStr map[string]map[string]string
var platDefStr map[string]map[string]map[string]string
var platDef4Level map[string]map[string]map[string]map[string]string


/* For parsing FEC data from config file*/

type fec_mode_t     string
type speed_t        string
type interface_t    string
type lane_t         string

/*  interface -> lane -> speed -> list of fec values */
type fec_tbl_t map[interface_t]map[lane_t]map[speed_t][]fec_mode_t

// Table of fec values when default is expected
var default_fec_tbl fec_tbl_t
// Allowed set of FEC values
var supported_fec_tbl fec_tbl_t

/* Functions */

func init () {
    parsePlatformJsonFile();
    parsePlatformDefJsonFile();
    populate_fec_modes_to_db();
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
    /*
        Due to GoLang strict typing, we cannot marshal to a strict format until we know what the table we will be parsing is.
        When parsing FEC, the format is slightly different from when parsing port-group
    */
    log.Info("Reading platform-def.json")

    file, err := ioutil.ReadFile(PLATFORM_DEF_JSON)

    if nil != err {
        log.Info("Unable to read platform-def file: Platform specific properties not supported");
        return err
    }

    //platDefStr = make(map[string]map[string]map[string]string)
    //err = json.Unmarshal([]byte(file), &platDefStr)
    //log.Info(platDefStr)
    //platDef4Level = make(map[string]map[string]map[string]map[string]string)
    //json.Unmarshal([]byte(file), &platDef4Level)
    //log.Info(platDef4Level)

    var fec_raw_map map[string]map[string]map[string]interface{}

    /* Map if for FEC parsing */
    err = json.Unmarshal([]byte(file), &fec_raw_map)

    if err != nil {
        log.Info("platform-def.json parse failed")
        return err
    }

    default_fec_tbl = make(fec_tbl_t)
    supported_fec_tbl = make(fec_tbl_t)

    /* Default table of fec */
    default_fec_tbl = parse_fec_config(fec_raw_map["default-fec-mode"])
    /* Supported table */
    supported_fec_tbl = parse_fec_config(fec_raw_map["fec-mode"])

    /* Check for port-group field */
    if pg_entries, ok := fec_raw_map["port-group"]; ok {
        parsePortGroupData (pg_entries)

        /* For backward compat */
        platDefStr = make(map[string]map[string]map[string]string)
        platDefStr["port-group"] = make(map[string]map[string]string)

        for pg_key, pg_val := range pg_entries {
            platDefStr["port-group"][pg_key] = make(map[string]string)
            for key, val := range pg_val {
                /* Val is of type interface{}
                   Need to conver to string first
                */
                switch reflect.TypeOf(val).Kind() {
                case reflect.String:
                    platDefStr["port-group"][pg_key][key] = val.(string)
                case reflect.Slice:
                }
            }
        }

        log.Info("Parsed port-group info as ", platDefStr)
    } else {
        log.Info("No port-group configs to parse in platform-def")
    }

/* Keeping this commented for now 
    platDefStr = make(map[string]map[string]map[string]string)
    err = json.Unmarshal([]byte(file), &platDefStr)
    log.Info(platDefStr)
    platDef4Level = make(map[string]map[string]map[string]map[string]string)
    json.Unmarshal([]byte(file), &platDef4Level)
    log.Info(platDefStr)
*/
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

    if len(portGroups) > 0 {
        for id, pg := range portGroups {
            var entry ocbinds.OpenconfigPortGroup_PortGroups_PortGroup_State
            var pgInstance *ocbinds.OpenconfigPortGroup_PortGroups_PortGroup
            idCopy := id
            entry.Id = &idCopy
            ifStart := pg.memberIfStart
            ifEnd := pg.memberIfEnd
            entry.MemberIfStart = utils.GetUINameFromNativeName(&ifStart)
            entry.MemberIfEnd = utils.GetUINameFromNativeName(&ifEnd)
            var val_speeds []ocbinds.E_OpenconfigIfEthernet_ETHERNET_SPEED
            defSpeed := 0
            for spd := range pg.validPortSpeeds{
                curSpeed, _ := strconv.Atoi(spd)
                val_speeds = append(val_speeds, speedMap[spd])
                if curSpeed > defSpeed {
                    defSpeed = curSpeed
                    entry.Speed = speedMap[spd]
                }
            }
            sort.SliceStable(val_speeds, func(i, j int) bool {
                first := val_speeds[i]
                second := val_speeds[j]
                return first  < second
            })
            entry.ValidSpeeds = val_speeds
            if _, ok := pgObj.PortGroup[id]; ok {
                pgInstance = pgObj.PortGroup[id]
            } else {
                pgInstance, _ = pgObj.NewPortGroup(id)
            }
            pgInstance.State = &entry
            log.Info("Entry ", id, " ", entry)
        }
    } else {
        log.Info("Platform does not support port-group");
        return tlerr.NotSupported("Platform does not support port-group")
    }

    log.Info("PG Data: ", pgObj.PortGroup)
    return nil
}

func getDefFecMode(ifName, lanes, speed string) (string) {
    if defFecRecords, ok := platDef4Level["default-fec-mode"]; ok {
        for ifRange, recs := range defFecRecords {
            ifRangeSplitted := strings.Split(strings.TrimLeft(ifRange, "Ethern"), "-")
            ifNum,_ := strconv.Atoi(strings.TrimLeft(ifName, "Ethern"))
            startNum,_ := strconv.Atoi(ifRangeSplitted[0])
            endNum,_ := strconv.Atoi(ifRangeSplitted[1])
            if (ifNum >= startNum) && (ifNum <= endNum) {
                for fecLanes, speedFec := range recs {
                    if fecLanes == lanes {
                        for fecSpeed, fec := range speedFec {
                            if fecSpeed == speed {
                                log.Info("FEC for ", ifName, ": ", fec)
                                return fec
                            }
                        }
                    }
                }
            }
        }
    }
    return ""
}

func isPortGroupMember(ifName string) (bool) {
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

    if len(portGroups) > 0 {
        for id, pg := range portGroups {
            if id == pgid {
                isSpeedValid := false
                maxSpeed := 0
                for spd := range pg.validPortSpeeds{
                    if *speed == spd {
                        isSpeedValid = true
                        break
                    } else if *speed == "" || maxSpeed > 0 {
                        spdi,_ := strconv.Atoi(spd)
                        if spdi > maxSpeed {
                            maxSpeed = spdi
                            *speed = spd
                            isSpeedValid = true
                            log.Info("Setting probable default speed to ", *speed)
                        }
                    }
                }
                if !isSpeedValid {
                    log.Info("speed ", *speed, " is not supported for PG#", pgid)
                    return members, tlerr.NotSupported("Unsupported speed")
                }
                startNum,_ := strconv.Atoi(strings.TrimLeft(pg.memberIfStart, "Ethern"))
                endNum,_ := strconv.Atoi(strings.TrimLeft(pg.memberIfEnd, "Ethern"))
                log.Info("PG ", id, " ", pg.validPortSpeeds[*speed], " ==> ",
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
        fec := getDefFecMode(ports[i].name, strconv.Itoa(strings.Count(ports[i].lanes, ",") + 1), ports[i].speed)
        if len(fec)>1 {
             value.Set("fec", fec)
        }
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


func populate_speed_fec_info(v interface {}) map[speed_t][]fec_mode_t {
    mp := make(map[speed_t][]fec_mode_t )
    speed_list := []speed_t {"1000", "10000", "25000", "40000", "50000","100000","200000","400000", "600000", "800000"}

    // If given as raw val/string, all speeds for this lane have one FEC value
    // Try as a raw val
    raw_str, ok := v.(string)
    if ok {
        /* Apply to all speeds */
        for _, spd := range speed_list {
            mp[speed_t(spd)] = []fec_mode_t {fec_mode_t(raw_str)}
        }
        return mp
    }
    // If given as slice, all speeds for this lane have a list/slice of FEC values
    // Try as a slice
    slice, ok := v.([]interface{})
    if ok {
        str_slice := []fec_mode_t{}
        for _, f := range slice {
            str_slice = append(str_slice, fec_mode_t(f.(string)))
        }
        /* Apply to all speeds */
        for _, spd := range speed_list {
            mp[speed_t(spd)] = str_slice
        }
        return mp
    }

    /* At this point the data is given as a dict/map */
    fec_str := v.(map[string]interface{})

    for spd, val := range fec_str {
        /* It can either be a string or list*/
        _, ok := val.([]interface{})
        if !ok {
            raw_str := val.(interface{})
            mp[speed_t(spd)] = []fec_mode_t {fec_mode_t(raw_str.(string))}
        } else {
            slice := val.([]interface{})
            str_slice := []fec_mode_t{}
            for _, f := range slice {
                str_slice = append(str_slice, fec_mode_t(f.(string)))
            }
            mp[speed_t(spd)] = str_slice
        }
    }
    return mp
}

func populate_lane_fec_info(v map[string]interface {}) map[lane_t]map[speed_t][]fec_mode_t {
    mp := make(map[lane_t]map[speed_t][]fec_mode_t)
    for lane, entry := range v {
        mp[lane_t(lane)] = populate_speed_fec_info(entry)
    }
    return mp
}

func parse_fec_config(tbl map[string]map[string]interface{}) fec_tbl_t {
    ret := make(fec_tbl_t)
    for intf, intf_fec_raw := range tbl {
        intf_token := intf
        start := 0
        end := 0
        /*  We can get either a range or a singleton */
        /* Chop off the Ethernet prefix if exist */
        if strings.HasPrefix(intf_token, "Ethernet"){
           intf_token = strings.Split(intf_token, "Ethernet")[1]
        }
        rng := strings.Split(intf_token, "-")
        if intf_start, err := strconv.Atoi(rng[0]); err != nil {
            return ret
        } else {
            start = intf_start
            end = intf_start
        }
        if len(rng) == 2 {
            if intf_end, err := strconv.Atoi(rng[1]); err != nil {
               return ret
            } else {
                end = intf_end
            }
        }
        for count := start; count < end+1; count++ {
            if_num := strconv.Itoa(count)
            ret[interface_t(if_num)] = populate_lane_fec_info(intf_fec_raw)
        }
    }
    return ret
}

/* Flattens/serializes the FEC info table */
func serialize_fec_info_tbl (tbl fec_tbl_t) (string, error) {
    if tbl == nil {
        log.Info("Cannot serialize nil FEC info table.")
        return "", errors.New("Invalid arg")
    }
    serial := []string{}
    for intf, lane_map := range tbl {
        intf_name := "Ethernet"+string(intf)
        intf_info := ""
        intf_info_list := []string {}
        for lane, speed_map := range lane_map {
            fec_modes_list := []string {}
            for speed, fec_modes := range speed_map {
                fm := []string{}
                for _, s := range fec_modes{
                    fm = append(fm, string(s))
                }

                fec_modes_list = append(fec_modes_list, string(speed) + utils.SPEED_TO_FEC_SEPARATOR + strings.Join(fm, utils.FEC_SEPARATOR))
            }
            intf_info_list = append(intf_info_list, string(lane) + utils.LANE_TO_SPEED_SEPARATOR + strings.Join(fec_modes_list, utils.SPEED_SEPARATOR))
        }
        intf_info = strings.Join(intf_info_list, utils.LANE_SEPARATOR)
        //serialized[intf_name] = intf_info
        serial = append(serial, intf_name+utils.INTF_TO_LANE_SEPARATOR+intf_info)
    }
    return strings.Join(serial, utils.INTF_SEPARATOR), nil
}

// Puts the flattened/serialized fec info into the DB (StateDB)
func populate_fec_modes_to_db() {
    /* Use StateDB */
    d, err := db.NewDB(getDBOptions(db.StateDB))
    if err != nil {
        log.Info("Unable to connect to StateDB")
        return
    }

    serialized_supported_fec_modes, _ := serialize_fec_info_tbl(supported_fec_tbl)
    serialized_default_fec_modes, err := serialize_fec_info_tbl(default_fec_tbl)
    log.Info("Done serializing default fec modes.", serialized_default_fec_modes)
    log.Info("Done serializing supported fec modes.", serialized_supported_fec_modes)
    if err == nil {
        fec_fields := db.Value{Field: make(map[string]string)}
        fec_fields.Set(utils.DB_FIELD_NAME_DEFAULT_FEC_MODES, serialized_default_fec_modes)
        fec_fields.Set(utils.DB_FIELD_NAME_SUPPORTED_FEC_MODES, serialized_supported_fec_modes)

        err := d.ModEntry(&db.TableSpec{Name:utils.DB_TABLE_NAME_FEC_INFO}, db.Key{Comp: []string{utils.DB_KEY_NAME_FEC_INFO}}, fec_fields)
        if err != nil {
            log.Info("Unable to write fec modes to db")
            return
        }
    }
}

func parsePortGroupData (pgs map[string]map[string]interface{}) (error) {

    portGroups = make(map[string]portGroup)
    for id, pg := range pgs {
        var entry portGroup
        mem, ok := pg["members"].(string)
        if ok {
            ifRange := strings.Split(mem,"-")
            entry.memberIfStart = ifRange[0]
            ifRange[1] = "Ethernet" + ifRange[1]
            entry.memberIfEnd = ifRange[1]
        } else {
            log.Error("Entry ", id, " members not string")
        }
        vspd, ok := pg["valid_speeds"].([]interface{})
        if ok {
            entry.validPortSpeeds = make(map[string]string)
            for _, spd := range vspd {
                var val_speeds []string
                var speed string
                switch reflect.TypeOf(spd).Kind() {
                    case reflect.String:
                        speed, ok = spd.(string)
                        if ok {
                            val_speeds = append(val_speeds, speed)
                        } else {
                            log.Error("Entry ", id, " speed not string")
                        }
                    case reflect.Slice:
                        speed_s, ok := spd.([]interface{})
                        if ok {
                            for i, nspd := range speed_s {
                                nested_speed, ok := nspd.(string)
                                if ok {
                                    if i == 0 {
                                        speed = nested_speed
                                    }
                                    val_speeds = append(val_speeds, nested_speed)
                                } else {
                                    log.Error("Entry ", id, " speed not string")
                                }
                            }
                        } else {
                            log.Error("Entry ", id, " speed not slice of interfaces")
                        }
                    default:
                        log.Error("PG ", id, "unsupported type: ", reflect.TypeOf(spd).Kind())
                 }
                 entry.validPortSpeeds[speed] = strings.Join(val_speeds,",")
            }
        } else {
            log.Error("Entry ", id, " vspeeds not slice")
        }
        portGroups[id] = entry
        log.Info("Entry ", id, "==> ", portGroups[id])
    }

    log.Info("PG Parsed entry map : ", portGroups)
    return nil

}

func getPgPortValidSpeeds(pgid string, speed string) (string, error) {
    var vspeed string
    var err error
    if pg, ok := portGroups[pgid]; ok {
        if vspeed, ok = pg.validPortSpeeds[speed]; ok {
            log.Info("PG-", pgid, ", PG speed: ", speed,", Valid speeds: ", vspeed)
        } else {
            err = tlerr.InvalidArgs("Invalid port-group speed ", speed)
        }
    } else {
        err = tlerr.NotSupported("Port-group ", pgid, " is not valid")
    }
    return vspeed, err
}
