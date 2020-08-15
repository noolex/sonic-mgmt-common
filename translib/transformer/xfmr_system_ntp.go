package transformer

import (
        "bufio"
        "os/exec"
        "strings"
        "strconv"
        log "github.com/golang/glog"
        "github.com/openconfig/ygot/ygot"
        "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
        "github.com/Azure/sonic-mgmt-common/translib/db"
        "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

const (
        NTP_SERVER_TABLE_NAME          = "NTP_SERVER"
)

func init() {
        XlateFuncBind("YangToDb_ntp_global_key_xfmr", YangToDb_ntp_global_key_xfmr)
        XlateFuncBind("YangToDb_ntp_server_subtree_xfmr", YangToDb_ntp_server_subtree_xfmr)
        XlateFuncBind("DbToYang_ntp_server_subtree_xfmr", DbToYang_ntp_server_subtree_xfmr)
        XlateFuncBind("Subscribe_ntp_server_subtree_xfmr", Subscribe_ntp_server_subtree_xfmr)
}

func getSystemRootObject(inParams XfmrParams) (*ocbinds.OpenconfigSystem_System) {
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    return deviceObj.System
}

// YangToDb_ntp_global_key_xfmr translate Yang to Db key for global level NTP configuration DB table
var YangToDb_ntp_global_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
        log.Info( "YangToDb_ntp_global_key_xfmr: root: ", inParams.ygRoot,
                 ", uri: ", inParams.uri)

        return "global", nil
}

// YangToDb_ntp_server_subtree_xfmr is a xfmr function at system/ntp/servers/server level to handle NTP server configuration
var YangToDb_ntp_server_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
        var err error
        var errStr string

        res_map := make(map[string]map[string]db.Value)

        log.Info( "YangToDb_ntp_server_subtree_xfmr: root: ", inParams.ygRoot,
                  ", uri: ", inParams.uri,
                  ", requestUri", inParams.requestUri,
                  ", op: ", inParams.oper)

        pathInfo := NewPathInfo(inParams.uri)

        targetUriPath, err := getYangPathFromUri(pathInfo.Path)

        log.Infof( " YangToDb_ntp_server_subtree_xfmr, pathInfo %v targetUri %v", pathInfo, targetUriPath)

        keyName := pathInfo.Var("address")

        if (inParams.oper == DELETE) {
                if keyName == "" {
                        errStr = "NTP server " + keyName + " empty"
                        log.Info("YangToDb_ntp_server_subtree_xfmr: DELETE ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
            }
        } else {
                /* for configure, YangToDb subtree xfmr gets called multiple times, only care about this one */
                if (targetUriPath != "/openconfig-system:system/ntp/servers/server/config") {
                        return res_map, err
                }
        }

        log.Infof( "YangToDb_ntp_server_subtree_xfmr: targetUriPath %v key %v", targetUriPath, keyName)

        res_map[NTP_SERVER_TABLE_NAME] = make(map[string]db.Value)

        res_map[NTP_SERVER_TABLE_NAME][keyName] = db.Value{Field: map[string]string{}}
        dbVal := res_map[NTP_SERVER_TABLE_NAME][keyName]
        (&dbVal).Set("NULL", "NULL")

        log.Infof ("YangToDb_ntp_server_subtree_xfmr: key %v return res_map %v", keyName, res_map)

        return res_map, nil
}

// Find is a function to find if a string is in the string slice
func Find(slice []string, val string) (int, bool) {
    for i, item := range slice {
        if item == val {
            return i, true
        }
    }
    return -1, false
}

// ProcessGetNtpServer is a function to run "ntpq -pn" cmd from the mgmt framework docker and populate the NTP peer config/states based on requestUri
func ProcessGetNtpServer (inParams XfmrParams, vrfName string, isMgmtVrfEnabled bool)  error {
        var err error
        var errStr string

        log.Infof("ProcessGetNtpServer  vrfName: %v isMgmtVrfEnabled %v", vrfName, isMgmtVrfEnabled)

        requestUriPath, _ := getYangPathFromUri(inParams.requestUri)

        pathInfo := NewPathInfo(inParams.uri)

        keyName := pathInfo.Var("address")

        log.Info("ProcessGetNtpServer: request ", requestUriPath,
                 ", key: ", keyName)

        /* If keyName is present, check if it is configured as NTP server */
        if (keyName != "") {
                _, err := inParams.d.GetMapAll(&db.TableSpec{Name:NTP_SERVER_TABLE_NAME+"|"+keyName})
                if err != nil {
                        errStr = "NTP server " + keyName + " is not configured"
                        log.Info("ProcessGetNtpServer: ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return err
                }

        }

        if ( (requestUriPath != "/openconfig-system:system") &&
             (requestUriPath != "/openconfig-system:system/ntp") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/config") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/config/address") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/state") ) {
                log.Info("ProcessGetNtpServer: no return of ntp server state at ", requestUriPath)
                return nil
        }

        var getServConfigOnly = false
        var getServStateOnly = false

        if ( (requestUriPath == "/openconfig-system:system/ntp/servers/server/config") ||
             (requestUriPath == "/openconfig-system:system/ntp/servers/server/config/address") ) {
                getServConfigOnly = true
        }

        if (requestUriPath == "/openconfig-system:system/ntp/servers/server/state") {
                getServStateOnly = true
        }

        sysObj := getSystemRootObject(inParams)
        ntpData := sysObj.Ntp
        ntpServers := ntpData.Servers
        ntpServer := ntpServers.Server

        var currNtpServer *ocbinds.OpenconfigSystem_System_Ntp_Servers_Server

        /*
         * if address is non-empty, set the config and state accordingly first
         * if the address name cannot be resolved, it won't show in ntpq output
         * else if address in empty, the get come for all ntp servers, so populate
         * each ntp server config&state
         */
        if (keyName != "") {
                currNtpServer = ntpServer[keyName]

                if (!getServStateOnly) {
                        if (currNtpServer.Config == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.Config.Address = &keyName
                }

                if (!getServConfigOnly) {
                        if (currNtpServer.State == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.State.Address = &keyName
                }
        } else {
                /* Get all ntp servers from config DB */
                ntpServTable := &db.TableSpec{Name: NTP_SERVER_TABLE_NAME}
                ntpServKeys, err := inParams.d.GetKeys(ntpServTable)

                if err != nil {
                        log.Info("ProcessGetNtpServer, unable to get NTP server table keys with err ", err)
                        return err
                }

                for i := range ntpServKeys {
                        currAddress := ntpServKeys[i].Comp
                        currNtpServer = ntpServer[currAddress[0]]
                        if (currNtpServer == nil) {
                                currNtpServer, _ = ntpServers.NewServer(currAddress[0])
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        if (currNtpServer.Config == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.Config.Address = &currAddress[0]

                        if (currNtpServer.State == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.State.Address = &currAddress[0]
                }
        }

        cmd := exec.Command("ntpq", "-pn")
        if ((isMgmtVrfEnabled) &&
            ((vrfName == "mgmt") ||
             (vrfName == ""))) {
                cmd = exec.Command("cgexec", "-g", "l3mdev:mgmt", "ntpq", "-pn")
        }

        output, err := cmd.StdoutPipe()

        if err != nil {
                log.Info("ProcessGetNtpServer: error ", err)
                return err
        }

        if err := cmd.Start(); err != nil {
            log.Info("ProcessGetNtpServer error  ", err)
            return err
        }

        in := bufio.NewScanner(output)

        /*  Sample output 
         *
         *                remote           refid      st t when poll reach   delay   offset  jitter
         *          ================================================================================
         *          *10.11.0.1       10.11.8.1        4 u  180  256  377    0.442   -27.516   7.380
         *          +10.11.0.2       10.11.8.1        4 u  174  256  377    0.443    22.323   3.238
         *
         */

        line_num := 0

        for in.Scan() {
                line := in.Text()
                list := strings.Fields(line)
                log.Infof( "ProcessGetNtpServer: list %v", list)

                /* If cmd returns no NTP peer state, return right away */
                if line_num == 0 {
                        _, found := Find(list, "remote")
                        if !found {
                                return nil
                         }
                }

                /* If peer exists, skip the first 2 lines */
                if ((line_num == 0) || (line_num == 1)) {
                        line_num ++
                        continue
                }

                /* Check if the 1st char exists for ntp peer selection */
                remote := list[0]

                var selMode string
                if ( (remote[:1] == "*") ||
                     (remote[:1] == "+") ||
                     (remote[:1] == "#") ||
                     (remote[:1] == "-") ||
                     (remote[:1] == "~") ) {
                        selMode = remote[:1]
                        remote = remote[1:]
                }

                /*
                 * For each NTP peer status, only populate the state if 
                 *  - keyName empty, populate each ntp server state and config
                 *  - keyName not empty, 
                 *      - if remote not match keyName, skip
                 *      - if configOnly true, only populate server/config/address
                 *      - if stateOnly  true, only populate server/config/state
                 */

                if ( (keyName != "") && (keyName != remote) ) {
                    line_num ++
                    continue
                }

                refId := list[1]
                stratum := list[2]
                peer_type := list[3]
                when := list[4]
                poll := list[5]
                reach := list[6]
                delay := list[7]
                offset := list[8]
                jitter := list[9]

                if (!getServConfigOnly) {

                        if (keyName == "") {
                                /* it's possible in some error condition remote is not in config DB but in the ntpq -pn */
                                currNtpServer = ntpServers.Server[remote] 
                                if (currNtpServer == nil)  {
                                        currNtpServer, _ = ntpServers.NewServer(remote)
                                        ygot.BuildEmptyTree(currNtpServer)
                                }

                                if (currNtpServer.Config == nil) {
                                        ygot.BuildEmptyTree(currNtpServer)
                                }

                                if (currNtpServer.State == nil) {
                                        ygot.BuildEmptyTree(currNtpServer)
                                }

                                currNtpServer.State.Address = &remote
                        }

                        when_num, _ := strconv.ParseUint(when, 10, 32)
                        when_num32 := uint32(when_num)
                        currNtpServer.State.Now = &when_num32

                        offset_sec, _ := strconv.ParseFloat(offset, 64)
                        offset_milli := offset_sec*1000
                        currNtpServer.State.Peeroffset = &offset_milli

                        currNtpServer.State.Selmode = &selMode

                        poll_num, _ := strconv.ParseUint(poll, 10, 32)
                        poll_num32 := uint32(poll_num)
                        currNtpServer.State.PollInterval = &poll_num32

                        stratum_num, _ := strconv.ParseUint(stratum, 10, 8)
                        stratum_num8 := uint8(stratum_num)
                        currNtpServer.State.Stratum = &stratum_num8

                        currNtpServer.State.Peertype = &peer_type

                        jitter_sec, _ := strconv.ParseFloat(jitter, 64)
                        jitter_milli := jitter_sec*1000
                        currNtpServer.State.Peerjitter = &jitter_milli

                        reach_num, _ := strconv.ParseUint(reach, 10, 8)
                        reach_num8 := uint8(reach_num)
                        currNtpServer.State.Reach = &reach_num8

                        delay_sec, _ := strconv.ParseFloat(delay, 64)
                        delay_milli := delay_sec*1000
                        currNtpServer.State.Peerdelay = &delay_milli

                        currNtpServer.State.Refid = &refId
                }

                line_num ++
        }

        if err := cmd.Wait(); err != nil {
                log.Info("ProcessGetNtpServer: error ", err)
                return err
        }

        return nil
}

// DbToYang_ntp_server_subtree_xfmr is a xfmr function for handling GET NTP server config/state
var DbToYang_ntp_server_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
        var err error
        var errStr string

        log.Info("DbToYang_ntp_server_subtree_xfmr: root ", inParams.ygRoot,
                 ", uri: ", inParams.uri)

        /*
         * Get MGMT VRF config from configDB
         * To get NTP server state
         *    - for NTP running in default VRF, use "ntpq -pn"
         *    - for pre-Buster image, only mgmt is supported for non-default VRF
         *      use "cgexec -g l3mdev:mgmt ntpq -pn"
         */

        isMgmtVrfEnabled := isMgmtVrfEnabled(inParams)

        ntpTable := &db.TableSpec{Name: "NTP"}
        key := db.Key{Comp: []string{"global"}}
        dbEntry, _ := inParams.d.GetEntry(ntpTable, key)

        var vrfName string
        if (dbEntry.IsPopulated()) {
                vrfName = (&dbEntry).Get("vrf")
                /* Before migrating to Buster only mgmt VRF supported beside default vrf */
                if ((vrfName != "default") && (vrfName != "mgmt")) {
                        errStr = "Unable to determin NTP sevice context for vrf " + vrfName
                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                }
        }

        err = ProcessGetNtpServer(inParams, vrfName, isMgmtVrfEnabled)

        return err
}

var Subscribe_ntp_server_subtree_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
        var err error
        var result XfmrSubscOutParams
        result.dbDataMap = make(RedisDbMap)

        pathInfo := NewPathInfo(inParams.uri)

        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

        keyName := pathInfo.Var("address")

        log.Infof("Subscribe_ntp_server_subtree_xfmr path %v key %v ", targetUriPath, keyName)

        if (keyName != "") {
                result.dbDataMap = RedisDbMap{db.ConfigDB:{NTP_SERVER_TABLE_NAME:{keyName:{}}}}
                log.Infof("Subscribe_ntp_server_subtree_xfmr keyName %v dbDataMap %v ", keyName, result.dbDataMap)
        } else {
                result.dbDataMap = RedisDbMap{db.ConfigDB:{NTP_SERVER_TABLE_NAME:{"*":{}}}}
                log.Infof("Subscribe_ntp_server_subtree_xfmr keyName %v dbDataMap %v ", keyName, result.dbDataMap)
        }
        result.needCache = true
        result.nOpts = new(notificationOpts)
        result.nOpts.mInterval = 15
        result.nOpts.pType = OnChange
        log.Info("Returning Subscribe_ntp_server_subtree_xfmr")
        return result, err
}
