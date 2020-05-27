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
}

func getSystemRootObject(inParams XfmrParams) (*ocbinds.OpenconfigSystem_System) {
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    return deviceObj.System
}

/* Xfmr function to return key for the NTP global table */
var YangToDb_ntp_global_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
        log.Info( "YangToDb_ntp_global_key_xfmr: root: ", inParams.ygRoot,
                 ", uri: ", inParams.uri)

        return "global", nil
}

/* Xfmr function at system/ntp/servers/server level to handle NTP server configuration */
var YangToDb_ntp_server_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
        var err error
        var errStr string

        res_map := make(map[string]map[string]db.Value)

        log.Info( "YangToDb_ntp_server_subtree_xfmr: root: ", inParams.ygRoot,
                  ", uri: ", inParams.uri,
                  ", requestUri", inParams.requestUri,
                  ", op: ", inParams.oper)

        pathInfo := NewPathInfo(inParams.requestUri)

        keyName := pathInfo.Var("address")

       if keyName == "" {
                errStr = "NTP server " + keyName + " empty"
                log.Info("YangToDb_ntp_server_subtree_xfmr: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return res_map, err
        }

        res_map[NTP_SERVER_TABLE_NAME] = make(map[string]db.Value)

        res_map[NTP_SERVER_TABLE_NAME][keyName] = db.Value{Field: map[string]string{}}
        dbVal := res_map[NTP_SERVER_TABLE_NAME][keyName]
        (&dbVal).Set("NULL", "NULL")

        log.Infof ("YangToDb_ntp_server_subtree_xfmr: key %v return res_map %v", keyName, res_map)

        return res_map, nil
}

/* Function to find if a string is in the string slice */
func Find(slice []string, val string) (int, bool) {
    for i, item := range slice {
        if item == val {
            return i, true
        }
    }
    return -1, false
}

/* Function to run "ntpq -p" from the mgmt framework docker and populate the NTP peer config/states based on requestUri */
func ProcessGetNtpServer (inParams XfmrParams, command string, flags ...string)  error {
        var err error
        var errStr string

        log.Infof("ProcessGetNtpServer  %v flags %v", command, flags)

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

        cmd := exec.Command(command, flags...)

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

        sysObj := getSystemRootObject(inParams)

        ygot.BuildEmptyTree(sysObj)

        ntpData := sysObj.Ntp

        ygot.BuildEmptyTree(ntpData)

        ntpServers := ntpData.Servers

        ygot.BuildEmptyTree(ntpServers)

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

                ntpServer := ntpServers.Server
                currNtpServer, ok := ntpServer[remote]
                if !ok {
                        currNtpServer, _ = ntpServers.NewServer(remote)
                        ygot.BuildEmptyTree(currNtpServer)
                }

                if (getServStateOnly == false) {
                        if (currNtpServer.Config == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.Config.Address = &remote
                }

                if (getServConfigOnly == false) {
                        if (currNtpServer.State == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.State.Address = &remote

                        when_num, _ := strconv.ParseUint(when, 10, 32)
                        when_num32 := uint32(when_num)
                        currNtpServer.State.Now = &when_num32

                        offset_sec, _ := strconv.ParseFloat(offset, 64)
                        offset_milli := offset_sec*1000
                        currNtpServer.State.PeerOffset = &offset_milli

                        currNtpServer.State.SelMode = &selMode

                        poll_num, _ := strconv.ParseUint(poll, 10, 32)
                        poll_num32 := uint32(poll_num)
                        currNtpServer.State.PollInterval = &poll_num32

                        stratum_num, _ := strconv.ParseUint(stratum, 10, 8)
                        stratum_num8 := uint8(stratum_num)
                        currNtpServer.State.Stratum = &stratum_num8

                        currNtpServer.State.PeerType = &peer_type

                        jitter_sec, _ := strconv.ParseFloat(jitter, 64)
                        jitter_milli := jitter_sec*1000
                        currNtpServer.State.PeerJitter = &jitter_milli

                        reach_num, _ := strconv.ParseUint(reach, 10, 8)
                        reach_num8 := uint8(reach_num)
                        currNtpServer.State.Reach = &reach_num8

                        delay_sec, _ := strconv.ParseFloat(delay, 64)
                        delay_milli := delay_sec*1000
                        currNtpServer.State.PeerDelay = &delay_milli

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

/* Xfmr function for handling GET NTP server config/state */
var DbToYang_ntp_server_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
        var err error
        var errStr string

        log.Info("DbToYang_ntp_server_subtree_xfmr: root ", inParams.ygRoot,
                 ", uri: ", inParams.uri)

        /*
         * Get MGMT VRF config from configDB
         * To get NTP server state
         *    - for NTP running in default VRF, use "ntpq -p"
         *    - for pre-Buster image, only mgmt is supported for non-default VRF
         *      use "cgexec -g l3mdev:mgmt ntpq -p"
         */

        d, err := db.NewDB(getDBOptions(db.ConfigDB))

        if err != nil {
                errStr = "Unable to access DB"
                log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return err
        }

        ntpTable := &db.TableSpec{Name: "NTP"}
        key := db.Key{Comp: []string{"global"}}
        dbEntry, _ := d.GetEntry(ntpTable, key)

        /* Before migrating to Buster only mgmt VRF supported beside default vrf */
        if (dbEntry.IsPopulated()) {
                vrfName := (&dbEntry).Get("vrf")

                if ( (vrfName == "") || (vrfName == "default") ) {
                        log.Info("DbToYang_ntp_server_subtree_xfmr, NTP vrf not configured")
                        err = ProcessGetNtpServer(inParams, "ntpq", "-p")
                } else if (vrfName == "mgmt") {
                        log.Info("DbToYang_ntp_server_subtree_xfmr: NTP vrf is mgmt")
                        arg0 := "-g"
                        arg1 := "l3mdev:mgmt"
                        arg2 := "ntpq"
                        arg3 := "-p"
                        err = ProcessGetNtpServer(inParams, "cgexec", arg0, arg1, arg2, arg3)
                } else {
                        errStr = "Invalid NTP vrf " + vrfName
                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return err
                }
        } else {
                log.Info("DbToYangng_ntp_server_subtree_xfmr: NTP global not configured")
                err = ProcessGetNtpServer(inParams, "ntpq", "-p")
        }

        return err
}
