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
        "bytes"
	"unicode"
        "encoding/hex"
        "encoding/base64"
)

const (
        NTP_SERVER_TABLE_NAME = "NTP_SERVER"
)

const (
        NTP_SECRET_PASSWORD = "asdffdsa"
)

const (
        NTP_KEY_VALUE_STR = "value"
)

const (
        NTP_KEY_ENCRYPTED_STR = "encrypted"
)

const (
        NTP_KEY_TYPE = "type"
)

const NTP_MAX_PLAIN_TXT_LEN = 20

const NTP_MAX_PWD_LEN = 64

const (
        NTP_DEFAULT_MINPOLL = 6
)

const (
        NTP_DEFAULT_MAXPOLL = 10
)

var NTP_AUTH_TYPE_MAP = map[string]string{
        strconv.FormatInt(int64(ocbinds.OpenconfigSystem_NTP_AUTH_TYPE_NTP_AUTH_MD5), 10):"MD5",
        strconv.FormatInt(int64(ocbinds.OpenconfigSystem_NTP_AUTH_TYPE_NTP_AUTH_SHA1), 10):"SHA1",
        strconv.FormatInt(int64(ocbinds.OpenconfigSystem_NTP_AUTH_TYPE_NTP_AUTH_SHA2_256), 10):"SHA2_256",
}

func init() {
        XlateFuncBind("YangToDb_ntp_global_key_xfmr", YangToDb_ntp_global_key_xfmr)
        XlateFuncBind("YangToDb_ntp_server_subtree_xfmr", YangToDb_ntp_server_subtree_xfmr)
        XlateFuncBind("DbToYang_ntp_server_subtree_xfmr", DbToYang_ntp_server_subtree_xfmr)
        XlateFuncBind("Subscribe_ntp_server_subtree_xfmr", Subscribe_ntp_server_subtree_xfmr)
        XlateFuncBind("DbToYangPath_ntp_server_path_xfmr", DbToYangPath_ntp_server_path_xfmr)
        XlateFuncBind("YangToDb_ntp_authentication_key_table_key_xfmr", YangToDb_ntp_authentication_key_table_key_xfmr)
	XlateFuncBind("DbToYang_ntp_authentication_key_table_key_xfmr", DbToYang_ntp_authentication_key_table_key_xfmr)
        XlateFuncBind("YangToDb_ntp_auth_key_id_xfmr", YangToDb_ntp_auth_key_id_xfmr)
        XlateFuncBind("DbToYang_ntp_auth_key_id_xfmr", DbToYang_ntp_auth_key_id_xfmr)
        XlateFuncBind("YangToDb_ntp_auth_key_type_xfmr", YangToDb_ntp_auth_key_type_xfmr)
        XlateFuncBind("DbToYang_ntp_auth_key_type_xfmr", DbToYang_ntp_auth_key_type_xfmr)
        XlateFuncBind("YangToDb_ntp_auth_key_value_xfmr", YangToDb_ntp_auth_key_value_xfmr)
        XlateFuncBind("DbToYang_ntp_auth_key_value_xfmr", DbToYang_ntp_auth_key_value_xfmr)
        XlateFuncBind("YangToDb_ntp_auth_encrypted_xfmr", YangToDb_ntp_auth_encrypted_xfmr)
        XlateFuncBind("DbToYang_ntp_auth_encrypted_xfmr", DbToYang_ntp_auth_encrypted_xfmr)
}

func openssl(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("openssl", args...)

	in := bytes.NewReader(stdin)

	out := &bytes.Buffer{}

	errs := &bytes.Buffer{}

	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errs

	if err := cmd.Run(); err != nil {
		if len(errs.Bytes()) > 0 {
	            log.Info("openssl error ", err)
                    return out.Bytes(), err
		}
	}

	return out.Bytes(), nil
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

        keyName := pathInfo.Var("address")

        log.Infof( "YangToDb_ntp_server_subtree_xfmr, pathInfo %v targetUri %v key %v", pathInfo, targetUriPath, keyName)

        if (inParams.oper == DELETE) {
                if keyName == "" {
                        errStr = "NTP server " + keyName + " empty"
                        log.Info("YangToDb_ntp_server_subtree_xfmr: DELETE ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
                } else {
                        // in case the delete is for a specific leaf
                        if (strings.Contains(targetUriPath, "/openconfig-system:system/ntp/servers/server/config/")) {
                                field_name := targetUriPath[strings.LastIndex(targetUriPath, "/")+1:]
                                field_name = field_name[strings.LastIndex(field_name, ":")+1:]
			        errStr = field_name + " cannot be deleted alone"
			        log.Info("YangToDb_ntp_server_subtree_xfmr: DELETE ", errStr)
			        err = tlerr.InvalidArgsError{Format: errStr}

                                return res_map, err
                        }
                }
        } else {
                /* for configure, YangToDb subtree xfmr gets called multiple times, only care about this one */
                if (targetUriPath != "/openconfig-system:system/ntp/servers/server/config") {
                        return res_map, err
                }
        }

        var auth_key_id_str string
        var minpoll_int_str string
        var maxpoll_int_str string
 
        //Delete only allowed for NTP server, and not the key id on the server
        if (inParams.oper != DELETE) {
                sysObj := getSystemRootObject(inParams)
                ntpData := sysObj.Ntp
                ntpServers := ntpData.Servers
                ntpServer := ntpServers.Server
                ntpServerConfig := ntpServer[keyName].Config
                auth_key_id := ntpServerConfig.KeyId
                if (auth_key_id != nil) { 
                        auth_key_id_int := int(*auth_key_id)
                        auth_key_id_str = strconv.Itoa(auth_key_id_int)
                }

                minpoll := ntpServerConfig.Minpoll
                var minpoll_int int
                if (minpoll != nil) {
                        minpoll_int = int(*minpoll)
                } else {
                        // If not configured, ntpd has internal default minpoll/maxpoll,
                        // subtree needs to enter the default value for configDB, so clish GET
                        // can retrieve the default values
                        minpoll_int = NTP_DEFAULT_MINPOLL
                }

                minpoll_int_str = strconv.Itoa(minpoll_int)

                maxpoll := ntpServerConfig.Maxpoll
                var maxpoll_int int
                if (maxpoll != nil) {
                        maxpoll_int = int(*maxpoll)
                } else {
                        // If not configured, ntpd has internal default minpoll/maxpoll,
                        // subtree needs to enter the default value for configDB, so clish GET
                        // can retrieve the default values
                        maxpoll_int = NTP_DEFAULT_MAXPOLL
                }

                maxpoll_int_str = strconv.Itoa(maxpoll_int)

                if ((minpoll_int_str != "") && (maxpoll_int_str != "")) {
                        if (minpoll_int >= maxpoll_int) {
                                errStr = "NTP server invalid minpoll or maxpoll"
                                log.Info("YangToDb_ntp_server_subtree_xfmr ", errStr)
                                err = tlerr.InvalidArgsError{Format: errStr}
                                return res_map, err
                        }
                }
        }

        res_map[NTP_SERVER_TABLE_NAME] = make(map[string]db.Value)

        res_map[NTP_SERVER_TABLE_NAME][keyName] = db.Value{Field: map[string]string{}}
        dbVal := res_map[NTP_SERVER_TABLE_NAME][keyName]
        if ((auth_key_id_str == "") && (minpoll_int_str == "") && (maxpoll_int_str == "")) {
                if (inParams.oper != DELETE) {
                        (&dbVal).Set("NULL", "NULL")
                }
        } else {
                if (auth_key_id_str != "") {
                        (&dbVal).Set("key_id", auth_key_id_str)
                }

                if (minpoll_int_str != "") {
                        (&dbVal).Set("minpoll", minpoll_int_str)
                }

                if (maxpoll_int_str != "") {
                        (&dbVal).Set("maxpoll", maxpoll_int_str)
                }
        }

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

// FillNtpServer is a function to populate the NTP peer config/states based on NTP server record from "ntpq" output
func FillNtpServer (keyName string, ntpqList []string, ntpServers *ocbinds.OpenconfigSystem_System_Ntp_Servers, isGetServConfigOnly bool) error {
        var err error
        var errStr string
        var currNtpServer *ocbinds.OpenconfigSystem_System_Ntp_Servers_Server

        log.Infof("FillNtpServer: keyName %v getServConfigOnly %v", keyName, isGetServConfigOnly)
        /* There are 10 fields in ntpq server association record */
        if len(ntpqList) != 10 {
                errStr = "Failed to analyze NTP server association message"
                log.Info("FillNtpServer: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return err
        }

        /* Check if the 1st char exists for ntp peer selection */
        remote := ntpqList[0]

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
            return nil
        }

        refId := ntpqList[1]
        stratum := ntpqList[2]
        peer_type := ntpqList[3]
        when := ntpqList[4]
        poll := ntpqList[5]
        reach := ntpqList[6]
        delay := ntpqList[7]
        offset := ntpqList[8]
        jitter := ntpqList[9]

        if (!isGetServConfigOnly) {

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
                } else {
                       currNtpServer = ntpServers.Server[keyName]
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

                /* reach is octal string */
                currNtpServer.State.Reach = &reach

                delay_sec, _ := strconv.ParseFloat(delay, 64)
                delay_milli := delay_sec*1000
                currNtpServer.State.Peerdelay = &delay_milli

                currNtpServer.State.Refid = &refId
        }

        return nil
}

// ProcessGetNtpServer is a function to run "ntpq -pn" cmd from the mgmt framework docker and populate the NTP peer config/states based on requestUri
func ProcessGetNtpServer (inParams XfmrParams, vrfName string, isMgmtVrfEnabled bool)  error {
        var err error
        var errStr string

        log.V(3).Info("ProcessGetNtpServer  vrfName: %v isMgmtVrfEnabled %v", vrfName, isMgmtVrfEnabled)

        requestUriPath, _ := getYangPathFromUri(inParams.requestUri)

        pathInfo := NewPathInfo(inParams.uri)

        keyName := pathInfo.Var("address")

        log.V(3).Info("ProcessGetNtpServer: request ", requestUriPath,
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
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/config/openconfig-system-ext:key-id") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/config/openconfig-system-ext:minpoll") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/config/openconfig-system-ext:maxpoll") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/state") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/state/address") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/state/openconfig-system-ext:key-id") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/state/openconfig-system-ext:minpoll") &&
             (requestUriPath != "/openconfig-system:system/ntp/servers/server/state/openconfig-system-ext:maxpoll") ) {
                log.Info("ProcessGetNtpServer: no return of ntp server state at ", requestUriPath)
                return nil
        }

        var getServConfigOnly = false
        var getServStateOnly = false

        if (strings.Contains(requestUriPath, "/openconfig-system:system/ntp/servers/server/config")) { 
                getServConfigOnly = true
        }

        if (strings.Contains(requestUriPath, "/openconfig-system:system/ntp/servers/server/state")) {
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

        ntpServTable := &db.TableSpec{Name: NTP_SERVER_TABLE_NAME}
        if (keyName != "") {
                serverKey := db.Key{Comp: []string{keyName}}

                ntpServEntry, err := inParams.d.GetEntry(ntpServTable, serverKey)
                if err != nil {
                        log.Infof("ProcessGetNtpServer, unable to get NTP server entry with key %v err %v", keyName, err)
                        return err

                }

                keyId_str := (&ntpServEntry).Get("key_id")

                minpoll_str := (&ntpServEntry).Get("minpoll")

                maxpoll_str := (&ntpServEntry).Get("maxpoll")

                currNtpServer = ntpServer[keyName]

                if (!getServStateOnly) {
                        if (currNtpServer.Config == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.Config.Address = &keyName

                        if (keyId_str != "") {
                                keyId_int, err := strconv.ParseUint(keyId_str, 10, 16)
                                if (err != nil) {
                                        errStr = "Unable to convert key_id " + keyId_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                keyId_uint16 := uint16(keyId_int)
                                currNtpServer.Config.KeyId = &keyId_uint16
                        }

                        if (minpoll_str != "") {
                                minpoll_int, err := strconv.ParseUint(minpoll_str, 10, 8)
                                if (err != nil) {
                                        errStr = "Unable to convert minpoll " + minpoll_str 
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                minpoll_uint8 := uint8(minpoll_int)
                                currNtpServer.Config.Minpoll = &minpoll_uint8
                        }

                        if (maxpoll_str != "") {
                                maxpoll_int, err := strconv.ParseUint(maxpoll_str, 10, 8)
                                if (err != nil) {
                                        errStr = "Unable to convert maxpoll " + maxpoll_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                maxpoll_uint8 := uint8(maxpoll_int)
                                currNtpServer.Config.Maxpoll = &maxpoll_uint8
                        }
                }

                if (!getServConfigOnly) {
                        if (currNtpServer.State == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.State.Address = &keyName

                        if (keyId_str != "") {
                                keyId_int, err := strconv.ParseUint(keyId_str, 10, 16)
                                if (err != nil) {
                                        errStr = "Unable to convert key_id " + keyId_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                keyId_uint16 := uint16(keyId_int)

                                currNtpServer.State.KeyId = &keyId_uint16
                        }

                        if (minpoll_str != "") {
                                minpoll_int, err := strconv.ParseUint(minpoll_str, 10, 8)
                                if (err != nil) {
                                        errStr = "Unable to convert minpoll " + minpoll_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                minpoll_uint8 := uint8(minpoll_int)
                                currNtpServer.State.Minpoll = &minpoll_uint8
                        }

                        if (maxpoll_str != "") {
                                maxpoll_int, err := strconv.ParseUint(maxpoll_str, 10, 8)
                                if (err != nil) {
                                        errStr = "Unable to convert maxpoll " + maxpoll_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                maxpoll_uint8 := uint8(maxpoll_int)
                                currNtpServer.State.Maxpoll = &maxpoll_uint8
                        }

                }
        } else {
                /* Get all ntp servers from config DB */
                ntpServKeys, err := inParams.d.GetKeys(ntpServTable)

                if err != nil {
                        log.Info("ProcessGetNtpServer, unable to get NTP server table keys with err ", err)
                        return err
                }

                for i := range ntpServKeys {
                        currAddress := ntpServKeys[i].Comp
                        currNtpServer = ntpServer[currAddress[0]]

                        serverKey := db.Key{Comp: []string{currAddress[0]}}
                        ntpServEntry, err := inParams.d.GetEntry(ntpServTable, serverKey)

                        if err != nil {
                                log.Infof("ProcessGetNtpServer, unable to get NTP server entry for key %v with err %v", currAddress[0], err)
                                return err
                        }

                        if (currNtpServer == nil) {
                                currNtpServer, _ = ntpServers.NewServer(currAddress[0])
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        if (currNtpServer.Config == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        keyId_str := (&ntpServEntry).Get("key_id")
                        minpoll_str := (&ntpServEntry).Get("minpoll")
                        maxpoll_str := (&ntpServEntry).Get("maxpoll")

                        currNtpServer.Config.Address = &currAddress[0]

                        if (currNtpServer.State == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.State.Address = &currAddress[0]

                        if (keyId_str != "") {
                                keyId_int, err := strconv.ParseUint(keyId_str, 10, 16)
                                if (err != nil) {
                                        errStr = "Unable to convert key_id " + keyId_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                keyId_uint16 := uint16(keyId_int)
                                currNtpServer.Config.KeyId =  &keyId_uint16
                                currNtpServer.State.KeyId = &keyId_uint16
                        }

                        if (minpoll_str != "") {
                                minpoll_int, err := strconv.ParseUint(minpoll_str, 10, 8)
                                if (err != nil) {
                                        errStr = "Unable to convert minpoll " + minpoll_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                minpoll_uint8 := uint8(minpoll_int)
                                currNtpServer.Config.Minpoll = &minpoll_uint8
                                currNtpServer.State.Minpoll = &minpoll_uint8
                        }

                        if (maxpoll_str != "") {
                                maxpoll_int, err := strconv.ParseUint(maxpoll_str, 10, 8)
                                if (err != nil) {
                                        errStr = "Unable to convert maxpoll " + maxpoll_str
                                        log.Info("DbToYang_ntp_server_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return err
                                }

                                maxpoll_uint8 := uint8(maxpoll_int)
                                currNtpServer.Config.Maxpoll = &maxpoll_uint8
                                currNtpServer.State.Maxpoll = &maxpoll_uint8
                        }

                }
        }

        // Return here if no need to access ntpq
        if ( getServConfigOnly ||
             (requestUriPath == "openconfig-system:system/ntp/servers/server/state/openconfig-system-ext:key-id") ||
             (requestUriPath == "openconfig-system:system/ntp/servers/server/state/openconfig-system-ext:minpoll") ||
             (requestUriPath == "openconfig-system:system/ntp/servers/server/state/openconfig-system-ext:maxpoll") ) {
                return nil 
        }

        cmd := exec.Command("ntpq", "-pnw")
        if ((isMgmtVrfEnabled) &&
            ((vrfName == "mgmt") ||
             (vrfName == ""))) {
                cmd = exec.Command("cgexec", "-g", "l3mdev:mgmt", "ntpq", "-pnw")
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

        defer cmd.Wait()

        in := bufio.NewScanner(output)

        /*  Sample output 
         *
         *                remote           refid      st t when poll reach   delay   offset  jitter
         *          ================================================================================
         line1      *10.11.0.1       10.11.8.1        4 u  180  256  377    0.442   -27.516   7.380
         line2      +10.11.0.2       10.11.8.1        4 u  174  256  377    0.443    22.323   3.238
         line3       2405:200:1410:1401::4:db1
         line4                       .INIT.          16 u    -   64    0    0.000    0.000   0.000
         *
         *  There are two cases on NTP server association outputs with "ntpq -pnw":
         *    case1: like the above line1 and line2, all server association information
         *           is shown in one line.
         *    case2: like the above line3 and line4, server association information
         *           is shown in more than one lines due to "remote" or "refid" string is
         *           too long.
         */

        line_num := 0
        var list0 []string

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

                /* Check if it is the above case2 line4, if so, concatenate line3 and line4 in list */
                /* There are 10 fields in ntpq server association record */
                if list0 != nil {
                        if len(list) < 10 {
                                list = append(list0, list...)
                                list0 = nil
                        }
                }

                /* Check if it is the above case2 line3, if so cache it and continue to next line */
                if len(list) < 10 {
                        list0 = list
                        line_num ++
                        continue
                }

                if list0 != nil {
                        log.Infof( "ProcessGetNtpServer: list0 %v, len %v, line no. %v", list0, len(list0), line_num)
                        err = FillNtpServer(keyName, list0, ntpServers, getServConfigOnly)
                        if err != nil {
                                return err
                        }
                        list0 = nil
                }

                log.Infof( "ProcessGetNtpServer: list %v, len %v, line no. %v", list, len(list), line_num)
                err = FillNtpServer(keyName, list, ntpServers, getServConfigOnly)
                if err != nil {
                        return err
                }

                line_num ++
        }

        return nil
}

// DbToYang_ntp_server_subtree_xfmr is a xfmr function for handling GET NTP server config/state
var DbToYang_ntp_server_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
        var err error
        var errStr string

        log.V(3).Info("DbToYang_ntp_server_subtree_xfmr: root ", inParams.ygRoot,
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
        result.dbDataMap = make(RedisDbSubscribeMap)

        pathInfo := NewPathInfo(inParams.uri)

        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

        keyName := pathInfo.Var("address")

        log.Infof("Subscribe_ntp_server_subtree_xfmr path %v key %v ", targetUriPath, keyName)

        if inParams.subscProc == TRANSLATE_SUBSCRIBE {
                // to handle the TRANSLATE_SUBSCRIBE
                ntpServerPath := "/openconfig-system:system/servers/server"
                ntpServerStatePath := ntpServerPath + "/state"

                // notification at ntpserver/state is not supported
                if (targetUriPath == ntpServerStatePath ||
                    targetUriPath == ntpServerPath) {
                    log.Infof("Subscirbe at %v is not supported", targetUriPath)
                    return result, nil 
                }

                result.onChange = OnchangeEnable
                result.nOpts = &notificationOpts{}
                result.nOpts.pType = OnChange
                result.isVirtualTbl = false

                if keyName == "" {
                        keyName = "*"
                }

                result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{"NTP_SERVER": {keyName:{"key_id":"key-id", "minpoll":"minpoll", "maxpoll":"maxpoll"}}}}
                log.Info("Subscribe_ntp_server_subtree_xfmr: result dbDataMap: ", result.dbDataMap)
 
                return result, err
        } else { 
                if (keyName != "") {
                        result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{NTP_SERVER_TABLE_NAME:{keyName:{}}}}
                        log.Infof("Subscribe_ntp_server_subtree_xfmr keyName %v dbDataMap %v ", keyName, result.dbDataMap)
                } else {
                        result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{NTP_SERVER_TABLE_NAME:{"*":{}}}}
                        log.Infof("Subscribe_ntp_server_subtree_xfmr keyName %v dbDataMap %v ", keyName, result.dbDataMap)
                }
                result.needCache = true
                result.nOpts = new(notificationOpts)
                result.nOpts.mInterval = 15
                result.nOpts.pType = OnChange
                log.Info("Returning Subscribe_ntp_server_subtree_xfmr")
                return result, err
        }
}

var DbToYangPath_ntp_server_path_xfmr PathXfmrDbToYangFunc = func(params XfmrDbToYgPathParams) (error) {
        log.V(3).Info("DbToYangPath_ntp_server_path_xfmr: params: ", params)

        ntpRoot := "/openconfig-system:system/ntp/servers/server"

        if (params.tblName != "NTP_SERVER") {
                log.Info("DbToYangPath_ntp_server_path_xfmr: from wrong table: ", params.tblName)
                return nil
        }

        if (len(params.tblKeyComp) > 0) {
                log.V(3).Info("DbToYangPath_ntp_server_path_xfmr, key: ", params.tblKeyComp[0])
                params.ygPathKeys[ntpRoot + "/address"] = params.tblKeyComp[0]
        } else {
                log.Info("DbToYangPath_ntp_server_path_xfmr, null key")
                return nil
        }

        log.V(3).Info("DbToYangPath_ntp_server_path_xfmr, params.ygPathKeys: ", params.ygPathKeys)

        return nil
}

var YangToDb_ntp_auth_key_value_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        pathInfo := NewPathInfo(inParams.uri)

        key_id := pathInfo.Var("key-id")

	if (key_id == "") {
	        return res_map, nil
        }

        if(inParams.oper == DELETE) {
                res_map[NTP_KEY_VALUE_STR] = ""
                return res_map, nil
        }

        // Get KeyEncrytped value and use it to determin if need to perform encryt the string
        sysObj := getSystemRootObject(inParams)
        ntpData := sysObj.Ntp
	keyId, err := strconv.ParseUint(key_id, 10, 16)
        if (err != nil) {
                errStr := "Unable to convert key id " + key_id 
                log.Info("YangToDb_ntp_auth_key_value_xfmr: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return res_map, err
        }

	keyIdUint16 := uint16(keyId)
	encrypted := ntpData.NtpKeys.NtpKey[keyIdUint16].Config.Encrypted

        key_value := inParams.param.(*string)

        var encrypted_str  string

        if ((encrypted == nil) || (!*encrypted)) {
                // if input is plaintext string, validate the string
                if ((strings.ContainsAny(*key_value, ",#")) ||
                    (strings.Contains(*key_value, " "))) {
                        errStr := "Invalid password"
                        log.Info("YangToDb_ntp_auth_key_value_xfmr, error ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
                }

                // check the plaintext length, if greater than 20 then it has to be in hex
                plaintxt_len := len(*key_value)
                if (plaintxt_len > NTP_MAX_PLAIN_TXT_LEN) {
                        if(plaintxt_len > NTP_MAX_PWD_LEN) {
                                errStr := "Exceed maximum length"
                                log.Info("YangToDb_ntp_auth_key_value_xfmr, error ", errStr)
                                err = tlerr.InvalidArgsError{Format: errStr}
                                return res_map, err
                        }

                        // If plaintxt length greater than 20 less than max (64), it has to be hexadecimal
                        _, err := hex.DecodeString(*key_value)
                        if (err != nil) {
                                errStr := "Invalid password"
                                log.Info("YangToDb_ntp_auth_key_value_xfmr, error ", errStr)
                                err = tlerr.InvalidArgsError{Format: errStr}
                                return res_map, err
                        }
                }

                key_value_byte := []byte(*key_value)
                encrypted_key_value, err := openssl(key_value_byte, "enc", "-aes-128-cbc", "-A", "-a", "-salt", "-pass", "pass:"+NTP_SECRET_PASSWORD)
                if (err != nil) {
                        log.Infof("YangToDb_ntp_auth_key_value_xfmr, encryption failed with err %v", err)
                        return res_map, err
                }

                encrypted_str = string([]byte(encrypted_key_value))
                encrypted_str = strings.TrimFunc(encrypted_str, func(r rune) bool {
				return !unicode.IsGraphic(r)
					})
        } else {
                // If the key value is encrypted, then validate it by decryption to prevent setting a bad key value in the configDB
                decrypt_data, err := base64.StdEncoding.DecodeString(*key_value)
                if (err != nil) {
                        errStr := "Invalid encrypted text"
                        log.Info("YangToDb_ntp_auth_key_value_xfmr, error ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
                }
                decrypt_data_byte := []byte(decrypt_data)
                _, err = openssl(decrypt_data_byte, "enc", "-aes-128-cbc", "-d", "-salt", "-pass", "pass:"+NTP_SECRET_PASSWORD)
                if (err != nil) {
                        errStr := "Decryption to plaintext failed, invalid encrypted text"
                        log.Info("YangToDb_ntp_auth_key_value_xfmr, error ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
                }
        }

        if ((encrypted == nil) || (!*encrypted)) {
                res_map[NTP_KEY_VALUE_STR] = encrypted_str 
        } else {
                res_map[NTP_KEY_VALUE_STR] = *key_value 
        }

        return res_map, err
}

var YangToDb_ntp_auth_encrypted_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        res_map[NTP_KEY_ENCRYPTED_STR] = "true"

        return res_map, err
}

var YangToDb_ntp_authentication_key_table_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
        pathInfo := NewPathInfo(inParams.uri)

        auth_key_num := pathInfo.Var("key-id")

        return auth_key_num, nil
}

var DbToYang_ntp_authentication_key_table_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        if (inParams.key != "") {
                keyIdFloat64, err  := strconv.ParseFloat(inParams.key, 64)
                if (err != nil) {
                        errStr := "Unable to convert key " + inParams.key 
                        log.Info("DbToYang_ntp_authentication_key_table_key_xfmr: ", errStr)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
                }

                res_map["key-id"] = keyIdFloat64 
        }

        return res_map, err
}

var YangToDb_ntp_auth_key_id_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        return res_map, err
}

var DbToYang_ntp_auth_key_id_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        keyIdFloat64, err := strconv.ParseFloat(inParams.key, 64)
        if (err != nil) {
                errStr := "Unable to convert key " + inParams.key
                log.Info("DbToYang_ntp_auth_key_id_xfmr: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return res_map, err
        }

        res_map["key-id"] = keyIdFloat64

        return res_map, err
}

var YangToDb_ntp_auth_key_type_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

	if (inParams.oper == DELETE)  {
            res_map[NTP_KEY_TYPE] = ""
	    return res_map, err
        }

        key_type, _ := inParams.param.(ocbinds.E_OpenconfigSystem_NTP_AUTH_TYPE)

        res_map[NTP_KEY_TYPE] = findInMap(NTP_AUTH_TYPE_MAP, strconv.FormatInt(int64(key_type), 10))

        return res_map, err
}

var DbToYang_ntp_auth_key_type_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) { 
        res_map := make(map[string]interface{})
        var err error

        data := (*inParams.dbDataMap)[inParams.curDb]
        key_tbl := data["NTP_AUTHENTICATION_KEY"]
        key_entry := key_tbl[inParams.key]
        key_type := findInMap(NTP_AUTH_TYPE_MAP, key_entry.Field[NTP_KEY_TYPE])
        var n int64
        n, err = strconv.ParseInt(key_type, 10, 64)
        if (err != nil) {
                errStr := "Unable to convert key type " + key_type 
                log.Info("DbToYang_ntp_auth_key_type_xfmr: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return res_map, err
        }

        res_map["key-type"] = ocbinds.E_OpenconfigSystem_NTP_AUTH_TYPE(n).ΛMap()["E_OpenconfigSystem_NTP_AUTH_TYPE"][n].Name

        return res_map, err
}

var DbToYang_ntp_auth_key_value_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        data := (*inParams.dbDataMap)[inParams.curDb]
        key_tbl := data["NTP_AUTHENTICATION_KEY"]
        key_entry := key_tbl[inParams.key]
        key_value := key_entry.Field["value"]

        res_map["key-value"] = key_value

        return res_map, err 
}

var DbToYang_ntp_auth_encrypted_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        data := (*inParams.dbDataMap)[inParams.curDb]
        key_tbl := data["NTP_AUTHENTICATION_KEY"]
        key_entry := key_tbl[inParams.key]
        encrypted := key_entry.Field["encrypted"]

        encryptedBool,err := strconv.ParseBool(encrypted)
        if (err != nil) {
                errStr := "Unable to convert encrypted " + encrypted 
                log.Info("DbToYang_ntp_auth_encrypted_xfmr: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return res_map, err
        }

        res_map["encrypted"] = encryptedBool

        return res_map, err
}

