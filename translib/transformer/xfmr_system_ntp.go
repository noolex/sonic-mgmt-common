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
        //"crypto/aes"
        //"crypto/cipher"
        //"crypto/rand"
        //"encoding/base64"
        //"crypto/md5"
        //"io/ioutil"
        "bytes"
	"unicode"
)

const (
        NTP_SERVER_TABLE_NAME = "NTP_SERVER"
)

const (
        NTP_SECRET_PASSWORD = "asdffdsa"
)

const (
        NTP_KEY_VALUE_STR = "key_value"
)

const (
        NTP_KEY_ENCRYPTED_STR = "key_encrypted"
)

const (
        NTP_KEY_TYPE = "key_type"
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

// bingbing test start
/*
const saltlen = 8
const keylen = 32
const iterations =10002

func base64Encode(src []byte) string {
        return base64.StdEncoding.EncodeToString(src)
}

func ntp_encrypt_string(decryptedStr string, password string) (string, error) {
        log.Info("bingbing ntp_encrypt_string: descriptedStr ", decryptedStr)

        header := make([]byte, saltlen +aes.BlockSize)
        log.Infof("bingbing ntp_encrypt_string: blocksize %v header %v", aes.BlockSize, header)

        salt := header[:saltlen]
        log.Infof("bingbing ntp_encrypt_string: salt %v", salt)

        if _, err := io.ReadFull(rand.Reader, salt); err != nil {
                log.Infof("bingbing ntp_encrypt_string error %v", err)
        }

        iv := header[saltlen:aes.BlockSize_saltlen]
        log.Infof("bingbing ntp_encrypt_string: iv %v", iv)

        if _, err := io.ReadFull(rand.Reader, iv); err != nil {
                log.Infof("bingbing ntp_encrypt_string error %v", err)
        }

        key := pbkdf2.Key([]byte(password), salt, iterations, keylen, md5.New)
        log.Infof("bingbing ntp_encrypt_string, key %v", key)

        block, err := aes.NewCipher(key)
        log.Infof("bingbing ntp_encrypt_string block %v", block)
        if err != nil {
                log.Infof("bingbing ntp_encrypt_string error %v", err)
        }

        ciphertext := make([]byte, len(header) + len(decryptedStr))
        log.Infof("bingbing ntp_encrypt_string ciphertext %v", ciphertext)

        log.Infof("bingbing ntp_encrypt_string header before copy %v",header)
        copy(ciphertext, header)
        log.Infof("bingbing ntp_encrypt_string header after copy %v",header)

        stream := cipher.NewCFBEncrypter(block, iv)
        log.Infof("bingbing ntp_encrypt_string stream %v", stream)

        stream.XORKeyStream(ciphertext[aes.BlockSize+saltlen:], []byte(plaintext))
        log.Infof("bingbing ntp_encrypt_string after XOR stream %v", stream)

        return base64Encode(ciphertext)
}
*/

func openssl(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("openssl", args...)

	in := bytes.NewReader(stdin)

        log.Infof("bingbing openssl in %v", in)

	out := &bytes.Buffer{}

        log.Infof("bingbing openssl out %v", out)

	errs := &bytes.Buffer{}

	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errs

	if err := cmd.Run(); err != nil {
		if len(errs.Bytes()) > 0 {
	            log.Infof("bingbing openssl error running %s (%s):\n %v", cmd.Args, err, errs.String())
		}
	}

	return out.Bytes(), nil
}
// bingbing test end

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

        //bingbing test start
        //encrypted_string := ntp_encrypt_string("dell", "pass") 
        //log.Infof("bingbing encrypted string is %v", encrypted_string)

        // echo foobar | openssl enc -aes-128-cbc -a -salt -pass pass:asdffdsa
        clearText := "foobar"
        secretPasswd := "pass:"+"asdffdsa"
        cmd := exec.Command("echo", clearText, "|", "openssl", "enc", "-aes-128-cbc", "-a", "-salt", "-pass", secretPasswd)
        output, err := cmd.StdoutPipe()
        log.Infof("bingbing echo output %v", output)

        if err != nil {
                log.Info("bingbing : error ", err)
        }

        if err := cmd.Start(); err != nil {
            log.Info("bingbing error  ", err)
        }

        in := bufio.NewScanner(output)
        log.Infof("bingbing in %v", in)

        num := 0
        for in.Scan() {
                line := in.Text()
                log.Infof("bingbing: line %v", line)
                list := strings.Fields(line)
                log.Infof( "bingbing : list %v num %v", list, num)

                num ++;
        }


        newCmd := exec.Command("echo", clearText, "|", "openssl", "enc", "-aes-128-cbc", "-a", "-salt", "-pass", secretPasswd)
        newOut, _ := newCmd.Output()
        log.Infof("bingbing newOut %v", newOut)
        str_newOut := string([]byte(newOut))
        log.Infof("bingbing str_newOut %v", str_newOut)
        strOutput  := newCmd.String()
        log.Infof("bingbing strOutput %v %v", strOutput, string(strOutput))

        tmpCmd := exec.Command("echo", clearText, "|", "openssl", "enc", "-aes-128-cbc", "-a", "-salt", "-pass", secretPasswd)
        tmpOut, _ := tmpCmd.CombinedOutput()
        log.Infof("bingbing tmpout %v stroutput %v", tmpOut, string(tmpOut))

        key_value := []byte("foobar")
        signed, _ := openssl(key_value, "enc", "-aes-128-cbc", "-a", "-salt", "-pass", secretPasswd)
        log.Infof("bingbing signed %v", signed)
        s := string([]byte(signed))
        log.Infof("bingbing str %v", s)
        //bingbing test end

        pathInfo := NewPathInfo(inParams.uri)

        targetUriPath, err := getYangPathFromUri(pathInfo.Path)

        log.Infof( " YangToDb_ntp_server_subtree_xfmr, pathInfo %v targetUri %v", pathInfo, targetUriPath)

        keyName := pathInfo.Var("address")
        //auth_key_id := pathInfo.Var("key-id")
        
        log.Infof("bingbing address %v", keyName)

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

        var auth_key_id_str string
        
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
        }

        res_map[NTP_SERVER_TABLE_NAME] = make(map[string]db.Value)

        res_map[NTP_SERVER_TABLE_NAME][keyName] = db.Value{Field: map[string]string{}}
        dbVal := res_map[NTP_SERVER_TABLE_NAME][keyName]
        if (auth_key_id_str == "") {
                if (inParams.oper != DELETE) {
                        (&dbVal).Set("NULL", "NULL")
                        log.Infof("bingbing add null null for value of server %v", keyName)
                }
        } else {
                //auth_key_id_int := int(*auth_key_id)
                //auth_key_id_str := strconv.Itoa(auth_key_id_int)
                (&dbVal).Set("key_id", auth_key_id_str)
                log.Infof("bingbing key id %v for server %v", auth_key_id_str, keyName)
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

                reach_num, _ := strconv.ParseUint(reach, 10, 8)
                reach_num8 := uint8(reach_num)
                currNtpServer.State.Reach = &reach_num8

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

        // bingbing check how to get key id using cvl !!!!

        ntpServTable := &db.TableSpec{Name: NTP_SERVER_TABLE_NAME}
        if (keyName != "") {
                //ntpServTbl, err := inParams.d.GetTable(ntpServTable)
                //if err != nil {
                //        log.Infof("ProcessGetNtpServer, unable to get NTP server table err %v", err)
                //        return err

                //}

                serverKey := db.Key{Comp: []string{keyName}}

                ntpServEntry, err := inParams.d.GetEntry(ntpServTable, serverKey)
                if err != nil {
                        log.Infof("ProcessGetNtpServer, unable to get NTP server entry with key %v err %v", keyName, err)
                        return err

                }

                keyId_str := (&ntpServEntry).Get("key_id")
                keyId_int, _ := strconv.ParseUint(keyId_str, 10, 16)
                keyId_uint16 := uint16(keyId_int)

                currNtpServer = ntpServer[keyName]

                if (!getServStateOnly) {
                        if (currNtpServer.Config == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.Config.Address = &keyName

                        if (keyId_uint16 != 0) {
                                currNtpServer.Config.KeyId = &keyId_uint16
                        }
                }

                if (!getServConfigOnly) {
                        if (currNtpServer.State == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.State.Address = &keyName

                        if (keyId_uint16 != 0) {
                                currNtpServer.State.KeyId = &keyId_uint16
                        }
                }
        } else {
                /* Get all ntp servers from config DB */
                //ntpServTable := &db.TableSpec{Name: NTP_SERVER_TABLE_NAME}
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
                        keyId_int, _ := strconv.ParseUint(keyId_str, 10, 16)
                        keyId_uint16 := uint16(keyId_int)

                        currNtpServer.Config.Address = &currAddress[0]

                        if (keyId_uint16 != 0) {
                                currNtpServer.Config.KeyId =  &keyId_uint16
                        }

                        if (currNtpServer.State == nil) {
                                ygot.BuildEmptyTree(currNtpServer)
                        }

                        currNtpServer.State.Address = &currAddress[0]

                        if (keyId_uint16 != 0) {
                                currNtpServer.State.KeyId = &keyId_uint16
                        }
                }
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

var YangToDb_ntp_auth_key_value_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        pathInfo := NewPathInfo(inParams.uri)

        key_id := pathInfo.Var("key-id")

	log.Infof("bingbing key vlaue xfmr key id %v", key_id)
	if (key_id == "") {
	        return res_map, nil
        }

        sysObj := getSystemRootObject(inParams)
        ntpData := sysObj.Ntp
	keyId, _ := strconv.ParseUint(key_id, 10, 16)
	keyIdUint16 := uint16(keyId)
	encrypted := ntpData.NtpKeys.NtpKey[keyIdUint16].Config.KeyEncrypted

        log.Infof("YangToDb_ntp_authen_key_value_xfmr key_id %v encrypted %v", key_id, encrypted)

        key_value := inParams.param.(*string)

	log.Infof("YangToDb_ntp_authen_key_value_xfmr key_value %v", key_value)

        var encrypted_str  string

        if (!*encrypted) {
                // read the password
                //d, err :=db.NewDB(getDBOptions(db.ConfigDB))
                //if err != nil {
                //        log.Infof("YangToDb_ntp_auth_key_value_xfmr, read password failed error %v", err)
                //        return res_map, err
                //}

                //defer d.DeleteDB()

                //var ntpGlTblName = "NTP"

                //ntpGlTbl := &db.TableSpec{Name: ntpGlTblName}

                //ntpGlKey := db.Key{Comp: []string{"global"}}

                //ntpGlEntry , err := d.GetEntry(ntpGlTbl, ntpGlKey)
                //if err != nil {
                //        log.Infof("YangToDb_ntp_auth_key_value_xfmr, get Ntp global table failed error %v", err)
                //        return res_map, err
                //}

                //NTP_SECRET_PASSWORD := ntpGlEntry.Get("password")

                //log.Infof("bingbing YangToDb_ntp_auth_key_value_xfmr password %v", NTP_SECRET_PASSWORD)

                key_value_byte := []byte(*key_value)
                encrypted_key_value, _ := openssl(key_value_byte, "enc", "-aes-128-cbc", "-a", "-salt", "-pass", "pass:"+NTP_SECRET_PASSWORD)
                log.Infof("bingbing encrypted %v", encrypted_key_value)
                encrypted_str = string([]byte(encrypted_key_value))
                log.Infof("bingbing encrypted str %v len %v", encrypted_str, len(encrypted_str))
                encrypted_str = strings.TrimFunc(encrypted_str, func(r rune) bool {
				return !unicode.IsGraphic(r)
					})
	        log.Infof("after trim %v len %v", encrypted_str, len(encrypted_str))
        }

        //ntpKey_file, err := os.OpenFile("/ntp_etc/ntp/ntp.keys", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

        //if err != nil {
        //        log.Infof("YangToDb_ntp_auth_key_value_xfmr, create file failed")
        //        return res_map, nil
        //}

	//defer ntpKey_file.Close()

        //datawriter := bufio.NewWriter(ntpKey_file)
	//var key_str string
	//var key_str = key_id + " " + "MD5" + " " + (*key_value) + "\n"
	//log.Infof("key_str %v", key_str)

        //n, err := ntpKey_file.WriteString(key_str)

        //if err != nil {
        //    log.Infof("YangToDb_ntp_auth_key_value_xfmr, append text failed")
        //    return res_map, nil
        //}

	//log.Infof("bingbing n %v", n)

        if (!*encrypted) {
                res_map[NTP_KEY_VALUE_STR] = encrypted_str 
        } else {
                res_map[NTP_KEY_VALUE_STR] = *key_value 
        }

        log.Infof("YangToDb_ntp_authen_key_value_xfmr, %v", res_map)

        return res_map, err
}

var YangToDb_ntp_auth_encrypted_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        pathInfo := NewPathInfo(inParams.uri)

        key_id := pathInfo.Var("key_id")
        log.Info("YangToDb_ntp_auth_encrytped_xfmr key_id ", key_id)

        res_map[NTP_KEY_ENCRYPTED_STR] = "true"

        return res_map, err
}

var YangToDb_ntp_authentication_key_table_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
        log.Info( "bingbing YangToDb_ntp_authentication_key_table_key_xfmr: root: ", inParams.ygRoot,
                 ", uri: ", inParams.uri)

        pathInfo := NewPathInfo(inParams.uri)

        log.Infof("bingbing pathInfo %v", pathInfo.Vars)

        auth_key_num := pathInfo.Var("key-id")

        log.Infof("bingbing YangToDb_ntp_authentication_key_table_key_xfmr key id %v", auth_key_num)

        return auth_key_num, nil
}

var DbToYang_ntp_authentication_key_table_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_authentication_key_table_key_xfmr: ")

        if (inParams.key != "") {
                keyIdFloat64, _  := strconv.ParseFloat(inParams.key, 64)
                res_map["key-id"] = keyIdFloat64 
        }

        log.Info("DbToYang_authentication_key_table_key_xfmr res_map %v", res_map)

        return res_map, err
}

var DbToYang_ntp_auth_key_id_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Infof("bingbing DbToYang_ntp_auth_key_id_xfmr key %v", inParams.key)

        keyIdFloat64, _ := strconv.ParseFloat(inParams.key, 64)

        res_map["key-id"] = keyIdFloat64

        log.Infof("bingbing DbToYang_ntp_auth_key_id_xfmr res_map %v", res_map) 

        return res_map, err
}

var YangToDb_ntp_auth_key_id_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        return res_map, err
}

var YangToDb_ntp_auth_key_type_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("bingbing YangToDb_ntp_auth_key_type_to_db_xfmr key ", inParams.key)

        pathInfo := NewPathInfo(inParams.uri)

        //key_type := pathInfo.Var("key-type")

        key_type, _ := inParams.param.(ocbinds.E_OpenconfigSystem_NTP_AUTH_TYPE)

        log.Infof(" bingbing YangToDb_ntp_auth_key_type_to_db_xfmr path vars %v key type %v", pathInfo.Var, key_type)

        //if (key_type == ocbinds.OpenconfigSystem_NTP_AUTH_TYPE_NTP_AUTH_MD5)
        //        res_map[NTP_KEY_TYPE] = "MD5"
        
        res_map[NTP_KEY_TYPE] = findInMap(NTP_AUTH_TYPE_MAP, strconv.FormatInt(int64(key_type), 10))

        log.Infof("bingbing YangToDb_ntp_auth_key_type_to_db_xfmr res_map %v", res_map)

        return res_map, err
}

var DbToYang_ntp_auth_key_type_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) { 
        res_map := make(map[string]interface{})
        var err error

        log.Infof("bingbing DbToYang_ntp_auth_key_type_xfmr key %v", inParams.key)

        data := (*inParams.dbDataMap)[inParams.curDb]
        key_tbl := data["NTP_AUTHENTICATION_KEY"]
        key_entry := key_tbl[inParams.key]
        key_type := findInMap(NTP_AUTH_TYPE_MAP, key_entry.Field[NTP_KEY_TYPE])
        var n int64
        n, err = strconv.ParseInt(key_type, 10, 64)
        if err == nil {
                res_map["key-type"] = ocbinds.E_OpenconfigSystem_NTP_AUTH_TYPE(n).ΛMap()["E_OpenconfigSystem_NTP_AUTH_TYPE"][n].Name
        }

        //if (key_type == "MD5")
        //        res_map["key-type"] = ocbinds.OpenconfigSystem_NTP_AUTH_TYPE_NTP_AUTH_MD5 

        log.Infof("bingbing DbToYang_ntp_auth_key_type_xfmr res_map %v", res_map) 
        return res_map, err
}

var DbToYang_ntp_auth_key_value_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        data := (*inParams.dbDataMap)[inParams.curDb]
        key_tbl := data["NTP_AUTHENTICATION_KEY"]
        key_entry := key_tbl[inParams.key]
        key_value := key_entry.Field["key_value"]

        res_map["key-value"] = key_value

        log.Infof("DbToYang_ntp_auth_key_value_xfmr res_map %v", res_map)

        return res_map, err 
}

var DbToYang_ntp_auth_encrypted_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        data := (*inParams.dbDataMap)[inParams.curDb]
        key_tbl := data["NTP_AUTHENTICATION_KEY"]
        key_entry := key_tbl[inParams.key]
        encrypted := key_entry.Field["key_encrypted"]

        encryptedBool,_ := strconv.ParseBool(encrypted)

        res_map["key-encrypted"] = encryptedBool

        log.Infof("DbToYang_ntp_auth_encrypted_xfmr res_map %v", res_map)

        return res_map, err
} 
