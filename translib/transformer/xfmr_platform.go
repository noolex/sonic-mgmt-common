//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Dell, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer

import (
    "bufio"
    "encoding/binary"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "math"
    "os"
    "strconv"
    "strings"
    "syscall"
    log "github.com/golang/glog"
)

const (
/** EEPROM type code
 * https://opencomputeproject.github.io/onie/design-spec/hw_requirements.html
 */
   BASE_MAC_KEY     = "0x24"
   CRC32_KEY        = "0xfe"
   DEV_VER_KEY      = "0x26"
   DIAG_VER_KEY     = "0x2e"
   LABEL_REV_KEY    = "0x27"
   MFT_CNT_KEY      = "0x2c"
   MFT_DATE_KEY     = "0x25"
   MFT_NAME_KEY     = "0x2b"
   NUM_MAC_KEY      = "0x2a"
   ONIE_VER_KEY     = "0x29"
   PART_NUM_KEY     = "0x22"
   PLAT_NAME_KEY    = "0x28"
   PROD_NAME_KEY    = "0x21"
   SERIAL_NUM_KEY   = "0x23"
   SERV_TAG_KEY     = "0x2f"
   VEND_EXT_KEY     = "0xfd"
   VEND_NAME_KEY    = "0x2d"
   /** END OF EEPROM type code **/

   EEPROM_TBL       = "EEPROM_INFO"
   PSU_TBL          = "PSU_INFO"
   FAN_TBL          = "FAN_INFO"
   TRANSCEIVER_TBL  = "TRANSCEIVER_INFO"
   PORT_TBL         = "PORT_TABLE"

   PORT_IF_NAME_PREFIX   = "Ethernet"
   ALIAS_IN_NAME_PREFIX  = "Eth"

   /** Valid System Components **/
   PSU1             = "PSU 1"
   PSU2             = "PSU 2"
   SYSEEPROM        = "System Eeprom"

   /** Supported oc-platform component state URIs **/
   COMP_STATE_DESCR           = "/openconfig-platform:components/component/state/description"
   COMP_STATE_EMPTY           = "/openconfig-platform:components/component/state/empty"
   COMP_STATE_HW_VER          = "/openconfig-platform:components/component/state/hardware-version"
   COMP_STATE_ID              = "/openconfig-platform:components/component/state/id"
   COMP_STATE_LOCATION        = "/openconfig-platform:components/component/state/location"
   COMP_STATE_MFG_DATE        = "/openconfig-platform:components/component/state/mfg-date"
   COMP_STATE_MFG_NAME        = "/openconfig-platform:components/component/state/mfg-name"
   COMP_STATE_NAME            = "/openconfig-platform:components/component/state/name"
   COMP_STATE_OPER_STATUS     = "/openconfig-platform:components/component/state/oper-status"
   COMP_STATE_PART_NO         = "/openconfig-platform:components/component/state/part-no"
   COMP_STATE_REMOVABLE       = "/openconfig-platform:components/component/state/removable"
   COMP_STATE_SERIAL_NO       = "/openconfig-platform:components/component/state/serial-no"
   COMP_STATE_SW_VER          = "/openconfig-platform:components/component/state/software-version"
   COMP_LED_STATUS             = "/openconfig-platform:components/component/state/openconfig-platform-ext:status-led"
   COMP_FANS                   = "/openconfig-platform:components/component/state/openconfig-platform-ext:fans"

   /** Supported Software component URIs **/
   SW_ASIC_VER                = "/openconfig-platform:components/component/openconfig-platform-ext:software/asic-version"
   SW_BUILD_COMMIT            = "/openconfig-platform:components/component/openconfig-platform-ext:software/build-commit"
   SW_BUILD_DATE              = "/openconfig-platform:components/component/openconfig-platform-ext:software/build-date"
   SW_BUILT_BY                = "/openconfig-platform:components/component/openconfig-platform-ext:software/built-by"
   SW_COMP                    = "/openconfig-platform:components/component/openconfig-platform-ext:software"
   SW_DIST_VER                = "/openconfig-platform:components/component/openconfig-platform-ext:software/distribution-version"
   SW_DOCKER_VER              = "/openconfig-platform:components/component/openconfig-platform-ext:software/docker-version"
   SW_HWSKU_VER               = "/openconfig-platform:components/component/openconfig-platform-ext:software/hwsku-version"
   SW_HW_VER                  = "/openconfig-platform:components/component/openconfig-platform-ext:software/hardware-version"
   SW_KERN_VER                = "/openconfig-platform:components/component/openconfig-platform-ext:software/kernel-version"
   SW_MFG_NAME                = "/openconfig-platform:components/component/openconfig-platform-ext:software/mfg-name"
   SW_PLAT_NAME               = "/openconfig-platform:components/component/openconfig-platform-ext:software/platform-name"
   SW_PROD_VER                = "/openconfig-platform:components/component/openconfig-platform-ext:software/product-version"
   SW_SERIAL_NUM              = "/openconfig-platform:components/component/openconfig-platform-ext:software/serial-number"
   SW_SW_VER                  = "/openconfig-platform:components/component/openconfig-platform-ext:software/software-version"
   SW_UP_TIME                 = "/openconfig-platform:components/component/openconfig-platform-ext:software/up-time"

   /** Supported System EEprom URIs **/
   SYS_EEPROM_BASE_MAC        = "/openconfig-platform:components/component/state/openconfig-platform-ext:base-mac-address"
   SYS_EEPROM_DIAG_VER        = "/openconfig-platform:components/component/state/openconfig-platform-ext:diag-version"
   SYS_EEPROM_MAC_ADDRS       = "/openconfig-platform:components/component/state/openconfig-platform-ext:mac-addresses"
   SYS_EEPROM_MFG_CNT         = "/openconfig-platform:components/component/state/openconfig-platform-ext:manufacture-country"
   SYS_EEPROM_ONIE_VER        = "/openconfig-platform:components/component/state/openconfig-platform-ext:onie-version"
   SYS_EEPROM_SERV_TAG        = "/openconfig-platform:components/component/state/openconfig-platform-ext:service-tag"
   SYS_EEPROM_VENDOR_NAME     = "/openconfig-platform:components/component/state/openconfig-platform-ext:vendor-name"

   /** Supported PSU URIs **/

   PSU_OUTPUT_CURRENT         = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-psu:output-current"
   PSU_OUTPUT_POWER           = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-psu:output-power"
   PSU_OUTPUT_VOLTAGE         = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-psu:output-voltage"

   /** Supported Fan URIs **/
   FAN_SPEED                  = "/openconfig-platform:components/component/fan/state/openconfig-platform-fan:speed"
   FAN_TARGET_SPEED           = "/openconfig-platform:components/component/fan/state/openconfig-platform-ext:target-speed"
   FAN_DIRECTION              = "/openconfig-platform:components/component/fan/state/openconfig-platform-ext:direction"

    /** Supported Xcvr URIs **/
    XCVR_FORM_FACTOR             = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-transceiver:form-factor"
    XCVR_DISPLAY_NAME            = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:display-name"
    XCVR_MEDIA_INTERFACE         = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:media-interface"
    XCVR_CABLE_TYPE              = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:cable-type"
    XCVR_CONNECTOR_TYPE          = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-transceiver:connector-type"
    XCVR_CABLE_LENGTH            = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:cable-length"
    XCVR_MAX_PORT_POWER          = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:max-port-power"
    XCVR_MAX_MODULE_POWER        = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:max-module-power"
    XCVR_VENDOR_NAME             = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-transceiver:vendor-name"
    XCVR_VENDOR_PART_NUMBER      = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-transceiver:vendor-part-number"
    XCVR_VENDOR_SERIAL_NUMBER    = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-transceiver:vendor-serial-number"
    XCVR_VENDOR_REVISION         = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-transceiver:vendor-revision"
    XCVR_VENDOR_DATE_CODE        = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-transceiver:vendor-date-code"

    XCVR_VENDOR_OUI              = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:vendor-oui"

    XCVR_LPMODE                  = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:lpmode"
    XCVR_MODULE_LANE_COUNT       = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:module-lane-count"
    XCVR_PRESENCE                = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:present"
    XCVR_QSA_ADAPTER_TYPE        = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:qsa-adapter-type"

)

/**
Structure Eeprom read from stateDb
*/

type Eeprom  struct {
    Base_MAC_Address    string
    Card_Type           string
    Device_Version      string
    Diag_Version        string
    Hardware_Version    string
    Label_Revision      string
    MAC_Addresses       int32
    Magic_Number        int32
    Manufacture_Country string
    Manufacture_Date    string
    Manufacturer        string
    Model_Name          string
    ONIE_Version        string
    Part_Number         string
    Platform_Name       string
    Product_Name        string
    Serial_Number       string
    Service_Tag         string
    Software_Version    string
    Vendor_Extension    string
    Vendor_Name         string
}

type PSU struct {
    Capacity            string
    Enabled             bool
    Fans                string
    Input_Current       string
    Input_Voltage       string
    Manufacturer        string
    Model_Name          string
    Output_Current      string
    Output_Power        string
    Output_Voltage      string
    Presence            bool
    Serial_Number       string
    Status              bool
    Status_Led          string
}

type Fan struct {
    Direction           string
    Model_Name          string
    Name                string
    Presence            bool
    Serial_Number       string
    Speed               string
    Speed_Tolerance     string
    Status              bool
    Status_Led          string
    Target_Speed        string
}

/* Most are strings since media sends 'N/A' when data is not available */
/* Conversion will be done before sending along */
type Xcvr struct {
    Presence                bool
    Form_Factor             string
    Display_Name            string
    Media_Interface         string
    Cable_Type              string
    Connector_Type          string
    Cable_Length            string
    Max_Port_Power          string
    Max_Module_Power        string

    Lpmode                  string
    Module_Lane_Count       string
    Qsa_Adapter_Type        string

    Vendor_Name             string
    Vendor_Part_Number      string
    Vendor_Serial_Number    string
    Vendor_Revision         string
    Vendor_Date_Code        string
    Vendor_OUI              string
}

var FAN_LST = []string {"FAN 1", "FAN 2", "FAN 3", "FAN 4", "FAN 5", "FAN 6", "FAN 7",
                     "FAN 8", "FAN 9", "FAN 10", "PSU 1 FAN 1", "PSU 2 FAN 1"}
var PSU_LST = []string {"PSU 1", "PSU 2"}

func init () {
    XlateFuncBind("DbToYang_pfm_components_xfmr", DbToYang_pfm_components_xfmr)
    XlateFuncBind("DbToYang_pfm_components_psu_xfmr", DbToYang_pfm_components_psu_xfmr)
    XlateFuncBind("DbToYang_pfm_components_fan_xfmr", DbToYang_pfm_components_fan_xfmr)
    XlateFuncBind("DbToYang_pfm_components_transceiver_xfmr", DbToYang_pfm_components_transceiver_xfmr)
}

func getPfmRootObject (s *ygot.GoStruct) (*ocbinds.OpenconfigPlatform_Components) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Components
}

var DbToYang_pfm_components_transceiver_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    pathInfo := NewPathInfo(inParams.uri)
    log.Infof("Received GET for PlatformApp Template: %s ,path: %s, vars: %v",
    pathInfo.Template, pathInfo.Path, pathInfo.Vars)

    if strings.Contains(inParams.requestUri, "/openconfig-platform:components") ||
        strings.Contains(inParams.requestUri, "/openconfig-platform:components/component/transceiver") {

        log.Info("inParams.Uri:",inParams.requestUri)
        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
        err := getSysXcvr(getPfmRootObject(inParams.ygRoot), targetUriPath, inParams.uri, inParams.dbs[db.StateDB])
        return err
    }

    return errors.New("Component not supported")
}

var DbToYang_pfm_components_psu_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    pathInfo := NewPathInfo(inParams.uri)
    log.Infof("Received GET for PlatformApp Template: %s ,path: %s, vars: %v",
    pathInfo.Template, pathInfo.Path, pathInfo.Vars)

    if strings.Contains(inParams.requestUri, "/openconfig-platform:components") ||
        strings.Contains(inParams.requestUri, "/openconfig-platform:components/component/power-supply") {

        log.Info("inParams.Uri:",inParams.requestUri)
        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
        err := getSysPsu(getPfmRootObject(inParams.ygRoot), targetUriPath, inParams.uri, inParams.dbs[db.StateDB])
        return err
    }

    return errors.New("Component not supported")
}

var DbToYang_pfm_components_fan_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    pathInfo := NewPathInfo(inParams.uri)
    log.Infof("Received GET for PlatformApp Template: %s ,path: %s, vars: %v",
    pathInfo.Template, pathInfo.Path, pathInfo.Vars)

    if strings.Contains(inParams.requestUri, "/openconfig-platform:components") ||
        strings.Contains(inParams.requestUri, "/openconfig-platform:components/component/fan") {

        log.Info("inParams.Uri:",inParams.requestUri)
        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
        err := getSysFans(getPfmRootObject(inParams.ygRoot), targetUriPath, inParams.uri, inParams.dbs[db.StateDB])
        return err
    }

    return errors.New("Component not supported")
}

var DbToYang_pfm_components_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    pathInfo := NewPathInfo(inParams.uri)
    log.Infof("Received GET for PlatformApp Template: %s ,path: %s, vars: %v",
    pathInfo.Template, pathInfo.Path, pathInfo.Vars)

    if strings.Contains(inParams.requestUri, "/openconfig-platform:components") {
        log.Info("inParams.Uri:",inParams.requestUri)
        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
        return getSysComponents(getPfmRootObject(inParams.ygRoot), targetUriPath, inParams.uri, inParams.dbs[db.StateDB])
    }
    return errors.New("Component not supported")
}

func getSoftwareVersion() string {
    var versionString string
    versionFile, err := os.Open("/etc/sonic/sonic_version.yml")
    if err != nil {
        log.Infof("sonic_version.yml open failed")
        return ""
    }
    defer versionFile.Close()
    versionScanner := bufio.NewScanner(versionFile)
    versionScanner.Split(bufio.ScanLines)

    for versionScanner.Scan() {
        if strings.Contains(versionScanner.Text(), "build_version:") {
            res1 := strings.Split(versionScanner.Text(), ": ")
            versionString = res1[1]
            break
        }
    }
    versionFile.Close()

    return versionString
}

func getSoftwareVersionComponent (swComp *ocbinds.OpenconfigPlatform_Components_Component_Software, targetUriPath string, allAttr bool, d *db.DB) (error) {

    versionScanner := bufio.NewScanner(strings.NewReader(""))
    scanner := bufio.NewScanner(strings.NewReader(""))
    var eepromInfo Eeprom
    var err error

    if allAttr == true || targetUriPath == SW_COMP || targetUriPath == SW_DIST_VER || targetUriPath == SW_KERN_VER ||
       targetUriPath == SW_BUILD_COMMIT || targetUriPath == SW_ASIC_VER || targetUriPath == SW_BUILD_DATE ||
       targetUriPath == SW_BUILT_BY || targetUriPath == SW_SW_VER{
        swVersionFile, err := os.Open("/etc/sonic/sonic_version.yml")
        if err != nil {
            log.Infof("sonic_version.yml open failed")
            errStr := "Information not available or Not supported"
            return tlerr.NotFoundError{Format: errStr}
        }
        defer swVersionFile.Close()
        versionScanner = bufio.NewScanner(swVersionFile)
        versionScanner.Split(bufio.ScanLines)
    }

    if allAttr == true || targetUriPath == SW_COMP || targetUriPath == SW_HWSKU_VER || targetUriPath == SW_HW_VER ||
       targetUriPath == SW_PLAT_NAME || targetUriPath == COMP_STATE_SERIAL_NO || targetUriPath == SW_MFG_NAME {
        eepromInfo, err = getSysEepromFromDb(d)
        if err != nil {
            return err
        }
    }

    if allAttr == true || targetUriPath == SW_COMP || targetUriPath == SW_DOCKER_VER {
        var query_result HostResult
        query_result = HostQuery("docker_version.action", "")
        if query_result.Err != nil {
            log.Infof("Error in Calling dbus fetch_environment %v", query_result.Err)
            return query_result.Err
        }
        env_op := query_result.Body[1].(string)
        scanner = bufio.NewScanner(strings.NewReader(env_op))
    }

    if allAttr == true || targetUriPath == SW_COMP {
        for versionScanner.Scan() {
            if strings.Contains(versionScanner.Text(), "build_version:") {
                res1 := strings.Split(versionScanner.Text(), ": ")
                swComp.SoftwareVersion = &res1[1]
                continue
            }
            if strings.Contains(versionScanner.Text(), "debian_version:") {
            res1 := strings.Split(versionScanner.Text(), ": ")
            swComp.DistributionVersion = &res1[1]
            continue
            }
            if strings.Contains(versionScanner.Text(), "kernel_version:") {
                res1 := strings.Split(versionScanner.Text(), ": ")
                swComp.KernelVersion = &res1[1]
                continue
            }
            if strings.Contains(versionScanner.Text(), "asic_type:") {
                res1 := strings.Split(versionScanner.Text(), ": ")
                swComp.AsicVersion = &res1[1]
                continue
            }
            if strings.Contains(versionScanner.Text(), "commit_id:") {
                res1 := strings.Split(versionScanner.Text(), ": ")
                swComp.BuildCommit = &res1[1]
                continue
            }
            if strings.Contains(versionScanner.Text(), "build_date:") {
                res1 := strings.Split(versionScanner.Text(), ": ")
                swComp.BuildDate = &res1[1]
                continue
            }
            if strings.Contains(versionScanner.Text(), "built_by:") {
                res1 := strings.Split(versionScanner.Text(), ": ")
                swComp.BuiltBy = &res1[1]
                continue
            }

        }

        if eepromInfo.Platform_Name != "" {
            swComp.PlatformName = &eepromInfo.Platform_Name
        }
        if eepromInfo.Product_Name != "" && eepromInfo.Vendor_Name != ""{
            HwskuVer := eepromInfo.Product_Name + "-" + eepromInfo.Vendor_Name
            swComp.HwskuVersion = &HwskuVer
        }
        if eepromInfo.Label_Revision != "" {
            swComp.HardwareVersion = &eepromInfo.Label_Revision
        }
        if eepromInfo.Serial_Number != "" {
            swComp.SerialNumber = &eepromInfo.Serial_Number
        }
        if eepromInfo.Vendor_Name != "" {
            swComp.MfgName = &eepromInfo.Vendor_Name
        }

        info := syscall.Sysinfo_t{}
        err = syscall.Sysinfo(&info)

        if err != nil {
        }
        uptimeSec := info.Uptime
        days := uptimeSec / (60 * 60 * 24)
        hours := (uptimeSec - (days * 60 * 60 * 24)) / (60 * 60)
        minutes := ((uptimeSec - (days * 60 * 60 * 24))  -  (hours * 60 * 60)) / 60
        uptime := strconv.FormatInt(days,10) +" days "+strconv.FormatInt(hours,10)+ " hours "+strconv.FormatInt(minutes,10)+" minutes"
        swComp.UpTime = &uptime

        for scanner.Scan() {
            var pf_docker_ver *ocbinds.OpenconfigPlatform_Components_Component_Software_Docker_DockerVersion
            s := strings.Fields(scanner.Text())
            pf_docker_ver, _ = swComp.Docker.NewDockerVersion(scanner.Text())
            if pf_docker_ver == nil {
                /* If DockerVersion list with key already exist,
                 * then reuse it
                 */
                pf_docker_ver = swComp.Docker.DockerVersion[scanner.Text()]
            }
            ygot.BuildEmptyTree(pf_docker_ver)
            pf_docker_ver.DockerName = &s[0]
            pf_docker_ver.DockerTagId = &s[1]
            pf_docker_ver.DockerImageId = &s[2]
            pf_docker_ver.DockerSize = &s[3]
        }
    } else {
        switch targetUriPath {
        case SW_SW_VER:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "build_version:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.SoftwareVersion = &res1[1]
                    break
                }
            }
        case SW_DIST_VER:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "debian_version:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.DistributionVersion = &res1[1]
                    break
                }
            }
        case SW_KERN_VER:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "kernel_version:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.KernelVersion = &res1[1]
                    break
                }
            }
        case SW_ASIC_VER:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "asic_type:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.AsicVersion = &res1[1]
                    break
                }
            }
        case SW_BUILD_COMMIT:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "commit_id:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.BuildCommit = &res1[1]
                    break
                }
            }
        case SW_BUILD_DATE:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "build_date:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.BuildDate = &res1[1]
                    break
                }
            }
        case SW_BUILT_BY:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "built_by:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.BuiltBy = &res1[1]
                    break
                }
            }
        case SW_PLAT_NAME:
            if eepromInfo.Platform_Name != "" {
                swComp.PlatformName = &eepromInfo.Platform_Name
            }
        case SW_HWSKU_VER:
            if eepromInfo.Product_Name != "" && eepromInfo.Vendor_Name != ""{
                HwskuVer := eepromInfo.Product_Name + "-" + eepromInfo.Vendor_Name
                swComp.HwskuVersion = &HwskuVer
            }
        case SW_HW_VER:
            if eepromInfo.Label_Revision != "" {
                swComp.HardwareVersion = &eepromInfo.Label_Revision
            }
        case COMP_STATE_SERIAL_NO:
            if eepromInfo.Serial_Number != "" {
                swComp.SerialNumber = &eepromInfo.Serial_Number
            }
        case SW_MFG_NAME:
            if eepromInfo.Vendor_Name != "" {
                swComp.MfgName = &eepromInfo.Vendor_Name
            }
        case SW_UP_TIME:
            info := syscall.Sysinfo_t{}
            err = syscall.Sysinfo(&info)

            if err != nil {
            }
            uptimeSec := info.Uptime
            days := uptimeSec / (60 * 60 * 24)
            hours := (uptimeSec - (days * 60 * 60 * 24)) / (60 * 60)
            minutes := ((uptimeSec - (days * 60 * 60 * 24))  -  (hours * 60 * 60)) / 60
            uptime := strconv.FormatInt(days,10) +" days "+strconv.FormatInt(hours,10)+ " hours "+strconv.FormatInt(minutes,10)+" minutes"
            swComp.UpTime = &uptime
        case SW_DOCKER_VER:
            for scanner.Scan() {
                var pf_docker_ver *ocbinds.OpenconfigPlatform_Components_Component_Software_Docker_DockerVersion
                s := strings.Fields(scanner.Text())
                pf_docker_ver,_ = swComp.Docker.NewDockerVersion(scanner.Text())
                if pf_docker_ver == nil {
                    /* If DockerVersion list with key already exist,
                     * then reuse it
                     */
                    pf_docker_ver = swComp.Docker.DockerVersion[scanner.Text()]
                }
                ygot.BuildEmptyTree(pf_docker_ver)
                pf_docker_ver.DockerName = &s[0]
                pf_docker_ver.DockerTagId = &s[1]
                pf_docker_ver.DockerImageId = &s[2]
                pf_docker_ver.DockerSize = &s[3]
            }
        default:
            log.Infof("Attribute not found")
        }
    }
    return nil
}

func getSysEepromFromDb (d *db.DB) (Eeprom, error) {
    var eepromInfo Eeprom
    var err error
    var typeCode string
    var entryVal string

    eepromTbl, err := d.GetTable(&db.TableSpec{Name: EEPROM_TBL})
    if err != nil {
        log.Info("Can't get table: ", EEPROM_TBL)
        return eepromInfo, err
    }

    keys, err := eepromTbl.GetKeys()
    if err != nil {
        log.Info("Can't get keys from table")
        return eepromInfo, err
    }

    for _, key := range keys {
        typeCode = key.Get(0)
        eepromEntry, err := eepromTbl.GetEntry(db.Key{Comp: []string{typeCode}})
        if err != nil {
            log.Info("Can't get entry with key: ", typeCode)
            return eepromInfo, err
        }

        entryVal = eepromEntry.Get("Value")
        switch typeCode {
        case PROD_NAME_KEY:
            eepromInfo.Product_Name = entryVal
            break
        case PART_NUM_KEY:
            eepromInfo.Part_Number = entryVal
            break
        case SERIAL_NUM_KEY:
            eepromInfo.Serial_Number = entryVal
            break
        case BASE_MAC_KEY:
            eepromInfo.Base_MAC_Address = entryVal
            break
        case MFT_DATE_KEY:
            eepromInfo.Manufacture_Date = entryVal
            break
        case DEV_VER_KEY:
            eepromInfo.Device_Version = entryVal
            break
        case LABEL_REV_KEY:
            eepromInfo.Label_Revision = entryVal
            break
        case PLAT_NAME_KEY:
            eepromInfo.Platform_Name = entryVal
            break
        case ONIE_VER_KEY:
            eepromInfo.ONIE_Version = entryVal
            break
        case NUM_MAC_KEY:
            tmp,  _ := strconv.Atoi(entryVal)
            eepromInfo.MAC_Addresses = int32(tmp)
            break
        case MFT_NAME_KEY:
            eepromInfo.Manufacturer = entryVal
            break
        case MFT_CNT_KEY:
            eepromInfo.Manufacture_Country = entryVal
            break
        case VEND_NAME_KEY:
            eepromInfo.Vendor_Name = entryVal
            break
        case DIAG_VER_KEY:
            eepromInfo.Diag_Version = entryVal
            break
        case SERV_TAG_KEY:
            eepromInfo.Service_Tag = entryVal
            break
        case VEND_EXT_KEY:
            eepromInfo.Vendor_Extension = entryVal
            break
        case CRC32_KEY:
        default:
            break
        }
    }

    return eepromInfo, err
}

func fillSysEepromInfo (eeprom *ocbinds.OpenconfigPlatform_Components_Component_State,
                                 all bool, targetUriPath string, d *db.DB) (error) {

    log.Infof("fillSysEepromInfo Enter")
    eepromInfo, err := getSysEepromFromDb(d)
    if err != nil {
        return err
    }

    empty := false
    removable := false
    name := "System Eeprom"
    location  :=  "Slot 1"

    if all == true {
        eeprom.Empty = &empty
        eeprom.Removable = &removable
        eeprom.Name = &name
        eeprom.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        eeprom.Location = &location

        if eepromInfo.Product_Name != "" {
            eeprom.Id = &eepromInfo.Product_Name
        }
        if eepromInfo.Part_Number != "" {
            eeprom.PartNo = &eepromInfo.Part_Number
        }
        if eepromInfo.Serial_Number != "" {
            eeprom.SerialNo = &eepromInfo.Serial_Number
        }
        if eepromInfo.Base_MAC_Address != "" {
            eeprom.BaseMacAddress = &eepromInfo.Base_MAC_Address
        }
        if eepromInfo.Manufacture_Date != "" {
            mfg_date := eepromInfo.Manufacture_Date[6:10] + "-" +
                eepromInfo.Manufacture_Date[0:2] + "-" + eepromInfo.Manufacture_Date[3:5]
            eeprom.MfgDate = &mfg_date
        }
        if eepromInfo.Label_Revision != "" {
            eeprom.HardwareVersion = &eepromInfo.Label_Revision
        }
        if eepromInfo.Platform_Name != "" {
            eeprom.Description = &eepromInfo.Platform_Name
        }
        if eepromInfo.ONIE_Version != "" {
            eeprom.OnieVersion = &eepromInfo.ONIE_Version
        }
        if eepromInfo.MAC_Addresses != 0 {
            eeprom.MacAddresses = &eepromInfo.MAC_Addresses
        }
        if eepromInfo.Manufacturer != "" {
            eeprom.MfgName = &eepromInfo.Manufacturer
        }
        if eepromInfo.Manufacture_Country != "" {
            eeprom.ManufactureCountry = &eepromInfo.Manufacture_Country
        }
        if eepromInfo.Vendor_Name != "" {
            eeprom.VendorName = &eepromInfo.Vendor_Name
        }
        if eepromInfo.Diag_Version != "" {
            eeprom.DiagVersion = &eepromInfo.Diag_Version
        }
        if eepromInfo.Service_Tag != "" {
            if eeprom.SerialNo == nil {
                eeprom.SerialNo = &eepromInfo.Service_Tag
            }
            eeprom.ServiceTag = &eepromInfo.Service_Tag
        }
        if eepromInfo.Hardware_Version != "" {
            eeprom.HardwareVersion = &eepromInfo.Hardware_Version
        }
        if eepromInfo.Software_Version != "" {
            eeprom.SoftwareVersion = &eepromInfo.Software_Version
        } else {
            versionString := getSoftwareVersion()
            eeprom.SoftwareVersion = &versionString
        }
    } else {
        switch targetUriPath {
        case COMP_STATE_NAME:
            eeprom.Name = &name
        case COMP_STATE_LOCATION:
            eeprom.Location = &location
        case COMP_STATE_EMPTY:
            eeprom.Empty = &empty
        case COMP_STATE_REMOVABLE:
            eeprom.Removable = &removable
        case COMP_STATE_OPER_STATUS:
            eeprom.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        case COMP_STATE_ID:
            if eepromInfo.Product_Name != "" {
                eeprom.Id = &eepromInfo.Product_Name
            }
        case COMP_STATE_PART_NO:
            if eepromInfo.Part_Number != "" {
                eeprom.PartNo = &eepromInfo.Part_Number
            }
        case COMP_STATE_SERIAL_NO:
            if eepromInfo.Serial_Number != "" {
                eeprom.SerialNo = &eepromInfo.Serial_Number
            }
            if eepromInfo.Service_Tag != "" {
                if eeprom.SerialNo == nil || *eeprom.SerialNo == "" {
                    eeprom.SerialNo = &eepromInfo.Service_Tag
                }
            }
        case COMP_STATE_MFG_DATE:
            if eepromInfo.Manufacture_Date != "" {
                mfg_date := eepromInfo.Manufacture_Date[6:10] + "-" +
                    eepromInfo.Manufacture_Date[0:2] + "-" + eepromInfo.Manufacture_Date[3:5]
                eeprom.MfgDate = &mfg_date
            }
        case COMP_STATE_HW_VER:
            if eepromInfo.Label_Revision != "" {
                eeprom.HardwareVersion = &eepromInfo.Label_Revision
            }
            if eepromInfo.Hardware_Version != "" {
                if eeprom.HardwareVersion == nil || *eeprom.HardwareVersion == "" {
                    eeprom.HardwareVersion = &eepromInfo.Hardware_Version
                }
            }
        case COMP_STATE_DESCR:
            if eepromInfo.Platform_Name != "" {
                eeprom.Description = &eepromInfo.Platform_Name
            }
        case COMP_STATE_MFG_NAME:
            if eepromInfo.Manufacturer != "" {
                eeprom.MfgName = &eepromInfo.Manufacturer
            }
            if eepromInfo.Vendor_Name != "" {
                if eeprom.MfgName == nil || *eeprom.MfgName == "" {
                    eeprom.MfgName = &eepromInfo.Vendor_Name
                }
            }
        case COMP_STATE_SW_VER:
            if eepromInfo.Software_Version != "" {
                eeprom.SoftwareVersion = &eepromInfo.Software_Version
            } else {
                versionString := getSoftwareVersion()
                eeprom.SoftwareVersion = &versionString
            }
        case SYS_EEPROM_MFG_CNT:
            if eepromInfo.Manufacture_Country != "" {
                eeprom.ManufactureCountry = &eepromInfo.Manufacture_Country
            }
        case SYS_EEPROM_BASE_MAC:
            if eepromInfo.Base_MAC_Address != "" {
                eeprom.BaseMacAddress = &eepromInfo.Base_MAC_Address
            }
        case SYS_EEPROM_ONIE_VER:
            if eepromInfo.ONIE_Version != "" {
                eeprom.OnieVersion = &eepromInfo.ONIE_Version
            }
        case SYS_EEPROM_MAC_ADDRS:
            if eepromInfo.MAC_Addresses != 0 {
                eeprom.MacAddresses = &eepromInfo.MAC_Addresses
            }
        case SYS_EEPROM_VENDOR_NAME:
            if eepromInfo.Vendor_Name != "" {
                eeprom.VendorName = &eepromInfo.Vendor_Name
            }
        case SYS_EEPROM_DIAG_VER:
            if eepromInfo.Diag_Version != "" {
                eeprom.DiagVersion = &eepromInfo.Diag_Version
            }
        case SYS_EEPROM_SERV_TAG:
            if eepromInfo.Service_Tag != "" {
                if eeprom.SerialNo == nil {
                    eeprom.SerialNo = &eepromInfo.Service_Tag
                }
                eeprom.ServiceTag = &eepromInfo.Service_Tag
            }
        default:
            break
        }
    }
    return nil
}

func getPlatformEnvironment (pf_comp *ocbinds.OpenconfigPlatform_Components_Component) (error) {
    var err error
    var query_result HostResult

    query_result = HostQuery("fetch_environment.action", "")
    if query_result.Err != nil {
        log.Infof("Error in Calling dbus fetch_environment %v", query_result.Err)
    }
    env_op := query_result.Body[1].(string)
    scanner := bufio.NewScanner(strings.NewReader(env_op))
    for scanner.Scan() {
        var pf_sensor_cat *ocbinds.OpenconfigPlatform_Components_Component_Subcomponents_Subcomponent_State_SensorCategory
        log.Infof("comp: %s",scanner.Text())
        if strings.Contains(scanner.Text(), "Total Power") {
            continue
        }

        SubCatFound := false
        pf_scomp, perr := pf_comp.Subcomponents.NewSubcomponent(scanner.Text())
        if pf_scomp == nil {
            pf_scomp = pf_comp.Subcomponents.Subcomponent[scanner.Text()]
            if pf_scomp == nil {
                return perr
            }
        }
        ygot.BuildEmptyTree(pf_scomp)

        scanner.Scan()
        for scanner.Text() != "" {
            s := strings.Split(scanner.Text(), ":")
            if !SubCatFound || s[1] == "" {
                log.Infof("scomp: %s",scanner.Text())
                pf_sensor_cat, perr = pf_scomp.State.NewSensorCategory(scanner.Text())
                if pf_sensor_cat == nil {
                    pf_sensor_cat = pf_scomp.State.SensorCategory[scanner.Text()]
                    if pf_sensor_cat == nil {
                        return perr
                    }
                }
                ygot.BuildEmptyTree(pf_sensor_cat)
                SubCatFound = true
            } else {
                val := s[1]
                name := s[0]
                pf_sensor,_ := pf_sensor_cat.Sensors.NewSensor(name)
                if pf_sensor == nil {
                    pf_sensor = pf_sensor_cat.Sensors.Sensor[name]
                    if pf_sensor == nil {
                        return errors.New("Can't find component")
                    }
                }
                ygot.BuildEmptyTree(pf_sensor)
                pf_sensor.State.State = &val
            }
            scanner.Scan()
        }
    }

    return  err
}

func getSysComponents(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Infof("Preparing dB for system eeprom");

    var err error
    log.Info("targetUriPath:", targetUriPath)
    switch targetUriPath {
    case "/openconfig-platform:components/component":
        compName := NewPathInfo(uri).Var("name")
        matchStr := strings.ToLower(compName)
        log.Infof("compName: %v", compName)
        if compName == "" {
            /* All valid media interfaces as normal naming EthernetX */
            intfNames := getPhysicalIntfNames(d)
            for _, intf := range intfNames{
                if utils.IsAliasModeEnabled(){
                    intf = *(utils.GetUINameFromNativeName(&intf))
                }
                pf_comp, _ := pf_cpts.NewComponent(intf)

                ygot.BuildEmptyTree(pf_comp)
                fillSysXcvrInfo(pf_comp, intf, true, targetUriPath, d)
            }

            sensor_comp,_  := pf_cpts.NewComponent("Sensor")
            ygot.BuildEmptyTree(sensor_comp)
            sensor_comp.State.Type,_ = sensor_comp.State.To_OpenconfigPlatform_Components_Component_State_Type_Union(
                                ocbinds.OpenconfigPlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_SENSOR)
            err = getPlatformEnvironment(sensor_comp)
            if err != nil {
                return err
            }

            pf_comp,_ := pf_cpts.NewComponent("System Eeprom")
            ygot.BuildEmptyTree(pf_comp)
            err = fillSysEepromInfo(pf_comp.State, true, targetUriPath, d)
            if err != nil {
                return err
            }

            swversion_comp,_ := pf_cpts.NewComponent("Software")
            ygot.BuildEmptyTree(swversion_comp)
            err = getSoftwareVersionComponent(swversion_comp.Software, targetUriPath, true, d)
            if err != nil {
                return err
            }

            for _, psu := range PSU_LST {
                pf_comp, _ = pf_cpts.NewComponent(psu)
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysPsuInfo(pf_comp, psu, true, true, targetUriPath, d)
                if err != nil {
                    return err
                }
                err = fillSysPsuInfo(pf_comp, psu, true, false, targetUriPath, d)
                if err != nil {
                    return err
                }
            }


            for _, fan := range FAN_LST {
                pf_comp, _ = pf_cpts.NewComponent(fan)
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysFanInfo(pf_comp, fan, true, true, targetUriPath, d)
                if err != nil {
                    return err
                }
                err = fillSysFanInfo(pf_comp, fan, true, false, targetUriPath, d)
                if err != nil {
                    return err
                }
            }
            return err
        } else {
            if matchStr == "system eeprom" {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    err = fillSysEepromInfo(pf_comp.State, true, targetUriPath, d)
                    if err != nil {
                        return err
                    }
                } else {
                    err = errors.New("Invalid input component name")
                }
            } else if matchStr == "sensor" {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    err = getPlatformEnvironment(pf_comp)
                    if err != nil {
                        return err
                    }
                } else {
                    err = errors.New("Invalid input component name")
                }
            } else if matchStr == "software" {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    err = getSoftwareVersionComponent(pf_comp.Software, targetUriPath, true, d)
                    if err != nil {
                        return err
                    }
                } else {
                    err = errors.New("Invalid input component name")
                }
            } else if validPsuName(&compName) {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                fillSysPsuInfo(pf_comp, compName, true, false, targetUriPath, d)
            } else if validFanName(&compName) {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                fillSysFanInfo(pf_comp, compName, true, false, targetUriPath, d)
            } else if validXcvrName(&compName){
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                fillSysXcvrInfo(pf_comp, compName, true, targetUriPath, d)
            } else {
                err = errors.New("Invalid component name")
            }
        }
    case "/openconfig-platform:components/component/state":
        compName := NewPathInfo(uri).Var("name")
        if compName == "" {
            err = errors.New("Invalid component name ")
            break
        }

        matchStr := strings.ToLower(compName)
        if matchStr == "system eeprom" {
            pf_comp := pf_cpts.Component[compName]
            if pf_comp != nil {
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysEepromInfo(pf_comp.State, true, targetUriPath, d)
                if err != nil {
                    return err
                }
            } else {
                err = errors.New("Invalid input component name")
            }
        } else if matchStr == "sensor" {
            pf_comp := pf_cpts.Component[compName]
            if pf_comp != nil {
                ygot.BuildEmptyTree(pf_comp)
                err = getPlatformEnvironment(pf_comp)
                if err != nil {
                    return err
                }
            } else {
                err = errors.New("Invalid input component name")
            }
        } else if validPsuName(&compName) {
          pf_comp := pf_cpts.Component[compName]
          if pf_comp  == nil {
              log.Info("Invalid Component Name")
              return errors.New("Invalid component name")
          }
          ygot.BuildEmptyTree(pf_comp)
          fillSysPsuInfo(pf_comp, compName, true, false, targetUriPath, d)
        } else if validFanName(&compName) {
          pf_comp := pf_cpts.Component[compName]
          if pf_comp  == nil {
              log.Info("Invalid Component Name")
              return errors.New("Invalid component name")
          }
          ygot.BuildEmptyTree(pf_comp)
          fillSysFanInfo(pf_comp, compName, true, false, targetUriPath, d)
        } else if validXcvrName(&compName){
            pf_comp := pf_cpts.Component[compName]
            if pf_comp  == nil {
                log.Info("Invalid Component Name")
                return errors.New("Invalid component name")
            }
            ygot.BuildEmptyTree(pf_comp)
            fillSysXcvrInfo(pf_comp, compName, true, targetUriPath, d)
        } else {
            err = errors.New("Invalid component name ")
        }

    default:
        if strings.Contains(targetUriPath, "/openconfig-platform:components/component") {
            compName := NewPathInfo(uri).Var("name")
            if compName == "" {
                err = errors.New("Invalid component name ")
                break
            }

            matchStr := strings.ToLower(compName)
            if matchStr == "system eeprom" {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    err = fillSysEepromInfo(pf_comp.State, false, targetUriPath, d)
                    if err != nil {
                        return err
                    }
                } else {
                    err = errors.New("Invalid input component name")
                }
            } else if matchStr == "software" {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    err = getSoftwareVersionComponent(pf_comp.Software, targetUriPath, false, d)
                    if err != nil {
                        return err
                    }
                } else {
                    err = errors.New("Invalid input component name")
                }
            } else if validPsuName(&compName) {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    ygot.BuildEmptyTree(pf_comp.State)
                    err = fillSysPsuInfo(pf_comp, compName, false, false, targetUriPath, d)
                } else {
                    err = errors.New("Unable to locate component")
                }
            } else if validFanName(&compName) {
              pf_comp := pf_cpts.Component[compName]
              if pf_comp  == nil {
                  log.Info("Invalid Component Name")
                  return errors.New("Invalid component name")
              }
              ygot.BuildEmptyTree(pf_comp)
              fillSysFanInfo(pf_comp, compName, true, false, targetUriPath, d)
            } else if validXcvrName(&compName){
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                fillSysXcvrInfo(pf_comp, compName, true, targetUriPath, d)
            } else {
                err = errors.New("Invalid input component name")
            }
        } else {
            err = errors.New("Invalid Path")
        }
    }
    return err
}

func float32StrTo4Bytes(s string) ([]byte, error) {
    var data []byte
    float64val, err := strconv.ParseFloat(s, 32)
    if err != nil {
        log.Info("Error converting string to float32")
        return data, err
    }
    data = make([]byte, 4)
    /* Using Big Endian (network-order) to pack and unpack data
     * IMPORTANT: REST server will do a b64 encode before sending the output
     */
    binary.BigEndian.PutUint32(data, math.Float32bits(float32(float64val)))
    return data, err
}

func getSysPsuFromDb (name string, d *db.DB) (PSU, error) {
    var psuInfo PSU
    var err error

    psuEntry, err := d.GetEntry(&db.TableSpec{Name: PSU_TBL}, db.Key{Comp: []string{name}})
    if err != nil {
        log.Info("Cant get entry: ", name)
    }

    psuInfo.Enabled = false
    if psuEntry.Get("status") == "true" {
        psuInfo.Enabled = true
    }

    psuInfo.Output_Current = psuEntry.Get("output_current")
    psuInfo.Output_Voltage = psuEntry.Get("output_voltage")
    psuInfo.Output_Power = psuEntry.Get("output_power")

    psuInfo.Presence = false
    if psuEntry.Get("presence") == "true" {
        psuInfo.Presence = true
    }

    psuInfo.Status = false
    if psuEntry.Get("status") == "true" {
        psuInfo.Status = true
    }

    psuInfo.Model_Name = psuEntry.Get("model")
    psuInfo.Manufacturer = psuEntry.Get("mfr_id")
    psuInfo.Serial_Number = psuEntry.Get("serial")
    psuInfo.Fans = psuEntry.Get("num_fans")
    psuInfo.Status_Led = psuEntry.Get("status_led")
    return psuInfo, err
}

func fillSysPsuInfo (psuCom *ocbinds.OpenconfigPlatform_Components_Component,
                        name string, all bool, getPowerStats bool, targetUriPath string, d *db.DB) (error) {
    var err error
    psuInfo, err := getSysPsuFromDb(name, d)
    if err != nil {
        log.Info("Error Getting PSU info from dB")
        return err
    }

    empty := !psuInfo.Presence
    psuState := psuCom.PowerSupply.State
    psuEepromState := psuCom.State
    if all {
        if getPowerStats {
            if psuInfo.Output_Current != "" {
                psuState.OutputCurrent, err = float32StrTo4Bytes(psuInfo.Output_Current)
            }
            if psuInfo.Output_Voltage != "" {
                psuState.OutputVoltage, err = float32StrTo4Bytes(psuInfo.Output_Voltage)
            }
            if psuInfo.Output_Power != "" {
                psuState.OutputPower, err = float32StrTo4Bytes(psuInfo.Output_Power)
            }

            if err != nil {
                log.Info("float data error")
                return err
            }
            return err
        }

        psuEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_INACTIVE
        if psuInfo.Status {
            psuEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        }

        if psuInfo.Model_Name != "" {
            psuEepromState.Description = &psuInfo.Model_Name
        }
        if psuInfo.Manufacturer != "" {
            psuEepromState.MfgName = &psuInfo.Manufacturer
        }
        if psuInfo.Serial_Number != "" {
            psuEepromState.SerialNo = &psuInfo.Serial_Number
        }
        if psuInfo.Fans != "" {
            tmp, _ := strconv.ParseUint(psuInfo.Fans, 10, 32)
            fans := uint32(tmp)
            psuEepromState.Fans = &fans
        }
        if psuInfo.Status_Led != "" {
            psuEepromState.StatusLed = &psuInfo.Status_Led
        }

        return err
    }

    switch targetUriPath {
    case PSU_OUTPUT_CURRENT:
        if psuInfo.Output_Current != "" {
            psuState.OutputCurrent, err = float32StrTo4Bytes(psuInfo.Output_Current)
        }
    case PSU_OUTPUT_VOLTAGE:
        if psuInfo.Output_Voltage != ""{
            psuState.OutputVoltage, err = float32StrTo4Bytes(psuInfo.Output_Voltage)
        }
    case PSU_OUTPUT_POWER:
        if psuInfo.Output_Power != "" {
            psuState.OutputPower, err = float32StrTo4Bytes(psuInfo.Output_Power)
        }
    case COMP_LED_STATUS:
        if psuInfo.Status_Led != "" {
            psuEepromState.StatusLed = &psuInfo.Status_Led
        }
    case COMP_FANS:
        if psuInfo.Fans != "" {
            tmp, _ := strconv.ParseUint(psuInfo.Fans, 10, 32)
            fans := uint32(tmp)
            psuEepromState.Fans = &fans
        }
    case COMP_STATE_EMPTY:
        psuEepromState.Empty = &empty
    case COMP_STATE_OPER_STATUS:
        psuEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_INACTIVE
        if psuInfo.Status {
            psuEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        }
    case COMP_STATE_SERIAL_NO:
        if psuInfo.Serial_Number != "" {
            psuEepromState.SerialNo = &psuInfo.Serial_Number
        }
    case COMP_STATE_DESCR:
        if psuInfo.Model_Name != "" {
            psuEepromState.Description = &psuInfo.Model_Name
        }
    case COMP_STATE_MFG_NAME:
        if psuInfo.Manufacturer != "" {
            psuEepromState.MfgName = &psuInfo.Manufacturer
        }
    }

    return err
}

func validPsuName(name *string) bool {
    if name == nil || *name == "" {
        return false
    }
    tmp := strings.ToUpper(*name)
    for _ , psu := range PSU_LST {
        if tmp == psu {
            return true
        }
    }
    return false
}

func getSysPsu(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Info("Preparing dB for PSU info");

    var err error
    log.Info("targetUriPath:", targetUriPath)
    psuName := NewPathInfo(uri).Var("name")

    if validPsuName(&psuName) {
        psuCom := pf_cpts.Component[psuName]
        if psuCom  == nil {
            log.Info("Invalid Component Name")
            return errors.New("Invalid component name")
        }
        ygot.BuildEmptyTree(psuCom)
        ygot.BuildEmptyTree(psuCom.PowerSupply)
        ygot.BuildEmptyTree(psuCom.PowerSupply.State)
        switch targetUriPath {
        case "/openconfig-platform:components/component":
            fallthrough
        case "/openconfig-platform:components/component/power-supply":
            fallthrough
        case "/openconfig-platform:components/component/power-supply/state":
            fillSysPsuInfo(psuCom, psuName, true, true, targetUriPath, d)
        default:
            fillSysPsuInfo(psuCom, psuName, false, true, targetUriPath, d)
            break
        }
    }
    return err
}

func validFanName(name *string) (bool) {
    if name == nil || *name == "" {
        return false
    }
    tmp := strings.ToUpper(*name)
    for _ , fan := range FAN_LST {
        if tmp == fan {
            return true
        }
    }
    return false
}

func getSysFanFromDb(name string, d *db.DB) (Fan, error) {
    var fanInfo Fan
    var err error

    fanEntry, err := d.GetEntry(&db.TableSpec{Name: FAN_TBL}, db.Key{Comp: []string{name}})

    if err != nil {
        log.Info("Cant get entry: ", name)
    }


    fanInfo.Direction = fanEntry.Get("direction")
    fanInfo.Name = fanEntry.Get("name")
    fanInfo.Speed = fanEntry.Get("speed")
    fanInfo.Speed_Tolerance = fanEntry.Get("speed_tolerance")
    fanInfo.Target_Speed = fanEntry.Get("target_speed")

    fanInfo.Presence = false
    if fanEntry.Get("presence") == "true" {
        fanInfo.Presence = true
    }

    fanInfo.Status = false
    if fanEntry.Get("status") == "true" {
        fanInfo.Status = true
    }

    fanInfo.Model_Name = fanEntry.Get("model")
    fanInfo.Serial_Number = fanEntry.Get("serial")
    fanInfo.Status_Led = fanEntry.Get("status_led")

    return fanInfo, err
}

func fillSysFanInfo (psuCom *ocbinds.OpenconfigPlatform_Components_Component,
                        name string, all bool, getPowerStats bool, targetUriPath string, d *db.DB) (error) {
    var err error
    var tmp uint64

    fanInfo, err := getSysFanFromDb(name, d)
    if err != nil {
        log.Info("Error Getting fan info from dB")
        return err
    }

    empty := !fanInfo.Presence
    fanState := psuCom.Fan.State
    fanEepromState := psuCom.State
    if all {
        if getPowerStats {
            if fanInfo.Target_Speed != "" {
                tmp, _ = strconv.ParseUint(fanInfo.Target_Speed, 10, 32)
                targetSpeed := uint32(tmp)
                fanState.TargetSpeed = &targetSpeed
            }
            if fanInfo.Speed != "" {
                tmp, _ = strconv.ParseUint(fanInfo.Speed, 10, 32)
                speed := uint32(tmp)
                fanState.Speed = &speed
            }
            if fanInfo.Speed_Tolerance != "" {
                tmp, _ = strconv.ParseUint(fanInfo.Speed_Tolerance, 10, 32)
                speedTolerance := uint32(tmp)
                fanState.SpeedTolerance = &speedTolerance
            }
            if fanInfo.Direction != "" {
                fanState.Direction = &fanInfo.Direction
            }

            return err
        }

        fanEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_INACTIVE
        if fanInfo.Status {
            fanEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        }

        if fanInfo.Model_Name != "" {
            fanEepromState.Description = &fanInfo.Model_Name
        }
        if fanInfo.Name != "" {
            fanEepromState.Name = &fanInfo.Name
        }
        if fanInfo.Serial_Number != "" {
            fanEepromState.SerialNo = &fanInfo.Serial_Number
        }
        if fanInfo.Status_Led != "" {
            fanEepromState.StatusLed = &fanInfo.Status_Led
        }

        return err
    }

    switch targetUriPath {
    case FAN_SPEED:
        if fanInfo.Speed != "" {
            tmp, _ = strconv.ParseUint(fanInfo.Speed, 10, 32)
            speed := uint32(tmp)
            fanState.Speed = &speed
        }
    case FAN_TARGET_SPEED:
        if fanInfo.Target_Speed != "" {
            tmp, _ = strconv.ParseUint(fanInfo.Target_Speed, 10, 32)
            targetSpeed := uint32(tmp)
            fanState.TargetSpeed = &targetSpeed
        }
    case FAN_DIRECTION:
        if fanInfo.Direction != "" {
            fanState.Direction = &fanInfo.Direction
        }
    case COMP_LED_STATUS:
        if fanInfo.Status_Led != "" {
            fanEepromState.StatusLed = &fanInfo.Status_Led
        }
    case COMP_STATE_EMPTY:
        fanEepromState.Empty = &empty
    case COMP_STATE_OPER_STATUS:
        fanEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_INACTIVE
        if fanInfo.Status {
            fanEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        }
    case COMP_STATE_SERIAL_NO:
        if fanInfo.Serial_Number != "" {
            fanEepromState.SerialNo = &fanInfo.Serial_Number
        }
    case COMP_STATE_DESCR:
        if fanInfo.Model_Name != "" {
            fanEepromState.Description = &fanInfo.Model_Name
        }
    case COMP_STATE_NAME:
        if fanInfo.Name != "" {
            fanEepromState.Name = &fanInfo.Name
        }
    }

    return err
}

func getSysFans(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Info("Preparing dB for Fan info");

    var err error
    log.Info("targetUriPath:", targetUriPath)
    fanName := NewPathInfo(uri).Var("name")

    if validFanName(&fanName) {
        fanCom := pf_cpts.Component[fanName]
        if fanCom  == nil {
            log.Info("Invalid Component Name")
            return errors.New("Invalid component name")
        }
        ygot.BuildEmptyTree(fanCom)
        ygot.BuildEmptyTree(fanCom.Fan)
        ygot.BuildEmptyTree(fanCom.Fan.State)
        switch targetUriPath {
        case "/openconfig-platform:components/component":
            fallthrough
        case "/openconfig-platform:components/component/fan":
            fallthrough
        case "/openconfig-platform:components/component/fan/state":
            fillSysFanInfo(fanCom, fanName, true, true, targetUriPath, d)
        default:
            fillSysFanInfo(fanCom, fanName, false, true, targetUriPath, d)
            break
        }
    }
    return err
}


func validXcvrName(name *string) (bool) {
    if name == nil || *name == "" {
        return false
    }

    if utils.IsAliasModeEnabled() {
        /*
            Expect interface name of form Ethx/y/z or Ethx/y, where x,y,z are integers
        */
        return utils.IsValidAliasName(name)
    }

    /*
        Expect interface name of form EthernetX, where X is an integer
    */
    if !strings.HasPrefix(*name, PORT_IF_NAME_PREFIX){
        return false
    }

    sp := strings.SplitAfter(*name, "Ethernet")

    if _, err := strconv.Atoi(sp[1]); err != nil {
        return false
    }
    return true
}

func getSysXcvrFromDb(name string, d *db.DB) (Xcvr, error) {
    var xcvrInfo Xcvr
    var err error

    /* Adjust name before calling DB
        DB expects name of form EthernetX, where X is an integer
    */
    if utils.IsAliasModeEnabled(){
        name = *(utils.GetNativeNameFromUIName(&name))
    }

    xcvrEntry, err := d.GetEntry(&db.TableSpec{Name: TRANSCEIVER_TBL}, db.Key{Comp: []string{name}})

    if err != nil {
        log.Info("Cant get entry: ", name)
        xcvrInfo.Presence = false
        return xcvrInfo, err
    }

    /* Existence of entry implies presence */
    xcvrInfo.Presence = true

    xcvrInfo.Form_Factor = xcvrEntry.Get("form_factor")
    xcvrInfo.Display_Name = xcvrEntry.Get("display_name")
    xcvrInfo.Media_Interface = xcvrEntry.Get("media_interface")
    xcvrInfo.Cable_Type = xcvrEntry.Get("cable_type")
    xcvrInfo.Connector_Type = xcvrEntry.Get("connector_type")
    xcvrInfo.Cable_Length = xcvrEntry.Get("cable_length")
    xcvrInfo.Max_Port_Power = xcvrEntry.Get("max_port_power")
    xcvrInfo.Max_Module_Power = xcvrEntry.Get("power_rating_max")

    xcvrInfo.Lpmode = xcvrEntry.Get("lpmode")
    xcvrInfo.Module_Lane_Count = xcvrEntry.Get("module_lane_count")
    xcvrInfo.Qsa_Adapter_Type = xcvrEntry.Get("qsa_adapter")

    xcvrInfo.Vendor_Name = xcvrEntry.Get("vendor_name")
    xcvrInfo.Vendor_Part_Number = xcvrEntry.Get("vendor_part_number")
    xcvrInfo.Vendor_Serial_Number = xcvrEntry.Get("vendor_serial_number")
    xcvrInfo.Vendor_Revision = xcvrEntry.Get("vendor_revision")
    xcvrInfo.Vendor_Date_Code = xcvrEntry.Get("vendor_date_code")
    xcvrInfo.Vendor_OUI = xcvrEntry.Get("vendor_oui")

    return xcvrInfo, err
}

func test_if_available (s string) bool {
    return ((s != "") && (s != "N/A") && (s != "n/a"))
}

func convert_connector_type(ct string) ocbinds.E_OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE {
    switch ct {
    case "N/A":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_UNSET
    case "SC":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_SC_CONNECTOR
    case "Optical Pigtail":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_OPTICAL_PIGTAIL_CONNECTOR
    case "Copper Pigtail":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_COPPER_PIGTAIL_CONNECTOR
    case "LC":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_LC_CONNECTOR
    case "No separable connector":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_NO_SEPARABLE_CONNECTOR
    case "RJ45":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_RJ45_CONNECTOR
    case "MPOx12", "MPOx16", "MPO 2x12", "MPO 1x16":
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_MPO_CONNECTOR
    default:
        return ocbinds.OpenconfigTransportTypes_FIBER_CONNECTOR_TYPE_UNSET
    }
}

func convert_form_factor_type (ft string) ocbinds.E_OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE {
    switch ft {
    case "N/A", "":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_UNSET
    case "SFP":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_SFP
    case "SFP28":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_SFP28
    case "SFP56":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_SFP56
    case "QSFP":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_QSFP
    case "QSFP28":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_QSFP28
    case "SFP+":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_SFP_PLUS
    case "SFP56-DD":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_SFP56_DD
    case "QSFP+":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_QSFP_PLUS
    case "QSFP28-DD":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_QSFP28_DD
    case "QSFP56-DD":
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_QSFP56_DD
    default:
        return ocbinds.OpenconfigTransportTypes_TRANSCEIVER_FORM_FACTOR_TYPE_UNSET
    }
}

func fillSysXcvrInfo (xcvrCom *ocbinds.OpenconfigPlatform_Components_Component,
                        name string, all bool, targetUriPath string, d *db.DB) (error) {
    var err error

    xcvrInfo, err := getSysXcvrFromDb(name, d)
    if err != nil {
        log.Info("Error Getting transceiver info from dB")
        return err
    }

    xcvrState := xcvrCom.Transceiver.State
    xcvrEEPROMState := xcvrCom.State

    if all {

        /* Top level */
        nm := name
        xcvrEEPROMState.Name = &nm

        /* Present state */
        p := !xcvrInfo.Presence
        xcvrEEPROMState.Empty = &p

        q := true
        xcvrEEPROMState.Removable = &q
        /* Not present */
        if p {
            return err
        }

        if test_if_available(xcvrInfo.Display_Name) {
            xcvrEEPROMState.Description = &xcvrInfo.Display_Name
        }

        /* Vendor info */
        if test_if_available(xcvrInfo.Vendor_Serial_Number) {
            xcvrEEPROMState.SerialNo = &xcvrInfo.Vendor_Serial_Number
        }
        if test_if_available(xcvrInfo.Vendor_Part_Number) {
            xcvrEEPROMState.PartNo = &xcvrInfo.Vendor_Part_Number
        }
        if test_if_available(xcvrInfo.Vendor_Name) {
            xcvrEEPROMState.VendorName = &xcvrInfo.Vendor_Name
            xcvrEEPROMState.MfgName = &xcvrInfo.Vendor_Name
        }
        if test_if_available(xcvrInfo.Vendor_Revision) {
            xcvrEEPROMState.HardwareVersion = &xcvrInfo.Vendor_Revision
        }
        if test_if_available(xcvrInfo.Vendor_Date_Code) {
            xcvrEEPROMState.MfgDate = &xcvrInfo.Vendor_Date_Code
        }
        xcvrEEPROMState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE

        /* Inner level */
        xcvrState.Present = ocbinds.OpenconfigPlatform_Components_Component_Transceiver_State_Present_PRESENT

        if (test_if_available(xcvrInfo.Cable_Length)){
            tmp, err := strconv.ParseFloat(xcvrInfo.Cable_Length, 64)
            if err == nil {
                xcvrState.CableLength = &tmp
            }
        }
        if (test_if_available(xcvrInfo.Max_Port_Power)){
            tmp, err := strconv.ParseFloat(xcvrInfo.Max_Port_Power, 64)
            if err == nil {
                xcvrState.MaxPortPower = &tmp
            }
        }
        if (test_if_available(xcvrInfo.Max_Module_Power)){
            tmp, err := strconv.ParseFloat(xcvrInfo.Max_Module_Power, 64)
            if err == nil {
                xcvrState.MaxModulePower = &tmp
            }
        }

        if (test_if_available(xcvrInfo.Display_Name)){
            xcvrState.DisplayName = &xcvrInfo.Display_Name
        }
        if (test_if_available(xcvrInfo.Vendor_Name)){
            xcvrState.Vendor = &xcvrInfo.Vendor_Name
        }
        if (test_if_available(xcvrInfo.Vendor_Part_Number)){
            xcvrState.VendorPart = &xcvrInfo.Vendor_Part_Number
        }
        if (test_if_available(xcvrInfo.Vendor_Revision)){
            xcvrState.VendorRev = &xcvrInfo.Vendor_Revision
        }
        if (test_if_available(xcvrInfo.Vendor_Serial_Number)){
            xcvrState.SerialNo = &xcvrInfo.Vendor_Serial_Number
        }
        if (test_if_available(xcvrInfo.Vendor_Date_Code)){
            xcvrState.DateCode = &xcvrInfo.Vendor_Date_Code
        }
        if (test_if_available(xcvrInfo.Vendor_OUI)){
            xcvrState.VendorOui = &xcvrInfo.Vendor_OUI
        }

        if (test_if_available(xcvrInfo.Connector_Type)){
            xcvrState.ConnectorType = convert_connector_type(xcvrInfo.Connector_Type)
        }
        if (test_if_available(xcvrInfo.Form_Factor)){
            xcvrState.FormFactor = convert_form_factor_type(xcvrInfo.Form_Factor)
        }

        /*
            Pending YANG updates
        if (test_if_available(xcvrInfo.Module_Lane_Count)){
            tmp, err := strconv.ParseUint(xcvrInfo.Module_Lane_Count, 10, 64)
            if err == nil {
                q := uint32(tmp)
                xcvrState.ModuleLaneCount = &q
            }
        }
        if (test_if_available(xcvrInfo.Lpmode)){
            tmp, err := strconv.ParseBool(xcvrInfo.Lpmode)
            if err == nil {
                xcvrState.Lpmode = &tmp
            }
        }


        if (test_if_available(xcvrInfo.Media_Interface)){
            xcvrState.MediaInterface = &xcvrInfo.Media_Interface
        }
        if (test_if_available(xcvrInfo.Cable_Type)){
            xcvrState.CableType = &xcvrInfo.Cable_Type
        }

        if (test_if_available(xcvrInfo.Qsa_Adapter_Type)){
            xcvrState.QsaAdapterType = &xcvrInfo.Qsa_Adapter_Type
        }
        */

        return err
    }

    switch targetUriPath {
        case COMP_STATE_EMPTY:
            q := false
            xcvrEEPROMState.Empty = &q
        case COMP_STATE_NAME:
            nm := name
            xcvrEEPROMState.Name = &nm
        case COMP_STATE_DESCR:
            if test_if_available(xcvrInfo.Display_Name) {
                xcvrEEPROMState.Description = &xcvrInfo.Display_Name
            }
        case COMP_STATE_SERIAL_NO:
            if test_if_available(xcvrInfo.Vendor_Serial_Number) {
                xcvrEEPROMState.SerialNo = &xcvrInfo.Vendor_Serial_Number
            }
        case COMP_STATE_PART_NO:
            if test_if_available(xcvrInfo.Vendor_Part_Number) {
                xcvrEEPROMState.PartNo = &xcvrInfo.Vendor_Part_Number
            }
        case COMP_STATE_MFG_NAME:
            if test_if_available(xcvrInfo.Vendor_Name) {
                xcvrEEPROMState.VendorName = &xcvrInfo.Vendor_Name
                xcvrEEPROMState.MfgName = &xcvrInfo.Vendor_Name
            }
        case COMP_STATE_HW_VER:
            if test_if_available(xcvrInfo.Vendor_Revision) {
                xcvrEEPROMState.HardwareVersion = &xcvrInfo.Vendor_Revision
            }
        case COMP_STATE_MFG_DATE:
            if test_if_available(xcvrInfo.Vendor_Date_Code) {
                xcvrEEPROMState.MfgDate = &xcvrInfo.Vendor_Date_Code
            }
        case COMP_STATE_OPER_STATUS:
            xcvrEEPROMState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE

        case COMP_STATE_REMOVABLE:
            q := true
            xcvrEEPROMState.Removable = &q

        case XCVR_PRESENCE:
            xcvrState.Present = ocbinds.OpenconfigPlatform_Components_Component_Transceiver_State_Present_PRESENT
        case XCVR_CABLE_LENGTH:
            if (test_if_available(xcvrInfo.Cable_Length)){
                tmp, err := strconv.ParseFloat(xcvrInfo.Cable_Length, 64)
                if err == nil {
                    xcvrState.CableLength = &tmp
                }
            }
        case XCVR_MAX_PORT_POWER:
        if (test_if_available(xcvrInfo.Max_Port_Power)){
            tmp, err := strconv.ParseFloat(xcvrInfo.Max_Port_Power, 64)
            if err == nil {
                xcvrState.MaxPortPower = &tmp
            }
        }
        case XCVR_MAX_MODULE_POWER:
        if (test_if_available(xcvrInfo.Max_Module_Power)){
            tmp, err := strconv.ParseFloat(xcvrInfo.Max_Module_Power, 64)
            if err == nil {
                xcvrState.MaxModulePower = &tmp
            }
        }
        case XCVR_FORM_FACTOR:
            if (test_if_available(xcvrInfo.Form_Factor)){
                xcvrState.FormFactor = convert_form_factor_type(xcvrInfo.Form_Factor)
            }
        case XCVR_CONNECTOR_TYPE:
            if (test_if_available(xcvrInfo.Connector_Type)){
                xcvrState.ConnectorType = convert_connector_type(xcvrInfo.Connector_Type)
            }
        case XCVR_DISPLAY_NAME:
            if (test_if_available(xcvrInfo.Display_Name)){
                xcvrState.DisplayName = &xcvrInfo.Display_Name
            }
        case XCVR_VENDOR_NAME:
            if (test_if_available(xcvrInfo.Vendor_Name)){
                xcvrState.Vendor = &xcvrInfo.Vendor_Name
            }
        case XCVR_VENDOR_PART_NUMBER:
            if (test_if_available(xcvrInfo.Vendor_Part_Number)){
                xcvrState.VendorPart = &xcvrInfo.Vendor_Part_Number
            }
        case XCVR_VENDOR_SERIAL_NUMBER:
            if (test_if_available(xcvrInfo.Vendor_Revision)){
                xcvrState.VendorRev = &xcvrInfo.Vendor_Revision
            }
        case XCVR_VENDOR_REVISION:
            if (test_if_available(xcvrInfo.Vendor_Serial_Number)){
                xcvrState.SerialNo = &xcvrInfo.Vendor_Serial_Number
            }
        case XCVR_VENDOR_DATE_CODE:
            if (test_if_available(xcvrInfo.Vendor_Date_Code)){
                xcvrState.DateCode = &xcvrInfo.Vendor_Date_Code
            }
        case XCVR_VENDOR_OUI:
            if (test_if_available(xcvrInfo.Vendor_OUI)){
                xcvrState.VendorOui = &xcvrInfo.Vendor_OUI
            }

            /*
            Pending YANG updates

        case XCVR_MEDIA_INTERFACE:
            if (test_if_available(xcvrInfo.Media_Interface)){
                xcvrState.MediaInterface = &xcvrInfo.Media_Interface
            }
        case XCVR_CABLE_TYPE:
            if (test_if_available(xcvrInfo.Cable_Type)){
                xcvrState.CableType = &xcvrInfo.Cable_Type
            }

        case XCVR_LPMODE:
            if (test_if_available(xcvrInfo.Lpmode)){
                tmp, err := strconv.ParseBool(xcvrInfo.Lpmode)
                if err == nil {
                    xcvrState.Lpmode = &tmp
                }
            }
        case XCVR_MODULE_LANE_COUNT:
            if (test_if_available(xcvrInfo.Module_Lane_Count)){
                tmp, err := strconv.ParseUint(xcvrInfo.Module_Lane_Count, 10, 64)
                if err == nil {
                    q := uint32(tmp)
                    xcvrState.ModuleLaneCount = &q
                }
            }
        case XCVR_QSA_ADAPTER_TYPE:
            if (test_if_available(xcvrInfo.Qsa_Adapter_Type)){
                xcvrState.QsaAdapterType = &xcvrInfo.Qsa_Adapter_Type
            }
            */
    }
    return err
}

func getSysXcvr(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Info("Preparing dB for XCVR info");

    var err error
    log.Info("targetUriPath:", targetUriPath)
    xcvrId := NewPathInfo(uri).Var("name")

    xcvrCom := pf_cpts.Component[xcvrId]
    if xcvrCom  == nil {
        log.Info("Invalid Component Name")
        return errors.New("Invalid component name")
    }

    ygot.BuildEmptyTree(xcvrCom)
    ygot.BuildEmptyTree(xcvrCom.Transceiver)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.State)
    switch targetUriPath {
        case "/openconfig-platform:components/component":
            fallthrough
        case "/openconfig-platform:components/component/transceiver":
            fallthrough
        case "/openconfig-platform:components/component/transceiver/state":
            fillSysXcvrInfo(xcvrCom, xcvrId, true, targetUriPath, d)
        default:
            /* For individual components*/
            fillSysXcvrInfo(xcvrCom, xcvrId, false, targetUriPath, d)
            break
    }

    return err
}

/* Get a list of all physical interfaces available */
func getPhysicalIntfNames(d *db.DB) []string{

    var ret []string

    keyList, _ := d.GetKeysPattern(&(db.TableSpec{Name: PORT_TBL}), db.Key{Comp: []string{PORT_IF_NAME_PREFIX + "*"}})
    for _, v := range keyList{
        if len(v.Comp) == 0 {
            continue
        }
        ret = append(ret, v.Comp[0])
    }
    return ret
}
