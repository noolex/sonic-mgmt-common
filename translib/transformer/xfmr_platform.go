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
    "fmt"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "math"
    "os"
    "strconv"
    "strings"
    "regexp"
    "unicode/utf8"
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
   TRANSCEIVER_DOM  = "TRANSCEIVER_DOM_SENSOR"
   PORT_TBL         = "PORT_TABLE"
   BREAKOUT_TBL     = "BREAKOUT_CFG"
   FIRMWARE_TBL     = "FIRMWARE_INFO"

   PORT_IF_NAME_PREFIX   = "Ethernet"
   ALIAS_IN_NAME_PREFIX  = "Eth"
   TEMP_TBL         = "TEMPERATURE_INFO"

   /** Valid System Components **/
   PSU1             = "PSU 1"
   PSU2             = "PSU 2"
   SYSEEPROM        = "System Eeprom"

   /** Valid Device Metadata Components **/
   DEVICE_METADATA  = "DEVICE_METADATA"
   HWSKU            = "hwsku"
   PLATFORM_TYPE    = "platform"

   /** Upper-level URIs **/
   COMPS                      = "/openconfig-platform:components"
   COMP                       = "/openconfig-platform:components/component"

   /** Config container name **/
   COMP_CONFIG_NAME           = "/openconfig-platform:components/component/config/name"

   /** Supported oc-platform component state URIs **/
   COMP_STATE_DESCR           = "/openconfig-platform:components/component/state/description"
   COMP_STATE_EMPTY           = "/openconfig-platform:components/component/state/empty"
   COMP_STATE_FIRM_VER        = "/openconfig-platform:components/component/state/firmware-version"
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
   COMP_LED_STATUS            = "/openconfig-platform:components/component/state/openconfig-platform-ext:status-led"
   COMP_FANS                  = "/openconfig-platform:components/component/state/openconfig-platform-ext:fans"

   /** Supported Software component URIs **/
   SW_ASIC_VER                = "/openconfig-platform:components/component/openconfig-platform-ext:software/asic-version"
   SW_BUILD_COMMIT            = "/openconfig-platform:components/component/openconfig-platform-ext:software/build-commit"
   SW_BUILD_DATE              = "/openconfig-platform:components/component/openconfig-platform-ext:software/build-date"
   SW_BUILT_BY                = "/openconfig-platform:components/component/openconfig-platform-ext:software/built-by"
   SW_COMP                    = "/openconfig-platform:components/component/openconfig-platform-ext:software"
   SW_DIST_VER                = "/openconfig-platform:components/component/openconfig-platform-ext:software/distribution-version"
   SW_DOCKER_VER              = "/openconfig-platform:components/component/openconfig-platform-ext:software/docker-version"
   SW_PRODUCT_DESCR           = "/openconfig-platform:components/component/openconfig-platform-ext:software/product-description"
   SW_CONFIGDB_VER            = "/openconfig-platform:components/component/openconfig-platform-ext:software/config-db-version"
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
   PSU_TEMPERATURE            = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-psu:temperature"
   PSU_VOLT_TYPE              = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-ext:power-type"
   PSU_INPUT_POWER            = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-ext:input-power"
   PSU_INPUT_CURRENT          = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-psu:input-current"
   PSU_INPUT_VOLTAGE          = "/openconfig-platform:components/component/power-supply/state/openconfig-platform-psu:input-voltage"

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

   XCVR_REVISION_COMPLIANCE              = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:revision-compliance"

   XCVR_LPMODE                  = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:lpmode"
   XCVR_MODULE_LANE_COUNT       = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:module-lane-count"
   XCVR_PRESENCE                = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:present"
   XCVR_QSA_ADAPTER_TYPE        = "/openconfig-platform:components/component/transceiver/state/openconfig-platform-ext:qsa-adapter-type"

   /** Support Temperature Sensor URIs **/
   TEMP_COMP                  = "/openconfig-platform:components/component/state/temperature"
   TEMP_CRIT_HIGH_THRES       = "/openconfig-platform:components/component/state/temperature/openconfig-platform-ext:critical-high-threshold"
   TEMP_CRIT_LOW_THRES        = "/openconfig-platform:components/component/state/temperature/openconfig-platform-ext:critical-low-threshold"
   TEMP_CURRENT               = "/openconfig-platform:components/component/state/temperature/openconfig-platform-ext:current"
   TEMP_HIGH_THRES            = "/openconfig-platform:components/component/state/temperature/openconfig-platform-ext:high-threshold"
   TEMP_LOW_THRES             = "/openconfig-platform:components/component/state/temperature/openconfig-platform-ext:low-threshold"
   TEMP_TIMESTAMP             = "/openconfig-platform:components/component/state/temperature/openconfig-platform-ext:timestamp"
   TEMP_WARNING_STATUS        = "/openconfig-platform:components/component/state/temperature/openconfig-platform-ext:warning-status"

   /** Supported Firmware URIs **/
   FIRMWARE_CHASSIS              = "/openconfig-platform:components/component/chassis"
   FIRMWARE_CHASSIS_STATE        = "/openconfig-platform:components/component/chassis/state"
   FIRMWARE_CHASSIS_STATE_MODULE = "/openconfig-platform:components/component/chassis/state/openconfig-platform-ext:module"
   FIRMWARE_CHASSIS_STATE_NAME   = "/openconfig-platform:components/component/chassis/state/openconfig-platform-ext:name"
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
    Input_Power         string
    Manufacturer        string
    Model_Name          string
    Output_Current      string
    Output_Power        string
    Output_Voltage      string
    Presence            bool
    Serial_Number       string
    Status              bool
    Status_Led          string
    Volt_Type           string
    Temperature         string
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

type Xcvr struct {
/* Most are strings since media sends 'N/A' when data is not available
   Conversion will be done before sending along */
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
    Revision_Compliance     string
    LolLane_1                string
    LolLane_2                string
    LolLane_3                string
    LolLane_4                string
    LolLane_5                string
    LolLane_6                string
    LolLane_7                string
    LolLane_8                string
    LosLane_1                string
    LosLane_2                string
    LosLane_3                string
    LosLane_4                string
    LosLane_5                string
    LosLane_6                string
    LosLane_7                string
    LosLane_8                string
    RxPowerLane_1            string
    RxPowerLane_2            string
    RxPowerLane_3            string
    RxPowerLane_4            string
    RxPowerLane_5            string
    RxPowerLane_6            string
    RxPowerLane_7            string
    RxPowerLane_8            string
    TxBiasLane_1             string
    TxBiasLane_2             string
    TxBiasLane_3             string
    TxBiasLane_4             string
    TxBiasLane_5             string
    TxBiasLane_6             string
    TxBiasLane_7             string
    TxBiasLane_8             string
    TxPowerLane_1            string
    TxPowerLane_2            string
    TxPowerLane_3            string
    TxPowerLane_4            string
    TxPowerLane_5            string
    TxPowerLane_6            string
    TxPowerLane_7            string
    TxPowerLane_8            string
    Temperature              string
    Voltage                  string
}

type TempSensor struct {
    Crit_High_Threshold  string
    Crit_Low_Threshold   string
    Current              string
    High_Threshold       string
    Low_Threshold        string
    Name                 string
    Warning_Status       string
    Timestamp            string
}

type DeviceMetadata struct {
    HWSKU    string
    PLATFORM string
}

type Firmware struct {
    Chassis             string
    Description         string
    Module              string
    Name                string
    Version             string
}

func init () {
    XlateFuncBind("DbToYang_pfm_components_xfmr", DbToYang_pfm_components_xfmr)
    XlateFuncBind("Subscribe_pfm_components_xfmr", Subscribe_pfm_components_xfmr)
    XlateFuncBind("DbToYang_pfm_components_psu_xfmr", DbToYang_pfm_components_psu_xfmr)
    XlateFuncBind("DbToYang_pfm_components_fan_xfmr", DbToYang_pfm_components_fan_xfmr)
    XlateFuncBind("DbToYang_pfm_components_chassis_xfmr", DbToYang_pfm_components_chassis_xfmr)
    XlateFuncBind("DbToYang_pfm_components_transceiver_xfmr", DbToYang_pfm_components_transceiver_xfmr)
    XlateFuncBind("YangToDb_pfm_components_transceiver_diag_xfmr", YangToDb_pfm_components_transceiver_diag_xfmr)
    XlateFuncBind("DbToYang_pfm_components_transceiver_diag_xfmr", DbToYang_pfm_components_transceiver_diag_xfmr)
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

// Returns 'defs' if the field does not exists.
func getString(v db.Value, name string, defs string) (string) {
    data, ok := v.Field[name]
    if !ok || (data == "") {
        return defs
    }
    return data
}

var DbToYang_pfm_components_transceiver_diag_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {

    var capLoopback string
    var capPattern string
    var capPatternChkHost string
    var capPatternChkMedia string
    var capPatternGenHost string
    var capPatternGenMedia string
    var capReport string

    var cfgLbHostInputEnabled bool
    var cfgLbHostOutputEnabled bool
    var cfgLbMediaInputEnabled bool
    var cfgLbMediaOutputEnabled bool
    var cfgPatternGenHostEnabled bool
    var cfgPatternChkHostEnabled bool
    var cfgPatternGenMediaEnabled bool
    var cfgPatternChkMediaEnabled bool

    var staLbHostInputEnabled bool
    var staLbHostOutputEnabled bool
    var staLbMediaInputEnabled bool
    var staLbMediaOutputEnabled bool
    var staPatternGenHostEnabled bool
    var staPatternChkHostEnabled bool
    var staPatternGenMediaEnabled bool
    var staPatternChkMediaEnabled bool

    var berHost [8]string
    var berMedia [8]string
    var snrHost [8]string
    var snrMedia [8]string

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    log.Infof("targetUriPath: %v", targetUriPath)

    if !strings.HasPrefix(targetUriPath, "/openconfig-platform:components/component/openconfig-platform-transceiver:transceiver/openconfig-platform-transceiver-ext:diagnostics") {
        return nil
    }

    name := pathInfo.Var("name")
    pf_cpts := getPfmRootObject(inParams.ygRoot)
    xcvrCom := pf_cpts.Component[name]
    if xcvrCom == nil {
        log.Info("Invalid Component Name")
        return errors.New("Invalid component name")
    }

    if utils.IsAliasModeEnabled(){
        name = *(utils.GetNativeNameFromUIName(&name))
    }
    log.Infof("xcvrId: %v", name)

    tbl := db.TableSpec { Name: "TRANSCEIVER_DIAG" }
    key := db.Key { Comp : [] string { name } }
    d := inParams.dbs[db.ConfigDB]
    d.Opts.KeySeparator = "|"
    d.Opts.TableNameSeparator = "|"
    val, err := d.GetEntry(&tbl, key)
    if err == nil {
        cfgLbHostInputEnabled, _ = strconv.ParseBool(val.Get("lb_host_input_enabled"))
        cfgLbHostOutputEnabled, _ = strconv.ParseBool(val.Get("lb_host_output_enabled"))
        cfgLbMediaInputEnabled, _ = strconv.ParseBool(val.Get("lb_media_input_enabled"))
        cfgLbMediaOutputEnabled, _ = strconv.ParseBool(val.Get("lb_media_output_enabled"))
        cfgPatternChkHostEnabled, _ = strconv.ParseBool(val.Get("prbs_chk_host_enabled"))
        cfgPatternChkMediaEnabled, _ = strconv.ParseBool(val.Get("prbs_chk_media_enabled"))
        cfgPatternGenHostEnabled, _ = strconv.ParseBool(val.Get("prbs_gen_host_enabled"))
        cfgPatternGenMediaEnabled, _ = strconv.ParseBool(val.Get("prbs_gen_media_enabled"))
    }

    tbl = db.TableSpec { Name: "TRANSCEIVER_INFO" }
    key = db.Key { Comp : [] string { name } }
    d = inParams.dbs[db.StateDB]
    d.Opts.KeySeparator = "|"
    d.Opts.TableNameSeparator = "|"
    val, err = d.GetEntry(&tbl, key)
    if err == nil {
        capLoopback        = getString(val, "diag_caps_loopback",  "[]")
        capPattern         = getString(val, "diag_caps_pattern",  "[]")
        capPatternChkHost  = getString(val, "diag_caps_pattern_chk_host",  "[]")
        capPatternChkMedia = getString(val, "diag_caps_pattern_chk_media", "[]")
        capPatternGenHost  = getString(val, "diag_caps_pattern_gen_host",  "[]")
        capPatternGenMedia = getString(val, "diag_caps_pattern_gen_media", "[]")
        capReport          = getString(val, "diag_caps_report",  "[]")
    } else {
        capLoopback = "[]"
        capPattern = "[]"
        capPatternChkHost = "[]"
        capPatternChkMedia = "[]"
        capPatternGenHost = "[]"
        capPatternGenMedia = "[]"
        capReport = "[]"
    }

    tbl = db.TableSpec { Name: "TRANSCEIVER_DIAG" }
    key = db.Key { Comp : [] string { name } }
    d = inParams.dbs[db.StateDB]
    d.Opts.KeySeparator = "|"
    d.Opts.TableNameSeparator = "|"
    val, err = d.GetEntry(&tbl, key)
    if err == nil {
        staLbHostInputEnabled, _ = strconv.ParseBool(val.Get("lb_host_input_enabled"))
        staLbHostOutputEnabled, _ = strconv.ParseBool(val.Get("lb_host_output_enabled"))
        staLbMediaInputEnabled, _ = strconv.ParseBool(val.Get("lb_media_input_enabled"))
        staLbMediaOutputEnabled, _ = strconv.ParseBool(val.Get("lb_media_output_enabled"))
        staPatternChkHostEnabled, _ = strconv.ParseBool(val.Get("prbs_chk_host_enabled"))
        staPatternChkMediaEnabled, _ = strconv.ParseBool(val.Get("prbs_chk_media_enabled"))
        staPatternGenHostEnabled, _ = strconv.ParseBool(val.Get("prbs_gen_host_enabled"))
        staPatternGenMediaEnabled, _ = strconv.ParseBool(val.Get("prbs_gen_media_enabled"))

        for lane := 1; lane <= 8; lane++ {
            berHost[lane - 1]  = getString(val, fmt.Sprintf("diag_host_ber%d", lane),  "0")
            berMedia[lane - 1] = getString(val, fmt.Sprintf("diag_media_ber%d", lane), "0")
            snrHost[lane - 1]  = getString(val, fmt.Sprintf("diag_host_snr%d", lane),  "0")
            snrMedia[lane - 1] = getString(val, fmt.Sprintf("diag_media_snr%d", lane), "0")
        }
    } else {
        for lane := 1; lane <= 8; lane++ {
            berHost[lane - 1]  = "0"
            berMedia[lane - 1] = "0"
            snrHost[lane - 1]  = "0"
            snrMedia[lane - 1] = "0"
        }
    }

    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Capabilities)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Capabilities.State)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Loopbacks)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Loopbacks.Config)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Loopbacks.State)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Patterns)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Patterns.State)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Reports)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Reports.Host)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Reports.Host.State)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Reports.Media)
    ygot.BuildEmptyTree(xcvrCom.Transceiver.Diagnostics.Reports.Media.State)

    xcvrDiag := xcvrCom.Transceiver.Diagnostics

    xcvrDiag.Capabilities.State.Loopback = &capLoopback
    xcvrDiag.Capabilities.State.Pattern = &capPattern
    xcvrDiag.Capabilities.State.PatternChkHost = &capPatternChkHost
    xcvrDiag.Capabilities.State.PatternChkMedia = &capPatternChkMedia
    xcvrDiag.Capabilities.State.PatternGenHost = &capPatternGenHost
    xcvrDiag.Capabilities.State.PatternGenMedia = &capPatternGenMedia
    xcvrDiag.Capabilities.State.Report = &capReport

    xcvrDiag.Loopbacks.Config.LbHostInputEnabled = &cfgLbHostInputEnabled
    xcvrDiag.Loopbacks.Config.LbHostOutputEnabled = &cfgLbHostOutputEnabled
    xcvrDiag.Loopbacks.Config.LbMediaInputEnabled = &cfgLbMediaInputEnabled
    xcvrDiag.Loopbacks.Config.LbMediaOutputEnabled = &cfgLbMediaOutputEnabled

    xcvrDiag.Loopbacks.State.LbHostInputEnabled = &staLbHostInputEnabled
    xcvrDiag.Loopbacks.State.LbHostOutputEnabled = &staLbHostOutputEnabled
    xcvrDiag.Loopbacks.State.LbMediaInputEnabled = &staLbMediaInputEnabled
    xcvrDiag.Loopbacks.State.LbMediaOutputEnabled = &staLbMediaOutputEnabled

    xcvrDiag.Patterns.Config.PatternChkHostEnabled = &cfgPatternChkHostEnabled
    xcvrDiag.Patterns.Config.PatternGenHostEnabled = &cfgPatternGenHostEnabled
    xcvrDiag.Patterns.Config.PatternChkMediaEnabled = &cfgPatternChkMediaEnabled
    xcvrDiag.Patterns.Config.PatternGenMediaEnabled = &cfgPatternGenMediaEnabled

    xcvrDiag.Patterns.State.PatternChkHostEnabled = &staPatternChkHostEnabled
    xcvrDiag.Patterns.State.PatternGenHostEnabled = &staPatternGenHostEnabled
    xcvrDiag.Patterns.State.PatternChkMediaEnabled = &staPatternChkMediaEnabled
    xcvrDiag.Patterns.State.PatternGenMediaEnabled = &staPatternGenMediaEnabled

    xcvrDiag.Reports.Host.State.Ber1 = &berHost[0]
    xcvrDiag.Reports.Host.State.Ber2 = &berHost[1]
    xcvrDiag.Reports.Host.State.Ber3 = &berHost[2]
    xcvrDiag.Reports.Host.State.Ber4 = &berHost[3]
    xcvrDiag.Reports.Host.State.Ber5 = &berHost[4]
    xcvrDiag.Reports.Host.State.Ber6 = &berHost[5]
    xcvrDiag.Reports.Host.State.Ber7 = &berHost[6]
    xcvrDiag.Reports.Host.State.Ber8 = &berHost[7]
    xcvrDiag.Reports.Media.State.Ber1 = &berMedia[0]
    xcvrDiag.Reports.Media.State.Ber2 = &berMedia[1]
    xcvrDiag.Reports.Media.State.Ber3 = &berMedia[2]
    xcvrDiag.Reports.Media.State.Ber4 = &berMedia[3]
    xcvrDiag.Reports.Media.State.Ber5 = &berMedia[4]
    xcvrDiag.Reports.Media.State.Ber6 = &berMedia[5]
    xcvrDiag.Reports.Media.State.Ber7 = &berMedia[6]
    xcvrDiag.Reports.Media.State.Ber8 = &berMedia[7]
    xcvrDiag.Reports.Host.State.Snr1 = &snrHost[0]
    xcvrDiag.Reports.Host.State.Snr2 = &snrHost[1]
    xcvrDiag.Reports.Host.State.Snr3 = &snrHost[2]
    xcvrDiag.Reports.Host.State.Snr4 = &snrHost[3]
    xcvrDiag.Reports.Host.State.Snr5 = &snrHost[4]
    xcvrDiag.Reports.Host.State.Snr6 = &snrHost[5]
    xcvrDiag.Reports.Host.State.Snr7 = &snrHost[6]
    xcvrDiag.Reports.Host.State.Snr8 = &snrHost[7]
    xcvrDiag.Reports.Media.State.Snr1 = &snrMedia[0]
    xcvrDiag.Reports.Media.State.Snr2 = &snrMedia[1]
    xcvrDiag.Reports.Media.State.Snr3 = &snrMedia[2]
    xcvrDiag.Reports.Media.State.Snr4 = &snrMedia[3]
    xcvrDiag.Reports.Media.State.Snr5 = &snrMedia[4]
    xcvrDiag.Reports.Media.State.Snr6 = &snrMedia[5]
    xcvrDiag.Reports.Media.State.Snr7 = &snrMedia[6]
    xcvrDiag.Reports.Media.State.Snr8 = &snrMedia[7]

    return nil
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

var DbToYang_pfm_components_chassis_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    pathInfo := NewPathInfo(inParams.uri)
    log.Infof("Received GET for PlatformApp Template: %s ,path: %s, vars: %v",
    pathInfo.Template, pathInfo.Path, pathInfo.Vars)

    if strings.Contains(inParams.requestUri, "/openconfig-platform:components") ||
        strings.Contains(inParams.requestUri, "/openconfig-platform:components/component/chassis") {

        log.Info("inParams.Uri:",inParams.requestUri)
        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
        err := getSysFirmware(getPfmRootObject(inParams.ygRoot), targetUriPath, inParams.uri, inParams.dbs[db.StateDB])
        return err
    }

    return errors.New("Component not supported")
}

var Subscribe_pfm_components_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    key := NewPathInfo(inParams.uri).Var("name")
    mstr := strings.ToLower(key)

    log.Infof("+++ Subscribe_pfm_components_xfmr (%v) +++", inParams.uri)

    if key == "" || mstr == "sensor" {
        /* no need to verify DB data if we are requesting ALL
           components or if request is for sensor */
        result.isVirtualTbl = true
        return result, err
    }
    result.dbDataMap = make(RedisDbSubscribeMap)
    if mstr == "system eeprom" {
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {EEPROM_TBL:{"*":{}}}}
    } else if mstr == "software" {
        /* software component reads from XML file but also
         * gets EEPROM information from DB */
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {EEPROM_TBL:{"*":{}}}}
    } else if validPsuName(&key) {
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {PSU_TBL:{key:{}}}}
    } else if validFanName(&key) {
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {FAN_TBL:{key:{}}}}
    } else if validTempName(&key) {
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {TEMP_TBL:{key:{}}}}
    } else if validFirmwareName(&key) {
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {FIRMWARE_TBL:{key:{}}}}
    } else if validXcvrName(&key) {
        ifName := key
        if utils.IsAliasModeEnabled() {
            ifName = *(utils.GetNativeNameFromUIName(&key))
        }
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {TRANSCEIVER_TBL:{ifName:{}}}}
    } else {
        ifName := getIfName(key);
        if len(ifName) > 1 {
            result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{BREAKOUT_TBL:{ifName:{}}}}
        } else {
            log.Info("Invalid component name ", key)
            return result, errors.New("Invalid component name")
        }
    }

    return result, err
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

var YangToDb_pfm_components_transceiver_diag_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {

    value := db.Value {make(map[string]string)}
    cfgMap := make(map[string]map[string]db.Value)

    log.Infof("+++ YangToDb_pfm_components_transceiver_diag_xfmr (requestUri=%v) +++", inParams.requestUri)

    name := NewPathInfo(inParams.uri).Var("name")
    if len(name) == 0 {
        return cfgMap, nil
    }

    tblName := "TRANSCEIVER_DIAG"
    keyName := name
    if utils.IsAliasModeEnabled() {
        keyName = *(utils.GetNativeNameFromUIName(&keyName))
    }
    inParams.table = tblName
    inParams.key = keyName

    if inParams.oper == DELETE {
        if strings.Contains(inParams.requestUri, "lb-host-input-enabled") {
            value.Field["lb_host_input_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "lb-host-output-enabled") {
            value.Field["lb_host_output_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "lb-media-input-enabled") {
            value.Field["lb_media_input_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "lb-media-output-enabled") {
            value.Field["lb_media_output_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "pattern-gen-host-enabled") {
            value.Field["prbs_gen_host_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "pattern-chk-host-enabled") {
            value.Field["prbs_chk_host_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "pattern-gen-media-enabled") {
            value.Field["prbs_gen_media_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "pattern-chk-media-enabled") {
            value.Field["prbs_chk_media_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "loopbacks") {
            value.Field["lb_host_input_enabled"] = ""
            value.Field["lb_host_output_enabled"] = ""
            value.Field["lb_media_input_enabled"] = ""
            value.Field["lb_media_output_enabled"] = ""
        } else if strings.Contains(inParams.requestUri, "patterns") {
            value.Field["prbs_gen_host_enabled"] = ""
            value.Field["prbs_chk_host_enabled"] = ""
            value.Field["prbs_gen_media_enabled"] = ""
            value.Field["prbs_chk_media_enabled"] = ""
        }
    } else {
        if strings.Contains(inParams.requestUri, "loopbacks") {
            cfg, _ := inParams.param.(*ocbinds.OpenconfigPlatform_Components_Component_Transceiver_Diagnostics_Loopbacks_Config)

            if cfg.LbHostInputEnabled != nil {
                value.Field["lb_host_input_enabled"] = strconv.FormatBool(*cfg.LbHostInputEnabled)
            }
            if cfg.LbHostOutputEnabled != nil {
                value.Field["lb_host_output_enabled"] = strconv.FormatBool(*cfg.LbHostOutputEnabled)
            }
            if cfg.LbMediaInputEnabled != nil {
                value.Field["lb_media_input_enabled"] = strconv.FormatBool(*cfg.LbMediaInputEnabled)
            }
            if cfg.LbMediaOutputEnabled != nil {
                value.Field["lb_media_output_enabled"] = strconv.FormatBool(*cfg.LbMediaOutputEnabled)
            }
        } else if strings.Contains(inParams.requestUri, "patterns") {
            cfg, _ := inParams.param.(*ocbinds.OpenconfigPlatform_Components_Component_Transceiver_Diagnostics_Patterns_Config)

            if cfg.PatternChkHostEnabled != nil {
                value.Field["prbs_chk_host_enabled"] = strconv.FormatBool(*cfg.PatternChkHostEnabled)
            }
            if cfg.PatternChkMediaEnabled != nil {
                value.Field["prbs_chk_media_enabled"] = strconv.FormatBool(*cfg.PatternChkMediaEnabled)
            }
            if cfg.PatternGenHostEnabled != nil {
                value.Field["prbs_gen_host_enabled"] = strconv.FormatBool(*cfg.PatternGenHostEnabled)
            }
            if cfg.PatternGenMediaEnabled != nil {
                value.Field["prbs_gen_media_enabled"] = strconv.FormatBool(*cfg.PatternGenMediaEnabled)
            }
        }
    }

    cfgMap[tblName] = make(map[string]db.Value)
    cfgMap[tblName][keyName] = value
    return cfgMap, nil
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

func getSoftwareVersionComponent (pfComp *ocbinds.OpenconfigPlatform_Components_Component, targetUriPath string, allAttr bool, d *db.DB) (error) {

    swCompName := "Software"
    swComp := pfComp.Software
    brandingScanner := bufio.NewScanner(strings.NewReader(""))
    versionScanner := bufio.NewScanner(strings.NewReader(""))
    scanner := bufio.NewScanner(strings.NewReader(""))
    serialScanner := bufio.NewScanner(strings.NewReader(""))
    uptimeScanner := bufio.NewScanner(strings.NewReader(""))
    var eepromInfo Eeprom
    var deviceMetadata DeviceMetadata
    var err error

    if allAttr || targetUriPath == COMP_CONFIG_NAME {
        pfComp.Config.Name = &swCompName
    }

    if allAttr || targetUriPath == COMP_STATE_NAME {
        pfComp.State.Name = &swCompName
    }

    if allAttr || targetUriPath == SW_COMP || targetUriPath == SW_DIST_VER || targetUriPath == SW_KERN_VER ||
       targetUriPath == SW_BUILD_COMMIT || targetUriPath == SW_ASIC_VER || targetUriPath == SW_BUILD_DATE ||
       targetUriPath == SW_BUILT_BY || targetUriPath == SW_SW_VER || targetUriPath == SW_CONFIGDB_VER {
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

    if allAttr || targetUriPath == SW_COMP || targetUriPath == SW_PRODUCT_DESCR {
        brandingFile, err := os.Open("/etc/sonic/sonic_branding.yml")
        if err != nil {
            log.Infof("sonic_branding.yml open failed")
            errStr := "Information not available or Not supported"
            return tlerr.NotFoundError{Format: errStr}
        }
        defer brandingFile.Close()
        brandingScanner = bufio.NewScanner(brandingFile)
        brandingScanner.Split(bufio.ScanLines)
    }

    if allAttr || targetUriPath == SW_COMP || targetUriPath == SW_HW_VER || targetUriPath == SW_MFG_NAME {
        eepromInfo, err = getSysEepromFromDb(d)
        if err != nil {
            return err
        }
    }

    if allAttr || targetUriPath == SW_COMP || targetUriPath == SW_HWSKU_VER || targetUriPath == SW_PLAT_NAME {
        deviceMetadata, err = getDeviceMetadataFromDb()
        if err != nil {
            return err
        }
        if !strings.EqualFold(deviceMetadata.PLATFORM, eepromInfo.Platform_Name) && 
                 len(eepromInfo.Platform_Name) > 0 {
            deviceMetadata.PLATFORM = eepromInfo.Platform_Name
        }
    }

    if allAttr || targetUriPath == SW_COMP || targetUriPath == SW_DOCKER_VER {
        var query_result = HostQuery("docker_version.action", "")
        if query_result.Err != nil {
            log.Infof("Error in Calling dbus fetch_environment %v", query_result.Err)
            return query_result.Err
        }
        env_op := query_result.Body[1].(string)
        scanner = bufio.NewScanner(strings.NewReader(env_op))
    }

    if allAttr || targetUriPath == SW_COMP || targetUriPath == SW_SERIAL_NUM {
        var query_result_ser = HostQuery("serial_number_cmd.action", "")
        if query_result_ser.Err != nil {
            log.Infof("Error in Calling dbus Serial Number %v", query_result_ser.Err)
            return query_result_ser.Err
        }
        serial_no_op := query_result_ser.Body[1].(string)
        serialScanner = bufio.NewScanner(strings.NewReader(serial_no_op))
    }

    if allAttr || targetUriPath == SW_COMP || targetUriPath == SW_UP_TIME {
        var query_result_uptime = HostQuery("sys_uptime.action", "")
        if query_result_uptime.Err != nil {
            log.Infof("Error in Calling dbus System uptime %v", query_result_uptime.Err)
            return query_result_uptime.Err
        }
        sys_Uptime_no_op := query_result_uptime.Body[1].(string)
        uptimeScanner = bufio.NewScanner(strings.NewReader(sys_Uptime_no_op))
    }

    if allAttr || targetUriPath == SW_COMP {
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
            if strings.Contains(versionScanner.Text(), "config_db_version:") {
                res1 := strings.Split(versionScanner.Text(), ": ")
                swComp.ConfigDbVersion = &res1[1]
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

        for brandingScanner.Scan() {
            if strings.Contains(brandingScanner.Text(), "product_name:") {
                res1 := strings.Split(brandingScanner.Text(), ": ")
                swComp.ProductDescription = &res1[1]
                continue
            }
        }

        if eepromInfo.Label_Revision != "" {
            swComp.HardwareVersion = &eepromInfo.Label_Revision
        }
        if eepromInfo.Vendor_Name != "" {
            swComp.MfgName = &eepromInfo.Vendor_Name
        }

        if deviceMetadata.HWSKU != "" {
            swComp.HwskuVersion = &deviceMetadata.HWSKU
        }

        if deviceMetadata.PLATFORM != "" {
            swComp.PlatformName = &deviceMetadata.PLATFORM
        }

        for serialScanner.Scan() {
            s := strings.Fields(serialScanner.Text())
            swComp.SerialNumber = &s[0]
        }

        for uptimeScanner.Scan() {
            s := strings.Fields(uptimeScanner.Text())
            sysUptime := ""
            for i:= 0; i<len(s); i++ {
                sysUptime += s[i] + " "
            }
            swComp.UpTime = &sysUptime
        }

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
            ygot.BuildEmptyTree(pf_docker_ver.State)
            pf_docker_ver.DockerName = &s[0]
            pf_docker_ver.State.DockerName = &s[0]
            pf_docker_ver.State.DockerTagId = &s[1]
            pf_docker_ver.State.DockerImageId = &s[2]
            pf_docker_ver.State.DockerSize = &s[3]
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
        case SW_PRODUCT_DESCR:
            for brandingScanner.Scan() {
                if strings.Contains(brandingScanner.Text(), "product_name:") {
                    res1 := strings.Split(brandingScanner.Text(), ": ")
                    swComp.ProductDescription = &res1[1]
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
        case SW_CONFIGDB_VER:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "config_db_version:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.ConfigDbVersion = &res1[1]
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
            if deviceMetadata.PLATFORM != "" {
                swComp.PlatformName = &deviceMetadata.HWSKU
            }
        case SW_HWSKU_VER:
            if deviceMetadata.HWSKU != "" {
                swComp.HwskuVersion = &deviceMetadata.HWSKU
            }
        case SW_HW_VER:
            if eepromInfo.Label_Revision != "" {
                swComp.HardwareVersion = &eepromInfo.Label_Revision
            }
        case SW_SERIAL_NUM:
            for serialScanner.Scan() {
                s := strings.Fields(serialScanner.Text())
                swComp.SerialNumber = &s[0]
            }
        case SW_MFG_NAME:
            if eepromInfo.Vendor_Name != "" {
                swComp.MfgName = &eepromInfo.Vendor_Name
            }
        case SW_UP_TIME:
            for uptimeScanner.Scan() {
                s := strings.Fields(uptimeScanner.Text())
                sysUptime := ""
                for i:= 0; i<len(s); i++ {
                    sysUptime += s[i] + " "
                }
                swComp.UpTime = &sysUptime
            }
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
                ygot.BuildEmptyTree(pf_docker_ver.State)
                pf_docker_ver.DockerName = &s[0]
                pf_docker_ver.State.DockerName = &s[0]
                pf_docker_ver.State.DockerTagId = &s[1]
                pf_docker_ver.State.DockerImageId = &s[2]
                pf_docker_ver.State.DockerSize = &s[3]
            }
        default:
            log.Infof("Attribute not found")
        }
    }
    return nil
}

func getDeviceMetadataFromDb () (DeviceMetadata, error) {
    var dmdInfo DeviceMetadata
    var err error
    var typeCode string
    d, err := db.NewDB(getDBOptions(db.ConfigDB))
    if err != nil {
        log.Infof("getDeviceMetadataFromDb, unable to get configDB, error %v", err)
        return dmdInfo, err
    }

    defer d.DeleteDB()

    dmdTbl, err := d.GetTable(&db.TableSpec{Name: DEVICE_METADATA})
    if err != nil {
        log.Info("Can't get table: ", DEVICE_METADATA)
        return dmdInfo, err
    }

    keys, err := dmdTbl.GetKeys()
    if err != nil {
        log.Info("Can't get keys from table")
        return dmdInfo, err
    }

    for _, key := range keys {
        typeCode = key.Get(0)
        dmdEntry, err := dmdTbl.GetEntry(db.Key{Comp: []string{typeCode}})
        if err != nil {
            log.Info("Can't get entry with key: ", typeCode)
            return dmdInfo, err
        }
        if dmdEntry.Has(HWSKU) {
            dmdInfo.HWSKU = dmdEntry.Get(HWSKU)
        }
        if dmdEntry.Has(PLATFORM_TYPE) {
            dmdInfo.PLATFORM = dmdEntry.Get(PLATFORM_TYPE)
        }
    }
    return dmdInfo, err
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
        eepromEntry, err := eepromTbl.GetEntry(key)
        if err != nil {
            log.Info("Can't get entry with key: ", typeCode)
            return eepromInfo, err
        }

        entryVal = eepromEntry.Get("Value")
        if !utf8.ValidString(entryVal) {
            v := make([]rune, 0, len(entryVal))
            for i, r := range entryVal {
                if r == utf8.RuneError {
                     _, size := utf8.DecodeRuneInString(entryVal[i:])
                     if size == 1 {
                        continue
                     }
                 }
                 v = append(v, r)
             }
             entryVal = string(v)
         }
        switch typeCode {
        case PROD_NAME_KEY:
            eepromInfo.Product_Name = entryVal
        case PART_NUM_KEY:
            eepromInfo.Part_Number = entryVal
        case SERIAL_NUM_KEY:
            eepromInfo.Serial_Number = entryVal
        case BASE_MAC_KEY:
            eepromInfo.Base_MAC_Address = entryVal
        case MFT_DATE_KEY:
            eepromInfo.Manufacture_Date = entryVal
        case DEV_VER_KEY:
            eepromInfo.Device_Version = entryVal
        case LABEL_REV_KEY:
            eepromInfo.Label_Revision = entryVal
        case PLAT_NAME_KEY:
            eepromInfo.Platform_Name = entryVal
        case ONIE_VER_KEY:
            eepromInfo.ONIE_Version = entryVal
        case NUM_MAC_KEY:
            tmp,  _ := strconv.Atoi(entryVal)
            eepromInfo.MAC_Addresses = int32(tmp)
        case MFT_NAME_KEY:
            eepromInfo.Manufacturer = entryVal
        case MFT_CNT_KEY:
            eepromInfo.Manufacture_Country = entryVal
        case VEND_NAME_KEY:
            eepromInfo.Vendor_Name = entryVal
        case DIAG_VER_KEY:
            eepromInfo.Diag_Version = entryVal
        case SERV_TAG_KEY:
            eepromInfo.Service_Tag = entryVal
        case VEND_EXT_KEY:
            eepromInfo.Vendor_Extension = entryVal
        case CRC32_KEY:
        default:
        }
    }

    return eepromInfo, err
}

func fillSysEepromInfo (eepromComp *ocbinds.OpenconfigPlatform_Components_Component,
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
    eeprom := eepromComp.State

    if all {
        eeprom.Empty = &empty
        eeprom.Removable = &removable
        eeprom.Name = &name
        eeprom.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        eeprom.Location = &location
        eepromComp.Config.Name = &name
        eeprom.Name = &name

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
        case COMP_CONFIG_NAME:
            eepromComp.Config.Name = &name
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

    var query_result = HostQuery("fetch_environment.action", "")
    if query_result.Err != nil {
        log.Error("Error in Calling dbus fetch_environment %v", query_result.Err)
        return query_result.Err
    }

    if (len(query_result.Body) < 2) {
        log.Error("Error result body is incomplete")
        return errors.New("Result body is incomplete")
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
            if len(s) < 2 {
                log.Error("Unable to parse sensor info: ", scanner.Text())
            } else if !SubCatFound || s[1] == "" {
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
    comp_name := "Sensor"
    pf_comp.State.Name = &comp_name
    pf_comp.Config.Name = &comp_name

    return  err
}

func getSysComponents(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Infof("Preparing DB for system components");

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

            var comp_cnt int
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
            err = fillSysEepromInfo(pf_comp, true, targetUriPath, d)
            if err != nil {
                return err
            }

            swversion_comp,_ := pf_cpts.NewComponent("Software")
            ygot.BuildEmptyTree(swversion_comp)
            err = getSoftwareVersionComponent(swversion_comp, targetUriPath, true, d)
            if err != nil {
                return err
            }

            comp_cnt = 0
            for i := 1; true; i++ {
                psu := "PSU " + strconv.Itoa(i)
                pf_comp, _ = pf_cpts.NewComponent(psu)
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysPsuInfo(pf_comp, psu, true, true, targetUriPath, d)
                if err != nil {
                    if comp_cnt > 0 && strings.Contains(err.Error(), "Entry does not exist") {
                        delete(pf_cpts.Component, psu)
                        err = nil
                        break
                    }
                    return err
                }
                err = fillSysPsuInfo(pf_comp, psu, true, false, targetUriPath, d)
                if err != nil {
                    return err
                }
                comp_cnt++;
            }

            comp_cnt = 0
            for i := 1; true; i++ {
                fan := "FAN " + strconv.Itoa(i)
                pf_comp, _ = pf_cpts.NewComponent(fan)
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysFanInfo(pf_comp, fan, true, true, targetUriPath, d)
                if err != nil {
                    if comp_cnt > 0 && strings.Contains(err.Error(), "Entry does not exist") {
                        delete(pf_cpts.Component, fan)
                        err = nil
                        break
                    }
                    return err
                }
                err = fillSysFanInfo(pf_comp, fan, true, false, targetUriPath, d)
                if err != nil {
                    return err
                }
                comp_cnt++
            }

            comp_cnt = 0
            for i := 1; true; i++ {
                firmware := "FIRMWARE " + strconv.Itoa(i)
                pf_comp, _ = pf_cpts.NewComponent(firmware)
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysFirmwareInfo(pf_comp, firmware, true, true, targetUriPath, d)
                if err != nil {
                    if comp_cnt > 0 && strings.Contains(err.Error(), "Entry does not exist") {
                        delete(pf_cpts.Component, firmware)
                        err = nil
                        break
                    }
                    return err
                }
                err = fillSysFirmwareInfo(pf_comp, firmware, true, false, targetUriPath, d)
                if err != nil {
                    return err
                }
                comp_cnt++
            }

            comp_cnt = 0
            for i := 1; true; i++ {
                temp := "TEMP " + strconv.Itoa(i)
                pf_comp, _ = pf_cpts.NewComponent(temp)
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysTempInfo(pf_comp, temp, true, targetUriPath, d)
                if err != nil {
                    if comp_cnt > 0 && strings.Contains(err.Error(), "Entry does not exist") {
                        delete(pf_cpts.Component, temp)
                        err = nil
                        break
                    }
                    return err
                }
                comp_cnt++
            }
            dpbCaps := getCapabilities()
            for _, prt := range dpbCaps {
                pf_comp, _ = pf_cpts.NewComponent(prt.Port)
                log.Info("DPB Adding ", prt.Port)
                ygot.BuildEmptyTree(pf_comp)
                //err = fillDpbData(pf_comp, prt.Port, targetUriPath, d)
                //log.Info(err)
            }
            return err
        } else {
            if matchStr == "system eeprom" {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    err = fillSysEepromInfo(pf_comp, true, targetUriPath, d)
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
                    err = getSoftwareVersionComponent(pf_comp, targetUriPath, true, d)
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
                err = fillSysPsuInfo(pf_comp, compName, true, false, targetUriPath, d)
            } else if validFanName(&compName) {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysFanInfo(pf_comp, compName, true, false, targetUriPath, d)
            } else if validXcvrName(&compName){
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysXcvrInfo(pf_comp, compName, true, targetUriPath, d)
            } else if validTempName(&compName) {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysTempInfo(pf_comp, compName, true, targetUriPath, d)
            } else if len(getIfName(compName)) > 1 {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name ", compName)
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
            } else if validFirmwareName(&compName) {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysFirmwareInfo(pf_comp, compName, true, false, targetUriPath, d)
            } else {
                log.Info("Invalid Component Name: ", compName)
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
                err = fillSysEepromInfo(pf_comp, true, targetUriPath, d)
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
            err = fillSysPsuInfo(pf_comp, compName, true, false, targetUriPath, d)
        } else if validFanName(&compName) {
            pf_comp := pf_cpts.Component[compName]
            if pf_comp  == nil {
                log.Info("Invalid Component Name")
                return errors.New("Invalid component name")
            }
            ygot.BuildEmptyTree(pf_comp)
            err = fillSysFanInfo(pf_comp, compName, true, false, targetUriPath, d)
        } else if validXcvrName(&compName){
            pf_comp := pf_cpts.Component[compName]
            if pf_comp  == nil {
                log.Info("Invalid Component Name")
                return errors.New("Invalid component name")
            }
            ygot.BuildEmptyTree(pf_comp)
            err = fillSysXcvrInfo(pf_comp, compName, true, targetUriPath, d)
        } else if validTempName(&compName) {
            pf_comp := pf_cpts.Component[compName]
            if pf_comp  == nil {
                log.Info("Invalid Component Name")
                return errors.New("Invalid component name")
            }
            ygot.BuildEmptyTree(pf_comp)
            ygot.BuildEmptyTree(pf_comp.Config)
            ygot.BuildEmptyTree(pf_comp.State)
            ygot.BuildEmptyTree(pf_comp.State.Temperature)
            err = fillSysTempInfo(pf_comp, compName, true, targetUriPath, d)
        } else if validFirmwareName(&compName) {
            pf_comp := pf_cpts.Component[compName]
            if pf_comp  == nil {
                log.Info("Invalid Component Name")
                return errors.New("Invalid component name")
            }
            ygot.BuildEmptyTree(pf_comp)
            err = fillSysFirmwareInfo(pf_comp, compName, true, false, targetUriPath, d)
        } else {
            log.Info("Invalid Component Name: ", compName)
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
                    err = fillSysEepromInfo(pf_comp, false, targetUriPath, d)
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
                    err = getSoftwareVersionComponent(pf_comp, targetUriPath, false, d)
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
              err = fillSysFanInfo(pf_comp, compName, true, false, targetUriPath, d)
            } else if validXcvrName(&compName){
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name")
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
                err = fillSysXcvrInfo(pf_comp, compName, true, targetUriPath, d)
            } else if validTempName(&compName) {
              pf_comp := pf_cpts.Component[compName]
              if pf_comp  == nil {
                  log.Info("Invalid Component Name")
                  return errors.New("Invalid component name")
              }
              ygot.BuildEmptyTree(pf_comp)
              err = fillSysTempInfo(pf_comp, compName, false, targetUriPath, d)
            } else if len(getIfName(compName)) > 1 {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp  == nil {
                    log.Info("Invalid Component Name", compName)
                    return errors.New("Invalid component name")
                }
                ygot.BuildEmptyTree(pf_comp)
            } else {
                log.Info("Invalid Component Name: ", compName)
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

func convertUTF8EndcodedString (s string) (string) {
     if !utf8.ValidString(s) {
	v := make([]rune, 0, len(s))
	for i, r := range s{
	    if r == utf8.RuneError {
		_, size := utf8.DecodeRuneInString(s[i:])
	       if size == 1 {
		  continue
	       }
	    }
	    v = append(v, r)
       }
       return string(v)
     }
     return s
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
    psuInfo.Input_Current = psuEntry.Get("input_current")
    psuInfo.Input_Voltage = psuEntry.Get("input_voltage")
    psuInfo.Input_Power = psuEntry.Get("input_power")
    psuInfo.Volt_Type = psuEntry.Get("type")

    psuInfo.Presence = false
    if psuEntry.Get("presence") == "true" {
        psuInfo.Presence = true
    }

    psuInfo.Status = false
    if psuEntry.Get("status") == "true" {
        psuInfo.Status = true
    }

    psuInfo.Model_Name = convertUTF8EndcodedString(psuEntry.Get("model"))
    psuInfo.Manufacturer = convertUTF8EndcodedString(psuEntry.Get("mfr_id"))
    psuInfo.Serial_Number = convertUTF8EndcodedString(psuEntry.Get("serial"))
    psuInfo.Fans = psuEntry.Get("num_fans")
    psuInfo.Status_Led = psuEntry.Get("led_status")
    psuInfo.Temperature = psuEntry.Get("temperature")
    return psuInfo, err
}

func fillSysPsuInfo (psuCom *ocbinds.OpenconfigPlatform_Components_Component,
                        name string, all bool, getPowerStats bool, targetUriPath string, d *db.DB) (error) {
    var err error
    psuInfo, err := getSysPsuFromDb(name, d)
    if err != nil {
        log.Info("Error Getting PSU info from DB")
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
            if psuInfo.Input_Current != "" {
                psuState.InputCurrent, err = float32StrTo4Bytes(psuInfo.Input_Current)
            }
            if psuInfo.Input_Voltage != "" {
                psuState.InputVoltage, err = float32StrTo4Bytes(psuInfo.Input_Voltage)
            }
            if psuInfo.Input_Power != "" {
                psuState.InputPower, err = float32StrTo4Bytes(psuInfo.Input_Power)
            }
            if psuInfo.Temperature!= "" {
                psuState.Temperature, err = float32StrTo4Bytes(psuInfo.Temperature)
            }

            if psuInfo.Volt_Type == "AC" {
                psuState.PowerType = ocbinds.OpenconfigPlatform_Components_Component_PowerSupply_State_PowerType_VOLT_AC
            } else if psuInfo.Volt_Type == "DC" {
                psuState.PowerType = ocbinds.OpenconfigPlatform_Components_Component_PowerSupply_State_PowerType_VOLT_DC
            }

            if err != nil {
                log.Info("float data error")
                return err
            }
            return err
        }
        psuCom.Config.Name = &name
        psuEepromState.Name = &name
        psuEepromState.Empty = &empty
        psuEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_DISABLED
        if psuInfo.Presence {
            if psuInfo.Status {
                psuEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
            } else {
                psuEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_INACTIVE
            }
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
    case PSU_INPUT_CURRENT:
        if psuInfo.Input_Current != "" {
            psuState.InputCurrent, err = float32StrTo4Bytes(psuInfo.Input_Current)
        }
    case PSU_INPUT_VOLTAGE:
        if psuInfo.Input_Voltage != ""{
            psuState.InputVoltage, err = float32StrTo4Bytes(psuInfo.Input_Voltage)
        }
    case PSU_INPUT_POWER:
        if psuInfo.Input_Power != "" {
            psuState.InputPower, err = float32StrTo4Bytes(psuInfo.Input_Power)
        }
    case PSU_TEMPERATURE:
        if psuInfo.Temperature != "" {
            psuState.Temperature, err = float32StrTo4Bytes(psuInfo.Temperature)
        }
    case PSU_VOLT_TYPE:
        psuState.PowerType = ocbinds.OpenconfigPlatform_Components_Component_PowerSupply_State_PowerType_UNSET
        if psuInfo.Volt_Type == "AC" {
            psuState.PowerType = ocbinds.OpenconfigPlatform_Components_Component_PowerSupply_State_PowerType_VOLT_AC
        } else if psuInfo.Volt_Type == "DC" {
            psuState.PowerType = ocbinds.OpenconfigPlatform_Components_Component_PowerSupply_State_PowerType_VOLT_DC
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
    case COMP_STATE_NAME:
        psuEepromState.Name = &name
    case COMP_CONFIG_NAME:
        psuCom.Config.Name = &name
    }

    return err
}

func validPsuName(name *string) bool {
    if name == nil || *name == "" {
        return false
    }
    valid, _ := regexp.MatchString("PSU [1-9][0-9]*$", *name)
    return valid
}

func getSysPsu(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Info("Preparing DB for PSU info");

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
        }
    }
    return err
}

func validFanName(name *string) (bool) {
    if name == nil || *name == "" {
        return false
    }
    validFan, _ := regexp.MatchString("(PSU [1-9][0-9]* ){0,1}FAN [1-9][0-9]*$", *name)
    return validFan
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
    fanInfo.Status_Led = fanEntry.Get("led_status")

    return fanInfo, err
}

func fillSysFanInfo (fanCom *ocbinds.OpenconfigPlatform_Components_Component,
                        name string, all bool, getFanStats bool, targetUriPath string, d *db.DB) (error) {
    var err error
    var tmp uint64

    fanInfo, err := getSysFanFromDb(name, d)
    if err != nil {
        log.Info("Error Getting fan info from DB")
        return err
    }

    empty := !fanInfo.Presence
    fanState := fanCom.Fan.State
    fanEepromState := fanCom.State
    if all {
        if getFanStats {
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

        fanCom.Config.Name = &name
        fanEepromState.Name = &name
        fanEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_DISABLED
        if fanInfo.Presence {
            if fanInfo.Status {
                fanEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
            } else {
                fanEepromState.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_INACTIVE
            }
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
        fanEepromState.Name = &name
        if fanInfo.Name != "" {
            fanEepromState.Name = &fanInfo.Name
        }
    case COMP_CONFIG_NAME:
        fanCom.Config.Name = &name
    }

    return err
}

func getSysFans(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Info("Preparing DB for Fan info");

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
        log.Info("Cant get entry in TRANSCEIVER_TBL   ", name)
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

    xcvrInfo.Vendor_Name = xcvrEntry.Get("manufacturename")
    xcvrInfo.Vendor_Part_Number = xcvrEntry.Get("modelname")
    xcvrInfo.Vendor_Serial_Number = xcvrEntry.Get("serialnum")
    xcvrInfo.Vendor_Revision = xcvrEntry.Get("hardwarerev")
    xcvrInfo.Vendor_Date_Code = xcvrEntry.Get("vendor_date")
    xcvrInfo.Vendor_OUI = xcvrEntry.Get("vendor_oui")
    xcvrInfo.Revision_Compliance = xcvrEntry.Get("revision_compliance")

    xcvrDOMEntry, err := d.GetEntry(&db.TableSpec{Name: TRANSCEIVER_DOM}, db.Key{Comp: []string{name}})
    if err != nil {
        log.Info("Cant get entry in TRANSCEIVER_DOM: ", name)
        xcvrInfo.Presence = false
        return xcvrInfo, err
    }

    xcvrInfo.LolLane_1 = xcvrDOMEntry.Get("rx1lol")
    xcvrInfo.LolLane_2 = xcvrDOMEntry.Get("rx2lol")
    xcvrInfo.LolLane_3 = xcvrDOMEntry.Get("rx3lol")
    xcvrInfo.LolLane_4 = xcvrDOMEntry.Get("rx4lol")
    xcvrInfo.LolLane_5 = xcvrDOMEntry.Get("rx5lol")
    xcvrInfo.LolLane_6 = xcvrDOMEntry.Get("rx6lol")
    xcvrInfo.LolLane_7 = xcvrDOMEntry.Get("rx7lol")
    xcvrInfo.LolLane_8 = xcvrDOMEntry.Get("rx8lol")

    xcvrInfo.LosLane_1 = xcvrDOMEntry.Get("rx1los")
    xcvrInfo.LosLane_2 = xcvrDOMEntry.Get("rx2los")
    xcvrInfo.LosLane_3 = xcvrDOMEntry.Get("rx3los")
    xcvrInfo.LosLane_4 = xcvrDOMEntry.Get("rx4los")
    xcvrInfo.LosLane_5 = xcvrDOMEntry.Get("rx5los")
    xcvrInfo.LosLane_6 = xcvrDOMEntry.Get("rx6los")
    xcvrInfo.LosLane_7 = xcvrDOMEntry.Get("rx7los")
    xcvrInfo.LosLane_8 = xcvrDOMEntry.Get("rx8los")

    xcvrInfo.RxPowerLane_1 = xcvrDOMEntry.Get("rx1power")
    xcvrInfo.RxPowerLane_2 = xcvrDOMEntry.Get("rx2power")
    xcvrInfo.RxPowerLane_3 = xcvrDOMEntry.Get("rx3power")
    xcvrInfo.RxPowerLane_4 = xcvrDOMEntry.Get("rx4power")
    xcvrInfo.RxPowerLane_5 = xcvrDOMEntry.Get("rx5power")
    xcvrInfo.RxPowerLane_6 = xcvrDOMEntry.Get("rx6power")
    xcvrInfo.RxPowerLane_7 = xcvrDOMEntry.Get("rx7power")
    xcvrInfo.RxPowerLane_8 = xcvrDOMEntry.Get("rx8power")
    xcvrInfo.TxBiasLane_1  = xcvrDOMEntry.Get("tx1bias")
    xcvrInfo.TxBiasLane_2  = xcvrDOMEntry.Get("tx2bias")
    xcvrInfo.TxBiasLane_3  = xcvrDOMEntry.Get("tx3bias")
    xcvrInfo.TxBiasLane_4  = xcvrDOMEntry.Get("tx4bias")
    xcvrInfo.TxBiasLane_5  = xcvrDOMEntry.Get("tx5bias")
    xcvrInfo.TxBiasLane_6  = xcvrDOMEntry.Get("tx6bias")
    xcvrInfo.TxBiasLane_7  = xcvrDOMEntry.Get("tx7bias")
    xcvrInfo.TxBiasLane_8  = xcvrDOMEntry.Get("tx8bias")
    xcvrInfo.TxPowerLane_1 = xcvrDOMEntry.Get("tx1power")
    xcvrInfo.TxPowerLane_2 = xcvrDOMEntry.Get("tx2power")
    xcvrInfo.TxPowerLane_3 = xcvrDOMEntry.Get("tx3power")
    xcvrInfo.TxPowerLane_4 = xcvrDOMEntry.Get("tx4power")
    xcvrInfo.TxPowerLane_5 = xcvrDOMEntry.Get("tx5power")
    xcvrInfo.TxPowerLane_6 = xcvrDOMEntry.Get("tx6power")
    xcvrInfo.TxPowerLane_7 = xcvrDOMEntry.Get("tx7power")
    xcvrInfo.TxPowerLane_8 = xcvrDOMEntry.Get("tx8power")
    xcvrInfo.Temperature   = xcvrDOMEntry.Get("temperature")
    xcvrInfo.Voltage       = xcvrDOMEntry.Get("voltage")

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

    log.Infof("DS: fillSysXcvrInfo: %v, %v", name, all)

    xcvrInfo, err := getSysXcvrFromDb(name, d)
    if err != nil {
        log.Info("Error Getting transceiver info from DB")
        return err
    }

    xcvrState := xcvrCom.Transceiver.State
    xcvrEEPROMState := xcvrCom.State

    if all {

        /* Top level */
        nm := name
        xcvrEEPROMState.Name = &nm
        xcvrCom.Config.Name = &nm

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
        if (test_if_available(xcvrInfo.Revision_Compliance)){
            xcvrState.RevisionCompliance = &xcvrInfo.Revision_Compliance
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
        case COMP_CONFIG_NAME:
            nm := name
            xcvrCom.Config.Name = &nm
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
        case XCVR_REVISION_COMPLIANCE:
            if (test_if_available(xcvrInfo.Revision_Compliance)){
                xcvrState.RevisionCompliance = &xcvrInfo.Revision_Compliance
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

    /* log.Info("Preparing DB for XCVR info"); */

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
        case "/openconfig-platform:components/component/openconfig-platform-transceiver:transceiver":
            fallthrough
        case "/openconfig-platform:components/component/openconfig-platform-transceiver:transceiver/state":
            fillSysXcvrInfo(xcvrCom, xcvrId, true, targetUriPath, d)
        default:
            /* For individual components*/
            fillSysXcvrInfo(xcvrCom, xcvrId, false, targetUriPath, d)
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

func validTempName(name *string) bool {
    if name == nil || *name == "" {
        return false
    }
    valid, _ := regexp.MatchString("TEMP [1-9][0-9]*$", *name)
    return valid
}

func getSysTempFromDb(name string, d *db.DB) (TempSensor, error) {
    var tempInfo TempSensor
    var err error

    tempEntry, err := d.GetEntry(&db.TableSpec{Name: TEMP_TBL}, db.Key{Comp: []string{name}})

    if err != nil {
        log.Info("Cant get entry: ", name)
    }

    tempInfo.Current = tempEntry.Get("temperature")
    tempInfo.Name = tempEntry.Get("name")
    tempInfo.Crit_High_Threshold = tempEntry.Get("critical_high_threshold")
    tempInfo.Crit_Low_Threshold = tempEntry.Get("critical_low_threshold")
    tempInfo.High_Threshold = tempEntry.Get("high_threshold")
    tempInfo.Low_Threshold = tempEntry.Get("low_threshold")
    tempInfo.Timestamp = tempEntry.Get("timestamp")
    tempInfo.Warning_Status = tempEntry.Get("warning_status")

    return tempInfo, err
}

/* This function converts the timestamp stored in the DB to the pattern accepted
 * by the IETF timestamp pattern specified in the YANG model
 */
func convertToIetfTime(time string) (string) {
    time = time[:8] + "T" + time[9:]
    time = time[:4] + "-" + time[4:6] + "-" + time[6:8] + time[8:] + "Z"
    return time
}

func fillSysTempInfo (temp *ocbinds.OpenconfigPlatform_Components_Component,
                        name string, all bool, targetUriPath string, d *db.DB) (error) {
    var err error
    tempInfo, err := getSysTempFromDb(name, d)
    if err != nil {
        log.Info("Error Getting Temp Sensor info from DB")
        return err
    }

    tempCom := temp.State.Temperature
    tempState := temp.State

    if all || targetUriPath == TEMP_COMP {
        tempState.Name = &name
        temp.Config.Name = &name
        if tempInfo.Name != "" {
            tempState.Name = &tempInfo.Name
        }
        if tempInfo.Current != "" {
            cur, terr := strconv.ParseFloat(tempInfo.Current, 64)
            if terr != nil {
                return terr
            }
            tempCom.Current = &cur
        }
        if tempInfo.Crit_High_Threshold != "" {
            cht, terr := strconv.ParseFloat(tempInfo.Crit_High_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.CriticalHighThreshold = &cht
        }
        if tempInfo.Crit_Low_Threshold != "" {
            clt, terr := strconv.ParseFloat(tempInfo.Crit_Low_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.CriticalLowThreshold = &clt
        }
        if tempInfo.High_Threshold != "" {
            ht, terr := strconv.ParseFloat(tempInfo.High_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.HighThreshold = &ht
        }
        if tempInfo.Low_Threshold != "" {
            lt, terr := strconv.ParseFloat(tempInfo.Low_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.LowThreshold = &lt
        }
        warning := false
        if tempInfo.Warning_Status != "" && strings.ToLower(tempInfo.Warning_Status) == "true" {
            warning = true
        }
        tempCom.WarningStatus = &warning

        if tempInfo.Timestamp != "" {
            timeStamp := convertToIetfTime(tempInfo.Timestamp)
            tempCom.Timestamp = &timeStamp
        }

        return err
    }

    switch targetUriPath {
    case COMP_CONFIG_NAME:
        temp.Config.Name = &name
    case COMP_STATE_NAME:
        tempState.Name = &name
        if tempInfo.Name != "" {
            tempState.Name = &tempInfo.Name
        }
    case TEMP_CURRENT:
        if tempInfo.Current != "" {
            cur, terr := strconv.ParseFloat(tempInfo.Current, 64)
            if terr != nil {
                return terr
            }
            tempCom.Current = &cur
        }
    case TEMP_CRIT_HIGH_THRES:
        if tempInfo.Crit_High_Threshold != "" {
            cht, terr := strconv.ParseFloat(tempInfo.Crit_High_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.CriticalHighThreshold = &cht
        }
    case TEMP_CRIT_LOW_THRES:
        if tempInfo.Crit_Low_Threshold != "" {
            clt, terr := strconv.ParseFloat(tempInfo.Crit_Low_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.CriticalLowThreshold = &clt
        }
    case TEMP_HIGH_THRES:
        if tempInfo.High_Threshold != "" {
            ht, terr := strconv.ParseFloat(tempInfo.High_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.HighThreshold = &ht
        }
    case TEMP_LOW_THRES:
        if tempInfo.Low_Threshold != "" {
            lt, terr := strconv.ParseFloat(tempInfo.Low_Threshold, 64)
            if terr != nil {
                return terr
            }
            tempCom.LowThreshold = &lt
        }
    case TEMP_WARNING_STATUS:
        warning := false
        if tempInfo.Warning_Status != "" && strings.ToLower(tempInfo.Warning_Status) == "true" {
            warning = true
        }
        tempCom.WarningStatus = &warning
    case TEMP_TIMESTAMP:
        if tempInfo.Timestamp != "" {
            timeStamp := convertToIetfTime(tempInfo.Timestamp)
            tempCom.Timestamp = &timeStamp
        }
    }

    return err
}

/** Get Firmware **/

func validFirmwareName(name *string) bool {
    if name == nil || *name == "" {
        return false
    }
    valid, _ := regexp.MatchString("FIRMWARE [1-9][0-9]*$", *name)
    return valid
}

func getSysFirmwareFromDb(name string, d *db.DB) (Firmware, error) {
    var firmwareInfo Firmware
    var err error

    firmwareEntry, err := d.GetEntry(&db.TableSpec{Name: FIRMWARE_TBL}, db.Key{Comp: []string{name}})

    if err != nil {
        log.Info("Cant get entry: ", name)
    }

    firmwareInfo.Chassis = firmwareEntry.Get("chassis")
    firmwareInfo.Description = firmwareEntry.Get("description")
    firmwareInfo.Module = firmwareEntry.Get("module")
    firmwareInfo.Name = firmwareEntry.Get("name")
    firmwareInfo.Version = firmwareEntry.Get("version")

    return firmwareInfo, err
}

func fillSysFirmwareInfo (firmwareCom *ocbinds.OpenconfigPlatform_Components_Component,
                        name string, all bool, getProperty bool, targetUriPath string, d *db.DB) (error) {
    var err error

    firmwareInfo, err := getSysFirmwareFromDb(name, d)
    if err != nil {
        log.Info("Error Getting firmware info from DB")
        return err
    }

    firmwareCh := firmwareCom.Chassis.State
    firmware := firmwareCom.State

    if all {
        if getProperty {
            if firmwareInfo.Chassis != "" {
                firmwareCh.Name = &firmwareInfo.Chassis
            }

            if firmwareInfo.Module != "" {
                firmwareCh.Module = &firmwareInfo.Module
            }
            return err
        }

        firmwareCom.Config.Name = &name
        firmware.Name = &name
        if firmwareInfo.Description != "" {
            firmware.Description = &firmwareInfo.Description
        }
        if firmwareInfo.Name != "" {
            firmware.Name = &firmwareInfo.Name
        }
        if firmwareInfo.Version != "" {
            firmware.FirmwareVersion = &firmwareInfo.Version
        }
        return err
    }

    switch targetUriPath {
    case COMP_STATE_DESCR:
        if firmwareInfo.Description != "" {
            firmware.Description = &firmwareInfo.Description
        }
    case COMP_STATE_FIRM_VER:
        if firmwareInfo.Version != "" {
            firmware.FirmwareVersion = &firmwareInfo.Version
        }
    case COMP_STATE_NAME:
        firmware.Name = &name
        if firmwareInfo.Name != "" {
            firmware.Name = &firmwareInfo.Name
        }
    case COMP_CONFIG_NAME:
        firmwareCom.Config.Name = &name
    case FIRMWARE_CHASSIS_STATE_MODULE:
        if firmwareInfo.Module != "" {
            firmwareCh.Module = &firmwareInfo.Module
        }
    case FIRMWARE_CHASSIS_STATE_NAME:
        if firmwareInfo.Chassis != "" {
            firmwareCh.Name = &firmwareInfo.Chassis
        }
    }

    return err
}

func getSysFirmware(pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string, d *db.DB) (error) {

    log.Info("Preparing DB for Firmware info");

    var err error
    log.Info("targetUriPath:", targetUriPath)
    firmwareName := NewPathInfo(uri).Var("name")

    if validFirmwareName(&firmwareName) {
        firmwareCom := pf_cpts.Component[firmwareName]
        if firmwareCom  == nil {
            log.Info("Invalid Component Name")
            return errors.New("Invalid component name")
        }
        ygot.BuildEmptyTree(firmwareCom)
        ygot.BuildEmptyTree(firmwareCom.Chassis)
        switch targetUriPath {
        case COMP:
            fallthrough
        case FIRMWARE_CHASSIS:
            fallthrough
        case FIRMWARE_CHASSIS_STATE:
            fillSysFirmwareInfo(firmwareCom, firmwareName, true, true, targetUriPath, d)
        default:
            fillSysFirmwareInfo(firmwareCom, firmwareName, false, true, targetUriPath, d)
        }
    }
    return err
}
