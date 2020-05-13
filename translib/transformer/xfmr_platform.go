//////////////////////////////////////////////////////////////////////////
//
// Copyright 2019 Dell, Inc.
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
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/openconfig/ygot/ygot"
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
)

/**
Structure Eeprom read from stateDb
*/

type Eeprom  struct {
    Product_Name        string
    Part_Number         string
    Serial_Number       string
    Base_MAC_Address    string
    Manufacture_Date    string
    Device_Version      string
    Label_Revision      string
    Platform_Name       string
    ONIE_Version        string
    MAC_Addresses       int32
    Manufacturer        string
    Manufacture_Country string
    Vendor_Name         string
    Diag_Version        string
    Service_Tag         string
    Vendor_Extension    string
    Magic_Number        int32
    Card_Type           string
    Hardware_Version    string
    Software_Version    string
    Model_Name          string

}

func init () {
    XlateFuncBind("DbToYang_pfm_components_xfmr", DbToYang_pfm_components_xfmr)
}

func getPfmRootObject (s *ygot.GoStruct) (*ocbinds.OpenconfigPlatform_Components) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Components
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
	    var pf_docker_ver *ocbinds.OpenconfigPlatform_Components_Component_Software_DockerVersion
	    s := strings.Fields(scanner.Text())
	    pf_docker_ver,_ = swComp.NewDockerVersion(scanner.Text())
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
                var pf_docker_ver *ocbinds.OpenconfigPlatform_Components_Component_Software_DockerVersion
                s := strings.Fields(scanner.Text())
                pf_docker_ver,_ = swComp.NewDockerVersion(scanner.Text())
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
        pf_scomp,_ := pf_comp.Subcomponents.NewSubcomponent(scanner.Text())
        ygot.BuildEmptyTree(pf_scomp)

        scanner.Scan()
        for scanner.Text() != "" {
            s := strings.Split(scanner.Text(), ":")
            if !SubCatFound || s[1] == "" {
                log.Infof("scomp: %s",scanner.Text())
                pf_sensor_cat,_ = pf_scomp.State.NewSensorCategory(scanner.Text())
                ygot.BuildEmptyTree(pf_sensor_cat)
                SubCatFound = true
            } else {
                val := s[1]
                name := s[0]
                pf_sensor,_ := pf_sensor_cat.NewSensor(name)
                ygot.BuildEmptyTree(pf_sensor)
                pf_sensor.State = &val
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
    case "/openconfig-platform:components":
        sensor_comp,_  := pf_cpts.NewComponent("Sensor")
        ygot.BuildEmptyTree(sensor_comp)
        sensor_comp.State.Type,_ = sensor_comp.State.To_OpenconfigPlatform_Components_Component_State_Type_Union(
                            ocbinds.OpenconfigPlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_SENSOR)
        err = getPlatformEnvironment(sensor_comp)
        if err != nil {
            return err
        }
        eeprom_comp,_ := pf_cpts.NewComponent("System Eeprom")
        ygot.BuildEmptyTree(eeprom_comp)
        err = fillSysEepromInfo(eeprom_comp.State, true, targetUriPath, d)
        if err != nil {
            return err
        }
        eeprom_comp.State.Type,_ = eeprom_comp.State.To_OpenconfigPlatform_Components_Component_State_Type_Union(
                                ocbinds.OpenconfigPlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CHASSIS)

        swversion_comp,_ := pf_cpts.NewComponent("Software")
        ygot.BuildEmptyTree(swversion_comp)
        err = getSoftwareVersionComponent(swversion_comp.Software, targetUriPath, true, d)
        if err != nil {
            return err
        }

        return err
    case "/openconfig-platform:components/component":
        compName := NewPathInfo(uri).Var("name")
        log.Infof("compName: %v", compName)
        if compName == "" {
            pf_comp,_ := pf_cpts.NewComponent("System Eeprom")
            ygot.BuildEmptyTree(pf_comp)
            err = fillSysEepromInfo(pf_comp.State, true, targetUriPath, d)
            if err != nil {
                return err
            }
        } else {
            if strings.ToLower(compName) == "system eeprom" {
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
            } else if strings.ToLower(compName) == "sensor" {
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
            } else if strings.ToLower(compName) == "software" {
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
            } else {
                err = errors.New("Invalid component name")
            }
        }
    case "/openconfig-platform:components/component/state":
        compName := NewPathInfo(uri).Var("name")
        if compName != "" && strings.ToLower(compName) == "system eeprom" {
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
        } else if compName != "" && strings.ToLower(compName) == "sensor" {
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
        } else {
            err = errors.New("Invalid component name ")
        }

    default:
        if strings.Contains(targetUriPath, "/openconfig-platform:components/component") {
            compName := NewPathInfo(uri).Var("name")
            if strings.ToLower(compName) == "system eeprom" {
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
            } else if strings.ToLower(compName) == "software" {
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
            } else {
                err = errors.New("Invalid input component name")
            }
        } else {
            err = errors.New("Invalid Path")
        }
    }
    return err
}

