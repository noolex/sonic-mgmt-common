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
    "encoding/json"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "os"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "io/ioutil"
    "bufio"
    "strings"
    "syscall"
    "strconv"
    log "github.com/golang/glog"
)

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
        return getSysEepromJson(getPfmRootObject(inParams.ygRoot), targetUriPath, inParams.uri)
    }
    return errors.New("Component not supported")
}


/**
Map of openconfig attributes
*/

var ocAttr = map[string]string{
    "SOFTWARE-COMPONENT"        :"/openconfig-platform:components/component/openconfig-platform-ext:software",
    "SOFTWARE-VERSION"          :"/openconfig-platform:components/component/openconfig-platform-ext:software/software-version",
    "PRODUCT-VERSION"           :"/openconfig-platform:components/component/openconfig-platform-ext:software/product-version",
    "DISTRIBUTION-VERSION"      :"/openconfig-platform:components/component/openconfig-platform-ext:software/distribution-version",
    "KERNEL-VERSION"            :"/openconfig-platform:components/component/openconfig-platform-ext:software/kernel-version",
    "BUILD-COMMIT"              :"/openconfig-platform:components/component/openconfig-platform-ext:software/build-commit",
    "BUILD-DATE"                :"/openconfig-platform:components/component/openconfig-platform-ext:software/build-date",
    "BUILT-BY"                  :"/openconfig-platform:components/component/openconfig-platform-ext:software/built-by",
    "PLATFORM-NAME"             :"/openconfig-platform:components/component/openconfig-platform-ext:software/platform-name",
    "HWSKU-VERSION"             :"/openconfig-platform:components/component/openconfig-platform-ext:software/hwsku-version",
    "ASIC-VERSION"              :"/openconfig-platform:components/component/openconfig-platform-ext:software/asic-version",
    "HARDWARE-VERSION"          :"/openconfig-platform:components/component/openconfig-platform-ext:software/hardware-version",
    "SERIAL-NUMBER"             :"/openconfig-platform:components/component/openconfig-platform-ext:software/serial-number",
    "UP-TIME"                   :"/openconfig-platform:components/component/openconfig-platform-ext:software/up-time",
    "MFG-NAME"                  :"/openconfig-platform:components/component/openconfig-platform-ext:software/mfg-name",
    "DOCKER-VERSION"            :"/openconfig-platform:components/component/openconfig-platform-ext:software/docker-version",
    "COMPONENT-NAME"            :"/openconfig-platform:components/component/state/name",
    "LOCATION"                  :"/openconfig-platform:components/component/state/location",
    "EMPTY"                     :"/openconfig-platform:components/component/state/empty",
    "REMOVABLE"                 :"/openconfig-platform:components/component/state/removable",
    "OPER-STATUS"               :"/openconfig-platform:components/component/state/oper-status",
    "STATE-ID"                  :"/openconfig-platform:components/component/state/id",
    "PART-NO"                   :"/openconfig-platform:components/component/state/part-no",
    "SERIAL-NO"                 :"/openconfig-platform:components/component/state/serial-no",
    "MFG-DATE"                  :"/openconfig-platform:components/component/state/mfg-date",
    "STATE-HARDWARE-VERSION"    :"/openconfig-platform:components/component/state/hardware-version",
    "DESCRIPTION"               :"/openconfig-platform:components/component/state/description",
    "STATE-MFG-NAME"            :"/openconfig-platform:components/component/state/mfg-name",
    "STATE-SOFTWARE-VERSION"    :"/openconfig-platform:components/component/state/software-version",

}

/**
Structures to read syseeprom from json file
*/

type JSONEeprom  struct {
    Product_Name        string `json:"Product Name"`
    Part_Number         string `json:"Part Number"`
    Serial_Number       string `json:"Serial Number"`
    Base_MAC_Address    string `json:"Base MAC Address"`
    Manufacture_Date    string `json:"Manufacture Date"`
    Device_Version      string `json:"Device Version"`
    Label_Revision      string `json:"Label Revision"`
    Platform_Name       string `json:"Platform Name"`
    ONIE_Version        string `json:"ONIE Version"`
    MAC_Addresses       int    `json:"MAC Addresses"`
    Manufacturer        string `json:"Manufacturer"`
    Manufacture_Country  string `json:"Manufacture Country"`
    Vendor_Name         string `json:"Vendor Name"`
    Diag_Version        string `json:"Diag Version"`
    Service_Tag         string `json:"Service Tag"`
    Vendor_Extension    string `json:"Vendor Extension"`
    Magic_Number        int    `json:"Magic Number"`
    Card_Type           string `json:"Card Type"`
    Hardware_Version    string `json:"Hardware Version"`
    Software_Version    string `json:"Software Version"`
    Model_Name          string `json:"Model Name"`
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

func getSoftwareVersionComponent (swComp *ocbinds.OpenconfigPlatform_Components_Component_Software, targetUriPath string, allAttr bool) (error) {

    versionScanner := bufio.NewScanner(strings.NewReader(""))
    scanner := bufio.NewScanner(strings.NewReader(""))
    var jsoneeprom JSONEeprom
    var err error

    if allAttr == true || targetUriPath == ocAttr["SOFTWARE-COMPONENT"] || targetUriPath == ocAttr["DISTRIBUTION-VERSION"] || targetUriPath == ocAttr["KERNEL-VERSION"] ||
       targetUriPath == ocAttr["BUILD-COMMIT"] || targetUriPath == ocAttr["ASIC-VERSION"] || targetUriPath == ocAttr["BUILD-DATE"] ||
       targetUriPath == ocAttr["BUILT-BY"] || targetUriPath == ocAttr["SOFTWARE-VERSION"]{
        swVersionFile, err := os.Open("/etc/sonic/sonic_version.yml")
        if err != nil {
            log.Infof("sonic_version.yml open failed")
            errStr := "Information not available or Not supported"
            terr := tlerr.NotFoundError{Format: errStr}
            return terr
        }
        defer swVersionFile.Close()
        versionScanner = bufio.NewScanner(swVersionFile)
        versionScanner.Split(bufio.ScanLines)
    }

    if allAttr == true || targetUriPath == ocAttr["SOFTWARE-COMPONENT"] || targetUriPath == ocAttr["HWSKU-VERSION"] || targetUriPath == ocAttr["HARDWARE-VERSION"] ||
       targetUriPath == ocAttr["PLATFORM-NAME"] || targetUriPath == ocAttr["SERIAL-NUMBER"] || targetUriPath == ocAttr["MFG-NAME"] {
        jsonFile, err := os.Open("/mnt/platform/syseeprom")
        if err != nil {
            log.Infof("syseeprom.json open failed")
            errStr := "Information not available or Not supported"
            terr := tlerr.NotFoundError{Format: errStr}
            return terr
        }
        defer jsonFile.Close()
        byteValue, _ := ioutil.ReadAll(jsonFile)
        json.Unmarshal(byteValue, &jsoneeprom)
    }

    if allAttr == true || targetUriPath == ocAttr["SOFTWARE-COMPONENT"] || targetUriPath == ocAttr["DOCKER-VERSION"] {
        var query_result HostResult
        query_result = HostQuery("docker_version.action", "")
        if query_result.Err != nil {
            log.Infof("Error in Calling dbus fetch_environment %v", query_result.Err)
        }
        env_op := query_result.Body[1].(string)
        scanner = bufio.NewScanner(strings.NewReader(env_op))
    }

    if allAttr == true || targetUriPath == ocAttr["SOFTWARE-COMPONENT"] {
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

	if jsoneeprom.Platform_Name != "" {
	    swComp.PlatformName = &jsoneeprom.Platform_Name
	}
	if jsoneeprom.Product_Name != "" && jsoneeprom.Vendor_Name != ""{
	    HwskuVer := jsoneeprom.Product_Name + "-" + jsoneeprom.Vendor_Name
	    swComp.HwskuVersion = &HwskuVer
	}
	if jsoneeprom.Label_Revision != "" {
	    swComp.HardwareVersion = &jsoneeprom.Label_Revision
	}
	if jsoneeprom.Serial_Number != "" {
	    swComp.SerialNumber = &jsoneeprom.Serial_Number
	}
	if jsoneeprom.Vendor_Name != "" {
	    swComp.MfgName = &jsoneeprom.Vendor_Name
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
        case ocAttr["SOFTWARE-VERSION"]:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "build_version:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.SoftwareVersion = &res1[1]
                    break
                }
            }
        case ocAttr["DISTRIBUTION-VERSION"]:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "debian_version:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.DistributionVersion = &res1[1]
                    break
                }
            }
        case ocAttr["KERNEL-VERSION"]:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "kernel_version:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.KernelVersion = &res1[1]
                    break
                }
            }
        case ocAttr["ASIC-VERSION"]:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "asic_type:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.AsicVersion = &res1[1]
                    break
                }
            }
        case ocAttr["BUILD-COMMIT"]:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "commit_id:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.BuildCommit = &res1[1]
                    break
                }
            }
        case ocAttr["BUILD-DATE"]:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "build_date:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.BuildDate = &res1[1]
                    break
                }
            }
        case ocAttr["BUILT-BY"]:
            for versionScanner.Scan() {
                if strings.Contains(versionScanner.Text(), "built_by:") {
                    res1 := strings.Split(versionScanner.Text(), ": ")
                    swComp.BuiltBy = &res1[1]
                    break
                }
            }
        case ocAttr["PLATFORM-NAME"]:
            if jsoneeprom.Platform_Name != "" {
                swComp.PlatformName = &jsoneeprom.Platform_Name
            }
        case ocAttr["HWSKU-VERSION"]:
            if jsoneeprom.Product_Name != "" && jsoneeprom.Vendor_Name != ""{
                HwskuVer := jsoneeprom.Product_Name + "-" + jsoneeprom.Vendor_Name
                swComp.HwskuVersion = &HwskuVer
            }
        case ocAttr["HARDWARE-VERSION"]:
            if jsoneeprom.Label_Revision != "" {
                swComp.HardwareVersion = &jsoneeprom.Label_Revision
            }
        case ocAttr["SERIAL-NUMBER"]:
            if jsoneeprom.Serial_Number != "" {
                swComp.SerialNumber = &jsoneeprom.Serial_Number
            }
        case ocAttr["MFG-NAME"]:
            if jsoneeprom.Vendor_Name != "" {
                swComp.MfgName = &jsoneeprom.Vendor_Name
            }
        case ocAttr["UP-TIME"]:
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
        case ocAttr["DOCKER-VERSION"]:
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

func getSysEepromFromFile (eeprom *ocbinds.OpenconfigPlatform_Components_Component_State,
				 all bool, targetUriPath string) (error) {

    log.Infof("getSysEepromFromFile Enter")
    jsonFile, err := os.Open("/mnt/platform/syseeprom")
    if err != nil {
        log.Infof("syseeprom.json open failed")
        errStr := "Information not available or Not supported"
        terr := tlerr.NotFoundError{Format: errStr}
        return terr
    }

    defer jsonFile.Close()

    byteValue, _ := ioutil.ReadAll(jsonFile)
    var jsoneeprom JSONEeprom

    json.Unmarshal(byteValue, &jsoneeprom)
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

        if jsoneeprom.Product_Name != "" {
            eeprom.Id = &jsoneeprom.Product_Name
        }
        if jsoneeprom.Part_Number != "" {
            eeprom.PartNo = &jsoneeprom.Part_Number
        }
        if jsoneeprom.Serial_Number != "" {
            eeprom.SerialNo = &jsoneeprom.Serial_Number
        }
        if jsoneeprom.Base_MAC_Address != "" {
        }
        if jsoneeprom.Manufacture_Date != "" {
            mfg_date := jsoneeprom.Manufacture_Date[6:10] + "-" +
                jsoneeprom.Manufacture_Date[0:2] + "-" + jsoneeprom.Manufacture_Date[3:5]
            eeprom.MfgDate = &mfg_date
        }
        if jsoneeprom.Label_Revision != "" {
            eeprom.HardwareVersion = &jsoneeprom.Label_Revision
        }
        if jsoneeprom.Platform_Name != "" {
            eeprom.Description = &jsoneeprom.Platform_Name
        }
        if jsoneeprom.ONIE_Version != "" {
        }
        if jsoneeprom.MAC_Addresses != 0 {
        }
        if jsoneeprom.Manufacturer != "" {
            eeprom.MfgName = &jsoneeprom.Manufacturer
        }
        if jsoneeprom.Manufacture_Country != "" {
        }
        if jsoneeprom.Vendor_Name != "" {
            if eeprom.MfgName == nil {
                eeprom.MfgName = &jsoneeprom.Vendor_Name
            }
        }
        if jsoneeprom.Diag_Version != "" {
        }
        if jsoneeprom.Service_Tag != "" {
            if eeprom.SerialNo == nil {
                eeprom.SerialNo = &jsoneeprom.Service_Tag
            }
        }
        if jsoneeprom.Hardware_Version != "" {
            eeprom.HardwareVersion = &jsoneeprom.Hardware_Version
        }
        if jsoneeprom.Software_Version != "" {
            eeprom.SoftwareVersion = &jsoneeprom.Software_Version
        } else {
            versionString := getSoftwareVersion()
            eeprom.SoftwareVersion = &versionString
        }
    } else {
        switch targetUriPath {
        case ocAttr["COMPONENT-NAME"]:
            eeprom.Name = &name
        case ocAttr["LOCATION"]:
            eeprom.Location = &location
        case ocAttr["EMPTY"]:
            eeprom.Empty = &empty
        case ocAttr["REMOVABLE"]:
            eeprom.Removable = &removable
        case ocAttr["OPER-STATUS"]:
            eeprom.OperStatus = ocbinds.OpenconfigPlatformTypes_COMPONENT_OPER_STATUS_ACTIVE
        case ocAttr["STATE-ID"]:
            if jsoneeprom.Product_Name != "" {
                eeprom.Id = &jsoneeprom.Product_Name
            }
        case ocAttr["PART-NO"]:
            if jsoneeprom.Part_Number != "" {
                eeprom.PartNo = &jsoneeprom.Part_Number
            }
        case ocAttr["SERAIL-NO"]:
            if jsoneeprom.Serial_Number != "" {
                eeprom.SerialNo = &jsoneeprom.Serial_Number
            }
            if jsoneeprom.Service_Tag != "" {
                if eeprom.SerialNo == nil || *eeprom.SerialNo == "" {
                    eeprom.SerialNo = &jsoneeprom.Service_Tag
                }
            }
        case ocAttr["MFG-DATE"]:
            if jsoneeprom.Manufacture_Date != "" {
                mfg_date := jsoneeprom.Manufacture_Date[6:10] + "-" +
                    jsoneeprom.Manufacture_Date[0:2] + "-" + jsoneeprom.Manufacture_Date[3:5]
                eeprom.MfgDate = &mfg_date
            }
        case ocAttr["STATE-HARDWARE-VERSION"]:
            if jsoneeprom.Label_Revision != "" {
                eeprom.HardwareVersion = &jsoneeprom.Label_Revision
            }
            if jsoneeprom.Hardware_Version != "" {
                if eeprom.HardwareVersion == nil || *eeprom.HardwareVersion == "" {
                    eeprom.HardwareVersion = &jsoneeprom.Hardware_Version
                }
            }
        case ocAttr["DESCRIPTION"]:
            if jsoneeprom.Platform_Name != "" {
                eeprom.Description = &jsoneeprom.Platform_Name
            }
        case ocAttr["STATE-MFG-NAME"]:
            if jsoneeprom.Manufacturer != "" {
                eeprom.MfgName = &jsoneeprom.Manufacturer
            }
            if jsoneeprom.Vendor_Name != "" {
                if eeprom.MfgName == nil || *eeprom.MfgName == "" {
                    eeprom.MfgName = &jsoneeprom.Vendor_Name
                }
            }
        case ocAttr["STATE-SOFTWARE-VERSION"]:
            if jsoneeprom.Software_Version != "" {
                eeprom.SoftwareVersion = &jsoneeprom.Software_Version
            } else {
                versionString := getSoftwareVersion()
                eeprom.SoftwareVersion = &versionString
            }
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

func getSysEepromJson (pf_cpts *ocbinds.OpenconfigPlatform_Components, targetUriPath string, uri string) (error) {

    log.Infof("Preparing json for system eeprom");

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
        err = getSysEepromFromFile(eeprom_comp.State, true, targetUriPath)
        if err != nil {
            return err
        }
        eeprom_comp.State.Type,_ = eeprom_comp.State.To_OpenconfigPlatform_Components_Component_State_Type_Union(
                                ocbinds.OpenconfigPlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_CHASSIS)

        swversion_comp,_ := pf_cpts.NewComponent("Software")
        ygot.BuildEmptyTree(swversion_comp)
        err = getSoftwareVersionComponent(swversion_comp.Software, targetUriPath, true)
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
            err = getSysEepromFromFile(pf_comp.State, true, targetUriPath)
            if err != nil {
                return err
            }
        } else {
            if strings.ToLower(compName) == "system eeprom" {
                pf_comp := pf_cpts.Component[compName]
                if pf_comp != nil {
                    ygot.BuildEmptyTree(pf_comp)
                    err = getSysEepromFromFile(pf_comp.State, true, targetUriPath)
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
                    err = getSoftwareVersionComponent(pf_comp.Software, targetUriPath, true)
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
                err = getSysEepromFromFile(pf_comp.State, true, targetUriPath)
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
                    err = getSysEepromFromFile(pf_comp.State, false, targetUriPath)
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
                    err = getSoftwareVersionComponent(pf_comp.Software, targetUriPath, false)
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

