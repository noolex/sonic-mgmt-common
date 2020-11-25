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
    "errors"
    "strings"
    "reflect"
    "sort"
    "strconv"
    "regexp"
    "net"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "bufio"
    "os"
    "fmt"
    "encoding/json"
    "time"
)

func init () {
    XlateFuncBind("intf_table_xfmr", intf_table_xfmr)
    XlateFuncBind("alias_value_xfmr", alias_value_xfmr)
    XlateFuncBind("alternate_name_value_xfmr", alternate_name_value_xfmr)
    XlateFuncBind("YangToDb_intf_name_xfmr", YangToDb_intf_name_xfmr)
    XlateFuncBind("DbToYang_intf_name_xfmr", DbToYang_intf_name_xfmr)
    XlateFuncBind("YangToDb_intf_enabled_xfmr", YangToDb_intf_enabled_xfmr)
    XlateFuncBind("DbToYang_intf_enabled_xfmr", DbToYang_intf_enabled_xfmr)
    XlateFuncBind("YangToDb_intf_mtu_xfmr", YangToDb_intf_mtu_xfmr)
    XlateFuncBind("DbToYang_intf_mtu_xfmr", DbToYang_intf_mtu_xfmr)
    XlateFuncBind("YangToDb_intf_type_xfmr", YangToDb_intf_type_xfmr)
    XlateFuncBind("DbToYang_intf_type_xfmr", DbToYang_intf_type_xfmr)
    XlateFuncBind("DbToYang_intf_admin_status_xfmr", DbToYang_intf_admin_status_xfmr)
    XlateFuncBind("DbToYang_intf_oper_status_xfmr", DbToYang_intf_oper_status_xfmr)
    XlateFuncBind("DbToYang_intf_eth_auto_neg_xfmr", DbToYang_intf_eth_auto_neg_xfmr)
    XlateFuncBind("DbToYang_intf_eth_port_speed_xfmr", DbToYang_intf_eth_port_speed_xfmr)
    XlateFuncBind("DbToYang_intf_eth_port_fec_xfmr", DbToYang_intf_eth_port_fec_xfmr)
    XlateFuncBind("DbToYang_intf_eth_port_unreliable_los_xfmr", DbToYang_intf_eth_port_unreliable_los_xfmr)
    XlateFuncBind("YangToDb_intf_eth_port_config_xfmr", YangToDb_intf_eth_port_config_xfmr)
    XlateFuncBind("DbToYang_intf_eth_port_config_xfmr", DbToYang_intf_eth_port_config_xfmr)
    XlateFuncBind("YangToDb_intf_ip_addr_xfmr", YangToDb_intf_ip_addr_xfmr)
    XlateFuncBind("DbToYang_intf_ip_addr_xfmr", DbToYang_intf_ip_addr_xfmr)
    XlateFuncBind("YangToDb_ipv6_enabled_xfmr", YangToDb_ipv6_enabled_xfmr)
    XlateFuncBind("DbToYang_ipv6_enabled_xfmr", DbToYang_ipv6_enabled_xfmr)
    XlateFuncBind("YangToDb_intf_subintfs_xfmr", YangToDb_intf_subintfs_xfmr)
    XlateFuncBind("DbToYang_intf_subintfs_xfmr", DbToYang_intf_subintfs_xfmr)
    XlateFuncBind("DbToYang_intf_get_counters_xfmr", DbToYang_intf_get_counters_xfmr)
    XlateFuncBind("DbToYang_intf_get_ether_counters_xfmr", DbToYang_intf_get_ether_counters_xfmr)
    XlateFuncBind("YangToDb_intf_tbl_key_xfmr", YangToDb_intf_tbl_key_xfmr)
    XlateFuncBind("DbToYang_intf_tbl_key_xfmr", DbToYang_intf_tbl_key_xfmr)
    XlateFuncBind("YangToDb_subintf_ipv6_tbl_key_xfmr", YangToDb_subintf_ipv6_tbl_key_xfmr)
    XlateFuncBind("DbToYang_subintf_ipv6_tbl_key_xfmr", DbToYang_subintf_ipv6_tbl_key_xfmr)
    XlateFuncBind("YangToDb_subintf_ip_addr_key_xfmr", YangToDb_subintf_ip_addr_key_xfmr)
    XlateFuncBind("DbToYang_subintf_ip_addr_key_xfmr", DbToYang_subintf_ip_addr_key_xfmr)
    /* XlateFuncBind("DbToYang_igmp_tbl_key_xfmr", DbToYang_igmp_tbl_key_xfmr)
    XlateFuncBind("YangToDb_igmp_tbl_key_xfmr", YangToDb_igmp_tbl_key_xfmr)
    XlateFuncBind("DbToYang_igmp_mcastgrpaddr_fld_xfmr", DbToYang_igmp_mcastgrpaddr_fld_xfmr)
    XlateFuncBind("YangToDb_igmp_mcastgrpaddr_fld_xfmr", YangToDb_igmp_mcastgrpaddr_fld_xfmr)
    XlateFuncBind("DbToYang_igmp_srcaddr_fld_xfmr", DbToYang_igmp_srcaddr_fld_xfmr)
    XlateFuncBind("YangToDb_igmp_srcaddr_fld_xfmr", YangToDb_igmp_srcaddr_fld_xfmr) */
    XlateFuncBind("rpc_clear_counters", rpc_clear_counters)
    XlateFuncBind("rpc_oc_clear_counters", rpc_oc_clear_counters)
    XlateFuncBind("rpc_clear_ip", rpc_clear_ip)
    XlateFuncBind("intf_subintfs_table_xfmr", intf_subintfs_table_xfmr)
    XlateFuncBind("intf_post_xfmr", intf_post_xfmr)
    XlateFuncBind("intf_pre_xfmr", intf_pre_xfmr)
    XlateFuncBind("YangToDb_routed_vlan_ip_addr_xfmr", YangToDb_routed_vlan_ip_addr_xfmr)
    XlateFuncBind("DbToYang_routed_vlan_ip_addr_xfmr", DbToYang_routed_vlan_ip_addr_xfmr)
    XlateFuncBind("Subscribe_intf_ip_addr_xfmr", Subscribe_intf_ip_addr_xfmr)
    XlateFuncBind("Subscribe_routed_vlan_ip_addr_xfmr", Subscribe_routed_vlan_ip_addr_xfmr)
    XlateFuncBind("rpc_oc_vlan_replace", rpc_oc_vlan_replace)
}

const (
    PORT_INDEX         = "index"
    PORT_MTU           = "mtu"
    PORT_ADMIN_STATUS  = "admin_status"
    PORT_SPEED         = "speed"
    PORT_FEC           = "fec"
    PORT_UNRELIABLE_LOS = "override_unreliable_los"
    PORT_LANES         = "lanes"
    PORT_DESC          = "description"
    PORT_OPER_STATUS   = "oper_status"
    PORT_AUTONEG       = "autoneg"
    VLAN_TN            = "VLAN"
    VLAN_MEMBER_TN     = "VLAN_MEMBER"
    VLAN_INTERFACE_TN  = "VLAN_INTERFACE"
    PORTCHANNEL_TN     = "PORTCHANNEL"
    PORTCHANNEL_INTERFACE_TN  = "PORTCHANNEL_INTERFACE"
    PORTCHANNEL_MEMBER_TN  = "PORTCHANNEL_MEMBER"
    LOOPBACK_TN            = "LOOPBACK"
    LOOPBACK_INTERFACE_TN  = "LOOPBACK_INTERFACE"
    UNNUMBERED         = "unnumbered"
    DEFAULT_MTU        = "9100"
)

const (
    PIPE                     =  "|"
    COLON                    =  ":"

    ETHERNET                 = "Eth"
    MGMT                     = "eth"
    VLAN                     = "Vlan"
    PORTCHANNEL              = "PortChannel"
    LOOPBACK                 = "Loopback"
    VXLAN                    = "vtep"
)

type TblData  struct  {
    portTN           string
    memberTN         string
    intfTN           string
    keySep           string
}

type PopulateIntfCounters func (inParams XfmrParams, counters interface{}) (error)
type CounterData struct {
    OIDTN             string
    CountersTN        string
    PopulateCounters  PopulateIntfCounters
}

type IntfTblData struct {
    cfgDb               TblData
    appDb               TblData
    stateDb             TblData
    CountersHdl         CounterData
}

var IntfTypeTblMap = map[E_InterfaceType]IntfTblData {
    IntfTypeEthernet: IntfTblData{
        cfgDb:TblData{portTN:"PORT", intfTN: "INTERFACE", keySep:PIPE},
        appDb:TblData{portTN:"PORT_TABLE", intfTN: "INTF_TABLE", keySep: COLON},
        stateDb:TblData{portTN: "PORT_TABLE", intfTN: "INTERFACE_TABLE", keySep: PIPE},
        CountersHdl:CounterData{OIDTN: "COUNTERS_PORT_NAME_MAP", CountersTN: "COUNTERS", PopulateCounters: populatePortCounters},
    },
    IntfTypeMgmt : IntfTblData{
        cfgDb:TblData{portTN:"MGMT_PORT", intfTN:"MGMT_INTERFACE", keySep: PIPE},
        appDb:TblData{portTN:"MGMT_PORT_TABLE", intfTN:"MGMT_INTF_TABLE", keySep: COLON},
        stateDb:TblData{portTN:"MGMT_PORT_TABLE", intfTN:"MGMT_INTERFACE_TABLE", keySep: PIPE},
        CountersHdl:CounterData{OIDTN: "", CountersTN:"", PopulateCounters: populateMGMTPortCounters},
    },
    IntfTypePortChannel : IntfTblData{
        cfgDb:TblData{portTN:"PORTCHANNEL", intfTN:"PORTCHANNEL_INTERFACE", memberTN:"PORTCHANNEL_MEMBER", keySep: PIPE},
        appDb:TblData{portTN:"LAG_TABLE", intfTN:"INTF_TABLE", keySep: COLON, memberTN:"LAG_MEMBER_TABLE"},
        stateDb:TblData{portTN:"LAG_TABLE", intfTN:"INTERFACE_TABLE", keySep: PIPE},
        CountersHdl:CounterData{OIDTN: "COUNTERS_PORT_NAME_MAP", CountersTN:"COUNTERS", PopulateCounters: populatePortCounters},
    },
    IntfTypeVlan : IntfTblData{
        cfgDb:TblData{portTN:"VLAN", memberTN: "VLAN_MEMBER", intfTN:"VLAN_INTERFACE", keySep: PIPE},
        appDb:TblData{portTN:"VLAN_TABLE", memberTN: "VLAN_MEMBER_TABLE", intfTN:"INTF_TABLE", keySep: COLON},
    },
    IntfTypeLoopback : IntfTblData {
       cfgDb:TblData{portTN:"LOOPBACK", intfTN: "LOOPBACK_INTERFACE", keySep: PIPE},
       appDb:TblData{portTN:"LOOPBACK_TABLE", intfTN: "INTF_TABLE", keySep: COLON},
   },
}

var dbIdToTblMap = map[db.DBNum][]string {
    db.ConfigDB: {"PORT", "MGMT_PORT", "VLAN", "PORTCHANNEL", "LOOPBACK", "VXLAN_TUNNEL"},
    db.ApplDB  : {"PORT_TABLE", "MGMT_PORT_TABLE", "VLAN_TABLE", "LAG_TABLE"},
    db.StateDB : {"PORT_TABLE", "MGMT_PORT_TABLE", "LAG_TABLE"},
}

var intfOCToSpeedMap = map[ocbinds.E_OpenconfigIfEthernet_ETHERNET_SPEED] string {
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_10MB: "10",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_100MB: "100" ,
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_1GB: "1000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_2500MB: "2500",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_5GB: "5000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_10GB: "10000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_25GB: "25000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_40GB: "40000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_50GB: "50000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_100GB: "100000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_200GB: "200000",
    ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_400GB: "400000",

}

var yangToDbFecMap = map[ocbinds.E_OpenconfigPlatformTypes_FEC_MODE_TYPE] string {
    ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_FEC_DISABLED : "none",
    ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_FEC_AUTO     : "default",
    ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_FEC_RS       : "rs",
    ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_FEC_FC       : "fc",
}

var yangToDbLosMap = map[ocbinds.E_OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE] string {
    ocbinds.OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE_UNRELIABLE_LOS_MODE_OFF  : "off",
    ocbinds.OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE_UNRELIABLE_LOS_MODE_ON   : "on",
    ocbinds.OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE_UNRELIABLE_LOS_MODE_AUTO : "auto",
}

type E_InterfaceType  int64
const (
    IntfTypeUnset           E_InterfaceType = 0
    IntfTypeEthernet        E_InterfaceType = 1
    IntfTypeMgmt            E_InterfaceType = 2
    IntfTypeVlan            E_InterfaceType = 3
    IntfTypePortChannel     E_InterfaceType = 4
    IntfTypeLoopback        E_InterfaceType = 5
    IntfTypeVxlan           E_InterfaceType = 6
)
type E_InterfaceSubType int64
const (
    IntfSubTypeUnset        E_InterfaceSubType = 0
    IntfSubTypeVlanL2  E_InterfaceSubType = 1
    InterfaceSubTypeVlanL3  E_InterfaceSubType = 2
)

var IF_TYPE_MAP = map[E_InterfaceType]ocbinds.E_IETFInterfaces_InterfaceType {
    IntfTypeUnset:  ocbinds.IETFInterfaces_InterfaceType_UNSET,
    IntfTypeEthernet:  ocbinds.IETFInterfaces_InterfaceType_ethernetCsmacd,
    IntfTypeMgmt:  ocbinds.IETFInterfaces_InterfaceType_ethernetCsmacd,
    IntfTypeVlan:  ocbinds.IETFInterfaces_InterfaceType_l2vlan,
    IntfTypePortChannel:  ocbinds.IETFInterfaces_InterfaceType_ieee8023adLag,
    IntfTypeLoopback:  ocbinds.IETFInterfaces_InterfaceType_softwareLoopback,
    IntfTypeVxlan:  ocbinds.IETFInterfaces_InterfaceType_IF_NVE,
}

func alias_value_xfmr(inParams XfmrDbParams) (string, error) {
    var err error

    ifName := inParams.value
    log.V(3).Infof("alias_value_xfmr:- Operation Type - %d Interface name - %s", inParams.oper, ifName)

    if !utils.IsAliasModeEnabled() {
        return ifName, err
    }
    var convertedName *string

    if inParams.oper == GET {
        convertedName = utils.GetUINameFromNativeName(&ifName)
    } else {
        convertedName = utils.GetNativeNameFromUIName(&ifName)
    }
    log.V(3).Info("Returned string from alias_value_xfmr = ", *convertedName)
    return *convertedName, err
}

func alternate_name_value_xfmr(inParams XfmrDbParams) (string, error) {

    aliasName := inParams.value
    log.Infof("alternate_name_value_xfmr:- Operation Type - %d Interface name - %s", inParams.oper, aliasName)

    if !utils.IsAliasModeEnabled() {
        log.Info("Alias mode is not enabled!")
        return aliasName, nil
    }

    if inParams.oper != GET {
        err_str := "CRUD operations are not allowed for interface alternate name"
        return aliasName, tlerr.NotSupported(err_str)
    }
    ifName := utils.GetNativeNameFromUIName(&aliasName)

    log.Info("Returned string from alternate_name_value_xfmr = ", *ifName)
    return *ifName, nil
}


var intf_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {

    requestUriPath, _ := getYangPathFromUri(inParams.requestUri)
    retDbDataMap := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("Entering intf_post_xfmr")

    if inParams.oper == DELETE {

        err_str := "Delete not allowed at this container"
        /* Preventing delete at IPv6 config level*/
        if requestUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/config" {
            log.Info("In interface Post transformer for DELETE op ==> URI : ", inParams.requestUri)
            return retDbDataMap, tlerr.NotSupported(err_str)
        }

        /* For delete request and for fields with default value, transformer adds subOp map with update operation (to update with default value).
           So, adding code to clear the update SubOp map for delete operation to go through for the following requestUriPath */
        if requestUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/config/enabled" ||
           requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/config/enabled" {
            if len(inParams.subOpDataMap) > 0 {
                dbMap := make(map[string]map[string]db.Value)
                if inParams.subOpDataMap[4] != nil && inParams.subOpDataMap[5] != nil {
                    (*inParams.subOpDataMap[4])[db.ConfigDB] = dbMap
                }
                log.Info("intf_post_xfmr inParams.subOpDataMap :", inParams.subOpDataMap)
            }
        }
        if requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/openconfig-if-ethernet-ext:storm-control/storm-control-list/config/kbps" {
            log.Info("intf_post_xfmr: storm-control kbps")
            pathInfo := NewPathInfo(inParams.uri)
            tblName := "PORT_STORM_CONTROL"
            intfName := pathInfo.Var("name")
            stormType := pathInfo.Var("storm-type")
            if (stormType == "BROADCAST") {
                stormType = "broadcast"
            } else if (stormType == "UNKNOWN_UNICAST") {
                stormType = "unknown-unicast"
            } else if (stormType == "UNKNOWN_MULTICAST") {
                stormType = "unknown-multicast"
            }
            tblKeyStr := intfName+"|"+stormType
            log.Infof("intfName:%s, stormType:%s tblKeyStr:%s",intfName,stormType,tblKeyStr)
            subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
            subIntfmap_del := make(map[string]map[string]db.Value)
            subIntfmap_del[tblName] = make(map[string]db.Value)
            subIntfmap_del[tblName][tblKeyStr] = db.Value{}
            subOpMap[db.ConfigDB] = subIntfmap_del
            inParams.subOpDataMap[DELETE] = &subOpMap
            log.Info("Original retDbDataMap:",retDbDataMap)
            retDbDataMap = subIntfmap_del
            log.Info("Returning retDbDataMap:",retDbDataMap)
        }
    }
    return retDbDataMap, nil
}

var intf_pre_xfmr PreXfmrFunc = func(inParams XfmrParams) (error) {
    var err error
    if inParams.oper == DELETE {
        requestUriPath, _ := getYangPathFromUri(inParams.requestUri)
        if log.V(3) {
            log.Info("intf_pre_xfmr:- Request URI path = ", requestUriPath)
        }
        errStr := "Delete operation not supported for this path - "

        switch requestUriPath {
            case "/openconfig-interfaces:interfaces":
                errStr += requestUriPath
                return tlerr.InvalidArgsError{Format: errStr}
            case "/openconfig-interfaces:interfaces/interface":
                pathInfo := NewPathInfo(inParams.uri)
                if len(pathInfo.Vars) == 0 {
                    errStr += requestUriPath
                    return tlerr.InvalidArgsError{Format:errStr}
                }
        }
    }
    return err
}

// GetCountOfAddrType helper function to get a count of IP/IPv6 address 
func GetCountOfAddrType (ipKeys []db.Key, matchStr string) int { 
   count := 0

   for key := range ipKeys {
       ipAddr := ipKeys[key].Get(1)
        
       if strings.Contains(ipAddr, matchStr) {
           count++
       }
   }
   return count
}

// ValidateIntfProvisionedForRelay helper function to validate IP address deletion if DHCP relay is provisioned
func ValidateIntfProvisionedForRelay(d *db.DB, ifName string, prefixIp string) (bool, error) {
   var tblList string

   intfType, _, ierr := getIntfTypeByName(ifName)
   if intfType == IntfTypeUnset || ierr != nil {
       log.Info("ValidateIntfProvisionedForRelay - Invalid interface type IntfTypeUnset");
       return false, errors.New("Invalid InterfaceType");
   }

   // get all the IP addresses on this interface, refer to the intf table name
   intTbl := IntfTypeTblMap[intfType]
   tblList = intTbl.cfgDb.intfTN

   ipKeys, _ := doGetIntfIpKeys(d, tblList, ifName)
   numIpv6 := GetCountOfAddrType(ipKeys, ":")

   // for VLAN - DHCP info is stored in the VLAN Table
   if intfType == IntfTypeVlan {
       tblList = intTbl.cfgDb.portTN
   }

   entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblList}, db.Key{Comp: []string{ifName}})
   if dbErr != nil {
     log.Warning("Failed to read entry from config DB, " + tblList + " " + ifName)
     return false, nil
   }

   //check if dhcp_sever is provisioned for ipv4
   if strings.Contains(prefixIp, ".") || strings.Contains(prefixIp, "ipv4") {
       log.V(2).Info("ValidateIntfProvisionedForRelay  - IPv4Check")
       log.V(2).Info(entry)
       if len(entry.Field["dhcp_servers@"]) > 0 {
           return true, nil
       }
   } else if (strings.Contains(prefixIp, ":") && numIpv6 <2) || strings.Contains(prefixIp, "ipv6"){
   //check if dhcpv6_sever is provisioned for ipv6
       log.V(2).Info("ValidateIntfProvisionedForRelay  - IPv6Check")
       log.V(2).Info(entry)
       if len(entry.Field["dhcpv6_servers@"]) > 0 {
           return true, nil
       }
   }
   return false, nil
}

func getIntfTypeByName (name string) (E_InterfaceType, E_InterfaceSubType, error) {

    var err error
    if strings.HasPrefix(name, ETHERNET) {
        return IntfTypeEthernet, IntfSubTypeUnset, err
    } else if strings.HasPrefix(name, MGMT) {
        return IntfTypeMgmt, IntfSubTypeUnset, err
    } else if strings.HasPrefix(name, VLAN) {
        return IntfTypeVlan, IntfSubTypeUnset, err
    } else if strings.HasPrefix(name, PORTCHANNEL) {
        return IntfTypePortChannel, IntfSubTypeUnset, err
    } else if strings.HasPrefix(name, LOOPBACK) {
        return IntfTypeLoopback, IntfSubTypeUnset, err
    } else if strings.HasPrefix(name, VXLAN) {
        return IntfTypeVxlan, IntfSubTypeUnset, err
    } else {
        err = errors.New("Interface name prefix not matched with supported types")
        return IntfTypeUnset, IntfSubTypeUnset, err
    }
}

func getIntfsRoot (s *ygot.GoStruct) *ocbinds.OpenconfigInterfaces_Interfaces {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Interfaces
}

/* Perform action based on the operation and Interface type wrt Interface name key */
/* It should handle only Interface name key xfmr operations */
func performIfNameKeyXfmrOp(inParams *XfmrParams, requestUriPath *string, ifName *string, ifType E_InterfaceType) error {
    var err error
    switch inParams.oper {
    case DELETE:
        if *requestUriPath == "/openconfig-interfaces:interfaces/interface" {
            switch ifType {
            case IntfTypeVlan:
                /* VLAN Interface Delete Handling */
                /* Update the map for VLAN and VLAN MEMBER table */
                err := deleteVlanIntfAndMembers(inParams, ifName)
                if err != nil {
                    log.Errorf("Deleting VLAN: %s failed! Err:%v", *ifName, err)
                    return tlerr.InvalidArgsError{Format: err.Error()}
                }
            case IntfTypePortChannel:
                err := deleteLagIntfAndMembers(inParams, ifName)
                if err != nil {
                    log.Errorf("Deleting LAG: %s failed! Err:%v", *ifName, err)
                    return tlerr.InvalidArgsError{Format: err.Error()}
                }
            case IntfTypeLoopback:
                err := deleteLoopbackIntf(inParams, ifName)
                if err != nil {
                    log.Errorf("Deleting Loopback: %s failed! Err:%s", *ifName, err.Error())
                    return tlerr.InvalidArgsError{Format: err.Error()}
                }
            case IntfTypeVxlan:
                err := deleteVxlanIntf(inParams, ifName)
                if err != nil {
                    log.Errorf("Deleting Vxlan: %s failed! Err:%s", *ifName, err.Error())
                    return tlerr.InvalidArgsError{Format: err.Error()}
                }
            case IntfTypeEthernet:
                errStr := "Physical Interface: " + *ifName + " cannot be deleted"
                err = tlerr.InvalidArgsError{Format:errStr}
                return err
            default:
                errStr := "Invalid interface for delete:"+*ifName
                log.Error(errStr)
                return tlerr.InvalidArgsError{Format:errStr}
            }

        }
    case CREATE:
	fallthrough
    case UPDATE,REPLACE:
        if(ifType == IntfTypeVlan){
	    if(validateIntfExists(inParams.d, IntfTypeTblMap[IntfTypeVlan].cfgDb.portTN, *ifName)!=nil){
            err = enableStpOnVlanCreation(inParams, ifName)
            if (err != nil) {
                return err
            }
	    }
	}
    }
    return err
}

func rpc_get_resultTblList_for_intf_ip_delete(intfType E_InterfaceType) []string {
    var resultTblList []string
    switch intfType {
    case IntfTypeEthernet:
        resultTblList = append(resultTblList, "INTERFACE")
    case IntfTypeVlan:
        resultTblList = append(resultTblList, "VLAN_INTERFACE")
    case IntfTypePortChannel:
        resultTblList = append(resultTblList, "PORTCHANNEL_INTERFACE")
    case IntfTypeMgmt:
        resultTblList = append(resultTblList, "MGMT_INTERFACE")
    case IntfTypeLoopback:
        resultTblList = append(resultTblList, "LOOPBACK_INTERFACE")
    }
    log.Infof("Result Table List = %v", resultTblList)
    return resultTblList
}

func rpc_intf_ip_delete(d *db.DB, ifName *string, ipPrefix *string, intTbl IntfTblData, ipEntry db.Value, isSec bool) error {
    ip := strings.Split(*ipPrefix, "/")
    if validIPv4(ip[0]) {

        secVal, ok := ipEntry.Field["secondary"]
        if ok && secVal == "true" {
            if isSec {
                err := d.DeleteEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{*ifName, *ipPrefix}})
                if err != nil {
                    return err
                }
            } else {
                errStr := "No such address (" + *ipPrefix + ") configured on this interface as primary address"
                return tlerr.InvalidArgsError {Format: errStr}
            }
        } else {
            if isSec {
                log.Errorf("Secondary IPv4 Address : %s for interface : %s doesn't exist!", *ipPrefix, *ifName)
                errStr := "No such address (" + *ipPrefix + ") configured on this interface as secondary address"
                return tlerr.InvalidArgsError {Format: errStr}
            }
            var ifIpMap map[string]db.Value
            ifIpMap, _ = getIntfIpByName(d, intTbl.cfgDb.intfTN, *ifName, true, false, "")

            if(!utlCheckSecondaryIPConfigured(ifIpMap)) {
                dhcpProv, _ :=ValidateIntfProvisionedForRelay(d, *ifName, *ipPrefix)
                if dhcpProv {
                   errStr := "IP address cannot be deleted. DHCP Relay is configured on the interface."
                   return tlerr.InvalidArgsError {Format: errStr}
                }
                err := d.DeleteEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{*ifName, *ipPrefix}})
                if err != nil {
                    return err
                }
            } else {
                return tlerr.InvalidArgsError {Format: "Primary IPv4 address delete not permitted when secondary IPv4 address exists"}
            }
        }
    } else {
        dhcpProv, _ :=ValidateIntfProvisionedForRelay(d, *ifName, *ipPrefix)
        if dhcpProv {
           errStr := "IP address cannot be deleted. DHCP Relay is configured on the interface."
           return tlerr.InvalidArgsError {Format: errStr}
        }
        err := d.DeleteEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{*ifName, *ipPrefix}})
        if err != nil {
            return err
        }
    }

    count := 0
    _ = interfaceIPcount(intTbl.cfgDb.intfTN, d, ifName, &count)
    log.Info("IP count retrieved  = ", count)

    if (count == 2) {
        intfEntry, err := d.GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{*ifName}})
        if err != nil {
            log.Error(err.Error())
            return err
        }
        intfEntryMap := intfEntry.Field
        _, nullValPresent := intfEntryMap["NULL"]
        llVal, llValPresent := intfEntryMap["ipv6_use_link_local_only"]


        /* Note: Unbinding shouldn't happen if VRF or link-local config is associated with interface.
        Hence, we check for map length to be 1 and only if either NULL or ipv6_use_link_local_only with "disable" value is present */
        if len(intfEntryMap) == 1 && (nullValPresent || (llValPresent && llVal == "disable")) {
            // Deleting the INTERFACE|<ifName> entry from DB
            err = d.DeleteEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{*ifName}})
            if err != nil {
                log.Error(err.Error())
                return err
            }
        }
    }
    return nil
}

var rpc_clear_ip RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status uint32 `json:"status"`
            Status_detail string `json:"status-detail"`
        } `json:"sonic-interface:output"`
    }
    result.Output.Status = 1

    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data for removing the IP address")
        result.Output.Status_detail = "Error: Failed to unmarshall given input data"
        return json.Marshal(&result)
    }
    input := mapData["sonic-interface:input"]
    mapData = input.(map[string]interface{})

    inputIfName, ok := mapData["ifName"]
    if !ok {
        result.Output.Status_detail = "ifName field not present in the input for clear_ip rpc!"
        return json.Marshal(&result)
    }
    ipPrefixIntf, ok := mapData["ipPrefix"]
    if !ok {
        result.Output.Status_detail = "ipPrefix field not present in the input for clear_ip rpc!"
        return json.Marshal(&result)
    }
    isSec := false
    secVal, ok := mapData["secondary"]
    if ok {
        if secVal.(bool) {
            isSec = true
        }
    }

    ipPrefix := ipPrefixIntf.(string)
    ifNameStr := inputIfName.(string)
    ifName := utils.GetNativeNameFromUIName(&ifNameStr)

    intfType, _, ierr := getIntfTypeByName(*ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Error("Invalid interface type IntfTypeUnset")
        return json.Marshal(&result)
    }
    intTbl := IntfTypeTblMap[intfType]

    log.Info("Interface type = ", intfType)
    log.Infof("Deleting IP address: %s for interface: %s", ipPrefix, *ifName)

    d, err := db.NewDB(getDBOptions(db.ConfigDB))
    if err != nil {
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }
    defer d.DeleteDB()

    /* Checking whether entry exists in DB. If not, return from here */
    ipEntry, err := d.GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{*ifName, ipPrefix}})
    if err != nil || !ipEntry.IsPopulated() {
        log.Errorf("IP address: %s doesn't exist for Interafce: %s", ipPrefix, *ifName)
        result.Output.Status_detail = "No such address configured on this interface"
        return json.Marshal(&result)
    }
    moduleNm := "sonic-interface"
    resultTblList := rpc_get_resultTblList_for_intf_ip_delete(intfType)
    var tblsToWatch []*db.TableSpec

    if len(resultTblList) > 0 {
        depTbls := GetTablesToWatch(resultTblList, moduleNm)
        if len(depTbls) == 0 {
            log.Errorf("Failure to get Tables to watch for module %v", moduleNm)
            return json.Marshal(&result)
        }
        log.Info("Dependent Tables = ", depTbls)
        for _, tbl := range depTbls {
            tblsToWatch = append(tblsToWatch, &db.TableSpec{Name: tbl})
        }
    }
    err = d.StartTx(nil, tblsToWatch)
    if err != nil {
        log.Error("Transaction start failed")
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }

    err = rpc_intf_ip_delete(d, ifName, &ipPrefix, intTbl, ipEntry, isSec)
    if err != nil {
        d.AbortTx()
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }
    err = d.CommitTx()
    if err != nil {
        log.Error(err)
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }
    result.Output.Status = 0
    log.Infof("Commit transaction succesful for IP address: %s delete", ipPrefix)
    return  json.Marshal(&result)
}

func util_rpc_clear_counters (dbs [db.MaxDB]*db.DB, input string) (bool, string) {
    portOidmapTs := &db.TableSpec{Name: "COUNTERS_PORT_NAME_MAP"}
    ifCountInfo, err := dbs[db.CountersDB].GetMapAll(portOidmapTs)
    if err != nil {
        return false, "Error: Port-OID (Counters) get for all the interfaces failed!"
    }

    if input == "all" {
        log.Info("util_rpc_clear_counters : Clear Counters for all interfaces")
        for  intf, oid := range ifCountInfo.Field {
            verr, cerr := resetCounters(dbs[db.CountersDB], oid)
            if verr != nil || cerr != nil {
                log.Info("Failed to reset counters for ", intf)
            } else {
                log.Info("Counters reset for " + intf)
            }
        }
    } else if input == "Ethernet" || input == "PortChannel" {
        log.Info("util_rpc_clear_counters : Reset counters for given interface type")
        for  intf, oid := range ifCountInfo.Field {
            if strings.HasPrefix(strings.ToUpper(intf), input) {
                verr, cerr := resetCounters(dbs[db.CountersDB], oid)
                if verr != nil || cerr != nil {
                    log.Error("Failed to reset counters for: ", intf)
                } else {
                    log.Info("Counters reset for " + intf)
                }
            }
        }
    } else {
        log.Info("util_rpc_clear_counters: Clear counters for given interface name")
        ok, id := getIdFromIntfName(&input) ; if !ok {
            log.Info("Invalid Interface format")
            return false, fmt.Sprintf("Error: Clear Counters not supported for %s", input)
        }
        if strings.HasPrefix(input, "Ethernet") {
            input = "Ethernet" + id
        } else if strings.HasPrefix(input, "PortChannel") {
            input = "PortChannel" + id
        } else {
            log.Info("Invalid Interface")
            return false, fmt.Sprintf("Error: Clear Counters not supported for %s", input)
        }
        oid, ok := ifCountInfo.Field[input]
        if !ok {
            return false, fmt.Sprintf("Error: OID info not found in COUNTERS_PORT_NAME_MAP for %s", input)
        }
        verr, cerr := resetCounters(dbs[db.CountersDB], oid)
        if verr != nil {
            return false, fmt.Sprintf("Error: Failed to get counter values from COUNTERS table for %s", input)
        }
        if cerr != nil {
            log.Info("Failed to reset counters values")
            return false, fmt.Sprintf("Error: Failed to reset counters values for %s.", input)
        }
        log.Info("Counters reset for " + input)
    }

    return true, "Success: Cleared Counters"
}

/* RPC for clear counters through Sonic-RPC */
var rpc_clear_counters RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string`json:"status-detail"`
        } `json:"sonic-interface:output"`
    }
    result.Output.Status = 1
    /* Get input data */
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        result.Output.Status_detail = "Error: Failed to unmarshall given input data"
        return json.Marshal(&result)
    }
    log.Info("-----mapData[sonic-interface:input]----", mapData["sonic-interface:input"])
    input, ok := mapData["sonic-interface:input"] ; if !ok {
        err_str := "Error: Mandatory info missing! Input container not present!"
        log.Info(err_str)
        result.Output.Status_detail = err_str
        return json.Marshal(&result)
    }
    mapData = input.(map[string]interface{})
    input, ok = mapData["interface-param"] ; if !ok {
        err_str := "Error: Mandatory info missing! interface-param attribute not present!"
        log.Info(err_str)
        result.Output.Status_detail = err_str
        return json.Marshal(&result)
    }
    input_str := fmt.Sprintf("%v", input)
    sonicName := utils.GetNativeNameFromUIName(&input_str)
    input_str = *sonicName

    ok, result.Output.Status_detail = util_rpc_clear_counters(dbs, input_str) ; if ok {
        result.Output.Status = 0
    }
    return json.Marshal(&result)
}

/* RPC for clear counters through Openconfig-RPC */
var rpc_oc_clear_counters RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string`json:"status-detail"`
        } `json:"openconfig-interfaces-ext:output"`
    }
    result.Output.Status = 1
    /* Get input data */
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data")
        result.Output.Status_detail = "Error: Failed to unmarshall given input data"
        return json.Marshal(&result)
    }
    log.Info("-----mapData[openconfig-interfaces-ext:input]----", mapData["openconfig-interfaces-ext:input"])
    input, ok := mapData["openconfig-interfaces-ext:input"] ; if !ok {
        err_str := "Error: Mandatory info missing! Input container not present!"
        log.Info(err_str)
        result.Output.Status_detail = err_str
        return json.Marshal(&result)
    }
    mapData = input.(map[string]interface{})
    input, ok = mapData["interface-param"] ; if !ok {
        err_str := "Error: Mandatory info missing! interface-param attribute not present!"
        log.Info(err_str)
        result.Output.Status_detail = err_str
        return json.Marshal(&result)
    }
    input_str := fmt.Sprintf("%v", input)
    sonicName := utils.GetNativeNameFromUIName(&input_str)
    input_str = *sonicName

    ok, result.Output.Status_detail = util_rpc_clear_counters(dbs, input_str) ; if ok {
        result.Output.Status = 0
    }
    return json.Marshal(&result)
}

/* Reset counter values in COUNTERS_BACKUP table for given OID */
func resetCounters(d *db.DB, oid string) (error,error) {
    var verr,cerr error
    CountrTblTs := db.TableSpec {Name: "COUNTERS"}
    CountrTblTsCp := db.TableSpec { Name: "COUNTERS_BACKUP" }
    value, verr := d.GetEntry(&CountrTblTs, db.Key{Comp: []string{oid}})
    if verr == nil {
        secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        cerr = d.CreateEntry(&CountrTblTsCp, db.Key{Comp: []string{oid}}, value)
    }
    return verr, cerr
}

//returns difference between existing list of Vlans and new list of Vlans. 
func vlanDifference(vlanList1, vlanList2 []string) []string {
    mb := make(map[string]struct{}, len(vlanList2))
    for _, ifName := range vlanList2 {
        mb[ifName] = struct{}{}
    }
    var diff []string
    for _, ifName := range vlanList1 {
        if _, found := mb[ifName]; !found {
            diff = append(diff, ifName)
        }
    }
    return diff
}
//checks if interface is part of any portchannel 
func retrievePortChannelReplaceVlan(d *db.DB, ifName *string) (*string, error) {
    var err error

    if strings.HasPrefix(*ifName, ETHERNET) {
        var lagStr string
        lagKeys, err := d.GetKeysByPattern(&db.TableSpec{Name: PORTCHANNEL_MEMBER_TN}, "*"+*ifName)
        /* Find the port-channel the given ifname is part of */
        if err != nil {
            return nil, err
        }
        var flag bool = false
        if len(lagKeys) != 0{
                flag = true
                lagStr = lagKeys[0].Get(0)
                log.Info("Given interface part of PortChannel", lagStr)
        }
        if !flag {
            log.Info("Given Interface not part of any PortChannel")
            return nil, err
        }
        return &lagStr, err
    }
    return nil, err
}
//Creates new entry in VLAN_MEMBER table and updated VLAN table. 
func rpc_create_vlan(d *db.DB, vlanList []string, ifName string) error {
    var err error
    stpPortMap := make(map[string]db.Value)
    var ifList []string
    ifList = append(ifList,ifName)
    for _,vlanName := range vlanList{
        //create entry in VLAN_MEMBER_TABLE
       tag_mode := db.Value{Field:make(map[string]string)}
       tag_mode.Set("tagging_mode", "tagged")
       err = d.CreateEntry(&db.TableSpec{Name:VLAN_MEMBER_TN}, db.Key{Comp: []string{vlanName,ifName}}, tag_mode)
        if err != nil{
           errStr := "Creating entry in VLAN_MEMBER_TABLE failed!"
           log.Error(errStr)
           return errors.New(errStr)
           }

       //update members@ field in VLAN_TABLE entry
       vlanEntry, err := d.GetEntry(&db.TableSpec{Name:VLAN_TN}, db.Key{Comp: []string{vlanName}})
       if err != nil || !vlanEntry.IsPopulated() {
           errStr := "Invalid Vlan:" + vlanName
           log.Error(errStr)
           return errors.New(errStr)
           }
       membersList := vlanEntry.GetList("members")
       membersList = append(membersList, ifName)
       vlanEntry.SetList("members", membersList)
       err = d.ModEntry(&db.TableSpec{Name:VLAN_TN}, db.Key{Comp: []string{vlanName}}, vlanEntry)
        if err != nil {
            errStr := "Modifying vlan entry in VLAN_TABLE failed!"
            log.Error(errStr)
            return errors.New(errStr)
            }
	}
        enableStpOnInterfaceVlanMembership(d, &vlanList[0], ifList, stpPortMap)
	if len(stpPortMap) != 0 {
	    err = d.CreateEntry(&db.TableSpec{Name: STP_PORT_TABLE}, db.Key{Comp:[]string {ifName}},stpPortMap[ifName])
            if err != nil{
               errStr := "Creating entry in STP_PORT_TABLE failed!"
               log.Error(errStr)
               return errors.New(errStr)
            }
	}
       return nil
}
//Deletes entry from VLAN_MEMBER table and updates VLAN table. 
func rpc_delete_vlan(d *db.DB, vlanList []string, ifName string) error {
    var err error

    for _,vlanName := range vlanList{
        //delete entry from VLAN_MEMBER_TABLE
        err = d.DeleteEntry(&db.TableSpec{Name:VLAN_MEMBER_TN},db.Key{Comp: []string{vlanName,ifName}})
        if err != nil{
            errStr := "Deleting entry in VLAN_MEMBER_TABLE failed!"
            log.Error(errStr)
            return errors.New(errStr)
            }

       //update members@ field in VLAN_TABLE entry
       vlanEntry, err := d.GetEntry(&db.TableSpec{Name:VLAN_TN}, db.Key{Comp: []string{vlanName}})
       if err != nil || !vlanEntry.IsPopulated() {
           errStr := "Invalid Vlan:" + vlanName
           log.Error(errStr)
           return errors.New(errStr)
           }
       membersList := vlanEntry.GetList("members")
       updatedList := utils.RemoveElement(membersList, ifName)
       vlanEntry.SetList("members", updatedList)
       err = d.SetEntry(&db.TableSpec{Name:VLAN_TN},db.Key{Comp: []string{vlanName}},vlanEntry)
        if err != nil{
            errStr := "Setting entry in VLAN_TABLE failed!"
            return errors.New(errStr)
            }
        }

	return nil
}

var rpc_oc_vlan_replace RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result struct {
        Output struct {
            Status uint32 `json:"status"`
            Status_detail string `json:"status-detail"`
        } `json:"openconfig-interfaces-ext:output"`
    }
    result.Output.Status = 1

    var mapData map[string]interface{}
    intTbl := IntfTypeTblMap[IntfTypeVlan]
    err = json.Unmarshal(body, &mapData)
    if err != nil {
        log.Info("Failed to unmarshall given input data for replacing VLANs")
        result.Output.Status_detail = "Error: Failed to unmarshall given input data"
        return json.Marshal(&result)
    }
    input := mapData["openconfig-interfaces-ext:input"]
    mapData = input.(map[string]interface{})
    inputIfName, ok := mapData["ifname"]
    if !ok {
        result.Output.Status_detail = "ifName field not present in the input for replace_vlan rpc!"
        return json.Marshal(&result)
    }
    vlanList, ok := mapData["vlanlist"]
    if !ok {
        result.Output.Status_detail = "vlanlist field not present in the input for replace_vlan rpc!"
        return json.Marshal(&result)
    }
    ifNameStr := inputIfName.(string)
    vlanListStr := vlanList.(string)
    ifName := utils.GetNativeNameFromUIName(&ifNameStr)

    d, err := db.NewDB(getDBOptions(db.ConfigDB))
    if err != nil {
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }
    defer d.DeleteDB()

    err = validateL3ConfigExists(d,ifName)
    if err != nil{
       result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }

    lagStr,_ := retrievePortChannelReplaceVlan(d,ifName)
    intfType, _, ierr := getIntfTypeByName(*ifName)

    if intfType == IntfTypeUnset || ierr != nil {
        log.Error("Invalid interface type IntfTypeUnset")
        return json.Marshal(&result)
    }

    if intfType == IntfTypeEthernet{
        if lagStr != nil{
           errStr := ifNameStr + " already member of " + *lagStr
           err = tlerr.InvalidArgsError{Format: errStr}
            result.Output.Status_detail = err.Error()
            return json.Marshal(&result)
           }
       }

    var cfgredAccessVlan string
    exists, err := validateUntaggedVlanCfgredForIf(d,&intTbl.cfgDb.memberTN, ifName, &cfgredAccessVlan)
    if err != nil{
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }
    if exists {
        errStr := cfgredAccessVlan + " already configured as access for " + *ifName
        err = tlerr.InvalidArgsError{Format: errStr}
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }

    newVlanList := strings.Split(vlanListStr,",")
    var newList []string
    var existList []string
    for _,vlan := range newVlanList {
       if strings.Contains(vlan, "..") {
            err = extractVlanIdsfrmRng(d,vlan,&newList)
           if err != nil{
                result.Output.Status_detail = err.Error()
                return json.Marshal(&result)
           }

       } else{
           vid, _ := strconv.Atoi(vlan)
           vlanName := "Vlan" + strconv.Itoa(vid)
           err = validateVlanExists(d, &vlanName)
           if err != nil {
                result.Output.Status_detail = err.Error()
                return json.Marshal(&result)
            }
           newList = append(newList,vlanName)

       }
    }

    vlanMemberKeys, err := d.GetKeysByPattern(&db.TableSpec{Name:VLAN_MEMBER_TN}, "*"+*ifName)
    if err != nil {
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }
    log.Infof("Found %d vlan-member-table keys", len(vlanMemberKeys))
    for _, vlanMember := range vlanMemberKeys {
        if len(vlanMember.Comp) < 2 {
            continue
        }
        vlanId := vlanMember.Get(0)
        existList = append(existList,vlanId)
    }

    delList := vlanDifference(existList,newList)
    createList := vlanDifference(newList,existList)

    //no changes in vlans
    if len(delList) == 0 && len(createList) == 0 {
        result.Output.Status = 0
        return  json.Marshal(&result)
    }

    moduleNm := "sonic-vlan"
    resultTblList := []string{VLAN_MEMBER_TN,VLAN_TN}
    var tblsToWatch []*db.TableSpec

    if len(resultTblList) > 0 {
        depTbls := GetTablesToWatch(resultTblList, moduleNm)
        if len(depTbls) == 0 {
            log.Errorf("Failure to get Tables to watch for module %v", moduleNm)
            return json.Marshal(&result)
        }
        log.Info("Dependent Tables = ", depTbls)
        for _, tbl := range depTbls {
            tblsToWatch = append(tblsToWatch, &db.TableSpec{Name: tbl})
        }
    }
    err = d.StartTx(nil, tblsToWatch)
    if err != nil {
        log.Error("Transaction start failed")
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }

    if len(delList) != 0 {
        err = rpc_delete_vlan(d,delList,*ifName)
        if err != nil {
           d.AbortTx()
            result.Output.Status_detail = err.Error()
            return json.Marshal(&result)
        }
    }

    if len(createList) != 0 {
        err = rpc_create_vlan(d,createList,*ifName)
        if err != nil {
           d.AbortTx()
            result.Output.Status_detail = err.Error()
            return json.Marshal(&result)
        }
    }

    err = d.CommitTx()
    if err != nil {
        log.Error(err)
        result.Output.Status_detail = err.Error()
        return json.Marshal(&result)
    }

    result.Output.Status = 0
    log.Infof("Commit transaction succesful for replace VLAN for interface: %s", ifNameStr)
    return  json.Marshal(&result)
}


/* Extract ID from Intf String */
func getIdFromIntfName(intfName *string) (bool, string) {
    var re = regexp.MustCompile("[0-9]+")
    id := re.FindStringSubmatch(*intfName)
    if len(id) != 0 {return true, id[0]}
    return false, ""
}

var YangToDb_intf_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    requestUriPath, _ := getYangPathFromUri(inParams.requestUri)
    log.Infof("YangToDb_intf_tbl_key_xfmr: inParams.uri: %s, pathInfo: %s, inParams.requestUri: %s", inParams.uri, pathInfo, requestUriPath)

    ifName := pathInfo.Var("name")
    if ifName != "" {
        log.Info("YangToDb_intf_tbl_key_xfmr: ifName: ", ifName)
        intfType, _, ierr := getIntfTypeByName(ifName)
        if ierr != nil {
            log.Errorf("Extracting Interface type for Interface: %s failed!", ifName)
            return "", tlerr.New (ierr.Error())
        }
        err = performIfNameKeyXfmrOp(&inParams, &requestUriPath, &ifName, intfType)
        if err != nil {
            return "", tlerr.InvalidArgsError{Format: err.Error()}
        }
    }
    return ifName, err
}

var DbToYang_intf_tbl_key_xfmr  KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
/* Code for DBToYang - Key xfmr. */
    if log.V(3) {
        log.Info("Entering DbToYang_intf_tbl_key_xfmr")
    }
    res_map := make(map[string]interface{})

    log.Info("DbToYang_intf_tbl_key_xfmr: Interface Name = ", inParams.key)
    res_map["name"] = inParams.key
    return res_map, nil
}

var intf_table_xfmr TableXfmrFunc = func (inParams XfmrParams) ([]string, error) {
    var tblList []string
    var err error

    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)

    ifName := pathInfo.Var("name");
    if ifName == "" {
        log.Info("TableXfmrFunc - intf_table_xfmr Intf key is not present")

        if _, ok := dbIdToTblMap[inParams.curDb]; !ok {
            if log.V(3) {
                log.Info("TableXfmrFunc - intf_table_xfmr db id entry not present")
            }
            return tblList, errors.New("Key not present")
        } else {
            return dbIdToTblMap[inParams.curDb], nil
        }
    }
    sonicIfName := utils.GetNativeNameFromUIName(&ifName)
    if log.V(3) {
        log.Infof("TableXfmrFunc - Sonic Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    }
    ifName = *sonicIfName

    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        return tblList, errors.New("Invalid interface type IntfTypeUnset");
    }
    intTbl := IntfTypeTblMap[intfType]
    log.Info("TableXfmrFunc - targetUriPath : ", targetUriPath)

    subIfUri := "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/"
    rvlanUri := "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/"

    if IntfTypeVxlan == intfType {
	//handle VXLAN interface.
	intfsObj := getIntfsRoot(inParams.ygRoot)
	for intfKey, intfValObj := range intfsObj.Interface {
 		if strings.HasPrefix(intfKey, VXLAN) && intfValObj != nil && intfValObj.Config != nil {
 			if intfValObj.Config.Type != ocbinds.IETFInterfaces_InterfaceType_UNSET && intfValObj.Config.Type != ocbinds.IETFInterfaces_InterfaceType_IF_NVE {
 				return tblList, tlerr.InvalidArgs("Invalid Vxlan Interface type %d", intfValObj.Config.Type)
 			}
                        if strings.HasPrefix(targetUriPath, rvlanUri)  ||
                           strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation") {
                            return tblList, tlerr.InvalidArgs("Invalid access to routed-vlan or aggregation - Interface %s", ifName)
                        }
 		}
 	}
    }
    if  inParams.oper == DELETE && (targetUriPath == "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4" ||
                targetUriPath ==  "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6") {
        return tblList, tlerr.New("DELETE operation not allowed on  this container")

	} else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/config") {
		if IntfTypeVxlan == intfType {
                        if log.V(3) {
	                    log.Info("VXLAN_TUNNEL ==> intfPathTmp ==> inParams.requestUri ==> ", inParams.requestUri)
                        }
			tblList = append(tblList, "VXLAN_TUNNEL")
		} else {
			tblList = append(tblList, intTbl.cfgDb.portTN)
		}
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface") && IntfTypeVxlan == intfType  {
		if inParams.oper == 5 {
			tblList = append(tblList, "VXLAN_TUNNEL")
		} else if inParams.oper == 1 || inParams.oper == 2 {
			// allowed for create
			tblList = append(tblList, "VXLAN_TUNNEL")
		} else if inParams.oper == 3 || inParams.oper == 4 {
              if log.V(3) {
	          log.Info("VXLAN_TUNNEL testing ==> intfPathTmp ==> inParams.requestUri ==> ", inParams.requestUri)
              }
	      intfPathTmp, errIntf := getIntfUriPath(inParams.requestUri)
	      if errIntf == nil && intfPathTmp != nil {
                if log.V(3) {
	            log.Info("VXLAN_TUNNEL testing ==> intfPathTmp target string", intfPathTmp.Target)
                }
	        intfPathElem := intfPathTmp.Elem
	        if len(intfPathElem) > 0 {
	          targetIdx :=  len(intfPathElem)-1
	          if intfPathElem[targetIdx].Name == "interfaces" ||
                  intfPathElem[targetIdx].Name == "interface" ||
                      intfPathElem[targetIdx].Name == "config" || intfPathElem[targetIdx].Name == "source-vtep-ip" ||
                      intfPathElem[targetIdx].Name == "qos-mode" ||
                      intfPathElem[targetIdx].Name == "dscp" {
                        if log.V(3) {
	                    log.Info("VXLAN_TUNNEL testing ==> TARGET FOUND ==>", intfPathElem[targetIdx].Name)
                        }
	                _, errTmp := inParams.d.GetEntry(&db.TableSpec{Name:"VXLAN_TUNNEL"}, db.Key{Comp: []string{ifName}})
	                if errTmp == nil {
	                    tblList = append(tblList, "VXLAN_TUNNEL")
	                } else {
	                    return tblList, tlerr.New("PUT / PATCH method not allowed to replace the existing Vxlan Interface %s", ifName)
	                }
	          } else {
                    if log.V(3) {
	                log.Info("VXLAN_TUNNEL testing ==> target not found - target node", intfPathElem[targetIdx].Name)
                    }
	          }
	        }
	      } else {
                if log.V(3) {
	            log.Info("VXLAN_TUNNEL testing ==> TARGET err ==>", errIntf)
                }
	      }
		}
    } else if intfType != IntfTypeEthernet &&
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet") {
        //Checking interface type at container level, if not Ethernet type return nil
        return nil, nil
    } else if intfType != IntfTypePortChannel &&
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-aggregate:aggregation") {
        //Checking interface type at container level, if not PortChannel type return nil
        return nil, nil
    } else if intfType != IntfTypeVlan &&
        strings.HasPrefix(targetUriPath, "openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan") {
        //Checking interface type at container level, if not Vlan type return nil
        return nil, nil
    } else if  intfType != IntfTypeVxlan && 
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vxlan:vxlan-if") {
        //Checking interface type at container level, if not Vxlan type return nil
        return nil, nil
    } else if  strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/state/counters") {
        tblList = append(tblList, "NONE")
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/ethernet/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state") {
        tblList = append(tblList, intTbl.appDb.portTN)
    } else if strings.HasPrefix(targetUriPath,"/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone/config")||
        strings.HasPrefix(targetUriPath,"/openconfig-interfaces:interfaces/interface/nat-zone/config") {
        tblList = append(tblList, intTbl.cfgDb.intfTN)
    } else if strings.HasPrefix(targetUriPath,"/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone/state")||
        strings.HasPrefix(targetUriPath,"/openconfig-interfaces:interfaces/interface/nat-zone/state") {
        tblList = append(tblList, intTbl.appDb.intfTN)
    } else if strings.HasPrefix(targetUriPath, subIfUri + "ipv4/ospfv2/if-addresses/md-authentications") ||
        strings.HasPrefix(targetUriPath, rvlanUri + "ipv4/ospfv2/if-addresses/md-authentications") ||
        strings.HasPrefix(targetUriPath, subIfUri + "openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2/if-addresses/md-authentications") ||
        strings.HasPrefix(targetUriPath, rvlanUri + "openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2/if-addresses/md-authentications") {
        tblList = append(tblList, "NONE")
        if log.V(3) {
            log.Info("intf_table_xfmr - ospf md auth uri return table ", tblList)
        }
    } else if strings.HasPrefix(targetUriPath, subIfUri + "ipv4/ospfv2") ||
        strings.HasPrefix(targetUriPath, rvlanUri + "ipv4/ospfv2") ||
        strings.HasPrefix(targetUriPath, subIfUri + "ipv4/ospfv2/if-addresses/config") ||
        strings.HasPrefix(targetUriPath, rvlanUri + "ipv4/ospfv2/if-addresses/config") ||
        strings.HasPrefix(targetUriPath, subIfUri + "openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2") ||
        strings.HasPrefix(targetUriPath, rvlanUri + "openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2") {
        tblList = append(tblList, "NONE")
        if log.V(3) {
            log.Info("intf_table_xfmr - ospf uri return table ", tblList)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/config") {
        tblList = append(tblList, intTbl.cfgDb.intfTN)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/state") {
        tblList = append(tblList, intTbl.appDb.intfTN)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses") {
        tblList = append(tblList, intTbl.cfgDb.intfTN)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan") ||
               strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan") {
        if IntfTypeVlan == intfType {
	     if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/config") ||
                 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/config") ||
                 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/config") ||
                 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/config") {
                     tblList = append(tblList, intTbl.cfgDb.intfTN)
             } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/state") ||
		 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/state") ||
		 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/state") ||
		 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/state") {
                     tblList = append(tblList, intTbl.appDb.intfTN)
             } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses") ||
                 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses") ||
                 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses") ||
                 strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses") {
                     tblList = append(tblList, intTbl.cfgDb.intfTN)
             } else {
                 tblList = append(tblList, intTbl.cfgDb.intfTN)
             }
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/ethernet") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet") {
        if inParams.oper != DELETE {
            tblList = append(tblList, intTbl.cfgDb.portTN)
        }
    } else if strings.HasPrefix(targetUriPath,"/openconfig-interfaces:interfaces/interface/openconfig-interfaces-ext:nat-zone") ||
        strings.HasPrefix(targetUriPath,"/openconfig-interfaces:interfaces/interface/nat-zone") {
        tblList = append(tblList, intTbl.cfgDb.intfTN)
    } else if targetUriPath == "/openconfig-interfaces:interfaces/interface" {
        tblList = append(tblList, intTbl.cfgDb.portTN)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface") {
        if inParams.oper != DELETE {
            tblList = append(tblList, intTbl.cfgDb.portTN)
        }
    }else {
        err = errors.New("Invalid URI")
    }

    log.Infof("TableXfmrFunc - Uri: (%v), targetUriPath: %s, tblList: (%v)\r\n", inParams.uri, targetUriPath, tblList)

    return tblList, err
}

var YangToDb_intf_name_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")

    ifName := *utils.GetNativeNameFromUIName(&uriIfName)

    if strings.HasPrefix(ifName, VXLAN) {
        res_map["NULL"] = "NULL"
    } else if strings.HasPrefix(ifName, VLAN) {
        vlanId := ifName[len("Vlan"):]
        res_map["vlanid"] = vlanId
    } else if strings.HasPrefix(ifName, PORTCHANNEL) {
        res_map["NULL"] = "NULL"
    } else if strings.HasPrefix(ifName, LOOPBACK) {
        res_map["NULL"] = "NULL"
    } else if strings.HasPrefix(ifName, ETHERNET) {
        intTbl := IntfTypeTblMap[IntfTypeEthernet]
        //Check if physical interface exists, if not return error
        err = validateIntfExists(inParams.d, intTbl.cfgDb.portTN, ifName)
        if err != nil {
            errStr := "Interface " + ifName + " cannot be configured."
            return res_map, tlerr.InvalidArgsError{Format:errStr}
        }
    }
    log.Info("YangToDb_intf_name_xfmr: res_map:", res_map)
    return res_map, err
}

var DbToYang_intf_name_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})

    pathInfo := NewPathInfo(inParams.uri)
    ifName:= pathInfo.Var("name")
    log.Info("DbToYang_intf_name_xfmr: Interface Name = ", ifName)
    res_map["name"] = ifName
    return res_map, nil
}

func updateDefaultMtu(inParams *XfmrParams, ifName *string, ifType E_InterfaceType, resMap map[string]string) error {
    var err error
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    intfMap := make(map[string]map[string]db.Value)

    intTbl := IntfTypeTblMap[ifType]
    resMap["mtu"] = DEFAULT_MTU

    intfMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
    intfMap[intTbl.cfgDb.portTN][*ifName] = db.Value{Field:resMap}

    subOpMap[db.ConfigDB] = intfMap
    inParams.subOpDataMap[UPDATE] = &subOpMap
    return err
}

var YangToDb_intf_mtu_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var ifName string
    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        return res_map, nil
    } else {
        for infK := range intfsObj.Interface {
            ifName = infK
        }
    }
    intfType, _, _ := getIntfTypeByName(ifName)
    if IntfTypeVxlan == intfType {
        return res_map, nil
    }
    if inParams.oper == DELETE {
        log.Infof("Updating the Interface: %s with default MTU", ifName)
        if intfType == IntfTypeLoopback {
            log.Infof("MTU not supported for Loopback Interface Type: %d", intfType)
            return res_map, nil
        }
        /* Note: For the mtu delete request, res_map with delete operation and
           subOp map with update operation (default MTU value) is filled. This is because, transformer default
           updates the result DS for delete oper with table and key. This needs to be fixed by transformer
           for deletion of an attribute */
        err := updateDefaultMtu(&inParams, &ifName, intfType, res_map)
        if err != nil {
            log.Errorf("Updating Default MTU for Interface: %s failed", ifName)
            return res_map, err
        }
        return res_map, nil
    }
    // Handles all the operations other than Delete
    intfTypeVal, _ := inParams.param.(*uint16)
    intTypeValStr := strconv.FormatUint(uint64(*intfTypeVal), 10)

    if IntfTypePortChannel == intfType {
        /* Apply the MTU to all the portchannel member ports */
        updateMemberPortsMtu(&inParams, &ifName, &intTypeValStr)
    } else if IntfTypeEthernet == intfType {
        /* Do not allow MTU configuration on a portchannel member port */
        lagId, _ := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
        if lagId != nil {
            log.Infof("%s is member of %s", ifName, *lagId)
            errStr := "Configuration not allowed when port is member of Portchannel."
            return nil, tlerr.InvalidArgsError{Format: errStr}
        }
    }

    res_map["mtu"] = intTypeValStr
    return res_map, nil
}

var DbToYang_intf_mtu_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]

    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_mtu_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeVxlan == intfType {
	    return result, nil
    }
    intTbl := IntfTypeTblMap[intfType]

    tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
    if _, ok := data[tblName]; !ok {
        log.Info("DbToYang_intf_mtu_xfmr table not found : ", tblName)
        return result, errors.New("table not found : " + tblName)
    }

    pTbl := data[tblName]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_intf_mtu_xfmr Interface not found : ", inParams.key)
        return result, errors.New("Interface not found : " + inParams.key)
    }
    prtInst := pTbl[inParams.key]
    mtuStr, ok := prtInst.Field["mtu"]
    if ok {
	    mtuVal, err := strconv.ParseFloat(mtuStr, 64)
	    if err != nil {
	        return result, err
	    }
        result["mtu"] = mtuVal
    }
    return result, err
}

var YangToDb_intf_type_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_intf_type_xfmr: IntfsObj/interface list is empty.")
        return res_map, errors.New("IntfsObj/Interface is not specified")
    }
    if (inParams.oper == DELETE) {
        return res_map, tlerr.NotSupported("Operation Not Supported")
    }
    if inParams.param == nil {
        return res_map, nil
    }
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name");
    if ifName == "" {
        errStr := "YangToDb_intf_type_xfmr: Interface KEY not present"
        log.Info(errStr)
        return res_map, errors.New(errStr)
    }

    errStr := "YangToDb_intf_type_xfmr: Interface type not found, ifname: " + ifName
    intfType, _, ierr := getIntfTypeByName(ifName)
    if ierr != nil {
        return res_map, tlerr.InvalidArgsError{Format: errStr}
    }

    intfTypeVal, _ := inParams.param.(ocbinds.E_IETFInterfaces_InterfaceType)
    if val, ok := IF_TYPE_MAP[intfType]; ok {
        //Check if intfTypeVal valid for given interface
        if intfTypeVal == val {
            return res_map, nil
        }
    }
    errStr = "YangToDb_intf_type_xfmr: Invalid Interface type provided for ifname: " + ifName
    return res_map, tlerr.InvalidArgsError{Format: errStr}
}

var DbToYang_intf_type_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        return res_map, errors.New("IntfsObj/Interface is not specified")
    }
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name");
    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("DbToYang_intf_type_xfmr : " + errStr)
        return res_map, errors.New(errStr)
    }
    errStr := "DbToYang_intf_type_xfmr: Interface type not found, ifname: " + ifName
    intfType, _, ierr := getIntfTypeByName(ifName)
    if ierr != nil {
        return res_map, errors.New(errStr);
    }
    if val, ok := IF_TYPE_MAP[intfType]; ok {
        intfTypeStr := ocbinds.E_IETFInterfaces_InterfaceType.ΛMap(val)["E_IETFInterfaces_InterfaceType"][int64(val)].Name
        log.Infof("DbToYang_intf_type_xfmr, Interface: %s type:%s.",ifName, intfTypeStr)
        res_map["type"] = intfTypeStr
        return res_map, nil
    }
    return res_map, errors.New(errStr)
}

var YangToDb_intf_enabled_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var ifName string
    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        return res_map, nil
    } else {
	for infK := range intfsObj.Interface {
		ifName = infK
	}
    }
    intfType, _, _ := getIntfTypeByName(ifName)
    if IntfTypeVxlan == intfType || IntfTypeLoopback == intfType {
	    return res_map, nil
    }
    enabled, _ := inParams.param.(*bool)
    var enStr string
    if *enabled {
        enStr = "up"
    } else {
        enStr = "down"
    }
    res_map[PORT_ADMIN_STATUS] = enStr

    return res_map, nil
}


func getPortTableNameByDBId (intftbl IntfTblData, curDb db.DBNum) (string, error) {

    var tblName string

    switch (curDb) {
    case db.ConfigDB:
        tblName = intftbl.cfgDb.portTN
    case db.ApplDB:
        tblName = intftbl.appDb.portTN
    case db.StateDB:
        tblName = intftbl.stateDb.portTN
    default:
        tblName = intftbl.cfgDb.portTN
    }

    return tblName, nil
}

var DbToYang_intf_enabled_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]

    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_enabled_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeVxlan == intfType {
	    return result, nil
    }

    intTbl := IntfTypeTblMap[intfType]

    tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
    if _, ok := data[tblName]; !ok {
        log.Info("DbToYang_intf_enabled_xfmr table not found : ", tblName)
        return result, errors.New("table not found : " + tblName)
    }

    pTbl := data[tblName]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_intf_enabled_xfmr Interface not found : ", inParams.key)
        return result, errors.New("Interface not found : " + inParams.key)
    }
    prtInst := pTbl[inParams.key]
    adminStatus, ok := prtInst.Field[PORT_ADMIN_STATUS]
    if ok {
        if adminStatus == "up" {
            result["enabled"] = true
        } else {
            result["enabled"] = false
        }
    } else {
        log.Info("Admin status field not found in DB")
    }
    return result, err
}

var DbToYang_intf_admin_status_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]

    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_admin_status_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeVxlan == intfType {
	    return result, nil
    }
    intTbl := IntfTypeTblMap[intfType]

    tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
    if _, ok := data[tblName]; !ok {
        log.Info("DbToYang_intf_admin_status_xfmr table not found : ", tblName)
        return result, errors.New("table not found : " + tblName)
    }
    pTbl := data[tblName]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_intf_admin_status_xfmr Interface not found : ", inParams.key)
        return result, errors.New("Interface not found : " + inParams.key)
    }
    prtInst := pTbl[inParams.key]
    adminStatus, ok := prtInst.Field[PORT_ADMIN_STATUS]
    var status ocbinds.E_OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus
    if ok {
        if adminStatus == "up" {
            status = ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus_UP
        } else {
            status = ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus_DOWN
        }
        result["admin-status"] = ocbinds.E_OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus.ΛMap(status)["E_OpenconfigInterfaces_Interfaces_Interface_State_AdminStatus"][int64(status)].Name
    } else {
        log.Info("Admin status field not found in DB")
    }

    return result, err
}

var DbToYang_intf_oper_status_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    var prtInst db.Value

    data := (*inParams.dbDataMap)[inParams.curDb]
    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_oper_status_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeVxlan == intfType || IntfTypeVlan == intfType || IntfTypeLoopback == intfType {
	    return result, nil
    }
    intTbl := IntfTypeTblMap[intfType]
    if intfType == IntfTypeMgmt {
        pathInfo := NewPathInfo(inParams.uri)
        ifName := pathInfo.Var("name");
        entry, dbErr := inParams.dbs[db.StateDB].GetEntry(&db.TableSpec{Name:intTbl.stateDb.portTN}, db.Key{Comp: []string{ifName}})
        if dbErr != nil {
            log.Info("Failed to read mgmt port status from state DB, " + intTbl.stateDb.portTN + " " + ifName)
            return result, dbErr
        }
        prtInst = entry
    } else {
        tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
        pTbl := data[tblName]
        prtInst = pTbl[inParams.key]
    }

    operStatus, ok := prtInst.Field[PORT_OPER_STATUS]
    var status ocbinds.E_OpenconfigInterfaces_Interfaces_Interface_State_OperStatus
    if ok {
        if operStatus == "up" {
            status = ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_OperStatus_UP
        } else {
            status = ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_OperStatus_DOWN
        }
        result["oper-status"] = ocbinds.E_OpenconfigInterfaces_Interfaces_Interface_State_OperStatus.ΛMap(status)["E_OpenconfigInterfaces_Interfaces_Interface_State_OperStatus"][int64(status)].Name
    } else {
        log.Info("Oper status field not found in DB")
    }

    return result, err
}

var DbToYang_intf_eth_auto_neg_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_eth_auto_neg_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeMgmt != intfType && IntfTypeEthernet != intfType {
	    return result, nil
    }
    intTbl := IntfTypeTblMap[intfType]

    tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
    pTbl := data[tblName]
    prtInst := pTbl[inParams.key]
    autoNeg, ok := prtInst.Field[PORT_AUTONEG]
    if ok {
        if autoNeg == "true" {
            result["auto-negotiate"] = true
        } else {
            result["auto-negotiate"] = false
        }
    } else {
        log.Info("auto-negotiate field not found in DB")
    }
    return result, err
}

var DbToYang_intf_eth_port_speed_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_eth_port_speed_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeVxlan == intfType || IntfTypeVlan == intfType {
	    return result, nil
    }

    intTbl := IntfTypeTblMap[intfType]

    tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
    pTbl := data[tblName]
    prtInst := pTbl[inParams.key]
    speed, ok := prtInst.Field[PORT_SPEED]
    portSpeed := ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_UNSET
    if ok {
        portSpeed, err = getDbToYangSpeed(speed)
        result["port-speed"] = ocbinds.E_OpenconfigIfEthernet_ETHERNET_SPEED.ΛMap(portSpeed)["E_OpenconfigIfEthernet_ETHERNET_SPEED"][int64(portSpeed)].Name
    } else {
        log.Info("Speed field not found in DB")
    }

    return result, err
}

var DbToYang_intf_eth_port_fec_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_eth_port_fec_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeEthernet != intfType {
           return result, nil
    }
    intTbl := IntfTypeTblMap[intfType]

    tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
    pTbl := data[tblName]
    prtInst := pTbl[inParams.key]
    fec, ok := prtInst.Field[PORT_FEC]
    portFec := ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_UNSET
    if ok {
        portFec, err = getDbToYangFec(fec)
        result["port-fec"] = ocbinds.E_OpenconfigPlatformTypes_FEC_MODE_TYPE.ΛMap(portFec)["E_OpenconfigPlatformTypes_FEC_MODE_TYPE"][int64(portFec)].Name
    } else {
        log.Info("FEC field not found in DB")
    }
    return result, err
}

func getDbToYangFec(fec string) (ocbinds.E_OpenconfigPlatformTypes_FEC_MODE_TYPE, error) {
    portFec := ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_FEC_DISABLED
    var err error = errors.New("Not found in port speed map")
    for k, v := range yangToDbFecMap {
        if fec == v {
            portFec = k
            err = nil
        }
    }
    return portFec, err
}

var DbToYang_intf_eth_port_unreliable_los_xfmr = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    intfType, _, ierr := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_eth_port_unreliable_los_xfmr - Invalid interface type IntfTypeUnset");
        return result, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeEthernet != intfType {
           return result, nil
    }
    intTbl := IntfTypeTblMap[intfType]

    tblName, _ := getPortTableNameByDBId(intTbl, inParams.curDb)
    pTbl := data[tblName]
    prtInst := pTbl[inParams.key]
    los, ok := prtInst.Field[PORT_UNRELIABLE_LOS]
    portLos := ocbinds.OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE_UNRELIABLE_LOS_MODE_OFF
    if ok {
        portLos, err = getDbToYangLos(los)
        result["port-unreliable-los"] = ocbinds.E_OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE.ΛMap(portLos)["E_OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE"][int64(portLos)].Name
    } else {
        log.Info("Unreliable los field not found in DB")
    }
    return result, err
}

func getDbToYangLos(los string) (ocbinds.E_OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE, error) {
    portLos := ocbinds.OpenconfigIfEthernetExt2_UNRELIABLE_LOS_MODE_TYPE_UNRELIABLE_LOS_MODE_OFF
    var err error = errors.New("Unreliable los mode not found in db")
    for k, v := range yangToDbLosMap {
        if los == v {
            portLos = k
            err = nil
        }
    }
    return portLos, err
}

func getDbToYangSpeed (speed string) (ocbinds.E_OpenconfigIfEthernet_ETHERNET_SPEED, error) {
    portSpeed := ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_SPEED_UNKNOWN
    var err error = errors.New("Not found in port speed map")
    for k, v := range intfOCToSpeedMap {
        if speed == v {
            portSpeed = k
            err = nil
        }
    }
    return portSpeed, err
}

func intf_intf_tbl_key_gen (intfName string, ip string, prefixLen int, keySep string) string {
    return intfName + keySep + ip + "/" + strconv.Itoa(prefixLen)
}

var intf_subintfs_table_xfmr TableXfmrFunc = func (inParams XfmrParams) ([]string, error) {
    var tblList []string
    log.Info("intf_subintfs_table_xfmr: URI: ", inParams.uri)

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        return tblList, errors.New("Invalid interface type IntfTypeUnset");
    }

    if IntfTypeVlan == intfType || IntfTypeVxlan == intfType {
	    return tblList, nil
    }

    if (inParams.oper == GET || inParams.oper == DELETE) {
        if(inParams.dbDataMap != nil) {
            (*inParams.dbDataMap)[db.ConfigDB]["SUBINTF_TBL"] = make(map[string]db.Value)
            (*inParams.dbDataMap)[db.ConfigDB]["SUBINTF_TBL"]["0"] = db.Value{Field: make(map[string]string)}
            (*inParams.dbDataMap)[db.ConfigDB]["SUBINTF_TBL"]["0"].Field["NULL"] = "NULL"
            tblList = append(tblList, "SUBINTF_TBL")
        }
        if log.V(3) {
            log.Info("intf_subintfs_table_xfmr - Subinterface get operation ")
        }
    }

    return tblList, nil
}

var Subscribe_intf_ip_addr_xfmr = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    if log.V(3) {
        log.Info("Entering Subscribe_intf_ip_addr_xfmr")
    }
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)
    result.isVirtualTbl = false
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    uriIfName := pathInfo.Var("name")
    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    keyName := *sonicIfName

    log.Infof("Subscribe_intf_ip_addr_xfmr path:%s; template:%s targetUriPath:%s key:%s",pathInfo.Path, pathInfo.Template, targetUriPath, keyName)

    if (keyName != "") {
        intfType, _, _ := getIntfTypeByName(keyName)
        intTbl := IntfTypeTblMap[intfType]
        tblName := intTbl.cfgDb.intfTN
        result.dbDataMap = RedisDbMap{db.ConfigDB:{tblName:{keyName:{}}}}
    }
    result.needCache = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 15
    result.nOpts.pType = OnChange
    log.Info("Returning Subscribe_intf_ip_addr_xfmr, result:", result)
    return result, err
}

var Subscribe_routed_vlan_ip_addr_xfmr = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    if log.V(3) {
        log.Info("Entering Subscribe_routed_vlan_ip_addr_xfmr")
    }
    var err error
    var result XfmrSubscOutParams
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    uriIfName := pathInfo.Var("name")
    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    keyName := *sonicIfName

    log.Infof("Subscribe_routed_vlan_ip_addr_xfmr path:%s; template:%s targetUriPath:%s key:%s",pathInfo.Path, pathInfo.Template, targetUriPath, keyName)

    if (keyName != "") {
        result.dbDataMap = make(RedisDbMap)
        result.isVirtualTbl = false
        intfType, _, _ := getIntfTypeByName(keyName)
        intTbl := IntfTypeTblMap[intfType]
        tblName := intTbl.cfgDb.intfTN
        result.dbDataMap = RedisDbMap{db.ConfigDB:{tblName:{keyName:{}}}}
    } else  {
        err = errors.New("Invalid or Null Key")
    }
    log.Info("Returning Subscribe_routed_vlan_ip_addr_xfmr, result:", result)
    return result, err
}

var YangToDb_intf_subintfs_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var subintf_key string
    var err error

    log.Info("YangToDb_intf_subintfs_xfmr - inParams.uri ", inParams.uri)

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        return ifName, errors.New("Invalid interface type IntfTypeUnset");
    }
    if IntfTypeVlan == intfType {
        log.Info("YangToDb_intf_subintfs_xfmr - IntfTypeVlan")
        return ifName, nil
    }

    idx := pathInfo.Var("index")

    if idx != "0"  {
        errStr := "Invalid sub-interface index: " + idx
        err := tlerr.InvalidArgsError{Format: errStr}
        return idx, err
    }

    if (inParams.oper == GET) || (inParams.oper == DELETE) {
        subintf_key = "0"
    }

    log.Info("YangToDb_intf_subintfs_xfmr - return subintf_key ", subintf_key)
    return subintf_key, err
}

var DbToYang_intf_subintfs_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    if log.V(3) {
        log.Info("Entering DbToYang_intf_subintfs_xfmr")
    }

    rmap := make(map[string]interface{})
    var err error
    rmap["index"] = 0

    log.Info("DbToYang_intf_subintfs_xfmr rmap ", rmap)
    return rmap, err
}

var YangToDb_subintf_ip_addr_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    if log.V(3) {
        log.Info("Entering YangToDb_subintf_ip_addr_key_xfmr")
    }
    var err error
    var inst_key string
    pathInfo := NewPathInfo(inParams.uri)
    inst_key = pathInfo.Var("ip")
    log.Info("Interface IP: ", inst_key)
    return inst_key, err
}

var DbToYang_subintf_ip_addr_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info("Entering DbToYang_subintf_ip_addr_key_xfmr")
    }
    rmap := make(map[string]interface{})
    return rmap, nil
}

func intf_ip_addr_del (d *db.DB , ifName string, tblName string, subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface) (map[string]map[string]db.Value, error) {
    var err error
    subIntfmap := make(map[string]map[string]db.Value)
    intfIpMap := make(map[string]db.Value)

    // Handles the case when the delete request at subinterfaces/subinterface[index = 0]
    if subIntf == nil || (subIntf.Ipv4 == nil && subIntf.Ipv6 == nil) {
        ipMap, _ := getIntfIpByName(d, tblName, ifName, true, true, "")
        if len(ipMap) > 0 {
            for k, v := range ipMap {
                intfIpMap[k] = v
            }
        }
    }

    // This handles the delete for a specific IPv4 address or a group of IPv4 addresses
    if subIntf != nil && subIntf.Ipv4 != nil {
        if subIntf.Ipv4.Addresses != nil {
            if len(subIntf.Ipv4.Addresses.Address) < 1 {
                ipMap, _:= getIntfIpByName(d, tblName, ifName, true, false, "")
                if len(ipMap) > 0 {
                    for k, v := range ipMap {
                        intfIpMap[k] = v
                    }
                }
            } else {
                for ip := range subIntf.Ipv4.Addresses.Address {
                    ipMap, _ := getIntfIpByName(d, tblName, ifName, true, false, ip)
                    isSec := false

                    addr := subIntf.Ipv4.Addresses.Address[ip]
                    if addr.Config != nil && addr.Config.Secondary != nil {
                        isSec = true
                    }

                    if len(ipMap) > 0 {
                        for k, v := range ipMap {
                            secVal, ok := v.Field["secondary"]
                            if ok && secVal == "true" {
                                if isSec {
                                    intfIpMap[k] = v
                                } else {
                                    errStr := "No such address (" + k + ") configured on this interface as primary address"
                                    return nil, tlerr.InvalidArgsError {Format: errStr}
                                }
                            } else {
                                if isSec {
                                    log.Errorf("Secondary IPv4 Address : %s for interface : %s doesn't exist!", ip, ifName)
                                    errStr := "No such address (" + k + ") configured on this interface as secondary address"
                                    return nil, tlerr.InvalidArgsError {Format: errStr}
                                }
                                // Primary IPv4 delete
                                ifIpMap, _ := getIntfIpByName(d, tblName, ifName, true, false, "")
                                if(!utlCheckSecondaryIPConfigured(ifIpMap)) {
                                    intfIpMap[k]= v
                                } else {
                                    errStr := "Primary IPv4 address delete not permitted when secondary IPv4 address exists"
                                    log.Error(errStr)
                                    return nil, tlerr.InvalidArgsError {Format: errStr}
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Case when delete request is at IPv4 container level
            ipMap, _ := getIntfIpByName(d, tblName, ifName, true, false, "")
            if len(ipMap) > 0 {
                for k, v := range ipMap {
                    intfIpMap[k] = v
                }
            }
        }
    }

    // This handles the delete for a specific IPv6 address or a group of IPv6 addresses
    if subIntf != nil && subIntf.Ipv6 != nil {
        if subIntf.Ipv6.Addresses != nil {
            if len(subIntf.Ipv6.Addresses.Address) < 1 {
                ipMap, _ := getIntfIpByName(d, tblName, ifName, false, true, "")
                if len(ipMap) > 0 {
                    for k, v := range ipMap {
                        intfIpMap[k] = v
                    }
                }
            } else {
                for ip := range subIntf.Ipv6.Addresses.Address {
                    ipMap, _ := getIntfIpByName(d, tblName, ifName, false, true, ip)

                    if len(ipMap) > 0 {
                        for k, v := range ipMap {
                            intfIpMap[k]= v
                        }
                    }
                }
            }
        } else {
            // Case when the delete request is at IPv6 container level
            ipMap, _ := getIntfIpByName(d, tblName, ifName, false, true, "")
            if len(ipMap) > 0 {
                for k, v := range ipMap {
                    intfIpMap[k] = v
                }
            }
        }
    }
    if len(intfIpMap) > 0 {
        if _, ok := subIntfmap[tblName]; !ok {
            subIntfmap[tblName] = make (map[string]db.Value)
        }
        var data db.Value
        for k := range intfIpMap {
            ifKey := ifName + "|" + k
            subIntfmap[tblName][ifKey] = data
        }
        count := 0
        _ = interfaceIPcount(tblName, d, &ifName, &count)

        /* Delete interface from interface table if no other interface attributes/ip */
        if ((count - len(intfIpMap)) == 1 ) {
            IntfMapObj, err := d.GetMapAll(&db.TableSpec{Name:tblName+"|"+ifName})
            if err != nil {
                return nil, errors.New("Entry "+tblName+"|"+ifName+" missing from ConfigDB")
            }
            IntfMap := IntfMapObj.Field
            if len(IntfMap) == 1 {
                if _, ok := IntfMap["NULL"]; ok {
                    subIntfmap[tblName][ifName] = data
                }
            }
        }
    }
    log.Info("Delete IP address list ", subIntfmap,  " ", err)
    return subIntfmap, err
}

func routed_vlan_ip_addr_del (d *db.DB , ifName string, tblName string, routedVlanIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan) (map[string]map[string]db.Value, error) {
    var err error
    vlanIntfmap := make(map[string]map[string]db.Value)
    intfIpMap := make(map[string]db.Value)

    // Handles the case when the delete request at interfaces/interface[name] or at routed-vlan
    if routedVlanIntf == nil || (routedVlanIntf.Ipv4 == nil && routedVlanIntf.Ipv6 == nil) {
	    ipMap, _ := getIntfIpByName(d, tblName, ifName, true, true, "")
	    if len(ipMap) > 0 {
            for k, v := range ipMap {
                intfIpMap[k] = v
            }
        }
    }

    // This handles the delete for a specific IPv4 address or a group of IPv4 addresses
    if routedVlanIntf != nil && routedVlanIntf.Ipv4 != nil {
        if routedVlanIntf.Ipv4.Addresses != nil {
            if len(routedVlanIntf.Ipv4.Addresses.Address) < 1 {
                ipMap, _:= getIntfIpByName(d, tblName, ifName, true, false, "")
                if len(ipMap) > 0 {
                    for k, v := range ipMap {
                        intfIpMap[k] = v
                    }
                }
            } else {
                for ip := range routedVlanIntf.Ipv4.Addresses.Address {
                    ipMap, _ := getIntfIpByName(d, tblName, ifName, true, false, ip)
                    isSec := false

                    addr := routedVlanIntf.Ipv4.Addresses.Address[ip]
                    if addr.Config != nil && addr.Config.Secondary != nil {
                        isSec = true
                    }

                    if len(ipMap) > 0 {
                        for k, v := range ipMap {
                            secVal, ok := v.Field["secondary"]
                            if ok && secVal == "true" {
                                if isSec {
                                    intfIpMap[k] = v
                                } else {
                                    errStr := "No such address (" + k + ") configured on this interface as primary address"
                                    log.Error(errStr)
                                    return nil, tlerr.InvalidArgsError {Format: errStr}
                                }
                            } else {
                                if isSec {
                                    log.Errorf("Secondary IPv4 Address : %s for interface : %s doesn't exist!", ip, ifName)
                                    errStr := "No such address (" + ip + ") configured on this interface as secondary address"
                                    return nil, tlerr.InvalidArgsError {Format: errStr}
                                }
                                // Primary IPv4 delete
                                ifIpMap, _ := getIntfIpByName(d, tblName, ifName, true, false, "")
                                if(!utlCheckSecondaryIPConfigured(ifIpMap)) {
                                    intfIpMap[k]= v
                                } else {
                                    return nil, tlerr.InvalidArgsError {Format: "Primary IPv4 address delete not permitted when secondary IPv4 address exists"}
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Case when delete request is at IPv4 container level
            ipMap, _ := getIntfIpByName(d, tblName, ifName, true, false, "")
            if len(ipMap) > 0 {
                for k, v := range ipMap {
                    intfIpMap[k] = v
                }
            }
        }
    }

    // This handles the delete for a specific IPv6 address or a group of IPv6 addresses
    if routedVlanIntf != nil && routedVlanIntf.Ipv6 != nil {
        if routedVlanIntf.Ipv6.Addresses != nil {
            if len(routedVlanIntf.Ipv6.Addresses.Address) < 1 {
                ipMap, _ := getIntfIpByName(d, tblName, ifName, false, true, "")
                if len(ipMap) > 0 {
                    for k, v := range ipMap {
                        intfIpMap[k] = v
                    }
                }
            } else {
                for ip := range routedVlanIntf.Ipv6.Addresses.Address {
                    ipMap, _ := getIntfIpByName(d, tblName, ifName, false, true, ip)

                    if len(ipMap) > 0 {
                        for k, v := range ipMap {
                            intfIpMap[k] = v
                        }
                    }
                }
            }
        } else {
            // Case when the delete request is at IPv6 container level
            ipMap, _ := getIntfIpByName(d, tblName, ifName, false, true, "")
            if len(ipMap) > 0 {
                for k, v := range ipMap {
                    intfIpMap[k] = v
                }
            }
        }
    }

    vlanIntfCount := 0
    _ = interfaceIPcount(tblName, d, &ifName, &vlanIntfCount)
    var data db.Value

    // There is atleast one IP Address Configured on Vlan Intf
    // Add the key "<ifname>|<IP>" to the Map
    if len(intfIpMap) > 0 {
        if _, ok := vlanIntfmap[tblName]; !ok {
            vlanIntfmap[tblName] = make (map[string]db.Value)
        }

        for k := range intfIpMap {
            ifKey := ifName + "|" + k
            vlanIntfmap[tblName][ifKey] = data
        }
    }

    // Case-1: Last IP Address getting deleted on Vlan Interface
    // Case-2: Interface Vlan getting deleted with L3 Attributes Present
    if (vlanIntfCount - len(intfIpMap)) == 1 {
        sagIpKey, _ := d.GetKeysByPattern(&db.TableSpec{Name: "SAG"}, ifName+"|*")
        IntfMapObj, err := d.GetMapAll(&db.TableSpec{Name:tblName+"|"+ifName})
        if err != nil {
            return nil, errors.New("Entry "+tblName+"|"+ifName+" missing from ConfigDB")
        }
        IntfMap := IntfMapObj.Field
        // NULL indicates atleast one a) IP Address Config or b) SAG IP Config
        // So delete only when it is the Last IP and no SAG Config
        if len(IntfMap) == 1 &&   len(sagIpKey) == 0 {
            if _, ok := IntfMap["NULL"]; ok {
                if _, ok := vlanIntfmap[tblName]; !ok {
                    vlanIntfmap[tblName] = make (map[string]db.Value)
                }
                vlanIntfmap[tblName][ifName] = data
            }
        }
        // Case-2: If deletion at parent container(routedVlanIntf)
        // Delete it only when no SAG Config is present
        if routedVlanIntf == nil &&  len(sagIpKey) == 0 {
            if _, ok := vlanIntfmap[tblName]; !ok {
                vlanIntfmap[tblName] = make (map[string]db.Value)
            }
            vlanIntfmap[tblName][ifName] = data
        }
    }

    log.Info("routed_vlan_ip_addr_del: Delete IP address list ", vlanIntfmap,  " ", err)
    return vlanIntfmap, err
}
/* Validate interface in L3 mode, if true return error */
func validateL3ConfigExists(d *db.DB, ifName *string) error {
    intfType, _, ierr := getIntfTypeByName(*ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        return errors.New("Invalid interface type IntfTypeUnset");
    }
    intTbl := IntfTypeTblMap[intfType]
    IntfMapObj, err := d.GetMapAll(&db.TableSpec{Name:intTbl.cfgDb.intfTN+"|"+*ifName})
    if err == nil && IntfMapObj.IsPopulated() {
        ifUIName := utils.GetUINameFromNativeName(ifName)
        errStr := "L3 Configuration exists for Interface: " + *ifUIName
        IntfMap := IntfMapObj.Field
        if intfType == IntfTypeLoopback {
            // Checks specific to Loopback interface
            ipKeys, err := doGetIntfIpKeys(d, LOOPBACK_INTERFACE_TN, *ifName)
            if (err == nil && len(ipKeys) > 0) {
                return tlerr.InvalidArgsError{Format:errStr}
            }
            if len(IntfMap) == 2 {
                /* Loopback interface is created with a NULL field,
                   now checking if ipv6_use_link_local_only field also
                   exists and if it's value is disabled. */
                if val, ok := IntfMap["ipv6_use_link_local_only"]; ok && val == "disable" {
                    return nil
                }
                return tlerr.InvalidArgsError{Format:errStr}
            }
            if len(IntfMap) > 2 {
                return tlerr.InvalidArgsError{Format:errStr}
            }
        } else {
            // L3 config exists if interface in interface table
            return tlerr.InvalidArgsError{Format:errStr}
        }
    }
    return nil
}

/* Validate whether intf exists in DB */
func validateIntfExists(d *db.DB, intfTs string, ifName string) error {
    if len(ifName) == 0 {
        return errors.New("Length of Interface name is zero")
    }
    nativeName := utils.GetNativeNameFromUIName(&ifName)
    ifName = *nativeName
    log.V(3).Info("Converted Interface name = ", ifName)
    entry, err := d.GetEntry(&db.TableSpec{Name:intfTs}, db.Key{Comp: []string{ifName}})
    if err != nil || !entry.IsPopulated() {
        errStr := "Invalid Interface:" + ifName
        if log.V(3) {
            log.Error(errStr)
        }
        return tlerr.InvalidArgsError{Format:errStr}
    }
    return nil
}

// Validates Prefix Length for all interface types except loopback
func isValidPrefixLength(pLen *uint8, isIpv4 bool) bool {
    // maxPrfxLen corresponds to Maximum prefix length for all interface types other than loopback
    var maxPrfxLen uint8 = 31
    if !isIpv4 {
        maxPrfxLen = 127
    }
    return *pLen <= maxPrfxLen
}

/* Note: This function can be extended for IP validations for all Interface types */
func validateIpPrefixForIntfType(ifType E_InterfaceType, ip *string, prfxLen *uint8, isIpv4 bool) error {
    var err error

    switch ifType {
    case IntfTypeLoopback:
        if(isIpv4) {
            if *prfxLen != 32 {
                errStr := "Not supported prefix length (32 is supported)"
                err = tlerr.InvalidArgsError{Format:errStr}
                return err
            }
        } else {
            if(*prfxLen != 128) {
                errStr := "Not supported prefix length (128 is supported)"
                err = tlerr.InvalidArgsError{Format:errStr}
                return err
            }
        }
    case IntfTypeEthernet, IntfTypeVlan, IntfTypePortChannel, IntfTypeMgmt:
        if !isValidPrefixLength(prfxLen, isIpv4) {
            log.Errorf("Invalid Mask configuration!")
            errStr := "Prefix length " + strconv.Itoa(int(*prfxLen)) + " not supported"
            err = tlerr.InvalidArgsError{Format: errStr}
            return err
        }
    }
    return err
}


func checkIfSagAfiExistOnIntf(d *db.DB, afi string, ifName string) (bool){
    preKey := make([]string, 2)
    preKey[0] = ifName
    preKey[1] = afi

    sagKey := db.Key{ Comp: preKey}

    sagEntry, err := d.GetEntry(&db.TableSpec{Name: "SAG"}, sagKey)
    if(err == nil) {
        sagIpList, ok := sagEntry.Field["gwip@"]

        if (!ok) {
            return true
        }

        if (len(sagIpList) != 0) {
            return true
        }
    }

    return false
}

func chekIfSagExistOnIntf(d *db.DB, ifName string) (bool) {

    return (checkIfSagAfiExistOnIntf(d, "IPv4", ifName) || checkIfSagAfiExistOnIntf(d, "IPv6", ifName))

}

/* Check for IP overlap */
func validateIpOverlap(d *db.DB, intf string, ipPref string, tblName string, isIntfIp bool) (string, error) {
    log.Info("Checking for IP overlap ....")

    ipA, ipNetA, err := net.ParseCIDR(ipPref)
    if err != nil {
        log.Info("Failed to parse IP address: ", ipPref)
        return "", err
    }

    var allIntfKeys []db.Key

    for key := range IntfTypeTblMap {
        intTbl := IntfTypeTblMap[key]
        keys, err := d.GetKeys(&db.TableSpec{Name:intTbl.cfgDb.intfTN})
        if err != nil {
            log.Info("Failed to get keys; err=%v", err)
            return "", err
        }
        allIntfKeys = append(allIntfKeys, keys...)
    }

    sagKeys, err := d.GetKeys(&db.TableSpec{Name:"SAG"})
    if nil == err {

        for _, sagIf := range sagKeys {
            sagEntry, err := d.GetEntry(&db.TableSpec{Name: "SAG"}, sagIf)
            if(err != nil) {
                continue
            }

            sagIpList, ok := sagEntry.Field["gwip@"]

            if (!ok) {
                continue;
            }

            sagIpMap := strings.Split(sagIpList, ",")

            if (sagIpMap[0] == "") {
                continue
            }

            for _, sagIp := range sagIpMap {
                prekey := make([]string, 3)
                prekey[0] = sagIf.Get(0)
                prekey[1] = sagIp
                prekey[2] = "SAG"
                appendKey := db.Key{ Comp: prekey}
                allIntfKeys = append(allIntfKeys, appendKey)
            }
        }
    }

    if len(allIntfKeys) > 0 {
        for _, key := range allIntfKeys {
            if len(key.Comp) < 2 {
                continue
            }
            ipB, ipNetB, perr := net.ParseCIDR(key.Get(1))
            //Check if key has IP, if not continue
            if ipB == nil || perr != nil {
                continue
            }
            if ipNetA.Contains(ipB) || ipNetB.Contains(ipA) {
                if log.V(3) {
                    log.Info("IP: ", ipPref, " overlaps with ", key.Get(1), " of ", key.Get(0))
                }
                //Handle IP overlap across different interface, reject if in same VRF
                intfType, _, ierr := getIntfTypeByName(key.Get(0))
                if ierr != nil {
                    log.Errorf("Extracting Interface type for Interface: %s failed!", key.Get(0))
                    return "", ierr
                }
                intTbl := IntfTypeTblMap[intfType]
                if intf != key.Get(0) {
                    vrfNameA, _ := d.GetMap(&db.TableSpec{Name:tblName+"|"+intf}, "vrf_name")
                    vrfNameB, _ := d.GetMap(&db.TableSpec{Name:intTbl.cfgDb.intfTN+"|"+key.Get(0)}, "vrf_name")
                    if vrfNameA == vrfNameB {
			intfName := key.Get(0)
			intfNameUi := *utils.GetUINameFromNativeName(&intfName)
                        errStr := "IP " + ipPref + " overlaps with IP or IP Anycast " + key.Get(1) + " of Interface " + intfNameUi
                        log.Error(errStr)
                        return "", errors.New(errStr)
                    }
                } else if isIntfIp {
                    //Handle IP overlap on same interface, replace
                    //log.Error("Entry ", key.Get(1), " on ", intf, " needs to be deleted")
                    errStr := "IP overlap on same interface with IP or IP Anycast " + key.Get(1)

                    if ((len(key.Comp) == 3) && (key.Get(2) == "SAG")) {
                        return "", errors.New(errStr)
                    }
                    /* Handling overlap for IPv6 address only here, overlapping in case of IPv4 address
                       is handled as part of address type check (Primary / Secondary) */
                    ip := strings.Split(ipPref, "/")
                    if validIPv6(ip[0]) {
                        return key.Get(1), errors.New(errStr)
                    }
                }
            }
        }
    }
    return "", nil
}

func utlCheckAndRetrievePrimaryIPConfigured(ipMap map[string]db.Value) (bool, string) {
    for ipKey, ipVal := range ipMap {
        if _, ok := ipVal.Field["secondary"]; !ok {
            return true, ipKey
        }
    }
    return false, ""
}

func utlCheckSecondaryIPConfigured(ipMap map[string]db.Value) bool {
    for _, ipVal := range ipMap {
        if _, ok := ipVal.Field["secondary"]; ok {
            return true
        }
    }
    return false
}

/* Following logic to handle the case when the IP address already exists and handles the case when
   IP address is configured as primary and the current request(same IP) for secondary IP address config and viceversa */
func utlValidateIpTypeForCfgredSameIp(ipEntry *db.Value, secFlag bool,
                                         ipPref *string, ifName *string) error {
    dbgStr := "IPv4 address: "
    dbgStr += *ipPref

    if ipEntry.IsPopulated() {
        _, ok := ipEntry.Field["secondary"]
        if ok {
            if !secFlag {
                errStr := dbgStr + " is already configured as secondary for interface: " + *ifName
                log.Error(errStr)
                return tlerr.InvalidArgsError{Format: errStr}
             }
             log.Infof("%s is already configured as secondary! Processing further attributes", dbgStr)
        } else {
            if secFlag {
                errStr := dbgStr + " is already configured as primary for interface: " + *ifName
                log.Error(errStr)
                return tlerr.InvalidArgsError{Format: errStr}
             }
             log.Infof("%s is already configured as primary! Processing further attributes", dbgStr)
        }
    }
    return nil
}

func utlValidateIpTypeForCfgredDiffIp(m map[string]string, ipMap map[string]db.Value, ipEntry *db.Value, secFlag bool,
                                       ipPref *string, ifName *string) (string, bool, error) {

    dbgStr := "IPv4 address"

    checkPrimIPCfgred, cfgredPrimIP := utlCheckAndRetrievePrimaryIPConfigured(ipMap)
    if secFlag {
        if !checkPrimIPCfgred {
	    intfNameUi := utils.GetUINameFromNativeName(ifName)
            errStr := "Primary " + dbgStr + " is not configured for interface: " + *intfNameUi
            log.Error(errStr)
            return "", false, tlerr.InvalidArgsError{Format: errStr}
        }
        m["secondary"] = "true"
    } else {
        if checkPrimIPCfgred && !ipEntry.IsPopulated() {
            infoStr := "Primary " + dbgStr + " is already configured for interface: " + *ifName
            log.Info(infoStr)
            return cfgredPrimIP, true, nil
        }
    }
    return "", false, nil
}

func checkLocalIpExist(d *db.DB, nbrAddr string) (bool, error) {
    var allIntfKeys []db.Key
    var err error

    nbrIp := net.ParseIP(nbrAddr)
    if nbrIp == nil {
        err = errors.New("Failed to parse IP address")
        log.Info("Failed to parse IP address: ", nbrAddr)
        return false, err
    }

    for key := range IntfTypeTblMap {
        intTbl := IntfTypeTblMap[key]
        keys, err := d.GetKeys(&db.TableSpec{Name:intTbl.cfgDb.intfTN})
        if err == nil {
            allIntfKeys = append(allIntfKeys, keys...)
        }
    }

    sagKeys, err := d.GetKeys(&db.TableSpec{Name:"SAG"})
    if nil == err {

        for _, sagIf := range sagKeys {
            sagEntry, err := d.GetEntry(&db.TableSpec{Name: "SAG"}, sagIf)
            if(err != nil) {
                continue
            }

            sagIpList, ok := sagEntry.Field["gwip@"]

            if (!ok) {
                continue;
            }

            sagIpMap := strings.Split(sagIpList, ",")

            if (sagIpMap[0] == "") {
                continue
            }

            for _, sagIp := range sagIpMap {
                prekey := make([]string, 3)
                prekey[0] = sagIf.Get(0)
                prekey[1] = sagIp
                prekey[2] = "SAG"
                appendKey := db.Key{ Comp: prekey}
                allIntfKeys = append(allIntfKeys, appendKey)
            }
        }
    }

    if len(allIntfKeys) > 0 {
        for _, key := range allIntfKeys {
            if len(key.Comp) < 2 {
                continue
            }
            localIp, _, perr := net.ParseCIDR(key.Get(1))
            //Check if key has IP, if not continue
            if localIp == nil || perr != nil {
                continue
            }
            if localIp.Equal(nbrIp) {
                if log.V(3) {
                    log.Info("Neighbor address: ", nbrAddr, " exist in local address ")
                }
                return true, nil
            }
        }
    }
    return false, nil
}

var YangToDb_intf_ip_addr_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err, oerr error
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subIntfmap := make(map[string]map[string]db.Value)
    subIntfmap_del := make(map[string]map[string]db.Value)
    var value db.Value
    var overlapIP string

    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("YangToDb_intf_ip_addr_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName
	intfType, _, ierr := getIntfTypeByName(ifName)

    if IntfTypeVxlan == intfType || IntfTypeVlan == intfType {
	    return subIntfmap, nil
    }

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_intf_subintf_ip_xfmr : IntfsObj/interface list is empty.")
        return subIntfmap, errors.New("IntfsObj/Interface is not specified")
    }

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    /* Validate whether the Interface is configured as member-port associated with any vlan */
    if intfType == IntfTypeEthernet || intfType == IntfTypePortChannel {
        err = validateIntfAssociatedWithVlan(inParams.d, &ifName)
        if err != nil {
            return subIntfmap, err
        }
    }
    /* Validate whether the Interface is configured as member-port associated with any portchannel */
    if intfType == IntfTypeEthernet {
        err = validateIntfAssociatedWithPortChannel(inParams.d, &ifName)
        if err != nil {
            errStr := "IP config is not permitted on LAG member port."
            return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
        }
    }

    /* Validate if DHCP_Relay is provisioned on the interface */
    prefixType := ""
    if (strings.Contains(inParams.uri, "ipv4")) {
       prefixType = "ipv4"
    }else if (strings.Contains(inParams.uri, "ipv6")) {
       prefixType = "ipv6"
    }

    if inParams.oper == DELETE {
       dhcpProv, _ :=ValidateIntfProvisionedForRelay(inParams.d, ifName, prefixType)
       if dhcpProv {
           errStr := "IP address cannot be deleted. DHCP Relay is configured on the interface."
           return subIntfmap, tlerr.InvalidArgsError{Format: errStr}
       }
    }

    if _, ok := intfsObj.Interface[uriIfName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
    intfObj := intfsObj.Interface[uriIfName]

    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        // Handling the scenario for Interface instance delete at interfaces/interface[name] level or subinterfaces container level
        if inParams.oper == DELETE {
            log.Info("Top level Interface instance delete or subinterfaces container delete for Interface: ", ifName)
            return intf_ip_addr_del(inParams.d, ifName, tblName, nil)
        }
        errStr := "SubInterface node doesn't exist"
        log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
        err = tlerr.InvalidArgsError{Format:errStr}
        return subIntfmap, err
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        log.Info("YangToDb_intf_subintf_ip_xfmr : No IP address handling required")
        errStr := "SubInterface index 0 doesn't exist"
        err = tlerr.InvalidArgsError{Format:errStr}
        return subIntfmap, err
    }

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]
    if inParams.oper == DELETE {
        return intf_ip_addr_del(inParams.d, ifName, tblName, subIntfObj)
    }

    entry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})
    if dbErr != nil || !entry.IsPopulated() {
        ifdb := make(map[string]string)
        ifdb["NULL"] = "NULL"
        value := db.Value{Field: ifdb}
        if _, ok := subIntfmap[tblName]; !ok {
            subIntfmap[tblName] = make(map[string]db.Value)
        }
        subIntfmap[tblName][ifName] = value

    }

    if subIntfObj.Ipv4 != nil && subIntfObj.Ipv4.Addresses != nil {
        for ip := range subIntfObj.Ipv4.Addresses.Address {
            addr := subIntfObj.Ipv4.Addresses.Address[ip]
            if addr.Config != nil {
                if addr.Config.Ip == nil {
                    addr.Config.Ip = new(string)
                    *addr.Config.Ip = ip
                }
                log.Info("Ip:=", *addr.Config.Ip)
                if addr.Config.PrefixLength == nil {
                    log.Error("Prefix Length empty!")
                    errStr := "Prefix Length not present"
                    err = tlerr.InvalidArgsError{Format:errStr}
                    return subIntfmap, err
                }
                log.Info("prefix:=", *addr.Config.PrefixLength)
                if !validIPv4(*addr.Config.Ip) {
                    errStr := "Invalid IPv4 address " + *addr.Config.Ip
                    err = tlerr.InvalidArgsError{Format: errStr}
                    return subIntfmap, err
                }
                /* Validate IP specific to Interface type */
                err = validateIpPrefixForIntfType(intfType, addr.Config.Ip, addr.Config.PrefixLength,  true)
                if err != nil {
                    return subIntfmap, err
                }
                /* Check for IP overlap */
                ipPref := *addr.Config.Ip+"/"+strconv.Itoa(int(*addr.Config.PrefixLength))
                overlapIP, oerr = validateIpOverlap(inParams.d, ifName, ipPref, tblName, true);

                ipEntry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName, ipPref}})
                ipMap, _ := getIntfIpByName(inParams.d, intTbl.cfgDb.intfTN, ifName, true, false, "")

                secFlag := false
                if addr.Config.Secondary != nil {
                    secFlag = *addr.Config.Secondary
                    log.Info("IPv4: Secondary Flag received = ", secFlag)

                    if ((intfType == IntfTypeLoopback) && (validateMultiIPForDonorIntf(inParams.d, &ifName))) {
                        errStr := "Loopback interface is Donor for Unnumbered interface. Cannot add Multiple IPv4 address"
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return subIntfmap, err
                    }
                }

                if dbErr == nil {
                    err := utlValidateIpTypeForCfgredSameIp(&ipEntry, secFlag, &ipPref, &uriIfName)
                    if err != nil {
                        return nil, err
                    }
                }

                m := make(map[string]string)
                alrdyCfgredIP, primaryIpAlrdyCfgred, err := utlValidateIpTypeForCfgredDiffIp(m, ipMap, &ipEntry, secFlag, &ipPref, &ifName)
                if err != nil {
                    return nil, err
                }
                // Primary IP config already happened and replacing it with new one
                if primaryIpAlrdyCfgred && len(alrdyCfgredIP) != 0 && alrdyCfgredIP != ipPref {
                    subIntfmap_del[tblName] = make(map[string]db.Value)
                    key := ifName + "|" + alrdyCfgredIP
                    subIntfmap_del[tblName][key] = value
                    subOpMap[db.ConfigDB] = subIntfmap_del
                    log.Info("subOpMap: ", subOpMap)
                    inParams.subOpDataMap[DELETE] = &subOpMap
                }

                intf_key := intf_intf_tbl_key_gen(ifName, *addr.Config.Ip, int(*addr.Config.PrefixLength), "|")

                if addr.Config.GwAddr != nil {
                    if intfType != IntfTypeMgmt {
                        errStr := "GwAddr config is not supported " + ifName
                        log.Info("GwAddr config is not supported for intfType: ", intfType, " " , ifName)
                        return subIntfmap, errors.New(errStr)
                    }
                    if !validIPv4(*addr.Config.GwAddr) {
                        errStr := "Invalid IPv4 Gateway address " + *addr.Config.GwAddr
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return subIntfmap, err
                    }
                    m["gwaddr"] = *addr.Config.GwAddr
                } else {
                    m["NULL"] = "NULL"
                }
                value := db.Value{Field: m}
                if _, ok := subIntfmap[tblName]; !ok {
                    subIntfmap[tblName] = make(map[string]db.Value)
                }
                subIntfmap[tblName][intf_key] = value
                if log.V(3) {
                    log.Info("tblName :", tblName, " intf_key: ", intf_key, " data : ", value)
                }
            }
        }
    }
    if subIntfObj.Ipv6 != nil && subIntfObj.Ipv6.Addresses != nil {
        for ip := range subIntfObj.Ipv6.Addresses.Address {
            addr := subIntfObj.Ipv6.Addresses.Address[ip]
            if addr.Config != nil {
                if addr.Config.Ip == nil {
                    addr.Config.Ip = new(string)
                    *addr.Config.Ip = ip
                }
                log.Info("Ipv6 IP:=", *addr.Config.Ip)
                if addr.Config.PrefixLength == nil {
                    log.Error("Prefix Length empty!")
                    errStr := "Prefix Length not present"
                    err = tlerr.InvalidArgsError{Format:errStr}
                    return subIntfmap, err
                }
                log.Info("Ipv6 prefix:=", *addr.Config.PrefixLength)
                if !validIPv6(*addr.Config.Ip) {
                    errStr := "Invalid IPv6 address " + *addr.Config.Ip
                    err = tlerr.InvalidArgsError{Format: errStr}
                    return subIntfmap, err
                }
                /* Validate IP specific to Interface type */
                err = validateIpPrefixForIntfType(intfType, addr.Config.Ip, addr.Config.PrefixLength, false)
                if err != nil {
                    return subIntfmap, err
                }
                /* Check for IPv6 overlap */
                ipPref := *addr.Config.Ip+"/"+strconv.Itoa(int(*addr.Config.PrefixLength))
                overlapIP, oerr = validateIpOverlap(inParams.d, ifName, ipPref, tblName, true);

                m := make(map[string]string)

                intf_key := intf_intf_tbl_key_gen(ifName, *addr.Config.Ip, int(*addr.Config.PrefixLength), "|")

                if addr.Config.GwAddr != nil {
                    if intfType != IntfTypeMgmt {
                        errStr := "GwAddr config is not supported " + ifName
                        log.Info("GwAddr config is not supported for intfType: ", intfType, " " , ifName)
                        return subIntfmap, errors.New(errStr)
                    }
                    if !validIPv6(*addr.Config.GwAddr) {
                        errStr := "Invalid IPv6 Gateway address " + *addr.Config.GwAddr
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return subIntfmap, err
                    }
                    m["gwaddr"] = *addr.Config.GwAddr
                } else {
                    m["NULL"] = "NULL"
                }
                value := db.Value{Field: m}
                if _, ok := subIntfmap[tblName]; !ok {
                    subIntfmap[tblName] = make(map[string]db.Value)
                }
                subIntfmap[tblName][intf_key] = value
                log.Info("tblName :", tblName, "intf_key: ", intf_key, "data : ", value)
            }
        }
    }

    if oerr != nil {
        if overlapIP == "" {
            log.Error(oerr)
            return nil, tlerr.InvalidArgsError{Format: oerr.Error()}
        } else {
            subIntfmap_del[tblName] = make(map[string]db.Value)
            key := ifName + "|" + overlapIP
            subIntfmap_del[tblName][key] = value
            subOpMap[db.ConfigDB] = subIntfmap_del
            log.Info("subOpMap: ", subOpMap)
            inParams.subOpDataMap[DELETE] = &subOpMap
        }
    }

    log.Info("YangToDb_intf_subintf_ip_xfmr : subIntfmap : ",  subIntfmap)
    return subIntfmap, err
}

var YangToDb_routed_vlan_ip_addr_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err, oerr error
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    vlanIntfmap := make(map[string]map[string]db.Value)
    vlanIntfmap_del := make(map[string]map[string]db.Value)
    var value db.Value
    var overlapIP string

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
	intfType, _, ierr := getIntfTypeByName(ifName)

    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_routed_vlan_ip_addr_xfmr : IntfsObj/interface list is empty.")
        return vlanIntfmap, errors.New("IntfsObj/Interface is not specified")
    }

    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_routed_vlan_ip_addr_xfmr: " + errStr)
        return vlanIntfmap, errors.New(errStr)
    }

    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_routed_vlan_ip_addr_xfmr: " + errStr)
        return vlanIntfmap, errors.New(errStr)
    }

    if IntfTypeVlan != intfType {
        return vlanIntfmap, nil
    }

    if _, ok := intfsObj.Interface[ifName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_routed_vlan_ip_addr_xfmr: " + errStr)
        return vlanIntfmap, errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
    log.Info("YangToDb_routed_vlan_ip_addr_xfmr: tblName: ", tblName)
    intfObj := intfsObj.Interface[ifName]

    // Validate if DHCP_Relay is provisioned on the interface
    prefixType := ""
    if (strings.Contains(inParams.uri, "ipv4")) {
       prefixType = "ipv4"
    }else if (strings.Contains(inParams.uri, "ipv6")) {
       prefixType = "ipv6"
    }

    if intfObj.RoutedVlan == nil {
        // Handling the scenario for Interface instance delete at interfaces/interface[name] level or subinterfaces container level
        if inParams.oper == DELETE {
           dhcpProv, _ :=ValidateIntfProvisionedForRelay(inParams.d, ifName, prefixType)
           if dhcpProv {
               errStr := "IP address cannot be deleted. DHCP Relay is configured on the interface"
               return vlanIntfmap, tlerr.InvalidArgsError {Format: errStr}
            }
            log.Info("YangToDb_routed_vlan_ip_addr_xfmr: Top level Interface instance delete or routed-vlan container delete for Interface: ", ifName)
            return routed_vlan_ip_addr_del(inParams.d, ifName, tblName, nil)
        }
        errStr := "routed-vlan node doesn't exist"
        log.Info("YangToDb_routed_vlan_ip_xfmr : " + errStr)
        err = tlerr.InvalidArgsError{Format:errStr}
        return vlanIntfmap, err
    }

    vlanIntfObj := intfObj.RoutedVlan
    if inParams.oper == DELETE {
        dhcpProv, _ :=ValidateIntfProvisionedForRelay(inParams.d, ifName, prefixType)
        if dhcpProv {
            errStr := "IP address cannot be deleted. DHCP Relay is configured on the interface."
            return vlanIntfmap, tlerr.InvalidArgsError {Format: errStr}
        }
        return routed_vlan_ip_addr_del(inParams.d, ifName, tblName, vlanIntfObj)
    }

    entry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName}})
    if dbErr != nil || !entry.IsPopulated() {
        ifdb := make(map[string]string)
        ifdb["NULL"] = "NULL"
        value := db.Value{Field: ifdb}
        if _, ok := vlanIntfmap[tblName]; !ok {
            vlanIntfmap[tblName] = make(map[string]db.Value)
        }
        vlanIntfmap[tblName][ifName] = value

    }

    if vlanIntfObj.Ipv4 != nil && vlanIntfObj.Ipv4.Addresses != nil {
        for ip := range vlanIntfObj.Ipv4.Addresses.Address {
            addr := vlanIntfObj.Ipv4.Addresses.Address[ip]
            if addr.Config != nil {
                if addr.Config.Ip == nil {
                    addr.Config.Ip = new(string)
                    *addr.Config.Ip = ip
                }
                log.Info("Ip:=", *addr.Config.Ip)
                if addr.Config.PrefixLength == nil {
                    log.Error("Prefix Length empty!")
                    errStr := "Prefix Length not present"
                    err = tlerr.InvalidArgsError{Format:errStr}
                    return vlanIntfmap, err
                }
                log.Info("prefix:=", *addr.Config.PrefixLength)
                if !validIPv4(*addr.Config.Ip) {
                    errStr := "Invalid IPv4 address " + *addr.Config.Ip
                    err = tlerr.InvalidArgsError{Format: errStr}
                    return vlanIntfmap, err
                }
                /* Validate IP specific to Interface type */
                err = validateIpPrefixForIntfType(intfType, addr.Config.Ip, addr.Config.PrefixLength,  true)
                if err != nil {
                    return vlanIntfmap, err
                }
                /* Check for IP overlap */
                ipPref := *addr.Config.Ip+"/"+strconv.Itoa(int(*addr.Config.PrefixLength))
                overlapIP, oerr = validateIpOverlap(inParams.d, ifName, ipPref, tblName, true);

                ipEntry, dbErr := inParams.d.GetEntry(&db.TableSpec{Name:intTbl.cfgDb.intfTN}, db.Key{Comp: []string{ifName, ipPref}})
                ipMap, _ := getIntfIpByName(inParams.d, intTbl.cfgDb.intfTN, ifName, true, false, "")

                secFlag := false
                if addr.Config.Secondary != nil {
                    secFlag = *addr.Config.Secondary
                    log.Info("IPv4: Secondary Flag received = ", secFlag)
                }

                if dbErr == nil {
                    err := utlValidateIpTypeForCfgredSameIp(&ipEntry, secFlag, &ipPref, &ifName)
                    if err != nil {
                        return nil, err
                    }
                }

                m := make(map[string]string)
                alrdyCfgredIP, primaryIpAlrdyCfgred, err := utlValidateIpTypeForCfgredDiffIp(m, ipMap, &ipEntry, secFlag, &ipPref, &ifName)
                if err != nil {
                    return nil, err
                }
                // Primary IP config already happened and replacing it with new one
                if primaryIpAlrdyCfgred && len(alrdyCfgredIP) != 0 && alrdyCfgredIP != ipPref {
                    vlanIntfmap_del[tblName] = make(map[string]db.Value)
                    key := ifName + "|" + alrdyCfgredIP
                    vlanIntfmap_del[tblName][key] = value
                    subOpMap[db.ConfigDB] = vlanIntfmap_del
                    log.Info("subOpMap: ", subOpMap)
                    inParams.subOpDataMap[DELETE] = &subOpMap
                }

                intf_key := intf_intf_tbl_key_gen(ifName, *addr.Config.Ip, int(*addr.Config.PrefixLength), "|")
                m["NULL"] = "NULL"
                value := db.Value{Field: m}
                if _, ok := vlanIntfmap[tblName]; !ok {
                    vlanIntfmap[tblName] = make(map[string]db.Value)
                }
                vlanIntfmap[tblName][intf_key] = value
                log.Info("tblName :", tblName, " intf_key: ", intf_key, " data : ", value)
            }
        }
    }
    if vlanIntfObj.Ipv6 != nil && vlanIntfObj.Ipv6.Addresses != nil {
        for ip := range vlanIntfObj.Ipv6.Addresses.Address {
            addr := vlanIntfObj.Ipv6.Addresses.Address[ip]
            if addr.Config != nil {
                if addr.Config.Ip == nil {
                    addr.Config.Ip = new(string)
                    *addr.Config.Ip = ip
                }
                log.Info("Ipv6 IP:=", *addr.Config.Ip)
                if addr.Config.PrefixLength == nil {
                    log.Error("Prefix Length empty!")
                    errStr := "Prefix Length not present"
                    err = tlerr.InvalidArgsError{Format:errStr}
                    return vlanIntfmap, err
                }
                log.Info("Ipv6 prefix:=", *addr.Config.PrefixLength)
                if !validIPv6(*addr.Config.Ip) {
                    errStr := "Invalid IPv6 address " + *addr.Config.Ip
                    err = tlerr.InvalidArgsError{Format: errStr}
                    return vlanIntfmap, err
                }
                /* Validate IP specific to Interface type */
                err = validateIpPrefixForIntfType(intfType, addr.Config.Ip, addr.Config.PrefixLength, false)
                if err != nil {
                    return vlanIntfmap, err
                }
                /* Check for IPv6 overlap */
                ipPref := *addr.Config.Ip+"/"+strconv.Itoa(int(*addr.Config.PrefixLength))
                overlapIP, oerr = validateIpOverlap(inParams.d, ifName, ipPref, tblName, true);

                m := make(map[string]string)

                intf_key := intf_intf_tbl_key_gen(ifName, *addr.Config.Ip, int(*addr.Config.PrefixLength), "|")
                m["NULL"] = "NULL"
                value := db.Value{Field: m}
                if _, ok := vlanIntfmap[tblName]; !ok {
                    vlanIntfmap[tblName] = make(map[string]db.Value)
                }
                vlanIntfmap[tblName][intf_key] = value
                log.Info("tblName :", tblName, " intf_key: ", intf_key, " data : ", value)
            }
        }
    }

    if oerr != nil {
        if overlapIP == "" {
            log.Error(oerr)
            return nil, tlerr.InvalidArgsError{Format: oerr.Error()}
        } else {
            vlanIntfmap_del[tblName] = make(map[string]db.Value)
            key := ifName + "|" + overlapIP
            vlanIntfmap_del[tblName][key] = value
            subOpMap[db.ConfigDB] = vlanIntfmap_del
            log.Info("subOpMap: ", subOpMap)
            inParams.subOpDataMap[DELETE] = &subOpMap
        }
    }

    log.Info("YangToDb_routed_vlan_ip_addr_xfmr: vlanIntfmap : ",  vlanIntfmap)
    return vlanIntfmap, err
}

func convertIpMapToOC (intfIpMap map[string]db.Value, ifInfo *ocbinds.OpenconfigInterfaces_Interfaces_Interface, isState bool) error {
    var subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
    var err error

    if _, ok := ifInfo.Subinterfaces.Subinterface[0]; !ok {
        _, err = ifInfo.Subinterfaces.NewSubinterface(0)
        if err != nil {
            log.Error("Creation of subinterface subtree failed!")
            return err
        }
    }

    subIntf = ifInfo.Subinterfaces.Subinterface[0]
    ygot.BuildEmptyTree(subIntf)
    ygot.BuildEmptyTree(subIntf.Ipv4)
    ygot.BuildEmptyTree(subIntf.Ipv6)

    for ipKey, ipdata := range intfIpMap {
        log.Info("IP address = ", ipKey)
        ipB, ipNetB, _ := net.ParseCIDR(ipKey)
        v4Flag := false
        v6Flag := false

        var v4Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_Addresses_Address
        var v6Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv6_Addresses_Address
        if validIPv4(ipB.String()) {
            if _, ok := subIntf.Ipv4.Addresses.Address[ipB.String()]; !ok {
                _, err = subIntf.Ipv4.Addresses.NewAddress(ipB.String())
            }
            v4Address = subIntf.Ipv4.Addresses.Address[ipB.String()]
            v4Flag = true
        } else if validIPv6(ipB.String()) {
            if _, ok := subIntf.Ipv6.Addresses.Address[ipB.String()]; !ok {
                _, err = subIntf.Ipv6.Addresses.NewAddress(ipB.String())
            }
            v6Address =  subIntf.Ipv6.Addresses.Address[ipB.String()]
            v6Flag = true
        } else {
            log.Error("Invalid IP address " + ipB.String())
            continue
        }
        if err != nil {
            log.Error("Creation of address subtree failed!")
            return err
        }
        if v4Flag {
            ygot.BuildEmptyTree(v4Address)
            ipStr := new(string)
            *ipStr = ipB.String()
            v4Address.Ip = ipStr
            ipNetBNum, _ := ipNetB.Mask.Size()
            prfxLen := new(uint8)
            *prfxLen = uint8(ipNetBNum)
            if isState {
                v4Address.State.Ip = ipStr
                v4Address.State.PrefixLength = prfxLen
                if ipdata.Has("gwaddr") {
                    gwaddr := new(string)
                    *gwaddr = ipdata.Get("gwaddr")
                    v4Address.State.GwAddr = gwaddr
                }
                secValStr, ok := ipdata.Field["secondary"]
                secVal := new(bool)
                *secVal = false
                if ok {
                    if secValStr == "true" {
                        *secVal = true
                    }
                }
                v4Address.State.Secondary = secVal
            } else {
                v4Address.Config.Ip = ipStr
                v4Address.Config.PrefixLength = prfxLen
                if ipdata.Has("gwaddr") {
                    gwaddr := new(string)
                    *gwaddr = ipdata.Get("gwaddr")
                    v4Address.Config.GwAddr = gwaddr
                }
                secValStr, ok := ipdata.Field["secondary"]
                secVal := new(bool)
                *secVal = false
                if ok {
                    if secValStr == "true" {
                        *secVal = true
                    }
                }
                v4Address.Config.Secondary = secVal
            }
        }
        if v6Flag {
            ygot.BuildEmptyTree(v6Address)
            ipStr := new(string)
            *ipStr = ipB.String()
            v6Address.Ip = ipStr
            ipNetBNum, _ := ipNetB.Mask.Size()
            prfxLen := new(uint8)
            *prfxLen = uint8(ipNetBNum)
            if isState {
                v6Address.State.Ip = ipStr
                v6Address.State.PrefixLength = prfxLen
                if ipdata.Has("gwaddr") {
                    gwaddr := new(string)
                    *gwaddr = ipdata.Get("gwaddr")
                    v6Address.State.GwAddr = gwaddr
                }
            } else {
                v6Address.Config.Ip = ipStr
                v6Address.Config.PrefixLength = prfxLen
                if ipdata.Has("gwaddr") {
                    gwaddr := new(string)
                    *gwaddr = ipdata.Get("gwaddr")
                    v6Address.Config.GwAddr = gwaddr
                }
            }
        }
    }
    return err
}

func convertRoutedVlanIpMapToOC (intfIpMap map[string]db.Value, ifInfo *ocbinds.OpenconfigInterfaces_Interfaces_Interface, isState bool) error {
    var routedVlan *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan
    var err error

    routedVlan = ifInfo.RoutedVlan
    ygot.BuildEmptyTree(routedVlan)
    ygot.BuildEmptyTree(routedVlan.Ipv4)
    ygot.BuildEmptyTree(routedVlan.Ipv6)

    for ipKey, ipdata := range intfIpMap {
        log.Info("IP address = ", ipKey)
        ipB, ipNetB, _ := net.ParseCIDR(ipKey)
        v4Flag := false
        v6Flag := false

        var v4Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv4_Addresses_Address
        var v6Address *ocbinds.OpenconfigInterfaces_Interfaces_Interface_RoutedVlan_Ipv6_Addresses_Address
        if validIPv4(ipB.String()) {
            if _, ok := routedVlan.Ipv4.Addresses.Address[ipB.String()]; !ok {
                _, err = routedVlan.Ipv4.Addresses.NewAddress(ipB.String())
            }
            v4Address = routedVlan.Ipv4.Addresses.Address[ipB.String()]
            v4Flag = true
        } else if validIPv6(ipB.String()) {
            if _, ok := routedVlan.Ipv6.Addresses.Address[ipB.String()]; !ok {
                _, err = routedVlan.Ipv6.Addresses.NewAddress(ipB.String())
            }
            v6Address =  routedVlan.Ipv6.Addresses.Address[ipB.String()]
            v6Flag = true
        } else {
            log.Error("Invalid IP address " + ipB.String())
            continue
        }
        if err != nil {
            log.Error("Creation of address subtree failed!")
            return err
        }
        if v4Flag {
            ygot.BuildEmptyTree(v4Address)
            ipStr := new(string)
            *ipStr = ipB.String()
            v4Address.Ip = ipStr
            ipNetBNum, _ := ipNetB.Mask.Size()
            prfxLen := new(uint8)
            *prfxLen = uint8(ipNetBNum)
            if isState {
                v4Address.State.Ip = ipStr
                v4Address.State.PrefixLength = prfxLen

                secValStr, ok := ipdata.Field["secondary"]
                secVal := new(bool)
                *secVal = false
                if ok {
                    if secValStr == "true" {
                        *secVal = true
                    }
                }
                v4Address.State.Secondary = secVal
            } else {
                v4Address.Config.Ip = ipStr
                v4Address.Config.PrefixLength = prfxLen

                secValStr, ok := ipdata.Field["secondary"]
                secVal := new(bool)
                *secVal = false
                if ok {
                    if secValStr == "true" {
                        *secVal = true
                    }
                }
                v4Address.Config.Secondary = secVal
            }
        }
        if v6Flag {
            ygot.BuildEmptyTree(v6Address)
            ipStr := new(string)
            *ipStr = ipB.String()
            v6Address.Ip = ipStr
            ipNetBNum, _ := ipNetB.Mask.Size()
            prfxLen := new(uint8)
            *prfxLen = uint8(ipNetBNum)
            if isState {
                v6Address.State.Ip = ipStr
                v6Address.State.PrefixLength = prfxLen
            } else {
                v6Address.Config.Ip = ipStr
                v6Address.Config.PrefixLength = prfxLen
            }
        }
    }
    return err
}

func interfaceIPcount(tblName string, d *db.DB, intfName *string, ipCnt *int) error {
    intfIPKeys, _ := d.GetKeys(&db.TableSpec{Name:tblName})
    if len(intfIPKeys) > 0 {
        for i := range intfIPKeys {
            if *intfName == intfIPKeys[i].Get(0) {
                *ipCnt = *ipCnt+1
            }
        }
    }
    return nil
}

/* Function to delete Vxlan Interface */
func deleteVxlanIntf(inParams *XfmrParams, ifName *string) error {
    var err error
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    resMap := make(map[string]map[string]db.Value)

    log.Infof("deleteVxlanIntf: vxlanIf: %s ", *ifName)
    _, err = inParams.d.GetEntry(&db.TableSpec{Name:"VXLAN_TUNNEL"}, db.Key{Comp: []string{*ifName}})
    if err != nil {
        log.Infof("deleteVxlanIntf: vxlanIf: %s not found ", *ifName)
    	return tlerr.NotFound("Resource Not Found")
    }

    _, err = inParams.d.GetEntry(&db.TableSpec{Name:"EVPN_NVO"}, db.Key{Comp: []string{"nvo1"}})
    if err == nil {
        log.Infof("deleteVxlanIntf: vxlanIf: %s EVPN_NVO Table found ", *ifName)
	    evpnNvoMap := make(map[string]db.Value)
	    evpnDbV := db.Value{Field:map[string]string{}}
	    //evpnDbV.Field["source_vtep"] = *ifName
	    evpnNvoMap["nvo1"] = evpnDbV
	    resMap["EVPN_NVO"] = evpnNvoMap
    }

    vxlanIntfMap := make(map[string]db.Value)
    vxlanIntfMap[*ifName] = db.Value{Field:map[string]string{}}
    resMap["VXLAN_TUNNEL"] = vxlanIntfMap

    subOpMap[db.ConfigDB] = resMap
    inParams.subOpDataMap[DELETE] = &subOpMap
    return nil
}

/* Function to delete Loopback Interface */
func deleteLoopbackIntf(inParams *XfmrParams, loName *string) error {
    var err error
    intTbl := IntfTypeTblMap[IntfTypeLoopback]
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    resMap := make(map[string]map[string]db.Value)
    loMap := make(map[string]db.Value)
    loIntfMap := make(map[string]db.Value)

    loMap[*loName] = db.Value{Field:map[string]string{}}

    IntfMapObj, err := inParams.d.GetMapAll(&db.TableSpec{Name:intTbl.cfgDb.portTN + "|" + *loName})

    if err != nil || !IntfMapObj.IsPopulated() {
        errStr := "Retrieving data from LOOPBACK table for Loopback: " + *loName + " failed!"
        log.Errorf(errStr)
        // Not returning error from here since mgmt infra will return "Resource not found" error in case of non existence entries
        return nil
    }
    /* Validate L3 config only if operation is not delete */
    if inParams.oper != DELETE {
        err = validateL3ConfigExists(inParams.d, loName)
        if err != nil {
            return err
        }
    }

    /* Handle LOOPBACK_INTERFACE TABLE */
    processIntfTableRemoval(inParams.d, *loName, LOOPBACK_INTERFACE_TN, loIntfMap)
    if len(loIntfMap) != 0 {
        resMap[LOOPBACK_INTERFACE_TN] = loIntfMap
    }

    resMap[intTbl.cfgDb.portTN] = loMap

    subOpMap[db.ConfigDB] = resMap
    inParams.subOpDataMap[DELETE] = &subOpMap
    return nil
}

func getIntfIpByName(dbCl *db.DB, tblName string, ifName string, ipv4 bool, ipv6 bool, ip string) (map[string]db.Value, error) {
    var err error
    intfIpMap := make(map[string]db.Value)
    all := true
    if !ipv4 || !ipv6 {
        all = false
    }
    log.V(3).Info("Updating Interface IP Info from DB to Internal DS for Interface Name : ", ifName)

    keys, err := doGetIntfIpKeys(dbCl, tblName , ifName)
    if log.V(3) {
	log.Infof("Found %d keys for (%v)(%v)", len(keys), tblName, ifName)
    }
    if( err != nil) {
        return intfIpMap, err
    }
    for _, key := range keys {
        if len(key.Comp) < 2 {
            continue
        }
        if key.Get(0) != ifName {
            continue
        }
        if len(key.Comp) > 2 {
            for i := range key.Comp {
                if i == 0 || i == 1 {
                    continue
                }
                key.Comp[1] = key.Comp[1] + ":" + key.Comp[i]
            }
        }
        if !all {
            ipB, _, _ := net.ParseCIDR(key.Get(1))
            if ((validIPv4(ipB.String()) && (!ipv4)) ||
                (validIPv6(ipB.String()) && (!ipv6))) {
                continue
            }
            if ip != "" {
                if ipB.String() != ip {
                    continue
                }
            }
        }

        ipInfo, _ := dbCl.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{key.Get(0), key.Get(1)}})
        intfIpMap[key.Get(1)]= ipInfo
    }
    return intfIpMap, err
}

func handleIntfIPGetByTargetURI (inParams XfmrParams, targetUriPath string, ifName string, intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface) error {
    var ipMap map[string]db.Value
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    ipAddr := pathInfo.Var("ip")
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_subintf_ip_xfmr : " + errStr)
        return errors.New(errStr)
    }
    intTbl := IntfTypeTblMap[intfType]

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/config") ||
       strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/config") {
           ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, true, false, ipAddr)
           log.Info("handleIntfIPGetByTargetURI : ipv4 config ipMap - : ", ipMap)
           convertIpMapToOC(ipMap, intfObj, false)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/config") {
           ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, false, true, ipAddr)
           log.Info("handleIntfIPGetByTargetURI : ipv6 config ipMap - : ", ipMap)
           convertIpMapToOC(ipMap, intfObj, false)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses/address/state") ||
         strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses/address/state") {
           ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, true, false, ipAddr)
           log.Info("handleIntfIPGetByTargetURI : ipv4 state ipMap - : ", ipMap)
           convertIpMapToOC(ipMap, intfObj, true)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses/address/state") ||
         strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses/address/state") {
           ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, false, true, ipAddr)
           log.Info("handleIntfIPGetByTargetURI : ipv6 state ipMap - : ", ipMap)
           convertIpMapToOC(ipMap, intfObj, true)
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/addresses") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/addresses") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, true, false, ipAddr)
        if err == nil {
           log.Info("handleIntfIPGetByTargetURI : ipv4 config ipMap - : ", ipMap)
            convertIpMapToOC(ipMap, intfObj, false)
        }
        ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, true, false, ipAddr)
        if err == nil {
            log.Info("handleIntfIPGetByTargetURI : ipv4 state ipMap - : ", ipMap)
            convertIpMapToOC(ipMap, intfObj, true)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv6/addresses") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv6/addresses") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, false, true, ipAddr)
        if err == nil {
            log.Info("handleIntfIPGetByTargetURI : ipv6 config ipMap - : ", ipMap)
            convertIpMapToOC(ipMap, intfObj, false)
        }
        ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, false, true, ipAddr)
        if err == nil {
            log.Info("handleIntfIPGetByTargetURI : ipv6 state ipMap - : ", ipMap)
            convertIpMapToOC(ipMap, intfObj, true)
        }
    }
    return err
}

func handleVlanIntfIPGetByTargetURI (inParams XfmrParams, targetUriPath string, ifName string, intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface) error {
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    ipAddr := pathInfo.Var("ip")
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("handleVlanIntfIPGetByTargetURI: " + errStr)
        return errors.New(errStr)
    }
    intTbl := IntfTypeTblMap[intfType]

    var ipMap map[string]db.Value

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/config") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, true, false, ipAddr)
        if err == nil {
            log.Info("handleVlanIntfIPGetByTargetURI: ipv4 config ipMap - : ", ipMap)
            convertRoutedVlanIpMapToOC(ipMap, intfObj, false)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/config") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/config") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, false, true, ipAddr)
        if err == nil {
            log.Info("handleVlanIntfIPGetByTargetURI: ipv6 config ipMap - : ", ipMap)
            convertRoutedVlanIpMapToOC(ipMap, intfObj, false)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses/address/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses/address/state") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, true, false, ipAddr)
        if err == nil {
            log.Info("handleVlanIntfIPGetByTargetURI: ipv4 state ipMap - : ", ipMap)
            convertRoutedVlanIpMapToOC(ipMap, intfObj, true)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses/address/state") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses/address/state") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, false, true, ipAddr)
        if err == nil {
            log.Info("handleVlanIntfIPGetByTargetURI: ipv6 state ipMap - : ", ipMap)
            convertRoutedVlanIpMapToOC(ipMap, intfObj, true)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv4/addresses") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv4/addresses") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, true, false, ipAddr)
        if err == nil {
            log.Info("handleVlanIntfIPGetByTargetURI: ipv4 config ipMap - : ", ipMap)
             convertRoutedVlanIpMapToOC(ipMap, intfObj, false)
        }
        ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, true, false, ipAddr)
        if err == nil {
            log.Info("handleVlanIntfIPGetByTargetURI: ipv4 state ipMap - : ", ipMap)
            convertRoutedVlanIpMapToOC(ipMap, intfObj, true)
        }
    } else if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan/openconfig-if-ip:ipv6/addresses") ||
        strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan/ipv6/addresses") {
        ipMap, err = getIntfIpByName(inParams.dbs[db.ConfigDB], intTbl.cfgDb.intfTN, ifName, false, true, ipAddr)
        if err == nil {
           log.Info("handleVlanIntfIPGetByTargetURI: ipv6 config ipMap - : ", ipMap)
            convertRoutedVlanIpMapToOC(ipMap, intfObj, false)
        }
        ipMap, err = getIntfIpByName(inParams.dbs[db.ApplDB], intTbl.appDb.intfTN, ifName, false, true, ipAddr)
        if err == nil {
            log.Info("handleVlanIntfIPGetByTargetURI: ipv6 state ipMap - : ", ipMap)
            convertRoutedVlanIpMapToOC(ipMap, intfObj, true)
        }
    }
    return err
}

var DbToYang_intf_ip_addr_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    if err != nil {
        return err
    }
    log.Info("DbToYang_intf_ip_addr_xfmr: targetUriPath is ", targetUriPath)

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("DbToYang_intf_ip_addr_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    intfType, _, _ := getIntfTypeByName(ifName)
    if IntfTypeVlan == intfType {
	    return nil
    }

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces") {
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
                intfObj, _ = intfsObj.NewInterface(uriIfName)
            }
            ygot.BuildEmptyTree(intfObj)
            if intfObj.Subinterfaces == nil {
                ygot.BuildEmptyTree(intfObj.Subinterfaces)
            }
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(uriIfName)
            ygot.BuildEmptyTree(intfObj)
        }

        err = handleIntfIPGetByTargetURI(inParams, targetUriPath, ifName, intfObj)

    } else {
        err = errors.New("Invalid URI : " + targetUriPath)
    }

    return err
}

var DbToYang_routed_vlan_ip_addr_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("name")
    targetUriPath, err := getYangPathFromUri(inParams.uri)
    if err != nil {
        return err
    }
    log.Info("DbToYang_routed_vlan_ip_addr_xfmr: targetUriPath is ", targetUriPath)
    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-vlan:routed-vlan") ||
       strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/routed-vlan") {
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[intfName]; !ok {
                intfObj, _ = intfsObj.NewInterface(intfName)
            }
            ygot.BuildEmptyTree(intfObj)
            if intfObj.Subinterfaces == nil {
                ygot.BuildEmptyTree(intfObj.RoutedVlan)
            }
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(intfName)
            ygot.BuildEmptyTree(intfObj)
        }

        err = handleVlanIntfIPGetByTargetURI(inParams, targetUriPath, intfName, intfObj)

    } else {
        err = errors.New("Invalid URI : " + targetUriPath)
    }

    return err
}

func validIPv4(ipAddress string) bool {
    /* Dont allow ip addresses that start with "0." or "255."*/
    if (strings.HasPrefix(ipAddress, "0.") || strings.HasPrefix(ipAddress, "255.")) {
        log.Info("validIP: IP is reserved ", ipAddress)
        return false
    }

    ip := net.ParseIP(ipAddress)
    ipAddress = strings.Trim(ipAddress, " ")

    re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
    if re.MatchString(ipAddress) {
        return validIP(ip)
    }
    return false
}

func validIPv6(ipAddress string) bool {
    ip := net.ParseIP(ipAddress)
    ipAddress = strings.Trim(ipAddress, " ")

    re, _ := regexp.Compile(`(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`)
    if re.MatchString(ipAddress) {
        return validIP(ip)
    }
    return false
}

func validIP(ip net.IP) bool {
    if (ip.IsUnspecified() ||  ip.IsLoopback() ||  ip.IsMulticast()) {
        return false
    }
    return true
}

/* Get all IP keys for given interface */
func doGetIntfIpKeys(d *db.DB, tblName string, intfName string) ([]db.Key, error) {
    ts := db.TableSpec{Name: tblName + d.Opts.KeySeparator + intfName}
    ipKeys, err := d.GetKeys(&ts)
    log.Infof("doGetIntfIpKeys for %s with %v - %v", intfName, ts, ipKeys)
    return ipKeys, err
}

func getMemTableNameByDBId (intftbl IntfTblData, curDb db.DBNum) (string, error) {

    var tblName string

    switch (curDb) {
    case db.ConfigDB:
        tblName = intftbl.cfgDb.memberTN
    case db.ApplDB:
        tblName = intftbl.appDb.memberTN
    case db.StateDB:
        tblName = intftbl.stateDb.memberTN
    default:
        tblName = intftbl.cfgDb.memberTN
    }

    return tblName, nil
}

func getIntfTableNameByDBId (intftbl IntfTblData, curDb db.DBNum) (string, error) {

    var tblName string

    switch (curDb) {
    case db.ConfigDB:
        tblName = intftbl.cfgDb.intfTN
    case db.ApplDB:
        tblName = intftbl.appDb.intfTN
    case db.StateDB:
        tblName = intftbl.stateDb.intfTN
    default:
        tblName = intftbl.cfgDb.intfTN
    }

    return tblName, nil
}

func processIntfTableRemoval(d *db.DB, ifName string, tblName string, intfMap map[string]db.Value) {
    intfKey, _ := d.GetKeysByPattern(&db.TableSpec{Name: tblName}, "*"+ifName)
    if len(intfKey) != 0 {
        key := ifName
        intfMap[key] = db.Value{Field:map[string]string{}}
    }
}

func getIntfCountersTblKey (d *db.DB, ifKey string) (string, error) {
    var oid string

    portOidCountrTblTs := &db.TableSpec{Name: "COUNTERS_PORT_NAME_MAP"}
    ifCountInfo, err := d.GetMapAll(portOidCountrTblTs)
    if err != nil {
        log.Error("Port-OID (Counters) get for all the interfaces failed!")
        return oid, err
    }

    if ifCountInfo.IsPopulated() {
        _, ok := ifCountInfo.Field[ifKey]
        if !ok {
            err = errors.New("OID info not found from Counters DB for interface " + ifKey)
        } else {
            oid = ifCountInfo.Field[ifKey]
        }
    } else {
        err = errors.New("Get for OID info from all the interfaces from Counters DB failed!")
    }

    return oid, err
}

func getSpecificCounterAttr(targetUriPath string, entry *db.Value, entry_backup *db.Value, counter interface{}) (bool, error) {

    var e error
    var counter_val *ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_Counters
    var eth_counter_val *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Ethernet_State_Counters

    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/state/counters") {
        counter_val = counter.(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_Counters)
    } else {
        eth_counter_val = counter.(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_Ethernet_State_Counters)
    }

    switch targetUriPath {
    case "/openconfig-interfaces:interfaces/interface/state/counters/in-octets":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_OCTETS", &counter_val.InOctets)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-unicast-pkts":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_UCAST_PKTS", &counter_val.InUnicastPkts)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-broadcast-pkts":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS", &counter_val.InBroadcastPkts)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-multicast-pkts":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_MULTICAST_PKTS", &counter_val.InMulticastPkts)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-errors":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_ERRORS", &counter_val.InErrors)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-discards":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_DISCARDS", &counter_val.InDiscards)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-pkts":
        var inNonUCastPkt, inUCastPkt *uint64
        var in_pkts uint64

        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS", &inNonUCastPkt)
        if e == nil {
            e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_IN_UCAST_PKTS", &inUCastPkt)
            if e != nil {
                return true, e
            }
            in_pkts = *inUCastPkt + *inNonUCastPkt
            counter_val.InPkts = &in_pkts
            return true, e
        } else {
            return true, e
        }

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-octets-per-second":
        value, e := getIntfCounterValue(entry, "PORT_STAT_IF_IN_OCTETS_PER_SECOND")
        if e == nil {
            counter_val.InOctetsPerSecond = &value
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-pkts-per-second":
        value, e := getIntfCounterValue(entry, "PORT_STAT_IF_IN_PKTS_PER_SECOND")
        if e == nil {
            counter_val.InPktsPerSecond = &value
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-bits-per-second":
        value, e := getIntfCounterValue(entry, "PORT_STAT_IF_IN_BITS_PER_SECOND")
        if e == nil {
            counter_val.InBitsPerSecond = &value
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/in-utilization":
        value, e := getIntfCounterValue(entry, "PORT_STAT_IF_IN_UTILIZATION")
        if e == nil {
            tmp := uint8(value)
            counter_val.InUtilization = &tmp
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-octets-per-second":
        value, e := getIntfCounterValue(entry, "PORT_STAT_IF_OUT_OCTETS_PER_SECOND")
        if e == nil {
            counter_val.OutOctetsPerSecond = &value
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-pkts-per-second":
        value, e := getIntfCounterValue(entry, "PORT_STAT_IF_OUT_PKTS_PER_SECOND")
        if e == nil {
            counter_val.OutPktsPerSecond = &value
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-bits-per-second":
        value, e := getIntfCounterValue(entry, "PORT_STAT_IF_OUT_BITS_PER_SECOND")
        if e == nil {
            counter_val.OutBitsPerSecond = &value
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-utilization":
        value, e := getIntfCounterValue(entry, "SAI_PORT_STAT_IF_OUT_UTILIZATION")
        if e == nil {
            tmp := uint8(value)
            counter_val.OutUtilization = &tmp
        }
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-octets":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_OCTETS", &counter_val.OutOctets)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-unicast-pkts":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_UCAST_PKTS", &counter_val.OutUnicastPkts)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-broadcast-pkts":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS", &counter_val.OutBroadcastPkts)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-multicast-pkts":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS", &counter_val.OutMulticastPkts)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-errors":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_ERRORS", &counter_val.OutErrors)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-discards":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_DISCARDS", &counter_val.OutDiscards)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/last-clear":
        timestampStr := (entry_backup.Field["LAST_CLEAR_TIMESTAMP"])
        timestamp, _ := strconv.ParseUint(timestampStr, 10, 64)
        counter_val.LastClear = &timestamp
        return true, e

    case "/openconfig-interfaces:interfaces/interface/state/counters/out-pkts":
        var outNonUCastPkt, outUCastPkt *uint64
        var out_pkts uint64

        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS", &outNonUCastPkt)
        if e == nil {
            e = getCounters(entry, entry_backup, "SAI_PORT_STAT_IF_OUT_UCAST_PKTS", &outUCastPkt)
            if e != nil {
                return true, e
            }
            out_pkts = *outUCastPkt + *outNonUCastPkt
            counter_val.OutPkts = &out_pkts
            return true, e
        } else {
            return true, e
        }

    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/in-oversize-frames",
    "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/in-oversize-frames":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_RX_OVERSIZE_PKTS", &eth_counter_val.InOversizeFrames)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/in-undersize-frames",
    "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/in-undersize-frames":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_STATS_UNDERSIZE_PKTS", &eth_counter_val.InUndersizeFrames)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/in-jabber-frames",
    "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/in-jabber-frames":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_STATS_JABBERS", &eth_counter_val.InJabberFrames)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/in-fragment-frames",
    "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/in-fragment-frames":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_STATS_FRAGMENTS", &eth_counter_val.InFragmentFrames)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/out-oversize-frames",
    "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/out-oversize-frames":
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS", &eth_counter_val.OutOversizeFrames)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-64-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS", &eth_counter_val.EthInDistribution.InFrames_64Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-65-127-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS", &eth_counter_val.EthInDistribution.InFrames_65_127Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/in-distribution/in-frames-128-255-octets",
    "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/openconfig-if-ethernet-ext:in-distribution/in-frames-128-255-octets",
    "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext:in-distribution/in-frames-128-255-octets",
    "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-128-255-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS", &eth_counter_val.EthInDistribution.InFrames_128_255Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-256-511-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS", &eth_counter_val.EthInDistribution.InFrames_256_511Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-512-1023-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS", &eth_counter_val.EthInDistribution.InFrames_512_1023Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-1024-1518-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_1024_TO_1518_OCTETS", &eth_counter_val.EthInDistribution.InFrames_1024_1518Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-1519-2047-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_1519_TO_2047_OCTETS", &eth_counter_val.EthInDistribution.InFrames_1519_2047Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-2048-4095-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_2048_TO_4095_OCTETS", &eth_counter_val.EthInDistribution.InFrames_2048_4095Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-4096-9216-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_4096_TO_9216_OCTETS", &eth_counter_val.EthInDistribution.InFrames_4096_9216Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution/in-frames-9217-16383-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_IN_PKTS_9217_TO_16383_OCTETS", &eth_counter_val.EthInDistribution.InFrames_9217_16383Octets)
        return true, e

    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-64-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_64_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_64Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-65-127-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_65_TO_127_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_65_127Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-128-255-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_128_TO_255_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_128_255Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-256-511-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_256_TO_511_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_256_511Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-512-1023-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_512_TO_1023_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_512_1023Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-1024-1518-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_1024_1518Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-1519-2047-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_1519_TO_2047_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_1519_2047Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-2048-4095-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_2048_TO_4095_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_2048_4095Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-4096-9216-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_4096_TO_9216_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_4096_9216Octets)
        return true, e
    case "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:out-distribution/out-frames-9217-16383-octets":
        ygot.BuildEmptyTree(eth_counter_val)
        e = getCounters(entry, entry_backup, "SAI_PORT_STAT_ETHER_OUT_PKTS_9217_TO_16383_OCTETS", &eth_counter_val.EthOutDistribution.OutFrames_9217_16383Octets)
        return true, e
    default:
        log.Infof(targetUriPath + " - Not an interface state counter attribute")
    }
    return false, nil
}

func getIntfCounterValue(entry *db.Value, attr string) (float64, error) {
    var err error
    var value float64
    val, ok := entry.Field[attr]
    if !ok {
        return value, errors.New("Attr " + attr + " doesn't exist in counters entry Map!")
    }
    value, err = strconv.ParseFloat(val, 64)
    if err != nil {
        log.Infof("Attr " + attr + " parse failed: " + err.Error())
    }
    return value, err
}

func getCounters(entry *db.Value, entry_backup *db.Value, attr string, counter_val **uint64 ) error {

    var ok bool = false
    var err error
    val1, ok := entry.Field[attr]
    if !ok {
        return errors.New("Attr " + attr + "doesn't exist in IF table Map!")
    }
    val2, ok := entry_backup.Field[attr]
    if !ok {
        return errors.New("Attr " + attr + "doesn't exist in IF backup table Map!")
    }

    if len(val1) > 0 {
        v, _ := strconv.ParseUint(val1, 10, 64)
        v_backup, _ := strconv.ParseUint(val2, 10, 64)
        val := v-v_backup
        *counter_val = &val
        return nil
    }
    return err
}

var portCntList [] string = []string {"in-octets", "in-unicast-pkts", "in-broadcast-pkts", "in-multicast-pkts",
"in-errors", "in-discards", "in-pkts", "out-octets", "out-unicast-pkts",
"out-broadcast-pkts", "out-multicast-pkts", "out-errors", "out-discards",
"out-pkts", "in-octets-per-second", "in-pkts-per-second", "in-bits-per-second", "in-utilization",
"out-octets-per-second", "out-pkts-per-second", "out-bits-per-second", "out-utilization", "last-clear"}

var etherCntList [] string = [] string {"in-oversize-frames", "out-oversize-frames", "in-undersize-frames", "in-jabber-frames",
                        "in-fragment-frames", "openconfig-if-ethernet-ext:in-distribution/in-frames-128-255-octets"}
var etherCntOutList [] string = [] string {"out-frames-64-octets", "out-frames-65-127-octets", "out-frames-128-255-octets",
                        "out-frames-256-511-octets", "out-frames-512-1023-octets", "out-frames-1024-1518-octets", "out-frames-1519-2047-octets",
                        "out-frames-2048-4095-octets", "out-frames-4096-9216-octets", "out-frames-9217-16383-octets"}
var etherCntInList [] string = [] string {"in-frames-64-octets", "in-frames-65-127-octets", "in-frames-128-255-octets",
                        "in-frames-256-511-octets", "in-frames-512-1023-octets", "in-frames-1024-1518-octets", "in-frames-1519-2047-octets",
                        "in-frames-2048-4095-octets", "in-frames-4096-9216-octets", "in-frames-9217-16383-octets"}

var populatePortCounters PopulateIntfCounters = func (inParams XfmrParams, counter interface{}) (error) {
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")

    sonicIfName := utils.GetNativeNameFromUIName(&ifName)
    log.Infof("Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)

    if log.V(3) {
        log.Info("PopulateIntfCounters : inParams.curDb : ", inParams.curDb, "D: ", inParams.d, "DB index : ", inParams.dbs[inParams.curDb])
    }
    oid, oiderr := getIntfCountersTblKey(inParams.dbs[inParams.curDb], ifName)
    if oiderr != nil {
        log.Info(oiderr)
        return oiderr
    }
    cntTs := &db.TableSpec{Name: "COUNTERS"}
    entry, dbErr := inParams.dbs[inParams.curDb].GetEntry(cntTs, db.Key{Comp: []string{oid}})
    if dbErr != nil {
        log.Info("PopulateIntfCounters : not able find the oid entry in DB Counters table")
        return dbErr
    }
    CounterData := entry
    cntTs_cp := &db.TableSpec { Name: "COUNTERS_BACKUP" }
    entry_backup, dbErr := inParams.dbs[inParams.curDb].GetEntry(cntTs_cp, db.Key{Comp: []string{oid}})
    if dbErr != nil {
        m := make(map[string]string)
        log.Info("PopulateIntfCounters : not able find the oid entry in DB COUNTERS_BACKUP table")
        /* Frame backup data with 0 as counter values */
        for  attr := range entry.Field {
            m[attr] = "0"
        }
        m["LAST_CLEAR_TIMESTAMP"] = "0"
        entry_backup = db.Value{Field: m}
    }
    CounterBackUpData := entry_backup

    switch (targetUriPath) {
    case "/openconfig-interfaces:interfaces/interface/state/counters":
        for _, attr := range portCntList {
            uri := targetUriPath + "/" + attr
            if ok, err := getSpecificCounterAttr(uri, &CounterData, &CounterBackUpData, counter); !ok || err != nil {
                log.Info("Get Counter URI failed :", uri)
                //err = errors.New("Get Counter URI failed")
            }
        }
    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters",
         "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters":
        for _, attr := range etherCntList {
            uri := targetUriPath + "/" + attr
            if ok, err := getSpecificCounterAttr(uri, &CounterData, &CounterBackUpData, counter); !ok || err != nil {
                log.Info("Get Ethernet Counter URI failed :", uri)
                //err = errors.New("Get Ethernet Counter URI failed")
            }
        }
        for _, attr := range etherCntOutList {
            uri := targetUriPath + "/openconfig-if-ethernet-ext2:out-distribution/" + attr
            if ok, err := getSpecificCounterAttr(uri, &CounterData, &CounterBackUpData, counter); !ok || err != nil {
                log.Info("Get Ethernet Counter URI failed :", uri)
            }
        }
        targetUriPath = "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext2:in-distribution"
        fallthrough
    case "/openconfig-interfaces:interfaces/interface/ethernet/state/counters/in-distribution",
         "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters/openconfig-if-ethernet-ext:in-distribution":
        for _, attr := range etherCntInList {
            uri := targetUriPath + "/" + attr
            if ok, err := getSpecificCounterAttr(uri, &CounterData, &CounterBackUpData, counter); !ok || err != nil {
                log.Info("Get Ethernet Counter URI failed :", uri)
            }
        }

    default:
        _, err = getSpecificCounterAttr(targetUriPath, &CounterData, &CounterBackUpData, counter)
    }

    return err
}

var mgmtCounterIndexMap = map[string]int {
    "in-octets"            : 1,
    "in-pkts"              : 2,
    "in-errors"            : 3,
    "in-discards"          : 4,
    "in-multicast-pkts"    : 8,
    "out-octets"           : 9,
    "out-pkts"             : 10,
    "out-errors"           : 11,
    "out-discards"         : 12,
}

func getMgmtCounters(val string, counter_val **uint64 ) error {

    var err error
    if len(val) > 0 {
        v, e := strconv.ParseUint(val, 10, 64)
        if err == nil {
            *counter_val = &v
            return nil
        }
        err = e
    }
    return err
}
func getMgmtSpecificCounterAttr (uri string, cnt_data []string, counter *ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_Counters) (error) {

    var e error
    switch (uri) {
    case "/openconfig-interfaces:interfaces/interface/state/counters/in-octets":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["in-octets"]], &counter.InOctets)
        return e
    case "/openconfig-interfaces:interfaces/interface/state/counters/in-pkts":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["in-pkts"]], &counter.InPkts)
        return  e
    case "/openconfig-interfaces:interfaces/interface/state/counters/in-errors":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["in-errors"]], &counter.InErrors)
        return  e
    case "/openconfig-interfaces:interfaces/interface/state/counters/in-discards":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["in-discards"]], &counter.InDiscards)
        return e
    case "/openconfig-interfaces:interfaces/interface/state/counters/in-multicast-pkts":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["in-multicast-pkts"]], &counter.InMulticastPkts)
        return e
    case "/openconfig-interfaces:interfaces/interface/state/counters/out-octets":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["out-octets"]], &counter.OutOctets)
        return e
    case "/openconfig-interfaces:interfaces/interface/state/counters/out-pkts":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["out-pkts"]], &counter.OutPkts)
        return e
    case "/openconfig-interfaces:interfaces/interface/state/counters/out-errors":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["out-errors"]], &counter.OutErrors)
        return e
    case "/openconfig-interfaces:interfaces/interface/state/counters/out-discards":
        e = getMgmtCounters(cnt_data[mgmtCounterIndexMap["out-discards"]], &counter.OutDiscards)
        return e
    case "/openconfig-interfaces:interfaces/interface/state/counters":
        for key := range mgmtCounterIndexMap {
            xuri := uri + "/" + key
            getMgmtSpecificCounterAttr(xuri, cnt_data, counter)
        }
        return nil
    }

    log.Info("getMgmtSpecificCounterAttr - Invalid counters URI : ", uri)
    return errors.New("Invalid counters URI")

}

var populateMGMTPortCounters PopulateIntfCounters = func (inParams XfmrParams, counter interface{}) (error) {
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("name")
    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    if err != nil {
        return err
    }

    fileName := "/proc/net/dev"
    file, err := os.Open(fileName)
    if err != nil {
        log.Info("failed opening file: %s", err)
        return err
    }

    counter_val := counter.(*ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_Counters)

    scanner := bufio.NewScanner(file)
    scanner.Split(bufio.ScanLines)
    var txtlines []string
    for scanner.Scan() {
        txtlines = append(txtlines, scanner.Text())
    }
    file.Close()
    var entry string
    for _, eachline := range txtlines {
        ln := strings.TrimSpace(eachline)
        if strings.HasPrefix(ln, intfName) {
            entry = ln
            log.Info(" Interface stats : ", entry)
            break
        }
    }

    if entry  == "" {
        log.Info("Counters not found for Interface " + intfName)
        return errors.New("Counters not found for Interface " + intfName)
    }

    stats := strings.Fields(entry)
    log.Info(" Interface filds: ", stats)

    ret := getMgmtSpecificCounterAttr(targetUriPath, stats, counter_val)
    log.Info(" getMgmtCounters : ", *counter_val)
    return ret
}

var YangToDb_intf_counters_key KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var entry_key string
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    intfName := pathInfo.Var("name")
    oid, oiderr := getIntfCountersTblKey(inParams.dbs[inParams.curDb], intfName)

    if oiderr == nil {
        entry_key = oid
    }
    return entry_key, err
}

var DbToYang_intf_counters_key KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error
    return rmap, err
}

var DbToYang_intf_get_ether_counters_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName
    log.Info("Ether counters subtree and ifname: ", ifName)
    sonicIfName := utils.GetNativeNameFromUIName(&ifName)

    log.Infof("DbToYang_intf_get_ether_counters_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_get_ether_counters_xfmr - Invalid interface type IntfTypeUnset");
        return errors.New("Invalid interface type IntfTypeUnset");
    }
    if intfType == IntfTypeMgmt {
        log.Info("DbToYang_intf_get_ether_counters_xfmr - Ether Stats not supported.")
        return errors.New("Ethernet counters not supported.")
    }

    if !strings.Contains(targetUriPath, "/openconfig-interfaces:interfaces/interface/ethernet/state/counters") &&
        !strings.Contains(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/state/counters") {
        log.Info("%s is redundant", targetUriPath)
        return err
    }

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    var eth_counters *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Ethernet_State_Counters

    if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
        var ok bool = false
        if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
            intfObj, _ = intfsObj.NewInterface(uriIfName)
        }
        ygot.BuildEmptyTree(intfObj)
    } else {
        ygot.BuildEmptyTree(intfsObj)
        intfObj, _ = intfsObj.NewInterface(uriIfName)
        ygot.BuildEmptyTree(intfObj)
    }

    ygot.BuildEmptyTree(intfObj.Ethernet)
    ygot.BuildEmptyTree(intfObj.Ethernet.State)
    ygot.BuildEmptyTree(intfObj.Ethernet.State.Counters)
    eth_counters = intfObj.Ethernet.State.Counters

    return populatePortCounters(inParams, eth_counters)
}

var DbToYang_intf_get_counters_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    sonicIfName := utils.GetNativeNameFromUIName(&ifName)
    if log.V(3) {
        log.Infof("DbToYang_intf_get_counters_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    }
    ifName = *sonicIfName

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath is ", targetUriPath)

    if  (!strings.Contains(targetUriPath, "/openconfig-interfaces:interfaces/interface/state/counters")) {
        log.Info("%s is redundant", targetUriPath)
        return err
    }

    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        log.Info("DbToYang_intf_get_counters_xfmr - Invalid interface type IntfTypeUnset");
        return errors.New("Invalid interface type IntfTypeUnset");
    }
    intTbl := IntfTypeTblMap[intfType]
    if intTbl.CountersHdl.PopulateCounters == nil {
         log.Infof("Counters for Interface: %s not supported!", ifName)
         return nil
    }
    var state_counters * ocbinds.OpenconfigInterfaces_Interfaces_Interface_State_Counters

    if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
        var ok bool = false
        var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
        if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
            intfObj, _ = intfsObj.NewInterface(uriIfName)
            ygot.BuildEmptyTree(intfObj)
        }
        ygot.BuildEmptyTree(intfObj)
        if intfObj.State == nil  ||  intfObj.State.Counters == nil {
            ygot.BuildEmptyTree(intfObj.State)
        }
        state_counters = intfObj.State.Counters
    } else {
        ygot.BuildEmptyTree(intfsObj)
        intfObj, _:= intfsObj.NewInterface(uriIfName)
        ygot.BuildEmptyTree(intfObj)
        state_counters = intfObj.State.Counters
    }

    err = intTbl.CountersHdl.PopulateCounters(inParams, state_counters)
    if log.V(3) {
        log.Info("DbToYang_intf_get_counters_xfmr - ", state_counters)
    }

    return err
}

func retrievePortChannelAssociatedWithIntf(inParams *XfmrParams, ifName *string) (*string, error) {
    var err error

    if strings.HasPrefix(*ifName, ETHERNET) {
        intTbl := IntfTypeTblMap[IntfTypePortChannel]
        tblName, _ := getMemTableNameByDBId(intTbl, inParams.curDb)
        var lagStr string

        lagKeys, err := inParams.d.GetKeys(&db.TableSpec{Name:tblName})
        /* Find the port-channel the given ifname is part of */
        if err != nil {
            return nil, err
        }
        var flag bool = false
        for i := range lagKeys {
            if *ifName == lagKeys[i].Get(1) {
                flag = true
                lagStr = lagKeys[i].Get(0)
                log.Info("Given interface part of PortChannel", lagStr)
                break
            }
        }
        if !flag {
            log.Info("Given Interface not part of any PortChannel")
            return nil, err
        }
        return &lagStr, err
    }
    return nil, err
}

/* Get default speed from valid speeds.  Max valid speed should be the default speed.*/
func validateSpeed(d *db.DB, ifName string, speed string) error {

    intfType, _, err := getIntfTypeByName(ifName)
    if err != nil {
        errStr := "Invalid Interface"
        err = tlerr.InvalidArgsError{Format: errStr}
        return err
    }

    /* No validation possible for MGMT interface */
    if IntfTypeMgmt == intfType {
        log.Info("Management port ",ifName, " skipped speed validation.")
        return nil
    }

    portEntry, err := d.GetEntry(&db.TableSpec{Name: "PORT"}, db.Key{Comp: []string{ifName}})
    if(err != nil) {
        log.Info("Could not retrieve PORT|",ifName)
    } else {
        err = tlerr.InvalidArgs("Unsupported speed")
        speeds := strings.Split(portEntry.Field["valid_speeds"], ",");
        /*  Allow speed change for port-group member ports only when there more than 1 valid speeds.
            This is to make sure than port-group speed change error is thrown in other cases. */
        if (len(speeds) < 2) && isPortGroupMember(ifName) {
            err = tlerr.InvalidArgs("Port group member. Please use port group command to change the speed")
            return err
        }
        if len(portEntry.Field["valid_speeds"]) < 1 {
            speeds,_ = getValidSpeeds(ifName)
            log.Info("Speed from platform.json ", speeds)
        }
        log.Info("Valid speeds for ",ifName, " is ", speeds, " SET ", speed)
        for _, vspeed := range speeds {
            if  speed == strings.TrimSpace(vspeed) {
                if speed == portEntry.Field["speed"] {
                    err = tlerr.InvalidArgs("No change in the speed")
                } else {
                    err = nil
                    log.Info(vspeed, " is valid.")
                }
                break
            }
        }
    }
    return err
}


/* Get default speed from valid speeds.  Max valid speed should be the default speed.*/
func getDefaultSpeed(d *db.DB, ifName string) int {

    var defaultSpeed int
    defaultSpeed = 0
    portEntry, err := d.GetEntry(&db.TableSpec{Name: "PORT"}, db.Key{Comp: []string{ifName}})
    if(err != nil) {
        log.Info("Could not retrieve PORT|",ifName)
    } else {
        speeds := strings.Split(portEntry.Field["valid_speeds"], ",");
        if len(portEntry.Field["valid_speeds"]) < 1 {
            speeds,_ = getValidSpeeds(ifName)
        }
        for _, speed := range speeds {
            log.Info("Speed check ", defaultSpeed, " vs ", speed)
            speed_i,_ := strconv.Atoi(speed)
            if  speed_i > defaultSpeed {
                log.Info("Updating  ", defaultSpeed, " with ", speed)
                defaultSpeed = speed_i
            }
        }
    }
    return defaultSpeed
}


// YangToDb_intf_eth_port_config_xfmr handles port-speed, fec, unreliable-los, auto-neg and aggregate-id config.
var YangToDb_intf_eth_port_config_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    var lagStr string
    memMap := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    requestUriPath, err := getYangPathFromUri(inParams.requestUri)
    if err != nil {
        return memMap, err
    }
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("YangToDb_intf_eth_port_config_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    intfType, _, err := getIntfTypeByName(ifName)
    if err != nil {
        errStr := "Invalid Interface"
        err = tlerr.InvalidArgsError{Format: errStr}
        return nil, err
    }
    if IntfTypeVxlan == intfType || IntfTypeVlan == intfType {
        return memMap, nil
    }

    intfsObj := getIntfsRoot(inParams.ygRoot)
    intfObj := intfsObj.Interface[uriIfName]

    // Need to differentiate between config container delete and any attribute other than aggregate-id delete
    if inParams.oper == DELETE {
    /* Handles 3 cases
       case 1: Deletion request at top-level container / list
       case 2: Deletion request at ethernet container level
       case 3: Deletion request at ethernet/config container level */

        //case 1
        if intfObj.Ethernet == nil ||
          //case 2
          intfObj.Ethernet.Config == nil ||
            //case 3
            (intfObj.Ethernet.Config != nil && requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config") {

            // Delete all the Vlans for Interface and member port removal from port-channel
            lagId, err := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
            if lagId != nil {
                log.Infof("%s is member of %s", ifName, *lagId)
            }
            if err != nil {
                errStr := "Retrieveing PortChannel associated with Interface: " + ifName + " failed!"
                return nil, errors.New(errStr)
            }
            if lagId != nil {
                lagStr = *lagId
                intTbl := IntfTypeTblMap[IntfTypePortChannel]
                tblName, _ := getMemTableNameByDBId(intTbl, inParams.curDb)

                m := make(map[string]string)
                value := db.Value{Field: m}
                m["NULL"] = "NULL"
                intfKey := lagStr + "|" + ifName
                if _, ok := memMap[tblName]; !ok {
                    memMap[tblName] = make(map[string]db.Value)
                }
                memMap[tblName][intfKey] = value
            }
            return memMap, err
        }
    }

    /* Handle AggregateId config */
    if intfObj.Ethernet.Config.AggregateId != nil {
        if !strings.HasPrefix(ifName, ETHERNET) {
            return nil, errors.New("Invalid config request")
        }
        intTbl := IntfTypeTblMap[IntfTypePortChannel]
        tblName, _ := getMemTableNameByDBId(intTbl, inParams.curDb)

        switch inParams.oper {
            case CREATE:
            case REPLACE:
                fallthrough
            case UPDATE:
                log.Info("Add member port")
                lagId := intfObj.Ethernet.Config.AggregateId
                lagStr = "PortChannel" + (*lagId)

                intfType, _, err := getIntfTypeByName(ifName)
                if intfType != IntfTypeEthernet || err != nil {
                    intfTypeStr := strconv.Itoa(int(intfType))
                    errStr := "Invalid interface type" + intfTypeStr
                    log.Error(errStr)
                    return nil, tlerr.InvalidArgsError{Format: errStr}
                }
                /* Check if PortChannel exists */
                err = validateIntfExists(inParams.d, intTbl.cfgDb.portTN, lagStr)
                if err != nil {
                    return nil, err
                }
                /* Check if given iface already part of another PortChannel */
                intf_lagId, _ := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
                if intf_lagId != nil && *intf_lagId != lagStr {
                    errStr := uriIfName + " already member of "+ *intf_lagId
                    return nil, tlerr.InvalidArgsError{Format: errStr}
                }
                /* Restrict configuring member-port if iface configured as member-port of any vlan */
                err = validateIntfAssociatedWithVlan(inParams.d, &ifName)
                if err != nil {
                    return nil, err
                }
                /* Check if L3 configs present on given physical interface */
                err = validateL3ConfigExists(inParams.d, &ifName)
                if err != nil {
                    return nil, tlerr.InvalidArgsError{Format: err.Error()}
                }

            case DELETE:
                lagId, err := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
                if lagId != nil {
                    log.Infof("%s is member of %s", ifName, *lagId)
                }
                if lagId == nil || err != nil {
                    return nil, nil
                }
                lagStr = *lagId
       }/* End of switch case */
       if len(lagStr) != 0 {
            m := make(map[string]string)
            value := db.Value{Field: m}
            m["NULL"] = "NULL"
            intfKey := lagStr + "|" + ifName
            if _, ok := memMap[tblName]; !ok {
                memMap[tblName] = make(map[string]db.Value)
            }
            memMap[tblName][intfKey] = value
       }
    }
    /* Handle PortSpeed config */
    if intfObj.Ethernet.Config.PortSpeed != 0 {
        res_map := make(map[string]string)
        value := db.Value{Field: res_map}
        intTbl := IntfTypeTblMap[intfType]
        if isPortGroupMember(ifName) {
            err = tlerr.InvalidArgs("Port group member. Please use port group command to change the speed")
        }
        portSpeed := intfObj.Ethernet.Config.PortSpeed
        val, ok := intfOCToSpeedMap[portSpeed]
        if ok {
            err = validateSpeed(inParams.d, ifName, val)
            if err == nil {
                res_map[PORT_SPEED] = val
            }
        } else {
            err = tlerr.InvalidArgs("Invalid speed %s", val)
        }

        if err == nil {
            if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
                memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
            }
            memMap[intTbl.cfgDb.portTN][ifName] = value
        }
    } else if  (requestUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/port-speed") {
        if inParams.oper == DELETE {
            updateMap := make(map[string]map[string]db.Value)
            intTbl := IntfTypeTblMap[intfType]
            res_map := make(map[string]string)
            value := db.Value{Field: res_map}
            defSpeed := getDefaultSpeed(inParams.d, ifName)
            log.Info("Default speed for ", ifName, " is ", defSpeed)
            if defSpeed != 0 {
                val := strconv.FormatInt(int64(defSpeed), 10)
                err = validateSpeed(inParams.d, ifName, val)
                if err == nil {
                    res_map[PORT_SPEED] = val
                    if _, ok := updateMap[intTbl.cfgDb.portTN]; !ok {
                        updateMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
                    }
                    updateMap[intTbl.cfgDb.portTN][ifName] = value
                    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
                    subOpMap[db.ConfigDB] = updateMap
                    inParams.subOpDataMap[UPDATE] = &subOpMap
                }
            } else {
                err = tlerr.NotSupported("Default speed not available")
            }
        } else {
            log.Error("Unexpected oper ", inParams.oper)
        }
    }
    /* Handle Port FEC config */
    if (strings.Contains(inParams.requestUri, "openconfig-if-ethernet-ext2:port-fec")) {
        res_map := make(map[string]string)
        value := db.Value{Field: res_map}
        intTbl := IntfTypeTblMap[intfType]

        portFec := intfObj.Ethernet.Config.PortFec

        if inParams.oper == DELETE {
            /* Delete implies default*/
            portFec = ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_FEC_AUTO
        }

        fec_val, ok := yangToDbFecMap[portFec]

        if !ok {
            err = tlerr.InvalidArgs("Invalid FEC %s", portFec)
            log.Infof("Did not find FEC entry")
        } else {
            /* Need the number of lanes */
            port_info, err := inParams.d.GetEntry(&db.TableSpec{Name: "PORT"}, db.Key{Comp: []string{ifName}})
            if err != nil{
                err = tlerr.NotSupported("Port info not readable")
                log.Infof("DB not readable when attempting FEC set to %s", fec_val)
            } else {
                lane_count := len(strings.Split(port_info.Get(PORT_LANES), ","))
                port_speed := port_info.Get(PORT_SPEED)

                log.Infof("Will use lane_count: %d, port_speed: %s, ifname: %s to lookup fec value %s",lane_count, port_speed, ifName, fec_val)

                if fec_val == "default"{
                    log.Infof("Default FEC will be used")
                    fec_val = utils.Get_default_fec(ifName, lane_count, port_speed)
                    log.Infof("Setting default FEC via DB write %s", fec_val)

                    res_map[PORT_FEC] = fec_val
                } else {
                    log.Infof("Looking for non default FEC")
                    /* Check if fec is valid */
                    if !utils.Is_fec_mode_valid(ifName, lane_count, port_speed, fec_val) {
                        err = tlerr.NotSupported("FEC mode %s not supported on interface %s", strings.ToUpper(fec_val), ifName)
                        log.Infof("Fec support check failed")
                        return nil, err
                    } else {
                        res_map[PORT_FEC] = fec_val
                        log.Infof("Validated fec of %s", fec_val)
                    }
                }
            }
            if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
                log.Infof("Creating map entry", fec_val)
                memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
            }
            log.Infof("Finishing map assign  %s", fec_val)
            memMap[intTbl.cfgDb.portTN][ifName] = value
        }
    }

    /* unreliable los mode */
    if (strings.Contains(inParams.requestUri, "openconfig-if-ethernet-ext2:port-unreliable-los")) {
        res_map := make(map[string]string)
        value := db.Value{Field: res_map}
        intTbl := IntfTypeTblMap[intfType]

        portLos := intfObj.Ethernet.Config.PortUnreliableLos

        los_val, ok := yangToDbLosMap[portLos]

        if !ok {
            err = tlerr.InvalidArgs("Invalid unreliable los %s", portLos)
            log.Errorf("Did not find valid unreliable los configuration entry")
        } else {
            /* Need the number of lanes */
            log.Infof("Configuring unreliable los of port %s to %s", ifName, los_val)
            res_map[PORT_UNRELIABLE_LOS] = los_val
            if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
                log.Infof("Creating map entry", los_val)
                memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
            }
            log.Infof("Finishing map assign  %s", los_val)
            memMap[intTbl.cfgDb.portTN][ifName] = value
        }
    }

    /* Handle AutoNegotiate config */
    if intfObj.Ethernet.Config.AutoNegotiate != nil {
        if intfType != IntfTypeMgmt {
            return nil, errors.New("AutoNegotiate config not supported for given Interface type")
        }
        res_map := make(map[string]string)
        value := db.Value{Field: res_map}
        intTbl := IntfTypeTblMap[IntfTypeMgmt]

        autoNeg := intfObj.Ethernet.Config.AutoNegotiate
        var enStr string
        if *autoNeg {
            enStr = "true"
        } else {
            enStr = "false"
        }
        res_map[PORT_AUTONEG] = enStr

        if _, ok := memMap[intTbl.cfgDb.portTN]; !ok {
            memMap[intTbl.cfgDb.portTN] = make(map[string]db.Value)
        }
        memMap[intTbl.cfgDb.portTN][ifName] = value
    }
    return memMap, err
}

// DbToYang_intf_eth_port_config_xfmr is to handle DB to yang translation of port-speed, auto-neg and aggregate-id config.
var DbToYang_intf_eth_port_config_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    uriIfName := pathInfo.Var("name")
    ifName := uriIfName

    sonicIfName := utils.GetNativeNameFromUIName(&uriIfName)
    log.Infof("DbToYang_intf_eth_port_config_xfmr: Interface name retrieved from alias : %s is %s", ifName, *sonicIfName)
    ifName = *sonicIfName

    intfType, _, err := getIntfTypeByName(ifName)
    if err != nil {
        errStr := "Invalid Interface"
        err = tlerr.InvalidArgsError{Format: errStr}
        return err
    }
    if IntfTypeVxlan == intfType {
        return nil
    }
    intTbl := IntfTypeTblMap[intfType]
    tblName := intTbl.cfgDb.portTN
    entry, dbErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})
    if (dbErr != nil){
        errStr := "Invalid Interface"
        err = tlerr.InvalidArgsError{Format: errStr}
        return err
    }
    targetUriPath, err := getYangPathFromUri(inParams.uri)
    if strings.HasPrefix(targetUriPath, "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config") {
        get_cfg_obj := false
        var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[uriIfName]; !ok {
                intfObj, _ = intfsObj.NewInterface(uriIfName)
            }
            ygot.BuildEmptyTree(intfObj)
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(uriIfName)
            ygot.BuildEmptyTree(intfObj)
        }
        ygot.BuildEmptyTree(intfObj.Ethernet)
        ygot.BuildEmptyTree(intfObj.Ethernet.Config)

        if (targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config") {
            get_cfg_obj = true;
        }
        var errStr string
        if (get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-aggregate:aggregate-id"){
            is_id_populated := false
            intf_lagId, _ := retrievePortChannelAssociatedWithIntf(&inParams, &ifName)
            if intf_lagId != nil {
                lagPrefix := "PortChannel"
                if strings.HasPrefix(*intf_lagId, lagPrefix) {
                    aggrId := strings.TrimPrefix(*intf_lagId, lagPrefix)
                    intfObj.Ethernet.Config.AggregateId = &aggrId
                    is_id_populated = true
                }
            }
            if (!is_id_populated) {
                errStr = "aggregate-id not set"
            }
        }

        if (entry.IsPopulated()) {
            if (get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/auto-negotiate") {
                autoNeg, ok := entry.Field[PORT_AUTONEG]
                if ok {
                    var oc_auto_neg bool
                    if autoNeg == "true" {
                        oc_auto_neg = true
                    } else {
                        oc_auto_neg = false
                    }
                    intfObj.Ethernet.Config.AutoNegotiate = &oc_auto_neg
                } else {
                    errStr = "auto-negotiate not set"
                }
            }
            if (get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/port-speed") {
                speed, ok := entry.Field[PORT_SPEED]
                portSpeed := ocbinds.OpenconfigIfEthernet_ETHERNET_SPEED_UNSET
                if ok {
                    portSpeed, err = getDbToYangSpeed(speed)
                    intfObj.Ethernet.Config.PortSpeed = portSpeed
                } else {
                    errStr = "port-speed not set"
                }
            }
            if (get_cfg_obj || targetUriPath == "/openconfig-interfaces:interfaces/interface/openconfig-if-ethernet:ethernet/config/openconfig-if-ethernet-ext2:port-fec") {
                fec, ok := entry.Field[PORT_FEC]
                portFec := ocbinds.OpenconfigPlatformTypes_FEC_MODE_TYPE_UNSET
                if ok {
                    portFec, err = getDbToYangFec(fec)
                    intfObj.Ethernet.Config.PortFec = portFec
                } else {
                    errStr = "port-fec not set"
                }
            }
        } else {
            errStr = "Attribute not set"
        }
        if (!get_cfg_obj && errStr != "") {
            err = tlerr.InvalidArgsError{Format: errStr}
        }
    }

    return err
}

// YangToDb_subintf_ipv6_tbl_key_xfmr is a YangToDB Key transformer for IPv6 config.
var YangToDb_subintf_ipv6_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    if log.V(3) {
        log.Info("Entering YangToDb_subintf_ipv6_tbl_key_xfmr")
    }

    var err error
    var inst_key string
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")

    requestUriPath, err := getYangPathFromUri(inParams.requestUri)
    if log.V(3) {
        log.Info("inParams.requestUri: ", requestUriPath)
    }

    inst_key = ifName
    log.Info("YangToDb_subintf_ipv6_tbl_key_xfmr inst_key : ", inst_key)
    return inst_key, err
}

// DbToYang_subintf_ipv6_tbl_key_xfmr is a DbToYang key transformer for IPv6 config.
var DbToYang_subintf_ipv6_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info("Entering DbToYang_subintf_ipv6_tbl_key_xfmr")
    }

    rmap := make(map[string]interface{})
    return rmap, nil
}

// YangToDb_ipv6_enabled_xfmr is a YangToDB Field transformer for IPv6 config "enabled".
var YangToDb_ipv6_enabled_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(3) {
        log.Info("Entering YangToDb_ipv6_enabled_xfmr")
    }
    var err error
    res_map := make(map[string]string)
    pathInfo := NewPathInfo(inParams.uri)
    ifUIName := pathInfo.Var("name");

    intfType, _, ierr := getIntfTypeByName(ifUIName)
    if ierr != nil || intfType == IntfTypeUnset || intfType == IntfTypeVxlan || intfType == IntfTypeMgmt {
	return res_map, errors.New("YangToDb_ipv6_enabled_xfmr, Error: Unsupported Interface: "+ifUIName )
    }

    if ifUIName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_ipv6_enabled_xfmr: " + errStr)
        return res_map, errors.New(errStr)
    }

    if inParams.param == nil {
        return res_map, err
    }

    // Vlan Interface (routed-vlan) contains only one Key "ifname"
    // For all other interfaces (subinterfaces/subintfaces) will have 2 keys "ifname" & "subintf-index"
    if len(pathInfo.Vars) < 2 && intfType != IntfTypeVlan {
        return res_map, errors.New("YangToDb_ipv6_enabled_xfmr, Error: Invalid Key length")
    }

    if log.V(3) {
        log.Info("YangToDb_ipv6_enabled_xfmr, inParams.key: ", inParams.key)
    }

    ifName := utils.GetNativeNameFromUIName(&ifUIName)

    intTbl := IntfTypeTblMap[intfType]
    tblName := intTbl.cfgDb.intfTN
    ipMap, _ := getIntfIpByName(inParams.d, tblName, *ifName, true, true, "")
    var enStr string
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subOpTblMap := make(map[string]map[string]db.Value)
    field_map := make(map[string]db.Value)
    res_values := db.Value{Field: map[string]string{}}
    IntfMap := make(map[string]string)

    enabled, _ := inParams.param.(*bool)
    if *enabled {
        enStr = "enable"
    } else {
        enStr = "disable"
    }

    IntfMapObj, err := inParams.d.GetMapAll(&db.TableSpec{Name:tblName+"|"+*ifName})
    if err == nil || IntfMapObj.IsPopulated() {
        IntfMap = IntfMapObj.Field
    }
    if val, ok := IntfMap["ipv6_use_link_local_only"]; ok && val == enStr {
        // Check if already set to required value
        log.Info("IPv6 is already %s.", enStr)
        return nil, nil
    }

    res_map["ipv6_use_link_local_only"] = enStr
    if log.V(3) {
        log.Info("YangToDb_ipv6_enabled_xfmr, res_map: ", res_map)
    }

    if enStr == "disable" {

        keys := make([]string, 0, len(IntfMap))
        for k := range IntfMap {
            keys = append(keys, k)
        }
        check_keys := []string{"NULL", "ipv6_use_link_local_only"}
        sort.Strings(keys)
        /* Delete interface from interface table if disabling IPv6 and no other interface attributes/ip
           else remove ipv6_use_link_local_only field */
        if !((reflect.DeepEqual(keys, check_keys) || reflect.DeepEqual(keys, check_keys[1:])) && len(ipMap) == 0 ) {
            log.Info("YangToDb_ipv6_enabled_xfmr, deleting ipv6_use_link_local_only field")
            // Adding field to the map
            (&res_values).Set("ipv6_use_link_local_only", enStr)
        }
        field_map[*ifName] = res_values
        subOpTblMap[tblName]= field_map
        subOpMap[db.ConfigDB] = subOpTblMap
        inParams.subOpDataMap[DELETE] = &subOpMap
        if log.V(3) {
            log.Info("YangToDb_ipv6_enabled_xfmr, subOpMap: ", subOpMap)
        }
        return nil, nil
    }

    return res_map, nil
}

// DbToYang_ipv6_enabled_xfmr is a DbToYang Field transformer for IPv6 config "enabled". */
var DbToYang_ipv6_enabled_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    if log.V(3) {
        log.Info("Entering DbToYang_ipv6_enabled_xfmr")
    }
    res_map := make(map[string]interface{})

    if log.V(3) {
        log.Info("DbToYang_ipv6_enabled_xfmr, inParams.key ", inParams.key)
    }
    pathInfo := NewPathInfo(inParams.uri)
    ifName:= pathInfo.Var("name")

    ifUIName := utils.GetUINameFromNativeName(&ifName)
    log.Info("Interface Name = ", *ifUIName)

    intfType, _, _ := getIntfTypeByName(inParams.key)
    if intfType == IntfTypeVxlan || intfType == IntfTypeMgmt {
        return res_map, nil
    }


    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)

    data := (*inParams.dbDataMap)[inParams.curDb]

    res_map["enabled"] = false
    ipv6_status, ok := data[tblName][inParams.key].Field["ipv6_use_link_local_only"]

    if ok && ipv6_status == "enable" {
        res_map["enabled"] = true
    }
    return res_map, nil
}

/* var YangToDb_igmp_mcastgrpaddr_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	log.Info("YangToDb_igmp_mcastgrpaddr_xfmr: ", inParams.key)
        res_map["enable"] = "true"
	return res_map, nil
}

var DbToYang_igmp_mcastgrpaddr_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Info("DbToYang_igmp_mcastgrpaddr_fld_xfmr: ", inParams.key)

	cdb := inParams.dbs[db.ConfigDB]
	igmpEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "IGMP_INTERFACE"}, db.Key{Comp: []string{inParams.key}})
	mcastgrpaddr := igmpEntry.Get("mcastgrpaddr")

	result["mcastgrpaddr"] = &mcastgrpaddr

	return result, err
}

var YangToDb_igmp_srcaddr_fld_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	log.Info("YangToDb_igmp_srcaddr_xfmr: ", inParams.key)

        res_map["enable"] = "true"
	return res_map, nil
}

var DbToYang_igmp_srcaddr_fld_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	log.Info("DbToYang_igmp_srcaddr_fld_xfmr: ", inParams.key)

	cdb := inParams.dbs[db.ConfigDB]
	igmpEntry, _ := cdb.GetEntry(&db.TableSpec{Name: "IGMP_INTERFACE"}, db.Key{Comp: []string{inParams.key}})
	srcaddr := igmpEntry.Get("srcaddr")

	result["srcaddr"] = &srcaddr

	return result, err
}

var YangToDb_igmp_tbl_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var igmptbl_key string
    var err error
    requestUriPath, err := getYangPathFromUri(inParams.requestUri)
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")

    if ifName == "" {
       errStr := "Interface KEY not present"
       log.Info("YangToDb_igmp_tbl_key_xfmr: " + errStr)
       return "", errors.New(errStr)
    }

    log.Info("YangToDb_igmp_tbl_key_xfmr - requestUriPath:", requestUriPath)

    if strings.HasPrefix(requestUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/openconfig-if-ip:ipv4/openconfig-igmp-ext:igmp/joins") || strings.HasPrefix(requestUriPath, "/openconfig-interfaces:interfaces/interface/subinterfaces/subinterface/ipv4/igmp/joins") {
        mcastGrpAddr := pathInfo.Var("mcastgrpaddr")
        srcAddr := pathInfo.Var("srcaddr")

        log.Info("YangToDb_igmp_tbl_key_xfmr - mcastGrpAddr:", mcastGrpAddr)
        log.Info("YangToDb_igmp_tbl_key_xfmr - srcAddr:", srcAddr)
        if (len(mcastGrpAddr) > 0 && len(srcAddr) > 0) {
            igmptbl_key = ifName + "|" +  mcastGrpAddr + "|" + srcAddr
            log.Info("YangToDb_neigh_tbl_key_xfmr - key returned: ", igmptbl_key)
            return igmptbl_key, err
        }
    } else {
        igmptbl_key = ifName
    }
    return igmptbl_key, err
}

var DbToYang_igmp_tbl_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error

    return nil, err
} */

