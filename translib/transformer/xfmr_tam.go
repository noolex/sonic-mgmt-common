////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
    "fmt"
    "bytes"
    "errors"
    "strings"
    "strconv"
    "reflect"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/openconfig/ygot/util"  // NEEDED
    log "github.com/golang/glog"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
)

const (
    SRC_MASK_CONFIG_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/l2/config/source-mac-mask"
    DST_MASK_CONFIG_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/l2/config/destination-mac-mask"
    SRC_MASK_STATE_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/l2/state/source-mac-mask"
    DST_MASK_STATE_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/l2/state/destination-mac-mask"
    IPV4_HOP_LIMIT_CONFIG_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/ipv4/config/hop-limit"
    IPV4_HOP_LIMIT_STATE_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/ipv4/state/hop-limit"
    IPV6_HOP_LIMIT_CONFIG_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/ipv6/config/hop-limit"
    IPV6_HOP_LIMIT_STATE_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{name}/ipv6/state/hop-limit"
)

var URL_MAP = map[string]bool {
    SRC_MASK_CONFIG_TEMPLATE: false,
    DST_MASK_CONFIG_TEMPLATE: false,
    SRC_MASK_STATE_TEMPLATE: false,
    DST_MASK_STATE_TEMPLATE: false,
    IPV4_HOP_LIMIT_CONFIG_TEMPLATE: false,
    IPV4_HOP_LIMIT_STATE_TEMPLATE: false,
    IPV6_HOP_LIMIT_CONFIG_TEMPLATE: false,
    IPV6_HOP_LIMIT_STATE_TEMPLATE: false,
}

func isSupported(template string) (bool) {
  if v, ok := URL_MAP[template]; ok {
    return v
  } else {
    return true
  }
}

var IP_PROTOCOL_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]uint8{
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_ICMP: 1,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_IGMP: 2,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_TCP:  6,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_UDP:  17,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_RSVP: 46,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_GRE:  47,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_AUTH: 51,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_PIM:  103,
    ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_L2TP: 115,
}

var ETHERTYPE_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_ETHERTYPE]uint32{
    ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_LLDP: 0x88CC,
    ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_VLAN: 0x8100,
    ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ROCE: 0x8915,
    ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ARP:  0x0806,
    ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV4: 0x0800,
    ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV6: 0x86DD,
    ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_MPLS: 0x8847,
}

func getL2EtherType(etherType uint64) interface{} {
    for k, v := range ETHERTYPE_MAP {
        if uint32(etherType) == v {
            return k
        }
    }
    return uint16(etherType)
}

func getIpProtocol(proto int64) interface{} {
    for k, v := range IP_PROTOCOL_MAP {
        if uint8(proto) == v {
            return k
        }
    }
    return uint8(proto)
}

func getTransportSrcDestPorts(portVal string, portType string) interface{} {
    if strings.Contains(portVal, "-") {
        return strings.Replace(portVal, "-", "..", 1)
    } else if len(portVal) > 0 {
        portNum, err := strconv.Atoi(portVal)
        if err == nil {
            return uint16(portNum)
        }
    } else {
        if portType == "src" {
            return ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort_ANY
        } else if portType == "dest" {
            return ocbinds.OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort_ANY
        }
    }
    return nil
}

type AclRule struct {
    TableName          string;
    RuleName           string;
    Priority           uint16;
    Description        string;
    PacketAction       string;
    IpType             string;
    IpProtocol         string;
    EtherType          string;
    SrcMac             string;
    DstMac             string;
    SrcIp              string;
    DstIp              string;
    SrcIpv6            string;
    DstIpv6            string;
    L4SrcPort          string;
    L4DstPort          string;
    TcpFlags           string;
    Dscp               uint8;
    InPorts            string;
    Id                 uint32;
}

func init () {
    XlateFuncBind("YangToDb_tam_switch_global_key_xfmr", YangToDb_tam_switch_global_key_xfmr)
    XlateFuncBind("DbToYang_tam_switch_global_key_xfmr", DbToYang_tam_switch_global_key_xfmr)
    XlateFuncBind("YangToDb_tam_feature_key_xfmr", YangToDb_tam_feature_key_xfmr)
    XlateFuncBind("DbToYang_tam_feature_key_xfmr", DbToYang_tam_feature_key_xfmr)

    XlateFuncBind("YangToDb_tam_sampler_key_xfmr", YangToDb_tam_sampler_key_xfmr)
    XlateFuncBind("DbToYang_tam_sampler_key_xfmr", DbToYang_tam_sampler_key_xfmr)

    XlateFuncBind("YangToDb_tam_ifa_sessions_key_xfmr", YangToDb_tam_ifa_sessions_key_xfmr)
    XlateFuncBind("DbToYang_tam_ifa_sessions_key_xfmr", DbToYang_tam_ifa_sessions_key_xfmr)

    XlateFuncBind("YangToDb_tam_tailstamping_sessions_key_xfmr", YangToDb_tam_tailstamping_sessions_key_xfmr)
    XlateFuncBind("DbToYang_tam_tailstamping_sessions_key_xfmr", DbToYang_tam_tailstamping_sessions_key_xfmr)

    // L2
    XlateFuncBind("YangToDb_tam_flowgroup_l2_key_xfmr", YangToDb_tam_flowgroup_l2_key_xfmr)
    XlateFuncBind("DbToYang_tam_flowgroup_l2_key_xfmr", DbToYang_tam_flowgroup_l2_key_xfmr)

    // Common Field Transformer
    XlateFuncBind("YangToDb_tam_common_key_xfmr", YangToDb_tam_common_key_xfmr)
    XlateFuncBind("DbToYang_tam_common_key_xfmr", DbToYang_tam_common_key_xfmr)

    XlateFuncBind("YangToDb_tam_dropmonitor_global_key_xfmr", YangToDb_tam_dropmonitor_global_key_xfmr)
    XlateFuncBind("DbToYang_tam_dropmonitor_global_key_xfmr", DbToYang_tam_dropmonitor_global_key_xfmr)

    XlateFuncBind("YangToDb_tam_feature_field_xfmr", YangToDb_tam_feature_field_xfmr)
    XlateFuncBind("DbToYang_tam_feature_field_xfmr", DbToYang_tam_feature_field_xfmr)

    XlateFuncBind("DbToYang_tam_flowgroups_xfmr", DbToYang_tam_flowgroups_xfmr)
    XlateFuncBind("YangToDb_tam_flowgroups_xfmr", YangToDb_tam_flowgroups_xfmr)
    XlateFuncBind("Subscribe_tam_flowgroups_xfmr", Subscribe_tam_flowgroups_xfmr)

    XlateFuncBind("tam_post_xfmr", tam_post_xfmr)
}

func getTamRoot(s *ygot.GoStruct) (*ocbinds.OpenconfigTam_Tam) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.Tam
}

func getSessionInfo(template string) (string, bool) {
    var isSession = false
    var feature = ""

    if (strings.Contains(template, "ifa-sessions")) {
        feature = "ifa"
        isSession = true
    }
    if (strings.Contains(template, "dropmonitor-sessions")) {
        feature = "mod"
        isSession = true
    }
    if (strings.Contains(template, "tailstamping-sessions")) {
        feature = "tailstamp"
        isSession = true
    }
    return feature, isSession
}

var tam_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    pathInfo := NewPathInfo(inParams.uri)
    template := pathInfo.Template
    method := inParams.oper
    key := NewPathInfo(inParams.uri).Var("name")
    log.Info("key: " , key)
    feature, isSessionsUri := getSessionInfo(template)

    if (isSessionsUri) {
        updateMap := make(map[db.DBNum]map[string]map[string]db.Value)
        updateMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        updateMap[db.ConfigDB]["ACL_RULE"] = make(map[string]db.Value)
        var configDbPtr, _ = db.NewDB(getDBOptions(db.ConfigDB))

        var aclKey string
        sessions := (*inParams.dbDataMap)[db.ConfigDB]
        var sessionEntries map[string]db.Value
        if (feature == "ifa") {
            sessionEntries = sessions["TAM_IFA_SESSIONS_TABLE"]
            if (key != "") {
                // get flowgroup associated to the session
                var IFA_SESSIONS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_IFA_SESSIONS_TABLE"}
                sessionsTable, _ := configDbPtr.GetTable(IFA_SESSIONS_TABLE_TS)
                sessionKeys, _ := sessionsTable.GetKeys()
                for _, r := range sessionKeys {
                    entry, err := sessionsTable.GetEntry(r)
                    if (key == r.Get(0)) {
                        if err == nil {
                            aclKey = "TAM|"+entry.Get("flowgroup")
                        }
                        break
                    }
                }
            }
        } else if (feature == "mod") {
            sessionEntries = sessions["TAM_DROPMONITOR_SESSIONS_TABLE"]
            if (key != "") {
                // get flowgroup associated to the session
                var DROPMONITOR_SESSIONS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_DROPMONITOR_SESSIONS_TABLE"}
                sessionsTable, _ := configDbPtr.GetTable(DROPMONITOR_SESSIONS_TABLE_TS)
                sessionKeys, _ := sessionsTable.GetKeys()
                for _, r := range sessionKeys {
                    entry, err := sessionsTable.GetEntry(r)
                    if (key == r.Get(0)) {
                        if err == nil {
                            aclKey = "TAM|"+entry.Get("flowgroup")
                        }
                        break
                    }
                }
            }
        } else if (feature == "tailstamp") {
            sessionEntries = sessions["TAM_TAILSTAMPING_SESSIONS_TABLE"]
            if (key != "") {
                // get flowgroup associated to the session
                var TAM_TAILSTAMPING_SESSIONS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_TAILSTAMPING_SESSIONS_TABLE"}
                sessionsTable, _ := configDbPtr.GetTable(TAM_TAILSTAMPING_SESSIONS_TABLE_TS)
                sessionKeys, _ := sessionsTable.GetKeys()
                for _, r := range sessionKeys {
                    entry, err := sessionsTable.GetEntry(r)
                    if (key == r.Get(0)) {
                        if err == nil {
                            aclKey = "TAM|"+entry.Get("flowgroup")
                        }
                        break
                    }
                }
            }
        }

        var ACL_RULE_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "ACL_RULE"}
        entry_found := false
        for _, v := range sessionEntries {
            if (key == "") {
                aclKey = "TAM|"+v.Get("flowgroup")
            }
            _, err := configDbPtr.GetEntry(ACL_RULE_TABLE_TS, db.Key{[]string{aclKey}})
            if (err == nil) {
                entry_found = true
                updateMap[db.ConfigDB]["ACL_RULE"][aclKey] = db.Value{Field: make(map[string]string)}
                if (feature == "ifa") {
                    if (v.Get("node-type") == "INGRESS") {
                        updateMap[db.ConfigDB]["ACL_RULE"][aclKey].Field["PACKET_ACTION"] = "INT_INSERT"
                    } else if (v.Get("node-type") == "EGRESS") {
                        updateMap[db.ConfigDB]["ACL_RULE"][aclKey].Field["PACKET_ACTION"] = "INT_DELETE"
                    } else {
                        updateMap[db.ConfigDB]["ACL_RULE"][aclKey].Field["PACKET_ACTION"] = "INT_INSERT"
                    }
                } else if (feature == "tailstamp") {
                    updateMap[db.ConfigDB]["ACL_RULE"][aclKey].Field["PACKET_ACTION"] = "INT_INSERT"
                } else {
                    updateMap[db.ConfigDB]["ACL_RULE"][aclKey].Field["PACKET_ACTION"] = "MONITOR_DROPS"
                }
            }
        }
        if (entry_found) {
            inParams.subOpDataMap[method] = &updateMap
        }
    }
    return (*inParams.dbDataMap)[db.ConfigDB], nil
}

func getRecord(d *db.DB, name string) (AclRule, error) {
    var aclRule AclRule
    ruleEntry, err := d.GetEntry(&db.TableSpec{Name: "ACL_RULE"}, db.Key{Comp: []string{"TAM", name}})
    if err != nil {
        return aclRule, tlerr.NotFound("Resource Not Found")
    }
    aclRule.TableName = "TAM"
    aclRule.RuleName = name
    priority, _ := strconv.ParseInt(ruleEntry.Get("PRIORITY"), 10, 32)
    aclRule.Priority = uint16(priority)
    aclRule.Description = ruleEntry.Get("DESCRIPTION")
    aclRule.PacketAction = ruleEntry.Get("PACKET_ACTION")
    aclRule.IpType = ruleEntry.Get("IP_TYPE")
    aclRule.IpProtocol = ruleEntry.Get("IP_PROTOCOL")
    aclRule.EtherType = ruleEntry.Get("ETHER_TYPE")
    aclRule.SrcMac = ruleEntry.Get("SRC_MAC")
    aclRule.DstMac = ruleEntry.Get("DST_MAC")
    aclRule.SrcIp = ruleEntry.Get("SRC_IP")
    aclRule.DstIp = ruleEntry.Get("DST_IP")
    aclRule.SrcIpv6 = ruleEntry.Get("SRC_IPV6")
    aclRule.DstIpv6 = ruleEntry.Get("DST_IPV6")
    aclRule.L4SrcPort = ruleEntry.Get("L4_SRC_PORT")
    aclRule.L4DstPort = ruleEntry.Get("L4_DST_PORT")
    aclRule.TcpFlags = ruleEntry.Get("TCP_FLAGS")
    dscp, _ := strconv.ParseInt(ruleEntry.Get("DSCP"), 10, 32)
    aclRule.Dscp = uint8(dscp)
    aclRule.InPorts = ruleEntry.Get("IN_PORTS")

    flowEntry, err := d.GetEntry(&db.TableSpec{Name: "TAM_FLOWGROUP_TABLE"}, db.Key{Comp: []string{name}})
    if err != nil {
        return aclRule, tlerr.NotFound("Resource Not Found")
    }
    id, _ := strconv.ParseInt(flowEntry.Get("id"), 10, 32)
    aclRule.Id = uint32(id)
    return aclRule, err
}

func getFlowGroupsFromDb(d *db.DB, name string) (map[string]AclRule, error) {
    var ruleEntries = make(map[string]AclRule)
    var err error
    if name != "" {
        entry, err := getRecord(d, name)
        if err != nil {
            return ruleEntries, err
        }
        ruleEntries[name] = entry
    } else {
        AclRules, err := d.GetTable(&db.TableSpec{Name: "ACL_RULE"})
        if err != nil {
            return ruleEntries, tlerr.NotFound("Resource Not Found")
        }
        keys, _ := AclRules.GetKeys()
        for _, key := range keys {
            rule := key.Get(1)
            entry, _ := getRecord(d, key.Get(1))
            ruleEntries[rule] = entry
        }
    }
    return ruleEntries, err
}

func appendFlowGroupToYang(flowGroups *ocbinds.OpenconfigTam_Tam_Flowgroups, rule string, entry AclRule) (error) {
    var err error
    flowGroup, found := flowGroups.Flowgroup[rule]
    if !found {
        flowGroup, err = flowGroups.NewFlowgroup(rule)
        if err != nil {
            log.Errorf("Error creating flowgroup component")
            return err
        }
    }
    ygot.BuildEmptyTree(flowGroup)
    ygot.BuildEmptyTree(flowGroup.Config)
    ygot.BuildEmptyTree(flowGroup.State)
    flowGroup.Name = &rule
    flowGroup.Config.Priority = &(entry.Priority)
    flowGroup.Config.Id = &(entry.Id)
    flowGroup.Config.Name = &rule
    flowGroup.State.Priority = &(entry.Priority)
    flowGroup.State.Id = &(entry.Id)
    flowGroup.State.Name = &rule

    // Ipv4
    if (entry.IpType == "IPV4ANY") {
        flowGroup.Config.IpVersion = ocbinds.OpenconfigTam_IpVersion_IPV4
        flowGroup.State.IpVersion = ocbinds.OpenconfigTam_IpVersion_IPV4
        ygot.BuildEmptyTree(flowGroup.Ipv4)
        ygot.BuildEmptyTree(flowGroup.Ipv4.Config)
        ygot.BuildEmptyTree(flowGroup.Ipv4.State)
        if (entry.SrcIp != "") {flowGroup.Ipv4.Config.SourceAddress = &(entry.SrcIp)}
        if (entry.SrcIp != "") {flowGroup.Ipv4.State.SourceAddress = &(entry.SrcIp)}
        if (entry.DstIp != "") {flowGroup.Ipv4.Config.DestinationAddress = &(entry.DstIp)}
        if (entry.DstIp != "") {flowGroup.Ipv4.State.DestinationAddress = &(entry.DstIp)}
        if (entry.Dscp != 0) {flowGroup.Ipv4.Config.Dscp = &(entry.Dscp)}
        if (entry.Dscp != 0) {flowGroup.Ipv4.State.Dscp = &(entry.Dscp)}
        if ((entry.IpProtocol != "") && (entry.IpType == "IPV4ANY")) {
            ipProto, _ := strconv.ParseInt(entry.IpProtocol, 10, 64)
            protocolVal := getIpProtocol(ipProto)
            flowGroup.Ipv4.Config.Protocol, _ = flowGroup.Ipv4.Config.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_Config_Protocol_Union(protocolVal)
            flowGroup.Ipv4.State.Protocol, _ = flowGroup.Ipv4.State.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_State_Protocol_Union(protocolVal)
        }
    }

    // Ipv6
    if (entry.IpType == "IPV6ANY") {
        flowGroup.Config.IpVersion = ocbinds.OpenconfigTam_IpVersion_IPV6
        flowGroup.State.IpVersion = ocbinds.OpenconfigTam_IpVersion_IPV6
        ygot.BuildEmptyTree(flowGroup.Ipv6)
        ygot.BuildEmptyTree(flowGroup.Ipv6.Config)
        ygot.BuildEmptyTree(flowGroup.Ipv6.State)
        if (entry.SrcIpv6 != "") {flowGroup.Ipv6.Config.SourceAddress = &(entry.SrcIpv6)}
        if (entry.SrcIpv6 != "") {flowGroup.Ipv6.State.SourceAddress = &(entry.SrcIpv6)}
        if (entry.DstIpv6 != "") {flowGroup.Ipv6.Config.DestinationAddress = &(entry.DstIpv6)}
        if (entry.DstIpv6 != "") {flowGroup.Ipv6.State.DestinationAddress = &(entry.DstIpv6)}
        if (entry.Dscp != 0) {flowGroup.Ipv6.Config.Dscp = &(entry.Dscp)}
        if (entry.Dscp != 0) {flowGroup.Ipv6.State.Dscp = &(entry.Dscp)}
        if ((entry.IpProtocol != "") && (entry.IpType == "IPV6ANY")) {
            ipProto, _ := strconv.ParseInt(entry.IpProtocol, 10, 64)
            protocolVal := getIpProtocol(ipProto)
            flowGroup.Ipv6.Config.Protocol, _ = flowGroup.Ipv6.Config.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv6_Config_Protocol_Union(protocolVal)
            flowGroup.Ipv6.State.Protocol, _ = flowGroup.Ipv6.State.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv6_State_Protocol_Union(protocolVal)
        }
    }

    // L2
    ygot.BuildEmptyTree(flowGroup.L2)
    ygot.BuildEmptyTree(flowGroup.L2.Config)
    ygot.BuildEmptyTree(flowGroup.L2.State)
    if (entry.SrcMac != "") {flowGroup.L2.Config.SourceMac = &(entry.SrcMac)}
    if (entry.SrcMac != "") {flowGroup.L2.State.SourceMac = &(entry.SrcMac)}
    if (entry.DstMac != "") {flowGroup.L2.Config.DestinationMac = &(entry.DstMac)}
    if (entry.DstMac != "") {flowGroup.L2.State.DestinationMac = &(entry.DstMac)}
    if (entry.EtherType != "") {
        ethType, _ := strconv.ParseUint(strings.Replace(entry.EtherType, "0x", "", -1), 16, 32)
        ethertype := getL2EtherType(ethType)
        flowGroup.L2.Config.Ethertype, _ = flowGroup.L2.Config.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_L2_Config_Ethertype_Union(ethertype)
        flowGroup.L2.State.Ethertype, _ = flowGroup.L2.State.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_L2_State_Ethertype_Union(ethertype)
    }

    // Transport
    ygot.BuildEmptyTree(flowGroup.Transport)
    ygot.BuildEmptyTree(flowGroup.Transport.Config)
    ygot.BuildEmptyTree(flowGroup.Transport.State)
    if (entry.L4SrcPort != "") {
        srcPort := getTransportSrcDestPorts(entry.L4SrcPort, "src")
        flowGroup.Transport.Config.SourcePort, _ = flowGroup.Transport.Config.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_SourcePort_Union(srcPort)
        flowGroup.Transport.State.SourcePort, _ = flowGroup.Transport.State.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_State_SourcePort_Union(srcPort)
    }
    if (entry.L4DstPort != "") {
        dstPort := getTransportSrcDestPorts(entry.L4DstPort, "dest")
        flowGroup.Transport.Config.DestinationPort, _ = flowGroup.Transport.Config.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_DestinationPort_Union(dstPort)
        flowGroup.Transport.State.DestinationPort, _ = flowGroup.Transport.State.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_State_DestinationPort_Union(dstPort)
    }
    if (entry.TcpFlags != "") {
        flowGroup.Transport.Config.TcpFlags = getTransportConfigTcpFlags(entry.TcpFlags)
        flowGroup.Transport.State.TcpFlags = getTransportConfigTcpFlags(entry.TcpFlags)
    }
    return err
}

func fillFlowgroupInfo(flowGroups *ocbinds.OpenconfigTam_Tam_Flowgroups, name string, targetUriPath string, uri string, d *db.DB) (error) {
    ruleEntries , err := getFlowGroupsFromDb(d, name)
    if err == nil {
        for k, v := range ruleEntries {
            err = appendFlowGroupToYang(flowGroups, k, v)
        }
    }
    return err
}

func getFlowGroups(tamObj *ocbinds.OpenconfigTam_Tam, targetUriPath string, uri string, d *db.DB) (error) {
    name := NewPathInfo(uri).Var("name")
    ygot.BuildEmptyTree(tamObj)
    ygot.BuildEmptyTree(tamObj.Flowgroups)
    return fillFlowgroupInfo(tamObj.Flowgroups, name, targetUriPath, uri, d)
}

var Subscribe_tam_flowgroups_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)

    pathInfo := NewPathInfo(inParams.uri)
    keyName := pathInfo.Var("name")

    if (keyName != "") {
        result.dbDataMap = RedisDbMap{db.ConfigDB:{"ACL_RULE":{"TAM|"+keyName:{}}}}
    } else {
        errStr := "Flow Group not present in request"
        log.Info("Subscribe_tam_flowgroups_xfmr: " + errStr)
        return result, errors.New(errStr)
    }
    result.isVirtualTbl = false
    log.Info("Subscribe_tam_flowgroups_xfmr resultMap:", result.dbDataMap)
    return result, err
}

var DbToYang_tam_flowgroups_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    tamObj := getTamRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    if (!isSupported(pathInfo.Template)) {
        return tlerr.NotSupported("Operation Not Supported")
    } else {
        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
        uri := inParams.uri
        return getFlowGroups(tamObj, targetUriPath, uri, inParams.dbs[db.ConfigDB])
    }
}

var YangToDb_tam_flowgroups_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    tamObj := getTamRoot(inParams.ygRoot)
    method := inParams.oper

    key := NewPathInfo(inParams.uri).Var("name")

    updateMap := make(map[db.DBNum]map[string]map[string]db.Value)
    updateMap[db.ConfigDB] = make(map[string]map[string]db.Value)

    var configDbPtr, _ = db.NewDB(getDBOptions(db.ConfigDB))
    var TAM_FLOWGROUP_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_FLOWGROUP_TABLE"}
    flowGroupTable, _ := configDbPtr.GetTable(TAM_FLOWGROUP_TABLE_TS)
    flowGroupsKeys, _ := flowGroupTable.GetKeys()

    set := make(map[string]bool)
    for _, v := range flowGroupsKeys {
        flowEntry, _ := configDbPtr.GetEntry(&db.TableSpec{Name: "TAM_FLOWGROUP_TABLE"}, db.Key{Comp: []string{v.Get(0)}})
        id := flowEntry.Get("id")
        set[id] = true
    }

    updateMap[db.ConfigDB]["ACL_RULE"] = make(map[string]db.Value)
    updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"] = make(map[string]db.Value)
    currentSet := make(map[string]bool)
    if key != "" {
        if (method == DELETE) {
            for _, k := range flowGroupsKeys {
                entry_key := k.Get(0)
                aclKey := "TAM|"+entry_key
                if (key == k.Get(0)) {
                    updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][entry_key] = db.Value{Field: make(map[string]string)}
                    updateMap[db.ConfigDB]["ACL_RULE"][aclKey] = db.Value{Field: make(map[string]string)}
                }
            }
            inParams.subOpDataMap[DELETE] = &updateMap
        }
        if (method == CREATE) { // POST
            errStr := fmt.Sprintf("Flowgroup (%v) is alreay present", key)
            err = tlerr.AlreadyExistsError{AppTag: "invalid-value", Path: "", Format: errStr}
            return res_map, err
        }
    } else {
        if (method == DELETE) {
            for _, k := range flowGroupsKeys {
                entry_key := k.Get(0)
                aclKey := "TAM|"+entry_key
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][entry_key] = db.Value{Field: make(map[string]string)}
                updateMap[db.ConfigDB]["ACL_RULE"][aclKey] = db.Value{Field: make(map[string]string)}
            }
            inParams.subOpDataMap[DELETE] = &updateMap
        } else {
            for thiskey, flowgroup := range tamObj.Flowgroups.Flowgroup {
                entry_key := "TAM|"+thiskey
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key] = db.Value{Field: make(map[string]string)}

                // mandatory
                if flowgroup.Config.Id == nil {
                    errStr := "key field id (uint32) has nil value"
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                id := strconv.FormatInt(int64(*flowgroup.Config.Id), 10)
                if (set[id] || currentSet[id]) {
                    errStr := fmt.Sprintf("Flowgroup with id %v already exists", *flowgroup.Config.Id)
                    err = tlerr.AlreadyExistsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                if (currentSet[id]) {
                    errStr := fmt.Sprintf("Duplicate id (%v) present in the payload", *flowgroup.Config.Id)
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                if flowgroup.Config.Name == nil {
                    errStr := "key field name (*string) has nil value"
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                if flowgroup.Config.IpVersion == ocbinds.OpenconfigTam_IpVersion_UNSET {
                    errStr := "Mandatory parameter ip-version is not set"
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                if ((flowgroup.Config.IpVersion != ocbinds.OpenconfigTam_IpVersion_IPV4) && (flowgroup.Config.IpVersion != ocbinds.OpenconfigTam_IpVersion_IPV6)) {
                    errStr := "Invalid ip-version"
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                priority := "100"
                if (flowgroup.Config.Priority != nil) {
                    priority = strconv.FormatInt(int64(*(flowgroup.Config.Priority)), 10)
                }
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["PRIORITY"] = priority

                // IPv4
                if (flowgroup.Config.IpVersion == ocbinds.OpenconfigTam_IpVersion_IPV4) {
                    updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_TYPE"] = "IPV4ANY"
                    if flowgroup.Ipv4 != nil && flowgroup.Ipv4.Config != nil {
                        if flowgroup.Ipv4.Config.SourceAddress != nil {
                            updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["SRC_IP"] = *(flowgroup.Ipv4.Config.SourceAddress)
                        }
                        if flowgroup.Ipv4.Config.DestinationAddress != nil {
                            updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["DST_IP"] = *(flowgroup.Ipv4.Config.DestinationAddress)
                        }
                        if flowgroup.Ipv4.Config.Dscp != nil {
                            updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["DSCP"] = strconv.FormatInt(int64(*flowgroup.Ipv4.Config.Dscp), 10)
                        }

                        if flowgroup.Ipv4.Config.Protocol != nil && util.IsTypeStructPtr(reflect.TypeOf(flowgroup.Ipv4.Config.Protocol)) {
                            protocolType := reflect.TypeOf(flowgroup.Ipv4.Config.Protocol).Elem()
                            switch protocolType {
                                case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
                                    v := (flowgroup.Ipv4.Config.Protocol).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
                                    updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_PROTOCOL"] = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
                                case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_Config_Protocol_Union_Uint8{}):
                                    v := (flowgroup.Ipv4.Config.Protocol).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_Config_Protocol_Union_Uint8)
                                    updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_PROTOCOL"] = strconv.FormatInt(int64(v.Uint8), 10)
                            }
                        }
                        if flowgroup.Ipv4.Config.HopLimit != nil {
                            errStr := "parameter hop-limit is not supported"
                            err = tlerr.NotSupportedError{AppTag: "invalid-value", Path: "", Format: errStr}
                            return res_map, err
                        }
                    }
                }

                // IPv6
                if (flowgroup.Config.IpVersion == ocbinds.OpenconfigTam_IpVersion_IPV6) {
                    updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_TYPE"] = "IPV6ANY"

                    if flowgroup.Ipv6.Config.Protocol != nil && util.IsTypeStructPtr(reflect.TypeOf(flowgroup.Ipv6.Config.Protocol)) {
                        protocolType := reflect.TypeOf(flowgroup.Ipv6.Config.Protocol).Elem()
                        switch protocolType {
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv6_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
                                v := (flowgroup.Ipv6.Config.Protocol).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv6_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_PROTOCOL"] = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv6_Config_Protocol_Union_Uint8{}):
                                v := (flowgroup.Ipv6.Config.Protocol).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv6_Config_Protocol_Union_Uint8)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_PROTOCOL"] = strconv.FormatInt(int64(v.Uint8), 10)
                        }
                    }
                    if flowgroup.Ipv6.Config.Dscp != nil {
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["DSCP"] = strconv.FormatInt(int64(*flowgroup.Ipv6.Config.Dscp), 10)
                    }
                    if flowgroup.Ipv6.Config.SourceAddress != nil {
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["SRC_IPV6"] = *flowgroup.Ipv6.Config.SourceAddress
                    }
                    if flowgroup.Ipv6.Config.DestinationAddress != nil {
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["DST_IPV6"] = *flowgroup.Ipv6.Config.DestinationAddress
                    }
                    if flowgroup.Ipv6.Config.HopLimit != nil {
                        errStr := "parameter hop-limit is not supported"
                        err = tlerr.NotSupportedError{AppTag: "invalid-value", Path: "", Format: errStr}
                        return res_map, err
                    }
                    if flowgroup.Ipv6.Config.SourceFlowLabel != nil {
                        errStr := "parameter source-flow-label is not supported"
                        err = tlerr.NotSupportedError{AppTag: "invalid-value", Path: "", Format: errStr}
                        return res_map, err
                    }
                    if flowgroup.Ipv6.Config.DestinationFlowLabel != nil {
                        errStr := "parameter destination-flow-label is not supported"
                        err = tlerr.NotSupportedError{AppTag: "invalid-value", Path: "", Format: errStr}
                        return res_map, err
                    }
                }

                // L2
                if flowgroup.L2 != nil && flowgroup.L2.Config != nil {
                    if flowgroup.L2.Config.DestinationMac != nil {
                        ocMacStr := *(flowgroup.L2.Config.DestinationMac)
                        if flowgroup.L2.Config.DestinationMacMask != nil {
                            ocMacStr = ocMacStr + "/" + *(flowgroup.L2.Config.DestinationMacMask)
                        }
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["DST_MAC"] = ocMacStr
                    }
                    if flowgroup.L2.Config.SourceMac != nil {
                        ocMacStr := *(flowgroup.L2.Config.SourceMac)
                        if flowgroup.L2.Config.SourceMacMask != nil {
                            ocMacStr = ocMacStr + "/" + *(flowgroup.L2.Config.SourceMacMask)
                        }
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["SRC_MAC"] = ocMacStr
                    }
                    if flowgroup.L2.Config.Ethertype != nil {
                        ethertypeType := reflect.TypeOf(flowgroup.L2.Config.Ethertype).Elem()
                        var b bytes.Buffer
                        switch ethertypeType {
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE{}):
                                v := flowgroup.L2.Config.Ethertype.(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE)
                                fmt.Fprintf(&b, "0x%x", ETHERTYPE_MAP[v.E_OpenconfigPacketMatchTypes_ETHERTYPE])
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_L2_Config_Ethertype_Union_Uint16{}):
                                v := flowgroup.L2.Config.Ethertype.(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_L2_Config_Ethertype_Union_Uint16)
                                fmt.Fprintf(&b, "0x%x", v.Uint16)
                        }
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["ETHER_TYPE"] = b.String()
                    }
                }
                //Transport
                if flowgroup.Transport != nil && flowgroup.Transport.Config != nil {
                    if flowgroup.Transport.Config.SourcePort != nil && util.IsTypeStructPtr(reflect.TypeOf(flowgroup.Transport.Config.SourcePort)) {
                        sourceportType := reflect.TypeOf(flowgroup.Transport.Config.SourcePort).Elem()
                        switch sourceportType {
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_SourcePort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort{}):
                                v := (flowgroup.Transport.Config.SourcePort).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_SourcePort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["L4_SRC_PORT"] = v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort.ΛMap()["E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort"][int64(v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort)].Name
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_SourcePort_Union_String{}):
                                v := (flowgroup.Transport.Config.SourcePort).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_SourcePort_Union_String)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["L4_SRC_PORT_RANGE"] = strings.Replace(v.String, "..", "-", 1)
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_SourcePort_Union_Uint16{}):
                                v := (flowgroup.Transport.Config.SourcePort).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_SourcePort_Union_Uint16)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["L4_SRC_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
                        }
                    }

                    if flowgroup.Transport.Config.DestinationPort != nil && util.IsTypeStructPtr(reflect.TypeOf(flowgroup.Transport.Config.DestinationPort)) {
                        destportType := reflect.TypeOf(flowgroup.Transport.Config.DestinationPort).Elem()
                        switch destportType {
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_DestinationPort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort{}):
                                v := (flowgroup.Transport.Config.DestinationPort).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_DestinationPort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["L4_DST_PORT"] = v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort.ΛMap()["E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort"][int64(v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort)].Name
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_DestinationPort_Union_String{}):
                                v := (flowgroup.Transport.Config.DestinationPort).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_DestinationPort_Union_String)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["L4_DST_PORT_RANGE"] = strings.Replace(v.String, "..", "-", 1)
                            case reflect.TypeOf(ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_DestinationPort_Union_Uint16{}):
                                v := (flowgroup.Transport.Config.DestinationPort).(*ocbinds.OpenconfigTam_Tam_Flowgroups_Flowgroup_Transport_Config_DestinationPort_Union_Uint16)
                                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["L4_DST_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
                        }
                    }

                    if len(flowgroup.Transport.Config.TcpFlags) > 0 {
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["TCP_FLAGS"] = convertOCTcpFlagsToDbFormat(flowgroup.Transport.Config.TcpFlags)
                    }
                }
                // Create Flowgroup Table
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][thiskey] = db.Value{Field: make(map[string]string)}
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][thiskey].Field["id"] = id //strconv.FormatInt(int64(*flowgroup.Config.Id), 10)
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][thiskey].Field["table-name"] = "TAM"
                currentSet[id] = true
                inParams.subOpDataMap[method] = &updateMap
            }
        }
    }
    return res_map, err
}

var YangToDb_tam_switch_global_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    log.Info("YangToDb_tam_switch_global_key_xfmr: ", inParams.uri)
    dvKey := "global"
    return dvKey, nil
}

var DbToYang_tam_switch_global_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    log.Info("DbToYang_tam_switch_global_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)
    return rmap, nil
}

var YangToDb_tam_dropmonitor_global_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    log.Info("YangToDb_tam_dropmonitor_global_key_xfmr: ", inParams.uri)
    dvKey := "global"
    return dvKey, nil
}

var DbToYang_tam_dropmonitor_global_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    log.Info("DbToYang_tam_dropmonitor_global_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)
    return rmap, nil
}

var YangToDb_tam_feature_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    log.Info("YangToDb_tam_feature_key_xfmr: ", inParams.uri)
    dvKey := "Values"
    return dvKey, nil
}

var DbToYang_tam_feature_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    log.Info("DbToYang_tam_feature_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)
   return rmap, nil
}

var YangToDb_tam_sampler_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    dvKey := pathInfo.Var("name")
    return dvKey, nil
}

var DbToYang_tam_sampler_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    rmap["name"] = inParams.key
    return rmap, nil
}

var YangToDb_tam_common_key_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    return res_map, nil
}

var DbToYang_tam_common_key_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    rmap["name"] = inParams.key
    return rmap, nil
}


var YangToDb_tam_feature_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    return res_map, nil
}

var DbToYang_tam_feature_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    rmap["feature-ref"] = inParams.key
    return rmap, nil
}


var YangToDb_tam_ifa_sessions_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    dvKey := pathInfo.Var("feature-ref")
    return dvKey, nil
}

var DbToYang_tam_ifa_sessions_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    rmap["name"] = inParams.key
    return rmap, nil
}

var YangToDb_tam_tailstamping_sessions_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    dvKey := pathInfo.Var("name")
    return dvKey, nil
}

var DbToYang_tam_tailstamping_sessions_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    rmap["name"] = inParams.key
    return rmap, nil
}

var YangToDb_tam_flowgroup_l2_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    dvKey := pathInfo.Var("name")
    return dvKey, nil
}

var DbToYang_tam_flowgroup_l2_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    rmap["name"] = inParams.key
    return rmap, nil
}

func convertOCTcpFlagsToDbFormat(flags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS) string {
    var tcpFlags uint32 = 0x00
    var tcpFlagsMask uint32 = 0x00
    for _, flag := range flags {
        switch flag {
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN:
                tcpFlags |= 0x01
                tcpFlagsMask |= 0x1
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_FIN:
                tcpFlagsMask |= 0x1
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN:
                tcpFlags |= 0x02
                tcpFlagsMask |= 0x2
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_SYN:
                tcpFlagsMask |= 0x2
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST:
                tcpFlags |= 0x04
                tcpFlagsMask |= 0x4
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_RST:
                tcpFlagsMask |= 0x4
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH:
                tcpFlags |= 0x08
                tcpFlagsMask |= 0x8
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_PSH:
                tcpFlagsMask |= 0x8
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK:
                tcpFlags |= 0x10
                tcpFlagsMask |= 0x10
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ACK:
                tcpFlagsMask |= 0x10
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG:
                tcpFlags |= 0x20
                tcpFlagsMask |= 0x20
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_URG:
                tcpFlagsMask |= 0x20
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE:
                tcpFlags |= 0x40
                tcpFlagsMask |= 0x40
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ECE:
                tcpFlagsMask |= 0x40
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR:
                tcpFlags |= 0x80
                tcpFlagsMask |= 0x80
            case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_CWR:
                tcpFlagsMask |= 0x80
        }
    }
    var b bytes.Buffer
    fmt.Fprintf(&b, "0x%x/0x%x", tcpFlags, tcpFlagsMask)
    return b.String()
}

func getTransportConfigTcpFlags(tcpFlags string) []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS {
    var flags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS
    flagParts := strings.Split(tcpFlags, "/")
    valueStr := flagParts[0]
    maskStr := flagParts[1]
    flagValue, _ := strconv.ParseUint(valueStr, 0, 8)
    flagMask, _ := strconv.ParseUint(maskStr, 0, 8)
    for i := 0; i < 8; i++ {
        mask := uint64(1 << i)
        if (flagValue&mask) > 0 || (flagMask&mask) > 0 {
            switch mask {
                case 0x01:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_FIN)
                    }
                case 0x02:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_SYN)
                    }
                case 0x04:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_RST)
                    }
                case 0x08:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_PSH)
                    }
                case 0x10:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ACK)
                    }
                case 0x20:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_URG)
                    }
                case 0x40:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ECE)
                    }
                case 0x80:
                    if (flagValue & mask) > 0 {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR)
                    } else {
                        flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_CWR)
                    }
                default:
            }
        }
    }
    return flags
}

