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
    "github.com/openconfig/ygot/util"
    log "github.com/golang/glog"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "encoding/json"
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
    SWITCH_ID_TEMPLATE = "/openconfig-tam:tam/switch/config/switch-id"
    ENTERPRISE_ID_TEMPLATE = "/openconfig-tam:tam/switch/config/enterprise-id"

    FLOWGROUP_INTERFACE_CFG_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{}/config/interfaces{}"
    FLOWGROUP_CFG_TEMPLATE = "/openconfig-tam:tam/flowgroups/flowgroup{}"

    FLOWGROUPS_TEMPLATE = "/openconfig-tam:tam/flowgroups"
    FEATURES_TEMPLATE = "/openconfig-tam:tam/features"
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
    bytes              uint64;
    packets            uint64;
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

	XlateFuncBind("rpc_clear_flowgroup_counters_cb", rpc_clear_flowgroup_counters_cb)
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

func isSwitchTemplate (template string) (bool) {
    if ((strings.Contains(template, SWITCH_ID_TEMPLATE)) || (strings.Contains(template, ENTERPRISE_ID_TEMPLATE)))  {
        return true
    } else {
        return false
   }
}

func isTamTableExists(d *db.DB) (bool) {
    exists := false
    var ACL_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "ACL_TABLE"}
    _, err := d.GetEntry(ACL_TABLE_TS, db.Key{Comp: []string{"TAM"}})
    if (err == nil) {
        exists = true
    }
    return exists
}

func createTamTable(dataMap map[string]map[string]db.Value) {
   dataMap["ACL_TABLE"] = make(map[string]db.Value)
   dataMap["ACL_TABLE"]["TAM"] = db.Value{Field: make(map[string]string)}
   dataMap["ACL_TABLE"]["TAM"].Field["policy_desc"] = "TAM Features"
   dataMap["ACL_TABLE"]["TAM"].Field["ports@"] = "Switch"
   dataMap["ACL_TABLE"]["TAM"].Field["stage"] = "INGRESS"
   dataMap["ACL_TABLE"]["TAM"].Field["type"] = "TAM"
}

func anyTamFeaturesActive(d *db.DB) (bool) {
    ifaEnabled := false
    modEnabled := false
    tsEnabled := false

    var TAM_STATE_FEATURES_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_STATE_FEATURES_TABLE"}
    ifaEntry, _ := d.GetEntry(TAM_STATE_FEATURES_TABLE_TS, db.Key{Comp: []string{"IFA"}})
    if (ifaEntry.Field["op-status"] == "ACTIVE") {
        ifaEnabled = true
    }
    modEntry, _ := d.GetEntry(TAM_STATE_FEATURES_TABLE_TS, db.Key{Comp: []string{"DROPMONITOR"}})
    if (modEntry.Field["op-status"] == "ACTIVE") {
        modEnabled = true
    }
    tsEntry, _ := d.GetEntry(TAM_STATE_FEATURES_TABLE_TS, db.Key{Comp: []string{"TAILSTAMPING"}})
    if (tsEntry.Field["op-status"] == "ACTIVE") {
        tsEnabled = true
    }
    return (ifaEnabled || modEnabled || tsEnabled)
}

func getFeatureDetails(featuresMap map[string]db.Value, feature string) (bool, bool) {
    active := false
    exists := false
    if f, ok := featuresMap[feature]; ok {
        exists = true
        if (f.Field["status"] == "ACTIVE") {
            active = true
        }
    }
    return exists, active
}

var tam_post_xfmr PostXfmrFunc = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    pathInfo := NewPathInfo(inParams.uri)
    template := pathInfo.Template
    method := inParams.oper
    key := NewPathInfo(inParams.uri).Var("name")
    log.Info("key: ", key)
    feature, isSessionsUri := getSessionInfo(template)

    updateMap := make(map[db.DBNum]map[string]map[string]db.Value)
    updateMap[db.ConfigDB] = make(map[string]map[string]db.Value)
    var configDbPtr, _ = db.NewDB(getDBOptions(db.ConfigDB))
    var stateDbPtr, _ = db.NewDB(getDBOptions(db.StateDB))

    // check if we need to create TAM table
    if (method != DELETE) {
        if (!isTamTableExists(configDbPtr)) {
            if strings.Contains(template, FLOWGROUPS_TEMPLATE) {
                createTamTable((*inParams.dbDataMap)[db.ConfigDB])
            } else if strings.Contains(template, FEATURES_TEMPLATE) {
                if (key == "") {
                    features := (*inParams.dbDataMap)[db.ConfigDB]["TAM_FEATURES_TABLE"]
                    _, modEnabled := getFeatureDetails(features, "DROPMONITOR")
                    _, ifaEnabled := getFeatureDetails(features, "IFA")
                    _, tsEnabled := getFeatureDetails(features, "TAILSTAMPING")
                    if (modEnabled || ifaEnabled || tsEnabled) {
                        createTamTable((*inParams.dbDataMap)[db.ConfigDB])
                    }
                }
            }
        } else {
            if (strings.Contains(template, FEATURES_TEMPLATE)) {
                if (key == ""){
                    var TAM_FLOWGROUP_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_FLOWGROUP_TABLE"}
                    flowGroupTable, err := configDbPtr.GetTable(TAM_FLOWGROUP_TABLE_TS)
                    if (err == nil) {
                        flowGroupsKeys, _ := flowGroupTable.GetKeys()
                        flowGroupCount := len(flowGroupsKeys)
                        var TAM_STATE_FEATURES_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_STATE_FEATURES_TABLE"}
                        features := (*inParams.dbDataMap)[db.ConfigDB]["TAM_FEATURES_TABLE"]
                        modExists, modEnabled := getFeatureDetails(features, "DROPMONITOR")
                        ifaExists, ifaEnabled := getFeatureDetails(features, "IFA")
                        tsExists, tsEnabled := getFeatureDetails(features, "TAILSTAMPING")
                        if (!ifaExists) {
                            ifaEntry, _ := stateDbPtr.GetEntry(TAM_STATE_FEATURES_TABLE_TS, db.Key{Comp: []string{"IFA"}})
                            if (ifaEntry.Field["op-status"] == "ACTIVE") {
                                ifaEnabled = true
                            }
                        }
                        if (!modExists) {
                            modEntry, _ := stateDbPtr.GetEntry(TAM_STATE_FEATURES_TABLE_TS, db.Key{Comp: []string{"DROPMONITOR"}})
                            if (modEntry.Field["op-status"] == "ACTIVE") {
                                modEnabled = true
                            }
                        }
                        if (!tsExists) {
                            tsEntry, _ := stateDbPtr.GetEntry(TAM_STATE_FEATURES_TABLE_TS, db.Key{Comp: []string{"TAILSTAMPING"}})
                            if (tsEntry.Field["op-status"] == "ACTIVE") {
                                tsEnabled = true
                            }
                        }
                        noActiveTamFeatures := !(ifaEnabled || modEnabled || tsEnabled)
                        if ((flowGroupCount == 0) && noActiveTamFeatures) {
                           // delete TAM Table
                           updateMap[db.ConfigDB]["ACL_TABLE"] = make(map[string]db.Value)
                           updateMap[db.ConfigDB]["ACL_TABLE"]["TAM"] = db.Value{Field: make(map[string]string)}
                           inParams.subOpDataMap[DELETE] = &updateMap
                        }
                    }
                }
            }
        }
    } else {
        var TAM_FLOWGROUP_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_FLOWGROUP_TABLE"}
        flowGroupTable, err := configDbPtr.GetTable(TAM_FLOWGROUP_TABLE_TS)
        if (err == nil) {
            flowGroupsKeys, _ := flowGroupTable.GetKeys()
            anyFeaturesActive := anyTamFeaturesActive(stateDbPtr)
            if ((len(flowGroupsKeys) == 1) && !anyFeaturesActive) {
                if (key != "") {
                    found := false
                    for _, r := range flowGroupsKeys {
                        if (key == r.Get(0)) {
                            found = true
                            break
                        }
                    }
                    if (found) {
                        // delete TAM Table
                        resMap := make(map[string]map[string]db.Value)
                        aclTableMap := make(map[string]db.Value)
                        aclTableDbValues := db.Value{Field: map[string]string{}}
                        aclTableMap["TAM"] = aclTableDbValues
                        resMap["ACL_TABLE"] = aclTableMap
                        if inParams.subOpDataMap[method] != nil && (*inParams.subOpDataMap[method])[db.ConfigDB] != nil {
                            delete((*inParams.subOpDataMap[method])[db.ConfigDB], "ACL_RULE")
                            mapCopy((*inParams.subOpDataMap[method])[db.ConfigDB], resMap)
                        } else {
                            updateMap[db.ConfigDB]["ACL_TABLE"] = make(map[string]db.Value)
                            updateMap[db.ConfigDB]["ACL_TABLE"]["TAM"] = db.Value{Field: make(map[string]string)}
                            inParams.subOpDataMap[method] = &updateMap
                        }
                    }
                }
            }
        }
    }

    if (method == DELETE) {
        if (isSwitchTemplate(template)) {
            var SWITCH_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_SWITCH_TABLE"}
            switchTableEntry, _ := configDbPtr.GetEntry(SWITCH_TABLE_TS, db.Key{Comp: []string{"global"}})
            if (len(switchTableEntry.Field) == 1) {
                var existingKeyArray []string
                for k := range switchTableEntry.Field {
                    existingKeyArray = append(existingKeyArray, k)
                }
                requestMap := (*inParams.dbDataMap)[db.ConfigDB]["TAM_SWITCH_TABLE"]["global"].Field
                _, found := requestMap[existingKeyArray[0]]
                if found {
                    updateMap[db.ConfigDB]["TAM_SWITCH_TABLE"] = make(map[string]db.Value)
                    updateMap[db.ConfigDB]["TAM_SWITCH_TABLE"]["global"] = db.Value{Field: make(map[string]string)}
                    delete((*inParams.dbDataMap)[db.ConfigDB]["TAM_SWITCH_TABLE"], "global")
                    inParams.subOpDataMap[method] = &updateMap
                }
            }
        }
    }

    if (isSessionsUri) {
        updateMap[db.ConfigDB]["ACL_RULE"] = make(map[string]db.Value)
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

func getRecord(d *db.DB, cdb *db.DB, ruleEntry db.Value,  statEntry db.Value, lastStatEntry db.Value, name string) (AclRule, error) {
    var aclRule AclRule
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
    if (ruleEntry.Get("DST_IP") == "0.0.0.0/0") {
        aclRule.DstIp = ""
    } else {
        aclRule.DstIp = ruleEntry.Get("DST_IP")
    }
    if (ruleEntry.Get("SRC_IP") == "0.0.0.0/0") {
        aclRule.SrcIp = ""
    } else {
        aclRule.SrcIp = ruleEntry.Get("SRC_IP")
    }
    aclRule.SrcIpv6 = ruleEntry.Get("SRC_IPV6")
    aclRule.DstIpv6 = ruleEntry.Get("DST_IPV6")
    aclRule.L4SrcPort = ruleEntry.Get("L4_SRC_PORT")
    aclRule.L4DstPort = ruleEntry.Get("L4_DST_PORT")
    aclRule.TcpFlags = ruleEntry.Get("TCP_FLAGS")
    dscp, _ := strconv.ParseInt(ruleEntry.Get("DSCP"), 10, 32)
    aclRule.Dscp = uint8(dscp)
    aclRule.InPorts = ruleEntry.Get("IN_PORTS@")

    flowEntry, err := d.GetEntry(&db.TableSpec{Name: "TAM_FLOWGROUP_TABLE"}, db.Key{Comp: []string{name}})
    if err != nil {
        return aclRule, tlerr.NotFound("Resource Not Found")
    }
    id, _ := strconv.ParseInt(flowEntry.Get("id"), 10, 32)
    aclRule.Id = uint32(id)

    packets, _ := strconv.ParseInt(statEntry.Get("Packets"), 10, 64)
    lastPackets,_ := strconv.ParseInt(lastStatEntry.Get("Packets"), 10, 64)
    aclRule.packets = uint64(packets) - uint64(lastPackets)

    bytes, _ := strconv.ParseInt(statEntry.Get("Bytes"), 10, 64)
    lastBytes, _ := strconv.ParseInt(lastStatEntry.Get("Bytes"), 10, 64)
    aclRule.bytes = uint64(bytes) - uint64(lastBytes)

    return aclRule, err
}

func getFlowGroupsFromDb(d *db.DB, cdb *db.DB, name string) (map[string]AclRule, error) {
    var ruleEntries = make(map[string]AclRule)
    var err error
    var configDbPtr, _ = db.NewDB(getDBOptions(db.ConfigDB))
    var ACL_RULE_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "ACL_RULE"}
    aclRuleTable, _ := configDbPtr.GetTable(ACL_RULE_TABLE_TS)

    var countersDbPtr, _ = db.NewDB(getDBOptions(db.CountersDB))
    var ACL_COUNTERS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "COUNTERS"}
    
    var ACL_LAST_COUNTERS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "LAST_COUNTERS"}

    if name != "" {
        aclKey := "TAM|"+name
        ruleEntry, err := configDbPtr.GetEntry(ACL_RULE_TABLE_TS, db.Key{[]string{aclKey}})
        if err != nil {
            return ruleEntries, err
        }

        statKey := "TAM:"+name
        statEntry, e2 := countersDbPtr.GetEntry(ACL_COUNTERS_TABLE_TS, db.Key{[]string{statKey}})
        if e2 != nil {
            return ruleEntries, e2
        }
        
        lastStatKey := "TAM:"+name
        lastStatEntry, e3 := countersDbPtr.GetEntry(ACL_LAST_COUNTERS_TABLE_TS, db.Key{[]string{lastStatKey}})
        if e3 != nil {
            return ruleEntries, e3
        }

        record, _ := getRecord(d, cdb, ruleEntry, statEntry, lastStatEntry, name)
        ruleEntries[name] = record
    } else {
        keys, _ := aclRuleTable.GetKeys()
        for _, key := range keys {
            rule := key.Get(1)
            if (key.Get(0) == "TAM") {
                entry, _ := aclRuleTable.GetEntry(key)
                statKey := "TAM:"+rule
                statEntry, _ := countersDbPtr.GetEntry(ACL_COUNTERS_TABLE_TS, db.Key{[]string{statKey}})
                lastStatEntry, _ := countersDbPtr.GetEntry(ACL_LAST_COUNTERS_TABLE_TS, db.Key{[]string{statKey}})
                record, _ := getRecord(d, cdb, entry, statEntry, lastStatEntry, rule)
                ruleEntries[rule] = record
            }
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
    flowGroup.State.Statistics.Packets = &(entry.packets);
    flowGroup.State.Statistics.Bytes = &(entry.bytes);
    if (entry.InPorts != "") {
        flowGroup.Config.Interfaces = strings.Split(entry.InPorts, ",")
        flowGroup.State.Interfaces = strings.Split(entry.InPorts, ",")
    }

    // Ipv4
    if (entry.IpType == "IPV4ANY") {
        ygot.BuildEmptyTree(flowGroup.Ipv4)
        ygot.BuildEmptyTree(flowGroup.Ipv4.Config)
        ygot.BuildEmptyTree(flowGroup.Ipv4.State)
        if (entry.SrcIp != "") {flowGroup.Ipv4.Config.SourceAddress = &(entry.SrcIp)}
        if (entry.SrcIp != "") {flowGroup.Ipv4.State.SourceAddress = &(entry.SrcIp)}
        if (entry.DstIp != "") {flowGroup.Ipv4.Config.DestinationAddress = &(entry.DstIp)}
        if (entry.DstIp != "") {flowGroup.Ipv4.State.DestinationAddress = &(entry.DstIp)}
        if (entry.Dscp != 0) {flowGroup.Ipv4.Config.Dscp = &(entry.Dscp)}
        if (entry.Dscp != 0) {flowGroup.Ipv4.State.Dscp = &(entry.Dscp)}
        if (entry.IpProtocol != "") {
            ipProto, _ := strconv.ParseInt(entry.IpProtocol, 10, 64)
            protocolVal := getIpProtocol(ipProto)
            flowGroup.Ipv4.Config.Protocol, _ = flowGroup.Ipv4.Config.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_Config_Protocol_Union(protocolVal)
            flowGroup.Ipv4.State.Protocol, _ = flowGroup.Ipv4.State.To_OpenconfigTam_Tam_Flowgroups_Flowgroup_Ipv4_State_Protocol_Union(protocolVal)
        }
    }

    // Ipv6
    if (entry.IpType == "IPV6ANY") {
        ygot.BuildEmptyTree(flowGroup.Ipv6)
        ygot.BuildEmptyTree(flowGroup.Ipv6.Config)
        ygot.BuildEmptyTree(flowGroup.Ipv6.State)
        if (entry.SrcIpv6 != "") {flowGroup.Ipv6.Config.SourceAddress = &(entry.SrcIpv6)}
        if (entry.SrcIpv6 != "") {flowGroup.Ipv6.State.SourceAddress = &(entry.SrcIpv6)}
        if (entry.DstIpv6 != "") {flowGroup.Ipv6.Config.DestinationAddress = &(entry.DstIpv6)}
        if (entry.DstIpv6 != "") {flowGroup.Ipv6.State.DestinationAddress = &(entry.DstIpv6)}
        if (entry.Dscp != 0) {flowGroup.Ipv6.Config.Dscp = &(entry.Dscp)}
        if (entry.Dscp != 0) {flowGroup.Ipv6.State.Dscp = &(entry.Dscp)}
        if (entry.IpProtocol != "") {
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

func fillFlowgroupInfo(flowGroups *ocbinds.OpenconfigTam_Tam_Flowgroups, name string, targetUriPath string, uri string, d *db.DB, cdb *db.DB) (error) {
    ruleEntries , err := getFlowGroupsFromDb(d, cdb, name)
    if err == nil {
        for k, v := range ruleEntries {
            err = appendFlowGroupToYang(flowGroups, k, v)
        }
    }
    return err
}

func getFlowGroups(tamObj *ocbinds.OpenconfigTam_Tam, targetUriPath string, uri string, d *db.DB, cdb *db.DB) (error) {
    name := NewPathInfo(uri).Var("name")
    ygot.BuildEmptyTree(tamObj)
    ygot.BuildEmptyTree(tamObj.Flowgroups)
    return fillFlowgroupInfo(tamObj.Flowgroups, name, targetUriPath, uri, d, cdb)
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
        return getFlowGroups(tamObj, targetUriPath, uri, inParams.dbs[db.ConfigDB], inParams.dbs[db.CountersDB])
    }
}

var YangToDb_tam_flowgroups_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {
    var err error
    res_map := make(map[string]map[string]db.Value)

    tamObj := getTamRoot(inParams.ygRoot)
    method := inParams.oper

    pathInfo := NewPathInfo(inParams.uri)
    key := pathInfo.Var("name")
    template := pathInfo.Template

    updateMap := make(map[db.DBNum]map[string]map[string]db.Value)
    updateMap[db.ConfigDB] = make(map[string]map[string]db.Value)

    var configDbPtr, _ = db.NewDB(getDBOptions(db.ConfigDB))
    var TAM_FLOWGROUP_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "TAM_FLOWGROUP_TABLE"}
    var ACL_RULE_TABLE_TS *db.TableSpec = &db.TableSpec{Name: "ACL_RULE"}
    flowGroupTable, _ := configDbPtr.GetTable(TAM_FLOWGROUP_TABLE_TS)
    flowGroupsKeys, _ := flowGroupTable.GetKeys()

    set := make(map[string]bool)
    existingFlowGroups := make(map[string]db.Value)
    for _, v := range flowGroupsKeys {
        flowEntry, _ := flowGroupTable.GetEntry(v)
        id := flowEntry.Get("id")
        set[id] = true
        existingFlowGroups[v.Get(0)] = db.Value{Field: make(map[string]string)}
        aclKey := "TAM|"+v.Get(0)
        aclEntry, err := configDbPtr.GetEntry(ACL_RULE_TABLE_TS, db.Key{[]string{aclKey}})
        if (err == nil) {
            existingFlowGroups[v.Get(0)] = aclEntry
            existingFlowGroups[v.Get(0)].Field["id"] = id
        }
    }

    currentSet := make(map[string]bool)
    if key != "" {
        if (method == DELETE) {
            flowGroupName := pathInfo.Var("name")
            aclKey := "TAM|"+flowGroupName
            if (template == FLOWGROUP_INTERFACE_CFG_TEMPLATE) {
                intf := pathInfo.Var("interfaces")
                inports := existingFlowGroups[flowGroupName].Field["IN_PORTS@"]
                if (inports != "") {
                    s := strings.Split(inports, ",")
                    tmp := make(map[string]bool)
                    for _, v := range s {
                        tmp[v] = true
                    }
                    if (tmp[intf]) {
                        updateMap[db.ConfigDB]["ACL_RULE"] = make(map[string]db.Value)
                        updateMap[db.ConfigDB]["ACL_RULE"][aclKey] = db.Value{Field: make(map[string]string)}
                        updateMap[db.ConfigDB]["ACL_RULE"][aclKey].Field["IN_PORTS@"] = intf
                    } else {
                        errStr := fmt.Sprintf("Flowgroup (%v) is not associated with interface (%v).", key, intf)
                        err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                        return res_map, err
                    }
                } else {
                    errStr := fmt.Sprintf("Flowgroup (%v) is not associated with interface (%v).", key, intf)
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
            } else if (template == FLOWGROUP_CFG_TEMPLATE) {
                updateMap[db.ConfigDB]["ACL_RULE"] = make(map[string]db.Value)
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"] = make(map[string]db.Value)
                updateMap[db.ConfigDB]["ACL_RULE"][aclKey] = db.Value{Field: make(map[string]string)}
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][flowGroupName] = db.Value{Field: make(map[string]string)}
            }
            inParams.subOpDataMap[DELETE] = &updateMap
        } else if (method == CREATE) {
            errStr := fmt.Sprintf("Flowgroup (%v) is already present", key)
            err = tlerr.AlreadyExistsError{AppTag: "invalid-value", Path: "", Format: errStr}
            return res_map, err
        }
    } else {
        if (method == DELETE) {
            updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"] = make(map[string]db.Value)
            updateMap[db.ConfigDB]["ACL_RULE"] = make(map[string]db.Value)
            for _, k := range flowGroupsKeys {
                entry_key := k.Get(0)
                aclKey := "TAM|"+entry_key
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][entry_key] = db.Value{Field: make(map[string]string)}
                updateMap[db.ConfigDB]["ACL_RULE"][aclKey] = db.Value{Field: make(map[string]string)}
            }
            inParams.subOpDataMap[DELETE] = &updateMap
        } else {
            updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"] = make(map[string]db.Value)
            updateMap[db.ConfigDB]["ACL_RULE"] = make(map[string]db.Value)
            for thiskey, flowgroup := range tamObj.Flowgroups.Flowgroup {
                entry_key := "TAM|"+thiskey
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key] = db.Value{Field: make(map[string]string)}

                // mandatory
                if flowgroup.Config.Id == nil {
                    errStr := "key field id (uint32) has nil value."
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                id := strconv.FormatInt(int64(*flowgroup.Config.Id), 10)
                if val, ok := existingFlowGroups[thiskey].Field["id"]; ok {
                    if (val != id) {
                        errStr := fmt.Sprintf("Flowgroup name(%v) and id(%v) are not matching.", thiskey, *flowgroup.Config.Id)
                        err = tlerr.AlreadyExistsError{AppTag: "invalid-value", Path: "", Format: errStr}
                        return res_map, err
                    }
                } else {
                    if (set[id]) {
                        errStr := fmt.Sprintf("Flowgroup id(%v) is used by other flowgroup.", *flowgroup.Config.Id)
                        err = tlerr.AlreadyExistsError{AppTag: "invalid-value", Path: "", Format: errStr}
                        return res_map, err
                    }
                }
                if (currentSet[id]) {
                    errStr := fmt.Sprintf("Duplicate id (%v) present in the payload.", *flowgroup.Config.Id)
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                if flowgroup.Config.Name == nil {
                    errStr := "key field name (*string) has nil value."
                    err = tlerr.InvalidArgsError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                if flowgroup.L2 != nil && flowgroup.L2.Config != nil {
                    errStr := "L2 match criterion for flowgroups is not supported."
                    err = tlerr.NotSupportedError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                if flowgroup.Ipv6 != nil && flowgroup.Ipv6.Config != nil {
                    errStr := "IPv6 flowgroups are not supported."
                    err = tlerr.NotSupportedError{AppTag: "invalid-value", Path: "", Format: errStr}
                    return res_map, err
                }
                priority := "100"
                if (flowgroup.Config.Priority != nil) {
                    priority = strconv.FormatInt(int64(*(flowgroup.Config.Priority)), 10)
                }
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["PRIORITY"] = priority

                // update interfaces
                if (flowgroup.Config.Interfaces != nil) {
                    interfaces := flowgroup.Config.Interfaces
                    updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IN_PORTS@"] = strings.Join(interfaces, ",")
                }

                // IPv4
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_TYPE"] = "IPV4ANY"
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["SRC_IP"] = "0.0.0.0/0"
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["DST_IP"] = "0.0.0.0/0"
                updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_PROTOCOL"] = "17"
                if _, ok := existingFlowGroups[thiskey].Field["id"]; ok {
                    if (existingFlowGroups[thiskey].Field["protocol"] != "17") {
                        updateMap[db.ConfigDB]["ACL_RULE"][entry_key].Field["IP_PROTOCOL"] = existingFlowGroups[thiskey].Field["IP_PROTOCOL"]
                    }
                }
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
                        errStr := "Parameter hop-limit is not supported."
                        err = tlerr.NotSupportedError{AppTag: "invalid-value", Path: "", Format: errStr}
                        return res_map, err
                    }
                }

                // IPv6
                if flowgroup.Ipv6 != nil && flowgroup.Ipv6.Config != nil {
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
                updateMap[db.ConfigDB]["TAM_FLOWGROUP_TABLE"][thiskey].Field["id"] = id
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

var rpc_clear_flowgroup_counters_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        var out_list []string
        var exec_cmd_list []string
        log.Info("rpc_clear_flowgroup_counters_cb body:", string(body))

        var result struct {
                Output struct {
                        Status int32 `json:"status"`
                        Status_detail []string`json:"status-detail"`
                } `json:"openconfig-tam:output"`
        }

        var operand struct {
                Input struct {
                     Name string `json:"name"`
                } `json:"openconfig-tam:input"`
        }

       err := json.Unmarshal(body, &operand)
       if err != nil {
                result.Output.Status = 1
                out_list = append(out_list, "[FAILED] unmarshal input: " + err.Error())
                result.Output.Status_detail  = out_list
                return json.Marshal(&result)
       }
       name := operand.Input.Name

       if name != "" {
           exec_cmd_list = append(exec_cmd_list, "aclshow -c -r")
           exec_cmd_list = append(exec_cmd_list,   name)
        } else {
           exec_cmd_list = append(exec_cmd_list, "aclshow -c -t TAM")
        }
       
       exec_cmd := strings.Join(exec_cmd_list," ")

    return counters_clear_operation(exec_cmd)
}

func counters_clear_operation(exec_cmd string) ([]byte, error) {

   log.Info("counters_clear_operation cmd:", exec_cmd)
        var out_list []string

    var result struct {
            Output struct {
                Status int32 `json:"status"`
                Status_detail []string`json:"status-detail"`
            } `json:"openconfig-tam:output"`
        }


        host_output := HostQuery("infra_host.exec_cmd", exec_cmd)
        if host_output.Err != nil {
              log.Errorf("counters_clear_operation: host Query FAILED: err=%v", host_output.Err)
              result.Output.Status = 1
              out_list  = append(out_list, host_output.Err.Error()) 
              out_list  = append(out_list, "[ FAILED ] host query") 
              result.Output.Status_detail  = out_list 
              return json.Marshal(&result)
        }

        var output string
        output, _ = host_output.Body[1].(string)
        _output := strings.TrimLeft(output,"\n")
        failure_status :=  strings.Contains(_output, "FAILED")
        success_status :=  strings.Contains(_output, "SUCCESS")

        if (failure_status || !success_status) {
           out_list = strings.Split(_output,"\n")
        } else { 
           _out_list := strings.Split(_output,"\n")
           for index, each := range _out_list {
                 i := strings.Index(each, "SUCCESS")
                 if i != -1 {
                     out_list = append(out_list, _out_list[index])
                 }
           }
        }

        result.Output.Status = 0
        result.Output.Status_detail  = out_list 
        return json.Marshal(&result)
}


