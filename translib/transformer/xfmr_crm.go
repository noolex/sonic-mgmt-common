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
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "strconv"
    "strings"
    ygot "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
)

type CrmThreshold struct {
    aclGroupType            ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    aclGroupHigh            uint32
    aclGroupLow             uint32
    aclCounterType          ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    aclCounterHigh          uint32
    aclCounterLow           uint32
    aclEntryType            ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    aclEntryHigh            uint32
    aclEntryLow             uint32
    aclTableType            ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    aclTableHigh            uint32
    aclTableLow             uint32
    dnatType                ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    dnatHigh                uint32
    dnatLow                 uint32
    snatType                ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    snatHigh                uint32
    snatLow                 uint32
    fdbType                 ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    fdbHigh                 uint32
    fdbLow                  uint32
    ipmcType                ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    ipmcHigh                uint32
    ipmcLow                 uint32
    ipv4NeighborType        ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    ipv4NeighborHigh        uint32
    ipv4NeighborLow         uint32
    ipv4NexthopType         ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    ipv4NexthopHigh         uint32
    ipv4NexthopLow          uint32
    ipv4RouteType           ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    ipv4RouteHigh           uint32
    ipv4RouteLow            uint32
    ipv6NeighborType        ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    ipv6NeighborHigh        uint32
    ipv6NeighborLow         uint32
    ipv6NexthopType         ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    ipv6NexthopHigh         uint32
    ipv6NexthopLow          uint32
    ipv6RouteType           ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    ipv6RouteHigh           uint32
    ipv6RouteLow            uint32
    nexthopGroupMemberType  ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    nexthopGroupMemberHigh  uint32
    nexthopGroupMemberLow   uint32
    nexthopGroupType        ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType
    nexthopGroupHigh        uint32
    nexthopGroupLow         uint32
}

type CrmStats struct {
    dnatFree                uint32
    dnatUsed                uint32
    fdbFree                 uint32
    fdbUsed                 uint32
    ipmcFree                uint32
    ipmcUsed                uint32
    ipv4NeighborFree        uint32
    ipv4NeighborUsed        uint32
    ipv4NexthopFree         uint32
    ipv4NexthopUsed         uint32
    ipv4RouteFree           uint32
    ipv4RouteUsed           uint32
    ipv6NeighborFree        uint32
    ipv6NeighborUsed        uint32
    ipv6NexthopFree         uint32
    ipv6NexthopUsed         uint32
    ipv6RouteFree           uint32
    ipv6RouteUsed           uint32
    nexthopGroupMemberFree  uint32
    nexthopGroupMemberUsed  uint32
    nexthopGroupFree        uint32
    nexthopGroupUsed        uint32
    snatFree                uint32
    snatUsed                uint32
}

type CrmAclStats struct {
    groupFree               uint32
    groupUsed               uint32
    tableFree               uint32
    tableUsed               uint32
}

var dataAclStats [10]CrmAclStats

func init() {
    XlateFuncBind("YangToDb_crm_config_xfmr", YangToDb_crm_config_xfmr)
    XlateFuncBind("DbToYang_crm_config_xfmr", DbToYang_crm_config_xfmr)
    XlateFuncBind("DbToYang_crm_stats_xfmr", DbToYang_crm_stats_xfmr)
    XlateFuncBind("DbToYang_crm_acl_stats_xfmr", DbToYang_crm_acl_stats_xfmr)
    XlateFuncBind("DbToYang_crm_acl_table_stats_xfmr", DbToYang_crm_acl_table_stats_xfmr)
}

// getUint32 returns value of a field as uint32. Returns 0 if the field does
// not exists.
func getUint32(v db.Value, name string) (uint32, bool) {
    data, ok := v.Field[name]
    if ok {
        n, _ := strconv.ParseUint(data, 10, 32)
        return uint32(n), ok
    }
    return 0, false
}

// getThresholdTypeId returns value of a field as uppercase string. Returns "" if the field does
// not exists.
func getThresholdTypeId(v db.Value, name string) ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType {
    data, ok := v.Field[name]
    if ok {
        if data == "used" {
            return ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_USED
        } else if data == "free" {
            return ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_FREE
        } else if data == "percentage" {
            return ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_PERCENTAGE
        }
    }
    return ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET
}

var DbToYang_crm_config_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    var info CrmThreshold
    var all bool
    var has_hi bool
    var has_lo bool

    log.Infof("+++ DbToYang: crm_config_xfmr (%v) +++", inParams.uri)

    inParams.table = "CRM"
    inParams.key = "Config"
    tbl := db.TableSpec { Name: inParams.table }
    key := db.Key { Comp : [] string { inParams.key } }
    d := inParams.dbs[db.ConfigDB]
    d.Opts.KeySeparator = "|"
    d.Opts.TableNameSeparator = "|"

    val, err := d.GetEntry(&tbl, key)

    if err != nil {
        log.Infof("ERR: unable to get entry from database")
        return err
    }

    uri := ""
    dev := (*inParams.ygRoot).(*ocbinds.Device)
    idx := strings.Index(inParams.uri, ":crm")
    if idx >= 0 {
        uri = inParams.uri[idx+1:]
    }

    if uri == "crm" {
        ygot.BuildEmptyTree(dev.System.Crm)
    } else if uri == "crm/threshold" {
        ygot.BuildEmptyTree(dev.System.Crm.Threshold)
    }

    if (uri == "crm") || strings.Contains(inParams.uri, "crm/config") {
        ygot.BuildEmptyTree(dev.System.Crm.Config)
        sec, ok := getUint32(val, "polling_interval")
        if ok {
            dev.System.Crm.Config.PollingInterval = &sec
        }
        return nil
    }

    if (uri == "crm") || strings.Contains(inParams.uri, "crm/state") {
        ygot.BuildEmptyTree(dev.System.Crm.State)
        sec, ok := getUint32(val, "polling_interval")
        if ok {
            dev.System.Crm.State.PollingInterval = &sec
        }
        return nil
    }

    if !(uri == "crm") && !strings.Contains(inParams.uri, "crm/threshold") {
        return nil
    }

    uri = "/"
    idx = strings.Index(inParams.uri, "crm/threshold")
    if idx >= 0 {
        uri = inParams.uri[idx+13:]
    }
    log.Infof("*** URI: '%v'", uri)

    cfg := dev.System.Crm.Threshold
    if len(uri) <= 1 {
        all = true
    } else {
        all = false
    }

    info.fdbType = getThresholdTypeId(val, "fdb_entry_threshold_type")
    info.fdbHigh, has_hi = getUint32(val, "fdb_entry_high_threshold")
    info.fdbLow , has_lo = getUint32(val, "fdb_entry_low_threshold")
    if all || strings.Contains(uri, "/fdb") {
        ygot.BuildEmptyTree(cfg.Fdb)
        cfg.Fdb.Config.Type = info.fdbType
        cfg.Fdb.State.Type  = info.fdbType
        if has_hi {
            cfg.Fdb.Config.High = &info.fdbHigh
            cfg.Fdb.State.High  = &info.fdbHigh
        }
        if has_lo {
            cfg.Fdb.Config.Low  = &info.fdbLow
            cfg.Fdb.State.Low   = &info.fdbLow
        }
    }

    info.ipmcType = getThresholdTypeId(val, "ipmc_entry_threshold_type")
    info.ipmcHigh, has_hi = getUint32(val, "ipmc_entry_high_threshold")
    info.ipmcLow , has_lo = getUint32(val, "ipmc_entry_low_threshold")
    if all || strings.Contains(uri, "/ipmc") {
        ygot.BuildEmptyTree(cfg.Ipmc)
        cfg.Ipmc.Config.Type = info.ipmcType
        cfg.Ipmc.State.Type  = info.ipmcType
        if has_hi {
            cfg.Ipmc.Config.High = &info.ipmcHigh
            cfg.Ipmc.State.High  = &info.ipmcHigh
        }
        if has_lo {
            cfg.Ipmc.Config.Low  = &info.ipmcLow
            cfg.Ipmc.State.Low   = &info.ipmcLow
        }
    }

    info.dnatType = getThresholdTypeId(val, "dnat_entry_threshold_type")
    info.dnatHigh, has_hi = getUint32(val, "dnat_entry_high_threshold")
    info.dnatLow , has_lo = getUint32(val, "dnat_entry_low_threshold")
    if all || strings.Contains(uri, "/dnat") {
        ygot.BuildEmptyTree(cfg.Dnat)
        cfg.Dnat.Config.Type = info.dnatType
        cfg.Dnat.State.Type  = info.dnatType
        if has_hi {
            cfg.Dnat.Config.High = &info.dnatHigh
            cfg.Dnat.State.High  = &info.dnatHigh
        }
        if has_lo {
            cfg.Dnat.Config.Low  = &info.dnatLow
            cfg.Dnat.State.Low   = &info.dnatLow
        }
    }

    info.snatType = getThresholdTypeId(val, "snat_entry_threshold_type")
    info.snatHigh, has_hi = getUint32(val, "snat_entry_high_threshold")
    info.snatLow , has_lo = getUint32(val, "snat_entry_low_threshold")
    if all || strings.Contains(uri, "/snat") {
        ygot.BuildEmptyTree(cfg.Snat)
        cfg.Snat.Config.Type = info.snatType
        cfg.Snat.State.Type  = info.snatType
        if has_hi {
            cfg.Snat.Config.High = &info.snatHigh
            cfg.Snat.State.High  = &info.snatHigh
        }
        if has_lo {
            cfg.Snat.Config.Low  = &info.snatLow
            cfg.Snat.State.Low   = &info.snatLow
        }
    }

    if (uri == "/ipv4") {
        ygot.BuildEmptyTree(cfg.Ipv4)
    }

    info.ipv4NeighborType = getThresholdTypeId(val, "ipv4_neighbor_threshold_type")
    info.ipv4NeighborHigh, has_hi = getUint32(val, "ipv4_neighbor_high_threshold")
    info.ipv4NeighborLow , has_lo = getUint32(val, "ipv4_neighbor_low_threshold")
    if all || (uri == "/ipv4") || strings.Contains(uri, "/ipv4/neighbor") {
        ygot.BuildEmptyTree(cfg.Ipv4.Neighbor)
        cfg.Ipv4.Neighbor.Config.Type = info.ipv4NeighborType
        cfg.Ipv4.Neighbor.State.Type  = info.ipv4NeighborType
        if has_hi {
            cfg.Ipv4.Neighbor.Config.High = &info.ipv4NeighborHigh
            cfg.Ipv4.Neighbor.State.High  = &info.ipv4NeighborHigh
        }
        if has_lo {
            cfg.Ipv4.Neighbor.Config.Low  = &info.ipv4NeighborLow
            cfg.Ipv4.Neighbor.State.Low   = &info.ipv4NeighborLow
        }
    }

    info.ipv4NexthopType = getThresholdTypeId(val, "ipv4_nexthop_threshold_type")
    info.ipv4NexthopHigh, has_hi = getUint32(val, "ipv4_nexthop_high_threshold")
    info.ipv4NexthopLow , has_lo = getUint32(val, "ipv4_nexthop_low_threshold")
    if all || (uri == "/ipv4") || strings.Contains(uri, "/ipv4/nexthop") {
        ygot.BuildEmptyTree(cfg.Ipv4.Nexthop)
        cfg.Ipv4.Nexthop.Config.Type = info.ipv4NexthopType
        cfg.Ipv4.Nexthop.State.Type  = info.ipv4NexthopType
        if has_hi {
            cfg.Ipv4.Nexthop.Config.High = &info.ipv4NexthopHigh
            cfg.Ipv4.Nexthop.State.High  = &info.ipv4NexthopHigh
        }
        if has_lo {
            cfg.Ipv4.Nexthop.Config.Low  = &info.ipv4NexthopLow
            cfg.Ipv4.Nexthop.State.Low   = &info.ipv4NexthopLow
        }
    }

    info.ipv4RouteType = getThresholdTypeId(val, "ipv4_route_threshold_type")
    info.ipv4RouteHigh, has_hi = getUint32(val, "ipv4_route_high_threshold")
    info.ipv4RouteLow , has_lo = getUint32(val, "ipv4_route_low_threshold")
    if all || (uri == "/ipv4") || strings.Contains(uri, "/ipv4/route") {
        ygot.BuildEmptyTree(cfg.Ipv4.Route)
        cfg.Ipv4.Route.Config.Type = info.ipv4RouteType
        cfg.Ipv4.Route.State.Type  = info.ipv4RouteType
        if has_hi {
            cfg.Ipv4.Route.Config.High = &info.ipv4RouteHigh
            cfg.Ipv4.Route.State.High  = &info.ipv4RouteHigh
        }
        if has_lo {
            cfg.Ipv4.Route.Config.Low  = &info.ipv4RouteLow
            cfg.Ipv4.Route.State.Low   = &info.ipv4RouteLow
        }
    }

    if (uri == "/ipv6") {
        ygot.BuildEmptyTree(cfg.Ipv6)
    }

    info.ipv6NeighborType = getThresholdTypeId(val, "ipv6_neighbor_threshold_type")
    info.ipv6NeighborHigh, has_hi = getUint32(val, "ipv6_neighbor_high_threshold")
    info.ipv6NeighborLow , has_lo = getUint32(val, "ipv6_neighbor_low_threshold")
    if all || (uri == "/ipv6") || strings.Contains(uri, "/ipv6/neighbor") {
        ygot.BuildEmptyTree(cfg.Ipv6.Neighbor)
        cfg.Ipv6.Neighbor.Config.Type = info.ipv6NeighborType
        cfg.Ipv6.Neighbor.State.Type  = info.ipv6NeighborType
        if has_hi {
            cfg.Ipv6.Neighbor.Config.High = &info.ipv6NeighborHigh
            cfg.Ipv6.Neighbor.State.High  = &info.ipv6NeighborHigh
        }
        if has_lo {
            cfg.Ipv6.Neighbor.Config.Low  = &info.ipv6NeighborLow
            cfg.Ipv6.Neighbor.State.Low   = &info.ipv6NeighborLow
        }
    }

    info.ipv6NexthopType = getThresholdTypeId(val, "ipv6_nexthop_threshold_type")
    info.ipv6NexthopHigh, has_hi = getUint32(val, "ipv6_nexthop_high_threshold")
    info.ipv6NexthopLow , has_lo = getUint32(val, "ipv6_nexthop_low_threshold")
    if all || (uri == "/ipv6") || strings.Contains(uri, "/ipv6/nexthop") {
        ygot.BuildEmptyTree(cfg.Ipv6.Nexthop)
        cfg.Ipv6.Nexthop.Config.Type = info.ipv6NexthopType
        cfg.Ipv6.Nexthop.State.Type  = info.ipv6NexthopType
        if has_hi {
            cfg.Ipv6.Nexthop.Config.High = &info.ipv6NexthopHigh
            cfg.Ipv6.Nexthop.State.High  = &info.ipv6NexthopHigh
        }
        if has_lo {
            cfg.Ipv6.Nexthop.Config.Low  = &info.ipv6NexthopLow
            cfg.Ipv6.Nexthop.State.Low   = &info.ipv6NexthopLow
        }
    }

    info.ipv6RouteType = getThresholdTypeId(val, "ipv6_route_threshold_type")
    info.ipv6RouteHigh, has_hi = getUint32(val, "ipv6_route_high_threshold")
    info.ipv6RouteLow , has_lo = getUint32(val, "ipv6_route_low_threshold")
    if all || (uri == "/ipv6") || strings.Contains(uri, "/ipv6/route") {
        ygot.BuildEmptyTree(cfg.Ipv6.Route)
        cfg.Ipv6.Route.Config.Type = info.ipv6RouteType
        cfg.Ipv6.Route.State.Type  = info.ipv6RouteType
        if has_hi {
            cfg.Ipv6.Route.Config.High = &info.ipv6RouteHigh
            cfg.Ipv6.Route.State.High  = &info.ipv6RouteHigh
        }
        if has_lo {
            cfg.Ipv6.Route.Config.Low  = &info.ipv6RouteLow
            cfg.Ipv6.Route.State.Low   = &info.ipv6RouteLow
        }
    }

    if uri == "nexthop" {
        ygot.BuildEmptyTree(cfg.Nexthop)
    }

    info.nexthopGroupMemberType = getThresholdTypeId(val, "nexthop_group_member_threshold_type")
    info.nexthopGroupMemberHigh, has_hi = getUint32(val, "nexthop_group_member_high_threshold")
    info.nexthopGroupMemberLow , has_lo = getUint32(val, "nexthop_group_member_low_threshold")
    if all || (uri == "/nexthop") || strings.Contains(uri, "/nexthop/group-member") {
        ygot.BuildEmptyTree(cfg.Nexthop.GroupMember)
        cfg.Nexthop.GroupMember.Config.Type = info.nexthopGroupMemberType
        cfg.Nexthop.GroupMember.State.Type  = info.nexthopGroupMemberType
        if has_hi {
            cfg.Nexthop.GroupMember.Config.High = &info.nexthopGroupMemberHigh
            cfg.Nexthop.GroupMember.State.High  = &info.nexthopGroupMemberHigh
        }
        if has_lo {
            cfg.Nexthop.GroupMember.Config.Low  = &info.nexthopGroupMemberLow
            cfg.Nexthop.GroupMember.State.Low   = &info.nexthopGroupMemberLow
        }
    }

    info.nexthopGroupType = getThresholdTypeId(val, "nexthop_group_threshold_type")
    info.nexthopGroupHigh, has_hi = getUint32(val, "nexthop_group_high_threshold")
    info.nexthopGroupLow , has_lo = getUint32(val, "nexthop_group_low_threshold")
    if all || (uri == "/nexthop") || strings.Contains(uri, "/nexthop/group-object") {
        ygot.BuildEmptyTree(cfg.Nexthop.GroupObject)
        cfg.Nexthop.GroupObject.Config.Type = info.nexthopGroupType
        cfg.Nexthop.GroupObject.State.Type  = info.nexthopGroupType
        if has_hi {
            cfg.Nexthop.GroupObject.Config.High = &info.nexthopGroupHigh
            cfg.Nexthop.GroupObject.State.High  = &info.nexthopGroupHigh
        }
        if has_lo {
            cfg.Nexthop.GroupObject.Config.Low  = &info.nexthopGroupLow
            cfg.Nexthop.GroupObject.State.Low   = &info.nexthopGroupLow
        }
    }

    if uri == "acl" {
        ygot.BuildEmptyTree(cfg.Acl)
    }

    info.aclGroupType = getThresholdTypeId(val, "acl_group_threshold_type")
    info.aclGroupHigh, has_hi = getUint32(val, "acl_group_high_threshold")
    info.aclGroupLow , has_lo = getUint32(val, "acl_group_low_threshold")
    if all || (uri == "/acl") || (uri == "/acl/group") || (uri == "/acl/group/config") || (uri == "/acl/group/state") {
        ygot.BuildEmptyTree(cfg.Acl.Group)
        cfg.Acl.Group.Config.Type = info.aclGroupType
        cfg.Acl.Group.State.Type = info.aclGroupType
        if has_hi {
            cfg.Acl.Group.Config.High = &info.aclGroupHigh
            cfg.Acl.Group.State.High = &info.aclGroupHigh
        }
        if has_lo {
            cfg.Acl.Group.Config.Low  = &info.aclGroupLow
            cfg.Acl.Group.State.Low  = &info.aclGroupLow
        }
    }

    info.aclCounterType = getThresholdTypeId(val, "acl_counter_threshold_type")
    info.aclCounterHigh, has_hi = getUint32(val, "acl_counter_high_threshold")
    info.aclCounterLow , has_lo = getUint32(val, "acl_counter_low_threshold")
    if all || (uri == "/acl") || (uri == "/acl/group") || strings.Contains(uri, "/acl/group/counter") {
        ygot.BuildEmptyTree(cfg.Acl.Group.Counter)
        cfg.Acl.Group.Counter.Config.Type = info.aclCounterType
        cfg.Acl.Group.Counter.State.Type  = info.aclCounterType
        if has_hi {
            cfg.Acl.Group.Counter.Config.High = &info.aclCounterHigh
            cfg.Acl.Group.Counter.State.High  = &info.aclCounterHigh
        }
        if has_lo {
            cfg.Acl.Group.Counter.Config.Low  = &info.aclCounterLow
            cfg.Acl.Group.Counter.State.Low   = &info.aclCounterLow
        }
    }

    info.aclEntryType = getThresholdTypeId(val, "acl_entry_threshold_type")
    info.aclEntryHigh, has_hi = getUint32(val, "acl_entry_high_threshold")
    info.aclEntryLow , has_lo = getUint32(val, "acl_entry_low_threshold")
    if all || (uri == "/acl") || (uri == "/acl/group") || strings.Contains(uri, "/acl/group/entry") {
        ygot.BuildEmptyTree(cfg.Acl.Group.Entry)
        cfg.Acl.Group.Entry.Config.Type = info.aclEntryType
        cfg.Acl.Group.Entry.State.Type  = info.aclEntryType
        if has_hi {
            cfg.Acl.Group.Entry.Config.High = &info.aclEntryHigh
            cfg.Acl.Group.Entry.State.High  = &info.aclEntryHigh
        }
        if has_lo {
            cfg.Acl.Group.Entry.Config.Low  = &info.aclEntryLow
            cfg.Acl.Group.Entry.State.Low   = &info.aclEntryLow
        }
    }

    info.aclTableType = getThresholdTypeId(val, "acl_table_threshold_type")
    info.aclTableHigh, has_hi = getUint32(val, "acl_table_high_threshold")
    info.aclTableLow , has_lo = getUint32(val, "acl_table_low_threshold")
    if all || (uri == "/acl") || strings.Contains(uri, "/acl/table") {
        ygot.BuildEmptyTree(cfg.Acl.Table)
        cfg.Acl.Table.Config.Type = info.aclTableType
        cfg.Acl.Table.State.Type  = info.aclTableType
        if has_hi {
            cfg.Acl.Table.Config.High = &info.aclTableHigh
            cfg.Acl.Table.State.High  = &info.aclTableHigh
        }
        if has_lo {
            cfg.Acl.Table.Config.Low  = &info.aclTableLow
            cfg.Acl.Table.State.Low   = &info.aclTableLow
        }
    }

    return nil
}

func getThresholdType(t ocbinds.E_OpenconfigSystemCrm_SystemCrmThresholdType) string {

    switch (t) {
    case ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_USED:
        return "used"
    case ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_FREE:
        return "free"
    case ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_PERCENTAGE:
        return "percentage"
    default:
    }

    return ""
}

func getUint32String(v uint32) string {
    return strconv.FormatInt(int64(v), 10)
}

var YangToDb_crm_config_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error) {

    value := db.Value {make(map[string]string)}
    cfgMap := make(map[string]map[string]db.Value)
    subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
    subOpMap_del := make(map[string]map[string]db.Value)

    log.Infof("+++ YangToDb: crm_config_xfmr (%v) +++", inParams.uri)

    tblName := "CRM"
    keyName := "Config"
    inParams.table = tblName
    inParams.key = keyName

    if strings.Contains(inParams.uri, "crm/config") {
        if inParams.oper == DELETE {
            value.Field["polling_interval"] = ""
            subOpMap_del[tblName] = make(map[string]db.Value)
            subOpMap_del[tblName][keyName] = value
            subOpMap[db.ConfigDB] = subOpMap_del
            inParams.subOpDataMap[DELETE] = &subOpMap
        } else {
            dev := (*inParams.ygRoot).(*ocbinds.Device)
            cfg := dev.System.Crm.Config
            if cfg.PollingInterval != nil {
                value.Field["polling_interval"] = getUint32String(*cfg.PollingInterval)
                cfgMap[tblName] = make(map[string]db.Value)
                cfgMap[tblName][keyName] = value
            }
        }
        return cfgMap, nil
    }

    if !strings.Contains(inParams.uri, "crm/threshold") {
        return cfgMap, nil
    }

    idx := strings.Index(inParams.uri, "crm/threshold")
    uri := "/"
    if idx >= 0 {
        uri = inParams.uri[idx+13:]
    }
    log.Infof("*** URI: '%v'", uri)

    if inParams.oper == DELETE {
        // IPv4
        if uri == "/ipv4/neighbor/config" {
            value.Field["ipv4_neighbor_threshold_type"] = ""
            value.Field["ipv4_neighbor_high_threshold"] = ""
            value.Field["ipv4_neighbor_low_threshold"] = ""
        } else if uri == "/ipv4/neighbor/config/type" {
            value.Field["ipv4_neighbor_threshold_type"] = ""
        } else if uri == "/ipv4/neighbor/config/high" {
            value.Field["ipv4_neighbor_high_threshold"] = ""
        } else if uri == "/ipv4/neighbor/config/low" {
            value.Field["ipv4_neighbor_low_threshold"] = ""
        } else if uri == "/ipv4/nexthop/config" {
            value.Field["ipv4_nexthop_threshold_type"] = ""
            value.Field["ipv4_nexthop_high_threshold"] = ""
            value.Field["ipv4_nexthop_low_threshold"] = ""
        } else if uri == "/ipv4/nexthop/config/type" {
            value.Field["ipv4_nexthop_threshold_type"] = ""
        } else if uri == "/ipv4/nexthop/config/high" {
            value.Field["ipv4_nexthop_high_threshold"] = ""
        } else if uri == "/ipv4/nexthop/config/low" {
            value.Field["ipv4_nexthop_low_threshold"] = ""
        } else if uri == "/ipv4/route/config" {
            value.Field["ipv4_route_threshold_type"] = ""
            value.Field["ipv4_route_high_threshold"] = ""
            value.Field["ipv4_route_low_threshold"] = ""
        } else if uri == "/ipv4/route/config/type" {
            value.Field["ipv4_route_threshold_type"] = ""
        } else if uri == "/ipv4/route/config/high" {
            value.Field["ipv4_route_high_threshold"] = ""
        } else if uri == "/ipv4/route/config/low" {
            value.Field["ipv4_route_low_threshold"] = ""

        // IPv6
        } else if uri == "/ipv6/neighbor/config" {
            value.Field["ipv6_neighbor_threshold_type"] = ""
            value.Field["ipv6_neighbor_high_threshold"] = ""
            value.Field["ipv6_neighbor_low_threshold"] = ""
        } else if uri == "/ipv6/neighbor/config/type" {
            value.Field["ipv6_neighbor_threshold_type"] = ""
        } else if uri == "/ipv6/neighbor/config/high" {
            value.Field["ipv6_neighbor_high_threshold"] = ""
        } else if uri == "/ipv6/neighbor/config/low" {
            value.Field["ipv6_neighbor_low_threshold"] = ""
        } else if uri == "/ipv6/nexthop/config" {
            value.Field["ipv6_nexthop_threshold_type"] = ""
            value.Field["ipv6_nexthop_high_threshold"] = ""
            value.Field["ipv6_nexthop_low_threshold"] = ""
        } else if uri == "/ipv6/nexthop/config/type" {
            value.Field["ipv6_nexthop_threshold_type"] = ""
        } else if uri == "/ipv6/nexthop/config/high" {
            value.Field["ipv6_nexthop_high_threshold"] = ""
        } else if uri == "/ipv6/nexthop/config/low" {
            value.Field["ipv6_nexthop_low_threshold"] = ""
        } else if uri == "/ipv6/route/config" {
            value.Field["ipv6_route_threshold_type"] = ""
            value.Field["ipv6_route_high_threshold"] = ""
            value.Field["ipv6_route_low_threshold"] = ""
        } else if uri == "/ipv6/route/config/type" {
            value.Field["ipv6_route_threshold_type"] = ""
        } else if uri == "/ipv6/route/config/high" {
            value.Field["ipv6_route_high_threshold"] = ""
        } else if uri == "/ipv6/route/config/low" {
            value.Field["ipv6_route_low_threshold"] = ""

        // ACL Group
        } else if uri == "/acl/group/config" {
            value.Field["acl_group_threshold_type"] = ""
            value.Field["acl_group_high_threshold"] = ""
            value.Field["acl_group_low_threshold"] = ""
        } else if uri == "/acl/group/config/type" {
            value.Field["acl_group_threshold_type"] = ""
        } else if uri == "/acl/group/config/high" {
            value.Field["acl_group_high_threshold"] = ""
        } else if uri == "/acl/group/config/low" {
            value.Field["acl_group_low_threshold"] = ""

        // ACL Group - Counter
        } else if uri == "/acl/group/counter/config" {
            value.Field["acl_counter_threshold_type"] = ""
            value.Field["acl_counter_high_threshold"] = ""
            value.Field["acl_counter_low_threshold"] = ""
        } else if uri == "/acl/group/counter/config/type" {
            value.Field["acl_counter_threshold_type"] = ""
        } else if uri == "/acl/group/counter/config/high" {
            value.Field["acl_counter_high_threshold"] = ""
        } else if uri == "/acl/group/counter/config/low" {
            value.Field["acl_counter_low_threshold"] = ""

        // ACL Group - Entry
        } else if uri == "/acl/group/entry/config" {
            value.Field["acl_entry_threshold_type"] = ""
            value.Field["acl_entry_high_threshold"] = ""
            value.Field["acl_entry_low_threshold"] = ""
        } else if uri == "/acl/group/entry/config/type" {
            value.Field["acl_entry_threshold_type"] = ""
        } else if uri == "/acl/group/entry/config/high" {
            value.Field["acl_entry_high_threshold"] = ""
        } else if uri == "/acl/group/entry/config/low" {
            value.Field["acl_entry_low_threshold"] = ""

        // ACL Table
        } else if uri == "/acl/table/config" {
            value.Field["acl_table_threshold_type"] = ""
            value.Field["acl_table_high_threshold"] = ""
            value.Field["acl_table_low_threshold"] = ""
        } else if uri == "/acl/table/config/type" {
            value.Field["acl_table_threshold_type"] = ""
        } else if uri == "/acl/table/config/high" {
            value.Field["acl_table_high_threshold"] = ""
        } else if uri == "/acl/table/config/low" {
            value.Field["acl_table_low_threshold"] = ""

        // Nexthop
        } else if uri == "/nexthop/group-member/config" {
            value.Field["nexthop_group_member_threshold_type"] = ""
            value.Field["nexthop_group_member_high_threshold"] = ""
            value.Field["nexthop_group_member_low_threshold"] = ""
        } else if uri == "/nexthop/group-member/config/type" {
            value.Field["nexthop_group_member_threshold_type"] = ""
        } else if uri == "/nexthop/group-member/config/high" {
            value.Field["nexthop_group_member_high_threshold"] = ""
        } else if uri == "/nexthop/group-member/config/low" {
            value.Field["nexthop_group_member_low_threshold"] = ""
        } else if uri == "/nexthop/group-object/config" {
            value.Field["nexthop_group_threshold_type"] = ""
            value.Field["nexthop_group_high_threshold"] = ""
            value.Field["nexthop_group_low_threshold"] = ""
        } else if uri == "/nexthop/group-object/config/type" {
            value.Field["nexthop_group_threshold_type"] = ""
        } else if uri == "/nexthop/group-object/config/high" {
            value.Field["nexthop_group_high_threshold"] = ""
        } else if uri == "/nexthop/group-object/config/low" {
            value.Field["nexthop_group_low_threshold"] = ""

        // FDB
        } else if uri == "/fdb/config" {
            value.Field["fdb_entry_threshold_type"] = ""
            value.Field["fdb_entry_high_threshold"] = ""
            value.Field["fdb_entry_low_threshold"] = ""
        } else if uri == "/fdb/config/type" {
            value.Field["fdb_entry_threshold_type"] = ""
        } else if uri == "/fdb/config/high" {
            value.Field["fdb_entry_high_threshold"] = ""
        } else if uri == "/fdb/config/low" {
            value.Field["fdb_entry_low_threshold"] = ""

        // DNAT
        } else if uri == "/dnat/config" {
            value.Field["dnat_entry_threshold_type"] = ""
            value.Field["dnat_entry_high_threshold"] = ""
            value.Field["dnat_entry_low_threshold"] = ""
        } else if uri == "/dnat/config/type" {
            value.Field["dnat_entry_threshold_type"] = ""
        } else if uri == "/dnat/config/high" {
            value.Field["dnat_entry_high_threshold"] = ""
        } else if uri == "/dnat/config/low" {
            value.Field["dnat_entry_low_threshold"] = ""

        // SNAT
        } else if uri == "/snat/config" {
            value.Field["snat_entry_threshold_type"] = ""
            value.Field["snat_entry_high_threshold"] = ""
            value.Field["snat_entry_low_threshold"] = ""
        } else if uri == "/snat/config/type" {
            value.Field["snat_entry_threshold_type"] = ""
        } else if uri == "/snat/config/high" {
            value.Field["snat_entry_high_threshold"] = ""
        } else if uri == "/snat/config/low" {
            value.Field["snat_entry_low_threshold"] = ""

        // IPMC
        } else if uri == "/ipmc/config" {
            value.Field["ipmc_entry_threshold_type"] = ""
            value.Field["ipmc_entry_high_threshold"] = ""
            value.Field["ipmc_entry_low_threshold"] = ""
        } else if uri == "/ipmc/config/type" {
            value.Field["ipmc_entry_threshold_type"] = ""
        } else if uri == "/ipmc/config/high" {
            value.Field["ipmc_entry_high_threshold"] = ""
        } else if uri == "/ipmc/config/low" {
            value.Field["ipmc_entry_low_threshold"] = ""

        // Unknown URI
        } else {
            log.Infof("skipping unknown uri '%v'...", uri)
        }

        subOpMap_del[tblName] = make(map[string]db.Value)
        subOpMap_del[tblName][keyName] = value
        subOpMap[db.ConfigDB] = subOpMap_del
        inParams.subOpDataMap[DELETE] = &subOpMap
    } else {

        dev := (*inParams.ygRoot).(*ocbinds.Device)

        // ACL
        if strings.Contains(uri, "/acl/group/counter/config") {
            cfg := dev.System.Crm.Threshold.Acl.Group.Counter.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["acl_counter_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["acl_counter_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["acl_counter_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else if strings.Contains(uri, "/acl/group/entry/config") {
            cfg := dev.System.Crm.Threshold.Acl.Group.Entry.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["acl_entry_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["acl_entry_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["acl_entry_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else if strings.Contains(uri, "/acl/group/config") {
            cfg := dev.System.Crm.Threshold.Acl.Group.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["acl_group_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["acl_group_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["acl_group_low_threshold"] = getUint32String(*cfg.Low)
            }

        } else if strings.Contains(uri, "/acl/table/config") {
            cfg := dev.System.Crm.Threshold.Acl.Table.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["acl_table_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["acl_table_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["acl_table_low_threshold"] = getUint32String(*cfg.Low)
            }

        // FDB
        } else if strings.Contains(uri, "/fdb/config") {
            cfg := dev.System.Crm.Threshold.Fdb.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["fdb_entry_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["fdb_entry_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["fdb_entry_low_threshold"] = getUint32String(*cfg.Low)
            }

        // IPMC
        } else if strings.Contains(uri, "/ipmc/config") {
            cfg := dev.System.Crm.Threshold.Ipmc.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["ipmc_entry_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["ipmc_entry_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["ipmc_entry_low_threshold"] = getUint32String(*cfg.Low)
            }

        // DNAT
        } else if strings.Contains(uri, "/dnat/config") {
            cfg := dev.System.Crm.Threshold.Dnat.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["dnat_entry_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["dnat_entry_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["dnat_entry_low_threshold"] = getUint32String(*cfg.Low)
            }

        // SNAT
        } else if strings.Contains(uri, "/snat/config") {
            cfg := dev.System.Crm.Threshold.Snat.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["snat_entry_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["snat_entry_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["snat_entry_low_threshold"] = getUint32String(*cfg.Low)
            }

        // IPv4
        } else if strings.Contains(uri, "/ipv4/neighbor/config") {
            cfg := dev.System.Crm.Threshold.Ipv4.Neighbor.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["ipv4_neighbor_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["ipv4_neighbor_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["ipv4_neighbor_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else if strings.Contains(uri, "/ipv4/nexthop/config") {
            cfg := dev.System.Crm.Threshold.Ipv4.Nexthop.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["ipv4_nexthop_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["ipv4_nexthop_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["ipv4_nexthop_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else if strings.Contains(uri, "/ipv4/route/config") {
            cfg := dev.System.Crm.Threshold.Ipv4.Route.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["ipv4_route_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["ipv4_route_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["ipv4_route_low_threshold"] = getUint32String(*cfg.Low)
            }

        // IPv6
        } else if strings.Contains(uri, "/ipv6/neighbor/config") {
            cfg := dev.System.Crm.Threshold.Ipv6.Neighbor.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["ipv6_neighbor_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["ipv6_neighbor_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["ipv6_neighbor_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else if strings.Contains(uri, "/ipv6/nexthop/config") {
            cfg := dev.System.Crm.Threshold.Ipv6.Nexthop.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["ipv6_nexthop_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["ipv6_nexthop_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["ipv6_nexthop_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else if strings.Contains(uri, "/ipv6/route/config") {
            cfg := dev.System.Crm.Threshold.Ipv6.Route.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["ipv6_route_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["ipv6_route_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["ipv6_route_low_threshold"] = getUint32String(*cfg.Low)
            }

        // Nexthop
        } else if strings.Contains(uri, "/nexthop/group-member/config") {
            cfg := dev.System.Crm.Threshold.Nexthop.GroupMember.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["nexthop_group_member_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["nexthop_group_member_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["nexthop_group_member_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else if strings.Contains(uri, "/nexthop/group-object/config") {
            cfg := dev.System.Crm.Threshold.Nexthop.GroupObject.Config
            if cfg.Type != ocbinds.OpenconfigSystemCrm_SystemCrmThresholdType_UNSET {
                value.Field["nexthop_group_threshold_type"] = getThresholdType(cfg.Type)
            }
            if cfg.High != nil {
                value.Field["nexthop_group_high_threshold"] = getUint32String(*cfg.High)
            }
            if cfg.Low != nil {
                value.Field["nexthop_group_low_threshold"] = getUint32String(*cfg.Low)
            }
        } else {
            log.Infof("skipping unknown uri '%v'...", uri)
        }

        cfgMap[tblName] = make(map[string]db.Value)
        cfgMap[tblName][keyName] = value
    }

    return cfgMap, nil
}

func getCrmStats (d *db.DB, stats *ocbinds.OpenconfigSystem_System_Crm_Statistics) (error) {

    var info CrmStats
    var ok bool

    tbl := db.TableSpec { Name: "CRM" }
    key := db.Key { Comp : [] string { "STATS" } }
    d.Opts.KeySeparator = ":"
    d.Opts.TableNameSeparator = ":"

    val, err := d.GetEntry(&tbl, key)

    if err == nil {
        info.dnatFree, ok = getUint32(val, "crm_stats_dnat_entry_available")
        if ok {
            stats.DnatEntriesAvailable = &info.dnatFree
        }
        info.dnatUsed, ok = getUint32(val, "crm_stats_dnat_entry_used")
        if ok {
            stats.DnatEntriesUsed = &info.dnatUsed
        }
        info.snatFree, ok = getUint32(val, "crm_stats_snat_entry_available")
        if ok {
            stats.SnatEntriesAvailable = &info.snatFree
        }
        info.snatUsed, ok = getUint32(val, "crm_stats_snat_entry_used")
        if ok {
            stats.SnatEntriesUsed = &info.snatUsed
        }
        info.fdbFree, ok = getUint32(val, "crm_stats_fdb_entry_available")
        if ok {
            stats.FdbEntriesAvailable = &info.fdbFree
        }
        info.fdbUsed, ok = getUint32(val, "crm_stats_fdb_entry_used")
        if ok {
            stats.FdbEntriesUsed = &info.fdbUsed
        }
        info.ipmcFree, ok = getUint32(val, "crm_stats_ipmc_entry_available")
        if ok {
            stats.IpmcEntriesAvailable = &info.ipmcFree
        }
        info.ipmcUsed, ok = getUint32(val, "crm_stats_ipmc_entry_used")
        if ok {
            stats.IpmcEntriesUsed = &info.ipmcUsed
        }
        info.ipv4NeighborFree, ok = getUint32(val, "crm_stats_ipv4_neighbor_available")
        if ok {
            stats.Ipv4NeighborsAvailable = &info.ipv4NeighborFree
        }
        info.ipv4NeighborUsed, ok = getUint32(val, "crm_stats_ipv4_neighbor_used")
        if ok {
            stats.Ipv4NeighborsUsed = &info.ipv4NeighborUsed
        }
        info.ipv4NexthopFree, ok = getUint32(val, "crm_stats_ipv4_nexthop_available")
        if ok {
            stats.Ipv4NexthopsAvailable = &info.ipv4NexthopFree
        }
        info.ipv4NexthopUsed, ok = getUint32(val, "crm_stats_ipv4_nexthop_used")
        if ok {
            stats.Ipv4NexthopsUsed = &info.ipv4NexthopUsed
        }
        info.ipv4RouteFree, ok = getUint32(val, "crm_stats_ipv4_route_available")
        if ok {
            stats.Ipv4RoutesAvailable = &info.ipv4RouteFree
        }
        info.ipv4RouteUsed, ok = getUint32(val, "crm_stats_ipv4_route_used")
        if ok {
            stats.Ipv4RoutesUsed = &info.ipv4RouteUsed
        }
        info.ipv6NeighborFree, ok = getUint32(val, "crm_stats_ipv6_neighbor_available")
        if ok {
            stats.Ipv6NeighborsAvailable = &info.ipv6NeighborFree
        }
        info.ipv6NeighborUsed, ok = getUint32(val, "crm_stats_ipv6_neighbor_used")
        if ok {
            stats.Ipv6NeighborsUsed = &info.ipv6NeighborUsed
        }
        info.ipv6NexthopFree, ok = getUint32(val, "crm_stats_ipv6_nexthop_available")
        if ok {
            stats.Ipv6NexthopsAvailable = &info.ipv6NexthopFree
        }
        info.ipv6NexthopUsed, ok = getUint32(val, "crm_stats_ipv6_nexthop_used")
        if ok {
            stats.Ipv6NexthopsUsed = &info.ipv6NexthopUsed
        }
        info.ipv6RouteFree, ok = getUint32(val, "crm_stats_ipv6_route_available")
        if ok {
            stats.Ipv6RoutesAvailable = &info.ipv6RouteFree
        }
        info.ipv6RouteUsed, ok = getUint32(val, "crm_stats_ipv6_route_used")
        if ok {
            stats.Ipv6RoutesUsed = &info.ipv6RouteUsed
        }
        info.nexthopGroupMemberFree, ok = getUint32(val, "crm_stats_nexthop_group_member_available")
        if ok {
            stats.NexthopGroupMembersAvailable = &info.nexthopGroupMemberFree
        }
        info.nexthopGroupMemberUsed, ok = getUint32(val, "crm_stats_nexthop_group_member_used")
        if ok {
            stats.NexthopGroupMembersUsed = &info.nexthopGroupMemberUsed
        }
        info.nexthopGroupFree      , ok = getUint32(val, "crm_stats_nexthop_group_available")
        if ok {
            stats.NexthopGroupsAvailable = &info.nexthopGroupFree
        }
        info.nexthopGroupUsed      , ok = getUint32(val, "crm_stats_nexthop_group_used")
        if ok {
            stats.NexthopGroupsUsed = &info.nexthopGroupUsed
        }
    }

    return err
}

var DbToYang_crm_stats_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    devObj := (*inParams.ygRoot).(*ocbinds.Device)
    ygot.BuildEmptyTree(devObj.System.Crm.Statistics)

    return getCrmStats(inParams.dbs[db.CountersDB], devObj.System.Crm.Statistics)
}


func getCrmAclStats (d *db.DB, stats *ocbinds.OpenconfigSystem_System_Crm_AclStatistics) (error) {
    var err error
    var val db.Value
    var has0 bool
    var has1 bool
    var has2 bool
    var has3 bool

    stage := []string { "EGRESS", "INGRESS" }
    point := []string { "SWITCH", "VLAN", "PORT", "RIF", "LAG" }

    d.Opts.KeySeparator = ":"
    d.Opts.TableNameSeparator = ":"
    tbl := db.TableSpec { Name: "CRM" }

    for x, s := range stage {
        for y, p := range point {
            key := db.Key { Comp : [] string { "ACL_STATS", s, p } }
            val, err = d.GetEntry(&tbl, key)
            if err != nil {
                break;
            }

            tmp := &dataAclStats[(x * 5) + y]
            tmp.groupFree, has0 = getUint32(val, "crm_stats_acl_group_available")
            tmp.groupUsed, has1 = getUint32(val, "crm_stats_acl_group_used")
            tmp.tableFree, has2 = getUint32(val, "crm_stats_acl_table_available")
            tmp.tableUsed, has3 = getUint32(val, "crm_stats_acl_table_used")

            switch (s) {
            case "EGRESS":
                switch (p) {
                case "SWITCH":
                    if has0 {
                        stats.Egress.Switch.GroupsAvailable  = &tmp.groupFree
                    }
                    if has1 {
                        stats.Egress.Switch.GroupsUsed       = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Egress.Switch.TablesAvailable  = &tmp.tableFree
                    }
                    if has3 {
                        stats.Egress.Switch.TablesUsed       = &tmp.tableUsed
                    }
                case "VLAN":
                    if has0 {
                        stats.Egress.Vlan.GroupsAvailable    = &tmp.groupFree
                    }
                    if has1 {
                        stats.Egress.Vlan.GroupsUsed         = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Egress.Vlan.TablesAvailable    = &tmp.tableFree
                    }
                    if has3 {
                        stats.Egress.Vlan.TablesUsed         = &tmp.tableUsed
                    }
                case "PORT":
                    if has0 {
                        stats.Egress.Port.GroupsAvailable    = &tmp.groupFree
                    }
                    if has1 {
                        stats.Egress.Port.GroupsUsed         = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Egress.Port.TablesAvailable    = &tmp.tableFree
                    }
                    if has3 {
                        stats.Egress.Port.TablesUsed         = &tmp.tableUsed
                    }
                case "RIF":
                    if has0 {
                        stats.Egress.Rif.GroupsAvailable     = &tmp.groupFree
                    }
                    if has1 {
                        stats.Egress.Rif.GroupsUsed          = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Egress.Rif.TablesAvailable     = &tmp.tableFree
                    }
                    if has3 {
                        stats.Egress.Rif.TablesUsed          = &tmp.tableUsed
                    }
                case "LAG":
                    if has0 {
                        stats.Egress.Lag.GroupsAvailable     = &tmp.groupFree
                    }
                    if has1 {
                        stats.Egress.Lag.GroupsUsed          = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Egress.Lag.TablesAvailable     = &tmp.tableFree
                    }
                    if has3 {
                        stats.Egress.Lag.TablesUsed          = &tmp.tableUsed
                    }
                default:
                }
            case "INGRESS":
                switch (p) {
                case "SWITCH":
                    if has0 {
                        stats.Ingress.Switch.GroupsAvailable = &tmp.groupFree
                    }
                    if has1 {
                        stats.Ingress.Switch.GroupsUsed      = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Ingress.Switch.TablesAvailable = &tmp.tableFree
                    }
                    if has3 {
                        stats.Ingress.Switch.TablesUsed      = &tmp.tableUsed
                    }
                case "VLAN":
                    if has0 {
                        stats.Ingress.Vlan.GroupsAvailable   = &tmp.groupFree
                    }
                    if has1 {
                        stats.Ingress.Vlan.GroupsUsed        = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Ingress.Vlan.TablesAvailable   = &tmp.tableFree
                    }
                    if has3 {
                        stats.Ingress.Vlan.TablesUsed        = &tmp.tableUsed
                    }
                case "PORT":
                    if has0 {
                        stats.Ingress.Port.GroupsAvailable   = &tmp.groupFree
                    }
                    if has1 {
                        stats.Ingress.Port.GroupsUsed        = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Ingress.Port.TablesAvailable   = &tmp.tableFree
                    }
                    if has3 {
                        stats.Ingress.Port.TablesUsed        = &tmp.tableUsed
                    }
                case "RIF":
                    if has0 {
                        stats.Ingress.Rif.GroupsAvailable    = &tmp.groupFree
                    }
                    if has1 {
                        stats.Ingress.Rif.GroupsUsed         = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Ingress.Rif.TablesAvailable    = &tmp.tableFree
                    }
                    if has3 {
                        stats.Ingress.Rif.TablesUsed         = &tmp.tableUsed
                    }
                case "LAG":
                    if has0 {
                        stats.Ingress.Lag.GroupsAvailable    = &tmp.groupFree
                    }
                    if has1 {
                        stats.Ingress.Lag.GroupsUsed         = &tmp.groupUsed
                    }
                    if has2 {
                        stats.Ingress.Lag.TablesAvailable    = &tmp.tableFree
                    }
                    if has3 {
                        stats.Ingress.Lag.TablesUsed         = &tmp.tableUsed
                    }
                default:
                }
            default:
            }
        }
    }

    return err
}

var DbToYang_crm_acl_stats_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    devObj := (*inParams.ygRoot).(*ocbinds.Device)
    ygot.BuildEmptyTree(devObj.System.Crm.AclStatistics)

    return getCrmAclStats(inParams.dbs[db.CountersDB], devObj.System.Crm.AclStatistics)
}

func getCrmAclTableStats (d *db.DB, stats *ocbinds.OpenconfigSystem_System_Crm_AclTableStatistics) (error) {

    tbl := db.TableSpec { Name: "CRM" }
    key := db.Key { Comp : [] string { "ACL_TABLE_STATS", "*" } }
    d.Opts.KeySeparator = ":"
    d.Opts.TableNameSeparator = ":"

    keys, err := d.GetKeysPattern(&tbl, key)
    if err != nil {
        return err
    }

    if stats.AclTableStatisticsList == nil {
        stats.AclTableStatisticsList = make(map[string]*ocbinds.OpenconfigSystem_System_Crm_AclTableStatistics_AclTableStatisticsList)
    }

    for i := 0; i < len(keys); i++ {
        var row ocbinds.OpenconfigSystem_System_Crm_AclTableStatistics_AclTableStatisticsList
        var counter ocbinds.OpenconfigSystem_System_Crm_AclTableStatistics_AclTableStatisticsList_Counter
        var entry ocbinds.OpenconfigSystem_System_Crm_AclTableStatistics_AclTableStatisticsList_Entry
        var val db.Value
        var id string

        val, err = d.GetEntry(&tbl, keys[i])
        if err != nil {
            continue
        }

        cntFree, hasCntFree := getUint32(val, "crm_stats_acl_counter_available")
        cntUsed, hasCntUsed := getUint32(val, "crm_stats_acl_counter_used")
        if hasCntFree {
            counter.Available = &cntFree
        }
        if hasCntUsed {
            counter.Used = &cntUsed
        }

        entFree, hasEntFree := getUint32(val, "crm_stats_acl_entry_available")
        entUsed, hasEntUsed := getUint32(val, "crm_stats_acl_entry_used")
        if hasEntFree {
            entry.Available = &entFree
        }
        if hasEntUsed {
            entry.Used = &entUsed
        }

        id = keys[i].Comp[1]
        row.Id = &id
        row.Counter = &counter
        row.Entry = &entry
        stats.AclTableStatisticsList[id] = &row
    }

    return err
}

var DbToYang_crm_acl_table_stats_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

    devObj := (*inParams.ygRoot).(*ocbinds.Device)
    ygot.BuildEmptyTree(devObj.System.Crm.AclTableStatistics)

    return getCrmAclTableStats(inParams.dbs[db.CountersDB], devObj.System.Crm.AclTableStatistics)
}

var Subscribe_crm_config_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var result XfmrSubscOutParams

    if strings.Contains(inParams.uri, "crm/config") ||
       strings.Contains(inParams.uri, "crm/threshold") ||
       strings.Contains(inParams.uri, "crm/state") {

        result.dbDataMap = RedisDbMap{db.ConfigDB:{"CRM":{"Config":{}}}}
    }
    result.isVirtualTbl = false
    result.needCache = true
    result.onChange = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, nil
}

var Subscribe_crm_stats_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var result XfmrSubscOutParams

    if strings.Contains(inParams.uri, "crm/statistics") {

        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"STATS":{}}}}
    }
    result.isVirtualTbl = false
    result.needCache = true
    result.onChange = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, nil
}

var Subscribe_crm_acl_stats_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var result XfmrSubscOutParams

    if strings.Contains(inParams.uri, "crm/acl-statistics/egress/rif") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:EGRESS:RIF":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/egress/vlan") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:EGRESS:VLAN":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/egress/lag") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:EGRESS:LAG":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/egress/port") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:EGRESS:PORT":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/ingress/switch") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:EGRESS:SWITCH":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/ingress/rif") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:INGRESS:RIF":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/ingress/vlan") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:INGRESS:VLAN":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/ingress/lag") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:INGRESS:LAG":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/ingress/port") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:INGRESS:PORT":{}}}}
    } else if strings.Contains(inParams.uri, "crm/acl-statistics/ingress/switch") {
        result.dbDataMap = RedisDbMap{db.CountersDB:{"CRM":{"ACL_STATS:INGRESS:SWITCH":{}}}}
    }
    result.isVirtualTbl = false
    result.needCache = true
    result.onChange = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, nil
}
