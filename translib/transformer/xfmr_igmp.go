
/////////////////////////////////////////////////////////////////////////
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
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    log "github.com/golang/glog"
)

func init () {
    XlateFuncBind("DbToYang_igmp_groups_get_xfmr", DbToYang_igmp_groups_get_xfmr)
    XlateFuncBind("DbToYang_igmp_sources_get_xfmr", DbToYang_igmp_sources_get_xfmr)
    XlateFuncBind("DbToYang_igmp_stats_get_xfmr", DbToYang_igmp_stats_get_xfmr)
    XlateFuncBind("DbToYang_igmp_interface_get_xfmr", DbToYang_igmp_interface_get_xfmr)
}

func getIgmpRoot (inParams XfmrParams) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp, string, error) {
    pathInfo := NewPathInfo(inParams.uri)
    igmpVrfName := pathInfo.Var("name")
    igmpIdentifier := pathInfo.Var("identifier")
    igmpInstanceNumber := pathInfo.Var("name#2")
    var err error

    if len(pathInfo.Vars) <  3 {
        return nil, "", errors.New("Invalid Key length")
    }

    if len(igmpVrfName) == 0 {
        return nil, "", errors.New("vrf name is missing")
    }

    if !strings.Contains(igmpIdentifier, "IGMP") {
        return nil, "", errors.New("Protocol ID IGMP is missing")
    }

    if len(igmpInstanceNumber) == 0 {
        return nil, "", errors.New("Protocol Insatnce Id is missing")
    }

    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    jsonStr, err := ygot.EmitJSON(deviceObj, &ygot.EmitJSONConfig{
           Format:         ygot.RFC7951,
           Indent:         "  ",
           SkipValidation: true,
           RFC7951Config: &ygot.RFC7951JSONConfig{
                   AppendModuleName: true,
           },
    })
    log.Info("################################")
    log.Infof(" getIgmpRoot App ygot jsonStr: %v", jsonStr)
    log.Info("################################")

    netInstsObj := deviceObj.NetworkInstances

    if netInstsObj.NetworkInstance == nil {
        return nil, "", errors.New("Network-instances container missing")
    }

    netInstObj := netInstsObj.NetworkInstance[igmpVrfName]
    if netInstObj == nil {
        return nil, "", errors.New("Network-instance obj for IGMP missing")
    }

    if netInstObj.Protocols == nil || len(netInstObj.Protocols.Protocol) == 0 {
        return nil, "", errors.New("Network-instance protocols-container for IGMP missing or protocol-list empty")
    }

    var protoKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Key
    protoKey.Identifier = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_IGMP
    protoKey.Name = igmpInstanceNumber
    protoInstObj := netInstObj.Protocols.Protocol[protoKey]
    if protoInstObj == nil {
        return nil, "", errors.New("Network-instance IGMP-Protocol obj missing")
    }

    if protoInstObj.Igmp == nil {
        var _Igmp_obj ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp
        protoInstObj.Igmp = &_Igmp_obj
        ygot.BuildEmptyTree (protoInstObj.Igmp)
    }

    return protoInstObj.Igmp, igmpVrfName, err
}

func fill_igmp_groups_xfmr (igmp_map map[string]interface{}, igmpGroups_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Groups) error {
    var err error
    var igmpIgmpGroup_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Groups_Group
    var igmpGroupState_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Groups_Group_State
    var igmpGroupKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Groups_Group_Key
    log.Info("fill_igmp_groups_xfmr igmp_map %s ",igmp_map)
    oper_err := errors.New("Operational error")
    cmn_log := "GET: xfmr for IGMP IGMP Groups"
    var interfaceId string
    var mcastgrpAddr string
    for key, value := range igmp_map {
        interfaceId = key
        group_map := value.(map[string]interface {})
        for grp_addr, value := range group_map {
            mcastgrpAddr = grp_addr
            switch v := value.(type) {
                case map[string]interface{}:
                    if _grpaddr,ok := v["group"].(string) ; ok {
                          mcastgrpAddr = _grpaddr
                    }
                    log.Info("interfaceId : ",interfaceId)
                    log.Info("mcastgrpAddr : ",mcastgrpAddr)
                    igmpGroupKey.InterfaceId = interfaceId
                    igmpGroupKey.McastgrpAddr = mcastgrpAddr
                    igmpIgmpGroup_obj = igmpGroups_obj.Group[igmpGroupKey]
                    if (nil == igmpIgmpGroup_obj) {
                        igmpIgmpGroup_obj, err = igmpGroups_obj.NewGroup(interfaceId,mcastgrpAddr)
                        if err  != nil {
                            log.Errorf("%s failed !! Error: Failed to create IgmpGroup  under IgmpGroups", cmn_log)
                            return  oper_err
                        }
                    }
                    ygot.BuildEmptyTree (igmpIgmpGroup_obj)
                    
                    igmpGroupState_obj = igmpIgmpGroup_obj.State
                    if (nil == igmpGroupState_obj) {
                        log.Info("igmp group state obj is nill creating new")
                        ygot.BuildEmptyTree(igmpGroupState_obj)
                        igmpIgmpGroup_obj.State = igmpGroupState_obj
                    } 
                    if _ipaddr,ok := v["source"].(string) ; ok {
                        igmpIgmpGroup_obj.State.IpAddr = &_ipaddr
                    }
                    if _mode,ok := v["mode"].(string) ; ok {
                        igmpIgmpGroup_obj.State.Mode = &_mode
                    }
                    if _timer,ok := v["timer"].(string) ; ok {
                        igmpIgmpGroup_obj.State.Timer = &_timer
                    }
                    if _uptime, ok := v["uptime"].(string) ; ok {
                        igmpIgmpGroup_obj.State.Uptime = &_uptime
                    }
                    if value,ok := v["version"] ; ok {
                       _version := uint8(value.(float64))
                        igmpIgmpGroup_obj.State.Version = &_version
                    }
                    if value,ok := v["sourcesCount"] ; ok {
                       _srcs := uint16(value.(float64))
                       igmpIgmpGroup_obj.State.SourcesCount = &_srcs
                    }
              }
         }
    }

    return err
}

func fill_igmp_sources_xfmr (igmp_map map[string]interface{},igmpSources_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Sources) error {
    var err error
    var igmpIgmpSource_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Sources_Source
    var igmpSourceState_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Sources_Source_State
    var igmpSourceKey ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Sources_Source_Key
    log.Info("fill_igmp__xfmr igmp_map %s ",igmp_map)
    oper_err := errors.New("Operational error")
    cmn_log := "GET: xfmr for IGMP IGMP Sources"
    var interfaceId string
    var srcAddr string
    var grpAddr string
    for key, value := range igmp_map {
        interfaceId = key
            log.Info("0 ", key)
        group_map := value.(map[string]interface {})
            log.Info("1 ", group_map)
        for src_addr, value := range group_map {
            srcAddr = src_addr
            log.Info("2 ", srcAddr)
            switch v := value.(type) {
                case map[string]interface{}:
                    if _srcaddr,ok := v["source"].(string) ; ok {
                          srcAddr = _srcaddr
                    }
                    if _grpaddr,ok := v["group"].(string) ; ok {
                          grpAddr = _grpaddr
                    }
                    log.Info("interfaceId : ",interfaceId)
                    log.Info("grpAddr : ",grpAddr)
                    log.Info("srcAddr : ",srcAddr)
                    igmpSourceKey.InterfaceId = interfaceId
                    igmpSourceKey.McastgrpAddr = grpAddr
                    igmpSourceKey.SrcAddr = srcAddr
                    igmpIgmpSource_obj = igmpSources_obj.Source[igmpSourceKey]
                    if (nil == igmpIgmpSource_obj) {
            log.Info("3 source obj nil creating new")
                        igmpIgmpSource_obj, err = igmpSources_obj.NewSource(interfaceId,grpAddr,srcAddr)
                        if err  != nil {
                            log.Errorf("%s failed !! Error: Failed to create Source under Sources", cmn_log)
                            return  oper_err
                        }
                    }
                    ygot.BuildEmptyTree (igmpIgmpSource_obj)

                    igmpSourceState_obj = igmpIgmpSource_obj.State
                    if (nil == igmpSourceState_obj) {
                        log.Info("igmp source state obj is nill creating new")
                        ygot.BuildEmptyTree(igmpSourceState_obj)
                        igmpIgmpSource_obj.State = igmpSourceState_obj
                    }
                    if _ipaddr,ok := v["ifaddr"].(string) ; ok {
                        igmpIgmpSource_obj.State.IpAddr = &_ipaddr
                    }
                    if _uptime, ok := v["uptime"].(string) ; ok {
                        igmpIgmpSource_obj.State.Uptime = &_uptime
                    }
                    if _timer, ok := v["timer"].(string) ; ok {
                        igmpIgmpSource_obj.State.Timer = &_timer
                    }
                    if _srcfwd, ok := v["sourceforwarding"].(string) ; ok {
                        igmpIgmpSource_obj.State.SourceForwarding = &_srcfwd
                    }
              }
         }
     }
     return err
}

func fill_igmp_stats_xfmr (output_state map[string]interface{}, igmp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp) error { 
    var err error
    var igmpStats_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics
    var igmpCounters_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters
    var igmpQueries_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries
    var igmpQueriesSent_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Sent
    var igmpQueriesSentState_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Sent_State
    var igmpQueriesRcvd_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Received
    var igmpQueriesRcvdState_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Received_State
    var igmpReports_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Reports
    var igmpReportsState_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Reports_State
    var igmpMtraceCounters_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_MtraceCounters
    var igmpMtraceCountersState_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_MtraceCounters_State
    var oper_err error
    var cmn_log string

    oper_err = errors.New("Operational error")
    cmn_log = "GET: xfmr for IGMP IGMP Groups"
    log.Info("fill_igmp_stats_xfmr output_state %s",output_state)

    igmpStats_obj = igmp_obj.Statistics
    if igmpStats_obj == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Statistics  container missing", cmn_log)
        igmpStats_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics)
        if igmpStats_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Statistics container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpStats_obj)
        igmp_obj.Statistics = igmpStats_obj
    }
    if igmpStats_obj.Counters == nil {
       igmpCounters_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters)
               if igmpCounters_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Counters container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpCounters_obj)
        igmpStats_obj.Counters = igmpCounters_obj
    }
    
    if igmpStats_obj.Counters.Queries == nil {
       igmpQueries_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries)
               if igmpQueries_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create IgmpQueries container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpQueries_obj)
        igmpStats_obj.Counters.Queries = igmpQueries_obj
    
    }
    if igmpStats_obj.Counters.Queries.Sent == nil {
      igmpQueriesSent_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Sent)
               if igmpQueriesSent_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create IgmpQueries Sent container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpQueriesSent_obj)
        igmpStats_obj.Counters.Queries.Sent = igmpQueriesSent_obj
    
    }
    if igmpStats_obj.Counters.Queries.Received == nil {
      igmpQueriesRcvd_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Received)
               if igmpQueriesRcvd_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create IgmpQueries received container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpQueriesRcvd_obj)
        igmpStats_obj.Counters.Queries.Received = igmpQueriesRcvd_obj
    
    }
    if igmpStats_obj.Counters.Queries.Received.State == nil {
      igmpQueriesRcvdState_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Received_State)
               if igmpQueriesRcvdState_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create IgmpQueries received state container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpQueriesRcvdState_obj)
        igmpStats_obj.Counters.Queries.Received.State = igmpQueriesRcvdState_obj
   
    }
    if igmpStats_obj.Counters.Queries.Sent.State == nil {
          igmpQueriesSentState_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Queries_Sent_State)
               if igmpQueriesSentState_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create IgmpQueries Sent State container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpQueriesSentState_obj)
        igmpStats_obj.Counters.Queries.Sent.State = igmpQueriesSentState_obj

    }
    if igmpStats_obj.Counters.Reports == nil {
      igmpReports_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Reports)
               if igmpReports_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create IgmpReports received container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpReports_obj)
        igmpStats_obj.Counters.Reports = igmpReports_obj
    
    }
    if igmpStats_obj.Counters.Reports.State == nil {
      igmpReportsState_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_Counters_Reports_State)
               if igmpReportsState_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create IgmpReports state received container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpReportsState_obj)
        igmpStats_obj.Counters.Reports.State = igmpReportsState_obj
    
    }
    if igmpStats_obj.MtraceCounters == nil {
       igmpMtraceCounters_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_MtraceCounters)
       if igmpMtraceCounters_obj == nil {
           log.Errorf("%s failed !! Error:Failed to create Igmp Mtrace container", cmn_log)
           return oper_err
       }
        ygot.BuildEmptyTree (igmpMtraceCounters_obj)
        igmpStats_obj.MtraceCounters = igmpMtraceCounters_obj
    }
    if igmpStats_obj.MtraceCounters.State == nil {
       igmpMtraceCountersState_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Statistics_MtraceCounters_State)
       if igmpMtraceCountersState_obj == nil {
           log.Errorf("%s failed !! Error:Failed to create Igmp Mtrace state container", cmn_log)
           return oper_err
       }
        ygot.BuildEmptyTree (igmpMtraceCountersState_obj)
        igmpStats_obj.MtraceCounters.State = igmpMtraceCountersState_obj
    }

    if value,ok := output_state["queryV1"] ; ok {
        _v1query := uint32(value.(float64))
        igmpStats_obj.Counters.Queries.Sent.State.V1 = &_v1query
        log.Info("v1query %d",_v1query)
    }
    if value,ok := output_state["queryV2"] ; ok {
        _v2query := uint32(value.(float64))
        log.Info("v2query %d",_v2query)
        igmpStats_obj.Counters.Queries.Sent.State.V2 = &_v2query
    }
    if value,ok := output_state["queryV3"] ; ok {
        _v3query := uint32(value.(float64))
        igmpStats_obj.Counters.Queries.Sent.State.V3 = &_v3query
    }
    if value,ok := output_state["leaveV3"] ; ok {
        _v3recv := uint32(value.(float64))
        igmpStats_obj.Counters.Queries.Received.State.V3 = &_v3recv
    }
    if value,ok := output_state["reportV1"] ; ok {
        _v1report := uint32(value.(float64))
        igmpStats_obj.Counters.Reports.State.V1 = &_v1report
    }
    if value,ok := output_state["reportV2"] ; ok {
        _v2report := uint32(value.(float64))
        igmpStats_obj.Counters.Reports.State.V2 = &_v2report
    }
    if value,ok := output_state["reportV3"] ; ok {
        _v3report := uint32(value.(float64))
        igmpStats_obj.Counters.Reports.State.V3 = &_v3report
    }
    if value,ok := output_state["mtraceResponse"] ; ok {
        _mtraceresp := uint32(value.(float64))
        igmpStats_obj.MtraceCounters.State.MtraceResponse = &_mtraceresp
    }
    if value,ok := output_state["mtraceRequest"] ; ok {
        _mtracereq := uint32(value.(float64))
        igmpStats_obj.MtraceCounters.State.MtraceRequest = &_mtracereq
    }
    if value,ok := output_state["unsupported"] ; ok {
        _unsupported := uint32(value.(float64))
        igmpStats_obj.MtraceCounters.State.Unsupported = &_unsupported
    }
    return err
}

func fill_igmp_interface_xfmr (interface_info map[string]interface{}, interfaceId string, igmp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp) error {
    var err error
    var igmpInterfaces_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces
    var igmpInterfacesInterface_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface
    var igmpInterfaceState_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State
    var igmpInterfaceQuerier_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State_Querier
    var igmpInterfaceTimer_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State_Timers
    var igmpInterfaceFlags_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State_Flags
    var oper_err error
    var cmn_log string
    var flag_yes string
    var flag_no string
    flag_yes = "yes"
    flag_no = "no"

    oper_err = errors.New("Operational error")
    cmn_log = "GET: xfmr for IGMP Interface"
    log.Info("fill_igmp_interface_xfmr interface_info %s ",interface_info)

    igmpInterfaces_obj = igmp_obj.Interfaces
    if igmpInterfaces_obj == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Interfaces  container missing", cmn_log)
        igmpInterfaces_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces)
        if igmpInterfaces_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Interfaces container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpInterfaces_obj)
        igmp_obj.Interfaces = igmpInterfaces_obj
    }
    igmpInterfacesInterface_obj = igmp_obj.Interfaces.Interface[interfaceId]
    if igmp_obj.Interfaces.Interface == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Interfaces  container missing", cmn_log)
        igmpInterfacesInterface_obj, err = igmpInterfaces_obj.NewInterface(interfaceId)
        if err  != nil {
            log.Errorf("%s failed !! Error: Failed to create Igmp Interface  under Interfaces", cmn_log)
            return  oper_err
        }
        ygot.BuildEmptyTree (igmpInterfacesInterface_obj)
        igmp_obj.Interfaces.Interface[interfaceId] = igmpInterfacesInterface_obj
    }
    igmpInterfaceState_obj = igmpInterfacesInterface_obj.State
    if igmpInterfaceState_obj == nil {
        log.Errorf("%s failed !! State container missing create now", cmn_log)
        igmpInterfaceState_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State)
        if igmpInterfaceState_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Interfaces State container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpInterfaceState_obj)
        igmpInterfacesInterface_obj.State = igmpInterfaceState_obj
    }
    igmpInterfaceQuerier_obj =igmpInterfaceState_obj.Querier
    if igmpInterfaceQuerier_obj == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Interface State Querier container missing", cmn_log)
        igmpInterfaceQuerier_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State_Querier)
        if igmpInterfaceQuerier_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Interfaces State Querier container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpInterfaceQuerier_obj)
        igmpInterfaceState_obj.Querier = igmpInterfaceQuerier_obj
    }
    igmpInterfaceFlags_obj = igmpInterfaceState_obj.Flags
    if igmpInterfaceFlags_obj == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Interface State Flags container missing", cmn_log)
        igmpInterfaceFlags_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State_Flags)
        if igmpInterfaceFlags_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Interfaces State Flags container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpInterfaceFlags_obj)
        igmpInterfaceState_obj.Flags = igmpInterfaceFlags_obj
    }
    igmpInterfaceTimer_obj = igmpInterfaceState_obj.Timers
    if igmpInterfaceTimer_obj == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Interface State Timer container missing", cmn_log)
        igmpInterfaceTimer_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Interfaces_Interface_State_Timers)
        if igmpInterfaceTimer_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Interfaces State Timer container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpInterfaceTimer_obj)
        igmpInterfaceState_obj.Timers = igmpInterfaceTimer_obj
    }

    if value,ok := interface_info["upTime"].(string) ; ok {
        igmpInterfacesInterface_obj.State.FilterPrefixes  = &value
    }
    if value,ok := interface_info["upTime"].(string) ; ok {
        igmpInterfacesInterface_obj.State.InterfaceId  = &value
    }
/*
    if value,ok := interface_info["upTime"] ; ok {
        _mtracereq := uint32(value.(float64))
        igmpInterfacesInterface_obj.State.Enabled  = &_mtracereq
    }
*/
    if value,ok := interface_info["version"] ; ok {
        _version := uint8(value.(float64))
        igmpInterfacesInterface_obj.State.Version  = &_version
    }
/*
    if value,ok := interface_info["upTime"] ; ok {
        _mtracereq := uint32(value.(float64))
        igmpInterfacesInterface_obj.State.QueryInterval  = &_mtracereq
    }
*/
    if value,ok := interface_info["address"].(string) ; ok {
        igmpInterfacesInterface_obj.State.Querier.IpAddr  = &value
    }
    if value,ok := interface_info["state"].(string) ; ok {
        igmpInterfaceState_obj.Querier.Status  = &value
    }

    /* Set flags to default value 'no' */
    igmpInterfacesInterface_obj.State.Flags.AllMulticast  = &flag_no
    igmpInterfacesInterface_obj.State.Flags.Broadcast  = &flag_no
    igmpInterfacesInterface_obj.State.Flags.Deleted  = &flag_no
    igmpInterfacesInterface_obj.State.Flags.Multicast  = &flag_no
    igmpInterfacesInterface_obj.State.Flags.MulticastLoop  = &flag_no
    igmpInterfacesInterface_obj.State.Flags.Promiscous  = &flag_no

    if value,ok := interface_info["flagAllMulticast"].(bool) ; ok {
        if value {
           igmpInterfaceFlags_obj.AllMulticast  = &flag_yes
        }
    }
    if value,ok := interface_info["flagBroadcast"].(bool) ; ok {
        if value {
           igmpInterfacesInterface_obj.State.Flags.Broadcast  = &flag_yes
        }
    }
    if value,ok := interface_info["flagDeleted"].(bool) ; ok {
        if value {
           igmpInterfacesInterface_obj.State.Flags.Deleted  = &flag_yes
        }
    }
    if value,ok := interface_info["index"] ; ok {
        _index := uint32(value.(float64))
        igmpInterfacesInterface_obj.State.Flags.Index  = &_index
    }
    if value,ok := interface_info["flagMulticast"].(bool) ; ok {
        if value {
           igmpInterfacesInterface_obj.State.Flags.Multicast  = &flag_yes
        }
    }
    if value,ok := interface_info["lanDelayEnabled"].(bool) ; ok {
        if value {
           igmpInterfacesInterface_obj.State.Flags.MulticastLoop  = &flag_yes
        }
    }
    if value,ok := interface_info["flagPromiscuous"].(bool) ; ok {
        if value {
           igmpInterfacesInterface_obj.State.Flags.Promiscous  = &flag_yes
        }
    }

    if value,ok := interface_info["querier"].(string) ; ok {
        igmpInterfaceQuerier_obj.QuerierType  = &value
    }
    if value,ok := interface_info["queryStartCount"] ; ok {
        _qsc := uint32(value.(float64))
        igmpInterfacesInterface_obj.State.Querier.QueryStartupCount  = &_qsc
    }
    if value,ok := interface_info["queryQueryTimer"].(string) ; ok {
        igmpInterfacesInterface_obj.State.Querier.QueryTimer  = &value
    }
    if value,ok := interface_info["queryOtherTimer"].(string) ; ok {
        igmpInterfacesInterface_obj.State.Querier.QueryGeneralTimer  = &value
    }


    if value,ok := interface_info["timerGroupMembershipIntervalMsec"] ; ok {
        _gmi := uint16(value.(float64))
        igmpInterfaceTimer_obj.GroupMembershipInterval  = &_gmi
    }
    if value,ok := interface_info["lastMemberQueryCount"] ; ok {
        _lmq := uint16(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.LastMemberQueryCount  = &_lmq
    }
    if value,ok := interface_info["timerLastMemberQueryMsec"] ; ok {
        _lmqt := uint32(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.LastMemberQueryTime  = &_lmqt
    }
    if value,ok := interface_info["timerOlderHostPresentIntervalMsec"] ; ok {
        _old := uint16(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.OlderHostPresentInterval  = &_old
    }
    if value,ok := interface_info["timerOtherQuerierPresentIntervalMsec"] ; ok {
        _qpi := uint16(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.QuerierPresentInterval  = &_qpi
    }
    if value,ok := interface_info["timerQueryInterval"] ; ok {
        _qi := uint16(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.QueryInterval  = &_qi
    }
    if value,ok := interface_info["timerQueryResponseIntervalMsec"] ; ok {
        _qri := uint16(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.QueryResponseInterval  = &_qri
    }
    if value,ok := interface_info["timerRobustnessVariable"] ; ok {
        _trv := uint8(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.RobustnessVariable  = &_trv
    }
    if value,ok := interface_info["timerStartupQueryInterval"] ; ok {
        _sqi := uint16(value.(float64))
        igmpInterfacesInterface_obj.State.Timers.StartupQueryInterval  = &_sqi
    }

    return err
}

var DbToYang_igmp_groups_get_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var cmd_err error
    oper_err := errors.New("Operational error")
    cmn_log := "GET: xfmr for Igmp Groups "
    var vtysh_cmd string

    log.Info("DbToYang_igmp_groups_get_xfmr ***", inParams.uri)
    var igmp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp
    var igmpGroups_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Groups
    igmp_obj, vrfName, err := getIgmpRoot (inParams)
    if err != nil {
        log.Errorf ("%s failed !! Error:%s", cmn_log , err);
        return  oper_err
    }
    log.Info(vrfName)

    // get the values from the backend
    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    log.Info(targetUriPath)
    log.Info(err)

    vtysh_cmd = "show ip igmp vrf "+vrfName+" groups json"
    output_state, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
      log.Errorf("Failed to fetch igmp groups:, err=%s", cmd_err)
      return  cmd_err
    }

    log.Info(output_state)
    log.Info(vrfName)


    igmpGroups_obj = igmp_obj.Groups
    if igmpGroups_obj == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Groups  container missing", cmn_log)
        igmpGroups_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Groups)
        if igmpGroups_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Groups container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpGroups_obj)
        igmp_obj.Groups = igmpGroups_obj
    }

    err = fill_igmp_groups_xfmr (output_state, igmpGroups_obj)
    return  err;
}

var DbToYang_igmp_interface_get_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var cmd_err error
    oper_err := errors.New("Operational error")
    cmn_log := "GET: xfmr for Igmp Interface "
    var vtysh_cmd string
    var interfacename string

    log.Info("DbToYang_igmp_interface_get_xfmr ***", inParams.uri)
    var igmp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp
    igmp_obj, vrfName, err := getIgmpRoot (inParams)
    if err != nil {
        log.Errorf ("%s failed !! Error:%s", cmn_log , err);
        return  oper_err
    }
    log.Info(vrfName)
    // get the values from the backend
    pathInfo := NewPathInfo(inParams.uri)
    log.Info(pathInfo)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    log.Info(targetUriPath)
    
    interfacename = pathInfo.Var("interface-id")
    log.Info(interfacename)

    vtysh_cmd = "show ip igmp vrf "+vrfName+" interface "+interfacename+" json"
    output_state, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
      log.Errorf("Failed to fetch igmp interface details:, err=%s", cmd_err)
      return  cmd_err
    }
    log.Info(output_state)
    log.Info(vrfName)

    for key,value := range output_state {
        interface_info := value.(map[string]interface{})
        log.Info(key)
        log.Info(interface_info)
        err = fill_igmp_interface_xfmr (interface_info,key,igmp_obj)
    }
    return err;
}

var DbToYang_igmp_stats_get_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var cmd_err error
    oper_err := errors.New("Operational error")
    cmn_log := "GET: xfmr for Igmp Groups "
    var vtysh_cmd string

    log.Info("DbToYang_igmp_stats_get_xfmr ***", inParams.uri)
    var igmp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp
    igmp_obj, vrfName, err := getIgmpRoot (inParams)
    if err != nil {
        log.Errorf ("%s failed !! Error:%s", cmn_log , err);
        return  oper_err
    }
    log.Info(vrfName)
    // get the values from the backend
    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    log.Info(targetUriPath)
    
    vtysh_cmd = "show ip igmp vrf "+vrfName+" statistics json"
    output_state, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
      log.Errorf("Failed to fetch igmp statistics:, err=%s", cmd_err)
      return  cmd_err
    }
    log.Info(output_state)
    log.Info(vrfName)

    for key,value := range output_state {
        stats_info := value.(map[string]interface{})
        log.Info(key)
        log.Info(stats_info)
        err = fill_igmp_stats_xfmr (stats_info, igmp_obj)
    }
    return  err;
}

var DbToYang_igmp_sources_get_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    var cmd_err error
    oper_err := errors.New("Operational error")
    cmn_log := "GET: xfmr for Igmp Groups "
    var vtysh_cmd string

    log.Info("DbToYang_igmp_sources_get_xfmr ***", inParams.uri)
    var igmp_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp
    var igmpSources_obj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Sources
    igmp_obj, vrfName, err := getIgmpRoot (inParams)
    if err != nil {
        log.Errorf ("%s failed !! Error:%s", cmn_log , err);
        return  oper_err
    }
    log.Info(vrfName)

    // get the values from the backend
    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, err := getYangPathFromUri(pathInfo.Path)
    log.Info(targetUriPath)
    log.Info(err)

    vtysh_cmd = "show ip igmp vrf "+vrfName+" sources json"
    output_state, cmd_err := exec_vtysh_cmd (vtysh_cmd)
    if cmd_err != nil {
      log.Errorf("Failed to fetch igmp sources:, err=%s", cmd_err)
      return  cmd_err
    }

    log.Info(output_state)
    log.Info(vrfName)


    igmpSources_obj = igmp_obj.Sources
    if igmpSources_obj == nil {
        log.Errorf("%s failed !! Error: IGMP Igmp Sources  container missing", cmn_log)
        igmpSources_obj = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Igmp_Sources)
        if igmpSources_obj == nil {
            log.Errorf("%s failed !! Error:Failed to create Igmp Sources container", cmn_log)
            return oper_err
        }
        ygot.BuildEmptyTree (igmpSources_obj)
        igmp_obj.Sources = igmpSources_obj
    }

    err = fill_igmp_sources_xfmr (output_state, igmpSources_obj)
    return  err;
}

