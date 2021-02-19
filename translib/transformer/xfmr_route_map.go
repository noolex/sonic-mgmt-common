package transformer

import (
	"bytes"
	"strings"
    "strconv" 
	"fmt"
	"errors"
    log "github.com/golang/glog"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"reflect"
	"github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/db"
)

func init () {
    XlateFuncBind("YangToDb_route_map_key_xfmr", YangToDb_route_map_key_xfmr)
    XlateFuncBind("DbToYang_route_map_key_xfmr", DbToYang_route_map_key_xfmr)
    XlateFuncBind("YangToDb_route_map_action_policy_result_xfmr", YangToDb_route_map_action_policy_result_xfmr)
    XlateFuncBind("DbToYang_route_map_action_policy_result_xfmr", DbToYang_route_map_action_policy_result_xfmr)
    XlateFuncBind("YangToDb_route_map_match_protocol_xfmr", YangToDb_route_map_match_protocol_xfmr)
    XlateFuncBind("DbToYang_route_map_match_protocol_xfmr", DbToYang_route_map_match_protocol_xfmr)
    XlateFuncBind("YangToDb_route_map_match_set_options_xfmr", YangToDb_route_map_match_set_options_xfmr)
    XlateFuncBind("DbToYang_route_map_match_set_options_xfmr", DbToYang_route_map_match_set_options_xfmr)
    XlateFuncBind("YangToDb_route_map_match_set_options_restrict_type_xfmr", YangToDb_route_map_match_set_options_restrict_type_xfmr)
    XlateFuncBind("DbToYang_route_map_match_set_options_restrict_type_xfmr", DbToYang_route_map_match_set_options_restrict_type_xfmr)
    XlateFuncBind("YangToDb_route_map_bgp_action_set_community", YangToDb_route_map_bgp_action_set_community)
    XlateFuncBind("DbToYang_route_map_bgp_action_set_community", DbToYang_route_map_bgp_action_set_community)
    XlateFuncBind("YangToDb_route_map_bgp_action_set_ext_community", YangToDb_route_map_bgp_action_set_ext_community)
    XlateFuncBind("DbToYang_route_map_bgp_action_set_ext_community", DbToYang_route_map_bgp_action_set_ext_community)
    XlateFuncBind("YangToDb_route_map_set_next_hop_xfmr", YangToDb_route_map_set_next_hop_xfmr)
    XlateFuncBind("DbToYang_route_map_set_next_hop_xfmr", DbToYang_route_map_set_next_hop_xfmr)
    XlateFuncBind("DbToYang_route_map_field_xfmr", DbToYang_route_map_field_xfmr)
    XlateFuncBind("YangToDb_route_map_field_xfmr", YangToDb_route_map_field_xfmr)
    XlateFuncBind("YangToDb_route_map_stmt_field_xfmr", YangToDb_route_map_stmt_field_xfmr)
    XlateFuncBind("DbToYang_route_map_stmt_field_xfmr", DbToYang_route_map_stmt_field_xfmr)
    XlateFuncBind("YangToDb_route_map_set_ipv6_next_hop_xfmr", YangToDb_route_map_set_ipv6_next_hop_xfmr)
    XlateFuncBind("DbToYang_route_map_set_ipv6_next_hop_xfmr", DbToYang_route_map_set_ipv6_next_hop_xfmr)
    XlateFuncBind("YangToDb_route_map_set_med_xfmr", YangToDb_route_map_set_med_xfmr)
    XlateFuncBind("DbToYang_route_map_set_med_xfmr", DbToYang_route_map_set_med_xfmr)
    XlateFuncBind("DbToYangPath_route_map_path_xfmr", DbToYangPath_route_map_path_xfmr)
}

var DbToYang_route_map_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error
    
    entry_key := inParams.key
    log.Info("DbToYang_route_map_field_xfmr: ", entry_key)

    dynKey := strings.Split(entry_key, "|")

    rmap["name"] = dynKey[0]

    return rmap, err
}

var YangToDb_route_map_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    rmap := make(map[string]string)
    var err error

    log.Info("YangToDb_route_map_field_xfmr")
    rmap["NULL"] = "NULL"
    
    return rmap, err
}

var YangToDb_route_map_stmt_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    rmap := make(map[string]string)
    var err error

    log.Info("YangToDb_route_map_stmt_field_xfmr")
    rmap["NULL"] = "NULL"
    
    return rmap, err
}

var DbToYang_route_map_stmt_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error
    
    entry_key := inParams.key
    log.Info("DbToYang_route_map_stmt_field_xfmr: ", entry_key)

    dynKey := strings.Split(entry_key, "|")

    rmap["name"] = dynKey[1]

    return rmap, err
}

var YangToDb_route_map_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var entry_key string
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    rtMapName := pathInfo.Var("name")
    stmtName := pathInfo.Var("name#2")

    if len(stmtName) == 0 {
        return entry_key, err
    }
    /* @@TODO For now, due to infra. ordering issue, always assuming statement name is uint16 value. */
    _, err = strconv.ParseUint(stmtName, 10, 16)
    if err != nil {
        log.Info("URI route-map invalid statement name type, use values in range (1-65535)", stmtName)
	    return entry_key, tlerr.InvalidArgs("Statement '%s' not supported, use values in range (1-65535)", stmtName)
    }
    entry_key = rtMapName + "|" + stmtName
    log.Info("URI route-map ", entry_key)

    return entry_key, err
}

var DbToYang_route_map_key_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    var err error
    
    entry_key := inParams.key
    log.Info("DbToYang_route_map_key_xfmr: ", entry_key)

    dynKey := strings.Split(entry_key, "|")

    rmap["name"] = dynKey[1]

    return rmap, err
}

var YangToDb_route_map_action_policy_result_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)
    var err error
    if inParams.oper == DELETE {
        res_map["route_operation"] = ""
        return res_map, nil
    }

    if inParams.param == nil {
        return res_map, err
    }
 
    action, _ := inParams.param.(ocbinds.E_OpenconfigRoutingPolicy_PolicyResultType)
    log.Info("YangToDb_route_map_action_policy_result_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " route-operation: ", action)
    if action == ocbinds.OpenconfigRoutingPolicy_PolicyResultType_ACCEPT_ROUTE {
        res_map["route_operation"] = "permit"
    } else if action == ocbinds.OpenconfigRoutingPolicy_PolicyResultType_REJECT_ROUTE {
        res_map["route_operation"] = "deny"
    }
    return res_map, err
}

var DbToYang_route_map_action_policy_result_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_bgp_external_compare_router_id_xfmr", data, "inParams : ", inParams)

    pTbl := data["ROUTE_MAP"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_route_map_action_policy_result_xfmr table not found : ", inParams.key)
        return result, errors.New("Policy definition table not found : " + inParams.key)
    }
    niInst := pTbl[inParams.key]
    route_operation, ok := niInst.Field["route_operation"]
    if ok {
        if route_operation == "permit" {
            result["policy-result"] = "ACCEPT_ROUTE"
        } else {
            result["policy-result"] = "REJECT_ROUTE"
        }
    } else {
        log.Info("DbToYang_route_map_action_policy_result_xfmr field not found in DB")
    }
    return result, err
}



var DbToYang_route_map_set_next_hop_xfmr FieldXfmrDbtoYang= func(inParams XfmrParams) (map[string]interface{}, error) {

    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_route_map_set_next_hop_xfmr: ", data, "inParams : ", inParams)

    pTbl := data["ROUTE_MAP"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_route_map_action_policy_result_xfmr table not found : ", inParams.key)
        return result, errors.New("Policy definition table not found : " + inParams.key)
    }
    niInst := pTbl[inParams.key]
    route_hop, ok := niInst.Field["set_next_hop"]
    if ok {
            result["set-next-hop"] = route_hop
    } else {
        log.Info("DbToYang_route_map_set_next_hop_xfmr field not found in DB")
    }
    return result, nil 
}

var YangToDb_route_map_set_next_hop_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    if inParams.oper == DELETE {
        res_map["set_next_hop"] = ""
        return res_map, nil
    }

    if inParams.param == nil {
        err = errors.New("No Params")
        return res_map, err
    }
    addr := inParams.param.(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_Config_SetNextHop_Union_String).String

    /* Reject special address settings */
    if (addr == "0.0.0.0") {
        log.Info("YangToDb_route_map_set_next_hop_xfmr ipPtr value 0.0.0.0, multicast and reserved address are not acceptable")
        err = errors.New("ip addr 0.0.0.0, multicast and reserved address are not acceptable")   
        return res_map, err
    }

    first_no := strings.Split(addr, ".") 
    fst_byt, err:= strconv.ParseInt(first_no[0],10,64)
    if (err != nil) {
       log.Error("Parse set_nex_hop addr failed ")
       return res_map, err

    }
    if (fst_byt >= 224 ) {
       err = errors.New("ip addr 0.0.0.0, multicast and reserved address are not acceptable")
       log.Info("YangToDb_route_map_set_next_hop_xfmr ipPtr value 0.0.0.0, multicast and reserd address are not acceptable");
       return res_map, err

    }
    res_map["set_next_hop"] = addr;
    return res_map, nil
}

var DbToYang_route_map_set_ipv6_next_hop_xfmr FieldXfmrDbtoYang= func(inParams XfmrParams) (map[string]interface{}, error) {

    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_route_map_set_ipv6_next_hop_xfmr: ", data, "inParams : ", inParams)

    pTbl := data["ROUTE_MAP"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_route_map_set_ipv6_next_hop_xfmr table not found : ", inParams.key)
        return result, errors.New("Policy definition table not found : " + inParams.key)
    }
    niInst := pTbl[inParams.key]
    route_hop, ok := niInst.Field["set_ipv6_next_hop_global"]
    if ok {
            result["set-ipv6-next-hop-global"] = route_hop
    } else {
        log.Info("DbToYang_route_map_set_ipv6_next_hop_xfmr field not found in DB")
    }
    return result, nil 
}

var YangToDb_route_map_set_ipv6_next_hop_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    if inParams.oper == DELETE {
        res_map["set_ipv6_next_hop_global"] = ""
        return res_map, nil
    }

    if inParams.param == nil {
        err = errors.New("No Params")
        return res_map, err
    }
    addr, _ := inParams.param.(*string)

    if (!validIPv6(*addr)) {
        log.Error("Invalid IPv6 address ", *addr)
        err = errors.New("Invalid IPv6 address!")
        return res_map, err
    }
    res_map["set_ipv6_next_hop_global"] = *addr;
    return res_map, nil
}


var YangToDb_route_map_match_protocol_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)
    var err error
 
    if inParams.oper == DELETE {
        res_map["match_protocol"] = ""
        return res_map, nil
    }

    if inParams.param == nil {
        return res_map, err
    }
    protocol, _ := inParams.param.(ocbinds.E_OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE)
    log.Info("YangToDb_route_map_match_protocol_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " protocol: ", protocol)
    switch protocol {
        case ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_BGP:
            res_map["match_protocol"] = "bgp"
        case ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_DIRECTLY_CONNECTED:
            res_map["match_protocol"] = "connected"
        case ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_ISIS:
            res_map["match_protocol"] = "isis"
        case ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF:
            res_map["match_protocol"] = "ospf"
        case ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF3:
            res_map["match_protocol"] = "ospf3"
        case ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC:
            res_map["match_protocol"] = "static"
        default:
    }
    return res_map, err
}

var DbToYang_route_map_match_protocol_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_route_map_match_protocol_xfmr", data, "inParams : ", inParams)

    pTbl := data["ROUTE_MAP"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_route_map_match_protocol_xfmr table not found : ", inParams.key)
        return result, errors.New("Policy definition table not found : " + inParams.key)
    }
    niInst := pTbl[inParams.key]
    protocol, ok := niInst.Field["match_protocol"]
    if ok {
        switch protocol {
            case "bgp":
                result["install-protocol-eq"] = "BGP"
            case "connected":
                result["install-protocol-eq"] = "DIRECTLY_CONNECTED"
            case "isis":
                result["install-protocol-eq"] = "ISIS"
            case "ospf":
                result["install-protocol-eq"] = "OSPF"
            case "ospf3":
                result["install-protocol-eq"] = "OSPF3"
            case "static":
                result["install-protocol-eq"] = "STATIC"
            default:
        }
    } else {
        log.Info("DbToYang_route_map_match_protocol_xfmr field not found in DB")
    }
    return result, err
}

var YangToDb_route_map_match_set_options_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)
    var err error
    if inParams.param == nil {
        return res_map, err
    }
    action, _ := inParams.param.(ocbinds.E_OpenconfigRoutingPolicy_MatchSetOptionsType)
    log.Info("YangToDb_route_map_match_set_options_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " match-set-option: ", action)
    if action != ocbinds.OpenconfigRoutingPolicy_MatchSetOptionsType_ANY {
        err = errors.New("Invalid match set option")
        return res_map, err
    }
    return res_map, err
}

var DbToYang_route_map_match_set_options_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    
    result["match-set-options"] = "ANY"
    return result, err
}

var YangToDb_route_map_match_set_options_restrict_type_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {

    res_map := make(map[string]string)
    var err error
    if inParams.param == nil {
        return res_map, err
    }
    action, _ := inParams.param.(ocbinds.E_OpenconfigRoutingPolicy_MatchSetOptionsRestrictedType)
    log.Info("YangToDb_route_map_match_set_options_restrict_type_xfmr: ", inParams.ygRoot, " Xpath: ", inParams.uri, " match-set-option: ", action)
    if action != ocbinds.OpenconfigRoutingPolicy_MatchSetOptionsRestrictedType_ANY {
        err = errors.New("Invalid match set option")
        return res_map, err
    }
    return res_map, err
}

var DbToYang_route_map_match_set_options_restrict_type_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    result := make(map[string]interface{})
    
    result["match-set-options"] = "ANY"
    return result, err
}


func getRoutingPolicyRoot (s *ygot.GoStruct) *ocbinds.OpenconfigRoutingPolicy_RoutingPolicy {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.RoutingPolicy
}

var YangToDb_route_map_bgp_action_set_community SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)
    stmtmap := make(map[string]db.Value)

    log.Info("YangToDb_route_map_bgp_action_set_community: ", inParams.ygRoot, inParams.uri, inParams.requestUri)
    rtPolDefsObj := getRoutingPolicyRoot(inParams.ygRoot)
    if rtPolDefsObj == nil || rtPolDefsObj.PolicyDefinitions == nil || len (rtPolDefsObj.PolicyDefinitions.PolicyDefinition) < 1 {
        if inParams.oper == DELETE {
            /* If parent level delete has triggered 
             * this child sub tree transfomer return success*/
            res_map["ROUTE_MAP"] = stmtmap
            res_map["ROUTE_MAP_SET"] = stmtmap
            return res_map, nil
        }
        log.Info("YangToDb_route_map_bgp_action_set_community : Routing policy definitions list is empty.")
        return res_map, errors.New("Routing policy definitions list is empty")
    }
    pathInfo := NewPathInfo(inParams.uri)
    rtPolicyName := pathInfo.Var("name")
    rtStmtName := pathInfo.Var("name#2")

    if rtPolicyName == "" || rtStmtName == "" {
        return res_map, errors.New("Routing policy keys are not present")
    }

    rtPolDefObj := rtPolDefsObj.PolicyDefinitions.PolicyDefinition[rtPolicyName]

    if rtPolDefObj.Statements == nil || rtPolDefObj.Statements.Statement == nil {
        if inParams.oper == DELETE {
            /* If parent level delete has triggered 
             * this child sub tree transfomer return success*/
            return res_map, nil
        }
        return res_map, errors.New("Routing policy statement config is not present ")
    }

    rtStmtObj := rtPolDefObj.Statements.Statement[rtStmtName]

    if rtStmtObj.Actions == nil || rtStmtObj.Actions.BgpActions == nil || rtStmtObj.Actions.BgpActions.SetCommunity == nil {
        if inParams.oper == DELETE {
            /* If parent level delete has triggered 
             * this child sub tree transfomer return success*/
            return res_map, nil
        }
        return res_map, errors.New("Routing policy invalid action parameters")
    }

    rtStmtActionCommObj := rtStmtObj.Actions.BgpActions.SetCommunity
    if rtStmtActionCommObj == nil || (inParams.oper != DELETE && rtStmtActionCommObj.Config == nil) {
        return res_map, errors.New("Routing policy invalid action parameters")
    }

    entry_key := rtPolicyName + "|" + rtStmtName
    stmtmap[entry_key] = db.Value{Field: make(map[string]string)}

    final_std_community := ""
    if rtStmtActionCommObj.Config != nil && rtStmtActionCommObj.Config.Method == ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_INLINE {
        if rtStmtActionCommObj.Inline == nil || rtStmtActionCommObj.Inline.Config == nil || len(rtStmtActionCommObj.Inline.Config.Communities) == 0 {
            return res_map, errors.New("Routing policy invalid action parameters")
        }

        log.Info("YangToDb_route_map_bgp_action_set_community: ", rtStmtActionCommObj.Inline.Config.Communities)
        for _, commUnion := range rtStmtActionCommObj.Inline.Config.Communities {
            log.Info("YangToDb_route_map_bgp_action_set_community individual community value: ", commUnion)
            var b bytes.Buffer
            commType := reflect.TypeOf(commUnion).Elem()
            std_community := ""
            switch commType {
            case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union_E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY{}):
                v := (commUnion).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union_E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY)
                switch v.E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY {
                case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NOPEER:
                    std_community = "no-peer"
                case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_ADVERTISE:
                    std_community = "no-advertise"
                case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT:
                    std_community = "no-export"
                case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT_SUBCONFED:
                    std_community = "local-AS"
                case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_ADDITIVE:
                    std_community = "additive"
                }
            case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union_Uint32{}):
                v := (commUnion).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union_Uint32)
                fmt.Fprintf(&b, "0x%x", v.Uint32)
                std_community = b.String()
            case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union_String{}):
                v := (commUnion).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union_String)
                std_community = v.String
            }
            if final_std_community == "" {
                final_std_community = std_community
            } else {
                final_std_community = final_std_community + "," + std_community
            }
        }
        if rtStmtActionCommObj.Config.Options == ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_ADD {
            log.Info("YangToDb_route_map_bgp_action_set_ext_community : ADD ", final_std_community)
            if final_std_community == "additive" {
                return res_map, errors.New("Routing policy community cant have just additive")
            }
            stmtmap[entry_key].Field["set_community_inline@"] = final_std_community
        } else {
             subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

             if _, ok := subOpMap[db.ConfigDB]; !ok {
                 subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
             }
             if _, ok := subOpMap[db.ConfigDB]["ROUTE_MAP"]; !ok {
                 subOpMap[db.ConfigDB]["ROUTE_MAP"] = make(map[string]db.Value)
             }
             subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key] = db.Value{Field: make(map[string]string)}

             if rtStmtActionCommObj.Config.Options == ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_REMOVE {
                 log.Info("YangToDb_route_map_bgp_action_set_ext_community : REMOVE")
                 subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key].Field["set_community_inline@"] = final_std_community
                 inParams.subOpDataMap[DELETE] = &subOpMap
             } else {
                 log.Info("YangToDb_route_map_bgp_action_set_ext_community : REPLACE ", final_std_community)
                 if final_std_community == "additive" {
                     return res_map, errors.New("Routing policy community cant have just additive")
                 }

                 rtMapInst, _ := inParams.d.GetEntry(&db.TableSpec{Name:"ROUTE_MAP"}, db.Key{Comp: []string{entry_key}})
                 subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key] = rtMapInst
                 subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key].Field["set_community_inline@"] = final_std_community
                 inParams.subOpDataMap[REPLACE] = &subOpMap
             }
             return res_map, nil
         }
    } else if rtStmtActionCommObj.Config != nil && rtStmtActionCommObj.Config.Method == ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_REFERENCE {
        if rtStmtActionCommObj.Reference == nil {
            return res_map, errors.New("Routing policy invalid action parameters")
        }
        if rtStmtActionCommObj.Config.Options == ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_REMOVE { 
            subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

             if _, ok := subOpMap[db.ConfigDB]; !ok {
                 subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
             }
             if _, ok := subOpMap[db.ConfigDB]["ROUTE_MAP"]; !ok {
                 subOpMap[db.ConfigDB]["ROUTE_MAP"] = make(map[string]db.Value)
             }
             subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key] = db.Value{Field: make(map[string]string)}
             subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key].Field["set_community_ref"] = *rtStmtActionCommObj.Reference.Config.CommunitySetRef
             inParams.subOpDataMap[DELETE] = &subOpMap
             return res_map, nil
        } else {
            stmtmap[entry_key].Field["set_community_ref"] = *rtStmtActionCommObj.Reference.Config.CommunitySetRef
        }
    } else if (rtStmtActionCommObj.Config == nil) && (inParams.oper == DELETE) {
         stmtmap[entry_key].Field["set_community_inline@"] = ""
         stmtmap[entry_key].Field["set_community_ref"] = ""
    }
    res_map["ROUTE_MAP"] = stmtmap
    return res_map, err
}

var DbToYang_route_map_bgp_action_set_community SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("targetUriPath is ", targetUriPath)
    rtPolDefsObj := getRoutingPolicyRoot(inParams.ygRoot)
    if rtPolDefsObj == nil {
        log.Info("DbToYang_route_map_bgp_action_set_community: Routing policy definitions list is empty.")
        return errors.New("Routing policy definitions list is empty")
    }
    ygot.BuildEmptyTree(rtPolDefsObj)
    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_route_map_bgp_action_set_community: ", data, inParams.ygRoot)

    rtPolicyName := pathInfo.Var("name")
    rtStmtName := pathInfo.Var("name#2")

    if rtPolicyName == "" || rtStmtName == "" {
        return errors.New("Routing policy keys are not present")
    }
    rtPolDefObj := rtPolDefsObj.PolicyDefinitions.PolicyDefinition[rtPolicyName]
    if rtPolDefObj == nil {
        rtPolDefObj,_ = rtPolDefsObj.PolicyDefinitions.NewPolicyDefinition(rtPolicyName)
    }
    ygot.BuildEmptyTree(rtPolDefObj)

    rtStmtObj := rtPolDefObj.Statements.Statement[rtStmtName]
    if rtStmtObj == nil {
        rtStmtObj,_ = rtPolDefObj.Statements.NewStatement(rtStmtName)
    }
    ygot.BuildEmptyTree(rtStmtObj)
    if rtStmtObj.Actions == nil {
        var actions ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions
        rtStmtObj.Actions = &actions
    }
    ygot.BuildEmptyTree(rtStmtObj.Actions)
    rtStmtActionCommObj := rtStmtObj.Actions.BgpActions.SetCommunity
    if rtStmtActionCommObj == nil {
        var set_comm ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity
        rtStmtObj.Actions.BgpActions.SetCommunity =&set_comm
        rtStmtActionCommObj = rtStmtObj.Actions.BgpActions.SetCommunity
    }
    ygot.BuildEmptyTree(rtStmtActionCommObj)
    entry_key := rtPolicyName + "|" + rtStmtName
    pTbl := data["ROUTE_MAP"]
    if _, ok := pTbl[entry_key]; !ok {
        log.Info("DbToYang_intf_enabled_xfmr Interface not found : ")
        return errors.New("Route map entry not found : ")
    }
    rtMapInst := pTbl[entry_key]

    communityInlineVal, ok := rtMapInst.Field["set_community_inline@"]
    log.Info("DbToYang_route_map_bgp_action_set_community: ", communityInlineVal)
    if ok {    
       rtStmtActionCommObj.Config.Method = ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_INLINE
           var CfgCommunities []ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union
           var StateCommunities []ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union
       for _, comm_val := range strings.Split(communityInlineVal, ",") {
           log.Info("DbToYang_route_map_bgp_action_set_community individual community value: ", comm_val)
           if (comm_val == "no-peer") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NOPEER)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NOPEER)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
           } else if (comm_val == "no-advertise") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_ADVERTISE)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_ADVERTISE)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
           } else if (comm_val == "no-export") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
            } else if (comm_val == "local-AS") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT_SUBCONFED)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT_SUBCONFED)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
            } else if (comm_val == "additive") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_ADDITIVE)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_ADDITIVE)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)

            } else {
                n, err := strconv.ParseInt(comm_val, 10, 32)
                if err == nil {
                    n := uint32(n)
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union(n)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union(n)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
                } else {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_Config_Communities_Union(comm_val)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Inline_State_Communities_Union(comm_val)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
                }
           }
       }
       rtStmtActionCommObj.Inline.Config.Communities = CfgCommunities
       rtStmtActionCommObj.Inline.State.Communities = StateCommunities
    } else {
       communityRef, ok := rtMapInst.Field["set_community_ref"]
       log.Info("DbToYang_route_map_bgp_action_set_community reference: ", communityRef)
       if ok {
           rtStmtActionCommObj.Config.Method = ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_REFERENCE
           rtStmtActionCommObj.Reference.Config.CommunitySetRef = &communityRef
           rtStmtActionCommObj.Reference.State.CommunitySetRef = &communityRef
       } else {
           return err
       }
    }
    rtStmtActionCommObj.Config.Options = ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_ADD
    rtStmtActionCommObj.State.Method = rtStmtActionCommObj.Config.Method
    rtStmtActionCommObj.State.Options = rtStmtActionCommObj.Config.Options

    return err
}

var YangToDb_route_map_bgp_action_set_ext_community SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    res_map := make(map[string]map[string]db.Value)
    stmtmap := make(map[string]db.Value)

    log.Info("YangToDb_route_map_bgp_action_set_ext_community: ", inParams.ygRoot, inParams.uri)
    rtPolDefsObj := getRoutingPolicyRoot(inParams.ygRoot)
    if rtPolDefsObj == nil || rtPolDefsObj.PolicyDefinitions == nil || len (rtPolDefsObj.PolicyDefinitions.PolicyDefinition) < 1 {
        if inParams.oper == DELETE {
            /* If parent level delete has triggered 
             * this child sub tree transfomer return success*/
            res_map["ROUTE_MAP"] = stmtmap
            res_map["ROUTE_MAP_SET"] = stmtmap
            return res_map, nil
        }

        log.Info("YangToDb_route_map_bgp_action_set_community : Routing policy definitions list is empty.")
        return res_map, errors.New("Routing policy definitions list is empty")
    }
    pathInfo := NewPathInfo(inParams.uri)
    rtPolicyName := pathInfo.Var("name")
    rtStmtName := pathInfo.Var("name#2")

    if rtPolicyName == "" || rtStmtName == "" {
        return res_map, errors.New("Routing policy keys are not present")
    }

    rtPolDefObj := rtPolDefsObj.PolicyDefinitions.PolicyDefinition[rtPolicyName]
    if rtPolDefObj.Statements == nil || rtPolDefObj.Statements.Statement == nil {
        if inParams.oper == DELETE {
            /* If parent level delete has triggered 
             * this child sub tree transfomer return success*/
            return res_map, nil
        }
        return res_map, errors.New("Routing policy statement config is not present ")
    }

    rtStmtObj := rtPolDefObj.Statements.Statement[rtStmtName]

    if rtStmtObj.Actions == nil || rtStmtObj.Actions.BgpActions == nil || rtStmtObj.Actions.BgpActions.SetExtCommunity == nil {
        if inParams.oper == DELETE {
            /* If parent level delete has triggered 
             * this child sub tree transfomer return success*/
            return res_map, nil
        }

        return res_map, errors.New("Routing policy invalid action parameters")
    }

    rtStmtActionCommObj := rtStmtObj.Actions.BgpActions.SetExtCommunity
    if rtStmtActionCommObj == nil || (inParams.oper != DELETE && rtStmtActionCommObj.Config == nil) {
        return res_map, errors.New("Routing policy invalid action parameters")
    }

    entry_key := rtPolicyName + "|" + rtStmtName
    stmtmap[entry_key] = db.Value{Field: make(map[string]string)}

    final_std_community := ""
    if rtStmtActionCommObj.Config != nil && (rtStmtActionCommObj.Config.Method == ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_INLINE) {

        if rtStmtActionCommObj.Inline == nil || rtStmtActionCommObj.Inline.Config == nil || len(rtStmtActionCommObj.Inline.Config.Communities) == 0 {
            return res_map, errors.New("Routing policy invalid action parameters")
        }

        for _, commUnion := range rtStmtActionCommObj.Inline.Config.Communities {
            log.Info("YangToDb_route_map_bgp_action_set_ext_community individual community: ",commUnion) 
            commType := reflect.TypeOf(commUnion).Elem()
            std_community := ""
            switch commType {
                case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union_E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY{}):
v := (commUnion).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union_E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY)
                    switch v.E_OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY {
                        case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NOPEER:
                            std_community = "no-peer"
                        case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_ADVERTISE:
                            std_community = "no-advertise"
                        case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT:
                            std_community = "no-export"
                        case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT_SUBCONFED:
                            std_community = "local-AS"
                        case ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_ADDITIVE:
                            std_community = "additive"
                    }
                case reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union_String{}):
                    v := (commUnion).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union_String)
                    std_community = v.String
            }
            if final_std_community == "" {
                final_std_community = std_community
            } else {
                final_std_community = final_std_community + "," + std_community
            }
          }
          if rtStmtActionCommObj.Config.Options == ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_ADD {
              stmtmap[entry_key].Field["set_ext_community_inline@"] = final_std_community
          } else {
             subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

             if _, ok := subOpMap[db.ConfigDB]; !ok {
                 subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
             }
             if _, ok := subOpMap[db.ConfigDB]["ROUTE_MAP"]; !ok {
                 subOpMap[db.ConfigDB]["ROUTE_MAP"] = make(map[string]db.Value)
             }
             subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key] = db.Value{Field: make(map[string]string)}

             if rtStmtActionCommObj.Config.Options == ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_REMOVE {
                 log.Info("YangToDb_route_map_bgp_action_set_community : REMOVE")
                 subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key].Field["set_ext_community_inline@"] = final_std_community
                 inParams.subOpDataMap[DELETE] = &subOpMap
             } else {
                 log.Info("YangToDb_route_map_bgp_action_set_community : REPLACE")
                 rtMapInst, _ := inParams.d.GetEntry(&db.TableSpec{Name:"ROUTE_MAP"}, db.Key{Comp: []string{entry_key}})
                 subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key] = rtMapInst
                 subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key].Field["set_community_inline@"] = final_std_community
                 inParams.subOpDataMap[REPLACE] = &subOpMap
             }
             return res_map, nil
         }
    } else if rtStmtActionCommObj.Config != nil && rtStmtActionCommObj.Config.Method == ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_REFERENCE {
        if rtStmtActionCommObj.Reference == nil {
            return res_map, errors.New("Routing policy invalid action parameters")
        }
        if rtStmtActionCommObj.Config.Options == ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_REMOVE { 
             subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)

             if _, ok := subOpMap[db.ConfigDB]; !ok {
                 subOpMap[db.ConfigDB] = make(map[string]map[string]db.Value)
             }
             if _, ok := subOpMap[db.ConfigDB]["ROUTE_MAP"]; !ok {
                 subOpMap[db.ConfigDB]["ROUTE_MAP"] = make(map[string]db.Value)
             }
             subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key] = db.Value{Field: make(map[string]string)}
             subOpMap[db.ConfigDB]["ROUTE_MAP"][entry_key].Field["set_ext_community_ref"] = *rtStmtActionCommObj.Reference.Config.ExtCommunitySetRef

             inParams.subOpDataMap[DELETE] = &subOpMap
             return res_map, nil
        } else {
            stmtmap[entry_key].Field["set_ext_community_ref"] = *rtStmtActionCommObj.Reference.Config.ExtCommunitySetRef
        }
    } else if ((rtStmtActionCommObj.Config == nil) && (inParams.oper == DELETE)) {
         stmtmap[entry_key].Field["set_ext_community_inline@"] = ""
         stmtmap[entry_key].Field["set_ext_community_ref"] = ""
    }

    res_map["ROUTE_MAP"] = stmtmap
    return res_map, err
}

var DbToYang_route_map_bgp_action_set_ext_community SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error

    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Info("targetUriPath is ", targetUriPath)
    rtPolDefsObj := getRoutingPolicyRoot(inParams.ygRoot)
    if rtPolDefsObj == nil {
        log.Info("DbToYang_route_map_bgp_action_set_ext_community: Routing policy definitions list is empty.")
        return errors.New("Routing policy definitions list is empty")
    }
    ygot.BuildEmptyTree(rtPolDefsObj)
    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_route_map_bgp_action_set_ext_community: ", data, inParams.ygRoot)

    rtPolicyName := pathInfo.Var("name")
    rtStmtName := pathInfo.Var("name#2")

    if rtPolicyName == "" || rtStmtName == "" {
        return errors.New("Routing policy keys are not present")
    }
    rtPolDefObj := rtPolDefsObj.PolicyDefinitions.PolicyDefinition[rtPolicyName]

    if rtPolDefObj == nil {
        rtPolDefObj,_ = rtPolDefsObj.PolicyDefinitions.NewPolicyDefinition(rtPolicyName)
    }
    ygot.BuildEmptyTree(rtPolDefObj)

    rtStmtObj := rtPolDefObj.Statements.Statement[rtStmtName]
    if rtStmtObj == nil {
        rtStmtObj,_ = rtPolDefObj.Statements.NewStatement(rtStmtName)
    }
    ygot.BuildEmptyTree(rtStmtObj)

    if rtStmtObj.Actions == nil {
        var actions ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions
        rtStmtObj.Actions = &actions
    }
    ygot.BuildEmptyTree(rtStmtObj.Actions)
    rtStmtActionCommObj := rtStmtObj.Actions.BgpActions.SetExtCommunity
    if rtStmtActionCommObj == nil {
        var set_comm ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity
        rtStmtObj.Actions.BgpActions.SetExtCommunity =&set_comm
        rtStmtActionCommObj = rtStmtObj.Actions.BgpActions.SetExtCommunity
    }
    ygot.BuildEmptyTree(rtStmtActionCommObj)

    entry_key := rtPolicyName + "|" + rtStmtName
    pTbl := data["ROUTE_MAP"]
    if _, ok := pTbl[entry_key]; !ok {
        log.Info("DbToYang_intf_enabled_xfmr Interface not found : ")
        return errors.New("Route map entry not found : ")
    }
    rtMapInst := pTbl[entry_key]

    communityInlineVal, ok := rtMapInst.Field["set_ext_community_inline@"]
    log.Info("DbToYang_route_map_bgp_action_set_ext_community inline value: ", communityInlineVal)
    if ok {    
       rtStmtActionCommObj.Config.Method = ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_INLINE
           var CfgCommunities [] ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union
           var StateCommunities [] ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_State_Communities_Union
       for _, comm_val := range strings.Split(communityInlineVal, ",") {
           if (comm_val == "no-peer") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NOPEER)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NOPEER)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
           } else if (comm_val == "no-advertise") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_ADVERTISE)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_ADVERTISE)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
           } else if (comm_val == "no-export") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
         } else if (comm_val == "local-AS") {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT_SUBCONFED)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_State_Communities_Union(ocbinds.OpenconfigBgpTypes_BGP_WELL_KNOWN_STD_COMMUNITY_NO_EXPORT_SUBCONFED)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
         } else {
                    cfg_val, _ := rtStmtActionCommObj.Inline.Config.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_Config_Communities_Union(comm_val)
                    state_val, _ := rtStmtActionCommObj.Inline.State.To_OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetExtCommunity_Inline_State_Communities_Union(comm_val)
                    CfgCommunities = append(CfgCommunities, cfg_val)
                    StateCommunities = append(StateCommunities, state_val)
           }
       }
       rtStmtActionCommObj.Inline.Config.Communities = CfgCommunities
       rtStmtActionCommObj.Inline.State.Communities = StateCommunities
    } else {
       communityRef, ok := rtMapInst.Field["set_ext_community_ref"]
       log.Info("DbToYang_route_map_bgp_action_set_ext_community reference value: ", communityRef)
       if ok {
           rtStmtActionCommObj.Config.Method = ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_SetCommunity_Config_Method_REFERENCE
           rtStmtActionCommObj.Reference.Config.ExtCommunitySetRef = &communityRef
           rtStmtActionCommObj.Reference.State.ExtCommunitySetRef = &communityRef
       } else {
           return err
       }
   }
   rtStmtActionCommObj.Config.Options = ocbinds.OpenconfigBgpPolicy_BgpSetCommunityOptionType_ADD
   rtStmtActionCommObj.State.Method = rtStmtActionCommObj.Config.Method
   rtStmtActionCommObj.State.Options = rtStmtActionCommObj.Config.Options

    return err
}

var DbToYang_route_map_set_med_xfmr FieldXfmrDbtoYang= func(inParams XfmrParams) (map[string]interface{}, error) {

    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_route_map_set_med_xfmr: ", data, "inParams : ", inParams)

    pTbl := data["ROUTE_MAP"]
    if _, ok := pTbl[inParams.key]; !ok {
        log.Info("DbToYang_route_map_set_med_xfmr table not found : ", inParams.key)
        return result, errors.New("Policy definition table not found : " + inParams.key)
    }
    niInst := pTbl[inParams.key]
    set_med, ok := niInst.Field["set_med"]
    if ok {
        result["set-med"] = set_med
    } else {
        log.Info("DbToYang_route_map_set_med_xfmr field not found in DB")
    }
    return result, nil 
}

var YangToDb_route_map_set_med_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    var err error

    if inParams.oper == DELETE {
        res_map["set_med"] = ""
        return res_map, nil
    }

    if inParams.param == nil {
        err = errors.New("No Params")
        return res_map, err
    }
    setMed := inParams.param.(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_Config_SetMed_Union)
    setMedType := reflect.TypeOf(setMed).Elem()

    if setMedType != reflect.TypeOf(ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_Config_SetMed_Union_Uint32{}) {
        log.Info("YangToDb_route_map_set_med_xfmr invalid type ", setMedType)
        return res_map, errors.New("Set MED value should be in uint32 format!")
    }
    var b bytes.Buffer
    v := (setMed).(*ocbinds.OpenconfigRoutingPolicy_RoutingPolicy_PolicyDefinitions_PolicyDefinition_Statements_Statement_Actions_BgpActions_Config_SetMed_Union_Uint32)
    fmt.Fprintf(&b, "%d", v.Uint32)

    res_map["set_med"] = b.String()
    log.Info("YangToDb_route_map_set_med_xfmr DB write value ", res_map["set_med"])
    return res_map, nil
}

var DbToYangPath_route_map_path_xfmr PathXfmrDbToYang = func(params XfmrDbToYgPathParams) (map[sting]string, error) {
    //params.tableName - ROUTE_MAP_SET
    //params.tableKey - "name"

    rpRoot = "/openconfig-routing-policy:routing-policy/policy-definitions/policy-definition"

    pathKeys := make(map[string]string)
    pathKeys[rpRoot + "/name"] = params.tableKeyComp[0]

    return pathKeys, nil
}

