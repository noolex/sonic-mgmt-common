package transformer

import (
    "errors"
    "strings"
    "strconv"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "encoding/json"
    "time"
    log "github.com/golang/glog"
)

type ReferingPolicyEntry struct {
    POLICY_NAME string
    DESCRIPTION string
    PRIORITY    int
}


type ClassifierEntry struct {
    DESCRIPTION string
        MATCH_TYPE string  
        ACL_NAME   string  
        ETHER_TYPE string
        SRC_MAC    string
        DST_MAC    string
        VLAN       int
        PCP        int
        DEI        int
        IP_PROTOCOL int
        SRC_IP     string
        DST_IP     string
        SRC_IPV6   string
        DST_IPV6   string
        DSCP       int
        L4_SRC_PORT int
        L4_SRC_PORT_RANGE string
        L4_DST_PORT int
        L4_DST_PORT_RANGE string
        TCP_FLAGS  string
        REF_POLICY_LIST []  ReferingPolicyEntry
}

type IpNextHopEntry struct {
    NEXTHOP string
    VRF       string
    PRIORITY  int

    //PBF_GROUP_TABLE STATE DB
    SELECTED  bool
}

type ReferringClassConfigEntry struct {
    CLASS_NAME string
    POLICY_NAME string
    DESCRIPTION string
    PRIORITY    int
    SET_DSCP    int
    SET_PCP     int
    SET_POLICER_CIR     uint64
    SET_POLICER_CBS     uint64
    SET_POLICER_PIR     uint64
    SET_POLICER_PBS     uint64
    SET_MIRROR_SESSION  string 
    SET_INTERFACE      string
    SET_IP_NEXTHOP     string
    SET_IPV6_NEXTHOP     string
    IP_NEXTHOP_LIST    [] IpNextHopEntry 
    IPV6_NEXTHOP_LIST    [] IpNextHopEntry 
    DEFAULT_PKT_ACTION  string
}

type PolicyBindPortEntry struct {
    POLICY_BIND_PORT string;
    POLICY_BIND_DIR string;
}

//POLICY_NAME key
type PolicyEntry struct {
    DESCRIPTION string
    TYPE string  
    REF_CLASS_LIST [] ReferringClassConfigEntry 
    APPLIED_PORT_LIST [] PolicyBindPortEntry
}


type ReferringClassOperEntry struct {
   POLICY_BIND_STATUS string

   //FBS_COUNTERS in COUNTERS DB
   FBS_PACKET_COUNT uint64
   FBS_BYTE_COUNT uint64

   //POLICER_COUNTERS in COUNTERS DB
   CONFORMED_PACKET_COUNT uint64
   CONFORMED_BYTE_COUNT uint64
   EXCEED_PACKET_COUNT uint64
   EXCEED_BYTE_COUNT uint64
   VIOLATED_PACKET_COUNT uint64
   VIOLATED_BYTE_COUNT uint64
   CONFORMED_PACKET_ACTION string 
   EXCEED_PACKET_ACTION string 
   VIOLATED_PACKET_ACTION string 

   //POLICER_TABLE in APP DB
   POLICER_CIR uint64
   POLICER_CBS uint64
   POLICER_PIR uint64
   POLICER_PBS uint64
   POLICER_METER_TYPE string
   POLICER_TYPE string
   POLICER_MODE string
   POLICER_COLOR_SOURCE string

}


type ReferringClassEntry struct {
    CONFIG ReferringClassConfigEntry
    STATE   ReferringClassOperEntry
}


type ServicePolicyEntry struct {
    POLICY_NAME string  
    DESCRIPTION string
    TYPE string  
    POLICY_BIND_DIR string;
    REF_CLASS_LIST [] ReferringClassEntry 
} 

type ServicePolicyPort struct {
    MATCHING_SERVICE_POLICY_LIST [] ServicePolicyEntry;
}


func init () {
    XlateFuncBind("rpc_show_classifier", rpc_show_classifier)
    XlateFuncBind("rpc_show_policy", rpc_show_policy)
    XlateFuncBind("rpc_show_service_policy", rpc_show_service_policy)
    XlateFuncBind("rpc_clear_service_policy", rpc_clear_service_policy)
}

func fill_classifier_details(class_name string, classifierTblVal db.Value, classEntry *ClassifierEntry) (err error) {

        classEntry.MATCH_TYPE  = classifierTblVal.Field["MATCH_TYPE"]
        classEntry.DESCRIPTION = classifierTblVal.Field["DESCRIPTION"]
        classEntry.ACL_NAME    = classifierTblVal.Field["ACL_NAME"]

        if classEntry.MATCH_TYPE == "FIELDS" {
            classEntry.ETHER_TYPE          = classifierTblVal.Field["ETHER_TYPE"]
            classEntry.SRC_MAC             = classifierTblVal.Field["SRC_MAC"]
            classEntry.DST_MAC             = classifierTblVal.Field["DST_MAC"]
            classEntry.VLAN,_              = strconv.Atoi(classifierTblVal.Field["VLAN"])
            classEntry.PCP,_               = strconv.Atoi(classifierTblVal.Field["PCP"])
            classEntry.DEI,_               = strconv.Atoi(classifierTblVal.Field["DEI"])
            classEntry.IP_PROTOCOL,_       = strconv.Atoi(classifierTblVal.Field["IP_PROTOCOL"])
            classEntry.SRC_IP              = classifierTblVal.Field["SRC_IP"]
            classEntry.DST_IP              = classifierTblVal.Field["DST_IP"]
            classEntry.SRC_IPV6            = classifierTblVal.Field["SRC_IPV6"]
            classEntry.DST_IPV6            = classifierTblVal.Field["DST_IPV6"]
            classEntry.DSCP,_              = strconv.Atoi(classifierTblVal.Field["DSCP"])
            classEntry.L4_SRC_PORT,_       = strconv.Atoi(classifierTblVal.Field["L4_SRC_PORT"])
            classEntry.L4_DST_PORT,_       = strconv.Atoi(classifierTblVal.Field["L4_DST_PORT"])
            classEntry.L4_SRC_PORT_RANGE   = classifierTblVal.Field["L4_SRC_PORT_RANGE"] 
            classEntry.L4_DST_PORT_RANGE   = classifierTblVal.Field["L4_DST_PORT_RANGE"]
            classEntry.TCP_FLAGS    = classifierTblVal.Field["TCP_FLAGS"]
        }                           

        var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
        policySectionTblclassKeyStr := "*" + "|" + class_name
        classReferingPolicyKeys, err := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{[]string{policySectionTblclassKeyStr}})


        log.Info("show classifier ==> classReferingPolicyKeys ==> ", classReferingPolicyKeys)

        for  i := 0; i < len(classReferingPolicyKeys); i++ {

                var referringPolicy ReferingPolicyEntry

                policySectionTblVal, err := configDbPtr.GetEntry(POLICY_SECTION_TABLES_TS, classReferingPolicyKeys[i])
                log.Infof("In rpc_show_classifier, RPC policySectionTblVal:%v", policySectionTblVal)
                if err != nil {
                    log.Errorf("Failed to  find related policy:%v err%v", classReferingPolicyKeys[i], err)
                        return errors.New("classifier not found")
                }
            priority, _ := strconv.Atoi(policySectionTblVal.Field["PRIORITY"]) 
                referringPolicy.PRIORITY    = priority
                referringPolicy.POLICY_NAME = classReferingPolicyKeys[i].Comp[0]
                classEntry.REF_POLICY_LIST = append(classEntry.REF_POLICY_LIST, referringPolicy)
        }
        return nil
}

var rpc_show_classifier RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
    var class_name, match_type string

    log.Info("In rpc_show_classifier")
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
       xfmrLogInfo("In rpc_show_classifier, error: %v", err)
       log.Error("Failed to  marshal input data; err=%v", err)
       return nil,  errors.New("RPC show classifier, invalid input")
    }

    input, _ := mapData["sonic-flow-based-services:input"]
    mapData = input.(map[string]interface{})
    log.Infof("In rpc_show_classifier, RPC Input data: %v", mapData)
	configDbPtr := dbs[db.ConfigDB]
    var CLASSIFIER_TABLE_TS  *db.TableSpec = &db.TableSpec { Name: "CLASSIFIER_TABLE" }

    
    var  showOutput struct {
        Output struct {
            MATCHING_CLASSIFIER_TABLE_LIST  map[string] ClassifierEntry
        } `json:"sonic-flow-based-services:output"`
    }

     arg_class_name, arg_class_name_found := mapData["CLASSIFIER_NAME"].(string)
     arg_match_type, arg_match_type_found := mapData["MATCH_TYPE"].(string)
    if  arg_class_name_found && arg_class_name != "" {
        class_name = arg_class_name 

        //get classifier db output
	    classifierTblVal, err := configDbPtr.GetEntry(CLASSIFIER_TABLE_TS, db.Key{Comp: []string{class_name}})
        xfmrLogInfo("In rpc_show_classifier, class_name:%v, RPC classifierTblVal:%v", class_name, classifierTblVal)
        if err != nil {
        xfmrLogInfo("In rpc_show_classifier, class_name:%v, RPC classifierTblVal:%v", class_name, classifierTblVal)
            log.Errorf("Failed to  find classifier:%v err%v", class_name, err)
            return nil,  errors.New("classifier not found")
        }

        showOutput.Output.MATCHING_CLASSIFIER_TABLE_LIST = make(map[string] ClassifierEntry)
        var classEntry ClassifierEntry;
        err = fill_classifier_details(class_name, classifierTblVal, &classEntry)
        if err != nil {
            return nil, err
        }
        showOutput.Output.MATCHING_CLASSIFIER_TABLE_LIST[class_name]  = classEntry
        result,err = json.Marshal(&showOutput)
        return result, err
        //get associated policies
    } else if  arg_match_type_found && arg_match_type != "" {
        match_type = arg_match_type

        showOutput.Output.MATCHING_CLASSIFIER_TABLE_LIST = make(map[string] ClassifierEntry)
        classifierTbl, err := configDbPtr.GetTable(CLASSIFIER_TABLE_TS)

		classKeys, _ := classifierTbl.GetKeys()
        var match_found bool = false    
        xfmrLogInfo("In rpc_show_classifier, match_type:%v RPC classifierTbl:%v, classkeys:%v ", match_type, classifierTbl, classKeys)
	    for index, _ := range classKeys {
            class_name = classKeys[index].Comp[0]
			classifierTblVal, err := classifierTbl.GetEntry(classKeys[index])
            if classifierTblVal.Field["MATCH_TYPE"] != match_type {
                xfmrLogInfo("In rpc_show_classifier, not matching index:%v class_name:%v match_type:%v ", index, class_name, classifierTblVal.Field["MATCH_TYPE"])
                continue;
            }
            var classEntry ClassifierEntry;
            err = fill_classifier_details(class_name, classifierTblVal, &classEntry)
            if err != nil {
                continue;
            }
            match_found = true

            showOutput.Output.MATCHING_CLASSIFIER_TABLE_LIST[class_name]  = classEntry
        }

        if match_found {
        result,err = json.Marshal(&showOutput)
        return result, err
        }
    }

    return nil, err
}

func is_nhop_chosen_one(dbs[db.MaxDB] *db.DB, pbfKey string, nhopToMatch string) (selected bool, err error) {
    stateDbPtr := dbs[db.StateDB]
    key := db.Key{[]string{pbfKey}}

    var PBF_GROUP_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "PBF_GROUP_TABLE"}
    pbfGroupTblVal, err  := stateDbPtr.GetEntry(PBF_GROUP_TABLES_TS, key)
    xfmrLogInfo("pbfGroupTblVal:%v", pbfGroupTblVal)
    if err == nil {
        selectedNhop := pbfGroupTblVal.Field["CONFIGURED_SELECTED"]
        //match nexthop,vrf, prirority which is encoded part of the nhop string
        if (nhopToMatch == selectedNhop) {
           selected = true
           xfmrLogInfo("chosen nhop:%v ", selectedNhop)
           return selected, nil
        }
    }
    log.Errorf("is_nhop_chosen_one error%v ; key:%v, nhopToMatch:%v ", err, key, nhopToMatch)
    return false, err

}


func fill_policy_section_table_info(policy_name string, class_name string, policySectionTblVal db.Value, dbs[db.MaxDB]*db.DB, fill_selected_nh bool, pbfKey string, policySectionInfo *ReferringClassConfigEntry) { 
    policySectionInfo.POLICY_NAME   = policy_name
    policySectionInfo.CLASS_NAME    = class_name 

    policySectionInfo.PRIORITY, _   = strconv.Atoi(policySectionTblVal.Field["PRIORITY"])
    policySectionInfo.SET_DSCP, _   = strconv.Atoi(policySectionTblVal.Field["SET_DSCP"])
    policySectionInfo.SET_PCP, _    = strconv.Atoi(policySectionTblVal.Field["SET_PCP"])

    policySectionInfo.SET_POLICER_CIR, _    = strconv.ParseUint(policySectionTblVal.Field["SET_POLICER_CIR"], 10, 64)
    policySectionInfo.SET_POLICER_CBS, _    = strconv.ParseUint(policySectionTblVal.Field["SET_POLICER_CBS"], 10, 64)
    policySectionInfo.SET_POLICER_PIR, _    = strconv.ParseUint(policySectionTblVal.Field["SET_POLICER_PIR"], 10, 64)
    policySectionInfo.SET_POLICER_PBS, _    = strconv.ParseUint(policySectionTblVal.Field["SET_POLICER_PBS"], 10, 64)

    policySectionInfo.SET_MIRROR_SESSION   = policySectionTblVal.Field["SET_MIRROR_SESSION"]
    policySectionInfo.SET_INTERFACE        = policySectionTblVal.Field["SET_INTERFACE"]

    if (len(policySectionTblVal.Get("SET_IP_NEXTHOP@")) > 0) {
        ipNhops := policySectionTblVal.GetList("SET_IP_NEXTHOP")
        for i, _ := range ipNhops {
            var ipNhopEntry IpNextHopEntry 
            nhopSplits := strings.Split(ipNhops[i],"|") 
            ipNhopEntry.NEXTHOP  = nhopSplits[0]
            ipNhopEntry.VRF      = nhopSplits[1]
            ipNhopEntry.PRIORITY,_ = strconv.Atoi(nhopSplits[2])

            if (fill_selected_nh) {
                selected, err := is_nhop_chosen_one(dbs, pbfKey, ipNhops[i])
                if (err == nil) {
                    ipNhopEntry.SELECTED = selected
                }
            }
            policySectionInfo.IP_NEXTHOP_LIST = append(policySectionInfo.IP_NEXTHOP_LIST, ipNhopEntry)
        }
    }

    if (len(policySectionTblVal.Get("SET_IPV6_NEXTHOP@")) > 0)  {
        ipNhops := policySectionTblVal.GetList("SET_IPV6_NEXTHOP")
        for i, _ := range ipNhops {
            var ipNhopEntry IpNextHopEntry 
            nhopSplits := strings.Split(ipNhops[i],"|") 
            ipNhopEntry.NEXTHOP  = nhopSplits[0]
            ipNhopEntry.VRF      = nhopSplits[1]
            ipNhopEntry.PRIORITY,_ = strconv.Atoi(nhopSplits[2])
            if (fill_selected_nh) {
                selected, err := is_nhop_chosen_one(dbs, pbfKey, ipNhops[i])
                    if (err == nil) {
                        ipNhopEntry.SELECTED = selected
                    }
            }
            policySectionInfo.IPV6_NEXTHOP_LIST = append(policySectionInfo.IPV6_NEXTHOP_LIST, ipNhopEntry)
        }
    }

    policySectionInfo.DEFAULT_PKT_ACTION   = policySectionTblVal.Field["DEFAULT_PKT_ACTION"]
    xfmrLogInfo("policySectionInfo:%v ", policySectionInfo)

}

func fill_policy_class_state_info(policy_name string, class_name string, interface_name string, bind_dir string, dbs [db.MaxDB]*db.DB, policyClassStateInfo *ReferringClassOperEntry) {

	countersDbPtr := dbs[db.CountersDB]

    policyCountersTblKey := db.Key{[]string{policy_name + ":"+ class_name + ":"+ interface_name + ":" + bind_dir}}

    var POLICER_COUNTERS_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICER_COUNTERS"}
    policerCountersTblVal, err  := countersDbPtr.GetEntry(POLICER_COUNTERS_TABLES_TS, policyCountersTblKey)
    xfmrLogInfo("policerCountersTblVal:%v", policerCountersTblVal)
    if err == nil {
            policyClassStateInfo.CONFORMED_PACKET_COUNT, _ = strconv.ParseUint(policerCountersTblVal.Field["GreenPackets"], 10, 64)  
            policyClassStateInfo.CONFORMED_BYTE_COUNT, _ = strconv.ParseUint(policerCountersTblVal.Field["GreenBytes"], 10, 64) 

            policyClassStateInfo.EXCEED_PACKET_COUNT, _ = strconv.ParseUint(policerCountersTblVal.Field["YellowPackets"], 10, 64) 
            policyClassStateInfo.EXCEED_BYTE_COUNT, _ = strconv.ParseUint(policerCountersTblVal.Field["YellowBytes"], 10, 64) 

            policyClassStateInfo.VIOLATED_PACKET_COUNT, _ = strconv.ParseUint(policerCountersTblVal.Field["RedPackets"], 10, 64) 
            policyClassStateInfo.VIOLATED_BYTE_COUNT, _ = strconv.ParseUint(policerCountersTblVal.Field["RedBytes"], 10, 64) 

    }

    var FBS_COUNTERS_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "FBS_COUNTERS"}
    fbsCountersTblVal, err := countersDbPtr.GetEntry(FBS_COUNTERS_TABLES_TS, policyCountersTblKey)
    log.Infof("fbsCountersTblVal:%v", fbsCountersTblVal)
    if err == nil {
            policyClassStateInfo.FBS_PACKET_COUNT, _ = strconv.ParseUint(fbsCountersTblVal.Field["Packets"], 10, 64) 
            policyClassStateInfo.FBS_BYTE_COUNT, _ = strconv.ParseUint(fbsCountersTblVal.Field["Bytes"], 10, 64) 
    }

	appDbPtr := dbs[db.ApplDB]
    var POLICER_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICER_TABLE"}
    policerTblVal, err := appDbPtr.GetEntry(POLICER_TABLES_TS, policyCountersTblKey)
    xfmrLogInfo("policerTblVal:%v", policerTblVal)
     if err == nil {
            policyClassStateInfo.POLICER_CIR, _ = strconv.ParseUint(policerTblVal.Field["CIR"], 10, 64) 
            policyClassStateInfo.POLICER_CBS, _ = strconv.ParseUint(policerTblVal.Field["CBS"], 10, 64) 
            policyClassStateInfo.POLICER_PIR, _ = strconv.ParseUint(policerTblVal.Field["PIR"], 10, 64) 
            policyClassStateInfo.POLICER_PBS, _ = strconv.ParseUint(policerTblVal.Field["PBS"], 10, 64) 

            policyClassStateInfo.POLICER_METER_TYPE = policerTblVal.Field["METER_TYPE"] 
            policyClassStateInfo.POLICER_MODE = policerTblVal.Field["MODE"] 
            policyClassStateInfo.POLICER_COLOR_SOURCE = policerTblVal.Field["COLOR_SOURCE"] 

            policyClassStateInfo.CONFORMED_PACKET_ACTION = policerTblVal.Field["GREEN_PACKET_ACTION"]
            policyClassStateInfo.EXCEED_PACKET_ACTION = policerTblVal.Field["YELLOW_PACKET_ACTION"]
            policyClassStateInfo.VIOLATED_PACKET_ACTION = policerTblVal.Field["RED_PACKET_ACTION"]
      }

    stateDbPtr := dbs[db.StateDB]
    var POLICY_SECTION_BIND_STATUS_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTION_BINDING_STATUS"}
    policyBindStatusTblVal, err := stateDbPtr.GetEntry(POLICY_SECTION_BIND_STATUS_TABLES_TS, policyCountersTblKey)
    xfmrLogInfo("policyBindStatusTblVal:%v", policyBindStatusTblVal)
    if err == nil {
        policyClassStateInfo.POLICY_BIND_STATUS = policerTblVal.Field["STATUS"] 
    } else {
        policyClassStateInfo.POLICY_BIND_STATUS =  "InActive"
    }
    xfmrLogInfo("policyClassStateInfo:%v", policyClassStateInfo)

}

func clear_policer_counters(key db.Key, countersDbPtr *db.DB) (get_err error, create_err error) {

    var POLICER_COUNTERS_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICER_COUNTERS"}
    var POLICER_COUNTERS_TABLES_TS_COPY *db.TableSpec = &db.TableSpec{Name: "POLICER_COUNTERS_BACKUP"}
    value, get_err := countersDbPtr.GetEntry(POLICER_COUNTERS_TABLES_TS, key)
    xfmrLogInfo("clear_policer_counters fbsCountersTblVal:%v", value)
    if get_err == nil {
        secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        create_err = countersDbPtr.CreateEntry(POLICER_COUNTERS_TABLES_TS_COPY, key, value)
    }
    return get_err, create_err
}

func clear_fbs_counters(key db.Key, countersDbPtr *db.DB) (get_err error, create_err error) {
    var FBS_COUNTERS_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "FBS_COUNTERS"}
    var FBS_COUNTERS_TABLES_TS_COPY *db.TableSpec = &db.TableSpec{Name: "FBS_COUNTERS_BACKUP"}
    value, get_err := countersDbPtr.GetEntry(FBS_COUNTERS_TABLES_TS, key)
    xfmrLogInfo("clear_fbs_counters fbsCountersTblVal:%v", value)
    if get_err == nil {
        secs := time.Now().Unix()
        timeStamp := strconv.FormatInt(secs, 10)
        value.Field["LAST_CLEAR_TIMESTAMP"] = timeStamp
        create_err = countersDbPtr.CreateEntry(FBS_COUNTERS_TABLES_TS_COPY, key, value)
    }
    return get_err, create_err
}

func fill_policy_details(policy_name string, policyTblVal db.Value, dbs[db.MaxDB] *db.DB, policyEntry *PolicyEntry) (err error) {

        policyEntry.DESCRIPTION = policyTblVal.Field["DESCRIPTION"]
        policyEntry.TYPE  = policyTblVal.Field["TYPE"]

        var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
        policySectionTblclassKeyStr := policy_name + "|" + "*"
        referingClassKeys, err := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{[]string{policySectionTblclassKeyStr}})

        log.Info("referingClassKeys ==> ", referingClassKeys)

        for  i := 0; i < len(referingClassKeys); i++ {

                var referingClass ReferringClassConfigEntry
                log.Info("show policy ==> referingClassKeys[i].Comp[0] ==> ", referingClassKeys[i].Comp[0])
                log.Info("show policy ==> referingClassKeys[i].Comp[1] ==> ", referingClassKeys[i].Comp[1])

                policySectionTblVal, err := configDbPtr.GetEntry(POLICY_SECTION_TABLES_TS, referingClassKeys[i])
                xfmrLogInfo("In rpc_show_policy, RPC policySectionTblValue:%v", policySectionTblVal)
                if err != nil {
                    log.Error("Failed to  find related class:%v err%v", referingClassKeys[i], err)
                        return errors.New("policy not found")
                }

                fill_policy_section_table_info(policy_name, referingClassKeys[i].Comp[1], policySectionTblVal, dbs, false, "", &referingClass)
                policyEntry.REF_CLASS_LIST = append(policyEntry.REF_CLASS_LIST, referingClass)
        }

    var POLICY_BIND_TABLE_TS  *db.TableSpec = &db.TableSpec { Name: "POLICY_BINDING_TABLE" }
    policyBindTbl, bind_err := configDbPtr.GetTable(POLICY_BIND_TABLE_TS)
    xfmrLogInfo("In rpc_show_policy, policyBindtbl:%v ", policyBindTbl)
    if (bind_err == nil) {
		policyBindKeys, _ := policyBindTbl.GetKeys()

	    for index, _ := range policyBindKeys {
             var appliedPort PolicyBindPortEntry;
            policyBindTblVal, _ := policyBindTbl.GetEntry(policyBindKeys[index])
            xfmrLogInfo("In rpc_show_policy, policy_name:%v key:%v policyBindTblVal:%v ", policy_name, policyBindKeys[index], policyBindTblVal)

            for field, value := range policyBindTblVal.Field {
              field_splits := strings.Split(field,"_") 
              policy_bind_dir := field_splits[0]
              if value == policy_name { 
                appliedPort.POLICY_BIND_PORT = policyBindKeys[index].Comp[0] 
                appliedPort.POLICY_BIND_DIR =  policy_bind_dir
                break;
              }
            }
            policyEntry.APPLIED_PORT_LIST = append(policyEntry.APPLIED_PORT_LIST, appliedPort)
        }
    }
    return nil
}


var rpc_show_policy RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
    var policy_name, match_type string

    log.Info("In rpc_show_policy")
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
       xfmrLogInfo("In rpc_show_policy, error: %v", err)
       log.Error("Failed to  marshal input data; err=%v", err)
       return nil,  errors.New("RPC show policy, invalid input")
    }

    input, _ := mapData["sonic-flow-based-services:input"]
    mapData = input.(map[string]interface{})
    log.Info("In rpc_show_policy, RPC Input data: %v", mapData)
    configDbPtr := dbs[db.ConfigDB]
    var POLICY_TABLE_TS  *db.TableSpec = &db.TableSpec { Name: "POLICY_TABLE" }

    var  showOutput struct {
        Output struct {
            MATCHING_POLICY_TABLE_LIST map[string] PolicyEntry
        }  `json:"sonic-flow-based-services:output"`
    }

    arg_policy_name, arg_policy_name_found := mapData["POLICY_NAME"].(string)
    arg_type, arg_type_found := mapData["TYPE"].(string)
    var match_found bool = false    
    if  arg_policy_name_found && arg_policy_name != "" {
        policy_name = arg_policy_name 
        //get policy db output
        policyTblVal, err := configDbPtr.GetEntry(POLICY_TABLE_TS, db.Key{Comp: []string{policy_name}})
        xfmrLogInfo("In rpc_show_policy, policy_name:%v, RPC policyTblVal:%v", policy_name, policyTblVal)
        if err != nil {
            log.Error("Failed to  find policy:%v err%v", policy_name, err)
            return nil,  errors.New("policy not found")
        }

        showOutput.Output.MATCHING_POLICY_TABLE_LIST = make(map[string] PolicyEntry)
        var policyEntry PolicyEntry;
        err = fill_policy_details(policy_name, policyTblVal, dbs, &policyEntry)
        if err != nil {
            log.Errorf("Failed to fetch policy:%v details err%v", policy_name, err)
            return nil,  errors.New("policy fetch error")
        }
        
        showOutput.Output.MATCHING_POLICY_TABLE_LIST[policy_name]  = policyEntry
        match_type = policyTblVal.Field["MATCH_TYPE"]
        match_found = true
    } else if  arg_type_found && arg_type != "" {
        match_type = strings.ToUpper(arg_type)

        showOutput.Output.MATCHING_POLICY_TABLE_LIST = make(map[string] PolicyEntry)
        policyTbl, _ := configDbPtr.GetTable(POLICY_TABLE_TS)
        xfmrLogInfo("In rpc_show_policy, match_type:%v, RPC policyTbl:%v", match_type, policyTbl)

		policyKeys, _ := policyTbl.GetKeys()
        log.Info("In rpc_show_policy, RPC policykeys:%v", policyKeys)
	    for index, _ := range policyKeys {
            policy_name = policyKeys[index].Comp[0]
            log.Info("In rpc_show_policy, index:%v policy_name:%v ", index, policy_name)
			policyTblVal, err := policyTbl.GetEntry(policyKeys[index])
            if policyTblVal.Field["TYPE"] != match_type {
                xfmrLogInfo("In rpc_show_policy, not matching index:%v policy_name:%v match_type:%v ", index, policy_name, policyTblVal.Field["TYPE"])
                continue;
            }
            var policyEntry PolicyEntry;
            err = fill_policy_details(policy_name, policyTblVal, dbs, &policyEntry)
            if err != nil {
                continue;
            }
            match_found = true

            showOutput.Output.MATCHING_POLICY_TABLE_LIST[policy_name]  = policyEntry
        }
    }

    
    if match_found {
        result,err = json.Marshal(&showOutput)
            return result, err
    }
    return nil, err
}

var rpc_show_service_policy RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {

    log.Info("In rpc_show_service_policy")
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
       xfmrLogInfo("In rpc_show_service_policy, error: %v", err)
       log.Error("Failed to  marshal input data; err=%v", err)
       return nil,  errors.New("RPC show service policy, invalid input")
    }

    input, _ := mapData["sonic-flow-based-services:input"]
    mapData = input.(map[string]interface{})
    xfmrLogInfo("In rpc_show_service_policy, RPC Input data: %v", mapData)

    configDbPtr := dbs[db.ConfigDB]

    var  showOutput struct {
        Output struct {
            MATCHING_SERVICE_PORT_LIST  map[string] ServicePolicyPort  
        }  `json:"sonic-flow-based-services:output"`
    } 

    var POLICY_BIND_TABLE_TS  *db.TableSpec = &db.TableSpec { Name: "POLICY_BINDING_TABLE" }
    arg_match_type, arg_match_type_found := mapData["MATCH_TYPE"].(string)
    arg_match_sub_type, arg_sub_type_found := mapData["MATCH_SUB_TYPE"].(string)
    if  arg_match_type_found == false {
       log.Errorf("no match type passed; err=%v", err)
       return nil,  errors.New("RPC show service policy, invalid input")
    }

    var interface_name string
    var policy_type    string
    var policyBindKeys [] db.Key
    var arg2_interface_name string

    var policy_name string
    if (strings.HasPrefix(arg_match_type, "interface ")) {
        match_port := strings.TrimPrefix(arg_match_type, "interface ")
        if (match_port != arg_match_type) {
            interface_name = match_port
            if (arg_sub_type_found) {
                match_policy_type := strings.TrimPrefix(arg_match_sub_type, "type ")
                if match_policy_type != "type" {
                    policy_type = strings.ToUpper(match_policy_type)
                }
             }
         }
         xfmrLogInfo("In rpc_show_service_policy match_type:interface interface_name:%v  policy_type:%v ", interface_name, policy_type)
         var bind_err error
         policyBindKeys, bind_err = configDbPtr.GetKeysPattern(POLICY_BIND_TABLE_TS, db.Key{[]string{interface_name}})
         if (bind_err != nil) {
             log.Errorf("no matching service policy for this interface; err=%v", err)
                 return nil,  errors.New("RPC show service policy, no matching service policy")
         }
    } else  if (strings.HasPrefix(arg_match_type, "policy ")) {
        match_policy := strings.TrimPrefix(arg_match_type, "policy ")
        if (match_policy != arg_match_type) {
            policy_name = match_policy
            if (arg_sub_type_found) {
                match_port := strings.TrimPrefix(arg_match_sub_type, "interface ")
                if match_port != arg_match_sub_type {
                    arg2_interface_name = match_port
                }
            }
            xfmrLogInfo("In rpc_show_service_policy match_type:policy policy_name:%v interface_name:%v ", policy_name, arg2_interface_name)
            var bind_err error
            policyBindKeys, bind_err = configDbPtr.GetKeysPattern(POLICY_BIND_TABLE_TS, db.Key{[]string{"*"}})
            if (bind_err != nil) {
                log.Errorf("no matching service policy; err=%v", err)
                    return nil,  errors.New("RPC show service policy, no matching service policy")
            }
        }
    }

    policyBindTbl, _ := configDbPtr.GetTable(POLICY_BIND_TABLE_TS)
    showOutput.Output.MATCHING_SERVICE_PORT_LIST = make(map[string] ServicePolicyPort)
    var servicePolicyPort ServicePolicyPort
    var match_found bool = false
    var show_output bool = false
    var interface_match_done = false
    for index, _ := range policyBindKeys {
        match_found = false
        if (strings.HasPrefix(arg_match_type, "policy "))  {
            interface_name = ""
            if (interface_match_done == true)    {
               break
            }
        }
        policyBindTblVal, _ := policyBindTbl.GetEntry(policyBindKeys[index])
        xfmrLogInfo("In rpc_show_service_policy,  key:%v policyBindTblVal:%v ", policyBindKeys[index], policyBindTblVal)
    
            for field, value := range policyBindTblVal.Field {
                var servicePolicyEntry ServicePolicyEntry;
                field_splits := strings.Split(field,"_") 
    
                //filter by policy type - if first level filter is interface_name
                xfmrLogInfo("In rpc_show_service_policy,  field:%v value:%v", field, value)
                if (strings.HasPrefix(arg_match_type, "interface "))  {
                    if ( (len(policy_type) != 0) && (field_splits[1] != policy_type) )  {
                        xfmrLogInfo("continue policy_type:%v arg_policy_type:%v not matching", field_splits[1], policy_type) 
                        continue;
                    }
                }
    
                //filter by policy_name if first level filter is policy
                if (strings.HasPrefix(arg_match_type, "policy "))  {
                    if (len(policy_name) != 0) {
                        if (strings.Contains(value, policy_name) == true) {
                            interface_name = policyBindKeys[index].Comp[0]
                            xfmrLogInfo(" interface name ", interface_name)
                            if (len(arg2_interface_name) != 0) {
                                if (interface_name != arg2_interface_name) {
                                    //xfmrLogInfo("continue interface name:%v arg_interface_name:%v not matching",    interface_name, arg2_interface_name) 
                                    continue; //not matching second level filter interface name
                                } else {
                                    interface_match_done = true
                                }
                            }
                        } else {
                            log.Info("continue policy name not matching") 
                            //xfmrLogInfo("continue policy_name:%v arg_policy_name:%v not matching", policy_name, value) 
                            continue; //not matching first level filter policy name
                        }
                    }
               }
              match_found = true
              show_output = true
              servicePolicyEntry.TYPE = field_splits[1] 
              servicePolicyEntry.POLICY_NAME =  value
              servicePolicyEntry.POLICY_BIND_DIR =  field_splits[0]
    
              xfmrLogInfo("In rpc_show_service_policy,  interface_name:%v policy_name:%v policy_type:%v  policy_bind_dir:%v ", interface_name, value, field_splits[1], field_splits[0])
    
              var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
              policySectionTblclassKeyStr := value + "|" + "*"
                             referingClassKeys, _ := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{[]string{policySectionTblclassKeyStr}})
                             for  i := 0; i < len(referingClassKeys); i++ {
                                 var referingClassEntry ReferringClassEntry
                                     policySectionTblVal, err := configDbPtr.GetEntry(POLICY_SECTION_TABLES_TS, referingClassKeys[i])
                                     if err != nil {
                                         continue;
                                     }
                                     xfmrLogInfo("In rpc_show_service_policy,  referingClassKeys:%v ", referingClassKeys[i])
                                     fill_policy_class_state_info(value, referingClassKeys[i].Comp[1], interface_name, servicePolicyEntry.POLICY_BIND_DIR, dbs, &referingClassEntry.STATE)
                                     pbfKey := value + ":"+ referingClassKeys[i].Comp[1]  + ":"+ interface_name + ":" +  servicePolicyEntry.POLICY_BIND_DIR
                                     fill_policy_section_table_info(value, referingClassKeys[i].Comp[1], policySectionTblVal, dbs, true, pbfKey, &referingClassEntry.CONFIG)
                                     servicePolicyEntry.REF_CLASS_LIST = append(servicePolicyEntry.REF_CLASS_LIST, referingClassEntry)
                                     xfmrLogInfo("In rpc_show_service_policy, servicePolicyEntry:%v ", servicePolicyEntry)
                             }
                         servicePolicyPort.MATCHING_SERVICE_POLICY_LIST = append(servicePolicyPort.MATCHING_SERVICE_POLICY_LIST, servicePolicyEntry)
        }
        if (match_found) {
            showOutput.Output.MATCHING_SERVICE_PORT_LIST[interface_name]  = servicePolicyPort
        }
    }
    xfmrLogInfo("In rpc_show_service_policy,  showOuptut:%v", showOutput)
    if(show_output) {
        result,err = json.Marshal(&showOutput)
            log.Info("In rpc_show_service_policy,  showOuptut:%v", showOutput)
            return result, err
    }
    
    return nil, err
}


var rpc_clear_service_policy RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
    log.Info("In rpc_clear_service_policy")

    log.Info("In rpc_show_service_policy")
    var mapData map[string]interface{}
    err = json.Unmarshal(body, &mapData)
    if err != nil {
       xfmrLogInfo("In rpc_show_service_policy, error: %v", err)
       log.Errorf("Failed to  marshal input data; err=%v", err)
       return nil,  errors.New("RPC show service policy, invalid input")
    }

    input, _ := mapData["sonic-flow-based-services:input"]
    mapData = input.(map[string]interface{})
    xfmrLogInfo("In rpc_show_service_policy, RPC Input data: %v", mapData)

    var POLICY_BIND_TABLE_TS  *db.TableSpec = &db.TableSpec { Name: "POLICY_BINDING_TABLE" }
    arg_match_type, arg_match_type_found := mapData["MATCH_TYPE"].(string)
    arg_match_sub_type, arg_sub_type_found := mapData["MATCH_SUB_TYPE"].(string)
    if  arg_match_type_found == false {
       log.Errorf("no match type passed; err=%v", err)
       return nil,  errors.New("RPC show service policy, invalid input")
    }

    var interface_name string
    var policy_type    string
    var policyBindKeys [] db.Key
    var arg2_interface_name string

    var policy_name string
    if (strings.HasPrefix(arg_match_type, "interface ")) {
        match_port := strings.TrimPrefix(arg_match_type, "interface ")
        if (match_port != arg_match_type) {
            interface_name = match_port
            if (arg_sub_type_found) {
                match_policy_type := strings.TrimPrefix(arg_match_sub_type, "type ")
                if match_policy_type != "type" {
                    policy_type = strings.ToUpper(match_policy_type)
                }
             }
         }
         xfmrLogInfo("In rpc_show_service_policy match_type:interface interface_name:%v  policy_type:%v ", interface_name, policy_type)
         var bind_err error
         policyBindKeys, bind_err = configDbPtr.GetKeysPattern(POLICY_BIND_TABLE_TS, db.Key{[]string{interface_name}})
         if (bind_err != nil) {
             log.Errorf("no matching service policy for this interface; err=%v", err)
                 return nil,  errors.New("RPC show service policy, no matching service policy")
         }
    } else  if (strings.HasPrefix(arg_match_type, "policy ")) {
        match_policy := strings.TrimPrefix(arg_match_type, "policy ")
        if (match_policy != arg_match_type) {
            policy_name = match_policy
            if (arg_sub_type_found) {
                match_port := strings.TrimPrefix(arg_match_sub_type, "interface ")
                if match_port != arg_match_sub_type {
                    arg2_interface_name = match_port
                }
            }
            xfmrLogInfo("In rpc_show_service_policy match_type:policy policy_name:%v interface_name:%v ", policy_name, arg2_interface_name)
            var bind_err error
            policyBindKeys, bind_err = configDbPtr.GetKeysPattern(POLICY_BIND_TABLE_TS, db.Key{[]string{"*"}})
            if (bind_err != nil) {
                log.Errorf("no matching service policy; err=%v", err)
                    return nil,  errors.New("RPC show service policy, no matching service policy")
            }
        }
    }
    var  showOutput struct {
        Output struct {
            STATUS int32
            STATUS_DETAIL string 
        } `json:"sonic-flow-based-services:output"`
    }

    policyBindTbl, _ := configDbPtr.GetTable(POLICY_BIND_TABLE_TS)
    var match_found bool = false
    var interface_match_done = false
	countersDbPtr := dbs[db.CountersDB]
    for index, _ := range policyBindKeys {
        if (strings.HasPrefix(arg_match_type, "policy "))  {
            interface_name = ""
            if (interface_match_done == true)    {
               break
            }
        }
        policyBindTblVal, _ := policyBindTbl.GetEntry(policyBindKeys[index])
        xfmrLogInfo("In rpc_show_service_policy,  key:%v policyBindTblVal:%v ", policyBindKeys[index], policyBindTblVal)
    
        for field, value := range policyBindTblVal.Field {
  
            //filter by policy type - if first level filter is interface_name
            xfmrLogInfo("In rpc_show_service_policy,  field:%v value:%v", field, value)
            if (strings.HasPrefix(arg_match_type, "interface "))  {
                if ( (len(policy_type) != 0) && (strings.Contains(field, policy_type) == false) ) {
                    continue;
                }
            }
    
            //filter by policy_name if first level filter is policy
            if (strings.HasPrefix(arg_match_type, "policy "))  {
                if (len(policy_name) != 0) {
                    if (strings.Contains(value, policy_name) == true) {
                        interface_name = policyBindKeys[index].Comp[0]
                        if (len(arg2_interface_name) != 0) {
                            if (interface_name != arg2_interface_name) {
                                continue; //not matching second level filter interface name
                            } else {
                                interface_match_done = true
                            }
                        }
                    } else {
                        continue; //not matching first level filter policy name
                    }
                }
           }
          match_found = true
          field_splits := strings.Split(field,"_") 
          matching_policy_type     := field_splits[1] 
          matching_policy_bind_dir :=  field_splits[0]
    
          xfmrLogInfo("In rpc_show_service_policy,  policy_name:%v policy_type:%v  policy_bind_dir:%v ", value, field_splits[1], field_splits[0])
    
          var POLICY_SECTION_TABLES_TS *db.TableSpec = &db.TableSpec{Name: "POLICY_SECTIONS_TABLE"}
          policySectionTblclassKeyStr := value + "|" + "*"
          referingClassKeys, _ := configDbPtr.GetKeysPattern(POLICY_SECTION_TABLES_TS, db.Key{[]string{policySectionTblclassKeyStr}})
          for  i := 0; i < len(referingClassKeys); i++ {
              log.Info("In rpc_show_service_policy,  referingClassKeys:%v ", referingClassKeys[i])
              countersStr := value + ":"+ referingClassKeys[i].Comp[1]  + ":"+ interface_name + ":" + matching_policy_bind_dir
              fbsCountersKey := db.Key{[]string{countersStr}}
              if (matching_policy_type == "QOS") {
                  get_err, create_err := clear_policer_counters(fbsCountersKey, countersDbPtr)
                      if (get_err != nil || create_err != nil) {
                          log.Errorf("Failed to reset policer counters for: ", countersStr)
                      } else {
                          xfmrLogInfo("policer Counters reset for ", countersStr)
                      }
              }
              get_err, create_err := clear_fbs_counters(fbsCountersKey, countersDbPtr)
              if (get_err != nil || create_err != nil) {
                  log.Errorf("Failed to reset FBS counters for: ", countersStr)
              } else {
                  xfmrLogInfo("FBS Counters reset for ", countersStr)
              }
          }
        }
    }
    if (match_found) {
        showOutput.Output.STATUS = 1
        showOutput.Output.STATUS_DETAIL = "Cleared Counters"
    } else  {
        showOutput.Output.STATUS = 0
        showOutput.Output.STATUS_DETAIL = "No Matching Counters"
    }
    result,err = json.Marshal(&showOutput)
    xfmrLogInfo("In rpc_show_service_policy,  showOuptut:%v", showOutput)
    return result, err
}
