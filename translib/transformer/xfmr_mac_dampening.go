package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/kylelemons/godebug/pretty"
    "strings"
    "strconv"
    "errors"
    log "github.com/golang/glog"
)

func init () {
    XlateFuncBind("YangToDb_mac_dampening_config_key_xfmr", YangToDb_mac_dampening_config_key_xfmr)
    XlateFuncBind("DbToYang_mac_dampening_config_key_xfmr", DbToYang_mac_dampening_config_key_xfmr)
    XlateFuncBind("YangToDb_mac_dampening_config_value_xfmr", YangToDb_mac_dampening_config_value_xfmr)
    XlateFuncBind("DbToYang_mac_dampening_config_value_xfmr", DbToYang_mac_dampening_config_value_xfmr)
    //XlateFuncBind("YangToDb_mac_dampening_state_key_xfmr", YangToDb_mac_dampening_state_key_xfmr)
    //XlateFuncBind("DbToYang_mac_dampening_state_key_xfmr", DbToYang_mac_dampening_state_key_xfmr)
    //XlateFuncBind("YangToDb_mac_dampening_state_field_xfmr", YangToDb_mac_dampening_state_field_xfmr)
    //XlateFuncBind("DbToYang_mac_dampening_state_field_xfmr", DbToYang_mac_dampening_state_field_xfmr)
    //XlateFuncBind("YangToDb_mac_dampening_config_subtree_xfmr", YangToDb_mac_dampening_config_subtree_xfmr)
    //XlateFuncBind("DbToYang_mac_dampening_config_subtree_xfmr", DbToYang_mac_dampening_config_subtree_xfmr)
    //XlateFuncBind("YangToDb_mac_dampening_state_subtree_xfmr", YangToDb_mac_dampening_state_subtree_xfmr)
    XlateFuncBind("DbToYang_mac_dampening_state_subtree_xfmr", DbToYang_mac_dampening_state_subtree_xfmr)
//    XlateFuncBind("YangToDb_mac_dampening_state_value_xfmr", YangToDb_mac_dampening_state_value_xfmr)
//    XlateFuncBind("DbToYang_mac_dampening_state_value_xfmr", DbToYang_mac_dampening_state_value_xfmr)
//    XlateFuncBind("Subscribe_mac_dampening_state_subtree_xfmr", Subscribe_mac_dampening_state_subtree_xfmr)
}

var YangToDb_mac_dampening_config_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var key string
    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")
    config := pathInfo.Var("config")
    key = "config"
    if log.V(1) {
        log.Infof("YangToDb_mac_dampening_config_key_xfmr:pathInfo:%s,instance:%s,config:%s,key:%s",
                   pathInfo,instance,config,key)
    }
    return key,nil
}

func DbToYang_mac_dampening_config_key_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var key string
    result := make(map[string]interface{})
    key = inParams.key
    if log.V(1) {
        log.Infof("DbToYang_mac_dampening_config_key_xfmr key:%s",key)
        log.Info("result:",result)
    }
    return result,nil
}

var YangToDb_mac_dampening_state_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var key string
    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")
    config := pathInfo.Var("config")
    key = ""
    if log.V(1) {
        log.Infof("YangToDb_mac_dampening_state_key_xfmr:pathInfo:%s,instance:%s,config:%s,key:%s",
                   pathInfo,instance,config,key)
    }
    return key,nil
}

func DbToYang_mac_dampening_state_key_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var key string
    result := make(map[string]interface{})
    key = inParams.key
    if log.V(1) {
        log.Infof("DbToYang_mac_dampening_state_key_xfmr key:%s",key)
        log.Info("result:",result)
    }
    return result,nil
}

var YangToDb_mac_dampening_state_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    log.Info("YangToDb_mac_dampening_state_field_xfmr:inParams",inParams)
    res_map := make(map[string]string)
    return res_map,nil
}

func DbToYang_mac_dampening_state_field_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("DbToYang_mac_dampening_state_field_xfmr:inParams",inParams)
    res_map := make(map[string]interface{})
    return res_map,nil
}

var YangToDb_mac_dampening_config_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    pathInfo := NewPathInfo(inParams.uri)
    log.Info("YangToDb_mac_dampening_config_subtree_xfmr:pathInfo:",pathInfo)
    instance := pathInfo.Var("name")
    log.Info("YangToDb_mac_dampening_config_subtree_xfmr:instance:",instance)
    targetUriPath, err  := getYangPathFromUri(inParams.uri)
    if err != nil {
        log.Error("getASICStateMaps failed.")
        return nil, err
    }
    log.Info("YangToDb_mac_dampening_config_subtree_xfmr:targetUriPath:",targetUriPath)

    if strings.HasPrefix(instance, "Vrf") || strings.HasPrefix(instance, "mgmt") {
        log.Info("YangToDb_mac_dampening_config_subtree_xfmr Ignoring OP:",inParams.oper," for FDB on VRF:", instance)
        return nil, err
    }

    log.Info("YangToDb_mac_dampening_config_subtree_xfmr=>", inParams)

    return nil, err
}

var DbToYang_mac_dampening_config_subtree_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    log.Info("DbToYang_mac_dampening_config_subtree_xfmr:inParams:",inParams)
    pathInfo := NewPathInfo(inParams.uri)
    log.Info("DbToYang_mac_dampening_config_subtree_xfmr:pathInfo:",pathInfo)
    instance := pathInfo.Var("name")
    log.Info("DbToYang_mac_dampening_config_subtree_xfmr:instance:",instance)
    if strings.HasPrefix(instance, "Vrf") {
        log.Info("DbToYang_mac_dampening_config_subtree_xfmr:vrf")
        return nil
    }

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("DbToYang_mac_dampening_config_subtree_xfmr:targetUriPath",targetUriPath)

    return err
}


var YangToDb_mac_dampening_config_value_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(1) {
        log.Info("Entering YangToDb_mac_dampening_config_value_xfmr")
    }
    res_map := make(map[string]string)
    return res_map, nil
}

func DbToYang_mac_dampening_config_value_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var key string
    result := make(map[string]interface{})
    key = inParams.key
    if log.V(1) {
        log.Infof("DbToYang_mac_dampening_config_value_xfmr: inParams.key:%s key:%s", inParams.key,key)
    }
    result["global"] = "config"

    entry, err := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:"MAC_DAMPENING"}, db.Key{Comp: []string{"config"}})
    if err == nil {
        value := entry.Field["threshold"]
        result["threshold"],_ = strconv.ParseUint(value,10,8)
    } else {
        log.Error("Error ", err)
        return result, tlerr.NotFound("Resource Not Found")
    }
    if log.V(1) {
        log.Info(result)
    }
    return result, nil
}

/*
var YangToDb_mac_dampening_state_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    pathInfo := NewPathInfo(inParams.uri)
    log.Info("YangToDb_mac_dampening_state_subtree_xfmr=>", inParams)
    log.Info("YangToDb_mac_dampening_state_subtree_xfmr:pathInfo:",pathInfo)
    instance := pathInfo.Var("name")
    log.Info("YangToDb_mac_dampening_state_subtree_xfmr:instance:",instance)
    targetUriPath, err  := getYangPathFromUri(inParams.uri)
    if err != nil {
        log.Error("getASICStateMaps failed.")
        return nil, err
    }
    log.Info("YangToDb_mac_dampening_state_subtree_xfmr:targetUriPath:",targetUriPath)

    if strings.HasPrefix(instance, "Vrf") || strings.HasPrefix(instance, "mgmt") {
        log.Info("YangToDb_mac_dampening_state_subtree_xfmr Ignoring OP:",inParams.oper," for FDB on VRF:", instance)
        return nil, err
    }

    return nil, err
}
*/

var DbToYang_mac_dampening_state_subtree_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    log.Info("YangToDb_mac_dampening_state_subtree_xfmr:inParams:",inParams)
    pathInfo := NewPathInfo(inParams.uri)
    log.Info("DbToYang_mac_dampening_state_subtree_xfmr:pathInfo:",pathInfo)
    instance := pathInfo.Var("name")
    log.Info("DbToYang_mac_dampening_state_subtree_xfmr:instance:",instance)
    if strings.HasPrefix(instance, "Vrf") {
        log.Info("DbToYang_mac_dampening_state_subtree_xfmr:vrf")
        return nil
    }

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("DbToYang_mac_dampening_state_subtree_xfmr:targetUriPath:",targetUriPath)

    ifNames, _ := getMACDampIntfNames(inParams,inParams.dbs[db.AsicDB])
    log.Info("ifNames: ",ifNames)

    macDampTbl := getMacDampTableRoot(inParams.ygRoot, instance, true)

    if macDampTbl == nil {
        log.Info("DbToYang_mac_dampening_state_subtree_xfmr - getMacDampTableRoot returned nil, for URI: ", inParams.uri)
        return errors.New("Not able to get MAC Damp table root.");
    }

    ygot.BuildEmptyTree(macDampTbl)
    macDampTbl.Interfaces = ifNames
    macDampTbl.Global = ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_MacDampening_Config_Global_GLOBAL

    pretty.Print(macDampTbl)

    return err
}

func getMACDampIntfNames(inParams XfmrParams, d *db.DB) ([]string, error) {
    brPrtOidToIntfOid := make(map[string]string)
    macDampBrPrtIfName := make(map[string]string)
    var iflist []string
    tblName := "MAC_DAMP_TABLE"
    retstr := ""
    OidInfMap,_  := getOidToIntfNameMap(inParams.dbs[db.CountersDB], inParams.txCache)
    //log.Info("OidInfMap: ",OidInfMap)
    keys, tblErr := d.GetKeys(&db.TableSpec{Name:tblName} )
    //log.Info("keys: ",keys)
    if tblErr != nil {
        log.Error("Get Keys from ASIC_STATE table failed.", tblErr);
        return iflist,tblErr
    }
    if brPrtOidToIntfOid == nil {
        return iflist,tblErr
    }
    _, brPrtOidToIntfOid,_,_ = getASICStateMaps(inParams.dbs[db.AsicDB], inParams.txCache)
    //log.Info("brPrtOidToIntfOid: ",brPrtOidToIntfOid)
    for _, key := range keys {
        //log.Info("key:",key)
        macdkey := key.Comp[0]+":"+key.Comp[1]
        //log.Info("macdkey:",macdkey)
        intfOid:=findInMap(brPrtOidToIntfOid, macdkey)
        //log.Info("intfOid:",intfOid)
        if intfOid != "" {
            intfName := new(string)
            *intfName = findInMap(OidInfMap,intfOid)
            //log.Info("intfName:",intfName)
            if *intfName !="" {
                intfNameCon := utils.GetUINameFromNativeName(intfName)
                //log.Info("intfNameCon:",*intfNameCon)
                macDampBrPrtIfName[macdkey]=*intfNameCon
                retstr = retstr + *intfNameCon + "\n"
                //log.Info("getMACDampIntfNames:*intfNameCon:",*intfNameCon)
                iflist = append(iflist,*intfNameCon)
            }
        }
    }
    log.Info("getMACDampIntfNames:iflist:",iflist)
    return iflist,nil
}

func getMacDampTableRoot (s *ygot.GoStruct, instance string, build bool) *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_MacDampening_State{
    var macDampTableObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_MacDampening_State

    deviceObj := (*s).(*ocbinds.Device)
    niObj := deviceObj.NetworkInstances

    if instance == "" {
        instance = "default"
    }
    if niObj != nil {
        if niObj.NetworkInstance != nil && len(niObj.NetworkInstance) > 0 {
            if _, ok := niObj.NetworkInstance[instance]; ok {
                niInst := niObj.NetworkInstance[instance]
                if niInst.MacDampening!= nil {
                    if niInst.MacDampening.State != nil {
                        macDampTableObj = niInst.MacDampening.State
                    }
                }
            }
        }
    }

    if macDampTableObj == nil && (build) {
        if niObj.NetworkInstance == nil || len(niObj.NetworkInstance) < 1 {
            ygot.BuildEmptyTree(niObj)
        }
        var niInst *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance
        if _, ok := niObj.NetworkInstance[instance]; !ok {
            niInst, _  = niObj.NewNetworkInstance(instance)
        } else {
            niInst = niObj.NetworkInstance[instance]
        }
        ygot.BuildEmptyTree(niInst)
        ygot.BuildEmptyTree(niInst.MacDampening)
        if niInst.MacDampening == nil {
            ygot.BuildEmptyTree(niInst.MacDampening.State)
        }
        macDampTableObj = niInst.MacDampening.State
    }

    return macDampTableObj 
}

/*
var YangToDb_mac_dampening_state_value_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    if log.V(1) {
        log.Info("Entering YangToDb_mac_dampening_state_value_xfmr")
    }
    res_map := make(map[string]string)
    return res_map, nil
}

func DbToYang_mac_dampening_state_value_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    var key string
    result := make(map[string]interface{})
    key = inParams.key
    if log.V(1) {
        log.Infof("DbToYang_mac_dampening_state_value_xfmr: inParams.key:%s key:%s", inParams.key,key)
    }
    result["global"] = ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_MacDampening_Config_Global_global

    entry, err := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:"MAC_DAMPENING"}, db.Key{Comp: []string{"config"}})
    if err == nil {
        value := entry.Field["threshold"]
        result["threshold"],_ = strconv.ParseUint(value,10,8)
    } else {
        log.Error("Error ", err)
        return result, tlerr.NotFound("Resource Not Found")
    }
    if log.V(1) {
        log.Info(result)
    }
    return result, nil
}
*/


/*
var Subscribe_mac_dampening_state_subtree_xfmr = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    log.Info("Entering Subscribe_mac_dampening_state_subtree_xfmr")
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)
    pathInfo := NewPathInfo(inParams.uri)
    threshold := pathInfo.Var("threshold")
    global := pathInfo.Var("global")
    config := pathInfo.Var("config")
    keyName := "Vlan" + vlan + "|" + macAddr
    tblName := "MAC_DAMP_TABLE"
    result.dbDataMap = RedisDbMap{db.ConfigDB:{tblName:{keyName:{}}}}

    result.needCache = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 15
    result.nOpts.pType = OnChange
    log.Info("Returning Subscribe_mac_dampening_state_subtree_xfmr, result:", result)
    return result, err
}
*/
