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
	"encoding/json"
    "fmt"
)

func init () {
    XlateFuncBind("YangToDb_mac_dampening_config_key_xfmr", YangToDb_mac_dampening_config_key_xfmr)
    XlateFuncBind("DbToYang_mac_dampening_config_key_xfmr", DbToYang_mac_dampening_config_key_xfmr)
    XlateFuncBind("DbToYang_mac_dampening_state_subtree_xfmr", DbToYang_mac_dampening_state_subtree_xfmr)
	XlateFuncBind("rpc_clear_oc_mac_damp_disabled_ports", rpc_clear_oc_mac_damp_disabled_ports)
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

func getBridgePortOidIntfMap (inParams XfmrParams) (map[string]string, error) {
    bpOidIntfMap := make(map[string]string)
    d := inParams.dbs[db.AsicDB]

    tempTxCache , present := inParams.txCache.Load("BPTOINTFOID")
    if present {
        bpCache,_ := tempTxCache.(map[string]string)
        bpOidIntfMap = bpCache
        if log.V(3) {
            log.Infof("getBridgePortOidIntfMap - cache present BP cache: %v", bpOidIntfMap)
        }
        return bpOidIntfMap, nil
    }

    tblName := "ASIC_STATE"
    bridgePortPrefix := "SAI_OBJECT_TYPE_BRIDGE_PORT"

    keys, tblErr := d.GetKeysByPattern(&db.TableSpec{Name: tblName, CompCt:2}, bridgePortPrefix+":*")
    if tblErr != nil {
        log.Error("Get Keys from ASIC_STATE bridge port table failed.", tblErr);
        return bpOidIntfMap, tblErr
    }
    if log.V(3) {
        log.Infof("getBridgePortOidIntfMap bridge port keys :%v", keys)
    }
    for _, key := range keys {
        brPKey := key.Comp[1]
        entry, dbErr := d.GetEntry(&db.TableSpec{Name:tblName}, key)
        if dbErr != nil {
            log.Error("DB GetEntry failed for key : ", key)
            continue
        }
        if entry.Has("SAI_BRIDGE_PORT_ATTR_PORT_ID") {
            bpOidIntfMap[brPKey] = entry.Get("SAI_BRIDGE_PORT_ATTR_PORT_ID")
        }
    }
    if log.V(3) {
        log.Infof("getBridgePortOidIntfMap Port OID to Intf OID :%v", bpOidIntfMap)
    }

    xfmrLogInfoAll("Storing ASICStateMaps in Cache")
    inParams.txCache.Store("BPTOINTFOID", bpOidIntfMap)
    return bpOidIntfMap, nil 
}

var DbToYang_mac_dampening_state_subtree_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {
    var err error
    pathInfo := NewPathInfo(inParams.uri)
    instance := pathInfo.Var("name")
    if !strings.EqualFold(instance, "default")  {
        log.Info("DbToYang_mac_dampening_state_subtree_xfmr:", instance)
        return nil
    }
    log.Info("DbToYang_mac_dampening_state_subtree_xfmr:instance:",instance)

    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("DbToYang_mac_dampening_state_subtree_xfmr:targetUriPath:",targetUriPath)

    macDampTbl := getMacDampTableRoot(inParams.ygRoot, instance, true)
    if macDampTbl == nil {
        log.Info("DbToYang_mac_dampening_state_subtree_xfmr - getMacDampTableRoot returned nil, for URI: ", inParams.uri)
        return errors.New("Not able to get MAC Damp table root.");
    }

    ygot.BuildEmptyTree(macDampTbl)


    ifNames, _ := getMACDampIntfNames(inParams,inParams.dbs[db.AsicDB])
    log.Info("ifNames: ",ifNames)
    macDampTbl.Interfaces = ifNames

    //Fill mac dampening threshold config
    macDampCfgEntry, cfgEntryErr := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name:"MAC_DAMPENING"}, db.Key{Comp: []string{"config"}})
    if cfgEntryErr == nil {
        value := macDampCfgEntry.Field["threshold"]
        intVal, _ := strconv.Atoi(value)
        ocThreshold := uint8(intVal)
        macDampTbl.Threshold = &ocThreshold

        value = macDampCfgEntry.Field["interval"]
        intVal, _  = strconv.Atoi(value)
        ocInterval := uint8(intVal)
        macDampTbl.Interval = &ocInterval
    }
    pretty.Print(macDampTbl)



    pretty.Print(macDampTbl)

    return err
}

func getMACDampIntfNames(inParams XfmrParams, d *db.DB) ([]string, error) {
    brPrtOidToIntfOid := make(map[string]string)
    macDampBrPrtIfName := make(map[string]string)
    var iflist []string
    tblName := "MAC_DAMP_TABLE"
    retstr := ""
    OidInfMap,_  := getOidToIntfNameMap(inParams.dbs[db.CountersDB])
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
    brPrtOidToIntfOid,_ = getBridgePortOidIntfMap(inParams)
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

var rpc_clear_oc_mac_damp_disabled_ports RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
    log.Infof("Enter")

	var mapData map[string]interface{}
	err = json.Unmarshal(body, &mapData)
	if err != nil {
		log.Infof("Error: %v. Input:%s", err, string(body))
		log.Errorf("Failed to  marshal input data; err=%v", err)
		return nil, tlerr.InvalidArgs("Invalid input %s", string(body))
	}

    input, ok := mapData["openconfig-mac-dampening:input"] ; if !ok {
		log.Infof("Invalid input ifname should be either all or specific interface name")
		return nil, tlerr.InvalidArgs("Invalid input ifname should be either all or specific interface name")
    }

	mapData = input.(map[string]interface{})
	log.Infof("RPC Input data: %v", mapData)
	ifname, found := mapData["ifname"] ; if !found {
		log.Infof("Invalid input ifname should be either all or specific interface name")
		return nil, tlerr.InvalidArgs("Invalid input ifname should be either all or specific interface name")
    }

    input_str := fmt.Sprintf("%v", ifname)

    err = util_rpc_clear_mac_damp_disabled_ports(dbs, input_str)
    return nil, err
}


/*
var Subscribe_mac_dampening_state_subtree_xfmr = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    log.Info("Entering Subscribe_mac_dampening_state_subtree_xfmr")
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbSubscribeMap)
    pathInfo := NewPathInfo(inParams.uri)
    threshold := pathInfo.Var("threshold")
    config := pathInfo.Var("config")
    keyName := "Vlan" + vlan + "|" + macAddr
    tblName := "MAC_DAMP_TABLE"
    result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB:{tblName:{keyName:{}}}}

    result.needCache = true
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 15
    result.nOpts.pType = OnChange
    log.Info("Returning Subscribe_mac_dampening_state_subtree_xfmr, result:", result)
    return result, err
}
*/
