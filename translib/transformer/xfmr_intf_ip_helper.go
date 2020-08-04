package transformer

import (
	log "github.com/golang/glog"
    "strings"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init() {
    XlateFuncBind("YangToDb_intf_ip_helper_xfmr", YangToDb_intf_ip_helper_xfmr)
    XlateFuncBind("DbToYang_intf_ip_helper_xfmr", DbToYang_intf_ip_helper_xfmr)
    XlateFuncBind("Subscribe_intf_ip_helper_xfmr", Subscribe_intf_ip_helper_xfmr)
}

var Subscribe_intf_ip_helper_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams
    result.dbDataMap = make(RedisDbMap)

    pathInfo := NewPathInfo(inParams.uri)

    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

    keyName := pathInfo.Var("name")

    //Get correct interface table to be modified. Start
    intfType, _, ierr := getIntfTypeByName(keyName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("Subscribe_intf_ip_helper_xfmr: " + errStr)
        return result, errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, db.ConfigDB)
    log.Info("Subscribe_intf_ip_helper_xfmr: table name- " + tblName)
    //Get correct interface table to be modified. End

    log.Infof("Subscribe_intf_ip_helper_xfmr path %v key %v ", targetUriPath, keyName)

    if (keyName != "") {
        result.dbDataMap = RedisDbMap{db.ConfigDB:{tblName:{keyName:{}}}}
        log.Infof("Subscribe_intf_ip_helper_xfmr keyName %v dbDataMap %v ", keyName, result.dbDataMap)
    } else {
        errStr := "Interface name not present in request"
        log.Info("Subscribe_intf_ip_helper_xfmr: " + errStr)
        return result, errors.New(errStr)
    }
    result.isVirtualTbl = false
    log.Info("Returning Subscribe_intf_ip_helper_xfmr")
    return result, err
}

var YangToDb_intf_ip_helper_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    ifMap := make(map[string]db.Value)
    subIntfmap := make(map[string]map[string]db.Value)
    log.Info("YangToDb_intf_ip_helper_xfmr. Entered" )

    //Validate and get to the Subintf object. Start
    intfsObj := getIntfsRoot(inParams.ygRoot)
    if intfsObj == nil || len(intfsObj.Interface) < 1 {
        log.Info("YangToDb_intf_ip_helper_xfmr: IntfsObj/interface list is empty.")
        return subIntfmap, errors.New("IntfsObj/Interface is not specified")
    }

    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")

    log.Info("YangToDb_intf_ip_helper_xfmr Ifname: " + ifName)
    if ifName == "" {
        errStr := "Interface KEY not present"
        log.Info("YangToDb_intf_ip_helper_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfsObj.Interface[ifName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("YangToDb_intf_ip_helper_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intfObj := intfsObj.Interface[ifName]

    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        if inParams.oper == DELETE {
            return nil, nil
        }
        errStr := "SubInterface node is not set"
        log.Info("YangToDb_intf_ip_helper_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        if inParams.oper == DELETE {
            return nil, nil
        }
        errStr := "SubInterface[0] node is not set"
        log.Info("YangToDb_intf_ip_helper_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]
    //Validate and get to the Servers object. End

    //Get correct interface table to be modified. Start
    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_ip_helper_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
    log.Info("YangToDb_intf_ip_helper_xfmr: table name- " + tblName)
    //Get correct interface table to be modified. End

    //Handle delete when req uri is less specific
    requestUri, _ := getYangPathFromUri(inParams.requestUri)
    if !strings.Contains(requestUri, "openconfig-interfaces-ext:ip-helper/servers") {
        if inParams.oper == DELETE {
            ifMap[ifName] = db.Value{Field:make(map[string]string)}
            ifMap[ifName].Field["helper_addresses@"] = ""
            subIntfmap[tblName] = ifMap
            log.Info("YangToDb_intf_ip_helper_xfmr : subIntfmap : ", subIntfmap)
            return subIntfmap, nil
        }
    }

    //Validate and get to the Servers object. Start
    if subIntfObj.Ipv4 == nil {
        errStr := "subintf.Ipv4 is not set"
        log.Info("YangToDb_intf_ip_helper_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if subIntfObj.Ipv4.IpHelper == nil {
        errStr := "subintf.Ipv4.IpHelper is not set"
        log.Info("YangToDb_intf_ip_helper_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    if subIntfObj.Ipv4.IpHelper.Servers == nil {
        errStr := "subintf.Ipv4.IpHelper.Servers is not set"
        log.Info("YangToDb_intf_ip_helper_xfmr : " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    serversObj := subIntfObj.Ipv4.IpHelper.Servers
    //Validate and get to the Servers object. End

    

    var finalServerListStr string
    ifEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})
    newserverList := ""

    for serverKey := range serversObj.Server {
        log.Info("Server vrf := IP:=", serverKey.Vrf, serverKey.Ip)
        if serverKey.Vrf == "default" {
            newserverList = serverKey.Ip
        } else {
            newserverList = serverKey.Vrf + "|" + serverKey.Ip
        }
    }

    if inParams.oper == DELETE {
        finalServerListStr = newserverList
    } else {
        //CREATE, REPLACE, UPDATE case  
        if ifEntry.Has("helper_addresses@") {
            finalServerListStr = ifEntry.Field["helper_addresses@"]
            finalServerListStr = finalServerListStr + "," + newserverList
        } else {
            finalServerListStr = newserverList
        }
    }

    ifMap[ifName] = db.Value{Field:make(map[string]string)}
    ifMap[ifName].Field["helper_addresses@"] = finalServerListStr
    subIntfmap[tblName] = ifMap

    log.Info("YangToDb_intf_ip_helper_xfmr : subIntfmap : ", subIntfmap)
    return subIntfmap, err
} 

var DbToYang_intf_ip_helper_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    reqVrf := pathInfo.Var("vrf")
    reqIp := pathInfo.Var("ip")
    targetUriPath, err := getYangPathFromUri(inParams.uri)
    db_if_name_ptr := utils.GetNativeNameFromUIName(&ifName)
    dbifName := *db_if_name_ptr

    log.Info("DbToYang_intf_ip_helper_xfmr. Entered. targetUriPath ", targetUriPath )

    //Validate and get to the Servers object. Start
    if intfsObj == nil {
        errStr := "Interface object not found in Ygot tree"
        log.Info("DbToYang_intf_ip_helper_xfmr: intfsObj empty ")
        return errors.New(errStr)
    }

    if _, ok := intfsObj.Interface[ifName]; !ok {
        errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
        log.Info("DbToYang_intf_ip_helper_xfmr: " + errStr)
        return errors.New(errStr)
    }

    intfObj := intfsObj.Interface[ifName]

    if intfObj.Subinterfaces == nil || len(intfObj.Subinterfaces.Subinterface) < 1 {
        errStr := "SubInterface node is not set"
        log.Info("DbToYang_intf_ip_helper_xfmr: " + errStr)
        return errors.New(errStr)
    }

    if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
        errStr := "SubInterface[0] is not set"
        log.Info("DbToYang_intf_ip_helper_xfmr: " + errStr)
        return errors.New(errStr)
    }

    subIntf := intfObj.Subinterfaces.Subinterface[0]

    if subIntf.Ipv4 == nil {
        errStr := "subintf.Ipv4 is not set"
        log.Info("DbToYang_intf_ip_helper_xfmr: " + errStr)
        return errors.New(errStr)
    }

    if subIntf.Ipv4.IpHelper == nil {
        errStr := "subintf.Ipv4.IpHelper is not set"
        log.Info("DbToYang_intf_ip_helper_xfmr: " + errStr)
        return errors.New(errStr)
    }

    if subIntf.Ipv4.IpHelper.Servers == nil {
        errStr := "subintf.Ipv4.IpHelper.Servers is not set"
        log.Info("DbToYang_intf_ip_helper_xfmr : subintf.Ipv4.IpHelper.Servers is not set")
        return errors.New(errStr)
    }

    serversObj := subIntf.Ipv4.IpHelper.Servers
    //Validate and get to the Servers object. End

    //Get correct interface table to be modified. Start
    intfType, _, ierr := getIntfTypeByName(dbifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("DbToYang_intf_ip_helper_xfmr : " + errStr)
        return errors.New(errStr)
    }

    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
    log.Info("DbToYang_intf_ip_helper_xfmr: table name- " + tblName)
    //Get correct interface table to be modified. End

    ifEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{dbifName}})
    serverList := ifEntry.Get("helper_addresses@")
    servers := strings.Split(serverList, ",")

    if (servers[0] == "") {
        log.Info("DbToYang_intf_ip_helper_xfmr: field empty " + serverList)
        return err
    }

    ygot.BuildEmptyTree(serversObj)

    if(reqVrf != "" && reqIp != "") {
        //Specific case
        var present bool
        var dbkey string
        if reqVrf == "default" {
            dbkey = reqIp
        } else {
            dbkey = reqVrf + "|" + reqIp
        }
        for _ , server := range servers {
            if server == dbkey {
                present = true
            }
        }
        if present {
            var key ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_IpHelper_Servers_Server_Key
            key.Vrf = reqVrf
            key.Ip = reqIp
            serverObj := serversObj.Server[key]
            ygot.BuildEmptyTree(serverObj)
            ygot.BuildEmptyTree(serverObj.Config)
            serverObj.Config.Vrf = &reqVrf
            serverObj.Config.Ip = &reqIp
            ygot.BuildEmptyTree(serverObj.State)
            serverObj.State.Vrf = &reqVrf
            serverObj.State.Ip = &reqIp
        } else {
            return tlerr.NotFound("Resource Not Found")
        }
        
    } else {
        for _ , server := range servers {
            log.Info("Server: ", server)
            var serverObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_IpHelper_Servers_Server
            key := strings.Split(server, "|")
            var vrf string
            var ip string
            if len(key) > 1 {
                vrf = key[0]
                ip = key[1]
            } else {
                vrf = "default"
                ip = key[0]
            }
            if(reqVrf != "" && reqIp != "") {
                var key ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface_Ipv4_IpHelper_Servers_Server_Key
                key.Vrf = reqVrf
                key.Ip = reqIp
                serverObj = serversObj.Server[key]
            } else {
                serverObj, _ = serversObj.NewServer(vrf,ip)
            }
            ygot.BuildEmptyTree(serverObj)
            ygot.BuildEmptyTree(serverObj.Config)
            serverObj.Config.Vrf = &vrf
            serverObj.Config.Ip = &ip
            ygot.BuildEmptyTree(serverObj.State)
            serverObj.State.Vrf = &vrf
            serverObj.State.Ip = &ip
        }
    }

    return err
}