package transformer

import (
	log "github.com/golang/glog"
    "strings"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
)

func init() {
    XlateFuncBind("YangToDb_intf_ip_helper_xfmr", YangToDb_intf_ip_helper_xfmr)
    XlateFuncBind("DbToYang_intf_ip_helper_xfmr", DbToYang_intf_ip_helper_xfmr)
}

var YangToDb_intf_ip_helper_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
    subIntfmap := make(map[string]map[string]db.Value)

    log.Info("YangToDb_intf_ip_helper_xfmr" )

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
        log.Info("YangToDb_intf_ip_helper_xfmr : Not required for sub intf")
        return subIntfmap, err
    }

    intfType, _, ierr := getIntfTypeByName(ifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("YangToDb_intf_ip_helper_xfmr: " + errStr)
        return subIntfmap, errors.New(errStr)
    }

    //Get correct interface table to be modified
    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
    log.Info("YangToDb_intf_ip_helper_xfmr: table name- " + tblName)

    subIntfObj := intfObj.Subinterfaces.Subinterface[0]

    var gwIPListStr string
    ifMap := make(map[string]db.Value)

    ifEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{ifName}})

    if subIntfObj.Ipv4 != nil && subIntfObj.Ipv4.IpHelper != nil {
        ipHelperObj := subIntfObj.Ipv4.IpHelper

        if ipHelperObj.Servers != nil {
            serversObj := ipHelperObj.Servers
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
                gwIPListStr = newserverList

                if ifEntry.IsPopulated() {
                    if strings.Count(ifEntry.Field["helper_addresses@"], ",") == 0 {
                        log.Info("last field")
                        /*if len(ifEntry.Field) == 1 {
                            if _, ok := ifEntry.Field["NULL"]; ok {
                                subIntfmap[tblName] = intfMap
                            }
                        }*/
                    }
                }
            } else {
                /*if !ifEntry.IsPopulated() {
                    intfMap[ifName].Field["NULL"] = "NULL"
                    subIntfmap[tblName] = intfMap
                }*/

                if ifEntry.Has("helper_addresses@") {
                    gwIPListStr = ifEntry.Field["helper_addresses@"]
                    gwIPListStr = gwIPListStr + "," + newserverList
                } else {
                    gwIPListStr = newserverList

                }
            }

            ifMap[ifName] = db.Value{Field:make(map[string]string)}
            ifMap[ifName].Field["helper_addresses@"] = gwIPListStr

            subIntfmap[tblName] = ifMap
        }
    }

    log.Info("YangToDb_intf_ip_helper_xfmr : subIntfmap : ", subIntfmap)

    return subIntfmap, err
} 

var DbToYang_intf_ip_helper_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
    var err error
    intfsObj := getIntfsRoot(inParams.ygRoot)
    pathInfo := NewPathInfo(inParams.uri)
    ifName := pathInfo.Var("name")
    targetUriPath, err := getYangPathFromUri(inParams.uri)
    log.Info("targetUriPath is ", targetUriPath)
    log.Info("ifName is ", ifName)
    db_if_name_ptr := utils.GetNativeNameFromUIName(&ifName)
    dbifName := *db_if_name_ptr

    var intfObj *ocbinds.OpenconfigInterfaces_Interfaces_Interface
    intfType, _, ierr := getIntfTypeByName(dbifName)
    if intfType == IntfTypeUnset || ierr != nil {
        errStr := "Invalid interface type IntfTypeUnset"
        log.Info("DbToYang_intf_ip_helper_xfmr : " + errStr)
        return errors.New(errStr)
    }

    //Get correct interface table to be modified
    intTbl := IntfTypeTblMap[intfType]
    tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
    log.Info("DbToYang_intf_ip_helper_xfmr: table name- " + tblName)

    ifEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{dbifName}})
    serverList := ifEntry.Get("helper_addresses@")
    servers := strings.Split(serverList, ",")

    if (servers[0] == "") {
        log.Info("DbToYang_intf_ip_helper_xfmr: field empty " + serverList)
        return err
    }

    ipv4_req := true

    if ipv4_req {
        if intfsObj != nil && intfsObj.Interface != nil && len(intfsObj.Interface) > 0 {
            var ok bool = false
            if intfObj, ok = intfsObj.Interface[ifName]; !ok {
                intfObj, _ = intfsObj.NewInterface(ifName)
                ygot.BuildEmptyTree(intfObj)
            }
        } else {
            ygot.BuildEmptyTree(intfsObj)
            intfObj, _ = intfsObj.NewInterface(ifName)
            ygot.BuildEmptyTree(intfObj)
        }

        if intfObj.Subinterfaces == nil {
            var _subintfs ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces
            intfObj.Subinterfaces = &_subintfs
            ygot.BuildEmptyTree(intfObj.Subinterfaces)
        }

        var subIntf *ocbinds.OpenconfigInterfaces_Interfaces_Interface_Subinterfaces_Subinterface
        if _, ok := intfObj.Subinterfaces.Subinterface[0]; !ok {
            subIntf, err = intfObj.Subinterfaces.NewSubinterface(0)
            if err != nil {
                log.Error("Creation of subinterface subtree failed!")
                return err
            }
            ygot.BuildEmptyTree(subIntf)
        }

        subIntf = intfObj.Subinterfaces.Subinterface[0]
        ygot.BuildEmptyTree(subIntf)

        if ipv4_req {
            ygot.BuildEmptyTree(subIntf.Ipv4)
            ygot.BuildEmptyTree(subIntf.Ipv4.IpHelper)
            ygot.BuildEmptyTree(subIntf.Ipv4.IpHelper.Servers)
            for _ , server := range servers {
                log.Info("Server: ", server)
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
                serverObj, _ := subIntf.Ipv4.IpHelper.Servers.NewServer(vrf,ip)
                ygot.BuildEmptyTree(serverObj)
            }
        }
    }

    return err
}