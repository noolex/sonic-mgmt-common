package transformer

import (
	"errors"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
)

func init() {
	XlateFuncBind("YangToDb_ip_helper_intf_xfmr", YangToDb_ip_helper_intf_xfmr)
	XlateFuncBind("DbToYang_ip_helper_intf_xfmr", DbToYang_ip_helper_intf_xfmr)
	XlateFuncBind("Subscribe_ip_helper_intf_xfmr", Subscribe_ip_helper_intf_xfmr)
}

var Subscribe_ip_helper_intf_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
	var err error
	var result XfmrSubscOutParams
	result.dbDataMap = make(RedisDbSubscribeMap)

	pathInfo := NewPathInfo(inParams.uri)

	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	keyName := pathInfo.Var("id")

	//Get correct interface table to be modified. Start
	intfType, _, ierr := getIntfTypeByName(keyName)
	if intfType == IntfTypeUnset || ierr != nil {
		errStr := "Invalid interface type IntfTypeUnset"
		log.Info("Subscribe_ip_helper_intf_xfmr: " + errStr)
		return result, errors.New(errStr)
	}

	intTbl := IntfTypeTblMap[intfType]
	tblName, _ := getIntfTableNameByDBId(intTbl, db.ConfigDB)
	log.Info("Subscribe_ip_helper_intf_xfmr: table name- " + tblName)
	//Get correct interface table to be modified. End

	log.Infof("Subscribe_ip_helper_intf_xfmr path %v key %v ", targetUriPath, keyName)

	if keyName != "" {
		result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB: {tblName: {keyName: {}}}}
		log.Infof("Subscribe_ip_helper_intf_xfmr keyName %v dbDataMap %v ", keyName, result.dbDataMap)
	} else {
		errStr := "Interface name not present in request"
		log.Info("Subscribe_ip_helper_intf_xfmr: " + errStr)
		return result, errors.New(errStr)
	}
	result.isVirtualTbl = false
	log.Info("Returning Subscribe_ip_helper_intf_xfmr")
	return result, err
}

var YangToDb_ip_helper_intf_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	ifMap := make(map[string]db.Value)
	subIntfmap := make(map[string]map[string]db.Value)
	log.Info("YangToDb_ip_helper_intf_xfmr. Entered")

	iph := getIpHelperRoot(inParams.ygRoot)

	//Validate and get to the intf object. Start
	intfsObj := iph.Interfaces
	if intfsObj == nil || len(intfsObj.Interface) < 1 {
		log.Info("YangToDb_ip_helper_intf_xfmr: IntfsObj/interface list is empty.")
		return subIntfmap, errors.New("IntfsObj/Interface is not specified")
	}

	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("id")

	log.Info("YangToDb_ip_helper_intf_xfmr Ifname: " + ifName)
	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_ip_helper_intf_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	if _, ok := intfsObj.Interface[ifName]; !ok {
		errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
		log.Info("YangToDb_ip_helper_intf_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	intfObj := intfsObj.Interface[ifName]
	//Validate and get to the intf object. End

	//Get correct interface table to be modified. Start
	intfType, _, ierr := getIntfTypeByName(ifName)
	if intfType == IntfTypeUnset || ierr != nil {
		errStr := "Invalid interface type IntfTypeUnset"
		log.Info("YangToDb_ip_helper_intf_xfmr: " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	intTbl := IntfTypeTblMap[intfType]
	tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
	log.Info("YangToDb_ip_helper_intf_xfmr: table name- " + tblName)
	//Get correct interface table to be modified. End

	//Handle delete when req uri is less specific
	requestUri, _ := getYangPathFromUri(inParams.requestUri)
	if !strings.Contains(requestUri, "openconfig-ip-helper:ip-helper/interfaces/interface/servers") {
		if inParams.oper == DELETE {
			ifMap[ifName] = db.Value{Field: make(map[string]string)}
			ifMap[ifName].Field["helper_addresses@"] = ""
			subIntfmap[tblName] = ifMap
			log.Info("YangToDb_ip_helper_intf_xfmr : subIntfmap : ", subIntfmap)
			return subIntfmap, nil
		}
	}

	//Validate and get to the Servers object. Start
	if intfObj.Servers == nil {
		errStr := "subintf.Ipv4.IpHelper.Servers is not set"
		log.Info("YangToDb_ip_helper_intf_xfmr : " + errStr)
		return subIntfmap, errors.New(errStr)
	}

	serversObj := intfObj.Servers
	//Validate and get to the Servers object. End

	var finalServerListStr string
	ifEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: tblName}, db.Key{Comp: []string{ifName}})
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

	ifMap[ifName] = db.Value{Field: make(map[string]string)}
	ifMap[ifName].Field["helper_addresses@"] = finalServerListStr
	subIntfmap[tblName] = ifMap

	log.Info("YangToDb_ip_helper_intf_xfmr : subIntfmap : ", subIntfmap)
	return subIntfmap, err
}

var DbToYang_ip_helper_intf_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	var err error
	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("id")
	reqVrf := pathInfo.Var("vrf")
	reqIp := pathInfo.Var("ip")
	targetUriPath, err := getYangPathFromUri(inParams.uri)
	db_if_name_ptr := utils.GetNativeNameFromUIName(&ifName)
	dbifName := *db_if_name_ptr

	log.Info("DbToYang_ip_helper_intf_xfmr. Entered. targetUriPath ", targetUriPath)

	iph := getIpHelperRoot(inParams.ygRoot)
	intfsObj := iph.Interfaces

	//Validate and get to the Servers object. Start
	if intfsObj == nil {
		errStr := "Interface object not found in Ygot tree"
		log.Info("DbToYang_ip_helper_intf_xfmr: intfsObj empty ")
		return errors.New(errStr)
	}

	if _, ok := intfsObj.Interface[ifName]; !ok {
		errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
		log.Info("DbToYang_ip_helper_intf_xfmr: " + errStr)
		return errors.New(errStr)
	}

	intfObj := intfsObj.Interface[ifName]

	if intfObj.Servers == nil {
		errStr := "subintf.Ipv4.IpHelper.Servers is not set"
		log.Info("DbToYang_ip_helper_intf_xfmr : subintf.Ipv4.IpHelper.Servers is not set")
		return errors.New(errStr)
	}

	serversObj := intfObj.Servers
	//Validate and get to the Servers object. End

	//Get correct interface table to be modified. Start
	intfType, _, ierr := getIntfTypeByName(dbifName)
	if intfType == IntfTypeUnset || ierr != nil {
		errStr := "Invalid interface type IntfTypeUnset"
		log.Info("DbToYang_ip_helper_intf_xfmr : " + errStr)
		return errors.New(errStr)
	}

	intTbl := IntfTypeTblMap[intfType]
	tblName, _ := getIntfTableNameByDBId(intTbl, inParams.curDb)
	log.Info("DbToYang_ip_helper_intf_xfmr: table name- " + tblName)
	//Get correct interface table to be modified. End

	ifEntry, _ := inParams.d.GetEntry(&db.TableSpec{Name: tblName}, db.Key{Comp: []string{dbifName}})
	serverList := ifEntry.Get("helper_addresses@")
	servers := strings.Split(serverList, ",")

	if servers[0] == "" {
		log.Info("DbToYang_ip_helper_intf_xfmr: field empty " + serverList)
		return err
	}

	ygot.BuildEmptyTree(serversObj)

	if reqVrf != "" && reqIp != "" {
		//Specific case
		var present bool
		var dbkey string
		if reqVrf == "default" {
			dbkey = reqIp
		} else {
			dbkey = reqVrf + "|" + reqIp
		}
		for _, server := range servers {
			if server == dbkey {
				present = true
			}
		}
		if present {
			var key ocbinds.OpenconfigIpHelper_IpHelper_Interfaces_Interface_Servers_Server_Key
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
		for _, server := range servers {
			log.Info("Server: ", server)
			var serverObj *ocbinds.OpenconfigIpHelper_IpHelper_Interfaces_Interface_Servers_Server
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
			if reqVrf != "" && reqIp != "" {
				var key ocbinds.OpenconfigIpHelper_IpHelper_Interfaces_Interface_Servers_Server_Key
				key.Vrf = reqVrf
				key.Ip = reqIp
				serverObj = serversObj.Server[key]
			} else {
				serverObj, _ = serversObj.NewServer(vrf, ip)
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
