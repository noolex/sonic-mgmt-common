package transformer

import (
        "errors"
        log "github.com/golang/glog"
        "github.com/openconfig/ygot/ygot"
        "strings"
        "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
        "github.com/Azure/sonic-mgmt-common/translib/db"
        "github.com/Azure/sonic-mgmt-common/translib/tlerr"
        "github.com/Azure/sonic-mgmt-common/translib/utils"
)

type NwInstMapKey struct {
        NwInstName    string
        NwInstType    string
}

const (
        MGMT_VRF_ENABLE        = "mgmtVrfEnabled"
)

const (
        MGMT_VRF_NAME          = "mgmt-vrf-name"
)

const (
        DEFAULT_NETWORK_INSTANCE_CONFIG_TYPE        = "L3VRF"
)


var nwInstTypeMap = map[ocbinds.E_OpenconfigNetworkInstanceTypes_NETWORK_INSTANCE_TYPE] string {
        ocbinds.OpenconfigNetworkInstanceTypes_NETWORK_INSTANCE_TYPE_DEFAULT_INSTANCE: "DEFAULT_INSTANCE",
        ocbinds.OpenconfigNetworkInstanceTypes_NETWORK_INSTANCE_TYPE_L3VRF: "L3VRF",
        ocbinds.OpenconfigNetworkInstanceTypes_NETWORK_INSTANCE_TYPE_L2L3: "L2L3",
}

// NwInstTblNameMapWithNameAndType is the top level network instance table name based on key name and type
var NwInstTblNameMapWithNameAndType = map[NwInstMapKey]string {
        {NwInstName: "mgmt", NwInstType: "L3VRF"}: "MGMT_VRF_CONFIG",
        {NwInstName: "Vrf",  NwInstType: "L3VRF"}: "VRF",
        {NwInstName: "default", NwInstType: "L3VRF"}: "VRF",
        {NwInstName: "default", NwInstType: "DEFAULT_INSTANCE"}: "VRF",
        {NwInstName: "Vlan", NwInstType: "L2L3"}: "VLAN",
}

// NwInstTblNameMapWithName is the top level network instance table name based on key name
var NwInstTblNameMapWithName = map[string]string {
	"mgmt": "MGMT_VRF_CONFIG",
	"Vrf": "VRF",
	"default": "VRF",
    "Vlan": "VLAN",
}

var intf_tbl_name_list = [4]string{"INTERFACE", "LOOPBACK_INTERFACE", "VLAN_INTERFACE", "PORTCHANNEL_INTERFACE"}

/*
 * Get internal network instance name based on the incoming network instance name
 * and use it for top level table map lookup
 */
func getInternalNwInstName (name string) (string, error) {
        var err error

        if name == "" {
                return "", errors.New("Network instance name is empty")
        } else if (strings.Compare(name, "mgmt") == 0) {
                return "mgmt", err
        } else if (strings.HasPrefix(name, "Vrf")) {
                return "Vrf", err
        } else if (strings.HasPrefix(name, "Vlan")) {
                return "Vlan", err
        } else if (strings.Compare(name, "default") == 0) {
                return "default", err
        } else {
                /* For other types */
                return "", errors.New("Network instance name uknonwn")
        }
}

/* Get table entry key based on the network instance name */
func getVrfTblKeyByName (name string) (string) {
        var vrf_key string

        if (strings.Compare(name, "mgmt") == 0) { 
            vrf_key = "vrf_global"
        } else {
            vrf_key = name
        }

        return vrf_key
}

/* Check if this is "MGMT_VRF_CONFIG" */
func isMgmtVrfDbTbl (inParams XfmrParams) (bool) {
        data := (*inParams.dbDataMap)[inParams.curDb]

        mgmtTbl := data["MGMT_VRF_CONFIG"]
        if (mgmtTbl != nil) {
                return true
        } else {
                return false
        }
}

/* Check if this is "VRF" table */
func isVrfDbTbl (inParams XfmrParams) (bool)  {
        data := (*inParams.dbDataMap)[inParams.curDb]
        log.Info("isVrfDbTbl: ", data, "inParams :", inParams)

        vrfTbl := data["VRF"]
        if (vrfTbl != nil) {
                return true
        } else {
                return false
        }
}

/* Check if "mgmtVrfEnabled" is set to true in the "MGMT_VRF_CONFIG" table */
func mgmtVrfEnabledInDb (inParams XfmrParams) (string) {
        data := (*inParams.dbDataMap)[inParams.curDb]
        log.V(3).Info("mgmtVrfEnabledInDb ")

        mgmtTbl := data["MGMT_VRF_CONFIG"]
        mgmtVrf := mgmtTbl[inParams.key]
        enabled_status := mgmtVrf.Field["mgmtVrfEnabled"]
        return enabled_status;
}

/* Get the top level network instance type. Note this is used for the create, update only */
func getNwInstType (nwInstObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances, keyName string) (string, error) {
        var err error

        /* If config not set or config.type not set, return L3VRF */
        if (nwInstObj != nil) {
            if ntinstKeyVal, ok := nwInstObj.NetworkInstance[keyName]; ok && ntinstKeyVal != nil {
                if ((ntinstKeyVal.Config == nil) ||
                    (ntinstKeyVal.Config.Type == ocbinds.OpenconfigNetworkInstanceTypes_NETWORK_INSTANCE_TYPE_UNSET)) {
                        return DEFAULT_NETWORK_INSTANCE_CONFIG_TYPE, errors.New("Network instance type not set")
                } else {
                    instType, ok :=nwInstTypeMap[ntinstKeyVal.Config.Type]
                    if ok {
                        return instType, err
                    } else {
                        return instType, errors.New("Unknown network instance type")
                    }
                }
            }
        }
        return DEFAULT_NETWORK_INSTANCE_CONFIG_TYPE, errors.New("Network instance type not set")
}

func validateMgmtVrfExists(d *db.DB) error {
        var err error
        if log.V(3) {
            log.Infof("IsMgmtVrfExists")
        }

        mvrfKeys, _ := d.GetKeys(&db.TableSpec{Name: "MGMT_VRF_CONFIG"})

        if len(mvrfKeys) <= 0 {
            errStr := "Management VRF does not exist"
            log.Info("validateMgmtVrfExists: ", errStr);
            err = tlerr.InvalidArgsError{Format: errStr}
        }

        return err
}

func isIntfBindToOtherVrf(intf_tbl_name string, intf_name string, nwInst_name string, inParams XfmrParams) (bool, string) {
        intfTable := &db.TableSpec{Name: intf_tbl_name}
        intfEntry, err := inParams.d.GetEntry(intfTable, db.Key{Comp: []string{intf_name}})
        if (err != nil) {
               return false, "" 
        }

        vrfName_str :=  (&intfEntry).Get("vrf_name")

        if (vrfName_str == ""){
                return false, "" 
        } else if (vrfName_str != nwInst_name) {
                return true, vrfName_str
        } else {
                /* If the interface is binding with the same VRF, let it pass */
                return false, "" 
        }
}

func ValidateIntfNotL3ConfigedOtherThanVrf(d *db.DB, tblName string, intfName string, otherValueExist *bool) error {
        ifUIName := utils.GetUINameFromNativeName(&intfName)
        var err error
        if log.V(3) {
            log.Infof("ValidateIntfNotL3ConfigedOtherThanVrf: table %v, intf %v", tblName, *ifUIName)
        }

        ipKeys, err := doGetIntfIpKeys(d, tblName, intfName)
        if (err == nil && len(ipKeys) > 0) {
            errStr :=  "IP address configuration exists for " + *ifUIName
            log.Info("ValidateIntfNotL3ConfigedOtherThanVrf: ", errStr);
            err = tlerr.InvalidArgsError{Format: errStr}
        }
        if err != nil {
            return err
        }

        IntfMap, _ := d.GetMapAll(&db.TableSpec{Name:tblName+"|"+intfName})
        for key := range IntfMap.Field {

            /* update the otherValueExist value if non vrf_name field is seen */
            if  (key != "vrf_name") {
                *otherValueExist = true
            }

            if (key == "NULL" || key == "vrf_name") {
                continue
            } else {
                errStr := "Layer 3 configuration exists for " + *ifUIName
                log.Info("ValidateIntfNotL3ConfigedOtherThanVrf: ", errStr);
                err = tlerr.InvalidArgsError{Format: errStr}
                break
            }
        }
        return err
}


func checkOspfv2CfgExistOnIntf(inParams *XfmrParams, intfName string) (bool) {

    if (intfName == "") {
        log.Info("checkOspfv2CfgExistOnIntf: empty intfName parameter")
        return false
    }

    return ospf_interface_config_present(inParams, intfName)
}

func xfmr_set_default_vrf_configDb() error {
        log.Info ("xfmr_set_default_vrf_configDb")

        d, err := db.NewDB(getDBOptions(db.ConfigDB))

        if err != nil {
                log.Infof("xfmr_set_default_vrf_configDb, unable to get configDB, error %v", err)
                return err
        }

        defer d.DeleteDB()

        var VRF_TABLE= "VRF"

        vrfTable := &db.TableSpec{Name: VRF_TABLE}

        key :=db.Key{Comp: []string{"default"}}

        dbEntry, err := d.GetEntry(vrfTable, key)
        if err != nil {
                log.Infof("xfmr_set_default_vrf_configDb, get default entry error %v", err)
        }

        /* If entry found no need to create again */
        if (dbEntry.IsPopulated()) {
                log.Info("xfmr_set_default_vrf_configDb, entry exists")
                return err
        }

        vrfInfo := db.Value {Field: map[string]string{}}
        (&vrfInfo).Set("enabled", "true")

        err = d.CreateEntry(vrfTable, key, vrfInfo)

        if err != nil {
                log.Infof("xfmr_set_default_vrf_configDb, set default entry error %v", err)
                return err
        }

        return err
}

// isMgmtVrfEnabled  checks if mgmt vrf is configured and enabled
func isMgmtVrfEnabled(inParams XfmrParams) (bool) {

        mgmtVrf, err := inParams.d.GetMapAll(&db.TableSpec{Name:"MGMT_VRF_CONFIG"+"|"+"vrf_global"})
        if (err == nil) {
                enabled_status := mgmtVrf.Field["mgmtVrfEnabled"]
                if (enabled_status == "true") {
                        return true
                }
        }

        return false 
}

func init() {
        xfmr_set_default_vrf_configDb()
        XlateFuncBind("network_instance_table_name_xfmr", network_instance_table_name_xfmr)
        XlateFuncBind("YangToDb_network_instance_table_key_xfmr", YangToDb_network_instance_table_key_xfmr)
        XlateFuncBind("DbToYang_network_instance_table_key_xfmr", DbToYang_network_instance_table_key_xfmr)
        XlateFuncBind("YangToDb_network_instance_enabled_field_xfmr", YangToDb_network_instance_enabled_field_xfmr)
        XlateFuncBind("DbToYang_network_instance_enabled_field_xfmr", DbToYang_network_instance_enabled_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_name_key_xfmr", YangToDb_network_instance_name_key_xfmr)
        XlateFuncBind("DbToYang_network_instance_name_key_xfmr", DbToYang_network_instance_name_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_name_field_xfmr", YangToDb_network_instance_name_field_xfmr)
        XlateFuncBind("DbToYang_network_instance_name_field_xfmr", DbToYang_network_instance_name_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_type_field_xfmr", YangToDb_network_instance_type_field_xfmr)
        XlateFuncBind("DbToYang_network_instance_type_field_xfmr", DbToYang_network_instance_type_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_mtu_field_xfmr", YangToDb_network_instance_mtu_field_xfmr)
        XlateFuncBind("DbToYang_network_instance_mtu_field_xfmr", DbToYang_network_instance_mtu_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_router_id_field_xfmr", YangToDb_network_instance_router_id_field_xfmr)
        XlateFuncBind("DbToYang_network_instance_router_id_field_xfmr", DbToYang_network_instance_router_id_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_route_distinguisher_field_xfmr", YangToDb_network_instance_route_distinguisher_field_xfmr)
        XlateFuncBind("DbToYang_network_instance_route_distinguisher_field_xfmr", DbToYang_network_instance_route_distinguisher_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_enabled_addr_family_field_xfmr", YangToDb_network_instance_enabled_addr_family_field_xfmr)
        XlateFuncBind("DbToYang_network_instance_enabled_addr_family_field_xfmr", DbToYang_network_instance_enabled_addr_family_field_xfmr)
        XlateFuncBind("YangToDb_network_instance_interface_binding_subtree_xfmr", YangToDb_network_instance_interface_binding_subtree_xfmr)
        XlateFuncBind("DbToYang_network_instance_interface_binding_subtree_xfmr", DbToYang_network_instance_interface_binding_subtree_xfmr)
        XlateFuncBind("Subscribe_network_instance_interface_binding_subtree_xfmr", Subscribe_network_instance_interface_binding_subtree_xfmr)
}

func getNwInstRoot(s *ygot.GoStruct) *ocbinds.OpenconfigNetworkInstance_NetworkInstances  {
        deviceObj := (*s).(*ocbinds.Device)
        return deviceObj.NetworkInstances
}

// network_instance_table_name_xfmr is a table name in config DB correspoinding to the top level network instance name
var network_instance_table_name_xfmr TableXfmrFunc = func (inParams XfmrParams)  ([]string, error) {
        var tblList []string
        var err error

        log.V(3).Info("network_instance_table_name_xfmr")

        nwInstObj := getNwInstRoot(inParams.ygRoot)

        pathInfo := NewPathInfo(inParams.uri)
        /* get the name at the top network-instance table level, this is the key */
        keyName := pathInfo.Var("name")

        if keyName == "" {
                /* for GET with no keyName, return table name for mgmt VRF and data VRF */
                if (inParams.oper == GET) {
                        tblList = append(tblList , "MGMT_VRF_CONFIG")
                        tblList = append(tblList, "VRF")
                        tblList = append(tblList, "VLAN")
                        log.Info("network_instance_table_name_xfmr: tblList ", tblList)
                        return tblList, err
                } else {
                        log.Info("network_instance_table_name_xfmr, for key name not present")
                        return tblList, errors.New("Empty network instance name")
                }
        }

        /* get internal network instance name in order to fetch the DB table name */
        intNwInstName, ierr := getInternalNwInstName(keyName)
        if intNwInstName == "" || ierr != nil {
            log.Info("network_instance_table_name_xfmr, invalid network instance name ", keyName)
            errStr := "Invalid name " + keyName
            err = tlerr.InvalidArgsError{Format: errStr}
            return tblList, err
        }

        /*
         * For CREATE or PATCH at top level (Network_instances), check the config type if user provides one 
         * For other cases of UPATE, CREATE, or GET/DELETE, get the table name from the key only
         */ 
        oc_nwInstType, ierr := getNwInstType(nwInstObj, keyName)
        if (((inParams.oper == CREATE) ||
             (inParams.oper == REPLACE) ||
             (inParams.oper == UPDATE)) &&
             (ierr == nil)) {

                log.Info("network_instance_table_name_xfmr, name ", keyName)
                log.Info("network_instance_table_name_xfmr, type ", oc_nwInstType)

                tblName, ok  := NwInstTblNameMapWithNameAndType[NwInstMapKey{intNwInstName, oc_nwInstType}]
                if !ok {
                        log.Info("network_instance_table_name_xfmr, type not matching name")
                        return tblList, errors.New("network instance type not matching name")
                }

                tblList = append(tblList, tblName)
        } else if ierr.Error() == "Network instance type not set" {
                tblList = append(tblList, NwInstTblNameMapWithName[intNwInstName])
        }

        log.V(3).Info("network_instance_table_name_xfmr, OP ", inParams.oper, " DB table name ", tblList)

        return tblList, err
}

// YangToDb_network_instance_enabled_field_xfmr is a YangToDB Field transformer for top level network instance config "enabled" 
var YangToDb_network_instance_enabled_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_enabled_field_xfmr")

        nwInstObj := getNwInstRoot(inParams.ygRoot)
        if nwInstObj.NetworkInstance == nil {
                return res_map, errors.New("Network instance not set")
        }

        pathInfo := NewPathInfo(inParams.uri)

        if strings.HasPrefix(pathInfo.Var("name"), "Vlan") {
                return res_map, err
        }

        if len(pathInfo.Vars) < 1 {
                /* network instance table has 1 key "name" */
                return res_map, errors.New("Invalid xpath, key attributes not found")
        }

        targetUriPath, err := getYangPathFromUri(pathInfo.Path)

        log.Info("YangToDb_network_instance_enabled_field_xfmr targetUri: ", targetUriPath)

        /* get the name at the top network-instance table level, this is the key */
        keyName := pathInfo.Var("name")
        if keyName != "mgmt" {
                log.Info("YangToDb_network_instance_enabled_field_xfmr, not mgmt vrf ", keyName)

                /* ToDo, put this until sonic yang default value is implemented */
                res_map["fallback"] = "false"
                return res_map, err 
        }

        enabled, _ := inParams.param.(*bool)

        var enStr string
        if *enabled {
                enStr = "true"
        } else {
                enStr = "false"
        }

        res_map[MGMT_VRF_ENABLE] = enStr
        log.Info("YangToDb_network_instance_enabled_field_xfmr: ", res_map)

        return res_map, err
}

// DbToYang_network_instance_enabled_field_xfmr is a  DbToYang Field transformer for top level network instance config "enabled"
var DbToYang_network_instance_enabled_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_enabled_field_xfmr: ")

        if (mgmtVrfEnabledInDb(inParams) == "true") {
                res_map["enabled"] = true
        } else if (mgmtVrfEnabledInDb(inParams) == "false") {
                res_map["enabled"] = false
        }
        return res_map, err
}

func ValidateInbandMgmtConfigOnMgmtVRF(d *db.DB) error {
    var err error

    mgmtVrfTblSpec := &db.TableSpec{Name:"MGMT_VRF_CONFIG"}
    key :=db.Key{Comp: []string{"vrf_global"}}
    dbEntry, err := d.GetEntry(mgmtVrfTblSpec, key)
    if err != nil {
        return err
    }
    log.Infof("ValidateInbandMgmtConfigOnMgmtVRF")
    mgmt_vrf_enabled := (&dbEntry).Get("mgmtVrfEnabled")
    if mgmt_vrf_enabled == "" {
        return err
    }
    in_band_mgmt := (&dbEntry).Get("in_band_mgmt_enabled")
    if in_band_mgmt == "" {
        return err
    }
    if ((mgmt_vrf_enabled == "true") && (in_band_mgmt == "true")) {
        errStr := "Management VRF is associated with data interface(s), unbind them before VRF deletion!"
        log.Info(":ValidateInbandMgmtConfigOnMgmtVRF ", errStr);
        err = tlerr.InvalidArgsError{Format: errStr}
    }
    return err
}


// YangToDb_network_instance_table_key_xfmr is a YangToDB key transformer for top level network instance
var YangToDb_network_instance_table_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
        var vrfTbl_key  string
        var err error

        pathInfo := NewPathInfo(inParams.uri)
        keyName := pathInfo.Var("name")

        /* Get key for the respective table based on the network instance key "name" */
        vrfTbl_key = getVrfTblKeyByName(pathInfo.Var("name"))

        log.V(3).Info("YangToDb_network_instance_table_key_xfmr: ", vrfTbl_key)

        /* Validate:
         * - if management VRF is used by TACACS+ server or in-band data interfaces, deletion is not allowed
           -
         */
        if (keyName == "mgmt" && inParams.oper == DELETE) {
            err = ValidateTacplusServerNotUseMgmtVRF(inParams.d)
            if err != nil {
                return vrfTbl_key, err
            }
            requestUriPath, _ := getYangPathFromUri(inParams.requestUri)
            log.V(3).Info("YangToDb_network_instance_table_key_xfmr request URI: ", requestUriPath)
            if ((requestUriPath == "/openconfig-network-instance:network-instances/network-instance") ||
                (requestUriPath == "/openconfig-network-instance:network-instances")) {
                // Validate only for mgmt VRF delete
                err = ValidateInbandMgmtConfigOnMgmtVRF(inParams.d)
                if err != nil {
                    return vrfTbl_key, err
                }
            }
        }

        /*
         * For SSH to work with a VRF, the VRF name needs to be installed in the
         * SSH_SERVER_VRF config DB. 
         * click has a cmd to configure <vrf_name> in this table. For now, add an entry
         * for mgmt VRF in this table when mgmt VRF is configured. Data VRF won't be added
         * to this table. This is because in the click cmd, MAX_SSH_VRF is 15.
         * A clish CLI is required to configure data VRF in the SSH_SERVER_VRF
         */
        if ((inParams.oper == CREATE) ||
             (inParams.oper == REPLACE) ||
             (inParams.oper == UPDATE) ||
             (inParams.oper == DELETE)) {

                if keyName == "mgmt" {
                        resMap := make(map[string]map[string]db.Value)
                        sshVrfMap := make(map[string]db.Value)

                        sshVrfDbValues  := db.Value{Field: map[string]string{}}
                        (&sshVrfDbValues).Set("port", "22")
                        sshVrfMap["mgmt"] = sshVrfDbValues

                        log.Infof("ssh server vrf %v", sshVrfMap)
                        resMap["SSH_SERVER_VRF"] = sshVrfMap

                        if inParams.subOpDataMap[inParams.oper] != nil && (*inParams.subOpDataMap[inParams.oper])[db.ConfigDB] != nil {
                            mapCopy((*inParams.subOpDataMap[inParams.oper])[db.ConfigDB], resMap)
                        } else {
                            subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
                            subOpMap[db.ConfigDB] = resMap
                            inParams.subOpDataMap[inParams.oper] = &subOpMap
                        }
                }
        }

        return vrfTbl_key, err
}

// DbToYang_network_instance_table_key_xfmr is a DbToYang key transformer for top level network instance
var DbToYang_network_instance_table_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_table_key_xfmr: ", inParams.key)

         if (inParams.key != "") {
                if ((inParams.key == "default") || (strings.HasPrefix(inParams.key, "Vrf")) || (strings.HasPrefix(inParams.key, "Vlan"))) {
                        res_map["name"] = inParams.key
                } else if (strings.HasPrefix(inParams.key, "vrf_global")) {
                        res_map["name"] = "mgmt"
                }
        } else {
                log.Info("DbToYang_network_instance_table_key_xfmr, empty key")
        }

        return  res_map, err
}

// YangToDb_network_instance_name_key_xfmr is a YangToDb Field transformer for name(key) in the top level network instance
var YangToDb_network_instance_name_key_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_name_key_xfmr")

        return res_map, err
}

// YangToDb_network_instance_name_field_xfmr is a YangToDb Field transformer for name in the top level network instance confi
var YangToDb_network_instance_name_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_name_field_xfmr")

        if inParams.key != "" && strings.HasPrefix(inParams.key, "Vlan") {
            vlanIdStr := strings.TrimPrefix(inParams.key, "Vlan")
            res_map["vlanid"] = vlanIdStr
        } else {
            /* the key name is not repeated as attr name in the DB */
            if inParams.key != "default" {
                res_map["NULL"] = "NULL"
            }
        }

        return res_map, err
}

// DbToYang_network_instance_name_field_xfmr is a DbToYang Field transformer for name in the top level network instance config
var DbToYang_network_instance_name_field_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_name_field_xfmr")

        if (inParams.key != "") {
                if (((inParams.key == "default") ||
                     (strings.HasPrefix(inParams.key, "Vrf"))) && 
                     (isVrfDbTbl(inParams))) {
                        res_map["name"] = inParams.key 
                } else if ((strings.HasPrefix(inParams.key, "vrf_global")) &&
                           (isMgmtVrfDbTbl(inParams))) {
                        res_map["name"] = "mgmt"
                } else if (strings.HasPrefix(inParams.key, "Vlan")) {
                        res_map["name"] =  inParams.key
                }
        } else {
                log.Info("DbToYang_network_instance_name_field_xfmr, empty key")
        }

        return  res_map, err
}

// YangToDb_network_instance_type_field_xfmr is a YangToDb Field transformer for type in the top level network instance config
var YangToDb_network_instance_type_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_type_field_xfmr")

        return res_map, err
}

// DbToYang_network_instance_type_field_xfmr is a DbToYang Field transformer for type in the top level network instance config
var DbToYang_network_instance_type_field_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_type_field_xfmr")

        if (((inParams.key == "vrf_global") && (isMgmtVrfDbTbl(inParams))) ||
             ((strings.HasPrefix(inParams.key, "Vrf")) && ((isVrfDbTbl(inParams))))) {
                res_map["type"] = "L3VRF"
        } else if ((inParams.key == "default") && (isVrfDbTbl(inParams))) {
                res_map["type"] = "DEFAULT_INSTANCE"
        } else if strings.HasPrefix(inParams.key, "Vlan") {
                res_map["type"] = "L2L3"
        }


        return  res_map, err
}

// YangToDb_network_instance_enabled_addr_family_field_xfmr is a YangToDb Field transformer for enabled_address_family in the top level network instance config
var YangToDb_network_instance_enabled_addr_family_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_enabled_addr_fam_field_xfmr")

        return res_map, err
}

// DbToYang_network_instance_enabled_addr_family_field_xfmr is a DbToYang Field transformer for enabled_address_family in the top level network instance config
var DbToYang_network_instance_enabled_addr_family_field_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_enabled_addr_fam_field_xfmr")

        return res_map, err
}

// YangToDb_network_instance_mtu_field_xfmr is a YangToDb Field transformer for mtu in the top level network instance config
var YangToDb_network_instance_mtu_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_mtu_field_xfmr")

        return res_map, err
}

// DbToYang_network_instance_mtu_field_xfmr is a DbToYang Field transformer for mtu in the top level network instance config
var DbToYang_network_instance_mtu_field_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_mtu_field_xfmr")

        return res_map, err
}

// YangToDb_network_instance_router_id_field_xfmr is a YangToDb Field transformer for router_id in the top level network instance config
var YangToDb_network_instance_router_id_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_router_id_field_xfmr")

        return res_map, err
}

// DbToYang_network_instance_router_id_field_xfmr is a DbToYang Field transformer for router_id in the top level network instance config
var DbToYang_network_instance_router_id_field_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_router_id_field_xfmr")

        return res_map, err
}

// YangToDb_network_instance_route_distinguisher_field_xfmr is a YangToDb Field transformer for route_distinguisher in the top level network instance config
var YangToDb_network_instance_route_distinguisher_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
        res_map := make(map[string]string)
        var err error

        log.Info("YangToDb_network_instance_route_distinguisher_field_xfmr")

        return res_map, err
}

// DbToYang_network_instance_route_distinguisher_field_xfmr is a DbToYang Field transformer for route_distinguisher in the top level network instance config
var DbToYang_network_instance_route_distinguisher_field_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        res_map := make(map[string]interface{})
        var err error

        log.Info("DbToYang_network_instance_route_distinguisher_field_xfmr")

        return res_map, err
}

func inBandMgmtFieldUpdate(inParams XfmrParams, is_set bool) error {
    var err error
    mgmtVrfTblSpec := &db.TableSpec{Name:"MGMT_VRF_CONFIG"}
    key :=db.Key{Comp: []string{"vrf_global"}}
    dbEntry, err := inParams.d.GetEntry(mgmtVrfTblSpec, key)
    mgmt_vrf_enabled := (&dbEntry).Get("mgmtVrfEnabled")
    log.Infof("Mgmt VRF %s", mgmt_vrf_enabled)
    if mgmt_vrf_enabled == "true" {
        in_band_mgmt := (&dbEntry).Get("in_band_mgmt_enabled")
        log.Infof("Mgmt VRF in-band %s", in_band_mgmt)
        var update_req bool = false
        if is_set {
            if ((in_band_mgmt == "") || (in_band_mgmt == "false")) {
                update_req = true
            }
        } else if (in_band_mgmt == "true") {
            update_req = true
        }
        if update_req {
            resMap := make(map[string]map[string]db.Value)
            mgmtVrfMap := make(map[string]db.Value)

            mgmtVrfDbValues  := db.Value{Field: map[string]string{}}
            (&mgmtVrfDbValues).Set("in_band_mgmt_enabled", "true")
            mgmtVrfMap["vrf_global"] = mgmtVrfDbValues

            log.Infof("Mgmt VRF %v op:%d", mgmtVrfMap, is_set)
            resMap["MGMT_VRF_CONFIG"] = mgmtVrfMap

            oper := DELETE
            if is_set {
                oper = UPDATE
            }
            if inParams.subOpDataMap[oper] != nil && (*inParams.subOpDataMap[oper])[db.ConfigDB] != nil {
                mapCopy((*inParams.subOpDataMap[oper])[db.ConfigDB], resMap)
            } else {
                subOpMap := make(map[db.DBNum]map[string]map[string]db.Value)
                subOpMap[db.ConfigDB] = resMap
                inParams.subOpDataMap[oper] = &subOpMap
            }
        }
    }
    return err
}

// YangToDb_network_instance_interface_binding_subtree_xfmr is a YangToDb subtree transformer for network instance interface binding
var YangToDb_network_instance_interface_binding_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
        var err error
        var errStr string
        res_map := make(map[string]map[string]db.Value)
        var fieldOtherThanVrf bool

        pathInfo := NewPathInfo(inParams.uri)

        targetUriPath, err := getYangPathFromUri(pathInfo.Path)

        log.V(3).Infof("YangToDb_network_instance_interface_binding_subtree_xfmr: targetUri %v ygRoot %v uri %v",
                       targetUriPath, inParams.ygRoot, inParams.uri)

        /* get the name at the top network-instance table level, this is the key */
        keyName := pathInfo.Var("name")
        intfId := pathInfo.Var("id")

        if (keyName == "") {
                log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: no intf binding for VRF ", keyName)
                return res_map, err
        }

        if intfId == "" {
                log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: empty interface id for VRF ", keyName)

                /* Process empty intfId only for delete operation */
                if (inParams.oper != DELETE) {
                        log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: empty intfid for non-del op")
                        return res_map, err
                }

                /* Check if any intf bound to this vrf has L3 configuration, if so, delete at network instance level should be rejected */
                for _, tblName := range intf_tbl_name_list {
                        intfTable := &db.TableSpec{Name: tblName}

                        intfKeys, err := inParams.d.GetKeys(intfTable)

                        if err != nil {
                                errStr = "Unable to get interface keys from " + tblName
                                log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                                err = tlerr.InvalidArgsError{Format: errStr}
                                return res_map, err
                        }

                        for i := range intfKeys {
                                /* vrf_name is only in the entry with intf name alone as the key */
                                if (len(intfKeys[i].Comp)) >1 {
                                        continue
                                }

                                intfEntry,_ := inParams.d.GetEntry(intfTable, intfKeys[i])

                                vrfName_str := (&intfEntry).Get("vrf_name")

                                if (vrfName_str != keyName) {
                                        continue
                                }

                                intfName := intfKeys[i].Comp
                                convUIName := utils.GetUINameFromNativeName(&intfName[0])


                                if chekIfSagExistOnIntf(inParams.d, intfName[0]) {
                                        errStr = "Interface " + *convUIName + " has IP static anycast gateway configuration"
                                        log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}  
                                        return res_map, err                                    
                                }

                                fieldOtherThanVrf = false
                                err = ValidateIntfNotL3ConfigedOtherThanVrf(inParams.d, tblName, intfName[0], &fieldOtherThanVrf)
                                if err != nil {
                                        errStr = "Interface " + *convUIName + " has L3 configuration"
                                        log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                                        err = tlerr.InvalidArgsError{Format: errStr}
                                        return res_map, err
                                }

                                if checkPimCfgExistOnIntf(inParams.d, intfName[0]) {
                                    errStr = "Interface " + *convUIName + " has PIM configurations"
                                    log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                                    err = tlerr.InvalidArgsError{Format: errStr}
                                    return res_map, err
                                }

                                if checkOspfv2CfgExistOnIntf(&inParams, intfName[0]) {
                                    errStr = "Interface " + *convUIName + " has OSPFv2 configurations"
                                    log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                                    err = tlerr.InvalidArgsError{Format: errStr}
                                    return res_map, err
                                }

                                /* Now add this interface to res_map */
                                _, ok := res_map[tblName]
                                if !ok {
                                        res_map[tblName] = make(map[string]db.Value)
                                }

                                res_map[tblName][intfName[0]] = db.Value{Field: map[string]string{}}
                                dbVal := res_map[tblName][intfName[0]]

                                /* for DELETE operation, if vrf_name is the last field, delete the entry */
                                if (fieldOtherThanVrf) {
                                        (&dbVal).Set("vrf_name", keyName)
                                }
                        }
                }

                if keyName == "mgmt" {
                    inBandMgmtFieldUpdate(inParams, false)
                }
                log.Infof("YangToDb_network_instance_interface_binding_subtree_xfmr: delete VRF %v res_map %v", keyName, res_map)
                return res_map, err
        }

        /* Check if interfaces exists, if not, return */
        vrfObj := getNwInstRoot(inParams.ygRoot)

        if vrfObj.NetworkInstance[keyName].Interfaces == nil {
                return res_map, err
        }

        intf_type, _, err := getIntfTypeByName(intfId)
        if err != nil {
                log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: unknown intf type for ", intfId)
        }

        intTbl := IntfTypeTblMap[intf_type]

        ifName := utils.GetNativeNameFromUIName(&intfId)
        log.Info("UI Name - "+intfId+" Native Name -  "+*ifName)

        /* For non-delete op,  make sure the interface is already created */
        if (inParams.oper != DELETE){

                port_tbl_name, _ := getPortTableNameByDBId(intTbl, inParams.curDb)

                _, err := inParams.d.GetMapAll(&db.TableSpec{Name:port_tbl_name+"|"+*ifName})
                if err != nil {
                        errStr = "Interface " + intfId + " is not configured"
                        log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr,
                                 "tbl ", port_tbl_name)
                        err = tlerr.InvalidArgsError{Format: errStr}
                        return res_map, err
                }
        }

        intf_tbl_name, _ :=  getIntfTableNameByDBId(intTbl, inParams.curDb)

        /* Check if interface already has VRF association */
        intfVrfBind, vrf_name := isIntfBindToOtherVrf(intf_tbl_name, *ifName, keyName, inParams)
        if (intfVrfBind) {
                var errStr string
                if (inParams.oper == DELETE) {
                        errStr = "Interface is associated with VRF " + vrf_name
                } else {
                        errStr = "Interface is already associated with VRF " + vrf_name
                }
                log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr);
                err = tlerr.InvalidArgsError{Format: errStr}
                return res_map, err
        }

         /* Do not set vrf_name for the interface for default network instance */
        if keyName == "default" {
                log.Infof("YangToDb_network_instance_interface_binding_subtree_xfmr vrf intf binding for default intf %v", intfId)
                return res_map, err
        }
        if ((inParams.oper == CREATE) ||
            (inParams.oper == REPLACE) ||
            (inParams.oper == UPDATE)) {
            /* Validate whether the Interface is configured as member-port with any portchannel */
            if intf_type == IntfTypeEthernet {
                err = validateIntfAssociatedWithPortChannel(inParams.d, ifName)
                if err != nil {
                    return res_map, err
                }
            }

            /* Validate whether the Interface is configured as member-port with any vlan */
            if intf_type == IntfTypeEthernet || intf_type == IntfTypePortChannel {
                err = validateIntfAssociatedWithVlan(inParams.d, ifName)
                if err != nil {
                    return res_map, err
                }
            }

            /* Check if L3 configs present on given interface */
            if intf_type == IntfTypeLoopback {
                ipKeys, err1 := doGetIntfIpKeys(inParams.d, LOOPBACK_INTERFACE_TN, *ifName)
                if (err1 == nil && len(ipKeys) > 0) {
                    errStr := "Interface: " + intfId + " configured with IP address"
                    log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr);
                    err = tlerr.InvalidArgsError{Format: errStr}
                }

                isDonor := validateUnnumIntfExistsForDonorIntf(inParams.d, ifName)
                if (isDonor) {
                    errStr := "Interface: " + intfId + " configured as Donor interface"
                    log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr);
                    err = tlerr.InvalidArgsError{Format: errStr}
				}
            } else {
                err = validateL3ConfigExists(inParams.d, ifName)
            }

            if err == nil {
                // verify if interface has ospfv2 configs
                if checkOspfv2CfgExistOnIntf(&inParams, *ifName) {
                    errStr = "Interface " + intfId + " has OSPFv2 configurations"
                    log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                    err = tlerr.InvalidArgsError{Format: errStr}
                }
            }

            if err != nil {
                return res_map, err
            }
            if keyName == "mgmt" {
                inBandMgmtFieldUpdate(inParams, true)
            }
        } else {
            // VRF Unbind case. Check if all IP has been deleted before VRF unbind
		    ipKeys, _ := inParams.d.GetKeysPattern(&db.TableSpec{Name: intf_tbl_name}, db.Key{Comp: []string{ *ifName, "*" }})
		    if len(ipKeys) != 0 {
			    errStr := "L3 Configuration exists for Interface: " + intfId
			    log.Error(errStr)
			    err = tlerr.InvalidArgsError{Format: errStr}
			    return res_map, err
		    }

                // verify if interface has ospfv2 configs
                if checkOspfv2CfgExistOnIntf(&inParams, *ifName) {
                    errStr = "Interface " + intfId + " has OSPFv2 configurations"
                    log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                    err = tlerr.InvalidArgsError{Format: errStr}
                    return res_map, err
                }
	}

        if chekIfSagExistOnIntf(inParams.d, *ifName) {
                errStr = "Interface " + intfId + " has IP static anycast gateway configuration"
                log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
                err = tlerr.InvalidArgsError{Format: errStr}
                return res_map, err
        }

        /* Check if L3 configs present on given interface */
        fieldOtherThanVrf = false
        err = ValidateIntfNotL3ConfigedOtherThanVrf(inParams.d, intf_tbl_name, *ifName, &fieldOtherThanVrf)
        if err != nil {
            return res_map, err
        }

        if checkPimCfgExistOnIntf(inParams.d, *ifName) {
            errStr = "Interface " + intfId + " has PIM configurations"
            log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
            err = tlerr.InvalidArgsError{Format: errStr}
            return res_map, err
        }

        // verify if interface has ospfv2 configs
        if checkOspfv2CfgExistOnIntf(&inParams, *ifName) {
            errStr = "Interface " + intfId + " has OSPFv2 configurations"
            log.Info("YangToDb_network_instance_interface_binding_subtree_xfmr: ", errStr)
            err = tlerr.InvalidArgsError{Format: errStr}
            return res_map, err
        }

        res_map[intf_tbl_name] = make(map[string]db.Value)

        res_map[intf_tbl_name][intfId] = db.Value{Field: map[string]string{}}
        dbVal := res_map[intf_tbl_name][intfId]

        /* for DELETE operation, if vrf_name is the last field, delete the entry */
        if ((inParams.oper != DELETE) ||
            ((inParams.oper == DELETE) && fieldOtherThanVrf)) {
                (&dbVal).Set("vrf_name", keyName)
        }

        if ((keyName == "mgmt") && (inParams.oper == DELETE)) {
            // If no L3 interface is associated with mgmt VRF, 
            // delete the in_band_mgmt_enabled field in MGMT_VRF_CONFIG table.
            var last_in_band_intf_in_mgmt_vrf = true
            for _, tblName := range intf_tbl_name_list {
                intfTable := &db.TableSpec{Name: tblName}
                intfKeys, err := inParams.d.GetKeys(intfTable)
                if err != nil {
                    continue
                }
                for i := range intfKeys {
                    /* vrf_name is only in the entry with intf name alone as the key */
                    if (len(intfKeys[i].Comp)) > 1 {
                        continue
                    }
                    tempIntfName  := intfKeys[i].Comp
                    if tempIntfName[0] == *ifName {
                        continue
                    }
                    intfEntry,_ := inParams.d.GetEntry(intfTable, intfKeys[i])
                    vrfName_str := (&intfEntry).Get("vrf_name")
                    if (vrfName_str == keyName) {
                        last_in_band_intf_in_mgmt_vrf = false
                    }
                }
            }
            if last_in_band_intf_in_mgmt_vrf {
                inBandMgmtFieldUpdate(inParams, false)
            }
        }
        log.Infof("YangToDb_network_instance_interface_binding_subtree_xfmr: set vrf_name %v for %v in %v",
                  keyName, intfId, intf_tbl_name)

        log.Infof("YangToDb_network_instance_interface_binding_subtree_xfmr: %v", res_map)

        return res_map, err
}

//DbToYang_network_instance_interface_binding_subtree_xfmr is a DbtoYang subtree transformer for network instance interface binding
var DbToYang_network_instance_interface_binding_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {

        var err error

        nwInstTree := getNwInstRoot(inParams.ygRoot)

        log.V(3).Infof("DbToYang_network_instance_interface_binding_subtree_xfmr: ygRoot %v ", nwInstTree)

        pathInfo := NewPathInfo(inParams.uri)

        /* Get network instance name and interface Id */
        pathNwInstName := pathInfo.Var("name")
        pathIntfId := pathInfo.Var("id")

        ifUIName := utils.GetUINameFromNativeName(&pathIntfId)

        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

        log.V(3).Infof("DbToYang_network_instance_interface_binding_subtree_xfmr, key(:%v) id(:%v) targeturiPath %v", 
                       pathNwInstName, *ifUIName, targetUriPath)

        /* If nwInst name and intf Id are given, get the db entry directly, else go through all interface tables */
        if ((pathNwInstName != "") && (pathIntfId != "")) {
                intf_type, _, err := getIntfTypeByName(pathIntfId)
                if err != nil {
                        log.Info("DbToYang_network_instance_interface_binding_subtree_xfmr: unknown intf type for ", pathIntfId)
                        return err
                }

                intTbl := IntfTypeTblMap[intf_type]
                intf_tbl_name, _ :=  getIntfTableNameByDBId(intTbl, inParams.curDb)

                log.V(3).Info("DbToYang_network_instance_interface_binding_subtree_xfmr: intf tbl name: ", intf_tbl_name)

                intfTable := &db.TableSpec{Name: intf_tbl_name}
                intfEntry, err1 := inParams.d.GetEntry(intfTable, db.Key{Comp: []string{pathIntfId}})
                if (err1 != nil) {
                        log.Infof("DbToYang_network_instance_interface_binding_subtree_xfmr, no entry found for key(:%v) id(:%v)", 
                                  pathNwInstName, pathIntfId)
                        return err
                }

                /* If intf entry is found, check if the vrf name matches */
                vrfName_str :=  (&intfEntry).Get("vrf_name")

                /* If the vrf_name is not associated with an intf, check if it is a L3 intf */
                if ((vrfName_str == "") && (pathNwInstName == "default")){
                        err2 := validateL3ConfigExists(inParams.d, &pathIntfId)
                        if (err2 == nil) {
                               log.Infof("DbToYang_network_instance_interface_binding_subtree_xfmr, default instance, %v not L3 intf", 
                                         *ifUIName)
                               return err
                        }

                        /* for default network instance and intf with no vrf_name, set vrfName_str to default */
                        vrfName_str = "default"
                } else if (vrfName_str != pathNwInstName) {
                        log.Info("DbToYang_network_instance_interface_binding_subtree_xfmr, vrf name not matching for  key(:%v) id(:%v)", 
                                 pathNwInstName, *ifUIName)
                        return err
                }

                /* Now build the config and state intf id info, Interfaces.Interface should be present for this case */
                intfData := nwInstTree.NetworkInstance[vrfName_str].Interfaces.Interface[*ifUIName]

                if  (intfData.Config == nil) {
                        ygot.BuildEmptyTree(intfData)
                }

                intfData.Config.Id = intfData.Id

                if  (intfData.State == nil) {
                        ygot.BuildEmptyTree(intfData)
                }

                intfData.State.Id =  intfData.Id

                log.V(3).Infof("DbToYang_network_instance_interface_binding_subtree_xfmr: vrf_name %v intf %v ygRoot %v ", 
                          vrfName_str, *ifUIName, nwInstTree)
        } else {
                for _, tblName := range intf_tbl_name_list {
                        intfTable := &db.TableSpec{Name: tblName}

                        intfKeys, err := inParams.d.GetKeys(intfTable)

                        if err != nil {
                                log.Info("DbToYang_network_instance_interface_binding_subtree_xfmr: error getting keys from ", tblName)
                                return errors.New("Unable to get interface table keys")
                        }

                        for i := range intfKeys {
                                /* Skip the interface entry with both interface name and ip as key, as vrf_name is not there */
                                if (len(intfKeys[i].Comp)) > 1 {
                                        continue
                                }

                                intfEntry, _ := inParams.d.GetEntry(intfTable, intfKeys[i])

                                vrfName_str :=  (&intfEntry).Get("vrf_name")

                                /* if the VRF name is in the GET, then check if the vrf_name from interface matches it */
                                if (((pathNwInstName != "") && (pathNwInstName != "default") && (pathNwInstName != vrfName_str)) ||
                                    ((pathNwInstName == "default") && (vrfName_str != ""))) {
                                        continue
                                }

                                /* for empty vrf_name string, check if the intf is L3 intf */
                                if (vrfName_str == "") {
                                        tempIntfName  := intfKeys[i].Comp
                                        err3 := validateL3ConfigExists(inParams.d, &tempIntfName[0])
                                        if (err3 == nil) {
                                                continue
                                        } else {
                                                /* Set the temp vrfName_str to default */
                                                vrfName_str = "default"
                                        }
                                }

                                log.V(3).Infof("DbToYang_network_instance_interface_binding_subtree_xfmr: nwInst %v vrfname_str %v",
                                          pathNwInstName, vrfName_str)

                                /* add the VRF name to the nwInstTree if not already there */
                                nwInstData, ok := nwInstTree.NetworkInstance[vrfName_str]
                                if !ok {
                                        nwInstData, _ = nwInstTree.NewNetworkInstance(vrfName_str)
                                        ygot.BuildEmptyTree(nwInstData)
                                }

                                if (nwInstTree.NetworkInstance[vrfName_str].Interfaces == nil) {
                                        ygot.BuildEmptyTree(nwInstTree.NetworkInstance[vrfName_str])
                                }

                                intfName := intfKeys[i].Comp
                                ifUIName = utils.GetUINameFromNativeName(&(intfName[0]))

                                var intfData *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Interfaces_Interface

                                /* if Interfaces.Interface is nil, then allocate for the new interface name */
                                if (nwInstTree.NetworkInstance[vrfName_str].Interfaces.Interface == nil) {
                                        intfData, _ = nwInstData.Interfaces.NewInterface(*ifUIName)
                                        ygot.BuildEmptyTree(intfData)
                                }

                                /* if interface name not in Interfaces.Interface list, then allocate it */
                                intfData, ok = nwInstTree.NetworkInstance[vrfName_str].Interfaces.Interface[*ifUIName] 
                                if  !ok {
                                        intfData, _ = nwInstData.Interfaces.NewInterface(*ifUIName)
                                        ygot.BuildEmptyTree(intfData)
                                }

                                intfData.Config.Id = intfData.Id
                                intfData.State.Id = intfData.Id

                                log.V(3).Infof("DbToYang_network_instance_interface_binding_subtree_xfmr: vrf_name %v intf %v ygRoot %v",
                                          vrfName_str, *ifUIName, nwInstTree)
                        }
                }
        }

        return err
}

var Subscribe_network_instance_interface_binding_subtree_xfmr = func(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
        var err error
        var result XfmrSubscOutParams
        result.dbDataMap = make(RedisDbMap)

        pathInfo := NewPathInfo(inParams.uri)

        targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

        /* get the name at the top network-instance table level, this is the key */
        keyName := pathInfo.Var("name")
        intfId := pathInfo.Var("id")

        log.Infof("Subscribe_network_instance_interface_binding_subtree_xfmr: targetUri %v key %v intfId %v", targetUriPath, keyName, intfId)

        if (intfId != "") {
                intf_type, _, err := getIntfTypeByName(intfId)
                if err != nil {
                        log.Info("Subscribe_network_instance_interface_binding_subtree_xfmr: unknown intf type for  ", intfId)
                }

                intTbl := IntfTypeTblMap[intf_type]

                port_tbl_name, _ := getPortTableNameByDBId(intTbl, 4)

                result.dbDataMap = RedisDbMap{db.ConfigDB:{port_tbl_name:{intfId:{}}}}   // tablename & table-idx for the inParams.uri
        } else {
                /* for GET at VRF level, interface name is not given */
                result.dbDataMap = RedisDbMap{db.ConfigDB:{"VRF":{keyName:{}}}}
        }

        result.needCache = true
        result.nOpts = new(notificationOpts)
        result.nOpts.mInterval = 15
        result.nOpts.pType = OnChange
        log.Info("Returning Subscribe_network_instance_interface_binding_subtree_xfmr")
        return result, err
}

