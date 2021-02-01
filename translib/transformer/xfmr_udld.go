package transformer

import (
	log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "strings"
    "strconv"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

func init() {
    XlateFuncBind("DbToYang_udld_global_key_xfmr", DbToYang_udld_global_key_xfmr)
	XlateFuncBind("YangToDb_udld_global_key_xfmr", YangToDb_udld_global_key_xfmr)
	XlateFuncBind("DbToYang_udld_port_table_ifname_xfmr", DbToYang_udld_port_table_ifname_xfmr)
	XlateFuncBind("YangToDb_udld_port_table_ifname_xfmr", YangToDb_udld_port_table_ifname_xfmr)
	XlateFuncBind("DbToYang_udld_port_status_xfmr", DbToYang_udld_port_status_xfmr)
    XlateFuncBind("YangToDb_udld_port_status_xfmr", YangToDb_udld_port_status_xfmr)
	XlateFuncBind("DbToYang_udld_port_nbr_status_xfmr", DbToYang_udld_port_nbr_status_xfmr)
    XlateFuncBind("YangToDb_udld_port_nbr_status_xfmr", YangToDb_udld_port_nbr_status_xfmr)
	XlateFuncBind("YangToDb_udld_nbr_key_xfmr", YangToDb_udld_nbr_key_xfmr)
	XlateFuncBind("DbToYang_udld_nbr_key_xfmr", DbToYang_udld_nbr_key_xfmr)
}

func getUdldIntfStatus(dbCl *db.DB, tblName string, key string) (string) {
    var err error

    log.Info("Checking APP DB for UDLD key, Table >>", key, tblName)

    _, err = dbCl.GetTable(&db.TableSpec{Name:tblName})
    if err != nil {
        return "Error"
    }

    entry , err := dbCl.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{key}})

    if err != nil {
        return "Error"
    }

    return entry.Field["status"]
}


func isUdldEnabled(dbCl *db.DB, tblName string, key string) (bool) {
    var err error

    log.Info("Checking CFG DB for UDLD GLOBAL Table, Table >>", tblName)

    _, err = configDbPtr.GetTable(&db.TableSpec{Name:tblName})
    if err != nil {
        return false
    }

    _, err = configDbPtr.GetEntry(&db.TableSpec{Name:tblName}, db.Key{Comp: []string{key}})
    return err == nil
}

func DbToYang_udld_global_key_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    return res_map, nil
}

var YangToDb_udld_global_key_xfmr = func(inParams XfmrParams) (string, error) {

    if inParams.oper == GET {
        if !isUdldEnabled(inParams.dbs[db.ConfigDB], "UDLD", "GLOBAL"){
               log.Info("UDLD is not Enabled")
            return "", nil
        }
    }
    log.Info("YangToDb_udld_global_key_xfmr: ", inParams.uri)

	return "GLOBAL", nil
}

var YangToDb_udld_port_status_xfmr = func(inParams XfmrParams) (string, error) {
    return "", nil
}

func DbToYang_udld_port_status_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    db_status := getUdldIntfStatus(inParams.dbs[db.ApplDB], "_UDLD_PORT_TABLE", inParams.key) 
    if db_status == "Error" {
        return res_map, tlerr.NotFound("Resource Not Found")
    }
    res_map["status"] = strings.ToUpper(db_status)
    log.Info("res_map :", res_map)
    return res_map, nil
}

var YangToDb_udld_port_nbr_status_xfmr = func(inParams XfmrParams) (string, error) {
    return "", nil
}

func DbToYang_udld_port_nbr_status_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    db_status := getUdldIntfStatus(inParams.dbs[db.ApplDB], "_UDLD_PORT_NEIGH_TABLE", inParams.key) 
    if db_status == "Error" {
        return res_map, tlerr.NotFound("Resource Not Found")
    }
    res_map["status"] = strings.ToUpper(db_status)
    log.Info("res_map :", res_map)
    return res_map, nil
}


func DbToYang_udld_port_table_ifname_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    res_map["name"] = inParams.key
    log.Info("Entering DbToYang_udld_port_table_ifname_xfmr")
    log.Info("key : ", inParams.key)
    log.Info("res_map :", res_map)
    return res_map, nil
}

var YangToDb_udld_port_table_ifname_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)
    return res_map, nil
}


var YangToDb_udld_nbr_key_xfmr = func(inParams XfmrParams) (string, error) {
    var err error
    var udld_nbr_tbl_key string

    log.Info(" YangToDb_udld_nbr_key_xfmr uri ***", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    name    :=  pathInfo.Var("name")
    index      := pathInfo.Var("index")
    if len(name) == 0 || len(index) == 0 {
        udld_nbr_tbl_key = ""
        // SONIC-35015: change the log level from Error to Info, 
        // since transformer ignores this error and proceeds with dumping the table.
        log.Infof(" YangToDb_udld_nbr_key_xfmr Invalid name : %s, index : %s", name, index)
        err = errors.New("YangToDb_udld_nbr_key_xfmr Invalid ifname/index")
    } else {
            udld_nbr_tbl_key = name + ":" + index
    }

    log.Info("YangToDb_udld_nbr_key_xfmr returning : ", udld_nbr_tbl_key)
    return udld_nbr_tbl_key, err
}


func DbToYang_udld_nbr_key_xfmr (inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    arr := strings.Split(inParams.key, ":")
    if len(arr) == 2 {
        indexVal, err := strconv.ParseUint(arr[1], 10, 16)
        if err != nil {
                log.Error("DbToYang_udld_nbr_key_xfmr error in converting index to float64")
                return res_map, err
        }
        //res_map["name"] = arr[0]
        res_map["index"] = indexVal
    }
    log.Info("DbToYang_udld_nbr_key_xfmr >> res_map :", res_map)
    return res_map, nil
}
