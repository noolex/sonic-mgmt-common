package transformer

import (
	log "github.com/golang/glog"
    "strings"
    "strconv"
    "errors"
)

func init() {
	XlateFuncBind("YangToDb_udld_global_key_xfmr", YangToDb_udld_global_key_xfmr)
	XlateFuncBind("DbToYang_udld_port_table_ifname_xfmr", DbToYang_udld_port_table_ifname_xfmr)
	XlateFuncBind("YangToDb_udld_port_table_ifname_xfmr", YangToDb_udld_port_table_ifname_xfmr)
	XlateFuncBind("YangToDb_udld_nbr_key_xfmr", YangToDb_udld_nbr_key_xfmr)
	XlateFuncBind("DbToYang_udld_nbr_key_xfmr", DbToYang_udld_nbr_key_xfmr)
}

var YangToDb_udld_global_key_xfmr = func(inParams XfmrParams) (string, error) {
	log.Info("YangToDb_udld_global_key_xfmr: ", inParams.ygRoot, inParams.uri)
	return "GLOBAL", nil
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
        // set appropriate err
        log.Error(" YangToDb_udld_nbr_key_xfmr Invalid name : ", name)
        log.Error(" YangToDb_udld_nbr_key_xfmr Invalid index : ", index)
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
