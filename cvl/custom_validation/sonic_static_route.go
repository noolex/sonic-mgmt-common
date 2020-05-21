package custom_validation

import (
    "github.com/go-redis/redis/v7"
    "fmt"
    "net"
    "strings"
)

func getNexthopAttrList(vc *CustValidationCtxt) (string, []string, error) {
    keys := strings.Split(vc.CurCfg.Key, "|")
    if len(keys) < 2 || keys[0] != "STATIC_ROUTE" {
        return "", nil, fmt.Errorf("Invalid key format: %s", vc.CurCfg.Key)
    }
    prefix := keys[len(keys) - 1]
    if len(vc.YNodeVal) == 0 {
        return prefix, []string{}, nil
    }
    if vc.SessCache.Data == nil {
        vc.SessCache.Data = make(map[string]int)
    }
    nhNumMap, ok := vc.SessCache.Data.(map[string]int)
    if !ok {
        return "", nil, fmt.Errorf("Invalid data type in session cache")
    }
    vals := strings.Split(vc.YNodeVal, ",")
    num, ok := nhNumMap[prefix]
    if !ok {
        attrs, err := vc.RClient.HGetAll(vc.CurCfg.Key).Result()
	    if err != nil && err != redis.Nil {
            return "", nil, fmt.Errorf("Failed to read NH attribute from DB, key: %s", vc.CurCfg.Key)
        }
	    if err == redis.Nil || len(attrs) == 0 {
            nhNumMap[prefix] = len(vals)
        } else {
            for _, fldVal := range attrs {
                nhNumMap[prefix] = len(strings.Split(fldVal, ","))
                break
            }
        }
        num = nhNumMap[prefix]
    }
    if num != len(vals) {
        return "", nil, fmt.Errorf("Given attr number %d is not aligned to existing NH number %d",
                                   len(vals), num)
    }

    return prefix, vals, nil
}

func checkTableKeyExists(db *redis.Client, tableList []string, key string) bool {
    for _, table := range tableList {
        fullKey := fmt.Sprintf("%s|%s", table, key)
        attrs, err := db.HGetAll(fullKey).Result()
        if err == nil && attrs != nil && len(attrs) > 0 {
            return true
        }
    }
    return false
}

//Path : /sonic-static-route/STATIC_ROUTE/nexthop
// Purpose: To check if every item in comma separated list is valid IP address
// Returns -  CVL Error object
func (t *CustomValidation) ValidateNexthopGateway(
	vc *CustValidationCtxt) CVLErrorInfo {
    prefix, gwIpList, err := getNexthopAttrList(vc)
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: err.Error()}
    }
    if len(gwIpList) == 0 {
        return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    }
    pfxIpStr := strings.Split(prefix, "/")[0]
    pfxIp := net.ParseIP(pfxIpStr)
    if pfxIp == nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: "Invalid static route IP prefix"}
    }
    pfxIpv4 := pfxIp.To4() != nil
    for _, gwIP := range gwIpList {
        ip := net.ParseIP(gwIP)
        if ip == nil {
            errMsg := fmt.Sprintf("Invalid gateway IP format %s", gwIP)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
        gwIpv4 := ip.To4() != nil
        if gwIpv4 != pfxIpv4 {
            errMsg := fmt.Sprintf("Address family of NH gateway %s not same as prefix %s", gwIP, pfxIpStr)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
    }
    return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//Path : /sonic-static-route/STATIC_ROUTE/ifname
// Purpose: To check if every item in comma separated list is an active interface name
// Returns -  CVL Error object
func (t *CustomValidation) ValidateNexthopInterface(
	vc *CustValidationCtxt) CVLErrorInfo {
    _, intfList, err := getNexthopAttrList(vc)
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: err.Error()}
    }
    var tableList = []string{"PORT", "PORTCHANNEL", "VLAN", "LOOPBACK_INTERFACE"}
    for _, ifName := range intfList {
        if len(ifName) == 0 {
            continue
        }
        if found := checkTableKeyExists(vc.RClient, tableList, ifName); !found {
            errMsg := fmt.Sprintf("Interface %s not found in config DB", ifName)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
    }
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}

//Path : /sonic-static-route/STATIC_ROUTE/nexthop-vrf
// Purpose: To check if every item in comma separated list is an active VRF name
// Returns -  CVL Error object
func (t *CustomValidation) ValidateNexthopVrf(
	vc *CustValidationCtxt) CVLErrorInfo {
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
    _, vrfList, err := getNexthopAttrList(vc)
    if err != nil {
        return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                            Msg: err.Error()}
    }
    var tableList = []string{"VRF"}
    for _, vrfName := range vrfList {
        if len(vrfName) == 0 {
            continue
        }
        if found := checkTableKeyExists(vc.RClient, tableList, vrfName); !found {
            errMsg := fmt.Sprintf("VRF %s not found in config DB", vrfName)
            return CVLErrorInfo{ErrCode: CVL_ERROR, Keys:[]string{vc.CurCfg.Key}, Value: vc.YNodeVal, Field: vc.YNodeName,
                                Msg: errMsg}
        }
    }
	return CVLErrorInfo{ErrCode: CVL_SUCCESS}
}
