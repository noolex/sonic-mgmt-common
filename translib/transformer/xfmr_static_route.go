package transformer

import (
        "errors"
        "strconv"
        "net"
        "strings"
        "fmt"
        log "github.com/golang/glog"
        "github.com/openconfig/ygot/ygot"
        "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
        "github.com/Azure/sonic-mgmt-common/translib/db"
        "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

const (
        STATIC_ROUTE_TABLE = "STATIC_ROUTE"
        DEFAULT_VRF = "default"
      )

var tableFieldNames [5]string = [5]string{"blackhole", "nexthop", "ifname", "distance", "nexthop-vrf"}

func zeroIp(ipv4 bool) string {
    var gwIp string
    if ipv4 {
        gwIp = "0.0.0.0"
    } else {
        gwIp = "::"
    }
    return gwIp
}

func isZeroIp(ipAddr *net.IP) bool {
    ipv4 := ipAddr.To4()
    if ipv4 != nil {
        ipAddr = &ipv4
    }
    byteLen := len(*ipAddr)
    for i := 0; i < byteLen; i ++ {
        if (*ipAddr)[i] != 0 {
            return false
        }
    }
    return true
}

func isPrefixIpv4(prefix string) bool {
    ip := net.ParseIP(strings.Split(prefix, "/")[0])
    if ip == nil {
        return false
    }
    ipv4 := ip.To4()
    return ipv4 != nil
}

func getNexthopIndex(blackhole bool, ip string, intf string, vrf string) string {
    var nhIndex string
    if blackhole {
        return "DROP"
    } else {
        if len(intf) > 0 {
            nhIndex = intf
        }
        nhIp := net.ParseIP(ip)
        if nhIp != nil && !isZeroIp(&nhIp) {
            if len(nhIndex) > 0 {
                nhIndex += "_"
            }
            nhIndex += ip
        }
    }
    if len(nhIndex) == 0 {
        log.Info("Nexthop is not blackhole and without IP and interface")
        return nhIndex
    }
    if len(vrf) > 0 {
        nhIndex += (fmt.Sprintf("_%s", vrf))
    }
    return nhIndex
}

type ipNexthop struct {
    blackhole bool
    gwIp net.IP
    ifName string
    distance uint32
    vrf string

    index string
    empty bool
}

func (nh ipNexthop) String() string {
    str := "{NH:"
    if nh.blackhole {
        str += " blackhole"
    }
    if !isZeroIp(&nh.gwIp) {
        str += fmt.Sprintf(" GW %s", nh.gwIp.String())
    }
    if len(nh.ifName) > 0 {
        str += fmt.Sprintf(" INTF %s", nh.ifName)
    }
    if nh.distance != 0 {
        str += fmt.Sprintf(" DIST %d", nh.distance)
    }
    if len(nh.vrf) > 0 {
        str += fmt.Sprintf(" NH_VRF %s", nh.vrf)
    }
    str += "}"
    return str
}

func newNexthop(srcVrf string, bkh bool, gw string, intf string, dist uint32, vrf string) (*ipNexthop, error) {
    nh := new(ipNexthop)
    nh.index = getNexthopIndex(bkh, gw, intf, vrf)
    if len(nh.index) == 0 {
        nh.empty = true
        return nh, nil
    }
    nh.blackhole = bkh
    nh.gwIp = net.ParseIP(gw)
    if nh.gwIp == nil {
        return nil, tlerr.InvalidArgs("Invalid Nexthop IP format: %v", gw)
    }
    nh.ifName = intf
    nh.distance = dist
    if vrf != srcVrf {
        nh.vrf = vrf
    }
    return nh, nil
}

type ipNexthopSet struct {
    isIpv4 bool
    nhList map[string]ipNexthop
}

func (nhs *ipNexthopSet)updateNH(nh ipNexthop, oper int) (bool, error) {
    if !nh.empty {
        nhIsIpv4 := (nh.gwIp.To4() != nil)
        if nhs.isIpv4 != nhIsIpv4 {
            return false, tlerr.InvalidArgs("IP type mismatch: route_ipv4 %v nh_ipv4 %v", nhs.isIpv4, nhIsIpv4)
        }
    }
    var changed bool
    if _, ok := nhs.nhList[nh.index]; !ok {
        if oper == CREATE || oper == UPDATE {
            nhs.nhList[nh.index] = nh
            changed = true
        }
    } else {
        if oper == DELETE {
            delete(nhs.nhList, nh.index)
            changed = true
        } else if oper == REPLACE {
            nhs.nhList[nh.index] = nh
            changed = true
        }
    }

    return changed, nil
}

type routeAttrInfo struct {
    haveData bool
    value []string
}

func (nhs *ipNexthopSet)toAttrMap() db.Value {
    retVal := db.Value{Field: map[string]string{}}
    attrList := make([]routeAttrInfo, len(tableFieldNames))

    for _, nh := range nhs.nhList {
        if nh.blackhole {
            attrList[0].haveData = true
            attrList[0].value = append(attrList[0].value, "true")
        } else {
            attrList[0].value = append(attrList[0].value, "false")
        }
        if !isZeroIp(&nh.gwIp) {
            attrList[1].haveData = true
        }
        attrList[1].value = append(attrList[1].value, nh.gwIp.String())

        if len(nh.ifName) > 0 {
            attrList[2].haveData = true
        }
        attrList[2].value = append(attrList[2].value, nh.ifName)
        if nh.distance != 0 {
            attrList[3].haveData = true
        }
        attrList[3].value = append(attrList[3].value, strconv.FormatUint(uint64(nh.distance), 10))
        if len(nh.vrf) > 0 {
            attrList[4].haveData = true
        }
        attrList[4].value = append(attrList[4].value, nh.vrf)
    }
    for idx, attr := range attrList {
        if attr.haveData {
            retVal.Set(tableFieldNames[idx], strings.Join(attr.value, ","))
        }
    }

    return retVal
}

func (nhs *ipNexthopSet)fromDbData(srcVrf string, prefix string, data *db.Value) error {
    var fieldValues [len(tableFieldNames)][]string
    var nhNum int
    for idx := 0; idx < len(tableFieldNames); idx ++ {
        if data.Has(tableFieldNames[idx]) {
            fieldValues[idx] = strings.Split(data.Get(tableFieldNames[idx]), ",")
            num := len(fieldValues[idx])
            if nhNum == 0 {
                nhNum = num
            } else if nhNum != num {
                return tlerr.InvalidArgs("Nexthop attribute list size not aligned")
            }
        }
    }
    prefixIp := strings.Split(prefix, "/")[0]
    nhs.isIpv4 = true
    if net.ParseIP(prefixIp).To4() == nil {
        nhs.isIpv4 = false
    }
    if nhs.nhList == nil {
        nhs.nhList = make(map[string]ipNexthop)
    }
    for idx := 0; idx < nhNum; idx ++ {
        var blackhole bool
        if fieldValues[0] != nil && fieldValues[0][idx] == "true" {
            blackhole = true
        }
        var gateway string
        if fieldValues[1] != nil {
            gateway = fieldValues[1][idx]
        } else {
            gateway = zeroIp(nhs.isIpv4)
        }
        var intf string
        if fieldValues[2] != nil {
            intf = fieldValues[2][idx]
        }
        var distance uint32
        if fieldValues[3] != nil {
            distNum, _ := strconv.ParseUint(fieldValues[3][idx], 10, 32)
            distance = uint32(distNum)
        }
        var vrf string
        if fieldValues[4] != nil {
            vrf = fieldValues[4][idx]
        }
        nhIndex := getNexthopIndex(blackhole, gateway, intf, vrf)
        if nh, err := newNexthop(srcVrf, blackhole, gateway, intf, distance, vrf); err == nil {
            nhs.nhList[nhIndex] = *nh
        }
    }

    return nil
}

type uriScopeType int

const (
        STATIC_ROUTES           uriScopeType = iota
        STATIC_ROUTES_STATIC
        STATIC_ROUTES_NEXTHOP
      )

func (scope uriScopeType) String() string {
    switch scope {
    case STATIC_ROUTES:
        return "StaticRoutes"
    case STATIC_ROUTES_STATIC:
        return "Static"
    case STATIC_ROUTES_NEXTHOP:
        return "NextHop"
    }
    return "Unknown Scope Type"
}

func getYgotStaticRoutesObj(s *ygot.GoStruct, vrf string) (
        *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes, error) {
    deviceObj, ok := (*s).(*ocbinds.Device)
    if !ok {
        return nil, errors.New("Invalid root object type")
    }
    vrfInstObj := deviceObj.NetworkInstances.NetworkInstance[vrf]
    if  vrfInstObj == nil {
        return nil, errors.New("Invalid VRF name")
    }
    protoKey := ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Key{
                            Identifier: ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
                            Name: "static",
              }
    protoInstObj := vrfInstObj.Protocols.Protocol[protoKey]
    if protoInstObj == nil || protoInstObj.StaticRoutes == nil {
        return nil, errors.New("Network-instance Static-Protocol obj missing")
    }

    return protoInstObj.StaticRoutes, nil
}

func getYgotNexthopObj(s *ygot.GoStruct, vrf string, prefix string) (map[string]*ipNexthopSet, error) {
    staticRoutes, err := getYgotStaticRoutesObj(s, vrf)
    if err != nil {
        return nil, err
    }
    resMap := make(map[string]*ipNexthopSet)
    for ipPrefix, routeObj := range staticRoutes.Static {
        if len(prefix) > 0 && prefix != ipPrefix {
            continue
        }
        if routeObj == nil || routeObj.NextHops == nil {
            continue
        }
        ipAndPrefix := strings.Split(ipPrefix, "/")
        if len(ipAndPrefix) != 2 {
            return nil, tlerr.InvalidArgs("Invalid route IP with prefix format: %s", ipPrefix)
        }
        prefixNum, err := strconv.ParseInt(ipAndPrefix[1], 10, 32)
        if err != nil {
            return nil, tlerr.InvalidArgs("Invalid route prefix format: %s", ipPrefix)
        }
        ipAddr := net.ParseIP(ipAndPrefix[0])
        if ipAddr == nil {
            return nil, tlerr.InvalidArgs("Invalid route target IP format: %s", ipAndPrefix[0])
        }
        var isIpv4 bool = true
        if ipAddr.To4() == nil {
            isIpv4 = false
        }
        if (isIpv4 && prefixNum > 32) || (!isIpv4 && prefixNum > 128) {
            return nil, tlerr.InvalidArgs("Invalid route prefix number: %d", prefixNum)
        }

        resMap[ipPrefix] = &ipNexthopSet{isIpv4, make(map[string]ipNexthop)}
        for nhIndex, nexthopObj := range routeObj.NextHops.NextHop {
            if nexthopObj == nil {
                continue
            }
            var blackhole bool
            var intfName, nhVrf string
            var distance uint32
            var gwIp string
            if nexthopObj.Config != nil {
                if nexthopObj.Config.Blackhole != nil {
                    blackhole = *nexthopObj.Config.Blackhole
                }
                if nexthopObj.Config.Metric != nil {
                    distance = *nexthopObj.Config.Metric
                }
                if nexthopObj.Config.NexthopVrfName != nil {
                    nhVrf = *nexthopObj.Config.NexthopVrfName
                }
                if nexthopObj.Config.NextHop != nil {
                    switch nexthopObj.Config.NextHop.(type) {
                    case *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_Config_NextHop_Union_E_OpenconfigLocalRouting_LOCAL_DEFINED_NEXT_HOP:
                        return nil, tlerr.InvalidArgs("Local defined nexthop not supported")
                    case *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_Config_NextHop_Union_String:
                        gwIp = nexthopObj.Config.NextHop.
                            (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_Config_NextHop_Union_String).String
                    default:
                        return nil, tlerr.InvalidArgs("Invalid Nexthop IP attribute type: %v", nhIndex)
                    }
                }
                if len(gwIp) == 0 {
                    gwIp = zeroIp(isIpv4)
                }
            }
            if nexthopObj.InterfaceRef != nil && nexthopObj.InterfaceRef.Config != nil && nexthopObj.InterfaceRef.Config.Interface != nil {
                intfName = *nexthopObj.InterfaceRef.Config.Interface
            }
            log.Infof("NH[%v]: blackhole %v IP %v interface %v distance %v VRF %v", nhIndex, blackhole, gwIp, intfName, distance, nhVrf)
            nhObj, err := newNexthop(vrf, blackhole, gwIp, intfName, distance, nhVrf)
            if err != nil {
                log.Infof("Failed to create nexthop object: %v", err)
                return nil, err
            }
            if len(nhObj.index) > 0 && nhObj.index != nhIndex {
                log.Infof("Generated NH index %s not equal to given index %s", nhObj.index, nhIndex)
                return nil, tlerr.InvalidArgs("Generated NH index %s not equal to given index %s", nhObj.index, nhIndex)
            } else if len(nhObj.index) == 0 {
                nhObj.index = nhIndex
            }

            _, err = resMap[ipPrefix].updateNH(*nhObj, CREATE)
            if err != nil {
                log.Infof("Failed to add nexthop object to list: %v", err)
                return nil, err
            }
        }
    }
    return resMap, nil
}

func nexthopFromStrList(srcVrf string, strList []string, isIpv4 bool) (*ipNexthop, error) {
    argCnt := len(strList)
    if argCnt < 5 {
        addArgs := 5 - argCnt
        for idx := 0; idx < addArgs; idx ++ {
            strList = append(strList, "")
        }
    }
    var blackhole bool
    if strList[0] == "true" {
        blackhole = true
    }
    var distance int64
    var err error
    if len(strList[3]) > 0 {
        distance, err = strconv.ParseInt(strList[3], 10, 32)
        if err != nil {
            return nil, err
        }
    }
    gwIp := strList[1]
    if len(gwIp) == 0 {
        gwIp = zeroIp(isIpv4)
    }
    return newNexthop(srcVrf, blackhole, gwIp, strList[2], uint32(distance), strList[4])
}

func getAllPrefixFromDB(d *db.DB, vrf string) []string {
    var prefixList []string
    var keys []db.Key
    var err error
    tblSpec := db.TableSpec{Name: STATIC_ROUTE_TABLE}
    if vrf == DEFAULT_VRF {
        keys, err = d.GetKeys(&tblSpec)
    } else {
        keys, err = d.GetKeysPattern(&tblSpec, db.Key{Comp: []string{vrf, "*"}})
    }
    if err != nil {
        return prefixList
    }
    for _, k := range keys {
        if len(k.Comp) > 1 && k.Comp[0] != vrf {
            continue
        }
        prefixList = append(prefixList, k.Comp[len(k.Comp) - 1])
    }
    return prefixList
}

func getNexthopListFromDB(d *db.DB, srcVrf string, ipPrefix string) (ipNexthopSet, bool, error) {
    ipv4 := isPrefixIpv4(ipPrefix)
    tblSpec := db.TableSpec{Name: STATIC_ROUTE_TABLE}
    nhList := ipNexthopSet{ipv4, make(map[string]ipNexthop)}
    var vrfInKey bool = true
    keys, err := d.GetKeysPattern(&tblSpec, db.Key{Comp: []string{srcVrf, ipPrefix}})
    if err == nil && len(keys) == 0 && srcVrf == DEFAULT_VRF {
        vrfInKey = false
        keys, err = d.GetKeysPattern(&tblSpec, db.Key{Comp: []string{ipPrefix}})
    }
    if err != nil {
        log.Infof("Failed to get table key for prefix %s from DB: %v", ipPrefix, err)
        return nhList, true, err
    }
    if len(keys) == 0 {
        return nhList, true, nil
    }
    nhEntry, err := d.GetEntry(&tblSpec, keys[0])
    if err != nil {
        log.Infof("Failed to get nexthop entry for prefix %s from DB: %v", ipPrefix, err)
        return nhList, true, err
    }
    fldValList := [][]string{}
    var fldVal string
    var valList []string
    for _, fld := range tableFieldNames {
        fldVal = nhEntry.Get(fld)
        if len(fldVal) == 0 {
            valList = []string{}
        } else {
            valList = strings.Split(fldVal, ",")
        }
        fldValList = append(fldValList, valList)
    }
    if len(fldValList[0]) == 0 && len(fldValList[1]) == 0 && len(fldValList[2]) == 0 {
        return nhList, vrfInKey, nil
    }
    nhCnt := 0
    for _, val := range fldValList {
        valLen := len(val)
        if nhCnt == 0 && valLen != 0 {
            nhCnt = valLen
        } else if valLen != 0 && valLen != nhCnt {
            return nhList, true, tlerr.InvalidArgs("Size of nexthop attributes are not aligned")
        }
    }
    for idx := 0; idx < nhCnt; idx ++ {
        argList := []string{}
        for _, val := range fldValList {
            if len(val) == 0 {
                argList = append(argList, "")
            } else {
                argList = append(argList, val[idx])
            }
        }
        nhObj, err := nexthopFromStrList(srcVrf, argList, ipv4)
        if err != nil {
            return nhList, true, err
        }
        nhList.updateNH(*nhObj, CREATE)
    }
    return nhList, vrfInKey, nil
}

func getRouteKeysFromDB(d *db.DB, srcVrf string, ipPrefix string) ([]string, error) {
    keys, err := d.GetKeys(&db.TableSpec{Name: STATIC_ROUTE_TABLE})
    if err != nil {
        return nil, err
    }
    var dbKeyList []string
    for _, k := range keys {
        if (len(k.Comp) == 2 && k.Comp[0] == srcVrf) || (srcVrf == DEFAULT_VRF && len(k.Comp) == 1) {
            if len(ipPrefix) == 0 || k.Comp[len(k.Comp) - 1] == ipPrefix {
                dbKeyList = append(dbKeyList, strings.Join(k.Comp, d.Opts.KeySeparator))
            }
        }
    }
    return dbKeyList, nil
}

type dbNexthopInfo struct {
    vrfInKey bool
    nhList *ipNexthopSet
}

type cacheRouteInfo struct {
    ygotNhList *ipNexthopSet
    dbNh *dbNexthopInfo
}

type cacheVrfInfo map[string]map[string]*cacheRouteInfo

func getRouteData(inParams XfmrParams, scope uriScopeType) (*cacheVrfInfo, error) {
    pathInfo := NewPathInfo(inParams.uri)
    vrf := pathInfo.Var("name")
    cacheData := &cacheVrfInfo{}
    proto := pathInfo.Var("name#2")
    protoId := pathInfo.Var("identifier")
    ipPrefix := pathInfo.Var("prefix")

    if len(vrf) == 0 {
        log.Info("VRF name is missing")
        return nil, tlerr.NotFound("VRF name in URI")
    }
    if protoId != "STATIC" || proto != "static" {
        log.Info("Invalid protocol name or identifier")
        return nil, tlerr.InvalidArgs("Invalid protocol name %v or identifier %v", proto, protoId)
    }

    searchPrefix := ipPrefix
    if inParams.oper == REPLACE && scope == STATIC_ROUTES {
        searchPrefix = ""
    }
    srouteObjMap, err := getYgotNexthopObj(inParams.ygRoot, vrf, searchPrefix)
    if err != nil {
        log.Info("Failed to get ygot static route tree")
        return nil, err
    }
    if inParams.oper == REPLACE && scope == STATIC_ROUTES {
        dbPrefix := getAllPrefixFromDB(inParams.d, vrf)
        for _, pfx := range dbPrefix {
            if _, ok := srouteObjMap[pfx]; !ok {
                srouteObjMap[pfx] = nil
            }
        }
    }
    (*cacheData)[vrf] = make(map[string]*cacheRouteInfo)
    for prefix, nhs := range srouteObjMap {
        nhList, vrfInKey, err := getNexthopListFromDB(inParams.d, vrf, prefix)
        if err != nil {
            log.Infof("Faile to get nexthops of %s from DB: %v", prefix, err)
            return nil, err
        }
        dbNh := &dbNexthopInfo{vrfInKey, &nhList}
        (*cacheData)[vrf][prefix] = &cacheRouteInfo{nhs, dbNh}
    }

    return cacheData, nil
}

func (data *cacheVrfInfo)isDataValid(scope uriScopeType, oper int, vrf string) bool {
    vrfRoute, ok := (*data)[vrf]
    if !ok {
        log.Infof("VRF %s not in cached data", vrf)
        return false
    }
    if oper == CREATE {
        // check if route or nexthop already created
        for pfx, route := range vrfRoute {
            if route.dbNh != nil && len(route.dbNh.nhList.nhList) > 0 {
                if scope != STATIC_ROUTES_NEXTHOP {
                    log.Infof("route prefix %s was already in DB", pfx)
                    return false
                }
                for key, _ := range route.ygotNhList.nhList {
                    if _, ok := route.dbNh.nhList.nhList[key]; ok {
                        log.Infof("route prefix %s nexthop %s was already in DB", pfx, key)
                        return false
                    }
                }
            }
        }
    } else if oper == DELETE || (oper == REPLACE && scope != STATIC_ROUTES) {
        // check if route or nexthop in DB
        for pfx, route := range vrfRoute {
            if route.dbNh == nil || len(route.dbNh.nhList.nhList) == 0 {
                log.Infof("prefix %s not found in DB", pfx)
                return false
            }
            if scope == STATIC_ROUTES_STATIC {
                continue
            }
            for key, _ := range route.ygotNhList.nhList {
                if _, ok := route.dbNh.nhList.nhList[key]; !ok {
                    log.Infof("prefix %s nexthop %s not found in DB", pfx, key)
                    return false
                }
            }
        }
    }
    return true
}

func getUriScope(uri string) uriScopeType {
    pathInfo := NewPathInfo(uri)
    if pathInfo.HasVar("index") {
        return STATIC_ROUTES_NEXTHOP
    } else if pathInfo.HasVar("prefix") {
        return STATIC_ROUTES_STATIC
    } else {
        return STATIC_ROUTES
    }
}

func addRouteDelToMap(inParams XfmrParams, vrf string, prefix string, resMap map[string]map[string]db.Value) error {
    dbKeys, err := getRouteKeysFromDB(inParams.d, vrf, prefix)
    if err != nil {
        log.Infof("Failed to get table keys for VRF %s prefix %s", vrf, prefix)
        return err
    }
    if _, ok := resMap[STATIC_ROUTE_TABLE]; !ok {
        resMap[STATIC_ROUTE_TABLE] = make(map[string]db.Value)
    }
    for _, key := range dbKeys {
        resMap[STATIC_ROUTE_TABLE][key] = db.Value{Field: map[string]string{}}
    }
    return nil
}

func addRouteUpdToMap(inParams XfmrParams, vrf string, prefix string, nexthops *ipNexthopSet, resMap map[string]map[string]db.Value) error {
    dbKeys, err := getRouteKeysFromDB(inParams.d, vrf, prefix)
    if err != nil {
        log.Infof("Failed to get table keys for VRF %s prefix %s", vrf, prefix)
        return err
    }
    if _, ok := resMap[STATIC_ROUTE_TABLE]; !ok {
        resMap[STATIC_ROUTE_TABLE] = make(map[string]db.Value)
    }
    var key string
    if len(dbKeys) == 0 {
        key = vrf + "|" + prefix
    } else {
        key = dbKeys[0]
    }
    resMap[STATIC_ROUTE_TABLE][key] = nexthops.toAttrMap()
    return nil
}

var YangToDb_static_routes_nexthop_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    uriScope := getUriScope(inParams.requestUri)
    log.Infof("YangToDb_static_routes_nexthop_xfmr: URI %s, requestURI %s, Scope %s", inParams.uri, inParams.requestUri, uriScope)
    resMap := make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    vrf := pathInfo.Var("name")
    ipPrefix := pathInfo.Var("prefix")

    cacheData, err := getRouteData(inParams, uriScope)
    if err != nil {
        log.Info("Failed to get ygot and DB data")
        return resMap, err
    }
    if !cacheData.isDataValid(uriScope, inParams.oper, vrf) {
        log.Info("Data read from ygot root and DB is not valid")
        return resMap, tlerr.InvalidArgs("Invalid data from input or DB")
    }
    if inParams.oper == DELETE {
        if !pathInfo.HasVar("index") {
            log.Infof("Handling static route delete for VRF %s prefix %s", vrf, ipPrefix)
            if err = addRouteDelToMap(inParams, vrf, ipPrefix, resMap); err != nil {
                log.Infof("Failed to add route delete to map: VRF %s prefix %s", vrf, ipPrefix)
                return resMap, err
            }
        } else {
            nhIndex := pathInfo.Var("index")
            log.Infof("Handling static route nexthop delete for VRF %s prefix %s index %s", vrf, ipPrefix, nhIndex)
            route := (*cacheData)[vrf][ipPrefix]
            nh, ok := route.ygotNhList.nhList[nhIndex]
            if !ok {
                return resMap, tlerr.InvalidArgs("NH %s not found in ygot cache", nhIndex)
            }
            changed, err := route.dbNh.nhList.updateNH(nh, DELETE)
            if err != nil {
                log.Infof("Failed to delete nexthop from existing route: %s", ipPrefix)
                return resMap, err
            }
            if changed {
                if len(route.dbNh.nhList.nhList) == 0 {
                    if err = addRouteDelToMap(inParams, vrf, ipPrefix, resMap); err != nil {
                        log.Infof("Failed to add route delete to map: VRF %s prefix %s", vrf, ipPrefix)
                        return resMap, err
                    }
                } else {
                    var subDataMap = make(RedisDbMap)
                    subDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
                    if err = addRouteUpdToMap(inParams, vrf, ipPrefix, route.dbNh.nhList, subDataMap[db.ConfigDB]); err != nil {
                        log.Infof("Failed to add route update to map: VRF %s prefix %s", vrf, ipPrefix)
                        return resMap, err
                    }
                    inParams.subOpDataMap[REPLACE] = &subDataMap
                }
            }
        }
    } else if !pathInfo.HasVar("index") {
        log.Infof("Handling static route configuration for VRF %s prefix %s", vrf, ipPrefix)
        var updSubDataMap = make(RedisDbMap)
        var delSubDataMap = make(RedisDbMap)
        updSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        delSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        for prefix, routeInfo := range (*cacheData)[vrf] {
            if routeInfo.ygotNhList == nil {
                // delete route
                log.Infof("Put to be replaced route prefix %s in delete list", prefix)
                if err = addRouteDelToMap(inParams, vrf, prefix, delSubDataMap[db.ConfigDB]); err != nil {
                    log.Infof("Failed to add route delete to map: VRF %s prefix %s", vrf, prefix)
                    return resMap, nil
                }
            } else {
                if routeInfo.dbNh == nil || len(routeInfo.dbNh.nhList.nhList) == 0 {
                    // add new route
                    log.Infof("Put new route prefix %s in update list", prefix)
                    if err = addRouteUpdToMap(inParams, vrf, prefix, routeInfo.ygotNhList, resMap); err != nil {
                        log.Infof("Failed to add route add to map: VRF %s prefix %s", vrf, prefix)
                        return resMap, nil
                    }
                } else {
                    // udpate nexthop
                    if inParams.oper != REPLACE {
                        for k, v := range routeInfo.dbNh.nhList.nhList {
                            if _, ok := routeInfo.ygotNhList.nhList[k]; !ok {
                                routeInfo.ygotNhList.updateNH(v, CREATE)
                            }
                        }
                    }
                    log.Infof("Put to be updated route prefix %s in update list", prefix)
                    if err = addRouteUpdToMap(inParams, vrf, prefix, routeInfo.ygotNhList, updSubDataMap[db.ConfigDB]); err != nil {
                        log.Infof("Failed to add route update to map: VRF %s prefix %s", vrf, prefix)
                        return resMap, err
                    }
                }
            }
        }

        if len(updSubDataMap[db.ConfigDB]) > 0 {
            inParams.subOpDataMap[REPLACE] = &updSubDataMap
        }
        if len(delSubDataMap[db.ConfigDB]) > 0 {
            inParams.subOpDataMap[DELETE] = &delSubDataMap
        }
    }

    return resMap, nil
}

func setRouteObjWithDbData(inParams XfmrParams, vrf string, ipPrefix string, nhIndex string) error {
    sroutesObj, err := getYgotStaticRoutesObj(inParams.ygRoot, vrf)
    if err != nil {
        return err
    }
    routeData := (*inParams.dbDataMap)[db.ConfigDB]["STATIC_ROUTE"]
    for prefixKey, route := range routeData {
        tokens := strings.Split(prefixKey, "|")
        prefix := tokens[len(tokens) - 1]
        if len(ipPrefix) != 0 && ipPrefix != prefix {
            continue
        }
        var nhSet ipNexthopSet
        err := nhSet.fromDbData(vrf, prefix, &route)
        if err != nil {
            log.Infof("Failed to read static route attribute from DB data for %s: %v", prefix, err)
            return err
        }
        var routeObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static
        routeObj, ok := sroutesObj.Static[prefix]
        if !ok {
            routeObj, err = sroutesObj.NewStatic(prefix)
            if err != nil {
                log.Infof("Failed to get new static route object: %v", err)
                return err
            }
        }
        routeObj.NextHops = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops)
        for key, nh := range nhSet.nhList {
            if len(nhIndex) != 0 && nhIndex != key {
                continue
            }
            var nhObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop
            nhObj, ok := routeObj.NextHops.NextHop[key]
            if !ok {
                nhObj, err = routeObj.NextHops.NewNextHop(key)
                if err != nil {
                    log.Infof("Failed to get new nexthop object: %v", err)
                    return err
                }
            }
            if nhObj.Config == nil {
                nhObj.Config = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_Config)
            }
            if nhObj.Config.Index == nil {
                nhObj.Config.Index = new(string)
            }
            *nhObj.Config.Index = key
            if nh.blackhole {
                if nhObj.Config.Blackhole == nil {
                    nhObj.Config.Blackhole = new(bool)
                }
                *nhObj.Config.Blackhole = nh.blackhole
            }
            if !isZeroIp(&nh.gwIp) {
                gwObj, err :=
                    nhObj.Config.To_OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_Config_NextHop_Union(nh.gwIp.String())
                if err != nil {
                    log.Infof("Failed to get gateway IP object: %v", err)
                    return err
                }
                nhObj.Config.NextHop = gwObj
            }
            if nh.distance != 0 {
                if nhObj.Config.Metric == nil {
                    nhObj.Config.Metric = new(uint32)
                }
                *nhObj.Config.Metric = nh.distance
            }
            if len(nh.vrf) > 0 {
                if nhObj.Config.NexthopVrfName == nil {
                    nhObj.Config.NexthopVrfName = new(string)
                }
                *nhObj.Config.NexthopVrfName = nh.vrf
            }
            if len(nh.ifName) > 0 {
                if nhObj.InterfaceRef == nil {
                    nhObj.InterfaceRef = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_InterfaceRef)
                }
                if nhObj.InterfaceRef.Config == nil {
                    nhObj.InterfaceRef.Config =
                        new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_InterfaceRef_Config)
                }
                if nhObj.InterfaceRef.Config.Interface == nil {
                    nhObj.InterfaceRef.Config.Interface = new(string)
                }
                *nhObj.InterfaceRef.Config.Interface = nh.ifName
            }
        }
    }
    return nil
}

var DbToYang_static_routes_nexthop_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    log.Infof("DbToYang_static_routes_nexthop_xfmr: URI %s, requestURI %s", inParams.uri, inParams.requestUri)
    pathInfo := NewPathInfo(inParams.uri)
    vrf := pathInfo.Var("name")
    prefix := pathInfo.Var("prefix")
    nhIndex := pathInfo.Var("index")
    err := setRouteObjWithDbData(inParams, vrf, prefix, nhIndex)

    return err
}

var YangToDb_static_routes_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    log.Infof("YangToDb_static_routes_key_xfmr: URI %s", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)
    vrf := pathInfo.Var("name")
    if !pathInfo.HasVar("prefix") {
        return "", nil
    }
    prefix := pathInfo.Var("prefix")
    return vrf + "|" + prefix, nil
}

var DbToYang_static_routes_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Infof("DbToYang_static_routes_key_xfmr: URI %s, key %s", inParams.uri, inParams.key)
    rmap := make(map[string]interface{})
    dbKeys := strings.Split(inParams.key, "|")
    if len(dbKeys) >= 2 {
        rmap["prefix"] = dbKeys[1]
    }

    return rmap, nil
}

func init() {
    XlateFuncBind("YangToDb_static_routes_nexthop_xfmr", YangToDb_static_routes_nexthop_xfmr)
    XlateFuncBind("DbToYang_static_routes_nexthop_xfmr", DbToYang_static_routes_nexthop_xfmr)
    XlateFuncBind("YangToDb_static_routes_key_xfmr", YangToDb_static_routes_key_xfmr)
    XlateFuncBind("DbToYang_static_routes_key_xfmr", DbToYang_static_routes_key_xfmr)
}
