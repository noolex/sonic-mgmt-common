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
        "github.com/Azure/sonic-mgmt-common/translib/utils"
        "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

const (
        STATIC_ROUTE_TABLE = "STATIC_ROUTE"
        DEFAULT_VRF = "default"
        NH_KEY_SEPARATOR = "|"
      )

var tableFieldNames [7]string = [7]string{"blackhole", "nexthop", "ifname", "distance", "nexthop-vrf", "track", "tag" }

func zeroIp(ipv4 bool) string {
    var gwIp string
    if ipv4 {
        gwIp = "0.0.0.0"
    } else {
        gwIp = "::"
    }
    return gwIp
}

type IPExt struct {
    ipAddr net.IP
    isIpv4 bool
    origIpStr string
}

func parseIPExt(ipStr string) *IPExt {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return nil
    }
    retVal := new(IPExt)
    retVal.origIpStr = ipStr
    ipv4 := ip.To4()
    if ipv4 != nil {
        retVal.ipAddr = ipv4
        if strings.Contains(ipStr, ":") {
            // IPv4 in IPv6
            retVal.isIpv4 = false
        } else {
            retVal.isIpv4 = true
        }
    } else {
        retVal.ipAddr = ip
        retVal.isIpv4 = false
    }
    return retVal
}

func (ip *IPExt) isZeros() bool {
    for _, b := range ip.ipAddr {
        if b != 0 {
            return false
        }
    }
    return true
}

func (ip *IPExt) String() string {
    if len(ip.ipAddr) == net.IPv4len && !ip.isIpv4 {
        return fmt.Sprintf("::ffff:%v", ip.ipAddr)
    }
    return ip.ipAddr.String()
}

func isPrefixIpv4(prefix string) bool {
    ip := parseIPExt(strings.Split(prefix, "/")[0])
    if ip == nil {
        return false
    }
    return ip.isIpv4
}

func getNexthopIndex(srcVrf string, blackhole bool, ip string, intf string, vrf string) []string {
    if blackhole {
        return []string{"DROP"}
    }
    var nhIndex string
    if len(intf) > 0 {
        nhIndex = intf
    }
    nhIp := parseIPExt(ip)
    if nhIp != nil && !nhIp.isZeros() {
        if len(nhIndex) > 0 {
            nhIndex += "_"
        }
        nhIndex += ip
    }
    if len(nhIndex) == 0 {
        log.Info("Nexthop is not blackhole and without IP and interface")
        return []string{}
    }
    if len(vrf) > 0 && vrf != srcVrf {
        return []string{nhIndex + fmt.Sprintf("_%s", vrf)}
    } else {
        vrf = srcVrf
        return []string{nhIndex, nhIndex + fmt.Sprintf("_%s", vrf)}
    }
}

type ipNexthop struct {
    blackhole bool
    gwIp *IPExt
    ifName string
    tag uint32
    distance uint32
    vrf string
    track uint16

    index []string
    empty bool
}

func (nh ipNexthop) String() string {
    str := "{NH:"
    if nh.blackhole {
        str += " blackhole"
    }
    if !nh.gwIp.isZeros() {
        str += fmt.Sprintf(" GW %s", nh.gwIp)
    }
    if len(nh.ifName) > 0 {
        str += fmt.Sprintf(" INTF %s", nh.ifName)
    }
    if nh.tag != 0 {
        str += fmt.Sprintf(" TAG %d", nh.tag)
    }
    if nh.distance != 0 {
        str += fmt.Sprintf(" DIST %d", nh.distance)
    }
    if len(nh.vrf) > 0 {
        str += fmt.Sprintf(" NH_VRF %s", nh.vrf)
    }
    if nh.track != 0 {
        str += fmt.Sprintf(" TRACK %d", nh.track)
    }
    str += "}"
    return str
}

func (nh *ipNexthop) getKey() string {
    if len(nh.index) == 0 {
        return ""
    }
    return strings.Join(nh.index, NH_KEY_SEPARATOR)
}

func (nh *ipNexthop) isMatchedIndex(nhIndex string) bool {
    for _, idx := range nh.index {
        if idx == nhIndex {
            return true
        }
    }
    return false
}

func newNexthop(srcVrf string, bkh bool, gw string, intf string, tag uint32, dist uint32, vrf string, track uint16) (*ipNexthop, error) {
    nh := new(ipNexthop)
    nh.index = getNexthopIndex(srcVrf, bkh, gw, intf, vrf)
    if len(nh.index) == 0 {
        nh.empty = true
        return nh, nil
    }
    nh.blackhole = bkh
    nh.gwIp = parseIPExt(gw)
    if nh.gwIp == nil {
        return nil, tlerr.InvalidArgs("Invalid Nexthop IP format: %v", gw)
    }
    nh.ifName = intf
    nh.tag = tag
    nh.distance = dist
    if vrf != srcVrf {
        nh.vrf = vrf
    }
    nh.track = track
    return nh, nil
}

type ipNexthopSet struct {
    isIpv4 bool
    nhList map[string]ipNexthop
}

func (nhs *ipNexthopSet)getNexthopByKey(key string) (*ipNexthop, string) {
    if nh, ok := nhs.nhList[key]; ok {
        return &nh, key
    }
    for _, tk := range strings.Split(key, NH_KEY_SEPARATOR) {
        for nhKey, nh := range nhs.nhList {
            if nh.isMatchedIndex(tk) {
                return &nh, nhKey
            }
        }
    }
    return nil, ""
}

func (nhs *ipNexthopSet)updateNH(nh ipNexthop, oper int) (bool, error) {
    if !nh.empty {
        if nhs.isIpv4 != nh.gwIp.isIpv4 {
            return false, tlerr.InvalidArgs("IP type mismatch: route_ipv4 %v nh_ipv4 %v",
                                            nhs.isIpv4, nh.gwIp.isIpv4)
        }
    }
    var changed bool
    key := nh.getKey()
    if mnh, newKey := nhs.getNexthopByKey(key); mnh == nil {
        if oper == CREATE || oper == UPDATE || oper == REPLACE {
            nhs.nhList[key] = nh
            changed = true
        }
    } else {
        if oper == DELETE {
            delete(nhs.nhList, newKey)
            changed = true
        } else if oper == REPLACE || oper == UPDATE {
            nhs.nhList[newKey] = nh
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
        if !nh.gwIp.isZeros() {
            attrList[1].haveData = true
        }
        attrList[1].value = append(attrList[1].value, nh.gwIp.origIpStr)

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
        if nh.track != 0 {
            attrList[5].haveData = true
        }
        attrList[5].value = append(attrList[5].value, strconv.FormatUint(uint64(nh.track), 10))
        if nh.tag != 0 {
            attrList[6].haveData = true
        }
        attrList[6].value = append(attrList[6].value, strconv.FormatUint(uint64(nh.tag), 10))
    }
    for idx, attr := range attrList {
        if attr.haveData {
            retVal.Set(tableFieldNames[idx], strings.Join(attr.value, ","))
        }
    }

    return retVal
}

// set nexthop set based on NH attributes of DB data
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
    prefixIp := parseIPExt(strings.Split(prefix, "/")[0])
    if prefixIp == nil {
        return tlerr.InvalidArgs("Invalid IP address in prefix: %s", prefix)
    }
    nhs.isIpv4 = prefixIp.isIpv4
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
            if utils.IsAliasModeEnabled() {
                intf = *(utils.GetUINameFromNativeName(&fieldValues[2][idx]))
            } else {
                intf = fieldValues[2][idx]
            }
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

        var track uint16
        if fieldValues[5] != nil {
            trackNum, _ := strconv.ParseUint(fieldValues[5][idx], 10, 32)
            track = uint16(trackNum)
        }
        var tag uint32
        if fieldValues[6] != nil {
            tagNum, _ := strconv.ParseUint(fieldValues[6][idx], 10, 32)
            tag = uint32(tagNum)
        }
        if nh, err := newNexthop(srcVrf, blackhole, gateway, intf, tag, distance, vrf, track); err == nil {
            nhs.nhList[nh.getKey()] = *nh
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

func getYgotStaticRoutesObj(s *ygot.GoStruct, vrf string, is_validate bool) (
        *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes, error) {
    deviceObj, ok := (*s).(*ocbinds.Device)
    if !ok {
        return nil, errors.New("Invalid root object type")
    }
    if deviceObj.NetworkInstances == nil {
        if is_validate { return nil, errors.New("Network Instances object not found") }
        deviceObj.NetworkInstances = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances)
    }
    var err error
    vrfInstObj, ok := deviceObj.NetworkInstances.NetworkInstance[vrf]
    if !ok {
        if is_validate { return nil, errors.New("Network Instance object not found") }
        if vrfInstObj, err = deviceObj.NetworkInstances.NewNetworkInstance(vrf); err != nil {
            return nil, errors.New("Failed to allocate new network instance object")
        }
    }
    if vrfInstObj.Protocols == nil {
        if is_validate { return nil, errors.New("Protocols object not found") }
        vrfInstObj.Protocols = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols)
    }
    protoKey := ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_Key{
                            Identifier: ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC,
                            Name: "static",
              }
    protoInstObj, ok := vrfInstObj.Protocols.Protocol[protoKey]
    if !ok {
        if is_validate { return nil, errors.New("STATIC Protocol not found") }
        if protoInstObj, err = vrfInstObj.Protocols.NewProtocol(ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, "static"); err != nil {
            return nil, errors.New("Failed to allocate new static protocol object")
        }
    }
    if protoInstObj.StaticRoutes == nil {
        if is_validate { return nil, errors.New("Static routes object not found") }
        protoInstObj.StaticRoutes = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes)
    }

    return protoInstObj.StaticRoutes, nil
}

func verifyIpPrefix(pfx string) error {
    ipAddr, ipNet, err := net.ParseCIDR(pfx)
    if err != nil {
        return tlerr.InvalidArgs("Failed to parse IP prefix")
    }
    if !ipAddr.Equal(ipNet.IP) {
        return tlerr.InvalidArgs("Inconsistent IP address and mask")
    }
    return nil
}

// compose nexthop set based on data of ygot structure
func getYgotNexthopObj(s *ygot.GoStruct, vrf string, prefix string) (map[string]*ipNexthopSet, error) {
    /* Dont construct (by passing is_validate=false in the below function) the YGOT structure 
     * as it can leave the stale STATIC routes entry 
     * in the protocol list for VLAN key (which is invalid for static routes) */
    staticRoutes, err := getYgotStaticRoutesObj(s, vrf, false)
    if err != nil {
        log.Infof("Failed to get ygot nexthop object: %v", err)
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
        err := verifyIpPrefix(ipPrefix)
        if err != nil {
            log.Infof("Invalid IP prefix %s", ipPrefix)
            return nil, err
        }
        pfxIp := parseIPExt(strings.Split(ipPrefix, "/")[0])
        if pfxIp == nil {
            return nil, tlerr.InvalidArgs("Failed to parse prefix IP address: %s", ipPrefix)
        }

        resMap[ipPrefix] = &ipNexthopSet{pfxIp.isIpv4, make(map[string]ipNexthop)}
        for nhIndex, nexthopObj := range routeObj.NextHops.NextHop {
            if nexthopObj == nil {
                continue
            }
            var blackhole bool
            var intfName, nhVrf string
            var tag uint32
            var distance uint32
            var gwIp string
            var track uint16
            if nexthopObj.Config != nil {
                if nexthopObj.Config.Blackhole != nil {
                    blackhole = *nexthopObj.Config.Blackhole
                }
                if nexthopObj.Config.Tag != nil {
                    tag = *nexthopObj.Config.Tag
                }
                if nexthopObj.Config.Metric != nil {
                    distance = *nexthopObj.Config.Metric
                }
                if nexthopObj.Config.NexthopNetworkInstance != nil {
                    nhVrf = *nexthopObj.Config.NexthopNetworkInstance
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
                    gwIp = zeroIp(pfxIp.isIpv4)
                }
                if nexthopObj.Config.Track != nil {
                    track = *nexthopObj.Config.Track
                }
            }
            if nexthopObj.InterfaceRef != nil && nexthopObj.InterfaceRef.Config != nil && nexthopObj.InterfaceRef.Config.Interface != nil {
                intfName = *nexthopObj.InterfaceRef.Config.Interface
            }
            log.Infof("NH[%v]: blackhole %v IP %v interface %v tag %v distance %v VRF %v track %v", nhIndex, blackhole, gwIp, intfName, tag, distance, nhVrf, track)
            nhObj, err := newNexthop(vrf, blackhole, gwIp, intfName, tag, distance, nhVrf, track)
            if err != nil {
                log.Infof("Failed to create nexthop object: %v", err)
                return nil, err
            }
            if len(nhObj.index) == 0 {
                nhObj.index = []string{nhIndex}
            } else if !nhObj.isMatchedIndex(nhIndex) {
                log.Infof("Generated NH index %s does not match given index %s", nhObj.index, nhIndex)
                return nil, tlerr.InvalidArgs("Generated NH index %s does not match given index %s", nhObj.index, nhIndex)
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
    if argCnt < 6 {
        addArgs := 6 - argCnt
        for idx := 0; idx < addArgs; idx ++ {
            strList = append(strList, "")
        }
    }
    var blackhole bool
    if strList[0] == "true" {
        blackhole = true
    }
    var err error
    var distance int64
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
    ifName := strList[2]
    if len(ifName) > 0 {
        ifName = *(utils.GetUINameFromNativeName(&ifName))
    }
    var track uint64
    if len(strList[5]) > 0 {
        track, err = strconv.ParseUint(strList[5], 10, 32)
        if err != nil {
            return nil, err
        }
    }
    var tag uint64
    if len(strList[6]) > 0 {
        tag, err = strconv.ParseUint(strList[6], 10, 32)
        if err != nil {
            return nil, err
        }
    }
    return newNexthop(srcVrf, blackhole, gwIp, ifName, uint32(tag), uint32(distance), strList[4], uint16(track))
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

type routeNexthopInfo struct {
    ygotNhList *ipNexthopSet
    dbNh *dbNexthopInfo
}

// Store nexthop list read from ygot data and config DB for route of VRF
type vrfRouteInfo map[string]map[string]*routeNexthopInfo

func getRouteData(inParams XfmrParams, scope uriScopeType, vrf string, searchPrefix string) (*vrfRouteInfo, error) {
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
    routeData := &vrfRouteInfo{}
    (*routeData)[vrf] = make(map[string]*routeNexthopInfo)
    for prefix, nhs := range srouteObjMap {
        nhList, vrfInKey, err := getNexthopListFromDB(inParams.d, vrf, prefix)
        if err != nil {
            log.Infof("Failed to get nexthops of %s from DB: %v", prefix, err)
            return nil, err
        }
        dbNh := &dbNexthopInfo{vrfInKey, &nhList}
        (*routeData)[vrf][prefix] = &routeNexthopInfo{nhs, dbNh}
    }

    return routeData, nil
}

func (data *vrfRouteInfo)isDataValid(scope uriScopeType, oper int, vrf string) bool {
    vrfRoute, ok := (*data)[vrf]
    if !ok {
        log.Infof("VRF %s not in route data", vrf)
        return false
    }
    if oper == CREATE {
        // check if route already created
        for pfx, route := range vrfRoute {
            if route.dbNh != nil && len(route.dbNh.nhList.nhList) > 0 {
                for key := range route.ygotNhList.nhList {
                    if _, ok := route.dbNh.nhList.nhList[key]; ok {
                        log.Infof("route prefix %s with nexthop %s was already in DB", pfx, key)
                        return false
                    }
                }
            }
        }
    } else if scope != STATIC_ROUTES && oper == DELETE {
        // check if route or nexthop in DB
        for pfx, route := range vrfRoute {
            if route.dbNh == nil || len(route.dbNh.nhList.nhList) == 0 {
                log.Infof("prefix %s not found in DB", pfx)
                return false
            }
            if scope == STATIC_ROUTES_STATIC {
                continue
            }
            for key := range route.ygotNhList.nhList {
                if nh, _ := route.dbNh.nhList.getNexthopByKey(key); nh == nil {
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

var YangToDb_static_routes_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    resMap := make(map[string]map[string]db.Value)
    pathInfo := NewPathInfo(inParams.uri)
    vrf := pathInfo.Var("name")
    if len(vrf) == 0 || (strings.HasPrefix(vrf, "Vlan")) {
        return resMap, nil
    }
    proto := pathInfo.Var("name#2")
    protoId := pathInfo.Var("identifier")
    if !(protoId == "STATIC" && proto == "static") {
        return resMap, nil
    }

    uriScope := getUriScope(inParams.requestUri)
    targetUriPath, _ := getYangPathFromUri(pathInfo.Path)
    log.Infof("YangToDb_static_routes_subtree_xfmr: URI %s, requestURI %s, target URI %s Scope %s",
              inParams.uri, inParams.requestUri, targetUriPath, uriScope)

    ipPrefix := pathInfo.Var("prefix")
    routeData, err := getRouteData(inParams, uriScope, vrf, ipPrefix)
    if err != nil {
        log.Info("Failed to get ygot and DB data")
        return resMap, err
    }
    if !routeData.isDataValid(uriScope, inParams.oper, vrf) {
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
            route := (*routeData)[vrf][ipPrefix]
            nh, _ := route.ygotNhList.getNexthopByKey(nhIndex)
            if nh == nil {
                return resMap, tlerr.InvalidArgs("NH %s not found in ygot data", nhIndex)
            }
            changed, err := route.dbNh.nhList.updateNH(*nh, DELETE)
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
    } else {
        log.Infof("Handling static route configuration for VRF %s prefix %s", vrf, ipPrefix)
        var updSubDataMap = make(RedisDbMap)
        var delSubDataMap = make(RedisDbMap)
        updSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        delSubDataMap[db.ConfigDB] = make(map[string]map[string]db.Value)
        for prefix, routeInfo := range (*routeData)[vrf] {
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
                    if inParams.oper != REPLACE || uriScope == STATIC_ROUTES_NEXTHOP {
                        // add original nexthop to new list
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
            if inParams.subOpDataMap[REPLACE] == nil {
                inParams.subOpDataMap[REPLACE] = &updSubDataMap
            } else {
                for key, val := range updSubDataMap[db.ConfigDB][STATIC_ROUTE_TABLE] {
                    (*inParams.subOpDataMap[REPLACE])[db.ConfigDB][STATIC_ROUTE_TABLE][key] = val
                }
            }
        }
        if len(delSubDataMap[db.ConfigDB]) > 0 {
            if inParams.subOpDataMap[DELETE] == nil {
                inParams.subOpDataMap[DELETE] = &delSubDataMap
            } else {
                for key, val := range delSubDataMap[db.ConfigDB][STATIC_ROUTE_TABLE] {
                    (*inParams.subOpDataMap[DELETE])[db.ConfigDB][STATIC_ROUTE_TABLE][key] = val
                }
            }
        }
    }

    return resMap, nil
}

func setRouteObjWithDbData(inParams XfmrParams, vrf string, prefix string, nhIndex string) error {
    sroutesObj, err := getYgotStaticRoutesObj(inParams.ygRoot, vrf, true)
    if err != nil {
        return err
    }
    ygot.BuildEmptyTree(sroutesObj)

    tblName := "STATIC_ROUTE"
    var cfgDb = inParams.dbs[db.ConfigDB]
    var staticTbl = &db.TableSpec{Name: tblName, CompCt:2}
    var keyPattern = ""
    if len(prefix) > 0 {
        keyPattern = vrf + "|" + prefix
    } else {
        keyPattern = vrf + "|*"
    }
    keys, _ := cfgDb.GetKeysByPattern(staticTbl, keyPattern)
    for _, key := range keys {
        route, dbErr := cfgDb.GetEntry(&db.TableSpec{Name:tblName}, key)
        if dbErr != nil {
            log.Error("DB GetEntry failed for key : ", key)
            continue
        }
        if log.V(3) {
            log.Infof("setRouteObjWithDbData key %v entry %v", key, route)
        }

        prefix = key.Comp[1]
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
        if routeObj.Config == nil {
            routeObj.Config = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_Config)
        }
        if routeObj.State == nil {
            routeObj.State = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_State)
        }
        if routeObj.Config.Prefix == nil {
            routeObj.Config.Prefix = new(string)
        }
        *routeObj.Config.Prefix = prefix
        if routeObj.State.Prefix == nil {
            routeObj.State.Prefix = new(string)
        }
        *routeObj.State.Prefix = prefix
        routeObj.NextHops = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops)
        for _, nh := range nhSet.nhList {
            if len(nhIndex) != 0 && !nh.isMatchedIndex(nhIndex) {
                continue
            }
            outIndex := nh.index[0]
            var nhObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop
            nhObj, ok := routeObj.NextHops.NextHop[outIndex]
            if !ok {
                nhObj, err = routeObj.NextHops.NewNextHop(outIndex)
                if err != nil {
                    log.Infof("Failed to get new nexthop object: %v", err)
                    return err
                }
            }
            if nhObj.Config == nil {
                nhObj.Config = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_Config)
            }
            if nhObj.State == nil {
                nhObj.State = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_State)
            }

            if nhObj.Config.Index == nil {
                nhObj.Config.Index = new(string)
            }
            *nhObj.Config.Index = outIndex
            if nhObj.State.Index == nil {
                nhObj.State.Index = new(string)
            }
            *nhObj.State.Index = outIndex
            if nh.blackhole {
                if nhObj.Config.Blackhole == nil {
                    nhObj.Config.Blackhole = new(bool)
                }
                *nhObj.Config.Blackhole = nh.blackhole
                if nhObj.State.Blackhole == nil {
                    nhObj.State.Blackhole = new(bool)
                }
                *nhObj.State.Blackhole = nh.blackhole
            }
            if !nh.gwIp.isZeros() {
                gwCfgObj, err :=
                    nhObj.Config.To_OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_Config_NextHop_Union(nh.gwIp.origIpStr)
                if err != nil {
                    log.Infof("Failed to get config gateway IP object: %v", err)
                    return err
                }
                nhObj.Config.NextHop = gwCfgObj
                gwStateObj, err :=
                    nhObj.State.To_OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_State_NextHop_Union(nh.gwIp.origIpStr)
                if err != nil {
                    log.Infof("Failed to get state gateway IP object: %v", err)
                    return err
                }
                nhObj.State.NextHop = gwStateObj
            }
            if nh.tag != 0 {
                if nhObj.Config.Tag == nil {
                    nhObj.Config.Tag = new(uint32)
                }
                *nhObj.Config.Tag = nh.tag
                if nhObj.State.Tag == nil {
                    nhObj.State.Tag = new(uint32)
                }
                *nhObj.State.Tag = nh.tag
            }
            if nh.distance != 0 {
                if nhObj.Config.Metric == nil {
                    nhObj.Config.Metric = new(uint32)
                }
                *nhObj.Config.Metric = nh.distance
                if nhObj.State.Metric == nil {
                    nhObj.State.Metric = new(uint32)
                }
                *nhObj.State.Metric = nh.distance
            }
            if len(nh.vrf) > 0 {
                if nhObj.Config.NexthopNetworkInstance == nil {
                    nhObj.Config.NexthopNetworkInstance = new(string)
                }
                *nhObj.Config.NexthopNetworkInstance = nh.vrf
                if nhObj.State.NexthopNetworkInstance == nil {
                    nhObj.State.NexthopNetworkInstance = new(string)
                }
                *nhObj.State.NexthopNetworkInstance = nh.vrf
            }
            if len(nh.ifName) > 0 {
                if nhObj.InterfaceRef == nil {
                    nhObj.InterfaceRef = new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_InterfaceRef)
                }
                if nhObj.InterfaceRef.Config == nil {
                    nhObj.InterfaceRef.Config =
                        new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_InterfaceRef_Config)
                }
                if nhObj.InterfaceRef.State == nil {
                    nhObj.InterfaceRef.State =
                        new(ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Protocols_Protocol_StaticRoutes_Static_NextHops_NextHop_InterfaceRef_State)
                }

                if nhObj.InterfaceRef.Config.Interface == nil {
                    nhObj.InterfaceRef.Config.Interface = new(string)
                }
                *nhObj.InterfaceRef.Config.Interface = nh.ifName
                if nhObj.InterfaceRef.State.Interface == nil {
                    nhObj.InterfaceRef.State.Interface = new(string)
                }
                *nhObj.InterfaceRef.State.Interface = nh.ifName
            }
            if nh.track != 0 {
                if nhObj.Config.Track == nil {
                    nhObj.Config.Track = new(uint16)
                }
                *nhObj.Config.Track = nh.track
                if nhObj.State.Track == nil {
                    nhObj.State.Track = new(uint16)
                }
                *nhObj.State.Track = nh.track
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

func alias_list_value_xfmr(inParams XfmrDbParams) (string, error) {
    if len(inParams.value) == 0 {
        return inParams.value, nil
    }

    ifNameList := strings.Split(inParams.value, ",")
    log.Infof("alias_value_xfmr:- Operation Type - %d Interface list - %s", inParams.oper, ifNameList)
    var aliasList []string
    for _, ifName := range ifNameList {
        var convertedName *string
        if inParams.oper == GET {
            convertedName = utils.GetUINameFromNativeName(&ifName)
        } else {
            convertedName = utils.GetNativeNameFromUIName(&ifName)
        }
        aliasList = append(aliasList, *convertedName)
    }
    return strings.Join(aliasList, ","), nil
}

func Subscribe_static_routes_subtree_xfmr(inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var result XfmrSubscOutParams

    pathInfo := NewPathInfo(inParams.uri)
    var routeKey string
    if pathInfo.HasVar("name") {
        var prefix string
        vrf := pathInfo.Var("name")
        if pathInfo.HasVar("prefix") {
            prefix = pathInfo.Var("prefix")
        } else {
            prefix = "*"
        }
        routeKey = vrf + "|" + prefix
    } else {
        routeKey = "*"
    }

    log.Infof("Subscribe_static_routes_subtree_xfmr: URI %s", inParams.uri)
    result.dbDataMap = RedisDbSubscribeMap{db.ConfigDB: {STATIC_ROUTE_TABLE: {routeKey: {}}}}
    /* The below lines will be used only for subscription on a terminal node */
    result.needCache = true
    result.onChange = OnchangeEnable
    result.nOpts = new(notificationOpts)
    result.nOpts.mInterval = 0
    result.nOpts.pType = OnChange
    return result, nil
}

var DbToYang_static_routes_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    log.Infof("DbToYang_static_routes_subtree_xfmr: URI %s, requestURI %s", inParams.uri, inParams.requestUri)
    pathInfo := NewPathInfo(inParams.uri)
    vrf := pathInfo.Var("name")
    prefix := pathInfo.Var("prefix")
    nhIndex := pathInfo.Var("index")
    err := setRouteObjWithDbData(inParams, vrf, prefix, nhIndex)
    return err
}

func init() {
    XlateFuncBind("static_routes_alias_xfmr", alias_list_value_xfmr)
    XlateFuncBind("YangToDb_static_routes_subtree_xfmr", YangToDb_static_routes_subtree_xfmr)
    XlateFuncBind("DbToYang_static_routes_subtree_xfmr", DbToYang_static_routes_subtree_xfmr)
    XlateFuncBind("Subscribe_static_routes_subtree_xfmr", Subscribe_static_routes_subtree_xfmr)
}
