package transformer

import (
    "fmt"
    "errors"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/openconfig/ygot/ygot"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "strconv"
    "strings"
    log "github.com/golang/glog"
)

const TBL_TRANSCEIVER_INFO = "TRANSCEIVER_INFO"
const TBL_TRANSCEIVER_DOM = "TRANSCEIVER_DOM_SENSOR"

func init () {
    XlateFuncBind("DbToYang_platform_diag_xcvr_dom_xfmr", DbToYang_platform_diag_xcvr_dom_xfmr)
    XlateFuncBind("Subscribe_platform_diag_xcvr_dom_xfmr", Subscribe_platform_diag_xcvr_dom_xfmr)
}

func getXcvrDomRootObject (s *ygot.GoStruct) (*ocbinds.OpenconfigPlatformDiagnostics_TransceiverDom) {
    deviceObj := (*s).(*ocbinds.Device)
    return deviceObj.TransceiverDom
}

func validIntfName(name *string) (bool) {

    if name == nil || *name == "" {
        return false
    }

    if utils.IsAliasModeEnabled() {
        /* Expect interface name of form Ethx/y/z or Ethx/y, where x,y,z are integers */
        return utils.IsValidAliasName(name)
    }

    /* Expect interface name of form EthernetX, where X is an integer */
    if !strings.HasPrefix(*name, "Ethernet"){
        return false
    }

    sp := strings.SplitAfter(*name, "Ethernet")
    if _, err := strconv.Atoi(sp[1]); err != nil {
        return false
    }
    return true
}

// getDbString returns value of a field as *string. Returns nil if not exist.
func getDbString(v db.Value, name string) (*string, bool) {
    data, ok := v.Field[name]
    if ok {
        return &data, ok
    }
    return nil, false
}

var Subscribe_platform_diag_xcvr_dom_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams

    key := NewPathInfo(inParams.uri).Var("ifname")

    log.Infof("+++ Subscribe_platform_diag_xcvr_dom_xfmr (%v) +++", key)

    if key == "" {
        /* no need to verify DB data if we are requesting ALL interfaces */
        result.isVirtualTbl = true
        return result, err
    }
    result.dbDataMap = make(RedisDbSubscribeMap)
    if validIntfName(&key) {
        ifName := key
        if utils.IsAliasModeEnabled() {
            ifName = *(utils.GetNativeNameFromUIName(&key))
        }
        result.dbDataMap = RedisDbSubscribeMap{db.StateDB: {TBL_TRANSCEIVER_DOM:{ifName:{}}}}
    } else {
        log.Info("Invalid interface name ", key)
        return result, errors.New("Invalid interface name")
    }

    return result, err
}

var DbToYang_platform_diag_xcvr_dom_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) (error) {

    var e error
    var v db.Value
    var t db.TableSpec
    var keys []db.Key

    log.Infof("+++ DbToYang_platform_diag_xcvr_dom_xfmr (%v) +++", inParams.requestUri)

    intf := NewPathInfo(inParams.uri).Var("ifname")
    root := getXcvrDomRootObject(inParams.ygRoot)

    ifName := intf
    if utils.IsAliasModeEnabled(){
        ifName = *(utils.GetNativeNameFromUIName(&intf))
    }
    log.Infof("ifname: '%v' --> '%v'", intf, ifName)

    inParams.curDb = db.StateDB
    d := inParams.dbs[db.StateDB]
    if d == nil {
        d, e = db.NewDB(db.Options {
                         DBNo              : db.StateDB,
                         TableNameSeparator: "|",
                         KeySeparator      : "|",
                       })
        if e != nil {
            return nil
        }
        defer d.DeleteDB()
    } else {
        d.Opts.KeySeparator = "|"
        d.Opts.TableNameSeparator = "|"
    }

    t = db.TableSpec { Name: TBL_TRANSCEIVER_INFO }
    if len(ifName) == 0 {
        keys, e = d.GetKeys(&t)
        if e != nil {
            log.Infof("ERR: %v: '%v'", TBL_TRANSCEIVER_INFO, e)
            return e
        }
    } else {
        keys = []db.Key {{ Comp : [] string { ifName } }}
    }

    e = nil
    for i := 0; i < len(keys); i++ {
        var s *string
        var uiName *string
        var info *ocbinds.OpenconfigPlatformDiagnostics_TransceiverDom_TransceiverDomInfo

        name := strings.Join(keys[i].Comp, d.Opts.KeySeparator)
        if len(ifName) == 0 {
            info, _ = root.NewTransceiverDomInfo(name)
        } else {
            info = root.TransceiverDomInfo[intf]
        }
        if info == nil {
            e = errors.New("Invalid Interface Name")
            break
        }
        ygot.BuildEmptyTree(info)
        ygot.BuildEmptyTree(info.Config)
        ygot.BuildEmptyTree(info.State)

        uiName = utils.GetUINameFromNativeName(&name)
        info.Ifname = uiName
        info.Config.Ifname = uiName
        info.State.Ifname = uiName

        t = db.TableSpec { Name: TBL_TRANSCEIVER_INFO }
        v, e = d.GetEntry(&t, db.Key { Comp : [] string { name } })
        if e != nil {
            log.Infof("ERR: %v: '%v'", TBL_TRANSCEIVER_INFO, e)
            continue
        }

        s, _ = getDbString(v, "type_abbrv_name")
        info.State.Type = s
        s, _ = getDbString(v, "manufacturename")
        info.State.Vendor = s
        s, _ = getDbString(v, "modelname")
        info.State.VendorPart = s
        s, _ = getDbString(v, "memory_type")
        info.State.MemoryType = s

        if info.State.Type == nil {
            log.Infof("ERR: 'type' info is missing")
            continue
        }

        t = db.TableSpec { Name: TBL_TRANSCEIVER_DOM }
        v, e = d.GetEntry(&t, db.Key { Comp : [] string { name } })
        if e != nil {
            log.Infof("ERR: %v: '%v'", TBL_TRANSCEIVER_DOM, e)
            continue
        }

        lane_nr := 1
        switch (*info.State.Type) {
        case "QSFP":
            lane_nr = 4
        case "QSFP+":
            lane_nr = 4
        case "QSFP28":
            lane_nr = 4
        case "QSFP-DD":
            lane_nr = 8
        case "OSFP-8X":
            lane_nr = 8
        default:
            lane_nr = 1
        }

        /* rx*power */
        rxpower := ""
        for j := 1; j <= lane_nr; j++ {
            s, _ = getDbString(v, fmt.Sprintf("rx%dpower", j))
            if s != nil {
                if j > 1 {
                    rxpower += "," + *s
                } else {
                    rxpower += *s
                }
            }
        }
        info.State.RxPower = &rxpower

        /* tx*bias */
        txbias := ""
        for j := 1; j <= lane_nr; j++ {
            s, _ = getDbString(v, fmt.Sprintf("tx%dbias", j))
            if s != nil {
                if j > 1 {
                    txbias += "," + *s
                } else {
                    txbias += *s
                }
            }
        }
        info.State.TxBias = &txbias

        /* tx*power */
        txpower := ""
        for j := 1; j <= lane_nr; j++ {
            s, _ = getDbString(v, fmt.Sprintf("tx%dpower", j))
            if s != nil {
                if j > 1 {
                    txpower += "," + *s
                } else {
                    txpower += *s
                }
            }
        }
        info.State.TxPower = &txpower

        s, _ = getDbString(v, "rxpowerhighalarm")
        info.State.AlarmRxPowerHi = s
        s, _ = getDbString(v, "rxpowerlowalarm")
        info.State.AlarmRxPowerLo = s
        s, _ = getDbString(v, "txbiashighalarm")
        info.State.AlarmTxBiasHi = s
        s, _ = getDbString(v, "txbiaslowalarm")
        info.State.AlarmTxBiasLo = s
        s, _ = getDbString(v, "txpowerhighalarm")
        info.State.AlarmTxPowerHi = s
        s, _ = getDbString(v, "txpowerlowalarm")
        info.State.AlarmTxPowerLo = s
        s, _ = getDbString(v, "temphighalarm")
        info.State.AlarmTempHi = s
        s, _ = getDbString(v, "templowalarm")
        info.State.AlarmTempLo = s
        s, _ = getDbString(v, "vcchighalarm")
        info.State.AlarmVoltHi = s
        s, _ = getDbString(v, "vcclowalarm")
        info.State.AlarmVoltLo = s

        s, _ = getDbString(v, "rxpowerhighwarning")
        info.State.WarningRxPowerHi = s
        s, _ = getDbString(v, "rxpowerlowwarning")
        info.State.WarningRxPowerLo = s
        s, _ = getDbString(v, "txbiashighwarning")
        info.State.WarningTxBiasHi = s
        s, _ = getDbString(v, "txbiaslowwarning")
        info.State.WarningTxBiasLo = s
        s, _ = getDbString(v, "txpowerhighwarning")
        info.State.WarningTxPowerHi = s
        s, _ = getDbString(v, "txpowerlowwarning")
        info.State.WarningTxPowerLo = s
        s, _ = getDbString(v, "temphighwarning")
        info.State.WarningTempHi = s
        s, _ = getDbString(v, "templowwarning")
        info.State.WarningTempLo = s
        s, _ = getDbString(v, "vcchighwarning")
        info.State.WarningVoltHi = s
        s, _ = getDbString(v, "vcclowwarning")
        info.State.WarningVoltLo = s

        s, _ = getDbString(v, "temperature")
        info.State.Temperature = s
        s, _ = getDbString(v, "voltage")
        info.State.Voltage = s
        s, _ = getDbString(v, "timestamp")
        info.State.Timestamp = s
    }

    return e
}

