package transformer

import (
	"errors"
	"strings"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	"encoding/hex"
	"strconv"
)

const (
    LLDP_REMOTE_CAP_ENABLED     = "lldp_rem_sys_cap_enabled"
    LLDP_REMOTE_SYS_NAME        = "lldp_rem_sys_name"
    LLDP_REMOTE_PORT_DESC       = "lldp_rem_port_desc"
    LLDP_REMOTE_CHASS_ID        = "lldp_rem_chassis_id"
    LLDP_REMOTE_CAP_SUPPORTED   = "lldp_rem_sys_cap_supported"
    LLDP_REMOTE_PORT_ID_SUBTYPE = "lldp_rem_port_id_subtype"
    LLDP_REMOTE_SYS_DESC        = "lldp_rem_sys_desc"
    LLDP_REMOTE_REM_TIME        = "lldp_rem_time_mark"
    LLDP_REMOTE_PORT_ID         = "lldp_rem_port_id"
    LLDP_REMOTE_REM_ID          = "lldp_rem_index"
    LLDP_REMOTE_CHASS_ID_SUBTYPE = "lldp_rem_chassis_id_subtype"
    LLDP_REMOTE_MAN_ADDR        = "lldp_rem_man_addr"
    LLDP_REMOTE_TTL             = "lldp_rem_ttl"
)

func init() {
	XlateFuncBind("YangToDb_lldp_global_key_xfmr", YangToDb_lldp_global_key_xfmr)
	XlateFuncBind("YangToDb_suppress_tlv_adv_xfmr", YangToDb_suppress_tlv_adv_xfmr)
	XlateFuncBind("DbToYang_suppress_tlv_adv_xfmr", DbToYang_suppress_tlv_adv_xfmr)
	XlateFuncBind("YangToDb_lldp_intf_xfmr", YangToDb_lldp_intf_xfmr)
	XlateFuncBind("DbToYang_lldp_intf_xfmr", DbToYang_lldp_intf_xfmr)
}

var YangToDb_lldp_global_key_xfmr = func(inParams XfmrParams) (string, error) {
	log.Info("YangToDb_lldp_global_key_xfmr: ", inParams.ygRoot, inParams.uri)
	return "GLOBAL", nil
}

func getLldpRoot (s *ygot.GoStruct) *ocbinds.OpenconfigLldp_Lldp {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.Lldp
}

var YangToDb_suppress_tlv_adv_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error

	lldpObj := getLldpRoot(inParams.ygRoot)
	if lldpObj == nil || lldpObj.Config == nil {
		log.Info("YangToDb_suppress_tlv_adv_xfmr: lldpObj/Config is empty.")
		return res_map, errors.New("LldpObj/Config is not specified")
	}

	for _, tlv := range lldpObj.Config.SuppressTlvAdvertisement {
		if tlv == ocbinds.OpenconfigLldpTypes_LLDP_TLV_MANAGEMENT_ADDRESS {
			res_map["supp_mgmt_address_tlv"] = "true"
		} 
		if tlv == ocbinds.OpenconfigLldpTypes_LLDP_TLV_SYSTEM_CAPABILITIES {
			res_map["supp_system_capabilities_tlv"] = "true"
		}
	}

	log.Info("YangToDb_intf_name_xfm: res_map:", res_map)
    return res_map, err
}

var DbToYang_suppress_tlv_adv_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	res_map := make(map[string]interface{})
	//suppressTlv := make(map[string])
	//var suppressTlv []ocbinds.E_OpenconfigLldpTypes_LLDP_TLV
	var suppressTlv []string
	var tlv ocbinds.E_OpenconfigLldpTypes_LLDP_TLV

	entry, err := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name: "LLDP"}, db.Key{Comp: []string{"GLOBAL"}})
	if err == nil {
		if entry.Get("supp_mgmt_address_tlv") == "true" {
			tlv = ocbinds.OpenconfigLldpTypes_LLDP_TLV_MANAGEMENT_ADDRESS
        	suppressTlv = append(suppressTlv, ocbinds.E_OpenconfigLldpTypes_LLDP_TLV.ΛMap(tlv)["E_OpenconfigLldpTypes_LLDP_TLV"][int64(tlv)].Name)
			//suppressTlv = append(suppressTlv, tlv)
		}

		if entry.Get("supp_system_capabilities_tlv") == "true" {
			tlv = ocbinds.OpenconfigLldpTypes_LLDP_TLV_SYSTEM_CAPABILITIES
        	suppressTlv = append(suppressTlv, ocbinds.E_OpenconfigLldpTypes_LLDP_TLV.ΛMap(tlv)["E_OpenconfigLldpTypes_LLDP_TLV"][int64(tlv)].Name)
			//suppressTlv = append(suppressTlv, tlv)
		}

		log.Info("suppressTlv: ", suppressTlv)
		res_map["suppress-tlv-advertisement"] = suppressTlv
	}

	return res_map, nil
}

var YangToDb_lldp_intf_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	resMap := make(map[string]map[string]db.Value)

	lldpObj := getLldpRoot(inParams.ygRoot)
	if lldpObj == nil || lldpObj.Interfaces == nil {
		log.Info("YangToDb_lldp_intf_xfmr: lldpObj/interface list is empty.")
		return resMap, errors.New("LldpObj/Interface is not specified")
	}

	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("name")

	if ifName == "" {
		errStr := "Interface KEY not present"
		log.Info("YangToDb_lldp_intf_xfmr: " + errStr)
		return resMap, errors.New(errStr)
	}

	if _, ok := lldpObj.Interfaces.Interface[ifName]; !ok {
		errStr := "Interface entry not found in Ygot tree, ifname: " + ifName
		log.Info("YangToDb_lldp_intf_xfmr : " + errStr)
		return resMap, errors.New(errStr)
	}

	lldpIntfObj := lldpObj.Interfaces.Interface[ifName]
	if lldpIntfObj.Config != nil {
		dataMap := make(map[string]string)
		var value db.Value

		if lldpIntfObj.Config.Enabled != nil {
			if *lldpIntfObj.Config.Enabled {
				dataMap["enabled"] = "true"
			} else {
				dataMap["enabled"] = "false"
			}
		}

		if lldpIntfObj.Config.Mode == ocbinds.OpenconfigLldpExt_LldpExtModeType_RECEIVE {
			dataMap["mode"] = "RECEIVE"
		} else if lldpIntfObj.Config.Mode == ocbinds.OpenconfigLldpExt_LldpExtModeType_TRANSMIT {
			dataMap["mode"] = "TRANSMIT"
		}

		value = db.Value{Field: dataMap}
		if _, ok := resMap["LLDP_PORT"]; !ok {
			resMap["LLDP_PORT"] = make(map[string]db.Value)
		}
		resMap["LLDP_PORT"][ifName] = value
	}

	log.Info("YangToDb_lldp_intf_xfmr : resMap : ", resMap)
	return resMap, err
}

var DbToYang_lldp_intf_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) (error) {
	var err error

	log.Info("DbToYang_lldp_intf_xfmr")

	lldpObj := getLldpRoot(inParams.ygRoot)
	targetUriPath, err := getYangPathFromUri(inParams.uri)

	pathInfo := NewPathInfo(inParams.uri)
	ifName := pathInfo.Var("name")

	log.Info("targetUriPath is ", targetUriPath)
	log.Info("ifName ", ifName)
	if ifName == "" {
		log.Info("ifName NULL")
		err = errors.New("ifName NULL")
		return err
	}

	if lldpObj.Interfaces == nil {
		log.Info("Interfaces == nil")
		ygot.BuildEmptyTree(lldpObj)
		ygot.BuildEmptyTree(lldpObj.Interfaces)
	}
	intfsObj := lldpObj.Interfaces

	intfObj, ok := intfsObj.Interface[ifName]
	if !ok {
		log.Info("create new interface")
		intfObj, err = intfsObj.NewInterface(ifName)
		if err != nil {
			log.Info("Creation of interface subtree failed!")
			return err
		}
		log.Info("init interface obj")
		ygot.BuildEmptyTree(intfObj)
	}

	if strings.HasPrefix(targetUriPath, "/openconfig-lldp:lldp/interfaces/interface/config") {
		getLldpIntfEntry(inParams, false, ifName, intfObj)
	} else if strings.HasPrefix(targetUriPath, "/openconfig-lldp:lldp/interfaces/interface/state") {
		getLldpIntfEntry(inParams, true, ifName, intfObj)
	} else if strings.HasPrefix(targetUriPath, "/openconfig-lldp:lldp/interfaces/interface/neighbors"){
		getLldpNeighborEntry(inParams, ifName, intfObj)
	} else {
		log.Info("Invalid Request")
	}

	return err
}

func getLldpIntfEntry(inParams XfmrParams, isState bool, ifName string, intfObj *ocbinds.OpenconfigLldp_Lldp_Interfaces_Interface) error {

	var lldpIntfState *ocbinds.OpenconfigLldp_Lldp_Interfaces_Interface_State
	var lldpIntfCfg *ocbinds.OpenconfigLldp_Lldp_Interfaces_Interface_Config

	log.Info("getLldpIntfEntry: ", ifName, isState, intfObj)
	lldpEntry, err := inParams.dbs[db.ConfigDB].GetEntry(&db.TableSpec{Name: "LLDP_PORT"}, db.Key{Comp: []string{ifName}})
	if err != nil {
		log.Info("can't access LLDP_PORT table for ifName: ", ifName)
		errStr := "Can't access LLDP_PORT table"
		return errors.New(errStr)
	}

	if isState {
		if intfObj.State == nil {
			log.Info("lldpIntfState == nil")
			ygot.BuildEmptyTree(intfObj)
		}
		lldpIntfState = intfObj.State
		ygot.BuildEmptyTree(lldpIntfState)
	} else {
		if intfObj.Config == nil {
			log.Info("lldpIntfCfg == nil")
			ygot.BuildEmptyTree(intfObj)
		}
		lldpIntfCfg = intfObj.Config
		ygot.BuildEmptyTree(lldpIntfCfg)
	}

	if lldpEntry.Has("enabled") {
		log.Info("Has enabled")
		value := false
		if lldpEntry.Get("enabled") == "true" {
			value = true
		}
		if !isState {
			lldpIntfCfg.Enabled = &value
		} else {
			lldpIntfState.Enabled = &value
		}
	}

	if lldpEntry.Has("mode") {
		if lldpEntry.Get("mode") == "RECEIVE" {
			if !isState {
				lldpIntfCfg.Mode = ocbinds.OpenconfigLldpExt_LldpExtModeType_RECEIVE
			} else {
				lldpIntfState.Mode = ocbinds.OpenconfigLldpExt_LldpExtModeType_RECEIVE
			}
		} else {
			if !isState {
				lldpIntfCfg.Mode = ocbinds.OpenconfigLldpExt_LldpExtModeType_TRANSMIT
			} else {
				lldpIntfState.Mode = ocbinds.OpenconfigLldpExt_LldpExtModeType_TRANSMIT
			}
		}
	}

	return err
}

func getLldpNeighborEntry(inParams XfmrParams, ifName string, intfObj *ocbinds.OpenconfigLldp_Lldp_Interfaces_Interface) error {

	log.Info("getLldpNeighborEntry: ", ifName, intfObj)
	lldpNbrEntry, err := inParams.dbs[db.ApplDB].GetEntry(&db.TableSpec{Name: "LLDP_ENTRY_TABLE"}, db.Key{Comp: []string{ifName}})
	if err != nil {
		log.Info("can't access neighbor table for ifName: ", ifName)
		return nil
	}

	if intfObj.Neighbors == nil {
		log.Info("Neighbors == nil")
		ygot.BuildEmptyTree(intfObj)
		ygot.BuildEmptyTree(intfObj.Neighbors)
	}

	nbrObj, ok := intfObj.Neighbors.Neighbor[ifName]
	if !ok {
		ifStdName := utils.GetUINameFromNativeName(&ifName)
		nbrObj, err = intfObj.Neighbors.NewNeighbor(*ifStdName)
		if err != nil {
			log.Info("Creation of neighbor failed!")
			return err
		}
	}
	ygot.BuildEmptyTree(nbrObj)

	for attr := range lldpNbrEntry.Field {
		log.Info("LLDP Attr: ", attr)
		value := lldpNbrEntry.Get(attr)
		log.Info("LLDP Val : ", value)
		switch attr {
		case LLDP_REMOTE_CAP_ENABLED:
			if (len(value) == 0) {
				continue
			}
			num_str := strings.Split(value, " ")
			byte, _ := hex.DecodeString(num_str[0] + num_str[1])
			sysCap := byte[0]
			sysCap |= byte[1]

			log.Info("sysCap: ", sysCap)
			if (sysCap & (128 >> 1)) != 0  {
				repeaterCap := true
				capInfo, err :=  nbrObj.Capabilities.NewCapability(5)
				if err == nil  {
					ygot.BuildEmptyTree(capInfo)
					capInfo.State.Name = 5
					capInfo.State.Enabled = &repeaterCap
				}
			}
			if (sysCap & (128 >> 2)) != 0 {
				bridgeCap := true
				capInfo, err :=  nbrObj.Capabilities.NewCapability(3)
				if err == nil  {
					ygot.BuildEmptyTree(capInfo)
					capInfo.State.Name = 3
					capInfo.State.Enabled = &bridgeCap
				}
			}
			if (sysCap & (128 >> 4)) != 0 {
				routerCap := true
				capInfo, err :=  nbrObj.Capabilities.NewCapability(6)
				if err == nil  {
					ygot.BuildEmptyTree(capInfo)
					capInfo.State.Name = 6
					capInfo.State.Enabled = &routerCap
				}
			}
		case LLDP_REMOTE_SYS_NAME:
			name  := new(string)
			*name  = value
			nbrObj.State.SystemName = name
		case LLDP_REMOTE_PORT_DESC:
			pdescr := new(string)
			*pdescr = value
			nbrObj.State.PortDescription = pdescr
		case LLDP_REMOTE_CHASS_ID:
			chId := new (string)
			*chId = value
			nbrObj.State.ChassisId = chId
		case LLDP_REMOTE_PORT_ID_SUBTYPE:
			remPortIdTypeVal, err :=  strconv.Atoi(value)
			if err == nil {
				nbrObj.State.PortIdType =ocbinds.E_OpenconfigLldp_PortIdType(remPortIdTypeVal)
			}
		case LLDP_REMOTE_SYS_DESC:
			sdesc:= new(string)
			*sdesc = value
			nbrObj.State.SystemDescription = sdesc
		case LLDP_REMOTE_REM_TIME:
		/* Ignore Remote System time */
		case LLDP_REMOTE_PORT_ID:
			remPortIdPtr := new(string)
			*remPortIdPtr = value
			nbrObj.State.PortId = remPortIdPtr
		case LLDP_REMOTE_REM_ID:
			Id := new(string)
			*Id = value
			nbrObj.State.Id = Id
		case LLDP_REMOTE_CHASS_ID_SUBTYPE:
			remChassIdTypeVal , err:=strconv.Atoi(value)
			if err  == nil {
				nbrObj.State.ChassisIdType =ocbinds.E_OpenconfigLldp_ChassisIdType(remChassIdTypeVal)
			}
		case LLDP_REMOTE_MAN_ADDR:
			mgmtAdr:= new(string)
			*mgmtAdr = value
			nbrObj.State.ManagementAddress = mgmtAdr
		case LLDP_REMOTE_TTL:
			ttl, _:= strconv.Atoi(value) 
			ttlCast:= uint16(ttl)
			nbrObj.State.Ttl = &ttlCast
		default:
			log.Info("Not a valid attribute!")
		}
	}

	return err
}
