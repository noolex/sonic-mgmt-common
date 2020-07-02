////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Dell, Inc.                                                 //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//  http://www.apache.org/licenses/LICENSE-2.0                                //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/Azure/sonic-mgmt-common/translib/utils"
	log "github.com/golang/glog"
	"github.com/openconfig/ygot/ygot"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func init() {
	XlateFuncBind("YangToDb_ptp_entry_key_xfmr", YangToDb_ptp_entry_key_xfmr)
	XlateFuncBind("DbToYang_ptp_entry_key_xfmr", DbToYang_ptp_entry_key_xfmr)
	XlateFuncBind("YangToDb_ptp_port_ds_xfmr", YangToDb_ptp_port_ds_xfmr)
	XlateFuncBind("DbToYang_ptp_port_ds_xfmr", DbToYang_ptp_port_ds_xfmr)
	XlateFuncBind("YangToDb_ptp_global_key_xfmr", YangToDb_ptp_global_key_xfmr)
	XlateFuncBind("DbToYang_ptp_global_key_xfmr", DbToYang_ptp_global_key_xfmr)

	XlateFuncBind("YangToDb_ptp_tcport_entry_key_xfmr", YangToDb_ptp_tcport_entry_key_xfmr)
	XlateFuncBind("DbToYang_ptp_tcport_entry_key_xfmr", DbToYang_ptp_tcport_entry_key_xfmr)
	XlateFuncBind("YangToDb_ptp_clock_identity_xfmr", YangToDb_ptp_clock_identity_xfmr)
	XlateFuncBind("DbToYang_ptp_clock_identity_xfmr", DbToYang_ptp_clock_identity_xfmr)
	XlateFuncBind("YangToDb_ptp_boolean_xfmr", YangToDb_ptp_boolean_xfmr)
	XlateFuncBind("DbToYang_ptp_boolean_xfmr", DbToYang_ptp_boolean_xfmr)
	XlateFuncBind("YangToDb_ptp_inst_number_xfmr:", YangToDb_ptp_inst_number_xfmr)
	XlateFuncBind("DbToYang_ptp_inst_number_xfmr:", DbToYang_ptp_inst_number_xfmr)

	XlateFuncBind("YangToDb_ptp_network_transport_xfmr", YangToDb_ptp_network_transport_xfmr)
	XlateFuncBind("DbToYang_ptp_network_transport_xfmr", DbToYang_ptp_network_transport_xfmr)
	XlateFuncBind("YangToDb_ptp_domain_number_xfmr", YangToDb_ptp_domain_number_xfmr)
	XlateFuncBind("DbToYang_ptp_domain_number_xfmr", DbToYang_ptp_domain_number_xfmr)
	XlateFuncBind("YangToDb_ptp_clock_type_xfmr", YangToDb_ptp_clock_type_xfmr)
	XlateFuncBind("DbToYang_ptp_clock_type_xfmr", DbToYang_ptp_clock_type_xfmr)
	XlateFuncBind("YangToDb_ptp_domain_profile_xfmr", YangToDb_ptp_domain_profile_xfmr)
	XlateFuncBind("DbToYang_ptp_domain_profile_xfmr", DbToYang_ptp_domain_profile_xfmr)
	XlateFuncBind("YangToDb_ptp_unicast_multicast_xfmr", YangToDb_ptp_unicast_multicast_xfmr)
	XlateFuncBind("DbToYang_ptp_unicast_multicast_xfmr", DbToYang_ptp_unicast_multicast_xfmr)
	XlateFuncBind("YangToDb_ptp_udp6_scope_xfmr", YangToDb_ptp_udp6_scope_xfmr)
	XlateFuncBind("DbToYang_ptp_udp6_scope_xfmr", DbToYang_ptp_udp6_scope_xfmr)
}

var PTP_DELAY_MECH_MAP = map[string]string{
	strconv.FormatInt(int64(ocbinds.IETFPtp_DelayMechanismEnumeration_e2e), 10):   "E2E",
	strconv.FormatInt(int64(ocbinds.IETFPtp_DelayMechanismEnumeration_p2p), 10):   "P2P",
	strconv.FormatInt(int64(ocbinds.IETFPtp_DelayMechanismEnumeration_UNSET), 10): "Auto",
}

type ptp_id_bin [8]byte

type E_Ptp_AddressTypeEnumeration int64

const (
	PTP_ADDRESSTYPE_UNKNOWN E_Ptp_AddressTypeEnumeration = 0
	PTP_ADDRESSTYPE_IP_IPV4 E_Ptp_AddressTypeEnumeration = 2
	PTP_ADDRESSTYPE_IP_IPV6 E_Ptp_AddressTypeEnumeration = 3
	PTP_ADDRESSTYPE_IP_MAC  E_Ptp_AddressTypeEnumeration = 4
)

func check_address(address string) E_Ptp_AddressTypeEnumeration {
	trial := net.ParseIP(address)
	if trial != nil {
		if trial.To4() != nil {
			return PTP_ADDRESSTYPE_IP_IPV4
		}
		if strings.Contains(address, ":") {
			return PTP_ADDRESSTYPE_IP_IPV6
		}
	} else {
		matched, _ := regexp.Match(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`, []byte(address))
		if matched {
			return PTP_ADDRESSTYPE_IP_MAC
		}
		return PTP_ADDRESSTYPE_UNKNOWN
	}
	return PTP_ADDRESSTYPE_UNKNOWN
}

// ParseIdentity parses an s with the following format
// 010203.0405.060708
func ParseIdentity(s string) (ptp_id ptp_id_bin, err error) {
	if len(s) < 18 {
		return ptp_id, fmt.Errorf("Invalid input identity string %s", s)
	}
	fmt.Sscanf(s, "%02x%02x%02x.%02x%02x.%02x%02x%02x", &ptp_id[0], &ptp_id[1], &ptp_id[2], &ptp_id[3], &ptp_id[4], &ptp_id[5], &ptp_id[6], &ptp_id[7])
	return ptp_id, err
}

var YangToDb_ptp_entry_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var entry_key string
	var err error
	log.Info("YangToDb_ptp_entry_key_xfmr: ", inParams.ygRoot, " XPath ", inParams.uri, " key: ", inParams.key)
	pathInfo := NewPathInfo(inParams.uri)
	log.Info("YangToDb_ptp_entry_key_xfmr len(pathInfo.Vars): ", len(pathInfo.Vars))
	if len(pathInfo.Vars) < 1 {
		err = errors.New("Invalid xpath, key attributes not found")
		return entry_key, err
	}

	inkey, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	if inkey > 0 {
		err = errors.New("Invalid input instance-number")
		return entry_key, err
	}

	entry_key = "GLOBAL"

	log.Info("YangToDb_ptp_entry_key_xfmr - entry_key : ", entry_key)

	return entry_key, err
}

var DbToYang_ptp_entry_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	var err error
	log.Info("DbToYang_ptp_entry_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)
	// rmap["instance-number"] = 0
	return rmap, err
}

var YangToDb_ptp_global_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var entry_key string
	var err error
	log.Info("YangToDb_ptp_global_key_xfmr: ", inParams.ygRoot, inParams.uri)

	entry_key = "GLOBAL"

	log.Info("YangToDb_ptp_global_key_xfmr - entry_key : ", entry_key)

	return entry_key, err
}

var DbToYang_ptp_global_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	var err error
	log.Info("DbToYang_ptp_global_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)
	rmap["instance-number"] = 0
	return rmap, err
}

var YangToDb_ptp_tcport_entry_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
	var entry_key string
	var err error
	log.Info("YangToDb_ptp_tcport_entry_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	log.Info("YangToDb_ptp_tcport_entry_key_xfmr len(pathInfo.Vars): ", len(pathInfo.Vars))
	if len(pathInfo.Vars) < 1 {
		err = errors.New("Invalid xpath, key attributes not found")
		return entry_key, err
	}

	log.Info("YangToDb_ptp_tcport_entry_key_xfmr pathInfo.Var:port-number: ", pathInfo.Var("port-number"))
	entry_key = "Ethernet" + pathInfo.Var("port-number")

	log.Info("YangToDb_ptp_tcport_entry_key_xfmr - entry_key : ", entry_key)

	return entry_key, err
}

var DbToYang_ptp_tcport_entry_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	rmap := make(map[string]interface{})
	var err error
	log.Info("DbToYang_ptp_tcport_entry_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)

	entry_key := inParams.key
	log.Info("DbToYang_ptp_tcport_entry_key_xfmr: ", entry_key)

	portName := entry_key
	port_num := strings.Replace(portName, "Ethernet", "", 1)
	rmap["port-number"], _ = strconv.ParseInt(port_num, 10, 16)
	log.Info("DbToYang_ptp_tcport_entry_key_xfmr port-number: ", port_num)
	return rmap, err
}

func getPtpRoot(s *ygot.GoStruct) *ocbinds.IETFPtp_Ptp {
	deviceObj := (*s).(*ocbinds.Device)
	return deviceObj.Ptp
}

var YangToDb_ptp_clock_identity_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var field string
	var identity []byte
	if inParams.param == nil {
		log.Info("YangToDb_ptp_clock_identity_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_clock_identity_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_clock_identity_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	log.Info("YangToDb_ptp_clock_identity_xfmr instance-number: ", pathInfo.Var("instance-number"))
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)

	ptpObj := getPtpRoot(inParams.ygRoot)

	if strings.Contains(inParams.uri, "grandmaster-identity") {
		identity = ptpObj.InstanceList[uint32(instance_id)].ParentDs.GrandmasterIdentity
		field = "grandmaster-identity"
	} else if strings.Contains(inParams.uri, "parent-port-identity") {
		identity = ptpObj.InstanceList[uint32(instance_id)].ParentDs.ParentPortIdentity.ClockIdentity
		field = "clock-identity"
		// } else if strings.Contains(inParams.uri, "transparent-clock-default-ds") {
		// identity = ptpObj.TransparentClockDefaultDs.ClockIdentity
		// field = "clock-identity"
	} else if strings.Contains(inParams.uri, "default-ds") {
		identity = ptpObj.InstanceList[uint32(instance_id)].DefaultDs.ClockIdentity
		field = "clock-identity"
	}

	if len(identity) >= 8 {
		enc := fmt.Sprintf("%02x%02x%02x.%02x%02x.%02x%02x%02x",
			identity[0], identity[1], identity[2], identity[3], identity[4], identity[5], identity[6], identity[7])

		log.Info("YangToDb_ptp_clock_identity_xfmr enc: ", enc, " field: ", field)
		res_map[field] = enc
	}

	return res_map, err
}

var DbToYang_ptp_clock_identity_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var ptp_id ptp_id_bin
	var field, identity, sEnc string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_clock_identity_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	if strings.Contains(inParams.uri, "grandmaster-identity") {
		field = "grandmaster-identity"
		identity = data["PTP_PARENTDS"][inParams.key].Field[field]
	} else if strings.Contains(inParams.uri, "parent-port-identity") {
		field = "clock-identity"
		identity = data["PTP_PARENTDS"][inParams.key].Field[field]
	} else if strings.Contains(inParams.uri, "transparent-clock-default-ds") {
		field = "clock-identity"
		identity = data["PTP_TC_CLOCK"][inParams.key].Field[field]
	} else if strings.Contains(inParams.uri, "default-ds") {
		field = "clock-identity"
		identity = data["PTP_CLOCK"][inParams.key].Field[field]
	}
	if len(identity) >= 18 {
		ptp_id, err = ParseIdentity(identity)
		sEnc = b64.StdEncoding.EncodeToString(ptp_id[:])
		result[field] = sEnc
	} else {
		sEnc = ""
	}

	return result, err
}

var YangToDb_ptp_boolean_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var err error
	var outval string
	if inParams.param == nil {
		log.Info("YangToDb_ptp_boolean_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_boolean_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_boolean_xfmr inParams.key: ", inParams.key)
	log.Info("YangToDb_ptp_boolean_xfmr inParams.curDb: ", inParams.curDb)

	inval, _ := inParams.param.(*bool)
	_, field := filepath.Split(inParams.uri)
	log.Info("YangToDb_ptp_boolean_xfmr inval: ", *inval, " field: ", field)

	if *inval {
		outval = "1"
	} else {
		outval = "0"
	}

	log.Info("YangToDb_ptp_boolean_xfmr outval: ", outval, " field: ", field)
	res_map[field] = outval
	return res_map, err
}

var DbToYang_ptp_boolean_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})
	var inval string
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_boolean_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)

	_, field := filepath.Split(inParams.uri)
	if field == "two-step-flag" {
		inval = data["PTP_CLOCK"][inParams.key].Field[field]
	} else if field == "slave-only" {
		inval = data["PTP_CLOCK"][inParams.key].Field[field]
	} else if field == "parent-stats" {
		inval = data["PTP_PARENTDS"][inParams.key].Field[field]
	} else if field == "current-utc-offset-valid" {
		inval = data["PTP_TIMEPROPDS"][inParams.key].Field[field]
	} else if field == "leap59" {
		inval = data["PTP_TIMEPROPDS"][inParams.key].Field[field]
	} else if field == "leap61" {
		inval = data["PTP_TIMEPROPDS"][inParams.key].Field[field]
	} else if field == "time-traceable" {
		inval = data["PTP_TIMEPROPDS"][inParams.key].Field[field]
	} else if field == "frequency-traceable" {
		inval = data["PTP_TIMEPROPDS"][inParams.key].Field[field]
	} else if field == "ptp-timescale" {
		inval = data["PTP_TIMEPROPDS"][inParams.key].Field[field]
	} else if field == "faulty-flag" {
		inval = data["PTP_TC_PORT"][inParams.key].Field[field]
	}

	if inval == "0" {
		result[field] = false
	} else if inval == "1" {
		result[field] = true
	}

	return result, err
}

var YangToDb_ptp_inst_number_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	res_map["NULL"] = "NULL"
	return res_map, nil
}

var DbToYang_ptp_inst_number_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	/* do nothing */
	var err error
	result := make(map[string]interface{})
	return result, err
}

var YangToDb_ptp_network_transport_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var outval string
	var err error
	if inParams.param == nil {
		log.Info("YangToDb_ptp_network_transport_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_network_transport_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_network_transport_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	log.Info("YangToDb_ptp_network_transport_xfmr instance_number : ", instance_id)

	ptpObj := getPtpRoot(inParams.ygRoot)
	outval = *ptpObj.InstanceList[uint32(instance_id)].DefaultDs.NetworkTransport
	log.Info("YangToDb_ptp_network_transport_xfmr outval: ", outval)
	_, field := filepath.Split(inParams.uri)
	domain_profile := ""

	ts := db.TableSpec{Name: "PTP_CLOCK"}
	ca := make([]string, 1)

	ca[0] = "GLOBAL"
	akey := db.Key{Comp: ca}
	entry, _ := inParams.d.GetEntry(&ts, akey)
	if entry.Has("domain-profile") {
		domain_profile = entry.Get("domain-profile")
	}

	log.Info("YangToDb_ptp_network_transport_xfmr domain_profile : ", domain_profile)

	if outval == "L2" && domain_profile == "G.8275.x" {
		return res_map, tlerr.InvalidArgsError{Format: "L2 not supported with G.8275.2"}
	}

	log.Info("YangToDb_ptp_network_transport_xfmr outval: ", outval, " field: ", field)
	res_map[field] = outval
	return res_map, nil
}

var DbToYang_ptp_network_transport_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_network_transport_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)
	log.Info("DbToYang_ptp_network_transport_xfmr inParams.key: ", inParams.key)

	_, field := filepath.Split(inParams.uri)
	log.Info("DbToYang_ptp_network_transport_xfmr field: ", field)
	value := data["PTP_CLOCK"][inParams.key].Field[field]
	result[field] = value
	log.Info("DbToYang_ptp_network_transport_xfmr value: ", value)
	return result, err
}

var YangToDb_ptp_domain_number_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var outval uint8
	var err error
	if inParams.param == nil {
		log.Info("YangToDb_ptp_domain_number_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_domain_number_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_domain_number_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	log.Info("YangToDb_ptp_domain_number_xfmr instance_number : ", instance_id)

	ptpObj := getPtpRoot(inParams.ygRoot)
	outval = *ptpObj.InstanceList[uint32(instance_id)].DefaultDs.DomainNumber
	log.Info("YangToDb_ptp_domain_number_xfmr outval: ", outval)
	_, field := filepath.Split(inParams.uri)
	domain_profile := ""

	ts := db.TableSpec{Name: "PTP_CLOCK"}
	ca := make([]string, 1)

	ca[0] = "GLOBAL"
	akey := db.Key{Comp: ca}
	entry, _ := inParams.d.GetEntry(&ts, akey)
	if entry.Has("domain-profile") {
		domain_profile = entry.Get("domain-profile")
	}

	log.Info("YangToDb_ptp_domain_number_xfmr domain_profile : ", domain_profile)

	if domain_profile == "G.8275.x" {
		if outval < 44 || outval > 63 {
			return res_map, tlerr.InvalidArgsError{Format: "domain must be in range 44-63 with G.8275.2"}
		}
	}

	log.Info("YangToDb_ptp_domain_number_xfmr outval: ", outval, " field: ", field)
	res_map[field] = strconv.FormatInt(int64(outval), 10)
	return res_map, nil
}

var DbToYang_ptp_domain_number_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_domain_number_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)
	log.Info("DbToYang_ptp_domain_number_xfmr inParams.key: ", inParams.key)

	_, field := filepath.Split(inParams.uri)
	log.Info("DbToYang_ptp_domain_number_xfmr field: ", field)
	value := data["PTP_CLOCK"][inParams.key].Field[field]
	result[field], _ = strconv.ParseUint(value, 10, 64)
	log.Info("DbToYang_ptp_domain_number_xfmr value: ", value)
	return result, err
}

var YangToDb_ptp_clock_type_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var outval string
	var err error
	if inParams.param == nil {
		log.Info("YangToDb_ptp_clock_type_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_clock_type_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_clock_type_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	log.Info("YangToDb_ptp_clock_type_xfmr instance_number : ", instance_id)

	ptpObj := getPtpRoot(inParams.ygRoot)
	outval = *ptpObj.InstanceList[uint32(instance_id)].DefaultDs.ClockType

	if outval == "P2P_TC" {
		return res_map, tlerr.InvalidArgsError{Format: "peer-to-peer-transparent-clock is not supported"}
	}

	log.Info("YangToDb_ptp_clock_type_xfmr outval: ", outval)
	_, field := filepath.Split(inParams.uri)
	domain_profile := ""
	network_transport := ""
	unicast_multicast := ""

	ts := db.TableSpec{Name: "PTP_CLOCK"}
	ca := make([]string, 1)

	ca[0] = "GLOBAL"
	akey := db.Key{Comp: ca}
	entry, _ := inParams.d.GetEntry(&ts, akey)
	if entry.Has("domain-profile") {
		domain_profile = entry.Get("domain-profile")
	}
	if entry.Has("network-transport") {
		network_transport = entry.Get("network-transport")
	}
	if entry.Has("unicast-multicast") {
		unicast_multicast = entry.Get("unicast-multicast")
	}

	log.Info("YangToDb_ptp_clock_type_xfmr domain_profile : ", domain_profile, " network-transport : ", network_transport,
		" unicast-multicast : ", unicast_multicast)

	if outval == "P2P_TC" || outval == "E2E_TC" {
		if domain_profile == "G.8275.x" {
			return res_map, tlerr.InvalidArgsError{Format: "transparent-clock not supported with G.8275.2"}
		}
		if domain_profile == "ieee1588" && unicast_multicast == "unicast" {
			return res_map, tlerr.InvalidArgsError{Format: "transparent-clock not supported with default profile and unicast"}
		}
	}
	if outval == "BC" {
		if domain_profile == "G.8275.x" && network_transport == "L2" {
			return res_map, tlerr.InvalidArgsError{Format: "boundary-clock not supported with G.8275.2 and L2"}
		}
		if domain_profile == "G.8275.x" && unicast_multicast == "multicast" {
			return res_map, tlerr.InvalidArgsError{Format: "boundary-clock not supported with G.8275.2 and multicast"}
		}
		if domain_profile == "G.8275.x" && network_transport == "UDPv6" {
			return res_map, tlerr.InvalidArgsError{Format: "boundary-clock not supported with G.8275.2 and ipv6"}
		}
	}

	log.Info("YangToDb_ptp_clock_type_xfmr outval: ", outval, " field: ", field)
	res_map[field] = outval
	return res_map, nil
}

var DbToYang_ptp_clock_type_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_clock_type_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)
	log.Info("DbToYang_ptp_clock_type_xfmr inParams.key: ", inParams.key)

	_, field := filepath.Split(inParams.uri)
	log.Info("DbToYang_ptp_clock_type_xfmr field: ", field)
	value := data["PTP_CLOCK"][inParams.key].Field[field]
	result[field] = value
	log.Info("DbToYang_ptp_clock_type_xfmr value: ", value)
	return result, err
}

var YangToDb_ptp_domain_profile_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var outval string
	var err error
	if inParams.param == nil {
		log.Info("YangToDb_ptp_domain_profile_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_domain_profile_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_domain_profile_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	log.Info("YangToDb_ptp_domain_profile_xfmr instance_number : ", instance_id)

	ptpObj := getPtpRoot(inParams.ygRoot)
	outval = *ptpObj.InstanceList[uint32(instance_id)].DefaultDs.DomainProfile

	if outval == "G.8275.1" {
		return res_map, tlerr.InvalidArgsError{Format: "g8275.1 is not supported"}
	}
	if outval == "G.8275.2" {
		outval = "G.8275.x"
	}

	log.Info("YangToDb_ptp_domain_profile_xfmr outval: ", outval)
	_, field := filepath.Split(inParams.uri)
	var domain_number uint64
	network_transport := ""
	unicast_multicast := ""
	clock_type := ""

	ts := db.TableSpec{Name: "PTP_CLOCK"}
	ca := make([]string, 1)

	ca[0] = "GLOBAL"
	akey := db.Key{Comp: ca}
	entry, _ := inParams.d.GetEntry(&ts, akey)
	if entry.Has("domain-number") {
		domain_number, _ = strconv.ParseUint(entry.Get("domain-number"), 10, 64)
	}
	if entry.Has("network-transport") {
		network_transport = entry.Get("network-transport")
	}
	if entry.Has("unicast-multicast") {
		unicast_multicast = entry.Get("unicast-multicast")
	}
	if entry.Has("clock-type") {
		clock_type = entry.Get("clock-type")
	}

	log.Info("YangToDb_ptp_domain_profile_xfmr domain_number : ", domain_number, " network-transport : ", network_transport,
		" unicast-multicast : ", unicast_multicast, " clock-type : ", clock_type)

	if outval == "G.8275.x" {
		if clock_type == "BC" && network_transport == "L2" {
			return res_map, tlerr.InvalidArgsError{Format: "G.8275.2 not supported with L2 transport"}
		}
		if clock_type == "BC" && unicast_multicast == "multicast" {
			return res_map, tlerr.InvalidArgsError{Format: "G.8275.2 not supported with multicast transport"}
		}
		if clock_type == "BC" && (domain_number < 44 || domain_number > 63) {
			return res_map, tlerr.InvalidArgsError{Format: "domain must be in range 44-63 with G.8275.2"}
		}
		if clock_type == "BC" && network_transport == "UDPv6" {
			return res_map, tlerr.InvalidArgsError{Format: "ipv6 not supported with boundary-clock and G.8275.2"}
		}
		if clock_type == "P2P_TC" || clock_type == "E2E_TC" {
			return res_map, tlerr.InvalidArgsError{Format: "G.8275.2 not supported with transparent-clock"}
		}
	}
	if outval == "ieee1588" {
		if unicast_multicast == "unicast" && (clock_type == "PTP_TC" || clock_type == "E2E_TC") {
			return res_map, tlerr.InvalidArgsError{Format: "default profile not supported with transparent-clock and unicast"}
		}
	}

	log.Info("YangToDb_ptp_domain_profile_xfmr outval: ", outval, " field: ", field)
	res_map[field] = outval
	return res_map, nil
}

var DbToYang_ptp_domain_profile_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_domain_profile_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)
	log.Info("DbToYang_ptp_domain_profile_xfmr inParams.key: ", inParams.key)

	_, field := filepath.Split(inParams.uri)
	log.Info("DbToYang_ptp_domain_profile_xfmr field: ", field)
	value := data["PTP_CLOCK"][inParams.key].Field[field]
	result[field] = value
	log.Info("DbToYang_ptp_domain_profile_xfmr value: ", value)
	return result, err
}

var YangToDb_ptp_unicast_multicast_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var outval string
	var err error
	if inParams.param == nil {
		log.Info("YangToDb_ptp_unicast_multicast_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_unicast_multicast_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_unicast_multicast_xfmr inParams.key: ", inParams.key)

	pathInfo := NewPathInfo(inParams.uri)
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	log.Info("YangToDb_ptp_unicast_multicast_xfmr instance_number : ", instance_id)

	ptpObj := getPtpRoot(inParams.ygRoot)
	outval = *ptpObj.InstanceList[uint32(instance_id)].DefaultDs.UnicastMulticast
	log.Info("YangToDb_ptp_unicast_multicast_xfmr outval: ", outval)
	_, field := filepath.Split(inParams.uri)
	domain_profile := ""
	network_transport := ""
	clock_type := ""

	ts := db.TableSpec{Name: "PTP_CLOCK"}
	ca := make([]string, 1)

	ca[0] = "GLOBAL"
	akey := db.Key{Comp: ca}
	entry, _ := inParams.d.GetEntry(&ts, akey)
	if entry.Has("domain-profile") {
		domain_profile = entry.Get("domain-profile")
	}
	if entry.Has("network-transport") {
		network_transport = entry.Get("network-transport")
	}
	if entry.Has("clock-type") {
		clock_type = entry.Get("clock-type")
	}

	log.Info("YangToDb_ptp_unicast_multicast_xfmr domain_profile : ", domain_profile,
		" network_transport : ", network_transport, " clock_type : ", clock_type)

	if outval == "multicast" {
		if domain_profile == "G.8275.x" {
			return res_map, tlerr.InvalidArgsError{Format: "multicast not supported with G.8275.2"}
		}
		keys, tblErr := inParams.d.GetKeysPattern(&db.TableSpec{Name: "PTP_PORT"}, db.Key{[]string{"GLOBAL", "*"}})
		if tblErr == nil {
			for _, key := range keys {
				entry2, err2 := inParams.d.GetEntry(&db.TableSpec{Name: "PTP_PORT"}, key)
				if err2 == nil {
					if entry2.Has("unicast-table") {
						log.Info("YangToDb_ptp_unicast_multicast_xfmr unicast-table : ", entry2.Get("unicast-table"))
						if entry2.Get("unicast-table") != "" {
							return res_map, tlerr.InvalidArgsError{Format: "master table must be removed from " + key.Comp[1]}
						}
					}
				}
			}
		}
	}
	if outval == "unicast" {
		if domain_profile == "ieee1588" && (clock_type == "PTP_TC" || clock_type == "E2E_TC") {
			return res_map, tlerr.InvalidArgsError{Format: "unicast not supported with transparent-clock and default profile"}
		}
		if network_transport == "UDPv6" {
			return res_map, tlerr.InvalidArgsError{Format: "ipv6 not supported with unicast"}
		}
	}

	log.Info("YangToDb_ptp_unicast_multicast_xfmr outval: ", outval, " field: ", field)
	res_map[field] = outval
	return res_map, nil
}

var DbToYang_ptp_unicast_multicast_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error
	result := make(map[string]interface{})

	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_unicast_multicast_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)
	log.Info("DbToYang_ptp_unicast_multicast_xfmr inParams.key: ", inParams.key)

	_, field := filepath.Split(inParams.uri)
	log.Info("DbToYang_ptp_unicast_multicast_xfmr field: ", field)
	value := data["PTP_CLOCK"][inParams.key].Field[field]
	result[field] = value
	log.Info("DbToYang_ptp_unicast_multicast_xfmr value: ", value)
	return result, err
}

var YangToDb_ptp_udp6_scope_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
	res_map := make(map[string]string)
	var inval uint8
	var err error

	if inParams.param == nil {
		log.Info("YangToDb_ptp_udp6_scope_xfmr Error: ")
		return res_map, err
	}
	log.Info("YangToDb_ptp_udp6_scope_xfmr : ", *inParams.ygRoot, " Xpath: ", inParams.uri)
	log.Info("YangToDb_ptp_udp6_scope_xfmr inParams.key: ", inParams.key)
	pathInfo := NewPathInfo(inParams.uri)
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	port_number, _ := strconv.ParseUint(pathInfo.Var("port-number"), 10, 64)
	log.Info("YangToDb_ptp_udp6_scope_xfmr instance_number : ", instance_id, " port_number: ", port_number)

	ptpObj := getPtpRoot(inParams.ygRoot)
	inval = *ptpObj.InstanceList[uint32(instance_id)].DefaultDs.Udp6Scope
	log.Info("YangToDb_ptp_udp6_scope_xfmr inval: ", inval)
	_, field := filepath.Split(inParams.uri)

	if inval > 0xf {
		return res_map, tlerr.InvalidArgsError{Format: "Invalid value passed for udp6-scope"}
	}
	outval := fmt.Sprintf("0x%x", inval)

	log.Info("YangToDb_ptp_udp6_scope_xfmr outval: ", outval, " field: ", field)
	res_map[field] = outval
	return res_map, nil
}

var DbToYang_ptp_udp6_scope_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
	var err error

	result := make(map[string]interface{})
	data := (*inParams.dbDataMap)[inParams.curDb]
	log.Info("DbToYang_ptp_udp6_scope_xfmr ygRoot: ", *inParams.ygRoot, " Xpath: ", inParams.uri, " data: ", data)
	log.Info("DbToYang_ptp_udp6_scope_xfmr inParams.key: ", inParams.key)

	_, field := filepath.Split(inParams.uri)
	log.Info("DbToYang_ptp_udp6_scope_xfmr field: ", field)
	log.Info("DbToYang_ptp_udp6_scope_xfmr data: ", data["PTP_CLOCK"][inParams.key].Field[field])
	value, _ := strconv.ParseInt(strings.Replace(data["PTP_CLOCK"][inParams.key].Field[field], "0x", "", -1), 16, 64)
	result[field] = uint8(value)
	log.Info("DbToYang_ptp_udp6_scope_xfmr value: ", value)
	return result, err
}

var YangToDb_ptp_port_ds_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
	var err error
	res_map := make(map[string]map[string]db.Value)
	port_ds_map := make(map[string]db.Value)
	log.Info("YangToDb_ptp_port_ds_xfmr inParams: ", inParams)
	log.Info("YangToDb_ptp_port_ds_xfmr URI: ", inParams.uri)
	log.Info("YangToDb_ptp_port_ds_xfmr REQ URI: ", inParams.requestUri)
	log.Info("YangToDb_ptp_port_ds_xfmr OPER: ", inParams.oper)
	log.Info("YangToDb_ptp_port_ds_xfmr KEY: ", inParams.key)
	log.Info("YangToDb_ptp_port_ds_xfmr PARAM: ", inParams.param)

	ptpObj := getPtpRoot(inParams.ygRoot)
	if ptpObj == nil {
		log.Info("YangToDb_ptp_port_ds_xfmr : Empty component.")
		return res_map, errors.New("Interface is not specified")
	}

	pathInfo := NewPathInfo(inParams.uri)
	log.Info("len(pathInfo.Vars): ", len(pathInfo.Vars))
	log.Info("pathInfo.Vars: ", pathInfo.Vars)
	if len(pathInfo.Vars) < 2 {
		err = errors.New("Invalid xpath, key attributes not found")
		return res_map, err
	}
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	port_number_str := pathInfo.Var("port-number")
	log.Info(" port_number_str: ", port_number_str)
	port_number, _ := strconv.ParseUint(port_number_str, 10, 64)
	log.Info(" port_number: ", port_number)
	pDsList := ptpObj.InstanceList[uint32(instance_id)].PortDsList
	var underlying_interface string
	log.Info(" len(pDsList): ", len(pDsList))
	if inParams.oper == DELETE {
		keys, tblErr := inParams.d.GetKeysPattern(&db.TableSpec{Name: "PTP_PORT"}, db.Key{[]string{"GLOBAL", "*"}})
		if tblErr == nil {
			matched := false
			for _, key := range keys {
				entry, err2 := inParams.d.GetEntry(&db.TableSpec{Name: "PTP_PORT"}, key)
				if err2 == nil {
					if entry.Has("port-number") {
						var port_number_db string
						if entry.Get("port-number") != "" {
							port_number_db = entry.Get("port-number")
						}
						log.Info("port-number : ", port_number_db)

						if port_number_db == port_number_str {
							log.Info("port-number matches input")
							tblName := key.Comp[0] + "|" + key.Comp[1]

							port_ds_map[tblName] = db.Value{Field: make(map[string]string)}
							// port_ds_map[tblName].Field["port-number"] = port_number_str
							matched = true
						}
					}
				}
			}
			if !matched {
				return res_map, tlerr.InvalidArgsError{Format: "Input key does not match any entry "}
			}
		}
	} else {
		if len(pDsList) == 0 || pDsList[uint16(port_number)].UnderlyingInterface == nil ||
			*pDsList[uint16(port_number)].UnderlyingInterface == "" {
			keys, tblErr := inParams.d.GetKeysPattern(&db.TableSpec{Name: "PTP_PORT"}, db.Key{[]string{"GLOBAL", "*"}})
			if tblErr == nil {
				matched := false
				for _, key := range keys {
					entry, err2 := inParams.d.GetEntry(&db.TableSpec{Name: "PTP_PORT"}, key)
					if err2 == nil {
						if entry.Has("port-number") {
							var port_number_db string
							if entry.Get("port-number") != "" {
								port_number_db = entry.Get("port-number")
							}
							log.Info("port-number : ", port_number_db)

							if port_number_db == port_number_str {
								underlying_interface = key.Comp[1]
								matched = true
								break
							}
						}
					}
				}
				if !matched {
					return res_map, tlerr.InvalidArgsError{Format: "underlying-interface is needed"}
				}
			}

		} else {
			underlying_interface = *pDsList[uint16(port_number)].UnderlyingInterface
		}
		tblName := "GLOBAL|" + underlying_interface

		port_ds_map[tblName] = db.Value{Field: make(map[string]string)}
		//		port_ds_map[tblName].Field["underlying-interface"] = underlying_interface
		port_ds_map[tblName].Field["port-number"] = port_number_str
		if pDsList[uint16(port_number)].UnicastTable != nil {
			outval := *pDsList[uint16(port_number)].UnicastTable

			unicast_multicast := ""

			entry, _ := inParams.d.GetEntry(&db.TableSpec{Name: "PTP_CLOCK"}, db.Key{[]string{"GLOBAL"}})
			if entry.Has("unicast-multicast") {
				unicast_multicast = entry.Get("unicast-multicast")
			}

			if unicast_multicast == "multicast" {
				return res_map, tlerr.InvalidArgsError{Format: "master-table is not needed in with multicast transport"}
			}

			if outval != "" {
				addresses := strings.Split(outval, ",")
				var prev_tmp E_Ptp_AddressTypeEnumeration
				var tmp E_Ptp_AddressTypeEnumeration
				var first bool
				first = true
				for _, address := range addresses {
					tmp = check_address(address)
					if PTP_ADDRESSTYPE_UNKNOWN == tmp {
						return res_map, tlerr.InvalidArgsError{Format: "Invalid value passed for unicast-table"}
					}
					if !first && tmp != prev_tmp {
						return res_map, tlerr.InvalidArgsError{Format: "Mismatched addresses passed in unicast-table"}
					}
					prev_tmp = tmp
					first = false
				}
			}
			port_ds_map[tblName].Field["unicast-table"] = outval
		}
	}
	res_map["PTP_PORT"] = port_ds_map
	log.Info("map ==>", res_map)
	return res_map, err
}

var DbToYang_ptp_port_ds_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
	log.Info("DbToYang_ptp_port_ds_xfmr uri: ", inParams.uri)
	pathInfo := NewPathInfo(inParams.uri)

	targetUriPath, err := getYangPathFromUri(pathInfo.Path)
	log.Info("DbToYang_ptp_port_ds_xfmr targetUriPath:", targetUriPath)
	log.Info("DbToYang_ptp_port_ds_xfmr pathInfo.Path:", pathInfo.Path)
	ptpObj := getPtpRoot(inParams.ygRoot)
	if ptpObj == nil {
		log.Info("DbToYang_ptp_port_ds_xfmr : Empty component.")
		return errors.New("Interface is not specified")
	}
	instance_id, _ := strconv.ParseUint(pathInfo.Var("instance-number"), 10, 64)
	port_number_str := pathInfo.Var("port-number")
	log.Info(" port_number_str: ", port_number_str)
	port_number, _ := strconv.ParseUint(port_number_str, 10, 64)
	log.Info(" port_number: ", port_number)

	pDsList := ptpObj.InstanceList[uint32(instance_id)].PortDsList
	log.Info(" len(pDsList): ", len(pDsList))

	keys, tblErr := inParams.d.GetKeysPattern(&db.TableSpec{Name: "PTP_PORT"}, db.Key{[]string{"GLOBAL", "*"}})
	if tblErr == nil {
		for _, key := range keys {
			entry, err2 := inParams.d.GetEntry(&db.TableSpec{Name: "PTP_PORT"}, key)
			if err2 == nil {
				if entry.Has("port-number") {
					var port_number_db string
					if entry.Get("port-number") != "" {
						port_number_db = entry.Get("port-number")
					}
					log.Info("port-number : ", port_number_db)

					if port_number_db == port_number_str || port_number_str == "" {
						port_number, _ = strconv.ParseUint(port_number_db, 10, 64)
						log.Info("port-number matches input")
						log.Info("port-number : ", uint16(port_number))
						log.Info("pDsList[uint16(port_number)] : ", pDsList[uint16(port_number)])

						if pDsList[uint16(port_number)] == nil {

							ptpObj.InstanceList[uint32(instance_id)].NewPortDsList(uint16(port_number))
							pDsList = ptpObj.InstanceList[uint32(instance_id)].PortDsList
						}
						str := utils.GetUINameFromNativeName(&key.Comp[1])
						log.Info("UnderlyingInterface : ", *str)
						pDsList[uint16(port_number)].UnderlyingInterface = str

						temp := uint16(port_number)
						pDsList[uint16(port_number)].PortNumber = &temp

						if entry.Has("port-state") {
							port_state_db, _ := strconv.ParseUint(entry.Get("port-state"), 10, 64)
							log.Info("port-state : ", port_state_db)
							if port_state_db == 1 {
								port_state_db = 2
							} else if port_state_db == 2 {
								port_state_db = 3
							} else if port_state_db == 3 {
								port_state_db = 4
							} else if port_state_db == 4 {
								port_state_db = 5
							} else if port_state_db == 5 {
								port_state_db = 6
							} else if port_state_db == 6 {
								port_state_db = 7
							} else if port_state_db == 7 {
								port_state_db = 8
							} else if port_state_db == 8 {
								port_state_db = 9
							} else if port_state_db == 9 {
								port_state_db = 10
							}
							pDsList[uint16(port_number)].PortState = ocbinds.E_IETFPtp_PortStateEnumeration(port_state_db)
						}

						if entry.Has("log-min-delay-req-interval") {
							lmdri_db, _ := strconv.ParseInt(entry.Get("log-min-delay-req-interval"), 10, 64)
							log.Info("log-min-delay-req-interval: ", lmdri_db)
							temp := int8(lmdri_db)
							pDsList[uint16(port_number)].LogMinDelayReqInterval = &temp
						}

						if entry.Has("peer-mean-path-delay") {
							pmpd_db, _ := strconv.ParseInt(entry.Get("peer-mean-path-delay"), 10, 64)
							log.Info("peer-mean-path-delay: ", pmpd_db)
							pDsList[uint16(port_number)].PeerMeanPathDelay = &pmpd_db
						}

						if entry.Has("log-announce-interval") {
							lai_db, _ := strconv.ParseInt(entry.Get("log-announce-interval"), 10, 64)
							log.Info("log-announce-interval: ", lai_db)
							temp := int8(lai_db)
							pDsList[uint16(port_number)].LogAnnounceInterval = &temp
						}

						if entry.Has("announce-receipt-timeout") {
							art_db, _ := strconv.ParseUint(entry.Get("announce-receipt-timeout"), 10, 64)
							log.Info("announce-receipt-timeout: ", art_db)
							temp := uint8(art_db)
							pDsList[uint16(port_number)].AnnounceReceiptTimeout = &temp
						}

						if entry.Has("log-sync-interval") {
							lsi_db, _ := strconv.ParseInt(entry.Get("log-sync-interval"), 10, 64)
							log.Info("log-sync-interval: ", lsi_db)
							temp := int8(lsi_db)
							pDsList[uint16(port_number)].LogSyncInterval = &temp
						}

						if entry.Has("delay-mechanism") {
							delay_mech_db, _ := strconv.ParseUint(entry.Get("delay-mechanism"), 10, 64)
							log.Info("delay-mechanism : ", delay_mech_db)
							if delay_mech_db == 1 {
								delay_mech_db = 2
							} else if delay_mech_db == 2 {
								delay_mech_db = 3
							} else {
								delay_mech_db = 0
							}

							pDsList[uint16(port_number)].DelayMechanism = ocbinds.E_IETFPtp_DelayMechanismEnumeration(delay_mech_db)
						}

						if entry.Has("log-min-pdelay-req-interval") {
							lmpdri_db, _ := strconv.ParseInt(entry.Get("log-min-pdelay-req-interval"), 10, 64)
							log.Info("log-min-pdelay-req-interval: ", lmpdri_db)
							temp := int8(lmpdri_db)
							pDsList[uint16(port_number)].LogMinPdelayReqInterval = &temp
						}

						if entry.Has("version-number") {
							version_num_db, _ := strconv.ParseUint(entry.Get("version-number"), 10, 64)
							log.Info("version-number: ", version_num_db)
							temp := uint8(version_num_db)
							pDsList[uint16(port_number)].VersionNumber = &temp
						}

						if entry.Has("unicast-table") {
							unicast_table_db := entry.Get("unicast-table")
							log.Info("unicast-table: ", unicast_table_db)
							pDsList[uint16(port_number)].UnicastTable = &unicast_table_db
						}
					}
				}
			}
		}
	}
	return err
}
