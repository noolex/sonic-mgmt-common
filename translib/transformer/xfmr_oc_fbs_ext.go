////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
//  its subsidiaries.                                                         //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

package transformer

//import (
//	"bytes"
//	"errors"
//	"fmt"
//	"github.com/Azure/sonic-mgmt-common/translib/db"
//	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
//	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
//    "github.com/Azure/sonic-mgmt-common/translib/utils"
//	log "github.com/golang/glog"
//	"github.com/kylelemons/godebug/pretty"
//	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
//	"github.com/openconfig/goyang/pkg/yang"
//	ygot "github.com/openconfig/ygot/ygot"
//	"net"
//	"reflect"
//	"strconv"
//	"strings"
//)
//
//const (
//	SONIC_CLASS_MATCH_TYPE_ACL    = "ACL"
//	SONIC_CLASS_MATCH_TYPE_FIELDS = "FIELDS"
//	SONIC_POLICY_TYPE_QOS         = "QOS"
//	SONIC_POLICY_TYPE_FORWARDING  = "FORWARDING"
//	SONIC_POLICY_TYPE_MONITORING  = "MONITORING"
//	SONIC_PACKET_ACTION_DROP      = "DROP"
//	CFG_CLASSIFIER_TABLE          = "CLASSIFIER_TABLE"
//	CFG_POLICY_TABLE              = "POLICY_TABLE"
//	CFG_POLICY_SECTIONS_TABLE     = "POLICY_SECTIONS_TABLE"
//	CFG_POLICY_BINDING_TABLE      = "POLICY_BINDING_TABLE"
//	APP_POLICER_TABLE             = "POLICER_TABLE"
//	PBF_GROUP_TABLE               = "PBF_GROUP_TABLE"
//	FBS_COUNTERS_TABLE            = "FBS_COUNTERS"
//	LAST_FBS_COUNTERS_TABLE       = "LAST_FBS_COUNTERS"
//	POLICER_COUNTERS_TABLE        = "POLICER_COUNTERS"
//	LAST_POLICER_COUNTERS_TABLE   = "LAST_POLICER_COUNTERS"
//	OPENCONFIG_ACL_TYPE_IPV4      = "ACL_IPV4"
//	OPENCONFIG_ACL_TYPE_IPV6      = "ACL_IPV6"
//	OPENCONFIG_ACL_TYPE_L2        = "ACL_L2"
//)
//
//type FbsFwdCountersEntry struct {
//	Active         bool   `path:"active" module:"openconfig-fbs-ext"`
//	MatchedOctets  uint64 `path:"matched-octets" module:"openconfig-fbs-ext"`
//	MatchedPackets uint64 `path:"matched-packets" module:"openconfig-fbs-ext"`
//}
//
//type FbsFlowForwardingStateEntry struct {
//	IntfName        *string `path:"intf-name" module:"openconfig-fbs-ext"`
//	Priority        *uint16 `path:"priority" module:"openconfig-fbs-ext"`
//	IpAddress       *string `path:"ip-address" module:"openconfig-fbs-ext"`
//	NetworkInstance *string `path:"network-instance" module:"openconfig-fbs-ext"`
//	Discard         *bool   `path:"discard" module:"openconfig-fbs-ext"`
//
//	fbsFlowState FbsFwdCountersEntry //MatchedOctets,MatchedPackets, Active
//}
//
//type FbsPolicerStateEntry struct {
//	Bc  uint64 `path:"bc" module:"openconfig-fbs-ext"`
//	Be  uint64 `path:"be" module:"openconfig-fbs-ext"`
//	Cir uint64 `path:"cir" module:"openconfig-fbs-ext"`
//	Pir uint64 `path:"pir" module:"openconfig-fbs-ext"`
//}
//
//type FbsFlowQosStateEntry struct {
//	ConformingOctets uint64 `path:"conforming-octets" module:"openconfig-fbs-ext"`
//	ConformingPkts   uint64 `path:"conforming-pkts" module:"openconfig-fbs-ext"`
//	ExceedingOctets  uint64 `path:"exceeding-octets" module:"openconfig-fbs-ext"`
//	ExceedingPkts    uint64 `path:"exceeding-pkts" module:"openconfig-fbs-ext"`
//	ViolatingOctets  uint64 `path:"violating-octets" module:"openconfig-fbs-ext"`
//	ViolatingPkts    uint64 `path:"violating-pkts" module:"openconfig-fbs-ext"`
//	Active           bool   `path:"active" module:"openconfig-fbs-ext"`
//
//	policerState FbsPolicerStateEntry //MatchedOctets,MatchedPackets, Active
//	fbsFlowState FbsFwdCountersEntry  //MatchedOctets,MatchedPackets, Active
//}
//
//var ETHERTYPE_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_ETHERTYPE]uint32{
//	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_LLDP: 0x88CC,
//	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_VLAN: 0x8100,
//	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ROCE: 0x8915,
//	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ARP:  0x0806,
//	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV4: 0x0800,
//	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV6: 0x86DD,
//	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_MPLS: 0x8847,
//}
//
//// IP_PROTOCOL_MAP represents map of E_OpenconfigPacketMatchTypes_IP_PROTOCOL enum value to protocol value in DB
//var IP_PROTOCOL_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]uint8{
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_ICMP: 1,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_IGMP: 2,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_TCP:  6,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_UDP:  17,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_RSVP: 46,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_GRE:  47,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_AUTH: 51,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_PIM:  103,
//	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_L2TP: 115,
//}
//
//// CLASS_MATCH_TYPE_MAP represents map of E_OpenconfigFbsExt_MATCH_TYPE enum value to protocol value to db match type values
//var CLASS_MATCH_TYPE_MAP = map[string]string{
//	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_ACL), 10):    SONIC_CLASS_MATCH_TYPE_ACL,
//	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_FIELDS), 10): SONIC_CLASS_MATCH_TYPE_FIELDS,
//}
//
//// POLICY_POLICY_TYPE_MAP represents map of E_OpenconfigFbsExt_POLICY_TYPE enum value to protocol value to db match type values
//var POLICY_POLICY_TYPE_MAP = map[string]string{
//	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_FORWARDING), 10): SONIC_POLICY_TYPE_FORWARDING,
//	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_QOS), 10):        SONIC_POLICY_TYPE_QOS,
//	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_MONITORING), 10): SONIC_POLICY_TYPE_MONITORING,
//}
//
//var CLASSIFIER_TABLE_TS *db.TableSpec = &db.TableSpec{Name: CFG_CLASSIFIER_TABLE}
//var POLICY_TABLE_TS *db.TableSpec = &db.TableSpec{Name: CFG_POLICY_TABLE}
//var POLICY_SECTION_TABLE_TS *db.TableSpec = &db.TableSpec{Name: CFG_POLICY_SECTIONS_TABLE}
//var POLICER_TABLE_TS *db.TableSpec = &db.TableSpec{Name: APP_POLICER_TABLE}
//var POLICY_BINDING_TABLE_TS *db.TableSpec = &db.TableSpec{Name: CFG_POLICY_BINDING_TABLE}
//var PBF_GROUP_TABLE_TS *db.TableSpec = &db.TableSpec{Name: PBF_GROUP_TABLE}
//var FBS_COUNTERS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: FBS_COUNTERS_TABLE}
//var LAST_FBS_COUNTERS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: LAST_FBS_COUNTERS_TABLE}
//var POLICER_COUNTERS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: POLICER_COUNTERS_TABLE}
//var LAST_POLICER_COUNTERS_TABLE_TS *db.TableSpec = &db.TableSpec{Name: LAST_POLICER_COUNTERS_TABLE}
//
//func init() {
//	XlateFuncBind("DbToYang_fbs_classifier_subtree_xfmr", DbToYang_fbs_classifier_subtree_xfmr)
//	XlateFuncBind("YangToDb_fbs_classifier_subtree_xfmr", YangToDb_fbs_classifier_subtree_xfmr)
//	XlateFuncBind("DbToYang_fbs_policy_subtree_xfmr", DbToYang_fbs_policy_subtree_xfmr)
//	XlateFuncBind("YangToDb_fbs_policy_subtree_xfmr", YangToDb_fbs_policy_subtree_xfmr)
//	XlateFuncBind("DbToYang_fbs_interface_subtree_xfmr", DbToYang_fbs_interface_subtree_xfmr)
//	XlateFuncBind("YangToDb_fbs_interface_subtree_xfmr", YangToDb_fbs_interface_subtree_xfmr)
//}
//
//func isV4Address(str string) bool {
//	ip := net.ParseIP(str)
//	return ip != nil && strings.Contains(str, ".")
//}
//func getL2EtherType(etherType uint64) interface{} {
//	for k, v := range ETHERTYPE_MAP {
//		if uint32(etherType) == v {
//			return k
//		}
//	}
//	return uint16(etherType)
//}
//
//func getTransportConfigTcpFlags(tcpFlags string) []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS {
//	var flags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS
//	flagParts := strings.Split(tcpFlags, "/")
//	valueStr := flagParts[0]
//	maskStr := flagParts[1]
//	flagValue, _ := strconv.ParseUint(valueStr, 0, 8)
//	flagMask, _ := strconv.ParseUint(maskStr, 0, 8)
//	for i := 0; i < 8; i++ {
//		mask := uint64(1 << i)
//		if (flagValue&mask) > 0 || (flagMask&mask) > 0 {
//			switch mask {
//			case 0x01:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_FIN)
//				}
//			case 0x02:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_SYN)
//				}
//			case 0x04:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_RST)
//				}
//			case 0x08:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_PSH)
//				}
//			case 0x10:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ACK)
//				}
//			case 0x20:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_URG)
//				}
//			case 0x40:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ECE)
//				}
//			case 0x80:
//				if (flagValue & mask) > 0 {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR)
//				} else {
//					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_CWR)
//				}
//			default:
//			}
//		}
//	}
//	return flags
//}
//
//func getFbsRoot(s *ygot.GoStruct) *ocbinds.OpenconfigFbsExt_Fbs {
//	deviceObj := (*s).(*ocbinds.Device)
//
//	return deviceObj.Fbs
//}
//
//func getFbsUriPath(uri string) (*gnmipb.Path, error) {
//	log.Infof("Fbs uristring %v", uri)
//	//uriPath := strings.Replace(uri, "openconfig-fbs-ext:", "", -1)
//	path, err := ygot.StringToPath(uri, ygot.StructuredPath, ygot.StringSlicePath)
//	if err != nil {
//		return nil, tlerr.NotFound("Resource Not Found")
//	}
//	for _, p := range path.Elem {
//		pathSlice := strings.Split(p.Name, ":")
//		p.Name = pathSlice[len(pathSlice)-1]
//	}
//	//log.Info("Fbs uriPath path", )
//	//pretty.Print(path)
//	return path, nil
//}
//
//func getFbsYangNode(path *gnmipb.Path) (*yang.Entry, error) {
//	pathStr, err := ygot.PathToSchemaPath(path)
//
//	if err != nil {
//		return nil, errors.New("path to schema path conversion failed")
//	}
//
//	log.Info("tmpStr pathStr ==> ", pathStr)
//
//	pathStr = pathStr[1:]
//
//	log.Info("tmpStr pathStr ==> ", pathStr)
//
//	ygNode := ocbinds.SchemaTree["Device"].Find(pathStr)
//
//	//log.Info("translate == ygNode => ", ygNode)
//	return ygNode, err
//}
//
///* func isFbsConfigTargetNode(targetName string, nodeName string) bool {
//	if targetName == "fbs" || targetName == "classifiers" || targetName == "policies" || targetName == "interfaces" || targetName == "config" || nodeName == targetName {
//		return true
//	}
//	return false
//}
//
//
//func isFbsStateTargetNode(targetName string, nodeName string) bool {
//	if targetName == "fbs" || targetName == "classifiers" || targetName == "policies" || targetName == "interfaces" || targetName == "state" || nodeName == targetName {
//		return true
//	}
//	return false
//} */
//
////get fbs classifier oc yang match type for match type in db
//func getClassMatchTypeOCEnumFromDbStr(val string) (ocbinds.E_OpenconfigFbsExt_MATCH_TYPE, error) {
//	switch val {
//	case SONIC_CLASS_MATCH_TYPE_ACL, "openconfig-fbs-ext:MATCH_ACL":
//		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_ACL, nil
//	case SONIC_CLASS_MATCH_TYPE_FIELDS, "openconfig-fbs-ext:MATCH_FIELDS":
//		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_FIELDS, nil
//	default:
//		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_UNSET,
//			tlerr.NotSupported("FBS Class Match Type '%s' not supported", val)
//	}
//}
//
////get classifier match type - db string from oc enum match type
//func getClassMatchTypeDbStrromOcEnum(ocMatchType ocbinds.E_OpenconfigFbsExt_MATCH_TYPE) (string, error) {
//	dbMatchType := ""
//	if ocMatchType == ocbinds.OpenconfigFbsExt_MATCH_TYPE_UNSET {
//		return "", tlerr.NotSupported("FBS Class Match Type not set")
//	}
//	dbMatchType = findInMap(CLASS_MATCH_TYPE_MAP, strconv.FormatInt(int64(ocMatchType), 10))
//	return dbMatchType, nil
//}
//
////get L2Ethertype oc enum for given ether type string in DB
////func getL2EtherTypeOCEnumFromDbStr(val string) (ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union, error) {
//func getL2EtherTypeOCEnumFromDbStr(val string) interface{} {
//	etypeVal, _ := strconv.ParseUint(strings.Replace(val, "0x", "", -1), 16, 32)
//	return (getL2EtherType(etypeVal))
//}
//
////get Ip protocol oc enum from given Ip protocol in DB
//func getIpProtocol(proto int64) interface{} {
//	for k, v := range IP_PROTOCOL_MAP {
//		if uint8(proto) == v {
//			return k
//		}
//	}
//	return uint8(proto)
//}
//
////Classifiers - START
//
////convert from DB to OCYang and fill to OcYang Datastructure for given classifier name
//func fillFbsClassDetails(inParams XfmrParams, className string, classTblVal db.Value, classData *ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier) {
//	if classData == nil {
//		log.Infof("fillFbsClassDetails--> classData empty ; className:%v ", className)
//		return
//	}
//	ygot.BuildEmptyTree(classData)
//
//	classData.ClassName = &className
//	matchType := classTblVal.Get("MATCH_TYPE")
//
//	classData.Config.Name = &className
//	log.Infof("fillFbsClassDetails--> filled config container with className:%v and MatchType:%v", className, matchType)
//
//	ocMatchType, _ := getClassMatchTypeOCEnumFromDbStr(matchType)
//	classData.Config.MatchType = ocMatchType
//	if matchType == SONIC_CLASS_MATCH_TYPE_ACL {
//		aclNameInDb := classTblVal.Get("ACL_NAME")
//		aclTypeInDb := classTblVal.Get("ACL_TYPE")
//		aclType := ocbinds.OpenconfigAcl_ACL_TYPE_UNSET
//		if aclTypeInDb == "L2" {
//			aclType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2
//		} else if aclTypeInDb == "L3" {
//			aclType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4
//		} else if aclTypeInDb == "L3V6" {
//			aclType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4
//		}
//		classData.MatchAcl.Config.AclName = &aclNameInDb
//		classData.MatchAcl.Config.AclType = aclType
//
//		classData.MatchAcl.State.AclName = classData.MatchAcl.Config.AclName
//		classData.MatchAcl.State.AclType = classData.MatchAcl.Config.AclType
//	} else if matchType == SONIC_CLASS_MATCH_TYPE_FIELDS {
//		matchAll := true
//		ygot.BuildEmptyTree(classData.MatchHdrFields)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Config)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.State)
//		classData.MatchHdrFields.Config.MatchAll = &matchAll
//		classData.MatchHdrFields.State.MatchAll = classData.MatchHdrFields.Config.MatchAll
//
//		//Fill L2 Fields - START
//		ygot.BuildEmptyTree(classData.MatchHdrFields.L2)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.L2.Config)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.L2.State)
//
//		if str_val, found := classTblVal.Field["DST_MAC"]; found {
//			splitStr := strings.Split(str_val, "/")
//			classData.MatchHdrFields.L2.Config.DestinationMac = &splitStr[0]
//			classData.MatchHdrFields.L2.State.DestinationMac = &splitStr[0]
//			if len(splitStr[1]) != 0 {
//				classData.MatchHdrFields.L2.Config.DestinationMacMask = &splitStr[1]
//				classData.MatchHdrFields.L2.State.DestinationMacMask = &splitStr[1]
//			}
//		}
//		if str_val, found := classTblVal.Field["SRC_MAC"]; found {
//			classData.MatchHdrFields.L2.Config.SourceMac = &str_val
//			classData.MatchHdrFields.L2.State.SourceMac = &str_val
//		}
//		if str_val, found := classTblVal.Field["DEI"]; found {
//			dei, _ := strconv.Atoi(str_val)
//			oc_dei := uint8(dei)
//			classData.MatchHdrFields.L2.Config.Dei = &oc_dei
//			classData.MatchHdrFields.L2.State.Dei = &oc_dei
//		}
//		if str_val, found := classTblVal.Field["PCP"]; found {
//			pcp, _ := strconv.Atoi(str_val)
//			oc_pcp := uint8(pcp)
//			classData.MatchHdrFields.L2.Config.Pcp = &oc_pcp
//			classData.MatchHdrFields.L2.State.Pcp = &oc_pcp
//		}
//		if str_val, found := classTblVal.Field["VLAN"]; found {
//			vlan, _ := strconv.Atoi(str_val)
//			oc_vlan := uint16(vlan)
//			classData.MatchHdrFields.L2.Config.Vlanid = &oc_vlan
//			classData.MatchHdrFields.L2.State.Vlanid = &oc_vlan
//		}
//
//		if str_val, found := classTblVal.Field["ETHER_TYPE"]; found {
//			ocEtype := getL2EtherTypeOCEnumFromDbStr(str_val)
//			classData.MatchHdrFields.L2.Config.Ethertype, _ = classData.MatchHdrFields.L2.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union(ocEtype)
//			classData.MatchHdrFields.L2.State.Ethertype, _ = classData.MatchHdrFields.L2.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_State_Ethertype_Union(ocEtype)
//		}
//		//Fill L2 Fields - END
//
//		// Fill IP Common fields
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ip)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ip.Config)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ip.State)
//
//		if str_val, found := classTblVal.Field["DSCP"]; found {
//			dscp, _ := strconv.Atoi(str_val)
//			oc_dscp := uint8(dscp)
//			classData.MatchHdrFields.Ip.Config.Dscp = &oc_dscp
//			classData.MatchHdrFields.Ip.State.Dscp = classData.MatchHdrFields.Ip.Config.Dscp
//		}
//		if str_val, found := classTblVal.Field["IP_PROTOCOL"]; found {
//			ipProto, _ := strconv.ParseInt(str_val, 10, 64)
//			ip_proto_val := getIpProtocol(ipProto)
//			classData.MatchHdrFields.Ip.Config.Protocol, _ = classData.MatchHdrFields.Ip.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union(ip_proto_val)
//			classData.MatchHdrFields.Ip.State.Protocol, _ = classData.MatchHdrFields.Ip.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_State_Protocol_Union(ip_proto_val)
//		}
//
//		//Fill IPV4 Fields - START
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv4)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv4.Config)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv4.State)
//
//		if str_val, found := classTblVal.Field["SRC_IP"]; found {
//			classData.MatchHdrFields.Ipv4.Config.SourceAddress = &str_val
//			classData.MatchHdrFields.Ipv4.State.SourceAddress = &str_val
//		}
//		if str_val, found := classTblVal.Field["DST_IP"]; found {
//			classData.MatchHdrFields.Ipv4.Config.DestinationAddress = &str_val
//			classData.MatchHdrFields.Ipv4.State.DestinationAddress = &str_val
//		}
//		//Fill IPV4 Fields - END
//
//		//Fill IPV6 Fields - START
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv6)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv6.Config)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Ipv6.State)
//
//		if str_val, found := classTblVal.Field["SRC_IPV6"]; found {
//			classData.MatchHdrFields.Ipv6.Config.SourceAddress = &str_val
//			classData.MatchHdrFields.Ipv6.State.SourceAddress = &str_val
//		}
//		if str_val, found := classTblVal.Field["DST_IPV6"]; found {
//			classData.MatchHdrFields.Ipv6.Config.DestinationAddress = &str_val
//			classData.MatchHdrFields.Ipv6.State.DestinationAddress = &str_val
//		}
//		//Fill IPV6 Fields - END
//
//		//Fill Transport Fields - START
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Transport)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Transport.Config)
//		ygot.BuildEmptyTree(classData.MatchHdrFields.Transport.State)
//
//		if str_val, found := classTblVal.Field["L4_SRC_PORT"]; found {
//			src_port, _ := strconv.Atoi(str_val)
//			classData.MatchHdrFields.Transport.Config.SourcePort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union(src_port)
//			classData.MatchHdrFields.Transport.State.SourcePort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_SourcePort_Union(src_port)
//		}
//		if str_val, found := classTblVal.Field["L4_DST_PORT"]; found {
//			dst_port, _ := strconv.Atoi(str_val)
//			classData.MatchHdrFields.Transport.Config.DestinationPort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union(dst_port)
//			classData.MatchHdrFields.Transport.State.DestinationPort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_DestinationPort_Union(dst_port)
//		}
//		if str_val, found := classTblVal.Field["L4_SRC_PORT_RANGE"]; found {
//			src_port_range := strings.Replace(str_val, "-", "..", 1)
//			classData.MatchHdrFields.Transport.Config.SourcePort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union(src_port_range)
//			classData.MatchHdrFields.Transport.State.SourcePort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_SourcePort_Union(src_port_range)
//		}
//		if str_val, found := classTblVal.Field["L4_DST_PORT_RANGE"]; found {
//			dst_port_range := strings.Replace(str_val, "-", "..", 1)
//			classData.MatchHdrFields.Transport.Config.DestinationPort, _ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union(dst_port_range)
//			classData.MatchHdrFields.Transport.State.DestinationPort, _ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_DestinationPort_Union(dst_port_range)
//		}
//		if str_val, found := classTblVal.Field["TCP_FLAGS"]; found {
//			classData.MatchHdrFields.Transport.Config.TcpFlags = getTransportConfigTcpFlags(str_val)
//			classData.MatchHdrFields.Transport.State.TcpFlags = classData.MatchHdrFields.Transport.Config.TcpFlags
//		}
//		//Fill Transport Fields - END
//	}
//
//	classData.State.MatchType = classData.Config.MatchType
//	classData.State.Name = classData.Config.Name
//
//	log.Infof("fillFbsClassDetails; classData ")
//	pretty.Print(classData)
//}
//
////DbToYang_fbs_classifier_subtree_xfmr function takes care of handling Get operation for Classifier urls
//var DbToYang_fbs_classifier_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
//	var err error
//
//	pathInfo := NewPathInfo(inParams.uri)
//
//	fbsObj := getFbsRoot(inParams.ygRoot)
//	ygot.BuildEmptyTree(fbsObj)
//	log.Infof("Classifier Get;path:%v pathfbsObj:%v ", pathInfo.Template, fbsObj)
//	log.Info("fbsobj ")
//	pretty.Print(fbsObj)
//
//	log.Info("targetObj ")
//	pretty.Print(inParams.param)
//
//	if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers/classifier{class-name}") { //class level request
//		className := pathInfo.Var("class-name")
//		classObj := fbsObj.Classifiers.Classifier[className]
//		log.Infof("Classifier Get;class level request; className:%v ", className)
//
//		var classTblVal db.Value
//		classTblVal, err = inParams.d.GetEntry(CLASSIFIER_TABLE_TS, db.Key{[]string{className}})
//		log.Infof("Val:%v Error:%v", classTblVal, err)
//		if err == nil {
//			ygot.BuildEmptyTree(classObj)
//			fillFbsClassDetails(inParams, className, classTblVal, classObj)
//		}
//	} else { //top level get
//		log.Infof("Classifier Get;top level Get")
//
//		classTbl, err := inParams.d.GetTable(CLASSIFIER_TABLE_TS)
//		if err != nil {
//			log.Infof("Classifier Get; couldn't get classifier table")
//		}
//
//		classKeys, _ := classTbl.GetKeys()
//		log.Infof("Classifier Get;clasKeys %v classTbl:%v ", classKeys, classTbl)
//
//		if len(classKeys) > 0 {
//			for _, key := range classKeys {
//				className := key.Get(0)
//				log.Infof("Classifier Get;Key:%v className:%v ", key, className)
//				classObj, _ := fbsObj.Classifiers.NewClassifier(className)
//				classTblVal, _ := classTbl.GetEntry(key)
//				fillFbsClassDetails(inParams, className, classTblVal, classObj)
//				log.Infof("Classifier Get;top level request; classTblVal:%v  ", classTblVal)
//			}
//		}
//	}
//
//	return err
//}
//
////YangToDb_fbs_classifier_subtree_xfmr function takes care of handling CRUD operations for Classifier urls
//var YangToDb_fbs_classifier_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
//	var err error
//	var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)
//
//	pathInfo := NewPathInfo(inParams.uri)
//	keyName := pathInfo.Var("class-name")
//	log.Infof("Classifier CRUD:: key:%v pathInfo%v ", keyName, pathInfo)
//
//	log.Info("Classifier CRUD:: inParams.uri ")
//	pretty.Print(inParams.uri)
//
//	path, err := getFbsUriPath(inParams.uri)
//	if err != nil {
//		log.Infof("Classifier CRUD:: path get error:%v ", err)
//		return nil, err
//	}
//	targetNode, err := getFbsYangNode(path)
//	if err != nil {
//		log.Infof("Classifier %v operation ; targetNode get failed Error: %v", inParams.oper, err)
//		return res_map, tlerr.InvalidArgs("Invalid request - error: %v", err)
//	}
//
//	fbsObj := getFbsRoot(inParams.ygRoot)
//	fbsClassTblMap := make(map[string]db.Value)
//
//	if inParams.oper == DELETE {
//		if fbsObj == nil || fbsObj.Classifiers == nil || len(fbsObj.Classifiers.Classifier) == 0 {
//			log.Info("Classifiers DELETE operation; Top Level")
//			res_map[CFG_CLASSIFIER_TABLE] = fbsClassTblMap
//			return res_map, err
//		} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers/classifier{class-name}") { //ClassEntry level
//			for classKey, classVal := range fbsObj.Classifiers.Classifier {
//				log.Infof("Classifier %v DELETE operation; classVal ", classKey)
//				pretty.Print(classVal)
//				dbV := db.Value{Field: make(map[string]string)}
//				var oldDbVal db.Value
//				oldDbVal, err = inParams.d.GetEntry(CLASSIFIER_TABLE_TS, db.Key{[]string{classKey}})
//				if nil != err {
//					return res_map, err
//				}
//
//				if classVal.Config != nil { //class config level delete
//					if targetNode.Name == "match-type" {
//						dbV.Field["MATCH_TYPE"] = ""
//					} else if targetNode.Name == "description" {
//						dbV.Field["DESCRIPTION"] = ""
//					} else {
//						fbsClassTblMap[classKey] = dbV
//					}
//				} else if classVal.MatchAcl != nil { //class  matchacl delete
//					dbV.Field["ACL_NAME"] = ""
//					dbV.Field["ACL_TYPE"] = ""
//				} else if classVal.MatchHdrFields != nil { //class matchHdrFields delete
//					del_l2_flds := targetNode.Name == "match-hdr-fields"
//					del_ip_flds := targetNode.Name == "match-hdr-fields"
//					del_ipv4_flds := targetNode.Name == "match-hdr-fields"
//					del_ipv6_flds := targetNode.Name == "match-hdr-fields"
//					del_trans_flds := targetNode.Name == "match-hdr-fields"
//
//					if classVal.MatchHdrFields.L2 != nil { //class L2 matchhdrfields
//						if classVal.MatchHdrFields.L2.Config != nil { //class L2 matchhdrfields config
//							// TODO Handle source-mac-mask and dest-mac-mask delete
//							if targetNode.Name == "source-mac" {
//								dbV.Field["SRC_MAC"] = ""
//							} else if targetNode.Name == "source-mac-mask" {
//								oldValue, mac_found := oldDbVal.Field["SRC_MAC"]
//								if mac_found {
//									dbV.Field["SRC_MAC"] = strings.Split(oldValue, "/")[0]
//								} else {
//									dbV.Field["SRC_MAC"] = ""
//								}
//							} else if targetNode.Name == "destination-mac" {
//								dbV.Field["DST_MAC"] = ""
//							} else if targetNode.Name == "destination-mac-mask" {
//								oldValue, mac_found := oldDbVal.Field["DST_MAC"]
//								if mac_found {
//									dbV.Field["DST_MAC"] = strings.Split(oldValue, "/")[0]
//								} else {
//									dbV.Field["DST_MAC"] = ""
//								}
//							} else if targetNode.Name == "ethertype" {
//								dbV.Field["ETHER_TYPE"] = ""
//							} else if targetNode.Name == "pcp" {
//								dbV.Field["PCP"] = ""
//							} else if targetNode.Name == "dei" {
//								dbV.Field["DEI"] = ""
//							} else if targetNode.Name == "vlanid" {
//								dbV.Field["VLAN"] = ""
//							} else {
//								del_l2_flds = true
//							}
//						} else {
//							del_l2_flds = true
//						}
//					} else if classVal.MatchHdrFields.Ip != nil {
//						if classVal.MatchHdrFields.Ip.Config != nil {
//							if targetNode.Name == "dscp" {
//								dbV.Field["DSCP"] = ""
//							} else if targetNode.Name == "protocol" {
//								dbV.Field["IP_PROTOCOL"] = ""
//							} else {
//								del_ip_flds = true
//							}
//						} else {
//							del_ip_flds = true
//						}
//					} else if classVal.MatchHdrFields.Ipv4 != nil { //class Ipv4 matchhdrfields
//						if classVal.MatchHdrFields.Ipv4.Config != nil { //class Ipv4 matchhdrfields config
//							if targetNode.Name == "source-address" {
//								dbV.Field["SRC_IP"] = ""
//							} else if targetNode.Name == "destination-address" {
//								dbV.Field["DST_IP"] = ""
//							} else {
//								del_ipv4_flds = true
//							}
//						} else {
//							del_ipv4_flds = true
//						}
//					} else if classVal.MatchHdrFields.Ipv6 != nil { //class Ipv6 matchhdrfields
//						if classVal.MatchHdrFields.Ipv6.Config != nil { //class Ipv4 matchhdrfields config
//							if targetNode.Name == "source-address" {
//								dbV.Field["SRC_IPV6"] = ""
//							} else if targetNode.Name == "destination-address" {
//								dbV.Field["DST_IPV6"] = ""
//							} else {
//								del_ipv6_flds = true
//							}
//						} else {
//							del_ipv6_flds = true
//						}
//					} else if classVal.MatchHdrFields.Transport != nil { //class Ipv6 matchhdrfields
//						if classVal.MatchHdrFields.Transport.Config != nil { //class Ipv4 matchhdrfields config
//							if targetNode.Name == "source-port" {
//								dbV.Field["L4_SRC_PORT"] = ""
//								dbV.Field["L4_SRC_PORT_RANGE"] = ""
//							} else if targetNode.Name == "destination-port" {
//								dbV.Field["L4_DST_PORT"] = ""
//								dbV.Field["L4_DST_PORT_RANGE"] = ""
//							} else if targetNode.Name == "tcp-flags" {
//								if len(classVal.MatchHdrFields.Transport.Config.TcpFlags) > 0 {
//									log.Info("Delete specific flag")
//									existing, found := oldDbVal.Field["TCP_FLAGS"]
//									if found {
//										var newTcpFlags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS
//										for _, flag := range getTransportConfigTcpFlags(existing) {
//											if flag != classVal.MatchHdrFields.Transport.Config.TcpFlags[0] {
//												newTcpFlags = append(newTcpFlags, flag)
//											}
//										}
//										if len(newTcpFlags) > 0 {
//											dbV.Field["TCP_FLAGS"] = convertOCTcpFlagsToDbFormat(newTcpFlags)
//										} else {
//											dbV.Field["TCP_FLAGS"] = ""
//										}
//									}
//								} else {
//									log.Info("Delete all flag")
//									dbV.Field["TCP_FLAGS"] = ""
//								}
//							} else if targetNode.Name == "icmp-code" {
//								dbV.Field["ICMP_CODE"] = ""
//							} else if targetNode.Name == "icmp-type" {
//								dbV.Field["ICMP_TYPE"] = ""
//							} else {
//								del_trans_flds = true
//							}
//						} else {
//							del_trans_flds = true
//						}
//					} //transport
//					if del_l2_flds {
//						dbV.Field["SRC_MAC"] = ""
//						dbV.Field["DST_MAC"] = ""
//						dbV.Field["ETHER_TYPE"] = ""
//						dbV.Field["PCP"] = ""
//						dbV.Field["DEI"] = ""
//						dbV.Field["VLAN"] = ""
//					}
//					if del_ip_flds {
//						dbV.Field["DSCP"] = ""
//						dbV.Field["IP_PROTOCOL"] = ""
//					}
//					if del_ipv4_flds {
//						dbV.Field["SRC_IP"] = ""
//						dbV.Field["DST_IP"] = ""
//					}
//					if del_ipv6_flds {
//						dbV.Field["SRC_IPV6"] = ""
//						dbV.Field["DST_IPV6"] = ""
//					}
//					if del_trans_flds {
//						dbV.Field["L4_SRC_PORT"] = ""
//						dbV.Field["L4_SRC_PORT_RANGE"] = ""
//						dbV.Field["L4_DST_PORT"] = ""
//						dbV.Field["L4_DST_PORT_RANGE"] = ""
//						dbV.Field["TCP_FLAGS"] = ""
//						dbV.Field["ICMP_CODE"] = ""
//						dbV.Field["ICMP_TYPE"] = ""
//					}
//				} else { //matchhdrfields
//					fbsClassTblMap[classKey] = dbV
//				}
//				if len(dbV.Field) != 0 {
//					fbsClassTblMap[classKey] = dbV
//				}
//			} //classifiers forloop
//
//			if len(fbsClassTblMap) > 0 {
//				log.Infof("Fbs Class level DELETE operation")
//				res_map[CFG_CLASSIFIER_TABLE] = fbsClassTblMap
//			}
//		} //class level delete
//
//		return res_map, err
//	} //DELETE - END
//
//	//CRU
//	for className, classVal := range fbsObj.Classifiers.Classifier {
//		if classVal == nil {
//			continue
//		}
//		log.Infof("Classifier CRUD: --> key: %v classVal", className)
//		pretty.Print(classVal)
//
//		_, found := fbsClassTblMap[className]
//		if !found {
//			fbsClassTblMap[className] = db.Value{Field: make(map[string]string)}
//		}
//		log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", classVal, fbsClassTblMap)
//		var matchType string
//		if classVal.Config != nil {
//			matchType, _ = getClassMatchTypeDbStrromOcEnum(classVal.Config.MatchType)
//			if classVal.Config.Description != nil {
//				fbsClassTblMap[className].Field["DESCRIPTION"] = *classVal.Config.Description
//			}
//		} else if classVal.MatchAcl != nil {
//			matchType = SONIC_CLASS_MATCH_TYPE_ACL
//		} else if classVal.MatchHdrFields != nil {
//			matchType = SONIC_CLASS_MATCH_TYPE_FIELDS
//		}
//		if matchType != "" {
//			fbsClassTblMap[className].Field["MATCH_TYPE"] = matchType
//			log.Infof("Classifier CRUD: class%v matchType:%v ", classVal, matchType)
//		}
//
//		if matchType == SONIC_CLASS_MATCH_TYPE_ACL {
//			if classVal.MatchAcl != nil && classVal.MatchAcl.Config != nil {
//				ocAclName := *(classVal.MatchAcl.Config.AclName)
//				ocAclType := classVal.MatchAcl.Config.AclType
//				fbsClassTblMap[className].Field["ACL_NAME"] = ocAclName
//				if ocAclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4 {
//					fbsClassTblMap[className].Field["ACL_TYPE"] = "L3"
//				} else if ocAclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV6 {
//					fbsClassTblMap[className].Field["ACL_TYPE"] = "L3V6"
//				} else if ocAclType == ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2 {
//					fbsClassTblMap[className].Field["ACL_TYPE"] = "L2"
//				}
//
//				log.Infof("Classifier CRUD: matchType ACL --> key: %v fbsClassTblMap:%v ", className, fbsClassTblMap)
//			}
//		} else if matchType == SONIC_CLASS_MATCH_TYPE_FIELDS && classVal.MatchHdrFields != nil {
//			log.Infof("Classifier CRUD: class%v matchType:%v ", classVal, matchType)
//			//Fill L2 Fields - START
//			if classVal.MatchHdrFields.L2 != nil && classVal.MatchHdrFields.L2.Config != nil {
//				if classVal.MatchHdrFields.L2.Config.DestinationMac != nil {
//					ocMacStr := *(classVal.MatchHdrFields.L2.Config.DestinationMac)
//					log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
//					if classVal.MatchHdrFields.L2.Config.DestinationMacMask != nil {
//						log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, *(classVal.MatchHdrFields.L2.Config.DestinationMacMask))
//						ocMacStr = ocMacStr + "/" + *(classVal.MatchHdrFields.L2.Config.DestinationMacMask)
//					}
//					log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
//					fbsClassTblMap[className].Field["DST_MAC"] = ocMacStr
//				}
//
//				if classVal.MatchHdrFields.L2.Config.SourceMac != nil {
//					ocMacStr := *(classVal.MatchHdrFields.L2.Config.SourceMac)
//					log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
//					if classVal.MatchHdrFields.L2.Config.SourceMacMask != nil {
//						log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, *(classVal.MatchHdrFields.L2.Config.SourceMacMask))
//						ocMacStr = ocMacStr + "/" + *(classVal.MatchHdrFields.L2.Config.SourceMacMask)
//					}
//					log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
//					fbsClassTblMap[className].Field["SRC_MAC"] = ocMacStr
//					log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
//				}
//
//				if classVal.MatchHdrFields.L2.Config.Dei != nil {
//					fbsClassTblMap[className].Field["DEI"] = strconv.Itoa(int(*(classVal.MatchHdrFields.L2.Config.Dei)))
//				}
//				if classVal.MatchHdrFields.L2.Config.Pcp != nil {
//					fbsClassTblMap[className].Field["PCP"] = strconv.Itoa(int(*(classVal.MatchHdrFields.L2.Config.Pcp)))
//				}
//				if classVal.MatchHdrFields.L2.Config.Vlanid != nil {
//					log.Infof("Classifier CRUD: class%v vlanid:%v type:%v ", className, *classVal.MatchHdrFields.L2.Config.Vlanid, reflect.TypeOf(*classVal.MatchHdrFields.L2.Config.Vlanid))
//					fbsClassTblMap[className].Field["VLAN"] = strconv.Itoa(int(*classVal.MatchHdrFields.L2.Config.Vlanid))
//					log.Infof("Classifier CRUD: class%v vlanid:%v type:%v ", className, *classVal.MatchHdrFields.L2.Config.Vlanid, reflect.TypeOf(*classVal.MatchHdrFields.L2.Config.Vlanid))
//				}
//
//				if classVal.MatchHdrFields.L2.Config.Ethertype != nil {
//					ethertypeType := reflect.TypeOf(classVal.MatchHdrFields.L2.Config.Ethertype).Elem()
//					var b bytes.Buffer
//					switch ethertypeType {
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE{}):
//						v := classVal.MatchHdrFields.L2.Config.Ethertype.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE)
//						fmt.Fprintf(&b, "0x%x", ETHERTYPE_MAP[v.E_OpenconfigPacketMatchTypes_ETHERTYPE])
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_Uint16{}):
//						v := classVal.MatchHdrFields.L2.Config.Ethertype.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_Uint16)
//						fmt.Fprintf(&b, "0x%x", v.Uint16)
//					}
//					fbsClassTblMap[className].Field["ETHER_TYPE"] = b.String()
//				}
//				log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
//			}
//			//Fill L2 Fields - END
//
//			//Fill IPV4/Ipv6 Fields - START
//			if classVal.MatchHdrFields.Ipv4 != nil && classVal.MatchHdrFields.Ipv4.Config != nil {
//				if classVal.MatchHdrFields.Ipv4.Config.SourceAddress != nil {
//					fbsClassTblMap[className].Field["SRC_IP"] = *(classVal.MatchHdrFields.Ipv4.Config.SourceAddress)
//				}
//				if classVal.MatchHdrFields.Ipv4.Config.DestinationAddress != nil {
//					fbsClassTblMap[className].Field["DST_IP"] = *(classVal.MatchHdrFields.Ipv4.Config.DestinationAddress)
//				}
//			}
//			if classVal.MatchHdrFields.Ip != nil && classVal.MatchHdrFields.Ip.Config != nil {
//				if classVal.MatchHdrFields.Ip.Config.Dscp != nil {
//					fbsClassTblMap[className].Field["DSCP"] = strconv.Itoa(int(*classVal.MatchHdrFields.Ip.Config.Dscp))
//				}
//				if classVal.MatchHdrFields.Ip.Config.Protocol != nil {
//					ipProtocolType := reflect.TypeOf(classVal.MatchHdrFields.Ip.Config.Protocol).Elem()
//					var dbIpProto string
//					switch ipProtocolType {
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
//						v := classVal.MatchHdrFields.Ip.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
//						dbIpProto = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_Uint8{}):
//						v := classVal.MatchHdrFields.Ip.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ip_Config_Protocol_Union_Uint8)
//						dbIpProto = strconv.FormatInt(int64(v.Uint8), 10)
//					}
//					fbsClassTblMap[className].Field["IP_PROTOCOL"] = dbIpProto
//				}
//				log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
//			}
//
//			if classVal.MatchHdrFields.Ipv6 != nil && classVal.MatchHdrFields.Ipv6.Config != nil {
//				if classVal.MatchHdrFields.Ipv6.Config.SourceAddress != nil {
//					fbsClassTblMap[className].Field["SRC_IPV6"] = *(classVal.MatchHdrFields.Ipv6.Config.SourceAddress)
//				}
//				if classVal.MatchHdrFields.Ipv6.Config.DestinationAddress != nil {
//					fbsClassTblMap[className].Field["DST_IPV6"] = *(classVal.MatchHdrFields.Ipv6.Config.DestinationAddress)
//				}
//				log.Infof("Classifier CRUD: matchType FIELDS --> key: %v fbsClassTblMap:%v ", className, fbsClassTblMap)
//			}
//			//Fill IPV4/Ipv6 Fields - END
//
//			//Fill Transport Fields - START
//			if classVal.MatchHdrFields.Transport != nil && classVal.MatchHdrFields.Transport.Config != nil {
//				if classVal.MatchHdrFields.Transport.Config.SourcePort != nil {
//					srcPortType := reflect.TypeOf(classVal.MatchHdrFields.Transport.Config.SourcePort).Elem()
//					switch srcPortType {
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort{}):
//						v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort)
//
//						fbsClassTblMap[className].Field["L4_SRC_PORT"] = v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort.ΛMap()["E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort"][int64(v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort)].Name
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_String{}):
//						v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_String)
//						fbsClassTblMap[className].Field["L4_SRC_PORT_RANGE"] = strings.Replace(v.String, "..", "-", 1)
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_Uint16{}):
//						v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_Uint16)
//						fbsClassTblMap[className].Field["L4_SRC_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
//					}
//
//				}
//				if classVal.MatchHdrFields.Transport.Config.DestinationPort != nil {
//					dstPortType := reflect.TypeOf(classVal.MatchHdrFields.Transport.Config.DestinationPort).Elem()
//					switch dstPortType {
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort{}):
//						v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort)
//
//						fbsClassTblMap[className].Field["L4_DST_PORT"] = v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort.ΛMap()["E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort"][int64(v.E_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort)].Name
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_String{}):
//						v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_String)
//						fbsClassTblMap[className].Field["L4_DST_PORT_RANGE"] = strings.Replace(v.String, "..", "-", 1)
//					case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_Uint16{}):
//						v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_Uint16)
//						fbsClassTblMap[className].Field["L4_DST_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
//					}
//				}
//				if classVal.MatchHdrFields.Transport.Config.TcpFlags != nil && len(classVal.MatchHdrFields.Transport.Config.TcpFlags) > 0 {
//					log.Infof("Classifier CRUD: TCP_Flags:%v", classVal.MatchHdrFields.Transport.Config.TcpFlags)
//					fbsClassTblMap[className].Field["TCP_FLAGS"] = convertOCTcpFlagsToDbFormat(classVal.MatchHdrFields.Transport.Config.TcpFlags)
//					//Fill Transport Fields - END
//				}
//			}
//		}
//	}
//
//	//for replace operation delete all entries except matching ones
//	if inParams.oper == REPLACE {
//		log.Infof("Classifier REPLACE Operation ")
//		classTbl, _ := inParams.d.GetTable(CLASSIFIER_TABLE_TS)
//		classKeys, _ := classTbl.GetKeys()
//		if len(classKeys) > 0 {
//			for _, key := range classKeys {
//				className := key.Get(0)
//				_, found := fbsClassTblMap[className]
//				if !found {
//					fbsClassTblMap[className] = db.Value{Field: make(map[string]string)}
//				}
//				fbsClassTblMap[className].Field["NULL"] = "NULL"
//			}
//		}
//	}
//	res_map[CFG_CLASSIFIER_TABLE] = fbsClassTblMap
//	log.Info(res_map)
//
//	return res_map, err
//}
//
//func convertOCTcpFlagsToDbFormat(flags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS) string {
//	var tcpFlags uint32 = 0x00
//	var tcpFlagsMask uint32 = 0x00
//	for _, flag := range flags {
//		switch flag {
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN:
//			tcpFlags |= 0x01
//			tcpFlagsMask |= 0x1
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_FIN:
//			tcpFlagsMask |= 0x1
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN:
//			tcpFlags |= 0x02
//			tcpFlagsMask |= 0x2
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_SYN:
//			tcpFlagsMask |= 0x2
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST:
//			tcpFlags |= 0x04
//			tcpFlagsMask |= 0x4
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_RST:
//			tcpFlagsMask |= 0x4
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH:
//			tcpFlags |= 0x08
//			tcpFlagsMask |= 0x8
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_PSH:
//			tcpFlagsMask |= 0x8
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK:
//			tcpFlags |= 0x10
//			tcpFlagsMask |= 0x10
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ACK:
//			tcpFlagsMask |= 0x10
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG:
//			tcpFlags |= 0x20
//			tcpFlagsMask |= 0x20
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_URG:
//			tcpFlagsMask |= 0x20
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE:
//			tcpFlags |= 0x40
//			tcpFlagsMask |= 0x40
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_ECE:
//			tcpFlagsMask |= 0x40
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR:
//			tcpFlags |= 0x80
//			tcpFlagsMask |= 0x80
//		case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_NOT_CWR:
//			tcpFlagsMask |= 0x80
//		}
//	}
//	var b bytes.Buffer
//	fmt.Fprintf(&b, "0x%x/0x%x", tcpFlags, tcpFlagsMask)
//
//	return b.String()
//}
//
////Classifiers - END
//
////Policiers - START
//
////getPolicyTypeOCEnumFromDbStr function gets OC Yang Enum corresponding policyType string from DB
//func getPolicyTypeOCEnumFromDbStr(val string) (ocbinds.E_OpenconfigFbsExt_POLICY_TYPE, error) {
//	switch val {
//	case SONIC_POLICY_TYPE_QOS, "openconfig-fbs-ext:QOS":
//		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_QOS, nil
//	case SONIC_POLICY_TYPE_FORWARDING, "openconfig-fbs-ext:FORWARDING":
//		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_FORWARDING, nil
//	case SONIC_POLICY_TYPE_MONITORING, "openconfig-fbs-ext:MONITORING":
//		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_MONITORING, nil
//	default:
//		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_UNSET,
//			tlerr.NotSupported("FBS Policy Type '%s' not supported", val)
//	}
//}
//
//func getPolicyTypeDbStrromOcEnum(ocPolicyType ocbinds.E_OpenconfigFbsExt_POLICY_TYPE) (string, error) {
//	dbPolicyType := ""
//	if ocPolicyType == ocbinds.OpenconfigFbsExt_POLICY_TYPE_UNSET {
//		return "", tlerr.NotSupported("FBS Policy Type not set")
//	}
//	dbPolicyType = findInMap(POLICY_POLICY_TYPE_MAP, strconv.FormatInt(int64(ocPolicyType), 10))
//	return dbPolicyType, nil
//}
//
//func fillFbsPolicySectionDetails(inParams XfmrParams, policyName string, policyData *ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy) {
//	log.Infof("policyName:%v", policyName)
//
//	policySectionTbl, _ := inParams.d.GetTable(POLICY_SECTION_TABLE_TS)
//	policySectionKeys, _ := inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{policyName, "*"}})
//	log.Infof("Policy Get;clasKeys %v policySectionTbl:%v ", policySectionKeys, policySectionTbl)
//
//	if len(policySectionKeys) > 0 {
//		for _, key := range policySectionKeys {
//			className := key.Get(1)
//			log.Infof("Policy Get;Key:%v policyName:%v className:%v ", key, policyName, className)
//			policySectionData, _ := policyData.Sections.NewSection(className)
//			if policySectionData == nil {
//				policySectionData = policyData.Sections.Section[className]
//			}
//			policySectionTblVal, _ := policySectionTbl.GetEntry(key)
//
//			//Fill PolicySectionDetails
//			ygot.BuildEmptyTree(policySectionData)
//			policySectionData.Class = &className
//			policySectionData.Config.Name = &className
//			policySectionData.State.Name = &className
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//			if str_val, found := policySectionTblVal.Field["PRIORITY"]; found {
//				priority, _ := strconv.Atoi(str_val)
//				oc_priority := uint16(priority)
//				policySectionData.Config.Priority = &(oc_priority)
//				policySectionData.State.Priority = &(oc_priority)
//			}
//
//			//Forwarding START
//			//forwarding Config
//			if str_val, found := policySectionTblVal.Field["DEFAULT_PACKET_ACTION"]; found {
//				ygot.BuildEmptyTree(policySectionData.Forwarding)
//				dropFlag := false
//				if str_val == SONIC_PACKET_ACTION_DROP {
//					dropFlag = true
//				}
//				policySectionData.Forwarding.Config.Discard = &(dropFlag)
//			}
//
//			//forwarding EgressInterfaces
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//			if intfs := policySectionTblVal.GetList("SET_INTERFACE"); len(intfs) > 0 {
//				ygot.BuildEmptyTree(policySectionData.Forwarding)
//				ygot.BuildEmptyTree(policySectionData.Forwarding.EgressInterfaces)
//				for i := range intfs {
//					intfSplits := strings.Split(intfs[i], "|")
//                    convertedIfName := *(utils.GetUINameFromNativeName(&intfSplits[0]))
//					egressIfName := convertedIfName
//					egressIfData, _ := policySectionData.Forwarding.EgressInterfaces.NewEgressInterface(egressIfName)
//					ygot.BuildEmptyTree(egressIfData)
//					egressIfData.IntfName = &egressIfName
//					egressIfData.Config.IntfName = &egressIfName
//					egressIfData.State.IntfName = &egressIfName
//					if len(intfSplits[1]) > 0 {
//						prio, _ := strconv.Atoi(intfSplits[1])
//						oc_prio := uint16(prio)
//						egressIfData.Config.Priority = &oc_prio
//						egressIfData.State.Priority = &oc_prio
//					}
//				}
//			}
//
//			//forwarding NextHops
//			var ipNhops []string
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//			if ipNhops = policySectionTblVal.GetList("SET_IP_NEXTHOP"); len(ipNhops) == 0 {
//				ipNhops = policySectionTblVal.GetList("SET_IPV6_NEXTHOP")
//			}
//			if len(ipNhops) > 0 {
//				ygot.BuildEmptyTree(policySectionData.Forwarding)
//				ygot.BuildEmptyTree(policySectionData.Forwarding.NextHops)
//				for i := range ipNhops {
//					nhopSplits := strings.Split(ipNhops[i], "|")
//					nhopIp := nhopSplits[0]
//					//TBD - how to get default network instance
//					vrf := "default"
//					if len(nhopSplits[1]) > 0 {
//						vrf = nhopSplits[1]
//					}
//					nhopData, _ := policySectionData.Forwarding.NextHops.NewNextHop(nhopIp, vrf)
//					ygot.BuildEmptyTree(nhopData)
//					nhopData.IpAddress = &nhopIp
//					nhopData.NetworkInstance = &vrf
//
//					nhopData.Config.IpAddress = &nhopIp
//					nhopData.Config.NetworkInstance = &vrf
//
//					nhopData.State.IpAddress = &nhopIp
//					nhopData.State.NetworkInstance = &vrf
//					if len(nhopSplits[2]) > 0 {
//						prio, _ := strconv.Atoi(nhopSplits[2])
//						oc_prio := uint16(prio)
//						nhopData.Config.Priority = &oc_prio
//						nhopData.State.Priority = &oc_prio
//					}
//				}
//			}
//			//Forwarding - END
//
//			//Monitoring - START
//			if str_val, found := policySectionTblVal.Field["SET_MIRROR_SESSION"]; found {
//				ygot.BuildEmptyTree(policySectionData.Monitoring)
//				mirrorData, _ := policySectionData.Monitoring.MirrorSessions.NewMirrorSession(str_val)
//				ygot.BuildEmptyTree(mirrorData)
//				mirrorData.Config.SessionName = &str_val
//				mirrorData.State.SessionName = &str_val
//			}
//			//Forwarding - END
//
//			//QOS - START
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//			if str_val, found := policySectionTblVal.Field["SET_POLICER_CIR"]; found {
//				ygot.BuildEmptyTree(policySectionData.Qos)
//				ygot.BuildEmptyTree(policySectionData.Qos.Policer)
//				val, _ := strconv.ParseUint(str_val, 10, 64)
//				policySectionData.Qos.Policer.Config.Cir = &val
//				policySectionData.Qos.Policer.State.Cir = &val
//			}
//			if str_val, found := policySectionTblVal.Field["SET_POLICER_CBS"]; found {
//				val, _ := strconv.ParseUint(str_val, 10, 64)
//				policySectionData.Qos.Policer.Config.Bc = &val
//				policySectionData.Qos.Policer.State.Bc = &val
//			}
//			if str_val, found := policySectionTblVal.Field["SET_POLICER_PIR"]; found {
//				val, _ := strconv.ParseUint(str_val, 10, 64)
//				policySectionData.Qos.Policer.Config.Pir = &val
//				policySectionData.Qos.Policer.State.Pir = &val
//			}
//			if str_val, found := policySectionTblVal.Field["SET_POLICER_PBS"]; found {
//				val, _ := strconv.ParseUint(str_val, 10, 64)
//				policySectionData.Qos.Policer.Config.Be = &val
//				policySectionData.Qos.Policer.State.Be = &val
//			}
//			if str_val, found := policySectionTblVal.Field["SET_PCP"]; found {
//				ygot.BuildEmptyTree(policySectionData.Qos)
//				ygot.BuildEmptyTree(policySectionData.Qos.Remark)
//				val, _ := strconv.ParseUint(str_val, 10, 8)
//				val8 := uint8(val)
//				policySectionData.Qos.Remark.Config.SetDot1P = &val8
//				policySectionData.Qos.Remark.State.SetDot1P = &val8
//			}
//			if str_val, found := policySectionTblVal.Field["SET_DSCP"]; found {
//				ygot.BuildEmptyTree(policySectionData.Qos)
//				ygot.BuildEmptyTree(policySectionData.Qos.Remark)
//				val, _ := strconv.ParseUint(str_val, 10, 8)
//				val8 := uint8(val)
//				policySectionData.Qos.Remark.Config.SetDscp = &val8
//				policySectionData.Qos.Remark.State.SetDscp = &val8
//			}
//			if str_val, found := policySectionTblVal.Field["SET_TC"]; found {
//				ygot.BuildEmptyTree(policySectionData.Qos)
//				ygot.BuildEmptyTree(policySectionData.Qos.Queuing)
//				val, _ := strconv.ParseUint(str_val, 10, 8)
//				val8 := uint8(val)
//				policySectionData.Qos.Queuing.Config.OutputQueueIndex = &val8
//				policySectionData.Qos.Queuing.State.OutputQueueIndex = &val8
//			}
//
//			//QOS - END
//		}
//	}
//	pretty.Print(policyData)
//}
//
////convert from DB to OCYang and fill to OcYang Datastructure for given policy
//func fillFbsPolicyDetails(inParams XfmrParams, policyName string, policyTblVal db.Value, policyData *ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy) {
//	if policyData == nil {
//		log.Infof("fillFbsPolicyDetails--> policyData empty ; policyName:%v ", policyName)
//		return
//	}
//
//	ygot.BuildEmptyTree(policyData)
//
//	policyData.PolicyName = &policyName
//	policyType := policyTblVal.Get("TYPE")
//
//	policyData.Config.Name = &policyName
//	log.Infof("fillFbsPolicyDetails--> filled config container with policyName:%v and type:%v", policyName, policyType)
//
//	ocPolicyType, _ := getPolicyTypeOCEnumFromDbStr(policyType)
//	policyData.Config.Type = ocPolicyType
//	policyData.State.Type = policyData.Config.Type
//	policyData.State.Name = policyData.Config.Name
//
//	fillFbsPolicySectionDetails(inParams, policyName, policyData)
//}
//
////DbToYang_fbs_policy_subtree_xfmr function takes care of handling Get operation for policy urls
//var DbToYang_fbs_policy_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
//	var err error
//
//	pathInfo := NewPathInfo(inParams.uri)
//
//	fbsObj := getFbsRoot(inParams.ygRoot)
//	ygot.BuildEmptyTree(fbsObj)
//	log.Infof("Policy Get;path:%v pathfbsObj:%v ", pathInfo.Template, fbsObj)
//	log.Info("fbsobj ")
//	pretty.Print(fbsObj)
//
//	log.Info("targetObj ")
//	pretty.Print(inParams.param)
//
//	if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}") { //policy level request
//
//		policyKeys := reflect.ValueOf(fbsObj.Policies.Policy).MapKeys()
//		policyObj := fbsObj.Policies.Policy[policyKeys[0].Interface().(string)]
//		policyName := pathInfo.Var("policy-name")
//		log.Infof("Policy Get;policy level request; policyName:%v ", policyName)
//
//		ygot.BuildEmptyTree(policyObj)
//
//		PolicyTbl, _ := inParams.d.GetTable(POLICY_TABLE_TS)
//		PolicyTblVal, _ := PolicyTbl.GetEntry(db.Key{[]string{policyKeys[0].Interface().(string)}})
//		fillFbsPolicyDetails(inParams, policyName, PolicyTblVal, policyObj)
//	} else { //top level get
//		log.Infof("Policy Get;top level Get")
//
//		PolicyTbl, err := inParams.d.GetTable(POLICY_TABLE_TS)
//		if err != nil {
//			log.Infof("Policy Get; couldn't get Policy table")
//		}
//
//		policyKeys, _ := PolicyTbl.GetKeys()
//		log.Infof("Policy Get;clasKeys %v PolicyTbl:%v ", policyKeys, PolicyTbl)
//
//		if len(policyKeys) > 0 {
//			for _, key := range policyKeys {
//				policyName := key.Get(0)
//				log.Infof("Policy Get;Key:%v policyName:%v ", key, policyName)
//				policyObj, _ := fbsObj.Policies.NewPolicy(policyName)
//				PolicyTblVal, _ := PolicyTbl.GetEntry(key)
//				fillFbsPolicyDetails(inParams, policyName, PolicyTblVal, policyObj)
//				log.Infof("Policy Get;top level request; PolicyTblVal:%v  ", PolicyTblVal)
//			}
//		}
//	}
//	return err
//}
//
////YangToDb_fbs_policy_subtree_xfmr function takes care of handling CRUD operations for policy urls
//var YangToDb_fbs_policy_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
//	var err error
//	var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)
//
//	pathInfo := NewPathInfo(inParams.uri)
//
//	log.Infof("Opcode:%v URI:%v Req:%v", inParams.oper, inParams.uri, inParams.requestUri)
//	log.Info("pathInfo")
//	pretty.Print(pathInfo)
//
//	path, err := getFbsUriPath(inParams.uri)
//	if err != nil {
//		log.Infof("Policy CRUD;: path get error:%v ", err)
//		return nil, err
//	}
//	targetNode, err := getFbsYangNode(path)
//	if err != nil {
//		log.Infof("Policy %v operation ; targetNode get failed Error: %v", inParams.oper)
//		return res_map, tlerr.InvalidArgs("Invalid request - error: %v", err)
//	}
//	log.Infof("TargetNode %v", targetNode.Name)
//
//	fbsObj := getFbsRoot(inParams.ygRoot)
//	pretty.Print(fbsObj)
//
//	fbsPolicyTblMap := make(map[string]db.Value)
//	fbsPolicySectionTblMap := make(map[string]db.Value)
//
//	if inParams.oper == DELETE {
//		if fbsObj == nil || fbsObj.Policies == nil || len(fbsObj.Policies.Policy) == 0 {
//			log.Info("Policy DELETE operation; Top Level")
//			res_map[CFG_POLICY_TABLE] = fbsPolicyTblMap
//			res_map[CFG_POLICY_SECTIONS_TABLE] = fbsPolicySectionTblMap
//			return res_map, err
//		} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}") { //policyEntry level
//			for policyKey, policyVal := range fbsObj.Policies.Policy {
//				policyName := policyKey
//				log.Infof("DELETE Policy:%v related", policyKey)
//				dbV := db.Value{Field: make(map[string]string)}
//				sectionDbV := db.Value{Field: make(map[string]string)}
//				if policyVal.Config != nil { //policy config level delete
//					if targetNode.Name == "type" {
//						return res_map, tlerr.NotSupported("Type delete not allowed")
//					} else if targetNode.Name == "description" {
//						dbV.Field["DESCRIPTION"] = ""
//					} else {
//						fbsPolicyTblMap[policyKey] = dbV
//					}
//				} else if policyVal.Sections != nil { //policy Sections
//					if policyVal.Sections.Section != nil { //policy section
//						for className, policySectionVal := range policyVal.Sections.Section {
//							sectionDbKeyStr := policyName + "|" + className
//							log.Infof("DELETE Section:%v related", sectionDbKeyStr)
//							if policySectionVal.Config != nil { //policy section config
//								if targetNode.Name == "priority" {
//									return res_map, tlerr.NotSupported("Priority delete not allowed")
//								} else if targetNode.Name == "description" {
//									sectionDbV.Field["DESCRIPTION"] = ""
//								} else {
//									fbsPolicySectionTblMap[sectionDbKeyStr] = dbV
//								}
//							} else if policySectionVal.Qos != nil { //policy section Qos
//								delRemark := false
//								delPolicer := false
//								delQueue := false
//								if policySectionVal.Qos.Remark != nil { //policy section Qos Remark
//									if policySectionVal.Qos.Remark.Config != nil { //policy section Qos Remark
//										if targetNode.Name == "set-dscp" {
//											sectionDbV.Field["SET_DSCP"] = ""
//										} else if targetNode.Name == "set-dot1p" {
//											sectionDbV.Field["SET_PCP"] = ""
//										} else {
//											delRemark = true
//										}
//									} else { //qos remark config
//										delRemark = true
//									}
//								} else if policySectionVal.Qos.Policer != nil { //policer
//									if policySectionVal.Qos.Policer.Config != nil { //policer config
//										if targetNode.Name == "cir" {
//											sectionDbV.Field["SET_POLICER_CIR"] = ""
//										} else if targetNode.Name == "pir" {
//											sectionDbV.Field["SET_POLICER_PIR"] = ""
//										} else if targetNode.Name == "bc" {
//											sectionDbV.Field["SET_POLICER_CBS"] = ""
//										} else if targetNode.Name == "be" {
//											sectionDbV.Field["SET_POLICER_PBS"] = ""
//										} else {
//											delPolicer = true
//										}
//									} else {
//										delPolicer = true
//									}
//								} else if policySectionVal.Qos.Queuing != nil { //queuing
//									if policySectionVal.Qos.Queuing.Config != nil { //queuing config
//										if targetNode.Name == "output-queue-index" {
//											sectionDbV.Field["SET_TC"] = ""
//										} else {
//											delQueue = true
//										}
//									} else {
//										delRemark = true
//									}
//								} else {
//									delRemark = true
//									delPolicer = true
//									delQueue = true
//								}
//
//								if delRemark {
//									sectionDbV.Field["SET_DSCP"] = ""
//									sectionDbV.Field["SET_PCP"] = ""
//								}
//								if delPolicer {
//									sectionDbV.Field["SET_POLICER_CIR"] = ""
//									sectionDbV.Field["SET_POLICER_PIR"] = ""
//									sectionDbV.Field["SET_POLICER_CBS"] = ""
//									sectionDbV.Field["SET_POLICER_PBS"] = ""
//								}
//								if delQueue {
//									sectionDbV.Field["SET_TC"] = ""
//								}
//							} else if policySectionVal.Monitoring != nil { //monitoring
//								if policySectionVal.Monitoring.MirrorSessions != nil && policySectionVal.Monitoring.MirrorSessions.MirrorSession != nil {
//									for _, mirrorSessionVal := range policySectionVal.Monitoring.MirrorSessions.MirrorSession {
//										if mirrorSessionVal.Config != nil {
//											sectionDbV.Field["SET_MIRROR_SESSION"] = ""
//										}
//									}
//								} else {
//									sectionDbV.Field["SET_MIRROR_SESSION"] = ""
//								}
//							} else if policySectionVal.Forwarding != nil { //forwarding
//								if policySectionVal.Forwarding.Config != nil {
//									if targetNode.Name == "discard" {
//										sectionDbV.Field["DEFAULT_PACKET_ACTION"] = ""
//									}
//								} else if policySectionVal.Forwarding.EgressInterfaces != nil {
//									if policySectionVal.Forwarding.EgressInterfaces.EgressInterface != nil {
//										egressIfsDbStr := ""
//										for uiIfName, egressIfVal := range policySectionVal.Forwarding.EgressInterfaces.EgressInterface {
//                                            egressIfName := *(utils.GetNativeNameFromUIName(&uiIfName))
//			                                log.Infof("PolicySection Field EgressIf delete uiIfName:%v nativeIfName %v", uiIfName, egressIfName)
//											if egressIfsDbStr != "" {
//												egressIfsDbStr = egressIfsDbStr + ","
//											}
//											egressIfsDbStr = egressIfsDbStr + egressIfName
//											if (egressIfVal.Config != nil) && (egressIfVal.Config.Priority != nil) {
//												egressIfsDbStr = egressIfsDbStr + "|" + strconv.FormatInt(int64(*egressIfVal.Config.Priority), 10)
//											}
//										}
//										sectionDbV.Field["SET_INTERFACE"] = egressIfsDbStr
//									}
//
//								} else if policySectionVal.Forwarding.NextHops != nil {
//									if policySectionVal.Forwarding.NextHops.NextHop != nil {
//										var v4nhopsDbStr string
//										var v6nhopsDbStr string
//										for nhopKey := range policySectionVal.Forwarding.NextHops.NextHop {
//											nhopsDbStr := nhopKey.IpAddress + "|" + nhopKey.NetworkInstance
//											if isV4Address(nhopKey.IpAddress) {
//												if len(v4nhopsDbStr) > 0 {
//													v4nhopsDbStr = v4nhopsDbStr + ","
//												}
//												v4nhopsDbStr = v4nhopsDbStr + nhopsDbStr
//
//											} else {
//												if len(v6nhopsDbStr) > 0 {
//													v6nhopsDbStr = v6nhopsDbStr + ","
//												}
//												v6nhopsDbStr = v6nhopsDbStr + nhopsDbStr
//											}
//										}
//										if len(v4nhopsDbStr) > 0 {
//											sectionDbV.Field["SET_IP_NEXTHOP"] = v4nhopsDbStr
//										}
//										if len(v6nhopsDbStr) > 0 {
//											sectionDbV.Field["SET_IPV6_NEXTHOP"] = v6nhopsDbStr
//										}
//									} else {
//										sectionDbV.Field["SET_IP_NEXTHOP"] = ""
//										sectionDbV.Field["SET_IPV6_NEXTHOP"] = ""
//									}
//								} //Nexthops - END
//							} else { //Forwarding
//								fbsPolicySectionTblMap[sectionDbKeyStr] = dbV
//							}
//							if len(sectionDbV.Field) != 0 {
//								fbsPolicySectionTblMap[sectionDbKeyStr] = sectionDbV
//							}
//						} //for loop policy section
//					} //policy section
//				} else { //policy sections
//					fbsPolicyTblMap[policyKey] = dbV
//				}
//				if len(dbV.Field) != 0 {
//					fbsPolicyTblMap[policyKey] = dbV
//				}
//			} //policies for loop
//			if len(fbsPolicyTblMap) > 0 {
//				log.Infof("Fbs policy level delete operation")
//				res_map[CFG_POLICY_TABLE] = fbsPolicyTblMap
//			}
//			if len(fbsPolicySectionTblMap) > 0 {
//				log.Infof("Fbs policy section delete operation")
//				res_map[CFG_POLICY_SECTIONS_TABLE] = fbsPolicySectionTblMap
//			}
//		} //policy level delete
//
//		log.Infof("Res:%v Err:%v", res_map, err)
//		return res_map, err
//	} //DELETE - END
//
//	//CRU
//	if inParams.oper == REPLACE {
//		replaceAllSections := false
//		if pathInfo.Template == "/openconfig-fbs-ext:fbs" ||
//			pathInfo.Template == "/openconfig-fbs-ext:fbs/policies" ||
//			pathInfo.Template == "/openconfig-fbs-ext:fbs/policies/policy" {
//
//			log.Infof("All Policies needs to be replaced.")
//			PolicyTbl, err := inParams.d.GetTable(POLICY_TABLE_TS)
//			if err != nil {
//				log.Error(err)
//				return res_map, err
//			}
//			policyKeys, _ := PolicyTbl.GetKeys()
//			for _, key := range policyKeys {
//				log.Infof("Policy %v will be deleted", key)
//				fbsPolicyTblMap[key.Get(0)] = db.Value{Field: make(map[string]string)}
//			}
//		} else if pathInfo.Template == "/openconfig-fbs-ext:fbs/policies/policy{policy-name}" {
//			log.Infof("Replace at policy %v level", pathInfo.Var("policy-name"))
//			//fbsPolicyTblMap[policyName], err = inParams.d.GetEntry(POLICY_TABLE_TS, db.Key{[]string{pathInfo.Var("policy-name")}})
//			//if err != nil {
//			//	log.Error(err)
//			//	return res_map, err
//			//}
//			fbsPolicyTblMap[pathInfo.Var("policy-name")] = db.Value{Field: make(map[string]string)}
//			replaceAllSections = true
//		}
//
//		if pathInfo.Template == "/openconfig-fbs-ext:fbs/policies/policy{policy-name}/sections" ||
//			pathInfo.Template == "/openconfig-fbs-ext:fbs/policies/policy{policy-name}/sections/section" ||
//			replaceAllSections {
//			log.Infof("Replace at all section level of policy %v", pathInfo.Var("policy-name"))
//			sectionKeys, err := inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{pathInfo.Var("policy-name"), "*"}})
//			if err != nil {
//				log.Error(err)
//				return res_map, err
//			}
//			for _, sectionKey := range sectionKeys {
//				log.Infof("Section %v will be deleted", sectionKey)
//				fbsPolicySectionTblMap[sectionKey.Get(0) + "|" + sectionKey.Get(1)] = db.Value{Field: make(map[string]string)}
//			}
//		} else {
//			log.Infof("Section specific replace of %v and %v", pathInfo.Var("policy-name"), pathInfo.Var("class"))
//			sectionKey := db.Key{[]string{pathInfo.Var("policy-name"), pathInfo.Var("class")}}
//			sectionData, err := inParams.d.GetEntry(POLICY_SECTION_TABLE_TS, sectionKey)
//			log.Info(err)
//			sectionDbKey := sectionKey.Get(0) + "|" + sectionKey.Get(1)
//			fbsPolicySectionTblMap[sectionDbKey] = sectionData
//			if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}/sections/section{class}/config") {
//				delete(fbsPolicySectionTblMap[sectionDbKey].Field, "DESCRIPTION")
//			} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}/sections/section{class}/qos") {
//				delRemark := isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}/sections/section{class}/qos/remark")
//				delQueuing := isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}/sections/section{class}/qos/queuing")
//				delPolicer := isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}/sections/section{class}/qos/policer")
//
//				if !delRemark && !delQueuing && !delPolicer {
//					delRemark = true
//					delQueuing = true
//					delPolicer = true
//				}
//				log.Infof("QoS Actions specific replace Remark:%v Queue:%v Policer:%v", delRemark, delQueuing, delPolicer)
//				if delRemark {
//					delete(fbsPolicySectionTblMap[sectionDbKey].Field, "SET_DSCP")
//				    delete(fbsPolicySectionTblMap[sectionDbKey].Field, "SET_PCP")
//				}
//				if delPolicer {
//					delete(fbsPolicySectionTblMap[sectionDbKey].Field, "SET_POLICER_CIR")
//					delete(fbsPolicySectionTblMap[sectionDbKey].Field, "SET_POLICER_PIR")
//					delete(fbsPolicySectionTblMap[sectionDbKey].Field, "SET_POLICER_CBS")
//					delete(fbsPolicySectionTblMap[sectionDbKey].Field, "SET_POLICER_PBS")
//				}
//				if delQueuing {
//					delete(fbsPolicySectionTblMap[sectionDbKey].Field, "SET_TC")
//				}
//			}
//			// TODO More actions
//		}
//	}
//
//	for policyName, policyVal := range fbsObj.Policies.Policy {
//		log.Infof("Policy:%v", policyName)
//		if inParams.oper != REPLACE {
//			if _, found := fbsPolicyTblMap[policyName]; !found {
//				log.Infof("Policy doesnt exist in cache. Create empty")
//				fbsPolicyTblMap[policyName] = db.Value{Field: make(map[string]string)}
//			}
//		}
//
//		if policyVal.Config != nil {
//			ocpolicyType, _ := getPolicyTypeDbStrromOcEnum(policyVal.Config.Type)
//			if ocpolicyType != "" {
//				fbsPolicyTblMap[policyName].Field["TYPE"] = ocpolicyType
//			}
//
//			if policyVal.Config.Description != nil {
//				fbsPolicyTblMap[policyName].Field["DESCRIPTION"] = *policyVal.Config.Description
//			}
//		}
//
//		if policyVal.Sections != nil {
//			for className, policySectionVal := range policyVal.Sections.Section {
//				log.Infof("Policy:%v Class:%v", policyName, className)
//
//				sectionDbKeyStr := policyName + "|" + className
//				_, found := fbsPolicySectionTblMap[sectionDbKeyStr]
//				if !found {
//					log.Infof("Section doesnt exist in cache. Create empty")
//					fbsPolicySectionTblMap[sectionDbKeyStr] = db.Value{Field: make(map[string]string)}
//				}
//
//				if policySectionVal.Config != nil {
//                    if policySectionVal.Config.Priority != nil {
//    					priority := strconv.FormatInt(int64(*(policySectionVal.Config.Priority)), 10)
//	    				fbsPolicySectionTblMap[sectionDbKeyStr].Field["PRIORITY"] = priority
//                    }
//                    if policySectionVal.Config.Description != nil {
//                        fbsPolicySectionTblMap[sectionDbKeyStr].Field["DESCRIPTION"] = *policySectionVal.Config.Description
//                    }
//				}
//
//				if policySectionVal.Monitoring != nil {
//					log.Infof("Processing Monitoring")
//					if policySectionVal.Monitoring.MirrorSessions != nil && policySectionVal.Monitoring.MirrorSessions.MirrorSession != nil {
//						for _, mirrorSessionVal := range policySectionVal.Monitoring.MirrorSessions.MirrorSession {
//							if mirrorSessionVal.Config != nil {
//								fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_MIRROR_SESSION"] = *(mirrorSessionVal.Config.SessionName)
//							}
//						}
//					}
//				} else if policySectionVal.Forwarding != nil {
//					log.Infof("Processing Forwarding")
//					if policySectionVal.Forwarding.Config != nil {
//						if *(policySectionVal.Forwarding.Config.Discard) {
//							fbsPolicySectionTblMap[sectionDbKeyStr].Field["DEFAULT_PACKET_ACTION"] = SONIC_PACKET_ACTION_DROP
//						}
//					}
//
//					if policySectionVal.Forwarding.EgressInterfaces != nil && policySectionVal.Forwarding.EgressInterfaces.EgressInterface != nil {
//						log.Infof("Processing Egress Interfaces")
//						egressIfsDbStr := ""
//						for uiIfName, egressIfVal := range policySectionVal.Forwarding.EgressInterfaces.EgressInterface {
//                            egressIfName := *(utils.GetNativeNameFromUIName(&uiIfName))
//			                log.Infof("PolicySection Field EgressIf SET uiIfName:%v egressIfName %v", uiIfName, egressIfName)
//							if egressIfsDbStr != "" {
//								egressIfsDbStr = egressIfsDbStr + ","
//							}
//							egressIfsDbStr = egressIfsDbStr + egressIfName
//							if (egressIfVal.Config != nil) && (egressIfVal.Config.Priority != nil) {
//								egressIfsDbStr = egressIfsDbStr + "|" + strconv.FormatInt(int64(*egressIfVal.Config.Priority), 10)
//							}
//						}
//						if egressIfsDbStr != "" {
//							fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_INTERFACE"] = egressIfsDbStr
//						}
//					} //EgressInterfaces - END
//
//					if policySectionVal.Forwarding.NextHops != nil && policySectionVal.Forwarding.NextHops.NextHop != nil {
//						log.Infof("Processing Nexthops")
//						var v4nhopsDbStr string
//						var v6nhopsDbStr string
//						for nhopKey, nhopPtr := range policySectionVal.Forwarding.NextHops.NextHop {
//							nhopsDbStr := nhopKey.IpAddress + "|" + nhopKey.NetworkInstance
//							if nhopPtr.Config.Priority != nil {
//								nhopsDbStr = nhopsDbStr + "|" + strconv.FormatInt(int64(*nhopPtr.Config.Priority), 10)
//							} else {
//								nhopsDbStr = nhopsDbStr + "|"
//							}
//							if isV4Address(nhopKey.IpAddress) {
//								if len(v4nhopsDbStr) > 0 {
//									v4nhopsDbStr = v4nhopsDbStr + ","
//								}
//								v4nhopsDbStr = v4nhopsDbStr + nhopsDbStr
//
//							} else {
//								if len(v6nhopsDbStr) > 0 {
//									v6nhopsDbStr = v6nhopsDbStr + ","
//								}
//								v6nhopsDbStr = v6nhopsDbStr + nhopsDbStr
//							}
//						}
//						if len(v4nhopsDbStr) > 0 {
//							fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_IP_NEXTHOP"] = v4nhopsDbStr
//						}
//						if len(v6nhopsDbStr) > 0 {
//							fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_IPV6_NEXTHOP"] = v6nhopsDbStr
//						}
//					} //Nexthops - END
//				} else if policySectionVal.Qos != nil { //QOS - START
//					if policySectionVal.Qos.Policer != nil {
//						if policySectionVal.Qos.Policer.Config != nil {
//							if policySectionVal.Qos.Policer.Config.Cir != nil {
//								fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_POLICER_CIR"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Cir), 10)
//							}
//							if policySectionVal.Qos.Policer.Config.Pir != nil {
//								fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_POLICER_PIR"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Pir), 10)
//							}
//							if policySectionVal.Qos.Policer.Config.Bc != nil {
//								fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_POLICER_CBS"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Bc), 10)
//							}
//							if policySectionVal.Qos.Policer.Config.Be != nil {
//								fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_POLICER_PBS"] = strconv.FormatInt(int64(*policySectionVal.Qos.Policer.Config.Be), 10)
//							}
//						}
//					}
//
//					if policySectionVal.Qos.Queuing != nil {
//						if policySectionVal.Qos.Queuing.Config != nil {
//							fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_TC"] = strconv.Itoa(int(*policySectionVal.Qos.Queuing.Config.OutputQueueIndex))
//						}
//					}
//
//					if policySectionVal.Qos.Remark != nil {
//						if policySectionVal.Qos.Remark.Config != nil {
//							if policySectionVal.Qos.Remark.Config.SetDscp != nil {
//								fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_DSCP"] = strconv.Itoa(int(*policySectionVal.Qos.Remark.Config.SetDscp))
//							}
//							if policySectionVal.Qos.Remark.Config.SetDot1P != nil {
//								fbsPolicySectionTblMap[sectionDbKeyStr].Field["SET_PCP"] = strconv.Itoa(int(*policySectionVal.Qos.Remark.Config.SetDot1P))
//							}
//						}
//					}
//				} //Qos - END
//				log.Infof("Policy CRUD; PolicyName %v  fbsPolicySectionTblMap:%v ", policyVal, fbsPolicySectionTblMap)
//			} //policySections forloop - END
//			log.Infof("Policy CRUD; Policy %v  fbsPolicyTblMap:%v ", policyVal, fbsPolicyTblMap)
//		} //policySection check
//
//		if inParams.oper == REPLACE {
//			log.Info("For replace operation with no policy changes delete it from cache")
//			if len(fbsPolicyTblMap[policyName].Field) == 0 {
//				delete(fbsPolicyTblMap, policyName)
//			}
//		}
//	} //policies for loop
//
//	if len(fbsPolicyTblMap) > 0 {
//		res_map[CFG_POLICY_TABLE] = fbsPolicyTblMap
//	}
//	if len(fbsPolicySectionTblMap) > 0 {
//		res_map[CFG_POLICY_SECTIONS_TABLE] = fbsPolicySectionTblMap
//	}
//
//	log.Infof("Res:%v Err:%v", res_map, err)
//	return res_map, err
//}
//
//func fillFbsFwdCountersEntry(inParams XfmrParams, polPbfKey db.Key, fbsFlowState *FbsFwdCountersEntry) (err error) {
//	countersDbPtr := inParams.dbs[db.CountersDB]
//	fbsCtrVal, err := countersDbPtr.GetEntry(FBS_COUNTERS_TABLE_TS, polPbfKey)
//	lastFbsCtrVal, err2 := countersDbPtr.GetEntry(LAST_FBS_COUNTERS_TABLE_TS, polPbfKey)
//	log.Infof("fbsCtrVal:%v", fbsCtrVal)
//	activeFlag := false
//	if err == nil && err2 == nil {
//		count := get_counter_diff(fbsCtrVal, lastFbsCtrVal, "Packets")
//		fbsFlowState.MatchedPackets = count
//		count = get_counter_diff(fbsCtrVal, lastFbsCtrVal, "Bytes")
//		fbsFlowState.MatchedOctets = count
//		activeFlag = true
//		fbsFlowState.Active = activeFlag
//	} else {
//		fbsFlowState.Active = activeFlag
//	}
//	return err
//}
//
//func fillFbsForwardingStateEntry(inParams XfmrParams, polPbfKey db.Key, fwdState *FbsFlowForwardingStateEntry) (err error) {
//
//	stateDbPtr := inParams.dbs[db.StateDB]
//
//	pbfKey := db.Key{Comp: []string{strings.Join(polPbfKey.Comp, ":")}}
//	val, err := stateDbPtr.GetEntry(PBF_GROUP_TABLE_TS, pbfKey)
//	if err == nil {
//		selected := val.Field["CONFIGURED_SELECTED"]
//		log.Infof("Key:%v Selected:%v", pbfKey, selected)
//		if selected == "DROP" {
//			discard := true
//			fwdState.Discard = &discard
//		} else if selected != "FORWARD" {
//			parts := strings.Split(selected, "|")
//			if len(parts) == 3 {
//				fwdState.IpAddress = &parts[0]
//				fwdState.NetworkInstance = &parts[1]
//				if parts[2] != "" {
//					prio, _ := strconv.ParseInt(parts[2], 10, 32)
//					prio_int := uint16(prio)
//					fwdState.Priority = &prio_int
//				}
//			} else {
//				fwdState.IntfName = &parts[0]
//				if parts[1] != "" {
//					prio, _ := strconv.ParseInt(parts[1], 10, 32)
//					prio_int := uint16(prio)
//					fwdState.Priority = &prio_int
//				}
//			}
//		}
//	}
//
//	err = fillFbsFwdCountersEntry(inParams, polPbfKey, &fwdState.fbsFlowState)
//	return err
//}
//
//func fillFbsPolicerStateEntry(inParams XfmrParams, polPbfKey db.Key, qosState *FbsPolicerStateEntry) (err error) {
//	appDbPtr := inParams.dbs[db.ApplDB]
//	var policerTblVal db.Value
//	policerTblVal, err = appDbPtr.GetEntry(POLICER_TABLE_TS, polPbfKey)
//	log.Infof("Key:%v Val:%v Err:%v", polPbfKey, policerTblVal, err)
//	if err == nil {
//		if str_val, found := policerTblVal.Field["CIR"]; found {
//			val, _ := strconv.ParseUint(str_val, 10, 64)
//			qosState.Cir = val
//		}
//
//		if str_val, found := policerTblVal.Field["PIR"]; found {
//			val, _ := strconv.ParseUint(str_val, 10, 64)
//			qosState.Pir = val
//		}
//
//		if str_val, found := policerTblVal.Field["CBS"]; found {
//			val, _ := strconv.ParseUint(str_val, 10, 64)
//			qosState.Bc = val
//		}
//
//		if str_val, found := policerTblVal.Field["PBS"]; found {
//			val, _ := strconv.ParseUint(str_val, 10, 64)
//			qosState.Be = val
//		}
//	}
//
//	return err
//}
//
//func fillFbsQosStateEntry(inParams XfmrParams, polPbfKey db.Key, qosState *FbsFlowQosStateEntry) (err error) {
//
//	countersDbPtr := inParams.dbs[db.CountersDB]
//	polCntVal, err := countersDbPtr.GetEntry(POLICER_COUNTERS_TABLE_TS, polPbfKey)
//	lastPolCntVal, err2 := countersDbPtr.GetEntry(LAST_POLICER_COUNTERS_TABLE_TS, polPbfKey)
//
//	log.Infof("Key:%v Value:%v Last:%v Err:%v Err2:%v", polPbfKey, polCntVal, lastPolCntVal, err, err2)
//	if err == nil && err2 == nil {
//		count := get_counter_diff(polCntVal, lastPolCntVal, "GreenPackets")
//		qosState.ConformingPkts = count
//
//		count = get_counter_diff(polCntVal, lastPolCntVal, "GreenBytes")
//		qosState.ConformingOctets = count
//
//		count = get_counter_diff(polCntVal, lastPolCntVal, "YellowPackets")
//		qosState.ExceedingPkts = count
//
//		count = get_counter_diff(polCntVal, lastPolCntVal, "YellowBytes")
//		qosState.ExceedingOctets = count
//
//		count = get_counter_diff(polCntVal, lastPolCntVal, "RedPackets")
//		qosState.ViolatingPkts = count
//
//		count = get_counter_diff(polCntVal, lastPolCntVal, "RedBytes")
//		qosState.ViolatingOctets = count
//
//		qosState.Active = true
//	} else {
//		qosState.Active = false
//	}
//
//	fillFbsPolicerStateEntry(inParams, polPbfKey, &qosState.policerState)
//	fillFbsFwdCountersEntry(inParams, polPbfKey, &qosState.fbsFlowState)
//	return err
//}
//
//func fillFbsIngressIfPolicyFwdSections(inParams XfmrParams, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Forwarding_Sections) {
//	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
//	pathInfo := NewPathInfo(inParams.uri)
//
//	policySectionTbl, _ := inParams.d.GetTable(POLICY_SECTION_TABLE_TS)
//	policySectionKeys, _ := inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{policyName, "*"}})
//	log.Infof("Policy Get;clasKeys %v policySectionTbl:%v ", policySectionKeys, policySectionTbl)
//	bindDir := "INGRESS"
//
//	if policySectionsData == nil {
//		ygot.BuildEmptyTree(policySectionsData)
//	}
//	if len(policySectionKeys) > 0 {
//		for _, key := range policySectionKeys {
//			className := key.Get(1)
//			log.Infof("Policysection Get;Key:%v className:%v ", key, className)
//			var policySectionData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Forwarding_Sections_Section
//			if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/ingress-policies/forwarding/sections/section{class-name}") { //section level request
//				classNameInReq := pathInfo.Var("class-name")
//				if className != classNameInReq {
//					continue
//				}
//				log.Infof("class level request; className:%v ", classNameInReq)
//				policySectionData = policySectionsData.Section[className]
//			} else {
//				policySectionData, _ = policySectionsData.NewSection(className)
//			}
//
//			//Fill PolicySectionDetails
//			ygot.BuildEmptyTree(policySectionData)
//
//			policySectionData.ClassName = &className
//			policySectionData.State.ClassName = &className
//			log.Infof("Policy Get;policyName:%v className:%v ", policyName, className)
//
//			//forwarding Config
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//
//			//fill forwarding selected egress interface and select nexhop details
//			var fwdState FbsFlowForwardingStateEntry
//			polPbfKey := db.Key{[]string{policyName, className, nativeIfName, bindDir}}
//			fillFbsForwardingStateEntry(inParams, polPbfKey, &fwdState)
//			if fwdState.IntfName != nil {
//				policySectionData.EgressInterface.State.IntfName = fwdState.IntfName
//				if fwdState.Priority != nil {
//					policySectionData.EgressInterface.State.Priority = fwdState.Priority
//				}
//			}
//			if fwdState.IpAddress != nil {
//				policySectionData.NextHop.State.IpAddress = fwdState.IpAddress
//				if fwdState.NetworkInstance != nil {
//					policySectionData.NextHop.State.NetworkInstance = fwdState.NetworkInstance
//				}
//				if fwdState.Priority != nil {
//					policySectionData.NextHop.State.Priority = fwdState.Priority
//				}
//			}
//			if fwdState.Discard != nil {
//				policySectionData.State.Discard = fwdState.Discard
//			}
//			policySectionData.State.Active = &(fwdState.fbsFlowState.Active)
//			policySectionData.State.MatchedOctets = &(fwdState.fbsFlowState.MatchedOctets)
//			policySectionData.State.MatchedPackets = &(fwdState.fbsFlowState.MatchedPackets)
//
//			log.Info("policy seciton data")
//			pretty.Print(policySectionData)
//		}
//	}
//}
//
//func fillFbsIngressIfPolicyMonSections(inParams XfmrParams, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Monitoring_Sections) {
//	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
//	pathInfo := NewPathInfo(inParams.uri)
//
//	policySectionTbl, _ := inParams.d.GetTable(POLICY_SECTION_TABLE_TS)
//	policySectionKeys, _ := inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{policyName, "*"}})
//	log.Infof("Policy Get;clasKeys %v policySectionTbl:%v ", policySectionKeys, policySectionTbl)
//	bindDir := "INGRESS"
//
//	if len(policySectionKeys) > 0 {
//		for _, key := range policySectionKeys {
//			className := key.Get(1)
//			log.Infof("Policy Get;Key:%v policyName:%v className:%v ", key, policyName, className)
//			var policySectionData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Monitoring_Sections_Section
//			if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/ingress-policies/monitoring/sections/section{class-name}") { //section level request
//				classNameInReq := pathInfo.Var("class-name")
//				if className != classNameInReq {
//					continue
//				}
//				log.Infof("class level request; className:%v ", classNameInReq)
//				policySectionData = policySectionsData.Section[className]
//			} else {
//				policySectionData, _ = policySectionsData.NewSection(className)
//			}
//
//			//Fill PolicySectionDetails
//			ygot.BuildEmptyTree(policySectionData)
//
//			policySectionData.ClassName = &className
//			policySectionData.State.ClassName = &className
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//
//			var fbsFlowState FbsFwdCountersEntry
//			polPbfKey := db.Key{[]string{policyName, className, nativeIfName, bindDir}}
//			fillFbsFwdCountersEntry(inParams, polPbfKey, &fbsFlowState)
//
//			policySectionData.State.Active = &(fbsFlowState.Active)
//			policySectionData.State.MatchedOctets = &(fbsFlowState.MatchedOctets)
//			policySectionData.State.MatchedPackets = &(fbsFlowState.MatchedPackets)
//
//			log.Info("policy seciton data")
//			pretty.Print(policySectionData)
//		}
//	}
//}
//
//func fillFbsIngressIfPolicyQosSections(inParams XfmrParams, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Qos_Sections) {
//	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
//	pathInfo := NewPathInfo(inParams.uri)
//
//	if policySectionsData == nil {
//		ygot.BuildEmptyTree(policySectionsData)
//	}
//	policySectionTbl, _ := inParams.d.GetTable(POLICY_SECTION_TABLE_TS)
//	policySectionKeys, _ := inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{policyName, "*"}})
//	log.Infof("Policy Get;clasKeys %v policySectionTbl:%v ", policySectionKeys, policySectionTbl)
//	bindDir := "INGRESS"
//
//	if len(policySectionKeys) > 0 {
//		for _, key := range policySectionKeys {
//			className := key.Get(1)
//			log.Infof("Policy Get;Key:%v policyName:%v className:%v ", key, policyName, className)
//			var policySectionData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_IngressPolicies_Qos_Sections_Section
//			if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/ingress-policies/qos/sections/section{class-name}") { //section level request
//				classNameInReq := pathInfo.Var("class-name")
//				if className != classNameInReq {
//					continue
//				}
//				log.Infof("class level request; className:%v ", classNameInReq)
//				policySectionData = policySectionsData.Section[className]
//			} else {
//				policySectionData, _ = policySectionsData.NewSection(className)
//			}
//
//			//Fill PolicySectionDetails
//			ygot.BuildEmptyTree(policySectionData)
//
//			policySectionData.ClassName = &className
//			policySectionData.State.ClassName = &className
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//			polPbfKey := db.Key{[]string{policyName, className, nativeIfName, bindDir}}
//
//			var qosState FbsFlowQosStateEntry
//			fillFbsQosStateEntry(inParams, polPbfKey, &qosState)
//			policySectionData.State.Active = &qosState.Active
//			policySectionData.State.Cir = &(qosState.policerState.Cir)
//			policySectionData.State.Pir = &(qosState.policerState.Pir)
//			policySectionData.State.Bc = &(qosState.policerState.Bc)
//			policySectionData.State.Be = &(qosState.policerState.Be)
//
//			policySectionData.State.ConformingOctets = &(qosState.ConformingOctets)
//			policySectionData.State.ConformingPkts = &(qosState.ConformingPkts)
//			policySectionData.State.ExceedingOctets = &(qosState.ExceedingOctets)
//			policySectionData.State.ExceedingPkts = &(qosState.ExceedingPkts)
//			policySectionData.State.ViolatingOctets = &(qosState.ViolatingOctets)
//			policySectionData.State.ViolatingPkts = &(qosState.ViolatingPkts)
//
//			//fill flow state
//			var fbsFlowState FbsFwdCountersEntry
//			fillFbsFwdCountersEntry(inParams, polPbfKey, &fbsFlowState)
//
//			policySectionData.State.MatchedOctets = &(qosState.fbsFlowState.MatchedOctets)
//			policySectionData.State.MatchedPackets = &(qosState.fbsFlowState.MatchedPackets)
//
//			log.Info("policy seciton data")
//			pretty.Print(policySectionData)
//		}
//	}
//}
//
//func fillFbsEgressIfPolicyMonSections(inParams XfmrParams, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_EgressPolicies_Monitoring_Sections) {
//	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
//	pathInfo := NewPathInfo(inParams.uri)
//
//	if policySectionsData == nil {
//		ygot.BuildEmptyTree(policySectionsData)
//	}
//
//	policySectionTbl, _ := inParams.d.GetTable(POLICY_SECTION_TABLE_TS)
//	policySectionKeys, _ := inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{policyName, "*"}})
//	log.Infof("Policy Get;clasKeys %v policySectionTbl:%v ", policySectionKeys, policySectionTbl)
//	bindDir := "EGRESS"
//
//	if len(policySectionKeys) > 0 {
//		for _, key := range policySectionKeys {
//			className := key.Get(1)
//			log.Infof("Policy Get;Key:%v policyName:%v className:%v ", key, policyName, className)
//			var policySectionData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_EgressPolicies_Monitoring_Sections_Section
//			if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/egress-policies/monitoring/sections/section{class-name}") { //section level request
//				classNameInReq := pathInfo.Var("class-name")
//				if className != classNameInReq {
//					continue
//				}
//				log.Infof("class level request; className:%v ", classNameInReq)
//				policySectionData = policySectionsData.Section[className]
//			} else {
//				policySectionData, _ = policySectionsData.NewSection(className)
//			}
//
//			//Fill PolicySectionDetails
//			ygot.BuildEmptyTree(policySectionData)
//
//			policySectionData.ClassName = &className
//			policySectionData.State.ClassName = &className
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//
//			var fbsFlowState FbsFwdCountersEntry
//			polPbfKey := db.Key{[]string{policyName, className, nativeIfName, bindDir}}
//			fillFbsFwdCountersEntry(inParams, polPbfKey, &fbsFlowState)
//			policySectionData.State.Active = &(fbsFlowState.Active)
//			policySectionData.State.MatchedOctets = &(fbsFlowState.MatchedOctets)
//			policySectionData.State.MatchedPackets = &(fbsFlowState.MatchedPackets)
//
//			log.Info("policy seciton data")
//			pretty.Print(policySectionData)
//		}
//	}
//}
//
//func fillFbsEgressIfPolicyQosSections(inParams XfmrParams, nativeIfName string, policyName string, policySectionsData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_EgressPolicies_Qos_Sections) {
//	log.Infof("nativeIfName:%v policyName:%v", nativeIfName, policyName)
//	pathInfo := NewPathInfo(inParams.uri)
//
//	policySectionTbl, _ := inParams.d.GetTable(POLICY_SECTION_TABLE_TS)
//	policySectionKeys, _ := inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{policyName, "*"}})
//	log.Infof("Policy Get;clasKeys %v policySectionTbl:%v ", policySectionKeys, policySectionTbl)
//	bindDir := "EGRESS"
//
//	if len(policySectionKeys) > 0 {
//		for _, key := range policySectionKeys {
//			className := key.Get(1)
//			log.Infof("Policy Get;Key:%v policyName:%v className:%v ", key, policyName, className)
//			var policySectionData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface_EgressPolicies_Qos_Sections_Section
//			if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/egress-policies/qos/sections/section{class-name}") { //section level request
//				classNameInReq := pathInfo.Var("class-name")
//				if className != classNameInReq {
//					continue
//				}
//				log.Infof("class level request; className:%v ", classNameInReq)
//				policySectionData = policySectionsData.Section[className]
//			} else {
//				policySectionData, _ = policySectionsData.NewSection(className)
//			}
//
//			//Fill PolicySectionDetails
//			ygot.BuildEmptyTree(policySectionData)
//
//			policySectionData.ClassName = &className
//			policySectionData.State.ClassName = &className
//			log.Infof("Policy Get;Key:%v className:%v ", key, className)
//
//			var qosState FbsFlowQosStateEntry
//			polPbfKey := db.Key{[]string{policyName, className, nativeIfName, bindDir}}
//			fillFbsQosStateEntry(inParams, polPbfKey, &qosState)
//			policySectionData.State.Cir = &(qosState.policerState.Cir)
//			policySectionData.State.Pir = &(qosState.policerState.Pir)
//			policySectionData.State.Bc = &(qosState.policerState.Bc)
//			policySectionData.State.Be = &(qosState.policerState.Be)
//			policySectionData.State.Active = &(qosState.Active)
//			policySectionData.State.ConformingOctets = &(qosState.ConformingOctets)
//			policySectionData.State.ConformingPkts = &(qosState.ConformingPkts)
//			policySectionData.State.ExceedingOctets = &(qosState.ExceedingOctets)
//			policySectionData.State.ExceedingPkts = &(qosState.ExceedingPkts)
//			policySectionData.State.ViolatingOctets = &(qosState.ViolatingOctets)
//			policySectionData.State.ViolatingPkts = &(qosState.ViolatingPkts)
//
//			//fill flow state
//			var fbsFlowState FbsFwdCountersEntry
//			fillFbsFwdCountersEntry(inParams, polPbfKey, &fbsFlowState)
//
//			policySectionData.State.MatchedOctets = &(fbsFlowState.MatchedOctets)
//			policySectionData.State.MatchedPackets = &(fbsFlowState.MatchedPackets)
//
//			log.Info("policy seciton data")
//			pretty.Print(policySectionData)
//		}
//	}
//}
//
////convert from DB to OCYang and fill to OcYang Datastructure for given policy Bind Interface
//func fillFbsInterfaceDetails(inParams XfmrParams, uiIfName string, nativeIfName string, policyBindTblVal db.Value, policyBindData *ocbinds.OpenconfigFbsExt_Fbs_Interfaces_Interface) {
//	if policyBindData == nil {
//		log.Infof("fillFbsInterfaceDetails--> policyBindData empty ; interface:%v ", uiIfName)
//		return
//	}
//
//	policyTypes := []string{SONIC_POLICY_TYPE_FORWARDING, SONIC_POLICY_TYPE_MONITORING, SONIC_POLICY_TYPE_QOS}
//
//	ygot.BuildEmptyTree(policyBindData)
//
//	policyBindData.Config.Id = &uiIfName
//
//	for _, policyType := range policyTypes {
//		//Ingress Policies
//		bindDir := "INGRESS"
//		dbFieldKey := bindDir + "_" + policyType + "_POLICY"
//
//		var policyName = ""
//
//		if policyBindData.IngressPolicies != nil {
//			ygot.BuildEmptyTree(policyBindData.IngressPolicies)
//			if policyType == SONIC_POLICY_TYPE_FORWARDING {
//				ygot.BuildEmptyTree(policyBindData.IngressPolicies.Forwarding)
//				if str_val, found := policyBindTblVal.Field[dbFieldKey]; found {
//					if policyBindData.IngressPolicies.Forwarding.Config != nil {
//						policyBindData.IngressPolicies.Forwarding.Config.PolicyName = &str_val
//					}
//					if policyBindData.IngressPolicies.Forwarding.State != nil {
//						policyBindData.IngressPolicies.Forwarding.State.PolicyName = &str_val
//					}
//					policyName = str_val
//					log.Infof("fbs Interface Get;Interface level request; InterfaceId:%v ", uiIfName)
//					fillFbsIngressIfPolicyFwdSections(inParams, nativeIfName, policyName, policyBindData.IngressPolicies.Forwarding.Sections)
//				}
//			}
//			if policyType == SONIC_POLICY_TYPE_MONITORING {
//				log.Infof("fbs Interface Get;Interface level request; InterfaceId:%v ", uiIfName)
//				ygot.BuildEmptyTree(policyBindData.IngressPolicies.Monitoring)
//				if str_val, found := policyBindTblVal.Field[dbFieldKey]; found {
//					if policyBindData.IngressPolicies.Monitoring.Config != nil {
//						policyBindData.IngressPolicies.Monitoring.Config.PolicyName = &str_val
//					}
//					if policyBindData.IngressPolicies.Monitoring.State != nil {
//						policyBindData.IngressPolicies.Monitoring.State.PolicyName = &str_val
//					}
//					policyName = str_val
//					fillFbsIngressIfPolicyMonSections(inParams, nativeIfName, policyName, policyBindData.IngressPolicies.Monitoring.Sections)
//				}
//			}
//			if policyType == SONIC_POLICY_TYPE_QOS {
//				ygot.BuildEmptyTree(policyBindData.IngressPolicies.Qos)
//				log.Infof("fbs Interface Get;Interface level request; Interface:%v ", uiIfName)
//				if str_val, found := policyBindTblVal.Field[dbFieldKey]; found {
//					if policyBindData.IngressPolicies.Qos.Config != nil {
//						policyBindData.IngressPolicies.Qos.Config.PolicyName = &str_val
//					}
//					if policyBindData.IngressPolicies.Qos.State != nil {
//						policyBindData.IngressPolicies.Qos.State.PolicyName = &str_val
//					}
//					policyName = str_val
//					log.Infof("fbs Interface Get;Interface level request; Interface:%v ", uiIfName)
//					fillFbsIngressIfPolicyQosSections(inParams, nativeIfName, policyName, policyBindData.IngressPolicies.Qos.Sections)
//				}
//			}
//		}
//
//		//Egress Policies
//		dbFieldKey = "EGRESS_" + policyType + "_POLICY"
//		if policyBindData.EgressPolicies != nil {
//			ygot.BuildEmptyTree(policyBindData.EgressPolicies)
//			if policyType == SONIC_POLICY_TYPE_MONITORING {
//				ygot.BuildEmptyTree(policyBindData.EgressPolicies.Monitoring)
//				if str_val, found := policyBindTblVal.Field[dbFieldKey]; found {
//					if policyBindData.EgressPolicies.Monitoring.Config != nil {
//						policyBindData.EgressPolicies.Monitoring.Config.PolicyName = &str_val
//					}
//					if policyBindData.EgressPolicies.Monitoring.State != nil {
//						policyBindData.EgressPolicies.Monitoring.State.PolicyName = &str_val
//					}
//					policyName = str_val
//					fillFbsEgressIfPolicyMonSections(inParams, nativeIfName, policyName, policyBindData.EgressPolicies.Monitoring.Sections)
//				}
//			}
//			if policyType == SONIC_POLICY_TYPE_QOS {
//				ygot.BuildEmptyTree(policyBindData.EgressPolicies.Qos)
//				if str_val, found := policyBindTblVal.Field[dbFieldKey]; found {
//					if policyBindData.EgressPolicies.Qos.Config != nil {
//						policyBindData.EgressPolicies.Qos.Config.PolicyName = &str_val
//					}
//					if policyBindData.EgressPolicies.Qos.State != nil {
//						policyBindData.EgressPolicies.Qos.State.PolicyName = &str_val
//					}
//					policyName = str_val
//					fillFbsEgressIfPolicyQosSections(inParams, nativeIfName, policyName, policyBindData.EgressPolicies.Qos.Sections)
//				}
//			}
//		}
//		log.Infof("fillFbsPolicyDetails--> filled config container with policyName:%v and type:%v", policyName, policyType)
//	}
//}
//
////DbToYang_fbs_interface_subtree_xfmr function takes care of handling Get operation for interface urls
//var DbToYang_fbs_interface_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
//	var err error
//
//	pathInfo := NewPathInfo(inParams.uri)
//
//	fbsObj := getFbsRoot(inParams.ygRoot)
//	ygot.BuildEmptyTree(fbsObj)
//	log.Infof("Policy Get;path:%v pathfbsObj:%v ", pathInfo.Template, fbsObj)
//	log.Info("fbsobj ")
//	pretty.Print(fbsObj)
//
//	log.Info("targetObj ")
//	pretty.Print(inParams.param)
//
//	if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}") { //inerface level request
//
//		interfaceKeys := reflect.ValueOf(fbsObj.Interfaces.Interface).MapKeys()
//		interfaceObj := fbsObj.Interfaces.Interface[interfaceKeys[0].Interface().(string)]
//		uiIfName := pathInfo.Var("id")
//        nativeIfName := *(utils.GetNativeNameFromUIName(&uiIfName))
//		log.Infof("fbs Interface Get;Interface level request; uiIfName:%v nativeName:%v interfaceKeys:%v ", uiIfName, nativeIfName, interfaceKeys)
//
//		ygot.BuildEmptyTree(interfaceObj)
//
//		policyBindTbl, _ := inParams.d.GetTable(POLICY_BINDING_TABLE_TS)
//		policyBindTblVal, _ := policyBindTbl.GetEntry(db.Key{[]string{nativeIfName}})
//		fillFbsInterfaceDetails(inParams, uiIfName,  nativeIfName, policyBindTblVal, interfaceObj)
//		log.Infof("fbs Interface Get;Interface level request; InterfaceId:%v interfaceObj:%v ", uiIfName, interfaceObj)
//		pretty.Print(interfaceObj)
//	} else { //top level get
//		log.Infof("fbs Interface Get;top level Get")
//
//		policyBindTbl, err := inParams.d.GetTable(POLICY_BINDING_TABLE_TS)
//		if err != nil {
//			log.Infof("fbs interface Get; couldn't get Policy Binding table")
//		}
//
//		interfaceKeys, _ := policyBindTbl.GetKeys()
//		log.Infof("fbs Interface Get; InterfaceKeys %v policyBindTbl:%v ", interfaceKeys, policyBindTbl)
//
//		if len(interfaceKeys) > 0 {
//			for _, key := range interfaceKeys {
//				nativeIfName := key.Get(0)
//                uiIfName := *(utils.GetUINameFromNativeName(&nativeIfName))
//				log.Infof("Policy Bind interface Get;nativeIfName:%v uiIfName:%v ", nativeIfName, uiIfName)
//				policyBindObj, _ := fbsObj.Interfaces.NewInterface(uiIfName)
//				policyBindTblVal, _ := policyBindTbl.GetEntry(key)
//				fillFbsInterfaceDetails(inParams, uiIfName, nativeIfName, policyBindTblVal, policyBindObj)
//				log.Infof("Policy Bind Get;top level request; uiIfName:%v policyBindObj:%v ", uiIfName, policyBindObj)
//			}
//		}
//	}
//	return err
//}
//
////YangToDb_fbs_interface_subtree_xfmr function takes care of handling CRUD operations for interface urls
//var YangToDb_fbs_interface_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
//	var err error
//	var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)
//
//	log.Info("Fbs Interface CRUD;: inParams.uri ")
//	pretty.Print(inParams.uri)
//
//	fbsObj := getFbsRoot(inParams.ygRoot)
//
//	pathInfo := NewPathInfo(inParams.uri)
//	keyName := pathInfo.Var("id")
//	log.Infof("Fbs Interface CRUD;: key:%v pathInfo%v fbsObj ", keyName, pathInfo.Path)
//	pretty.Print(fbsObj)
//
//	path, _ := getFbsUriPath(inParams.uri)
//	log.Info("Fbs interface operation %v path:%v ", inParams.oper, path)
//	//pretty.Print(path)
//
//	targetNode, err := getFbsYangNode(path)
//	if err != nil {
//		log.Infof("Fbs Interface operation ; targetNode get failed Error: %v", inParams.oper)
//		return res_map, tlerr.InvalidArgs("Invalid request - error: %v", err)
//	}
//	log.Infof("Fbs interface operation %v targetNode.Name:%v ", inParams.oper, targetNode.Name)
//
//	fbsPolicyBindTblMap := make(map[string]db.Value)
//
//	if inParams.oper == DELETE {
//		if fbsObj == nil || fbsObj.Interfaces == nil || len(fbsObj.Interfaces.Interface) == 0 {
//			log.Info("Fbs Interface DELETE operation; Top Level")
//			res_map[CFG_POLICY_BINDING_TABLE] = fbsPolicyBindTblMap
//			return res_map, err
//		} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}") { //Fbs Interface level
//			for key, Val := range fbsObj.Interfaces.Interface {
//                nativeIfName := *(utils.GetNativeNameFromUIName(&key))
//				log.Infof("Fbs Interface %v DELETE operation; uiIfName:%v nativeIfName:%v  ", key, nativeIfName)
//				if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/ingress-policies") { //Fbs Interface ingress polcies level
//					if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/ingress-policies/qos") {
//						log.Infof("Fbs Interface Ingress Qos policies %v DELETE operation;", key)
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_QOS_POLICY"] = ""
//					} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/ingress-policies/forwarding") {
//						log.Infof("Fbs Interface %v DELETE operation; ingress policies  Forwarding ; targetName:%v ", key, targetNode.Name)
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_FORWARDING_POLICY"] = ""
//					} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/ingress-policies/monitoring") {
//						log.Infof("Fbs Interface Ingress Monitoring policies %v DELETE operation;  ", key)
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_MONITORING_POLICY"] = ""
//					} else {
//						log.Infof("Fbs Interface %v Ingress Policies DELETE operation; Val ", key)
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_QOS_POLICY"] = ""
//						fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_FORWARDING_POLICY"] = ""
//						fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_MONITORING_POLICY"] = ""
//					}
//				} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/egress-policies") { //Fbs Interface ingress polcies level
//					log.Infof("Fbs Interface %v Egress Policies DELETE operation; ", key)
//					if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/egress-policies/qos") {
//						log.Infof("Fbs Interface %v Egress Qos Policies DELETE operation; Val ", key)
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						fbsPolicyBindTblMap[nativeIfName].Field["EGRESS_QOS_POLICY"] = ""
//					} else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/interfaces/interface{id}/egress-policies/monitoring") {
//						log.Infof("Fbs Interface %v Egress Monitoring Policies DELETE operation; Val ", key)
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						fbsPolicyBindTblMap[nativeIfName].Field["EGRESS_MONITORING_POLICY"] = ""
//					} else {
//						log.Infof("Fbs Interface %v Egress Policies DELETE operation; ", key)
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						fbsPolicyBindTblMap[nativeIfName].Field["EGRESS_QOS_POLICY"] = ""
//						fbsPolicyBindTblMap[nativeIfName].Field["EGRESS_MONITORING_POLICY"] = ""
//					}
//				} else {
//					if Val.Config == nil { //interface level delete
//						fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//						log.Infof("Fbs Interface %v delete", key)
//						break
//					} else {
//						//Specific Field delete
//						log.Infof("Policy %v DELETE operation; specific field delete, targetName:%v ", key, targetNode.Name)
//					}
//				}
//			}
//			log.Info("Fbs interface level delete class data")
//			pretty.Print(fbsPolicyBindTblMap)
//			if len(fbsPolicyBindTblMap) > 0 {
//				log.Infof("Fbs Interface DELETE operation ")
//				res_map[CFG_POLICY_BINDING_TABLE] = fbsPolicyBindTblMap
//			}
//		}
//
//		return res_map, err
//	} //DELETE - END
//
//	//CRU
//	//fbsPolicySectionTblMap := make(map[string]db.Value)
//	//fbsCountersMap := make(map[string]db.Value)
//	//fbsPolicerCountersMap := make(map[string]db.Value)
//	//fbsPolicerMap := make(map[string]db.Value)
//	for ifId, ifVal := range fbsObj.Interfaces.Interface {
//		if ifVal == nil {
//			continue
//		}
//		log.Infof("Fbs Interface CRUD; --> key: %v policyBindVal", ifId)
//		pretty.Print(ifVal)
//        nativeIfName := *(utils.GetNativeNameFromUIName(&ifId))
//
//		_, found := fbsPolicyBindTblMap[nativeIfName]
//		if !found {
//			fbsPolicyBindTblMap[nativeIfName] = db.Value{Field: make(map[string]string)}
//		}
//
//		if ifVal.IngressPolicies != nil {
//			if ifVal.IngressPolicies.Forwarding != nil {
//				if ifVal.IngressPolicies.Forwarding.Config != nil {
//					fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_FORWARDING_POLICY"] = *(ifVal.IngressPolicies.Forwarding.Config.PolicyName)
//				}
//			} else if ifVal.IngressPolicies.Monitoring != nil {
//				if ifVal.IngressPolicies.Monitoring.Config != nil {
//					fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_MONITORING_POLICY"] = *(ifVal.IngressPolicies.Monitoring.Config.PolicyName)
//				}
//			} else if ifVal.IngressPolicies.Qos != nil {
//				if ifVal.IngressPolicies.Qos.Config != nil {
//					fbsPolicyBindTblMap[nativeIfName].Field["INGRESS_QOS_POLICY"] = *(ifVal.IngressPolicies.Qos.Config.PolicyName)
//				}
//			}
//		}
//
//		if ifVal.EgressPolicies != nil {
//			if ifVal.EgressPolicies.Monitoring != nil {
//				if ifVal.EgressPolicies.Monitoring.Config != nil {
//					fbsPolicyBindTblMap[nativeIfName].Field["EGRESS_MONITORING_POLICY"] = *(ifVal.EgressPolicies.Monitoring.Config.PolicyName)
//				}
//			} else if ifVal.EgressPolicies.Qos != nil {
//				if ifVal.EgressPolicies.Qos.Config != nil {
//					fbsPolicyBindTblMap[nativeIfName].Field["EGRESS_QOS_POLICY"] = *(ifVal.EgressPolicies.Qos.Config.PolicyName)
//				}
//			}
//		}
//		log.Infof("Policy CRUD; Policy %v  fbsPolicyTblMap:%v ", ifVal, fbsPolicyBindTblMap)
//	} //Fbs Interfaces forloop - END
//
//	if len(fbsPolicyBindTblMap) > 0 {
//		res_map[CFG_POLICY_BINDING_TABLE] = fbsPolicyBindTblMap
//	}
//	return res_map, err
//}
