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

import (
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
	"github.com/kylelemons/godebug/pretty"
	//gnmipb "github.com/openconfig/gnmi/proto/gnmi"
    ygot "github.com/openconfig/ygot/ygot"
	//"github.com/openconfig/ygot/ytypes"
    log "github.com/golang/glog"
    "bytes"
    "strings"
	"reflect"
    //"time"
    //"syscall"
    "strconv"
    "fmt"
    //"net"
    //"errors"
)

const (
	SONIC_CLASS_MATCH_TYPE_ACL     = "ACL"
	SONIC_CLASS_MATCH_TYPE_FIELDS  = "FIELDS"
	CFG_CLASSIFIER_TABLE           = "CLASSIFIER_TABLE"
	SONIC_POLICY_TYPE_QOS          = "QOS"
	SONIC_POLICY_TYPE_FORWARDING   = "FORWARDING"
	SONIC_POLICY_TYPE_MONITORING   = "MONITORING"
	CFG_POLICY_TABLE               = "POLICY_TABLE"
	CFG_POLICY_SECTION_TABLE       = "POLICY_SECTIONS_TABLE"
	APP_POLICER_TABLE              = "POLICER_TABLE"
	OPENCONFIG_ACL_TYPE_IPV4 = "ACL_IPV4"
	OPENCONFIG_ACL_TYPE_IPV6 = "ACL_IPV6"
	OPENCONFIG_ACL_TYPE_L2   = "ACL_L2"
)

var ETHERTYPE_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_ETHERTYPE]uint32{
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_LLDP: 0x88CC,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_VLAN: 0x8100,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ROCE: 0x8915,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_ARP:  0x0806,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV4: 0x0800,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV6: 0x86DD,
	ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_MPLS: 0x8847,
}

/* E_OpenconfigPacketMatchTypes_IP_PROTOCOL */
var IP_PROTOCOL_MAP = map[ocbinds.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]uint8{
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_ICMP: 1,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_IGMP: 2,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_TCP:  6,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_UDP:  17,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_RSVP: 46,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_GRE:  47,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_AUTH: 51,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_PIM:  103,
	ocbinds.OpenconfigPacketMatchTypes_IP_PROTOCOL_IP_L2TP: 115,
}

/* E_OpenconfigFbsExt_MATCH_TYPE */
var CLASS_MATCH_TYPE_MAP = map[string]string{
	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_ACL), 10): SONIC_CLASS_MATCH_TYPE_ACL,
	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_FIELDS), 10): SONIC_CLASS_MATCH_TYPE_FIELDS,
}

/* E_OpenconfigFbsExt_POLICY_TYPE */
var POLICY_POLICY_TYPE_MAP = map[string]string{
	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_FORWARDING), 10): SONIC_POLICY_TYPE_FORWARDING,
	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_QOS), 10): SONIC_POLICY_TYPE_QOS,
	strconv.FormatInt(int64(ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_MONITORING), 10): SONIC_POLICY_TYPE_MONITORING,
}


//config db tables
var CLASSIFIER_TABLE_TS  *db.TableSpec = &db.TableSpec { Name: CFG_CLASSIFIER_TABLE }
var POLICY_TABLE_TS      *db.TableSpec = &db.TableSpec { Name: CFG_POLICY_TABLE }
var POLICY_SECTION_TABLE_TS      *db.TableSpec = &db.TableSpec { Name: CFG_POLICY_SECTION_TABLE}
var POLICER_TABLE_TS      *db.TableSpec = &db.TableSpec { Name: APP_POLICER_TABLE}

func init () {
    XlateFuncBind("DbToYang_fbs_classifier_subtree_xfmr", DbToYang_fbs_classifier_subtree_xfmr)
    XlateFuncBind("YangToDb_fbs_classifier_subtree_xfmr", YangToDb_fbs_classifier_subtree_xfmr)
    XlateFuncBind("DbToYang_fbs_policy_subtree_xfmr", DbToYang_fbs_policy_subtree_xfmr)
    XlateFuncBind("YangToDb_fbs_policy_subtree_xfmr", YangToDb_fbs_policy_subtree_xfmr)
}


func getL2EtherType(etherType uint64) interface{} {
	for k, v := range ETHERTYPE_MAP {
		if uint32(etherType) == v {
			return k
		}
	}
	return uint16(etherType)
}

func getAclKeyStrFromOCKey(aclname string, acltype ocbinds.E_OpenconfigAcl_ACL_TYPE) string {
	aclN := strings.Replace(strings.Replace(aclname, " ", "_", -1), "-", "_", -1)
	aclT := acltype.ΛMap()["E_OpenconfigAcl_ACL_TYPE"][int64(acltype)].Name
	return aclN + "_" + aclT
}

func getOCAclKeysFromStrDBKey(aclKey string) (string, ocbinds.E_OpenconfigAcl_ACL_TYPE) {
	var aclOrigName string
	var aclOrigType ocbinds.E_OpenconfigAcl_ACL_TYPE

	if strings.Contains(aclKey, "_"+OPENCONFIG_ACL_TYPE_IPV4) {
		aclOrigName = strings.Replace(aclKey, "_"+OPENCONFIG_ACL_TYPE_IPV4, "", 1)
		aclOrigType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV4
	} else if strings.Contains(aclKey, "_"+OPENCONFIG_ACL_TYPE_IPV6) {
		aclOrigName = strings.Replace(aclKey, "_"+OPENCONFIG_ACL_TYPE_IPV6, "", 1)
		aclOrigType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_IPV6
	} else if strings.Contains(aclKey, "_"+OPENCONFIG_ACL_TYPE_L2) {
		aclOrigName = strings.Replace(aclKey, "_"+OPENCONFIG_ACL_TYPE_L2, "", 1)
		aclOrigType = ocbinds.OpenconfigAcl_ACL_TYPE_ACL_L2
	}
	return aclOrigName, aclOrigType
}

func getTransportConfigTcpFlags(tcpFlags string) []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS {
	var flags []ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS
	if len(tcpFlags) > 0 {
		flagStr := strings.Split(tcpFlags, "/")[0]
		flagNumber, _ := strconv.ParseUint(strings.Replace(flagStr, "0x", "", -1), 16, 32)
		for i := 0; i < 8; i++ {
			mask := 1 << uint(i)
			if (int(flagNumber) & mask) > 0 {
				switch int(flagNumber) & mask {
				case 0x01:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN)
				case 0x02:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN)
				case 0x04:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST)
				case 0x08:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH)
				case 0x10:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK)
				case 0x20:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG)
				case 0x40:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE)
				case 0x80:
					flags = append(flags, ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR)
				default:
				}
			}
		}
	}
	return flags
}







func getFbsRoot(s *ygot.GoStruct) *ocbinds.OpenconfigFbsExt_Fbs {
	deviceObj := (*s).(*ocbinds.Device)

	return deviceObj.Fbs
}

//get fbs classifier oc yang match type for match type in db
func getClassMatchTypeOCEnumFromDbStr(val string) (ocbinds.E_OpenconfigFbsExt_MATCH_TYPE, error) {
	switch val {
	case SONIC_CLASS_MATCH_TYPE_ACL, "openconfig-fbs-ext:MATCH_ACL":
		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_ACL, nil
	case SONIC_CLASS_MATCH_TYPE_FIELDS, "openconfig-fbs-ext:MATCH_FIELDS":
		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_MATCH_FIELDS, nil
	default:
		return ocbinds.OpenconfigFbsExt_MATCH_TYPE_UNSET,
			tlerr.NotSupported("FBS Class Match Type '%s' not supported", val)
	}
}

//get classifier match type - db string from oc enum match type
func getClassMatchTypeDbStrromOcEnum(ocMatchType ocbinds.E_OpenconfigFbsExt_MATCH_TYPE) (string, error) {
    dbMatchType := ""
    if (ocMatchType == ocbinds.OpenconfigFbsExt_MATCH_TYPE_UNSET) {
		return "", tlerr.NotSupported("FBS Class Match Type not set")
    }
    dbMatchType    = findInMap(CLASS_MATCH_TYPE_MAP, strconv.FormatInt(int64(ocMatchType), 10))
    return dbMatchType, nil
}


//get L2Ethertype oc enum for given ether type string in DB
//func getL2EtherTypeOCEnumFromDbStr(val string) (ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union, error) {
func getL2EtherTypeOCEnumFromDbStr(val string) interface{} {
    etypeVal, _ := strconv.ParseUint(strings.Replace(val, "0x", "", -1), 16, 32)
    return(getL2EtherType(etypeVal))
}

//get Ip protocol oc enum from given Ip protocol in DB
func getIpProtocol(proto int64) interface{} {
	for k, v := range IP_PROTOCOL_MAP {
		if uint8(proto) == v {
			return k
		}
	}
	return uint8(proto)
}


//Classifiers - START

//convert from DB to OCYang and fill to OcYang Datastructure for given classifier name
func fillFbsClassDetails(inParams XfmrParams, className string, classTblVal db.Value, classData *ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier) {
	if classData == nil {
        log.Infof("fillFbsClassDetails--> classData empty ; className:%v ", className)
		return
	}
	ygot.BuildEmptyTree(classData)

	classData.ClassName = &className
    matchType := classTblVal.Get("MATCH_TYPE")
    
    classData.Config.Name = &className
    log.Infof("fillFbsClassDetails--> filled config container with className:%v and MatchType:%v", className, matchType)

	ocMatchType, _ := getClassMatchTypeOCEnumFromDbStr(matchType)
    classData.Config.MatchType = ocMatchType 
    if matchType == SONIC_CLASS_MATCH_TYPE_ACL {
        aclNameInDb          :=  classTblVal.Get("ACL_NAME")
        ocAclName, ocAclType := getOCAclKeysFromStrDBKey(aclNameInDb)
        classData.MatchAcl.Config.AclName = &ocAclName
        classData.MatchAcl.Config.AclType = ocAclType

        classData.MatchAcl.State.AclName = &ocAclName
        classData.MatchAcl.State.AclType = ocAclType
        
    } else if matchType  == SONIC_CLASS_MATCH_TYPE_FIELDS { 
        matchAll := true
        classData.MatchHdrFields.Config.MatchAll = &matchAll
        classData.MatchHdrFields.State.MatchAll  = classData.MatchHdrFields.Config.MatchAll

        //Fill L2 Fields - START
        if str_val, found := classTblVal.Field["DST_MAC"]; found {
            splitStr := strings.Split(str_val, "/")
            classData.MatchHdrFields.L2.Config.DestinationMac = &splitStr[0]
            classData.MatchHdrFields.L2.State.DestinationMac  = &splitStr[0]
            if (len(splitStr[1]) != 0 ) {
                classData.MatchHdrFields.L2.Config.DestinationMacMask = &splitStr[1]
                classData.MatchHdrFields.L2.State.DestinationMacMask  = &splitStr[1]
            }
        }
        if str_val, found := classTblVal.Field["SRC_MAC"]; found {
            classData.MatchHdrFields.L2.Config.SourceMac = &str_val
            classData.MatchHdrFields.L2.State.SourceMac  = &str_val
        }
        if str_val, found := classTblVal.Field["DEI"]; found {
            dei,_ := strconv.Atoi(str_val)
            oc_dei := uint8(dei)
            classData.MatchHdrFields.L2.Config.Dei = &oc_dei
            classData.MatchHdrFields.L2.State.Dei  = &oc_dei
        }
        if str_val, found := classTblVal.Field["PCP"]; found {
            pcp, _ := strconv.Atoi(str_val)
            oc_pcp  := uint8(pcp)
            classData.MatchHdrFields.L2.Config.Pcp = &oc_pcp
            classData.MatchHdrFields.L2.State.Pcp  = &oc_pcp
        }
        if str_val, found := classTblVal.Field["VLAN"]; found {
            vlan, _ := strconv.Atoi(str_val)
            oc_vlan  := uint16(vlan)
            classData.MatchHdrFields.L2.Config.Vlanid = &oc_vlan
            classData.MatchHdrFields.L2.State.Vlanid  = &oc_vlan
        }

        ipv4 := false
        ipv6 := false
        if str_val, found := classTblVal.Field["ETHER_TYPE"]; found {
            ocEtype := getL2EtherTypeOCEnumFromDbStr(str_val)
             if (ocEtype == ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV4) {
                 ipv4 = true 
             } else  if (ocEtype == ocbinds.OpenconfigPacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV6) {
                 ipv6 = true 
             }
            
	        log.Infof("fillFbsClassDetails; Ethertype:%v ipv4:%v ipv6:%v ", ocEtype, ipv4, ipv6)
            classData.MatchHdrFields.L2.Config.Ethertype, _  = classData.MatchHdrFields.L2.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union(ocEtype)
            classData.MatchHdrFields.L2.State.Ethertype, _  = classData.MatchHdrFields.L2.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_State_Ethertype_Union(ocEtype)
        } 
        //Fill L2 Fields - END

        if str_val, found := classTblVal.Field["DSCP"]; found {
	        dscp, _ := strconv.Atoi(str_val)
            oc_dscp := uint8(dscp)
            classData.MatchHdrFields.Ipv4.Config.Dscp = &oc_dscp
            if (ipv4) {
                classData.MatchHdrFields.Ipv4.State.Dscp = classData.MatchHdrFields.Ipv4.Config.Dscp
            } else if (ipv6) {
                classData.MatchHdrFields.Ipv6.State.Dscp = classData.MatchHdrFields.Ipv4.Config.Dscp
            }
        }
        if str_val, found := classTblVal.Field["IP_PROTOCOL"]; found {
			ipProto, _ := strconv.ParseInt(str_val, 10, 64)
            ip_proto_val  := getIpProtocol(ipProto)

            if (ipv4 == true) {
	            log.Infof("fillFbsClassDetails; ipv4 protocol:%v ", ip_proto_val)
                
                classData.MatchHdrFields.Ipv4.Config.Protocol,_ = classData.MatchHdrFields.Ipv4.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv4_Config_Protocol_Union(ip_proto_val)
                classData.MatchHdrFields.Ipv4.State.Protocol,_  = classData.MatchHdrFields.Ipv4.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv4_State_Protocol_Union(ip_proto_val)
            } else if (ipv6 == true) {
	            log.Infof("fillFbsClassDetails; ipv6 protocol:%v ", ip_proto_val)
                //classData.MatchHdrFields.Ipv6.Config.Protocol,_ = classData.MatchHdrFields.Ipv6.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv6_Config_Protocol_Union(ip_proto_val)
                //classData.MatchHdrFields.Ipv6.State.Protocol,_  = classData.MatchHdrFields.Ipv6.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv6_State_Protocol_Union(ip_proto_val)
            }
             
        } 
        //Fill IPV4/IPV6 Fields - END


        //Fill IPV4 Fields - START
        if str_val, found := classTblVal.Field["SRC_IP"]; found {
            classData.MatchHdrFields.Ipv4.Config.SourceAddress  = &str_val
            classData.MatchHdrFields.Ipv4.State.SourceAddress   = &str_val
        }
        if str_val, found := classTblVal.Field["DST_IP"]; found {
           classData.MatchHdrFields.Ipv4.Config.DestinationAddress = &str_val
           classData.MatchHdrFields.Ipv4.State.DestinationAddress  = &str_val
        }
        //Fill IPV6 Fields - START

        //Fill IPV6 Fields - START
        if str_val, found := classTblVal.Field["SRC_IPV6"]; found {
            classData.MatchHdrFields.Ipv6.Config.SourceAddress  = &str_val
            classData.MatchHdrFields.Ipv6.State.SourceAddress   = &str_val
        }
        if str_val, found := classTblVal.Field["DST_IPV6"]; found {
            classData.MatchHdrFields.Ipv6.Config.DestinationAddress = &str_val
            classData.MatchHdrFields.Ipv6.State.DestinationAddress  = &str_val
        }
        //Fill IPV6 Fields - END

        
        //Fill Transport Fields - START
        if str_val, found := classTblVal.Field["L4_SRC_PORT"]; found {
            src_port,_ := strconv.Atoi(str_val)
            classData.MatchHdrFields.Transport.Config.SourcePort,_ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union(src_port) 
            classData.MatchHdrFields.Transport.State.SourcePort,_ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_SourcePort_Union(src_port) 
        } 
        if str_val, found := classTblVal.Field["L4_DST_PORT"]; found {
            dst_port,_ := strconv.Atoi(str_val)
            classData.MatchHdrFields.Transport.Config.DestinationPort,_ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union(dst_port) 
            classData.MatchHdrFields.Transport.State.DestinationPort,_ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_DestinationPort_Union(dst_port) 
        } 
         if str_val, found := classTblVal.Field["L4_SRC_PORT_RANGE"]; found {
            src_port_range := strings.Replace(str_val, "-", "..", 1) 
            classData.MatchHdrFields.Transport.Config.SourcePort,_ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union(src_port_range) 
            classData.MatchHdrFields.Transport.State.SourcePort,_ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_SourcePort_Union(src_port_range) 
        }
        if str_val, found := classTblVal.Field["L4_DST_PORT_RANGE"]; found {
            dst_port_range := strings.Replace(str_val, "-", "..", 1) 
            classData.MatchHdrFields.Transport.Config.DestinationPort,_ = classData.MatchHdrFields.Transport.Config.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union(dst_port_range) 
            classData.MatchHdrFields.Transport.State.DestinationPort,_ = classData.MatchHdrFields.Transport.State.To_OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_State_DestinationPort_Union(dst_port_range) 
        }
        
        if str_val, found := classTblVal.Field["TCP_FLAGS"]; found {
            classData.MatchHdrFields.Transport.Config.TcpFlags = getTransportConfigTcpFlags(str_val)
            classData.MatchHdrFields.Transport.State.TcpFlags = classData.MatchHdrFields.Transport.Config.TcpFlags        
        }

        //Fill Transport Fields - END


    } 
    classData.State.MatchType = classData.Config.MatchType
    classData.State.Name      = classData.Config.Name

	log.Infof("fillFbsClassDetails; classData ")
    pretty.Print(classData)

}


//Get
var DbToYang_fbs_classifier_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

	pathInfo := NewPathInfo(inParams.uri)

	fbsObj := getFbsRoot(inParams.ygRoot)
    ygot.BuildEmptyTree(fbsObj)
	log.Infof("Classifier Get;path:%v pathfbsObj:%v ", pathInfo.Template, fbsObj)
    log.Info("fbsobj ")
    pretty.Print(fbsObj)

    log.Info("targetObj ")
    pretty.Print(inParams.param)


    if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers/classifier{class-name}") { //class level request

        classKeys := reflect.ValueOf(fbsObj.Classifiers.Classifier).MapKeys()
        classObj := fbsObj.Classifiers.Classifier[classKeys[0].Interface().(string)]
        className := pathInfo.Var("class-name")
	    log.Infof("Classifier Get;class level request; className:%v ",  className)
        
        ygot.BuildEmptyTree(classObj)

        classTbl, _ := inParams.d.GetTable(CLASSIFIER_TABLE_TS)
        classTblVal, _ := classTbl.GetEntry(db.Key{[]string{classKeys[0].Interface().(string)}})
        fillFbsClassDetails(inParams, className, classTblVal, classObj)
    } else { //top level get
	    log.Infof("Classifier Get;top level Get")

        classTbl, err := inParams.d.GetTable(CLASSIFIER_TABLE_TS)
        if (err != nil) {
            log.Infof("Classifier Get; couldn't get classifier table" )
        }

        classKeys, _ := classTbl.GetKeys()
	    log.Infof("Classifier Get;clasKeys %v classTbl:%v ", classKeys, classTbl)

        if len(classKeys) > 0 {
            for _, key := range classKeys {
                className := key.Get(0)
	            log.Infof("Classifier Get;Key:%v className:%v ",  key, className)
                classObj, _ := fbsObj.Classifiers.NewClassifier(className)
                classTblVal, _ := classTbl.GetEntry(key)
                fillFbsClassDetails(inParams, className, classTblVal, classObj)
	            log.Infof("Classifier Get;top level request; classTblVal:%v  ",  classTblVal)
            }
        }
    } 
    return err
}

//CRUD
var YangToDb_fbs_classifier_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
	var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    keyName := pathInfo.Var("class-name")
    log.Infof("Classifier CRUD:: key:%v pathInfo%v ", keyName, pathInfo)
 
    log.Info("Classifier CRUD:: inParams.uri ")
    pretty.Print(inParams.uri)

    path, err := getUriPath(inParams.uri)
    if err != nil {
        log.Infof("Classifier CRUD:: path get error:%v ", err)
        return nil, err
    }
    targetNode, err := getYangNode(path)
    if err != nil {
        log.Infof("Classifier %v operation ; targetNode get failed Error: %v", inParams.oper)
        return res_map, tlerr.InvalidArgs("Invalid request - error: %v", err)
    }

	fbsObj := getFbsRoot(inParams.ygRoot)
	fbsClassTblMap := make(map[string]db.Value)

    if inParams.oper == DELETE {
        if fbsObj == nil || fbsObj.Classifiers == nil || len(fbsObj.Classifiers.Classifier) == 0 {
            log.Info("Classifiers DELETE operation; Top Level")
		    res_map[CFG_CLASSIFIER_TABLE] = fbsClassTblMap
            return res_map, err
        } else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/classifiers/classifier{class-name}") { //ClassEntry level
            for classKey, classVal := range fbsObj.Classifiers.Classifier {
                log.Infof("Classifier %v DELETE operation; classVal ", classKey)
                pretty.Print(classVal)
                if classVal.Config == nil { //class level delete
                    log.Infof("Classifier %v delete", classKey)
                    fbsClassTblMap[classKey] = db.Value{Field: make(map[string]string)}
                    res_map[CFG_CLASSIFIER_TABLE] = fbsClassTblMap
					log.Info("class level delete class data")
					pretty.Print(fbsClassTblMap)
                        break 
                } else  {
                    //Specific Field delete
                    log.Infof("Classifier %v DELETE operation; specific field delete, targetName:%v ", classKey, targetNode.Name)
                    dbV := db.Value{Field: make(map[string]string)}

                    if isSubtreeRequest(pathInfo.Template, "/match-hdr-fields/ipv4/config") { //Class match-hdr-fields ipv4
                        log.Infof("Classifier %v DELETE operation; IPV4 field delete; targetName:%v ", classKey, targetNode.Name)
                        if  targetNode.Name == "source-address" {
                            dbV.Field["source-address"] = ""
                            fbsClassTblMap[classKey] = dbV
                            res_map[CFG_CLASSIFIER_TABLE] =fbsClassTblMap 
                        } else if targetNode.Name == "destination-address" {
                            dbV.Field["destination-address"] = ""
                            fbsClassTblMap[classKey] = dbV
                            res_map[CFG_CLASSIFIER_TABLE] =fbsClassTblMap 
                        }
                    } 
                }
            }
        }

		return res_map, err
    }  //DELETE - END


   //CRU
   for className, classVal := range fbsObj.Classifiers.Classifier {
        if classVal == nil {
            continue
        }
        //if (classVal.Config  != nil) {
            log.Infof("Classifier CRUD: --> key: %v classVal", className)
            pretty.Print(classVal)
           

            _, found := fbsClassTblMap[className]
            if !found {
                    fbsClassTblMap[className] = db.Value{Field: make(map[string]string)}
            }
            log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", classVal, fbsClassTblMap)

            matchType, _ := getClassMatchTypeDbStrromOcEnum(classVal.Config.MatchType)
            fbsClassTblMap[className].Field["MATCH_TYPE"] = matchType
            log.Infof("Classifier CRUD: class%v matchType:%v ", classVal, matchType)

            if (matchType == SONIC_CLASS_MATCH_TYPE_ACL) {
                ocAclName      := *(classVal.MatchAcl.Config.AclName)
                ocAclType      := classVal.MatchAcl.Config.AclType
                aclNameinDb  := getAclKeyStrFromOCKey(ocAclName, ocAclType)
                fbsClassTblMap[className].Field["ACL_NAME"]   = aclNameinDb

                log.Infof("Classifier CRUD: matchType ACL --> key: %v fbsClassTblMap:%v ", className, fbsClassTblMap)
            }  else if (matchType == SONIC_CLASS_MATCH_TYPE_FIELDS) {
                log.Infof("Classifier CRUD: class%v matchType:%v ", classVal, matchType)
                //Fill L2 Fields - START
                if classVal.MatchHdrFields.L2 != nil {
                    if classVal.MatchHdrFields.L2.Config.DestinationMac != nil {
                        ocMacStr := *(classVal.MatchHdrFields.L2.Config.DestinationMac)
                        log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
                        if (classVal.MatchHdrFields.L2.Config.DestinationMacMask != nil) {
                            log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, *(classVal.MatchHdrFields.L2.Config.DestinationMacMask))
                            ocMacStr = ocMacStr + "/" + *(classVal.MatchHdrFields.L2.Config.DestinationMacMask)
                        }
                        log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
                        fbsClassTblMap[className].Field["DST_MAC"]   = ocMacStr
                    }
                    
                    if classVal.MatchHdrFields.L2.Config.SourceMac != nil {
                        ocMacStr := *(classVal.MatchHdrFields.L2.Config.SourceMac)
                        log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
                        if (classVal.MatchHdrFields.L2.Config.SourceMacMask != nil) {
                            log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, *(classVal.MatchHdrFields.L2.Config.SourceMacMask))
                            ocMacStr = ocMacStr + "/" + *(classVal.MatchHdrFields.L2.Config.SourceMacMask)
                        }
                        log.Infof("Classifier CRUD: class%v ocMacStr:%v ", className, ocMacStr)
                        fbsClassTblMap[className].Field["SRC_MAC"]   = ocMacStr
                        log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
                    }
                    
                    if classVal.MatchHdrFields.L2.Config.Dei != nil {
                        fbsClassTblMap[className].Field["DEI"]   = strconv.Itoa(int(*(classVal.MatchHdrFields.L2.Config.Dei)))
                    }
                    if classVal.MatchHdrFields.L2.Config.Pcp != nil {
                        fbsClassTblMap[className].Field["PCP"]   = strconv.Itoa(int(*(classVal.MatchHdrFields.L2.Config.Pcp)))
                    }
                    if classVal.MatchHdrFields.L2.Config.Vlanid != nil {
                        log.Infof("Classifier CRUD: class%v vlanid:%v type:%v ", className, *classVal.MatchHdrFields.L2.Config.Vlanid, reflect.TypeOf(*classVal.MatchHdrFields.L2.Config.Vlanid))
                        fbsClassTblMap[className].Field["VLAN"]   = strconv.Itoa(int(*classVal.MatchHdrFields.L2.Config.Vlanid))
                        log.Infof("Classifier CRUD: class%v vlanid:%v type:%v ", className, *classVal.MatchHdrFields.L2.Config.Vlanid, reflect.TypeOf(*classVal.MatchHdrFields.L2.Config.Vlanid))
                    }
                    
                        log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
                    if classVal.MatchHdrFields.L2.Config.Ethertype != nil {
                        ethertypeType := reflect.TypeOf(classVal.MatchHdrFields.L2.Config.Ethertype)
   		                var b bytes.Buffer
                        var dbEtype string
   		                switch ethertypeType {
				            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE{}):
				     	       v := classVal.MatchHdrFields.L2.Config.Ethertype.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_E_OpenconfigPacketMatchTypes_ETHERTYPE)
				     	       fmt.Fprintf(&b, "0x%0.4x", ETHERTYPE_MAP[v.E_OpenconfigPacketMatchTypes_ETHERTYPE])
				     	       dbEtype = b.String()
				     	       break
			 	            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_Uint16{}):
				    			v := classVal.MatchHdrFields.L2.Config.Ethertype.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_L2_Config_Ethertype_Union_Uint16)
				    			fmt.Fprintf(&b, "0x%0.4x", v.Uint16)
				     	        dbEtype = b.String()
				    			break
				        }
                        fbsClassTblMap[className].Field["ETHER_TYPE"]   = dbEtype
                    }
                }
                //Fill L2 Fields - END

                //Fill IPV4/Ipv6 Fields - START
                if classVal.MatchHdrFields.Ipv4 != nil {
                    if classVal.MatchHdrFields.Ipv4.Config.SourceAddress != nil {
                        fbsClassTblMap[className].Field["SRC_IP"]   = *(classVal.MatchHdrFields.Ipv4.Config.SourceAddress)
                    }
                    if classVal.MatchHdrFields.Ipv4.Config.DestinationAddress != nil {
                        fbsClassTblMap[className].Field["DST_IP"]   = *(classVal.MatchHdrFields.Ipv4.Config.DestinationAddress)
                    }
                    
                        log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
                    if classVal.MatchHdrFields.Ipv4.Config.Dscp != nil {
                        fbsClassTblMap[className].Field["DSCP"]   = strconv.Itoa(int(*classVal.MatchHdrFields.Ipv4.Config.Dscp))
                    } 
                        log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
                    if classVal.MatchHdrFields.Ipv4.Config.Protocol != nil  {
                        ipProtocolType := reflect.TypeOf(classVal.MatchHdrFields.Ipv4.Config.Protocol)
                        var dbIpProto string
   		                switch ipProtocolType {
				            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv4_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
				     	       v := classVal.MatchHdrFields.Ipv4.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv4_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
                               dbIpProto = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
				     	       break
			 	            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv4_Config_Protocol_Union_Uint8{}):
				    			v := classVal.MatchHdrFields.Ipv4.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv4_Config_Protocol_Union_Uint8)
                                dbIpProto =  strconv.FormatInt(int64(v.Uint8), 10)
				    			break
				        }
                        fbsClassTblMap[className].Field["IP_PROTOCOL"]   = dbIpProto 
                    }
                } 

                if classVal.MatchHdrFields.Ipv6 != nil   {
                    if  classVal.MatchHdrFields.Ipv6.Config.Protocol != nil  {
                        ipProtocolType := reflect.TypeOf(classVal.MatchHdrFields.Ipv6.Config.Protocol)
                        var dbIpProto string
   		                switch ipProtocolType {
				            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv6_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL{}):
				     	       v := classVal.MatchHdrFields.Ipv6.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv6_Config_Protocol_Union_E_OpenconfigPacketMatchTypes_IP_PROTOCOL)
                               dbIpProto = strconv.FormatInt(int64(IP_PROTOCOL_MAP[v.E_OpenconfigPacketMatchTypes_IP_PROTOCOL]), 10)
				     	       break
			 	            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv6_Config_Protocol_Union_Uint8{}):
				    			v := classVal.MatchHdrFields.Ipv6.Config.Protocol.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Ipv6_Config_Protocol_Union_Uint8)
                                dbIpProto =  strconv.FormatInt(int64(v.Uint8), 10)
				    			break
				        }
                        fbsClassTblMap[className].Field["IP_PROTOCOL"]   = dbIpProto 
                    }
                    
                        log.Infof("Classifier CRUD: class%v fbsClassTblMap:%v ", className, fbsClassTblMap)
                    if classVal.MatchHdrFields.Ipv6.Config.SourceAddress != nil {
                        fbsClassTblMap[className].Field["SRC_IPV6"]   = *(classVal.MatchHdrFields.Ipv6.Config.SourceAddress)
                    }
                    if classVal.MatchHdrFields.Ipv6.Config.DestinationAddress != nil {
                        fbsClassTblMap[className].Field["DST_IPV6"]   = *(classVal.MatchHdrFields.Ipv6.Config.DestinationAddress)
                    }
                    if classVal.MatchHdrFields.Ipv6.Config.Dscp != nil {
                        fbsClassTblMap[className].Field["DSCP"]   = strconv.Itoa(int(*classVal.MatchHdrFields.Ipv6.Config.Dscp))
                    }
                    log.Infof("Classifier CRUD: matchType FIELDS --> key: %v fbsClassTblMap:%v ", className, fbsClassTblMap)
                 }
                    
                //Fill IPV4/Ipv6 Fields - END


                //Fill Transport Fields - START
                if classVal.MatchHdrFields.Transport != nil   {
                    if classVal.MatchHdrFields.Transport.Config.SourcePort != nil {
                        srcPortType := reflect.TypeOf(classVal.MatchHdrFields.Transport.Config.SourcePort)
   		                switch srcPortType {
				            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort{}):
				     	       v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort)
                    
		                       fbsClassTblMap[className].Field["L4_SRC_PORT"] = v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort.ΛMap()["E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort"][int64(v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_SourcePort)].Name
				     	       break
				            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_String{}):
				     	       v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_String)
		                       fbsClassTblMap[className].Field["L4_SRC_PORT_RANGE"]  = strings.Replace(v.String, "..", "-", 1)
				    		   break
	                         case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_Uint16{}):
				     	       v := classVal.MatchHdrFields.Transport.Config.SourcePort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_SourcePort_Union_Uint16)
		                       fbsClassTblMap[className].Field["L4_SRC_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
				    		   break
				        }
                    
                    }
                    if classVal.MatchHdrFields.Transport.Config.DestinationPort != nil {
                        dstPortType := reflect.TypeOf(classVal.MatchHdrFields.Transport.Config.DestinationPort)
   		                switch dstPortType {
				            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort{}):
				     	       v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort)
                    
		                       fbsClassTblMap[className].Field["L4_DST_PORT"] = v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort.ΛMap()["E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort"][int64(v.E_OpenconfigAcl_Acl_AclSets_AclSet_AclEntries_AclEntry_Transport_Config_DestinationPort)].Name
				     	       break
				            case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_String{}):
				     	       v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_String)
		                       fbsClassTblMap[className].Field["L4_DST_PORT_RANGE"]  = strings.Replace(v.String, "..", "-", 1)
				    		   break
	                         case reflect.TypeOf(ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_Uint16{}):
				     	       v := classVal.MatchHdrFields.Transport.Config.DestinationPort.(*ocbinds.OpenconfigFbsExt_Fbs_Classifiers_Classifier_MatchHdrFields_Transport_Config_DestinationPort_Union_Uint16)
		                       fbsClassTblMap[className].Field["L4_DST_PORT"] = strconv.FormatInt(int64(v.Uint16), 10)
				    		   break
				        }
                    }
                    if classVal.MatchHdrFields.Transport.Config.TcpFlags != nil {
                        log.Infof("Classifier CRUD: matchType FIELDS --> key: %v ", className)
                        value := reflect.ValueOf(classVal.MatchHdrFields.Transport.Config.TcpFlags)
	                    flags := value.Interface().([]ocbinds.E_OpenconfigPacketMatchTypes_TCP_FLAGS)
	                    var tcpFlags uint32 = 0x00
                        log.Infof("Classifier CRUD: matchType FIELDS --> key: %v flags:%v value:%v ", className, flags, value)
	                    var b bytes.Buffer
                        for _, flag := range flags {
                            fmt.Println("TCP Flag name: " + flag.ΛMap()["E_OpenconfigPacketMatchTypes_TCP_FLAGS"][int64(flag)].Name)
                            switch flag {
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_FIN:
                                    tcpFlags |= 0x01
                                    break
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_SYN:
                                    tcpFlags |= 0x02
                                    break
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_RST:
                                    tcpFlags |= 0x04
                                    break
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_PSH:
                                    tcpFlags |= 0x08
                                    break
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ACK:
                                    tcpFlags |= 0x10
                                    break
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_URG:
                                    tcpFlags |= 0x20
                                    break
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_ECE:
                                    tcpFlags |= 0x40
                                    break
                                case ocbinds.OpenconfigPacketMatchTypes_TCP_FLAGS_TCP_CWR:
                                    tcpFlags |= 0x80
                                    break
                            }
                        }
				        fmt.Fprintf(&b, "0x%0.2x/0x%0.2x", tcpFlags, tcpFlags)
                        fbsClassTblMap[className].Field["TCP_FLAGS"]   = b.String()
                        //Fill Transport Fields - END
                    }
                }
            }

        //}
    }

    //for replace operation delete all entries except matching ones
    /*if (inParams.oper == REPLACE) {
        log.Infof("Classifier REPLACE Operation " )
        classTbl, _ := inParams.d.GetTable(CLASSIFIER_TABLE_TS)
        classKeys, _ := classTbl.GetKeys()
        if len(classKeys) > 0 {
            for _, key := range classKeys {
                className := key.Get(0)
                _, found := fbsClassTblMap[className]
                if !found {
                    fbsClassTblMap[className] = db.Value{Field: make(map[string]string)}
                }
                fbsClassTblMap[ClassName]["NULL"] = "NULL"
            }
        }
   } */
   res_map[CFG_CLASSIFIER_TABLE] = fbsClassTblMap
   return res_map, err
}
//Classifiers - END

//Policiers - START

//get fbs classifier oc yang match type for match type in db
func getPolicyTypeOCEnumFromDbStr(val string) (ocbinds.E_OpenconfigFbsExt_POLICY_TYPE, error) {
	switch val {
	case SONIC_POLICY_TYPE_QOS, "openconfig-fbs-ext:QOS":
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_QOS, nil
	case SONIC_POLICY_TYPE_FORWARDING, "openconfig-fbs-ext:FORWARDING":
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_FORWARDING, nil
	case SONIC_POLICY_TYPE_MONITORING, "openconfig-fbs-ext:MONITORING":
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_POLICY_MONITORING, nil
	default:
		return ocbinds.OpenconfigFbsExt_POLICY_TYPE_UNSET,
			tlerr.NotSupported("FBS Policy Type '%s' not supported", val)
	}
}

func getPolicyTypeDbStrromOcEnum(ocPolicyType ocbinds.E_OpenconfigFbsExt_POLICY_TYPE) (string, error) {
    dbPolicyType := ""
    if (ocPolicyType == ocbinds.OpenconfigFbsExt_POLICY_TYPE_UNSET) {
		return "", tlerr.NotSupported("FBS Policy Type not set")
    }
    dbPolicyType    = findInMap(POLICY_POLICY_TYPE_MAP, strconv.FormatInt(int64(ocPolicyType), 10))
    return dbPolicyType, nil
}


func fillFbsPolicySectionDetails(inParams XfmrParams, policyName string, policyData *ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy) {
    log.Infof("policyName:%v", policyName)

    policySectionTbl, _ := inParams.d.GetTable(POLICY_SECTION_TABLE_TS)
    policySectionKeys, _:= inParams.d.GetKeysPattern(POLICY_SECTION_TABLE_TS, db.Key{[]string{policyName, "*"}})
	log.Infof("Policy Get;clasKeys %v policySectionTbl:%v ", policySectionKeys, policySectionTbl)

    if len(policySectionKeys) > 0 {
        for _, key := range policySectionKeys {
            className := key.Get(0)
	        log.Infof("Policy Get;Key:%v className:%v ",  key, className)
            policySectionData, _ := policyData.NewSections(className)
            policySectionTblVal, _ := policySectionTbl.GetEntry(key)

            //Fill PolicySectionDetails
	        ygot.BuildEmptyTree(policySectionData)


	        policySectionData.Class = &className
	        policySectionData.Config.Name = &className
	        policySectionData.State.Name = &className
	        log.Infof("Policy Get;Key:%v className:%v ",  key, className)
            if str_val, found := policySectionTblVal.Field["PRIORITY"]; found {
                priority,_ := strconv.Atoi(str_val)
                oc_priority := uint16(priority)
                policySectionData.Config.Priority = &(oc_priority)
                policySectionData.State.Priority = &(oc_priority)
            }


            //Forwarding START
            //forwarding Config 
	        log.Infof("Policy Get;Key:%v className:%v ",  key, className)
            if str_val, found := policySectionTblVal.Field["DEFAULT_PACKET_ACTION"]; found {
                dropFlag := false
               if str_val == "DROP" {
                   dropFlag = true
               }
               policySectionData.Forwarding.Config.Discard = &(dropFlag)
            }

            //forwarding EgressInterfaces 
	        log.Infof("Policy Get;Key:%v className:%v ",  key, className)
            if intfs := policySectionTblVal.GetList("SET_INTERFACE"); len(intfs) > 0 {
                for i := range intfs {
                    intfSplits := strings.Split(intfs[i],"|")
                    egressIfName := intfSplits[0]
                    egressIfData, _ := policySectionData.Forwarding.EgressInterfaces.NewEgressInterface(egressIfName)
	                ygot.BuildEmptyTree(egressIfData)
                    egressIfData.IntfName = &egressIfName
                    egressIfData.Config.IntfName = &egressIfName
                    egressIfData.State.IntfName = &egressIfName
                    if len(intfSplits[1]) > 0 {
                        prio, _ := strconv.Atoi(intfSplits[1])
                        oc_prio := uint16(prio)
                        egressIfData.Config.Priority = &oc_prio
                        egressIfData.State.Priority = &oc_prio
                    }
                }
            }

            //forwarding NextHops 
            var ipNhops [] string
	        log.Infof("Policy Get;Key:%v className:%v ",  key, className)
            if ipNhops = policySectionTblVal.GetList("SET_IP_NEXTHOP"); len(ipNhops) == 0 {  
                ipNhops = policySectionTblVal.GetList("SET_IPV6_NEXTHOP")
            }
            if len(ipNhops) > 0 {
                for i := range ipNhops {
                    nhopSplits := strings.Split(ipNhops[i],"|")
                    nhopIp := nhopSplits[0]
                    //TBD - how to get default network instance
                    vrf := "default"
                    if len(nhopSplits[1]) > 0 {
                        vrf = nhopSplits[1]
                    }
                    nhopData, _ := policySectionData.Forwarding.NextHops.NewNextHop(nhopIp, vrf)
	                ygot.BuildEmptyTree(nhopData)
                    nhopData.IpAddress = &nhopIp
                    nhopData.NetworkInstance = &vrf

                    nhopData.Config.IpAddress = &nhopIp
                    nhopData.Config.NetworkInstance = &vrf

                    nhopData.State.IpAddress = &nhopIp
                    nhopData.State.NetworkInstance = &vrf
                    if len(nhopSplits[2]) > 0 {
                        prio, _ := strconv.Atoi(nhopSplits[2])
                        oc_prio := uint16(prio)
                        nhopData.Config.Priority = &oc_prio
                        nhopData.State.Priority = &oc_prio
                    }
                }
            } 
            //Forwarding - END

            //Monitoring - START 
	        log.Infof("Policy Get;Key:%v className:%v ",  key, className)
            if str_val, found := policySectionTblVal.Field["SET_MIRROR_SESSION"]; found {


                pretty.Print(policySectionData)
                mirrorData, _ := policySectionData.Monitoring.MirrorSessions.NewMirrorSession(str_val)
	            ygot.BuildEmptyTree(mirrorData)
                pretty.Print(policySectionData)
	            log.Infof("mirrorSession:%v ",  str_val)
                mirrorData.Config.SessionName = &str_val    
	            log.Infof("mirrorSession:%v ",  str_val)
                mirrorData.State.SessionName = &str_val    
	            log.Infof("mirrorSession:%v ",  str_val)
            }
            //Forwarding - END

            //QOS - START 
	        log.Infof("Policy Get;Key:%v className:%v ",  key, className)
            if str_val, found := policySectionTblVal.Field["SET_POLICER_CIR"]; found {
                val, _ := strconv.ParseUint(str_val, 10, 64)
                policySectionData.Qos.Policer.Config.Cir = &val
            }
            if str_val, found := policySectionTblVal.Field["SET_POLICER_CBS"]; found {
                val, _ := strconv.ParseUint(str_val, 10, 64)
                oc_val := uint32(val) 
                policySectionData.Qos.Policer.Config.Bc = &oc_val
            }
            if str_val, found := policySectionTblVal.Field["SET_POLICER_PIR"]; found {
                val, _ := strconv.ParseUint(str_val, 10, 64)
                policySectionData.Qos.Policer.Config.Pir = &val
            }
            if str_val, found := policySectionTblVal.Field["SET_POLICER_PBS"]; found {
                val, _ := strconv.ParseUint(str_val, 10, 64)
                oc_val := uint32(val) 
                policySectionData.Qos.Policer.Config.Be = &oc_val
            }

	     /* appDb := inParams.dbs[db.ApplDB]
        _ polPbfKey := db.Key{[]string{policyName, className, interface_name, bind_dir}}
        policerTblVal, err := appDb.GetEntry(POLICER_TABLE_TS, polPbfKey)
        log.Infof("policerTblVal:%v", policerTblVal)
        if err == nil {
            operationalCir, _ = strconv.ParseUint(policerTblVal.Field["CIR"], 10, 64)
            operationalCbs, _ = strconv.ParseUint(policerTblVal.Field["CBS"], 10, 64)
            operationalPir _ = strconv.ParseUint(policerTblVal.Field["PIR"], 10, 64)
            operationPbs, _ = strconv.ParseUint(policerTblVal.Field["PBS"], 10, 64)
            oc_operation_cbs := uint32(operationCbs)
            oc_operation_pbs := uint32(operationPbs)
            policySectionData.QOS.Policier.State.Cir = &operationalCir
            policySectionData.QOS.Policer.State.Pir = &operationalPir
            policySectionData.QOS.Policer.State.Bc = &oc_operational_cbs
            policySectionData.QOS.Policer.State.Be = &oc_operational_pbs
        }*/
        //QOS - END
            log.Info("policy seciton data")
        pretty.Print(policySectionData)
     }
  }
}

//convert from DB to OCYang and fill to OcYang Datastructure for given policy
func fillFbsPolicyDetails(inParams XfmrParams, policyName string, policyTblVal db.Value, policyData *ocbinds.OpenconfigFbsExt_Fbs_Policies_Policy) {
	if policyData == nil {
        log.Infof("fillFbsPolicyDetails--> policyData empty ; policyName:%v ", policyName)
		return
	}

	ygot.BuildEmptyTree(policyData)

	policyData.PolicyName = &policyName
    policyType := policyTblVal.Get("TYPE")
    
    policyData.Config.Name = &policyName
    log.Infof("fillFbsPolicyDetails--> filled config container with policyName:%v and type:%v", policyName, policyType)

	ocPolicyType, _ := getPolicyTypeOCEnumFromDbStr(policyType)
    policyData.Config.Type = ocPolicyType
    policyData.State.Type = policyData.Config.Type
    policyData.State.Name = policyData.Config.Name

        
    fillFbsPolicySectionDetails(inParams, policyName, policyData)
}


//Get
var DbToYang_fbs_policy_subtree_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

	pathInfo := NewPathInfo(inParams.uri)

	fbsObj := getFbsRoot(inParams.ygRoot)
    ygot.BuildEmptyTree(fbsObj)
	log.Infof("Policy Get;path:%v pathfbsObj:%v ", pathInfo.Template, fbsObj)
    log.Info("fbsobj ")
    pretty.Print(fbsObj)

    log.Info("targetObj ")
    pretty.Print(inParams.param)

    if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}") { //policy level request

        policyKeys := reflect.ValueOf(fbsObj.Policies.Policy).MapKeys()
        policyObj := fbsObj.Policies.Policy[policyKeys[0].Interface().(string)]
        policyName := pathInfo.Var("policy-name")
	    log.Infof("Policy Get;policy level request; policyName:%v ",  policyName)
        
        ygot.BuildEmptyTree(policyObj)

        PolicyTbl, _ := inParams.d.GetTable(POLICY_TABLE_TS)
        PolicyTblVal, _ := PolicyTbl.GetEntry(db.Key{[]string{policyKeys[0].Interface().(string)}})
        fillFbsPolicyDetails(inParams, policyName, PolicyTblVal, policyObj)
    } else { //top level get
	    log.Infof("Policy Get;top level Get")

        PolicyTbl, err := inParams.d.GetTable(POLICY_TABLE_TS)
        if (err != nil) {
            log.Infof("Policy Get; couldn't get Policy table" )
        }

        policyKeys, _ := PolicyTbl.GetKeys()
	    log.Infof("Policy Get;clasKeys %v PolicyTbl:%v ", policyKeys, PolicyTbl)

        if len(policyKeys) > 0 {
            for _, key := range policyKeys {
                policyName := key.Get(0)
	            log.Infof("Policy Get;Key:%v policyName:%v ",  key, policyName)
                policyObj, _ := fbsObj.Policies.NewPolicy(policyName)
                PolicyTblVal, _ := PolicyTbl.GetEntry(key)
                fillFbsPolicyDetails(inParams, policyName, PolicyTblVal, policyObj)
	            log.Infof("Policy Get;top level request; PolicyTblVal:%v  ",  PolicyTblVal)
            }
        }
    } 
    return err
}

//CRUD
var YangToDb_fbs_policy_subtree_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value, error) {
    var err error
	var res_map map[string]map[string]db.Value = make(map[string]map[string]db.Value)

    pathInfo := NewPathInfo(inParams.uri)
    keyName := pathInfo.Var("class-name")
    log.Infof("Policy CRUD;: key:%v pathInfo%v ", keyName, pathInfo)
 
    log.Info("Policy CRUD;: inParams.uri ")
    pretty.Print(inParams.uri)

    path, err := getUriPath(inParams.uri)
    if err != nil {
        log.Infof("Policy CRUD;: path get error:%v ", err)
        return nil, err
    }
    targetNode, err := getYangNode(path)
    if err != nil {
        log.Infof("Policy %v operation ; targetNode get failed Error: %v", inParams.oper)
        return res_map, tlerr.InvalidArgs("Invalid request - error: %v", err)
    }

	fbsObj := getFbsRoot(inParams.ygRoot)
	fbsPolicyTblMap := make(map[string]db.Value)

    if inParams.oper == DELETE {
        if fbsObj == nil || fbsObj.Policies == nil || len(fbsObj.Policies.Policy) == 0 {
            log.Info("Policy DELETE operation; Top Level")
		    res_map[CFG_POLICY_TABLE] = fbsPolicyTblMap
            return res_map, err
        } else if isSubtreeRequest(pathInfo.Template, "/openconfig-fbs-ext:fbs/policies/policy{policy-name}") { //policyEntry level
            for PolicyKey, PolicyVal := range fbsObj.Policies.Policy {
                log.Infof("Policy %v DELETE operation; PolicyVal ", PolicyKey)
                pretty.Print(PolicyVal)
                if PolicyVal.Config == nil { //policy level delete
                    log.Infof("Policy %v delete", PolicyKey)
                    fbsPolicyTblMap[PolicyKey] = db.Value{Field: make(map[string]string)}
                    res_map[CFG_POLICY_TABLE] = fbsPolicyTblMap
					log.Info("policy level delete class data")
					pretty.Print(fbsPolicyTblMap)
                        break 
                } else  {
                    //Specific Field delete
                    log.Infof("Policy %v DELETE operation; specific field delete, targetName:%v ", PolicyKey, targetNode.Name)

                    /*
                    dbV := db.Value{Field: make(map[string]string)}
                    if isSubtreeRequest(pathInfo.Template, "/match-hdr-fields/ipv4/config") { //Class match-hdr-fields ipv4
                        log.Infof("Policy %v DELETE operation; IPV4 field delete; targetName:%v ", PolicyKey, targetNode.Name)
                        if  targetNode.Name == "source-address" {
                            dbV.Field["source-address"] = ""
                            fbsPolicyTblMap[PolicyKey] = dbV
                            res_map[CFG_POLICY_TABLE] =fbsPolicyTblMap 
                        } else if targetNode.Name == "destination-address" {
                            dbV.Field["destination-address"] = ""
                            fbsPolicyTblMap[PolicyKey] = dbV
                            res_map[CFG_POLICY_TABLE] =fbsPolicyTblMap 
                        }
                    }
                    */
                }
            }
        }

		return res_map, err
    }  //DELETE - END


   //CRU
   for policyName, PolicyVal := range fbsObj.Policies.Policy {
        if PolicyVal == nil {
            continue
        }
        log.Infof("Policy CRUD; --> key: %v PolicyVal", policyName)
        pretty.Print(PolicyVal)

        _, found := fbsPolicyTblMap[policyName]
        if !found {
                fbsPolicyTblMap[policyName] = db.Value{Field: make(map[string]string)}
        }

        ocpolicyType, _ := getPolicyTypeDbStrromOcEnum(PolicyVal.Config.Type)
        fbsPolicyTblMap[policyName].Field["TYPE"] = ocpolicyType
        log.Infof("Policy CRUD; Policy %v  fbsPolicyTblMap:%v ", PolicyVal, fbsPolicyTblMap)
    }

    //for replace operation delete all entries except matching ones
    /*
    if (inParams.oper == REPLACE) {
        log.Infof("Policy REPLACE Operation " )
        PolicyTbl, _ := inParams.d.GetTable(POLICY_TABLE_TS)
        policyKeys, _ := PolicyTbl.GetKeys()
        if len(policyKeys) > 0 {
            for _, key := range policyKeys {
                policyName := key.Get(0)
                _, found := fbsPolicyTblMap[policyName]
                if !found {
                    fbsPolicyTblMap[policyName] = db.Value{Field: make(map[string]string)}
                }
                fbsPolicyTblMap[policyName]["NULL"] = "NULL"
            }
        }
        
   } */
   res_map[CFG_POLICY_TABLE] = fbsPolicyTblMap
   return res_map, err
}
