package transformer

import (
	"errors"
    "strings"
	_"fmt"
	"reflect"
	"strconv"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	log "github.com/golang/glog"
	    "github.com/openconfig/ygot/ygot"
    )


func init () {
	XlateFuncBind("DbToYang_ipv4_route_get_xfmr", DbToYang_ipv4_route_get_xfmr)
	XlateFuncBind("DbToYang_ipv6_route_get_xfmr", DbToYang_ipv6_route_get_xfmr)
}


func getIpRoot (inParams XfmrParams) (*ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts, string, string, uint64, error) {
	pathInfo := NewPathInfo(inParams.uri)
	niName := pathInfo.Var("name")
	prefix := pathInfo.Var("prefix")
	_nhindex,_ := strconv.Atoi(pathInfo.Var("index"))
	nhindex :=  uint64(_nhindex)
	var err error

	targetUriPath, _ := getYangPathFromUri(pathInfo.Path)

	if len(niName) == 0 {
		return nil, "", "",0, errors.New("vrf name is missing")
	}
    if !((niName == "default") || (niName == "mgmt") || (strings.HasPrefix(niName, "Vrf"))) {
		return nil, "", "", 0,errors.New("vrf name is invalid for AFT tables get operation")
    }

	deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
	netInstsObj := deviceObj.NetworkInstances

        netInstObj := netInstsObj.NetworkInstance[niName]
	if netInstObj == nil {
                netInstObj, _ = netInstsObj.NewNetworkInstance(niName)
	}
	ygot.BuildEmptyTree(netInstObj)

	netInstAftsObj := netInstObj.Afts

	if netInstAftsObj == nil {
                ygot.BuildEmptyTree(netInstObj)
                netInstAftsObj  = netInstObj.Afts
	}
	ygot.BuildEmptyTree(netInstAftsObj)
	log.Infof(" niName %s targetUriPath %s prefix %s nhindex %s", niName, targetUriPath, prefix, nhindex)

	return netInstAftsObj, niName, prefix, nhindex, err
}


func parse_protocol_type (jsonProtocolType string, originType *ocbinds.E_OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE) {

    switch jsonProtocolType {
        case "static":
            *originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC
        case "connected":
            *originType =  ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_DIRECTLY_CONNECTED
        case "bgp":
            *originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_BGP
        case "ospf":
        	*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF
        case "ospf3":
        	*originType = ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_OSPF3
        default:
        	*originType=  ocbinds.OpenconfigPolicyTypes_INSTALL_PROTOCOL_TYPE_UNSET
   	} 	
}

func fill_ipv4_nhop_entry(nexthopsArr []interface{},
                          ipv4NextHops *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry_NextHops,
                          nhindex uint64) (error) {
	var err error
	var index uint64

	for _, nextHops := range nexthopsArr {

	switch  t := nextHops.(type) {

		case map[string]interface{}:
			var nextHop *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry_NextHops_NextHop
			nextHopsMap := nextHops.(map[string]interface{})
			isactive, ok := nextHopsMap["active"]

			if !ok || isactive == false {
				log.Infof("Nexthop is not active, skip")
				break
			}

			index += 1
			/* if user specified specific next-hop index, just return that
			   otherwise retun all.*/
                        if nhindex != 0 && nhindex != index {
				continue
			}
			nextHop = ipv4NextHops.NextHop[index]
			if nextHop == nil {
				nextHop, err = ipv4NextHops.NewNextHop(uint64(index))
				if err != nil {
					return errors.New("Operational Error")
				}
			}
			ygot.BuildEmptyTree(nextHop)
			nextHop.Config.Index = nextHop.Index

			var state ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry_NextHops_NextHop_State
			state.Index = nextHop.Index

			for nextHopKey, nextHopVal := range nextHopsMap {
				if nextHopKey == "interfaceName" {
					intfName := nextHopVal.(string)
					ygot.BuildEmptyTree(nextHop.InterfaceRef)
					nextHop.InterfaceRef.Config.Interface = &intfName
					nextHop.InterfaceRef.State.Interface = &intfName
   				} else if nextHopKey == "ip" {
   					ip := nextHopVal.(string)
					state.IpAddress = &ip
   				} else if nextHopKey == "directlyConnected" {
   					isDirectlyConnected := nextHopVal.(bool)
   					state.DirectlyConnected = &isDirectlyConnected
  				}
			}
			nextHop.State = &state
   		default:
   			log.Infof("Unhandled nextHops type [%s]", t)
   		}
   	}
   	return err
}


func fill_ipv4_entry (prfxValArr []interface{},
			prfxKey string,
			aftsObjIpv4 *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast,
			nhindex uint64) (error) {
	var err error
 	var ipv4Entry *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv4Unicast_Ipv4Entry
	for _, prfxValArrVal := range prfxValArr {
		log.Infof("prfxValMap_type[%s]", reflect.TypeOf(prfxValArrVal))
		switch t := prfxValArrVal.(type) {

		case map[string]interface{}:

			prfxValArrValMap := prfxValArrVal.(map[string]interface{})
			if _, ok := prfxValArrValMap["selected"]; !ok {
				log.Infof("Route is not selected, skip %s", prfxKey)
			    break
			}
			var ok bool
			if ipv4Entry, ok = aftsObjIpv4.Ipv4Entry[prfxKey] ; !ok {
				ipv4Entry, err = aftsObjIpv4.NewIpv4Entry(prfxKey)
				if err != nil {
					return errors.New("Operational Error")
				}
			}
			ygot.BuildEmptyTree(ipv4Entry)
			ipv4Entry.Config.Prefix = &prfxKey
			ipv4Entry.State.Prefix = &prfxKey

			for prfxValKey, prfxValVal := range prfxValArrValMap {

				if prfxValKey == "protocol" {
					parse_protocol_type(prfxValVal.(string), &ipv4Entry.State.OriginProtocol)
				} else if prfxValKey == "distance" {
   	 				distance := (uint32)(prfxValVal.(float64))
					ipv4Entry.State.Distance = &distance
   	 			} else if prfxValKey == "metric" {
   	 				metric := (uint32)(prfxValVal.(float64))
   	 				ipv4Entry.State.Metric = &metric
   	 			}  else if prfxValKey == "uptime" {
   	 				uptime := prfxValVal.(string)
   	 				ipv4Entry.State.Uptime = &uptime
					log.Infof("uptime: [%s]", ipv4Entry.State.Uptime)
   	 			} else if prfxValKey == "nexthops" {
  	 				err = fill_ipv4_nhop_entry(prfxValVal.([]interface{}), ipv4Entry.NextHops, nhindex)
  	 				if err != nil {
  	 					return err
  	 				}
  	 			}
   	 		}

   	 	default:
   	 		log.Infof("Unhandled prfxValArrVal : type [%s]", t)
   	 	}
   	}
   	return err
}


func fill_ipv6_nhop_entry(nexthopsArr []interface{},
			  ipv6NextHops *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry_NextHops,
			  nhindex uint64) (error) {

	var err error
	var index uint64
	for _, nextHops := range nexthopsArr {

	switch  t := nextHops.(type) {

		case map[string]interface{}:
			var nextHop *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry_NextHops_NextHop

			nextHopsMap := nextHops.(map[string]interface{})
			isactive, ok := nextHopsMap["active"]

			if !ok || isactive == false {
				log.Infof("Nexthop is not active, skip")
			    break
			}
			index += 1
			/* if user specified specific next-hop index, just return that
			   otherwise retun all.*/
                        if nhindex != 0 && nhindex != index {
				continue
			}
			nextHop = ipv6NextHops.NextHop[index]
			if nextHop == nil {
				nextHop, err = ipv6NextHops.NewNextHop(uint64(index))
				if err != nil {
					return errors.New("Operational Error")
				}
			}
			ygot.BuildEmptyTree(nextHop)
			nextHop.Config.Index = nextHop.Index

			var state ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry_NextHops_NextHop_State
			state.Index = nextHop.Index

			for nextHopKey, nextHopVal := range nextHopsMap {
				if nextHopKey == "interfaceName" {
					intfName := nextHopVal.(string)
					ygot.BuildEmptyTree(nextHop.InterfaceRef)
					nextHop.InterfaceRef.Config.Interface = &intfName
					nextHop.InterfaceRef.State.Interface = &intfName
   				} else if nextHopKey == "ip" {
   					ip := nextHopVal.(string)
					state.IpAddress = &ip
   				} else if nextHopKey == "directlyConnected" {
   					isDirectlyConnected := nextHopVal.(bool)
   					state.DirectlyConnected = &isDirectlyConnected
  				}
			}
			nextHop.State = &state
   		default:
   			log.Infof("Unhandled nextHops type [%s]", t)
   		}
   	}
   	return err
}

func fill_ipv6_entry (prfxValArr []interface{},
			prfxKey string,
			aftsObjIpv6 *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast,
			nhindex uint64) (error) {

 	var err error
 	var ipv6Entry *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts_Ipv6Unicast_Ipv6Entry
	for _, prfxValArrVal := range prfxValArr {
		log.Infof("prfxValMap_type[%s]", reflect.TypeOf(prfxValArrVal))
		switch t := prfxValArrVal.(type) {

		case map[string]interface{}:
			// skip non-selected routes.

			prfxValArrValMap := prfxValArrVal.(map[string]interface{})
			if _, ok := prfxValArrValMap["selected"]; !ok {
				log.Infof("Route is not selected, skip %s", prfxKey)
			    break
			}
			var ok bool
			if ipv6Entry, ok = aftsObjIpv6.Ipv6Entry[prfxKey] ; !ok {
				ipv6Entry, err = aftsObjIpv6.NewIpv6Entry(prfxKey)
				if err != nil {
					return errors.New("Operational Error")
				}
			}

			ygot.BuildEmptyTree(ipv6Entry)
			ipv6Entry.Config.Prefix = &prfxKey
			ipv6Entry.State.Prefix = &prfxKey

			for prfxValKey, prfxValVal := range prfxValArrValMap {

				if prfxValKey == "protocol" {
   	 				parse_protocol_type(prfxValVal.(string), &ipv6Entry.State.OriginProtocol)
   	 			} else if prfxValKey == "distance" {
   	 				distance := (uint32)(prfxValVal.(float64))
   	 				ipv6Entry.State.Distance = &distance
   	 			} else if prfxValKey == "metric" {
   	 				metric := (uint32)(prfxValVal.(float64))
   	 				ipv6Entry.State.Metric = &metric
   	 			} else if prfxValKey == "uptime" {
   	 				uptime := prfxValVal.(string)
   	 				ipv6Entry.State.Uptime = &uptime
   	 				log.Infof("uptime: [%s]", ipv6Entry.State.Uptime)
   	 			}  else if prfxValKey == "nexthops" {
  	 				err = fill_ipv6_nhop_entry(prfxValVal.([]interface{}), ipv6Entry.NextHops, nhindex)
  	 				if err != nil {
  	 					return err
  	 				}
  	 			}
   	 		}

   	 	default:
   	 		log.Infof("Unhandled prfxValArrVal : type [%s]", t)
   	 	}
   	}
   	return err
}

var DbToYang_ipv4_route_get_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) error {

	var err error
	var aftsObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts
	var niName string
	var prefix string
	var nhindex uint64

	aftsObj, niName, prefix, nhindex, err = getIpRoot(inParams)

	_ = niName

	if (err != nil) {
		return err
	}

	aftsObjIpv4 := aftsObj.Ipv4Unicast
	if aftsObjIpv4  == nil {
                return errors.New("Network-instance IPv4 unicast object missing")
	}
	ygot.BuildEmptyTree(aftsObjIpv4)

	var outputJson map[string]interface{}
	cmd := "show ip route vrf " + niName
	if len(prefix) > 0 {
		cmd += " "
		cmd += prefix
	}
	cmd += " json"
 	log.Infof("vty cmd [%s]", cmd)
 
   	if outputJson, err = exec_vtysh_cmd(cmd); err == nil {

   		for prfxKey, prfxVal := range outputJson {
			if outError, ok := outputJson["warning"] ; ok {
				log.Errorf ("\"%s\" VTYSH-cmd execution failed with error-msg ==> \"%s\" !!", cmd, outError)
				return errors.New("Operational error")
			}

   			err = fill_ipv4_entry(prfxVal.([]interface{}), prfxKey, aftsObjIpv4, nhindex)

   			if (err != nil) {
   				return err
   			}
   		}
   	}
   	return err
}

var DbToYang_ipv6_route_get_xfmr SubTreeXfmrDbToYang = func (inParams XfmrParams) error {

	var err error
	var aftsObj *ocbinds.OpenconfigNetworkInstance_NetworkInstances_NetworkInstance_Afts
	var niName string
	var prefix string
	var nhindex uint64

	aftsObj, niName, prefix, nhindex, err = getIpRoot(inParams)
	_ = niName

	if (err != nil) {
		return err
	}

	aftsObjIpv6 := aftsObj.Ipv6Unicast
	if aftsObjIpv6  == nil {
                return errors.New("Network-instance IPv6 unicast object missing")
	}
	ygot.BuildEmptyTree(aftsObjIpv6)

	var outputJson map[string]interface{}
	cmd := "show ipv6 route vrf " + niName
	if len(prefix) > 0 {
		cmd += " "
		cmd += prefix
	}
	cmd += " json"
 	log.Infof("vty cmd [%s]", cmd)

   	if outputJson, err = exec_vtysh_cmd(cmd); err == nil {

   		for prfxKey, prfxVal := range outputJson {
			if outError, ok := outputJson["warning"] ; ok {
				log.Errorf ("\"%s\" VTYSH-cmd execution failed with error-msg ==> \"%s\" !!", cmd, outError)
				return errors.New("Operational error")
			}

  			err = fill_ipv6_entry(prfxVal.([]interface{}), prfxKey, aftsObjIpv6, nhindex)

   			if (err != nil) {
   				return err
   			}
   		}
   	}
   	return err
}
