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

/*
Package translib defines the functions to be used to authorize

an incoming user. It also includes caching of the UserDB data

needed to authorize the user.

*/

package translib

import (
	//"strconv"
	//log "github.com/golang/glog"
	"strings"
)

//TODO:define maps for storing the UserDB cache

var OPER_ALLOW_RPC = map[string]bool{
	"get-ipsla-history":               true,
	"show-sys-log":                    true,
	"sys-log-count":                   true,
	"get-loglevel-severity":           true,
	"show-pim":                        true,
	"interface_counters":              true,
	"get-auditlog":                    true,
	"get-vrrp":                        true,
	"get-vrrp6":                       true,
	"get-match-protocols":             true,
	"show-ipmroute":                   true,
	"crm-acl-group-stats":             true,
	"crm-acl-table-stats":             true,
	"crm-stats":                       true,
	"get-buffer-pool-wm-stats":        true,
	"xcvr_diag_loopback_capabilities": true,
	"xcvr_op_params":                  true,
	"show-ip-route":                   true,
	"sonic-show-techsupport-info":     true,
	"get-classifier":                  true,
	"get-policy":                      true,
	"get-service-policy":              true,
	"get-pbf-next-hop-group":          true,
	"show-ospfv2-max-age-lsa":         true,
	"show-bgp":                        true,
	"show-bgp-statistics":             true,
	"show-bgp-evpn":                   true,
	"breakout_dependencies":           true,
	"breakout_capabilities":           true,
	"show-counters":                   true,
	"sum":                             true,
	"my-echo":                         true,
}

func init() {
	//TODO:Allocate the maps and populate them here
}

func isAuthorizedForSet(req SetRequest) bool {
	if !req.AuthEnabled {
		return true
	}
	for _, r := range req.User.Roles {
		if r == "admin" {
			return true
		}
	}
	return false
}
func isAuthorizedForBulk(req BulkRequest) bool {
	if !req.AuthEnabled {
		return true
	}
	for _, r := range req.User.Roles {
		if r == "admin" {
			return true
		}
	}
	return false
}

func isAuthorizedForGet(req GetRequest) bool {
	if !req.AuthEnabled {
		return true
	}
	return true
}
func isAuthorizedForSubscribe(req SubscribeRequest) bool {
	if !req.AuthEnabled {
		return true
	}
	return true
}
func isAuthorizedForIsSubscribe(req IsSubscribeRequest) bool {
	if !req.AuthEnabled {
		return true
	}
	return true
}

func isAuthorizedForAction(req ActionRequest) bool {
	if !req.AuthEnabled {
		return true
	}
	for _, r := range req.User.Roles {
		if r == "admin" {
			return true
		}
	}
	path_parts := strings.Split(req.Path, ":")
	rpc_name := path_parts[len(path_parts)-1]
	if _, ok := OPER_ALLOW_RPC[rpc_name]; ok {
		return true
	}

	return false
}
