//////////////////////////////////////////////////////////////////////////
//
// Copyright 2020 Dell, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//////////////////////////////////////////////////////////////////////////

package transformer_test

import (
	"fmt"
	"testing"
	"time"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

/* to run Test_OC_Yang_Rpc_support, add the test OC YANG
1. define the rpc 
--- a/models/yang/extensions/openconfig-system-ext.yang
+++ b/models/yang/extensions/openconfig-system-ext.yang
@@ -463,4 +463,14 @@ module openconfig-system-ext {
         description
             "NTP server status.";
     }
+
+     rpc fast-reboot {
+           output {
+               leaf status{
+                    type string;
+                    description "fast-reboot status";
+               }
+           }
+     }
+
 }

2. add models/yang/annotations/openconfig-system-ext-annot.yang

module openconfig-system-ext-annot {

    yang-version "1";

    namespace "http://openconfig.net/yang/openconfig-system-ext-annot";
    prefix "oc-sys-ext-annot";

    import sonic-extensions { prefix sonic-ext; }
    import openconfig-system-ext { prefix oc-sys-ext; }

    deviation /oc-sys-ext:fast-reboot {
        deviate add {
           sonic-ext:rpc-callback "rpc_infra_fast_reboot";
       }
    }
}
 
3. add the annot file to the models_list  
--- a/config/transformer/models_list
+++ b/config/transformer/models_list
@@ -114,3 +114,4 @@ openconfig-ip-helper.yang
 openconfig-ip-helper-annot.yang
 sonic-ip-helper.yang
 sonic-ip-helper-annot.yang
+openconfig-system-ext-annot.yang

4. add the rpc callback
--- a/translib/transformer/xfmr_system.go
+++ b/translib/transformer/xfmr_system.go
@@ -36,6 +36,7 @@ func init () {
     XlateFuncBind("DbToYang_server_dns_key_xfmr", DbToYang_server_dns_key_xfmr)
     XlateFuncBind("YangToDb_server_dns_field_xfmr", YangToDb_server_dns_field_xfmr)
     XlateFuncBind("DbToYang_server_dns_field_xfmr", DbToYang_server_dns_field_xfmr)
+    XlateFuncBind("rpc_infra_fast_reboot", rpc_infra_fast_reboot)
 }

 type SysMem struct {
@@ -547,3 +548,12 @@ var DbToYang_server_dns_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (ma

     return rmap, nil
 }
+
+var rpc_infra_fast_reboot RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) (result []byte, err error) {
+
+    log.Infof("Enter rpc_infra_fast_reboot")
+    var rmap []byte
+
+    return rmap, nil
+
+}
 
*/


func Test_OC_Yang_Rpc_support(t *testing.T) {

	url := "/openconfig-system-ext:sys-log-count"

        fmt.Println("++++++++++++++  POST on sys-log-count  +++++++++++++")

        t.Run("POST on rpc fast-reboot", processActionRequest(url, "{}", "POST", "", "", false, false))
        time.Sleep(1 * time.Second)

}


func Test_SONiC_Yang_Rpc_support(t *testing.T) {

	url := "/sonic-nat:clear_nat"

        fmt.Println("++++++++++++++  POST on clear_nat  +++++++++++++")

        t.Run("POST on rpc clear_nat", processActionRequest(url, "{\"sonic-nat:input\":{\"nat-param\":\"test-nat\"}}", "POST", "", "", false, false))
        time.Sleep(1 * time.Second)

}

func Test_Rpc_AdminUser_Set(t *testing.T) {

        url := "/openconfig-interfaces-ext:clear-counters"

        fmt.Println("++++++++++++++  RPC for admin user Set  +++++++++++++")

        t.Run("POST on rpc admin user clear interface counters ", processActionRequest(url, "{\"openconfig-interfaces-ext:input\":{\"interface-param\":\"all\"}}", "POST", "admin", "admin", true, false))
        time.Sleep(1 * time.Second)

}

func Test_Rpc_AdminUser_Get(t *testing.T) {

        url := "/sonic-snmp:show-counters"

        fmt.Println("++++++++++++++  RPC for admin user Get  +++++++++++++")

        t.Run("POST on rpc snmp show-counters", processActionRequest(url, "{}", "POST", "admin", "admin", true, false))
        time.Sleep(1 * time.Second)

}

func Test_Rpc_OperUser_Get(t *testing.T) {

        url := "/sonic-snmp:show-counters"

        fmt.Println("++++++++++++++  RPC for oper user GET +++++++++++++")

        t.Run("POST on rpc snmp show counters", processActionRequest(url, "{}", "POST", "oper", "operator", true, false))
        time.Sleep(1 * time.Second)

}

func Test_Rpc_OperUser_Set(t *testing.T) {

        url := "/openconfig-system-ext:reboot-ops"

        fmt.Println("++++++++++++++  RPC for oper user Set +++++++++++++")

	expected_err := tlerr.AuthorizationError{Format:"User is unauthorized for Action Operation"}
        t.Run("POST on rpc reboot-ops", processActionRequest(url, "{\"openconfig-system-ext:input\":{\"param\":\"id\"}}", "POST", "oper", "operator", true, true, expected_err))
        time.Sleep(1 * time.Second)

}
