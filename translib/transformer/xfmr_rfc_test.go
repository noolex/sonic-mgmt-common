//////////////////////////////////////////////////////////////////////
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
	//db "github.com/Azure/sonic-mgmt-common/translib/db"
)

/***********************************************************************************************************************/
/***************************    RFC COMPLIANCE TEST - POST OPERATION   *************************************************/
/***********************************************************************************************************************/

func Test_Rfc_Post_Operation(t *testing.T) {

	/* expected return code - 201(Created) */

	prereq := map[string]interface{}{"AAA":map[string]interface{}{"authentication":""}}

	// Setup - Prerequisite
	unloadConfigDB(rclient, prereq)

	fmt.Println("++++++++++++++  POST -  uri: container, message-body: leaf and leaf-list  +++++++++++++")
	url := "/openconfig-system:system/aaa/authentication/config"
	payload :="{\"openconfig-system-ext:failthrough\": \"False\", \"openconfig-system:authentication-method\": [\"tacacs+\", \"local\"]}"
	expected := map[string]interface{}{"AAA":map[string]interface{}{"authentication":map[string]interface{}{"login":"tacacs+,local", "failthrough":"False"}}}

	t.Run("RFC - POST on Container", processSetRequest(url, payload, "POST", false))
	time.Sleep(1 * time.Second)
	t.Run("RFC - Verify POST on container", verifyDbResult(rclient, "AAA|authentication", expected, false))

	fmt.Println("++++++++++++++  POST - uri: list, message-body: list instance wth leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  POST - uri: list instance, message-body: leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  Idempotetnt POST +++++++++++++")

	// Teardown
}

func Test_Rfc_Post_Negative_Cases(t *testing.T) {

	/* expected return code - 404(Not Found) */
	fmt.Println("++++++++++++++  POST with uri: container, but parent instance not existent, return 404 +++++++++++++")
	fmt.Println("++++++++++++++  POST with uri: list instance, but the list instance not existent, return 404 +++++++++++++")

	/* expected return code - 400(Bad Request) */
	fmt.Println("++++++++++++++  POST - uri: leaf, message-body: leaf +++++++++++++")
	fmt.Println("++++++++++++++  POST - uri: leaf-list, message-body: leaf-list +++++++++++++")
}

func Test_Rfc_Put_Operation(t *testing.T) {
	/* expected return code - 201(Created) for resource creation */
	fmt.Println("++++++++++++++  PUT(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  PUT(create) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  PUT(create) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  PUT(create) uri: leaf, message-body: leaf  +++++++++++++")
	fmt.Println("++++++++++++++  PUT(create) uri: leaf-list, message-body: leaf-list  +++++++++++++")

	/* expected return code - 204(No Content) for resource modification */
	fmt.Println("++++++++++++++  PUT(replace) uri: container, message-body: container, leaf and leaf-list +++++++++++++")
	fmt.Println("++++++++++++++  PUT(replace) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  PUT(replace) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
}
func Test_Rfc_Put_Negative_Cases(t *testing.T) {
	/* expected return code - 400(Bad Request) */
	fmt.Println("++++++++++++++  PUT uri: list instance, but message-body has a diffent instance, return 400 +++++++++++++")

	/* expected return code - 404(Not Found) */
	fmt.Println("++++++++++++++  PUT with uri: container, but parent instance not existent, return 404 +++++++++++++")
}

func Test_Rfc_Patch_Operation(t *testing.T) {
	/* expected return code - 204(No Content) to create */
	fmt.Println("++++++++++++++  PATCH(create) uri: container, message-body: container, leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  PATCH(create) uri: list, message-body: list, instance, leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  PATCH(create) uri: list instance, message-body: list instance, leaf and leaf-list  +++++++++++++")
	fmt.Println("++++++++++++++  PATCH(create) uri: leaf, message-body: leaf  +++++++++++++")
	fmt.Println("++++++++++++++  PATCH(create) uri: leaf-list, message-body: leaf-list  +++++++++++++")

	/* expected return code - 204(No Content) for merge, fill some other nodes or override existing ones */
	/* repeat above */
}
func Test_Rfc_Patch_Negative_Cases(t *testing.T) {
	/* expected return code - 404(Not Found) */
	fmt.Println("++++++++++++++  PATCH with uri list instance that is not existent, SNC-3340  +++++++++++++")
}

func Test_Rfc_Delete_Operation(t *testing.T) {
	/* expected return code - 204(No Content) */
	fmt.Println("++++++++++++++  DELETE uri container  +++++++++++++")
	fmt.Println("++++++++++++++  DELETE uri list  +++++++++++++")
	fmt.Println("++++++++++++++  DELETE uri list instance +++++++++++++")
	fmt.Println("++++++++++++++  DELETE uri leaf +++++++++++++")
	fmt.Println("++++++++++++++  DELETE uri leaf-list +++++++++++++")
	fmt.Println("++++++++++++++  DELETE uri leaf-list instance +++++++++++++")
}
func Test_Rfc_Delete_Negative_Cases(t *testing.T) {
	/* expected return code - 404(Not Found) */
	fmt.Println("++++++++++++++  DELETE with uri: list instance not existent +++++++++++++")

	/* expected return code - 204(No Content), note we don't return 404 below cases. */
	fmt.Println("++++++++++++++  DELETE with uri: leaf not existent +++++++++++++")
	fmt.Println("++++++++++++++  DELETE with uri: leaf-lst not existent +++++++++++++")
	fmt.Println("++++++++++++++  DELETE with uri: leaf-lst instance not existent +++++++++++++")
}

func Test_Rfc_Get_Operation(t *testing.T) {
	/* expected return code - 200(Ok), with empty body */
	fmt.Println("++++++++++++++  GET with uri container, but no data nodes existent +++++++++++++")
	fmt.Println("++++++++++++++  GET with uri list, but no instances existent +++++++++++++")
	fmt.Println("++++++++++++++  GET with uri leaf-list, but no instances existent +++++++++++++")

	/* expected return code - 200(Ok), with non-empty body */
	fmt.Println("++++++++++++++  GET with uri OC list instance, and data exists +++++++++++++")
	fmt.Println("++++++++++++++  GET with uri OC list instance/config, and data exists +++++++++++++")
}
func Test_Rfc_Get_Negative_Cases(t *testing.T) {
	/* expected return code - 404(Not Found) */
	fmt.Println("++++++++++++++  GET with uri container: parent list instance not existent +++++++++++++")
	fmt.Println("++++++++++++++  GET with uri list instance not existent +++++++++++++")
}






