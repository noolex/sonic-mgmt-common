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
)

func Test_LeafList_oneToone_mapping_OCYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list one to one mapping ++++++++++++")
	// 1:1, field-name
	var prereq_snmp_vacm_view_map map[string]interface{}
	var expected_snmp_vacm_view_map map[string]interface{}
	var url, url_body_json string
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm"
	url_body_json = "{\"ietf-snmp:view\":[{\"name\":\"TestVacmView1\",\"exclude\":[\"1.2.3.4.*\",\"1.4.6.*\"]}]}"
	//automatically covers field-name case
	t.Run("1:1 mapping create", processSetRequest(url, url_body_json, "POST", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify 1:1 mapping create.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)

	// update/merge, 1:1, field-name
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*",
		"include@": "1.2.3.4.*,1.4.6.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*",
		"include@": "1.2.3.4.*,1.4.6.*,1.2.3.5.*,1.3.6.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	url_body_json = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
	t.Run("1:1 mapping update,merge.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify 1:1 mapping update,merge", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)

	// Update leaf-list with empty-string , on an empty-string leaf-list in DB
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	url_body_json = "{\"ietf-snmp:include\":[\"\"]}"
	t.Run("Update leaf-list with empty-string , on an empty-string leaf-list in DB.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Update leaf-list with empty-string , on an empty-string leaf-list in DB", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)

	// Update leaf-list with no element, on an empty-string leaf-list in DB
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	url_body_json = "{\"ietf-snmp:include\":[]}" //empty slice
	t.Run("Update leaf-list with no element, on an empty-string leaf-list in DB.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Update leaf-list with no element, on an empty-string leaf-list in DB", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)

	// replace/swap 1:1, field-name
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*",
		"include@": "1.2.3.4.*,1.4.6.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*",
		"include@": "1.2.3.5.*,1.3.6.*,1.4.6.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	url_body_json = "{ \"ietf-snmp:include\": [ \"1.2.3.5.*\",\"1.3.6.*\", \"1.4.6.*\"]}"
	t.Run("1:1 mapping replace,merge.", processSetRequest(url, url_body_json, "PUT", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify 1:1 mapping replace,swap", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)

	fmt.Println("+++++++++++++ Done!!! Performing Leaf-list one to one mapping OC Yang Cases ++++++++++++")

}

func Test_LeafList_Delete_OCYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list Deletion OC Yang Cases ++++++++++++")
	var prereq_snmp_vacm_view_map map[string]interface{}
	var expected_snmp_vacm_view_map map[string]interface{}
	var url string

	/** delete specific item from leaf-list .Also auto covers merge, 1:1, field-name **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": "1.2.3.4.*,1.4.6.*,1.2.3.5.*,1.3.6.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": "1.2.3.4.*,1.2.3.5.*,1.3.6.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.4.6.*]"
	t.Run("Delete an item in leaf-list.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item in leaf-list.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete specific item from leaf-list when leaf-list does not exist in DB.Also auto covers merge, 1:1, field-name **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.4.6.*]"
	t.Run("Delete an item when leaf-list doesn't exist in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item when leaf-list doesn't exist in DB.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete an item from leaf-list which happens to be the only element in leaf-list in DB. Also auto covers merge, 1:1, field-name **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"include@": "1.2.3.4.*",
		"exclude@": "1.2.3.4.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.2.3.4.*]"
	t.Run("Delete an item which is the only one in leaf-list.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item which is the only one in leaf-list.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete entire leaf-list. Also auto covers merge, 1:1, field-name **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"include@": "1.2.3.4.*,1.4.6.*,1.2.3.5.*,1.3.6.*",
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	t.Run("Delete entire leaf-list.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Delete entire leaf-list.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete entire leaf-list, when leaf-list doesn't exist in DB. Also auto covers merge, 1:1, field-name **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	t.Run("Delete leaf-list when it doesn't exist in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete leaf-list when it doesn't exist in DB.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete an item from leaf-list when leaf-list in DB is an empty string. Also auto covers merge, 1:1, field-name **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"include@": "",
		"exclude@": "1.2.3.4.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"include@": "",
		"exclude@": "1.2.3.4.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=1.2.3.4.*]"
	t.Run("Delete an item when leaf-list is empty-string in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item when leaf-list is empty-string in DB.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete an entire leaf-list when leaf-list is empty-string in DB **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"include@": "",
		"exclude@": "1.2.3.4.*"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	t.Run("Delete an ntire leaf-list when leaf-list is empty-string in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an ntire leaf-list when leaf-list is empty-string in DB.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete specific item from leaf-list . field-value has "/"  **/
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{"include@": "test1/1,test2/2"}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{"include@": "test2/2"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include[include=test1/1]"
	t.Run("Delete an item in leaf-list with field value having /.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item in leaf-list with field value having /.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	/** delete on leaf-list instance with regex pattern in value **/
	prereq_ext_community_set_map := map[string]interface{}{"EXTENDED_COMMUNITY_SET": map[string]interface{}{"community12": map[string]interface{}{"community_member@": "2[0-9]:3[0-9]5,1[0-9]:2[0-9]5"}}}
	expected_ext_community_set_map := map[string]interface{}{"EXTENDED_COMMUNITY_SET": map[string]interface{}{"community12": map[string]interface{}{"community_member@": "1[0-9]:2[0-9]5"}}}
	loadConfigDB(rclient, prereq_ext_community_set_map)
	url = "/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/ext-community-sets/ext-community-set[ext-community-set-name=community12]/config/ext-community-member[ext-community-member=REGEX:2[0-9\\]:3[0-9\\]5]"
	t.Run("Delete on leaf-list instance with regex pattern in value.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete on leaf-list instance with regex pattern in value.", verifyDbResult(rclient, "EXTENDED_COMMUNITY_SET|community12", expected_ext_community_set_map, false))
	unloadConfigDB(rclient, prereq_ext_community_set_map)
	/*********************/

	fmt.Println("+++++++++++++ Done!!! Performing Leaf-list Deletion OC Yang Cases ++++++++++++")
}

func Test_LeafList_FieldXfmr_OCYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list FieldXfmr OC Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var expected_map map[string]interface{}
	var url, url_body_json, expected_get_json string

	/** FieldXfmr getting called on leaf-list Create**/
	prereq_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	expected_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	unloadConfigDB(rclient, prereq_map)
	url = "/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets"
	url_body_json = "{ \"openconfig-bgp-policy:community-sets\": { \"community-set\": [ { \"community-set-name\": \"test1\", \"config\": { \"community-set-name\": \"test1\", \"community-member\": [ \"1:1\" ], \"match-set-options\": \"ANY\" } } ] }}"
	t.Run("FieldXfmr leaf-list create.", processSetRequest(url, url_body_json, "POST", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify FieldXfmr leaf-list create.", verifyDbResult(rclient, "COMMUNITY_SET|test1", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** FieldXfmr getting called on leaf-list Update**/
	prereq_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1,2:2",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	expected_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1,2:2,3:3",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets"
	url_body_json = "{ \"openconfig-bgp-policy:community-sets\": { \"community-set\": [ { \"community-set-name\": \"test1\", \"config\": { \"community-set-name\": \"test1\", \"community-member\": [ \"1:1\",\"3:3\",\"2:2\" ], \"match-set-options\": \"ANY\" } } ] }}"
	t.Run("FieldXfmr leaf-list update.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify FieldXfmr leaf-list update.", verifyDbResult(rclient, "COMMUNITY_SET|test1", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** FieldXfmr getting called on leaf-list Replace**/
	prereq_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1,4:4",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	expected_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1,3:3,2:2",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets"
	url_body_json = "{ \"openconfig-bgp-policy:community-sets\": { \"community-set\": [ { \"community-set-name\": \"test1\", \"config\": { \"community-set-name\": \"test1\", \"community-member\": [ \"1:1\",\"3:3\",\"2:2\" ], \"match-set-options\": \"ANY\" } } ] }}"
	t.Run("FieldXfmr leaf-list replace.", processSetRequest(url, url_body_json, "PUT", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify FieldXfmr leaf-list replace.", verifyDbResult(rclient, "COMMUNITY_SET|test1", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** FieldXfmr getting called on leaf-list Delete**/
	prereq_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1,2:2,3:3",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	expected_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1,3:3",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set[community-set-name=test1]/config/community-member[community-member=2:2]"
	t.Run("FieldXfmr leaf-list delete.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify FieldXfmr leaf-list delete.", verifyDbResult(rclient, "COMMUNITY_SET|test1", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** FieldXfmr getting called on leaf-list get**/
	prereq_map = map[string]interface{}{"COMMUNITY_SET": map[string]interface{}{"test1": map[string]interface{}{
		"community_member@": "1:1",
		"set_type":          "STANDARD",
		"match_action":      "ANY"}}}
	expected_get_json = "{\"openconfig-bgp-policy:community-member\":[\"1:1\"]}"
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/community-sets/community-set[community-set-name=test1]/config/community-member"
	t.Run("FieldXfmr leaf-list get.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	fmt.Println("\n\n+++++++++++++ Done Performing Leaf-list FieldXfmr OC Yang Cases ++++++++++++")
}

func Test_LeafList_Get_OCYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list Get OC Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var url, expected_get_json string

	/** empty-string leaf-list get**/
	prereq_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"include@": ""}}}
	expected_get_json = "{\"ietf-snmp:include\":[\"\"]}"
	loadConfigDB(rclient, prereq_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	t.Run("Empty string leaf-list in DB get.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** leaf-list get when leaf-list doesn't exist in DB(vliad field in bot yangs)**/
	prereq_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	expected_get_json = "{}"
	loadConfigDB(rclient, prereq_map)
	url = "/ietf-snmp:snmp/vacm/view[name=TestVacmView1]/include"
	t.Run("Get leaf-list not there in DB.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** get on leaf-list instance with regex pattern in value**/
	prereq_ext_community_set_map := map[string]interface{}{"EXTENDED_COMMUNITY_SET": map[string]interface{}{"community12": map[string]interface{}{"community_member@": "2[0-9]:3[0-9]5"}}}
	expected_get_json = "{\"openconfig-bgp-policy:ext-community-member\":[\"REGEX:2[0-9]:3[0-9]5\"]}"
	loadConfigDB(rclient, prereq_ext_community_set_map)
	url = "/openconfig-routing-policy:routing-policy/defined-sets/openconfig-bgp-policy:bgp-defined-sets/ext-community-sets/ext-community-set[ext-community-set-name=community12]/config/ext-community-member[ext-community-member=REGEX:2[0-9\\]:3[0-9\\]5]"
	t.Run("Get on leaf-list instance with regex pattern in value.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_ext_community_set_map)
	/*********************/

	fmt.Println("\n\n+++++++++++++ Done Performing Leaf-list Get OC Yang Cases ++++++++++++")
}

func Test_LeafList_SubtreeXfmr_OCYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list Subtree Xfmr OC Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var url, url_body_json /*, expected_get_json*/ string

	// Get on leaf-list having parent subtree(verify if duplication of elements occur)
	prereq_map = map[string]interface{}{"VLAN": map[string]interface{}{"Vlan5": map[string]interface{}{
		"vlanid":   "5",
		"members@": "Ethernet32"}},
		"VLAN_MEMBER": map[string]interface{}{"Vlan5|Ethernet32": map[string]interface{}{
			"tagging_mode": "tagged"}}}
	prereq_map_port := map[string]interface{}{"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{
		"alias": "fortyGigE0/32",
		"lanes": "13,14,15,16"}}}
	prepareDb()
	time.Sleep(6 * time.Second)
	unloadConfigDB(rclient, prereq_map)
	loadConfigDB(rclient, prereq_map_port)
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans"
	expected_get_json := "{\"openconfig-vlan:trunk-vlans\":[5]}"
	t.Run("Get leaf-list with parent-subtree.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)

	// SubtreeXfmr getting called on leaf-list Update(create on uri ending with leaf-list not allowed in restconf)
	prereq_cfg_exist_map := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan5": map[string]interface{}{
		"admin_status": "up",
		"vlanid":       "5"}},
		"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{
			"alias": "fortyGigE0/32",
			"lanes": "13,14,15,16"}}}
	prereq_cfg_not_exist_map := map[string]interface{}{"INTERFACE": map[string]interface{}{"Ethernet32": map[string]interface{}{
		"NULL": "NULL"}}}
	expected_map_vlan := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan5": map[string]interface{}{
		"vlanid":       "5",
		"admin_status": "up",
		"members@":     "Ethernet32"}}}
	expected_map_vlanmember := map[string]interface{}{"VLAN_MEMBER": map[string]interface{}{"Vlan5|Ethernet32": map[string]interface{}{"tagging_mode": "tagged"}}}

	prepareDb()
	time.Sleep(6 * time.Second)

	loadConfigDB(rclient, prereq_cfg_exist_map)
	unloadConfigDB(rclient, prereq_cfg_not_exist_map)
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans"
	url_body_json = "{  \"openconfig-vlan:trunk-vlans\": [5]}"
	t.Run("SubtreeXfmr leaf-list update/create.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify SubtreeXfmr leaf-list update/create - VLAN table.", verifyDbResult(rclient, "VLAN|Vlan5", expected_map_vlan, false))
	t.Run("Verify SubtreeXfmr leaf-list update/create - VLAN_MEMBER table.", verifyDbResult(rclient, "VLAN_MEMBER|Vlan5|Ethernet32", expected_map_vlanmember, false))
	unloadConfigDB(rclient, expected_map_vlan)
	unloadConfigDB(rclient, expected_map_vlanmember)

	// SubtreeXfmr getting called for an item delete in leaf-list
	prereq_map = map[string]interface{}{"VLAN": map[string]interface{}{"Vlan5": map[string]interface{}{
		"vlanid":   "5",
		"members@": "Ethernet32"},
		"Vlan10": map[string]interface{}{
			"vlanid":   "10",
			"members@": "Ethernet32"}},
		"VLAN_MEMBER": map[string]interface{}{"Vlan5|Ethernet32": map[string]interface{}{
			"tagging_mode": "tagged"},
			"Vlan10|Ethernet32": map[string]interface{}{
				"tagging_mode": "tagged"}},
		"PORT": map[string]interface{}{"Ethernet32": map[string]interface{}{
			"alias": "fortyGigE0/32",
			"lanes": "13,14,15,16"}}}
	expected_map_vlan5 := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan5": map[string]interface{}{
		"vlanid":   "5",
		"members@": "Ethernet32"}}}
	expected_map_vlanmember5 := map[string]interface{}{"VLAN_MEMBER": map[string]interface{}{"Vlan5|Ethernet32": map[string]interface{}{"tagging_mode": "tagged"}}}

	expected_map_vlan10 := map[string]interface{}{"VLAN": map[string]interface{}{"Vlan10": map[string]interface{}{
		"vlanid": "10"}}}
	expected_map_vlanmember10 := map[string]interface{}{"VLAN_MEMBER": map[string]interface{}{"Vlan10|Ethernet32": map[string]interface{}{"tagging_mode": "tagged"}}}

	prepareDb()
	time.Sleep(6 * time.Second)
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans[trunk-vlans=10]"
	t.Run("SubtreeXfmr leaf-list delete an item.", processDeleteRequest(url, false, nil))
	time.Sleep(2 * time.Second)
	t.Run("Verify SubtreeXfmr leaf-list delete an item - VLAN|Vlan5", verifyDbResult(rclient, "VLAN|Vlan5", expected_map_vlan5, false))
	t.Run("Verify SubtreeXfmr leaf-list delete an item - VLAN_MEMBER|Vlan5|Ethernet32", verifyDbResult(rclient, "VLAN_MEMBER|Vlan5|Ethernet32", expected_map_vlanmember5, false))
	t.Run("Verify SubtreeXfmr leaf-list delete an item - VLAN|Vlan10", verifyDbResult(rclient, "VLAN|Vlan10", expected_map_vlan10, false))
	unloadConfigDB(rclient, expected_map_vlan5)
	unloadConfigDB(rclient, expected_map_vlanmember5)
	unloadConfigDB(rclient, expected_map_vlan10)
	unloadConfigDB(rclient, expected_map_vlanmember10)

	// SubtreeXfmr getting called leaf-list replace
	prereq_map = map[string]interface{}{"VLAN": map[string]interface{}{"Vlan5": map[string]interface{}{
		"vlanid":   "5",
		"members@": "Ethernet32"},
		"Vlan10": map[string]interface{}{
			"vlanid": "10"}},
		"VLAN_MEMBER": map[string]interface{}{"Vlan5|Ethernet32": map[string]interface{}{
			"tagging_mode": "tagged"}}}
	expected_map_vlan10 = map[string]interface{}{"VLAN": map[string]interface{}{"Vlan10": map[string]interface{}{
		"members@": "Ethernet32",
		"vlanid":   "10"}}}
	expected_map_vlanmember10 = map[string]interface{}{"VLAN_MEMBER": map[string]interface{}{"Vlan10|Ethernet32": map[string]interface{}{"tagging_mode": "tagged"}}}

	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-interfaces:interfaces/interface[name=Ethernet32]/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans"
	url_body_json = "{  \"openconfig-vlan:trunk-vlans\": [10]}"
	t.Run("SubtreeXfmr leaf-list replace.", processSetRequest(url, url_body_json, "PUT", false, nil))
	t.Run("Verify SubtreeXfmr leaf-list replace an item - VLAN|Vlan5", verifyDbResult(rclient, "VLAN|Vlan5", expected_map_vlan5, false))
	t.Run("Verify SubtreeXfmr leaf-list replace an item - VLAN_MEMBER|Vlan5|Ethernet32", verifyDbResult(rclient, "VLAN_MEMBER|Vlan5|Ethernet32", expected_map_vlanmember5, false))
	t.Run("Verify SubtreeXfmr leaf-list replace an item - VLAN|Vlan10", verifyDbResult(rclient, "VLAN|Vlan10", expected_map_vlan10, false))
	t.Run("Verify SubtreeXfmr leaf-list replace an item - VLAN_MEMBER|Vlan10|Ethernet32", verifyDbResult(rclient, "VLAN_MEMBER|Vlan10|Ethernet32", expected_map_vlanmember10, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)
	unloadConfigDB(rclient, expected_map_vlan10)
	unloadConfigDB(rclient, expected_map_vlanmember10)
	fmt.Println("\n\n+++++++++++++ Done Performing Leaf-list Subtree Xfmr OC Yang Cases ++++++++++++")
}

func Test_LeafList_DataTypeConversion_OCYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list Data-Type Conversion getting called OC Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var expected_map map[string]interface{}
	var url, url_body_json, expected_get_json string

	// Data-type conversion getting called on leaf-list Create
	prereq_map = map[string]interface{}{"BGP_GLOBALS": map[string]interface{}{"default": map[string]interface{}{
		"NULL": "NULL"}},
		"VRF": map[string]interface{}{"default": map[string]interface{}{
			"NULL": "NULL"}}}
	expected_map = map[string]interface{}{"BGP_GLOBALS": map[string]interface{}{"default": map[string]interface{}{
		"NULL":          "NULL",
		"confed_peers@": "4294"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/confederation/config"
	url_body_json = "{\"openconfig-network-instance:member-as\":[4294]}"
	t.Run("Data-type conversion create.", processSetRequest(url, url_body_json, "POST", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Data-type conversion create.", verifyDbResult(rclient, "BGP_GLOBALS|default", expected_map, false))
	unloadConfigDB(rclient, prereq_map)

	// Data-type conversion getting called on leaf-list Update
	prereq_map = map[string]interface{}{"BGP_GLOBALS": map[string]interface{}{"default": map[string]interface{}{
		"confed_peers@": "4293"}},
		"VRF": map[string]interface{}{"default": map[string]interface{}{
			"NULL": "NULL"}}}
	expected_map = map[string]interface{}{"BGP_GLOBALS": map[string]interface{}{"default": map[string]interface{}{
		"confed_peers@": "4293,1,4294"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/confederation/config/member-as"
	url_body_json = "{\"openconfig-network-instance:member-as\":[4293,1,4294]}"
	t.Run("Data-type conversion update.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Data-type conversion update.", verifyDbResult(rclient, "BGP_GLOBALS|default", expected_map, false))
	unloadConfigDB(rclient, prereq_map)

	// Data-type conversion getting called on leaf-list get
	prereq_map = map[string]interface{}{"BGP_GLOBALS": map[string]interface{}{"default": map[string]interface{}{
		"confed_peers@": "4294967294"}},
		"VRF": map[string]interface{}{"default": map[string]interface{}{
			"NULL": "NULL"}}}
	expected_get_json = "{\"openconfig-network-instance:member-as\":[4294967294]}"
	loadConfigDB(rclient, prereq_map)
	url = "/openconfig-network-instance:network-instances/network-instance[name=default]/protocols/protocol[identifier=BGP][name=bgp]/bgp/global/confederation/config/member-as"
	t.Run("Data-type conversion leaf-list get.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)

	fmt.Println("\n\n+++++++++++++ Done Performing Leaf-list Data-Type Conversion getting called OC Yang Cases ++++++++++++")
}

func Test_LeafList_DataTypeConversion_SonicYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list Data-Type Conversion getting called Sonic Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var expected_map map[string]interface{}
	var url, url_body_json, expected_get_json string

	// Data-type conversion getting called on leaf-list create
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"stage": "INGRESS",
		"type":  "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	unloadConfigDB(rclient, prereq_map)
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]"
	url_body_json = "{\"sonic-acl:stage\":\"INGRESS\",\"sonic-acl:type\":\"L3\",\"sonic-acl:ports\":[\"Ethernet0\"]}"
	t.Run("Data-type conversion create.", processSetRequest(url, url_body_json, "POST", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Data-type conversion create.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)

	// Data-type conversion getting called on leaf-list Update
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet8",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet8,Ethernet124",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	unloadConfigDB(rclient, prereq_map)
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	url_body_json = "{\"sonic-acl:ports\":[\"Ethernet0\",\"Ethernet124\",\"Ethernet8\"]}"
	t.Run("Data-type conversion update.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Data-type conversion update.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)

	// Data-type conversion getting called on leaf-list delete
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet8,Ethernet124",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet124",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports[ports=Ethernet8]"
	t.Run("Data-type conversion delete.", processDeleteRequest(url, false))
	time.Sleep(1 * time.Second)
	t.Run("Verify Data-type conversion delete.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)

	// Data-type conversion getting called on leaf-list get
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet8",
		"stage":  "INGRESS",
		"type":   "L3"}}}

	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	expected_get_json = "{\"sonic-acl:ports\":[\"Ethernet8\"]}"
	loadConfigDB(rclient, prereq_map)
	t.Run("FieldXfmr leaf-list get.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)

	fmt.Println("\n\n+++++++++++++ Done Performing Leaf-list Data-Type Conversion getting called Sonic Yang Cases ++++++++++++")
}

func Test_LeafList_CRU_SonicYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list CRU Sonic Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var expected_map map[string]interface{}
	var prereq_snmp_vacm_view_map map[string]interface{}
	var expected_snmp_vacm_view_map map[string]interface{}
	var url, url_body_json string

	// sonic yang leaf-list create
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	unloadConfigDB(rclient, expected_snmp_vacm_view_map)
	url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW"
	url_body_json = "{\"sonic-snmp:SNMP_SERVER_VIEW_LIST\":[{\"name\":\"TestVacmView1\",\"exclude\": [\"1.2.3.4.*,1.4.6.*\"]}]}"
	t.Run("leaf-list create.", processSetRequest(url, url_body_json, "POST", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify leaf-list create.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, expected_snmp_vacm_view_map)

	//  sonic yang leaf-list Update/merge
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet8",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet8,Ethernet124",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	url_body_json = "{\"sonic-acl:ports\":[\"Ethernet0\",\"Ethernet124\",\"Ethernet8\"]}"
	t.Run("leaf-list update/merge.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify leaf-list update/merge.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)

	// Update leaf-list with empty-string , on an empty-string leaf-list in DB
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW/SNMP_SERVER_VIEW_LIST[name=TestVacmView1]/include"
	url_body_json = "{\"sonic-snmp:include\": [\"\"]}"
	t.Run("Update leaf-list with empty-string , on an empty-string leaf-list in DB.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Update leaf-list with empty-string , on an empty-string leaf-list in DB.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_map)

	// Update leaf-list with no element , on an empty-string leaf-list in DB
	prereq_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	expected_snmp_vacm_view_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW/SNMP_SERVER_VIEW_LIST[name=TestVacmView1]/include"
	url_body_json = "{\"sonic-snmp:include\": [\"\"]}"
	t.Run("Update leaf-list with no element, on an empty-string leaf-list in DB.", processSetRequest(url, url_body_json, "PATCH", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("verify Update leaf-list with no element , on an empty-string leaf-list in DB.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_map)

	//  sonic yang leaf-list Replace/swap
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet32,Ethernet8",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet124,Ethernet8",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	url_body_json = "{\"sonic-acl:ports\":[\"Ethernet0\",\"Ethernet124\",\"Ethernet8\"]}"
	t.Run("leaf-list replace/swap.", processSetRequest(url, url_body_json, "PUT", false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify leaf-list replace/swap.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)

	fmt.Println("\n\n+++++++++++++ Done Performing Leaf-list CRU Sonic Yang Cases ++++++++++++")
}

func Test_LeafList_Delete_SonicYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list Deletion Sonic Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var expected_map map[string]interface{}
	var url string

	/** delete specific item from leaf-list **/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet8,Ethernet124",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet0,Ethernet124",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports[ports=Ethernet8]"
	t.Run("Delete an item in leaf-list.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Delete an item in leaf-list.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/***********************************/

	/** Delete specific item from leaf-list, when leaf-list does not exist in DB **/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"type": "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"type": "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports[ports=Ethernet8]"

	t.Run("Delete an item when leaf-list doesn't exist in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item when leaf-list doesn't exist in DB.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** delete an item from leaf-list which happens to be the only element in leaf-lis in DB. **/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet8",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"stage": "INGRESS",
		"type":  "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports[ports=Ethernet8]"
	t.Run("Delete an item which is the only one in leaf-list.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item which is the only one in leaf-list.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** delete entire leaf-list. **/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "Ethernet8",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"stage": "INGRESS",
		"type":  "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	t.Run("Delete entire leaf-list.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Delete entire leaf-list.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** delete entire leaf-list, when leaf-list doesn't exist in DB. **/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"type": "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"type": "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	t.Run("Delete leaf-list not there in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Delete leaf-list not there in DB.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*************************

	/** delete an item from leaf-list when leaf-list is empty string in DB. **/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	expected_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports[ports=Ethernet8]"
	t.Run("Delete an item when leaf-list is empty string in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an when leaf-list is empty string in DB.", verifyDbResult(rclient, "ACL_TABLE|MyACL1_ACL_IPV4", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** Delete entire leaf-list which is an empty-string leaf-list in DB **/
	prereq_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*",
		"include@": ""}}}
	expected_map = map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{
		"exclude@": "1.2.3.4.*,1.4.6.*"}}}
	loadConfigDB(rclient, prereq_map)
	url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW/SNMP_SERVER_VIEW_LIST[name=TestVacmView1]/include"
	t.Run("Delete an entire leaf-list which is empty string in DB.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an entire leaf-list which is empty string in DB.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_map, false))
	unloadConfigDB(rclient, prereq_map)
	/*************************/

	/** delete specific item from leaf-list .Leaflist having / in the field value **/
	prereq_snmp_vacm_view_map := map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{"include@": "test1/1,test2/2"}}}
	expected_snmp_vacm_view_map := map[string]interface{}{"SNMP_SERVER_VIEW": map[string]interface{}{"TestVacmView1": map[string]interface{}{"include@": "test2/2"}}}
	loadConfigDB(rclient, prereq_snmp_vacm_view_map)
	url = "/sonic-snmp:sonic-snmp/SNMP_SERVER_VIEW/SNMP_SERVER_VIEW_LIST[name=TestVacmView1]/include[include=test1/1]"
	t.Run("Delete an item in leaf-list having / in field value.", processDeleteRequest(url, false, nil))
	time.Sleep(1 * time.Second)
	t.Run("Verify Delete an item in leaf-list having / in field value.", verifyDbResult(rclient, "SNMP_SERVER_VIEW|TestVacmView1", expected_snmp_vacm_view_map, false))
	unloadConfigDB(rclient, prereq_snmp_vacm_view_map)
	/*********************/

	fmt.Println("+++++++++++++ Done!!! Performing Leaf-list Deletion Sonic Yang Cases ++++++++++++")
}

func Test_LeafList_Get_SonicYang(t *testing.T) {
	fmt.Println("\n\n+++++++++++++ Performing Leaf-list Get Sonic Yang Cases ++++++++++++")
	var prereq_map map[string]interface{}
	var url, expected_get_json string

	/** leaf-list get when leaf-list doesn't exist in DB(valid field in yang)**/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"stage": "INGRESS",
		"type":  "L3"}}}

	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	expected_get_json = "{}"
	loadConfigDB(rclient, prereq_map)
	t.Run("Get leaf-list not there in DB.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	/** empty-string leaf-list get**/
	prereq_map = map[string]interface{}{"ACL_TABLE": map[string]interface{}{"MyACL1_ACL_IPV4": map[string]interface{}{
		"ports@": "",
		"stage":  "INGRESS",
		"type":   "L3"}}}
	url = "/sonic-acl:sonic-acl/ACL_TABLE/ACL_TABLE_LIST[aclname=MyACL1_ACL_IPV4]/ports"
	expected_get_json = "{\"sonic-acl:ports\":[\"\"]}"
	loadConfigDB(rclient, prereq_map)
	t.Run("Get leaf-list empty string in DB.", processGetRequest(url, expected_get_json, false))
	time.Sleep(1 * time.Second)
	unloadConfigDB(rclient, prereq_map)
	/*********************/

	fmt.Println("\n\n+++++++++++++ Done Performing Leaf-list Get Sonic Yang Cases ++++++++++++")
}
