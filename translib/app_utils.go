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

package translib

import (
	"reflect"
	"strings"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	"github.com/Azure/sonic-mgmt-common/translib/path"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"

	log "github.com/golang/glog"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func getYangPathFromUri(uri string) (string, error) {
	var path *gnmi.Path
	var err error

	path, err = ygot.StringToPath(uri, ygot.StructuredPath, ygot.StringSlicePath)
	if err != nil {
		log.Errorf("Error in uri to path conversion: %v", err)
		return "", err
	}

	yangPath, yperr := ygot.PathToSchemaPath(path)
	if yperr != nil {
		log.Errorf("Error in Gnmi path to Yang path conversion: %v", yperr)
		return "", yperr
	}

	return yangPath, err
}

func getYangPathFromYgotStruct(s ygot.GoStruct, yangPathPrefix string, appModuleName string) string {
	tn := reflect.TypeOf(s).Elem().Name()
	schema, ok := ocbinds.SchemaTree[tn]
	if !ok {
		log.Errorf("could not find schema for type %s", tn)
		return ""
	} else if schema != nil {
		yPath := schema.Path()
		//yPath = strings.Replace(yPath, "/device/acl", "/openconfig-acl:acl", 1)
		yPath = strings.Replace(yPath, yangPathPrefix, appModuleName, 1)
		return yPath
	}
	return ""
}

func generateGetResponsePayload(targetUri string, deviceObj *ocbinds.Device, ygotTarget *interface{}, fmtType TranslibFmtType) ([]byte, *ygot.ValidatedGoStruct, error) {
	var err error
	var payload []byte

	if len(targetUri) == 0 {
		return payload, nil, tlerr.InvalidArgs("GetResponse failed as target Uri is not valid")
	}
	path, err := ygot.StringToPath(targetUri, ygot.StructuredPath, ygot.StringSlicePath)
	if err != nil {
		return payload, nil, tlerr.InvalidArgs("URI to path conversion failed: %v", err)
	}

	// Get current node (corresponds to ygotTarget) and its parent node
	var pathList []*gnmi.PathElem = path.Elem
	parentPath := &gnmi.Path{}
	for i := 0; i < len(pathList); i++ {
		if log.V(3) {
			log.Infof("pathList[%d]: %s\n", i, pathList[i])
		}
		pathSlice := strings.Split(pathList[i].Name, ":")
		pathList[i].Name = pathSlice[len(pathSlice)-1]
		if i < (len(pathList) - 1) {
			parentPath.Elem = append(parentPath.Elem, pathList[i])
		}
	}
	parentNodeList, err := ytypes.GetNode(ygSchema.RootSchema(), deviceObj, parentPath)
	if err != nil {
		return payload, nil, err
	}
	if len(parentNodeList) == 0 {
		return payload, nil, tlerr.InvalidArgs("Invalid URI: %s", targetUri)
	}
	parentNode := parentNodeList[0].Data

	currentNodeList, ygerr := ytypes.GetNode(ygSchema.RootSchema(), deviceObj, path, &(ytypes.GetPartialKeyMatch{}))
	if ygerr != nil {
		log.Errorf("Error from ytypes.GetNode: %v", ygerr)
		if status.Convert(ygerr).Code() == codes.NotFound {
			return payload, nil, tlerr.NotFound("Resource not found")
		} else {
			return payload, nil, ygerr
		}
	}
	if len(currentNodeList) == 0 {
		return payload, nil, tlerr.NotFound("Resource not found")
	}
	//currentNode := currentNodeList[0].Data
	currentNodeYangName := currentNodeList[0].Schema.Name

	// Create empty clone of parent node
	parentNodeClone := reflect.New(reflect.TypeOf(parentNode).Elem())
	var parentCloneObj ygot.ValidatedGoStruct
	var ok bool
	if parentCloneObj, ok = (parentNodeClone.Interface()).(ygot.ValidatedGoStruct); ok {
		ygot.BuildEmptyTree(parentCloneObj)
		pcType := reflect.TypeOf(parentCloneObj).Elem()
		pcValue := reflect.ValueOf(parentCloneObj).Elem()

		var currentNodeOCFieldName string
		for i := 0; i < pcValue.NumField(); i++ {
			fld := pcValue.Field(i)
			fldType := pcType.Field(i)
			if fldType.Tag.Get("path") == currentNodeYangName {
				currentNodeOCFieldName = fldType.Name
				// Take value from original parent and set in parent clone
				valueFromParent := reflect.ValueOf(parentNode).Elem().FieldByName(currentNodeOCFieldName)
				fld.Set(valueFromParent)
				break
			}
		}
		if log.V(3) {
			log.Infof("Target yang name: %s  OC Field name: %s\n", currentNodeYangName, currentNodeOCFieldName)
		}
	}
	if fmtType == TRANSLIB_FMT_YGOT {
		return payload, &parentCloneObj, nil
	}

	payload, err = dumpIetfJson(parentCloneObj, true)

	return payload, nil, err
}

func getTargetNodeYangSchema(targetUri string, deviceObj *ocbinds.Device) (*yang.Entry, error) {
	if len(targetUri) == 0 {
		return nil, tlerr.InvalidArgs("GetResponse failed as target Uri is not valid")
	}
	path, err := ygot.StringToPath(targetUri, ygot.StructuredPath, ygot.StringSlicePath)
	if err != nil {
		return nil, tlerr.InvalidArgs("URI to path conversion failed: %v", err)
	}
	// Get current node (corresponds to ygotTarget)
	var pathList []*gnmi.PathElem = path.Elem
	for i := 0; i < len(pathList); i++ {
		if log.V(3) {
			log.Infof("pathList[%d]: %s\n", i, pathList[i])
		}
		pathSlice := strings.Split(pathList[i].Name, ":")
		pathList[i].Name = pathSlice[len(pathSlice)-1]
	}
	targetNodeList, err := ytypes.GetNode(ygSchema.RootSchema(), deviceObj, path, &(ytypes.GetPartialKeyMatch{}))
	if err != nil {
		return nil, tlerr.InvalidArgs("Getting node information failed: %v", err)
	}
	if len(targetNodeList) == 0 {
		return nil, tlerr.NotFound("Resource not found")
	}
	targetNodeSchema := targetNodeList[0].Schema
	//targetNode := targetNodeList[0].Data
	if log.V(3) {
		log.Infof("Target node yang name: %s\n", targetNodeSchema.Name)
	}
	return targetNodeSchema, nil
}

func dumpIetfJson(s ygot.ValidatedGoStruct, skipValidation bool) ([]byte, error) {
	jsonStr, err := ygot.EmitJSON(s, &ygot.EmitJSONConfig{
		Format:         ygot.RFC7951,
		SkipValidation: skipValidation,
		RFC7951Config: &ygot.RFC7951JSONConfig{
			AppendModuleName: true,
		},
	})
	return []byte(jsonStr), err
}

func contains(sl []string, str string) bool {
	for _, v := range sl {
		if v == str {
			return true
		}
	}
	return false
}

func removeElement(sl []string, str string) []string {
	for i := 0; i < len(sl); i++ {
		if sl[i] == str {
			sl = append(sl[:i], sl[i+1:]...)
			i--
			break
		}
	}
	return sl
}

// isNotFoundError return true if the error is a 'not found' error
func isNotFoundError(err error) bool {
	switch err.(type) {
	case tlerr.TranslibRedisClientEntryNotExist, tlerr.NotFoundError:
		return true
	default:
		return false
	}
}

// asKey cretaes a db.Key from given key components
func asKey(parts ...string) db.Key {
	return db.Key{Comp: parts}
}

func createEmptyDbValue(fieldName string) db.Value {
	return db.Value{Field: map[string]string{fieldName: ""}}
}

/* Check if targetUriPath is child (subtree) of nodePath
The return value can be used to decide if subtrees needs
to visited to fill the data or not.
*/
func isSubtreeRequest(targetUriPath string, nodePath string) bool {
	return strings.HasPrefix(targetUriPath, nodePath)
}

/* Unique elements */
func uniqueElements(elems []string) []string {
	temp := make(map[string]bool)
	for _, elem := range elems {
		temp[elem] = true
	}

	i := 0
	ret := make([]string, len(temp))
	for key := range temp {
		ret[i] = key
		i++
	}

	return ret
}

func indexOf(elems []string, match string) (int, bool) {
	for idx, val := range elems {
		if val == match {
			return idx, true
		}
	}

	return -1, false
}

func indexOfIfHasPrefix(elems []string, match string) (int, bool) {
	for idx, val := range elems {
		if strings.HasPrefix(val, match) {
			return idx, true
		}
	}

	return -1, false
}

func removeElementIfHasPrefix(sl []string, str string) []string {
	for i := 0; i < len(sl); i++ {
		if strings.HasPrefix(sl[i], str) {
			sl = append(sl[:i], sl[i+1:]...)
			i--
			break
		}
	}

	return sl
}

/*************************************************/

// notificationInfoBuilder provides utility APIs to build notificationAppInfo
// data.
type notificationInfoBuilder struct {
	pathInfo *PathInfo
	yangMap  yangMapTree

	primaryInfos []*notificationAppInfo
	subtreeInfos []*notificationAppInfo

	requestPath *gnmi.Path
	currentPath *gnmi.Path // Path cone to be used in notificationAppInfo
	currentIndx int        // Current yangMap node's element in currentPath
	fieldPrefix string     // Yang prefix to be used in Field()
	fieldFilter string     // Field name filter
	treeDepth   int        // depth of current call tree wrt requestPath
	currentInfo *notificationAppInfo
}

type yangMapFunc func(nb *notificationInfoBuilder) error

type yangMapTree struct {
	mapFunc yangMapFunc
	subtree map[string]*yangMapTree
}

func (nb *notificationInfoBuilder) Build() (*translateSubResponse, error) {
	log.Infof("translateSubscribe( %s )", nb.pathInfo.Path)

	var err error
	nb.requestPath, err = ygot.StringToStructuredPath(nb.pathInfo.Path)
	if err != nil {
		log.Warningf("Invalid subscribe path: \"%s\"; err=%v", nb.pathInfo.Path, err)
		return nil, tlerr.InvalidArgs("Invalid subscribe path")
	}

	// Find matching yangMapTree node
	index, ymap := nb.yangMap.match(nb.requestPath, 1)

	log.Infof("Path match index %d", index)
	if index < 0 {
		return nil, tlerr.InvalidArgsErr("invalid-path", nb.pathInfo.Path, "Invalid path")
	}

	nb.currentIndx = index
	nb.currentPath = nb.requestPath
	if err := ymap.collect(nb); err != nil {
		log.Warningf("translateSubscribe failed for path: \"%s\"; err=%s", nb.pathInfo.Path, err)
		return nil, tlerr.New("Internal error")
	}

	log.Infof("Found %d primary and %d subtree notificationAppInfo",
		len(nb.primaryInfos), len(nb.subtreeInfos))

	return &translateSubResponse{
		ntfAppInfoTrgt:      nb.primaryInfos,
		ntfAppInfoTrgtChlds: nb.subtreeInfos,
	}, nil
}

func (nb *notificationInfoBuilder) New() *notificationInfoBuilder {
	nb.currentInfo = &notificationAppInfo{
		path:                nb.currentPath,
		dbno:                db.MaxDB,
		isOnChangeSupported: true,
		pType:               OnChange,
	}
	if nb.treeDepth == 0 {
		nb.primaryInfos = append(nb.primaryInfos, nb.currentInfo)
	} else {
		nb.subtreeInfos = append(nb.subtreeInfos, nb.currentInfo)
	}
	return nb
}

func (nb *notificationInfoBuilder) PathKey(name, value string) *notificationInfoBuilder {
	path.SetKeyAt(nb.currentPath, nb.currentIndx, name, value)
	return nb
}

func (nb *notificationInfoBuilder) Table(dbno db.DBNum, tableName string) *notificationInfoBuilder {
	nb.currentInfo.dbno = dbno
	nb.currentInfo.table = &db.TableSpec{Name: tableName}
	return nb
}

func (nb *notificationInfoBuilder) Key(keyComp ...string) *notificationInfoBuilder {
	nb.currentInfo.key = &db.Key{Comp: keyComp}
	return nb
}

func (nb *notificationInfoBuilder) Field(yangAttr, dbField string) *notificationInfoBuilder {
	// Ignore unwanted fields
	if len(nb.fieldFilter) != 0 {
		if yangAttr != nb.fieldFilter {
			return nb
		}

		// When request path points to a leaf, we do not want the
		// yang leaf name in the fields map!!
		yangAttr = ""
	}

	isAdded := false
	for _, dbFldYgPath := range nb.currentInfo.dbFldYgPathInfoList {
		if dbFldYgPath.rltvPath == nb.fieldPrefix {
			dbFldYgPath.dbFldYgPathMap[dbField] = yangAttr
			isAdded = true
			break
		}
	}

	if !isAdded {
		dbFldInfo := dbFldYgPathInfo{nb.fieldPrefix, make(map[string]string)}
		dbFldInfo.dbFldYgPathMap[dbField] = yangAttr
		nb.currentInfo.dbFldYgPathInfoList = append(nb.currentInfo.dbFldYgPathInfoList, &dbFldInfo)
	}

	return nb
}

func (nb *notificationInfoBuilder) SetFieldPrefix(prefix string) bool {
	i := nb.currentIndx + 1
	n := path.Len(nb.currentPath)
	if i >= n {
		// Request does not contain any additional elements beyond
		// current path. Accept all sub containers & fields
		nb.fieldPrefix = prefix
		nb.fieldFilter = ""
		return true
	}

	pparts := strings.Split(prefix, "/")
	for j, p := range pparts {
		if p != nb.currentPath.Elem[i].Name {
			return false
		}

		i++
		if i >= n {
			if j == len(pparts) { // exact match
				nb.fieldPrefix = ""
			} else { // partial match
				nb.fieldPrefix = strings.Join(pparts[j+1:], "/")
			}
			nb.fieldFilter = ""
			return true
		}
	}

	// Current path is still longer than given prefix. Must be
	// field name filter
	nb.fieldPrefix = ""
	nb.fieldFilter = nb.currentPath.Elem[i].Name
	return true
}

func (nb *notificationInfoBuilder) OnChange(flag bool) *notificationInfoBuilder {
	nb.currentInfo.isOnChangeSupported = flag
	return nb
}

func (nb *notificationInfoBuilder) Interval(secs int) *notificationInfoBuilder {
	nb.currentInfo.mInterval = secs
	return nb
}

func (nb *notificationInfoBuilder) Preferred(mode NotificationType) *notificationInfoBuilder {
	nb.currentInfo.pType = mode
	return nb
}

func (y *yangMapTree) match(reqPath *gnmi.Path, index int) (int, *yangMapTree) {
	size := path.Len(reqPath)
	if len(y.subtree) == 0 || index >= size {
		return index - 1, y
	}

	next := reqPath.Elem[index].Name

	for segment, submap := range y.subtree {
		parts := strings.Split(segment, "/")
		if parts[0] != next {
			continue
		}

		// Reuse current handler func if subtree map is nil.
		if submap == nil {
			temp := yangMapTree{mapFunc: y.mapFunc}
			return temp.match(reqPath, index)
		}

		nparts := len(parts)
		if path.MergeElemsAt(reqPath, index, parts...) == nparts {
			return submap.match(reqPath, index+nparts)
		}
		break // no match
	}

	return -1, nil
}

func (y *yangMapTree) collect(nb *notificationInfoBuilder) error {
	// Reset previous states
	nb.fieldPrefix = ""
	nb.fieldFilter = ""
	bakupIndx := nb.currentIndx
	bakupPath := nb.currentPath
	bakupDepth := nb.treeDepth

	// Invoke yangMapFunc to collect notificationAppInfo
	if y.mapFunc != nil {
		if err := y.mapFunc(nb); err != nil {
			return err
		}

		nb.treeDepth++
	}

	// Recursively collect from subtree
	for subpath, subnode := range y.subtree {
		if subnode == nil {
			continue
		}

		parts := strings.Split(subpath, "/")
		nb.currentIndx = bakupIndx + len(parts)
		nb.currentPath = path.SubPath(bakupPath, 0, bakupIndx+1)
		path.AppendElems(nb.currentPath, parts...)

		if err := subnode.collect(nb); err != nil {
			return err
		}
	}

	nb.treeDepth = bakupDepth
	return nil
}

func wildcardMatch(v1, v2 string) bool {
	return v1 == v2 || v1 == "*"
}
