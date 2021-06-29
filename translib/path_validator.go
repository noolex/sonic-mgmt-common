////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2021 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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

	"fmt"

	"github.com/Azure/sonic-mgmt-common/translib/ocbinds"
	log "github.com/golang/glog"
	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/util"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
)

type pathValidator struct {
	gPath        *gnmi.Path
	rootObj      *ocbinds.Device
	sField       *reflect.StructField
	sValIntf     interface{}
	parentIntf   interface{}
	opts         []PathValidatorOpt
	parentSchema *yang.Entry
	err          error
}

// NewPathValidator returns the PathValidator struct to validate the gnmi path and also add the missing module
// prefix and key names and wild card values in the gnmi path based on the given PathValidatorOpt
func NewPathValidator(opts ...PathValidatorOpt) *pathValidator {
	return &pathValidator{rootObj: &(ocbinds.Device{}), opts: opts}
}

func (pv *pathValidator) init(gPath *gnmi.Path) {
	pv.gPath = gPath
	pv.sField = nil
	pv.sValIntf = pv.rootObj
	pv.parentIntf = pv.rootObj
	pv.parentSchema = nil
	pv.err = nil
}

// Validate the path and also add the module prefix / wild card keys in the gnmi path
// based on the given PathValidatorOpt while creating the path validator.
func (pv *pathValidator) Validate(gPath *gnmi.Path) error {
	log.Info("Validate: path: ", gPath.Elem)
	pv.init(gPath)
	if pv.err = pv.validatePath(); pv.err != nil {
		log.Error("Error in path validating the path: ", pv.err)
		return pv.err
	}
	return pv.err
}

func (pv *pathValidator) getYangSchema() (*yang.Entry, error) {
	sVal := reflect.ValueOf(pv.sValIntf)
	if sVal.Elem().Type().Kind() == reflect.Struct {
		objName := sVal.Elem().Type().Name()
		if log.V(5) {
			log.Info("getYangSchema: ygot object name: ", objName)
		}
		if ygSchema := ocbinds.SchemaTree[objName]; ygSchema == nil {
			log.Errorf("Error: ygot object name %v not found in the schema for the given path: %v", objName, pv.gPath)
			return ygSchema, fmt.Errorf("Invalid path %v", pv.gPath)
		} else {
			if log.V(5) {
				log.Infof("getYangSchema: found schema: %v for the field: %v", ygSchema.Name, *pv.sField)
			}
			return ygSchema, nil
		}
	} else {
		ygSchema, err := util.ChildSchema(pv.parentSchema, *pv.sField)
		if err != nil {
			return nil, err
		}
		if ygSchema == nil {
			return nil, fmt.Errorf("could not find schema for the field name %s", pv.sField.Name)
		}
		if log.V(5) {
			log.Infof("getYangSchema:ChildSchema - found schema: %v for the field: %v", ygSchema.Name, *pv.sField)
		}
		return ygSchema, nil
	}
}

func (pv *pathValidator) getStructField(nodeName string) *reflect.StructField {
	var sField *reflect.StructField
	sval := reflect.ValueOf(pv.sValIntf).Elem()
	stype := sval.Type()
	for i := 0; i < sval.NumField(); i++ {
		fType := stype.Field(i)
		if pathName, ok := fType.Tag.Lookup("path"); ok && pathName == nodeName {
			log.Infof("getStructField: found struct field: %v for the node name: %v ", fType, nodeName)
			sField = &fType
			break
		}
	}
	return sField
}

func (pv *pathValidator) getModuleName() string {
	modName, _ := pv.sField.Tag.Lookup("module")
	return modName
}

func (pv *pathValidator) validatePath() error {
	if log.V(5) {
		log.Info("validatePath: path: ", pv.gPath.Elem)
	}
	isApnndModPrefix := pv.hasAppendModulePrefixOption()
	isAddWcKey := pv.hasAddWildcardKeyOption()
	isIgnoreKey := pv.hasIgnoreKeyValidationOption()
	prevModName := ""

	for idx, pathElem := range pv.gPath.Elem {
		nodeName := pathElem.Name
		modName := ""
		names := strings.Split(pathElem.Name, ":")
		if len(names) > 1 {
			modName = names[0]
			nodeName = names[1]
			if log.V(5) {
				log.Infof("validatePath: modName %v, and node name %v in the given path", modName, nodeName)
			}
		}

		if sField := pv.getStructField(nodeName); sField == nil {
			log.Errorf("Node %v not found in the given gnmi path %v: ", pathElem.Name, pv.gPath)
			return fmt.Errorf("Node %v not found in the given gnmi path %v: ", pathElem.Name, pv.gPath)
		} else {
			pv.sField = sField
		}

		ygModName := pv.getModuleName()
		if len(ygModName) == 0 {
			log.Errorf("Module name not found for the node %v in the given gnmi path %v: ", pathElem.Name, pv.gPath)
			return fmt.Errorf("Module name not found for the node %v in the given gnmi path %v: ", pathElem.Name, pv.gPath)
		} else {
			if log.V(5) {
				log.Infof("validatePath: module name: %v found for the node %v: ", ygModName, pathElem.Name)
			}
		}

		if len(modName) > 0 {
			if ygModName != modName {
				log.Errorf("validatePath: Invalid yang module prefix in the path node %v: ", pathElem.Name)
				return fmt.Errorf("Invalid yang module prefix in the path node %v", pathElem.Name)
			}
		} else if isApnndModPrefix && (prevModName != ygModName || idx == 0) {
			log.Infof("validatePath: Appending the module prefix %v in the path node: %v", ygModName, pathElem.Name)
			pv.gPath.Elem[idx].Name = ygModName + ":" + pathElem.Name
			if log.V(5) {
				log.Info("validatePath: appeneded the module prefix name for the path node: ", pv.gPath.Elem[idx])
			}
		}

		pv.updateStructFieldVal()

		ygSchema, err := pv.getYangSchema()
		if err != nil {
			return fmt.Errorf("yang schema not found for the node %v in the given path; %v", pathElem.Name, pv.gPath)
		}

		if !isIgnoreKey {
			if ygSchema.IsList() {
				if len(pathElem.Key) > 0 {
					// validate the key names
					keysMap := make(map[string]bool)
					isWc := false
					for kn, kv := range pathElem.Key {
						keysMap[kn] = true
						if kv == "*" && !isWc {
							isWc = true
						}
					}
					if log.V(5) {
						log.Info("validatePath: validating the list key names for the node path: ", pathElem.Key)
					}
					if err := pv.validateListKeyNames(ygSchema, keysMap, idx); err != nil {
						log.Error("Error in validating the key names, ", err)
						return err
					}

					if !isWc {
						// validate the key values
						gpath := &gnmi.Path{}
						gpath.Elem = append(gpath.Elem, pathElem)
						log.Info("validatePath: validating the list key values for the path: ", gpath)
						if err := pv.validateListKeyValues(pv.parentSchema, gpath); err != nil {
							log.Error("Error in validating the key values", err)
							return err
						}
					}
				} else if isAddWcKey {
					pv.gPath.Elem[idx].Key = make(map[string]string)
					for _, kn := range strings.Fields(ygSchema.Key) {
						pv.gPath.Elem[idx].Key[kn] = "*"
					}
					if log.V(5) {
						log.Info("validatePath: added the key names and wild cards for the list node path: ", pv.gPath.Elem[idx])
					}
				}
			}
		}
		prevModName = ygModName
		pv.parentSchema = ygSchema
	}
	return nil
}

func (pv *pathValidator) validateListKeyNames(ygSchema *yang.Entry, keysMap map[string]bool, pathIdx int) error {
	keyNames := strings.Fields(ygSchema.Key)
	if len(keyNames) != len(keysMap) {
		return fmt.Errorf("Invalid key names since number of keys present in the node: %v does not match with the given keys", ygSchema.Name)
	}
	for _, kn := range keyNames {
		if !keysMap[kn] {
			return fmt.Errorf("Invalid key name: %v in the list node path: %v", pv.gPath.Elem[pathIdx].Key, pv.gPath.Elem[pathIdx].Name)
		}
	}
	return nil
}

func (pv *pathValidator) validateListKeyValues(schema *yang.Entry, gPath *gnmi.Path) error {
	sVal := reflect.ValueOf(pv.parentIntf)
	log.Infof("validateListKeyValues: schema name: %v, and parent ygot type name: %v: ", schema.Name, sVal.Elem().Type().Name())
	if objIntf, _, err := ytypes.GetOrCreateNode(schema, pv.parentIntf, gPath); err != nil {
		log.Error("Invalid key present in the path and the error is ", err)
		return fmt.Errorf("Invalid key present in the node path: %v", gPath)
	} else {
		if log.V(5) {
			log.Infof("validateListKeyValues: objIntf: %v", reflect.ValueOf(objIntf).Elem())
		}
		if ygotStruct, ok := objIntf.(ygot.ValidatedGoStruct); ok {
			if log.V(5) {
				pretty.Print(ygotStruct)
			}
			if err := ygotStruct.Validate(&ytypes.LeafrefOptions{IgnoreMissingData: true}); err != nil {
				log.Error("Invalid key present in the path and the error is ", err)
				return fmt.Errorf("Invalid key present in the node path: %v", gPath)
			}
		} else {
			log.Errorf("Could not validate the gnmi path: %v since casting to ValidatedGoStruct fails", gPath)
			return fmt.Errorf("Invalid key present in the node path: %v", gPath)
		}
	}
	return nil
}

func (pv *pathValidator) updateStructFieldVal() {
	log.Infof("updateStructFieldVal: struct field: %v; struct field type: %v", pv.sField, pv.sField.Type)
	var sVal reflect.Value

	if util.IsTypeMap(pv.sField.Type) || util.IsTypeSlice(pv.sField.Type) {
		log.Info("updateStructFieldVal: field type is map or slice")
		sVal = reflect.New(pv.sField.Type.Elem().Elem())
	} else {
		sVal = reflect.New(pv.sField.Type.Elem())
	}
	log.Info("updateStructFieldVal: sVal", sVal)
	pv.parentIntf = pv.sValIntf
	pv.sValIntf = sVal.Interface()
}

// PathValidatorOpt is an interface used for any option to be supplied
type PathValidatorOpt interface {
	IsPathValidatorOpt()
}

// AppendModulePrefix is an PathValidator option that indicates that
// the missing module prefix in the given gnmi path will be added
// during the path validation
type AppendModulePrefix struct{}

// IsPathValidatorOpt marks AppendModulePrefix as a valid PathValidatorOpt.
func (*AppendModulePrefix) IsPathValidatorOpt() {}

// AddWildcardKeys is an PathValidator option that indicates that
// the missing wild card keys in the given gnmi path will be added
// during the path validation
type AddWildcardKeys struct{}

// IsPathValidatorOpt marks AddWildcardKeys as a valid PathValidatorOpt.
func (*AddWildcardKeys) IsPathValidatorOpt() {}

// IgnoreKeyValidation is an PathValidator option to indicate the
// validator to ignore the key validation in the given gnmi path during the path validation
type IgnoreKeyValidation struct{}

// IsPathValidatorOpt marks IgnoreKeyValidation as a valid PathValidatorOpt.
func (*IgnoreKeyValidation) IsPathValidatorOpt() {}

func (pv *pathValidator) hasIgnoreKeyValidationOption() bool {
	for _, o := range pv.opts {
		if _, ok := o.(*IgnoreKeyValidation); ok {
			return true
		}
	}
	return false
}

func (pv *pathValidator) hasAppendModulePrefixOption() bool {
	for _, o := range pv.opts {
		if _, ok := o.(*AppendModulePrefix); ok {
			return true
		}
	}
	return false
}

func (pv *pathValidator) hasAddWildcardKeyOption() bool {
	for _, o := range pv.opts {
		if _, ok := o.(*AddWildcardKeys); ok {
			return true
		}
	}
	return false
}
