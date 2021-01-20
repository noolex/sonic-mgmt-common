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
	"fmt"
	"github.com/openconfig/goyang/pkg/yang"
	"os"
	"strings"
        "bufio"
        "path/filepath"
        "io/ioutil"
)

var YangPath = "/usr/models/yang/" // OpenConfig-*.yang and sonic yang models path
var ModelsListFile  = "models_list"
var TblInfoJsonFile = "sonic_table_info.json"

func reportIfError(errs []error) {
	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}

func getOcModelsList () ([]string) {
    var fileList []string
    file, err := os.Open(YangPath + ModelsListFile)
    if err != nil {
        return fileList
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        fileEntry := scanner.Text()
        if !strings.HasPrefix(fileEntry, "#") {
            _, err := os.Stat(YangPath + fileEntry)
            if err != nil {
                continue
            }
            fileList = append(fileList, fileEntry)
        }
    }
    return fileList
}

func getDefaultModelsList () ([]string) {
    var files []string
    fileInfo, err := ioutil.ReadDir(YangPath)
    if err != nil {
        return files
    }

    for _, file := range fileInfo {
        if strings.HasPrefix(file.Name(), "sonic-") && !strings.HasSuffix(file.Name(), "-dev.yang") &&  filepath.Ext(file.Name()) == ".yang" {
            files = append(files, file.Name())
        }
    }
    return files
}

func init() {
	initYangModelsPath()
	initRegex()
        ocList := getOcModelsList()
	yangFiles := getDefaultModelsList()
        yangFiles = append(yangFiles, ocList...)
        fmt.Println("Yang model List:", yangFiles)
	err := loadYangModules(yangFiles...)
    if err != nil {
	    fmt.Fprintln(os.Stderr, err)
    }
}

func initYangModelsPath() {
	if path, ok := os.LookupEnv("YANG_MODELS_PATH"); ok {
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		YangPath = path
	}

	fmt.Println("Yang modles path:", YangPath)
}

func loadYangModules(files ...string) error {

	var err error

	paths := []string{YangPath}

	for _, path := range paths {
		expanded, err := yang.PathsWithModules(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		yang.AddPath(expanded...)
	}

	ms := yang.NewModules()

	for _, name := range files {
		if err := ms.Read(name); err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
	}

	// Process the Yang files
	reportIfError(ms.Process())

	// Keep track of the top level modules we read in.
	// Those are the only modules we want to print below.
	mods := map[string]*yang.Module{}
	var names []string

	for _, m := range ms.Modules {
		if mods[m.Name] == nil {
			mods[m.Name] = m
			names = append(names, m.Name)
		}
	}

	sonic_entries       := make([]*yang.Entry, 0)
	oc_entries          := make(map[string]*yang.Entry)
	oc_annot_entries    := make([]*yang.Entry, 0)
	sonic_annot_entries := make([]*yang.Entry, 0)

	for _, n := range names {
		if strings.Contains(n, "annot") && strings.Contains(n, "sonic") {
			sonic_annot_entries = append(sonic_annot_entries, yang.ToEntry(mods[n]))
		} else if strings.Contains(n, "annot") {
			yangMdlNmDt := strings.Split(n, "-annot")
			if len(yangMdlNmDt) > 0 {
				addMdlCpbltEntry(yangMdlNmDt[0])
			}
			oc_annot_entries = append(oc_annot_entries, yang.ToEntry(mods[n]))
		} else if strings.Contains(n, "sonic") {
			sonic_entries = append(sonic_entries, yang.ToEntry(mods[n]))
		} else if oc_entries[n] == nil {
			oc_entries[n] = yang.ToEntry(mods[n])
		}
	}

	// populate model capabilities data
	for yngMdlNm := range(xMdlCpbltMap) {
		org := ""
		ver := ""
		ocVerSet := false
		yngEntry := oc_entries[yngMdlNm]
		if (yngEntry != nil) {
			// OC yang has version in standard extension oc-ext:openconfig-version
			if strings.HasPrefix(yngMdlNm, "openconfig-") {
				for _, ext := range yngEntry.Exts {
					dataTagArr := strings.Split(ext.Keyword, ":")
					tagType := dataTagArr[len(dataTagArr)-1]
					if tagType == "openconfig-version" {
						ver = ext.NName()
						fmt.Printf("Found version %v for yang module %v", ver, yngMdlNm)
						if len(strings.TrimSpace(ver)) > 0 {
							ocVerSet = true
						}
					break
					}

				}
			}
		}
		if ((strings.HasPrefix(yngMdlNm, "ietf-")) || (!ocVerSet)) {
			// as per RFC7895 revision date to be used as version
			ver = mods[yngMdlNm].Current() //gives the most recent revision date for yang module
		}
		org = mods[yngMdlNm].Organization.Name
		addMdlCpbltData(yngMdlNm, ver, org)
	}
	dbMapBuild(sonic_entries)
	annotDbSpecMap(sonic_annot_entries)
	annotToDbMapBuild(oc_annot_entries)
	yangToDbMapBuild(oc_entries)

	return err
}
