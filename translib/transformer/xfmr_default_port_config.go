package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/utils"
    "github.com/Azure/sonic-mgmt-common/cvl"
    log "github.com/golang/glog"
    "io/ioutil"
    "encoding/json"
    "fmt"
    "strings"
    "errors"
)

var defaultConfig map[string]map[string]map[string]string

/* Transformer specific functions */
func init () {
    XlateFuncBind("rpc_default_port_config", rpc_default_port_config)
}

type rpcResponse = struct {
        Output struct {
            Status int32 `json:"status"`
            Status_detail string`json:"status-detail"`
       } `json:"sonic-config-mgmt:output"`
}

func errResponse(errStr string) ([]byte, error) {
    var response rpcResponse
    var result []byte
    var err error

    log.Errorf(errStr)
    response.Output.Status = 1
    response.Output.Status_detail = errStr
    result, err = json.Marshal(&response)
    return result, err
}

var rpc_default_port_config RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    var err error
    var result []byte
    var configDB *db.DB
    var mapData map[string]interface{}
    var active_profile string
    var default_cfg_port_speed string
    var cfg_port string
    var testCode bool
    var errStr string

    /* Create a response payload */
    var response rpcResponse

    /* Read input data */
    err = json.Unmarshal(body, &mapData)
    if err != nil {
       errStr = fmt.Sprintf("Failed to interpret input data. Error %v\n", err)
       return errResponse(errStr)
    }

    /* Interpret input data */
    input := mapData["sonic-config-mgmt:input"]
    mapData = input.(map[string]interface{})
    input = mapData["ifname"]
    port_str := fmt.Sprintf("%v", input)
    /* Translate port name to native port name */
    nativePortName := utils.GetNativeNameFromUIName(&port_str)
    port_str = *nativePortName

    /* Create a DB instance with write permissions to communicate with Config DB */
    opts := getDBOptions(db.ConfigDB)
    opts.IsWriteDisabled = false
    configDB, err = db.NewDB(opts)
    if err != nil {
       errStr = fmt.Sprintf("Failed to create a DB object. Error %v\n", err)
       return errResponse(errStr)
    }
    defer configDB.DeleteDB()

    /* Create payload for cascadeHandleDelete */
    dbDataMap := make(map[int]map[db.DBNum]map[string]map[string]db.Value)

    /* Table entries to be added */
    dbDataMap[UPDATE] = make(map[db.DBNum]map[string]map[string]db.Value)
    dbDataMap[UPDATE][db.ConfigDB] = make(map[string]map[string]db.Value)
    /* dbMap for default configurations */
    updatePortMap := make(map[string]db.Value)
    portData := make(map[string]string)
    portValue := db.Value{Field: portData}

    portTblTs := db.TableSpec {Name: "PORT"}
    port_entry, err := configDB.GetEntry(&portTblTs, db.Key{Comp: []string{port_str}})
    if err != nil || !port_entry.IsPopulated() {
        errStr = fmt.Sprintf("Unable to fetch PORT|%s from ConfigDB. Error=%v", port_str, err)
        return errResponse(errStr)
    }

    if !port_entry.Has("index") || !port_entry.Has("lanes") || !port_entry.Has("alias") {
        errStr = fmt.Sprintf("Port information not found for %s. Port Entry %v.", port_str, port_entry)
        return errResponse(errStr)
    }

    /* Read configuration values from default config file */
    /* Detect active profile */
    metadataTblTs := db.TableSpec {Name: "DEVICE_METADATA"}
    device_metadata, err := configDB.GetEntry(&metadataTblTs, db.Key{Comp: []string{"localhost"}})
    if err != nil || !device_metadata.IsPopulated() {
        errStr = fmt.Sprintf("Unable to fetch DEVICE_METADATA from ConfigDB. Error=%v", err)
        return errResponse(errStr)
    }
    if !testCode && !device_metadata.Has("default_config_profile") {
        active_profile = "l3"
        log.Errorf("Default config profile information not found. Defaulting to l3.")
    } else {
        active_profile = device_metadata.Field["default_config_profile"]
    }

    /* Read the default configuration file corresponding to the active factory default profile */
    default_config_db_json := fmt.Sprintf("/usr/share/broadcom_sonic/config_profiles/%v/data/default_config_db.json", active_profile)
    cfg_err := parseDefaultConfigJsonFile(default_config_db_json)
    if cfg_err != nil {
        errStr = fmt.Sprintf("Failed to read default configuration file. Error=%v", cfg_err)
        return errResponse(errStr)
    }

    /* Determine if the port is a broken out port */
    is_broken_port := false
    brktPortTblTs := db.TableSpec {Name: "BREAKOUT_PORTS"}
    brkt_port_entry, err := configDB.GetEntry(&brktPortTblTs, db.Key{Comp: []string{port_str}})
    if err == nil && brkt_port_entry.IsPopulated() {
        if brkt_port_entry.Field["master"] != port_str {
            is_broken_port = true
        } else {
            brktCfgTblTs := db.TableSpec {Name: "BREAKOUT_CFG"}
            brkt_cfg_entry, err := configDB.GetEntry(&brktCfgTblTs, db.Key{Comp: []string{port_str}})
            if err == nil && brkt_cfg_entry.IsPopulated() {
                def_brkt_mode, err := getDefaultBreakoutMode(port_str)
                if err == nil {
                   if port_entry.Field["lanes"] != brkt_cfg_entry.Field["lanes"] ||
                      def_brkt_mode !=  brkt_cfg_entry.Field["brkout_mode"] {
                       is_broken_port = true
                   }
                }
            }
        }
    }

    /* port which is used to index read default configuration file. For a broken out port, its
       master interface is used to query the factory default values */
    if is_broken_port {
        cfg_port = brkt_port_entry.Field["master"]
    } else {
        cfg_port = port_str
    }

    /* Read and set PORT default configuration */
    if cfg_port_table, ok := defaultConfig["PORT"]; ok {
        if port_cfg, ok := cfg_port_table[cfg_port]; ok {
            if _, ok := port_cfg["speed"]; ok {
                 default_cfg_port_speed = port_cfg["speed"]
            } else {
                 errStr = fmt.Sprintf("Failed to read default speed value for port %v", cfg_port)
                 return errResponse(errStr)
            }
            if _, ok := port_cfg["mtu"]; ok {
                 portValue.Set("mtu", port_cfg["mtu"])
            } else {
                 errStr = fmt.Sprintf("Failed to read default MTU value for port %v", cfg_port)
                 return errResponse(errStr)
            }

            if _, ok := port_cfg["admin_status"]; ok {
                 portValue.Set("admin_status", port_cfg["admin_status"])
            } else {
                 errStr = fmt.Sprintf("Failed to read default admin status for port %v", cfg_port)
                 return errResponse(errStr)
            }
            if _, ok := port_cfg["fec"]; ok {
                 portValue.Set("fec", port_cfg["fec"])
            } else if port_entry.Has("fec") {
                 portValue.Set("fec", "None")
            }
        } else {
            errStr = fmt.Sprintf("Port default configuration not found for port %v", cfg_port)
            return errResponse(errStr)
        }
    } else {
        errStr = "Port configuration table not found"
        return errResponse(errStr)
    }

    /* Set STP configuration if present */
    if stp_port_table, ok := defaultConfig["STP_INTF"]; ok {
        if stp_port_cfg, ok := stp_port_table[cfg_port]; ok {
            updatestpPortMap := make(map[string]db.Value)
            stpPortData := make(map[string]string)
            stpPortValue := db.Value{Field: stpPortData}
            for k,v := range stp_port_cfg {
                stpPortValue.Set(k, v)
            }
            updatestpPortMap[port_str] = stpPortValue
            dbDataMap[UPDATE][db.ConfigDB]["STP_PORT"] = updatestpPortMap
        }
    }

    if stp_intf_table, ok := defaultConfig["STP_PORT"]; ok {
        if stp_intf_cfg, ok := stp_intf_table[cfg_port]; ok {
            updatestpIntfMap := make(map[string]db.Value)
            stpIntfData := make(map[string]string)
            stpIntfValue := db.Value{Field: stpIntfData}
            for k,v := range stp_intf_cfg {
                stpIntfValue.Set(k, v)
            }
            updatestpIntfMap[port_str] = stpIntfValue
            dbDataMap[UPDATE][db.ConfigDB]["STP_PORT"] = updatestpIntfMap
        }
    }

    /* Set VLAN membership */
    if vlan_member_table, ok := defaultConfig["VLAN_MEMBER"]; ok {
        for k, vdata := range vlan_member_table {
            if strings.Contains(k, cfg_port) {
                default_vlan := strings.Split(k, "|")[0]
                vlanTblTs := db.TableSpec {Name: "VLAN"}
                vlan_entry, err := configDB.GetEntry(&vlanTblTs, db.Key{Comp: []string{default_vlan}})
                if err != nil || !vlan_entry.IsPopulated() {
                    log.Infof("Default VLAN %v does not exist. Skip port %v member assignment", default_vlan, port_str)
                    continue
                }

                // VLAN table updates
                updateVlanMap := make(map[string]db.Value)
                vlanData := make(map[string]string)
                vlanValue := db.Value{Field: vlanData}
                if vlan_entry.Has("members@") {
                    port_list := strings.Split(vlan_entry.Field["members@"], ",")
                    _, member_found := Find(port_list, port_str)
                    if !member_found {
                        /* Append only if existing VLAN doesn't have the port as its member */
                        vlanValue.Set("members@", vlan_entry.Field["members@"] + "," + port_str)
                    } else {
                        /* Retain current VLAN membership */
                        vlanValue.Set("members@", vlan_entry.Field["members@"])
                    }
                } else {
                    vlanValue.Set("members@", port_str)
                }
                updateVlanMap[default_vlan] = vlanValue
                dbDataMap[UPDATE][db.ConfigDB]["VLAN"] = updateVlanMap

                // VLAN_MEMBER table updates
                updateVlanMemberMap := make(map[string]db.Value)
                vlanMemberData := make(map[string]string)
                vlanMemberValue := db.Value{Field: vlanMemberData}

                // Fill in vlan member table data
                for f,v := range vdata {
                    vlanMemberValue.Set(f, v)
                }
                updateVlanMemberMap[default_vlan + "|" + port_str] = vlanMemberValue
                dbDataMap[UPDATE][db.ConfigDB]["VLAN_MEMBER"] = updateVlanMemberMap

            }
        }
    }
    /* End of values from default config file */

    /* Read the below port specific parameters from ConfigDB */
    portValue.Set("index", port_entry.Field["index"])
    portValue.Set("lanes", port_entry.Field["lanes"])
    portValue.Set("alias", port_entry.Field["alias"])
    if port_entry.Has("valid_speeds") {
        portValue.Set("valid_speeds", port_entry.Field["valid_speeds"])
    }

    /* For a broken out port, keep the speed intact */
    if is_broken_port && port_entry.Has("speed") {
        portValue.Set("speed", port_entry.Field["speed"])
    } else {
        /* Read values from default config file */
        dflt_speed, err := getDefaultBreakoutModeSpeed(port_str)
        if err == nil {
            portValue.Set("speed", dflt_speed)
        } else {
            if testCode {
              default_cfg_port_speed = port_entry.Field["speed"]
            }
            portValue.Set("speed", default_cfg_port_speed)
        }
    }
    /* End of values from ConfigDB */

    updatePortMap[port_str] = portValue
    dbDataMap[UPDATE][db.ConfigDB]["PORT"] = updatePortMap

    /* Table entries to be deleted */
    dbDataMap[DELETE] = make(map[db.DBNum]map[string]map[string]db.Value)
    dbDataMap[DELETE][db.ConfigDB] = make(map[string]map[string]db.Value)
    delMap := make(map[string]db.Value)

    // Field value map is null to indicate entire entry delete.
    delMap[port_str] = db.Value{}
    dbDataMap[DELETE][db.ConfigDB]["PORT"] = delMap

    /* Obtain all dependent configuration for the port */
    cascadeDelTbl := []string{"PORT"}
    handleCascadeDelete(dbs[db.ConfigDB], dbDataMap, cascadeDelTbl)
    log.Infof("rpc_default_port_config : Configuration to be deleted: %v.", dbDataMap)

    /* Do not delete PORT as the same port needs to be updated with default configuration */
    delete(dbDataMap[DELETE][db.ConfigDB], "PORT")

    /* Obtain the list of dependent tables and keys to watch while performing the config operations */
    var tblsToWatch []*db.TableSpec
    cvlSess, cvlRes := cvl.ValidationSessOpen()
    if cvlRes != cvl.CVL_SUCCESS {
        errStr = fmt.Sprintf("rpc_default_port_config : Failed to start a CVL validation session. Result %v.", cvlRes)
        return errResponse(errStr)
    }
    defer cvl.ValidationSessClose(cvlSess)

    fullDepTblList := cvlSess.GetAllReferringTables("PORT")
    if len(fullDepTblList) != 0 {
        for tbl := range fullDepTblList {
            tblsToWatch = append(tblsToWatch, &db.TableSpec{Name: tbl})
        }
    }

    log.Infof("rpc_default_port_config : Configuration of port %v is being restored. dbDataMap: %v. tblsToWatch: %v", port_str, dbDataMap, fullDepTblList)

    /* Start applying updates to the DB  */
    err = configDB.StartTx(nil, tblsToWatch)
    if err != nil {
        errStr = fmt.Sprintf("rpc_default_port_config : Failed to start ConfigDB transaction %v.", err)
        return errResponse(errStr)
    }

    /* Perform DELETE operations */
    err = delDbOpn(configDB, dbDataMap[DELETE][db.ConfigDB], true, "openconfig-platform")
    if err != nil {
        errStr = fmt.Sprintf("rpc_default_port_config : Failed to perform delete operations. Error %v. dbDataMap %v.", err, dbDataMap[DELETE][db.ConfigDB])
        return errResponse(errStr)
    }

    /* Perform UPDATE operations */
    err = cruDbOpn(configDB, UPDATE, dbDataMap[UPDATE][db.ConfigDB], nil)
    if err != nil {
        errStr = fmt.Sprintf("rpc_default_port_config : Failed to perform update operations. Error %v. dbDataMap %v.", err, dbDataMap[UPDATE][db.ConfigDB])
        return errResponse(errStr)
    }

    /* Apply changes to the DB */
    err = configDB.CommitTx()
    if err != nil {
        errStr = fmt.Sprintf("rpc_default_port_config : Failed to commit ConfigDB transaction %v.", err)
        return errResponse(errStr)
    }

    response.Output.Status = 0
    response.Output.Status_detail = "Operation Successful"
    result, err = json.Marshal(&response)
    return result, err
}

// parseDefaultConfigJsonFile - Reads factory default configuration json file
func parseDefaultConfigJsonFile (default_config_json string) (error) {

    file, err := ioutil.ReadFile(default_config_json)
    if nil != err {
        log.Error("Failed to read default configuration");
        return err
    }
    defaultConfig = make(map[string]map[string]map[string]string)
    err = json.Unmarshal([]byte(file), &defaultConfig)
    return err
}

// delDbOpn - Perform delete operations on the dbMap
// This function is a copy of the function cmnAppDelDbOpn() from translib/common_app.go
func delDbOpn(d *db.DB, dbMap map[string]map[string]db.Value, skipOrdTableChk bool, moduleNm string) error {
	var err error
	var cmnAppTs, dbTblSpec *db.TableSpec
	var xfmrTblLst []string
	var resultTblLst []string
	var ordTblList []string

	for tblNm := range(dbMap) {
		xfmrTblLst = append(xfmrTblLst, tblNm)
	}
	resultTblLst, err = utils.SortAsPerTblDeps(xfmrTblLst)
	if err != nil {
		return err
	}


	log.Info("getModuleNmFromPath() returned module name = ", moduleNm)

	/* resultTblLst has child first, parent later order */
	for _, tblNm := range resultTblLst {
		log.Info("In Yang to DB map returned from transformer looking for table = ", tblNm)
		if tblVal, ok := dbMap[tblNm]; ok {
			cmnAppTs = &db.TableSpec{Name: tblNm}
			log.Info("Found table entry in yang to DB map")
			if !skipOrdTableChk {
				ordTblList = GetXfmrOrdTblList(tblNm)
				if len(ordTblList) == 0 {
					ordTblList = GetOrdTblList(tblNm, moduleNm)
				}
				if len(ordTblList) == 0 {
					log.Error("GetOrdTblList returned empty slice")
					err = errors.New("GetOrdTblList returned empty slice. Insufficient information to process request")
					return err
				}
				//log.Infof("GetOrdTblList for table - %v, module %v returns %v", tblNm, moduleNm, ordTblList)
			}
			if len(tblVal) == 0 {
				log.Info("DELETE case - No table instances/rows found hence delete entire table = ", tblNm)
				if !skipOrdTableChk {
					for _, ordtbl := range ordTblList {
						if ordtbl == tblNm {
							// Handle the child tables only till you reach the parent table entry
							break
						}
						log.Info("Since parent table is to be deleted, first deleting child table = ", ordtbl)
						dbTblSpec = &db.TableSpec{Name: ordtbl}
						err = d.DeleteTable(dbTblSpec)
						if err != nil {
							log.Warning("DELETE case - d.DeleteTable() failure for Table = ", ordtbl)
							return err
						}
					}
				}
				err = d.DeleteTable(cmnAppTs)
				if err != nil {
					log.Warning("DELETE case - d.DeleteTable() failure for Table = ", tblNm)
					return err
				}
				log.Info("DELETE case - Deleted entire table = ", tblNm)
				// Continue to repeat ordered deletion for all tables
				continue

			}

			for tblKey, tblRw := range tblVal {
				if len(tblRw.Field) == 0 {
					log.Info("DELETE case - no fields/cols to delete hence delete the entire row.")
					log.Info("First, delete child table instances that correspond to parent table instance to be deleted = ", tblKey)
					if !skipOrdTableChk {
						for _, ordtbl := range ordTblList {
							if ordtbl == tblNm {
								// Handle the child tables only till you reach the parent table entry
								break;
							}
							dbTblSpec = &db.TableSpec{Name: ordtbl}
							keyPattern := tblKey + "|*"
							log.Info("Key pattern to be matched for deletion = ", keyPattern)
							err = d.DeleteKeys(dbTblSpec, db.Key{Comp: []string{keyPattern}})
							if err != nil {
								log.Warning("DELETE case - d.DeleteTable() failure for Table = ", ordtbl)
								return err
							}
							log.Info("Deleted keys matching parent table key pattern for child table = ", ordtbl)
						}
					}
					err = d.DeleteEntry(cmnAppTs, db.Key{Comp: []string{tblKey}})
					if err != nil {
						log.Warning("DELETE case - d.DeleteEntry() failure")
						return err
					}
					log.Info("Finally deleted the parent table row with key = ", tblKey)
				} else {
					log.Info("DELETE case - fields/cols to delete hence delete only those fields.")
					existingEntry, _ := d.GetEntry(cmnAppTs, db.Key{Comp: []string{tblKey}})
					if !existingEntry.IsPopulated() {
						log.Info("Table Entry from which the fields are to be deleted does not exist")
						return err
					}
					/* handle leaf-list merge if any leaf-list exists */
					resTblRw := checkAndProcessLeafList(existingEntry, tblRw, DELETE, d, tblNm, tblKey)
					if len(resTblRw.Field) > 0 {
						/* add the NULL field if the last field gets deleted */
						deleteCount := 0
						for field := range existingEntry.Field {
							if resTblRw.Has(field) {
								deleteCount++
							}
						}
						if deleteCount == len(existingEntry.Field) {
							nullTblRw := db.Value{Field: map[string]string{"NULL": "NULL"}}
							log.Info("Last field gets deleted, add NULL field to keep an db entry")
							err = d.ModEntry(cmnAppTs, db.Key{Comp: []string{tblKey}}, nullTblRw)
							if err != nil {
								log.Error("UPDATE case - d.ModEntry() failure")
								return err
							}
						}
						/* deleted fields */
						err := d.DeleteEntryFields(cmnAppTs, db.Key{Comp: []string{tblKey}}, resTblRw)
						if err != nil {
							log.Error("DELETE case - d.DeleteEntryFields() failure")
							return err
						}
					}
				}
			}
		}
	} /* end of ordered table list for loop */
	return err
}

// checkAndProcessLeafList check if any field is leaf-list, if yes perform merge
// This function is a copy of the function checkAndProcessLeafList() from translib/common_app.go
func checkAndProcessLeafList(existingEntry db.Value, tblRw db.Value, opcode int, d *db.DB, tblNm string, tblKey string) db.Value {
	dbTblSpec := &db.TableSpec{Name: tblNm}
	mergeTblRw := db.Value{Field: map[string]string{}}
	for field, value := range tblRw.Field {
		if strings.HasSuffix(field, "@") {
			exstLst := existingEntry.GetList(field)
			//log.Infof("Existing DB value for field %v - %v", field, exstLst)
			var valueLst []string
			if value != "" { //zero len string as leaf-list value is treated as delete entire leaf-list
				valueLst = strings.Split(value, ",")
			}
			//log.Infof("Incoming value for field %v - %v", field, valueLst)
			if len(exstLst) != 0 {
				//log.Infof("Existing list is not empty for field %v", field)
				for _, item := range valueLst {
					if !contains(exstLst, item) {
						if opcode == UPDATE {
							exstLst = append(exstLst, item)
						}
					} else {
						if opcode == DELETE {
                                                        exstLst = utils.RemoveElement(exstLst, item)
                                                }

					}
				}
				//log.Infof("For field %v value after merging incoming with existing %v", field, exstLst)
				if opcode == DELETE {
					if len(valueLst) > 0 {
						mergeTblRw.SetList(field, exstLst)
						if len(exstLst) == 0 {
							tblRw.Field[field] = ""
						} else {
							delete(tblRw.Field, field)
						}
					}
				} else if opcode == UPDATE {
					tblRw.SetList(field, exstLst)
				}
			} else { //when existing list is empty(either empty string val in field or no field at all n entry)
				//log.Infof("Existing list is empty for field %v", field)
				if opcode == UPDATE {
					if len(valueLst) > 0 {
						exstLst = valueLst
						tblRw.SetList(field, exstLst)
					} else {
						tblRw.Field[field] = ""
					}
				} else if opcode == DELETE {
					_, fldExistsOk := existingEntry.Field[field]
					if (fldExistsOk && (len(valueLst) == 0)) {
						tblRw.Field[field] = ""
					} else {
						delete(tblRw.Field, field)
					}
				}
                        }
		}
	}
	/* delete specific item from leaf-list */
	if opcode == DELETE {
		if len(mergeTblRw.Field) == 0 {
			//log.Infof("mergeTblRow is empty - Returning Table Row %v", tblRw)
			return tblRw
		}
		err := d.ModEntry(dbTblSpec, db.Key{Comp: []string{tblKey}}, mergeTblRw)
		if err != nil {
			log.Warning("DELETE case(merge leaf-list) - d.ModEntry() failure")
		}
	}
	//log.Infof("Returning Table Row %v", tblRw)
	return tblRw
}

// cruDbOpn - Perform Create/Replace/Update operations on a dbMap
// This function is a copy of the function cmnAppCRUCommonDbOpn() from translib/common_app.go
func cruDbOpn(d *db.DB, opcode int, dbMap map[string]map[string]db.Value, deldbMap map[string]map[string]db.Value) error {
        var err error
        var cmnAppTs *db.TableSpec
        var xfmrTblLst []string
        var resultTblLst []string

        for tblNm := range(dbMap) {
                xfmrTblLst = append(xfmrTblLst, tblNm)
        }
        resultTblLst, err = utils.SortAsPerTblDeps(xfmrTblLst)
        if err != nil {
                return err
        }

        /* CVL sorted order is in child first, parent later order. CRU ops from parent first order */
        for idx := len(resultTblLst)-1; idx >= 0; idx-- {
                tblNm := resultTblLst[idx]
                log.Info("In Yang to DB map returned from transformer looking for table = ", tblNm)
                if tblVal, ok := dbMap[tblNm]; ok {
                        cmnAppTs = &db.TableSpec{Name: tblNm}
                        log.Info("Found table entry in yang to DB map")
                        if ((tblVal == nil) || (len(tblVal) == 0)) {
                                log.Info("No table instances/rows found.")
                                continue
                        }
                        for tblKey, tblRw := range tblVal {
                                log.Info("Processing Table key ", tblKey)
                                // REDIS doesn't allow to create a table instance without any fields
                                if tblRw.Field == nil {
                                        tblRw.Field = map[string]string{"NULL": "NULL"}
                                }
                                if len(tblRw.Field) == 0 {
                                        tblRw.Field["NULL"] = "NULL"
                                }
                                if len(tblRw.Field) > 1 {
                                        delete(tblRw.Field, "NULL")
                                }
                                log.Info("Processing Table row ", tblRw)
                                existingEntry, _ := d.GetEntry(cmnAppTs, db.Key{Comp: []string{tblKey}})
                                switch opcode {
                                case CREATE:
                                        deldbMapContains := false
                                        if deldbMap != nil {
                                            if _, ok := deldbMap[tblNm][tblKey] ; ok {
                                                deldbMapContains = true
                                            }
                                        }

                                        if existingEntry.IsPopulated() && !deldbMapContains {
                                                log.Info("Entry already exists hence return.")
                                                return tlerr.AlreadyExists("Entry %s already exists", tblKey)
                                        } else {
                                                err = d.CreateEntry(cmnAppTs, db.Key{Comp: []string{tblKey}}, tblRw)
                                                if err != nil {
                                                        log.Error("CREATE case - d.CreateEntry() failure")
                                                        return err
                                                }
                                        }
                                case UPDATE:
                                        if existingEntry.IsPopulated() {
                                                log.Info("Entry already exists hence modifying it.")
                                                /* Handle leaf-list merge if any leaf-list exists
                                                A leaf-list field in redis has "@" suffix as per swsssdk convention.
                                                */
                                                resTblRw := db.Value{Field: map[string]string{}}
                                                resTblRw = checkAndProcessLeafList(existingEntry, tblRw, UPDATE, d, tblNm, tblKey)
                                                err = d.ModEntry(cmnAppTs, db.Key{Comp: []string{tblKey}}, resTblRw)
                                                if err != nil {
                                                        log.Error("UPDATE case - d.ModEntry() failure")
                                                        return err
                                                }
                                        } else {
                                                // workaround to patch operation from CLI
                                                log.Info("Create(patch) an entry.")
                                                err = d.CreateEntry(cmnAppTs, db.Key{Comp: []string{tblKey}}, tblRw)
                                                if err != nil {
                                                        log.Error("UPDATE case - d.CreateEntry() failure")
                                                        return err
                                                }
                                        }
                                case REPLACE:
                                        if existingEntry.IsPopulated() {
                                                log.Info("Entry already exists hence execute db.SetEntry")
                                                err := d.SetEntry(cmnAppTs, db.Key{Comp: []string{tblKey}}, tblRw)
                                                if err != nil {
                                                        log.Error("REPLACE case - d.SetEntry() failure")
                                                        return err
                                                }
                                        } else {
                                                log.Info("Entry doesn't exist hence create it.")
                                                err = d.CreateEntry(cmnAppTs, db.Key{Comp: []string{tblKey}}, tblRw)
                                                if err != nil {
                                                        log.Error("REPLACE case - d.CreateEntry() failure")
                                                        return err
                                                }
                                        }
                                }
                        }
                }
        }
        return err
}
