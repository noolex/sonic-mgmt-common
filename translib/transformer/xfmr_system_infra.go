package transformer

import (
    "fmt"
    "strings"
    log "github.com/golang/glog"
    "github.com/shirou/gopsutil/host"
    "encoding/json"
    "time"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/db"
)

func init () {
    XlateFuncBind("DbToYang_sys_infra_state_clock_xfmr", DbToYang_sys_infra_state_clock_xfmr)
    XlateFuncBind("DbToYang_sys_infra_state_uptime_xfmr", DbToYang_sys_infra_state_uptime_xfmr)
    XlateFuncBind("DbToYang_sys_infra_state_reboot_cause_xfmr", DbToYang_sys_infra_state_reboot_cause_xfmr)
    XlateFuncBind("rpc_infra_reboot_cb",  rpc_infra_reboot_cb)
    XlateFuncBind("rpc_infra_config_cb",  rpc_infra_config_cb)
}

var DbToYang_sys_infra_state_clock_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        log.Info("DbToYang_sys_infra_state_clock_xfmr uri: ", inParams.uri)

        rmap := make(map[string]interface{})

        entry_key := inParams.key
        log.Info("DbToYang_sys_infra_time_test_xfmr: ", entry_key)

        crtime := time.Now().Format(time.RFC1123)
        rmap["clock"]=&crtime

        return rmap, nil 
}


var DbToYang_sys_infra_state_uptime_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        log.Info("DbToYang_sys_infra_state_uptime_xfmr uri: ", inParams.uri)

        rmap := make(map[string]interface{})
    	uptime,_ := host.Uptime()
    	days := uptime / (60 * 60 * 24)
    	hours := (uptime - (days * 60 * 60 * 24)) / (60 * 60)
    	minutes := ((uptime - (days * 60 * 60 * 24))  -  (hours * 60 * 60)) / 60
    	s := fmt.Sprintf("%d days, %d hours, %d minutes",days,hours,minutes)

        rmap["uptime"]=&s

        return rmap, nil 
}

var DbToYang_sys_infra_state_reboot_cause_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        log.Info("DbToYang_sys_infra_state_reboot_cause_xfmr uri: ", inParams.uri)

    var err error
    var host_output HostResult

    result := make(map[string]interface{})

    cmd := "cat /host/reboot-cause/previous-reboot-cause.txt" 
    log.Info("DbToYang_sys_infra_state_reboot_cause_xfmr cmd: ", cmd)
    host_output = HostQuery("infra_host.exec_cmd", cmd)
    if host_output.Err != nil {
           log.Errorf("rpc_infra_reboot_cb: host Query FAILED: err=%v", host_output.Err)
           result["reboot-cause"] = "FAILED: host query" 
           return result, err
    }

    output, _ := host_output.Body[1].(string)

    if len(output) > 0 {
        result["reboot-cause"] = &output 
    } else {
        result["reboot-cause"] = "Unable to determine cause of previous reboot" 
    }

    return result, err

}


var rpc_infra_reboot_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_reboot_cb body: ", string(body))

        var err error
        var operand struct {
                Input struct {
                        Param string `json:"param"`
                } `json:"sonic-system-infra:input"`
        }


        err = json.Unmarshal(body, &operand)
        if err != nil {
                log.Errorf("rpc_infra_reboot_cb: Failed to parse rpc input; err=%v", err)
                return nil,tlerr.InvalidArgs("Invalid rpc input")
        }

        var exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"sonic-system-infra:output"`
        }

        //Don't allow warm-reboot when spanning-tree is enabled
        if(strings.Contains(operand.Input.Param, "warm-reboot")){
            configDbPtr := dbs[db.ConfigDB]
            var stpGlobalTable *db.TableSpec = &db.TableSpec{Name: STP_GLOBAL_TABLE}
            stpGlobalDbEntry, err := configDbPtr.GetEntry(stpGlobalTable, db.Key{Comp: []string{"GLOBAL"}})
            if err == nil {
                mode := (&stpGlobalDbEntry).Get("mode")
                if(len(mode) != 0){
                    log.Errorf("rpc_infra_reboot_cb: warm-reboot not allowed as spanning-tree is enabled; mode=%s", mode)
                    exec.Output.Result = "Error: warm-reboot not allowed as spanning-tree is enabled"   
                    result, err := json.Marshal(&exec)
                    return result, err
                }
            }
        }

        log.Info("rpc_infra_reboot_cb cmd: ", operand.Input.Param)
        host_output := HostQuery("infra_host.exec_cmd", operand.Input.Param)
        if host_output.Err != nil {
              log.Errorf("rpc_infra_reboot_cb: host Query failed: err=%v", host_output.Err)
              return nil, host_output.Err
        }

        var output string
        output, _ = host_output.Body[1].(string)

        exec.Output.Result = output   
        result, err := json.Marshal(&exec)

        return result, err
}

var rpc_infra_config_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_config_cb body:", string(body))

        var err error
        var operand struct {
                Input struct {
                        Param string `json:"param"`
                } `json:"sonic-system-infra:input"`
        }

        var exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"sonic-system-infra:output"`
        }

        err = json.Unmarshal(body, &operand)
        if err != nil {
                log.Errorf("rpc_infra_reboot_cb: Failed to parse rpc input; err=%v", err)

                exec.Output.Result = "[FAILED] Invalid rpc input" 
                result, err := json.Marshal(&exec)

                return result, err
        }
        cmd := "config " + operand.Input.Param + " -y"
        log.Info("rpc_infra_config_cb cmd: ", cmd)

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              log.Errorf("rpc_infra_reboot_cb: host Query failed: err=%v", host_output.Err)
              exec.Output.Result = "[FAILED] host query" 
              result, err := json.Marshal(&exec)
              return result, err
        }

        var output string
        output, _ = host_output.Body[1].(string)

        exec.Output.Result = output
        result, err := json.Marshal(&exec)

        return result, err
}

