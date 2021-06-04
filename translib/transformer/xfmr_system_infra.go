package transformer

import (
    "fmt"
    "strings"
    log "github.com/golang/glog"
    "github.com/shirou/gopsutil/host"
    "encoding/json"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "io/ioutil"
    "os"
    "unicode"
)

func init () {
    XlateFuncBind("DbToYang_sys_infra_state_clock_xfmr", DbToYang_sys_infra_state_clock_xfmr)
    XlateFuncBind("DbToYang_sys_infra_state_uptime_xfmr", DbToYang_sys_infra_state_uptime_xfmr)
    XlateFuncBind("DbToYang_sys_infra_state_reboot_cause_xfmr", DbToYang_sys_infra_state_reboot_cause_xfmr)
    XlateFuncBind("DbToYang_sys_infra_state_show_user_list_xfmr", DbToYang_sys_infra_state_show_user_list_xfmr)
    XlateFuncBind("rpc_infra_reboot_cb",  rpc_infra_reboot_cb)
    XlateFuncBind("rpc_infra_config_cb",  rpc_infra_config_cb)
    XlateFuncBind("rpc_infra_show_sys_log_cb",  rpc_infra_show_sys_log_cb)
    XlateFuncBind("rpc_infra_clear_sys_log_cb",  rpc_infra_clear_sys_log_cb)
    XlateFuncBind("rpc_infra_sys_log_count_cb",  rpc_infra_sys_log_count_cb)
    XlateFuncBind("rpc_infra_set_loglevel_severity_cb",  rpc_infra_set_loglevel_severity_cb)
    XlateFuncBind("rpc_infra_get_loglevel_severity_cb",  rpc_infra_get_loglevel_severity_cb)
    XlateFuncBind("rpc_infra_show_sys_in_memory_log_cb",  rpc_infra_show_sys_in_memory_log_cb)
    XlateFuncBind("rpc_infra_sys_in_memory_log_count_cb",  rpc_infra_sys_in_memory_log_count_cb)
    XlateFuncBind("rpc_infra_logger_cb",  rpc_infra_logger_cb)
}


var DbToYang_sys_infra_state_clock_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
        log.Info("DbToYang_sys_infra_state_clock_xfmr uri: ", inParams.uri)
        var output string

        rmap := make(map[string]interface{})

        cmd := "show clock"

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              log.Errorf("rpc_infra_clear_sys_log: host Query failed: err=%v", host_output.Err)
              rmap["clock"]="[FAILED] host query"
              return rmap, nil 
        }

        s, _ := host_output.Body[1].(string)
        output = strings.TrimSpace(s)

        rmap["clock"]=&output
        log.Info("DbToYang_sys_infra_state_clock_xfmr clock: ", output)
        log.Info("DbToYang_sys_infra_state_clock_xfmr ramp: ", rmap)

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

var DbToYang_sys_infra_state_show_user_list_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    var err error
    var host_output HostResult
    var out_list []string

    result := make(map[string]interface{})

    cmd := "show users"
    log.Info("DbToYang_sys_infra_state_show_user_list_xfmr cmd:", cmd)
    host_output = HostQuery("infra_host.exec_cmd", cmd)
    if host_output.Err != nil {
              retErr := tlerr.New("Host Query [FAILED]: %v", host_output.Err)
              return nil, retErr
    }

    output, _ := host_output.Body[1].(string)
    log.Info("DbToYang_sys_infra_state_show_user_list_xfmr: %s", output)
    _output := strings.TrimLeft(output,"\n")
    out_list = strings.Split(_output,"\n")

    result["show-user-list"] = out_list

    return result, err

}

var rpc_infra_reboot_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_reboot_cb body: ", string(body))

        var err error
        var operand struct {
                Input struct {
                        Param string `json:"param"`
                } `json:"openconfig-system-ext:input"`
        }


        err = json.Unmarshal(body, &operand)
        if err != nil {
                log.Errorf("rpc_infra_reboot_cb: Failed to parse rpc input; err=%v", err)
                return nil,tlerr.InvalidArgs("Invalid rpc input")
        }

        var exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"openconfig-system-ext:output"`
        }

        //allow only reboot, warm-reboot, or fast-reboot
        if(!strings.Contains(operand.Input.Param, "warm-reboot") && 
           !strings.Contains(operand.Input.Param, "reboot") && 
           !strings.Contains(operand.Input.Param, "fast-reboot")) {
            return nil,tlerr.InvalidArgs("Invalid command")
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

var rpc_infra_show_sys_log_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_show_sys_log body:", string(body))

        var err error
        var HOST_MGM_DIR="/tmp/"
        var MGM_SYSLOG="/mnt/tmp/syslog"
        var MGM_SYSLOG1="/mnt/tmp/syslog.1"
        var HOST_SYSLOG="/var/log/syslog"
        var HOST_SYSLOG1="/var/log/syslog.1"
        var out_list []string
        var output string

        var operand struct {
                Input struct {
                        Param int `json:"num-lines"`
                } `json:"openconfig-system-ext:input"`
        }

        var exec struct {
                Output struct {
                        Result []string `json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }

        err = json.Unmarshal(body, &operand)
        if err != nil {
              out_list = append(out_list, "[FAILED] to umarshal input data")
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }
        MAX_NUM_LINES := 65535
        num_lines := operand.Input.Param
        if num_lines < 0 || num_lines > MAX_NUM_LINES {
              msg := fmt.Sprintf("[FAILED] invalid number [1-%d]", MAX_NUM_LINES)
              out_list = append(out_list, msg)
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }

        if _, err := os.Stat(MGM_SYSLOG1); err == nil {
            os.Remove(MGM_SYSLOG)
            os.Remove(MGM_SYSLOG1)
        }

        cmd := "cp -f " + HOST_SYSLOG + " " + HOST_SYSLOG1 +" " + HOST_MGM_DIR

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              msg := fmt.Sprintf("[FAILED] host Query failed: err=%v", host_output.Err) 
              log.Errorf("rpc_infra_show_sys_log: %s", msg)
              out_list = append(out_list, msg)
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }

        if _, err := os.Stat(MGM_SYSLOG); !os.IsNotExist(err) {
           syslog, err := ioutil.ReadFile(MGM_SYSLOG)
           if err != nil {
                out_list = append(out_list, "[FAILED] to read syslog")
                exec.Output.Result = out_list
                result, err := json.Marshal(&exec)
                return result, err
           } else {
              if _, err := os.Stat(MGM_SYSLOG1); !os.IsNotExist(err) {
                   syslog1, err := ioutil.ReadFile(MGM_SYSLOG1)
                   if err != nil {
                        log.Errorf("rpc_infra_show_sys_log: Failed to read %v err: %v", MGM_SYSLOG1, err)
                        output = string(syslog)
                   } else {
                        output = string(syslog1) + string(syslog)
                   }
              } else {
                   output = string(syslog)
              }
              _output := strings.TrimSuffix(output,"\n")
              out_list = strings.Split(_output,"\n")
              total := len(out_list)

              if num_lines > 0 && num_lines < total {
                    exec.Output.Result = out_list[total-num_lines:]
              } else {
                    exec.Output.Result = out_list
              }
           }
        } else {
             out_list = append(out_list, "[FAILED] to get syslog")
             exec.Output.Result = out_list
             result, err := json.Marshal(&exec)
             return result, err
        }
        result, err := json.Marshal(&exec)
        return result, err
}

var rpc_infra_clear_sys_log_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_clear_sys_log body:", string(body))
        var err error
        var exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"openconfig-system-ext:output"`
        }

        cmd := "sonic-clear logging"
        log.Info("rpc_infra_clear_sys_log cmd: ", cmd)

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              log.Errorf("rpc_infra_clear_sys_log: host Query failed: err=%v", host_output.Err)
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


var rpc_infra_sys_log_count_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        var err error
        var HOST_SYSLOG="/var/log/syslog"
        var HOST_SYSLOG1="/var/log/syslog.1"

        var _exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"openconfig-system-ext:output"`
        }

    	cmd := fmt.Sprintf(" wc -l %s %s | grep total ",HOST_SYSLOG1, HOST_SYSLOG)

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              msg := fmt.Sprintf("[FAILED] host Query failed: err=%v", host_output.Err) 
              _exec.Output.Result = msg 
              result, err := json.Marshal(&_exec)
              return result, err
        }

        var output string
        var _array []string
        output, _ = host_output.Body[1].(string)
        _output := strings.TrimSpace(output)
        _array = strings.Fields(_output)
        if (len(_array) > 1) {
           _exec.Output.Result = _array[len(_array)-2]
        } else {
           log.Errorf("rpc_infra_sys_log_count: [FAILED]: ", _array)
           _exec.Output.Result = "[FAILED]" 
        }
        result, err := json.Marshal(&_exec)
        return result, err
}

var rpc_infra_set_loglevel_severity_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        var err error
        var exec_cmd string
        var operand struct {
                Input struct {
                        LogLevel string `json:"loglevel"`
                        Component string `json:"component-name"`
                        IsSAI bool `json:"sai-component"`
                } `json:"openconfig-system-ext:input"`
        }
        var exec struct {
                Output struct {
                        Result []string `json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }
        err = json.Unmarshal(body, &operand)
        if err != nil {
              exec.Output.Result = append(exec.Output.Result, "[FAILED] to umarshal input data")
              result, err := json.Marshal(&exec)
              return result, err
        }
        loglevel := operand.Input.LogLevel
        component := operand.Input.Component
        is_sai := operand.Input.IsSAI
        if component != "string" && len(component) > 0 && loglevel != "string" && len(loglevel) > 0{
             if component == "all" {
                exec_cmd = "swssloglevel -l " + loglevel + " -a"  
             } else {
                exec_cmd = "swssloglevel -l " + loglevel + " -c " + component  
             }
        }
        if is_sai {
              exec_cmd = exec_cmd + " -s"
        } 

     return loglevel_severity_operation("config", exec_cmd)
}

var rpc_infra_get_loglevel_severity_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
     exec_cmd := "swssloglevel -p"
     return loglevel_severity_operation("display", exec_cmd)

}


func loglevel_severity_operation(ops_cmd string, exec_cmd string) ([]byte, error) {

        log.Info("loglevel_severity_operation cmd:", exec_cmd)

        var err error
        var out_list []string


        var exec struct {
                Output struct {
                        Result []string `json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }

        host_output := HostQuery("infra_host.exec_cmd", exec_cmd)
        if host_output.Err != nil {
              msg := fmt.Sprintf("[FAILED] host Query failed: err=%v", host_output.Err) 
              out_list = append(out_list, msg)
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }

        var output string
        output, _ = host_output.Body[1].(string)
        _output := strings.TrimLeft(output,"\n")
        if len(_output) > 0 {
              _out_list := strings.Split(_output,"\n")
            if ops_cmd == "display" { 
               out_list = _out_list
            } else {
               out_list = append(out_list, _out_list[0])
            }
        } else {
           out_list = append(out_list, "SUCCESS")
        } 
        exec.Output.Result = out_list
        result, err := json.Marshal(&exec)
        return result, err
}

var rpc_infra_show_sys_in_memory_log_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_show_sys_in_memory_log body:", string(body))

        var err error
        var out_list []string
        var output string

        var operand struct {
                Input struct {
                        Param int `json:"num-lines"`
                } `json:"openconfig-system-ext:input"`
        }

        var exec struct {
                Output struct {
                        Result []string `json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }

        err = json.Unmarshal(body, &operand)
        if err != nil {
              out_list = append(out_list, "[FAILED] to umarshal input data")
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }
        MAX_NUM_LINES := 65535
        num_lines := operand.Input.Param
        if num_lines < 0 || num_lines > MAX_NUM_LINES {
              msg := fmt.Sprintf("[FAILED] invalid number [1-%d]", MAX_NUM_LINES)
              out_list = append(out_list, msg)
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }

        cmd := "show in-memory-logging"

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              msg := fmt.Sprintf("[FAILED] host Query failed: err=%v", host_output.Err) 
              log.Errorf("rpc_infra_show_sys_log: %s", msg)
              out_list = append(out_list, msg)
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }

        output, _ = host_output.Body[1].(string)
        _output := strings.Map(func(r rune) rune {
	        if r > unicode.MaxASCII {
		        return -1
	         }
	         return r
        } , output)

        out_list = strings.Split(_output,"\n")
        total := len(out_list)
        if num_lines > 0 && num_lines < total {
              exec.Output.Result = out_list[total-num_lines:]
        } else {
              exec.Output.Result = out_list
        }
        result, err := json.Marshal(&exec)
        return result, err
}
var rpc_infra_sys_in_memory_log_count_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_show_sys_in_memory_log_count_cb body:", string(body))
        var err error
        var output string
        var out_list []string

        var _exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"openconfig-system-ext:output"`
        }

    	cmd := "show in-memory-logging"

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              msg := fmt.Sprintf("[FAILED] host Query failed: err=%v", host_output.Err) 
              _exec.Output.Result = msg 
              result, err := json.Marshal(&_exec)
              return result, err
        }

        output, _ = host_output.Body[1].(string)
        s := strings.TrimSpace(output)
        out_list = strings.Split(s,"\n")
        msg := fmt.Sprintf("%d", len(out_list)) 
        _exec.Output.Result =  msg 
        result, err := json.Marshal(&_exec)
        return result, err
}

var rpc_infra_logger_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_infra_logger_cb body:", string(body))
        var err error
        var operand struct {
                Input struct {
                        Messages string `json:"messages"`
                } `json:"openconfig-system-ext:input"`
        }

        err = json.Unmarshal(body, &operand)
        if err != nil {
                log.Errorf("rpc_infra_reboot_cb: Failed to parse rpc input; err=%v", err)
                return nil,tlerr.InvalidArgs("Invalid rpc input")
        }

        var exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"openconfig-system-ext:output"`
        }

       cmd := "logger " + operand.Input.Messages 

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              log.Errorf("rpc_infra_logger_cb: host Query failed: err=%v", host_output.Err)
              exec.Output.Result = "[FAILED] host query"
              result, err := json.Marshal(&exec)
              return result, err
        }

        var output string
        output, _ = host_output.Body[1].(string)
        if len(output) > 0 {
           exec.Output.Result = output
        } else {
           exec.Output.Result = "SUCCESS" 
        }
        result, err := json.Marshal(&exec)
        return result, err
}



