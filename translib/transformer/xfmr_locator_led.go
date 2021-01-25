package transformer

import (
    "encoding/json"
    "fmt"
    "strings"
    log "github.com/golang/glog"
    "github.com/Azure/sonic-mgmt-common/translib/db"
)

func init () {
    XlateFuncBind("rpc_locator_led_chassis_on_cb",  rpc_locator_led_chassis_on_cb)
    XlateFuncBind("rpc_locator_led_chassis_off_cb",  rpc_locator_led_chassis_off_cb)
    XlateFuncBind("rpc_show_locator_led_chassis_cb",  rpc_show_locator_led_chassis_cb)
}

var rpc_locator_led_chassis_on_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_locator_led_chassis_on_cb body: ", string(body))
        var err error
        var exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"openconfig-system-ext:output"`
        }

        cmd := "locator-led chassis on"

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

var rpc_locator_led_chassis_off_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_locator_led_chassis_off_cb body:", string(body))

        var err error
        var exec struct {
                Output struct {
                        Result string `json:"result"`
                } `json:"openconfig-system-ext:output"`
        }

        cmd := "locator-led chassis off"

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

var rpc_show_locator_led_chassis_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        log.Info("rpc_show_locator_led_chassis_cb body:", string(body))

        var err error
        var out_list []string

        var exec struct {
                Output struct {
                        Result []string `json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }

        cmd := "show locator-led chassis "

        host_output := HostQuery("infra_host.exec_cmd", cmd)
        if host_output.Err != nil {
              msg := fmt.Sprintf("[FAILED] host Query failed: err=%v", host_output.Err)
              out_list = append(out_list, msg)
              exec.Output.Result = out_list
              result, err := json.Marshal(&exec)
              return result, err
        }

        var output string
        output, _ = host_output.Body[1].(string)
        s := strings.TrimSpace(output)
        out_list = strings.Split(s,"\n")

        exec.Output.Result = out_list
        result, err := json.Marshal(&exec)
        return result, err
}

