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
   "encoding/json"
   "github.com/Azure/sonic-mgmt-common/translib/db"
   log "github.com/golang/glog"
   "strings"

)

func init() {
  XlateFuncBind("DbToYang_sys_tpcm_state_image_list_xfmr", DbToYang_sys_tpcm_state_image_list_xfmr)
  XlateFuncBind("rpc_tpcm_install_cb", rpc_tpcm_install_cb)
  XlateFuncBind("rpc_tpcm_uninstall_cb", rpc_tpcm_uninstall_cb)
  XlateFuncBind("rpc_tpcm_upgrade_cb", rpc_tpcm_upgrade_cb)
}


var DbToYang_sys_tpcm_state_image_list_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    log.Info("DbToYang_sys_tpcm_state_image_list_xfmr")

    var err error
    var host_output HostResult
    var out_list []string

    result := make(map[string]interface{})

    cmd := "tpcm list"
    host_output = HostQuery("infra_host.exec_cmd", cmd)
    if host_output.Err != nil {
           log.Errorf("rpc_infra_reboot_cb: host Query FAILED: err=%v", host_output.Err)
           out_list  = append(out_list, host_output.Err.Error()) 
           out_list  = append(out_list, "[ FAILED ] host query") 
           result["tpcm-image-list"] = out_list
           return result, err
    }

    output, _ := host_output.Body[1].(string)
    log.Info("DbToYang_sys_tpcm_state_image_list_xfmr: %s", output)
    _output := strings.TrimLeft(output,"\n")
    out_list = strings.Split(_output,"\n")

    result["tpcm-image-list"] = out_list

    return result, err

}


var rpc_tpcm_install_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    return tpcm_image_operation("install", body)
}

var rpc_tpcm_uninstall_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    return tpcm_image_operation("uninstall", body)
}

var rpc_tpcm_upgrade_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
    return tpcm_image_operation("upgrade", body)
}

func tpcm_image_operation(command string, body []byte) ([]byte, error) {

   log.Info("tpcm_image_operation cmd:", command, " body:" ,string(body))
        var err error
        var exec_cmd_list []string
        var options string
        var dockerName string
        var imageName string
        var out_list []string

        if command == "uninstall" {
            var operand struct {
                Input struct {
                     Options string `json:"options"`
                     DockerName string `json:"docker-name"`
               } `json:"sonic-tpcm:input"`
            }

            err = json.Unmarshal(body, &operand)
            if err == nil {
               options = operand.Input.Options
               dockerName = operand.Input.DockerName
            }
        } else {
            var operand struct {
                Input struct {
                     Options string `json:"options"`
                     DockerName string `json:"docker-name"`
                     ImageName string `json:"image-name"`
                } `json:"sonic-tpcm:input"`
            }
            err = json.Unmarshal(body, &operand)
            if err == nil {
               options = operand.Input.Options
               dockerName = operand.Input.DockerName
               imageName = operand.Input.ImageName
            }

        }

   	var result struct {
    		Output struct {
          		Status int32 `json:"status"`
          		Status_detail []string`json:"status-detail"`
      		} `json:"sonic-tpcm:output"`
    	}

        if err != nil {
                log.Errorf("tpcm_image_operation: FAILED to parse rpc input; err=%v", err)
                result.Output.Status = 1
                out_list = append(out_list, err.Error())
                out_list = append(out_list, "FAILED")
                result.Output.Status_detail  = out_list 
                return json.Marshal(&result)

        }

        exec_cmd_list = append(exec_cmd_list, "tpcm " + command)
        if (dockerName != "string") {
           exec_cmd_list = append(exec_cmd_list,  dockerName)
        }

        if ( command != "uninstall" && imageName != "string") {
              exec_cmd_list = append(exec_cmd_list,  imageName)
        }

        if (options != "string") {
              log.Info("tpcm_image_operation options:", options)
              exec_cmd_list = append(exec_cmd_list, options)
        }
        exec_cmd_list = append(exec_cmd_list,  "-y")
        exec_cmd := strings.Join(exec_cmd_list," ")

        log.Info("tpcm_image_operation exec_cmd:", exec_cmd)

        host_output := HostQuery("infra_host.exec_cmd", exec_cmd)
        if host_output.Err != nil {
              log.Errorf("tpcm_image_operation: host Query FAILED: err=%v", host_output.Err)
              result.Output.Status = 1
              out_list  = append(out_list, host_output.Err.Error()) 
              out_list  = append(out_list, "[ FAILED ] host query") 
              result.Output.Status_detail  = out_list 
              return json.Marshal(&result)
        }

        var output string
        output, _ = host_output.Body[1].(string)
        _output := strings.TrimLeft(output,"\n")
        failure_status :=  strings.Contains(_output, "FAILED")
        success_status :=  strings.Contains(_output, "SUCCESS")

        log.Info("tpcm_image_operation output:", _output)
        if (options == "--help" || failure_status == true || success_status != true) {
           log.Info("tpcm_image_operation Dispaly all")
           out_list = strings.Split(_output,"\n")
        } else { 
           _out_list := strings.Split(_output,"\n")
           for index, each := range _out_list {
                 log.Info("tpcm_image_operation each:", each)
                 i := strings.Index(each, "SUCCESS")
                 if i != -1 {
                     out_list = append(out_list, _out_list[index])
                 }
           }
        }

        result.Output.Status = 0
        result.Output.Status_detail  = out_list 
        log.Info("tpcm_image_operation exec_cmd output:", out_list)
        return json.Marshal(&result)
}



