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
        var out_list []string
        var exec_cmd_list []string
        log.Info("rpc_tpcm_install_cb body:", string(body))

        var result struct {
                Output struct {
                        Status int32 `json:"status"`
                        Status_detail []string`json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }

        var operand struct {
                Input struct {
                     DockerName string `json:"docker-name"`
                     ImageSource string `json:"image-source"`
                     ImageName string `json:"image-name"`
                     RemoteServer string `json:"remote-server"`
                     UserName string `json:"username"`
                     PassWord string `json:"password"`
                     Args  string `json:"args"`
                } `json:"openconfig-system-ext:input"`
        }

       err := json.Unmarshal(body, &operand)
       if err != nil {
                result.Output.Status = 1
                out_list = append(out_list, "[FAILED] unmarshal input: " + err.Error())
                result.Output.Status_detail  = out_list
                return json.Marshal(&result)
       }
       dockerName := operand.Input.DockerName
       imageSource := operand.Input.ImageSource
       imageName := operand.Input.ImageName
       remoteServer := operand.Input.RemoteServer
       userName := operand.Input.UserName
       passWord := operand.Input.PassWord
       args := operand.Input.Args

       exec_cmd_list = append(exec_cmd_list, "tpcm install")
       exec_cmd_list = append(exec_cmd_list,  "name " + dockerName)
       if imageSource == "scp" || imageSource == "sftp" {
               exec_cmd_list = append(exec_cmd_list,  imageSource)
               exec_cmd_list = append(exec_cmd_list,  remoteServer)
               exec_cmd_list = append(exec_cmd_list,  "--username " + userName)
               exec_cmd_list = append(exec_cmd_list,  "--password " + passWord)
               exec_cmd_list = append(exec_cmd_list,  "--filename " + imageName)
       } else {
               exec_cmd_list = append(exec_cmd_list,  imageSource)
               exec_cmd_list = append(exec_cmd_list,  imageName)
       } 
       if (args != "string") && (len(args) > 0)  {
               if strings.Contains(args, "\"") {
                   exec_cmd_list = append(exec_cmd_list,  "--args " + args )
               } else {
                   exec_cmd_list = append(exec_cmd_list,  "--args '" + args + "'")
               }
       }

        exec_cmd_list = append(exec_cmd_list,  "-y")
        exec_cmd := strings.Join(exec_cmd_list," ")

    return tpcm_image_operation(exec_cmd)
}

var rpc_tpcm_uninstall_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        var out_list []string
        var exec_cmd_list []string
        log.Info("rpc_tpcm_uninstall_cb body:", string(body))
        var result struct {
                Output struct {
                        Status int32 `json:"status"`
                        Status_detail []string`json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }
        var operand struct {
                Input struct {
                     CleanData string `json:"clean-data"`
                     DockerName string `json:"docker-name"`
               } `json:"openconfig-system-ext:input"`
       }

       err := json.Unmarshal(body, &operand)
       if err != nil {
                result.Output.Status = 1
                out_list = append(out_list, "[FAILED] unmarshal input: " + err.Error())
                result.Output.Status_detail  = out_list
                return json.Marshal(&result)
       }

       cleanData := strings.TrimSpace(operand.Input.CleanData)
       dockerName := operand.Input.DockerName

       exec_cmd_list = append(exec_cmd_list, "tpcm uninstall")
       exec_cmd_list = append(exec_cmd_list,  "name " + dockerName)
       if cleanData != "string" && len(cleanData) > 0 && cleanData == "yes" {
               exec_cmd_list = append(exec_cmd_list,  "--clean_data ")
       }

        exec_cmd_list = append(exec_cmd_list,  "-y")
        exec_cmd := strings.Join(exec_cmd_list," ")

       return tpcm_image_operation(exec_cmd)
}

var rpc_tpcm_upgrade_cb RpcCallpoint = func(body []byte, dbs [db.MaxDB]*db.DB) ([]byte, error) {
        var out_list []string
        var exec_cmd_list []string
        log.Info("rpc_tpcm_upgrade_cb body:", string(body))
        var result struct {
                Output struct {
                        Status int32 `json:"status"`
                        Status_detail []string`json:"status-detail"`
                } `json:"openconfig-system-ext:output"`
        }
        var operand struct {
                Input struct {
                     DockerName string `json:"docker-name"`
                     ImageSource string `json:"image-source"`
                     ImageName string `json:"image-name"`
                     RemoteServer string `json:"remote-server"`
                     UserName string `json:"username"`
                     PassWord string `json:"password"`
                     SkipDataMigration string `json:"skip-data-migration"`
                     Args  string `json:"args"`
                } `json:"openconfig-system-ext:input"`
        }
       err := json.Unmarshal(body, &operand)
       if err != nil {
                result.Output.Status = 1
                out_list = append(out_list, "[FAILED] unmarshal input: " + err.Error())
                result.Output.Status_detail  = out_list
                return json.Marshal(&result)
       }
       dockerName := operand.Input.DockerName
       imageSource := operand.Input.ImageSource
       imageName := operand.Input.ImageName
       remoteServer := operand.Input.RemoteServer
       userName := operand.Input.UserName
       passWord := operand.Input.PassWord
       skipDataMigration := strings.TrimSpace(operand.Input.SkipDataMigration)
       args := operand.Input.Args

       exec_cmd_list = append(exec_cmd_list, "tpcm upgrade")
       exec_cmd_list = append(exec_cmd_list,  "name " + dockerName)
       if  imageSource == "scp" || imageSource == "sftp"  {
               exec_cmd_list = append(exec_cmd_list,  imageSource)
               exec_cmd_list = append(exec_cmd_list,  remoteServer)
               exec_cmd_list = append(exec_cmd_list,  "--username " + userName)
               exec_cmd_list = append(exec_cmd_list,  "--password " + passWord)
               exec_cmd_list = append(exec_cmd_list,  "--filename " + imageName)
       } else {
               exec_cmd_list = append(exec_cmd_list,  imageSource)
               exec_cmd_list = append(exec_cmd_list,  imageName)
       } 
       if skipDataMigration != "string" && len(skipDataMigration) > 0 && skipDataMigration =="yes" {
               exec_cmd_list = append(exec_cmd_list,  "--skip_data_migration ")
       }
       if (args != "string") && (len(args) > 0)  {
               if strings.Contains(args, "\"") {
                   exec_cmd_list = append(exec_cmd_list,  "--args " + args )
               } else {
                   exec_cmd_list = append(exec_cmd_list,  "--args '" + args + "'")
               }
       }

        exec_cmd_list = append(exec_cmd_list,  "-y")
        exec_cmd := strings.Join(exec_cmd_list," ")
  
        return tpcm_image_operation(exec_cmd)
}

func tpcm_image_operation(exec_cmd string) ([]byte, error) {

   log.Info("tpcm_image_operation cmd:", exec_cmd)
        var out_list []string

   	var result struct {
    		Output struct {
          		Status int32 `json:"status"`
          		Status_detail []string`json:"status-detail"`
      		} `json:"openconfig-system-ext:output"`
    	}


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

        if (failure_status || !success_status) {
           out_list = strings.Split(_output,"\n")
        } else { 
           _out_list := strings.Split(_output,"\n")
           for index, each := range _out_list {
                 i := strings.Index(each, "SUCCESS")
                 if i != -1 {
                     out_list = append(out_list, _out_list[index])
                 }
           }
        }

        result.Output.Status = 0
        result.Output.Status_detail  = out_list 
        return json.Marshal(&result)
}



