package transformer

import (
    "github.com/Azure/sonic-mgmt-common/translib/ocbinds"
    "github.com/Azure/sonic-mgmt-common/translib/db"
    "time"
    "syscall"
    "strconv"
    "fmt"
    "strings"
    "errors"
    log "github.com/golang/glog"
    ygot "github.com/openconfig/ygot/ygot"
    "math/rand"
    "github.com/tredoe/osutil/user/crypt/sha512_crypt"
    "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

const (
    HOST_TBL = "HOST_STATS"
    MEM_TBL = "MEM_STATS"
    CPU_TBL = "CPU_STATS"
    PROC_TBL = "PROCESS_STATS"
    SYSMEM_KEY = "SYS_MEM"
    HOSTNAME_KEY = "HOSTNAME"
    CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func init () {
    XlateFuncBind("DbToYang_sys_state_xfmr", DbToYang_sys_state_xfmr)
    XlateFuncBind("DbToYang_sys_memory_xfmr", DbToYang_sys_memory_xfmr)
    XlateFuncBind("DbToYang_sys_cpus_xfmr", DbToYang_sys_cpus_xfmr)
    XlateFuncBind("DbToYang_sys_procs_xfmr", DbToYang_sys_procs_xfmr)
    XlateFuncBind("YangToDb_sys_aaa_auth_xfmr", YangToDb_sys_aaa_auth_xfmr)
    XlateFuncBind("YangToDb_sys_config_key_xfmr", YangToDb_sys_config_key_xfmr)
    XlateFuncBind("DbToYang_sys_config_key_xfmr", DbToYang_sys_config_key_xfmr)
    XlateFuncBind("YangToDb_global_dns_key_xfmr", YangToDb_global_dns_key_xfmr)
    XlateFuncBind("DbToYang_global_dns_key_xfmr", DbToYang_global_dns_key_xfmr)
    XlateFuncBind("YangToDb_server_dns_key_xfmr", YangToDb_server_dns_key_xfmr)
    XlateFuncBind("DbToYang_server_dns_key_xfmr", DbToYang_server_dns_key_xfmr)
    XlateFuncBind("YangToDb_server_dns_field_xfmr", YangToDb_server_dns_field_xfmr)
    XlateFuncBind("DbToYang_server_dns_field_xfmr", DbToYang_server_dns_field_xfmr)
    XlateFuncBind("Subscribe_sys_aaa_auth_xfmr", Subscribe_sys_aaa_auth_xfmr)
}

type SysMem struct {
    Total          uint64
    Used           uint64
    Free           uint64
}

type Cpu struct {
    User     int64
    System   int64
    Idle     int64
}

type Proc struct {
    Cmd        string
    Start      uint64
    User       uint64
    System     uint64
    Mem        uint64
    Cputil     float32
    Memutil    float32
}

type CpuState struct {
    user    uint8
    system  uint8
    idle    uint8
}

type ProcessState struct {
    Args                []string
    CpuUsageSystem      uint64
    CpuUsageUser        uint64
    CpuUtilization      uint8
    MemoryUsage         uint64
    MemoryUtilization   uint8
    Name                string
    Pid                 uint64
    StartTime           uint64
    Uptime              uint64
}

func getAppRootObject(inParams XfmrParams) (*ocbinds.OpenconfigSystem_System) {
    deviceObj := (*inParams.ygRoot).(*ocbinds.Device)
    return deviceObj.System
}

func getSystemState (hostname *string, sysstate *ocbinds.OpenconfigSystem_System_State) () {
    log.Infof("getSystemState Entry")

    crtime := time.Now().Format(time.RFC3339) + "+00:00"

    sysstate.Hostname = hostname
    sysstate.CurrentDatetime = &crtime;
    sysinfo := syscall.Sysinfo_t{}

    sys_err := syscall.Sysinfo(&sysinfo)
    if sys_err == nil {
        boot_time := uint64 (time.Now().Unix() - sysinfo.Uptime)
        sysstate.BootTime = &boot_time
    }
}

func getHostnameFromDb (d *db.DB) (*string, error) {
    var err error
    var hostname string

    hostTbl, err := d.GetTable(&db.TableSpec{Name: HOST_TBL})
    if err != nil {
        log.Info("Can't get table: ", HOST_TBL)
        return &hostname, err
    }

    nameEntry, err := hostTbl.GetEntry(db.Key{Comp: []string{HOSTNAME_KEY}})
    if err != nil {
        log.Info("Can't get entry with key: ", HOSTNAME_KEY)
        return &hostname, err
    }
    hostname = nameEntry.Get("name")
    return &hostname, err
}

var YangToDb_sys_config_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
       log.Info("YangToDb_sys_config_key_xfmr: ", inParams.uri)
       dvKey := "localhost"
       return dvKey, nil
}

var DbToYang_sys_config_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
       rmap := make(map[string]interface{})
       log.Info("DbToYang_sys_config_key_xfmr root, uri: ", inParams.ygRoot, inParams.uri)
       return rmap, nil
}

var DbToYang_sys_state_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    sysObj := getAppRootObject(inParams)

    hostname, err := getHostnameFromDb(inParams.dbs[db.StateDB])
    if err != nil {
        log.Infof("getHostnameFromDb failed")
        return err
    }
    ygot.BuildEmptyTree(sysObj)
    getSystemState(hostname, sysObj.State)
    return err;
}

func getSysMemFromDb (d *db.DB) (*SysMem, error) {
    var err error
    var memInfo SysMem

    memTbl, err := d.GetTable(&db.TableSpec{Name: MEM_TBL})
    if err != nil {
        log.Info("Can't get table: ", MEM_TBL)
        return &memInfo, err
    }

    memEntry, err := memTbl.GetEntry(db.Key{Comp: []string{SYSMEM_KEY}})
    if err != nil {
        log.Info("Can't get entry with key: ", SYSMEM_KEY)
        return &memInfo, err
    }

    memInfo.Total, _ = strconv.ParseUint(memEntry.Get("total"), 10, 64)
    memInfo.Used, _ = strconv.ParseUint(memEntry.Get("used"), 10, 64)
    memInfo.Free, _ = strconv.ParseUint(memEntry.Get("free"), 10, 64)

    return &memInfo, err
}

func getSystemMemory (meminfo *SysMem, sysmem *ocbinds.OpenconfigSystem_System_Memory_State) () {
    log.Infof("getSystemMemory Entry")

    sysmem.Physical = &meminfo.Total
    sysmem.Reserved = &meminfo.Used
}

var DbToYang_sys_memory_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    sysObj := getAppRootObject(inParams)

    meminfo, err := getSysMemFromDb(inParams.dbs[db.StateDB])
    if err != nil {
        log.Infof("getSysMemFromDb failed")
        return err
    }
    ygot.BuildEmptyTree(sysObj)

    sysObj.Memory.State = &ocbinds.OpenconfigSystem_System_Memory_State{}

    getSystemMemory(meminfo, sysObj.Memory.State)
    return err;
}

func getSystemCpu (idx int, cpuCnt int, cpu Cpu, syscpu *ocbinds.OpenconfigSystem_System_Cpus_Cpu) {
    log.Infof("getSystemCpu Entry idx ", idx)

    sysinfo := syscall.Sysinfo_t{}
    sys_err := syscall.Sysinfo(&sysinfo)
    if sys_err != nil {
        log.Infof("syscall.Sysinfo failed.")
    }
    var cpucur CpuState
    if idx == 0 {
        cpucur.user = uint8((cpu.User/int64(cpuCnt))/sysinfo.Uptime)
        cpucur.system = uint8((cpu.System/int64(cpuCnt))/sysinfo.Uptime)
        cpucur.idle = uint8((cpu.Idle/int64(cpuCnt))/sysinfo.Uptime)
    } else {
        cpucur.user = uint8(cpu.User/sysinfo.Uptime)
        cpucur.system = uint8(cpu.System/sysinfo.Uptime)
        cpucur.idle = uint8(cpu.Idle/sysinfo.Uptime)
    }

    ygot.BuildEmptyTree(syscpu.State)
    syscpu.State.User.Instant = &cpucur.user
    syscpu.State.Kernel.Instant = &cpucur.system
    syscpu.State.Idle.Instant = &cpucur.idle
}

func getSystemCpus (cpuLst []Cpu, syscpus *ocbinds.OpenconfigSystem_System_Cpus) {
    log.Infof("getSystemCpus Entry")

    sysinfo := syscall.Sysinfo_t{}
    sys_err := syscall.Sysinfo(&sysinfo)
    cpuCnt := len(cpuLst) - 1
    if sys_err != nil {
        log.Infof("syscall.Sysinfo failed.")
    }

    for idx, cpu := range cpuLst {
        var index  ocbinds.OpenconfigSystem_System_Cpus_Cpu_State_Index_Union_Uint32
        index.Uint32 = uint32(idx)
        syscpu, err := syscpus.NewCpu(&index)
        if err != nil {
           log.Infof("syscpus.NewCpu failed")
           return
        }
        ygot.BuildEmptyTree(syscpu)
        syscpu.Index = &index
        getSystemCpu(idx, cpuCnt, cpu, syscpu)
    }
}

func getCpusFromDb (d *db.DB) ([]Cpu, error) {
    var err error
    var cpus []Cpu

    cpuTbl, err := d.GetTable(&db.TableSpec{Name: CPU_TBL})
    if err != nil {
        log.Info("Can't get table: ", CPU_TBL)
        return cpus, err
    }

    keys, err := cpuTbl.GetKeys()
    if err != nil {
        log.Info("Can't get CPU keys from table")
        return cpus, err
    }

    cpus = make([]Cpu, len(keys))
    for idx := range keys {
        key := "CPU" + strconv.Itoa(idx)
        cpuEntry, err := cpuTbl.GetEntry(db.Key{Comp: []string{key}})
        if err != nil {
            log.Info("Can't get entry with key: ", key)
            return cpus, err
        }

        cpus[idx].User, _ = strconv.ParseInt(cpuEntry.Get("user"), 10, 64)
        cpus[idx].System, _ = strconv.ParseInt(cpuEntry.Get("sys"), 10, 64)
        cpus[idx].Idle, _ = strconv.ParseInt(cpuEntry.Get("idle"), 10, 64)
    }

    return cpus, err
}

var DbToYang_sys_cpus_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    sysObj := getAppRootObject(inParams)

    cpuLst, err := getCpusFromDb(inParams.dbs[db.StateDB])
    if err != nil {
        log.Infof("getCpusFromDb failed")
        return err
    }
    if sysObj.Cpus == nil {
        ygot.BuildEmptyTree(sysObj)
    }

    path := NewPathInfo(inParams.uri)
    val := path.Vars["index"]
    totalCpu := len(cpuLst)
    if len(val) != 0 {
        cpu, _ := strconv.Atoi(val)
        log.Info("Cpu id: ", cpu, ", max is ", totalCpu)
        if cpu >=0 && cpu < totalCpu {
	//Since key(a pointer) is unknown, there is no way to do a lookup. So looping through a map with only one entry
	    for _, value := range sysObj.Cpus.Cpu {
		ygot.BuildEmptyTree(value)
	        getSystemCpu(cpu, totalCpu - 1, cpuLst[cpu], value)
	    }
        } else {
            log.Info("Cpu id: ", cpu, "is invalid, max is ", totalCpu)
        }
    } else {
        getSystemCpus(cpuLst, sysObj.Cpus)
    }
    return err;
}

func getSystemProcess (proc *Proc, sysproc *ocbinds.OpenconfigSystem_System_Processes_Process, pid uint64) {

    var procstate ProcessState

    ygot.BuildEmptyTree(sysproc)
    procstate.CpuUsageUser = proc.User
    procstate.CpuUsageSystem = proc.System
    procstate.MemoryUsage  = proc.Mem * 1024
    procstate.MemoryUtilization = uint8(proc.Memutil)
    procstate.CpuUtilization  = uint8(proc.Cputil)
    procstate.Name = proc.Cmd
    procstate.Pid = pid
    procstate.StartTime = proc.Start * 1000000000  // ns
    procstate.Uptime = uint64(time.Now().Unix()) - proc.Start

    sysproc.Pid = &procstate.Pid
    sysproc.State.CpuUsageSystem = &procstate.CpuUsageSystem
    sysproc.State.CpuUsageUser = &procstate.CpuUsageUser
    sysproc.State.CpuUtilization =  &procstate.CpuUtilization
    sysproc.State.MemoryUsage = &procstate.MemoryUsage
    sysproc.State.MemoryUtilization = &procstate.MemoryUtilization
    sysproc.State.Name = &procstate.Name
    sysproc.State.Pid = &procstate.Pid
    sysproc.State.StartTime = &procstate.StartTime
    sysproc.State.Uptime = &procstate.Uptime
}

func getSystemProcesses (procs *map[string]Proc, sysprocs *ocbinds.OpenconfigSystem_System_Processes, pid uint64) {
    log.Infof("getSystemProcesses Entry")

    if pid != 0 {
        proc := (*procs)[strconv.Itoa(int(pid))]
        sysproc := sysprocs.Process[pid]

        getSystemProcess(&proc, sysproc, pid)
    } else {

        for pidstr,  proc := range *procs {
            idx, _:= strconv.Atoi(pidstr)
            sysproc, err := sysprocs.NewProcess(uint64 (idx))
            if err != nil {
                log.Infof("sysprocs.NewProcess failed")
                return
            }

            getSystemProcess(&proc, sysproc, uint64 (idx))
        }
    }
}

func getProcsFromDb (d *db.DB) (map[string]Proc, error) {
    var err error
    var procs map[string]Proc
    var ftmp float64
    var curProc Proc

    procTbl, err := d.GetTable(&db.TableSpec{Name: PROC_TBL})
    if err != nil {
        log.Info("Can't get table: ", PROC_TBL)
        return procs, err
    }

    keys, err := procTbl.GetKeys()
    if err != nil {
        log.Info("Can't get proc keys from table")
        return procs, err
    }

    procs = make(map[string]Proc)
    for _, key := range keys {
        pidstr := key.Get(0)
        procEntry, err := procTbl.GetEntry(db.Key{Comp: []string{pidstr}})
        if err != nil {
            log.Info("Can't get entry with key: ", pidstr)
            return procs, err
        }

        curProc.Cmd = procEntry.Get("CMD")
        curProc.Start, _ = strconv.ParseUint(procEntry.Get("START"), 10, 64)
        curProc.User, _ = strconv.ParseUint(procEntry.Get("USER_TIME"), 10, 64)
        curProc.System, _ = strconv.ParseUint(procEntry.Get("SYS_TIME"), 10, 64)
        curProc.Mem, _ = strconv.ParseUint(procEntry.Get("VSZ"), 10, 64)
        ftmp, _ = strconv.ParseFloat(procEntry.Get("%CPU"), 32)
        curProc.Cputil = float32(ftmp)
        ftmp, _ = strconv.ParseFloat(procEntry.Get("%MEM"), 32)
        curProc.Memutil = float32(ftmp)
        procs[pidstr] = curProc
    }

    /* Delete the one non-pid key procdockerstatsd deamon uses to store the last
     * update time in the PROCCESSSTATS table */
    delete(procs, "LastUpdateTime")

    return procs, err
}

var DbToYang_sys_procs_xfmr SubTreeXfmrDbToYang = func(inParams XfmrParams) error {
    var err error

    sysObj := getAppRootObject(inParams)

    procs, err := getProcsFromDb(inParams.dbs[db.StateDB])
    if err != nil {
        log.Infof("getProcsFromDb failed")
        return err
    }

    ygot.BuildEmptyTree(sysObj)
    path := NewPathInfo(inParams.uri)
    val := path.Vars["pid"]
    pid := 0
    if len(val) != 0 {
        pid, _ = strconv.Atoi(val)
    }
    getSystemProcesses(&procs, sysObj.Processes, uint64(pid))
    return err;
}

var Subscribe_sys_aaa_auth_xfmr SubTreeXfmrSubscribe = func (inParams XfmrSubscInParams) (XfmrSubscOutParams, error) {
    var err error
    var result XfmrSubscOutParams

    result.isVirtualTbl = true
    return result, err
}

func getSalt(seed []byte) ([]byte){
    saltRes := "$6$"+string(seed)
    return []byte(saltRes)
}

func getSeed() ([]byte){
    seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
    seed := make([]byte, 16)
    for i := range seed {
        seed[i] = CHARSET[seededRand.Intn(len(CHARSET))]
    }
    return seed
}
func getHashedPassword(userPassword string) (string,error) {
    seededRand := getSeed()
    salt := getSalt(seededRand)
    // use salt to hash user-supplied password
    c := sha512_crypt.New()
    hash, err := c.Generate([]byte(userPassword), salt)
    if err != nil {
        log.Infof("error hashing user's supplied password: %s\n", err)
        return "", err
    }
    return string(hash), nil
}


var YangToDb_sys_aaa_auth_xfmr SubTreeXfmrYangToDb = func(inParams XfmrParams) (map[string]map[string]db.Value,error){
    log.Info("SubtreeXfmrFunc - Uri SYS AUTH: ", inParams.uri);
    pathInfo := NewPathInfo(inParams.uri)
    targetUriPath,_ := getYangPathFromUri(pathInfo.Path)
    log.Info("TARGET URI PATH SYS AUTH:", targetUriPath)
    sysObj := getAppRootObject(inParams)
    usersObj := sysObj.Aaa.Authentication.Users
    userName := pathInfo.Var("username")
    log.Info("username:",userName)
    if len(userName) == 0 {
	return nil, nil
    }
    var status bool
    var err_str string
    var err error
    if _ , _ok := inParams.txCache.Load(userName);!_ok {
	    inParams.txCache.Store(userName, userName)
    } else {
	    if val,present := inParams.txCache.Load("tx_err"); present {
	            return nil, fmt.Errorf("%s",val)
	        }
	    return nil,nil
    }
    if inParams.oper == DELETE {
	status , err_str = hostAccountUserDel(userName)
        if (status){
            d, err := db.NewDB(getDBOptions(db.ConfigDB))
            if err != nil {
                log.Infof("YangToDb_sys_aaa_auth_xfmr, unable to get configDB, error %v", err)
                return nil, err
            }
            defer d.DeleteDB()
            var USER_TABLE= "USER"
            userTable := &db.TableSpec{Name: USER_TABLE}
            key :=db.Key{Comp: []string{userName}}
            err = d.DeleteEntry(userTable, key)
            if err != nil {
                log.Infof("YangToDb_sys_aaa_auth_xfmr, delete entry error %v", err)
                return nil, err
            }
        }
    } else {
        if value,present := usersObj.User[userName]; present {
           hashedPwd := *(value.Config.PasswordHashed)
           clearPwd := *(value.Config.Password)
           if (len(clearPwd) != 0) && (len(hashedPwd) != 0){
               errStr := "Clear text password and Hashed password entered for user "+userName
               log.Error(errStr)
               return nil, tlerr.InvalidArgsError{Format:errStr}
           }
           if len(clearPwd) != 0 {
               hashedPwd,err = getHashedPassword(clearPwd)
               if err != nil {
                   return nil, err
               }
           }
	    temp := value.Config.Role.(*ocbinds.OpenconfigSystem_System_Aaa_Authentication_Users_User_Config_Role_Union_String)
	    log.Info("Role:",temp.String)
            status, err_str = hostAccountUserMod(*(value.Config.Username), temp.String, hashedPwd)
            if (status) {
                d, err := db.NewDB(getDBOptions(db.ConfigDB))
                if err != nil {
                    log.Infof("YangToDb_sys_aaa_auth_xfmr, unable to get configDB, error %v", err)
                    return nil, err
                }
                defer d.DeleteDB()
                var USER_TABLE= "USER"
                userTable := &db.TableSpec{Name: USER_TABLE}
                key :=db.Key{Comp: []string{*(value.Config.Username)}}
                userInfo := db.Value {Field: map[string]string{}}
                (&userInfo).Set("password", hashedPwd)
                (&userInfo).Set("role@", temp.String)
                err = d.CreateEntry(userTable, key, userInfo)
                if err != nil {
                    log.Infof("YangToDb_sys_aaa_auth_xfmr, create entry error %v", err)
                    return nil, err
                }
            }
        }
    }
    if (!status) {
        if _,present := inParams.txCache.Load("tx_err"); !present {
            log.Info("Error in operation:",err_str)
            inParams.txCache.Store("tx_err",err_str)
            return nil, fmt.Errorf("%s", err_str)
        }
    } else {
       return nil, nil
    }
    return nil,nil
}

var YangToDb_global_dns_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    if log.V(3) {
        log.Info( "YangToDb_global_dns_key_xfmr: root: ", inParams.ygRoot,
            ", uri: ", inParams.uri)
    }

    return "global", nil
}

var DbToYang_global_dns_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    res_map := make(map[string]interface{})
    var err error

    log.Info("DbToYang_global_dns_key_xfmr: ", inParams.key)

    return  res_map, err
}

var YangToDb_server_dns_field_xfmr FieldXfmrYangToDb = func(inParams XfmrParams) (map[string]string, error) {
    res_map := make(map[string]string)

    res_map["NULL"] = "NULL"
    return res_map, nil
}

var DbToYang_server_dns_field_xfmr FieldXfmrDbtoYang = func(inParams XfmrParams) (map[string]interface{}, error) {

    var err error
    result := make(map[string]interface{})

    data := (*inParams.dbDataMap)[inParams.curDb]
    log.Info("DbToYang_server_dns_field_xfmr : ", data, "inParams : ", inParams)

    entry_key := inParams.key
    key := strings.Split(entry_key, "|")
    address := key[0]
    result["address"] = address

    return result, err
}


var YangToDb_server_dns_key_xfmr KeyXfmrYangToDb = func(inParams XfmrParams) (string, error) {
    var err error
    var address string

    log.Info("YangToDb_server_dns_key_xfmr ***", inParams.uri)
    pathInfo := NewPathInfo(inParams.uri)

    address =  pathInfo.Var("address")

    if len(pathInfo.Vars) <  1 {
        err = errors.New("Invalid Key length");
        log.Info("Invalid Key length", len(pathInfo.Vars))
        return address, err
    }

    return address, nil
}


var DbToYang_server_dns_key_xfmr KeyXfmrDbToYang = func(inParams XfmrParams) (map[string]interface{}, error) {
    rmap := make(map[string]interface{})
    entry_key := inParams.key
    log.Info("DbToYang_server_dns_key_xfmr: ", entry_key)

    key := strings.Split(entry_key, "|")
    address := key[0]

    rmap["address"] = address

    return rmap, nil
}
