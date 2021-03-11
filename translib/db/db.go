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

/*
Package db implements a wrapper over the go-redis/redis.

There may be an attempt to mimic sonic-py-swsssdk to ease porting of
code written in python using that SDK to Go Language.

Example:

 * Initialization:

        d, _ := db.NewDB(db.Options {
                        DBNo              : db.ConfigDB,
                        InitIndicator     : "CONFIG_DB_INITIALIZED",
                        TableNameSeparator: "|",
                        KeySeparator      : "|",
                      })

 * Close:

        d.DeleteDB()


 * No-Transaction SetEntry

        tsa := db.TableSpec { Name: "ACL_TABLE" }
        tsr := db.TableSpec { Name: "ACL_RULE" }

        ca := make([]string, 1, 1)

        ca[0] = "MyACL1_ACL_IPV4"
        akey := db.Key { Comp: ca}
        avalue := db.Value {map[string]string {"ports":"eth0","type":"mirror" }}

        d.SetEntry(&tsa, akey, avalue)

 * GetEntry

        avalue, _ := d.GetEntry(&tsa, akey)

 * GetKeys

        keys, _ := d.GetKeys(&tsa);

 * GetKeysPattern

        keys, _ := d.GetKeys(&tsa, akeyPattern);

 * No-Transaction DeleteEntry

        d.DeleteEntry(&tsa, akey)

 * GetTable

        ta, _ := d.GetTable(&tsa)

 * No-Transaction DeleteTable

        d.DeleteTable(&ts)

 * Transaction

        rkey := db.Key { Comp: []string { "MyACL2_ACL_IPV4", "RULE_1" }}
        rvalue := db.Value { Field: map[string]string {
                "priority" : "0",
                "packet_action" : "eth1",
                        },
                }

        d.StartTx([]db.WatchKeys { {Ts: &tsr, Key: &rkey} },
                  []*db.TableSpec { &tsa, &tsr })

        d.SetEntry( &tsa, akey, avalue)
        d.SetEntry( &tsr, rkey, rvalue)

        e := d.CommitTx()

 * Transaction Abort

        d.StartTx([]db.WatchKeys {},
                  []*db.TableSpec { &tsa, &tsr })
        d.DeleteEntry( &tsa, rkey)
        d.AbortTx()


*/
package db

import (
	"fmt"
	"strconv"

	//	"reflect"
	"errors"
	"strings"
	"time"

	"github.com/Azure/sonic-mgmt-common/cvl"
	"github.com/go-redis/redis/v7"
	"github.com/golang/glog"
	"github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

const (
	DefaultRedisUNIXSocket  string = "/var/run/redis/redis.sock"
	DefaultRedisLocalTCPEP  string = "localhost:6379"
	DefaultRedisRemoteTCPEP string = "127.0.0.1:6379"
)

func init() {
	dbConfigInit()
}

// DBNum type indicates the type of DB (Eg: ConfigDB, ApplDB, ...).
type DBNum int

const (
	ApplDB        DBNum = iota // 0
	AsicDB                     // 1
	CountersDB                 // 2
	LogLevelDB                 // 3
	ConfigDB                   // 4
	FlexCounterDB              // 5
	StateDB                    // 6
	SnmpDB                     // 7
	ErrorDB                    // 8
	// All DBs added above this line, please ----
	MaxDB //  The Number of DBs
)

func (dbNo DBNum) String() string {
	return fmt.Sprintf("%d", dbNo)
}

// Options gives parameters for opening the redis client.
type Options struct {
	DBNo               DBNum
	InitIndicator      string
	TableNameSeparator string //Overriden by the DB config file's separator.
	KeySeparator       string //Overriden by the DB config file's separator.
	IsWriteDisabled    bool //Is write/set mode disabled ?
	IsCacheEnabled     bool //Is cache (Per Connection) allowed?

	// OnChange caching for the DBs passed from Translib's Subscribe Infra
	// to the Apps. SDB is the SubscribeDB() returned handle on which
	// notifications of change are received.
	IsEnableOnChange   bool //SubscribeDB *SDB notifs update OnChange cache
	SDB                *DB  //The subscribeDB handle (Future Use)

	DisableCVLCheck bool
}

func (o Options) String() string {
	return fmt.Sprintf(
		"{ DBNo: %v, InitIndicator: %v, TableNameSeparator: %v, KeySeparator: %v, IsWriteDisabled: %v, IsCacheEnabled: %v, IsEnableOnChange: %v, SDB: %v, DisableCVLCheck: %v }",
		o.DBNo, o.InitIndicator, o.TableNameSeparator, o.KeySeparator,
		o.IsWriteDisabled, o.IsCacheEnabled, o.IsEnableOnChange, o.SDB,
		o.DisableCVLCheck)
}

type _txState int

const (
	txStateNone      _txState = iota // Idle (No transaction)
	txStateWatch                     // WATCH issued
	txStateSet                       // At least one Set|Mod|Delete done.
	txStateMultiExec                 // Between MULTI & EXEC
)

func (s _txState) String() string {
	var state string
	switch s {
	case txStateNone:
		state = "txStateNone"
	case txStateWatch:
		state = "txStateWatch"
	case txStateSet:
		state = "txStateSet"
	case txStateMultiExec:
		state = "txStateMultiExec"
	default:
		state = "Unknown _txState"
	}
	return state
}

const (
	InitialTxPipelineSize int = 100
	InitialTablesCount int = 20
	InitialTableEntryCount int = 50
	InitialTablePatternCount int = 5
	InitialMapsCount int = 10
	InitialMapKeyCount int = 50
)

// TableSpec gives the name of the table, and other per-table customizations.
// (Eg: { Name: ACL_TABLE" }).
type TableSpec struct {
	Name string
	// https://github.com/project-arlo/sonic-mgmt-framework/issues/29
	// CompCt tells how many components in the key. Only the last component
	// can have TableSeparator as part of the key. Otherwise, we cannot
	// tell where the key component begins.
	CompCt int
	// NoDelete flag (if it is set to true) is to skip the row entry deletion from
	// the table when the "SetEntry" or "ModEntry" method is called with empty Value Field map.
	NoDelete bool
}

func (v Value) String() string {
	var str string
	for k, v1 := range v.Field {
		str = str + fmt.Sprintf("\"%s\": \"%s\"\n", k, v1)
	}

	return str
}

// Value gives the fields as a map.
// (Eg: { Field: map[string]string { "type" : "l3v6", "ports" : "eth0" } } ).
type Value struct {
	Field map[string]string
}

type _txOp int

const (
	txOpNone  _txOp = iota // No Op
	txOpHMSet              // key, value gives the field:value to be set in key
	txOpHDel               // key, value gives the fields to be deleted in key
	txOpDel                // key
)

type _txCmd struct {
	ts    *TableSpec
	op    _txOp
	key   *Key
	value *Value
}

// DB is the main type.
type DB struct {
	client *redis.Client
	Opts   *Options

	txState           _txState
	txCmds            []_txCmd
	cv                *cvl.CVL
	cvlEditConfigData []cvl.CVLEditConfigData

	sPubSub *redis.PubSub // PubSub. non-Nil implies SubscribeDB
	sCIP    bool          // Close in Progress
	sOnCCacheDB *DB       // Update this DB for PubSub notifications

	dbStatsConfig DBStatsConfig
	dbCacheConfig DBCacheConfig

	// DBStats is used by both PerConnection cache, and OnChange cache
	// On a DB handle, the two are mutually exclusive.
	stats   DBStats
	cache	DBCache

	onCReg	dbOnChangeReg

}

func (d DB) String() string {
	return fmt.Sprintf("{ client: %v, Opts: %v, txState: %v, tsCmds: %v }",
		d.client, d.Opts, d.txState, d.txCmds)
}

func getDBInstName (dbNo DBNum) string {
	switch dbNo {
	case ApplDB:
		return "APPL_DB"
	case AsicDB:
		return "ASIC_DB"
	case CountersDB:
		return "COUNTERS_DB"
	case LogLevelDB:
		return "LOGLEVEL_DB"
	case ConfigDB:
		return "CONFIG_DB"
	case FlexCounterDB:
		return "FLEX_COUNTER_DB"
	case StateDB:
		return "STATE_DB"
	case SnmpDB:
		return "SNMP_OVERLAY_DB"
	case ErrorDB:
		return "ERROR_DB"
	}
	return ""
}

// NewDB is the factory method to create new DB's.
func NewDB(opt Options) (*DB, error) {

	var e error

	if glog.V(3) {
		glog.Info("NewDB: Begin: opt: ", opt)
	}

	// Time Start
	var now time.Time
	var dur	time.Duration
	now = time.Now()

	ipAddr := DefaultRedisLocalTCPEP
	dbId := int(opt.DBNo)
	dbPassword :=""
	if dbInstName := getDBInstName(opt.DBNo); dbInstName != "" {
		if isDbInstPresent(dbInstName) {
			ipAddr = getDbTcpAddr(dbInstName)
			dbId = getDbId(dbInstName)
			dbSepStr := getDbSeparator(dbInstName)
			dbPassword = getDbPassword(dbInstName)
			if len(dbSepStr) > 0 {
				if len(opt.TableNameSeparator) > 0 && opt.TableNameSeparator != dbSepStr {
					glog.Warning(fmt.Sprintf("TableNameSeparator '%v' in the Options is different from the" +
						" one configured in the Db config. file for the Db name %v", opt.TableNameSeparator, dbInstName))
				}
				opt.KeySeparator = dbSepStr
				opt.TableNameSeparator = dbSepStr
			} else {
				glog.Warning("Database Separator not present for the Db name: ", dbInstName)
			}
		} else {
			glog.Warning("Database instance not present for the Db name: ", dbInstName)
		}
	} else {
		glog.Error(fmt.Errorf("Invalid database number %d", dbId))
	}

	if opt.IsCacheEnabled && opt.IsEnableOnChange {
		glog.Error("Per Connection caching cannot be enabled with OnChange cache")
		glog.Error("Disabling Per Connectiontion caching")
		opt.IsCacheEnabled = false
	}

	d := DB{client: redis.NewClient(&redis.Options{
		Network: "tcp",
		Addr:    ipAddr,
		//Addr:     DefaultRedisRemoteTCPEP,
		Password: dbPassword, /* TBD */
		// DB:       int(4), /* CONFIG_DB DB No. */
		DB:          dbId,
		DialTimeout: 0,
		// For Transactions, limit the pool
		PoolSize: 1,
		// Each DB gets it own (single) connection.
	}),
		Opts:              &opt,
		txState:           txStateNone,
		txCmds:            make([]_txCmd, 0, InitialTxPipelineSize),
		cvlEditConfigData: make([]cvl.CVLEditConfigData, 0, InitialTxPipelineSize),
		dbStatsConfig:     getDBStatsConfig(),
		stats:             DBStats{Tables:make(map[string]Stats, InitialTablesCount), Maps:make(map[string]Stats, InitialMapsCount)},
		dbCacheConfig:     getDBCacheConfig(),
		cache:             DBCache{Tables:make(map[string]Table, InitialTablesCount), Maps:make(map[string]MAP, InitialMapsCount)},
	}

	if !d.Opts.IsWriteDisabled {
		if glog.V(1) {
			glog.Info("NewDB: IsWriteDisabled false. Disable Cache")
		}
		d.dbCacheConfig.PerConnection = false
	}

	if !d.Opts.IsCacheEnabled {
		if glog.V(1) {
			glog.Info("NewDB: IsCacheEnabled false. Disable Cache")
		}
		d.dbCacheConfig.PerConnection = false
	}

	if opt.IsEnableOnChange {
		d.onCReg = dbOnChangeReg{CacheTables:make(map[string]bool, InitialTablesCount)}
	}

	if d.client == nil {
		glog.Error("NewDB: Could not create redis client")
		e = tlerr.TranslibDBCannotOpen{}
		goto NewDBExit
	}

	if opt.DBNo != ConfigDB {
		if glog.V(3) {
			glog.Info("NewDB: ! ConfigDB. Skip init. check.")
		}
		goto NewDBSkipInitIndicatorCheck
	}

	if len(d.Opts.InitIndicator) == 0 {

		glog.Info("NewDB: Init indication not requested")

	} else if init, _ := d.client.Get(d.Opts.InitIndicator).Int(); init != 1 {

		glog.Error("NewDB: Database not inited")
		e = tlerr.TranslibDBNotInit{}
		goto NewDBExit
	}

NewDBSkipInitIndicatorCheck:

NewDBExit:

	if d.dbStatsConfig.TimeStats {
		dur = time.Since(now)
	}

	dbGlobalStats.updateStats(d.Opts.DBNo, true, dur, &(d.stats))

	if glog.V(3) {
		glog.Info("NewDB: End: d: ", d, " e: ", e)
	}

	return &d, e
}

// DeleteDB is the gentle way to close the DB connection.
func (d *DB) DeleteDB() error {

	if glog.V(3) {
		glog.Info("DeleteDB: Begin: d: ", d)
	}

	dbGlobalStats.updateStats(d.Opts.DBNo, false, 0, &(d.stats))

	if d.txState != txStateNone {
		glog.Warning("DeleteDB: not txStateNone, txState: ", d.txState)
	}

	return d.client.Close()
}

func (d *DB) key2redis(ts *TableSpec, key Key) string {

	if glog.V(5) {
		glog.Info("key2redis: Begin: ",
			ts.Name+
				d.Opts.TableNameSeparator+
				strings.Join(key.Comp, d.Opts.KeySeparator))
	}
	return ts.Name +
		d.Opts.TableNameSeparator +
		strings.Join(key.Comp, d.Opts.KeySeparator)
}

func (d *DB) redis2key(ts *TableSpec, redisKey string) Key {

	splitTable := strings.SplitN(redisKey, d.Opts.TableNameSeparator, 2)

	if ts.CompCt > 0 {
		return Key{strings.SplitN(splitTable[1], d.Opts.KeySeparator, ts.CompCt)}
	} else {
		return Key{strings.Split(splitTable[1], d.Opts.KeySeparator)}
	}

}

func (d *DB) ts2redisUpdated(ts *TableSpec) string {

	if glog.V(5) {
		glog.Info("ts2redisUpdated: Begin: ", ts.Name)
	}

	var updated string

	if strings.Contains(ts.Name, "*") {
		updated = string("CONFIG_DB_UPDATED")
	} else {
		updated = string("CONFIG_DB_UPDATED_") + ts.Name
	}

	return updated
}

// GetEntry retrieves an entry(row) from the table.
func (d *DB) GetEntry(ts *TableSpec, key Key) (Value, error) {
	return d.getEntry(ts,key,false)
}
func (d *DB) getEntry(ts *TableSpec, key Key, forceReadDB bool) (Value, error) {

	if glog.V(3) {
		glog.Info("GetEntry: Begin: ", "ts: ", ts, " key: ", key)
	}

	// GetEntryHits
	// Time Start
	var cacheHit bool
	var now time.Time
	var dur	time.Duration
	var stats Stats
	if d.dbStatsConfig.TimeStats {
		now = time.Now()
	}

	var table Table
	var value Value
	var e error
	var v map[string]string

	// If cache GetFromCache (CacheHit?)
	if (d.dbCacheConfig.PerConnection &&
			d.dbCacheConfig.isCacheTable(ts.Name)) ||
		(d.Opts.IsEnableOnChange && d.onCReg.isCacheTable(ts.Name) &&
			!forceReadDB) {
		var ok bool
		if table, ok = d.cache.Tables[ts.Name]; ok {
			if value, ok = table.entry[d.key2redis(ts, key)]; ok {
				cacheHit = true;
			}
		}
	}

	if !cacheHit {
		v, e = d.client.HGetAll(d.key2redis(ts, key)).Result()

		if len(v) != 0 {

			value = Value{Field: v}

			// If cache SetCache (i.e. a cache miss)
			if (d.dbCacheConfig.PerConnection &&
					d.dbCacheConfig.isCacheTable(ts.Name)) ||
				(d.Opts.IsEnableOnChange &&
					d.onCReg.isCacheTable(ts.Name)) {
				if _, ok := d.cache.Tables[ts.Name] ; !ok {
					d.cache.Tables[ts.Name] = Table {
						ts:       ts,
						entry:    make(map[string]Value, InitialTableEntryCount),
						complete: false,
						patterns: make(map[string][]Key, InitialTablePatternCount),
						db:       d,
					}
				}
				d.cache.Tables[ts.Name].entry[d.key2redis(ts, key)] = value
			}

		} else {
			if glog.V(4) {
				glog.Info("GetEntry: HGetAll(): empty map")
			}
			e = tlerr.TranslibRedisClientEntryNotExist{Entry: d.key2redis(ts, key)}
		}
	}

	// Time End, Time, Peak
	if d.dbStatsConfig.TableStats {
		stats = d.stats.Tables[ts.Name]
	} else {
		stats = d.stats.AllTables
	}

	stats.Hits++
	stats.GetEntryHits++
	if cacheHit {
		stats.GetEntryCacheHits++
	}

	if d.dbStatsConfig.TimeStats {
		dur = time.Since(now)

		if dur > stats.Peak {
			stats.Peak = dur
		}
		stats.Time += dur

		if dur > stats.GetEntryPeak {
			stats.GetEntryPeak = dur
		}
		stats.GetEntryTime += dur
	}

	if d.dbStatsConfig.TableStats {
		d.stats.Tables[ts.Name] = stats
	} else {
		d.stats.AllTables = stats
	}

	if glog.V(3) {
		glog.Info("GetEntry: End: ", "value: ", value, " e: ", e)
	}

	return value, e
}

// GetKeys retrieves all entry/row keys.
func (d *DB) GetKeys(ts *TableSpec) ([]Key, error) {
	return d.GetKeysPattern(ts, Key{Comp: []string{"*"}});
}

func (d *DB) GetKeysPattern(ts *TableSpec, pat Key) ([]Key, error) {

	if glog.V(3) {
		glog.Info("GetKeys: Begin: ", "ts: ", ts, "pat: ", pat)
	}

	// GetKeysHits
	// Time Start
	var cacheHit bool
	var now time.Time
	var dur	time.Duration
	var stats Stats
	if d.dbStatsConfig.TimeStats {
		now = time.Now()
	}

	var table Table
	var keys []Key
	var e error

	// If cache GetFromCache (CacheHit?)
	if d.dbCacheConfig.PerConnection && d.dbCacheConfig.isCacheTable(ts.Name) {
		var ok bool
		if table, ok = d.cache.Tables[ts.Name]; ok {
			if keys, ok = table.patterns[d.key2redis(ts,pat)]; ok {
				cacheHit = true;
			}
		}
	}

	if !cacheHit {
		redisKeys, e := d.client.Keys(d.key2redis(ts,pat)).Result()
		if glog.V(4) {
			glog.Info("GetKeys: redisKeys: ", redisKeys, " e: ", e)
		}

		keys = make([]Key, 0, len(redisKeys))
		for i := 0; i < len(redisKeys); i++ {
			keys = append(keys, d.redis2key(ts, redisKeys[i]))
		}

		// If cache SetCache (i.e. a cache miss)
		if d.dbCacheConfig.PerConnection && d.dbCacheConfig.isCacheTable(ts.Name) {
			if _, ok := d.cache.Tables[ts.Name] ; !ok {
				d.cache.Tables[ts.Name] = Table {
					ts:       ts,
					entry:    make(map[string]Value, InitialTableEntryCount),
					complete: false,
					patterns: make(map[string][]Key, InitialTablePatternCount),
					db:       d,
				}
			}
			d.cache.Tables[ts.Name].patterns[d.key2redis(ts,pat)] = keys
		}
	}

	// Time End, Time, Peak
	if d.dbStatsConfig.TableStats {
		stats = d.stats.Tables[ts.Name]
	} else {
		stats = d.stats.AllTables
	}

	stats.Hits++
	stats.GetKeysPatternHits++
	if cacheHit {
		stats.GetKeysPatternCacheHits++
	}
	if (len(pat.Comp) == 1) && (pat.Comp[0] == "*") {
		stats.GetKeysHits++
		if cacheHit {
			stats.GetKeysCacheHits++
		}
	}

	if d.dbStatsConfig.TimeStats {
		dur = time.Since(now)

		if dur > stats.Peak {
			stats.Peak = dur
		}
		stats.Time += dur

		if dur > stats.GetKeysPatternPeak {
			stats.GetKeysPatternPeak = dur
		}
		stats.GetKeysPatternTime += dur

		if (len(pat.Comp) == 1) && (pat.Comp[0] == "*") {

			if dur > stats.GetKeysPeak {
				stats.GetKeysPeak = dur
			}
			stats.GetKeysTime += dur
		}
	}

	if d.dbStatsConfig.TableStats {
		d.stats.Tables[ts.Name] = stats
	} else {
		d.stats.AllTables = stats
	}

	if glog.V(3) {
		glog.Info("GetKeys: End: ", "keys: ", keys, " e: ", e)
	}

	return keys, e
}

// GetKeysByPattern retrieves all entry/row keys matching
// with the given pattern.
func (d *DB) GetKeysByPattern(ts *TableSpec, pattern string) ([]Key, error) {
	return d.GetKeysPattern(ts, Key{Comp: []string{pattern}})
}

// DeleteKeys deletes all entry/row keys matching a pattern.
func (d *DB) DeleteKeys(ts *TableSpec, key Key) error {
	if glog.V(3) {
		glog.Info("DeleteKeys: Begin: ", "ts: ", ts, " key: ", key)
	}

	// This can be done via a LUA script as well. For now do this. TBD
	redisKeys, e := d.client.Keys(d.key2redis(ts, key)).Result()
	if glog.V(4) {
		glog.Info("DeleteKeys: redisKeys: ", redisKeys, " e: ", e)
	}

	for i := 0; i < len(redisKeys); i++ {
		if glog.V(4) {
			glog.Info("DeleteKeys: Deleting redisKey: ", redisKeys[i])
		}
		e = d.DeleteEntry(ts, d.redis2key(ts, redisKeys[i]))
		if e != nil {
			glog.Warning("DeleteKeys: Deleting: ts: ", ts, " key",
				d.redis2key(ts, redisKeys[i]), " : ", e)
		}
	}

	if glog.V(3) {
		glog.Info("DeleteKeys: End: e: ", e)
	}
	return e
}

func (d *DB) doCVL(ts *TableSpec, cvlOps []cvl.CVLOperation, key Key, vals []Value, isReplaceOp bool) error {
	var e error = nil

	var cvlRetCode cvl.CVLRetCode
	var cei cvl.CVLErrorInfo

	if d.Opts.DisableCVLCheck {
		glog.Info("doCVL: CVL Disabled. Skipping CVL")
		goto doCVLExit
	}

	// No Transaction case. No CVL.
	if d.txState == txStateNone {
		glog.Info("doCVL: No Transactions. Skipping CVL")
		goto doCVLExit
	}

	if len(cvlOps) != len(vals) {
		glog.Error("doCVL: Incorrect arguments len(cvlOps) != len(vals)")
		e = errors.New("CVL Incorrect args")
		return e
	}
	for i := 0; i < len(cvlOps); i++ {

		cvlEditConfigData := cvl.CVLEditConfigData{
			VType: cvl.VALIDATE_ALL,
			VOp:   cvlOps[i],
			Key:   d.key2redis(ts, key),
			ReplaceOp: isReplaceOp,
		}

		switch cvlOps[i] {
		case cvl.OP_CREATE, cvl.OP_UPDATE:
			cvlEditConfigData.Data = vals[i].Field
			d.cvlEditConfigData = append(d.cvlEditConfigData, cvlEditConfigData)

		case cvl.OP_DELETE:
			if len(vals[i].Field) == 0 {
				cvlEditConfigData.Data = map[string]string{}
			} else {
				cvlEditConfigData.Data = vals[i].Field
			}
			d.cvlEditConfigData = append(d.cvlEditConfigData, cvlEditConfigData)

		default:
			glog.Error("doCVL: Unknown, op: ", cvlOps[i])
			e = errors.New("Unknown Op: " + string(cvlOps[i]))
		}

	}

	if e != nil {
		goto doCVLExit
	}

	if glog.V(3) {
		glog.Info("doCVL: calling ValidateEditConfig: ", d.cvlEditConfigData)
	}

	cei, cvlRetCode = d.cv.ValidateEditConfig(d.cvlEditConfigData)

	if cvl.CVL_SUCCESS != cvlRetCode {
		glog.Warning("doCVL: CVL Failure: ", cvlRetCode)
		// e = errors.New("CVL Failure: " + string(cvlRetCode))
		e = tlerr.TranslibCVLFailure{Code: int(cvlRetCode),
			CVLErrorInfo: cei}
		glog.Info("doCVL: ", len(d.cvlEditConfigData), len(cvlOps))
		d.cvlEditConfigData = d.cvlEditConfigData[:len(d.cvlEditConfigData)-len(cvlOps)]
	} else {
		for i := 0; i < len(cvlOps); i++ {
			d.cvlEditConfigData[len(d.cvlEditConfigData)-1-i].VType = cvl.VALIDATE_NONE
		}
	}

doCVLExit:

	if glog.V(3) {
		glog.Info("doCVL: End: e: ", e)
	}

	return e
}

func (d *DB) doWrite(ts *TableSpec, op _txOp, key Key, val interface{}) error {
	var e error = nil
	var value Value

	if d.Opts.IsWriteDisabled {
		glog.Error("doWrite: Write to DB disabled")
		e = errors.New("Write to DB disabled during this operation")
		goto doWriteExit
	}

	switch d.txState {
	case txStateNone:
		glog.Info("doWrite: No Transaction.")
	case txStateWatch:
		if glog.V(2) {
			glog.Info("doWrite: Change to txStateSet, txState: ", d.txState)
		}
		d.txState = txStateSet
	case txStateSet:
		if glog.V(5) {
			glog.Info("doWrite: Remain in txStateSet, txState: ", d.txState)
		}
	case txStateMultiExec:
		glog.Error("doWrite: Incorrect State, txState: ", d.txState)
		e = errors.New("Cannot issue {Set|Mod|Delete}Entry in txStateMultiExec")
	default:
		glog.Error("doWrite: Unknown, txState: ", d.txState)
		e = errors.New("Unknown State: " + string(d.txState))
	}

	if e != nil {
		goto doWriteExit
	}

	// No Transaction case. No CVL.
	if d.txState == txStateNone {

		switch op {

		case txOpHMSet:
			value = Value{Field: make(map[string]string,
				len(val.(Value).Field))}
			vintf := make(map[string]interface{})
			for k, v := range val.(Value).Field {
				vintf[k] = v
			}
			e = d.client.HMSet(d.key2redis(ts, key), vintf).Err()

			if e != nil {
				glog.Error("doWrite: HMSet: ", key, " : ", value, " e: ", e)
			}

		case txOpHDel:
			fields := make([]string, 0, len(val.(Value).Field))
			for k := range val.(Value).Field {
				fields = append(fields, k)
			}

			e = d.client.HDel(d.key2redis(ts, key), fields...).Err()
			if e != nil {
				glog.Error("doWrite: HDel: ", key, " : ", fields, " e: ", e)
			}

		case txOpDel:
			e = d.client.Del(d.key2redis(ts, key)).Err()
			if e != nil {
				glog.Error("doWrite: Del: ", key, " : ", e)
			}

		default:
			glog.Error("doWrite: Unknown, op: ", op)
			e = errors.New("Unknown Op: " + string(op))
		}

		goto doWriteExit
	}

	// Transaction case.

	glog.Info("doWrite: op: ", op, "  ", d.key2redis(ts, key), " : ", value)

	switch op {
	case txOpHMSet, txOpHDel:
		value = val.(Value)

	case txOpDel:

	default:
		glog.Error("doWrite: Unknown, op: ", op)
		e = errors.New("Unknown Op: " + string(op))
	}

	if e != nil {
		goto doWriteExit
	}

	d.txCmds = append(d.txCmds, _txCmd{
		ts:    ts,
		op:    op,
		key:   &key,
		value: &value,
	})

doWriteExit:

	if glog.V(3) {
		glog.Info("doWrite: End: e: ", e)
	}

	return e
}

// setEntry either Creates, or Sets an entry(row) in the table.
func (d *DB) setEntry(ts *TableSpec, key Key, value Value, isCreate bool) error {

	var e error = nil
	var valueComplement Value = Value{Field: make(map[string]string, len(value.Field))}
	var valueCurrent Value

	if glog.V(3) {
		glog.Info("setEntry: Begin: ", "ts: ", ts, " key: ", key,
			" value: ", value, " isCreate: ", isCreate)
	}

	if len(value.Field) == 0 {
		if ts.NoDelete {
			glog.Info("setEntry: NoDelete flag is true, skipping deletion of the entry.")
		} else {
			glog.Info("setEntry: Mapping to DeleteEntry()")
			e = d.DeleteEntry(ts, key)
		}
		goto setEntryExit
	}

	if !isCreate {
		// Prepare the HDel list
		// Note: This is for compatibililty with PySWSSDK semantics.
		//       The CVL library will likely fail the SetEntry when
		//       the item exists.
		valueCurrent, e = d.GetEntry(ts, key)
		if e == nil {
			for k := range valueCurrent.Field {
				_, present := value.Field[k]
				if !present {
					valueComplement.Field[k] = string("")
				}
			}
		}
	}

	if !isCreate && e == nil {
		if glog.V(3) {
			glog.Info("setEntry: DoCVL for UPDATE")
		}
		if len(valueComplement.Field) == 0 {
			e = d.doCVL(ts, []cvl.CVLOperation{cvl.OP_UPDATE},
				key, []Value{value}, false)
		} else {
			// For Replace(SET) op, both UPDATE and DELETE operations to be sent to CVL
			// For CVL to identify Replace Op, setting the flag as true
			e = d.doCVL(ts, []cvl.CVLOperation{cvl.OP_UPDATE, cvl.OP_DELETE},
				key, []Value{value, valueComplement}, true)
		}
	} else {
		if glog.V(3) {
			glog.Info("setEntry: DoCVL for CREATE")
		}
		e = d.doCVL(ts, []cvl.CVLOperation{cvl.OP_CREATE}, key, []Value{value}, false)
	}

	if e != nil {
		goto setEntryExit
	}

	e = d.doWrite(ts, txOpHMSet, key, value)

	if (e == nil) && (len(valueComplement.Field) != 0) {
		if glog.V(3) {
			glog.Info("setEntry: DoCVL for HDEL (post-POC)")
		}
		e = d.doWrite(ts, txOpHDel, key, valueComplement)
	}

setEntryExit:
	return e
}

// CreateEntry creates an entry(row) in the table.
func (d *DB) CreateEntry(ts *TableSpec, key Key, value Value) error {

	return d.setEntry(ts, key, value, true)
}

// SetEntry sets an entry(row) in the table.
func (d *DB) SetEntry(ts *TableSpec, key Key, value Value) error {
	return d.setEntry(ts, key, value, false)
}

func (d *DB) Publish(channel string, message interface{}) error {
	e := d.client.Publish(channel, message).Err()
	return e
}

func (d *DB) RunScript(script *redis.Script, keys []string, args ...interface{}) *redis.Cmd {
    return script.Run(d.client, keys, args...)
}

// DeleteEntry deletes an entry(row) in the table.
func (d *DB) DeleteEntry(ts *TableSpec, key Key) error {

	var e error = nil
	if glog.V(3) {
		glog.Info("DeleteEntry: Begin: ", "ts: ", ts, " key: ", key)
	}

	if glog.V(3) {
		glog.Info("DeleteEntry: DoCVL for DELETE")
	}
	e = d.doCVL(ts, []cvl.CVLOperation{cvl.OP_DELETE}, key, []Value{Value{}}, false)

	if e == nil {
		e = d.doWrite(ts, txOpDel, key, nil)
	}

	return e
}

// ModEntry modifies an entry(row) in the table.
func (d *DB) ModEntry(ts *TableSpec, key Key, value Value) error {

	var e error = nil

	if glog.V(3) {
		glog.Info("ModEntry: Begin: ", "ts: ", ts, " key: ", key,
			" value: ", value)
	}

	if len(value.Field) == 0 {
		if ts.NoDelete {
			glog.Info("ModEntry: NoDelete flag is true, skipping deletion of the entry.")
		} else {
			glog.Info("ModEntry: Mapping to DeleteEntry()")
			e = d.DeleteEntry(ts, key)
		}
		goto ModEntryExit
	}

	if glog.V(3) {
		glog.Info("ModEntry: DoCVL for UPDATE")
	}
	e = d.doCVL(ts, []cvl.CVLOperation{cvl.OP_UPDATE}, key, []Value{value}, false)

	if e == nil {
		e = d.doWrite(ts, txOpHMSet, key, value)
	}

ModEntryExit:

	return e
}

// DeleteEntryFields deletes some fields/columns in an entry(row) in the table.
func (d *DB) DeleteEntryFields(ts *TableSpec, key Key, value Value) error {

	if glog.V(3) {
		glog.Info("DeleteEntryFields: Begin: ", "ts: ", ts, " key: ", key,
			" value: ", value)
	}

	if glog.V(3) {
		glog.Info("DeleteEntryFields: DoCVL for HDEL (post-POC)")
	}

	if glog.V(3) {
		glog.Info("DeleteEntryFields: DoCVL for HDEL")
	}

	e := d.doCVL(ts, []cvl.CVLOperation{cvl.OP_DELETE}, key, []Value{value}, false)

	if e == nil {
		d.doWrite(ts, txOpHDel, key, value)
	}

	return e
}

// DeleteTable deletes the entire table.
func (d *DB) DeleteTable(ts *TableSpec) error {
	if glog.V(3) {
		glog.Info("DeleteTable: Begin: ts: ", ts)
	}

	// This can be done via a LUA script as well. For now do this. TBD
	// Read Keys
	keys, e := d.GetKeys(ts)
	if e != nil {
		glog.Error("DeleteTable: GetKeys: " + e.Error())
		goto DeleteTableExit
	}

	// For each key in Keys
	// 	Delete the entry
	for i := 0; i < len(keys); i++ {
    // Don't define/declare a nested scope ``e''
		e = d.DeleteEntry(ts, keys[i])
		if e != nil {
			glog.Warning("DeleteTable: DeleteEntry: " + e.Error())
			break
		}
	}
DeleteTableExit:
	if glog.V(3) {
		glog.Info("DeleteTable: End: ")
	}
	return e
}

//===== Functions for db.Value =====

func (v *Value) IsPopulated() bool {
	return len(v.Field) > 0
}

// Has function checks if a field exists.
func (v *Value) Has(name string) bool {
	_, flag := v.Field[name]
	return flag
}

// Get returns the value of a field. Returns empty string if the field
// does not exists. Use Has() function to check existance of field.
func (v *Value) Get(name string) string {
	return v.Field[name]
}

// Set function sets a string value for a field.
func (v *Value) Set(name, value string) {
	v.Field[name] = value
}

// GetInt returns value of a field as int. Returns 0 if the field does
// not exists. Returns an error if the field value is not a number.
func (v *Value) GetInt(name string) (int, error) {
	data, ok := v.Field[name]
	if ok {
		return strconv.Atoi(data)
	}
	return 0, nil
}

// SetInt sets an integer value for a field.
func (v *Value) SetInt(name string, value int) {
	v.Set(name, strconv.Itoa(value))
}

// GetList returns the value of a an array field. A "@" suffix is
// automatically appended to the field name if not present (as per
// swsssdk convention). Field value is split by comma and resulting
// slice is returned. Empty slice is returned if field not exists.
func (v *Value) GetList(name string) []string {
	var data string
	if strings.HasSuffix(name, "@") {
		data = v.Get(name)
	} else {
		data = v.Get(name + "@")
	}

	if len(data) == 0 {
		return []string{}
	}

	return strings.Split(data, ",")
}

// SetList function sets an list value to a field. Field name and
// value are formatted as per swsssdk conventions:
// - A "@" suffix is appended to key name
// - Field value is the comma separated string of list items
func (v *Value) SetList(name string, items []string) {
	if !strings.HasSuffix(name, "@") {
		name += "@"
	}

	if len(items) != 0 {
		data := strings.Join(items, ",")
		v.Set(name, data)
	} else {
		v.Remove(name)
	}
}

// Remove function removes a field from this Value.
func (v *Value) Remove(name string) {
	delete(v.Field, name)
}

//////////////////////////////////////////////////////////////////////////
// The Transaction API for translib infra
//////////////////////////////////////////////////////////////////////////

// WatchKeys is array of (TableSpec, Key) tuples to be watched in a Transaction.
type WatchKeys struct {
	Ts  *TableSpec
	Key *Key
}

func (w WatchKeys) String() string {
	return fmt.Sprintf("{ Ts: %v, Key: %v }", w.Ts, w.Key)
}

// Tables2TableSpecs - Convenience function to make TableSpecs from strings.
// This only works on Tables having key components without TableSeparator
// as part of the key.
func Tables2TableSpecs(tables []string) []*TableSpec {
	var tss []*TableSpec

	tss = make([]*TableSpec, 0, len(tables))

	for i := 0; i < len(tables); i++ {
		tss = append(tss, &(TableSpec{Name: tables[i]}))
	}

	return tss
}

// StartTx method is used by infra to start a check-and-set Transaction.
func (d *DB) StartTx(w []WatchKeys, tss []*TableSpec) error {

	if glog.V(3) {
		glog.Info("StartTx: Begin: w: ", w, " tss: ", tss)
	}

	var e error = nil
	var ret cvl.CVLRetCode

	//Start CVL session
	if d.cv, ret = cvl.ValidationSessOpen(); ret != cvl.CVL_SUCCESS {
		e = errors.New("StartTx: Unable to create CVL session")
		goto StartTxExit
	}

	// Validate State
	if d.txState != txStateNone {
		glog.Error("StartTx: Incorrect State, txState: ", d.txState)
		e = errors.New("Transaction already in progress")
		goto StartTxExit
	}

	e = d.performWatch(w, tss)

StartTxExit:

	if glog.V(3) {
		glog.Info("StartTx: End: e: ", e)
	}
	return e
}

func (d *DB) AppendWatchTx(w []WatchKeys, tss []*TableSpec) error {
	if glog.V(3) {
		glog.Info("AppendWatchTx: Begin: w: ", w, " tss: ", tss)
	}

	var e error = nil

	// Validate State
	if d.txState == txStateNone {
		glog.Error("AppendWatchTx: Incorrect State, txState: ", d.txState)
		e = errors.New("Transaction has not started")
		goto AppendWatchTxExit
	}

	e = d.performWatch(w, tss)

AppendWatchTxExit:

	if glog.V(3) {
		glog.Info("AppendWatchTx: End: e: ", e)
	}
	return e
}

func (d *DB) performWatch(w []WatchKeys, tss []*TableSpec) error {
	var e error
	var args []interface{}

	// For each watchkey
	//   If a pattern, Get the keys, appending results to Cmd args.
	//   Else append keys to the Cmd args
	//   Note: (LUA scripts do not support WATCH)

	args = make([]interface{}, 0, len(w)+len(tss)+1)
	args = append(args, "WATCH")
	for i := 0; i < len(w); i++ {

		redisKey := d.key2redis(w[i].Ts, *(w[i].Key))

		if !strings.Contains(redisKey, "*") {
			args = append(args, redisKey)
			continue
		}

		redisKeys, e := d.client.Keys(redisKey).Result()
		if e != nil {
			glog.Warning("performWatch: Keys: " + e.Error())
			continue
		}
		for j := 0; j < len(redisKeys); j++ {
			args = append(args, d.redis2key(w[i].Ts, redisKeys[j]))
		}
	}

	// for each TS, append to args the CONFIG_DB_UPDATED_<TABLENAME> key

	for i := 0; i < len(tss); i++ {
		args = append(args, d.ts2redisUpdated(tss[i]))
	}

	if len(args) == 1 {
		glog.Warning("performWatch: Empty WatchKeys. Skipping WATCH")
		goto SkipWatch
	}

	// Issue the WATCH
	_, e = d.client.Do(args...).Result()

	if e != nil {
		glog.Warning("performWatch: Do: WATCH ", args, " e: ", e.Error())
	}

SkipWatch:

	// Switch State
	d.txState = txStateWatch

	return e
}

// CommitTx method is used by infra to commit a check-and-set Transaction.
func (d *DB) CommitTx() error {
	if glog.V(3) {
		glog.Info("CommitTx: Begin:")
	}

	var e error = nil
	var tsmap map[TableSpec]bool = make(map[TableSpec]bool, len(d.txCmds)) // UpperBound

	// Validate State
	switch d.txState {
	case txStateNone:
		glog.Error("CommitTx: No WATCH done, txState: ", d.txState)
		e = errors.New("StartTx() not done. No Transaction active.")
	case txStateWatch:
		if glog.V(1) {
			glog.Info("CommitTx: No SET|DEL done, txState: ", d.txState)
		}
	case txStateSet:
		break
	case txStateMultiExec:
		glog.Error("CommitTx: Incorrect State, txState: ", d.txState)
		e = errors.New("Cannot issue MULTI in txStateMultiExec")
	default:
		glog.Error("CommitTx: Unknown, txState: ", d.txState)
		e = errors.New("Unknown State: " + string(d.txState))
	}

	if e != nil {
		goto CommitTxExit
	}

	// Issue MULTI
	_, e = d.client.Do("MULTI").Result()

	if e != nil {
		glog.Warning("CommitTx: Do: MULTI e: ", e.Error())
	}

	// For each cmd in txCmds
	//   Invoke it
	for i := 0; i < len(d.txCmds); i++ {

		var args []interface{}

		redisKey := d.key2redis(d.txCmds[i].ts, *(d.txCmds[i].key))

		// Add TS to the map of watchTables
		tsmap[*(d.txCmds[i].ts)] = true

		switch d.txCmds[i].op {

		case txOpHMSet:

			args = make([]interface{}, 0, len(d.txCmds[i].value.Field)*2+2)
			args = append(args, "HMSET", redisKey)

			for k, v := range d.txCmds[i].value.Field {
				args = append(args, k, v)
			}

			if glog.V(4) {
				glog.Info("CommitTx: Do: ", args)
			}

			_, e = d.client.Do(args...).Result()

		case txOpHDel:

			args = make([]interface{}, 0, len(d.txCmds[i].value.Field)+2)
			args = append(args, "HDEL", redisKey)

			for k := range d.txCmds[i].value.Field {
				args = append(args, k)
			}

			if glog.V(4) {
				glog.Info("CommitTx: Do: ", args)
			}

			_, e = d.client.Do(args...).Result()

		case txOpDel:

			args = make([]interface{}, 0, 2)
			args = append(args, "DEL", redisKey)

			if glog.V(4) {
				glog.Info("CommitTx: Do: ", args)
			}

			_, e = d.client.Do(args...).Result()

		default:
			glog.Error("CommitTx: Unknown, op: ", d.txCmds[i].op)
			e = errors.New("Unknown Op: " + string(d.txCmds[i].op))
		}

		if e != nil {
			glog.Warning("CommitTx: Do: ", args, " e: ", e.Error())
		}
	}

	// Flag the Tables as updated.
	for ts := range tsmap {
		_, e = d.client.Do("SET", d.ts2redisUpdated(&ts), "1").Result()
		if e != nil {
			glog.Warning("CommitTx: Do: SET ",
				d.ts2redisUpdated(&ts), " 1: e: ",
				e.Error())
		}
	}
	_, e = d.client.Do("SET", d.ts2redisUpdated(&TableSpec{Name: "*"}),
		"1").Result()
	if e != nil {
		glog.Warning("CommitTx: Do: SET ",
			"CONFIG_DB_UPDATED", " 1: e: ", e.Error())
	}

	// Issue EXEC
	_, e = d.client.Do("EXEC").Result()

	if e != nil {
		glog.Warning("CommitTx: Do: EXEC e: ", e.Error())
		e = tlerr.TranslibTransactionFail{}
	}

	// Switch State, Clear Command list
	d.txState = txStateNone
	d.txCmds = d.txCmds[:0]
	d.cvlEditConfigData = d.cvlEditConfigData[:0]

	//Close CVL session
	if ret := cvl.ValidationSessClose(d.cv); ret != cvl.CVL_SUCCESS {
		glog.Error("CommitTx: End: Error in closing CVL session")
	}
	d.cv = nil

CommitTxExit:
	if glog.V(3) {
		glog.Info("CommitTx: End: e: ", e)
	}
	return e
}

// AbortTx method is used by infra to abort a check-and-set Transaction.
func (d *DB) AbortTx() error {
	if glog.V(3) {
		glog.Info("AbortTx: Begin:")
	}

	var e error = nil

	// Validate State
	switch d.txState {
	case txStateNone:
		glog.Error("AbortTx: No WATCH done, txState: ", d.txState)
		e = errors.New("StartTx() not done. No Transaction active.")
	case txStateWatch:
		if glog.V(1) {
			glog.Info("AbortTx: No SET|DEL done, txState: ", d.txState)
		}
	case txStateSet:
		break
	case txStateMultiExec:
		glog.Error("AbortTx: Incorrect State, txState: ", d.txState)
		e = errors.New("Cannot issue UNWATCH in txStateMultiExec")
	default:
		glog.Error("AbortTx: Unknown, txState: ", d.txState)
		e = errors.New("Unknown State: " + string(d.txState))
	}

	if e != nil {
		goto AbortTxExit
	}

	// Issue UNWATCH
	_, e = d.client.Do("UNWATCH").Result()

	if e != nil {
		glog.Warning("AbortTx: Do: UNWATCH e: ", e.Error())
	}

	// Switch State, Clear Command list
	d.txState = txStateNone
	d.txCmds = d.txCmds[:0]
	d.cvlEditConfigData = d.cvlEditConfigData[:0]

	//Close CVL session
	if ret := cvl.ValidationSessClose(d.cv); ret != cvl.CVL_SUCCESS {
		glog.Error("AbortTx: End: Error in closing CVL session")
	}
	d.cv = nil

AbortTxExit:
	if glog.V(3) {
		glog.Info("AbortTx: End: e: ", e)
	}
	return e
}

