////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or //
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

package db

import (
	// "fmt"
	// "strconv"

	// "errors"
	// "strings"
	"time"
	"sync"
  "reflect"

	"github.com/go-redis/redis/v7"
	// "github.com/golang/glog"
	// "github.com/Azure/sonic-mgmt-common/translib/tlerr"
)

////////////////////////////////////////////////////////////////////////////////
//  Exported Types                                                            //
////////////////////////////////////////////////////////////////////////////////

type Stats struct {

		// Total Hits

	Hits                    uint `json:"hits"`

		// TimeStats are being collected (true)

	Time                    time.Duration `json:"total-time"`
	Peak                    time.Duration `json:"peak-time"`

		// Category Hits

	GetEntryHits            uint `json:"get-entry-hits"`
	GetKeysHits             uint `json:"get-keys-hits"`
	GetKeysPatternHits      uint `json:"get-keys-pattern-hits"`
	GetMapHits              uint `json:"get-map-hits"`
	GetMapAllHits           uint `json:"get-map-all-hits"`

	NewScanCursorHits       uint `json:"new-scan-cursor-hits"`
	DeleteScanCursorHits    uint `json:"delete-scan-cursor-hits"`
	GetNextKeysHits         uint `json:"get-next-keys-hits"`

		// Cache Statistics

	GetEntryCacheHits       uint `json:"get-entry-cache-hits"`
	GetKeysCacheHits        uint `json:"keys-cache-hits"`
	GetKeysPatternCacheHits uint `json:"keys-pattern-cache-hits"`
	GetMapCacheHits         uint `json:"get-map-cache-hits"`
	GetMapAllCacheHits      uint `json:"get-map-all-cache-hits"`

		// TimeStats are being collected (true)

	GetEntryTime            time.Duration `json:"get-entry-time"`
	GetKeysTime             time.Duration `json:"get-keys-time"`
	GetKeysPatternTime      time.Duration `json:"get-keys-pattern-time"`
	GetMapTime              time.Duration `json:"get-map-time"`
	GetMapAllTime           time.Duration `json:"get-map-all-time"`
	GetNextKeysTime         time.Duration `json:"get-next-keys-time"`

	GetEntryPeak            time.Duration `json:"get-entry-peak-time"`
	GetKeysPeak             time.Duration `json:"get-keys-peak-time"`
	GetKeysPatternPeak      time.Duration `json:"get-keys-pattern-peak-time"`
	GetMapPeak              time.Duration `json:"get-map-peak-time"`
	GetMapAllPeak           time.Duration `json:"get-map-all-peak-time"`
	GetNextKeysPeak         time.Duration `json:"get-next-keys-peak-time"`

}

type DBStats struct {
	AllTables  Stats            `json:"all-tables"`
	AllMaps    Stats            `json:"all-maps"`
	Tables     map[string]Stats `json:"tables"`
	Maps       map[string]Stats `json:"maps"`
}

type DBGlobalStats struct {
	New         uint           `json:"new-db"`
	Delete      uint           `json:"delete-db"`
	PeakOpen    uint           `json:"peak-open"`

	NewTime     time.Duration  `json:"new-time"`
	NewPeak     time.Duration  `json:"peak-new-time"`

	ZeroGetHits uint           `json:"zero-get-ops-db"`

		// TableStats are being collected (true)

	Databases   [MaxDB]DBStats `json:"dbs"`
}


type DBStatsConfig struct {
	TimeStats  bool
	TableStats bool
	MapStats   bool
}

////////////////////////////////////////////////////////////////////////////////
//  Exported Functions                                                        //
////////////////////////////////////////////////////////////////////////////////

func GetDBStats() (*DBGlobalStats, error) {
	return dbGlobalStats.getStats()
}

func GetDBStatsTotals() (uint, time.Duration, time.Duration) {
	return dbGlobalStats.getStatsTotals()
}

func ClearDBStats() (error) {
	return dbGlobalStats.clearStats()
}

func ReconfigureStats() error {
	return dbStatsConfig.reconfigure()
}

////////////////////////////////////////////////////////////////////////////////
//  Internal Functions                                                        //
////////////////////////////////////////////////////////////////////////////////

var dbGlobalStats *DBGlobalStats
var mutexDBGlobalStats sync.Mutex
var zeroDBGlobalStats = &DBGlobalStats{}

var dbStatsConfig *DBStatsConfig
var defaultDBStatsConfig DBStatsConfig = DBStatsConfig {
	TimeStats: false,
	TableStats: false,
	MapStats: false,
	}

var reconfigureStatsConfig bool
var mutexStatsConfig sync.Mutex

func init() {

	dbGlobalStats = &DBGlobalStats{}

	dbStatsConfig = &DBStatsConfig{}
	dbStatsConfig.handleReconfigureSignal()
	dbStatsConfig.reconfigure()

}

////////////////////////////////////////////////////////////////////////////////
//  DBGlobalStats functions                                                   //
////////////////////////////////////////////////////////////////////////////////

func (stats *DBGlobalStats) getStats() (*DBGlobalStats, error) {

	// Need to give a (deep)copy of the Stats
	var dbGlobalStats DBGlobalStats

	mutexDBGlobalStats.Lock()

	dbGlobalStats = *stats
	for dbnum,db := range stats.Databases {

		dbGlobalStats.Databases[dbnum].Tables = make(map[string]Stats, len(db.Tables))
		for name,table := range db.Tables {
			dbGlobalStats.Databases[dbnum].Tables[name] = table
		}

		dbGlobalStats.Databases[dbnum].Maps = make(map[string]Stats, len(db.Maps))
		for name,mAP := range db.Maps {
			dbGlobalStats.Databases[dbnum].Maps[name] = mAP
		}

	}

	mutexDBGlobalStats.Unlock()

	return &dbGlobalStats, nil
}

func (stats *DBGlobalStats) getStatsTotals() (uint, time.Duration, time.Duration) {
	var hits uint
	var timetotal, peak time.Duration

	mutexDBGlobalStats.Lock()

	for _,db := range stats.Databases {

		if db.AllTables.Hits != 0 {
			hits += db.AllTables.Hits
			timetotal += db.AllTables.Time
			if peak < db.AllTables.Peak {
				peak = db.AllTables.Peak
			}
		} else {
			for _,table := range db.Tables {
				hits += table.Hits
				timetotal += table.Time
				if peak < table.Peak {
					peak = table.Peak
				}
			}
		}

		if db.AllMaps.Hits != 0 {
			hits += db.AllMaps.Hits
			timetotal += db.AllMaps.Time
			if peak < db.AllMaps.Peak {
				peak = db.AllMaps.Peak
			}
		} else {
			for _,mAP := range db.Maps {
				hits += mAP.Hits
				timetotal += mAP.Time
				if peak < mAP.Peak {
					peak = mAP.Peak
				}
			}
		}

	}

	mutexDBGlobalStats.Unlock()

	return hits, timetotal, peak
}

func (stats *DBGlobalStats) clearStats() (error) {

	mutexDBGlobalStats.Lock()
	*stats = *zeroDBGlobalStats
	mutexDBGlobalStats.Unlock()

	return nil
}


func (stats *DBGlobalStats) updateStats(dbNo DBNum, isNew bool, dur time.Duration, connStats * DBStats) (error) {

	mutexDBGlobalStats.Lock()

	if isNew {
		stats.NewTime += dur
		if (dur > stats.NewPeak) {
			stats.NewPeak = dur
		}
		if (stats.New)++ ; (stats.New - stats.Delete) > stats.PeakOpen {
			(stats.PeakOpen)++
		}
	} else {
		(stats.Delete)++
		if (connStats.AllTables.Hits == 0) && (connStats.AllMaps.Hits == 0) &&
			(len(connStats.Tables) == 0) && (len(connStats.Maps) == 0) {
			(stats.ZeroGetHits)++
		} else {
			stats.Databases[dbNo].updateStats(connStats)
		}
	}

	mutexDBGlobalStats.Unlock()

	return nil
}

////////////////////////////////////////////////////////////////////////////////
//  DBStats functions                                                         //
////////////////////////////////////////////////////////////////////////////////

func (dbstats *DBStats) updateStats(connStats *DBStats) (error) {

	var ok bool

	if connStats.AllTables.Hits != 0 {
		dbstats.AllTables.updateStats(&(connStats.AllTables))
	} else {
		if dbstats.Tables == nil {
			dbstats.Tables = make(map[string]Stats, InitialTablesCount)
		}
		for t,s := range connStats.Tables {
			if _,ok = dbstats.Tables[t]; !ok {
				dbstats.Tables[t] = s
			} else {
				var stats Stats = dbstats.Tables[t]
				stats.updateStats(&s)
				dbstats.Tables[t] = stats
			}
		}
	}

	if connStats.AllMaps.Hits != 0 {
		dbstats.AllMaps.updateStats(&(connStats.AllMaps))
	} else {
		if dbstats.Maps == nil {
			dbstats.Maps = make(map[string]Stats, InitialMapsCount)
		}
		for t,s := range connStats.Maps {
			if _,ok = dbstats.Maps[t]; !ok {
				dbstats.Maps[t] = s
			} else {
				var stats Stats = dbstats.Maps[t]
				stats.updateStats(&s)
				dbstats.Maps[t] = stats
			}
		}
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
//  Stats functions                                                           //
////////////////////////////////////////////////////////////////////////////////

func (stats *Stats) updateStats(connStats *Stats) (error) {

	if connStats.Hits != 0 {

		stats.Hits += connStats.Hits
		
		stats.GetEntryHits += connStats.GetEntryHits
		stats.GetKeysHits += connStats.GetKeysHits
		stats.GetKeysPatternHits += connStats.GetKeysPatternHits
		stats.GetMapHits += connStats.GetMapHits
		stats.GetMapAllHits += connStats.GetMapAllHits

		stats.NewScanCursorHits += connStats.NewScanCursorHits
		stats.DeleteScanCursorHits += connStats.DeleteScanCursorHits
		stats.GetNextKeysHits += connStats.GetNextKeysHits

		stats.GetEntryCacheHits += connStats.GetEntryCacheHits
		stats.GetKeysCacheHits += connStats.GetKeysCacheHits
		stats.GetKeysPatternCacheHits += connStats.GetKeysPatternCacheHits
		stats.GetMapCacheHits += connStats.GetMapCacheHits
		stats.GetMapAllCacheHits += connStats.GetMapAllCacheHits

		if connStats.Time != 0 {

			stats.Time += connStats.Time
			if connStats.Peak > stats.Peak {
				stats.Peak = connStats.Peak
			}

			stats.GetEntryTime += connStats.GetEntryTime
			stats.GetKeysTime += connStats.GetKeysTime
			stats.GetKeysPatternTime += connStats.GetKeysPatternTime
			stats.GetMapTime += connStats.GetMapTime
			stats.GetMapAllTime += connStats.GetMapAllTime
			stats.GetNextKeysTime += connStats.GetNextKeysTime

			if connStats.GetEntryPeak > stats.GetEntryPeak {
				stats.GetEntryPeak = connStats.GetEntryPeak
			}
			if connStats.GetKeysPeak > stats.GetKeysPeak {
				stats.GetKeysPeak = connStats.GetKeysPeak
			}
			if connStats.GetKeysPatternPeak > stats.GetKeysPatternPeak {
				stats.GetKeysPatternPeak = connStats.GetKeysPatternPeak
			}
			if connStats.GetMapPeak > stats.GetMapPeak {
				stats.GetMapPeak = connStats.GetKeysPatternPeak
			}
			if connStats.GetMapAllPeak > stats.GetMapAllPeak {
				stats.GetMapAllPeak = connStats.GetMapAllPeak
			}
			if connStats.GetNextKeysPeak > stats.GetNextKeysPeak {
				stats.GetNextKeysPeak = connStats.GetNextKeysPeak
			}

		}

	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////
//  Configure DB Stats                                                        //
////////////////////////////////////////////////////////////////////////////////

func getDBStatsConfig() DBStatsConfig {
	dbStatsConfig.reconfigure()
	mutexStatsConfig.Lock()
	statsConfig := *dbStatsConfig
	mutexStatsConfig.Unlock()
	return statsConfig
}

func (config *DBStatsConfig) reconfigure() error {
	mutexStatsConfig.Lock()
	var doReconfigure bool = reconfigureStatsConfig
	if reconfigureStatsConfig {
		reconfigureStatsConfig = false
	}
	mutexStatsConfig.Unlock()

	if doReconfigure {
		var readDBStatsConfig DBStatsConfig
		readDBStatsConfig.readFromDB()

		mutexStatsConfig.Lock()
		configChanged := !reflect.DeepEqual(*config, readDBStatsConfig)
		mutexStatsConfig.Unlock()

		if configChanged {
			ClearDBStats()
		}

		mutexStatsConfig.Lock()
		dbStatsConfig = &readDBStatsConfig
		mutexStatsConfig.Unlock()
	}
	return nil
}

func (config *DBStatsConfig) handleReconfigureSignal() error {
	mutexStatsConfig.Lock()
	reconfigureStatsConfig = true
	mutexStatsConfig.Unlock()
	return nil
}

////////////////////////////////////////////////////////////////////////////////
//  Read DB Stats Configuration                                               //
////////////////////////////////////////////////////////////////////////////////

func (config *DBStatsConfig) readFromDB() error {
	fields, e := readRedis("TRANSLIB_DB|default")
	if e != nil {
		config.TimeStats = defaultDBStatsConfig.TimeStats
		config.TableStats = defaultDBStatsConfig.TableStats
		config.MapStats = defaultDBStatsConfig.MapStats
	} else {
		for k,v := range fields {
			switch {
				case k == "time_stats" && v == "True":
					config.TimeStats = true
				case k == "time_stats" && v == "False":
					config.TimeStats = false
				case k == "table_stats" && v == "True":
					config.TableStats = true
				case k == "table_stats" && v == "False":
					config.TableStats = false
				case k == "map_stats" && v == "True":
					config.MapStats = true
				case k == "map_stats" && v == "False":
					config.MapStats = false
			}
		}
	}
	return e
}

////////////////////////////////////////////////////////////////////////////////
//  Utility Function to read Redis DB                                         //
////////////////////////////////////////////////////////////////////////////////

func readRedis(key string) (map[string]string, error) {

	ipAddr := DefaultRedisLocalTCPEP
	dbId := int(ConfigDB)
	dbPassword :=""
	if dbInstName := getDBInstName(ConfigDB); dbInstName != "" {
		if isDbInstPresent(dbInstName) {
			ipAddr = getDbTcpAddr(dbInstName)
			dbId = getDbId(dbInstName)
			dbPassword = getDbPassword(dbInstName)
		}
	}

	client := redis.NewClient(&redis.Options{
		Network: "tcp",
		Addr:    ipAddr,
		Password: dbPassword,
		DB:          dbId,
		DialTimeout: 0,
		PoolSize: 1,
	})

	fields, e := client.HGetAll(key).Result()

	client.Close()

	return fields, e
}

