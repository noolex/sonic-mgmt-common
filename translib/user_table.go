package translib

import (
	"errors"
	"strings"
	"sync"

	"github.com/Azure/sonic-mgmt-common/translib/db"
	"github.com/golang/glog"
)

var userDb *db.DB

const userTable = "USER"

func init() {
	userDb, _ = db.NewDB(db.Options{
		DBNo:               db.ConfigDB,
		InitIndicator:      "CONFIG_DB_INITIALIZED",
		TableNameSeparator: "|",
		KeySeparator:       "|",
		IsWriteDisabled:    true,
		DisableCVLCheck:    true,
	})
}

type User struct {
	Name     string
	Password string
	Roles    []string
}

var userCache = make(map[string]User)
var userCacheLock sync.RWMutex

func init() {
	userTableNotifSubscribe()
}

func GetUser(name string) (User, error) {
	// Try to get it from the local cache first
	userCacheLock.RLock()
	usr, ok := userCache[name]
	userCacheLock.RUnlock()

	// If found in cache, return that to the user
	if ok {
		return usr, nil
	}

	// Not in cache, get it from the DB, and save it to the cache
	var err error
	key := db.Key{Comp: []string{name}}
	usr, err = getUserFromDB(key)

	if err != nil {
		return usr, err
	}

	saveUserToCache(name, usr)
	return usr, nil
}

func saveUserToCache(name string, user User) {
	userCacheLock.Lock()
	userCache[name] = user
	userCacheLock.Unlock()
}

func deleteUserFromCache(name string) {
	userCacheLock.Lock()
	delete(userCache, name)
	userCacheLock.Unlock()
}

func getUserFromDB(akey db.Key) (User, error) {
	tsa := db.TableSpec{Name: userTable}
	avalue, err := userDb.GetEntry(&tsa, akey)

	var userStruct = User{
		Name: akey.Comp[0],
	}

	if err != nil {
		return userStruct, err
	}

	userStruct.Password = avalue.Field["password"]
	userStruct.Roles = strings.Split(avalue.Field["roles@"], ",")

	// Make sure that we have a valid set of roles
	if len(userStruct.Roles) == 0 {
		return userStruct, errors.New("Invalid roles field")
	}

	return userStruct, nil
}

func userTableNotifSubscribe() {
	tsa := db.TableSpec{Name: userTable}
	user := make([]string, 1)
	user[0] = "*"
	akey := db.Key{Comp: user}

	skeys := make([]*db.SKey, 1)
	skeys[0] = &db.SKey{
		Ts:  &tsa,
		Key: &akey,
		SEMap: map[db.SEvent]bool{
			db.SEventHSet: true,
			db.SEventDel:  true,
		},
	}

	_, err := db.SubscribeDB(db.Options{
		DBNo:               db.ConfigDB,
		InitIndicator:      "CONFIG_DB_INITIALIZED",
		TableNameSeparator: "|",
		KeySeparator:       "|",
	}, skeys, userTableNotifHandler)

	if err != nil {
		glog.Errorf("Subscribe returned error: %v", err)
		return
	}

	glog.Info("USER table subscribe done")
}

func userTableNotifHandler(d *db.DB, skey *db.SKey, key *db.Key, event db.SEvent) error {
	glog.Infof("Got USER table event %v key %#v", event, key)

	cacheKey := strings.Join(key.Comp, "|")
	glog.Infof("Local cache key %v\n", cacheKey)

	switch event {
	case db.SEventHSet:
		user, err := getUserFromDB(*key)
		if err != nil {
			return err
		}

		glog.Infof("Saving user %v to cache\n", cacheKey)
		saveUserToCache(cacheKey, user)

	case db.SEventDel:
		glog.Infof("Deleting user %v from cache\n", cacheKey)
		deleteUserFromCache(cacheKey)
	}
	return nil
}
