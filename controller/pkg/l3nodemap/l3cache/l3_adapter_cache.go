package l3cache

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/influxdata/telegraf/controller/pkg/l3nodemap/constant"
	"github.com/influxdata/telegraf/controller/pkg/l3nodemap/global"
)

var once sync.Once
var adapterCacheManager *l3AdapterCacheManager
var Logger = global.GetLogger()

type l3AdapterCacheManager struct {
	//读写锁(这里最好换成分段锁)
	//rw sync.RWMutex
	//key是Adapter名称(设备名称) （一个adapter对应一个设备，一个设备有多个不同执行方法的结果值）
	caches map[string][]*AdapterCache
}

type AdapterCache struct {
	//读写锁，针对Adapter的缓存读写
	rw sync.RWMutex
	//对应的设备名称(用于反向查找)
	adapterName string
	//key是Adapter具体的执行方法名称
	key string
	//value是具体方法返回的结果
	value []interface{}
	//是否是脏数据标识
	dirtyMark bool
	//最新记录存在时间
	recordTime time.Time
}

func Init() {
	once.Do(func() {
		adapterCacheManager = &l3AdapterCacheManager{}
		//adapterCacheManager.rw = sync.RWMutex{}
		adapterCacheManager.caches = map[string][]*AdapterCache{}
	})
}

func GetAdapterCacheManager() *l3AdapterCacheManager {
	return adapterCacheManager
}

func (mgr *l3AdapterCacheManager) SaveAdapterCache(adapterName string, funcKey string, val []interface{}) error {
	if adapterName == "" || funcKey == "" {
		errMsg := fmt.Sprintf("save adapter cache failed : [%s or %s] is empty", adapterName, funcKey)
		Logger.Error(errMsg)
		return errors.New(errMsg)
	}
	//mgr.rw.Lock()
	//defer mgr.rw.Unlock()
	caches := mgr.caches[adapterName]
	var matchedCache *AdapterCache
	for _, v := range caches {
		if v.adapterName == adapterName && v.key == funcKey {
			matchedCache = v
			break
		}
	}

	if matchedCache != nil {
		matchedCache.rw.Lock()
		defer matchedCache.rw.Unlock()
		matchedCache.value = val
		matchedCache.dirtyMark = false
		matchedCache.recordTime = time.Now()
	} else {
		caches = append(caches, &AdapterCache{
			rw:          sync.RWMutex{},
			key:         funcKey,
			adapterName: adapterName,
			value:       val,
			dirtyMark:   false,
			recordTime:  time.Now(),
		})
	}
	return nil
}

func (mgr *l3AdapterCacheManager) GetAdapterCaches(adapterName string) []*AdapterCache {
	//mgr.rw.RLock()
	//defer mgr.rw.RUnlock()
	return mgr.caches[adapterName]
}

func (mgr *l3AdapterCacheManager) Get(caches []*AdapterCache, adapterName string, funcKey string) []interface{} {
	var matchedCache *AdapterCache
	for _, cache := range caches {
		if cache.adapterName == adapterName && cache.key == funcKey {
			matchedCache = cache
			break
		}
	}
	if matchedCache != nil && len(matchedCache.value) != 0 && !matchedCache.dirtyMark && !expireRecordTime(matchedCache.recordTime) {
		matchedCache.rw.RLock()
		defer matchedCache.rw.RUnlock()
		return matchedCache.value
	}
	return nil
}

func (mgr *l3AdapterCacheManager) DrityMark(adapterName string, funcKey string) error {
	for _, cache := range mgr.caches[adapterName] {
		if cache.adapterName == adapterName && cache.key == funcKey {
			cache.dirtyMark = true
			return nil
		}
	}
	return errors.New(fmt.Sprintf("not found [%s:%s] cache info , the cache info not exist", adapterName, funcKey))
}

func expireRecordTime(recordTime time.Time) bool {
	duration, err := time.ParseDuration(constant.L3_GLOBAL_EXPIRE_TIME_MINUTES)
	if err != nil {
		Logger.Error("time parse err : [L3_GLOBAL_EXPIRE_TIME_MINUTES]")
		return false
	}
	return recordTime.Add(duration).Before(time.Now())
}
