package command

import (
	"time"
)

type CacheData struct {
	CreateAt time.Time `json:"create_at"`
	Data     []byte    `json:"data"`
}

//
func (cd *CacheData) IsTimeout() bool {
	//config := global.GVA_CONFIG

	//if cd.CreateAt.Add(time.Duration(config.SessionCache.Timeout) * time.Second).Before(time.Now()) {
	//	return true
	//}
	if cd.CreateAt.Add(time.Duration(1800) * time.Second).Before(time.Now()) {
		return true
	}
	return false
}

func NewCacheData(data []byte) *CacheData {
	return &CacheData{
		CreateAt: time.Now(),
		Data:     data,
	}
}
