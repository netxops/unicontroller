package session

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/influxdata/telegraf/controller/global"
	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"
	"golang.org/x/net/context"

	"github.com/redis/go-redis/v9"
)

type Session struct{}

func (s *Session) Set(ip string, cmd command.Command, cd *command.CacheData) (err error) {
	id := cmd.Id(ip)

	// if global.Redis == nil {
	// initialize.Redis()
	// }
	client := global.Redis
	//config := global.GVA_CONFIG

	var data []byte
	data, err = json.Marshal(cd)
	if err != nil {
		err = errors.New("redis client is nil")
		return
	}

	if client != nil {
		//err = client.Set(id, string(data), time.Duration(config.SessionCache.Timeout)*time.Second).Err()
		err = client.Set(context.Background(), id, string(data), time.Duration(1800)*time.Second).Err()
	}
	return
}

func (s *Session) Get(ip string, cmd command.Command) (cd *command.CacheData, err error) {
	id := cmd.Id(ip)

	cd = &command.CacheData{}

	client := global.Redis

	if client == nil {
		err = errors.New("redis client is nil")
		return
	}

	var val string
	val, err = client.Get(context.Background(), id).Result()
	if err == redis.Nil {
		return
	} else if err != nil {
		return
	}

	byteData := []byte(val)

	err = json.Unmarshal(byteData, cd)
	if err != nil {
		return
	}
	return
}
