package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	AttachMetricRedisBusinessKey = "AttachMetricRedisBusinessKey"
	PubSubTopic                  = "metricAttachMsg"
)

type RedisManager struct {
	client   *redis.Client
	data     []map[string]map[string]map[string]any
	rwMutex  sync.RWMutex
	stopChan chan struct{}
}

func ProvideRedisManager(config *Config) (*RedisManager, error) {
	if len(config.Redis.Addresses) == 0 {
		return nil, errors.New("redis addresses are not configured")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Addresses[0],
		DB:       config.Redis.DB,
		Password: config.Redis.Password,
		PoolSize: config.Redis.PoolSize,
	})

	pong, err := client.Ping(client.Context()).Result()
	if err != nil {
		return nil, fmt.Errorf("redis connect failed: %v", err)
	}
	fmt.Printf("redis connect success, pong response: %s\n", pong)

	rm := &RedisManager{
		client: client,
	}

	dimensionData, err := rm.GetAll()
	if err == nil {
		rm.data = dimensionData
	}

	return rm, nil
}
func (rm *RedisManager) Start() error {
	// 初始化数据
	dimensionData, err := rm.GetAll()
	if err != nil {
		return fmt.Errorf("failed to initialize data: %v", err)
	}

	rm.rwMutex.Lock()
	rm.data = dimensionData
	rm.rwMutex.Unlock()

	rm.stopChan = make(chan struct{})

	// 启动订阅过程
	go func() {
		for {
			select {
			case <-rm.stopChan:
				return
			default:
				err := rm.Subscribe()
				if err != nil {
					fmt.Printf("Subscription error: %v. Retrying in 5 seconds...\n", err)
					time.Sleep(5 * time.Second)
				}
			}
		}
	}()

	return nil
}

func (rm *RedisManager) Subscribe() error {
	pubSub := rm.client.Subscribe(rm.client.Context(), PubSubTopic)
	defer pubSub.Close()

	_, err := pubSub.Receive(rm.client.Context())
	if err != nil {
		return fmt.Errorf("redis pub sub receive failed: %v", err)
	}

	ch := pubSub.Channel()

	for {
		select {
		case <-rm.stopChan:
			return nil
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			if msg.Payload == "" {
				continue
			}
			dimensionData, err := rm.GetAll()
			if err != nil {
				return fmt.Errorf("redis refresh device dimension business data failed: %v", err)
			}
			rm.rwMutex.Lock()
			rm.data = dimensionData
			rm.rwMutex.Unlock()
		}
	}
}

func (rm *RedisManager) Stop() error {
	if rm.stopChan != nil {
		close(rm.stopChan)
	}
	return rm.Close()
}

func (rm *RedisManager) Close() error {
	if rm.client != nil {
		return rm.client.Close()
	}
	return nil
}
func (rm *RedisManager) Get(key string) (map[string]map[string]any, error) {
	rm.rwMutex.RLock()
	defer rm.rwMutex.RUnlock()
	for _, redisData := range rm.data {
		for k := range redisData {
			if k == key {
				return redisData[k], nil
			}
		}
	}
	return nil, nil
}

func (rm *RedisManager) GetAll() ([]map[string]map[string]map[string]any, error) {
	result, err := rm.client.HGetAll(rm.client.Context(), AttachMetricRedisBusinessKey).Result()
	if err != nil || len(result) == 0 {
		return nil, err
	}

	var data []map[string]map[string]map[string]any
	for key, mapStr := range result {
		var objMap map[string]map[string]any
		transMap := make(map[string]map[string]map[string]any)
		if err = json.Unmarshal([]byte(mapStr), &objMap); err != nil {
			return nil, err
		}
		transMap[key] = objMap
		data = append(data, transMap)
	}

	return data, nil
}

// GetClient 返回 Redis 客户端，用于其他模块访问
func (rm *RedisManager) GetClient() *redis.Client {
	return rm.client
}

// func (rm *RedisManager) Subscribe() error {
// 	pubSub := rm.client.Subscribe(rm.client.Context(), PubSubTopic)
// 	_, err := pubSub.Receive(rm.client.Context())
// 	if err != nil {
// 		return fmt.Errorf("redis pub sub receive failed: %v", err)
// 	}

// 	for msg := range pubSub.Channel() {
// 		if msg.Payload == "" {
// 			break
// 		}
// 		dimensionData, err := rm.GetAll()
// 		if err != nil {
// 			return fmt.Errorf("redis refresh device dimension business data failed: %v", err)
// 		}
// 		rm.rwMutex.Lock()
// 		rm.data = dimensionData
// 		rm.rwMutex.Unlock()
// 	}
// 	return nil
// }

// func (rm *RedisManager) Close() error {
// 	return rm.client.Close()
// }
