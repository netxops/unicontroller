// package utils

// import "sync"

// // SafeMap 是一个使用泛型的线程安全映射
// type SafeMap[K comparable, V any] struct {
// 	sync.RWMutex
// 	m map[K]V
// }

// // NewSafeMap 创建并返回一个新的 SafeMap 实例
// func NewSafeMap[K comparable, V any]() *SafeMap[K, V] {
// 	return &SafeMap[K, V]{
// 		m: make(map[K]V),
// 	}
// }

// // Set 添加或更新键值对
// func (sm *SafeMap[K, V]) Set(key K, value V) {
// 	sm.Lock()
// 	defer sm.Unlock()
// 	sm.m[key] = value
// }

// // Get 获取指定键的值
// func (sm *SafeMap[K, V]) Get(key K) (V, bool) {
// 	sm.RLock()
// 	defer sm.RUnlock()
// 	value, ok := sm.m[key]
// 	return value, ok
// }

// // Delete 删除指定键的值
// func (sm *SafeMap[K, V]) Delete(key K) {
// 	sm.Lock()
// 	defer sm.Unlock()
// 	delete(sm.m, key)
// }

// // Range 遍历映射中的所有键值对
// func (sm *SafeMap[K, V]) Range(f func(key K, value V) bool) {
// 	sm.RLock()
// 	defer sm.RUnlock()
// 	for k, v := range sm.m {
// 		if !f(k, v) {
// 			break
// 		}
// 	}
// }

// func (sm *SafeMap[K, V]) Len() int {
// 	sm.RLock()
// 	defer sm.RUnlock()
// 	return len(sm.m)
// }

// // CheckAndSet 检查键是否存在，如果不存在则设置它
// // 返回值：如果键不存在并成功设置，返回 true；如果键已存在，返回 false
// func (sm *SafeMap[K, V]) CheckAndSet(key K, value V) bool {
// 	sm.Lock()
// 	defer sm.Unlock()

// 	if _, exists := sm.m[key]; !exists {
// 		sm.m[key] = value
// 		return true
// 	}
// 	return false
// }

package utils

// import "sync"

// // SafeMap 是一个使用泛型的线程安全映射，基于 sync.Map 实现
// type SafeMap[K comparable, V any] struct {
// 	m sync.Map
// }

// // NewSafeMap 创建并返回一个新的 SafeMap 实例
// func NewSafeMap[K comparable, V any]() *SafeMap[K, V] {
// 	return &SafeMap[K, V]{}
// }

// // Set 添加或更新键值对
// func (sm *SafeMap[K, V]) Set(key K, value V) {
// 	sm.m.Store(key, value)
// }

// // Get 获取指定键的值
// func (sm *SafeMap[K, V]) Get(key K) (V, bool) {
// 	value, ok := sm.m.Load(key)
// 	if !ok {
// 		var zero V
// 		return zero, false
// 	}
// 	return value.(V), true
// }

// // Delete 删除指定键的值
// func (sm *SafeMap[K, V]) Delete(key K) {
// 	sm.m.Delete(key)
// }

// // Range 遍历映射中的所有键值对
// func (sm *SafeMap[K, V]) Range(f func(key K, value V) bool) {
// 	sm.m.Range(func(key, value interface{}) bool {
// 		return f(key.(K), value.(V))
// 	})
// }

// // Len 返回映射中的键值对数量
// func (sm *SafeMap[K, V]) Len() int {
// 	length := 0
// 	sm.m.Range(func(_, _ interface{}) bool {
// 		length++
// 		return true
// 	})
// 	return length
// }

// // CheckAndSet 检查键是否存在，如果不存在则设置它
// // 返回值：如果键不存在并成功设置，返回 true；如果键已存在，返回 false
// func (sm *SafeMap[K, V]) CheckAndSet(key K, value V) bool {
// 	_, loaded := sm.m.LoadOrStore(key, value)
// 	return !loaded
// }
