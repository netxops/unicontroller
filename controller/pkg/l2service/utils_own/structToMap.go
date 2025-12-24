package utils_own

import (
	"reflect"
)

func StructToMap(obj interface{}) map[string]interface{} {
	obj_type := reflect.TypeOf(obj).Elem()
	obj_value := reflect.ValueOf(obj).Elem()
	var data = make(map[string]interface{})
	for i := 0; i < obj_type.NumField(); i++ {
		data[obj_type.Field(i).Name] = obj_value.Field(i).Interface()
	}
	return data
}
