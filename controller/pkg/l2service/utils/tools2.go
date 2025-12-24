package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/go-cmp/cmp"
)

type PairFormatter string

func ContainsWithoutCase(s []string, e string) bool {
	for _, a := range s {
		if strings.ToLower(a) == strings.ToLower(e) {
			return true
		}
	}
	return false
}

func Contain(listOrMap, obj interface{}) bool {
	targetValue := reflect.ValueOf(listOrMap)
	switch reflect.TypeOf(listOrMap).Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < targetValue.Len(); i++ {
			if targetValue.Index(i).Interface() == obj {
				return true
			}
		}
	case reflect.Map:
		if targetValue.MapIndex(reflect.ValueOf(obj)).IsValid() {
			return true
		}
	}

	return false

	// return false, errors.New("not in array")
}

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func SubSlice(s1 []string, s2 []string) bool {
	if len(s1) > len(s2) {
		return false
	}
	for _, e := range s1 {
		if !Contains(s2, e) {
			return false
		}
	}
	return true
}

func Convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k.(string)] = Convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = Convert(v)
		}
	}
	return i
}

func PrettyPrintJson(b []byte) string {
	buf := new(bytes.Buffer)
	json.Indent(buf, b, "", "  ")
	return fmt.Sprintf("%s", buf)
}

func Intersection(s1, s2 []string) (inter []string) {
	hash := make(map[string]bool)
	for _, e := range s1 {
		hash[e] = true
	}
	for _, e := range s2 {
		// If elements present in the hashmap then append intersection list.
		if hash[e] {
			inter = append(inter, e)
		}
	}
	//Remove dups from slice.
	inter = removeDups(inter)
	return
}

//Remove dups from slice.
func removeDups(elements []string) (nodups []string) {
	encountered := make(map[string]bool)
	for _, element := range elements {
		if !encountered[element] {
			nodups = append(nodups, element)
			encountered[element] = true
		}
	}
	return
}

func Atoi(num string, value int) (int, error) {
	if num == "" {
		return value, nil
	}

	return strconv.Atoi(num)
}

func OR(one, value interface{}) interface{} {
	if one != nil {
		if reflect.TypeOf(one) != reflect.TypeOf(value) {
			panic("one and value must be same type.")
		}
	}

	switch one.(type) {
	case string:
		if one != "" {
			return one
		} else {
			return value
		}
	case int, int32, int64, int8, uint, uint32, uint64, uint8, float64:
		if one == 0 {
			return value
		} else {
			return one
		}
	case bool:
		if one == true {
			return one
		} else {
			return value
		}
	default:
		if IsNil(one) {
			return value
		} else {
			return one
		}
	}

}

func Must(ops ...interface{}) {
	for _, op := range ops {
		switch op.(type) {
		case error:
			panic(op)
		}
	}
}

func IsFunc(v interface{}) bool {
	return reflect.TypeOf(v).Kind() == reflect.Func
}

func Conditional(condition, trueExp, falseExp interface{}) interface{} {
	if reflect.TypeOf(trueExp) != reflect.TypeOf(falseExp) {
		panic(fmt.Sprint("current not support different type:", reflect.TypeOf(trueExp), reflect.TypeOf(falseExp)))
	}

	var cmp bool
	switch reflect.TypeOf(condition).Kind() {
	case reflect.Func:
		cmp = condition.(func() bool)()
	case reflect.Bool:
		cmp = condition.(bool)
	default:
		panic("current only support func condition or bool type")
	}

	if cmp {
		if reflect.TypeOf(trueExp).Kind() == reflect.Func {
			return trueExp.(func() interface{})()
		} else {
			return trueExp
		}
	} else {
		if reflect.TypeOf(falseExp).Kind() == reflect.Func {
			return falseExp.(func() interface{})()
		} else {
			return falseExp
		}
	}
}

func IsIn(dataList interface{}, data interface{}) bool {
	switch reflect.TypeOf(dataList).Kind() {
	case reflect.Slice:
		// listType := reflect.TypeOf(dataList).Elem()
		// if listType != reflect.TypeOf(data) {
		// fmt.Println(listType, reflect.TypeOf(data))
		// panic("dataList elem type must be same with data")
		// }

		s := reflect.ValueOf(dataList)

		for i := 0; i < s.Len(); i++ {
			if cmp.Equal(s.Index(i).Interface(), data) {
				return true
			}
		}
	}

	return false
}

func IsNil(i interface{}) bool {
	if i == nil {
		return true
	}
	vi := reflect.ValueOf(i)
	if vi.Kind() == reflect.Ptr {
		return vi.IsNil()
	}
	return false
}

//func InList(list []interface{}, e interface{}) bool {
//if list == nil {
//return false
//}

//for _, i := range list {
//if i == e {
//return true
//}
//}
//return false
//}

func InList(list []string, e string) bool {
	if list == nil {
		return false
	}

	for _, i := range list {
		if i == e {
			return true
		}
	}
	return false
}
