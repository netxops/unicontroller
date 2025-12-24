package text

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/dlclark/regexp2"
)

//多行拼接:
//两种情况,第一种是所有行都是平行结构，以某一个或多个关键字进行分组
//　　　　第二种情况是，有明确的分段方式，在同一分段中进行拼接

//=============================================================
//某些字段会重复出现，就要求最终结果可能是一项，也可能是数组。
//正则中的name capture，与实际字段名称不同，可能多项name capture对应一个结构字段的情况
//同一正则可能会存在多个可选分支
//平行结构的分组，可能需要多个正则进行预处理;有可能同一正在遍历全文后，再进行处理;也有可能进行预分段后再进行处理。区别是看数据的复杂程度。

//针对有分支的情况，golang分析处理有两种可能的选择，一是:统一结构，利用字段映射的方式实现，一种是利用某字段的信息来选择不同的的数据结构体。

func InitializeStruct(t reflect.Type, v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		ft := t.Field(i)
		switch ft.Type.Kind() {
		case reflect.Map:
			f.Set(reflect.MakeMap(ft.Type))
		case reflect.Slice:
			f.Set(reflect.MakeSlice(ft.Type, 0, 0))
		case reflect.Chan:
			f.Set(reflect.MakeChan(ft.Type, 0))
		case reflect.Struct:
			InitializeStruct(ft.Type, f)
		case reflect.Ptr:
			fv := reflect.New(ft.Type.Elem())
			InitializeStruct(ft.Type.Elem(), fv.Elem())
			f.Set(fv)
		default:
		}
	}
}

type SplitterResult struct {
	// 与Python版本的attr类似，指定保持到结果的字段名称
	Attr   []string
	Result []map[string]string
}

func (s SplitterResult) Len() int {
	return len(s.Result)
}

func (s SplitterResult) One() (map[string]string, bool) {
	if len(s.Result) == 0 {
		return nil, false
	}
	return s.Result[0], true
}

// 将正则匹配结果转换为json字符串
func (s SplitterResult) Json() ([]byte, error) {
	return json.Marshal(s.Result)
}

// 将匹配结果中指定行转换为json字符串
func (s SplitterResult) RowJson(index int) ([]byte, error) {
	if index < 0 || index >= len(s.Result) {
		return nil, errors.New(fmt.Sprintf("index: %d, len(s.Result) = %d", index, len(s.Result)))
	}
	return json.Marshal(s.Result[index])
}

// 从分割结果中取出COUNT行，如果有需要，还可以将原来结果中的字段，映射为指定字段
func (s SplitterResult) MapToFields(m map[string]string, count int) (interface{}, error) {
	list := []map[string]string{}
	first := 0
	last := len(s.Result)
	if count != -1 {
		if first+count < last {
			last = first + count
		}
	}

	for i := first; i < last; i++ {
		tmp_m := map[string]string{}
		if m != nil {
			for fieldName, mapTo := range m {
				value, ok := s.Result[i][fieldName]

				if ok {
					tmp_m[mapTo] = value
				}
			}
			list = append(list, tmp_m)
		} else {
			list = append(list, s.Result[i])
		}
	}

	if len(list) == 0 {
		return nil, nil
	}

	if count == 1 {
		return list[0], nil
	} else {
		rlist := []map[string]string{}
		for i := 0; i < len(list); i++ {
			rlist = append(rlist, list[i])
		}

		//fmt.Printf("list = %+v\n", list)
		return rlist, nil
	}
}

// 获取正则匹配结果的指定Cell
func (s SplitterResult) Cell(index int, field string) (string, error) {
	if index < 0 || index >= len(s.Result) {
		return "", errors.New(fmt.Sprintf("index: %d, len(s.Result) = %d", index, len(s.Result)))
	}
	v, ok := s.Result[index][field]
	if ok {
		return v, nil
	} else {
		return "", errors.New(fmt.Sprintf("fields: %s is not in: %s", field, s.Attr))
	}
}

// 与MapToFields类似，但是需要提供数据的类型，最终将数据dump成为指定结构
func (s SplitterResult) Dump(m map[string]string, count int, t reflect.Type) (interface{}, error) {
	list := []map[string]string{}
	first := 0
	last := len(s.Result)
	if count != -1 {
		if first+count < last {
			last = first + count
		}
	}

	for i := first; i < last; i++ {
		tmp_m := map[string]string{}
		if m != nil {
			for fieldName, mapTo := range m {
				value, ok := s.Result[i][fieldName]
				if ok {
					tmp_m[mapTo] = value
				}
			}
			list = append(list, tmp_m)
		} else {
			list = append(list, s.Result[i])
		}
	}
	//return json.Marshal(s.Result)
	//err := json.Unmarshal([]byte(j), &sp)

	//fmt.Printf("list = %+v\n", list)

	if count == 1 {
		jt, err := json.Marshal(list[0])
		if err != nil {
			//fmt.Printf("err = %+v\n", err)
			return nil, err
		}
		//fmt.Printf("jt = %s\n", string(jt))
		nv := reflect.New(t)
		InitializeStruct(t, nv.Elem())

		err = json.Unmarshal(jt, nv.Interface())
		if err != nil {
			//fmt.Printf("err = %+v\n", err)
			return nil, err
		}
		return nv, nil
	} else {
		//fmt.Printf("jt = %s\n", string(jt))
		rlist := []interface{}{}
		for i := 0; i < len(list); i++ {
			//fmt.Printf("list[i] = %+v\n", list[i])
			jt, err := json.Marshal(list[i])
			if err != nil {
				return nil, err
			}
			//fmt.Printf("string(jt) = %+v\n", string(jt))
			nv := reflect.New(t)
			InitializeStruct(t, nv.Elem())

			err = json.Unmarshal(jt, nv.Interface())
			if err != nil {
				return nil, err
			}
			//fmt.Printf("nv = %+v\n", nv)
			rlist = append(rlist, nv)
		}

		return rlist, nil
	}
}

// 按照多个key的组合进行分组
// 返回分组后__match__组成的字符串列表，在返回结果中并不包含分组字段的相关信息，纯粹就是一个聚合功能，用于后续继续处理
func (s SplitterResult) CombinKey(keys []string) ([]string, error) {
	if len(s.Result) == 0 {
		return nil, nil
	}

	if len(keys) == 0 {
		return nil, errors.New(fmt.Sprintf("keys is nil"))
	}

	for _, k := range keys {
		in := false
		for _, a := range s.Attr {
			if a == k {
				in = true
				break
			}
		}
		if !in {
			return nil, errors.New(fmt.Sprintf("keys:%+v not in attrs:%+v", keys, s.Attr))
		}
	}

	keymap := map[string]int{}
	list := []string{}
	for i := 0; i < len(s.Result); i++ {
		result := s.Result[i]["__match__"]
		//key := ""
		tmp := []string{}
		for _, k := range keys {
			tmp = append(tmp, s.Result[i][k])
			//key += other.Result[i][k]
		}
		key := strings.Join(tmp, "||")
		v, ok := keymap[key]
		if ok {
			list[v] = list[v] + "\n" + result
			//list[v] = list[v] + result
		} else {
			keymap[key] = len(list)
			list = append(list, result)
		}
	}

	return list, nil
}

// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule1 match destination-address 20.1.2.2/32
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule1 then source-nat interface
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 match destination-address 172.20.2.10/32
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 match destination-port 1234 to 2222
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 match destination-port 3333 to 3335
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 then source-nat interface

// 将destination-port (?<dport>\S+) to (?P<dport2>\S+)中dport与dport2作为一个pair，通过"-"进行连接，并将数据保存到pair对中第一个名称中
// dport=1234 dport2=2222，最终数据被保存为{"dport": "1234-2222"}
func (s SplitterResult) pairData(data map[string]string, pairFields [][]string, sep string) map[string]string {
	if pairFields == nil {
		return data
	}
	m := map[string]string{}
	keys := []string{}
	for _, pair := range pairFields {
		tmpList := []string{}
		// 在同一个pair之中，先把数据保存到tmpList中
		for _, p := range pair {
			if data[p] != "" {
				tmpList = append(tmpList, data[p])
			}
		}
		if len(pair) > 0 {
			// 用pair的第一字段作为组合后的字段名
			// 可以将我们希望组合的名字放到pair的首位，即使该字段并不真是存在也可以
			m[pair[0]] = strings.Join(tmpList, sep)
			keys = append(keys, pair...)
		}

	}

	for k, v := range data {
		if !Contains(keys, k) {
			m[k] = v
		}
	}

	return m
}

// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule1 match destination-address 20.1.2.2/32
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule1 then source-nat interface
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 match destination-address 172.20.2.10/32
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 match destination-port 1234 to 2222
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 match destination-port 3333 to 3335
// set security nat source rule-set OUT_TO_IN_DY_RULESET rule out_to_in_rule2 then source-nat interface
// multipleField字段定义的数据，将进行拼接，比如: dport=1234-2222 dport=3333-3335，最终返回{dport: "1234-2222,3333-3335"}
// 不在multipleField中的字段，返回最后的不为空的值，比如:[{"name": "testName"}, {"name": ""}]，返回{"name": "testName"}
func (sp SplitterResult) Projection(multipleField []string, sep string, pairFields [][]string) (map[string]string, error) {
	m := map[string]string{}
	multipleMap := map[string][]string{}
	if !Contains(multipleField, "__match__") {
		multipleField = append(multipleField, "__match__")
	}

	for _, result := range sp.Result {
		data := sp.pairData(result, pairFields, "-")
		for k, v := range data {
			if m[k] == "" {
				m[k] = v
			}

			if !Contains(multipleField, k) {
				if m[k] != "" && v != "" {
					m[k] = v
				}
			} else {
				if v != "" {
					multipleMap[k] = append(multipleMap[k], v)
				}
			}
		}
	}

	for k, valueList := range multipleMap {
		if k == "__match__" {
			m[k] = strings.Join(valueList, "\n")
		} else {
			m[k] = strings.Join(valueList, sep)
		}
	}

	return m, nil
}

// 将两个匹配结果集进行组合，主要用于文本预处理场景，用于将两个匹配结果进行拼接
// 拼接的方法:
// 1.只有包含了关键字字段的结果才能进行拼接,
// 2.拼接保持了s中的顺序
func (s SplitterResult) GroupWithCombinKey(other *SplitterResult, leftKey []string, rightKey []string) ([]string, error) {
	if len(other.Result) == 0 || len(s.Result) == 0 {
		return nil, nil
	}

	if len(leftKey) == 0 {
		return nil, errors.New(fmt.Sprintf("leftKey is nil"))
	}

	if len(rightKey) == 0 {
		return nil, errors.New(fmt.Sprintf("rightKey is nil"))
	}

	for _, k := range leftKey {
		in := false
		for _, a := range s.Attr {
			if a == k {
				in = true
				break
			}
		}
		if !in {
			return nil, errors.New(fmt.Sprintf("leftKey:%+v not in attrs:%+v", leftKey, s.Attr))
		}
	}
	for _, k := range rightKey {
		in := false
		for _, a := range other.Attr {
			if a == k {
				in = true
				break
			}
		}
		if !in {
			return nil, errors.New(fmt.Sprintf("rightKey:%+v not in attrs:%+v", rightKey, other.Attr))
		}
	}

	keymap := map[string][]string{}
	for i := 0; i < len(other.Result); i++ {
		result := other.Result[i]["__match__"]
		key := ""
		for _, k := range rightKey {
			key += other.Result[i][k]
		}
		_, ok := keymap[key]
		if !ok {
			keymap[key] = []string{}
		}
		keymap[key] = append(keymap[key], result)
	}

	result_list := [][]string{}

	key_to_index := map[string]int{}
	for i := 0; i < len(s.Result); i++ {
		key := ""
		for _, k := range leftKey {
			key += s.Result[i][k]
		}
		_, ok := keymap[key]
		if ok {
			_, ok := key_to_index[key]
			if !ok {
				key_to_index[key] = len(result_list)
				tmp_list := []string{}
				result_list = append(result_list, tmp_list)
			}

			result_list[key_to_index[key]] = append(result_list[key_to_index[key]],
				s.Result[i]["__match__"])
			result_list[key_to_index[key]] = append(result_list[key_to_index[key]],
				strings.Join(keymap[key], "\n"))
			delete(keymap, key)

			//result := s.Result[i]["__match__"] + "\n" + strings.Join(keymap[key], "\n")
			//result := s.Result[i]["__match__"] + list[v]
			//result_list = append(result_list, result)
		} else {
			_, ok = key_to_index[key]
			result_list[key_to_index[key]] = append(result_list[key_to_index[key]],
				s.Result[i]["__match__"])
		}

	}
	if len(result_list) > 0 {
		result := []string{}
		for i, _ := range result_list {
			result = append(result, strings.Join(result_list[i], "\n"))
		}
		//for _, e := range result {
		//fmt.Printf("e = %+v\n", e)
		//}
		return result, nil
	} else {
		return nil, nil
	}

	//keymap := map[string]int{}
	//list := []string{}
	//for i := 0; i < len(other.Result); i++ {
	//result := other.Result[i]["__match__"]
	//key := ""
	//for _, k := range rightKey {
	//key += other.Result[i][k]
	//}
	//keymap[key] = len(list)
	//list = append(list, result)
	//}

	//result_list := []string{}
	//for i := 0; i < len(s.Result); i++ {
	//key := ""
	//for _, k := range leftKey {
	//key += s.Result[i][k]
	//}
	//v, ok := keymap[key]
	//if ok {
	//result := s.Result[i]["__match__"] + "\n" + list[v]
	////result := s.Result[i]["__match__"] + list[v]
	//result_list = append(result_list, result)
	//}
	//}

	//if len(result_list) > 0 {
	//return result_list, nil
	//} else {
	//return nil, nil
	//}
}

// 将两个匹配结果集进行组合，主要用于文本预处理场景，用于将两个匹配结果进行拼接
// 拼接的方法:
// 1.只有包含了关键字字段的结果才能进行拼接
// 2.拼接保持了s中的顺序
func (s SplitterResult) GroupWith(other *SplitterResult, key string) ([]string, error) {
	if len(other.Result) == 0 || len(s.Result) == 0 {
		return nil, nil
	}

	if key == "" {
		return nil, errors.New(fmt.Sprintf("key is nil string"))
	}

	in := false
	for _, k := range s.Attr {
		if k == key {
			in = true
		}
	}
	if !in {
		return nil, errors.New(fmt.Sprintf("key: %s, not in this: %+v", key, s.Attr))
	}

	in = false
	for _, k := range other.Attr {
		if k == key {
			in = true
		}
	}
	if !in {
		return nil, errors.New(fmt.Sprintf("key: %s, not in other: %+v", key, other.Attr))
	}

	keymap := map[string]int{}
	list := []string{}
	for i := 0; i < len(other.Result); i++ {
		result := other.Result[i]["__match__"]
		keymap[other.Result[i][key]] = len(list)
		list = append(list, result)
	}

	result_list := []string{}
	for i := 0; i < len(s.Result); i++ {
		v, ok := keymap[s.Result[i][key]]
		if ok {
			result := s.Result[i]["__match__"] + "\n" + list[v]
			//result := s.Result[i]["__match__"] + list[v]
			result_list = append(result_list, result)
		}
	}

	if len(result_list) > 0 {
		return result_list, nil
	} else {
		return nil, nil
	}
}

// 主要用于文本的预处理，将匹配结果以给定关键字为key，进行拼接
// 如果fields字段为nil或长度为0，则用__match__进行拼接，否则用fields包含的字段进行拼接
// first和offset同时为-1时，表示在所有结果中进行拼接
// first为负，表示从末尾开始计数，-1表示最后，相当与last(s.Result)-1,first = len(s.Result) + first
// offset为-1时，表示从first直到s.Result的末尾
// 注意:最终数据以各关键字在文本中出现的先后为顺序
func (s SplitterResult) ConcatString(fields []string, first int,
	offset int, key string) ([]string, error) {
	last := first + offset
	if offset <= 0 {
		if offset != -1 {
			return nil, errors.New(fmt.Sprintf("first: %d, offset: %d, len(s.Result) = %d",
				first, offset, len(s.Result)))
		}
	}

	if first < 0 {
		if len(s.Result)+first < 0 {
			return nil, errors.New(fmt.Sprintf("first: %d, offset: %d, len(s.Result) = %d",
				first, offset, len(s.Result)))
		} else {
			first = len(s.Result) + first
			last = first + offset
		}
	}

	if offset == -1 {
		last = len(s.Result)
	}

	if first >= len(s.Result) || last > len(s.Result) || first > last {
		return nil, errors.New(fmt.Sprintf("first: %d, offset: %d, len(s.Result) = %d",
			first, offset, len(s.Result)))
	}

	if key == "" {
		return nil, errors.New(fmt.Sprintf("key is nil"))
	}

	in := false
	for _, k := range s.Attr {
		if k == key {
			in = true
		}
	}

	if !in {
		return nil, errors.New(fmt.Sprintf("key: %s, not in %+v", key, s.Attr))
	}

	if first == -1 {
		first = 0
		last = len(s.Result) - 1
	}

	list := []string{}
	keymap := map[string]int{}
	for i := first; i < last; i++ {
		result := ""
		if fields == nil || len(fields) == 0 {
			result += "\n" + s.Result[i]["__match__"]
			//result += s.Result[i]["__match__"]
		} else {
			for _, f := range fields {
				_, ok := s.Result[i][f]
				if ok {
					if s.Result[i][f] != "" {
						result += "\n" + s.Result[i][f]
						//result += s.Result[i][f]
					}
				} else {
					return nil, errors.New(fmt.Sprintf("field: %s is not exists", f))
				}
			}
		}
		if result != "" {
			v, ok := keymap[s.Result[i][key]]
			if ok {
				list[v] += result
			} else {
				keymap[s.Result[i][key]] = len(list)
				list = append(list, result)
			}
		}
	}

	return list, nil
}

// 主要用于文本的预处理
// 如果fields字段为nil或长度为0，则用__match__进行拼接，否则用fields包含的字段进行拼接
// first和offset同时为-1时，表示在所有结果中进行拼接
// first为负，表示从末尾开始计数，-1表示最后，相当与last(s.Result)-1,first = len(s.Result) + first
// offset为-1时，表示从first直到s.Result的末尾
func (s SplitterResult) Filter(fields []string, first int, offset int) ([]string, error) {
	last := first + offset
	if offset <= 0 {
		if offset != -1 {
			return nil, errors.New(fmt.Sprintf("first: %d, offset: %d, len(s.Result) = %d",
				first, offset, len(s.Result)))
		}
	}

	if first < 0 {
		if len(s.Result)+first < 0 {
			return nil, errors.New(fmt.Sprintf("first: %d, offset: %d, len(s.Result) = %d",
				first, offset, len(s.Result)))
		} else {
			first = len(s.Result) + first
			last = first + offset
		}
	}

	if offset == -1 {
		last = len(s.Result)
	}

	if first >= len(s.Result) || last > len(s.Result) || first > last {
		return nil, errors.New(fmt.Sprintf("first: %d, offset: %d, len(s.Result) = %d",
			first, offset, len(s.Result)))
	}

	//if first >= len(s.Result) || first > last || last >= len(s.Result) {
	//return nil, errors.New(fmt.Sprintf("first: %d, last: %d, len(s.Result) = %d",
	//first, last, len(s.Result)))
	//} else if first < 0 || last < 0 {
	//if !(first == -1 && last == -1) {
	//return nil, errors.New(fmt.Sprintf("first: %d, last: %d, len(s.Result) = %d",
	//first, last, len(s.Result)))
	//}
	//}

	//if first == -1 {
	//first = 0
	//last = len(s.Result) - 1
	//}

	list := []string{}
	for i := first; i < last; i++ {
		result := ""
		if fields == nil || len(fields) == 0 {
			result += "\n" + s.Result[i]["__match__"]
			//result += s.Result[i]["__match__"]
		} else {
			for _, f := range fields {
				_, ok := s.Result[i][f]
				if ok {
					if s.Result[i][f] != "" {
						result += "\n" + s.Result[i][f]
						//result += s.Result[i][f]
					}
				} else {
					return nil, errors.New(fmt.Sprintf("field: %s is not exists", f))
				}
			}
		}
		if result != "" {
			list = append(list, result)
		}
	}

	return list, nil
}

type SplitterResultIterator struct {
	sr    *SplitterResult
	index int
}

func (sp *SplitterResult) Iterator() *SplitterResultIterator {
	return &SplitterResultIterator{
		sp,
		0,
	}
}

func (it *SplitterResultIterator) HasNext() bool {
	return it.index < len(it.sr.Result)
}

func (it *SplitterResultIterator) Next() (int, []string, map[string]string) {
	e := it.sr.Result[it.index]
	index := it.index
	it.index++
	return index, it.sr.Attr, e
}

///////////////////////////////////////////////////////////////////////////

type Splitter struct {
	Regex      string   `json:"regex"`
	Name       string   `json:"name"`
	Flags      string   `json:"flags"`
	Pcre       bool     `json:"pcre"`
	pcreGroups []string `json:"pcre_groups"`
	//Attr  []string `json:"attr"`
}

// 从json字串中提取Splitter，
func GroupWithRegexFilter(j string, fields []string, first int, last int, data string) ([]string, error) {
	sp, err := NewSplitterFromJson(j)
	if err != nil {
		return nil, err
	}
	res, err := sp.Input(data)
	if err != nil {
		return nil, err
	}
	return res.Filter(fields, first, last)
}

func GroupWithMultipleRegex(j1 string, j2 string, key string, data string) ([]string, error) {
	sp1, err := NewSplitterFromJson(j1)
	if err != nil {
		return nil, err
	}

	sp2, err := NewSplitterFromJson(j2)
	if err != nil {
		return nil, nil
	}

	res1, err := sp1.Input(data)
	if err != nil {
		return nil, err
	}

	res2, err := sp2.Input(data)
	if err != nil {
		return nil, err
	}

	return res1.GroupWith(res2, key)
}

func SplitterProcessOneTime(m map[string]string, data string) (*SplitterResult, error) {
	sp, err := NewSplitterFromMap(m)
	if err != nil {
		return nil, err
	}
	r, err := sp.Input(data)
	if err != nil {
		return r, err
	}
	if r.Len() != 0 {
		return r, nil
	} else {
		return r, nil
	}
}

func NewSplitterFromJson(j string) (*Splitter, error) {
	var sp Splitter
	err := json.Unmarshal([]byte(j), &sp)
	//if sp.Pcre {
	//r, _ := regexp.Compile("\\(\\?P\\<(?P<name>[\\w]+)\\>")
	//columns := r.SubexpNames()
	//res := r.FindAllStringSubmatch(sp.Regex, -1)
	//if res != nil {
	////fmt.Printf("res[0] = %+v\n", res[0])
	//for _, row := range res {
	//for k, v := range row {
	//if columns[k] == "name" {
	//sp.pcreGroups = append(sp.pcreGroups, v)
	//}
	//}

	//}
	//}

	//}

	if err != nil {
		return nil, err
	}
	return &sp, nil
}

func NewSplitterFromMap(m map[string]string) (*Splitter, error) {
	regex, ok := m["regex"]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%+v", m))
	}

	name, ok := m["name"]
	if !ok {
		return nil, errors.New(fmt.Sprintf("%+v", m))
	}

	flags, ok := m["flags"]
	if !ok {
		flags = ""
	}
	//group := []string{}
	p, ok := m["pcre"]
	pcre := false

	if ok {
		//r, _ := regexp.Compile("\\(\\?P\\<(?P<name>[\\w]+)\\>")
		//columns := r.SubexpNames()
		//res := r.FindAllStringSubmatch(regex, -1)
		//if res != nil {
		//for k, v := range res[0] {
		//if columns[k] == "name" {
		//group = append(group, v)
		//}
		//}
		//}
		if p == "true" {
			pcre = true
		}
	}

	return &Splitter{
		regex,
		name,
		flags,
		pcre,
		nil,
	}, nil
}

func (s Splitter) Revert(text string) (string, error) {
	if s.Pcre {
		return s.PCRERevert(text)
	}

	regex := s.Regex
	if s.Flags != "" {
		regex = fmt.Sprintf("(?%s)%s", s.Flags, s.Regex)
	}

	re, err := regexp.Compile(regex)
	if err != nil {
		return "", err
	}

	buffer := []byte(text)
	offset := 0
	rb := new(bytes.Buffer)

	for {
		loc := re.FindIndex(buffer[offset:])
		if loc == nil {
			rb.Write(buffer[offset:])
			return rb.String(), nil
		} else {
			if loc[0] > 0 {
				rb.Write(buffer[offset : offset+loc[0]])
			}
			//offset = offset + loc[1] + 1
			offset = offset + loc[1]

			if offset >= len(buffer) {
				return rb.String(), nil
			}
		}
	}
}

func (s Splitter) Input(text string) (*SplitterResult, error) {
	if s.Pcre {
		r, _ := regexp.Compile("\\(\\?P\\<(?P<name>[\\w]+)\\>")
		columns := r.SubexpNames()
		res := r.FindAllStringSubmatch(s.Regex, -1)
		if res != nil {
			for _, row := range res {
				for k, v := range row {
					if columns[k] == "name" {
						s.pcreGroups = append(s.pcreGroups, v)
					}
				}

			}
		}

		return s.PCREInput(text)
	}
	regex := s.Regex
	if s.Flags != "" {
		regex = fmt.Sprintf("(?%s)%s", s.Flags, s.Regex)
	}

	r, err := regexp.Compile(regex)
	if err != nil {
		return &SplitterResult{}, err
	}

	columns := r.SubexpNames()
	res := r.FindAllStringSubmatch(text, -1)

	list := []map[string]string{}
	names := []string{}
	for id, row := range res {
		md := map[string]string{}
		for k, v := range row {
			md["__id__"] = fmt.Sprintf("%d", id)
			if k == 0 {
				md["__match__"] = v
				if id == 0 {
					names = append(names, "__match__")
				}
			} else {
				if columns[k] != "" {
					md[columns[k]] = v
					if id == 0 {
						names = append(names, columns[k])
					}
				}
			}
		}
		list = append(list, md)
	}

	columns[0] = "__match__"
	return &SplitterResult{
		names,
		list,
	}, nil
}

//
//
//
// func (s Splitter) Input(text string) (*SplitterResult, error) {
// if s.Pcre {
// r, _ := regexp.Compile("\\(\\?P\\<(?P<name>[\\w]+)\\>")
// columns := r.SubexpNames()
// res := r.FindAllStringSubmatch(s.Regex, -1)
// if res != nil {
// for _, row := range res {
// for k, v := range row {
// if columns[k] == "name" {
// s.pcreGroups = append(s.pcreGroups, v)
// }
// }
//
// }
// }
//
// return s.PCREInput(text)
// }
// regex := s.Regex
// if s.Flags != "" {
// regex = fmt.Sprintf("(?%s)%s", s.Flags, s.Regex)
// }
//
// r, err := regexp.Compile(regex)
// if err != nil {
// return nil, err
// }
//
// columns := r.SubexpNames()
// res := r.FindAllStringSubmatch(text, -1)
//
// list := []map[string]string{}
// names := []string{}
// for id, row := range res {
// md := map[string]string{}
// for k, v := range row {
// md["__id__"] = fmt.Sprintf("%d", id)
// if k == 0 {
// md["__match__"] = v
// if id == 0 {
// names = append(names, "__match__")
// }
// } else {
// if columns[k] != "" {
// md[columns[k]] = v
// if id == 0 {
// names = append(names, columns[k])
// }
// }
// }
// }
// list = append(list, md)
// }
//
// columns[0] = "__match__"
// return &SplitterResult{
// names,
// list,
// }, nil
// }
//
//func (s Splitter) PCREInput(text string) (*SplitterResult, error) {
//regex := s.Regex
//if s.Flags != "" {
//regex = fmt.Sprintf("(?%s)%s", s.Flags, s.Regex)
//}

//r, err := regexp.Compile(regex)
//if err != nil {
//return nil, err
//}

//columns := r.SubexpNames()
//res := r.FindAllStringSubmatch(text, -1)

//list := []map[string]string{}
//names := []string{}
//for id, row := range res {
//md := map[string]string{}
//for k, v := range row {
//md["__id__"] = fmt.Sprintf("%d", id)
//if k == 0 {
//md["__match__"] = v
//if id == 0 {
//names = append(names, "__match__")
//}
//} else {
//if columns[k] != "" {
//md[columns[k]] = v
//if id == 0 {
//names = append(names, columns[k])
//}
//}
//}
//}
//list = append(list, md)
//}

//columns[0] = "__match__"
//return &SplitterResult{
//names,
//list,
//}, nil
//}

// convertPCREToRegexp2 将 PCRE 语法转换为 regexp2 语法
// 主要转换: (?P<name>...) -> (?<name>...)
func convertPCREToRegexp2(pcreRegex string) string {
	// 使用正则表达式替换 (?P<name>...) 为 (?<name>...)
	re := regexp.MustCompile(`\(\?P<([^>]+)>`)
	return re.ReplaceAllString(pcreRegex, `(?<$1>`)
}

// func TestPCRERegexp(t *testing.T) {
func (s Splitter) PCRERevert(text string) (string, error) {
	// 构建 regexp2 选项
	opts := regexp2.None
	if strings.Contains(s.Flags, "m") {
		opts |= regexp2.Multiline
	}
	if strings.Contains(s.Flags, "s") {
		opts |= regexp2.Singleline // DOTALL in PCRE
	}
	if strings.Contains(s.Flags, "i") {
		opts |= regexp2.IgnoreCase
	}

	// regexp2 默认支持非贪婪匹配，UNGREEDY 标志不需要单独设置
	// EXTENDED (x) 标志在 regexp2 中通过 (?x) 内联标志处理

	// 转换 PCRE 语法到 regexp2 语法
	regexp2Pattern := convertPCREToRegexp2(s.Regex)
	re, err := regexp2.Compile(regexp2Pattern, opts)
	if err != nil {
		return "", fmt.Errorf("failed to compile regex: %w", err)
	}

	buffer := text
	offset := 0
	rb := new(bytes.Buffer)

	for {
		m, err := re.FindStringMatchStartingAt(buffer, offset)
		if err != nil {
			return "", fmt.Errorf("regex match error: %w", err)
		}
		if m == nil {
			rb.WriteString(buffer[offset:])
			return rb.String(), nil
		}

		// 写入匹配前的文本
		if m.Index > offset {
			rb.WriteString(buffer[offset:m.Index])
		}

		// 跳过匹配的文本
		offset = m.Index + m.Length

		if offset >= len(buffer) {
			return rb.String(), nil
		}
	}
}

func (s Splitter) PCREInput(text string) (*SplitterResult, error) {
	// 构建 regexp2 选项
	opts := regexp2.None
	if strings.Contains(s.Flags, "m") {
		opts |= regexp2.Multiline
	}
	if strings.Contains(s.Flags, "s") {
		opts |= regexp2.Singleline // DOTALL in PCRE
	}
	if strings.Contains(s.Flags, "i") {
		opts |= regexp2.IgnoreCase
	}

	// regexp2 默认支持非贪婪匹配，UNGREEDY 标志不需要单独设置
	// EXTENDED (x) 标志在 regexp2 中通过 (?x) 内联标志处理

	// 转换 PCRE 语法到 regexp2 语法
	regexp2Pattern := convertPCREToRegexp2(s.Regex)
	re, err := regexp2.Compile(regexp2Pattern, opts)
	if err != nil {
		return &SplitterResult{}, fmt.Errorf("failed to compile regex: %w", err)
	}

	list := []map[string]string{}
	index := 0
	offset := 0

	for {
		m, err := re.FindStringMatchStartingAt(text, offset)
		if err != nil {
			return &SplitterResult{}, fmt.Errorf("regex match error: %w", err)
		}
		if m == nil {
			break
		}

		mp := map[string]string{}
		mp["__match__"] = m.String()
		mp["__id__"] = fmt.Sprintf("%d", index)
		index++

		// 提取命名捕获组
		for _, name := range s.pcreGroups {
			group := m.GroupByName(name)
			if group != nil && group.Length > 0 {
				mp[name] = group.String()
			}
		}

		list = append(list, mp)
		offset = m.Index + m.Length

		if offset >= len(text) {
			break
		}
	}

	columns := []string{"__match__"}
	columns = append(columns, s.pcreGroups...)
	return &SplitterResult{
		columns,
		list,
	}, nil
}

func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func GetFieldByRegex(regex, data string, fields []string) (results map[string]string, err error) {
	regexMap := map[string]string{
		"regex": regex,
		"flags": "m",
		"pcre":  "true",
		"name":  "regex",
	}

	regexResult, err := SplitterProcessOneTime(regexMap, data)
	if err != nil {
		return
	}

	m, ok := regexResult.One()
	if !ok {
		err = fmt.Errorf("result is empty")
		return
	}

	results = map[string]string{}

	for _, field := range fields {
		results[field] = m[field]
	}

	return
}

func IndentSection(txt string) *SplitterResult {
	indentRegexMap := map[string]string{
		"regex": `(?P<section>^[\w\-][^\n]+(\n[ \t]+[^\n]+)+)`,
		"name":  "intent",
		"flags": "m",
		"pcre":  "true",
	}

	indentRegexSplitter, err := NewSplitterFromMap(indentRegexMap)
	if err != nil {
		panic(err)
	}

	indentResult, err := indentRegexSplitter.Input(txt)
	if err != nil {
		panic(err)
	}

	// fmt.Println(indentResult)
	return indentResult
}

func IndentSection2(txt string) []string {
	sectionMapRegex := map[string]string{
		"regex": `(?P<all>^(?P<prefix>[ ]+)\w[^\n]+)`,
		"name":  "all",
		"flags": "m",
		"pcre":  "true",
	}

	sectionResult, err := SplitterProcessOneTime(sectionMapRegex, txt)
	if err != nil {
		panic(err)
	}

	var result []string
	var records []string
	var prefixLen int
	for i := 0; i < len(sectionResult.Result); {
		sm := sectionResult.Result[i]

		if i != 0 {
			result = append(result, strings.Join(records, "\n"))
		}
		records = []string{}
		records = append(records, sm["all"])
		prefixLen = len(sm["prefix"])

		for j := i + 1; j < len(sectionResult.Result); {
			child := sectionResult.Result[j]
			if len(child["prefix"]) > prefixLen {
				records = append(records, child["all"])
			} else {
				i = j - 1
				break
			}
			// 防止最后一条数据数据可能重复记录的情况

			i = j
			j += 1

		}
		i += 1
	}

	if len(records) > 0 {
		result = append(result, strings.Join(records, "\n"))
	}

	return result

}

func RegexSplit(re string, text string) []string {
	rePattern := regexp.MustCompile(re)
	return rePattern.Split(text, -1)
}
