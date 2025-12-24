package jsonc

import (
	"encoding/json"
)

func Unmarshal(data []byte, v interface{}) error {
	j := translate(data)
	return json.Unmarshal(j, v)
}
