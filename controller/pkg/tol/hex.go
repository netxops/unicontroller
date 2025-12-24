package tol

import (
	"fmt"
	"strings"
)

func HexPDU(asntype byte, _ string, data interface{}) (result string, err error) {
	s := fmt.Sprintf("%x", data.([]byte))
	return strings.TrimRight(s, "0"), nil
}
