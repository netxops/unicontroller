package utils

import "math/big"

func CopyInt(src *big.Int) *big.Int {
	r := new(big.Int)
	r.Set(src)
	return r
}

func AddInt(x *big.Int, y int64) *big.Int {
	r := new(big.Int)
	r = r.Add(x, big.NewInt(y))
	return r
}
