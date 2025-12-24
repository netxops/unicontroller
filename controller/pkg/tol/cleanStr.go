package tol

import (
	"strings"
	"unicode"
)

func CleanStr(str string) (cleanStr string) {
	cleanStr = strings.Map(func(r rune) rune {
		if unicode.IsGraphic(r) {
			return r
		}
		return -1
	}, str)
	return
}

func CleanUnPrint(original string) (cleaned string) {
	cleaned = strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar {
			return -1 // 不可显示字符被转换为 rune(-1)，将被过滤掉
		}
		// 判断是否为可打印字符
		if !unicode.IsPrint(r) {
			return -1 // 不可显示字符被转换为 rune(-1)，将被过滤掉
		}
		return r
	}, original)
	return cleaned
}
