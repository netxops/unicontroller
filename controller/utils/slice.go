package utils

func Contains[T comparable](list []T, elem T) bool {
	for _, v := range list {
		if v == elem {
			return true
		}
	}
	return false
}
