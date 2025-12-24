package l2service

type LocalStorage struct {
	path string
}

func NewLocalStorage(path string) *LocalStorage {
	return &LocalStorage{path: path}
}
