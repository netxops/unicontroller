package utils

import "fmt"

type CopyAble interface {
	Copy() CopyAble
}

type List interface {
	Len() int
	List() []interface{}
	Add(s ...interface{}) bool
	Delete(index int) (bool, error)
	Insert(index int, s interface{}) (bool, error)
	Copy() BaseList
	Iterator() Iterator
}

type BaseList struct {
	L []interface{}
}

func (bl BaseList) Copy() CopyAble {
	r := BaseList{}
	for it := bl.Iterator(); it.HasNext(); {
		_, e := it.Next()
		ec := e.(CopyAble).Copy()
		r.L = append(r.L, ec)
	}

	return r
}

func NewBaseList(ls ...interface{}) BaseList {
	b := BaseList{}
	b.Add(ls...)
	return b
}

//func (bl *BaseList) Copy() BaseList {
//r := BaseList{}
//for it := bl.Iterator(); it.HasNext(); {
//_, e := it.Next()
//ec := e.(CopyAble).Copy()
//r.L = append(r.L, ec)
//}

//return r
//}

func (bl *BaseList) Len() int {
	return len(bl.L)
}

func (bl *BaseList) List() []interface{} {
	return bl.L
}

func (bl *BaseList) Insert(index int, s interface{}) (bool, error) {
	if index < 0 || index > len(bl.List()) {
		return false, fmt.Errorf("index: %d, len(r.List): %d", index, len(bl.List()))
	}
	if index == len(bl.List())-1 {
		bl.L = append(bl.List()[0:index+1], bl.List()[index:]...)
		bl.List()[index] = s
	} else {
		bl.L = append(bl.List()[0:index+1], bl.List()[index:]...)
		bl.List()[index] = s
	}
	return true, nil
}

func (bl *BaseList) Iterator() Iterator {
	return Iterator{
		bl,
		0,
		nil,
	}
}

func (bl *BaseList) Add(s ...interface{}) bool {
	bl.L = append(bl.L, s...)
	return true
}

//func (sl *ServiceList) Del(index int) (*ServiceInt, error) {
//if index < 0 || index >= len(sl.l) {
//return nil, fmt.Errorf("index: %d", index)
//}

//}

//func (sl *ServiceList) Add(s *ServiceInt) {
//sl.l = append(sl.l, s)
//}

func (bl *BaseList) Delete(index int) (bool, error) {
	if index < 0 || index > len(bl.List()) {
		return false, fmt.Errorf("index: %d, len(bl.List): %d", index, len(bl.List()))
	}

	if index == len(bl.List())-1 {
		bl.L = bl.List()[0:index]
	} else {
		bl.L = append(bl.List()[0:index], bl.List()[index+1:]...)
	}

	return true, nil
}

type Iterator struct {
	bl       *BaseList
	index    int
	register interface{}
}

func (i *Iterator) HasNext() bool {
	return i.index < len(i.bl.List())
}

func (i *Iterator) Delete() interface{} {
	d := i.bl.List()[i.index]

	i.bl.Delete(i.index)
	return d

	//v = i.bl.List()[i.index]
	//index = i.index
	//i.index++
	//return index, v

}

func (i *Iterator) Add(v interface{}) {
	i.bl.Insert(i.index, v)
}

func (i *Iterator) Next() (index int, v interface{}) {
	v = i.bl.List()[i.index]
	index = i.index
	i.index++
	return index, v
}
