package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
)

type DistinctList []interface{}

func (dl DistinctList) Distinct() DistinctList {
	m := map[interface{}]int{}
	list := DistinctList{}
	for _, date := range dl {
		if _, ok := m[date]; ok == false {
			list = append(list, date)
			m[date] = 1
		}
	}

	return list
}

type Column struct {
	Name     string
	Table    *Table
	DataList DistinctList
}

// return NewColumn(name, t, data)
func NewColumn(name string, t *Table, data []interface{}) *Column {
	return &Column{
		Name:     name,
		Table:    t,
		DataList: data,
	}
}

func (cl *Column) List() DistinctList {
	return cl.DataList
}

type TableIterator struct {
	index int
	table *Table
}

type Table struct {
	Columns      []string
	Rows         [][]interface{}
	DefaultValue interface{}
}

type Row struct {
	Table    *Table
	DataList DistinctList
}

func NewRow(t *Table, cells []interface{}) *Row {
	return &Row{
		Table:    t,
		DataList: cells,
	}
}

func (r Row) List() DistinctList {
	return r.DataList
}

func (r Row) Cell(name string) interface{} {
	d := r.Cells(name)
	return d[0]
}

func (r Row) Cells(fields ...string) []interface{} {
	d := []interface{}{}

	for _, field := range fields {
		index := r.Table.ColumnIndex(field)
		if index == -1 {
			panic(fmt.Sprintf("%d out of range", index))
		}

		d = append(d, r.DataList[index])
	}

	return d
}

func (r Row) Map() map[string]interface{} {
	m := map[string]interface{}{}

	for index, name := range r.Table.Columns {
		m[name] = r.DataList[index]
	}

	return m
}

func (t *Table) ColumnIndex(name string) (index int) {
	for index, columnName := range t.Columns {
		if name == columnName {
			return index
		}
	}

	return -1
}

func (t *Table) Column(name string) *Column {
	index := -1
	for i, columnName := range t.Columns {
		if name == columnName {
			index = i
		}
	}

	if index == -1 {
		return nil
	}

	data := DistinctList{}
	for _, r := range t.Rows {
		data = append(data, r[index])
	}

	return NewColumn(name, t, data)
}

func (t *Table) Row(index int) *Row {
	if index < 0 && index > len(t.Rows)-1 {
		panic(fmt.Sprintf("%d out of range", index))
	}

	return NewRow(t, t.Rows[index])
}

func (t *Table) AddColumn(name string) {
	t.Columns = append(t.Columns, name)
}

func (t *Table) Push(data map[string]interface{}) {
	row := []interface{}{}
	for k, _ := range data {
		if Contains(t.Columns, k) == false {
			t.AddColumn(k)
		}
	}
	for _, c := range t.Columns {
		d := t.DefaultValue
		if v, ok := data[c]; ok {
			row = append(row, v)
		} else {
			row = append(row, d)
		}
	}

	t.Rows = append(t.Rows, row)
}

func (t *Table) GroupBy(fields ...string) []*Table {
	for _, f := range fields {
		if Contains(t.Columns, f) == false {
			panic(fmt.Sprintf("field {%s} not in columns", f))
		}
	}

	group := map[string][]int{}

	for index, r := range t.Rows {
		row := NewRow(t, r)
		cs := []string{}
		for _, c := range row.Cells(fields...) {
			cs = append(cs, fmt.Sprintf("%v", c))
		}
		value := strings.Join(cs, "|")
		if _, ok := group[value]; ok == false {
			group[value] = []int{}
		}
		group[value] = append(group[value], index)
	}

	groups := []*Table{}
	for _, indexList := range group {
		table := &Table{}
		for _, index := range indexList {
			row := NewRow(t, t.Rows[index])
			table.Push(row.Map())
		}
		groups = append(groups, table)
	}

	return groups
}

func (t *Table) PrettyPrint() {
	table := tablewriter.NewWriter(os.Stdout)

	// Convert []string to []any for Header
	headers := make([]any, len(t.Columns))
	for i, col := range t.Columns {
		headers[i] = col
	}
	table.Header(headers...)

	rows := [][]string{}
	for it := t.Iterator(); it.HasNext(); {
		row := []string{}
		_, data := it.Next()
		for _, column := range t.Columns {
			row = append(row, fmt.Sprint(data[column]))
		}
		rows = append(rows, row)
	}

	table.Bulk(rows)
	table.Render()
}

func (t *Table) Iterator() *TableIterator {
	return &TableIterator{
		index: 0,
		table: t,
	}
}

func (it *TableIterator) HasNext() bool {
	return it.index < len(it.table.Rows)
}

func (it *TableIterator) Next() (index int, data map[string]interface{}) {
	index = it.index
	data = it.table.Row(index).Map()
	it.index++

	return
}
