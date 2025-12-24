package utils_own

import (
	"fmt"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/text"
	"path/filepath"
	"regexp"
	"strings"
)

func WorkorderData(dir string) (table *clitask.Table, err error) {
	dirName := strings.TrimSpace(filepath.Base(dir))

	sections := text.RegexSplit(`[\(（]全[\)）]`, dirName)
	if len(sections) != 2 {
		err = fmt.Errorf("文件夹命名格式不规范, 需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA, '全'表示信息已经提供完整")
		return
	}
	var data map[string]string
	data, err = sectionPre(sections[0])
	if err != nil {
		return
	}
	var name string
	if name, err = sectionSuf(sections[1]); err != nil {
		return
	}
	data["name"] = name
	header := []string{}
	for key := range data {
		header = append(header, key)
	}
	table = clitask.NewEmptyTableWithKeys(header)
	err = table.PushRow("", data, false, "")
	if err != nil {
		return
	}
	// table.Pretty()
	return
}

func sectionPre(f string) (data map[string]string, err error) {
	data = make(map[string]string)
	f = strings.TrimSpace(f)
	tokens := text.RegexSplit(`-+`, f)
	if len(tokens) < 3 {
		err = fmt.Errorf("文件夹命名格式不规范，需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA")
		return
	}

	reItsmID := regexp.MustCompile(`\d{4}$`)
	itsmID := tokens[0]
	if !reItsmID.MatchString(itsmID) {
		err = fmt.Errorf("ITSM ID不符合规范, 需要格式为: XXXX(4位数字)")
		return
	}
	data["itsmID"] = reItsmID.FindString(itsmID)
	data["operator"] = tokens[len(tokens)-1]
	var projectName string
	for i := 1; i < len(tokens)-1; i++ {
		projectName += tokens[i]
	}
	data["projectName"] = projectName
	return
}

func sectionSuf(f string) (name string, err error) {
	// 包含"加急"等字段的文件夹，暂时作为非法工单处理，但是后续需要共同制定加急工单的标准格式
	nameList := []string{"汤闻辉", "石麟", "王奇", "毛晓闻", "奚建春", "周晓"}
	f = strings.TrimSpace(f)
	f = strings.Trim(f, "-")
	if len(f) == 0 {
		err = fmt.Errorf("文件夹命名格式不规范, 需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA")
		return
	}

	if strings.Contains(f, "已分配") {
		err = fmt.Errorf("工单信息已分配")
		return
	}

	for _, n := range nameList {
		if n == f {
			name = n
			return
		}
	}

	err = fmt.Errorf("文件夹命名格式不规范, 需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA")
	return
}

func WorkorderServerData(data map[string][][]string) (table *clitask.Table, err error) {
	if len(data) != 1 {
		err = fmt.Errorf("file data result error: the length is false")
		return
	}
	for _, fileData := range data {
		header, content, _ := csvDataToMapList(fileData)
		table = clitask.NewEmptyTableWithKeys(header)
		for _, element := range content {
			table.PushRow("", element, false, "")
		}
		table.Pretty()
	}
	return
}

func csvDataToMapList(data [][]string) (header []string, content []map[string]string, err error) {
	if len(data) < 1 {
		err = fmt.Errorf("file content is null")
		return
	}
	header = data[0]

	fileData := data[1:]
	for _, row := range fileData {
		element := make(map[string]string)
		for i, h := range header {
			if i >= len(row) {
				element[h] = ""
				continue
			}
			element[h] = row[i]
		}
		content = append(content, element)
	}
	return
}
