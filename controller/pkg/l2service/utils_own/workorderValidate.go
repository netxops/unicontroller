package utils_own

import (
	"fmt"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/validator"
	"path"
	"reflect"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
)

type AllocateIpaddress struct {
	DirNames []string
}

func AllotIpaddressValidator(allocateIpaddress *AllocateIpaddress) validator.Result {
	chain := validator.NewValidateChain()
	chain.Add(WorkorderValidate{})

	var data map[string]interface{}
	mapstructure.Decode(allocateIpaddress, &data)

	return chain.Validate(data)
}

type WorkorderValidate struct {
}

func (w WorkorderValidate) Validate(data map[string]interface{}) validator.Result {
	result := validator.NewValidateResult(true, "")

	return result
}

func FileNameFormatValidateChain(data map[string]interface{}) validator.Result {
	chain := validator.NewValidateChain()
	chain.Add(FileNameTypeValidator{})
	chain.Add(CompareFilenameAndDirnameValidator{})

	return chain.Validate(data)
}

//暂时验证文件是否是CSV文件
type FileNameTypeValidator struct {
}

func (fv FileNameTypeValidator) Validate(data map[string]interface{}) validator.Result {
	fileName := data["name"].(string)
	suffix := path.Ext(fileName)
	if strings.ToLower(strings.TrimSpace(suffix)) == ".csv" {
		return validator.NewValidateResult(true, "")
	}
	return validator.NewValidateResult(false, fmt.Sprintf("文件: %s 不是csv文件", fileName))
}

//校验文件名和文件夹名是否一致
type CompareFilenameAndDirnameValidator struct {
}

func (cv CompareFilenameAndDirnameValidator) Validate(data map[string]interface{}) validator.Result {
	fileName := data["name"].(string)
	dirName := data["dir"].(string)
	baseName := strings.TrimSuffix(fileName, path.Ext(fileName))
	if baseName != "" && strings.Contains(dirName, baseName) {
		return validator.NewValidateResult(true, "")
	}
	return validator.NewValidateResult(false, fmt.Sprintf("文件:%s 文件夹: %s 不匹配", fileName, dirName))
}

func DirNameFormatValidateChain(data map[string]interface{}) validator.Result {
	chain := validator.NewValidateChain()
	chain.Add(DirectoryNameValidator{})
	return chain.Validate(data)
}

// 校验文件夹名称是否符合规范
type DirectoryNameValidator struct {
}

func (dre DirectoryNameValidator) Validate(data map[string]interface{}) validator.Result {
	// dirs := data["IP地址分配"]
	// dirList := directoryNameForStr(dirs)

	dirName := data["name"].(string)
	if ok, msg := IsValidDir2(dirName); !ok {
		return validator.NewValidateResult(false, fmt.Sprintf("目录: %s 校验错误, %s", dirName, msg))
	}

	//
	// for _, dirName := range dirList {
	// if IsValidDir(dirName) {
	// result.AddError(validator.NewValidateResult(false, dirName))
	// }
	// }
	return validator.NewValidateResult(true, "")
}

func directoryNameForStr(obj interface{}) (list []string) {
	if reflect.TypeOf(obj).Kind() == reflect.Slice {
		s := reflect.ValueOf(obj)
		for i := 0; i < s.Len(); i++ {
			ele := s.Index(i)
			list = append(list, ele.Interface().(string))
		}
	}
	return
}

func IsValidDir(f string) bool {
	f = strings.TrimSpace(f)
	r := regexp.MustCompile(`^\d{4}-{1}.*-{1}[^\x00-\xff]+(\(|（)全(\)|）)-{1}[\x00-\xff]+`)
	return r.MatchString(f)
}

func sectionOne(f string) (bool, string) {
	f = strings.TrimSpace(f)
	tokens := text.RegexSplit(`-+`, f)
	if len(tokens) < 3 {
		return false, "文件夹命名格式不规范，需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA"
	}

	itsmID := tokens[0]
	if !regexp.MustCompile(`\d{4}$`).MatchString(itsmID) {
		return false, "ITSM ID不符合规范, 需要格式为: XXXX(4位数字)"
	}

	return true, ""
}

func sectionTwo(f string) (bool, string) {
	// 包含"加急"等字段的文件夹，暂时作为非法工单处理，但是后续需要共同制定加急工单的标准格式
	nameList := []string{"汤闻辉", "石麟", "王奇", "毛晓闻", "奚建春", "周晓"}
	f = strings.TrimSpace(f)
	f = strings.Trim(f, "-")
	if len(f) == 0 {
		return false, "文件夹命名格式不规范, 需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA"
	}

	if strings.Contains(f, "已分配") {
		return false, "工单信息已分配"
	}

	for _, name := range nameList {
		if name == f {
			return true, ""
		}
	}

	return false, "文件夹命名格式不规范, 需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA"

}

func IsValidDir2(f string) (bool, string) {
	f = strings.TrimSpace(f)

	sections := text.RegexSplit(`[\(（]全[\)）]`, f)
	if len(sections) != 2 {
		return false, "文件夹命名格式不规范, 需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA, '全'表示信息已经提供完整"
	}

	if ok, msg := sectionOne(sections[0]); !ok {
		return false, msg
	}

	if ok, msg := sectionTwo(sections[1]); !ok {
		return false, msg
	}

	//
	// tokens := strings.Split(f, "-")
	// if len(tokens) != 4 {
	// return false, "文件夹命名格式不规范, 需要格式为：XXXX-YYYYYYYYYY-ZZZ（全）-AAA"
	// }

	// projectName := tokens[1]
	// operator := tokens[2]
	// name := token[3]

	// projectName暂时不校验，未来可考虑从ITSM系统获取ProjectName
	// if !regexp.MustCompile(`.*[\(（]全[\)）]`).MatchString(operator) {
	// return false, "主管姓名和信息完整性标志不符合规范， 需要格式为：ZZZ（全）"
	// }

	// 王奇(已分配)
	//

	return true, ""
	// r := regexp.MustCompile(`^\d{4}-{1}.*-{1}[^\x00-\xff]+(\(|（)全(\)|）)-{1}[\x00-\xff]+`)
	// return r.MatchString(f)
}
