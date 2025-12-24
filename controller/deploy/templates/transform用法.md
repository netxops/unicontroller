


# Expr 表达式引擎简要用法

## 基本用法
## 字段级表达式
对单个字段进行转换，使用 `value` 变量表示当前字段值：
```yaml
Regex: expr: strToUpper(value)           # 转大写
Regex: expr: int(toInt(value)) / 1000     # 数值计算
Regex: expr: value == "up"                # 布尔判断
```

```yaml
Mappings:
  - InputField: __expr__
    Regex: expr: device_name + " has " + string(len(interfaces)) + " interfaces"
```

## Transform YAML配置

```yaml
# 转换配置的名称，用于从系统描述中提取版本信息
name: iftableNameTransform

# 指定输出数据的类型为字符串到字符串的映射
dataType: map[string]string

# 定义一系列数据映射规则
mappings:
  # 第一个映射规则：从系统描述中提取版本信息
  - inputField: snmpIftableProcess  
    outputField: snmpIftableProcess                      
    regex: |
      expr: msRemoveSpaces(value, "name")            # 删除name字段中的空格
```

## 重要说明
1. inputField中引用其他Stage的输出有两种方法，一是整体引用（snmpIftableProcess），一是只引用字段（snmpIftableProcess#name）
2. inputField的引用方式，直接影响整个transform的输出。整体引用时，输出基本保持原有数据结果，比如引用一个[]map[string]string，则输出还是一个[]map[string]string；只引用字段时，只会输出该字段数据转换后的内容


## 常用函数
**字符串操作**：`strReplaceAll`, `strToUpper`, `strToLower`, `strTrim`, `matches`（正则）
**数组操作**：`arrayFirst`, `arrayLast`, `arrayContains`, `strJoin`
**类型转换**：`toInt`, `toFloat`, `toString`, `toBool`
**MapSlice 操作**：`msFilterBy`, `msTransformField`, `msRenameFields`, `msCountBy`
**工具函数**：`coalesce`, `defaultVal`, `isEmpty`, `len`
## 注意事项
- 所有数值运算结果会自动转换为字符串
- 支持的数据类型：`string`, `[]string`, `map[string]string`, `[]map[string]string`
- 表达式中的变量名对应 PipelineData 中的字段名

```
		// 字符串函数 (strX 前缀避免与 Expr 内置冲突)
		"strSplit":      stringsSplit,
		"strJoin":       stringsJoin,
		"strTrim":       stringsTrim,
		"strTrimSpace":  strings.TrimSpace,
		"strContains":   strings.Contains,
		"strHasPrefix":  strings.HasPrefix,
		"strHasSuffix":  strings.HasSuffix,
		"strReplace":    strings.Replace,
		"strReplaceAll": strings.ReplaceAll,
		"strToLower":    strings.ToLower,
		"strToUpper":    strings.ToUpper,
		"matches":       regexMatches,
		"match":         regexMatch,

		// 数组/切片函数
		"arrayFirst":    arrayFirst,
		"arrayLast":     arrayLast,
		"arrayContains": arrayContains,

		// 类型转换函数
		"toInt":    toInt,
		"toFloat":  toFloat,
		"toString": toString,
		"toBool":   toBool,

		// 工具函数
		"coalesce":   coalesce,
		"defaultVal": defaultValue,
		"isEmpty":    isEmpty,
		"isNotEmpty": isNotEmpty,

		// PipelineData 相关函数
		"pdKeys":   pdKeys,
		"pdGet":    pdGet,
		"pdType":   pdType,
		"pdHas":    pdHas,
		"pdLen":    pdLen,
		"pdGetAll": pdGetAll,

		// ============ 字段提取（改变数据结构：返回 []string）============
		// 输入：[]map[string]string, string(字段名)
		// 输出：[]string
		"msPluck":       pluckField,  // 输入: []map[string]string, string → 输出: []string
		"msPluckUnique": pluckUnique, // 输入: []map[string]string, string → 输出: []string

		// ============ 过滤（保持数据结构：返回 []map[string]string）============
		// 输入：[]map[string]string, string(字段名), string(值)
		// 输出：[]map[string]string
		"msFilterBy":       filterByField,    // 输入: []map[string]string, string, string → 输出: []map[string]string
		"msFilterMatches":  filterByRegex,    // 输入: []map[string]string, string, string(正则) → 输出: []map[string]string
		"msFilterContains": filterByContains, // 输入: []map[string]string, string, string(子串) → 输出: []map[string]string

		// ============ 转换（保持数据结构：返回 []map[string]string）============
		// 输入：[]map[string]string, string(字段名), function(转换函数)
		// 输出：[]map[string]string
		"msMapField":    mapFieldTransform, // 输入: []map[string]string, string, func → 输出: []map[string]string
		"msRenameField": renameField,       // 输入: []map[string]string, string(旧名), string(新名) → 输出: []map[string]string
		"msAddField":    addField,          // 输入: []map[string]string, string(字段名), string(值) → 输出: []map[string]string

		// ============ 常用字段转换（保持数据结构：返回 []map[string]string）============
		// 输入：[]map[string]string, string(字段名)
		// 输出：[]map[string]string
		"msRemoveSpaces": msRemoveSpaces, // 输入: []map[string]string, string → 输出: []map[string]string
		"msTrimField":    msTrimField,    // 输入: []map[string]string, string → 输出: []map[string]string
		"msUpperField":   msUpperField,   // 输入: []map[string]string, string → 输出: []map[string]string
		"msLowerField":   msLowerField,   // 输入: []map[string]string, string → 输出: []map[string]string

		// ============ 统一字段转换（保持数据结构：返回 []map[string]string）============
		// 输入：[]map[string]string, string(字段名), string(操作类型), string(操作参数，可选), string(目标字段名，可选)
		// 输出：[]map[string]string
		"msTransformField":        msTransformField,        // 输入: []map[string]string, string, string, string, string → 输出: []map[string]string
		"msCopyAndTransform":      msCopyAndTransform,      // 输入: []map[string]string, string(源), string(目标), string(操作), string(参数) → 输出: []map[string]string
		"msExtractRegex":          msExtractRegex,          // 输入: []map[string]string, string, string(正则), string(模式) → 输出: []map[string]string
		"msExtractRegexWithNames": msExtractRegexWithNames, // 输入: []map[string]string, string, string(正则), []string(新字段名) → 输出: []map[string]string

		// ============ 聚合（改变数据结构）============
		// 输入：[]map[string]string, string(字段名)
		"msGroupBy":  groupByField,    // 输入: []map[string]string, string → 输出: map[string][]map[string]string（分组）
		"msCountBy":  countByField,    // 输入: []map[string]string, string → 输出: map[string]string（统计计数）
		"msDistinct": distinctByField, // 输入: []map[string]string, string → 输出: []map[string]string（去重后仍为切片）

		// ============ 查找 ============
		// 输入：[]map[string]string, string(字段名), string(值)
		"msFindBy":    findByField, // 输入: []map[string]string, string, string → 输出: []map[string]string
		"msFindFirst": findFirst,   // 输入: []map[string]string, string, string → 输出: map[string]string（单个元素）

		// ============ 合并（改变数据结构：返回 map[string]string）============
		// 输入：...map[string]string（可变参数）
		// 输出：map[string]string
		"msMerge": mergeMaps, // 输入: ...map[string]string → 输出: map[string]string

		// ============ 组合函数（保持数据结构：返回 []map[string]string）============
		// 输入：[]map[string]string, string(过滤字段), string(过滤值), string(转换字段), string(操作类型), string(操作参数)
		// 输出：[]map[string]string
		"msFilterAndTransform": msFilterAndTransform, // 输入: []map[string]string, string, string, string, string, string → 输出: []map[string]string
		"msRenameFields":       msRenameFields,       // 输入: []map[string]string, map[string]string(重命名映射) → 输出: []map[string]string

		// ============ 便捷函数（保持数据结构：返回 []map[string]string）============
		// 输入：[]map[string]string, []string(字段列表) 或 []map[string]string, string, []string
		// 输出：[]map[string]string
		"msSelect":        SelectFields,  // 输入: []map[string]string, []string → 输出: []map[string]string
		"msWhereIn":       WhereIn,       // 输入: []map[string]string, string, []string → 输出: []map[string]string
		"msWhereNotEmpty": WhereNotEmpty, // 输入: []map[string]string, string → 输出: []map[string]string


// ============ 组合函数 ============

// msFilterAndTransform 先根据条件过滤，然后转换指定字段
// 输入: []map[string]string, string(过滤字段), string(过滤值), string(转换字段), string(操作类型), string(操作参数，可选)
// 输出: []map[string]string


// msRenameFields 批量重命名字段（直接重命名，不选择字段）
// 输入: []map[string]string, map[string]interface{}(旧名到新名的映射，会被转换为map[string]string)
// 输出: []map[string]string

```