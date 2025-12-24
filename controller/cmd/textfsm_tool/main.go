package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"github.com/netxops/gotextfsm"
)

//go:embed static/*
var staticFiles embed.FS

// TextFSMResult 表示textfsm解析结果
type TextFSMResult struct {
	Success bool                `json:"success"`
	Data    []map[string]string `json:"data,omitempty"`
	Error   string              `json:"error,omitempty"`
	Fields  []string            `json:"fields,omitempty"`
}

// RegexResult 表示正则表达式测试结果
type RegexResult struct {
	Success bool       `json:"success"`
	Matches []string   `json:"matches,omitempty"`
	Groups  [][]string `json:"groups,omitempty"`
	Error   string     `json:"error,omitempty"`
}

func main() {
	// 命令行参数
	var (
		host = flag.String("host", "localhost", "监听地址")
		port = flag.String("port", "8080", "监听端口")
	)
	flag.Parse()

	// 设置路由
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/textfsm", handleTextFSM)
	http.HandleFunc("/api/regex", handleRegex)

	// 静态文件服务
	http.Handle("/static/", http.FileServer(http.FS(staticFiles)))

	addr := fmt.Sprintf("%s:%s", *host, *port)
	fmt.Println("🚀 TextFSM & 正则表达式测试工具启动中...")
	fmt.Printf("📱 访问地址: http://%s\n", addr)
	fmt.Println("🛑 按 Ctrl+C 停止服务")

	// 启动服务器
	log.Fatal(http.ListenAndServe(addr, nil))
}

// 处理首页请求
func handleIndex(w http.ResponseWriter, r *http.Request) {
	// 读取HTML文件
	htmlContent, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "无法读取HTML文件", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(htmlContent)
}

// 处理TextFSM测试请求
func handleTextFSM(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Template string `json:"template"`
		Input    string `json:"input"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		response := TextFSMResult{
			Success: false,
			Error:   "请求解析错误: " + err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// 解析TextFSM模板
	fsm := gotextfsm.TextFSM{}
	err := fsm.ParseString(request.Template)
	if err != nil {
		response := TextFSMResult{
			Success: false,
			Error:   "TextFSM模板解析错误: " + err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// 执行解析
	parser := gotextfsm.ParserOutput{}
	err = parser.ParseTextString(request.Input, fsm, true)
	if err != nil {
		response := TextFSMResult{
			Success: false,
			Error:   "文本解析错误: " + err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// 转换结果格式
	var records []map[string]string
	for _, record := range parser.Dict {
		recordMap := make(map[string]string)
		for key, value := range record {
			if str, ok := value.(string); ok {
				recordMap[key] = str
			} else {
				recordMap[key] = fmt.Sprintf("%v", value)
			}
		}
		records = append(records, recordMap)
	}

	// 获取字段名
	var fields []string
	for key := range fsm.Values {
		fields = append(fields, key)
	}

	response := TextFSMResult{
		Success: true,
		Data:    records,
		Fields:  fields,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 处理正则表达式测试请求
func handleRegex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Pattern string `json:"pattern"`
		Input   string `json:"input"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		response := RegexResult{
			Success: false,
			Error:   "请求解析错误: " + err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// 编译正则表达式
	regex, err := regexp.Compile(request.Pattern)
	if err != nil {
		response := RegexResult{
			Success: false,
			Error:   "正则表达式编译错误: " + err.Error(),
		}
		json.NewEncoder(w).Encode(response)
		return
	}

	// 查找所有匹配
	matches := regex.FindAllString(request.Input, -1)

	// 查找所有捕获组
	allMatches := regex.FindAllStringSubmatch(request.Input, -1)

	response := RegexResult{
		Success: true,
		Matches: matches,
		Groups:  allMatches,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
