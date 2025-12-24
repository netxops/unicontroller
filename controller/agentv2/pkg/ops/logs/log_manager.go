package logs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// LogQueryOptions 日志查询选项
type LogQueryOptions struct {
	Keyword   string     // 搜索关键词
	Level     string     // 日志级别过滤
	StartTime *time.Time // 开始时间
	EndTime   *time.Time // 结束时间
	Limit     int        // 返回的最大行数
	Offset    int        // 偏移量
	Reverse   bool       // 是否反向排序
}

// LogQueryResult 日志查询结果
type LogQueryResult struct {
	Logs    []string // 匹配的日志行
	Total   int      // 总行数（匹配条件的）
	HasMore bool     // 是否还有更多结果
}

// LogManager 日志管理器接口
type LogManager interface {
	CollectLogs(ctx context.Context, serviceID string, lines int) ([]string, error)
	GetLogFile(serviceID string) (io.ReadCloser, error)
	RotateLogs(serviceID string) error
	StreamLogs(ctx context.Context, serviceID string, tailLines int, follow bool, logChan chan<- string) error
	QueryLogs(ctx context.Context, serviceID string, options LogQueryOptions) (*LogQueryResult, error)
}

// logManager 日志管理器实现
type logManager struct {
	logDir   string
	maxSize  int64
	maxFiles int
	logger   *zap.Logger
}

// NewLogManager 创建日志管理器
func NewLogManager(logDir string, maxSize int64, maxFiles int, logger *zap.Logger) LogManager {
	return &logManager{
		logDir:   logDir,
		maxSize:  maxSize,
		maxFiles: maxFiles,
		logger:   logger,
	}
}

// CollectLogs 收集日志
func (m *logManager) CollectLogs(ctx context.Context, serviceID string, lines int) ([]string, error) {
	// 尝试从 systemd journal 收集日志
	logs, err := m.collectFromJournal(ctx, serviceID, lines)
	if err == nil {
		return logs, nil
	}

	// 如果 journal 失败，尝试从日志文件收集
	return m.collectFromFile(ctx, serviceID, lines)
}

// collectFromJournal 从 systemd journal 收集日志
func (m *logManager) collectFromJournal(ctx context.Context, serviceID string, lines int) ([]string, error) {
	// 使用 journalctl 命令获取日志
	args := []string{
		"-u", serviceID, // 使用服务 ID 作为 systemd unit 名称
		"-n", fmt.Sprintf("%d", lines),
		"--no-pager",
		"-o", "short-precise",
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get logs from journal: %w", err)
	}

	// 分割输出为行
	logs := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(logs) == 1 && logs[0] == "" {
		return []string{}, nil
	}

	return logs, nil
}

// collectFromFile 从日志文件收集日志
func (m *logManager) collectFromFile(ctx context.Context, serviceID string, lines int) ([]string, error) {
	logFile := m.getLogFilePath(serviceID)

	file, err := os.Open(logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// 获取文件大小
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat log file: %w", err)
	}

	// 如果文件为空，返回空列表
	if stat.Size() == 0 {
		return []string{}, nil
	}

	// 从文件末尾读取指定行数
	var result []string
	scanner := bufio.NewScanner(file)

	// 如果文件不大，直接读取所有行
	if stat.Size() < 1024*1024 { // 小于 1MB
		for scanner.Scan() {
			result = append(result, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to scan log file: %w", err)
		}

		// 返回最后 lines 行
		if len(result) > lines {
			return result[len(result)-lines:], nil
		}
		return result, nil
	}

	// 对于大文件，使用 tail 命令（如果可用）
	cmd := exec.CommandContext(ctx, "tail", "-n", fmt.Sprintf("%d", lines), logFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果 tail 失败，回退到简单方法
		return m.collectFromFileSimple(file, lines)
	}

	logs := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(logs) == 1 && logs[0] == "" {
		return []string{}, nil
	}
	return logs, nil
}

// collectFromFileSimple 简单方法：读取文件末尾的行
func (m *logManager) collectFromFileSimple(file *os.File, lines int) ([]string, error) {
	// 移动到文件末尾附近
	stat, _ := file.Stat()
	offset := stat.Size()
	if offset > 64*1024 { // 如果文件大于 64KB，只读取最后 64KB
		offset = 64 * 1024
	}

	_, err := file.Seek(stat.Size()-offset, io.SeekStart)
	if err != nil {
		return nil, err
	}

	var result []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		result = append(result, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// 返回最后 lines 行
	if len(result) > lines {
		return result[len(result)-lines:], nil
	}
	return result, nil
}

// GetLogFile 获取日志文件
func (m *logManager) GetLogFile(serviceID string) (io.ReadCloser, error) {
	logFile := m.getLogFilePath(serviceID)
	return os.Open(logFile)
}

// RotateLogs 轮转日志
func (m *logManager) RotateLogs(serviceID string) error {
	logFile := m.getLogFilePath(serviceID)

	info, err := os.Stat(logFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在，无需轮转
		}
		return err
	}

	// 检查文件大小
	if info.Size() < m.maxSize {
		return nil // 文件未超过大小限制
	}

	// 执行日志轮转
	timestamp := time.Now().Format("20060102-150405")
	rotatedFile := fmt.Sprintf("%s.%s", logFile, timestamp)

	if err := os.Rename(logFile, rotatedFile); err != nil {
		return fmt.Errorf("failed to rotate log file: %w", err)
	}

	// 清理旧日志文件
	m.cleanupOldLogs(serviceID)

	return nil
}

// getLogFilePath 获取日志文件路径
func (m *logManager) getLogFilePath(serviceID string) string {
	return filepath.Join(m.logDir, fmt.Sprintf("%s.log", serviceID))
}

// cleanupOldLogs 清理旧日志文件
func (m *logManager) cleanupOldLogs(serviceID string) {
	pattern := filepath.Join(m.logDir, fmt.Sprintf("%s.log.*", serviceID))

	matches, err := filepath.Glob(pattern)
	if err != nil {
		m.logger.Error("Failed to glob log files", zap.Error(err))
		return
	}

	// 按修改时间排序，保留最新的 maxFiles 个文件
	if len(matches) > m.maxFiles {
		// 获取文件信息并按修改时间排序
		type fileInfo struct {
			path    string
			modTime time.Time
		}

		files := make([]fileInfo, 0, len(matches))
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue
			}
			files = append(files, fileInfo{
				path:    match,
				modTime: info.ModTime(),
			})
		}

		// 按修改时间排序（旧的在前）
		for i := 0; i < len(files)-1; i++ {
			for j := i + 1; j < len(files); j++ {
				if files[i].modTime.After(files[j].modTime) {
					files[i], files[j] = files[j], files[i]
				}
			}
		}

		// 删除最旧的文件
		toDelete := len(files) - m.maxFiles
		for i := 0; i < toDelete; i++ {
			if err := os.Remove(files[i].path); err != nil {
				m.logger.Error("Failed to remove old log file", zap.String("file", files[i].path), zap.Error(err))
			}
		}
	}
}

// StreamLogs 流式读取日志（类似 tail -f）
func (m *logManager) StreamLogs(ctx context.Context, serviceID string, tailLines int, follow bool, logChan chan<- string) error {
	// 首先尝试从 systemd journal 流式读取
	if err := m.streamFromJournal(ctx, serviceID, tailLines, follow, logChan); err == nil {
		return nil
	}

	// 如果 journal 失败，从日志文件流式读取
	return m.streamFromFile(ctx, serviceID, tailLines, follow, logChan)
}

// streamFromJournal 从 systemd journal 流式读取日志
func (m *logManager) streamFromJournal(ctx context.Context, serviceID string, tailLines int, follow bool, logChan chan<- string) error {
	args := []string{
		"-u", serviceID,
		"--no-pager",
		"-o", "short-precise",
	}

	if tailLines > 0 {
		args = append(args, "-n", fmt.Sprintf("%d", tailLines))
	}

	if follow {
		args = append(args, "-f")
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start journalctl: %w", err)
	}

	// 读取输出并发送到 channel
	go func() {
		defer cmd.Wait()
		defer close(logChan)

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			case logChan <- scanner.Text():
			}
		}

		if err := scanner.Err(); err != nil {
			m.logger.Error("Error scanning journal output", zap.Error(err))
		}
	}()

	return nil
}

// streamFromFile 从日志文件流式读取
func (m *logManager) streamFromFile(ctx context.Context, serviceID string, tailLines int, follow bool, logChan chan<- string) error {
	logFile := m.getLogFilePath(serviceID)

	// 如果文件不存在，等待文件创建
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		if !follow {
			// 如果不跟踪，直接返回
			close(logChan)
			return nil
		}
		// 等待文件创建
		for {
			select {
			case <-ctx.Done():
				close(logChan)
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				if _, err := os.Stat(logFile); err == nil {
					goto fileExists
				}
			}
		}
	}

fileExists:
	file, err := os.Open(logFile)
	if err != nil {
		close(logChan)
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// 如果需要读取历史日志
	if tailLines > 0 {
		// 先读取最后 tailLines 行
		lines, err := m.collectFromFile(ctx, serviceID, tailLines)
		if err == nil {
			for _, line := range lines {
				select {
				case <-ctx.Done():
					file.Close()
					close(logChan)
					return ctx.Err()
				case logChan <- line:
				}
			}
		}
	}

	if !follow {
		// 如果不跟踪，关闭文件并返回
		file.Close()
		close(logChan)
		return nil
	}

	// 移动到文件末尾
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		close(logChan)
		return fmt.Errorf("failed to stat log file: %w", err)
	}

	// 移动到文件末尾
	_, err = file.Seek(stat.Size(), io.SeekStart)
	if err != nil {
		file.Close()
		close(logChan)
		return fmt.Errorf("failed to seek to end of file: %w", err)
	}

	// 持续读取新日志
	go func() {
		defer file.Close()
		defer close(logChan)

		scanner := bufio.NewScanner(file)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// 检查文件是否被轮转（文件大小变小）
				currentStat, err := os.Stat(logFile)
				if err != nil {
					return
				}
				currentPos, _ := file.Seek(0, io.SeekCurrent)
				if currentStat.Size() < currentPos {
					// 文件被轮转，重新打开
					file.Close()
					file, err = os.Open(logFile)
					if err != nil {
						return
					}
					// 移动到文件末尾
					file.Seek(0, io.SeekEnd)
				}

				// 读取新行
				if scanner.Scan() {
					select {
					case <-ctx.Done():
						return
					case logChan <- scanner.Text():
					}
				} else {
					// 没有新行，等待一下
					time.Sleep(100 * time.Millisecond)
					// 重新创建 scanner（因为文件可能被轮转）
					scanner = bufio.NewScanner(file)
				}
			}
		}
	}()

	return nil
}

// QueryLogs 查询日志（支持搜索、过滤、分页）
func (m *logManager) QueryLogs(ctx context.Context, serviceID string, options LogQueryOptions) (*LogQueryResult, error) {
	// 设置默认值
	if options.Limit <= 0 {
		options.Limit = 100
	}
	if options.Limit > 10000 {
		options.Limit = 10000 // 限制最大返回行数
	}

	// 尝试从 systemd journal 查询
	result, err := m.queryFromJournal(ctx, serviceID, options)
	if err == nil {
		return result, nil
	}

	// 如果 journal 失败，从日志文件查询
	return m.queryFromFile(ctx, serviceID, options)
}

// queryFromJournal 从 systemd journal 查询日志
func (m *logManager) queryFromJournal(ctx context.Context, serviceID string, options LogQueryOptions) (*LogQueryResult, error) {
	args := []string{
		"-u", serviceID,
		"--no-pager",
		"-o", "short-precise",
	}

	// 时间范围过滤
	if options.StartTime != nil {
		args = append(args, "--since", options.StartTime.Format("2006-01-02 15:04:05"))
	}
	if options.EndTime != nil {
		args = append(args, "--until", options.EndTime.Format("2006-01-02 15:04:05"))
	}

	// 日志级别过滤
	if options.Level != "" {
		args = append(args, "--priority", m.mapLevelToPriority(options.Level))
	}

	// 反向排序
	if options.Reverse {
		args = append(args, "-r")
	}

	// 限制行数（journalctl 需要先获取所有行，然后过滤）
	args = append(args, "-n", "10000") // 先获取最多 10000 行

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query logs from journal: %w", err)
	}

	// 分割输出为行
	allLogs := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(allLogs) == 1 && allLogs[0] == "" {
		allLogs = []string{}
	}

	// 关键词过滤
	filteredLogs := m.filterByKeyword(allLogs, options.Keyword)

	// 计算总数
	total := len(filteredLogs)

	// 分页
	start := options.Offset
	if start < 0 {
		start = 0
	}
	end := start + options.Limit
	if end > len(filteredLogs) {
		end = len(filteredLogs)
	}

	var result []string
	if start < len(filteredLogs) {
		result = filteredLogs[start:end]
	}

	return &LogQueryResult{
		Logs:    result,
		Total:   total,
		HasMore: end < len(filteredLogs),
	}, nil
}

// queryFromFile 从日志文件查询
func (m *logManager) queryFromFile(ctx context.Context, serviceID string, options LogQueryOptions) (*LogQueryResult, error) {
	logFile := m.getLogFilePath(serviceID)

	file, err := os.Open(logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	// 读取所有日志行
	var allLogs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// 时间过滤（如果日志行包含时间戳）
		if options.StartTime != nil || options.EndTime != nil {
			if !m.matchTimeRange(line, options.StartTime, options.EndTime) {
				continue
			}
		}

		// 日志级别过滤
		if options.Level != "" {
			if !m.matchLevel(line, options.Level) {
				continue
			}
		}

		// 关键词过滤
		if options.Keyword != "" {
			if !strings.Contains(strings.ToLower(line), strings.ToLower(options.Keyword)) {
				continue
			}
		}

		allLogs = append(allLogs, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan log file: %w", err)
	}

	// 反向排序
	if options.Reverse {
		for i, j := 0, len(allLogs)-1; i < j; i, j = i+1, j-1 {
			allLogs[i], allLogs[j] = allLogs[j], allLogs[i]
		}
	}

	// 计算总数
	total := len(allLogs)

	// 分页
	start := options.Offset
	if start < 0 {
		start = 0
	}
	end := start + options.Limit
	if end > len(allLogs) {
		end = len(allLogs)
	}

	var result []string
	if start < len(allLogs) {
		result = allLogs[start:end]
	}

	return &LogQueryResult{
		Logs:    result,
		Total:   total,
		HasMore: end < len(allLogs),
	}, nil
}

// filterByKeyword 按关键词过滤日志
func (m *logManager) filterByKeyword(logs []string, keyword string) []string {
	if keyword == "" {
		return logs
	}

	keywordLower := strings.ToLower(keyword)
	filtered := make([]string, 0, len(logs))
	for _, log := range logs {
		if strings.Contains(strings.ToLower(log), keywordLower) {
			filtered = append(filtered, log)
		}
	}
	return filtered
}

// mapLevelToPriority 将日志级别映射到 systemd priority
func (m *logManager) mapLevelToPriority(level string) string {
	levelLower := strings.ToLower(level)
	switch levelLower {
	case "emerg", "emergency":
		return "0"
	case "alert":
		return "1"
	case "crit", "critical":
		return "2"
	case "err", "error":
		return "3"
	case "warn", "warning":
		return "4"
	case "notice":
		return "5"
	case "info":
		return "6"
	case "debug":
		return "7"
	default:
		return "3" // 默认 error
	}
}

// matchLevel 检查日志行是否匹配指定的日志级别
func (m *logManager) matchLevel(line, level string) bool {
	lineLower := strings.ToLower(line)
	levelLower := strings.ToLower(level)

	// 检查常见的日志级别标记
	levelMarkers := map[string][]string{
		"error":    {"error", "err", "failed", "failure", "fatal"},
		"warn":     {"warn", "warning"},
		"info":     {"info", "information"},
		"debug":    {"debug", "trace"},
		"critical": {"critical", "crit", "fatal", "panic"},
	}

	markers, ok := levelMarkers[levelLower]
	if !ok {
		return false
	}

	for _, marker := range markers {
		if strings.Contains(lineLower, marker) {
			return true
		}
	}

	return false
}

// matchTimeRange 检查日志行是否在指定的时间范围内
func (m *logManager) matchTimeRange(line string, startTime, endTime *time.Time) bool {
	// 尝试从日志行中解析时间戳
	if startTime == nil && endTime == nil {
		return true
	}

	// 尝试解析常见的时间格式
	timeFormats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}

	var logTime *time.Time
	for _, format := range timeFormats {
		// 尝试从行首提取时间（通常时间在行首）
		parts := strings.Fields(line)
		if len(parts) > 0 {
			if t, err := time.Parse(format, parts[0]); err == nil {
				logTime = &t
				break
			}
		}
	}

	// 如果无法解析时间，假设匹配（避免过度过滤）
	if logTime == nil {
		return true
	}

	// 检查时间范围
	if startTime != nil && logTime.Before(*startTime) {
		return false
	}
	if endTime != nil && logTime.After(*endTime) {
		return false
	}

	return true
}
