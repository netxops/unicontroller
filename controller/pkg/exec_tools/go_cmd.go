package exec_tools

import (
	"bufio"
	"go.uber.org/zap"
	"io"
	"os/exec"
)

func ExecWithStdout(cmdStr string, logger *zap.Logger) error {
	cmd := exec.Command("bash", "-c", cmdStr)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logger.Error("无法获取标准输出管道:", zap.Error(err), zap.Any("cmd", cmd))
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		logger.Error("无法获取标准错误管道:", zap.Error(err), zap.Any("cmd", cmd))
		return err
	}

	if err := cmd.Start(); err != nil {
		logger.Error("无法启动命令:", zap.Error(err), zap.Any("cmd", cmd))
		return err
	}

	go printOutput(&stdout, logger)
	go printOutput(&stderr, logger)

	if err := cmd.Wait(); err != nil {
		logger.Error("命令执行出错:", zap.Error(err), zap.Any("cmd", cmd))
		return err
	}
	return err
}
func printOutput(pipeReader *io.ReadCloser, logger *zap.Logger) {
	scanner := bufio.NewScanner(*pipeReader)
	const maxTokenSize = 100 * 1024 * 1024
	buf := make([]byte, maxTokenSize)
	scanner.Buffer(buf, maxTokenSize)
	for scanner.Scan() {
		line := scanner.Text()
		// fmt.Println(line)
		logger.Debug(line)
	}

	if err := scanner.Err(); err != nil {
		logger.Error("读取管道出错:", zap.Error(err))
	}
}
