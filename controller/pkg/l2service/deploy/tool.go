package deploy

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

type cmdResult struct {
	Output []byte
	Error  error
}

//cmd命令执行
func BaseexecuteCMD(cmdStr string, timeout int) ([]byte, error) {
	if timeout <= 0 {
		timeout = 10
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var outputChannel = make(chan cmdResult)
	var timeoutChannel = make(chan bool)

	go func() {
		time.Sleep(time.Duration(timeout+1) * time.Second)
		timeoutChannel <- true
	}()

	go func() {
		var cmd *exec.Cmd
		var result cmdResult

		// if ctx == nil {
		// cmd = exec.Command("/bin/bash", "-c", cmdStr)
		// } else {
		cmd = exec.CommandContext(ctx, "/bin/bash", "-c", cmdStr)
		// }

		result.Output, result.Error = cmd.CombinedOutput()
		// if err != nil {
		// errChannel <- err
		// }
		// byteChannel <- b
		outputChannel <- result

	}()

	select {
	case result := <-outputChannel:
		return result.Output, result.Error
	case <-timeoutChannel:
		return []byte{}, errors.New("execute command timeout")
	}

}
