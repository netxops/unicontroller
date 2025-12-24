package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/influxdata/telegraf/controller/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CommandService Command gRPC 服务实现
type CommandService struct {
	pb.UnimplementedCommandServer
	commands map[string]*CommandInfo
	mu       sync.Mutex
	logger   *zap.Logger
}

// CommandInfo 命令信息
type CommandInfo struct {
	Cmd        *exec.Cmd
	Cancel     context.CancelFunc
	StartTime  time.Time
	Status     string
	Continuous bool
	IsPaused   bool // 是否已暂停
}

// NewCommandService 创建 Command 服务
func NewCommandService(logger *zap.Logger) *CommandService {
	return &CommandService{
		commands: make(map[string]*CommandInfo),
		logger:   logger,
	}
}

// ExecCommand 执行命令
func (s *CommandService) ExecCommand(req *pb.ExecCommandReq, stream pb.Command_ExecCommandServer) error {
	if req == nil || req.Command == "" {
		return status.Errorf(codes.InvalidArgument, "command cannot be empty")
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", req.Command)

	commandID := uuid.New().String()
	s.mu.Lock()
	s.commands[commandID] = &CommandInfo{
		Cmd:        cmd,
		Cancel:     cancel,
		StartTime:  time.Now(),
		Status:     "running",
		Continuous: req.Continuous,
	}
	s.mu.Unlock()

	// 发送命令 ID
	if err := stream.Send(&pb.ExecCommandResp{CommandId: commandID}); err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating stdout pipe: %v", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating stderr pipe: %v", err)
	}

	if err = cmd.Start(); err != nil {
		return fmt.Errorf("error starting command: %v", err)
	}

	go s.pipeOutput(stdout, stream, commandID, false)
	go s.pipeOutput(stderr, stream, commandID, true)

	if err = cmd.Wait(); err != nil {
		if req.Continuous {
			s.mu.Lock()
			if s.commands[commandID] != nil {
				s.commands[commandID].Status = "finished"
			}
			s.mu.Unlock()
		} else {
			return fmt.Errorf("command finished with error: %v", err)
		}
	}

	if !req.Continuous {
		s.mu.Lock()
		delete(s.commands, commandID)
		s.mu.Unlock()
	}

	return nil
}

// pipeOutput 管道输出
func (s *CommandService) pipeOutput(r io.Reader, stream pb.Command_ExecCommandServer, commandID string, isError bool) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		resp := &pb.ExecCommandResp{CommandId: commandID}
		if isError {
			resp.Err = scanner.Text()
		} else {
			resp.Out = scanner.Text()
		}
		if err := stream.Send(resp); err != nil {
			return
		}
	}
}

// ExecCommandSignal 发送命令信号
func (s *CommandService) ExecCommandSignal(ctx context.Context, req *pb.ExecCommandSignalReq) (*pb.ExecCommandSignalResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmdInfo, exists := s.commands[req.CommandId]
	if !exists {
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.NotFound, "command not found")
	}

	switch req.Signal {
	case pb.ExecCommandSignalType_CANCEL:
		cmdInfo.Cancel()
		cmdInfo.Status = "cancelled"
		if !cmdInfo.Continuous {
			delete(s.commands, req.CommandId)
		}
		return &pb.ExecCommandSignalResp{Success: true}, nil
	case pb.ExecCommandSignalType_PAUSE:
		return s.pauseCommand(cmdInfo, req.CommandId)
	case pb.ExecCommandSignalType_RESUME:
		return s.resumeCommand(cmdInfo, req.CommandId)
	default:
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.InvalidArgument, "unknown signal")
	}
}

// GetCommandStatus 获取命令状态
func (s *CommandService) GetCommandStatus(ctx context.Context, req *pb.GetCommandStatusReq) (*pb.GetCommandStatusResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmdInfo, exists := s.commands[req.CommandId]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "command not found")
	}

	return &pb.GetCommandStatusResp{
		CommandId: req.CommandId,
		Status:    cmdInfo.Status,
		StartTime: cmdInfo.StartTime.Unix(),
		Duration:  time.Since(cmdInfo.StartTime).Seconds(),
	}, nil
}

// pauseCommand 暂停命令执行
func (s *CommandService) pauseCommand(cmdInfo *CommandInfo, commandID string) (*pb.ExecCommandSignalResp, error) {
	if cmdInfo.Cmd == nil || cmdInfo.Cmd.Process == nil {
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.FailedPrecondition, "command process not available")
	}

	// 检查是否已经暂停
	if cmdInfo.IsPaused {
		s.logger.Warn("Command already paused", zap.String("command_id", commandID))
		return &pb.ExecCommandSignalResp{Success: true}, nil
	}

	// 检查进程是否还在运行
	if cmdInfo.Cmd.ProcessState != nil && cmdInfo.Cmd.ProcessState.Exited() {
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.FailedPrecondition, "command process has already exited")
	}

	// 发送 SIGSTOP 信号暂停进程
	if err := cmdInfo.Cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		s.logger.Error("Failed to pause command",
			zap.String("command_id", commandID),
			zap.Int("pid", cmdInfo.Cmd.Process.Pid),
			zap.Error(err))
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.Internal, "failed to pause command: %v", err)
	}

	cmdInfo.IsPaused = true
	cmdInfo.Status = "paused"

	s.logger.Info("Command paused successfully",
		zap.String("command_id", commandID),
		zap.Int("pid", cmdInfo.Cmd.Process.Pid))

	return &pb.ExecCommandSignalResp{Success: true}, nil
}

// resumeCommand 恢复命令执行
func (s *CommandService) resumeCommand(cmdInfo *CommandInfo, commandID string) (*pb.ExecCommandSignalResp, error) {
	if cmdInfo.Cmd == nil || cmdInfo.Cmd.Process == nil {
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.FailedPrecondition, "command process not available")
	}

	// 检查是否已经运行（未暂停）
	if !cmdInfo.IsPaused {
		s.logger.Warn("Command is not paused", zap.String("command_id", commandID))
		return &pb.ExecCommandSignalResp{Success: true}, nil
	}

	// 检查进程是否还在运行
	if cmdInfo.Cmd.ProcessState != nil && cmdInfo.Cmd.ProcessState.Exited() {
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.FailedPrecondition, "command process has already exited")
	}

	// 发送 SIGCONT 信号恢复进程
	if err := cmdInfo.Cmd.Process.Signal(syscall.SIGCONT); err != nil {
		s.logger.Error("Failed to resume command",
			zap.String("command_id", commandID),
			zap.Int("pid", cmdInfo.Cmd.Process.Pid),
			zap.Error(err))
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.Internal, "failed to resume command: %v", err)
	}

	cmdInfo.IsPaused = false
	cmdInfo.Status = "running"

	s.logger.Info("Command resumed successfully",
		zap.String("command_id", commandID),
		zap.Int("pid", cmdInfo.Cmd.Process.Pid))

	return &pb.ExecCommandSignalResp{Success: true}, nil
}
