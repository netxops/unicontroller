package grpc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/influxdata/telegraf/controller/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CommandSrv struct {
	mu       sync.Mutex
	Commands map[string]*CommandInfo
	pb.UnimplementedCommandServer
}

type CommandInfo struct {
	Cmd        *exec.Cmd
	Cancel     context.CancelFunc
	StartTime  time.Time
	Status     string
	Continuous bool
}

func (s *CommandSrv) ExecCommand(req *pb.ExecCommandReq, stream pb.Command_ExecCommandServer) error {
	if req == nil || req.Command == "" {
		return status.Errorf(codes.InvalidArgument, "the command cannot be empty")
	}

	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", req.Command)

	commandID := uuid.New().String()
	s.mu.Lock()
	s.Commands[commandID] = &CommandInfo{
		Cmd:        cmd,
		Cancel:     cancel,
		StartTime:  time.Now(),
		Status:     "running",
		Continuous: req.Continuous,
	}
	s.mu.Unlock()

	// Send the command ID to the client
	if err := stream.Send(&pb.ExecCommandResp{CommandId: commandID}); err != nil {
		return err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error creating StdoutPipe for command: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error creating StderrPipe for command: %v", err)
	}

	if err = cmd.Start(); err != nil {
		return fmt.Errorf("error starting command: %v", err)
	}

	go s.pipeOutput(stdout, stream, commandID, false)
	go s.pipeOutput(stderr, stream, commandID, true)

	if err = cmd.Wait(); err != nil {
		if req.Continuous {
			// For continuous commands, we don't treat this as an error
			s.mu.Lock()
			if s.Commands[commandID] != nil {
				s.Commands[commandID].Status = "finished"
			}
			s.mu.Unlock()
		} else {
			return fmt.Errorf("command finished with error: %v", err)
		}
	}

	if !req.Continuous {
		s.mu.Lock()
		delete(s.Commands, commandID)
		s.mu.Unlock()
	}

	return nil
}

func (s *CommandSrv) pipeOutput(r io.Reader, stream pb.Command_ExecCommandServer, commandID string, isError bool) {
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

func (s *CommandSrv) ExecCommandSignal(ctx context.Context, req *pb.ExecCommandSignalReq) (*pb.ExecCommandSignalResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmdInfo, exists := s.Commands[req.CommandId]
	if !exists {
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.NotFound, "command not found")
	}

	switch req.Signal {
	case pb.ExecCommandSignalType_CANCEL:
		cmdInfo.Cancel()
		cmdInfo.Status = "cancelled"
		if !cmdInfo.Continuous {
			delete(s.Commands, req.CommandId)
		}
	case pb.ExecCommandSignalType_PAUSE:
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.Unimplemented, "pause action not implemented")
	case pb.ExecCommandSignalType_RESUME:
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.Unimplemented, "resume action not implemented")
	default:
		return &pb.ExecCommandSignalResp{Success: false}, status.Errorf(codes.InvalidArgument, "unknown action")
	}

	return &pb.ExecCommandSignalResp{Success: true}, nil
}

// New method to get the status of a command
func (s *CommandSrv) GetCommandStatus(ctx context.Context, req *pb.GetCommandStatusReq) (*pb.GetCommandStatusResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmdInfo, exists := s.Commands[req.CommandId]
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
