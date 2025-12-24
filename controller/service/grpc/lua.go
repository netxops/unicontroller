package grpc

import (
	"context"

	"github.com/influxdata/telegraf/controller/pb"
	"github.com/influxdata/telegraf/controller/pkg/lua"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type LuaSrv struct {
	pb.UnimplementedLuaServer
}

func (s *LuaSrv) ExecLuaScript(ctx context.Context, req *pb.ExecLuaScriptReq) (*pb.ExecLuaScriptResp, error) {
	if req == nil || req.Lua == "" {
		return nil, status.Errorf(codes.InvalidArgument, "the lua script cannot be empty")
	}

	lState, err := lua.NewLuaState(req.Lua)
	if err != nil {
		return &pb.ExecLuaScriptResp{}, err
	}
	output, err := lState.Run()
	return &pb.ExecLuaScriptResp{Output: output}, err
}
