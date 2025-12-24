package api

import (
	"context"
	"io"
	"os"

	"github.com/influxdata/telegraf/controller/pb"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// FileGRPCService File 服务的 gRPC 实现
type FileGRPCService struct {
	pb.UnimplementedFileServer
	fileService *FileService
	logger      *zap.Logger
}

// NewFileGRPCService 创建 File gRPC 服务
func NewFileGRPCService(fileService *FileService, logger *zap.Logger) *FileGRPCService {
	return &FileGRPCService{
		fileService: fileService,
		logger:      logger,
	}
}

// ListFiles 列出文件
func (s *FileGRPCService) ListFiles(ctx context.Context, req *pb.ListFilesReq) (*pb.ListFilesResp, error) {
	// 处理空路径或根路径，使用安全默认值
	path := req.Path
	if path == "" || path == "/" {
		// 使用用户主目录或工作目录作为默认路径
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			homeDir = os.Getenv("USERPROFILE") // Windows
		}
		if homeDir == "" {
			homeDir = "/tmp" // 最后的备选方案
		}
		path = homeDir
		s.logger.Info("Using default path instead of root", zap.String("default_path", path))
	}

	s.logger.Info("Received ListFiles request", zap.String("path", path))

	files, err := s.fileService.ListFiles(ctx, path)
	if err != nil {
		s.logger.Error("Failed to list files",
			zap.String("path", path),
			zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to list files: %v", err)
	}

	// 使用实际使用的路径（可能是默认路径）
	actualPath := path
	if req.Path == "" || req.Path == "/" {
		actualPath = path // 使用默认路径
	} else {
		actualPath = req.Path
	}

	resp := &pb.ListFilesResp{
		Path:  actualPath,
		Files: make([]*pb.FileInfo, 0, len(files)),
	}

	for _, file := range files {
		resp.Files = append(resp.Files, &pb.FileInfo{
			Path:    file.Path,
			Size:    file.Size,
			IsDir:   file.IsDir,
			Mode:    file.Mode,
			ModTime: timestamppb.New(file.ModTime),
			Md5:     file.MD5,
			Sha256:  file.SHA256,
		})
	}

	return resp, nil
}

// GetFileInfo 获取文件信息
func (s *FileGRPCService) GetFileInfo(ctx context.Context, req *pb.GetFileInfoReq) (*pb.GetFileInfoResp, error) {
	s.logger.Info("Received GetFileInfo request", zap.String("path", req.Path))

	fileInfo, err := s.fileService.GetFileInfo(ctx, req.Path)
	if err != nil {
		// 文件不存在
		return &pb.GetFileInfoResp{
			Exists: false,
		}, nil
	}

	return &pb.GetFileInfoResp{
		Exists: true,
		File: &pb.FileInfo{
			Path:    fileInfo.Path,
			Size:    fileInfo.Size,
			IsDir:   fileInfo.IsDir,
			Mode:    fileInfo.Mode,
			ModTime: timestamppb.New(fileInfo.ModTime),
			Md5:     fileInfo.MD5,
			Sha256:  fileInfo.SHA256,
		},
	}, nil
}

// StartFileUpload 开始文件上传
func (s *FileGRPCService) StartFileUpload(ctx context.Context, req *pb.StartFileUploadReq) (*pb.StartFileUploadResp, error) {
	s.logger.Info("Received StartFileUpload request",
		zap.String("file_path", req.FilePath),
		zap.Int64("file_size", req.FileSize))

	sessionID, err := s.fileService.StartUpload(ctx, req.FilePath, req.FileSize, req.Md5, req.Sha256)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to start upload: %v", err)
	}

	return &pb.StartFileUploadResp{
		SessionId: sessionID,
		FilePath:  req.FilePath,
		ChunkSize: s.fileService.GetChunkSize(),
	}, nil
}

// UploadFileChunk 上传文件块
func (s *FileGRPCService) UploadFileChunk(ctx context.Context, req *pb.UploadFileChunkReq) (*pb.UploadFileChunkResp, error) {
	s.logger.Debug("Received UploadFileChunk request",
		zap.String("session_id", req.SessionId),
		zap.Int64("chunk_index", req.ChunkIndex),
		zap.Int("data_size", len(req.Data)))

	err := s.fileService.UploadChunk(ctx, req.SessionId, req.ChunkIndex, req.Data)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to upload chunk: %v", err)
	}

	return &pb.UploadFileChunkResp{
		SessionId:  req.SessionId,
		ChunkIndex: req.ChunkIndex,
		Status:     "received",
	}, nil
}

// GetUploadStatus 获取上传状态
func (s *FileGRPCService) GetUploadStatus(ctx context.Context, req *pb.GetUploadStatusReq) (*pb.GetUploadStatusResp, error) {
	s.logger.Debug("Received GetUploadStatus request", zap.String("session_id", req.SessionId))

	session, err := s.fileService.GetUploadStatus(ctx, req.SessionId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "upload session not found: %v", err)
	}

	progress := 0.0
	if session.TotalSize > 0 {
		progress = float64(session.ReceivedSize) / float64(session.TotalSize) * 100.0
	}

	return &pb.GetUploadStatusResp{
		SessionId:    session.ID,
		Status:       session.Status,
		TotalSize:    session.TotalSize,
		ReceivedSize: session.ReceivedSize,
		Progress:     progress,
	}, nil
}

// DownloadFile 下载文件（流式）
func (s *FileGRPCService) DownloadFile(req *pb.DownloadFileReq, stream pb.File_DownloadFileServer) error {
	s.logger.Info("Received DownloadFile request",
		zap.String("path", req.Path),
		zap.Int64("offset", req.Offset),
		zap.Int64("length", req.Length))

	reader, fileSize, err := s.fileService.DownloadFile(stream.Context(), req.Path, req.Offset, req.Length)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to open file: %v", err)
	}
	defer reader.Close()

	chunkSize := int64(1024 * 1024) // 1MB chunks
	if req.Length > 0 && req.Length < chunkSize {
		chunkSize = req.Length
	}

	buffer := make([]byte, chunkSize)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if err := stream.Send(&pb.DownloadFileResp{
				Data: buffer[:n],
				Eof:  false,
			}); err != nil {
				return status.Errorf(codes.Internal, "failed to send chunk: %v", err)
			}
		}
		if err == io.EOF {
			// 发送最后一个空块表示结束
			if err := stream.Send(&pb.DownloadFileResp{
				Data: nil,
				Eof:  true,
			}); err != nil {
				return status.Errorf(codes.Internal, "failed to send final chunk: %v", err)
			}
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to read file: %v", err)
		}
	}

	s.logger.Info("File download completed",
		zap.String("path", req.Path),
		zap.Int64("file_size", fileSize))
	return nil
}

// DeleteFile 删除文件或目录
func (s *FileGRPCService) DeleteFile(ctx context.Context, req *pb.DeleteFileReq) (*pb.DeleteFileResp, error) {
	s.logger.Info("Received DeleteFile request",
		zap.String("path", req.Path),
		zap.Bool("recursive", req.Recursive))

	// 检查路径是否存在
	info, err := os.Stat(req.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return &pb.DeleteFileResp{
				Success: false,
				Message: "文件或目录不存在",
			}, nil
		}
		return nil, status.Errorf(codes.Internal, "failed to stat file: %v", err)
	}

	// 根据类型删除
	if info.IsDir() {
		if req.Recursive {
			// 递归删除目录
			if err := s.fileService.DeleteDirectory(ctx, req.Path); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to delete directory: %v", err)
			}
		} else {
			// 尝试删除空目录
			if err := os.Remove(req.Path); err != nil {
				return nil, status.Errorf(codes.Internal, "failed to delete directory: %v", err)
			}
		}
	} else {
		// 删除文件
		if err := s.fileService.DeleteFile(ctx, req.Path); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to delete file: %v", err)
		}
	}

	s.logger.Info("File deleted successfully",
		zap.String("path", req.Path),
		zap.Bool("recursive", req.Recursive))

	return &pb.DeleteFileResp{
		Success: true,
		Message: "删除成功",
	}, nil
}

// CreateDirectory 创建目录
func (s *FileGRPCService) CreateDirectory(ctx context.Context, req *pb.CreateDirectoryReq) (*pb.CreateDirectoryResp, error) {
	s.logger.Info("Received CreateDirectory request",
		zap.String("path", req.Path),
		zap.Uint32("mode", req.Mode))

	// 设置默认权限模式（0755）
	mode := os.FileMode(req.Mode)
	if mode == 0 {
		mode = 0755
	}

	// 创建目录
	if err := s.fileService.CreateDirectory(ctx, req.Path, mode); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create directory: %v", err)
	}

	s.logger.Info("Directory created successfully",
		zap.String("path", req.Path),
		zap.String("mode", mode.String()))

	return &pb.CreateDirectoryResp{
		Success: true,
		Message: "目录创建成功",
	}, nil
}
