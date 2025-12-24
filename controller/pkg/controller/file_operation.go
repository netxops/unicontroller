package controller

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/influxdata/telegraf/controller/pb"
	"google.golang.org/grpc/metadata"
)

// FileOperation 文件操作模块
type FileOperation struct {
	agentManager *AgentManager
}

// NewFileOperation 创建文件操作模块
func NewFileOperation(agentManager *AgentManager) *FileOperation {
	return &FileOperation{
		agentManager: agentManager,
	}
}

// ListFiles 列出文件
func (fo *FileOperation) ListFiles(ctx context.Context, agentCode, dirPath string) (map[string]interface{}, error) {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	resp, err := client.ListFiles(ctx, &pb.ListFilesReq{
		Path: dirPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	// 转换为 map
	result := map[string]interface{}{
		"path":  resp.Path,
		"files": make([]interface{}, 0, len(resp.Files)),
	}
	for _, file := range resp.Files {
		fileMap := map[string]interface{}{
			"path":     file.Path,
			"size":     file.Size,
			"is_dir":   file.IsDir,
			"mode":     file.Mode,
			"mod_time": file.ModTime.AsTime().Format(time.RFC3339),
		}
		if file.Md5 != "" {
			fileMap["md5"] = file.Md5
		}
		if file.Sha256 != "" {
			fileMap["sha256"] = file.Sha256
		}
		result["files"] = append(result["files"].([]interface{}), fileMap)
	}
	return result, nil
}

// GetFileInfo 获取文件信息
func (fo *FileOperation) GetFileInfo(ctx context.Context, agentCode, filePath string) (map[string]interface{}, error) {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	resp, err := client.GetFileInfo(ctx, &pb.GetFileInfoReq{
		Path: filePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// 转换为 map
	result := map[string]interface{}{
		"exists": resp.Exists,
		"file":   nil,
	}
	if resp.Exists && resp.File != nil {
		file := resp.File
		fileMap := map[string]interface{}{
			"path":     file.Path,
			"size":     file.Size,
			"is_dir":   file.IsDir,
			"mode":     file.Mode,
			"mod_time": file.ModTime.AsTime().Format(time.RFC3339),
		}
		if file.Md5 != "" {
			fileMap["md5"] = file.Md5
		}
		if file.Sha256 != "" {
			fileMap["sha256"] = file.Sha256
		}
		result["file"] = fileMap
	}
	return result, nil
}

// StartFileUpload 开始文件上传
func (fo *FileOperation) StartFileUpload(ctx context.Context, agentCode, filePath string, fileSize int64, md5, sha256 string) (map[string]interface{}, error) {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	resp, err := client.StartFileUpload(ctx, &pb.StartFileUploadReq{
		FilePath: filePath,
		FileSize: fileSize,
		Md5:      md5,
		Sha256:   sha256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start file upload: %w", err)
	}

	// 转换为 map
	result := map[string]interface{}{
		"session_id": resp.SessionId,
		"file_path":  resp.FilePath,
		"chunk_size": resp.ChunkSize,
	}
	return result, nil
}

// UploadFileChunk 上传文件块
func (fo *FileOperation) UploadFileChunk(ctx context.Context, agentCode, sessionID string, chunkIndex int64, data []byte) error {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	_, err = client.UploadFileChunk(ctx, &pb.UploadFileChunkReq{
		SessionId:  sessionID,
		ChunkIndex: chunkIndex,
		Data:       data,
	})
	if err != nil {
		return fmt.Errorf("failed to upload file chunk: %w", err)
	}

	return nil
}

// GetUploadStatus 获取上传状态
func (fo *FileOperation) GetUploadStatus(ctx context.Context, agentCode, sessionID string) (map[string]interface{}, error) {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	resp, err := client.GetUploadStatus(ctx, &pb.GetUploadStatusReq{
		SessionId: sessionID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get upload status: %w", err)
	}

	// 转换为 map
	result := map[string]interface{}{
		"session_id":    resp.SessionId,
		"status":        resp.Status,
		"total_size":    resp.TotalSize,
		"received_size": resp.ReceivedSize,
		"progress":      resp.Progress,
	}
	return result, nil
}

// DownloadFile 下载文件（返回读取器）
func (fo *FileOperation) DownloadFile(ctx context.Context, agentCode, filePath string, offset, length int64) (io.ReadCloser, error) {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	stream, err := client.DownloadFile(ctx, &pb.DownloadFileReq{
		Path:   filePath,
		Offset: offset,
		Length: length,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start file download: %w", err)
	}

	// 创建一个读取器来包装流
	return &fileDownloadReader{
		stream: stream,
		buffer: make([]byte, 0),
	}, nil
}

// fileDownloadReader 文件下载读取器
type fileDownloadReader struct {
	stream pb.File_DownloadFileClient
	buffer []byte
	eof    bool
}

func (r *fileDownloadReader) Read(p []byte) (n int, err error) {
	if r.eof {
		return 0, io.EOF
	}

	// 如果缓冲区为空，从流中读取
	if len(r.buffer) == 0 {
		resp, err := r.stream.Recv()
		if err != nil {
			if err == io.EOF {
				r.eof = true
				return 0, io.EOF
			}
			return 0, err
		}

		if resp.Eof {
			r.eof = true
		}

		r.buffer = resp.Data
	}

	// 从缓冲区复制数据
	n = copy(p, r.buffer)
	r.buffer = r.buffer[n:]

	return n, nil
}

func (r *fileDownloadReader) Close() error {
	return r.stream.CloseSend()
}

// DeleteFile 删除文件或目录
func (fo *FileOperation) DeleteFile(ctx context.Context, agentCode, filePath string, recursive bool) (map[string]interface{}, error) {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	resp, err := client.DeleteFile(ctx, &pb.DeleteFileReq{
		Path:      filePath,
		Recursive: recursive,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to delete file: %w", err)
	}

	result := map[string]interface{}{
		"success": resp.Success,
		"message": resp.Message,
	}
	return result, nil
}

// CreateDirectory 创建目录
func (fo *FileOperation) CreateDirectory(ctx context.Context, agentCode, dirPath string, mode uint32) (map[string]interface{}, error) {
	conn, err := fo.agentManager.getAgentConnection(agentCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent connection: %w", err)
	}

	// 创建带 metadata 的 context
	md := metadata.New(map[string]string{
		"agent-code": agentCode,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	client := pb.NewFileClient(conn)
	resp, err := client.CreateDirectory(ctx, &pb.CreateDirectoryReq{
		Path: dirPath,
		Mode: mode,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	result := map[string]interface{}{
		"success": resp.Success,
		"message": resp.Message,
	}
	return result, nil
}
