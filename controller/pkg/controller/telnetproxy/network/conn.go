package network

import (
	"io"
	"net"
	"strconv"
	"time"
)

// ReadAll 确保读取指定数量的字节
func ReadAll(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			if err == io.EOF {
				return total, err
			}
			return total, err
		}
		total += n
	}
	return total, nil
}

// WriteAll 确保写入所有数据
func WriteAll(conn net.Conn, data []byte) error {
	total := 0
	for total < len(data) {
		n, err := conn.Write(data[total:])
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

// SetKeepAlive 设置连接的keepalive
func SetKeepAlive(conn net.Conn) error {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return err
		}
		// 设置keepalive参数，使其更频繁地检测连接状态
		// 注意：这些参数在不同操作系统上可能有不同的默认值
		// 这里我们只设置基本的keepalive，具体的间隔由操作系统决定
		return nil
	}
	return nil
}

// SetReadDeadline 设置读取超时
func SetReadDeadline(conn net.Conn, timeout time.Duration) error {
	return conn.SetReadDeadline(time.Now().Add(timeout))
}

// SetWriteDeadline 设置写入超时
func SetWriteDeadline(conn net.Conn, timeout time.Duration) error {
	return conn.SetWriteDeadline(time.Now().Add(timeout))
}

// CheckPortAlive 检查目标端口是否存活
// 使用带超时的连接尝试，避免长时间等待
// timeout 建议设置为 3-5 秒
func CheckPortAlive(host string, port int, timeout time.Duration) error {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}
