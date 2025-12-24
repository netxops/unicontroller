package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
)

var (
	methods = map[string]int{
		"GET":    1,
		"HEAD":   1,
		"POST":   1,
		"PUT":    1,
		"PATCH":  1,
		"DELETE": 1,
		// "CONNECT": 1,
		"OPTIONS": 1,
		"TRACE":   1,
		"PRI":     1,
	}
)

// readWithTimeout 从 io.Reader 读取数据，使用超时机制
func readWithTimeout(r io.Reader, timeout time.Duration) ([]byte, error) {
	var result []byte

	go func() {
		for {
			b := make([]byte, 1)
			_, err := r.Read(b)
			if err != nil {
				return
			}
			result = append(result, b...)
		}
	}()

	select {
	case <-time.After(timeout):
		break
	}
	return result, nil
}

func Handler(body string, reader *bufio.Reader, conn net.Conn) {
	body = strings.TrimSpace(body)
	parts := strings.Split(body, " ")
	if len(parts) < 3 {
		xlog.Default().Error("invalid request line")
		return
	}

	method, urlStr, version := parts[0], parts[1], parts[2]

	if method == "CONNECT" {
		handleHTTPS(conn, urlStr)
	} else if methods[method] == 1 {
		handleHTTP2(conn, method, urlStr, version, reader)
	} else {
		xlog.Default().Error("unsupported method", xlog.String("method", method))
	}
}

func handleHTTP2(conn net.Conn, method, urlStr, _ string, reader *bufio.Reader) {
	bs, err := readWithTimeout(reader, 400*time.Millisecond)
	if err != nil {
		panic(err)
	}
	req := fmt.Sprintf("%s %s HTTP/1.1\n%s\n", method, urlStr, string(bs))

	us, _ := url.Parse(urlStr)
	address, _ := net.LookupHost(us.Hostname())
	var target string
	for _, addr := range address {
		ip := net.ParseIP(addr)
		if ip.To4() != nil {
			target = addr
			break
		}
	}

	if target == "" {
		err := fmt.Errorf("can not find target address: %s", urlStr)
		xlog.Default().Error("error parse address", xlog.FieldErr(err))
		return
	}

	port := us.Port()
	if port == "" {
		if strings.ToLower(us.Scheme) == "http" {
			port = "80"
		}
		if strings.ToLower(us.Scheme) == "https" {
			port = "443"
		}
	}

	xlog.Info("http proxy", xlog.String("url", urlStr), xlog.String("target", target), xlog.String("port", port))
	destAddr := fmt.Sprintf("%s:%s", target, port)

	destConn, err := net.Dial("tcp", destAddr)
	if err != nil {
		fmt.Println("Error dialing target:", err)
		_, _ = conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
		return
	}

	destConn.Write([]byte(req))
	go func() {
		defer func(destConn net.Conn) {
			_ = destConn.Close()
		}(destConn)
		_, _ = io.Copy(destConn, conn)
	}()

	func() {
		defer func(conn net.Conn) {
			_ = conn.Close()
		}(conn)
		_, _ = io.Copy(conn, destConn)
	}()
}

func handleHTTP(conn net.Conn, method, urlStr, _ string, reader *bufio.Reader) {
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		xlog.Default().Error("error creating request", xlog.FieldErr(err))
		return
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		xlog.Default().Error("error sending request", xlog.FieldErr(err))
		return
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	respHeader := fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, v := range resp.Header {
		for _, s := range v {
			respHeader += fmt.Sprintf("%s: %s\r\n", k, s)
		}
	}
	respHeader += "\r\n"

	_, _ = conn.Write([]byte(respHeader))
	_, _ = io.Copy(conn, resp.Body)
}

func handleHTTPS(conn net.Conn, urlStr string) {
	destAddr := strings.Split(urlStr, ":")
	if len(destAddr) != 2 {
		xlog.Default().Error("Invalid URL format for CONNECT method", xlog.String("url", urlStr))
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	host, port := destAddr[0], destAddr[1]

	xlog.Info("https proxy", xlog.String("url", urlStr), xlog.String("target", host), xlog.String("port", port))
	destConn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		fmt.Println("Error dialing target:", err)
		_, _ = conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
		return
	}

	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		defer func(destConn net.Conn) {
			_ = destConn.Close()
		}(destConn)
		_, _ = io.Copy(destConn, conn)
	}()

	func() {
		defer func(conn net.Conn) {
			_ = conn.Close()
		}(conn)
		_, _ = io.Copy(conn, destConn)
	}()
}
