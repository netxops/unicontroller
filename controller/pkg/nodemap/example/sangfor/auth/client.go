package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Client 深信服防火墙认证客户端
type Client struct {
	host   string
	client *http.Client
}

// LoginRequest 登录请求
type LoginRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Name        string `json:"name"`
		Role        string `json:"role"`
		Namespace   string `json:"namespace"`
		LoginResult struct {
			Token string `json:"token"`
		} `json:"loginResult"`
	} `json:"data"`
	Token  string `json:"token,omitempty"`
	SESSID string `json:"sessid,omitempty"` // 会话ID，从响应Cookie中提取
}

// NewClient 创建新的认证客户端
func NewClient(host string) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}

	return &Client{
		host:   host,
		client: client,
	}
}

// Login 执行登录操作
func (c *Client) Login(username, password string) (*LoginResponse, error) {
	// 登录URL，直接使用 @namespace 字符串
	loginURL := fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/login", c.host)

	// 构造登录请求体
	loginData := LoginRequest{
		Name:     username,
		Password: password,
	}

	jsonData, err := json.Marshal(loginData)
	if err != nil {
		return nil, fmt.Errorf("marshal login data: %w", err)
	}

	// 创建POST请求
	req, err := http.NewRequest("POST", loginURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// 发送请求
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应体
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// 解析响应
	var result LoginResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	// 检查响应头中是否有token
	if respToken := resp.Header.Get("X-Auth-Token"); respToken != "" {
		result.Token = respToken
	} else if result.Data.LoginResult.Token != "" {
		// 从data.loginResult.token提取token
		result.Token = result.Data.LoginResult.Token
	} else if result.Token == "" {
		// 尝试从其他可能的字段提取token
		var rawResult map[string]interface{}
		if err := json.Unmarshal(body, &rawResult); err == nil {
			if data, ok := rawResult["data"].(map[string]interface{}); ok {
				if loginResult, ok := data["loginResult"].(map[string]interface{}); ok {
					if token, ok := loginResult["token"].(string); ok {
						result.Token = token
					}
				}
				if token, ok := data["token"].(string); ok && result.Token == "" {
					result.Token = token
				}
			}
			if token, ok := rawResult["token"].(string); ok && result.Token == "" {
				result.Token = token
			}
			if token, ok := rawResult["access_token"].(string); ok && result.Token == "" {
				result.Token = token
			}
			if token, ok := rawResult["accessToken"].(string); ok && result.Token == "" {
				result.Token = token
			}
		}
	}

	// 从响应Cookie中提取SESSID
	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
		for _, cookie := range cookies {
			// 查找SESSID=xxx
			if len(cookie) > 7 && cookie[:7] == "SESSID=" {
				// 提取SESSID值（到分号或空格为止）
				sessid := cookie[7:]
				for i, char := range sessid {
					if char == ';' || char == ' ' {
						result.SESSID = sessid[:i]
						break
					}
				}
				if result.SESSID == "" {
					result.SESSID = sessid
				}
				break
			}
		}
	}

	return &result, nil
}

// GetToken 获取token（用于后续API调用）
func (r *LoginResponse) GetToken() string {
	return r.Token
}

// GetSESSID 获取SESSID（用于后续API调用）
func (r *LoginResponse) GetSESSID() string {
	return r.SESSID
}

// IsSuccess 检查登录是否成功
func (r *LoginResponse) IsSuccess() bool {
	return r.Code == 0 && r.Token != ""
}
