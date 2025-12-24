package session

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"

	"github.com/influxdata/telegraf/controller/pkg/nodemap/session/command"

	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	"go.uber.org/zap"
)

// type HttpWriter struct {
// hs   *HttpSession
// url  string
// data []byte
// }

type HeadBuilder interface {
	BuildHeader(hs *HttpSession) (header *http.Header)
}

type Authentication interface {
	Auth(hs *HttpSession) (ok bool, token string, err error)
}

type HttpSession struct {
	Session
	Info          *DeviceBaseInfo
	AuthUrl       string
	TokenId       string
	TokenTime     time.Time
	authData      []byte
	basicAuth     bool
	basicAuthAll  bool
	client        *http.Client
	tokenField    string
	headerBuilder HeadBuilder
	auth          Authentication
	log           *zap.Logger
}

type Debug struct {
	DNS struct {
		Start   string       `json:"start"`
		End     string       `json:"end"`
		Host    string       `json:"host"`
		Address []net.IPAddr `json:"address"`
		Error   error        `json:"error"`
	} `json:"dns"`
	Dial struct {
		Start string `json:"start"`
		End   string `json:"end"`
	} `json:"dial"`
	Connection struct {
		Time string `json:"time"`
	} `json:"connection"`
	WroteAllRequestHeaders struct {
		Time string `json:"time"`
	} `json:"wrote_all_request_header"`
	WroteAllRequest struct {
		Time string `json:"time"`
	} `json:"wrote_all_request"`
	FirstReceivedResponseByte struct {
		Time string `json:"time"`
	} `json:"first_received_response_byte"`
}

// 利用hex.Dumper打印http数据

type loggingConn struct {
	net.Conn
	d io.WriteCloser
}

func (c *loggingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.d.Write(p[:n])
	}
	if err != nil {
		c.d.Close()
	}
	return n, err
}

//
// client := http.Client{Transport: &http.Transport{
// DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
// d := net.Dialer{}
// c, err := d.DialContext(ctx, network, addr)
// if err != nil {
//
// return nil, err
// }
// return &loggingConn{c, hex.Dumper(os.Stdout)}, nil
// }
// }
// }

func NewHttpSession(info *DeviceBaseInfo, auth_url string) *HttpSession {
	// if global.GVA_LOG == nil {
	// global.GVA_LOG = core.Zap()
	// }
	log := zap.NewNop()
	return &HttpSession{
		Info:    info,
		AuthUrl: auth_url,
		// client:        &http.Client{Transport: tr},
		headerBuilder: &HttpHeader{},
		auth:          &Authenticator{},
		log:           log,
	}
}

func (hs *HttpSession) Client() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},

		// 利用hex.Dumper打印http数据
		// DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 	d := net.Dialer{}
		// 	c, err := d.DialContext(ctx, network, addr)
		// 	if err != nil {

		// 		return nil, err
		// 	}
		// 	return &loggingConn{c, hex.Dumper(os.Stdout)}, nil
		// },
	}

	hs.client = &http.Client{Transport: tr}
	return hs.client
}

func (hs *HttpSession) WithTokenField(tokenField string) *HttpSession {
	hs.tokenField = tokenField
	return hs
}

func (hs *HttpSession) WithAuthData(data []byte) *HttpSession {
	hs.authData = data
	return hs
}

func (hs *HttpSession) EnableBasicAuth() *HttpSession {
	hs.basicAuth = true
	return hs
}

func (hs *HttpSession) EnableBasicAuthAll() *HttpSession {
	if hs.basicAuth {
		hs.basicAuthAll = true
	}

	return hs
}

func (hs *HttpSession) RequestWithoutCache(cmd *command.HttpCmd) ([]byte, error) {
	data := bytes.NewReader(cmd.Data)

	// url := fmt.Sprintf("https://%s:%d/%s", hs.Info.BaseInfo.Host, tools.OR(hs.Info.BaseInfo.Port, 443).(int), cmd.Url)
	url := fmt.Sprintf("http://%s/%s", hs.Info.BaseInfo.Host, cmd.Url)

	req, err := http.NewRequest(cmd.Method, url, data)
	// req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	if err != nil {
		return nil, err
	}

	if hs.basicAuth {
		if hs.basicAuthAll {
			req.SetBasicAuth(hs.Info.BaseInfo.Username, hs.Info.BaseInfo.Password)
		} else {
			if hs.TokenId == "" {
				_, token, err := hs.auth.Auth(hs)
				if err != nil {
					return nil, err
				}
				hs.TokenId = token
			}
		}
	} else if hs.TokenId == "" {
		_, token, err := hs.auth.Auth(hs)
		if err != nil {
			return nil, err
		}
		hs.TokenId = token
	}

	req.Header = *hs.headerBuilder.BuildHeader(hs)

	resp, err := hs.Client().Do(req)
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
		hs.client.CloseIdleConnections()
	}()
	// defer hs.client.Close()
	// fmt.Println(debug)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 210 || resp.StatusCode < 200 {
		cmd.WithOk(false)
	} else {
		cmd.WithOk(true)
	}

	return body, err
}

func (hs *HttpSession) Request(cmd *command.HttpCmd) (*command.CacheData, error) {
	var cd *command.CacheData
	if !cmd.Force {
		cd, err := hs.Session.Get(hs.Info.BaseInfo.Host, cmd)
		if cd != nil {
			if !cd.IsTimeout() {
				hs.log.Info("using cache data, ", zap.Any("id", cmd.Id(hs.Info.BaseInfo.Host)))
				return cd, err
			}
		}
	}

	// trace, debug := trace()

	data := bytes.NewReader(cmd.Data)

	// url := fmt.Sprintf("https://%s:%d/%s", hs.Info.BaseInfo.Host, tools.OR(hs.Info.BaseInfo.Port, 443).(int), cmd.Url)
	url := fmt.Sprintf("http://%s/%s", hs.Info.BaseInfo.Host, cmd.Url)
	req, err := http.NewRequest(cmd.Method, url, data)
	// req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	if err != nil {
		return nil, err
	}

	if hs.basicAuth {
		if hs.basicAuthAll {
			req.SetBasicAuth(hs.Info.BaseInfo.Username, hs.Info.BaseInfo.Password)
		} else {
			if hs.TokenId == "" {
				_, token, err := hs.auth.Auth(hs)
				if err != nil {
					return nil, err
				}
				hs.TokenId = token
			}
		}
	} else if hs.TokenId == "" {
		_, token, err := hs.auth.Auth(hs)
		if err != nil {
			return nil, err
		}
		hs.TokenId = token
	}

	req.Header = *hs.headerBuilder.BuildHeader(hs)

	resp, err := hs.Client().Do(req)
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
		hs.client.CloseIdleConnections()
	}()
	// defer hs.client.Close()
	// fmt.Println(debug)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 210 || resp.StatusCode < 200 {
		cmd.WithOk(false)
	} else {
		cmd.WithOk(true)
	}

	cmd.WithMsg(string(body))
	cd = command.NewCacheData(body)

	// 将数据保存到Redis
	// err = hs.Session.Set(cmd.Id(hs.Info.BaseInfo.Host), cd)
	err = hs.Session.Set(hs.Info.BaseInfo.Host, cmd, cd)
	// 将数据保存到Command中
	cmd.SetCacheData(cd)

	return cd, err
}

type HttpHeader struct{}

func (th *HttpHeader) BuildHeader(hs *HttpSession) (header *http.Header) {
	header = &http.Header{}
	header.Add("Content-type", "application/json")
	header.Add("Accept", "application/json")
	if hs.TokenId != "" {
		if hs.tokenField == "" {
			header.Add("X-ACCESS-TOKEN", hs.TokenId)
		} else {
			header.Add(hs.tokenField, hs.TokenId)
		}
	}
	return
}

type Authenticator struct{}

func (au *Authenticator) Auth(hs *HttpSession) (ok bool, token string, err error) {
	// bi := hs.Info
	// url := fmt.Sprintf("https://%s:%d/%s", hs.Info.BaseInfo.Host, tools.OR(hs.Info.BaseInfo.Port, 443), hs.AuthUrl)
	url := fmt.Sprintf("http://%s/%s", hs.Info.BaseInfo.Host, hs.AuthUrl)

	var authBytes []byte
	var reader *bytes.Reader
	var req *http.Request

	if hs.authData != nil {
		// authBytes, _ = json.Marshal(&hs.authData)
		authBytes = make([]byte, len(hs.authData))
		copy(authBytes, hs.authData)
		reader = bytes.NewReader(authBytes)
		req, err = http.NewRequest("POST", url, reader)
	} else if hs.basicAuth && !hs.basicAuthAll {
		req, err = http.NewRequest("POST", url, nil)
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(hs.Info.BaseInfo.Username, hs.Info.BaseInfo.Password)
	} else {
		auth_data := struct {
			Username string `json:"userName"`
			Password string `json:"password"`
		}{
			Username: hs.Info.BaseInfo.Username,
			Password: hs.Info.BaseInfo.Password,
		}

		authBytes, _ = json.Marshal(&auth_data)

		reader = bytes.NewReader(authBytes)
		req, err = http.NewRequest("POST", url, reader)

	}

	if err != nil {
		return
	}

	resp, err := hs.Client().Do(req)
	defer func() {
		if req.Body != nil {
			req.Body.Close()
		}
		hs.client.CloseIdleConnections()
	}()
	// defer hs.client.Close()

	if err != nil {
		return
	}

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		body := make([]byte, 0)

		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		m := map[string]interface{}{}
		err = json.Unmarshal(body, &m)
		if err != nil {
			return
		}
		// 针对 F5 设备
		if _, ok = m["token"]; ok {
			token = m["token"].(map[string]interface{})["token"].(string)
		}
		// 针对 H3c SecPath 设备
		if _, ok = m["token-id"]; ok {
			token = m["token-id"].(string)
		}
		return
	} else {
		body := make([]byte, 0)
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		} else {
			err = fmt.Errorf("%s", string(body))
			return
		}
	}
	return
}

func client() *http.Client {
	return &http.Client{
		Transport: transport(),
	}
}

func transport() *http.Transport {
	return &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   tlsConfig(),
	}
}

func tlsConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

func trace() (*httptrace.ClientTrace, *Debug) {
	d := &Debug{}

	t := &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "dns start")
			d.DNS.Start = t
			d.DNS.Host = info.Host
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "dns end")
			d.DNS.End = t
			d.DNS.Address = info.Addrs
			d.DNS.Error = info.Err
		},
		ConnectStart: func(network, addr string) {
			t := time.Now().UTC().String()
			log.Println(t, "dial start")
			d.Dial.Start = t
		},
		ConnectDone: func(network, addr string, err error) {
			t := time.Now().UTC().String()
			log.Println(t, "dial end")
			d.Dial.End = t
		},
		GotConn: func(connInfo httptrace.GotConnInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "conn time")
			d.Connection.Time = t
		},
		WroteHeaders: func() {
			t := time.Now().UTC().String()
			log.Println(t, "wrote all request headers")
			d.WroteAllRequestHeaders.Time = t
		},
		WroteRequest: func(wr httptrace.WroteRequestInfo) {
			t := time.Now().UTC().String()
			log.Println(t, "wrote all request")
			d.WroteAllRequest.Time = t
		},
		GotFirstResponseByte: func() {
			t := time.Now().UTC().String()
			log.Println(t, "first received response byte")
			d.FirstReceivedResponseByte.Time = t
		},
	}

	return t, d
}

func (hs *HttpSession) BatchRun(cmds interface{}, stopOnError bool) error {
	cmdList := cmds.(*command.HttpCmdList)
	execList := []*command.HttpCmd{}
	count := 0
	if !cmdList.Force {
		// HttpCmdList的Force为False
		for _, cmd := range cmdList.Cmds {
			if cmd.(*command.HttpCmd).Force {
				// 如果具体Cmd的Force设置为true，该命令必须执行
				execList = append(execList, cmd.(*command.HttpCmd))
				count += 1
			} else {
				// 从Cache中获取执行结果，如果执行结果已经超时，则命令必须执行
				cd, err := hs.Session.Get(hs.Info.BaseInfo.Host, cmd)
				if err != nil || cd.IsTimeout() {
					execList = append(execList, cmd.(*command.HttpCmd))
					count += 1
				} else {
					if cd != nil {
						cmd.SetCacheData(cd)
					} else {
						// 如果Cache中的结果为空，则命令必须执行
						execList = append(execList, cmd.(*command.HttpCmd))
						count += 1
					}
				}
			}
			// 将命令设置为必须级别
			cmd.WithLevel(command.MUST)
		}
	} else {
		for _, cmd := range cmdList.Cmds {
			execList = append(execList, cmd.(*command.HttpCmd))
			count += 1
			cmd.WithLevel(command.MUST)
		}
	}

	if count > 0 {
		for _, cmd := range execList {
			_, err := hs.Request(cmd)
			if err != nil {
				// cmd.WithOk(false)
				if stopOnError {
					return err
				} else {
					// cmd.WithMsg(fmt.Sprint(err))
				}
			} else {
				if !cmd.Ok() && stopOnError {
					break
				}
			}
		}
	}

	return nil
}

func (hs *HttpSession) BatchConfig(cmds interface{}, stopOnError bool) error {
	return hs.BatchRun(cmds, stopOnError)
}
