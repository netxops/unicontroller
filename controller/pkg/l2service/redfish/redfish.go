package redfish

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/imroc/req"
	"github.com/influxdata/telegraf/controller/global"
	"github.com/netxops/log"
	"github.com/netxops/utils/tools"
	"go.uber.org/zap"
)

type Redfish struct {
	Username    string
	Password    string
	URLPrefix   string
	Mode        string
	Token       string
	cookie      string
	data        map[string]string
	header      map[string]string
	Tokenurl    string
	Json        map[string]interface{}
	Host        string
	Cpu         int8
	Mem         int8
	Pcie        int8
	Disk        int8
	BasicAuth   string
	isBasicAuth bool
	Params      map[string]map[string]string
	Log         *log.Logger
}

type ResultRedFish struct {
	Json map[string]interface{}
	Host string
	Mode string
}

func NewResultRedFish() *ResultRedFish {
	return &ResultRedFish{
		Json: map[string]interface{}{},
	}
}

type JsonRedFish struct {
	Memory map[string]interface{}
}

//获取token2

func NewRedFish() *Redfish {
	return &Redfish{data: map[string]string{},
		header: map[string]string{},
		Json:   map[string]interface{}{},
	}
}
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}
func redirectPolicyFunc(User, Pwd string) (field, auth string) {
	return "Authorization", "Basic " + basicAuth(User, Pwd)
}

func (redf *Redfish) DeleteSession() (err error) {
	deleteUrl := redf.URLPrefix + "/redfish/v1/SessionService/Sessions" + redf.Token
	_, err = req.Delete(deleteUrl)
	return
}

func ParamsInit(host, device_model string) (urlprefix, tokenurl string, isBasicAuth bool, params map[string]map[string]string) {
	params = map[string]map[string]string{
		"sugon":   {"url": "/redfish/v1/SessionService/Sessions", "ssl": "https://", "managersurl": "/redfish/v1/Managers/Self", "sysurl": "/redfish/v1/Systems/Self", "chassisurl": "/redfish/v1/Chassis/Self"},
		"sugon2":  {"url": "/redfish/v1/SessionService/Sessions", "ssl": "https://", "managersurl": "/redfish/v1/Managers/Self", "sysurl": "/redfish/v1/Systems/Self", "chassisurl": "/redfish/v1/Chassis/Self"},
		"hp":      {"url": "/redfish/v1/SessionService/Sessions", "ssl": "https://", "managersurl": "/redfish/v1/Managers/1", "sysurl": "/redfish/v1/Systems/1", "chassisurl": "/redfish/v1/Chassis/1"},
		"h3c":     {"url": "/redfish/v1/SessionService/Sessions", "ssl": "https://"},
		"nettrix": {"url": "/redfish/v1/SessionService/Sessions", "ssl": "https://", "managersurl": "/redfish/v1/Managers/Self", "sysurl": "/redfish/v1/Systems/Self", "chassisurl": "/redfish/v1/Chassis/Self"},
		"lenovo":  {"url": "/redfish/v1/SessionService/Sessions", "ssl": "https://", "managersurl": "/redfish/v1/Managers/1", "sysurl": "/redfish/v1/Systems/1", "chassisurl": "/redfish/v1/Chassis/1"},
		"dell":    {"url": "/redfish/v1/Sessions", "ssl": "https://", "managersurl": "/redfish/v1/Managers/iDRAC.Embedded.1", "sysurl": "/redfish/v1/Systems/System.Embedded.1", "chassisurl": "/redfish/v1/Chassis/System.Embedded.1"},
		"ibm":     {"ssl": "http://", "managersurl": "/redfish/v1/Managers/1", "sysurl": "/redfish/v1/Systems/1", "chassisurl": "/redfish/v1/Chassis/1"},
	}
	isBasicAuth = false
	switch strings.ToLower(device_model) {
	case "sugon":
		urlprefix = params["sugon"]["ssl"] + strings.TrimSpace(host)
		tokenurl = urlprefix + params["sugon"]["url"]
	case "dell":
		urlprefix = params["dell"]["ssl"] + strings.TrimSpace(host)
		tokenurl = urlprefix + params["dell"]["url"]
	case "hp":
		urlprefix = params["hp"]["ssl"] + strings.TrimSpace(host)
		tokenurl = urlprefix + params["hp"]["url"]
	case "h3c":
		urlprefix = params["h3c"]["ssl"] + strings.TrimSpace(host)
		tokenurl = urlprefix + params["h3c"]["url"]
	case "nettrix":
		urlprefix = params["nettrix"]["ssl"] + strings.TrimSpace(host)
		tokenurl = urlprefix + params["nettrix"]["url"]
	case "lenovo":
		urlprefix = params["lenovo"]["ssl"] + strings.TrimSpace(host)
		tokenurl = urlprefix + params["lenovo"]["url"]
	case "ibm":
		urlprefix = params["ibm"]["ssl"] + strings.TrimSpace(host)
		isBasicAuth = true
	}
	return
}

func (redf *Redfish) RedfishCollect(host, username, password, device_model string) (ok bool, err error) {
	redf.Username = username
	redf.Password = password
	//redf.URLPrefix = "https://" + strings.TrimSpace(host)
	redf.Mode = strings.ToLower(device_model)
	redf.Host = host
	redf.isBasicAuth = false
	fmt.Println("=====", redf.Mode)
	//if tools.IsContain([]string{"sugon", "hp", "lenovo", "nettrix", "h3c"}, redf.Mode) {
	//	redf.Tokenurl = redf.URLPrefix + "/redfish/v1/SessionService/Sessions"
	//} else if tools.IsContain([]string{"dell"}, redf.Mode) {
	//	redf.Tokenurl = redf.URLPrefix + "/redfish/v1/Sessions"
	//} else if tools.IsContain([]string{"ibm"}, redf.Mode) {
	//	redf.URLPrefix = "http://" + strings.TrimSpace(host)
	//	redf.isBasicAuth = true
	//}
	redf.Log = log.NewLogger(nil, true)
	redf.URLPrefix, redf.Tokenurl, redf.isBasicAuth, redf.Params = ParamsInit(host, device_model)

	header := req.Header{
		"Content-Type":    "application/json",
		"Accept":          "*/*",
		"Accept-Encoding": "gzip,deflate,br",
		"Cache-Control":   "no-cache",
		"User-Agent":      "gofish/1.0",
		"Connect":         "keep-alive",
		"Accept-Language": "zh-CN",
		"Origin":          redf.URLPrefix,
	}
	if redf.isBasicAuth {
		_, authKey := redirectPolicyFunc(username, password)
		////red.Ctx.Header.Add("Accept", "application/json; indent=4;")
		redf.BasicAuth = authKey
	} else {
		req.Client().Jar, _ = cookiejar.New(nil)
		trans, _ := req.Client().Transport.(*http.Transport)
		trans.MaxIdleConns = 100
		trans.TLSHandshakeTimeout = 20 * time.Second
		trans.DisableKeepAlives = true
		trans.IdleConnTimeout = 90 * time.Second
		trans.ForceAttemptHTTP2 = true
		trans.ExpectContinueTimeout = 1 * time.Second
		trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		param := req.Param{
			"UserName": username,
			"Password": password,
		}
		bytesData, _ := json.Marshal(param)
		response, err := req.Post(redf.Tokenurl, header, bytesData)
		if err != nil {
			redf.Log.Info("RedfishCollect.Post", zap.Any("tokenUrl", redf.Tokenurl), zap.Any("username", username), zap.Any("error", err))
			return false, err
		}
		if response.Response().StatusCode == 200 || response.Response().StatusCode == 201 {
			token := response.Response().Header["X-Auth-Token"]
			if len(token) == 0 {
				token = response.Response().Header["x-auth-token"]
			}
			if len(token) != 0 {
				redf.Token = token[0]
				if tools.IsContain([]string{"sugon", "nettrix"}, redf.Mode) {
					set_cookie := response.Response().Header["Set-Cookie"]
					if len(set_cookie) != 0 {
						redf.cookie = strings.Split(set_cookie[0], ";")[0]
					} else {
						redf.Mode = "sugon2"
						redf.cookie = ""
					}
				}
			} else {
				response.Response().Body.Close()
				redf.Log.Debug("RedfishCollect", zap.Any("error", "token is empty"), zap.Any("Token url", redf.Tokenurl))
				return false, err
			}
			redf.Log.Debug("RedfishCollect", zap.Any("get token", token))

			response.Response().Body.Close()
		} else {
			err = fmt.Errorf("token get error status:%d,error:%s", response.Response().StatusCode, response)
			response.Response().Body.Close()
			redf.Log.Info("RedfishCollect", zap.Any("StatusCode", response.Response().StatusCode), zap.Any("error", response))
			return false, err
		}
	}
	//fmt.Println("data", response.Response())
	mi := map[string]interface{}{}
	mg := map[string]interface{}{}
	r := redf.GetSysEmbedded()
	v1 := redf.GetV1()
	if v1 != nil {
		if err := json.Unmarshal([]byte(v1.String()), &mg); err == nil {
			redf.Json["v1"] = mg
		}
	} else {
		redf.Json["v1"] = mg
	}
	if err := json.Unmarshal([]byte(r.String()), &mi); err == nil {
		redf.Json["GetSysEmbedded"] = mi
	}
	manage := redf.GetManagersEmbedded()
	me := map[string]interface{}{}
	if err := json.Unmarshal([]byte(manage.String()), &me); err == nil {
		redf.Json["GetManagersEmbedded"] = me
	}
	chassis := redf.GetChassisEmbedded()
	mc := map[string]interface{}{}
	if err := json.Unmarshal([]byte(chassis.String()), &mc); err == nil {
		redf.Json["GetChassisEmbedded"] = mc
	}
	return true, nil
}

func (redf *Redfish) HeadGet(device_model string) (header map[string]string) {
	switch strings.ToLower(device_model) {
	case "sugon":
		header = req.Header{
			"Cookie":       redf.cookie,
			"Content-Type": "application/json",
			"X-Auth-Token": redf.Token,
		}
	case "nettrix":
		header = req.Header{
			"Cookie":       redf.cookie,
			"Content-Type": "application/json",
			"X-Auth-Token": redf.Token,
		}
	case "dell":
		header = req.Header{
			"Content-Type":    "application/json",
			"Accept":          "*/*",
			"Accept-Encoding": "gzip,deflate,br",
			"Cache-Control":   "no-cache",
			"User-Agent":      "gofish/1.0",
			"Connect":         "keep-alive",
			"Accept-Language": "zh-CN",
			"X-Auth-Token":    redf.Token,
		}
	case "sugon2":
		header = req.Header{
			"Content-Type":    "application/json",
			"Accept":          "*/*",
			"Accept-Encoding": "gzip,deflate,br",
			"Cache-Control":   "no-cache",
			"User-Agent":      "gofish/1.0",
			"Connect":         "keep-alive",
			"Accept-Language": "zh-CN",
			"X-Auth-Token":    redf.Token,
		}
	case "hp":
		header = req.Header{
			"Content-Type":    "application/json",
			"Accept":          "*/*",
			"Accept-Encoding": "gzip,deflate,br",
			"Cache-Control":   "no-cache",
			"User-Agent":      "gofish/1.0",
			"Connect":         "keep-alive",
			"Accept-Language": "zh-CN",
			"X-Auth-Token":    redf.Token,
		}
	case "lenovo":
		header = req.Header{
			"Content-Type":    "application/json",
			"Accept":          "*/*",
			"Accept-Encoding": "gzip,deflate,br",
			"Cache-Control":   "no-cache",
			"User-Agent":      "gofish/1.0",
			"Connect":         "keep-alive",
			"Accept-Language": "zh-CN",
			"X-Auth-Token":    redf.Token,
		}
	case "h3c":
		header = req.Header{
			"Content-Type":    "application/json",
			"Accept":          "*/*",
			"Accept-Encoding": "gzip,deflate,br",
			"Cache-Control":   "no-cache",
			"User-Agent":      "gofish/1.0",
			"Connect":         "keep-alive",
			"Accept-Language": "zh-CN",
			"X-Auth-Token":    redf.Token,
		}
	case "ibm":
		header = req.Header{
			"Content-Type":    "application/json",
			"Accept":          "*/*",
			"Accept-Encoding": "gzip,deflate,br",
			"Cache-Control":   "no-cache",
			"User-Agent":      "gofish/1.0",
			"Connect":         "keep-alive",
			"Accept-Language": "zh-CN",
			"Authorization":   redf.BasicAuth,
		}
	}
	return
}
func (redf *Redfish) GetInfo(URL_suffix string) (r *req.Resp) {
	urlset := redf.URLPrefix + strings.TrimSpace(URL_suffix)
	//redf.Token = "c84f3117977c5d18767c4ccf77f670bd"
	var header req.Header
	if redf.Token != "" || redf.isBasicAuth {
		//if tools.IsContain([]string{"sugon", "nettrix"}, redf.Mode) {
		//	header = req.Header{
		//		"Cookie":       redf.cookie,
		//		"Content-Type": "application/json",
		//		"X-Auth-Token": redf.Token,
		//	}
		//} else if tools.IsContain([]string{"dell", "hp", "lenovo", "sugon2", "h3c"}, redf.Mode) {
		//	header = req.Header{
		//		"Content-Type":    "application/json",
		//		"Accept":          "*/*",
		//		"Accept-Encoding": "gzip,deflate,br",
		//		"Cache-Control":   "no-cache",
		//		"User-Agent":      "gofish/1.0",
		//		"Connect":         "keep-alive",
		//		"Accept-Language": "zh-CN",
		//		"X-Auth-Token":    redf.Token,
		//	}
		//} else if tools.IsContain([]string{"ibm"}, redf.Mode) {
		//	header = req.Header{
		//		"Content-Type":    "application/json",
		//		"Accept":          "*/*",
		//		"Accept-Encoding": "gzip,deflate,br",
		//		"Cache-Control":   "no-cache",
		//		"User-Agent":      "gofish/1.0",
		//		"Connect":         "keep-alive",
		//		"Accept-Language": "zh-CN",
		//		"Authorization":   redf.BasicAuth,
		//	}
		//} else {
		//	panic(redf.Mode + "is error")
		//}
		header = redf.HeadGet(redf.Mode)
		r, err := req.Get(urlset, header)
		if err != nil {
			redf.Log.Info("GetInfo.Get", zap.Any("url", urlset), zap.Any("error", err))
		} else {
			//fmt.Printf("getinfo=======", r)
		}
		return r
	} else {
		redf.Log.Debug("GetInfo", zap.Any("error", "GetInfo error token is empty"), zap.Any("url", urlset))
		return nil
	}
}

func (redf *Redfish) GetV1() (r *req.Resp) {
	r = redf.GetInfo("/redfish/v1")
	return r
}

func (redf *Redfish) GetSysEmbedded() (r *req.Resp) {
	//if tools.IsContain([]string{"dell"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Systems/System.Embedded.1")
	//} else if tools.IsContain([]string{"sugon", "sugon2", "nettrix"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Systems/Self")
	//} else if tools.IsContain([]string{"lenovo", "hp", "ibm"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Systems/1")
	//} else {
	//	panic("model error")
	//}
	sysurl := redf.Params[redf.Mode]["sysurl"]
	r = redf.GetInfo(sysurl)
	return r
}

func (redf *Redfish) GetManagersEmbedded() (r *req.Resp) {
	managerurl := redf.Params[redf.Mode]["managersurl"]
	//if tools.IsContain([]string{"dell"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Managers/iDRAC.Embedded.1")
	//} else if tools.IsContain([]string{"sugon", "sugon2", "nettrix"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Managers/Self")
	//} else if tools.IsContain([]string{"lenovo", "hp", "ibm"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Managers/1")
	//} else {
	//	panic("model error")
	//}
	r = redf.GetInfo(managerurl)
	return r
}

func (redf *Redfish) GetChassisEmbedded() (r *req.Resp) {
	//if tools.IsContain([]string{"dell"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Chassis/System.Embedded.1")
	//} else if tools.IsContain([]string{"sugon", "sugon2", "nettrix"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Chassis/Self")
	//} else if tools.IsContain([]string{"lenovo", "hp", "ibm"}, redf.Mode) {
	//	r = redf.GetInfo("/redfish/v1/Chassis/1")
	//} else {
	//	panic("model error")
	//}
	chassisurl := redf.Params[redf.Mode]["chassisurl"]
	r = redf.GetInfo(chassisurl)
	return r
}

// 获取cpu简略信息
func (redf *Redfish) GetCpuSummary() (processor_summary interface{}) {
	//processor_summary = ""
	if tools.IsContain([]string{"dell", "hp", "lenovo", "nettrix"}, redf.Mode) {
		r := redf.GetSysEmbedded()
		m := map[string]interface{}{}
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			processor_summary = m["ProcessorSummary"]
		}
	} else if tools.IsContain([]string{"sugon"}, redf.Mode) {
		//processor_summary = redf.GetCpu_info()
	}
	return processor_summary
}

// 获取cpu详细信息
func (redf *Redfish) GetCpuInfo() (ok bool, err error) {
	if tools.IsContain([]string{"sugon", "dell", "hp", "lenovo", "nettrix", "ibm"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			cpu_query := m["Processors"]
			info := []map[string]interface{}{}
			//fmt.Println("==1111=",cpu_query,reflect.TypeOf(cpu_query))
			odataJson, _ := json.Marshal(cpu_query)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				cpuData := m["@odata.id"].(string)
				cpu_info := redf.GetInfo(cpuData)
				if err := json.Unmarshal([]byte(cpu_info.String()), &m); err == nil {
					cpuMembers := m["Members"]
					redf.Json["CpuMembers"] = cpuMembers
					cpuMembers2, _ := json.Marshal(cpuMembers)
					if err := json.Unmarshal(cpuMembers2, &m2); err == nil {
						for _, cpuOdata := range m2 {
							m3 := map[string]interface{}{}
							//var each_cpu_dict map[string]interface{}
							//each_cpu_dict = make(map[string]interface{})
							odataJson, _ := json.Marshal(cpuOdata)
							if err := json.Unmarshal(odataJson, &m3); err == nil {
								cpuInfo := redf.GetInfo(m3["@odata.id"].(string))
								if err := json.Unmarshal([]byte(cpuInfo.String()), &m3); err == nil {
									info = append(
										info,
										m3,
									)
								}
							}
						}
					} else {
						fmt.Println("json.Unmarshal(cpu_members2, &m2) err", err)
					}
				} else {
					fmt.Println("json.Unmarshal([]byte(cpu_info.String()) err", err)
				}
				//cpu_info["Members"]
			}
			redf.Json["CpuInfo"] = info
		}
	} else if tools.IsContain([]string{"sugon2"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		mr := map[string]interface{}{}
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			cpu_query := m["Processors"]
			info := []map[string]interface{}{}
			//fmt.Println("==1111=",cpu_query,reflect.TypeOf(cpu_query))
			odataJson, _ := json.Marshal(cpu_query)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				cpuData := m["@odata.id"].(string)
				cpu_info := redf.GetInfo(cpuData)
				if err := json.Unmarshal([]byte(cpu_info.String()), &m); err == nil {
					cpuMembers := m["Max CPU Amount"]
					cpuMembers2, _ := json.Marshal(cpuMembers)
					if err := json.Unmarshal(cpuMembers2, &m2); err == nil {
						for _, cpuOdata := range m2 {
							//var each_cpu_dict map[string]interface{}
							//each_cpu_dict = make(map[string]interface{})
							odataJson, _ := json.Marshal(cpuOdata)
							if err := json.Unmarshal(odataJson, &mr); err == nil {
								info = append(
									info,
									mr,
								)
								//each_cpu_dict["Manufacturer"] = m["Manufacturer"]
								//each_cpu_dict["Model"] = m["BrandName"]
								//each_cpu_dict["Name"] = m["Name"]
								//if each_cpu_dict["Name"] == nil {
								//	each_cpu_dict["Name"] = fmt.Sprintln("CPU %d", i+1)
								//}
								//each_cpu_dict["InstructionSet"] = m["InstructionSet"]
								//if m["CurrentCoresCurrentThreads"] != nil {
								//	CurrentCoresCurrentThreads := strings.Split(m["CurrentCoresCurrentThreads"].(string), "/")
								//	each_cpu_dict["TotalCores"] = CurrentCoresCurrentThreads[0]
								//	each_cpu_dict["TotalThreads"] = CurrentCoresCurrentThreads[1]
								//} else {
								//	each_cpu_dict["TotalCores"] = ""
								//	each_cpu_dict["TotalThreads"] = ""
								//}
								//each_cpu_dict["Socket"] = m["Socket"]
								//each_cpu_dict["Frequency"] = m["Frequency"]
								//each_cpu_dict["WorkFreq"] = m["TurboFrequency"]
								//each_cpu_dict["PartNumber"] = m["PartNumber"]
								//each_cpu_dict["SerialNumber"] = m["SerialNumber"]
								//each_cpu_dict["Tdp"] = m["TDP"]
								//each_cpu_dict["Status"] = m["Status"]
								//summaryCpu = append(summaryCpu, each_cpu_dict)
							}
						}
					}
				}
				redf.Json["CpuInfo"] = info
			}
		}
	}
	if redf.Json["CpuInfo"] == nil {
		redf.Cpu = 0
		return false, fmt.Errorf("get cpuInfo is empty")
	}
	redf.Cpu = 1
	return true, nil
}

func (redf *Redfish) GetRedfishVersion() (err error) {
	v1query := redf.Json["v1"]
	m := map[string]interface{}{}
	odataJson, _ := json.Marshal(v1query)
	if err := json.Unmarshal(odataJson, &m); err == nil {
		redf.Json["RedfishVersion"] = m["RedfishVersion"]
	}
	return
}

func (redf *Redfish) GetSerial() (err error) {
	sysQuery := redf.Json["GetSysEmbedded"]
	//listInterface := []interface{}{}
	m := map[string]interface{}{}
	odataJson, _ := json.Marshal(sysQuery)
	if err := json.Unmarshal(odataJson, &m); err == nil {
		//info := map[string]interface{}{}
		b := ""
		sku := ""
		if m["SKU"] != nil {
			sku = m["SKU"].(string)
		}
		if m["SerialNumber"] != nil {
			//info["serialNumber"] = m["SerialNumber"].(string)
			b = m["SerialNumber"].(string)
		}
		if sku != "" {
			redf.Json["SerialNumber"] = sku
		} else if b != "" {
			redf.Json["SerialNumber"] = b
		} else {
			redf.Json["SerialNumber"] = b
		}
		//redf.Json["SKU"] = sku
	}
	return err
}
func (redf *Redfish) GetBaseInfo() (err error) {
	sysQuery := redf.Json["GetSysEmbedded"]
	//listInterface := []interface{}{}
	m := map[string]interface{}{}
	odataJson, _ := json.Marshal(sysQuery)
	if err := json.Unmarshal(odataJson, &m); err == nil {
		info := map[string]interface{}{}
		//fmt.Printf("======%+v",m)
		if m["Manufacturer"] != nil {
			info["manufacturer"] = m["Manufacturer"].(string)
		}
		if m["HostName"] != nil {
			info["name"] = m["HostName"].(string)
		}
		if m["SKU"] != nil {
			info["sku"] = m["SKU"].(string)
		}
		if m["Model"] != nil {
			info["modelType"] = m["Model"].(string)
		}
		if m["PartNumber"] != nil {
			info["partNumber"] = m["PartNumber"].(string)
		}
		if m["SerialNumber"] != nil {
			info["serialNumber"] = m["SerialNumber"].(string)
		}
		redf.Json["BaseInfo"] = info
	}
	return
}

func (redf *Redfish) GetMemoryInfo() (ok bool, err error) {
	//allJson := map[string]interface{}{}
	if tools.IsContain([]string{"sugon", "dell", "hp", "lenovo", "nettrix", "ibm"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			memQuery := m["Memory"]
			info := []map[string]interface{}{}
			if memQuery != nil {
				//fmt.Println("==1111=",cpu_query,reflect.TypeOf(cpu_query))
				odataJson, _ := json.Marshal(memQuery)
				if err := json.Unmarshal(odataJson, &m); err == nil {
					memData := m["@odata.id"].(string)
					memInfo := redf.GetInfo(memData)
					if err := json.Unmarshal([]byte(memInfo.String()), &m); err == nil {
						memMembers := m["Members"]
						redf.Json["MemoryMembers"] = memMembers
						if memMembers != nil {
							memoryMembers2, _ := json.Marshal(memMembers)
							if err := json.Unmarshal(memoryMembers2, &m2); err == nil {
								for _, memOdata := range m2 {
									//var each_mem_dict map[string]interface{}
									//each_mem_dict = make(map[string]interface{})
									m3 := map[string]interface{}{}
									odataJson, _ := json.Marshal(memOdata)
									if err := json.Unmarshal(odataJson, &m3); err == nil {
										memInfo := redf.GetInfo(m3["@odata.id"].(string))
										if err := json.Unmarshal([]byte(memInfo.String()), &m3); err == nil {
											info = append(
												info,
												m3,
											)
											//fmt.Println("=====",info)
											//if m["CapacityMiB"]!=nil{
											//	each_mem_dict["Name"] = m["Name"]
											//	if m["CapacityMiB"]!=nil{
											//		CapacityGb:= strconv.FormatFloat(m["CapacityMiB"].(float64)/1024, 'f', -1, 64)+"GB"
											//		each_mem_dict["Size"] = CapacityGb
											//	}else{
											//		CapacityGb := ""
											//		each_mem_dict["Size"] = CapacityGb
											//	}
											//	if m["MemoryDeviceType"]!=nil{
											//		memoryDeviceType := m["MemoryDeviceType"]
											//		each_mem_dict["DimmType"] = memoryDeviceType
											//	}else if m["MemoryType"]!=nil{
											//		memoryDeviceType :=m["MemoryType"]
											//		each_mem_dict["DimmType"] = memoryDeviceType
											//	}else{
											//		memoryDeviceType := ""
											//		each_mem_dict["DimmType"] = memoryDeviceType
											//	}
											//	each_mem_dict["ModuleType"] = m["MemoryType"]
											//	each_mem_dict["SerialNumber"] = m["SerialNumber"]
											//	each_mem_dict["Manufacturer"] = m["Manufacturer"]
											//	each_mem_dict["RankCount"] = m["RankCount"]
											//	each_mem_dict["PartNumber"] = m["PartNumber"]
											//	each_mem_dict["Frequency"] = m["AllowedSpeedsMHz"]
											//	each_mem_dict["WorkFreq"] = m["OperatingSpeedMhz"]
											//	each_mem_dict["Location"] = m["Location"]
											//	each_mem_dict["status"] = m["Status"]
											//	smmmaryMemory=append(smmmaryMemory,each_mem_dict)
											//}
										}
									}
								}
							}
							//m4 := map[string]interface{}{}
							//if err := json.Unmarshal([]byte(redf.Json), &m4); err == nil {
							//	m4["MemoryInfo"]=info
							//	//jsonStr, _ := json.Marshal(m4)
							//	//mString :=string(jsonStr)
							//	fmt.Println("====",m4)
							//	//redf.Json=string(m4)
							//	//fmt.Println("111111",redf.Json)
							//}else{
							//	fmt.Println("errrr",err)
							//}
							//fmt.Println("-----------",redf.Json)
							//jsonStr, _ := json.Marshal(redf.Json)
							//mString :=string(jsonStr)
							//fmt.Println("11-----1",mString)
							//global.Redis.Set(redf.Host, mString, 86400*time.Second)
						}
					}
				}
			}
			redf.Json["MemoryInfo"] = info
		}
	} else if tools.IsContain([]string{"sugon2"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		mr := map[string]interface{}{}
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			memQuery := m["Memory"]
			info := []map[string]interface{}{}
			//fmt.Println("==1111=",cpu_query,reflect.TypeOf(cpu_query))
			odataJson, _ := json.Marshal(memQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				memData := m["@odata.id"].(string)
				memInfo := redf.GetInfo(memData)
				if err := json.Unmarshal([]byte(memInfo.String()), &m); err == nil {
					memMembers := m["Max Memory Amount"]
					memMembers2, _ := json.Marshal(memMembers)
					if err := json.Unmarshal(memMembers2, &m2); err == nil {
						for _, cpuOdata := range m2 {
							//var each_mem_dict map[string]interface{}
							//each_mem_dict = make(map[string]interface{})
							odataJson, _ := json.Marshal(cpuOdata)
							if err := json.Unmarshal(odataJson, &mr); err == nil {
								info = append(
									info,
									mr,
								)
								//if m["Capacity"]!="N/A"{
								//	each_mem_dict["SerialNumber"] = m["SN"]
								//	if each_mem_dict["Name"] == nil {
								//		each_mem_dict["Name"] = fmt.Sprintln("Mem %d", i+1)
								//	}
								//	each_mem_dict["Size"] = m["Capacity"]
								//	each_mem_dict["DimmType"] = m["DRAMType"]
								//	each_mem_dict["ModuleType"] = m["Module"]
								//	each_mem_dict["Manufacturer"] = m["Manufacturer"]
								//	each_mem_dict["PartNumber"] = m["PN"]
								//	each_mem_dict["RankNum"] = m["Rank"]
								//	each_mem_dict["Frequency"] = m["Frequency"]
								//	each_mem_dict["WorkFreq"] = m["work_freq"]
								//	each_mem_dict["Location"] = m["Location"]
								//	each_mem_dict["Status"] = m["Status"]
								//	smmmaryMemory = append(smmmaryMemory, each_mem_dict)
								//}
							}
						}
					}
				}
			}
			redf.Json["MemoryInfo"] = info
		}
	}
	if redf.Json["MemoryInfo"] == nil {
		redf.Mem = 0

		return false, fmt.Errorf("get MemoryInfo is empty")
	}
	redf.Mem = 1
	return true, nil
}

func (redf *Redfish) GetMemorySummary() (totalSystemMemory interface{}) {
	if tools.IsContain([]string{"sugon", "dell", "hp", "lenovo", "nettrix", "ibm"}, redf.Mode) {
		m := map[string]interface{}{}
		//m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			memQuery := m["MemorySummary"]
			if memQuery != nil {
				odataJson, _ := json.Marshal(memQuery)
				if err := json.Unmarshal(odataJson, &m); err == nil {
					SystemMemory := m["TotalSystemMemoryGiB"]
					if SystemMemory != nil {
						totalSystemMemory = int64(SystemMemory.(float64))
						return
					}
				} else {
					fmt.Println("GetMemorySummary json.Unmarshal(odataJson, &m)", err)
				}
			}
		}
	}
	return
}

// 获取硬盘详细信息
func (redf *Redfish) GetPhysicalDisk() (ok bool, err error) {
	if tools.IsContain([]string{"sugon", "dell", "lenovo", "nettrix", "ibm"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		driveOdataSt := map[string]string{}
		r := redf.GetSysEmbedded()
		info := []map[string]interface{}{}
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			physicalQuery := m["Storage"]
			if physicalQuery != nil {
				odataJson, _ := json.Marshal(physicalQuery)
				if err := json.Unmarshal(odataJson, &m); err == nil {
					storageData := m["@odata.id"].(string)
					storageInfo := redf.GetInfo(storageData)
					if err := json.Unmarshal([]byte(storageInfo.String()), &m); err == nil {
						storageMembers := m["Members"]
						redf.Json["PhysicalDiskMembers"] = storageMembers
						if storageMembers != nil {
							storageMembers2, _ := json.Marshal(storageMembers)
							if err := json.Unmarshal(storageMembers2, &m2); err == nil {
								for _, storageOdata := range m2 {
									//var each_mem_dict map[string]interface{}
									//each_mem_dict = make(map[string]interface{})
									odataJson, _ := json.Marshal(storageOdata)
									m3 := map[string]interface{}{}
									if err := json.Unmarshal(odataJson, &m3); err == nil {
										diskInfo := redf.GetInfo(m3["@odata.id"].(string))
										if err := json.Unmarshal([]byte(diskInfo.String()), &m3); err == nil {
											drivesQuery := m3["Drives"]
											if drivesQuery != nil || drivesQuery != "" {
												drivesQueryOid, _ := json.Marshal(drivesQuery)
												if err := json.Unmarshal(drivesQueryOid, &m2); err == nil {
													for _, driveOid := range m2 {
														driveIdJson, _ := json.Marshal(driveOid)
														dm := map[string]interface{}{}
														if err := json.Unmarshal(driveIdJson, &driveOdataSt); err == nil {
															driveOdataId := driveOdataSt["@odata.id"]
															driveOdataInfo := redf.GetInfo(driveOdataId)
															if err := json.Unmarshal([]byte(driveOdataInfo.String()), &dm); err == nil {
																info = append(
																	info,
																	dm,
																)
															}
														}
													}

												}

											}
										}
									}
								}
							}
							//fmt.Println("=====",info)
							//jsonStr, _ := json.Marshal(redf.Json)
							//mString :=string(jsonStr)
							//fmt.Println("11-----1",mString)
							//global.Redis.Set(redf.Host, mString, 86400*time.Second)
						}
					}
					//jsonStr, _ := json.Marshal(redf.Json)
					//mString := string(jsonStr)
					//fmt.Println("11-----1", mString)
				}
			} else if m["SimpleStorage"] != nil {
				odataJson, _ := json.Marshal(m["SimpleStorage"])
				if err := json.Unmarshal(odataJson, &m); err == nil {
					if m["@odata.id"] != nil {
						storageData := m["@odata.id"].(string)
						storageInfo := redf.GetInfo(storageData)
						if err := json.Unmarshal([]byte(storageInfo.String()), &m); err == nil {
							storageMembers := m["Members"]
							if storageMembers != nil {
								storageMembers2, _ := json.Marshal(storageMembers)
								if err := json.Unmarshal(storageMembers2, &m2); err == nil {
									for _, storageOdata := range m2 {
										//var each_mem_dict map[string]interface{}
										//each_mem_dict = make(map[string]interface{})
										odataJson, _ := json.Marshal(storageOdata)
										m3 := map[string]interface{}{}
										if err := json.Unmarshal(odataJson, &m3); err == nil {
											diskInfo := redf.GetInfo(m3["@odata.id"].(string))
											if diskInfo != nil {
												if err := json.Unmarshal([]byte(diskInfo.String()), &m3); err == nil {
													drivesQuery := m3["Devices"]
													m4 := []interface{}{}
													if drivesQuery != nil || drivesQuery != "" {
														drivesQueryOid, _ := json.Marshal(drivesQuery)
														if err := json.Unmarshal(drivesQueryOid, &m4); err == nil {
															for _, driveOid := range m4 {
																driveIdJson, _ := json.Marshal(driveOid)
																driveOdataSt2 := map[string]interface{}{}
																//dm := map[string]interface{}{}
																if err := json.Unmarshal(driveIdJson, &driveOdataSt2); err == nil {
																	//driveOdataId := driveOdataSt["@odata.id"]
																	info = append(
																		info,
																		driveOdataSt2,
																	)
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		redf.Json["PhysicalDiskInfo"] = info
		//fmt.Println("==1111=",cpu_query,reflect.TypeOf(cpu_query))
	} else if tools.IsContain([]string{"sugon2"}, redf.Mode) {
		m := map[string]interface{}{}
		//m2 := []interface{}{}
		//driveOdataSt := map[string]string{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			physicalQuery := m["Storage"]
			//info := []map[string]interface{}{}
			//fmt.Println("==1111=",cpu_query,reflect.TypeOf(cpu_query))
			odataJson, _ := json.Marshal(physicalQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				storageData := m["@odata.id"].(string)
				storageInfo := redf.GetInfo(storageData)
				if err := json.Unmarshal([]byte(storageInfo.String()), &m); err == nil {
					//storageMembers := m["Members@odata.count"]
					redf.Json["PhysicalDiskMembers"] = m
				}
			}
		}
	} else if tools.IsContain([]string{"hp"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		arrayControllers := redf.GetInfo("/redfish/v1/Systems/1/SmartStorage/ArrayControllers")
		if err := json.Unmarshal([]byte(arrayControllers.String()), &m); err == nil {
			physicalMembers := m["Members"]
			fmt.Println("kkkkk", m["Members"])
			memb := fmt.Sprintf("%s", m["Members"])
			if memb != "[]" {
				redf.Json["PhysicalDiskMembers"] = physicalMembers
				odataJson, _ := json.Marshal(physicalMembers)
				if err := json.Unmarshal(odataJson, &m2); err == nil {
					for _, storageOdata := range m2 {
						//var each_mem_dict map[string]interface{}
						//each_mem_dict = make(map[string]interface{})
						odataJson, _ := json.Marshal(storageOdata)
						m3 := map[string]interface{}{}
						info := []map[string]interface{}{}
						if err := json.Unmarshal(odataJson, &m3); err == nil {
							diskInfo := redf.GetInfo(m3["@odata.id"].(string))
							if err := json.Unmarshal([]byte(diskInfo.String()), &m3); err == nil {
								arrayLink := m3["Links"]
								drivesLink, _ := json.Marshal(arrayLink)
								if err := json.Unmarshal(drivesLink, &m); err == nil {
									physicalDrivesLink := m["PhysicalDrives"]
									if physicalDrivesLink != nil {
										physicalDrive, _ := json.Marshal(physicalDrivesLink)
										if err := json.Unmarshal(physicalDrive, &m); err == nil {
											driveOid := m["@odata.id"]
											physicalDrivesInfo := redf.GetInfo(driveOid.(string))
											physicalDrivesMembers, _ := json.Marshal(physicalDrivesInfo)
											if err := json.Unmarshal(physicalDrivesMembers, &m2); err == nil {
												for _, eachDrivesOid := range m2 {
													//var each_mem_dict map[string]interface{}
													//each_mem_dict = make(map[string]interface{})
													odataJson, _ := json.Marshal(eachDrivesOid)
													if err := json.Unmarshal(odataJson, &m3); err == nil {
														eachDriveInfo := redf.GetInfo(m3["@odata.id"].(string))
														if err := json.Unmarshal([]byte(eachDriveInfo.String()), &m3); err == nil {
															info = append(
																info,
																m3,
															)
														}

													}
												}
											}

										}
									}
								}
							}
						}
						redf.Json["PhysicalDiskInfo"] = info
					}
				}
			} else {
				m := map[string]interface{}{}
				m2 := []interface{}{}
				//driveOdataSt := map[string]string{}
				r := redf.GetSysEmbedded()
				info := []map[string]interface{}{}
				if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
					physicalQuery := m["Storage"]
					if physicalQuery != nil {
						odataJson, _ := json.Marshal(physicalQuery)
						if err := json.Unmarshal(odataJson, &m); err == nil {
							storageData := m["@odata.id"].(string)
							storageInfo := redf.GetInfo(storageData)
							if err := json.Unmarshal([]byte(storageInfo.String()), &m); err == nil {
								storageMembers := m["Members"]
								redf.Json["PhysicalDiskMembers"] = storageMembers
								if storageMembers != nil {
									storageMembers2, _ := json.Marshal(storageMembers)
									if err := json.Unmarshal(storageMembers2, &m2); err == nil {
										for _, storageOdata := range m2 {
											//var each_mem_dict map[string]interface{}
											//each_mem_dict = make(map[string]interface{})
											odataJson, _ := json.Marshal(storageOdata)
											m3 := map[string]interface{}{}
											if err := json.Unmarshal(odataJson, &m3); err == nil {
												diskInfo := redf.GetInfo(m3["@odata.id"].(string))
												if err := json.Unmarshal([]byte(diskInfo.String()), &m3); err == nil {
													drivesQuery := m3["StorageControllers"]
													fmt.Println("==3333", drivesQuery)
													m4 := []interface{}{}
													if drivesQuery != nil || drivesQuery != "" {
														drivesQueryOid, _ := json.Marshal(drivesQuery)
														if err := json.Unmarshal(drivesQueryOid, &m4); err == nil {
															for _, driveOid := range m4 {
																driveIdJson, _ := json.Marshal(driveOid)
																dm := map[string]interface{}{}
																if err := json.Unmarshal(driveIdJson, &dm); err == nil {
																	fmt.Println("========", dm)
																	info = append(
																		info,
																		dm,
																	)
																}
															}

														}

													}
												}
											}
										}
									}
									//fmt.Println("=====",info)
									//jsonStr, _ := json.Marshal(redf.Json)
									//mString :=string(jsonStr)
									//fmt.Println("11-----1",mString)
									//global.Redis.Set(redf.Host, mString, 86400*time.Second)
								}
							}
						}
					}
				}
				redf.Json["PhysicalDiskInfo"] = info
			}
		}
	}
	if redf.Json["PhysicalDiskInfo"] == nil {
		redf.Disk = 0
		return false, fmt.Errorf("get MemoryInfo is empty")
	}
	redf.Disk = 1
	return true, nil
}

// 获取网卡信息
func (redf *Redfish) GetNetworkInterfaces() (ok bool, err error) {
	if tools.IsContain([]string{"dell"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			networkInterfaceQuery := m["NetworkInterfaces"]
			info := []map[string]interface{}{}
			networkLists := []map[string]interface{}{}
			odataJson, _ := json.Marshal(networkInterfaceQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				networkInterfaceData := m["@odata.id"].(string)
				networkInterfaceInfo := redf.GetInfo(networkInterfaceData)
				if err := json.Unmarshal([]byte(networkInterfaceInfo.String()), &m); err == nil {
					networkInterfaceMembers := m["Members"]
					redf.Json["NetworkInterfaceMembers"] = networkInterfaceMembers
					if networkInterfaceMembers != nil {
						networkMembers2, _ := json.Marshal(networkInterfaceMembers)
						if err := json.Unmarshal(networkMembers2, &m2); err == nil {
							for _, networkOdata := range m2 {
								m3 := map[string]interface{}{}
								odataJson6, _ := json.Marshal(networkOdata)
								if err := json.Unmarshal(odataJson6, &m3); err == nil {
									eachNetworkInfo := redf.GetInfo(m3["@odata.id"].(string))
									if err := json.Unmarshal([]byte(eachNetworkInfo.String()), &m); err == nil {
										eachNetworkLink := m["Links"]
										if eachNetworkLink != nil {
											odataJson4, _ := json.Marshal(eachNetworkLink)
											if err := json.Unmarshal(odataJson4, &m); err == nil {
												networkAutilsQuery := m["Networkutils"]
												m5 := map[string]interface{}{}
												odataJson5, _ := json.Marshal(networkAutilsQuery)
												if err := json.Unmarshal(odataJson5, &m5); err == nil {
													if m5["@odata.id"] != nil {
														utilsOdata := m5["@odata.id"].(string)
														each_utils_info := redf.GetInfo(utilsOdata)
														eachNet := map[string]interface{}{}
														if err := json.Unmarshal([]byte(each_utils_info.String()), &eachNet); err == nil {
															//fmt.Println("====",eachNet)
															info = append(
																info,
																eachNet,
															)
															networkPorts := eachNet["NetworkPorts"]
															if networkPorts != nil {
																odataJson, _ := json.Marshal(networkPorts)
																m6 := map[string]interface{}{}
																if err := json.Unmarshal(odataJson, &m6); err == nil {
																	networkPortOid := m6["@odata.id"].(string)
																	eachPortInfo := redf.GetInfo(networkPortOid)
																	eachPo := map[string]interface{}{}
																	if err := json.Unmarshal([]byte(eachPortInfo.String()), &eachPo); err == nil {
																		eachPortMembers := eachPo["Members"]
																		if eachPortMembers != nil {
																			eachPortMembers2, _ := json.Marshal(eachPortMembers)
																			if err := json.Unmarshal(eachPortMembers2, &m2); err == nil {
																				for _, eachPortMember := range m2 {
																					epm := map[string]interface{}{}
																					networkEpm := map[string]interface{}{}
																					odataJson, _ := json.Marshal(eachPortMember)
																					if err := json.Unmarshal(odataJson, &epm); err == nil {
																						eachInfo := redf.GetInfo(epm["@odata.id"].(string))
																						//fmt.Println("====",eachInfo,reflect.TypeOf(eachInfo))
																						if err := json.Unmarshal([]byte(eachInfo.String()), &networkEpm); err == nil {
																							networkEpm["Manufacturer"] = eachNet["Manufacturer"]
																							networkEpm["Location"] = eachNet["Id"]
																							networkEpm["Model"] = eachNet["Model"]
																							networkLists = append(
																								networkLists,
																								networkEpm,
																							)
																						}
																					}
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}

											}
										}
									}
								}
							}
							redf.Json["Networkutils"] = info
							redf.Json["NetworkNIC"] = networkLists
						}

					}
				}
			}
		}
	} else if tools.IsContain([]string{"hp"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			info := []map[string]interface{}{}
			baseutils := redf.GetInfo("/redfish/v1/Systems/1/BaseNetworkutilss")
			if err := json.Unmarshal([]byte(baseutils.String()), &m); err == nil {
				networkMembers := m["Members"]
				odataJson, _ := json.Marshal(networkMembers)
				if err := json.Unmarshal(odataJson, &m2); err == nil {
					for _, eachMember := range m2 {
						m3 := map[string]interface{}{}
						odataJson, _ := json.Marshal(eachMember)
						if err := json.Unmarshal(odataJson, &m3); err == nil {
							eachBaseNetwork := redf.GetInfo(m3["@odata.id"].(string))
							if err := json.Unmarshal([]byte(eachBaseNetwork.String()), &m3); err == nil {
								info = append(
									info,
									m3,
								)
							}
						}
					}
					redf.Json["NetworkNIC"] = info
				}

			}
		}
	} else if tools.IsContain([]string{"lenovo", "ibm"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			networkInterfaceQuery := m["NetworkInterfaces"]
			info := []map[string]interface{}{}
			//networkLists := []map[string]interface{}{}
			odataJson, _ := json.Marshal(networkInterfaceQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				networkInterfaceData := m["@odata.id"].(string)
				networkInterfaceInfo := redf.GetInfo(networkInterfaceData)
				if err := json.Unmarshal([]byte(networkInterfaceInfo.String()), &m); err == nil {
					networkInterfaceMembers := m["Members"]
					redf.Json["NetworkInterfaceMembers"] = networkInterfaceMembers
					if networkInterfaceMembers != nil {
						networkMembers2, _ := json.Marshal(networkInterfaceMembers)
						if err := json.Unmarshal(networkMembers2, &m2); err == nil {
							for _, networkOdata := range m2 {
								m3 := map[string]interface{}{}
								odataJson, _ := json.Marshal(networkOdata)
								if err := json.Unmarshal(odataJson, &m3); err == nil {
									eachNetworkInfo := redf.GetInfo(m3["@odata.id"].(string))
									if err := json.Unmarshal([]byte(eachNetworkInfo.String()), &m); err == nil {
										eachNetworkLink := m["Links"]
										if eachNetworkLink != nil {
											odataJson, _ := json.Marshal(eachNetworkLink)
											if err := json.Unmarshal(odataJson, &m); err == nil {
												networkAutilsQuery := m["Networkutils"]
												odataJson, _ := json.Marshal(networkAutilsQuery)
												if err := json.Unmarshal(odataJson, &m3); err == nil {
													utilsOdata := m3["@odata.id"].(string)
													each_utils_info := redf.GetInfo(utilsOdata)
													eachNet := map[string]interface{}{}
													if err := json.Unmarshal([]byte(each_utils_info.String()), &eachNet); err == nil {
														//fmt.Println("====",eachNet)
														info = append(
															info,
															eachNet,
														)
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			redf.Json["Networkutils"] = info
		}

	} else if tools.IsContain([]string{"sugon", "nettrix"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetSysEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			networkInterfaceQuery := m["NetworkInterfaces"]
			info := []map[string]interface{}{}
			//networkLists := []map[string]interface{}{}
			odataJson, _ := json.Marshal(networkInterfaceQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				networkInterfaceData := m["@odata.id"].(string)
				networkInterfaceInfo := redf.GetInfo(networkInterfaceData)
				if err := json.Unmarshal([]byte(networkInterfaceInfo.String()), &m); err == nil {
					networkInterfaceMembers := m["Members"]
					redf.Json["NetworkInterfaceMembers"] = networkInterfaceMembers
					if networkInterfaceMembers != nil {
						networkMembers2, _ := json.Marshal(networkInterfaceMembers)
						if err := json.Unmarshal(networkMembers2, &m2); err == nil {
							for _, networkOdata := range m2 {
								m3 := map[string]interface{}{}
								odataJson, _ := json.Marshal(networkOdata)
								if err := json.Unmarshal(odataJson, &m3); err == nil {
									eachNetworkInfo := redf.GetInfo(m3["@odata.id"].(string))
									if err := json.Unmarshal([]byte(eachNetworkInfo.String()), &m3); err == nil {
										info = append(
											info,
											m3,
										)
									}
								}
							}
						}
					}
				}
			}
			redf.Json["Networkutils"] = info
		}
	}
	if redf.Json["Networkutils"] == nil {
		return false, fmt.Errorf("get Networkutils is empty")
	}
	return true, nil
}

type NetworkData struct {
	InterfaceName string
	MacAddress    []string
}

func (redf *Redfish) GetNetWorkInfo() (ok bool, err error) {
	m := map[string]interface{}{}
	m2 := []interface{}{}
	r := redf.GetChassisEmbedded()
	if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
		networkadapterQuery := m["NetworkAdapters"]
		info := []map[string]interface{}{}
		//networkLists := []map[string]interface{}{}
		odataJson, _ := json.Marshal(networkadapterQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			adapterOid := m["@odata.id"]
			if adapterOid != nil {
				adapterOidQuery := redf.GetInfo(adapterOid.(string))
				if err := json.Unmarshal([]byte(adapterOidQuery.String()), &m); err == nil {
					members := m["Members"]
					if members != nil {
						interfaceMembers2, _ := json.Marshal(members)
						if err := json.Unmarshal(interfaceMembers2, &m2); err == nil {
							for _, eachMember := range m2 {
								m3 := map[string]interface{}{}
								odataJson3, _ := json.Marshal(eachMember)
								if err := json.Unmarshal(odataJson3, &m3); err == nil {
									ethernetInterfaceMsg := redf.GetInfo(m3["@odata.id"].(string))
									m4 := map[string]interface{}{}
									if err := json.Unmarshal([]byte(ethernetInterfaceMsg.String()), &m4); err == nil {
										//networkport := m4["NetworkPorts"]
										info = append(
											info,
											m4,
										)
									}

								}
							}
						}
					}

				} else {
					fmt.Println("==GetInfo(powerOid err", err)
				}
			}
			//jsonStr, _ := json.Marshal(redf.Json)
			//mString := string(jsonStr)
			//fmt.Println("11-----1", mString)
		}
		redf.Json["Network"] = info
	} else {
		fmt.Println("===Getnetwork NetworkAdapters err", err)
	}
	if redf.Json["Network"] == nil {
		return false, fmt.Errorf("Getnetwork is empty")
	}
	return true, nil
}

func (redf *Redfish) GetNetWork() (ok bool, err error) {
	m := map[string]interface{}{}
	m2 := []interface{}{}
	r := redf.GetChassisEmbedded()
	if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
		networkadapterQuery := m["NetworkAdapters"]
		info := []map[string]interface{}{}
		//networkLists := []map[string]interface{}{}
		odataJson, _ := json.Marshal(networkadapterQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			adapterOid := m["@odata.id"]
			if adapterOid != nil {
				adapterOidQuery := redf.GetInfo(adapterOid.(string))
				if err := json.Unmarshal([]byte(adapterOidQuery.String()), &m); err == nil {
					members := m["Members"]
					if members != nil {
						interfaceMembers2, _ := json.Marshal(members)
						if err := json.Unmarshal(interfaceMembers2, &m2); err == nil {
							for _, eachMember := range m2 {
								m3 := map[string]interface{}{}
								odataJson3, _ := json.Marshal(eachMember)
								if err := json.Unmarshal(odataJson3, &m3); err == nil {
									ethernetInterfaceMsg := redf.GetInfo(m3["@odata.id"].(string))
									m4 := map[string]interface{}{}
									if err := json.Unmarshal([]byte(ethernetInterfaceMsg.String()), &m4); err == nil {
										networkport := m4["NetworkPorts"]
										networkportjson, _ := json.Marshal(networkport)
										m5 := map[string]interface{}{}
										if err := json.Unmarshal(networkportjson, &m5); err == nil {
											eachadapterOid := m5["@odata.id"]
											if eachadapterOid != nil {
												eachadapterOidQuery := redf.GetInfo(eachadapterOid.(string))
												m6 := map[string]interface{}{}
												if err := json.Unmarshal([]byte(eachadapterOidQuery.String()), &m6); err == nil {
													eachadaptermembers := m6["Members"]
													m7 := []interface{}{}
													if eachadaptermembers != nil {
														adapterMembers3, _ := json.Marshal(eachadaptermembers)
														if err := json.Unmarshal(adapterMembers3, &m7); err == nil {
															for _, eachadapterMember := range m7 {
																m8 := map[string]interface{}{}
																odataJson4, _ := json.Marshal(eachadapterMember)
																if err := json.Unmarshal(odataJson4, &m8); err == nil {
																	eachadapterInterface := redf.GetInfo(m8["@odata.id"].(string))
																	m9 := map[string]interface{}{}
																	if err := json.Unmarshal([]byte(eachadapterInterface.String()), &m9); err == nil {
																		info = append(
																			info,
																			m9,
																		)
																	}
																}

															}
														}
													}
												}
											}
										}
									}

								}
							}
						}
					}

				} else {
					fmt.Println("==GetInfo(powerOid err", err)
				}
			}
			//jsonStr, _ := json.Marshal(redf.Json)
			//mString := string(jsonStr)
			//fmt.Println("11-----1", mString)
		}
		redf.Json["Networkadapter"] = info
	} else {
		fmt.Println("===Getnetwork NetworkAdapters err", err)
	}
	if redf.Json["Networkadapter"] == nil {
		return false, fmt.Errorf("Getnetwork is empty")
	}
	return true, nil
}

func (redf *Redfish) GetPowerControl() (ok bool, err error) {
	if tools.IsContain([]string{"sugon", "hp", "dell", "nettrix"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetChassisEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			powerQuery := m["Power"]
			info := []map[string]interface{}{}
			//networkLists := []map[string]interface{}{}
			odataJson, _ := json.Marshal(powerQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				powerOid := m["@odata.id"]
				if powerOid != nil {
					powerQidQuery := redf.GetInfo(powerOid.(string))
					if err := json.Unmarshal([]byte(powerQidQuery.String()), &m); err == nil {
						powerControl := m["PowerControl"]
						redf.Json["PowerControl"] = powerControl
						if powerControl != nil {
							powerControlMembers, _ := json.Marshal(powerControl)
							if err := json.Unmarshal(powerControlMembers, &m2); err == nil {
								for _, eachPowerSupply := range m2 {
									m3 := map[string]interface{}{}
									odataJson, _ := json.Marshal(eachPowerSupply)
									if err := json.Unmarshal(odataJson, &m3); err == nil {
										info = append(
											info,
											m3,
										)
									}
								}
							}
						}

					} else {
						fmt.Println("==GetInfo(powerOid err", err)
					}
				}
				redf.Json["PowerControlInfo"] = info
				//jsonStr, _ := json.Marshal(redf.Json)
				//mString := string(jsonStr)
				//fmt.Println("11-----1", mString)
			} else {
				fmt.Println("===GetPowerControl powerOid err", err)
			}
		} else {
			fmt.Println("===GetPowerControl get power err", err)
		}
	} else if tools.IsContain([]string{"lenovo", "ibm"}, redf.Mode) {
		fmt.Println("====222")
		m := map[string]interface{}{}
		m2 := []interface{}{}
		powersupply := []interface{}{}
		//driveOdataSt := map[string]string{}
		r := redf.GetChassisEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			info := []map[string]interface{}{}
			linkQuery := m["Links"]
			if linkQuery != nil {
				odataJson, _ := json.Marshal(linkQuery)
				if err := json.Unmarshal(odataJson, &m); err == nil {
					linkPower := m["PoweredBy"]
					if linkPower != nil {
						powerMembers, _ := json.Marshal(linkPower)
						if err := json.Unmarshal(powerMembers, &m2); err == nil {
							for _, eachPowerLink := range m2 {
								//var each_mem_dict map[string]interface{}
								//each_mem_dict = make(map[string]interface{})
								odataJson, _ := json.Marshal(eachPowerLink)
								m3 := map[string]interface{}{}
								if err := json.Unmarshal(odataJson, &m3); err == nil {
									powerQuery := redf.GetInfo(m3["@odata.id"].(string))
									if err := json.Unmarshal([]byte(powerQuery.String()), &m3); err == nil {
										powerSupplies := m3["PowerControl"]
										if powerSupplies != nil {
											powerSupplieQuery, _ := json.Marshal(powerSupplies)
											if err := json.Unmarshal(powerSupplieQuery, &powersupply); err == nil {
												for _, eachPowersupply := range powersupply {
													//var each_mem_dict map[string]interface{}
													//each_mem_dict = make(map[string]interface{})
													odataJson, _ := json.Marshal(eachPowersupply)
													m4 := map[string]interface{}{}
													if err := json.Unmarshal(odataJson, &m4); err == nil {
														info = append(
															info,
															m4,
														)
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			redf.Json["PowerControlInfo"] = info
		}
	}
	if redf.Json["PowerControlInfo"] == nil {
		return false, fmt.Errorf("get PowerControlInfo is empty")
	}
	return true, nil
}

// 获取电源信息
func (redf *Redfish) GetPowerSupply() (ok bool, err error) {
	if tools.IsContain([]string{"sugon", "hp", "dell", "nettrix"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetChassisEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			powerQuery := m["Power"]
			info := []map[string]interface{}{}
			//networkLists := []map[string]interface{}{}
			odataJson, _ := json.Marshal(powerQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				powerOid := m["@odata.id"]
				if powerOid != nil {
					powerQidQuery := redf.GetInfo(powerOid.(string))
					if err := json.Unmarshal([]byte(powerQidQuery.String()), &m); err == nil {
						powerSupplies := m["PowerSupplies"]
						redf.Json["PowerSupplies"] = powerSupplies
						if powerSupplies != nil {
							powerSuppliesMembers, _ := json.Marshal(powerSupplies)
							if err := json.Unmarshal(powerSuppliesMembers, &m2); err == nil {
								for _, eachPowerSupply := range m2 {
									m3 := map[string]interface{}{}
									odataJson, _ := json.Marshal(eachPowerSupply)
									if err := json.Unmarshal(odataJson, &m3); err == nil {
										info = append(
											info,
											m3,
										)
									}
								}
							}
						}

					} else {
						fmt.Println("==GetInfo(powerOid err", err)
					}
				}
				redf.Json["PowerInfo"] = info
				//jsonStr, _ := json.Marshal(redf.Json)
				//mString := string(jsonStr)
				//fmt.Println("11-----1", mString)
			} else {
				fmt.Println("===GetPowerSupply powerOid err", err)
			}
		} else {
			fmt.Println("===GetPowerSupply get power err", err)
		}
	} else if tools.IsContain([]string{"lenovo", "ibm"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		powersupply := []interface{}{}
		//driveOdataSt := map[string]string{}
		r := redf.GetChassisEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			info := []map[string]interface{}{}
			linkQuery := m["Links"]
			if linkQuery != nil {
				odataJson, _ := json.Marshal(linkQuery)
				if err := json.Unmarshal(odataJson, &m); err == nil {
					linkPower := m["PoweredBy"]
					if linkPower != nil {
						powerMembers, _ := json.Marshal(linkPower)
						if err := json.Unmarshal(powerMembers, &m2); err == nil {
							for _, eachPowerLink := range m2 {
								//var each_mem_dict map[string]interface{}
								//each_mem_dict = make(map[string]interface{})
								odataJson, _ := json.Marshal(eachPowerLink)
								m3 := map[string]interface{}{}
								if err := json.Unmarshal(odataJson, &m3); err == nil {
									powerQuery := redf.GetInfo(m3["@odata.id"].(string))
									if err := json.Unmarshal([]byte(powerQuery.String()), &m3); err == nil {
										powerSupplies := m3["PowerSupplies"]
										if powerSupplies != nil {
											powerSupplieQuery, _ := json.Marshal(powerSupplies)
											if err := json.Unmarshal(powerSupplieQuery, &powersupply); err == nil {
												for _, eachPowersupply := range powersupply {
													//var each_mem_dict map[string]interface{}
													//each_mem_dict = make(map[string]interface{})
													odataJson, _ := json.Marshal(eachPowersupply)
													m4 := map[string]interface{}{}
													if err := json.Unmarshal(odataJson, &m4); err == nil {
														info = append(
															info,
															m4,
														)
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			redf.Json["PowerInfo"] = info
		}
	}
	if redf.Json["PowerInfo"] == nil {
		return false, fmt.Errorf("get PowerInfo is empty")
	}
	return true, nil
}

// 获取电源信息
func (redf *Redfish) GetPCIe() (ok bool, err error) {
	info := []map[string]interface{}{}
	if tools.IsContain([]string{"dell"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetChassisEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			linkQuery := m["Links"]
			//networkLists := []map[string]interface{}{}
			odataJson, _ := json.Marshal(linkQuery)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				if m["PCIeDevices"] != nil {
					pcieMembers, _ := json.Marshal(m["PCIeDevices"])
					if err := json.Unmarshal(pcieMembers, &m2); err == nil {
						for _, eachPowerLink := range m2 {
							var eachPciDict map[string]interface{}
							eachPciDict = make(map[string]interface{})
							odataJson, _ := json.Marshal(eachPowerLink)
							m3 := map[string]interface{}{}
							if err := json.Unmarshal(odataJson, &m3); err == nil {
								//eachPciDict["CurSpeed"] = m3["LinkSpeed"]
								//eachPciDict["Manufacturer"] = m3["Manufacturer"]
								//eachPciDict["Type"] = m3["Class"]
								//eachPciDict["Model"] = m3["BrandName"]
								//eachPciDict["Location"] = m3["Location"]
								//eachPciDict["NegoLinkWidth"] = m3["LinkWidth"]
								info = append(info, eachPciDict)

							}
						}
					}

				}
			}
		}
	}
	redf.Json["Pcie"] = info
	fmt.Println("---pcie", info)
	if redf.Json["Pcie"] == nil {
		redf.Pcie = 0
		return false, fmt.Errorf("pcie get is empty")
	}
	redf.Pcie = 1
	return true, nil
}

// 获取BMC
func (redf *Redfish) GetBMCIp() (ok bool, err error) {
	if tools.IsContain([]string{"dell", "sugon", "hp", "lenovo", "nettrix", "ibm"}, redf.Mode) {
		m := map[string]interface{}{}
		m2 := []interface{}{}
		r := redf.GetManagersEmbedded()
		if err := json.Unmarshal([]byte(r.String()), &m); err == nil {
			ethernetInterface := m["EthernetInterfaces"]
			info := []map[string]interface{}{}
			//networkLists := []map[string]interface{}{}
			odataJson, _ := json.Marshal(ethernetInterface)
			if err := json.Unmarshal(odataJson, &m); err == nil {
				ethernetInterfaceOid := m["@odata.id"].(string)
				ethernetInterfaceInfo := redf.GetInfo(ethernetInterfaceOid)
				if err := json.Unmarshal([]byte(ethernetInterfaceInfo.String()), &m); err == nil {
					ethernetInterfaceMembers := m["Members"]
					redf.Json["ethernetInterfaceMembers"] = ethernetInterfaceMembers
					if ethernetInterfaceMembers != nil {
						interfaceMembers2, _ := json.Marshal(ethernetInterfaceMembers)
						if err := json.Unmarshal(interfaceMembers2, &m2); err == nil {
							for _, eachMember := range m2 {
								m3 := map[string]interface{}{}
								odataJson, _ := json.Marshal(eachMember)
								if err := json.Unmarshal(odataJson, &m3); err == nil {
									ethernetInterfaceMsg := redf.GetInfo(m3["@odata.id"].(string))
									m4 := map[string]interface{}{}
									if err := json.Unmarshal([]byte(ethernetInterfaceMsg.String()), &m4); err == nil {
										info = append(info, m4)
									}

								}
							}
						}
					}
				}
			}
			redf.Json["BMC"] = info
		}
	}
	if redf.Json["BMC"] == nil {
		return false, fmt.Errorf("get BMC is empty")
	}
	return true, nil
}

// 保存json数据
func (redf *Redfish) RedFishToJson() (ok bool, err error) {
	jsonStr, _ := json.Marshal(redf.Json)
	mString := string(jsonStr)
	fmt.Println("========================\n", mString)
	global.Redis.Set(context.Background(), redf.Host, mString, 86400*time.Second)
	msg := fmt.Sprintf("========================\n%s", mString)
	if msg == "" {
		return false, fmt.Errorf("RedFishToJson is empty")
	}
	return true, nil
}

// 采集设备所有数据并入库
func RedFishCollect(host, username, password, device_model string) (ok bool, err error) {
	var red = NewRedFish()
	ok, err = red.RedfishCollect(host, username, password, device_model)
	if !ok {
		return false, err
	}
	//go func(){
	//	ok, msg =red.GetCpuInfo()
	//}()
	//go func(){
	//	ok, msg = red.GetMemoryInfo()
	//}()
	//go func(){
	//	ok, msg = red.GetNetworkInterfaces()
	//}()
	//go func(){
	//	ok, msg = red.GetPhysicalDisk()
	//}()
	//go func(){
	//	ok, msg = red.GetPowerSupply()
	//}()
	//go func(){
	//	ok, msg = red.GetBMCIp()
	//}()
	//go func(){
	//	ok, msg = red.GetPCIe()
	//}()
	//go func(){
	//	for {
	//		if red.Cpu ==1 &&red.Mem==1 &&red.Disk==1{
	//			ok, msg = red.RedFishToJson()
	//			break
	//		}
	//		fmt.Println("===11",&red.Disk)
	//	}
	//}()
	////red.GetCpuSummary()  //获取cpu简略信息
	ok, err = red.GetCpuInfo()    //获取cpu详细信息
	ok, err = red.GetMemoryInfo() //获取mem信息
	//red.GetMemorySummary()  //获取mem简略信息
	ok, err = red.GetPhysicalDisk()      //获取硬盘详细信息
	ok, err = red.GetNetworkInterfaces() //获取网卡信息
	ok, err = red.GetPowerSupply()       //获取电源信息
	ok, err = red.GetBMCIp()
	ok, err = red.GetPCIe()       //获取PCIE
	ok, err = red.RedFishToJson() //保存数据并打印
	return ok, err
}

// ----------------------------解析数据------------------------------
// 去redis数据并专为json
func (res *ResultRedFish) RedFishToMap(host, mode string) {
	result := global.Redis.Get(context.Background(), host)
	m := map[string]interface{}{}
	if err := json.Unmarshal([]byte(result.Val()), &m); err == nil {
		res.Json = m
		res.Mode = mode
	}
}

// 获取Cpu
func (res *ResultRedFish) GetCpu() (info []map[string]interface{}) {
	cpuQuery := res.Json["CpuInfo"]
	//mapInterface := map[string]interface{}{}
	listInterface := []interface{}{}
	cpuMembers, _ := json.Marshal(cpuQuery)
	//info := []map[string]interface{}{}
	if err := json.Unmarshal(cpuMembers, &listInterface); err == nil {
		for i, cpuData := range listInterface {
			m3 := map[string]interface{}{}
			odataJson, _ := json.Marshal(cpuData)
			var eachCpuDict map[string]interface{}
			eachCpuDict = make(map[string]interface{})
			if err := json.Unmarshal(odataJson, &m3); err == nil {
				if tools.IsContain([]string{"sugon", "dell", "hp", "lenovo", "nettrix"}, res.Mode) {
					eachCpuDict["Manufacturer"] = m3["Manufacturer"]
					eachCpuDict["Model"] = m3["Model"]
					eachCpuDict["Name"] = m3["Name"]
					eachCpuDict["InstructionSet"] = m3["InstructionSet"]
					eachCpuDict["TotalCores"] = m3["TotalCores"]
					eachCpuDict["TotalThreads"] = m3["TotalThreads"]
					eachCpuDict["Socket"] = m3["Socket"]
					eachCpuDict["Frequency"] = m3["Frequency"]
					eachCpuDict["PartNumber"] = m3["PartNumber"]
					eachCpuDict["SerialNumber"] = m3["SerialNumber"]
					eachCpuDict["Tdp"] = m3["Tdp"]
					eachCpuDict["Status"] = m3["Status"]
				} else if tools.IsContain([]string{"sugon2"}, res.Mode) {
					eachCpuDict["Manufacturer"] = m3["Manufacturer"]
					eachCpuDict["Model"] = m3["BrandName"]
					eachCpuDict["Name"] = m3["Name"]
					if eachCpuDict["Name"] == nil {
						eachCpuDict["Name"] = fmt.Sprintf("CPU %d", i+1)
					}
					eachCpuDict["InstructionSet"] = m3["InstructionSet"]
					if m3["CurrentCoresCurrentThreads"] != nil {
						CurrentCoresCurrentThreads := strings.Split(m3["CurrentCoresCurrentThreads"].(string), "/")
						eachCpuDict["TotalCores"] = CurrentCoresCurrentThreads[0]
						eachCpuDict["TotalThreads"] = CurrentCoresCurrentThreads[1]
					} else {
						eachCpuDict["TotalCores"] = ""
						eachCpuDict["TotalThreads"] = ""
					}
					eachCpuDict["Socket"] = m3["Socket"]
					eachCpuDict["Frequency"] = m3["Frequency"]
					eachCpuDict["WorkFreq"] = m3["TurboFrequency"]
					eachCpuDict["PartNumber"] = m3["PartNumber"]
					eachCpuDict["SerialNumber"] = m3["SerialNumber"]
					eachCpuDict["Tdp"] = m3["TDP"]
					eachCpuDict["Status"] = m3["Status"]
				}
				info = append(info, eachCpuDict)
			} else {
				fmt.Println("GetCpu m3 err", err)
			}
		}
		fmt.Println("====cpu result", info)
	} else {
		fmt.Println("GetCpu istInterface err", err)
	}
	return info
}

// 获取Mem
func (res *ResultRedFish) GetMem() (info []map[string]interface{}) {
	memQuery := res.Json["MemoryInfo"]
	listInterface := []interface{}{}
	memMembers, _ := json.Marshal(memQuery)
	//info := []map[string]interface{}{}
	if err := json.Unmarshal(memMembers, &listInterface); err == nil {
		for i, cpuData := range listInterface {
			m3 := map[string]interface{}{}
			odataJson, _ := json.Marshal(cpuData)
			var eachMemDict map[string]interface{}
			eachMemDict = make(map[string]interface{})
			if err := json.Unmarshal(odataJson, &m3); err == nil {
				if tools.IsContain([]string{"sugon", "dell", "hp", "lenovo", "nettrix", "ibm"}, res.Mode) {
					if m3["CapacityMiB"] != nil {
						eachMemDict["Name"] = m3["Name"]
						if m3["CapacityMiB"] != nil {
							CapacityGb := strconv.FormatFloat(m3["CapacityMiB"].(float64)/1024, 'f', -1, 64) + "GB"
							eachMemDict["Size"] = CapacityGb
						} else {
							CapacityGb := ""
							eachMemDict["Size"] = CapacityGb
						}
						if m3["MemoryDeviceType"] != nil {
							memoryDeviceType := m3["MemoryDeviceType"]
							eachMemDict["DimmType"] = memoryDeviceType
						} else if m3["MemoryType"] != nil {
							memoryDeviceType := m3["MemoryType"]
							eachMemDict["DimmType"] = memoryDeviceType
						} else {
							memoryDeviceType := ""
							eachMemDict["DimmType"] = memoryDeviceType
						}
						eachMemDict["ModuleType"] = m3["MemoryType"]
						eachMemDict["SerialNumber"] = m3["SerialNumber"]
						eachMemDict["Manufacturer"] = m3["Manufacturer"]
						eachMemDict["RankCount"] = m3["RankCount"]
						eachMemDict["PartNumber"] = m3["PartNumber"]
						eachMemDict["Frequency"] = m3["AllowedSpeedsMHz"]
						eachMemDict["WorkFreq"] = m3["OperatingSpeedMhz"]
						eachMemDict["Location"] = m3["Location"]
						eachMemDict["status"] = m3["Status"]
					}
				} else if tools.IsContain([]string{"Sugon2"}, res.Mode) {
					if m3["Capacity"] != "N/A" {
						eachMemDict["SerialNumber"] = m3["SN"]
						if eachMemDict["Name"] == nil {
							eachMemDict["Name"] = fmt.Sprintf("Mem %d", i+1)
						}
						eachMemDict["Size"] = m3["Capacity"]
						eachMemDict["DimmType"] = m3["DRAMType"]
						eachMemDict["ModuleType"] = m3["Module"]
						eachMemDict["Manufacturer"] = m3["Manufacturer"]
						eachMemDict["PartNumber"] = m3["PN"]
						eachMemDict["RankNum"] = m3["Rank"]
						eachMemDict["Frequency"] = m3["Frequency"]
						eachMemDict["WorkFreq"] = m3["work_freq"]
						eachMemDict["Location"] = m3["Location"]
						eachMemDict["Status"] = m3["Status"]
					}
				}
				info = append(info, eachMemDict)
			} else {
				fmt.Println("GetMem m3 err", err)
			}
		}
		fmt.Println("====get mem ", info)
	} else {
		fmt.Println("GetMem istInterface err", err)
	}
	return info
}

// 获取网卡信息
func (res *ResultRedFish) GetNetwork() (info []map[string]interface{}) {
	networkQuery := res.Json["NetworkNIC"]
	listInterface := []interface{}{}
	networkMembers, _ := json.Marshal(networkQuery)
	//info := []map[string]interface{}{}
	if err := json.Unmarshal(networkMembers, &listInterface); err == nil {
		for _, cpuData := range listInterface {
			m3 := map[string]interface{}{}
			odataJson, _ := json.Marshal(cpuData)
			var eachNetworkDict map[string]interface{}
			eachNetworkDict = make(map[string]interface{})
			if err := json.Unmarshal(odataJson, &m3); err == nil {
				if tools.IsContain([]string{"dell"}, res.Mode) {
					eachNetworkDict["Manufacturer"] = m3["Manufacturer"]
					eachNetworkDict["Location"] = m3["Location"]
					eachNetworkDict["Model"] = m3["Model"]
					eachNetworkDict["Mac"] = m3["AssociatedNetworkAddresses"]
					eachNetworkDict["LinkSpeed"] = m3["SupportedLinkCapabilities"]
					eachNetworkDict["port"] = m3["PhysicalPortNumber"]
				} else if tools.IsContain([]string{"hp"}, res.Mode) {
					eachNetworkDict["Manufacturer"] = m3["Manufacturer"]
					eachNetworkDict["Location"] = m3["Location"]
					eachNetworkDict["Model"] = m3["Model"]
					eachNetworkDict["Mac"] = m3["MacAddress"]
					eachNetworkDict["LinkSpeed"] = m3["SpeedMbps"]
					eachNetworkDict["port"] = m3["Name"]
				} else if tools.IsContain([]string{"sugon", "nettrix"}, res.Mode) {
					eachNetworkDict["Manufacturer"] = m3["Manufacturer"]
					eachNetworkDict["Location"] = m3["Location"]
					eachNetworkDict["Model"] = m3["Model"]
					eachNetworkDict["Mac"] = m3["AssociatedNetworkAddresses"]
					eachNetworkDict["LinkSpeed"] = m3["LinkSpeedMbps"]
					eachNetworkDict["port"] = m3["Id"]
				} else if tools.IsContain([]string{"lenovo", "ibm"}, res.Mode) {
					eachNetworkDict["Manufacturer"] = m3["Manufacturer"]
					eachNetworkDict["Location"] = m3["Location"]
					eachNetworkDict["Model"] = m3["Model"]
					eachNetworkDict["Mac"] = m3["AssociatedNetworkAddresses"]
					eachNetworkDict["LinkSpeed"] = m3["LinkSpeedMbps"]
					eachNetworkDict["port"] = m3["Id"]
				}
				info = append(
					info,
					eachNetworkDict,
				)
			}
		}
	}
	fmt.Println("===get network", info)
	return info
}

// 获取硬盘数据
func (res *ResultRedFish) GetStorage() (info []map[string]interface{}) {
	storageQuery := res.Json["PhysicalDiskInfo"]
	listInterface := []interface{}{}
	storageMembers, _ := json.Marshal(storageQuery)
	//info := []map[string]interface{}{}
	if err := json.Unmarshal(storageMembers, &listInterface); err == nil {
		for _, storageData := range listInterface {
			m3 := map[string]interface{}{}
			odataJson, _ := json.Marshal(storageData)
			var eachStorageDict map[string]interface{}
			eachStorageDict = make(map[string]interface{})
			if err := json.Unmarshal(odataJson, &m3); err == nil {
				if tools.IsContain([]string{"sugon", "dell", "lenovo", "nettrix"}, res.Mode) {
					var device_size, mamufacturer interface{}
					if m3["CapacityGB"] != nil {
						device_size = m3["CapacityGB"]
					} else if m3["CapacityBytes"] != nil {
						device_size = m3["CapacityBytes"].(float64) / 1024 / 1024 / 1024
					}
					eachStorageDict["Size"] = device_size
					eachStorageDict["Location"] = m3["Location"]
					eachStorageDict["Type"] = m3["MediaType"]
					eachStorageDict["Mode"] = m3["Model"]
					eachStorageDict["PartNumber"] = m3["PartNumber"]
					eachStorageDict["SerialNumber"] = m3["SerialNumber"]
					if m3["Manufacturer"] != nil {
						mamufacturer = m3["Manufacturer"]
					} else if m3["Manufacture"] != nil {
						mamufacturer = m3["Manufacture"]
					}
					eachStorageDict["Manufacturer"] = mamufacturer
					eachStorageDict["Model"] = m3["Name"]
					eachStorageDict["Status"] = m3["Status"]
				} else if tools.IsContain([]string{"hp"}, res.Mode) {
					eachStorageDict["Size"] = m3["CapacityGB"]
					eachStorageDict["Location"] = m3["Location"]
					eachStorageDict["Type"] = m3["MediaType"]
					eachStorageDict["Mode"] = m3["Model"]
					eachStorageDict["PartNumber"] = m3["PartNumber"]
					eachStorageDict["SerialNumber"] = m3["SerialNumber"]
					eachStorageDict["Manufacturer"] = m3["Manufacture"]
					eachStorageDict["Model"] = m3["Name"]
					eachStorageDict["Status"] = m3["Status"]
				}
				info = append(
					info,
					eachStorageDict,
				)
			}
		}
	}
	fmt.Println("====storage", info)
	return info
}

// 获取电源
func (res *ResultRedFish) GetPower() (info []map[string]interface{}) {
	powerQuery := res.Json["PowerInfo"]
	listInterface := []interface{}{}
	powerMembers, _ := json.Marshal(powerQuery)
	//info := []map[string]interface{}{}
	if err := json.Unmarshal(powerMembers, &listInterface); err == nil {
		for _, powerData := range listInterface {
			m3 := map[string]interface{}{}
			odataJson, _ := json.Marshal(powerData)
			var eachPowerDict map[string]interface{}
			eachPowerDict = make(map[string]interface{})
			if err := json.Unmarshal(odataJson, &m3); err == nil {
				if tools.IsContain([]string{"sugon", "hp", "dell", "nettrix"}, res.Mode) {
					eachPowerDict["Manufacturer"] = m3["Manufacturer"]
					eachPowerDict["RatedPower"] = m3["PowerCapacityWatts"]
					eachPowerDict["SerialNumber"] = m3["SerialNumber"]
					eachPowerDict["Model"] = m3["Model"]
					eachPowerDict["Location"] = m3["MemberId"]
					eachPowerDict["Status"] = m3["Status"]
				} else if tools.IsContain([]string{"lenovo"}, res.Mode) {
					eachPowerDict["Manufacturer"] = m3["Manufacturer"]
					eachPowerDict["RatedPower"] = m3["PowerCapacityWatts"]
					eachPowerDict["SerialNumber"] = m3["SerialNumber"]
					eachPowerDict["Model"] = m3["Model"]
					eachPowerDict["Location"] = m3["Name"]
					eachPowerDict["Status"] = m3["Status"]
				}
				info = append(
					info,
					eachPowerDict,
				)
			}
		}
	}
	fmt.Println("===pwer", info)
	return info
}

// 获取BMC
func (res *ResultRedFish) GetBMC() (info []map[string]interface{}) {
	bmcQuery := res.Json["BMC"]
	listInterface := []interface{}{}
	bmcMembers, _ := json.Marshal(bmcQuery)
	//info := []map[string]interface{}{}
	if err := json.Unmarshal(bmcMembers, &listInterface); err == nil {
		for _, bmcData := range listInterface {
			m3 := map[string]interface{}{}
			odataJson, _ := json.Marshal(bmcData)
			var eachBMCDict map[string]interface{}
			eachBMCDict = make(map[string]interface{})
			if err := json.Unmarshal(odataJson, &m3); err == nil {
				if tools.IsContain([]string{"dell"}, res.Mode) {
					if m3["Name"] != nil {
						r, _ := regexp.Compile("Manager Ethernet")
						reName := r.MatchString(m3["Name"].(string))
						if reName {
							ipv4Members, _ := json.Marshal(m3["IPv4Addresses"])
							m2 := []interface{}{}
							if err := json.Unmarshal(ipv4Members, &m2); err == nil {
								for _, each_ipv4 := range m2 {
									odataJson, _ := json.Marshal(each_ipv4)
									m4 := map[string]interface{}{}
									if err := json.Unmarshal(odataJson, &m4); err == nil {
										if m4["Address"] != nil {
											eachBMCDict["Ipv4Address"] = m4["Address"]
											eachBMCDict["Ipv4Gateway"] = m4["Gateway"]
											eachBMCDict["Ipv4Type"] = m4["AddressOrigin"]
											eachBMCDict["NetworkType"] = "Dedicated Lan"
											eachBMCDict["OnlineUser"] = ""
										}
									}
								}
							}
							ipv6Members, _ := json.Marshal(m3["IPv6Addresses"])
							m5 := []interface{}{}
							if err := json.Unmarshal(ipv6Members, &m5); err == nil {
								for _, each_ipv4 := range m5 {
									odataJson, _ := json.Marshal(each_ipv4)
									m4 := map[string]interface{}{}
									if err := json.Unmarshal(odataJson, &m4); err == nil {
										if m4["Address"] != nil {
											eachBMCDict["Ipv6Address"] = m4["Address"]
											eachBMCDict["IPv6Gateway"] = m4["Gateway"]
											eachBMCDict["IPv6Type"] = m4["AddressOrigin"]
										}
									}
								}
								if eachBMCDict["IPv6Gateway"] == nil {
									eachBMCDict["IPv6Gateway"] = m3["IPv6DefaultGateway"]
								}
							}
						}
					}
				} else if tools.IsContain([]string{"sugon", "sugno2", "nettrix"}, res.Mode) {
					if m3["HostName"] != nil {
						ipv4Members, _ := json.Marshal(m3["IPv4Addresses"])
						m2 := []interface{}{}
						if err := json.Unmarshal(ipv4Members, &m2); err == nil {
							for _, each_ipv4 := range m2 {
								odataJson, _ := json.Marshal(each_ipv4)
								m4 := map[string]interface{}{}
								if err := json.Unmarshal(odataJson, &m4); err == nil {
									if m4["Address"] != nil {
										eachBMCDict["Ipv4Address"] = m4["Address"]
										eachBMCDict["Ipv4Gateway"] = m4["Gateway"]
										eachBMCDict["Ipv4Type"] = m4["AddressOrigin"]
										eachBMCDict["NetworkType"] = "Dedicated Lan"
										eachBMCDict["OnlineUser"] = ""
									}
								}
							}
						}
						ipv6Members, _ := json.Marshal(m3["IPv6Addresses"])
						m5 := []interface{}{}
						if err := json.Unmarshal(ipv6Members, &m5); err == nil {
							for _, each_ipv4 := range m5 {
								odataJson, _ := json.Marshal(each_ipv4)
								m4 := map[string]interface{}{}
								if err := json.Unmarshal(odataJson, &m4); err == nil {
									if m4["Address"] != nil {
										eachBMCDict["Ipv6Address"] = m4["Address"]
										eachBMCDict["IPv6Gateway"] = m4["Gateway"]
										eachBMCDict["IPv6Type"] = m4["AddressOrigin"]
									}
								}
							}
							if eachBMCDict["IPv6Gateway"] == nil {
								eachBMCDict["IPv6Gateway"] = m3["IPv6DefaultGateway"]
							}
						}

					}
				} else if tools.IsContain([]string{"lenovo", "ibm"}, res.Mode) {
					moem := map[string]interface{}{}
					//interface_mode := map[string]interface{}{}
					if m3["Oem"] != nil {
						odataJson, _ := json.Marshal(m3["Oem"])
						if err := json.Unmarshal(odataJson, &moem); err == nil {
							if moem["Lenovo"] != nil {
								odataJson, _ := json.Marshal(moem["Lenovo"])
								if err := json.Unmarshal(odataJson, &moem); err == nil {
									interfaceMode := moem["InterfaceNicMode"].(string)
									r, _ := regexp.Compile("Dedicated")
									intMode := r.MatchString(interfaceMode)
									if intMode {
										ipv4Members, _ := json.Marshal(m3["IPv4Addresses"])
										m2 := []interface{}{}
										if err := json.Unmarshal(ipv4Members, &m2); err == nil {
											for _, each_ipv4 := range m2 {
												odataJson, _ := json.Marshal(each_ipv4)
												m4 := map[string]interface{}{}
												if err := json.Unmarshal(odataJson, &m4); err == nil {
													if m4["Address"] != nil {
														eachBMCDict["Ipv4Address"] = m4["Address"]
														eachBMCDict["Ipv4Gateway"] = m4["Gateway"]
														eachBMCDict["Ipv4Type"] = m4["AddressOrigin"]
														eachBMCDict["NetworkType"] = "Dedicated Lan"
														eachBMCDict["OnlineUser"] = ""
													}
												}
											}
										}
										ipv6Members, _ := json.Marshal(m3["IPv6Addresses"])
										m5 := []interface{}{}
										if err := json.Unmarshal(ipv6Members, &m5); err == nil {
											for _, each_ipv4 := range m5 {
												odataJson, _ := json.Marshal(each_ipv4)
												m4 := map[string]interface{}{}
												if err := json.Unmarshal(odataJson, &m4); err == nil {
													if m4["Address"] != nil {
														eachBMCDict["Ipv6Address"] = m4["Address"]
														eachBMCDict["IPv6Gateway"] = m4["Gateway"]
														eachBMCDict["IPv6Type"] = m4["AddressOrigin"]
													}
												}
											}
											if eachBMCDict["IPv6Gateway"] == nil {
												eachBMCDict["IPv6Gateway"] = m3["IPv6DefaultGateway"]
											}
										}
									}
								}
							}
						}

					}
				}
				info = append(
					info,
					eachBMCDict,
				)
			}
		}
	}
	fmt.Println("===BMC", info)
	return info
}

// 获取电源
func (res *ResultRedFish) GetPCi() (info []map[string]interface{}) {
	powerQuery := res.Json["PowerInfo"]
	listInterface := []interface{}{}
	powerMembers, _ := json.Marshal(powerQuery)
	//info := []map[string]interface{}{}
	if err := json.Unmarshal(powerMembers, &listInterface); err == nil {
		for _, powerData := range listInterface {
			m3 := map[string]interface{}{}
			odataJson, _ := json.Marshal(powerData)
			var eachPciDict map[string]interface{}
			eachPciDict = make(map[string]interface{})
			if err := json.Unmarshal(odataJson, &m3); err == nil {
				if tools.IsContain([]string{"dell"}, res.Mode) {
					eachPciDict["CurSpeed"] = m3["LinkSpeed"]
					eachPciDict["Manufacturer"] = m3["Manufacturer"]
					eachPciDict["Type"] = m3["Class"]
					eachPciDict["Model"] = m3["BrandName"]
					eachPciDict["Location"] = m3["Location"]
					eachPciDict["NegoLinkWidth"] = m3["LinkWidth"]
				}
				info = append(
					info,
					eachPciDict,
				)
			}
		}

	}
	fmt.Println("PCie==", info)
	return info
}

// 获取厂商
func (res *ResultRedFish) GetManufacturer() (manufacturer string) {
	if tools.IsContain([]string{"dell", "hp", "lenovo", "ibm"}, res.Mode) {
		sysQuery := res.Json["GetSysEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(sysQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["Manufacturer"] != nil {
				manufacturer = m["Manufacturer"].(string)
			}
		}
	} else if tools.IsContain([]string{"sugon", "sugon2", "nettrix"}, res.Mode) {
		sysQuery := res.Json["GetChassisEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(sysQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["Manufacturer"] != nil {
				manufacturer = m["Manufacturer"].(string)
			}
		}
	}
	return manufacturer
}

// 获取设备类型
func (res *ResultRedFish) GetDeviceType() (deviceType string) {
	if tools.IsContain([]string{"dell", "hp", "lenovo", "sugon", "sugon2", "nettrix", "ibm"}, res.Mode) {
		chassisQuery := res.Json["GetChassisEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(chassisQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["ChassisType"] != nil {
				deviceType = m["ChassisType"].(string)
			}
		}
	}
	return deviceType
}

// 获取model
func (res *ResultRedFish) GetModel() (model string) {
	if tools.IsContain([]string{"dell", "hp", "lenovo"}, res.Mode) {
		sysQuery := res.Json["GetSysEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(sysQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["Model"] != nil {
				model = m["Model"].(string)
			}
		}
	} else if tools.IsContain([]string{"sugon", "sugon", "nettrix"}, res.Mode) {
		manageQuery := res.Json["GetManagersEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(manageQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["Model"] != nil {
				model = m["Model"].(string)
			}
		}
	}
	return model
}

// 获取主机名
func (res *ResultRedFish) GetHostname() (hostName string) {
	if tools.IsContain([]string{"dell", "hp", "lenovo", "sugon", "sugon2", "nettrix", "ibm"}, res.Mode) {
		sysQuery := res.Json["GetSysEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(sysQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["HostName"] != nil {
				hostName = m["HostName"].(string)
			}
		}
	}
	return hostName
}

// 获取SerialNumber
func (res *ResultRedFish) GetSerialNumber() (serialNumber string) {
	if tools.IsContain([]string{"dell", "hp", "lenovo", "sugon", "sugon2", "nettrix", "ibm"}, res.Mode) {
		sysQuery := res.Json["GetSysEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(sysQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["SerialNumber"] != nil {
				serialNumber = m["SerialNumber"].(string)
			}
		}
	}
	return serialNumber
}

// 获取Watts
func (res *ResultRedFish) GetWatts() (watts string) {
	sysQuery := res.Json["GetSysEmbedded"]
	//listInterface := []interface{}{}
	m := map[string]interface{}{}
	odataJson, _ := json.Marshal(sysQuery)
	if err := json.Unmarshal(odataJson, &m); err == nil {
		if m["Watts"] != nil {
			watts = m["Watts"].(string)
		}
	}
	return watts
}

// 获取SerialNumber
func (res *ResultRedFish) GetPartNumber() (partNumber string) {
	sysQuery := res.Json["GetSysEmbedded"]
	//listInterface := []interface{}{}
	m := map[string]interface{}{}
	odataJson, _ := json.Marshal(sysQuery)
	if err := json.Unmarshal(odataJson, &m); err == nil {
		if m["PartNumber"] != nil {
			partNumber = m["PartNumber"].(string)
		}
	}
	return partNumber
}

// 获取BiosVersion
func (res *ResultRedFish) GetBiosVersion() (biosVersion string) {
	if tools.IsContain([]string{"dell", "hp", "lenovo", "ibm"}, res.Mode) {
		sysQuery := res.Json["GetSysEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(sysQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["BiosVersion"] != nil {
				biosVersion = m["BiosVersion"].(string)
			}
		}
	} else if tools.IsContain([]string{"sugon", "nettrix"}, res.Mode) {
		sysQuery := res.Json["GetSysEmbedded"]
		//listInterface := []interface{}{}
		m := map[string]interface{}{}
		odataJson, _ := json.Marshal(sysQuery)
		if err := json.Unmarshal(odataJson, &m); err == nil {
			if m["BIOSVersion"] != nil {
				biosVersion = m["BIOSVersion"].(string)
			}
		}
	}
	return biosVersion
}

// 获取BMCVersion
func (res *ResultRedFish) GetBMCVersion() (bmcVersion string) {
	manageQuery := res.Json["GetManagersEmbedded"]
	//listInterface := []interface{}{}
	m := map[string]interface{}{}
	odataJson, _ := json.Marshal(manageQuery)
	if err := json.Unmarshal(odataJson, &m); err == nil {
		if m["FirmwareVersion"] != nil {
			bmcVersion = m["FirmwareVersion"].(string)
		}
	}
	return bmcVersion
}

type basicServer struct {
	Manufacturer string
	HostName     string
	DeviceType   string
	Model        string
	PartNumber   string
	SerialNumber string
	Watts        string
	BiosVersion  string
	BmcVersion   string
}

// 获取基础信息
func (res *ResultRedFish) GetBasicServer() (result *basicServer) {
	manufacturer := res.GetManufacturer()
	hostName := res.GetHostname()
	deviceType := res.GetDeviceType()
	model := res.GetModel()
	partNumber := res.GetPartNumber()
	serialNumber := res.GetSerialNumber()
	watts := res.GetWatts()
	biosVersion := res.GetBiosVersion()
	bmcVersion := res.GetBMCVersion()
	result = &basicServer{
		Manufacturer: manufacturer,
		HostName:     hostName,
		DeviceType:   deviceType,
		Model:        model,
		PartNumber:   partNumber,
		SerialNumber: serialNumber,
		Watts:        watts,
		BiosVersion:  biosVersion,
		BmcVersion:   bmcVersion,
	}
	fmt.Println("===basic", result)
	return result
}
