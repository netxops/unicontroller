package controller

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
	"github.com/golang/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

type PrometheusForwarder struct {
	UpstreamURL    string
	Client         *http.Client
	BufferSize     int
	FlushInterval  time.Duration
	buffer         [][]byte
	bufferMutex    sync.Mutex
	AddressLabels  map[string]map[string]string
	RedisManager   *RedisManager
	AttachLabelKey string
}

func ProvidePrometheusForwarder(config *ConfigManager, redisManager *RedisManager) *PrometheusForwarder {
	pf := &PrometheusForwarder{
		UpstreamURL: config.Config.BaseConfig.UpstreamPrometheusUrl,
		Client: &http.Client{
			Timeout: time.Second * 30,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		BufferSize:     1000,
		FlushInterval:  5 * time.Second,
		buffer:         make([][]byte, 0),
		RedisManager:   redisManager,
		AttachLabelKey: config.Config.BaseConfig.PrometheusLabelKey,
	}

	go pf.flushPeriodically()
	return pf
}

func (pf *PrometheusForwarder) ForwardHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		xlog.Error("Failed to read request body", xlog.FieldErr(err))
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	pf.bufferMutex.Lock()
	pf.buffer = append(pf.buffer, body)
	if len(pf.buffer) >= pf.BufferSize {
		go pf.flush()
	}
	pf.bufferMutex.Unlock()

	w.WriteHeader(http.StatusAccepted)
}

func (pf *PrometheusForwarder) flush() {
	pf.bufferMutex.Lock()
	defer pf.bufferMutex.Unlock()

	if len(pf.buffer) == 0 {
		return
	}

	var writeRequest prompb.WriteRequest
	for _, data := range pf.buffer {
		decompressed, err := snappy.Decode(nil, data)
		if err != nil {
			xlog.Error("Failed to decompress data", xlog.FieldErr(err))
			decompressed = data
		}

		var req prompb.WriteRequest
		if err := proto.Unmarshal(decompressed, &req); err != nil {
			xlog.Error("Failed to unmarshal WriteRequest", xlog.FieldErr(err))
			xlog.Error("Received data (first 100 bytes)", xlog.String("data", string(decompressed[:min(100, len(decompressed))])))
			continue
		}

		for _, ts := range req.Timeseries {
			device_code := ""
			tags := make(map[string]string)

			// for _, label := range ts.Labels {
			// 	if label.Name == "__name__" {
			// 		metricName = label.Value
			// 	} else {
			// 		tags[label.Name] = label.Value
			// 	}
			// }

			for _, label := range ts.Labels {
				if label.Name == "device_code" {
					device_code = label.Value
				}

				tags[label.Name] = label.Value
			}

			// 从 Redis 获取附加标签
			additionalLabels, err := pf.getAdditionalLabels(device_code, tags)
			if err != nil {
				xlog.Error("Failed to get additional labels", xlog.FieldErr(err))
				continue
			}

			if len(additionalLabels) > 0 {
				ts.Labels = ts.Labels[:0]
				// 附加标签

				for k, v := range additionalLabels {
					ts.Labels = append(ts.Labels, prompb.Label{Name: k, Value: v})
				}
			}

			writeRequest.Timeseries = append(writeRequest.Timeseries, ts)
		}
	}

	pf.buffer = pf.buffer[:0]

	if len(writeRequest.Timeseries) == 0 {
		xlog.Warn("No valid timeseries data to send")
		return
	}

	// Serialize the WriteRequest to bytes
	uncompressed, err := proto.Marshal(&writeRequest)
	if err != nil {
		xlog.Error("Failed to marshal WriteRequest", xlog.FieldErr(err))
		return
	}

	// Compress using Snappy
	compressed := snappy.Encode(nil, uncompressed)

	req, err := http.NewRequest("POST", pf.UpstreamURL, bytes.NewReader(compressed))
	if err != nil {
		xlog.Error("Failed to create new request", xlog.FieldErr(err))
		return
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	resp, err := pf.Client.Do(req)
	if err != nil {
		xlog.Error("Failed to forward request to upstream",
			xlog.FieldErr(err),
			xlog.String("upstreamURL", pf.UpstreamURL))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		xlog.Error("Upstream server returned error",
			xlog.Int("statusCode", resp.StatusCode),
			xlog.String("responseBody", string(bodyBytes)))
	} else {
		xlog.Info("Successfully forwarded data to upstream",
			xlog.Int("statusCode", resp.StatusCode),
			xlog.Int("timeseriesCount", len(writeRequest.Timeseries)))
	}
}

// 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func (pf *PrometheusForwarder) flushPeriodically() {
	ticker := time.NewTicker(pf.FlushInterval)
	for range ticker.C {
		pf.flush()
	}
}

// func (pf *PrometheusForwarder) getAdditionalLabels(metricName string, tags map[string]string) (map[string]string, error) {
// 	// 根据指标名称选择适当的 Redis key
// 	var redisKey string
// 	switch metricName {
// 	case "ping":
// 		redisKey = string(enum.IpAddrForPing)
// 	case "snmp":
// 		redisKey = string(enum.DeviceForSnmp)
// 	case "snmp_interface":
// 		redisKey = string(enum.InterfaceForSnmp)
// 	case "tail":
// 		redisKey = string(enum.DeviceForTail)
// 	default:
// 		return nil, nil
// 	}

// 	// 构造 Redis 查询的 key
// 	var queryKey string
// 	switch metricName {
// 	case "ping":
// 		queryKey = tags["url"]
// 	case "snmp", "snmp_interface":
// 		ident := tags["ident"]
// 		if ident == "" {
// 			ident = tags["agent_host"]
// 		}
// 		source := tags["source"]
// 		if metricName == "snmp_interface" {
// 			ifDescr := tags["ifDescr"]
// 			queryKey = fmt.Sprintf("%s,%s,%s", ident, source, ifDescr)
// 		} else {
// 			queryKey = fmt.Sprintf("%s,%s", ident, source)
// 		}
// 	case "tail":
// 		queryKey = tags["hostname"]
// 	}

// 	if queryKey == "" {
// 		return nil, fmt.Errorf("unable to construct query key for metric %s", metricName)
// 	}

// 	// 从 Redis 获取数据
// 	data, err := pf.RedisManager.Get(enum.DataKey(redisKey))
// 	if err != nil {
// 		return nil, err
// 	}

// 	if additionalLabels, ok := data[queryKey]; ok {
// 		result := make(map[string]string)
// 		for k, v := range additionalLabels {
// 			result[k] = fmt.Sprint(v)
// 		}
// 		return result, nil
// 	}

// 	return nil, nil
// }

func (pf *PrometheusForwarder) getAdditionalLabels(deviceCode string, tags map[string]string) (map[string]string, error) {

	// 从 Redis 获取数据
	data, err := pf.RedisManager.Get(pf.AttachLabelKey)
	if err != nil {
		return nil, err
	}

	if additionalLabels, ok := data[deviceCode]; ok {
		result := make(map[string]string)
		for k, v := range additionalLabels {
			result[k] = fmt.Sprint(v)
		}
		for k, v := range tags {
			if _, ok := result[k]; !ok {
				result[k] = v
			}
		}
		result["host"] = result["hostname"]
		delete(result, "device_name")
		delete(result, "hostname")

		return result, nil
	}

	return nil, nil
}
