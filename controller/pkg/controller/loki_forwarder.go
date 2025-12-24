package controller

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/douyu/jupiter/pkg/xlog"
)

type LokiForwarder struct {
	UpstreamURL   string
	Client        *http.Client
	BufferSize    int
	FlushInterval time.Duration
	buffer        [][]byte
	bufferMutex   sync.Mutex
	RedisManager  *RedisManager
	LokiLabelKey  string
}

// LokiPushRequest represents the structure of a Loki push request
type LokiPushRequest struct {
	Streams []LokiStream `json:"streams"`
}

// LokiStream represents a stream of log entries in Loki
type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"` // [timestamp, log message]
}

func ProvideLokiForwarder(config *ConfigManager, redisManager *RedisManager) *LokiForwarder {
	lf := &LokiForwarder{
		UpstreamURL: config.Config.BaseConfig.UpstreamLokiUrl,
		Client: &http.Client{
			Timeout: time.Second * 30,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		BufferSize:    1000,
		FlushInterval: 5 * time.Second,
		buffer:        make([][]byte, 0),
		RedisManager:  redisManager,
		LokiLabelKey:  config.Config.BaseConfig.LokiLabelKey,
	}
	go lf.flushPeriodically()
	return lf
}

func (lf *LokiForwarder) ForwardHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		xlog.Error("Failed to read request body", xlog.FieldErr(err))
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	lf.bufferMutex.Lock()
	lf.buffer = append(lf.buffer, body)
	if len(lf.buffer) >= lf.BufferSize {
		go lf.flush()
	}
	lf.bufferMutex.Unlock()

	w.WriteHeader(http.StatusAccepted)
}

func (lf *LokiForwarder) flush() {
	lf.bufferMutex.Lock()
	defer lf.bufferMutex.Unlock()

	if len(lf.buffer) == 0 {
		return
	}

	// Process each buffered request
	for _, data := range lf.buffer {
		// Parse the Loki push request
		var pushRequest LokiPushRequest
		if err := json.Unmarshal(data, &pushRequest); err != nil {
			xlog.Error("Failed to unmarshal Loki push request",
				xlog.FieldErr(err),
				xlog.String("data_sample", string(data[:min(100, len(data))])))
			continue
		}

		xlog.Info("Processing Loki push request",
			xlog.Int("stream_count", len(pushRequest.Streams)))

		// Process each stream in the request
		for i, stream := range pushRequest.Streams {
			// Extract device_code from stream labels
			deviceCode := ""
			if code, ok := stream.Stream["device_code"]; ok {
				deviceCode = code
			}

			// Log the stream details
			streamLabels, _ := json.Marshal(stream.Stream)
			xlog.Info("Processing stream",
				xlog.Int("stream_index", i),
				xlog.String("device_code", deviceCode),
				xlog.String("labels", string(streamLabels)),
				xlog.Int("entry_count", len(stream.Values)))

			// Skip if no device code
			if deviceCode == "" {
				xlog.Info("Skipping stream without device_code",
					xlog.Int("stream_index", i))
				continue
			}

			// Get additional labels from Redis
			additionalLabels, err := lf.getAdditionalLabels(deviceCode, stream.Stream)
			if err != nil {
				xlog.Error("Failed to get additional labels",
					xlog.FieldErr(err),
					xlog.String("device_code", deviceCode))
				continue
			}

			// // Log the additional labels
			// if len(additionalLabels) > 0 {
			// 	labelsJSON, _ := json.Marshal(additionalLabels)
			// 	xlog.Info("Found additional labels for device",
			// 		xlog.String("device_code", deviceCode),
			// 		xlog.String("additional_labels", string(labelsJSON)),
			// 		xlog.Int("label_count", len(additionalLabels)))
			// } else {
			// 	xlog.Debug("No additional labels found for device",
			// 		xlog.String("device_code", deviceCode))
			// }

			if len(additionalLabels) > 0 {
				// Attach additional labels to the stream
				originalLabelCount := len(stream.Stream)
				pushRequest.Streams[i].Stream = additionalLabels

				// Log the label attachment
				xlog.Info("Attached additional labels to stream",
					xlog.String("device_code", deviceCode),
					xlog.Int("original_label_count", originalLabelCount),
					xlog.Int("new_label_count", len(pushRequest.Streams[i].Stream)),
					xlog.Int("added_label_count", len(additionalLabels)))

			}

		}

		// Re-marshal the enhanced request
		enhancedData, err := json.Marshal(pushRequest)
		if err != nil {
			xlog.Error("Failed to marshal enhanced Loki push request", xlog.FieldErr(err))
			continue
		}

		xlog.Info("Forwarding enhanced Loki push request",
			xlog.Int("byte_size", len(enhancedData)),
			xlog.Int("stream_count", len(pushRequest.Streams)))

		// Forward the enhanced request
		lf.forwardRequest(enhancedData)
	}

	// Clear the buffer
	lf.buffer = lf.buffer[:0]
}

func (lf *LokiForwarder) forwardRequest(body []byte) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(body); err != nil {
		xlog.Error("Failed to compress log data", xlog.FieldErr(err))
		return
	}
	gz.Close()

	req, err := http.NewRequest("POST", lf.UpstreamURL, &buf)
	if err != nil {
		xlog.Error("Failed to create new request", xlog.FieldErr(err))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := lf.Client.Do(req)
	if err != nil {
		xlog.Error("Failed to forward request to upstream",
			xlog.FieldErr(err),
			xlog.String("upstreamURL", lf.UpstreamURL))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := ioutil.ReadAll(resp.Body)
		xlog.Error("Upstream server returned error",
			xlog.Int("statusCode", resp.StatusCode),
			xlog.String("responseBody", string(bodyBytes)))
	} else {
		xlog.Info("Successfully forwarded logs to upstream",
			xlog.Int("statusCode", resp.StatusCode))
	}
}

func (lf *LokiForwarder) flushPeriodically() {
	ticker := time.NewTicker(lf.FlushInterval)
	for range ticker.C {
		lf.flush()
	}
}

func (pf *LokiForwarder) getAdditionalLabels(deviceCode string, tags map[string]string) (map[string]string, error) {
	// 从 Redis 获取数据
	data, err := pf.RedisManager.Get(pf.LokiLabelKey)
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
