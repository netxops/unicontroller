package fetch

import (
	"io"
	"net/http"
	"os"

	"github.com/douyu/jupiter/pkg/xlog"
)

type Fetch struct {
	url      string
	tempPath string
}

func NewFetch(url string) *Fetch {
	return &Fetch{
		url: url,
	}
}

func (f *Fetch) Download() (*Fetch, string, error) {
	xlog.Default().Info("new download with url", xlog.String("url", f.url))
	tempFile, err := os.CreateTemp(os.TempDir(), "UniOPS-AGENT-TEMP-*.zip")
	if err != nil {
		return f, "", err
	}
	defer func(tempFile *os.File) {
		_ = tempFile.Close()
	}(tempFile)

	// dialer, err := proxy.SOCKS5("tcp", global.Conf.ProxyAddr, nil, proxy.Direct)
	// if err != nil {
	// 	return f, "", err
	// }

	httpTransport := &http.Transport{}
	// if global.Conf.IsIsolatedNetworkEnv && !global.Conf.EnableProxy {
	// 	xlog.Default().Info("download with proxy", xlog.String("proxy", global.Conf.ProxyAddr))
	// 	httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	// 		return dialer.Dial(network, addr)
	// 	}
	// }
	client := &http.Client{
		Transport: httpTransport,
	}

	resp, err := client.Get(f.url)
	if err != nil {
		return f, "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if _, err = io.Copy(tempFile, resp.Body); err != nil {
		return f, "", err
	}

	f.tempPath = tempFile.Name()
	return f, f.tempPath, nil
}

func (f *Fetch) Clear() {
	_ = os.Remove(f.tempPath)
}
