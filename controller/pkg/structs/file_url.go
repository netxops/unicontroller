package structs

import (
	"fmt"
	"strings"
)

type FileUrl struct {
	Protocol ProtocolModel
	Host     string
	Path     string
	User     string
	Pwd      string
}

type ProtocolModel string

const (
	FTP       ProtocolModel = "ftp"
	SFTP      ProtocolModel = "sftp"
	SCP       ProtocolModel = "scp"
	HTTP      ProtocolModel = "http"
	HTTPS     ProtocolModel = "https"
	BOOTFLASH ProtocolModel = "bootflash"
	FLASH     ProtocolModel = "flash"
)

// copy ftp://1.1.1.1/public/a.iso bootflash://a.iso
// copy ftp://dev:dev@1.1.1.1/public/a.iso bootflash://a.iso
// copy scp://dev@1.1.1.1/public/a.iso bootlfalsh://a.iso
// copy bootflash://a.iso ftp://1.1.1.1/public/
// copy bootflash://a.iso tftp://1.1.1.1/public/
func (furl FileUrl) Url() string {
	var auth string
	if furl.User != "" {
		if furl.Pwd != "" {
			auth = strings.Join([]string{furl.User, furl.Pwd}, ":")
		} else {
			auth = furl.User
		}
		auth = auth + "@"
	}

	if furl.Host != "" {
		return fmt.Sprintf("%s://%s%s/%s", strings.ToLower(string(furl.Protocol)), auth, furl.Host, strings.TrimLeft(furl.Path, "/"))
	}
	if furl.Protocol == BOOTFLASH {
		return fmt.Sprintf("%s:///%s", furl.Protocol, strings.TrimLeft(furl.Path, "/"))
	}
	if furl.Protocol == FLASH {
		return fmt.Sprintf("%s:/%s", furl.Protocol, strings.TrimLeft(furl.Path, "/"))
	}
	return fmt.Sprintf("%s://%s", furl.Protocol, strings.TrimLeft(furl.Path, "/"))
}
