package structs

import (
	"testing"
)

var testFileUrlData = []struct {
	fileUrl FileUrl
	want    string
}{
	{
		fileUrl: FileUrl{
			Protocol: HTTP,
			Host:     "1.1.1.1",
			Path:     "a.iso",
		},
		want: "http://1.1.1.1/a.iso",
	},
	{
		fileUrl: FileUrl{
			Protocol: HTTP,
			Host:     "1.1.1.1",
			Path:     "/a.iso",
		},
		want: "http://1.1.1.1/a.iso",
	},
	{
		fileUrl: FileUrl{
			Protocol: SCP,
			Host:     "1.1.1.1",
			Path:     "/a.iso",
			User:     "hello",
		},
		want: "scp://hello@1.1.1.1/a.iso",
	},
	{
		fileUrl: FileUrl{
			Protocol: FTP,
			Host:     "1.1.1.1",
			Path:     "/a.iso",
			User:     "hello",
			Pwd:      "world",
		},
		want: "ftp://hello:world@1.1.1.1/a.iso",
	},
	{
		fileUrl: FileUrl{
			Protocol: SFTP,
			Host:     "1.1.1.1",
			Path:     "/a.iso",
			User:     "hello",
			Pwd:      "world",
		},
		want: "sftp://hello:world@1.1.1.1/a.iso",
	},
	{
		fileUrl: FileUrl{
			Protocol: BOOTFLASH,
			Path:     "/a.iso",
		},
		want: "bootflash:///a.iso",
	},
	{
		fileUrl: FileUrl{
			Protocol: BOOTFLASH,
			Path:     "a.iso",
		},
		want: "bootflash:///a.iso",
	},
	{
		fileUrl: FileUrl{
			Protocol: FLASH,
			Path:     "a.iso",
		},
		want: "flash:/a.iso",
	},
	// {
	// fileUrl: FileUrl{
	// Protocol: BOOTFLASH,
	// },
	// want: "bootflash: vrf default",
	// },
}

func TestFileUrl(t *testing.T) {
	for _, ss := range testFileUrlData {
		got := ss.fileUrl.Url()
		if got != ss.want {
			t.Errorf("%+v, got:%s, want:%s", ss, got, ss.want)
		}
	}
}
