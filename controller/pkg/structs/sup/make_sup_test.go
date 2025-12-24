package sup

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSupConfig(t *testing.T) {
	var s SupConfig
	var err error
	err = s.RunCommand("myping", "ping -c 127.0.0.1", "ping test")
	if err != nil {
		fmt.Println("run err", err)
		return
	}
	err = s.ScriptCommand("system", "./scripts/sysinfo.sh")
	if err != nil {
		fmt.Println("script err", err)
		return
	}
	var up []*Upload
	var up1, up2 Upload
	src1 := "./"
	dst1 := "/tmp/$IMAGE"
	up1.Src = &src1
	up1.Dst = &dst1
	src2 := "./"
	dst2 := "/tmp/$IMAG2"
	up2.Src = &src2
	up2.Dst = &dst2
	up = append(up, &up1, &up2)
	s.UploadCommand("uploads", up)
	var upone []*Upload
	var up3 Upload
	src3 := "./"
	dst3 := "/tmp/$IMAGE3"
	up3.Src = &src3
	up3.Dst = &dst3
	upone = append(upone, &up3)
	s.UploadCommand("uploadone", upone)
	s.AddEnv("Name", "example")
	s.AddEnv("HOST_PORT", "8000")
	a, _ := json.Marshal(s)
	fmt.Println("======store======")
	fmt.Println("///////", string(a))
}
