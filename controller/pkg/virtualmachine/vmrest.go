package virtualmachine

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/imroc/req"
	"net/http"
)

const (
	vmApi = "rest/vcenter/vm"
)

type VmWareHttp struct {
	SessionId string
	HostIp    string
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func redirectPolicyFunc(User, Pwd string) (field, auth string) {
	return "Authorization", "Basic " + basicAuth(User, Pwd)
}

func NewVmWareHttp(Ip, User, Pwd string) *VmWareHttp {
	vmUrl := fmt.Sprintf("https://%s/rest/com/vmware/cis/session", Ip)

	field, auth := redirectPolicyFunc(User, Pwd)
	header := req.Header{
		"Content-Type": "application/json",
		field:          auth,
	}
	trans, _ := req.Client().Transport.(*http.Transport)
	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	sess, err := req.Post(vmUrl, header)
	if err != nil {
		panic(err)
	}

	sessJosn := map[string]interface{}{}
	_ = json.Unmarshal([]byte(sess.String()), &sessJosn)
	return &VmWareHttp{SessionId: sessJosn["value"].(string), HostIp: Ip}
}

func (vm *VmWareHttp) GetVmList() {
	vmApiUrl := fmt.Sprintf("https://%s/%s", vm.HostIp, vmApi)
	header := req.Header{
		"Content-Type":          "application/json",
		"vmware-api-session-id": vm.SessionId,
	}
	fmt.Println(header)
	res, err := req.Get(vmApiUrl, header)
	if err != nil {
		panic(err)
	}
	fmt.Println(res.String())
}
