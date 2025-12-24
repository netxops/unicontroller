package service

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/influxdata/telegraf/controller/pkg/structs"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	"github.com/netxops/utils/network"
	"github.com/netxops/utils/reachable"
	clitask "github.com/netxops/utils/task"
	"github.com/netxops/utils/text"
	"github.com/netxops/utils/tools"
)

func isSSHPort(ip string) bool {
	return reachable.IsAlive(ip) && reachable.TCPPortAlive(ip, "22")
}

func isTelnetPort(ip string) bool {
	return reachable.IsAlive(ip) && reachable.TCPPortAlive(ip, "23")
}

func checkH3CSSHNetworkDeviceIftable(ip string, remote *structs.L2DeviceRemoteInfo) (*clitask.Table, error) {
	var port int
	table := clitask.NewEmptyTableWithKeys([]string{"name", "status", "ip", "mask", "mac"})
	isSSH := isSSHPort(remote.Ip)
	isTelnet := isTelnetPort(remote.Ip)
	// isSSH := utils.Conditional(*remote.Meta.EnableSSH, true, false).(bool)
	// isTelnet := utils.Conditional(*remote.Meta.EnableTelnet, true, false).(bool)
	if isSSH {
		port = 22
		isTelnet = false
	} else if isTelnet {
		port = 23
	}

	if port != 22 && port != 23 {
		return clitask.NewEmptyTableWithKeys([]string{}), nil
	}

	base := &terminal.BaseInfo{
		Host:       remote.Ip,
		Username:   remote.Username,
		Password:   remote.Password,
		PrivateKey: remote.PrivateKey,
		Telnet:     isTelnet,
		Port:       port,
	}

	base.WithActionID(remote.ActionID)
	//
	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Comware, base)
	exec.Id = uuid.Must(uuid.NewV4()).String()
	exec.Add("display int", "", 10, "dis_int", "")
	exec.Prepare(false)
	data := exec.Run(false)
	if data.Error() != nil {
		return table, data.Error()
	}
	ok, lines := data.GetResult("dis_int")
	if !ok {
		err := fmt.Errorf("get cmd result failed, cmd=%s", "display int")
		return table, err
	}

	txt := strings.Join(lines, "\n")
	resultList, err := parseDisplayInt(txt)
	if err != nil {
		return table, err
	}
	for _, r := range resultList {
		table.PushRow("", r, false, "")
	}

	return table, nil
}

func parseDisplayInt(txt string) ([]map[string]string, error) {
	// logger.Debug("parseDisplayInt", zap.Any("txt", txt))
	resultList := []map[string]string{}
	portFilter := []string{"Aux0", "InLoopBack0", "NULL0", "Register-Tunnel0"}
	regex := `\S+((\r\x{0000}\n)|\n|(\r\n))Current\sstate.*?(\r\x{0000}\n){2}|\n{2}|(\r\n){2}`
	ss := text.MustSectionsByRegex(regex, txt)

	regexMap := map[string]string{
		"regex": `
	((?P<name>\S+)((\r\x{0000}\n)|\n|(\r\n))(Current\sstate:\s(?P<status>\S+))) |
	(Description:\s(?P<description>[^\n]+)) |
	(Internet\saddress:\s(?P<ip>\S+)) |
	(IP\spacket\sframe\stype:\sEthernet\sII,\shardware\saddress:\s(?P<mac>\S+)) |
	(Bandwidth:\s(?P<rate>\d+))
	`,
		"name":  "",
		"flags": "mx",
		"pcre":  "true",
	}

	spliter := text.MustSplitterFromMap(regexMap)
	for _, s := range ss.Texts {
		result, err := spliter.Input(s)
		if err != nil {
			return resultList, err
		}

		m, err := result.Projection([]string{}, "-", [][]string{})
		if err != nil {
			return resultList, err
		}

		if tools.Contains(portFilter, m["name"]) {
			continue
		}

		ip := m["ip"]
		if ip != "" {
			n, err := network.ParseIPNet(ip)
			if err != nil {
				return resultList, err
			}
			m["ip"] = n.IP.String()
			m["mask"] = n.Mask.String()
		}

		mac := m["mac"]
		if mac != "" {
			mac = strings.ReplaceAll(mac, "-", "")
			m["mac"] = mac
		}
		if m["status"] != "" {
			if strings.ToLower(m["status"]) == "up" {
				m["status"] = "1"
			} else if strings.ToLower(m["status"]) == "down" {
				m["status"] = "2"
			} else {
				m["status"] = "3"
			}
		}
		resultList = append(resultList, m)
	}

	return resultList, nil
}
