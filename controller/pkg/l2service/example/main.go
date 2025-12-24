package main

import (
	"fmt"
	"github.com/netxops/cli/terminal"
	"github.com/netxops/cli/terminalmode"
	//"github.com/gofrs/uuid"
)

func f5() {
	base := &terminal.BaseInfo{
		Host:     "10.24.2.4",
		Username: "admin",
		Password: "admin@123",
		AuthPass: "admin@123",
		Telnet:   false,
	}

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.F5, base)
	//exec.Id = uuid.Must(uuid.NewV4()).String()
	exec.Add("show running-config", "", 10, "sh_run", "")
	exec.Prepare(true)
	result := exec.Run(true)
	fmt.Printf("result = %+v\n", result)
}

func ios() {
	base := &terminal.BaseInfo{
		Host:     "10.24.2.4",
		Username: "admin",
		Password: "admin@123",
		AuthPass: "admin@123",
		Telnet:   false,
	}

	exec := terminal.NewExecute(terminalmode.VIEW, terminalmode.Nexus, base)
	//exec.Id = uuid.Must(uuid.NewV4()).String()
	exec.Add("sh ver", "", 1, "sh_ver", "")
	exec.Add("sh ip int brief", "", 1, "", "")
	exec.Add("sh run", "", 1, "", "")
	exec.Prepare(true)
	result := exec.Run(true)
	fmt.Printf("result = %+v\n", result)
}

func main() {
	// f5()
	ios()
}
