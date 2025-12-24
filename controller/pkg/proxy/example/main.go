package main

import (
	"context"
	"net"

	"github.com/influxdata/telegraf/controller/pkg/proxy"
)

func main() {
	addr, _ := net.ResolveTCPAddr("tcp", "0.0.0.0:8888")
	listener, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		panic(err)
	}
	proxy.Proxy(context.Background(), listener)
}
