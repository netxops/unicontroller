#!/bin/bash
protoc -I . --go_out=. --go-grpc_out=. ./command.proto
protoc -I . --go_out=. --go-grpc_out=. ./lua.proto
protoc -I . --go_out=. --go-grpc_out=. ./package.proto
protoc -I . --go_out=. --go-grpc_out=. ./health.proto
protoc -I . --go_out=. --go-grpc_out=. ./metrics.proto

mv ./github.com/influxdata/telegraf/controller/pb/* ./

rm -rf ./github.com