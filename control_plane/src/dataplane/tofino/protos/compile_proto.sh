go install google.golang.org/protobuf/cmd/protoc-gen-go
go install  google.golang.org/grpc/cmd/protoc-gen-go-grpc

protoc  --go_out=./bfruntime/.  --go-grpc_out=./bfruntime/. --proto_path=. -I=. ./bfruntime/bfruntime_9.3.0.proto
