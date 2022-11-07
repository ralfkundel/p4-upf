## protobuf files compilen
cd ~/d-nets9_hybridcacheprototype/controller/src/dataplane/tofino/protos
go get google.golang.org/protobuf/cmd/protoc-gen-go
go get  google.golang.org/grpc/cmd/protoc-gen-go-grpc

protoc  --go_out=./bfruntime/.  --go-grpc_out=./bfruntime/. --proto_path=. -I=. ./bfruntime/bfruntime.proto
