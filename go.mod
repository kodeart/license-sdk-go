module github.com/kodeart/license-sdk-go

go 1.27.0

require (
	github.com/kodeart/license-server/api/proto v0.0.0
	google.golang.org/grpc v1.83.1
)

require (
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260819154853-08b0e4226688 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/kodeart/license-server/api/proto => ../../api/proto
