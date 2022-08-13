proto:
	protoc pkg/auth/pb/*.proto pkg/order/pb/*.proto pkg/product/pb/*.proto --go_out=plugins=grpc:.
#--go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative

server:
	go run cmd/main.go