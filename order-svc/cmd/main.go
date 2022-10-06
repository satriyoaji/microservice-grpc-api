package main

import (
	"fmt"
	service "github.com/satriyoaji/order-svc/pkg/services"
	"log"
	"net"

	"github.com/satriyoaji/order-svc/pkg/client"
	"github.com/satriyoaji/order-svc/pkg/config"
	"github.com/satriyoaji/order-svc/pkg/db"
	"github.com/satriyoaji/order-svc/pkg/pb"
	"google.golang.org/grpc"
)

func main() {
	c, err := config.LoadConfig()

	if err != nil {
		log.Fatalln("Failed at config", err)
	}

	h := db.Init(c.DBUrl)

	lis, err := net.Listen("tcp", c.Port)

	if err != nil {
		log.Fatalln("Failed to listing:", err)
	}

	productSvc := client.InitProductServiceClient(c.ProductSvcUrl)

	if err != nil {
		log.Fatalln("Failed to listing:", err)
	}

	fmt.Println("Order Svc on", c.Port)

	s := service.Server{
		H:          h,
		ProductSvc: productSvc,
	}

	grpcServer := grpc.NewServer()

	pb.RegisterOrderServiceServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalln("Failed to serve:", err)
	}
}
