package itest

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"aws-in-a-box/server"
	sqsImpl "aws-in-a-box/services/sqs"
)

func makeClientServerPair() (*sqs.Client, *http.Server) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	impl := sqsImpl.New(sqsImpl.Options{})
	if err != nil {
		panic(err)
	}

	srv := server.NewWithHandlerChain(
		sqsImpl.NewHandler(slog.Default(), impl),
	)
	go srv.Serve(listener)

	client := sqs.New(sqs.Options{
		EndpointResolver: sqs.EndpointResolverFromURL("http://" + listener.Addr().String()),
		Retryer:          aws.NopRetryer{},
	})

	return client, srv
}

func TestQueue(t *testing.T) {
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	resp, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{
		QueueName: aws.String("queue"),
		Tags: map[string]string{
			"k1": "v1",
			"k2": "v2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	msg, err := client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    resp.QueueUrl,
		MessageBody: aws.String("READ THIS AND WEEP"),
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("msg ", msg)
}
