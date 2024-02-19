package itest

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"

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

func TestSendReceiveMessage_RoundtripAttributes(t *testing.T) {
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	resp, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{
		QueueName: aws.String("queue"),
	})
	if err != nil {
		t.Fatal(err)
	}

	messageAttributes := map[string]types.MessageAttributeValue{
		"string": {
			DataType:    aws.String("String"),
			StringValue: aws.String("s"),
		},
		"stringList": {
			DataType:         aws.String("String"),
			StringListValues: []string{"s1", "s2"},
		},
		"binary": {
			DataType:    aws.String("Binary"),
			BinaryValue: []byte("b"),
		},
		"binaryList": {
			DataType:         aws.String("Binary"),
			BinaryListValues: [][]byte{[]byte("b1"), []byte("b2")},
		},
	}

	body := "just a body, nothing to see here"
	_, err = client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:          resp.QueueUrl,
		MessageBody:       aws.String(body),
		MessageAttributes: messageAttributes,
	})
	if err != nil {
		t.Fatal(err)
	}

	receiveResp, err := client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:              resp.QueueUrl,
		MessageAttributeNames: []string{".*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(receiveResp.Messages) != 1 {
		t.Fatalf("Did not receive right number of messages: %d", len(receiveResp.Messages))
	}
	msg := receiveResp.Messages[0]
	if *msg.Body != body {
		t.Fatal("Didn't get back the right message")
	}
	if *messageAttributes["string"].StringValue != *msg.MessageAttributes["string"].StringValue {
		t.Fatal("string attribute did not roundtrip")
	}
	if !slices.Equal(messageAttributes["binary"].BinaryValue, msg.MessageAttributes["binary"].BinaryValue) {
		t.Fatal("binary attribute did not roundtrip")
	}
	if !slices.Equal(messageAttributes["stringList"].StringListValues, msg.MessageAttributes["stringList"].StringListValues) {
		t.Fatalf("stringList attribute did not roundtrip, got %v, want %v",
			msg.MessageAttributes["stringList"].StringListValues,
			messageAttributes["stringList"].StringListValues,
		)
	}
	if !slices.EqualFunc(messageAttributes["binaryList"].BinaryListValues, msg.MessageAttributes["binaryList"].BinaryListValues, bytes.Equal) {
		t.Fatalf("binaryList attribute did not roundtrip, got %v, want %v",
			msg.MessageAttributes["binaryList"].BinaryListValues,
			messageAttributes["binaryList"].BinaryListValues,
		)
	}
}

func TestMessageVisibility(t *testing.T) {
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	resp, err := client.CreateQueue(ctx, &sqs.CreateQueueInput{
		QueueName: aws.String("queue"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    resp.QueueUrl,
		MessageBody: aws.String("body"),
	})
	if err != nil {
		t.Fatal(err)
	}

	receiveResp, err := client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl: resp.QueueUrl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(receiveResp.Messages) != 1 {
		t.Fatalf("Message should be visible")
	}
	receiptHandle := receiveResp.Messages[0].ReceiptHandle

	receiveResp, err = client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl: resp.QueueUrl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(receiveResp.Messages) != 0 {
		t.Fatalf("Message should be invisible")
	}

	_, err = client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl:      resp.QueueUrl,
		ReceiptHandle: receiptHandle,
	})
	if err != nil {
		t.Fatal(err)
	}

	receiveResp, err = client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl: resp.QueueUrl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(receiveResp.Messages) != 1 {
		t.Fatalf("Message should be visible again")
	}
	receiptHandle = receiveResp.Messages[0].ReceiptHandle

	_, err = client.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl:      resp.QueueUrl,
		ReceiptHandle: receiptHandle,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      resp.QueueUrl,
		ReceiptHandle: receiptHandle,
	})
	if err != nil {
		t.Fatal(err)
	}

	receiveResp, err = client.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl: resp.QueueUrl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(receiveResp.Messages) != 0 {
		t.Fatalf("Deleted message should not be returned")
	}
}
