package itest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"aws-in-a-box/arn"
	"aws-in-a-box/server"
	kinesisImpl "aws-in-a-box/services/kinesis"
)

func makeClientServerPair() (*kinesis.Client, *http.Server) {
	impl := kinesisImpl.New(arn.Generator{
		AwsAccountId: "123456789012",
		Region:       "us-east-1",
	}, time.Hour)

	methodRegistry := make(map[string]http.HandlerFunc)
	impl.RegisterHTTPHandlers(methodRegistry)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := server.New(methodRegistry)
	go srv.Serve(listener)

	client := kinesis.New(kinesis.Options{
		EndpointResolver: kinesis.EndpointResolverFromURL("http://" + listener.Addr().String()),
	})

	return client, srv
}
func TestSubscribeToShard(t *testing.T) {
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	streamName := aws.String("stream")
	_, err := client.CreateStream(ctx, &kinesis.CreateStreamInput{
		StreamName: streamName,
		ShardCount: aws.Int32(1),
	})
	if err != nil {
		panic(err)
	}
	stream, err := client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{
		StreamName: streamName,
	})

	consumerName := aws.String("consumer")
	consumer, err := client.RegisterStreamConsumer(ctx, &kinesis.RegisterStreamConsumerInput{
		StreamARN:    stream.StreamDescriptionSummary.StreamARN,
		ConsumerName: consumerName,
	})
	if err != nil {
		panic(err)
	}

	_, err = client.PutRecord(ctx, &kinesis.PutRecordInput{
		StreamARN:    stream.StreamDescriptionSummary.StreamARN,
		Data:         []byte("hello"),
		PartitionKey: aws.String("1"),
	})
	if err != nil {
		panic(err)
	}

	shards, err := client.ListShards(ctx, &kinesis.ListShardsInput{
		StreamName: streamName,
	})
	if err != nil {
		panic(err)
	}

	subscription, err := client.SubscribeToShard(ctx, &kinesis.SubscribeToShardInput{
		ConsumerARN: consumer.Consumer.ConsumerARN,
		ShardId:     shards.Shards[0].ShardId,
		StartingPosition: &types.StartingPosition{
			Type: "TRIM_HORIZON",
		},
	})
	if err != nil {
		panic(err)
	}

	for event := range subscription.GetStream().Events() {
		fmt.Println(event)
	}

	panic("frick")
}
