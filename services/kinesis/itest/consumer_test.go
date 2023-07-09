package itest

import (
	"bytes"
	"context"
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
	defer func() {
		// The shutdown is blocked by the 5-minute connection timeout.
		// Not sure how to handle this properly yet, but we don't want the
		// test to hang.
		ctx, _ := context.WithTimeout(ctx, 1*time.Millisecond)
		srv.Shutdown(ctx)
	}()

	streamName := aws.String("stream")
	_, err := client.CreateStream(ctx, &kinesis.CreateStreamInput{
		StreamName: streamName,
		ShardCount: aws.Int32(1),
	})
	if err != nil {
		panic(err)
	}

	streamSummary, err := client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{
		StreamName: streamName,
	})
	if err != nil {
		panic(err)
	}

	consumerName := aws.String("consumer")
	consumer, err := client.RegisterStreamConsumer(ctx, &kinesis.RegisterStreamConsumerInput{
		StreamARN:    streamSummary.StreamDescriptionSummary.StreamARN,
		ConsumerName: consumerName,
	})
	if err != nil {
		panic(err)
	}

	_, err = client.PutRecord(ctx, &kinesis.PutRecordInput{
		StreamARN:    streamSummary.StreamDescriptionSummary.StreamARN,
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
	stream := subscription.GetStream()

	const maxMessageData = 5
	go func() {
		for i := 0; i <= maxMessageData; i++ {
			_, err := client.PutRecord(ctx, &kinesis.PutRecordInput{
				StreamARN:    streamSummary.StreamDescriptionSummary.StreamARN,
				Data:         []byte{byte(i)},
				PartitionKey: aws.String("1"),
			})
			if err != nil {
				panic(err)
			}
		}
	}()

	for {
		e := <-stream.Events()
		event := e.(*types.SubscribeToShardEventStreamMemberSubscribeToShardEvent).Value
		for _, record := range event.Records {
			if bytes.Equal(record.Data, []byte{maxMessageData}) {
				err = stream.Close()
				if err != nil {
					panic(err)
				}
				return
			}
		}
	}
}
