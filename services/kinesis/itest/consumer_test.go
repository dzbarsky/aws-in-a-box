package itest

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"golang.org/x/exp/slog"

	"aws-in-a-box/arn"
	"aws-in-a-box/server"
	kinesisImpl "aws-in-a-box/services/kinesis"
)

func makeClientServerPair() (*kinesis.Client, *http.Server) {
	impl := kinesisImpl.New(kinesisImpl.Options{
		ArnGenerator: arn.Generator{
			AwsAccountId: "123456789012",
			Region:       "us-east-1",
		},
	})

	methodRegistry := make(map[string]http.HandlerFunc)
	impl.RegisterHTTPHandlers(slog.Default(), methodRegistry)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := server.NewWithHandlerChain(
		server.HandlerFuncFromRegistry(slog.Default(), methodRegistry),
	)
	go srv.Serve(listener)

	client := kinesis.New(kinesis.Options{
		EndpointResolver: kinesis.EndpointResolverFromURL("http://" + listener.Addr().String()),
		Retryer:          aws.NopRetryer{},
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

WaitForEvents:
	for {
		e := <-stream.Events()
		event := e.(*types.SubscribeToShardEventStreamMemberSubscribeToShardEvent).Value
		for _, record := range event.Records {
			if bytes.Equal(record.Data, []byte{maxMessageData}) {
				err = stream.Close()
				if err != nil {
					t.Fatal(err)
				}
				break WaitForEvents
			}
		}
	}

	_, err = client.DeregisterStreamConsumer(ctx, &kinesis.DeregisterStreamConsumerInput{
		StreamARN:    streamSummary.StreamDescriptionSummary.StreamARN,
		ConsumerName: consumerName,
	})

	if err != nil {
		t.Fatal(err)
	}
}
