package kinesis

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"aws-in-a-box/awserrors"
)

func TestRegisterStreamConsumer(t *testing.T) {
	k, streamName := newKinesisWithStream()

	streamName2 := streamName + "2"
	_, err := k.CreateStream(CreateStreamInput{
		StreamName: streamName2,
		ShardCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	consumerName := "exampleConsumer"
	//consumerName2 := "consumer2"

	output1, err := k.RegisterStreamConsumer(RegisterStreamConsumerInput{
		ConsumerName: consumerName,
		StreamARN:    k.arnForStream(streamName),
	})
	if err != nil {
		t.Fatal(err)
	}
	if output1.Consumer.ConsumerName != consumerName {
		t.Fatal("bad name")
	}

	_, err = k.RegisterStreamConsumer(RegisterStreamConsumerInput{
		ConsumerName: consumerName,
		StreamARN:    k.arnForStream(streamName),
	})
	if err == nil {
		t.Fatal("should have err")
	}

	// Should be able to reuse consumer name across streams
	output2, err := k.RegisterStreamConsumer(RegisterStreamConsumerInput{
		ConsumerName: consumerName,
		StreamARN:    k.arnForStream(streamName2),
	})
	if err != nil {
		t.Fatal(err)
	}
	if output2.Consumer.ConsumerName != consumerName {
		t.Fatal("bad name")
	}
}

func TestRegisterStreamConsumer_ARN(t *testing.T) {
	arnRe := regexp.MustCompile("^(arn):aws.*:kinesis:.*:\\d{12}:.*stream\\/[a-zA-Z0-9_.-]+\\/consumer\\/[a-zA-Z0-9_.-]+:[0-9]+")

	k, streamName := newKinesisWithStream()

	consumerName := "exampleConsumer"
	output, err := k.RegisterStreamConsumer(RegisterStreamConsumerInput{
		ConsumerName: consumerName,
		StreamARN:    k.arnForStream(streamName),
	})
	if err != nil {
		t.Fatal(err)
	}
	arn1 := output.Consumer.ConsumerARN
	if !arnRe.MatchString(arn1) {
		t.Fatal("bad arn", arn1)
	}

	_, err = k.DeregisterStreamConsumer(DeregisterStreamConsumerInput{
		ConsumerARN: arn1,
	})
	if err != nil {
		t.Fatal(err)
	}
	output, err = k.RegisterStreamConsumer(RegisterStreamConsumerInput{
		ConsumerName: consumerName,
		StreamARN:    k.arnForStream(streamName),
	})
	if err != nil {
		t.Fatal(err)
	}
	arn2 := output.Consumer.ConsumerARN
	if !arnRe.MatchString(arn2) {
		t.Fatal("bad arn", arn2)
	}

	if arn1 == arn2 {
		t.Fatal("should be unique")
	}
}

func TestDeregisterStreamConsumer(t *testing.T) {
	tests := map[string]struct {
		arnIndex     int
		consumerName string
		streamName   string
		err          *awserrors.Error
	}{
		"not specified": {
			err: awserrors.InvalidArgumentException("Consumer not specified"),
		},
		"by name": {streamName: "stream1", consumerName: "consumer1"},
		"real stream, bad consumer name": {
			streamName: "stream2", consumerName: "consumer1",
			err: awserrors.ResourceNotFoundException("No such consumer"),
		},
		"non-existent stream": {
			streamName: "stream3", consumerName: "consumer2",
			err: awserrors.ResourceNotFoundException("No such stream"),
		},
		"by ARN":           {arnIndex: 1},
		"by ARN with name": {arnIndex: 1, streamName: "stream1", consumerName: "consumer1"},
		"by ARN with wrong consumer name": {
			arnIndex: 1, streamName: "stream1", consumerName: "consumer2",
			err: awserrors.ResourceNotFoundException("No such consumer"),
		},
		"by ARN with other stream, bad consumer name": {
			arnIndex: 1, streamName: "stream2", consumerName: "consumer1",
			err: awserrors.ResourceNotFoundException("No such consumer"),
		},
		"by ARN with other consumer": {
			arnIndex: 1, streamName: "stream2", consumerName: "consumer2",
			err: awserrors.InvalidArgumentException("Multiple consumers specified"),
		},
		"by ARN with non-existent stream": {
			arnIndex: 1, streamName: "stream3", consumerName: "consumer2",
			err: awserrors.ResourceNotFoundException("No such stream"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			k := New(generator, time.Hour)
			arns := []string{""}
			for _, streamName := range []string{"stream1", "stream2"} {
				_, err := k.CreateStream(CreateStreamInput{
					StreamName: streamName,
					ShardCount: 1,
				})
				if err != nil {
					t.Fatal(err)
				}

				output, err := k.RegisterStreamConsumer(RegisterStreamConsumerInput{
					ConsumerName: strings.ReplaceAll(streamName, "stream", "consumer"),
					StreamARN:    k.arnForStream(streamName),
				})
				if err != nil {
					t.Fatal(err)
				}

				arns = append(arns, output.Consumer.ConsumerARN)
			}

			_, err := k.DeregisterStreamConsumer(
				DeregisterStreamConsumerInput{
					ConsumerARN:  arns[tc.arnIndex],
					ConsumerName: tc.consumerName,
					StreamARN:    k.arnForStream(tc.streamName),
				})
			if !reflect.DeepEqual(err, tc.err) {
				t.Fatal(err)
			}
		})
	}
}
