package kinesis

import (
	"reflect"
	"regexp"
	"testing"

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
	k, streamName := newKinesisWithStream()
	streamName2 := streamName + "2"

	consumerName := "exampleConsumer"
	consumerName2 := consumerName + "2"
	registerInput := RegisterStreamConsumerInput{
		ConsumerName: consumerName,
		StreamARN:    k.arnForStream(streamName),
	}

	tests := map[string]struct {
		byArn        bool
		consumerName string
		streamName   string
		err          *awserrors.Error
	}{
		"by ARN":           {byArn: true},
		"by ARN with name": {byArn: true, streamName: streamName, consumerName: consumerName},
		"by ARN with wrong consumer name": {
			byArn: true, streamName: streamName, consumerName: consumerName2,
			//err: awserrors.InvalidArgumentException("Multiple consumers specified")
		},
		"by ARN with wrong stream name": {
			byArn: true, streamName: streamName2, consumerName: consumerName,
			err: awserrors.ResourceNotFoundException("No such stream"),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			output, err := k.RegisterStreamConsumer(registerInput)
			if err != nil {
				t.Fatal(err)
			}
			arn := output.Consumer.ConsumerARN

			deregisterInput := DeregisterStreamConsumerInput{
				ConsumerName: tc.consumerName,
			}
			if tc.byArn {
				deregisterInput.ConsumerARN = arn
			}
			if tc.streamName != "" {
				deregisterInput.StreamARN = k.arnForStream(tc.streamName)
			}

			_, err = k.DeregisterStreamConsumer(deregisterInput)
			if !reflect.DeepEqual(err, tc.err) {
				t.Fatal(err)
			}
		})
	}
}
