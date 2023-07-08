package kinesis

import (
	"fmt"
	"regexp"
	"time"

	"aws-in-a-box/arn"
	"aws-in-a-box/awserrors"
)

var (
	consumerNameRe = regexp.MustCompile("[a-zA-Z0-9_.-]+")
)

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_RegisterStreamConsumer.html
func (k *Kinesis) RegisterStreamConsumer(input RegisterStreamConsumerInput) (*RegisterStreamConsumerOutput, *awserrors.Error) {
	if !consumerNameRe.MatchString(input.ConsumerName) {
		return nil, awserrors.InvalidArgumentException("Invalid character")
	}

	if input.ConsumerName == "" || len(input.ConsumerName) > 128 {
		return nil, awserrors.InvalidArgumentException("Invalid length")
	}

	_, streamName := arn.ExtractId(input.StreamARN)

	k.mu.Lock()
	defer k.mu.Unlock()

	stream, ok := k.streams[streamName]
	if !ok {
		return nil, awserrors.ResourceNotFoundException("")
	}

	if len(stream.Consumers) >= 20 {
		return nil, awserrors.LimitExceededException("")
	}

	if _, ok := stream.Consumers[input.ConsumerName]; ok {
		return nil, XXXTodoException("Consumer already exists")
	}

	now := time.Now().UnixNano()

	// See https://docs.aws.amazon.com/kinesis/latest/APIReference/API_Consumer.html#Streams-Type-Consumer-ConsumerARN
	arn := k.arnGenerator.Generate("kinesis", "stream",
		fmt.Sprintf("%s/consumer/%s:%d", stream.Name, input.ConsumerName, now))

	c := &Consumer{
		ARN:               arn,
		Name:              input.ConsumerName,
		CreationTimestamp: now,
		StreamName:        stream.Name,
	}
	stream.Consumers[input.ConsumerName] = c
	k.consumersByARN[arn] = c

	return &RegisterStreamConsumerOutput{
		Consumer: APIConsumer{
			ConsumerARN:               arn,
			ConsumerCreationTimestamp: now,
			ConsumerName:              c.Name,
			// TODO: delayed creation
			ConsumerStatus: "ACTIVE",
		},
	}, nil
}

func (k *Kinesis) lockedGetConsumer(
	consumerARN, streamARN, consumerName string,
) (*Consumer, *awserrors.Error) {
	var byArn, byName *Consumer

	if consumerARN != "" {
		byArn = k.consumersByARN[consumerARN]
	}

	if streamARN != "" && consumerName != "" {
		_, streamName := arn.ExtractId(streamARN)
		stream, ok := k.streams[streamName]
		if !ok {
			return nil, awserrors.ResourceNotFoundException("No such stream")
		}

		byName = stream.Consumers[consumerName]
	}

	if byArn == nil && byName == nil {
		return nil, awserrors.InvalidArgumentException("Consumer not specified")
	}

	if byArn != nil && byName != nil && byArn != byName {
		return nil, awserrors.InvalidArgumentException("Multiple consumers specified")
	}

	if byArn != nil {
		return byArn, nil
	}

	return byName, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_DeregisterStreamConsumer.html
func (k *Kinesis) DeregisterStreamConsumer(input DeregisterStreamConsumerInput) (*DeregisterStreamConsumerOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	c, err := k.lockedGetConsumer(input.ConsumerARN, input.StreamARN, input.ConsumerName)
	if err != nil {
		return nil, err
	}

	delete(k.consumersByARN, c.ARN)
	delete(k.streams[c.StreamName].Consumers, c.Name)
	return nil, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_DescribeStreamConsumer.html
func (k *Kinesis) DescribeStreamConsumer(input DescribeStreamConsumerInput) (*DescribeStreamConsumerOutput, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	c, err := k.lockedGetConsumer(input.ConsumerARN, input.StreamARN, input.ConsumerName)
	if err != nil {
		return nil, err
	}

	return &DescribeStreamConsumerOutput{
		ConsumerDescription: APIConsumerDescription{
			ConsumerARN:               c.ARN,
			ConsumerCreationTimestamp: c.CreationTimestamp,
			ConsumerName:              c.Name,
			ConsumerStatus:            "ACTIVE",
			StreamARN:                 k.arnForStream(c.StreamName),
		},
	}, nil
}
