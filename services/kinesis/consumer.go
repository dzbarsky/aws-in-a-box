package kinesis

import (
	"fmt"
	"regexp"
	"slices"
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

	if len(stream.consumersByName) >= 20 {
		return nil, awserrors.LimitExceededException("")
	}

	if _, ok := stream.consumersByName[input.ConsumerName]; ok {
		return nil, XXXTodoException("Consumer already exists")
	}

	now := time.Now().UnixNano()

	// See https://docs.aws.amazon.com/kinesis/latest/APIReference/API_Consumer.html#Streams-Type-Consumer-ConsumerARN
	arn := k.arnGenerator.Generate("kinesis", "stream",
		fmt.Sprintf("%s/consumer/%s:%d", stream.Name, input.ConsumerName, now))

	c := &Consumer{
		ARN:                    arn,
		Name:                   input.ConsumerName,
		CreationTimestamp:      now,
		StreamName:             stream.Name,
		SubscriptionsByShardId: make(map[string]consumerSubscription),
	}
	stream.consumersByName[input.ConsumerName] = c
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

		byName = stream.consumersByName[consumerName]
		if byName == nil {
			return nil, awserrors.ResourceNotFoundException("No such consumer")
		}
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
	delete(k.streams[c.StreamName].consumersByName, c.Name)

	for shardId, sub := range c.SubscriptionsByShardId {
		close(sub.Chan)
		shard, err := k.lockedGetShard(c.StreamName, shardId)
		if err != nil {
			// This shouldn't happen, we need to protect against dangling data when the stream is destroyed
			return nil, err
		}
		delete(shard.ConsumerChans, sub.Chan)
	}

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

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_SubscribeToShard.html
func (k *Kinesis) SubscribeToShard(input SubscribeToShardInput) (chan *APISubscribeToShardEvent, *awserrors.Error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	c := k.consumersByARN[input.ConsumerARN]
	if c == nil {
		return nil, awserrors.ResourceNotFoundException("")
	}

	shard, err := k.lockedGetShard(c.StreamName, input.ShardId)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	subscription, ok := c.SubscriptionsByShardId[input.ShardId]
	if ok {
		if subscription.CreationTime.Sub(now) < 5*time.Second {
			return nil, awserrors.ResourceInUseException("")
		} else {
			ch := subscription.Chan
			close(subscription.Chan)
			delete(shard.ConsumerChans, ch)
		}
	}

	index := 0
	switch input.StartingPosition.Type {
	case "TRIM_HORIZON":
	case "LATEST":
		index = len(shard.Records)
	case "AT_SEQUENCE_NUMBER":
		for i, record := range shard.Records {
			if record.SequenceNumber >= input.StartingPosition.SequenceNumber {
				index = i
				break
			}
		}
	case "AFTER_SEQUENCE_NUMBER":
		for i, record := range shard.Records {
			if record.SequenceNumber > input.StartingPosition.SequenceNumber {
				index = i
				break
			}
		}
	case "AT_TIMESTAMP":
		panic("Unsupported, need to work out timestamps")
	}

	outputChan := make(chan *APISubscribeToShardEvent, 1)
	outputChan <- &APISubscribeToShardEvent{
		Records:                    slices.Clone(shard.Records[index:]),
		ContinuationSequenceNumber: shard.Records[len(shard.Records)-1].SequenceNumber,
	}

	shard.ConsumerChans[outputChan] = struct{}{}
	c.SubscriptionsByShardId[input.ShardId] = consumerSubscription{
		CreationTime: now,
		Chan:         outputChan,
	}
	go func() {
		time.Sleep(5 * time.Minute)

		k.mu.Lock()
		defer k.mu.Unlock()
		close(outputChan)
		delete(shard.ConsumerChans, outputChan)
		delete(c.SubscriptionsByShardId, input.ShardId)
	}()

	return outputChan, nil
}
