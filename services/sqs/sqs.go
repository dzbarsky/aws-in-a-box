package sqs

import (
	"crypto/md5"
	"encoding/hex"
	"log/slog"
	"maps"
	"sync"

	"aws-in-a-box/arn"
	"aws-in-a-box/awserrors"
)

type Queue struct {
	// Immutable
	CreationTimestamp int64
	Attributes        map[string]string
	URL               string

	// Mutable
	Messages []byte
	Tags     map[string]string
}

type SQS struct {
	logger       *slog.Logger
	arnGenerator arn.Generator

	mu     sync.Mutex
	queues map[string]*Queue
	tags   map[string]string
}

type Options struct {
	Logger       *slog.Logger
	ArnGenerator arn.Generator
}

func New(options Options) *SQS {
	if options.Logger == nil {
		options.Logger = slog.Default()
	}

	s := &SQS{
		logger:       options.Logger,
		arnGenerator: options.ArnGenerator,
		queues:       make(map[string]*Queue),
	}

	return s
}

// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html
func (s *SQS) CreateQueue(input CreateQueueInput) (*CreateQueueOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if queue, ok := s.queues[input.QueueName]; ok {
		if maps.Equal(queue.Attributes, input.Attribute) {
			return &CreateQueueOutput{
				QueueUrl: queue.URL,
			}, nil
		}
		return nil, QueueNameExists("")
	}

	// TODO: We should make these not match to catch mistakes.
	// But this is expedient for now.
	url := input.QueueName

	s.queues[input.QueueName] = &Queue{
		Attributes: input.Attribute,
		Tags:       input.Tag,
		URL:        url,
	}

	return &CreateQueueOutput{
		QueueUrl: url,
	}, nil
}

// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
func (s *SQS) SendMessage(input SendMessageInput) (*SendMessageOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	queue, ok := s.queues[input.QueueUrl]
	if !ok {
		return nil, QueueDoesNotExist("")
	}
	_ = queue

	return &SendMessageOutput{
		MD5OfMessageBody: hexMD5([]byte(input.MessageBody)),
	}, nil
}

func hexMD5(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}
