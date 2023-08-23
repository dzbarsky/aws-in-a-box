package sqs

import (
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
	queues map[string]Queue
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
	}

	return s
}

// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html
func (s *SQS) CreateQueue(input CreateQueueInput) (*CreateQueueOutput, *awserrors.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if queue, ok := s.queues[input.QueueName]; ok {
		if maps.Equal(queue.Attributes, input.Attributes) {
			return &CreateQueueOutput{
				QueueUrl: queue.URL,
			}, nil
		}
		return nil, QueueNameExists("")
	}

	s.queues[input.QueueName] = Queue{
		Attributes: input.Attributes,
		Tags:       input.Tags,
		URL:        "TODO",
	}

	return nil, nil
}
