package sqs

import (
	"log/slog"
	"net/http"

	ahttp "aws-in-a-box/http"
)

const service = "AmazonSQS"

func registerHTTPHandlers(logger *slog.Logger, registry map[string]http.HandlerFunc, s *SQS) {
	register(logger, registry, "CreateQueue", s.CreateQueue)
	register(logger, registry, "ChangeMessageVisibility", s.ChangeMessageVisibility)
	register(logger, registry, "ChangeMessageVisibilityBatch", s.ChangeMessageVisibilityBatch)
	register(logger, registry, "DeleteMessage", s.DeleteMessage)
	register(logger, registry, "DeleteMessageBatch", s.DeleteMessageBatch)
	register(logger, registry, "DeleteQueue", s.DeleteQueue)
	register(logger, registry, "GetQueueAttributes", s.GetQueueAttributes)
	register(logger, registry, "GetQueueUrl", s.GetQueueUrl)
	register(logger, registry, "ListQueues", s.ListQueues)
	register(logger, registry, "ListQueueTags", s.ListQueueTags)
	register(logger, registry, "ReceiveMessage", s.ReceiveMessage)
	register(logger, registry, "SendMessage", s.SendMessage)
	register(logger, registry, "SetQueueAttributes", s.SetQueueAttributes)
	register(logger, registry, "TagQueue", s.TagQueue)
	register(logger, registry, "UntagQueue", s.UntagQueue)
}

func (s *SQS) RegisterHTTPHandlers(logger *slog.Logger, methodRegistry ahttp.Registry) {
	ahttp.Register(logger, methodRegistry, service, "CreateQueue", s.CreateQueue)
	ahttp.Register(logger, methodRegistry, service, "ChangeMessageVisibility", s.ChangeMessageVisibility)
	ahttp.Register(logger, methodRegistry, service, "ChangeMessageVisibilityBatch", s.ChangeMessageVisibilityBatch)
	ahttp.Register(logger, methodRegistry, service, "DeleteMessage", s.DeleteMessage)
	ahttp.Register(logger, methodRegistry, service, "DeleteMessageBatch", s.DeleteMessageBatch)
	ahttp.Register(logger, methodRegistry, service, "DeleteQueue", s.DeleteQueue)
	ahttp.Register(logger, methodRegistry, service, "GetQueueAttributes", s.GetQueueAttributes)
	ahttp.Register(logger, methodRegistry, service, "GetQueueUrl", s.GetQueueUrl)
	ahttp.Register(logger, methodRegistry, service, "ListQueues", s.ListQueues)
	ahttp.Register(logger, methodRegistry, service, "ListQueueTags", s.ListQueueTags)
	ahttp.Register(logger, methodRegistry, service, "ReceiveMessage", s.ReceiveMessage)
	ahttp.Register(logger, methodRegistry, service, "SendMessage", s.SendMessage)
	ahttp.Register(logger, methodRegistry, service, "SetQueueAttributes", s.SetQueueAttributes)
	ahttp.Register(logger, methodRegistry, service, "TagQueue", s.TagQueue)
	ahttp.Register(logger, methodRegistry, service, "UntagQueue", s.UntagQueue)
}
