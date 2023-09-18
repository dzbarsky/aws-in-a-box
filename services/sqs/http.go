package sqs

import (
	"log/slog"
	"net/http"
)

func registerHTTPHandlers(logger *slog.Logger, registry map[string]http.HandlerFunc, s *SQS) {
	register(logger, registry, "CreateQueue", s.CreateQueue)
	register(logger, registry, "DeleteMessage", s.DeleteMessage)
	register(logger, registry, "DeleteMessageBatch", s.DeleteMessageBatch)
	register(logger, registry, "DeleteQueue", s.DeleteQueue)
	register(logger, registry, "GetQueueAttributes", s.GetQueueAttributes)
	register(logger, registry, "GetQueueUrl", s.GetQueueUrl)
	register(logger, registry, "ListQueues", s.ListQueues)
	register(logger, registry, "ListQueueTags", s.ListQueueTags)
	register(logger, registry, "ReceiveMessage", s.ReceiveMessage)
	register(logger, registry, "SendMessage", s.SendMessage)
	register(logger, registry, "TagQueue", s.TagQueue)
	register(logger, registry, "UntagQueue", s.UntagQueue)
}
