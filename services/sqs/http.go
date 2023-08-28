package sqs

import (
	"log/slog"
	"net/http"
)

func registerHTTPHandlers(logger *slog.Logger, registry map[string]http.HandlerFunc, s *SQS) {
	register(logger, registry, "CreateQueue", s.CreateQueue)
	register(logger, registry, "SendMessage", s.SendMessage)
}
