package sqs

import (
	"log/slog"

	"aws-in-a-box/http"
)

const service = "TODO"

func (s *SQS) RegisterHTTPHandlers(logger *slog.Logger, methodRegistry http.Registry) {
	http.Register(logger, methodRegistry, service, "CreateQueue", s.CreateQueue)
}
