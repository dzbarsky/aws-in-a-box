package dynamodb

import (
	"golang.org/x/exp/slog"

	"aws-in-a-box/http"
)

const service = "DynamoDB_20120810"

func (d *DynamoDB) RegisterHTTPHandlers(logger *slog.Logger, methodRegistry http.Registry) {
	http.Register(logger, methodRegistry, service, "CreateTable", d.CreateTable)
	http.Register(logger, methodRegistry, service, "DescribeTable", d.DescribeTable)
	http.Register(logger, methodRegistry, service, "PutItem", d.PutItem)
	http.Register(logger, methodRegistry, service, "Scan", d.Scan)
	http.Register(logger, methodRegistry, service, "UpdateItem", d.UpdateItem)
}
