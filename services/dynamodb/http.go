package dynamodb

import "aws-in-a-box/http"

const service = "DynamoDB_20120810"

func (d *DynamoDB) RegisterHTTPHandlers(methodRegistry http.Registry) {
	http.Register(methodRegistry, service, "CreateTable", d.CreateTable)
	http.Register(methodRegistry, service, "DescribeTable", d.DescribeTable)
	http.Register(methodRegistry, service, "PutItem", d.PutItem)
	http.Register(methodRegistry, service, "Scan", d.Scan)
	http.Register(methodRegistry, service, "UpdateItem", d.UpdateItem)
}
