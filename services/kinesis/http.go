package kinesis

import (
	"log/slog"

	"aws-in-a-box/http"
)

const service = "Kinesis_20131202"

func (k *Kinesis) RegisterHTTPHandlers(logger *slog.Logger, methodRegistry http.Registry) {
	http.Register(logger, methodRegistry, service, "AddTagsToStream", k.AddTagsToStream)
	http.Register(logger, methodRegistry, service, "CreateStream", k.CreateStream)
	http.Register(logger, methodRegistry, service, "DecreaseStreamRetentionPeriod", k.DecreaseStreamRetentionPeriod)
	http.Register(logger, methodRegistry, service, "DeleteStream", k.DeleteStream)
	http.Register(logger, methodRegistry, service, "DescribeStreamConsumer", k.DescribeStreamConsumer)
	http.Register(logger, methodRegistry, service, "DescribeStreamSummary", k.DescribeStreamSummary)
	http.Register(logger, methodRegistry, service, "DeregisterStreamConsumer", k.DeregisterStreamConsumer)
	http.Register(logger, methodRegistry, service, "GetRecords", k.GetRecords)
	http.Register(logger, methodRegistry, service, "GetShardIterator", k.GetShardIterator)
	http.Register(logger, methodRegistry, service, "IncreaseStreamRetentionPeriod", k.IncreaseStreamRetentionPeriod)
	http.Register(logger, methodRegistry, service, "ListShards", k.ListShards)
	http.Register(logger, methodRegistry, service, "ListTagsForStream", k.ListTagsForStream)
	http.Register(logger, methodRegistry, service, "PutRecord", k.PutRecord)
	http.Register(logger, methodRegistry, service, "PutRecords", k.PutRecords)
	http.Register(logger, methodRegistry, service, "RegisterStreamConsumer", k.RegisterStreamConsumer)
	http.Register(logger, methodRegistry, service, "RemoveTagsFromStream", k.RemoveTagsFromStream)
	http.RegisterOutputStream(logger, methodRegistry, service, "SubscribeToShard", k.SubscribeToShard)
}
