package kinesis

import "aws-in-a-box/http"

const service = "Kinesis_20131202"

func (k *Kinesis) RegisterHTTPHandlers(methodRegistry http.Registry) {
	http.Register(methodRegistry, service, "AddTagsToStream", k.AddTagsToStream)
	http.Register(methodRegistry, service, "CreateStream", k.CreateStream)
	http.Register(methodRegistry, service, "DecreaseStreamRetentionPeriod", k.DecreaseStreamRetentionPeriod)
	http.Register(methodRegistry, service, "DeleteStream", k.DeleteStream)
	http.Register(methodRegistry, service, "DescribeStreamConsumer", k.DescribeStreamConsumer)
	http.Register(methodRegistry, service, "DescribeStreamSummary", k.DescribeStreamSummary)
	http.Register(methodRegistry, service, "DeregisterStreamConsumer", k.DeregisterStreamConsumer)
	http.Register(methodRegistry, service, "GetRecords", k.GetRecords)
	http.Register(methodRegistry, service, "GetShardIterator", k.GetShardIterator)
	http.Register(methodRegistry, service, "IncreaseStreamRetentionPeriod", k.IncreaseStreamRetentionPeriod)
	http.Register(methodRegistry, service, "ListShards", k.ListShards)
	http.Register(methodRegistry, service, "ListTagsForStream", k.ListTagsForStream)
	http.Register(methodRegistry, service, "PutRecord", k.PutRecord)
	http.Register(methodRegistry, service, "RegisterStreamConsumer", k.RegisterStreamConsumer)
	http.Register(methodRegistry, service, "RemoveTagsFromStream", k.RemoveTagsFromStream)
	http.RegisterOutputStream(methodRegistry, service, "SubscribeToShard", k.SubscribeToShard)
}
