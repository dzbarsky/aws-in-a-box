package kinesis

import (
	"encoding/json"
)

type CreateStreamInput struct {
	StreamName string
	ShardCount int64
}

type CreateStreamOutput struct{}

type PutRecordInput struct {
	PartitionKey string
	StreamName   string
	Data         string

	ExplicitHashKey string

	// TODO: generalize, doesn't even work
	UnknownFields map[string]json.RawMessage `json:"-"`
}

type PutRecordOutput struct{}

type GetShardIteratorInput struct {
	ShardId                string
	ShardIteratorType      string
	StreamName             string
	StartingSequenceNumber string
}

type GetShardIteratorOutput struct {
	ShardIterator string
}

type GetRecordsInput struct {
	Limit         uint64
	ShardIterator string
	StreamARN     string
}

type GetRecordsOutput struct {
	MillisBehindLatest uint64
	NextShardIterator  string
	Records            []APIRecord
}

type ListShardsInput struct {
	StreamName  string
	ShardFilter struct {
		Type string
	}
}

type ListShardsOutput struct {
	Shards []APIShard
}

type APIShard struct {
	ShardId             string
	HashKeyRange        APIHashKeyRange
	SequenceNumberRange APISequenceNumberRange
}
type APIHashKeyRange struct {
	StartingHashKey string
	EndingHashKey   string
}
type APISequenceNumberRange struct {
	StartingSequenceNumber string
	EndingSequenceNumber   string
}

type APIRecord struct {
	// uint64? seconds? Millis?
	ApproximateArrivalTimestamp int64
	Data                        string
	PartitionKey                string
	SequenceNumber              string
}
