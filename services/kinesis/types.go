package kinesis

type CreateStreamInput struct {
	StreamName string
	ShardCount int64
	Tags       map[string]string
}

type CreateStreamOutput struct{}

type DeleteStreamInput struct {
	// EnforceConsumerDeletion bool TODO
	StreamName string
	StreamARN  string
}

type DeleteStreamOutput struct{}

type PutRecordInput struct {
	PartitionKey string
	StreamName   string
	StreamARN    string
	Data         string

	ExplicitHashKey string
}

type PutRecordOutput struct {
	ShardId        string
	SequenceNumber string
}

type GetShardIteratorInput struct {
	ShardId                string
	ShardIteratorType      string
	StreamName             string
	StreamARN              string
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
	StreamARN   string
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
	// Unix Nanos?
	ApproximateArrivalTimestamp int64
	Data                        string
	PartitionKey                string
	SequenceNumber              string
}

type AddTagsToStreamInput struct {
	StreamName string
	StreamARN  string
	Tags       map[string]string
}

type AddTagsToStreamOutput struct{}

type RemoveTagsFromStreamInput struct {
	StreamName string
	StreamARN  string
	TagKeys    []string
}

type RemoveTagsFromStreamOutput struct{}

type ListTagsForStreamInput struct {
	StreamName string
	StreamARN  string
}

type ListTagsForStreamOutput struct {
	Tags []APITag
}

type APITag struct {
	Key   string
	Value string
}

type IncreaseStreamRetentionPeriodInput struct {
	StreamName           string
	StreamARN            string
	RetentionPeriodHours int32
}

type IncreaseStreamRetentionPeriodOutput struct{}

type DecreaseStreamRetentionPeriodInput struct {
	StreamName           string
	StreamARN            string
	RetentionPeriodHours int32
}

type DecreaseStreamRetentionPeriodOutput struct{}

type DescribeStreamSummaryInput struct {
	StreamName           string
	StreamARN            string
}

type DescribeStreamSummaryOutput struct {
	StreamDescriptionSummary APIStreamDescriptionSummary
}

type APIStreamDescriptionSummary struct {
	ConsumerCount int32
	EncryptionType string
	// EnhancedMonitoring - not implemented
	// KeyId string - not implemened
	OpenShardCount int
	RetentionPeriodHours int32
	StreamARN string
	// Unix Nanos?
	StreamCreationTimestamp int64
	// StreamModeDetails - not implemented
	StreamName string
	StreamStatus string
}