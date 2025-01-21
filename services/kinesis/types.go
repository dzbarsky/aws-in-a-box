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

type PutRecordsInputRecord struct {
	PartitionKey    string
	Data            string
	ExplicitHashKey string
}

type PutRecordsInput struct {
	StreamName string
	StreamARN  string
	Records    []PutRecordsInputRecord
}

type PutRecordsOutput struct {
	Records []PutRecordOutput
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

type ListStreamsInput struct {
	ExclusiveStartStreamName string
	Limit                    int
	NextToken                string
}

type ListStreamsOutput struct {
	// TODO: HasMoreStreams bool
	// TODO: NextToken string
	StreamNames     []string
	StreamSummaries []APIStreamSummary
}

type APIStreamSummary struct {
	StreamARN string
	// Unix Nanos?
	StreamCreationTimestamp int64
	// TODO: StreamModeDetails:
	StreamName   string
	StreamStatus string
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
	StreamName string
	StreamARN  string
}

type DescribeStreamSummaryOutput struct {
	StreamDescriptionSummary APIStreamDescriptionSummary
}

type APIStreamDescriptionSummary struct {
	ConsumerCount  int
	EncryptionType string
	// EnhancedMonitoring - not implemented
	// KeyId string - not implemened
	OpenShardCount       int
	RetentionPeriodHours int32
	StreamARN            string
	// Unix Nanos?
	StreamCreationTimestamp int64
	// StreamModeDetails - not implemented
	StreamName   string
	StreamStatus string
}

type RegisterStreamConsumerInput struct {
	ConsumerName string
	StreamARN    string
}

type RegisterStreamConsumerOutput struct {
	Consumer APIConsumer
}

type APIConsumer struct {
	ConsumerARN               string
	ConsumerCreationTimestamp int64
	ConsumerName              string
	ConsumerStatus            string
}

type DeregisterStreamConsumerInput struct {
	ConsumerARN  string
	ConsumerName string
	StreamARN    string
}

type DeregisterStreamConsumerOutput struct{}

type DescribeStreamConsumerInput struct {
	ConsumerARN  string
	ConsumerName string
	StreamARN    string
}

type DescribeStreamConsumerOutput struct {
	ConsumerDescription APIConsumerDescription
}

type APIConsumerDescription struct {
	ConsumerARN string
	// Unix Nanos?
	ConsumerCreationTimestamp int64
	ConsumerName              string
	ConsumerStatus            string
	StreamARN                 string
}

type SubscribeToShardInput struct {
	ConsumerARN      string
	ShardId          string
	StartingPosition APIStartingPosition
}

type APIStartingPosition struct {
	Type           string
	SequenceNumber string
	// A time stamp is the Unix epoch date with precision in milliseconds.
	// need to fix these!
	Timestamp int64
}

type APISubscribeToShardEvent struct {
	ContinuationSequenceNumber string
	MillisBehindLatest         int32
	Records                    []APIRecord
}
