package kinesis

import (
	"crypto/md5"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	uint128Max = big.NewInt(0).SetBytes([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
)

func i64toA(i int64) string {
	return strconv.FormatInt(i, 10)
}

type Shard struct {
	Id string

	StartingHashKey big.Int
	EndingHashKey   big.Int

	StartingSequenceNumber int64
	EndingSequenceNumber   int64

	Records []APIRecord
}

type Stream struct {
	Shards []*Shard
	Tags   map[string]string
}

type Kinesis struct {
	mu      sync.Mutex
	streams map[string]*Stream
}

func New() *Kinesis {
	return &Kinesis{
		streams: map[string]*Stream{},
	}
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_CreateStream.html
func (k *Kinesis) CreateStream(input CreateStreamInput) (CreateStreamOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.streams[input.StreamName]; ok {
		return CreateStreamOutput{}, fmt.Errorf("Stream already exists")
	}

	stream := &Stream{
		Tags: make(map[string]string),
	}

	for tagName, tagValue := range input.Tags {
		stream.Tags[tagName] = tagValue
	}

	sequenceNumber := time.Now().UnixNano()

	step := big.NewInt(0).Div(uint128Max, big.NewInt(input.ShardCount))
	for i := int64(0); i < input.ShardCount; i++ {
		var start, end big.Int

		start.Mul(big.NewInt(i), step)
		end.Add(&start, step).Sub(&end, big.NewInt(1))
		if i == input.ShardCount-1 {
			end = *uint128Max
		}

		stream.Shards = append(stream.Shards, &Shard{
			// HACKY NAME??
			Id:                     input.StreamName + "@" + i64toA(i),
			StartingHashKey:        start,
			EndingHashKey:          end,
			StartingSequenceNumber: sequenceNumber,
			EndingSequenceNumber:   sequenceNumber,
		})
	}

	k.streams[input.StreamName] = stream
	return CreateStreamOutput{}, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecord.html
func (k *Kinesis) PutRecord(input PutRecordInput) (PutRecordOutput, error) {
	fmt.Println("PutRecord", input.StreamName)

	var hashKey big.Int
	if input.ExplicitHashKey != "" {
		hashKey.SetString(input.ExplicitHashKey, 10)
	} else {
		hash := md5.Sum([]byte(input.PartitionKey))
		hashKey.SetBytes(hash[:])
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	stream, ok := k.streams[input.StreamName]
	if !ok {
		return PutRecordOutput{}, fmt.Errorf("Stream does not exist")
	}

	for _, shard := range stream.Shards {
		if hashKey.Cmp(&shard.EndingHashKey) <= 0 && hashKey.Cmp(&shard.StartingHashKey) >= 0 {
			timestamp := time.Now().UnixNano()
			shard.Records = append(shard.Records, APIRecord{
				ApproximateArrivalTimestamp: timestamp,
				Data:                        input.Data,
				PartitionKey:                input.PartitionKey,
				SequenceNumber:              i64toA(timestamp),
			})
			return PutRecordOutput{}, nil
		}
	}

	panic("Could not find shard for record?")
}

func (k *Kinesis) lockedGetShard(streamName, shardId string) (*Shard, error) {
	stream, ok := k.streams[streamName]
	if !ok {
		return nil, fmt.Errorf("Stream does not exist")
	}

	for _, shard := range stream.Shards {
		if shard.Id == shardId {
			return shard, nil
		}
	}

	return nil, fmt.Errorf("Shard does not exist")
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetRecords.html
func (k *Kinesis) GetRecords(input GetRecordsInput) (GetRecordsOutput, error) {
	fmt.Println("GetRecords", input.ShardIterator)

	streamName, shardId, start, err := decodeShardIterator(input.ShardIterator)
	if err != nil {
		return GetRecordsOutput{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	shard, err := k.lockedGetShard(streamName, shardId)
	if err != nil {
		return GetRecordsOutput{}, fmt.Errorf("Shard does not exist")
	}

	var output GetRecordsOutput
	var currIndex int
	fmt.Printf("Found %d records\n", len(shard.Records))
	for currIndex = start; currIndex < len(shard.Records); currIndex++ {
		output.Records = append(output.Records, shard.Records[currIndex])
		/*input.Limit -= 1
		if input.Limit <= 0 {
			break
		}*/
	}

	output.NextShardIterator = encodeShardIterator(streamName, shardId, currIndex)
	fmt.Println("READ RECORDS", input.ShardIterator, output.NextShardIterator)
	return output, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_GetShardIterator.html
func (k *Kinesis) GetShardIterator(input GetShardIteratorInput) (GetShardIteratorOutput, error) {
	fmt.Println("GetShardIterator", input.StreamName, input)

	output := GetShardIteratorOutput{}
	switch input.ShardIteratorType {
	case "TRIM_HORIZON":
		output.ShardIterator = encodeShardIterator(input.StreamName, input.ShardId, 0)
	case "AT_SEQUENCE_NUMBER", "LATEST":
		shard, err := k.lockedGetShard(input.StreamName, input.ShardId)
		if err != nil {
			return output, fmt.Errorf("Shard does not exist")
		}
		index := 0
		if input.ShardIteratorType == "AT_SEQUENCE_NUMBER" {
			for i, record := range shard.Records {
				if record.SequenceNumber >= input.StartingSequenceNumber {
					index = i
					break
				}
			}
		}
		output.ShardIterator = encodeShardIterator(input.StreamName, input.ShardId, index)
	default:
		return output, fmt.Errorf("Unsupported iterator type: %s", input.ShardIteratorType)
	}

	return output, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListShards.html
func (k *Kinesis) ListShards(input ListShardsInput) (ListShardsOutput, error) {
	fmt.Println("ListShards", input.StreamName)

	k.mu.Lock()
	defer k.mu.Unlock()

	stream, ok := k.streams[input.StreamName]
	if !ok {
		return ListShardsOutput{}, fmt.Errorf("Stream does not exist")
	}

	// TODO: do anything with the ShardFilter?

	out := ListShardsOutput{}
	for _, shard := range stream.Shards {
		out.Shards = append(out.Shards, APIShard{
			ShardId: shard.Id,
			HashKeyRange: APIHashKeyRange{
				StartingHashKey: shard.StartingHashKey.String(),
				EndingHashKey:   shard.EndingHashKey.String(),
			},
			SequenceNumberRange: APISequenceNumberRange{
				StartingSequenceNumber: i64toA(shard.StartingSequenceNumber),
				EndingSequenceNumber:   i64toA(shard.EndingSequenceNumber),
			},
		})
	}
	return out, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_AddTagsToStream.html
func (k *Kinesis) AddTagsToStream(input AddTagsToStreamInput) (AddTagsToStreamOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	stream, ok := k.streams[input.StreamName]
	if !ok {
		return AddTagsToStreamOutput{}, fmt.Errorf("Stream does not exist")
	}

	for tagName, tagValue := range input.Tags {
		stream.Tags[tagName] = tagValue
	}

	return AddTagsToStreamOutput{}, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_RemoveTagsFromStream.html
func (k *Kinesis) RemoveTagsFromStream(input RemoveTagsFromStreamInput) (RemoveTagsFromStreamOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	stream, ok := k.streams[input.StreamName]
	if !ok {
		return RemoveTagsFromStreamOutput{}, fmt.Errorf("Stream does not exist")
	}

	for _, tagName := range input.TagKeys {
		delete(stream.Tags, tagName)
	}

	return RemoveTagsFromStreamOutput{}, nil
}

// https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListTagsForStream.html
func (k *Kinesis) ListTagsForStream(input ListTagsForStreamInput) (ListTagsForStreamOutput, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	var output ListTagsForStreamOutput

	stream, ok := k.streams[input.StreamName]
	if !ok {
		return output, fmt.Errorf("Stream does not exist")
	}

	for tagName, tagValue := range stream.Tags {
		output.Tags = append(output.Tags, APITag{
			Key:   tagName,
			Value: tagValue,
		})
	}

	return output, nil
}

// These are complete HAX, they probably need to be more legit
func encodeShardIterator(streamName string, shardId string, index int) string {
	return fmt.Sprintf("%s/%s/%d", streamName, shardId, index)
}

func decodeShardIterator(
	shardIterator string,
) (
	streamName string, shardId string, start int, err error,
) {
	parts := strings.Split(shardIterator, "/")
	streamName = parts[0]
	shardId = parts[1]
	start, err = strconv.Atoi(parts[2])
	return
}
