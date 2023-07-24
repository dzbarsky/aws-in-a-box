package kinesis

import (
	"strconv"
	"testing"

	"golang.org/x/exp/slices"

	"aws-in-a-box/arn"
)

var generator = arn.Generator{
	AwsAccountId: "123456789012",
	Region:       "us-east-1",
}

func newKinesisWithStream() (*Kinesis, string) {
	streamName := "exampleStream"

	k := New(Options{ArnGenerator: generator})
	_, err := k.CreateStream(CreateStreamInput{
		StreamName: streamName,
		ShardCount: 1,
	})
	if err != nil {
		panic(err)
	}

	return k, streamName
}

func TestStreamTags(t *testing.T) {
	streamName := "stream"
	k := New(Options{ArnGenerator: generator})
	_, err := k.CreateStream(CreateStreamInput{
		StreamName: streamName,
		ShardCount: 2,
		Tags: map[string]string{
			"k1": "v1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err := k.ListTagsForStream(ListTagsForStreamInput{
		StreamName: streamName,
	})
	if err != nil {
		t.Fatal(err)
	}
	tags := output.Tags

	if len(tags) != 1 {
		t.Fatal("Wrong tags")
	}
	if tags[0].Key != "k1" || tags[0].Value != "v1" {
		t.Fatal("Wrong tags")
	}

	_, err = k.RemoveTagsFromStream(RemoveTagsFromStreamInput{
		StreamName: streamName,
		TagKeys:    []string{"k1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err = k.ListTagsForStream(ListTagsForStreamInput{
		StreamName: streamName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(output.Tags) != 0 {
		t.Fatal("Wrong tags")
	}

	_, err = k.AddTagsToStream(AddTagsToStreamInput{
		StreamName: streamName,
		Tags: map[string]string{
			"k1": "v1",
			"k2": "v2",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err = k.ListTagsForStream(ListTagsForStreamInput{
		StreamName: streamName,
	})
	if err != nil {
		t.Fatal(err)
	}
	tags = output.Tags

	if len(tags) != 2 {
		t.Fatal("Wrong tags")
	}
	slices.SortFunc(output.Tags, func(t1, t2 APITag) bool {
		return t1.Key < t2.Key
	})
	if tags[0].Key != "k1" || tags[0].Value != "v1" {
		t.Fatal("Wrong tags")
	}
	if tags[1].Key != "k2" || tags[1].Value != "v2" {
		t.Fatal("Wrong tags")
	}
}

func TestListShards(t *testing.T) {
	streamName := "stream"
	k := New(Options{ArnGenerator: generator})
	_, err := k.CreateStream(CreateStreamInput{
		StreamName: streamName,
		ShardCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	output, err := k.ListShards(ListShardsInput{
		StreamName: streamName,
	})
	if err != nil {
		t.Fatal(err)
	}
	shards := output.Shards

	if len(shards) != 2 {
		t.Fatal("bad shard count")
	}

	if shards[0].ShardId == shards[1].ShardId {
		t.Fatal("Ids should be unique")
	}

	if shards[0].HashKeyRange.StartingHashKey != "0" {
		t.Fatal("bad start range " + shards[0].HashKeyRange.StartingHashKey)
	}

	if shards[0].HashKeyRange.EndingHashKey >= shards[1].HashKeyRange.StartingHashKey {
		t.Fatal("shards not sorted")
	}

	if shards[1].HashKeyRange.EndingHashKey != "340282366920938463463374607431768211455" {
		t.Fatal("bad end range " + shards[1].HashKeyRange.EndingHashKey)
	}
}

func TestGetShardIterator(t *testing.T) {
	streamName := "stream"
	k := New(Options{ArnGenerator: generator})
	_, err := k.CreateStream(CreateStreamInput{
		StreamName: streamName,
		ShardCount: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		_, err := k.PutRecord(PutRecordInput{
			StreamName:   streamName,
			PartitionKey: "key",
			Data:         strconv.Itoa(i),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	shardsOutput, err := k.ListShards(ListShardsInput{
		StreamName: streamName,
	})
	if err != nil {
		t.Fatal(err)
	}
	shardId := shardsOutput.Shards[0].ShardId

	_, err = k.GetShardIterator(GetShardIteratorInput{
		StreamName: streamName,
	})
	if err == nil {
		t.Fatal("Expected error")
	}

	shardIteratorOutput, err := k.GetShardIterator(GetShardIteratorInput{
		StreamName:        streamName,
		ShardId:           shardId,
		ShardIteratorType: "TRIM_HORIZON",
	})
	if err != nil {
		t.Fatal(err)
	}
	recordsOutput, err := k.GetRecords(GetRecordsInput{
		ShardIterator: shardIteratorOutput.ShardIterator,
	})
	if err != nil {
		t.Fatal(err)
	}

	allRecords := recordsOutput.Records
	if len(allRecords) != 5 {
		t.Fatal("not all records found")
	}

	shardIteratorOutput, err = k.GetShardIterator(GetShardIteratorInput{
		StreamName:        streamName,
		ShardId:           shardId,
		ShardIteratorType: "LATEST",
	})
	if err != nil {
		t.Fatal(err)
	}
	recordsOutput, err = k.GetRecords(GetRecordsInput{
		ShardIterator: shardIteratorOutput.ShardIterator,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(recordsOutput.Records) != 0 {
		t.Fatal("records found")
	}

	shardIteratorOutput, err = k.GetShardIterator(GetShardIteratorInput{
		StreamName:             streamName,
		ShardId:                shardId,
		ShardIteratorType:      "AT_SEQUENCE_NUMBER",
		StartingSequenceNumber: allRecords[2].SequenceNumber,
	})
	if err != nil {
		t.Fatal(err)
	}
	recordsOutput, err = k.GetRecords(GetRecordsInput{
		ShardIterator: shardIteratorOutput.ShardIterator,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(recordsOutput.Records) != 3 {
		t.Fatal("records found", len(recordsOutput.Records))
	}
}

func TestClip(t *testing.T) {

	records := []APIRecord{
		{ApproximateArrivalTimestamp: 5},
		{ApproximateArrivalTimestamp: 10},
		{ApproximateArrivalTimestamp: 15},
	}

	records = clip(records, 3)
	if len(records) != 3 {
		t.Fatal("bad clip")
	}

	records = clip(records, 5)
	if len(records) != 3 {
		t.Fatal("bad clip")
	}

	records = clip(records, 7)
	if len(records) != 2 {
		t.Fatal("bad clip")
	}

	records = clip(records, 20)
	if len(records) != 0 {
		t.Fatal("bad clip")
	}
}
