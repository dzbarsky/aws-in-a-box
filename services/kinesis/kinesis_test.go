package kinesis

import (
	//"slices"
	"testing"

	"aws-in-a-box/arn"
)

var generator = arn.Generator{
		AwsAccountId: "12345",
		Region:       "us-east-1",
	}

func newKinesisWithStream() (*Kinesis, string) {
	streamName := "stream"

	k := New(generator)
	_, err := k.CreateStream(CreateStreamInput{
		StreamName: streamName,
	})
	if err != nil {
		panic(err)
	}

	return k, streamName
}

func TestStreamTags(t *testing.T) {
	streamName := "stream"
	k := New(generator)
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
		TagKeys: []string{"k1"},
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
	//slices.Sort(output.Tags)
	if tags[0].Key != "k1" || tags[0].Value != "v1" {
		t.Fatal("Wrong tags")
	}
	if tags[1].Key != "k2" || tags[1].Value != "v2" {
		t.Fatal("Wrong tags")
	}
}

func TestListShards(t *testing.T) {
	streamName := "stream"
	k := New(generator)
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