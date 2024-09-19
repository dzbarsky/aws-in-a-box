package itest

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestGetObject_Metadata(t *testing.T) {
	// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	key := "test-key"
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   strings.NewReader("hello"),
		Metadata: map[string]string{
			"ascii":     "AMAZONS3",
			"non-ascii": "ÄMÄZÕÑ S3",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.Metadata
	want := map[string]string{
		"ascii": "AMAZONS3",
		// Encoding doesn't match exactly but maybe compatible enough?
		"non-ascii": "=?utf-8?b?w4RNw4Raw5XDkSBTMw==?=",
		// "non-ascii": "=?UTF-8?B?w4PChE3Dg8KEWsODwpXDg8KRIFMz?=",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Wanted %v, got %v", want, got)
	}
}
