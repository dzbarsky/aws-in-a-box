package itest

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestCopyObject(t *testing.T) {
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	key := "test-key"
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   strings.NewReader("hello"),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     &bucket,
		Key:        &key,
		CopySource: aws.String("/" + bucket + "/" + key),
	})
	if err != nil {
		t.Fatal(err)
	}
}
