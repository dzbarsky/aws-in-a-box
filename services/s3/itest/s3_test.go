package itest

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"aws-in-a-box/server"
	s3Impl "aws-in-a-box/services/s3"
)

var bucket = "test-bucket"

func makeClientServerPair() (*s3.Client, *http.Server) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	// TODO: Move this to an API call once we have routing
	impl := s3Impl.New(listener.Addr().String())
	_, awserr := impl.CreateBucket(s3Impl.CreateBucketInput{
		Bucket: bucket,
	})
	if awserr != nil {
		panic(err)
	}
	srv := server.New(s3Impl.NewHandler(impl))
	go srv.Serve(listener)

	client := s3.New(s3.Options{
		EndpointResolver: s3.EndpointResolverFromURL("http://" + listener.Addr().String()),
		// Disable the subdomain addressing since it won't work (test-bucket.127.0.0.1)
		UsePathStyle: true,
	})

	return client, srv
}
func TestMultipartUpload(t *testing.T) {
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	kmsKey := "custom-kms-key"
	key := "test-key"
	kmsContext := "foo=bar"
	upload, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:                  &bucket,
		Key:                     &key,
		ServerSideEncryption:    types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:             &kmsKey,
		SSEKMSEncryptionContext: &kmsContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := upload.UploadId

	var parts []types.CompletedPart
	for i, s := range []string{"hello", " world"} {
		output, err := client.UploadPart(ctx, &s3.UploadPartInput{
			PartNumber: int32(i),
			Bucket:     &bucket,
			Key:        &key,
			UploadId:   id,
			Body:       strings.NewReader(s),
		})
		if output.ServerSideEncryption != types.ServerSideEncryptionAwsKms {
			t.Fatal("missing SSE header")
		}
		if *output.SSEKMSKeyId != kmsKey {
			t.Fatal("missing KMS key header: ", *output.SSEKMSKeyId)
		}
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, types.CompletedPart{
			ETag:       output.ETag,
			PartNumber: int32(i),
		})
	}

	output, err := client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: id,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	})
	if output.ServerSideEncryption != types.ServerSideEncryptionAwsKms {
		t.Fatal("missing SSE header")
	}
	if *output.SSEKMSKeyId != kmsKey {
		t.Fatal("missing KMS key header")
	}
	if err != nil {
		t.Fatal(err)
	}

	object, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world" {
		t.Fatal("Unexpected data: ", string(data))
	}
	if object.ServerSideEncryption != types.ServerSideEncryptionAwsKms {
		t.Fatal("missing SSE header")
	}
	if *object.SSEKMSKeyId != kmsKey {
		t.Fatal("missing KMS key header")
	}
}
