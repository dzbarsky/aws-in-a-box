package main

import (
	"flag"
	"log"
	"strings"
	"time"

	"aws-in-a-box/arn"
	"aws-in-a-box/http"
	"aws-in-a-box/server"
	"aws-in-a-box/services/dynamodb"
	"aws-in-a-box/services/kinesis"
	"aws-in-a-box/services/kms"
	"aws-in-a-box/services/s3"
)

func main() {
	addr := flag.String("addr", "localhost:4569", "Address to run on")
	persistDir := flag.String("persistDir", "", "Directory to persist data to. If empty, data is not persisted.")

	enableKinesis := flag.Bool("enableKinesis", true, "Enable Kinesis service")
	kinesisInitialStreams := flag.String("kinesisInitialStreams", "",
		"Streams to create at startup. Example: stream1,stream2,stream3")
	kinesisInitialShardsPerStream := flag.Int64("kinesisInitialShardsPerStream", 2,
		"How many shards to create for each stream listed in -kinesisInitialStreams")
	kinesisDefaultDuration := flag.Duration("kinesisDefaultDuration", 24*time.Hour,
		"How long to retain messages. Can be used to control memory usage. After creation, retention can be adjusted with [Increase/Decrease]StreamRetentionPeriod")

	enableKMS := flag.Bool("enableKMS", true, "Enable Kinesis service")

	enableDynamoDB := flag.Bool("experimental_enableDynamoDB", true, "Enable DynamoDB service")

	enableS3 := flag.Bool("experimental_enableS3", true, "Enable S3 service")
	s3InitialBuckets := flag.String("s3InitialBuckets", "", "Buckets to create at startup. Example: bucket1,bucket2,bucket3")

	flag.Parse()

	methodRegistry := make(http.Registry)

	arnGenerator := arn.Generator{
		// TODO: make these configurable?
		AwsAccountId: "123456789012",
		Region:       "us-east-1",
	}

	if *enableKinesis {
		k := kinesis.New(arnGenerator, *kinesisDefaultDuration)
		for _, name := range strings.Split(*kinesisInitialStreams, ",") {
			k.CreateStream(kinesis.CreateStreamInput{
				StreamName: name,
				ShardCount: *kinesisInitialShardsPerStream,
			})
		}
		k.RegisterHTTPHandlers(methodRegistry)
		//log.Println("Enabled Kinesis")
	}

	if *enableKMS {
		k, err := kms.New(arnGenerator, *persistDir)
		if err != nil {
			log.Fatal(err)
		}
		k.RegisterHTTPHandlers(methodRegistry)
		//log.Println("Enabled KMS")
	}

	if *enableDynamoDB {
		d := dynamodb.New(arnGenerator)
		d.RegisterHTTPHandlers(methodRegistry)
		//log.Println("Enabled DynamoDB (EXPERIMENTAL!!!)")
	}

	handlerChain := []server.HandlerFunc{server.HandlerFuncFromRegistry(methodRegistry)}

	if *enableS3 {
		s := s3.New(*addr)
		for _, name := range strings.Split(*s3InitialBuckets, ",") {
			s.CreateBucket(s3.CreateBucketInput{
				Bucket: name,
			})
		}
		handlerChain = append(handlerChain, s3.NewHandler(s))
	}

	srv := server.NewWithHandlerChain(handlerChain...)
	srv.Addr = *addr

	err := srv.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
