# aws-in-a-box

This project is an emulator for several AWS services, à la Localstack. README in progress!

Currently supported services (see below for full support details):
- [DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/Welcome.html) - highly experimental, only enough for Kinesis Client Library to work. Not recommended to use!
- [Kinesis](https://docs.aws.amazon.com/kinesis/latest/APIReference/Welcome.html)
- [KMS](https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html)
- [S3](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)
- [SQS](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html)

Aws-in-a-box runs on HTTP (not HTTPS) but supports HTTP2 upgrade with h2c (HTTP without TLS).

## Why use this over localstack?
- High-performance; no overhead from docker or proxies
- Single statically-linked 7MB native binary. No interpereter/runtime hell. (There are also 3MB compressed [docker images](https://hub.docker.com/r/dzbarsky/aws-in-a-box/tags) if you prefer)
- Simple persistence scheme using atomic file writes. When using the native binary, no more broken persistent docker volumes

## Usage
The easiest way to consume this project is from pre-built artifacts on the release page or the docker image.
You can also build from source with either go native tooling or with Bazel, see Development section.

```
  -addr string
    	Address to run on (default "localhost:4569")
  -reuse-port
      If set, will apply the SO_REUSEPORT socket option on Darwin/Linux platforms.
  -enableKMS
    	Enable Kinesis service (default true)
  -enableKinesis
    	Enable Kinesis service (default true)
  -enableSQS
    	Enable SQS service (default true)
  -experimental_enableDynamoDB
    	Enable DynamoDB service (default true)
  -experimental_enableS3
    	Enable S3 service (default true)
  -kinesisDefaultDuration duration
    	How long to retain messages. Can be used to control memory usage. After creation, retention can be adjusted with [Increase/Decrease]StreamRetentionPeriod (default 24h0m0s)
  -kinesisInitialShardsPerStream int
    	How many shards to create for each stream listed in -kinesisInitialStreams (default 2)
  -kinesisInitialStreams string
    	Streams to create at startup. Example: stream1,stream2,stream3
  -kinesisStreamCreateDuration duration
    	How long a new Kinesis stream stays in CREATING status (default 5s)
  -kinesisStreamDeleteDuration duration
    	How long a deleted Kinesis stream stays in DELETING status (default 5s)
  -logLevel string
    	debug/info/warn/error (default "debug")
  -persistDir string
    	Directory to persist data to. If empty, data is not persisted.
  -s3InitialBuckets string
    	Buckets to create at startup. Example: bucket1,bucket2,bucket3
```

## Development
You can use either native go tooling or Bazel.

### Running the service
- `go run .`
- `bazel run //:aws-in-a-box`

### Running tests
- `go test ./...`
- `bazel test //...`
<br>

## Kinesis Support
Most of Kinesis is implemented, including the Consumer APIS. Remaining work:
- KMS integration not wired up
- A few List/Describe APIs are missing
- Shard split/merge

There is no persistence for Kinesis data.
<details>
<summary>Click to expand the detailed support table</summary>
  
| API                           | Support Status | Caveats/Notes                             |
|-------------------------------|----------------|-------------------------------------------|
| AddTagsToStream               | ✅ Supported    |                                           |
| CreateStream                  | ✅ Supported    |                                           |
| DecreaseStreamRetentionPeriod | ✅ Supported    |                                           |
| DeleteStream                  | ✅ Supported    |                                           |
| DeregisterStreamConsumer      | ✅ Supported    |                                           |
| DescribeLimits                | ❌ Unsupported  |                                           |
| DescribeStream                | ❌ Unsupported  | This API is discouraged by AWS            |
| DescribeStreamConsumer        | ✅ Supported    |                                           |
| DescribeStreamSummary         | ✅ Supported    |                                           |
| DisableEnhancedMonitoring     | ❌ Unsupported  | Cloudwatch not implemented                |
| EnableEnhancedMonitoring      | ❌ Unsupported  | Cloudwatch not implemented                |
| GetRecords                    | ✅ Supported    |                                           |
| GetShardIterator              | ✅ Supported    |                                           |
| IncreaseStreamRetentionPeriod | ✅ Supported    |                                           |
| ListShards                    | ✅ Supported    |                                           |
| ListStreamConsumers           | ❌ Unsupported  |                                           |
| ListStreams                   | ✅ Supported    |                                           |
| ListTagsForStream             | ✅ Supported    |                                           |
| MergeShards                   | ❌ Unsupported  | No support for merging/splitting yet.     |
| PutRecord                     | ✅ Supported    |                                           |
| PutRecords                    | ❌ Unsupported  | Use PutRecord for single records instead. |
| RegisterStreamConsumer        | ✅ Supported    |                                           |
| RemoveTagsFromStream          | ✅ Supported    |                                           |
| SplitShard                    | ❌ Unsupported  | No support for merging/splitting yet.     |
| StartStreamEncryption         | ❌ Unsupported  |                                           |
| StopStreamEncryption          | ❌ Unsupported  |                                           |
| SubscribeToStream             | ✅ Supported    |                                           |
| UpdateShardCount              | ❌ Unsupported  | No support for merging/splitting yet.     |
| UpdateStreamMode              | ❌ Unsupported  |                                           |
</details>

<br>

## KMS Support
Most of KMS is implemented. Remaining work:
- Key deletion/key rotation is missing
- Grants are missing
- Key policies are missing

KMS data is fully persisted.
<details>
<summary>Click to expand the detailed support table</summary>
  
| API                                 | Support Status | Caveats/Notes                         |
|-------------------------------------|----------------|---------------------------------------|
| CancelKeyDeletion                   | ❌ Unsupported  |                                       |
| ConnectCustomKeyStore               | ❌ Unsupported  |                                       |
| CreateAlias                         | ✅ Supported    |                                       |
| CreateCustomKeyStore                | ❌ Unsupported  |                                       |
| CreateGrant                         | ❌ Unsupported  |                                       |
| CreateKey                           | ✅ Supported    | ECC_SECG_P256K1 and SM2 not supported |
| Decrypt                             | ✅ Supported    |                                       |
| DeleteAlias                         | ✅ Supported    |                                       |
| DeleteCustomKeyStore                | ❌ Unsupported  |                                       |
| DeleteImportedKeyMaterial           | ❌ Unsupported  |                                       |
| DescribeCustomKeyStores             | ❌ Unsupported  |                                       |
| DescribeKey                         | ✅ Supported    | Lots of metadata properties missing   |
| DisableKey                          | ✅ Supported    |                                       |
| DisableKeyRotation                  | ❌ Unsupported  |                                       |
| DisconnectCustomKeyStore            | ❌ Unsupported  |                                       |
| EnableKey                           | ✅ Supported    |                                       |
| EnableKeyRotation                   | ❌ Unsupported  |                                       |
| Encrypt                             | ✅ Supported    |                                       |
| GenerateDataKey                     | ✅ Supported    |                                       |
| GenerateDataKeyPair                 | ✅ Supported    | ECC_SECG_P256K1 not supported         |
| GenerateDataKeyPairWithoutPlaintext | ✅ Supported    | ECC_SECG_P256K1 not supported         |
| GenerateDataKeyWithoutPlaintext     | ✅ Supported    |                                       |
| GenerateMac                         | ✅ Supported    |                                       |
| GenerateRandom                      | ✅ Supported    |                                       |
| GetKeyPolicy                        | ❌ Unsupported  |                                       |
| GetKeyRotationStatus                | ❌ Unsupported  |                                       |
| GetParametersForImport              | ❌ Unsupported  |                                       |
| GetPublicKey                        | ❌ Unsupported  |                                       |
| ImportKeyMaterial                   | ❌ Unsupported  |                                       |
| ListAliases                         | ✅ Supported    |                                       |
| ListGrants                          | ❌ Unsupported  |                                       |
| ListKeyPolicies                     | ❌ Unsupported  |                                       |
| ListKeys                            | ✅ Supported    |                                       |
| ListResourceTags                    | ✅ Supported    |                                       |
| ListRetirableGrants                 | ❌ Unsupported  |                                       |
| PutKeyPolicy                        | ❌ Unsupported  |                                       |
| ReEncrypt                           | ✅ Supported    |                                       |
| ReplicateKey                        | ❌ Unsupported  |                                       |
| RetireGrant                         | ❌ Unsupported  |                                       |
| RevokeGrant                         | ❌ Unsupported  |                                       |
| ScheduleKeyDeletion                 | ❌ Unsupported  |                                       |
| Sign                                | ✅ Supported    |                                       |
| TagResource                         | ✅ Supported    |                                       |
| UntagResource                       | ✅ Supported    |                                       |
| UpdateAlias                         | ✅ Supported    |                                       |
| UpdateCustomKeyStore                | ❌ Unsupported  |                                       |
| UntagResource                       | ✅ Supported    |                                       |
| UpdateKeyDescription                | ✅ Supported    |                                       |
| UpdatePrimaryRegion                 | ❌ Unsupported  |                                       |
| Verify                              | ✅ Supported    |                                       |
| VerifyMac                           | ✅ Supported    |                                       |
</details>

<br>

## S3 Support
Most common operations of S3 are implemented. Remaining work:
- Versioning
- A bunch of metadata/usage APIs
- Policy/ACL is missing

S3 blocks are persisted, but metadata is not. This will be fixed in the future.
<details>
<summary>Click to expand the detailed support table</summary>
  
| API                                         | Support Status | Caveats/Notes                      |
|---------------------------------------------|----------------|------------------------------------|
| AbortMultipartUpload                        | ✅ Supported    |                                    |
| CompleteMultipartUpload                     | ✅ Supported    |                                    |
| CopyObject                                  | ✅ Supported    |                                    |
| CreateBucket                                | ✅ Supported    |                                    |
| CreateMultipartUpload                       | ✅ Supported    |                                    |
| DeleteBucket                                | ✅ Supported    |                                    |
| DeleteBucketAnalyticsConfiguration          | ❌ Unsupported  |                                    |
| DeleteBucketCors                            | ❌ Unsupported  |                                    |
| DeleteBucketEncryption                      | ❌ Unsupported  |                                    |
| DeleteBucketIntelligentTieringConfiguration | ❌ Unsupported  |                                    |
| DeleteBucketInventoryConfiguration          | ❌ Unsupported  |                                    |
| DeleteBucketLifecycle                       | ❌ Unsupported  |                                    |
| DeleteBucketMetricsConfiguration            | ❌ Unsupported  |                                    |
| DeleteBucketOwnershipControls               | ❌ Unsupported  |                                    |
| DeleteBucketPolicy                          | ❌ Unsupported  |                                    |
| DeleteBucketReplication                     | ❌ Unsupported  |                                    |
| DeleteBucketTagging                         | ✅ Supported    |                                    |
| DeleteBucketWebsite                         | ❌ Unsupported  |                                    |
| DeleteObject                                | ✅ Supported    |                                    |
| DeleteObjects                               | ✅ Supported    |                                    |
| DeleteObjectTagging                         | ✅ Supported    |                                    |
| DeletePublicAccessBlock                     | ❌ Unsupported  |                                    |
| GetBucketAccelerateConfiguration            | ❌ Unsupported  |                                    |
| GetBucketAcl                                | ❌ Unsupported  |                                    |
| GetBucketAnalyticsConfiguration             | ❌ Unsupported  |                                    |
| GetBucketCors                               | ❌ Unsupported  |                                    |
| GetBucketEncryption                         | ❌ Unsupported  |                                    |
| GetBucketIntelligentTieringConfiguration    | ❌ Unsupported  |                                    |
| GetBucketInventoryConfiguration             | ❌ Unsupported  |                                    |
| GetBucketLifecycle                          | ❌ Unsupported  | Discouraged by AWS                 |
| GetBucketLifecycleConfiguration             | ❌ Unsupported  |                                    |
| GetBucketLocation                           | ❌ Unsupported  |                                    |
| GetBucketLogging                            | ❌ Unsupported  |                                    |
| GetBucketMetricsConfiguration               | ❌ Unsupported  |                                    |
| GetBucketNotification                       | ❌ Unsupported  | Discouraged by AWS. no longer used |
| GetBucketNotificationConfiguration          | ❌ Unsupported  |                                    |
| GetBucketOwnershipControls                  | ❌ Unsupported  |                                    |
| GetBucketPolicy                             | ❌ Unsupported  |                                    |
| GetBucketPolicyStatus                       | ❌ Unsupported  |                                    |
| GetBucketReplication                        | ❌ Unsupported  |                                    |
| GetBucketRequestPayment                     | ❌ Unsupported  |                                    |
| GetBucketTagging                            | ✅ Supported    |                                    |
| GetBucketVersioning                         | ❌ Unsupported  |                                    |
| GetBucketWebsite                            | ❌ Unsupported  |                                    |
| GetObject                                   | ✅ Supported    |                                    |
| GetObjectAcl                                | ❌ Unsupported  |                                    |
| GetObjectAttributes                         | ❌ Unsupported  |                                    |
| GetObjectLegalHold                          | ❌ Unsupported  |                                    |
| GetObjectLockConfiguration                  | ❌ Unsupported  |                                    |
| GetObjectRetention                          | ❌ Unsupported  |                                    |
| GetObjectTagging                            | ✅ Supported    |                                    |
| GetObjectTorrent                            | ❌ Unsupported  |                                    |
| GetPublicAccessBlock                        | ❌ Unsupported  |                                    |
| HeadBucket                                  | ✅ Supported    |                                    |
| HeadObject                                  | ✅ Supported    |                                    |
| ListBucketAnalyticsConfigurations           | ❌ Unsupported  |                                    |
| ListBucketIntelligentTieringConfigurations  | ❌ Unsupported  |                                    |
| ListBucketInventoryConfigurations           | ❌ Unsupported  |                                    |
| ListBucketMetricsConfigurations             | ❌ Unsupported  |                                    |
| ListBuckets                                 | ✅ Supported    |                                    |
| ListMultipartUploads                        | ❌ Unsupported  | implement me!                      |
| ListObjects                                 | ❌ Unsupported  | implement me!                      |
| ListObjectsV2                               | ✅ Supported    |                                    |
| ListObjectVersions                          | ❌ Unsupported  |                                    |
| ListParts                                   | ✅ Supported    |                                    |
| PutBucketAccelerateConfiguration            | ❌ Unsupported  |                                    |
| PutBucketAcl                                | ❌ Unsupported  |                                    |
| PutBucketAnalyticsConfiguration             | ❌ Unsupported  |                                    |
| PutBucketCors                               | ❌ Unsupported  |                                    |
| PutBucketEncryption                         | ❌ Unsupported  |                                    |
| PutBucketIntelligentTieringConfiguration    | ❌ Unsupported  |                                    |
| PutBucketInventoryConfiguration             | ❌ Unsupported  |                                    |
| PutBucketLifecycle                          | ❌ Unsupported  | Deprecated                         |
| PutBucketLifecycleConfiguration             | ❌ Unsupported  |                                    |
| PutBucketLogging                            | ❌ Unsupported  |                                    |
| PutBucketMetricsConfiguration               | ❌ Unsupported  |                                    |
| PutBucketNotification                       | ❌ Unsupported  | No longer used                     |
| PutBucketNotificationConfiguration          | ❌ Unsupported  |                                    |
| PutBucketOwnershipControls                  | ❌ Unsupported  |                                    |
| PutBucketPolicy                             | ❌ Unsupported  |                                    |
| PutBucketReplication                        | ❌ Unsupported  |                                    |
| PutBucketRequestPayment                     | ❌ Unsupported  |                                    |
| PutBucketTagging                            | ✅ Supported    |                                    |
| PutBucketVersioning                         | ❌ Unsupported  |                                    |
| PutBucketWebsite                            | ❌ Unsupported  |                                    |
| PutObject                                   | ✅ Supported    |                                    |
| PutObjectAcl                                | ❌ Unsupported  |                                    |
| PutObjectLegalHold                          | ❌ Unsupported  |                                    |
| PutObjectLockConfiguration                  | ❌ Unsupported  |                                    |
| PutObjectRetention                          | ❌ Unsupported  |                                    |
| PutObjectTagging                            | ✅ Supported    |                                    |
| PutPublicAccessBlock                        | ❌ Unsupported  |                                    |
| RestoreObject                               | ❌ Unsupported  |                                    |
| SelectObjectContent                         | ❌ Unsupported  |                                    |
| UploadPart                                  | ✅ Supported    |                                    |
| UploadPartCopy                              | ❌ Unsupported  |                                    |
| WriteGetObjectResponse                      | ❌ Unsupported  |                                    |
</details>

<br>

## SQS Support
SQS support is in in-progress.
<details>
<summary>Click to expand the detailed support table</summary>

| API                          | Support Status | Caveats/Notes      |
|------------------------------|----------------|--------------------|
| AddPermission                | ❌ Unsupported  |                    |
| CancelMessageMoveTask        | ❌ Unsupported  |                    |
| ChangeMessageVisibility      | ✅ Supported    |                    |
| ChangeMessageVisibilityBatch | ✅ Supported    |                    |
| CreateQueue                  | ✅ Supported    |                    |
| DeleteMessage                | ✅ Supported    |                    |
| DeleteMessageBatch           | ✅ Supported    |                    |
| DeleteQueue                  | ✅ Supported    |                    |
| GetQueueAttributes           | ✅ Supported    |                    |
| GetQueueUrl                  | ✅ Supported    |                    |
| ListDeadLetterSourceQueues   | ❌ Unsupported  |                    |
| ListMessageMoveTasks         | ❌ Unsupported  |                    |
| ListQueues                   | ✅ Supported    |                    |
| ListQueueTags                | ✅ Supported    |                    |
| PurgeQueue                   | ❌ Unsupported  |                    |
| ReceiveMessage               | ✅ Supported    | wait not supported |
| RemovePermission             | ❌ Unsupported  |                    |
| SendMessage                  | ✅ Supported    |                    |
| SendMessageBatch             | ❌ Unsupported  |                    |
| SetQueueAttributes           | ✅ Supported    | not all attributes |
| StartMessageMoveTask         | ❌ Unsupported  |                    |
| TagQueue                     | ✅ Supported    |                    |
| UntagQueue                   | ✅ Supported    |                    |
</details>
