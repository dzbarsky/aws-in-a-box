# aws-in-a-box

This project is an emulator for several AWS services, à la Localstack. README in progress!

Currently supported services (see below for full support details):
- [DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/Welcome.html) - highly experimental, only enough for Kinesis Client Library to work. Not recommended to use!
- [Kinesis](https://docs.aws.amazon.com/kinesis/latest/APIReference/Welcome.html)
- [KMS](https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html)
- [S3](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)

Aws-in-a-box runs on HTTP (not HTTPS) but supports HTTP2 upgrade with h2c (HTTP without TLS).

## Why use this over localstack?
- Download and run a single 7MB file (statically-linked native binary). No interpereter/runtime hell. (There are also 3MB [docker images](https://hub.docker.com/r/dzbarsky/aws-in-a-box/tags) if you prefer)
- Simple persistence scheme using atomic file writes. When using the native binary, no more broken persistent docker volumes

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
| ListStreams                   | ❌ Unsupported  |                                           |
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
| GenerateDataKeyPair                 | ✅ Supported    |                                       |
| GenerateDataKeyPairWithoutPlaintext | ✅ Supported    |                                       |
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
| UpdateAlias                         | ✅ Supported    | need to implement, but its easy       |
| UpdateCustomKeyStore                | ❌ Unsupported  |                                       |
| UntagResource                       | ✅ Supported    |                                       |
| UpdateKeyDescription                | ✅ Supported    | need to implement, but its easy       |
| UpdatePrimaryRegion                 | ❌ Unsupported  |                                       |
| Verify                              | ✅ Supported    |                                       |
| VerifyMac                           | ✅ Supported    |                                       |
</details>
