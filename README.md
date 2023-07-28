# aws-in-a-box

This project is an emulator for several AWS services, a la Localstack. README in progress!




## Kinesis

<details>
<summary>Click to expand the support table</summary>
  
| API               | Support Status   | Caveats/Notes                              |
|-------------------|------------------|--------------------------------------------|
| AddTagsToStream      | ✅ Supported        |                                            |
| CreateStream      | ✅ Supported        |                                            |
| DecreaseStreamRetentionPeriod |  ✅ Supported |                                    |
| DescribeStreamConsumer|  ✅ Supported        |                                            |
| DeleteStream      | ✅ Supported        |                                            |
| DescribeStream | ❌ Unsupported         | This API is discouraged by AWS  |
| DescribeStreamSummary | ✅ Supported        |                                            |
| DeregisterStreamConsumer|  ✅ Supported        |                                            |
| GetShardIterator  | ✅ Supported        |                                            |
| GetRecords        | ✅ Supported        |                                            |
| IncreaseStreamRetentionPeriod |  ✅ Supported |                                    |
| ListShards       | ✅ Supported        |                                            |
| ListTagsForStream       | ✅ Supported        |                                            |
| MergeShards       | ❌ Unsupported      | No support for merging/splitting yet.          |
| PutRecord         | ✅ Supported        |                                            |
| PutRecords        | ❌ Unsupported      | Use PutRecord for single records instead.  |
| RegisterStreamConsumer|  ✅ Supported        |                                            |
| RemoveTagsFromStream      | ✅ Supported        |                                            |
| SplitShard        | ❌ Unsupported      | No support for merging/splitting yet.            |
| SubscribeToStream      | ✅ Supported        |                                            |
| UpdateShardCount  | ❌ Unsupported      | No support for merging/splitting yet.            |
</details>
