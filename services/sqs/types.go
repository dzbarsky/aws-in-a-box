package sqs

import "encoding/xml"

type CreateQueueInput struct {
	Attribute map[string]string
	QueueName string
	Tag       map[string]string
}

type CreateQueueOutput struct {
	XMLName  xml.Name `xml:"CreateQueueResult"`
	QueueUrl string
}

type DeleteQueueInput struct {
	QueueUrl string
}

type DeleteQueueOutput struct{}

const AWSTraceHeaderAttributeName = "AWSTraceHeader"

type SendMessageInput struct {
	DelaySeconds            int
	MessageAttributes       map[string]APIAttribute
	MessageBody             string
	MessageDeduplicationId  string
	MessageGroupId          string
	MessageSystemAttributes map[string]APIAttribute
	QueueUrl                string
}

type SendMessageOutput struct {
	XMLName xml.Name `xml:"SendMessageResult"`

	MD5OfMessageAttributes       string
	MD5OfMessageBody             string
	MD5OfMessageSystemAttributes string
	MessageId                    string
	SequenceNumber               string
}

type APIAttribute struct {
	BinaryListValues [][]byte
	BinaryValue      []byte
	DataType         string
	StringListValues []string
	StringValue      string
}

type TagQueueInput struct {
	QueueUrl string
	Tags     map[string]string
}

type TagQueueOutput struct{}

type UntagQueueInput struct {
	QueueUrl string
	TagKeys  []string
}

type UntagQueueOutput struct{}

type GetQueueUrlInput struct {
	QueueName string
}

type GetQueueUrlOutput struct {
	QueueUrl string
}

type ListQueuesInput struct {
	MaxResults      int
	QueueNamePrefix string
}

type ListQueuesOutput struct {
	QueueUrls []string `xml:"queueUrls"`
}

type GetQueueAttributesInput struct {
	attributeNames []string
	//`query:"attributeNames"`
	QueueUrl string
}

type GetQueueAttributesOutput struct {
	Attributes map[string]string `xml:"attributes"`
}

type ListQueueTagsInput struct {
	QueueUrl string
}

type ListQueueTagsOutput struct {
	Tags map[string]string
}

// https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html#SQS-ReceiveMessage-request-AttributeNames
type AttributeName string

const (
	All                              = AttributeName("All")
	ApproximateFirstReceiveTimestamp = AttributeName("ApproximateFirstReceiveTimestamp")
	ApproximateReceiveCount          = AttributeName("ApproximateReceiveCount")
	AWSTraceHeader                   = AttributeName("AWSTraceHeader")
	SenderId                         = AttributeName("SenderId")
	SentTimestamp                    = AttributeName("SentTimestamp")
	// TODO: this one not listedin https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html#SQS-ReceiveMessage-request-MessageSystemAttributeNames
	SqsManagedSseEnabled     = AttributeName("SqsManagedSseEnabled")
	MessageDeduplicationId   = AttributeName("MessageDeduplicationId")
	MessageGroupId           = AttributeName("MessageGroupId")
	SequenceNumber           = AttributeName("SequenceNumber")
	DeadLetterQueueSourceArn = AttributeName("DeadLetterQueueSourceArn")
	// TODO: there are more
)

type ReceiveMessageInput struct {
	// Deprecated
	AttributeNames              []AttributeName
	MaxNumberOfMessages         int
	MessageAttributeNames       []string
	MessageSystemAttributeNames []AttributeName
	QueueUrl                    string
	// ReceiveRequestAttemptId
	VisibilityTimeout int
	WaitTimeSeconds   int
}

type ReceiveMessageOutput struct {
	XMLName xml.Name `xml:"ReceiveMessageResult"`
	Message []APIMessage
}

type APIMessage struct {
	Attributes             map[string]string
	Body                   string
	MD5OfBody              string
	MD5OfMessageAttributes string
	MessageAttributes      map[string]APIAttribute
	MessageId              string
	ReceiptHandle          string
}

type DeleteMessageInput struct {
	QueueUrl      string
	ReceiptHandle string
}

type DeleteMessageOutput struct{}

type DeleteMessageBatchInput struct {
	QueueUrl string
	Entries  []struct {
		Id            string
		ReceiptHandle string
	}
}

type DeleteMessageBatchOutput struct {
	Failed     []BatchResultErrorEntry
	Successful []DeleteMessageBatchResultEntry
}

type BatchResultErrorEntry struct {
	Code        string
	Id          string
	Message     string
	SenderFault bool
}

type DeleteMessageBatchResultEntry struct {
	Id string
}
