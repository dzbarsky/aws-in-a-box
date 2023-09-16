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
