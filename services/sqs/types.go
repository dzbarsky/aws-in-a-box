package sqs

type CreateQueueInput struct {
	Attributes map[string]string
	QueueName  string
	Tags       map[string]string `json:"tags"`
}

type CreateQueueOutput struct {
	QueueUrl string
}
