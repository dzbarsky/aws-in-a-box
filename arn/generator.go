package arn

import (
	"fmt"
	"strings"
)

type ARN struct {
}

type Generator struct {
	AwsAccountId string
	Region       string
}

func (g Generator) Generate(service string, resourceType string, resourceId string) string {
	return fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s", service, g.Region, g.AwsAccountId, resourceType, resourceId)
}

func ExtractId(arn string) string {
	// TODO: should we try to validate the ARN?
	return strings.Split(arn, "/")[1]
}
