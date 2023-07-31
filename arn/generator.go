package arn

import (
	"fmt"
	"strings"
)

type Generator struct {
	AwsAccountId string
	Region       string
}

func (g Generator) Generate(service string, resourceType string, resourceId string) string {
	return fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s", service, g.Region, g.AwsAccountId, resourceType, resourceId)
}

// Returns the resource type and the resource ID
func ExtractId(arn string) (string, string) {
	// TODO: should we try to validate the ARN?
	parts := strings.Split(arn, ":")
	idWithType := parts[len(parts)-1]
	resourceType, id, found := strings.Cut(idWithType, "/")
	if !found {
		panic("Bogus arn? " + arn)
	}
	return resourceType, id
}
