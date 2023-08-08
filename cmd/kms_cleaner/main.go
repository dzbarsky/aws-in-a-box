package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const region = "us-east-2"

func makeClient() *kms.Client {
	options := kms.Options{
		Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
				SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			}, nil
		}),
		Retryer: aws.NopRetryer{},
		Region:  region,
	}
	return kms.New(options)
}

func main() {
	ctx := context.Background()
	client := makeClient()

	keys, err := client.ListKeys(ctx, &kms.ListKeysInput{})
	if err != nil {
		panic(err)
	}

	for _, key := range keys.Keys {
		fmt.Println("Deleting", key.KeyId)
		_, err = client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId: key.KeyId,
		})
		if err != nil {
			fmt.Println(err)
		}
	}

	aliases, err := client.ListAliases(ctx, &kms.ListAliasesInput{})
	if err != nil {
		panic(err)
	}

	for _, alias := range aliases.Aliases {
		fmt.Println("Deleting", alias.AliasName)
		_, err = client.DeleteAlias(ctx, &kms.DeleteAliasInput{
			AliasName: alias.AliasName,
		})
		if err != nil {
			fmt.Println(err)
		}
	}
}
