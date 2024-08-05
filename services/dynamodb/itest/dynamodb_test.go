package itest

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"aws-in-a-box/arn"
	"aws-in-a-box/server"
	dynamodbImpl "aws-in-a-box/services/dynamodb"
)

const region = "us-east-2"

func makeClientServerPair() (*dynamodb.Client, *http.Server) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	impl := dynamodbImpl.New(dynamodbImpl.Options{
		ArnGenerator: arn.Generator{
			AwsAccountId: "666354587717",
			Region:       region,
		},
	})

	methodRegistry := make(map[string]http.HandlerFunc)
	impl.RegisterHTTPHandlers(slog.Default(), methodRegistry)

	srv := server.NewWithHandlerChain(
		server.HandlerFuncFromRegistry(slog.Default(), methodRegistry),
	)
	go srv.Serve(listener)

	client := dynamodb.New(dynamodb.Options{
		EndpointResolver: dynamodb.EndpointResolverFromURL("http://" + listener.Addr().String()),
		Retryer:          aws.NopRetryer{},
	})

	return client, srv
}

func TestGetItem_PartitionKey(t *testing.T) {
	ctx := context.Background()
	client, srv := makeClientServerPair()
	defer srv.Shutdown(ctx)

	primaryKey := aws.String("pkey")

	for _, primaryKeyType := range types.ScalarAttributeType("").Values() {
		t.Run("_"+string(primaryKeyType), func(t *testing.T) {
			tableName := "table_" + string(primaryKeyType)
			_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
				AttributeDefinitions: []types.AttributeDefinition{
					{
						AttributeName: primaryKey,
						AttributeType: primaryKeyType,
					},
				},
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: primaryKey,
						KeyType:       types.KeyTypeHash,
					},
				},
				TableName: &tableName,
			})
			if err != nil {
				t.Fatal(err)
			}

			var primaryKeyValue types.AttributeValue
			switch primaryKeyType {
			case types.ScalarAttributeTypeS:
				primaryKeyValue = &types.AttributeValueMemberS{Value: "key"}
			case types.ScalarAttributeTypeN:
				primaryKeyValue = &types.AttributeValueMemberN{Value: "key"}
			case types.ScalarAttributeTypeB:
				primaryKeyValue = &types.AttributeValueMemberB{Value: []byte("key")}
			default:
				t.Fatal("Unknown type")
			}

			_, err = client.PutItem(ctx, &dynamodb.PutItemInput{
				TableName: &tableName,
				Item:      map[string]types.AttributeValue{*primaryKey: primaryKeyValue},
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.GetItem(ctx, &dynamodb.GetItemInput{
				TableName: &tableName,
				Key:       map[string]types.AttributeValue{*primaryKey: primaryKeyValue},
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
