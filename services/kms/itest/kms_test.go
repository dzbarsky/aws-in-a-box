package kms

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"golang.org/x/exp/slog"

	"aws-in-a-box/server"
	kmsImpl "aws-in-a-box/services/kms"
)

func makeClient(addrOverride string) *kms.Client {
	options := kms.Options{
		Credentials: aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
				SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			}, nil
		}),
		Retryer: aws.NopRetryer{},
		Region:  "us-east-2",
	}
	if addrOverride != "" {
		options.BaseEndpoint = aws.String("http://" + addrOverride)
	}
	return kms.New(options)
}

func makeServer() (*http.Server, net.Listener) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	impl, err := kmsImpl.New(kmsImpl.Options{})
	if err != nil {
		panic(err)
	}

	methodRegistry := make(map[string]http.HandlerFunc)
	impl.RegisterHTTPHandlers(slog.Default(), methodRegistry)

	srv := server.NewWithHandlerChain(
		server.HandlerFuncFromRegistry(slog.Default(), methodRegistry),
	)
	go srv.Serve(listener)
	return srv, listener
}

var generateSnapshot = os.Getenv("GENERATE_SNAPSHOT") == "1"

type APIError struct {
	Code    string
	Message string
	Fault   string
}

type APIResponse struct {
	Err  *APIError
	Resp any
}

var snapshots = map[string]APIResponse{}

const snapshotsFilename = "snapshots.json"

func TestMain(m *testing.M) {
	if !generateSnapshot {
		data, err := os.ReadFile(snapshotsFilename)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(data, &snapshots)
		if err != nil {
			panic(err)
		}
	}

	exitCode := m.Run()

	if generateSnapshot {
		data, err := json.MarshalIndent(snapshots, "", "    ")
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(snapshotsFilename, data, 0666)
		if err != nil {
			panic(err)
		}
	}

	os.Exit(exitCode)
}

func TestCreateKey(t *testing.T) {
	var addr string
	if !generateSnapshot {
		srv, listener := makeServer()
		defer srv.Shutdown(context.Background())
		addr = listener.Addr().String()
	}

	client := makeClient(addr)

	tests := map[string]*kms.CreateKeyInput{
		"unknown keyspec":     {KeySpec: types.KeySpec("FAKE")},
		"unsupported keyspec": {KeySpec: types.KeySpecSm2},
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			fmt.Println(t.Name())
			resp, err := client.CreateKey(context.Background(), input)
			if err != nil {
				var apiErr smithy.APIError
				if !errors.As(err, &apiErr) {
					t.Fatal("unexpected error")
				}
				gotErr := APIError{
					Code:    apiErr.ErrorCode(),
					Message: apiErr.ErrorMessage(),
					Fault:   apiErr.ErrorFault().String(),
				}
				if generateSnapshot {
					snapshots[t.Name()] = APIResponse{
						Err: &gotErr,
					}
				} else {
					expectedErr := snapshots[t.Name()].Err
					if expectedErr == nil {
						t.Fatalf("Unexpected error: %s", apiErr)
					}
					apiErr.ErrorFault()
					if expectedErr.Fault != apiErr.ErrorFault().String() {
						t.Fatalf("Bad error fault, want \n%v, got \n%v", expectedErr.Fault, apiErr.ErrorFault().String())
					}
					if expectedErr.Code != apiErr.ErrorCode() {
						t.Fatalf("Bad error code, want \n%v, got \n%v", expectedErr.Code, apiErr.ErrorCode())
					}
					if expectedErr.Message != apiErr.ErrorMessage() {
						t.Fatalf("Bad error message, want \n%v, got \n%v", expectedErr.Message, apiErr.ErrorMessage())
					}
				}
			} else {
				if generateSnapshot {
					snapshots[t.Name()] = APIResponse{
						Resp: resp,
					}
				} else {
					expectedResp := snapshots[t.Name()].Resp
					if !reflect.DeepEqual(expectedResp, resp) {
						t.Fatalf("Bad resp, want %v, got %v", expectedResp, resp)
					}
				}
			}
		})
	}
}
