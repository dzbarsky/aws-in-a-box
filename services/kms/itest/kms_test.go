package kms

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/exp/slog"

	"aws-in-a-box/arn"
	"aws-in-a-box/server"
	kmsImpl "aws-in-a-box/services/kms"
)

const region = "us-east-2"

func makeClient(addrOverride string) *kms.Client {
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
	impl, err := kmsImpl.New(kmsImpl.Options{
		ArnGenerator: arn.Generator{
			AwsAccountId: "666354587717",
			Region:       region,
		},
	})
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
	tests := map[string]*kms.CreateKeyInput{
		"unknown keyspec":         {KeySpec: types.KeySpec("FAKE")},
		"unsupported keyspec":     {KeySpec: types.KeySpecSm2},
		"bad usage for symmetric": {KeyUsage: types.KeyUsageTypeGenerateVerifyMac},
		"bad usage for hmac":      {KeySpec: types.KeySpecHmac224, KeyUsage: types.KeyUsageTypeEncryptDecrypt},

		"good symmetric":           {},
		"good HMAC_224":            {KeySpec: types.KeySpecHmac224, KeyUsage: types.KeyUsageTypeGenerateVerifyMac},
		"good HMAC_256":            {KeySpec: types.KeySpecHmac256, KeyUsage: types.KeyUsageTypeGenerateVerifyMac},
		"good HMAC_384":            {KeySpec: types.KeySpecHmac384, KeyUsage: types.KeyUsageTypeGenerateVerifyMac},
		"good HMAC_512":            {KeySpec: types.KeySpecHmac512, KeyUsage: types.KeyUsageTypeGenerateVerifyMac},
		"good RSA_2048 encryption": {KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeEncryptDecrypt},
		"good RSA_2048 sign":       {KeySpec: types.KeySpecRsa2048, KeyUsage: types.KeyUsageTypeSignVerify},
		"good RSA_3072 sign":       {KeySpec: types.KeySpecRsa3072, KeyUsage: types.KeyUsageTypeSignVerify},
		"good RSA_4096 sign":       {KeySpec: types.KeySpecRsa4096, KeyUsage: types.KeyUsageTypeSignVerify},
		"good ECC_NIST_P256":       {KeySpec: types.KeySpecEccNistP256, KeyUsage: types.KeyUsageTypeSignVerify},
		"good ECC_NIST_P384":       {KeySpec: types.KeySpecEccNistP384, KeyUsage: types.KeyUsageTypeSignVerify},
		"good ECC_NIST_P521":       {KeySpec: types.KeySpecEccNistP521, KeyUsage: types.KeyUsageTypeSignVerify},
	}

	createKey := func(client *kms.Client, input *kms.CreateKeyInput) (*kms.CreateKeyOutput, error) {
		return client.CreateKey(context.Background(), input)
	}

	endpointTest(t, nil, tests, createKey,
		// KeyId is random and Arn depends on it. Verified structure manually.
		cmp.FilterPath(func(path cmp.Path) bool { return path.Last().String() == `["KeyId"]` }, cmp.Ignore()),
		cmp.FilterPath(func(path cmp.Path) bool { return path.Last().String() == `["Arn"]` }, cmp.Ignore()),
		// Example: 2023-08-06T23:45:13.719Z
		// TODO: figure out how to verify the format here
		cmp.FilterPath(func(path cmp.Path) bool { return path.Last().String() == `["CreationDate"]` }, cmp.Ignore()),
	)
}

func endpointTest[Input any, Output any](
	t *testing.T,
	setupFunc func(client *kms.Client) error,
	tests map[string]Input,
	runTestFunc func(client *kms.Client, input Input) (Output, error),
	cmpRespOptions ...cmp.Option,
) {
	var addr string
	if !generateSnapshot {
		srv, listener := makeServer()
		defer srv.Shutdown(context.Background())
		addr = listener.Addr().String()
	}

	client := makeClient(addr)

	if setupFunc != nil {
		err := setupFunc(client)
		if err != nil {
			t.Fatal(err)
		}
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			resp, err := runTestFunc(client, input)
			if err != nil {
				var apiErr smithy.APIError
				if !errors.As(err, &apiErr) {
					t.Fatal("unwant error", err)
				}
				gotErr := &APIError{
					Code:    apiErr.ErrorCode(),
					Message: apiErr.ErrorMessage(),
					Fault:   apiErr.ErrorFault().String(),
				}
				if generateSnapshot {
					snapshots[t.Name()] = APIResponse{
						Err: gotErr,
					}
				} else {
					wantErr := snapshots[t.Name()].Err
					if !cmp.Equal(gotErr, wantErr) {
						t.Fatal(cmp.Diff(gotErr, wantErr))
					}
				}
			} else {
				if generateSnapshot {
					snapshots[t.Name()] = APIResponse{
						Resp: resp,
					}
				} else {
					wantResp := snapshots[t.Name()].Resp.(map[string]interface{})

					data, err := json.Marshal(resp)
					if err != nil {
						t.Fatal(err)
					}
					var gotResp map[string]interface{}
					err = json.Unmarshal(data, &gotResp)
					if err != nil {
						t.Fatal(err)
					}

					diff := cmp.Diff(gotResp, wantResp, cmpRespOptions...)
					if diff != "" {
						t.Fatal(diff)
					}
				}
			}
		})
	}
}
