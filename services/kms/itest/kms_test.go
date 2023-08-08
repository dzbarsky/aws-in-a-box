package kms

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
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

	withClient(func(client *kms.Client) {
		for name, input := range tests {
			t.Run(name, func(t *testing.T) {
				resp, err := client.CreateKey(context.Background(), input)

				checkResult(t, resp, err,
					// KeyId is random and Arn depends on it. Verified structure manually.
					cmp.FilterPath(func(path cmp.Path) bool { return path.Last().String() == `["KeyId"]` }, cmp.Ignore()),
					cmp.FilterPath(func(path cmp.Path) bool { return path.Last().String() == `["Arn"]` }, cmp.Ignore()),
					// Example: 2023-08-06T23:45:13.719Z
					// TODO: figure out how to verify the format here
					cmp.FilterPath(func(path cmp.Path) bool { return path.Last().String() == `["CreationDate"]` }, cmp.Ignore()),
				)
			})
		}
	})
}

func TestCreateAlias(t *testing.T) {
	tests := map[string]*kms.CreateAliasInput{
		"missing alias prefix":               {AliasName: aws.String("name")},
		"confusing alias name":               {AliasName: aws.String("alias/aws")},
		"reversed alias name":                {AliasName: aws.String("alias/aws/kinesis")},
		"overly long alias name":             {AliasName: aws.String("alias/" + strings.Repeat("a", 254))},
		"invalid char in alias name":         {AliasName: aws.String("alias/name?")},
		"overly long and invalid alias name": {AliasName: aws.String("alias/" + strings.Repeat("?", 254))},

		"good alias name": {AliasName: aws.String("alias/good")},
		"long alias name": {AliasName: aws.String("alias/" + strings.Repeat("a", 245))},
	}

	withClient(func(client *kms.Client) {
		key, err := client.CreateKey(context.Background(), &kms.CreateKeyInput{})
		if err != nil {
			t.Fatal(err)
		}

		t.Run("already exists", func(t *testing.T) {
			input := &kms.CreateAliasInput{
				TargetKeyId: key.KeyMetadata.KeyId,
				AliasName:   aws.String("alias/duplicate"),
			}
			_, err := client.CreateAlias(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.CreateAlias(context.Background(), input)
			checkResult(t, resp, err)
		})

		t.Run("target doesn't exists", func(t *testing.T) {
			resp, err := client.CreateAlias(context.Background(), &kms.CreateAliasInput{
				TargetKeyId: aws.String("6e7c7e7a-b9ae-41af-8a1f-227a3ed1e398"),
				AliasName:   aws.String("alias/nonexistant"),
			})

			checkResult(t, resp, err)
		})

		for name, input := range tests {
			t.Run(name, func(t *testing.T) {
				input.TargetKeyId = key.KeyMetadata.KeyId
				resp, err := client.CreateAlias(context.Background(), input)
				checkResult(t, resp, err)
			})
		}
	})
}

func withClient(fn func(client *kms.Client)) {
	var addr string
	if !generateSnapshot {
		srv, listener := makeServer()
		defer srv.Shutdown(context.Background())
		addr = listener.Addr().String()
	}

	client := makeClient(addr)
	fn(client)
}

func checkResult(t *testing.T, resp any, err error, cmpRespOptions ...cmp.Option) {
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
}
