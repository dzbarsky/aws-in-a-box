package kinesis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/fxamacker/cbor/v2"
)

const (
	service = "Kinesis_20131202"

	jsonContentType = "application/x-amz-json-1.1"
	cborContentType = "application/x-amz-cbor-1.1"
)

func strictUnmarshal(r io.Reader, contentType string, target any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	switch contentType {
	case jsonContentType:
		decoder := json.NewDecoder(bytes.NewBuffer(data))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(target)
		if err != nil {
			return fmt.Errorf("json unmarshal failed: %v", err)
		}
		err = decoder.Decode(target)
		if err != io.EOF {
			return errors.New("Unexpected more JSON?")
		}
	case cborContentType:
		decoder, err := cbor.DecOptions{
			ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		}.DecMode()
		if err != nil {
			return err
		}
		err = decoder.Unmarshal(data, target)
		if err != nil {
			return fmt.Errorf("%v, cbor unmarshal failed for %v", err, string(data))
		}
	default:
		return errors.New("Unknown contentType: " + contentType)
	}
	return nil
}

func register[Input any, Output any](
	registry map[string]http.HandlerFunc,
	method string,
	handler func(input Input) (Output, error),
) {
	registry[service+"."+method] = func(w http.ResponseWriter, r *http.Request) {

		contentType := r.Header.Get("Content-Type")

		var input Input
		err := strictUnmarshal(r.Body, contentType, &input)
		if err != nil {
			panic(fmt.Errorf("%s: %v", method, err))
		}

		output, err := handler(input)
		if err != nil {
			panic(err)
		}

		var data []byte
		if contentType == jsonContentType {
			data, err = json.Marshal(output)
		} else {
			data, err = cbor.Marshal(output)
		}
		if err != nil {
			panic(err)
		}

		w.Write(data)
	}
}

func (k *Kinesis) RegisterHTTPHandlers(methodRegistry map[string]http.HandlerFunc) {
	register(methodRegistry, "CreateStream", k.CreateStream)
	register(methodRegistry, "PutRecord", k.PutRecord)
	register(methodRegistry, "ListShards", k.ListShards)
	register(methodRegistry, "GetShardIterator", k.GetShardIterator)
	register(methodRegistry, "GetRecords", k.GetRecords)
}
