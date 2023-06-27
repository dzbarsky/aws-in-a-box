package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/fxamacker/cbor/v2"

	"aws-in-a-box/awserrors"
)

const (
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

func writeResponse(w http.ResponseWriter, output any, awserr *awserrors.Error, contentType string) {
	if awserr != nil {
		// TODO: correct error handling
		w.WriteHeader(awserr.Code)
		output = awserr.Body
	} else {
		w.WriteHeader(http.StatusOK)
	}

	if output == nil {
		return
	}

	marshalFunc := cbor.Marshal
	if contentType == jsonContentType {
		marshalFunc = json.Marshal
	}

	data, err := marshalFunc(output)
	if err != nil {
		panic(err)
	}
	w.Write(data)
}

type Registry = map[string]http.HandlerFunc

func Register[Input any, Output any](
	registry map[string]http.HandlerFunc,
	service string,
	method string,
	handler func(input Input) (*Output, *awserrors.Error),
) {
	registry[service+"."+method] = func(w http.ResponseWriter, r *http.Request) {

		contentType := r.Header.Get("Content-Type")

		var input Input
		err := strictUnmarshal(r.Body, contentType, &input)
		if err != nil {
			panic(fmt.Errorf("%s: %v", method, err))
		}

		output, awserr := handler(input)
		writeResponse(w, output, awserr, contentType)
	}
}
