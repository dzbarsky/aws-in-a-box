package http

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"

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
			return errors.New("unexpected more JSON?")
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

const binaryDataTypeString = 7

func RegisterOutputStream[Input any, Output any](
	registry map[string]http.HandlerFunc,
	service string,
	method string,
	handler func(input Input) (chan *Output, *awserrors.Error),
) {
	registry[service+"."+method] = func(w http.ResponseWriter, r *http.Request) {

		contentType := r.Header.Get("Content-Type")

		var input Input
		err := strictUnmarshal(r.Body, contentType, &input)
		if err != nil {
			panic(fmt.Errorf("%s: %v", method, err))
		}

		outputCh, awserr := handler(input)

		w.WriteHeader(http.StatusOK)
		w.Write(encodeEvent("initial-response", nil, awserr))
		w.(http.Flusher).Flush()
		if awserr != nil {
			return
		}

		for output := range outputCh {
			data, err := json.Marshal(output)
			if err != nil {
				panic(err)
			}
			data = encodeEvent(method+"Event", data, nil)
			w.Write(data)
			w.(http.Flusher).Flush()
		}
	}
}

func mustCRC(data []byte) uint32 {
	crc := crc32.NewIEEE()
	_, err := crc.Write(data)
	if err != nil {
		panic(err)
	}
	return crc.Sum32()
}

func encodeEvent(eventType string, serializedEvent []byte, awserr *awserrors.Error) []byte {
	// AWS has a custom binary event encoding.
	// See https://docs.aws.amazon.com/AmazonS3/latest/API/RESTSelectObjectAppendix.html
	headers := map[string]string{
		":event-type": eventType,
	}
	if awserr != nil {
		headers[":message-type"] = "error"
		headers[":error-message"] = awserr.Body.Message
		headers[":error-code"] = strconv.Itoa(awserr.Code)
	} else {
		headers[":message-type"] = "event"
	}

	var headersBuf []byte
	for k, v := range headers {
		headersBuf = append(headersBuf, byte(len(k)))
		headersBuf = append(headersBuf, k...)
		headersBuf = append(headersBuf, binaryDataTypeString)
		headersBuf = binary.BigEndian.AppendUint16(headersBuf, uint16(len(v)))
		headersBuf = append(headersBuf, v...)
	}

	headersLen := len(headersBuf)
	payloadLen := len(serializedEvent)

	finalBuf := binary.BigEndian.AppendUint32(nil, uint32(headersLen+payloadLen+16))
	finalBuf = binary.BigEndian.AppendUint32(finalBuf, uint32(headersLen))
	finalBuf = binary.BigEndian.AppendUint32(finalBuf, mustCRC(finalBuf))
	finalBuf = append(finalBuf, headersBuf...)
	finalBuf = append(finalBuf, serializedEvent...)
	finalBuf = binary.BigEndian.AppendUint32(finalBuf, mustCRC(finalBuf))

	return finalBuf
}
