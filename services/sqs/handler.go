package sqs

import (
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/gofrs/uuid/v5"

	"aws-in-a-box/awserrors"
)

func register[Input any, Output any](
	logger *slog.Logger,
	registry map[string]http.HandlerFunc,
	method string,
	handler func(input Input) (*Output, *awserrors.Error),
) {
	logger = logger.With("method", method)
	registry[method] = func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Handling request")

		var input Input
		err := unmarshal(r, &input)
		if err != nil {
			logger.Error("Unmarshaling input", "err", err)
			panic(fmt.Errorf("%s: %v", method, err))
		}
		logger.Debug("Parsed input", "input", input)

		output, awserr := handler(input)
		logger.Debug("Got output", "output", output, "error", awserr)

		requestId := uuid.Must(uuid.NewV4()).String()
		marshal(w, xmlResp[Output]{
			output,
			ResponseMetadata{RequestId: requestId},
		}, awserr)
	}
}

func NewHandler(logger *slog.Logger, s *SQS) func(w http.ResponseWriter, r *http.Request) bool {
	registry := make(map[string]http.HandlerFunc)
	registerHTTPHandlers(logger, registry, s)

	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			return false
		}

		r.ParseForm()
		action := r.Form.Get("Action")
		handler, ok := registry[action]
		if !ok {
			return false
		}
		handler(w, r)
		return true
	}
}

func unmarshal(r *http.Request, target any) error {
	v := reflect.ValueOf(target).Elem()
	ty := v.Type()

	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		f := v.Field(i)

		switch field.Type.Kind() {
		case reflect.String:
			f.Set(reflect.ValueOf(r.FormValue(field.Name)))
		case reflect.Map:
			// Initialize the map and then read as many elements as we can.
			f.Set(reflect.MakeMap(f.Type()))

			for i := 1; ; i++ {
				mapKey := r.FormValue(fmt.Sprintf("%s.%d.Key", field.Name, i))
				mapValue := r.FormValue(fmt.Sprintf("%s.%d.Value", field.Name, i))
				if mapKey == "" && mapValue == "" {
					break
				}
				if mapKey != "" && mapValue != "" {
					f.SetMapIndex(reflect.ValueOf(mapKey), reflect.ValueOf(mapValue))
					continue
				}
				return errors.New("mismatched key/value?")
			}
		}
	}

	return nil
}

type xmlResp[T any] struct {
	T                *T
	ResponseMetadata ResponseMetadata
}

type ResponseMetadata struct {
	RequestId string
}

func marshal(w http.ResponseWriter, output any, awserr *awserrors.Error) {
	if awserr != nil {
		w.WriteHeader(awserr.Code)
		w.Write([]byte(awserr.Body.Message))
	} else {
		err := xml.NewEncoder(w).Encode(output)
		if err != nil {
			panic(err)
		}
	}
}
