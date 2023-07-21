package s3

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"aws-in-a-box/awserrors"
)

func NewHandler(s3 *S3) func(w http.ResponseWriter, r *http.Request) bool {
	return func(w http.ResponseWriter, r *http.Request) bool {
		//log.Print("Handling S3 request ", r.Method, " ", r.URL.String())
		path := strings.Trim(r.URL.Path, "/")
		parts := strings.SplitN(path, "/", 2)

		if len(parts) == 1 {
			if r.URL.Query().Has("tagging") {
				switch r.Method {
				case http.MethodGet:
					handle(w, r, s3.GetBucketTagging)
				case http.MethodPut:
					handle(w, r, s3.PutBucketTagging)
				case http.MethodDelete:
					handle(w, r, s3.DeleteBucketTagging)
				}
				return true
			}
			switch r.Method {
			case http.MethodPut:
				handle(w, r, s3.CreateBucket)
			case http.MethodDelete:
				handle(w, r, s3.DeleteBucket)
			case http.MethodHead:
				handle(w, r, s3.HeadBucket)
			}
		}
		if len(parts) == 2 {
			if r.URL.Query().Has("tagging") {
				switch r.Method {
				case http.MethodGet:
					handle(w, r, s3.GetObjectTagging)
				case http.MethodPut:
					handle(w, r, s3.PutObjectTagging)
				case http.MethodDelete:
					handle(w, r, s3.DeleteObjectTagging)
				}
				return true
			} else if r.URL.Query().Has("uploads") {
				switch r.Method {
				case http.MethodGet:
					panic("Unhandled GetMultipartUploads")
				case http.MethodPost:
					handle(w, r, s3.CreateMultipartUpload)
				}
				return true
			} else if r.URL.Query().Has("uploadId") {
				switch r.Method {
				case http.MethodPut:
					handle(w, r, s3.UploadPart)
				case http.MethodPost:
					handle(w, r, s3.CompleteMultipartUpload)
				case http.MethodDelete:
					handle(w, r, s3.AbortMultipartUpload)
				}
				return true
			}
			switch r.Method {
			case http.MethodGet:
				handle(w, r, s3.GetObject)
			case http.MethodHead:
				handle(w, r, s3.HeadObject)
			case http.MethodPut:
				if r.Header.Get("x-amz-copy-source") != "" {
					handle(w, r, s3.CopyObject)
				} else {
					handle(w, r, s3.PutObject)
				}
			case http.MethodDelete:
				handle(w, r, s3.DeleteObject)
			default:
				panic("unknown method")
			}
		}
		return true
	}
}

func handle[Input any, Output any](
	w http.ResponseWriter,
	r *http.Request,
	handler func(input Input) (*Output, *awserrors.Error),
) {
	var input Input
	err := unmarshal(r, &input)
	if err != nil {
		panic(err)
	}
	output, awserr := handler(input)
	marshal(w, output, awserr)
}

func unmarshal(r *http.Request, target any) error {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)

	v := reflect.ValueOf(target).Elem()
	ty := v.Type()

	if _, ok := ty.FieldByName("XMLName"); ok {
		err := xml.NewDecoder(r.Body).Decode(target)
		if err != nil && err != io.EOF {
			return err
		}
	}

	for i := 0; i < ty.NumField(); i++ {
		field := ty.Field(i)
		tag := field.Tag.Get("s3")
		if tag == "" {
			continue
		}

		var value any
		if tag == "bucket" {
			value = parts[0]
		} else if tag == "key" {
			value = parts[1]
		} else if tag == "body" {
			var err error
			value, err = io.ReadAll(r.Body)
			if err != nil {
				panic(err)
			}
			defer r.Body.Close()
		} else if q, ok := strings.CutPrefix(tag, "query:"); ok {
			v := r.URL.Query().Get(q)
			if field.Type.Kind() == reflect.Int {
				var err error
				value, err = strconv.Atoi(v)
				if err != nil {
					panic(err)
				}
			} else {
				value = v
			}
		} else if h, ok := strings.CutPrefix(tag, "header:"); ok {
			value = r.Header.Get(h)
		}
		v.Field(i).Set(reflect.ValueOf(value))
	}
	return nil
}

func marshal(w http.ResponseWriter, output any, awserr *awserrors.Error) {
	var body io.Reader
	if awserr != nil {
		fmt.Println("ERRR", awserr)
		w.WriteHeader(awserr.Code)
		w.Write([]byte(awserr.Body.Message))
	} else {
		v := reflect.ValueOf(output).Elem()
		ty := v.Type()
		for i := 0; i < ty.NumField(); i++ {
			tag := ty.Field(i).Tag.Get("s3")
			if tag == "body" {
				body = bytes.NewReader(v.Field(i).Bytes())
			} else if h, ok := strings.CutPrefix(tag, "header:"); ok {
				w.Header().Set(h, v.Field(i).String())
			}
		}

		if output == response204 {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if body != nil {
			_, err := io.Copy(w, body)
			if err != nil {
				panic(err)
			}
		} else if _, ok := ty.FieldByName("XMLName"); ok {
			err := xml.NewEncoder(w).Encode(output)
			if err != nil {
				panic(err)
			}
		}
	}
}
